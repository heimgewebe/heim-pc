"""Regression tests for the shipped tmux hook, not the user's live terminal."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import pty
import re
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "nixos/system/modules/ssh-cockpit-autocopy"
OSC52 = re.compile(rb"\x1b\]52;c;([A-Za-z0-9+/=]+)\x07")


def load_migration():
    spec = importlib.util.spec_from_file_location("autocopy_migration", SOURCE / "migrate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AutocopyTests(unittest.TestCase):
    def test_watcher_selftest(self):
        subprocess.run([sys.executable, str(SOURCE / "watch.py"), "--self-test"], check=True)

    def test_migration_and_rollback_preserve_legacy(self):
        module = load_migration()
        old = b"known synthetic legacy config\n"
        module.LEGACY_SHA256 = hashlib.sha256(old).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / ".tmux.conf"
            config.write_bytes(old)
            self.assertIn("migrated", module.migrate(home))
            self.assertEqual(config.read_bytes(), module.LOADER)
            self.assertEqual((home / module.BACKUP_NAME).read_bytes(), old)
            self.assertIn(b"source-file ~/.tmux.conf.before-heim-pc-managed-autocopy", module.LOADER)
            self.assertIn("unchanged", module.migrate(home))
            self.assertEqual((home / module.BACKUP_NAME).read_bytes(), old)

    def test_migration_does_not_overwrite_custom_or_symlink(self):
        module = load_migration()
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / ".tmux.conf"
            config.write_bytes(b"custom user configuration")
            self.assertIn("unchanged", module.migrate(home))
            self.assertEqual(config.read_bytes(), b"custom user configuration")
            self.assertFalse((home / module.BACKUP_NAME).exists())
            config.unlink()
            target = home / "other"
            target.write_bytes(b"custom")
            config.symlink_to(target)
            self.assertIn("unchanged", module.migrate(home))
            self.assertTrue(config.is_symlink())
            self.assertEqual(target.read_bytes(), b"custom")

    @unittest.skipUnless(sys.platform == "linux" and shutil.which("tmux") and shutil.which("setsid") and shutil.which("bash"), "Linux tmux PTY prerequisites unavailable")
    def test_real_pty_osc52_and_opt_out(self):
        with tempfile.TemporaryDirectory(prefix="autocopy-") as directory:
            path = Path(directory)
            socket = str(path / "sock")
            watcher = path / "watch"
            watcher.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(SOURCE / "watch.py")) + ' "$@"\n')
            watcher.chmod(0o700)
            config = path / "tmux.conf"
            config.write_text((SOURCE / "tmux.conf.in").read_text()
                              .replace("@setsid@", shutil.which("setsid"))
                              .replace("@watcher@", str(watcher))
                              .replace("@omnicopy@", shutil.which("true")))
            env = dict(os.environ, TERM="xterm-256color")
            env.pop("TMUX", None)
            env.pop("TMUX_PANE", None)
            env.pop("PROMPT_COMMAND", None)
            env["PS1"] = "[probe@heim-pc:~]$ "
            tm = lambda *a: subprocess.run(["tmux", "-S", socket, *a], env=env, capture_output=True, check=True, timeout=10)
            tm("-f", str(config), "new-session", "-d", "-s", "probe", "bash --noprofile --norc -i")
            master, slave = pty.openpty()
            client = subprocess.Popen(["tmux", "-S", socket, "attach", "-t", "probe"],
                                      stdin=slave, stdout=slave, stderr=slave, env=env,
                                      start_new_session=True)
            os.close(slave)

            def drain(seconds):
                raw = b""
                until = time.monotonic() + seconds
                while time.monotonic() < until:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            raw += os.read(master, 65536)
                        except OSError:
                            break
                return [base64.b64decode(value) for value in OSC52.findall(raw)]

            try:
                drain(3)
                os.write(master, b"printf 'AUTO_NORMAL_73\\n'\r")
                normal = drain(4)
                self.assertTrue(any(b"\nAUTO_NORMAL_73\n" in p for p in normal), normal)
                os.write(master, b"printf 'password=synthetic-test-only\\n'\r")
                self.assertFalse(drain(4), "sensitive output copied")
                os.write(master, b"printf 'AUTO_RECOVERY_91\\n'\r")
                recovered = drain(4)
                self.assertTrue(any(b"\nAUTO_RECOVERY_91" in p for p in recovered), recovered)
                self.assertTrue(all(b"synthetic-test-only" not in p for p in recovered))
                os.write(master, b"true\r")
                self.assertFalse(drain(3.5), "command without output copied")
                os.write(master, b"unsubmitted-input")
                self.assertFalse(drain(3.5), "unsubmitted input copied")
                os.write(master, b"\x15")
                self.assertFalse(drain(3.5), "clearing input recopied old output")
                tm("set-environment", "-t", "=probe", "HEIM_AUTOCOPY", "off")
                os.write(master, b"printf 'AUTO_DISABLED_55\\n'\r")
                self.assertFalse(drain(4), "opt-out ignored")
            finally:
                tm("kill-server")
                client.wait(timeout=5)
                os.close(master)


if __name__ == "__main__":
    unittest.main()
