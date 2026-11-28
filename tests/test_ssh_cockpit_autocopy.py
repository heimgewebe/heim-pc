"""Regression tests for the shipped tmux hook, not the user's live terminal."""
from __future__ import annotations

import base64
import fcntl
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

    def test_complete_visible_output_preserved(self):
        spec = importlib.util.spec_from_file_location("autocopy_watcher", SOURCE / "watch.py")
        watcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watcher)
        prompt = b"[probe@heim-pc:~]$ "
        # Deliberately artificial text: it matched the old content heuristic.
        fixture = prompt + b"printf 'password=synthetic-test-only'\npassword=synthetic-test-only\n"
        neutral_lines = b"synthetic-output\n" * 30
        safe = prompt + b"printf OK\nOK\n"
        for command in ("bash", "cat"):
            raw = fixture + neutral_lines + safe + prompt
            self.assertEqual(watcher.copy_payload(raw, command), raw)
        self.assertEqual(watcher.copy_payload(raw + b"unsubmitted", "bash"), b"")

    def test_inline_prompt_after_output_without_newline(self):
        spec = importlib.util.spec_from_file_location("autocopy_watcher", SOURCE / "watch.py")
        watcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watcher)
        prompt = b"[probe@heim-pc:~]$ "
        result = prompt + b"printf hello\nhello" + prompt
        marker = watcher.output_marker(result, "bash")
        self.assertIsNotNone(marker)
        self.assertIsNone(watcher.output_marker(result + b"unsubmitted-input", "bash"))
        self.assertEqual(watcher.copy_payload(result + b"unsubmitted-input", "bash"), b"")
        self.assertEqual(watcher.output_marker(result.rstrip(), "bash"), marker)
        # Bash readline can erase the inline prompt and part of the output
        # on Ctrl-U. This is not a new output event.
        redraw = prompt + b"printf hello\nhe   "
        self.assertIsNone(watcher.output_marker(redraw, "bash"))
        self.assertEqual(watcher.copy_payload(redraw, "bash"), b"")
        no_output_after_redraw = prompt + b"printf hello\nhetrue   \n" + prompt
        self.assertEqual(watcher.output_marker(no_output_after_redraw, "bash"), marker)
        # Actual PTY shape: Ctrl-U destroys the inline prompt; the next
        # producer is no longer recognizable but its result adds a row.
        new_output_after_redraw = prompt + b"printf hello\nheprintf next   \nNEXT\n" + prompt
        self.assertNotEqual(watcher.output_marker(new_output_after_redraw, "bash"), marker)
        self.assertIn(b"NEXT", watcher.copy_payload(new_output_after_redraw, "bash"))
        old = prompt + b"echo example\nexample=value\n"
        self.assertEqual(watcher.copy_payload(old + result, "bash"), old + result)

    def test_private_history_boundary(self):
        spec = importlib.util.spec_from_file_location("autocopy_watcher", SOURCE / "watch.py")
        watcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watcher)
        prompt = b"[probe@heim-pc:~]$ "
        # Inline prompt after disabled output; the prefix includes the old
        # bytes, but the outgoing payload must not.
        prior = prompt + b"printf hidden\nPRIVATE_OLD" + prompt
        anchor = watcher.private_anchor(prior, "bash")
        self.assertIsNotNone(anchor)
        current = prior + b"printf safe\nSAFE\n" + prompt
        self.assertIn(b"SAFE", watcher.private_payload(current, "bash", anchor))
        self.assertNotIn(b"PRIVATE_OLD", watcher.private_payload(current, "bash", anchor))
        self.assertEqual(watcher.private_payload(prompt + b"printf safe\nSAFE\n" + prompt, "bash", anchor), b"")
        self.assertEqual(watcher.private_payload(current, "vim", anchor), b"")
        self.assertEqual(watcher.private_payload(current, "bash", None), b"")

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

    def test_direct_new_session_and_slow_native_osc52(self):
        missing = [name for name in ("tmux", "setsid", "bash") if not shutil.which(name)]
        if sys.platform != "linux" or missing:
            reason = f"Linux tmux PTY prerequisites unavailable: {missing}"
            if sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true":
                self.fail(reason)
            self.skipTest(reason)
        with tempfile.TemporaryDirectory(prefix="autocopy-direct-") as directory:
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
            for key in ("TMUX", "TMUX_PANE", "PROMPT_COMMAND"):
                env.pop(key, None)
            env["PS1"] = "[probe@heim-pc:~]$ "
            tm = lambda *a: subprocess.run(["tmux", "-S", socket, *a], env=env, capture_output=True, timeout=10)
            lock_name = "heim-cockpit-autocopy-" + hashlib.sha256(socket.encode()).hexdigest()[:12] + ".lock"
            lock = os.open(path / lock_name, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            master, slave = pty.openpty()
            # No detached session and no later attach: this exercises the
            # direct new-session lifecycle and a transient lock handoff.
            client = subprocess.Popen(
                ["tmux", "-S", socket, "-f", str(config), "new-session", "-s", "probe",
                 "bash --noprofile --norc -i"],
                stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True,
            )
            os.close(slave)

            def drain(seconds):
                raw = b""
                until = time.monotonic() + seconds
                while time.monotonic() < until:
                    if select.select([master], [], [], 0.1)[0]:
                        raw += os.read(master, 65536)
                return raw

            try:
                drain(0.5)
                fcntl.flock(lock, fcntl.LOCK_UN)
                drain(3)
                # Withhold PTY reads while native tmux queues a long OSC52
                # publication, then send another command and drain both.
                os.write(master, b"printf 'NATIVE_LONG_%030000d_TAIL\\n' 7\r")
                time.sleep(4)
                os.write(master, b"printf 'NATIVE_AFTER_67\\n'\r")
                raw = drain(5)
                payloads = [base64.b64decode(value) for value in OSC52.findall(raw)]
                large = b"NATIVE_LONG_" + b"0" * 29999 + b"7_TAIL"
                self.assertTrue(any(large in data for data in payloads),
                                [(len(data), data[:100]) for data in payloads])
                self.assertTrue(any(b"\nNATIVE_AFTER_67" in data for data in payloads),
                                [(len(data), data[-100:]) for data in payloads])
            finally:
                tm("kill-server")
                try:
                    client.wait(timeout=5)
                finally:
                    if client.poll() is None:
                        client.terminate()
                    os.close(master)
                    os.close(lock)

    def test_nested_copy_off_and_manual_version_binding(self):
        missing = [name for name in ("tmux", "bash") if not shutil.which(name)]
        if sys.platform != "linux" or missing:
            reason = f"Linux tmux PTY prerequisites unavailable: {missing}"
            if sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true":
                self.fail(reason)
            self.skipTest(reason)
        with tempfile.TemporaryDirectory(prefix="autocopy-nested-") as directory:
            path = Path(directory)
            socket = str(path / "socket")
            tmux = shutil.which("tmux")
            env = dict(os.environ, TERM="xterm-256color")
            for key in ("TMUX", "TMUX_PANE", "PROMPT_COMMAND"):
                env.pop(key, None)
            env["PS1"] = "[probe@heim-pc:~]$ "
            tm = lambda *a: subprocess.run([tmux, "-S", socket, *a], env=env, capture_output=True, timeout=10, check=True)
            master, slave = pty.openpty()
            client = subprocess.Popen([tmux, "-S", socket, "-f", "/dev/null", "new-session", "-s", "probe",
                                       "bash --noprofile --norc -i"], stdin=slave, stdout=slave,
                                      stderr=slave, env=env, start_new_session=True)
            os.close(slave)

            def wait_for(predicate, seconds=8):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        os.read(master, 65536)
                    try:
                        result = predicate()
                        if result:
                            return result
                    except subprocess.CalledProcessError:
                        pass
                self.fail("tmux state did not converge")

            try:
                wait_for(lambda: tm("list-clients", "-F", "#{client_session}").stdout.strip() == b"probe")
                os.write(master, b"printf 'MANUAL_COPY_FIXTURE\\n'\r")
                wait_for(lambda: b"MANUAL_COPY_FIXTURE\n" in tm("capture-pane", "-p", "-t", "probe").stdout)
                pid, pane = tm("display-message", "-p", "-t", "probe", "#{pid} #{pane_id}").stdout.decode().split()
                fake = path / "tmux"
                fake.write_text("#!/bin/sh\nexit 99\n")
                fake.chmod(0o700)
                manual_env = dict(env, PATH=str(path) + os.pathsep + env["PATH"],
                                  TMUX=f"{socket},{pid},0", TMUX_PANE=pane)
                for args in ([], [pane, "--socket", socket, "--tmux-bin", f"/proc/{pid}/exe"]):
                    subprocess.run([sys.executable, str(SOURCE / "omnicopy.py"), *args],
                                   env=manual_env, capture_output=True, timeout=10, check=True)
                    self.assertIn(b"MANUAL_COPY_FIXTURE", tm("show-buffer").stdout)
                command = "bash " + shlex.quote(str(SOURCE / "copy-off.sh"))
                os.write(master, command.encode() + b"\r")
                new = wait_for(lambda: next((s for s in tm("list-clients", "-F", "#{client_session}").stdout.decode().splitlines()
                                             if s.startswith("copy-off-")), None))
                self.assertEqual(tm("show-environment", "-t", "=" + new, "HEIM_AUTOCOPY").stdout.strip(),
                                 b"HEIM_AUTOCOPY=off")
                self.assertIn(b"probe", tm("list-sessions", "-F", "#{session_name}").stdout.splitlines())
                self.assertEqual(tm("display-message", "-p", "-t", "=" + new, "#{pid}").stdout.strip(), pid.encode())
            finally:
                subprocess.run([tmux, "-S", socket, "kill-server"], env=env, capture_output=True, timeout=5)
                try:
                    client.wait(timeout=5)
                finally:
                    if client.poll() is None:
                        client.terminate()
                    os.close(master)

    def test_real_pty_osc52_and_opt_out(self):
        self._exercise_real_pty(include_full_history=True)

    def test_real_pty_opt_out_history(self):
        self._exercise_real_pty(include_full_history=False)

    def _exercise_real_pty(self, *, include_full_history):
        missing = [name for name in ("tmux", "setsid", "bash") if not shutil.which(name)]
        if sys.platform != "linux" or missing:
            reason = f"Linux tmux PTY prerequisites unavailable: {missing}"
            if sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true":
                self.fail(reason)
            self.skipTest(reason)
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
            second_master, second_slave = pty.openpty()
            second_client = subprocess.Popen(
                ["tmux", "-S", socket, "attach", "-t", "probe"],
                stdin=second_slave, stdout=second_slave, stderr=second_slave,
                env=env, start_new_session=True,
            )
            os.close(second_slave)
            second_updates = []

            def drain(seconds):
                raw = {master: b"", second_master: b""}
                until = time.monotonic() + seconds
                while time.monotonic() < until:
                    for fd in select.select([master, second_master], [], [], 0.1)[0]:
                        raw[fd] += os.read(fd, 65536)
                second_updates[:] = [base64.b64decode(value) for value in OSC52.findall(raw[second_master])]
                return [base64.b64decode(value) for value in OSC52.findall(raw[master])]

            try:
                drain(3)
                os.write(master, b"printf 'AUTO_NORMAL_73\\n'\r")
                normal = drain(4)
                self.assertTrue(any(b"\nAUTO_NORMAL_73\n" in p for p in normal), normal)
                self.assertTrue(any(b"\nAUTO_NORMAL_73\n" in p for p in second_updates), second_updates)
                os.write(master, b"printf 'AUTO_NO_NEWLINE_27'\r")
                inline = drain(4)
                self.assertTrue(any(b"\nAUTO_NO_NEWLINE_27" in p for p in inline), inline)
                self.assertTrue(any(b"\nAUTO_NO_NEWLINE_27" in p for p in second_updates), second_updates)
                os.write(master, b"inline-unsubmitted-input")
                self.assertFalse(drain(3.5), "inline editable prompt copied")
                self.assertFalse(second_updates, "inline editable prompt copied (second client)")
                os.write(master, b"\x15")
                self.assertFalse(drain(3.5), "clearing inline input recopied output")
                self.assertFalse(second_updates, "clearing inline input recopied output (second client)")
                if include_full_history:
                    os.write(master, b"printf 'EXAMPLE_OPTION=fixture-only\\n'\r")
                    complete = drain(4)
                    self.assertTrue(any(b"EXAMPLE_OPTION=fixture-only" in p for p in complete), complete)
                    self.assertTrue(any(b"EXAMPLE_OPTION=fixture-only" in p for p in second_updates), second_updates)
                    os.write(master, b"printf 'AUTO_RECOVERY_91\\n'\r")
                    recovered = drain(4)
                    self.assertTrue(any(b"\nAUTO_RECOVERY_91" in p and b"EXAMPLE_OPTION=fixture-only" in p for p in recovered), recovered)
                    self.assertTrue(any(b"\nAUTO_RECOVERY_91" in p and b"EXAMPLE_OPTION=fixture-only" in p for p in second_updates), second_updates)
                os.write(master, b"true\r")
                self.assertFalse(drain(3.5), "command without output copied")
                self.assertFalse(second_updates, "command without output copied (second client)")
                os.write(master, b"unsubmitted-input")
                self.assertFalse(drain(3.5), "unsubmitted input copied")
                self.assertFalse(second_updates, "unsubmitted input copied (second client)")
                os.write(master, b"\x15")
                self.assertFalse(drain(3.5), "clearing input recopied old output")
                self.assertFalse(second_updates, "clearing input recopied old output (second client)")
                tm("set-environment", "-t", "=probe", "HEIM_AUTOCOPY", "off")
                os.write(master, b"printf 'AUTO_DISABLED_55\\n'\r")
                self.assertFalse(drain(4), "opt-out ignored")
                self.assertFalse(second_updates, "opt-out ignored (second client)")
                tm("set-environment", "-t", "=probe", "-u", "HEIM_AUTOCOPY")
                self.assertFalse(drain(3), "disabled-session history copied on re-enable")
                self.assertFalse(second_updates, "disabled-session history copied on re-enable (second client)")
                os.write(master, b"printf 'AUTO_REENABLED_83\\n'\r")
                reenabled = drain(4)
                self.assertTrue(any(b"\nAUTO_REENABLED_83" in p for p in reenabled), reenabled)
                self.assertTrue(any(b"\nAUTO_REENABLED_83" in p for p in second_updates), second_updates)
                self.assertFalse(any(b"AUTO_DISABLED_55" in p for p in reenabled + second_updates),
                                 "disabled-session history included in later safe publication")
                marker = tm("show-environment", "-t", "=probe", "HEIM_AUTOCOPY_PRIVATE_HISTORY")
                self.assertEqual(marker.stdout.strip(), b"HEIM_AUTOCOPY_PRIVATE_HISTORY=1")
            finally:
                tm("kill-server")
                client.wait(timeout=5)
                second_client.wait(timeout=5)
                os.close(master)
                os.close(second_master)


if __name__ == "__main__":
    unittest.main()
