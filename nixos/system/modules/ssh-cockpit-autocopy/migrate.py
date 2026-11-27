"""Replace only the known legacy tmux config; keep a rollback-compatible loader."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import sys

LEGACY_SHA256 = "9e7adaa29ee4a0591e06766d2733f17b05b8c61cea0a5e34d5a4aa50e610f536"
BACKUP_NAME = ".tmux.conf.before-heim-pc-managed-autocopy"
LOADER = b"""# Heim-PC: managed generation when present, preserved legacy config on rollback.
if-shell 'test -r /etc/heim-pc/tmux-autocopy.conf' 'source-file /etc/heim-pc/tmux-autocopy.conf' 'source-file ~/.tmux.conf.before-heim-pc-managed-autocopy'
"""


def known_bytes(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (FileNotFoundError, OSError):
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 8192:
            return None
        return stream.read(8193)


def migrate(home: Path) -> str:
    config = home / ".tmux.conf"
    previous = known_bytes(config)
    if previous is None or hashlib.sha256(previous).hexdigest() != LEGACY_SHA256:
        return "unchanged (missing, already migrated, or user-customized)"
    backup = home / BACKUP_NAME
    try:
        fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if known_bytes(backup) != previous:
            return "unchanged (different existing backup)"
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(previous)
            stream.flush()
            os.fsync(stream.fileno())
    fd, temp = tempfile.mkstemp(prefix=".tmux.conf.managed-", dir=home)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(LOADER)
            stream.flush()
            os.fsync(stream.fileno())
        if known_bytes(config) != previous:
            return "unchanged (configuration changed during migration)"
        os.replace(temp, config)
        return "migrated known legacy config; rollback backup retained"
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


if __name__ == "__main__":
    print(migrate(Path(sys.argv[1])))
