"""Install Nabu's narrowly scoped ChatGPT sender without exporting its private key.

The user loads the generated unpacked extension once in their existing Chrome
profile. Re-running this installer preserves the key and extension identity.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile


SOURCE = Path(__file__).resolve().parent
KEY_PATH = Path.home() / ".local/share/heimgewebe/home-assistant/.nabu-chatgpt-autosend.key"
EXTENSION_DIR = Path.home() / ".local/share/heimgewebe/nabu-chatgpt-autosend-extension"
MARKER = "__NABU_SEND_SECRET_HEX__"


def _private_atomic_write(destination: Path, value: str) -> None:
    if destination.is_symlink():
        raise RuntimeError("refusing symlink target " + destination.name)
    fd, temporary = tempfile.mkstemp(prefix=".nabu-send-", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install() -> dict:
    KEY_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    EXTENSION_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if EXTENSION_DIR.is_symlink() or KEY_PATH.is_symlink():
        raise RuntimeError("private Nabu sender paths must not be symlinks")
    if KEY_PATH.exists():
        key = KEY_PATH.read_text(encoding="ascii").strip()
        if KEY_PATH.stat().st_mode & 0o077:
            raise RuntimeError("sender key permissions must be owner-only")
        if re.fullmatch(r"[0-9a-f]{64}", key) is None:
            raise RuntimeError("existing sender key is invalid; not replacing it")
    else:
        key = secrets.token_hex(32)
        # Exclusive creation: no preimage or race is silently overwritten.
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(key + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    manifest = (SOURCE / "chatgpt_sender.manifest.json").read_text(encoding="utf-8")
    parsed = json.loads(manifest)
    if parsed.get("manifest_version") != 3 or parsed["content_scripts"][0]["matches"] != ["https://chatgpt.com/*"]:
        raise RuntimeError("unexpected Chrome extension host scope")
    template = (SOURCE / "chatgpt_sender.content.js.in").read_text(encoding="utf-8")
    if template.count(MARKER) != 1:
        raise RuntimeError("invalid extension template")
    content = template.replace(MARKER, key)
    background = (SOURCE / "chatgpt_sender.background.js").read_text(encoding="utf-8")
    _private_atomic_write(EXTENSION_DIR / "manifest.json", manifest)
    _private_atomic_write(EXTENSION_DIR / "background.js", background)
    _private_atomic_write(EXTENSION_DIR / "content.js", content)
    return {
        "installed": True,
        "extension_directory": str(EXTENSION_DIR),
        "key_present": True,
        "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
        "chrome_activation_required": True,
        "chatgpt_send_verified": False,
    }


if __name__ == "__main__":
    print(json.dumps(install(), ensure_ascii=False, sort_keys=True))