#!/run/current-system/sw/bin/python3
"""One-shot Chrome native messaging host for Nabu's content-free send receipts."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import time

HOST_NAME = "net.heimgewebe.nabu_receipt"
RECEIPT_PATH = Path.home() / ".local/share/heimgewebe/home-assistant/.nabu-chatgpt-send-receipts.json"
MAX_BYTES = 32768
MAX_RECEIPTS = 64
CONFIRMED = {"message_sent", "message_verified"}
STAGES = CONFIRMED | {
    "click_attempted", "send_unconfirmed", "already_present", "claim_unconfirmed",
    "claim_denied", "composer_changed", "expired", "verification_not_found",
    "verification_login_required", "verification_text_mismatch",
    "verification_no_user_messages", "timeout_login_required",
    "timeout_account_unconfirmed", "timeout_composer_missing",
    "timeout_composer_mismatch", "timeout_send_button_missing",
    "timeout_send_button_unavailable",
}


def valid_nonce(value):
    return isinstance(value, str) and re.fullmatch("[a-f0-9]{24}", value) is not None


def recent_receipts(path, now):
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return {}
    if len(raw) > MAX_BYTES:
        raise ValueError("receipt store exceeds bound")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("invalid receipt store")
    return {nonce: {"stage": value["stage"], "at": value["at"]}
            for nonce, value in data.items()
            if valid_nonce(nonce) and isinstance(value, dict)
            and isinstance(value.get("stage"), str) and value["stage"] in STAGES
            and type(value.get("at")) is int and now - 3600 <= value["at"] <= now + 15}


def record_receipt(path, message, *, now=None):
    """Merge only a fixed stage and opaque nonce; never accept text, paths or commands."""
    if (not isinstance(message, dict) or set(message) != {"nonce", "stage"}
            or not valid_nonce(message["nonce"]) or not isinstance(message["stage"], str)
            or message["stage"] not in STAGES):
        raise ValueError("invalid Nabu receipt")
    now = int(time.time()) if now is None else now
    path = Path(path)
    if path.is_symlink():
        raise ValueError("receipt file is a symlink")
    nonce, stage = message["nonce"], message["stage"]
    lock_fd = os.open(path.with_name(path.name + ".lock"),
                      os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "wb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old = recent_receipts(path, now)
        before = old.get(nonce, {}).get("stage")
        # An old or duplicate browser event must never erase a proven send.
        if before in CONFIRMED:
            return {"recorded": True}
        if before in ("click_attempted", "send_unconfirmed") and stage in (
                "already_present", "claim_denied", "claim_unconfirmed", "expired",
                "composer_changed"):
            return {"recorded": True}
        ordered = sorted(((key, value) for key, value in old.items() if key != nonce),
                         key=lambda item: item[1]["at"], reverse=True)
        records = dict(ordered[:MAX_RECEIPTS - 1])
        records[nonce] = {"stage": stage, "at": now}
        fd, tmp = tempfile.mkstemp(prefix=".nabu-receipt-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(records, stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return {"recorded": True}


def serve(source, destination, path):
    """Chrome sends one length-prefixed JSON frame to sendNativeMessage."""
    header = source.read(4)
    if len(header) != 4:
        return 2
    size, = struct.unpack("=I", header)
    if not 0 < size <= 1024:
        return 2
    payload = source.read(size)
    if len(payload) != size:
        return 2
    try:
        result = record_receipt(path, json.loads(payload))
    except (OSError, ValueError, UnicodeError):
        result = {"recorded": False}
    response = json.dumps(result, separators=(",", ":")).encode("ascii")
    destination.write(struct.pack("=I", len(response)) + response)
    destination.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve(sys.stdin.buffer, sys.stdout.buffer, RECEIPT_PATH))
