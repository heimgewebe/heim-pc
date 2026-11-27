#!/usr/bin/env python3
"""Auto-copy active tmux pane after two seconds quiet; relay via OSC52.

Only panes visible to attached clients are observed. HEIM_AUTOCOPY=off
disables copying for a session. Each copy is capped at 1000 lines/32 KiB.
"""
from __future__ import annotations
import argparse
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

TMUX_EXECUTABLE = "tmux"
LINES = 1000
BYTES = 32768
QUIET_SECONDS = 2.0
POLL_SECONDS = 0.5
SHELL_PROMPT = re.compile(
    r"^(?:\[[^]\r\n]+@[^]\r\n]+:[^]\r\n]+\]|"
    r"[^ @:\r\n]+@[^ :\r\n]+:[^\r\n]+|"
    r"(?:bash|sh|zsh|fish)(?:-\d+(?:\.\d+)*)?)"
    r"[$#](?:\s|$)"
)
SHELLS = {"bash", "sh", "dash", "zsh", "fish"}

SENSITIVE = re.compile(
    r"-----BEGIN (?:OPENSSH |RSA |EC |DSA |PGP )?PRIVATE KEY-----"
    r"|\b(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
SENSITIVE_COMMAND = re.compile(
    r"(?:\b(?:passwd|ssh-add)\b|gpg\s+--export-secret-keys|"
    r"(?:cat|less|head|tail)\s+[^\n]*(?:\.ssh/id_|/run/secrets/))",
    re.IGNORECASE,
)

def tmux(socket: str, *args: str, content: bytes | None = None):
    try:
        return subprocess.run(
            [TMUX_EXECUTABLE, "-S", socket, *args],
            input=content, capture_output=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

def payload(raw: bytes) -> bytes:
    text = raw.decode("utf-8", "replace")
    text = "".join(
        ch for ch in text if ch in "\n\t" or (ord(ch) >= 32 and ord(ch) != 127)
    ).rstrip("\n")
    if not text.strip():
        return b""
    if SENSITIVE.search(text) or SENSITIVE_COMMAND.search("\n".join(text.splitlines()[-20:])):
        return b""
    encoded = text.encode("utf-8")
    if len(encoded) <= BYTES:
        return encoded
    prefix = b"[autocopy: last 32 KiB of pane]\n"
    clipped = encoded[-(BYTES - len(prefix)):]
    return prefix + clipped.decode("utf-8", "ignore").encode("utf-8")

def output_marker(raw: bytes, current_command: str) -> bytes | None:
    """Content identity for actual output, invariant under editing at a shell prompt.

    A tmux pane contains readline's echo of keystrokes. Copying on pane
    changes alone would therefore overwrite the clipboard while typing.
    Require a non-prompt line after a shell command, or an earlier completed
    command's output between consecutive prompts. Exclude the active prompt
    line from the marker, so editing that line cannot retrigger a copy.
    """
    rows = raw.decode("utf-8", "replace").splitlines()
    while rows and not rows[-1].strip():
        rows.pop()
    prompt_positions = []
    for i, row in enumerate(rows):
        match = SHELL_PROMPT.match(row)
        if match:
            prompt_positions.append((i, match))
    if prompt_positions:
        end, match = prompt_positions[-1]
        tail = [
            line for line in rows[end + 1:]
            if line.strip() and not line.lstrip().startswith(("> ", "... "))
        ]
        if tail:
            return hashlib.sha256("\n".join(rows[:end] + tail).encode()).digest()
        # A command line is being edited but has not produced output.
        if rows[end][match.end():].strip():
            return None
        if len(prompt_positions) >= 2:
            start = prompt_positions[-2][0]
            between = [
                line for line in rows[start + 1:end]
                if line.strip() and not line.lstrip().startswith(("> ", "... "))
            ]
            if between:
                return hashlib.sha256("\n".join(rows[:end]).encode()).digest()
        return None
    # Terminal apps with no detectable shell prompt retain their prior
    # behavior; for unknown shell prompts avoid auto-copying typed input.
    return None if current_command in SHELLS else hashlib.sha256(raw).digest()


def copy_payload(raw: bytes, current_command: str) -> bytes:
    """Keep normal pane copying; recover only a safe current shell result."""
    data = payload(raw)
    if data or current_command not in SHELLS:
        return data
    rows = raw.decode("utf-8", "replace").splitlines()
    while rows and not rows[-1].strip():
        rows.pop()
    prompts = [(i, SHELL_PROMPT.match(row)) for i, row in enumerate(rows)
               if SHELL_PROMPT.match(row)]
    if not prompts:
        return b""
    end, match = prompts[-1]
    if end < len(rows) - 1:
        block = rows[end:]
    elif not rows[end][match.end():].strip() and len(prompts) >= 2:
        block = rows[prompts[-2][0]:end]
    else:
        return b""
    if len(block) < 2 or not any(line.strip() for line in block[1:]):
        return b""
    candidate = "\n".join(block)
    if SENSITIVE_COMMAND.search(candidate):
        return b""
    return payload(candidate.encode("utf-8"))


def already_published(marker: bytes | None, last_published: bytes | None) -> bool:
    """A transient shell edit must not cause stale pane output to be copied again."""
    return marker is None or marker == last_published

def active_panes(socket: str) -> tuple[dict[str, tuple[set[str], str]], bool] | None:
    res = tmux(socket, "list-clients", "-F", "#{client_session}\t#{client_tty}")
    if res is None or res.returncode:
        return None
    panes: dict[str, tuple[set[str], str]] = {}
    clients: dict[str, set[str]] = {}
    for line in res.stdout.decode("utf-8", "replace").splitlines():
        if "\t" not in line:
            continue
        name, tty = line.split("\t", 1)
        if name and re.fullmatch(r"/dev/pts/[0-9]+", tty):
            clients.setdefault(name, set()).add(tty)
    for name, ttys in clients.items():
        disabled = tmux(socket, "show-environment", "-t", "=" + name, "HEIM_AUTOCOPY")
        if disabled is not None and disabled.returncode == 0:
            if disabled.stdout.strip() == b"HEIM_AUTOCOPY=off":
                continue
        listing = tmux(socket, "list-panes", "-t", "=" + name, "-F", "#{pane_active} #{pane_id} #{pane_current_command}")
        if listing is None or listing.returncode:
            continue
        for line in listing.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(" ", 2)
            if len(parts) != 3:
                continue
            active, pane, current_command = parts
            if active == "1" and re.fullmatch(r"%[0-9]+", pane):
                if pane not in panes:
                    panes[pane] = (set(), current_command)
                panes[pane][0].update(ttys)
    return panes, bool(clients)

def capture(socket: str, pane: str) -> bytes | None:
    res = tmux(socket, "capture-pane", "-a", "-J", "-p", "-S", f"-{LINES}", "-t", pane)
    if res is None or res.returncode or not res.stdout.strip():
        res = tmux(socket, "capture-pane", "-J", "-p", "-S", f"-{LINES}", "-t", pane)
    return None if res is None or res.returncode else res.stdout

def write_clipboard_tty(tty: str, data: bytes) -> bool:
    """Use explicit c selector; tmux load-buffer -w emits 52;; on this host."""
    if not re.fullmatch(r"/dev/pts/[0-9]+", tty):
        return False
    seq = b"\x1b]52;c;" + base64.b64encode(data) + b"\x07"
    fd = -1
    try:
        fd = os.open(tty, os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISCHR(info.st_mode) or info.st_uid != os.getuid():
            return False
        written = 0
        deadline = time.monotonic() + 2.0
        while written < len(seq) and time.monotonic() < deadline:
            _, writable, _ = select.select([], [fd], [], max(0, deadline - time.monotonic()))
            if writable:
                n = os.write(fd, seq[written:])
                if n <= 0:
                    return False
                written += n
        return written == len(seq)
    except (OSError, ValueError):
        return False
    finally:
        if fd >= 0:
            os.close(fd)

def watch(socket: str) -> int:
    runtime = Path(socket).parent
    lock_name = "heim-cockpit-autocopy-" + hashlib.sha256(socket.encode()).hexdigest()[:12] + ".lock"
    try:
        fd = os.open(runtime / lock_name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return 0
    except OSError:
        return 1
    observed: dict[str, tuple[bytes, float, bool, bytes | None]] = {}
    published: dict[str, bytes] = {}
    no_clients = 0
    while True:
        observation = active_panes(socket)
        if observation is None:
            return 0
        pane_ids, has_clients = observation
        if not has_clients:
            no_clients += 1
            if no_clients >= 6:
                return 0
        else:
            no_clients = 0
        now = time.monotonic()
        for pane in pane_ids:
            raw = capture(socket, pane)
            if raw is None:
                continue
            digest = hashlib.sha256(raw).digest()
            marker = output_marker(raw, pane_ids[pane][1])
            prev = observed.get(pane)
            if prev is None:
                # Opening an existing session must not overwrite the clipboard.
                observed[pane] = (digest, now, True, marker)
                if marker is not None:
                    published[pane] = marker
            elif prev[3] != marker:
                observed[pane] = (digest, now, already_published(marker, published.get(pane)), marker)
            elif prev[0] != digest:
                # Updating the editable prompt resets quiet time but is never
                # itself a reason for another copy.
                observed[pane] = (digest, now, prev[2], marker)
            elif marker is not None and not prev[2] and now - prev[1] >= QUIET_SECONDS:
                data = copy_payload(raw, pane_ids[pane][1])
                if data:
                    copied = tmux(socket, "load-buffer", "-", content=data)
                    if copied is not None and copied.returncode == 0:
                        current = active_panes(socket)
                        current_ttys = current[0] if current is not None else {}
                        attached = current_ttys.get(pane)
                        targets = pane_ids[pane][0].intersection(attached[0] if attached else set())
                        # Attempt every attached client; any(generator) short-circuits.
                        results = [write_clipboard_tty(tty, data) for tty in sorted(targets)]
                        if any(results):
                            observed[pane] = (digest, prev[1], True, marker)
                            published[pane] = marker
                else:
                    observed[pane] = (digest, prev[1], True, marker)
                    published[pane] = marker
        for pane in list(observed):
            if pane not in pane_ids:
                del observed[pane]
                published.pop(pane, None)
        time.sleep(POLL_SECONDS)

def main() -> int:
    global TMUX_EXECUTABLE
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default=f"/tmp/tmux-{os.getuid()}/default")
    parser.add_argument("--tmux-bin", default="tmux")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    TMUX_EXECUTABLE = args.tmux_bin
    if args.self_test:
        assert payload(b"hello\n") == b"hello"
        p = b"sh-5.3$ "
        assert output_marker(p + b"printf 'x'\n", "bash") is None
        assert output_marker(p + b"echo hello\nhello\n" + p, "bash") is not None
        assert output_marker(p + b"true\n" + p, "bash") is None
        sample = p + b"echo hello\nhello\n" + p
        assert output_marker(sample, "bash") is not None
        assert output_marker(sample + b"half-typed-command", "bash") is None
        real_prompt = b"[alex@heim-pc:~]$ "
        assert output_marker(real_prompt + b"unsubmitted", "bash") is None
        assert output_marker(real_prompt + b"printf 'ok\\n'\nok\n" + real_prompt, "bash") is not None
        assert b"\x1b]52;c;" + base64.b64encode(b"hello") + b"\x07" == b"\x1b]52;c;aGVsbG8=\x07"
        assert already_published(None, b"prior")
        assert already_published(b"prior", b"prior")  # typing then clearing must not re-copy
        assert not already_published(b"new output", b"prior")
        assert not already_published(b"first output", None)
        assert payload(b"password=abc123\n") == b""
        old_sensitive = real_prompt + b"echo example\npassword=synthetic-test-only\n"
        safe_result = real_prompt + b"printf OK\nOK\n"
        assert copy_payload(old_sensitive + safe_result + real_prompt, "bash") == safe_result.rstrip(b"\n")
        assert copy_payload(old_sensitive + real_prompt, "bash") == b""
        assert copy_payload(safe_result + old_sensitive + real_prompt, "bash") == b""
        assert copy_payload(old_sensitive + safe_result + real_prompt, "vim") == b""
        assert copy_payload(old_sensitive + real_prompt + b"cat ~/.ssh/id_test\nexample\n" + real_prompt, "bash") == b""
        assert copy_payload(old_sensitive + real_prompt + b"unsubmitted", "bash") == b""

        assert payload(b"normal\n" * 10000).startswith(b"[autocopy:")
        assert len(payload(b"normal\n" * 10000)) <= BYTES
        return 0
    return watch(args.socket)

if __name__ == "__main__":
    raise SystemExit(main())