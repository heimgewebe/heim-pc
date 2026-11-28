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
import subprocess
import time

TMUX_EXECUTABLE = "tmux"
LINES = 1000
BYTES = 32768
QUIET_SECONDS = 2.0
POLL_SECONDS = 0.5
SHELL_PROMPT = re.compile(
    r"^(?:\[[^]\r\n]+@[^]\r\n]+:[^]\r\n]+\]|"
    r"[^ @:\r\n]+@[^ :\r\n]+:[^\r\n]+?|"
    r"(?:bash|sh|zsh|fish)(?:-\d+(?:\.\d+)*)?)"
    r"[$#](?:\s|$)"
)
SHELLS = {"bash", "sh", "dash", "zsh", "fish"}

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
    encoded = text.encode("utf-8")
    if len(encoded) <= BYTES:
        return encoded
    prefix = b"[autocopy: last 32 KiB of pane]\n"
    clipped = encoded[-(BYTES - len(prefix)):]
    return prefix + clipped.decode("utf-8", "ignore").encode("utf-8")

def capture_rows(raw: bytes) -> list[str]:
    """Recognize the last known prompt even after output without a newline.

    Only reuse the most recent line-leading prompt, not an arbitrary
    prompt-like fragment. An earlier recognized prompt on the last row
    takes precedence over a repeated literal in its editable input.
    """
    rows = raw.decode("utf-8", "replace").splitlines()
    while rows and not rows[-1].strip():
        rows.pop()
    for row in reversed(rows[:-1]):
        previous = SHELL_PROMPT.match(row)
        if previous is None:
            continue
        token = previous.group().rstrip()
        last = rows[-1]
        offset = last.find(token)
        leading = SHELL_PROMPT.match(last)
        if offset > 0 and (leading is None or leading.end() > offset):
            inline = SHELL_PROMPT.match(last[offset:])
            if inline and inline.group().rstrip() == token:
                rows[-1:] = [last[:offset], last[offset:]]
        break
    return rows


def output_marker(raw: bytes, current_command: str) -> bytes | None:
    """Content identity for actual output, invariant under editing at a shell prompt.

    A tmux pane contains readline's echo of keystrokes. Copying on pane
    changes alone would therefore overwrite the clipboard while typing.
    Require a non-prompt line after a shell command, or an earlier completed
    command's output between consecutive prompts. Exclude the active prompt
    line from the marker, so editing that line cannot retrigger a copy.
    """
    rows = capture_rows(raw)
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
            # Readline may redraw an inline prompt over preceding output
            # (even erasing the prompt itself). With the shell in foreground,
            # do not treat an unbounded tail as a new completed result.
            if current_command in SHELLS:
                return None
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
                # A completed shell command is a publication event. Redraw
                # of its old result, including a subsequent command whose
                # prompt was erased, is not a new recognized producer.
                producer = "\n".join(rows[:start + 1]).encode()
                return hashlib.sha256(b"shell-result\0" + producer).digest()
        return None
    # Terminal apps with no detectable shell prompt retain their prior
    # behavior; for unknown shell prompts avoid auto-copying typed input.
    return None if current_command in SHELLS else hashlib.sha256(raw).digest()


def copy_payload(raw: bytes, current_command: str) -> bytes:
    """Copy visible output without content classification; skip editable prompts."""
    rows = capture_rows(raw) if current_command in SHELLS else []
    if current_command in SHELLS:
        active = SHELL_PROMPT.match(rows[-1]) if rows else None
        if not active or rows[-1][active.end():].strip():
            return b""
    return payload(raw)


def already_published(marker: bytes | None, last_published: bytes | None) -> bool:
    """A transient shell edit must not cause stale pane output to be copied again."""
    return marker is None or marker == last_published

PRIVATE_HISTORY = "HEIM_AUTOCOPY_PRIVATE_HISTORY"

def session_environment(socket: str, name: str, variable: str) -> tuple[bool, str]:
    result = tmux(socket, "show-environment", "-t", "=" + name, variable)
    if result is None:
        return False, ""
    if result.returncode == 0:
        value = result.stdout.decode("utf-8", "replace").rstrip("\n")
        if value == "-" + variable:
            return True, ""
        if value.startswith(variable + "="):
            return True, value[len(variable) + 1:]
    elif result.stderr.strip() == ("unknown variable: " + variable).encode():
        return True, ""
    return False, ""

def active_panes(socket: str) -> tuple[dict[str, tuple[set[str], str, bool]], bool] | None:
    res = tmux(socket, "list-clients", "-F", "#{client_session}\t#{client_tty}")
    if res is None or res.returncode:
        return None
    panes: dict[str, tuple[set[str], str, bool]] = {}
    clients: dict[str, set[str]] = {}
    for line in res.stdout.decode("utf-8", "replace").splitlines():
        if "\t" not in line:
            continue
        name, tty = line.split("\t", 1)
        if name and re.fullmatch(r"/dev/pts/[0-9]+", tty):
            clients.setdefault(name, set()).add(tty)
    for name, ttys in clients.items():
        known, disabled = session_environment(socket, name, "HEIM_AUTOCOPY")
        if not known:
            continue
        marked, private = session_environment(socket, name, PRIVATE_HISTORY)
        if not marked:
            continue
        if disabled == "off":
            # Remember the privacy interval on the tmux server, not just in
            # this watcher process. copy-off sets the marker at creation too.
            if private != "1":
                tmux(socket, "set-environment", "-t", "=" + name, PRIVATE_HISTORY, "1")
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
                prior = panes.get(pane)
                if prior is None:
                    panes[pane] = (set(ttys), current_command, private == "1")
                else:
                    panes[pane] = (prior[0] | ttys, current_command, prior[2] or private == "1")
    return panes, bool(clients)

def capture(socket: str, pane: str) -> bytes | None:
    res = tmux(socket, "capture-pane", "-a", "-J", "-p", "-S", f"-{LINES}", "-t", pane)
    if res is None or res.returncode or not res.stdout.strip():
        res = tmux(socket, "capture-pane", "-J", "-p", "-S", f"-{LINES}", "-t", pane)
    return None if res is None or res.returncode else res.stdout

def publish_clipboard(socket: str, targets: set[str], data: bytes) -> bool:
    """Let tmux serialize OSC52 with its terminal output; never write a PTY."""
    accepted = []
    for tty in sorted(targets):
        if re.fullmatch(r"/dev/pts/[0-9]+", tty):
            result = tmux(socket, "load-buffer", "-w", "-t", tty, "-", content=data)
            accepted.append(result is not None and result.returncode == 0)
    return any(accepted)


def capture_text(raw: bytes) -> str:
    rows = raw.decode("utf-8", "replace").splitlines()
    while rows and not rows[-1].strip():
        rows.pop()
    return "\n".join(rows)

def private_anchor(raw: bytes, current_command: str) -> tuple[str, str] | None:
    # A private session may only publish new results after an observed clean
    # shell prompt. No claim is made about arbitrary terminal redraws.
    if current_command not in SHELLS:
        return None
    rows = capture_rows(raw)
    if not rows:
        return None
    active = SHELL_PROMPT.match(rows[-1])
    if not active or rows[-1][active.end():].strip():
        return None
    text, prompt = capture_text(raw), rows[-1]
    return (text, prompt) if text.endswith(prompt) else None

def private_payload(raw: bytes, current_command: str, anchor: tuple[str, str] | None) -> bytes:
    if current_command not in SHELLS or anchor is None:
        return b""
    text, (prefix, prompt) = capture_text(raw), anchor
    # Never infer a history boundary from similarity or a newly seen prompt.
    # If the capture scrolled or was redrawn, skip this publication and
    # establish a new boundary once a clean prompt is observed.
    if not text.startswith(prefix) or text == prefix:
        return b""
    scope = (prompt + text[len(prefix):]).encode("utf-8")
    if output_marker(scope, current_command) is None:
        return b""
    return copy_payload(scope, current_command)

def watch(socket: str) -> int:
    runtime = Path(socket).parent
    lock_name = "heim-cockpit-autocopy-" + hashlib.sha256(socket.encode()).hexdigest()[:12] + ".lock"
    try:
        fd = os.open(runtime / lock_name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        # A reattach can race the previous watcher's final empty-client
        # poll. Give the exiting process a bounded chance to drop its lock.
        lock_deadline = time.monotonic() + 1.5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= lock_deadline:
                    os.close(fd)
                    return 0
                time.sleep(0.1)
    except OSError:
        return 1
    observed: dict[str, tuple[bytes, float, bool, bytes | None]] = {}
    published: dict[str, bytes] = {}
    private_anchors: dict[str, tuple[str, str] | None] = {}
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
            private = pane_ids[pane][2]
            prev = observed.get(pane)
            if private and pane not in private_anchors:
                private_anchors[pane] = private_anchor(raw, pane_ids[pane][1])
                prev = None
            elif not private:
                private_anchors.pop(pane, None)
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
                data = (private_payload(raw, pane_ids[pane][1], private_anchors.get(pane))
                        if private else copy_payload(raw, pane_ids[pane][1]))
                if data:
                    current = active_panes(socket)
                    attached = current[0].get(pane) if current is not None else None
                    if attached and attached[2] == private:
                        targets = pane_ids[pane][0].intersection(attached[0])
                        publish_clipboard(socket, targets, data)
                # One attempt per output event. A disconnected/unsupported
                # client must not cause unbounded buffer creation or retries.
                observed[pane] = (digest, prev[1], True, marker)
                published[pane] = marker
                if private:
                    private_anchors[pane] = private_anchor(raw, pane_ids[pane][1])
        for pane in list(observed):
            if pane not in pane_ids:
                del observed[pane]
                published.pop(pane, None)
                private_anchors.pop(pane, None)
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
        fixture = real_prompt + b"printf 'example=value'\nexample=value\n"
        next_result = real_prompt + b"printf OK\nOK\n"
        assert copy_payload(fixture + next_result + real_prompt, "bash") == payload(fixture + next_result + real_prompt)
        assert copy_payload(fixture + real_prompt + b"unsubmitted", "bash") == b""

        assert payload(b"normal\n" * 10000).startswith(b"[autocopy:")
        assert len(payload(b"normal\n" * 10000)) <= BYTES
        return 0
    return watch(args.socket)

if __name__ == "__main__":
    raise SystemExit(main())
