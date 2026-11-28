#!/usr/bin/env python3
"""Copy the last 180 lines of one tmux pane to the terminal's clipboard."""
import argparse
import os
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("pane", nargs="?", default=os.environ.get("TMUX_PANE", ""))
parser.add_argument("--socket")
parser.add_argument("--tmux-bin")
args = parser.parse_args()
p = args.pane
if not p.startswith("%") or not p[1:].isdigit():
    parser.error("specify a pane ID or invoke inside tmux")
if args.socket is None and args.tmux_bin is None:
    try:
        args.socket, pid, _ = os.environ.get("TMUX", "").rsplit(",", 2)
        if not pid.isdecimal() or int(pid) <= 0 or not args.socket:
            raise ValueError
        args.tmux_bin = f"/proc/{pid}/exe"
    except ValueError:
        parser.error("cannot identify the running tmux server")
elif not args.socket or not args.tmux_bin:
    parser.error("--socket and --tmux-bin must be provided together")
tmux = [args.tmux_bin, "-S", args.socket]

def cap(extra):
    return subprocess.run([*tmux, "capture-pane", "-p", *extra, "-S", "-180", "-t", p],
                          capture_output=True, timeout=5)

r = cap(["-a"])
if r.returncode or not r.stdout.strip():
    r = cap([])
if r.returncode or not r.stdout.strip():
    parser.exit(1, "omnicopy: pane empty/unavailable\n")
s = r.stdout.decode("utf-8", "replace").strip("\n")
data = s.encode()
if len(data) > 45000:
    s = "[last 45 KB of pane]\n" + data[-44900:].decode("utf-8", "replace")
subprocess.run([*tmux, "set-buffer", "-w", "--", s], check=True, timeout=5)
print("omnicopy: copied")
