#!/usr/bin/env python3
"""Copy the last 180 lines of one tmux pane to the terminal's clipboard."""
import os,subprocess,sys
p=sys.argv[1] if len(sys.argv)==2 else os.environ.get("TMUX_PANE","")
if not p.startswith("%") or not p[1:].isdigit():sys.exit("Usage: omnicopy [pane-id] (inside tmux)")
def cap(extra):
 return subprocess.run(["tmux","capture-pane","-p",*extra,"-S","-180","-t",p],capture_output=True,timeout=5)
r=cap(["-a"])
if r.returncode or not r.stdout.strip():r=cap([])
if r.returncode or not r.stdout.strip():sys.exit("omnicopy: pane empty/unavailable")
s=r.stdout.decode("utf-8","replace").strip("\n")
data=s.encode()
if len(data)>45000:s="[last 45 KB of pane]\n"+data[-44900:].decode("utf-8","replace")
subprocess.run(["tmux","set-buffer","-w","--",s],check=True,timeout=5)
print("omnicopy: copied")
