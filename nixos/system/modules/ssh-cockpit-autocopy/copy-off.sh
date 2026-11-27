#!/usr/bin/env bash
# Open a new tmux shell that the autocopy watcher deliberately ignores.
set -euo pipefail
name="copy-off-$(date +%s)-$$"
exec tmux new-session -e HEIM_NO_TMUX=1 -e HEIM_AUTOCOPY=off -s "$name"
