#!/usr/bin/env bash
# Open a new tmux shell that the autocopy watcher deliberately ignores.
set -euo pipefail
name="copy-off-$(date +%s)-$$"
args=(new-session -e HEIM_NO_TMUX=1 -e HEIM_AUTOCOPY=off -e HEIM_AUTOCOPY_PRIVATE_HISTORY=1 -s "$name")
if [[ -n ${TMUX:-} ]]; then
    # Reuse the running server and switch the current client instead of nesting.
    server_info=${TMUX%,*}
    pid=${server_info##*,}
    socket=${server_info%,*}
    [[ $pid =~ ^[1-9][0-9]*$ && -S $socket && -x /proc/$pid/exe ]] || {
        printf '%s\n' 'copy-off: cannot identify the current tmux server' >&2
        exit 1
    }
    tmux_cmd=("/proc/$pid/exe" -S "$socket")
    "${tmux_cmd[@]}" "${args[@]}" -d
    exec "${tmux_cmd[@]}" switch-client -t "=$name"
fi
exec tmux "${args[@]}"
