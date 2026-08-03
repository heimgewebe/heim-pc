# FluidSynth supervisor v1

## Problem

The distribution FluidSynth 2.2.5 unit was started with `-is`. On this version, `-s` opens the command server on TCP port 9800 and binds to all interfaces. The same service used `KillMode=control-group`; on the live user manager, the cgroup signal operation returned an input/output error, so a controlled restart waited 15 seconds and ended in SIGKILL.

Live validation on 2026-08-03 established two separate facts:

- direct SIGTERM terminated the FluidSynth main process in about 0.1 seconds;
- `KillMode=process` stopped the service without timeout, but did not remove the TCP server.

User-level systemd IP firewalling and `PrivateNetwork=yes` were tested and explicitly reported as ineffective on this host. They are not part of the final design.

## Decision

`/usr/local/libexec/heim-pc-fluidsynth-supervisor` becomes the service main process. It starts exactly `/usr/bin/fluidsynth` with stdin connected to a private pipe and rejects all command forms that enable the TCP server or disable the stdin shell:

- `-s` and compact short-option forms containing `s`;
- `--server`;
- `-i` and compact short-option forms containing `i`;
- `--no-shell`.

The canonical ExecStart omits both `-s` and `-i`. No process listens on port 9800. Audio and ALSA MIDI remain owned by the child FluidSynth process.

## Stop sequence

1. systemd sends SIGTERM to the supervisor.
2. The supervisor writes `quit` to FluidSynth stdin and closes the pipe.
3. FluidSynth performs its normal cleanup and exits.
4. If it has not exited after five seconds, the supervisor sends SIGTERM directly to the child and returns a visible failure status.
5. If it still has not exited after a further three seconds, the child is killed. systemd retains its own 15-second `TimeoutStopSec` and final cgroup SIGKILL boundary.

The normal stop path is therefore graceful. Fallback use is deliberately not reported as success.

## systemd contract

- `Type=simple`
- `KillMode=mixed`: SIGTERM first reaches only the supervisor; the final timeout action still covers the complete cgroup.
- `KillSignal=SIGTERM`
- `RestartKillSignal=SIGTERM`
- `TimeoutStopSec=15s`
- `SendSIGKILL=yes`
- `FinalKillSignal=SIGKILL`

The distribution `NotifyAccess=main` value is retained but has no readiness role under `Type=simple`.

## Evidence and limits

The change preserves the existing commit-bound host installer, exact Git-blob source binding, descriptor-relative no-follow writes, transactional rollback, and effective systemd composition verification.

The contract establishes no claim that FluidSynth 2.2.5 is current. Upgrading the distribution package is a separate compatibility decision. It also does not guarantee that arbitrary future `OTHER_OPTS` are safe; server and no-shell forms are rejected at runtime before the child starts.
