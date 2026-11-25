# Netdata: lokale maschinenlesbare Heim-PC-Diagnose

Netdata is the existing host time-series collector. The Heim-PC dashboard
remains the authority for Git, Bureau and operator context. There is no
second metrics database or new remote listener.

## Discover and read

Resolve `monitoring.netdata` using `grabowski_host_capability_resolve`
if a more specific native typed surface is not already available. A
resolved locator is not live readiness: run the declared `doctor` operation.

After NixOS activation, the installed executable is
`/run/current-system/sw/bin/heim-pc-netdata`. Its normal operations are read-only:

```sh
heim-pc-netdata doctor
heim-pc-netdata snapshot --minutes 10
heim-pc-netdata snapshot --minutes 60
heim-pc-netdata watch --dry-run
```

All results are JSON. The doctor performs a real local native MCP CPU
metric query (not only a handshake). Snapshot includes bounded per-series
statistics, timestamps, units, raised alarms, service resource counters
and rootless Podman statistics. A partial result is not healthy by
definition. Missing, empty or stale core host metrics also make the
snapshot partial. The selected time series are not the entire Netdata catalog.
For deeper historical analysis use the native MCP endpoint
`http://127.0.0.1:19999/mcp` and its own list_metrics, get_metrics_details,
query_metrics, list_raised_alerts and anomaly tools. Always supply all
required query_metrics arguments from the live tool schema; group by
dimension and instance rather than averaging unrelated metrics together.

Container statistics are read with the normal account's existing
`podman ps` and `podman stats --no-stream --format json`. Expected and
observed names are compared; missing names are explicit. This is a
current snapshot, not a historical per-container series.

The native cgroup collector separately admits Alex's rootless Podman
payload cgroups and libpod scope/container leaves before Netdata 2.10.3's
general user.slice exclusion. All other stock filters remain in place.
CPU, memory, I/O and PSI are collected from the existing cgroup files;
no Podman management socket or new collector is required. Resolve the
current container ID with `podman ps --no-trunc` and use native MCP
`get_metrics_details` for `cgroup.cpu`, `cgroup.mem` or `cgroup.io` to
find the corresponding instance. If needed, correlate the ID and
`podman inspect --format '{{.State.Pid}}' <container>` with the process's
`/proc/<pid>/cgroup`. The native ID can change when a container is
recreated. Do not claim name-stable cross-recreation history. Use the
actual returned finite series, not only a chart name, as evidence.
The collector does not need permission to rename or manage rootless
containers. Recheck the pinned native filter defaults on a Netdata upgrade.

## Actionable notifications

The NixOS user timer `heim-pc-netdata-watch.timer` runs one bounded
oneshot per five minutes for alex. It uses the existing
`grabowski_alert_outbox` and installed `grabowski_ntfy_dispatch`,
with the preconfigured notification route. It has no new credentials,
destination, ingress or persistent daemon. The timer does not switch
power profiles, restart services, reset counters or repair anything.

The watcher sends an owner-decision event for a new native critical
alarm, sustained Tctl >=89 C in at least 80% of at least 24 fresh samples
from the preceding five-minute window, or an increase in a previously observed Btrfs
device-error counter. Thermal recovery requires 80% of samples below
85 C; missing readings retain an active episode. Existing Btrfs totals
are initially baselines, not new failures. A decreasing counter updates
the baseline without proving repair. A later increase to a previously
seen counter value has a new event identity. Two consecutive incomplete or unsuccessful monitor reads produce one
service-failure event per failure episode. Missing, stale or non-finite
Tctl readings and incomplete Btrfs counter sets count as failed reads,
not as healthy polls. Valid independent readings still advance their
own episodes/counters, and unavailable thermal readings retain any
active heat episode. The normal hysteresis band is not a read failure.
The JSON output includes explicit read_errors.
Generic NVMe backlog warnings remain visible in snapshots; use await
and I/O PSI to judge actual contention, not backlog alone.

The small user-owned state at
`~/.local/state/heim-pc/netdata-watch/state.json` records active episodes,
counter baselines and pending events. An event is persisted before
publication; repeated publication uses the existing outbox idempotency
contract. The outbox, not this state, owns notification acknowledgement. A failed
publication keeps the original event identity for retry. Each poll
publishes at most 64 pending events; larger backlogs are drained over
successive polls rather than rejected. The JSON status publication_pending
reports remaining events and any publication error.
`watch --dry-run` previews without modifying state or sending anything.
The normal `watch` operation may enqueue and dispatch notifications and
is not a read-only capability. Missing ntfy topic configuration and a full
100-receipt shared outbox window are explicitly reported as delivery pending.
The timer does not drain a saturated shared outbox: recover the existing
notification route and triage historical receipts before enabling delivery. The current Grabowski renderer presents
owner-decision events compactly; the precise condition and correlation
are retained in the canonical outbox. Inspect the corresponding
outbox receipt for context.

## Persistence and acceptance

The executable and timer are derived from the same production NixOS
module as Netdata. Merge and NixOS activation are separate effects.
Use the existing operator-entry installer after merging, review its plan
and check the installed projection against canonical Git. Do not copy
a feature-branch manifest to the active contract.

Acceptance:

- Native MCP doctor returns finite CPU metrics.
- Snapshot returns recent time-series data and compares all running
  Podman names. Missing metrics and partial results stay explicit.
- Query finite native cgroup CPU and memory series for the actual running
  container IDs after activation. A readable cgroup or a matching filter
  alone does not prove historical coverage.
- Watch preview and controlled fixture checks cover initial cumulative
  Btrfs counts, a new counter increase, sustained heat, thermal
  hysteresis, a clear and recurrence, and temporary API unavailability.
- Verify the actual user timer and one existing-route ntfy acknowledgement;
  enqueue or HTTP acknowledgement alone does not prove phone display.
- Record Netdata unit CPU time and cgroup memory, oldest/newest timestamps
  and tier retention metrics. The 14-day targets and initial 4 GiB/1 GiB
  tier sizes are soft limits, not a guarantee: the size limit can remove
  history earlier. These sizes allow headroom for the measured host
  growth and new container series. Check growth, effective retention,
  memory and CPU overhead after representative use; adjust only if needed.
  A recently started daemon cannot establish 14 days of real history.
  Do not interpret an unreadable cache directory as zero DB size.

No other monitoring stack is required.
