# Storage hygiene v2

## Purpose

Storage hygiene v2 converts the emergency cleanup performed on 2026-08-02 into commit-bound, testable and rollback-aware repository policy. It treats large build outputs as regenerable data while preserving source, active work, leases, processes, named Docker volumes and evidence artifacts.

The implementation is bound to the live evidence file:

- path: `/home/alex/.local/state/heim-pc/storage-hygiene/1785660701-final-evidence.json`
- SHA-256: `9a83ae06ab2cdb0b97e5e45987580133eae30cb2d1dbd520ff1398e359b1be95`
- observed root use: 29.54 percent
- net additional free space: 576,718,004,224 bytes

The evidence describes one observed host state. It does not prove future timer success or authorize deletion outside the declared policies.

## Decision

The primary objective is bounded local storage, not permanently warm build caches. Cold rebuilds and renewed image downloads are accepted when an artifact is old, inactive and reproducible. Source files and active coordination remain authoritative protection boundaries.

An alternative would be a shared remote compiler cache. That can reduce cold-build latency, but it adds another service, availability dependency and cache-integrity boundary. It is not part of this change.

## Budgets

### Rust worktree targets

`config/worktree-target-policy.v1.json` applies an aggregate warning threshold of 32 GiB and a hard threshold of 64 GiB. Warning cleanup requires three days of age; hard-pressure cleanup requires twelve hours. One run may select at most 16 targets and 128 GiB.

A dirty or lifecycle-classified source checkout does not by itself protect its `target/` directory, because that directory is reproducible build output. Main worktrees, missing or prunable worktrees, active task/lease/process coordination, incomplete process observation, recent files and unsafe tree structure still block cleanup.

### Managed builds

`config/managed-build.v1.json` keeps the managed Cargo cache near 30 GiB and treats 40 GiB as the upper bound. Candidates must be at least 24 hours old, and a run may remove at most 64 GiB across 16 identities.

The existing `managed_cargo_maintenance.py` and `managed_cargo_gc.py` remain the sole Cargo lifecycle authority. They require complete Grabowski task evidence, local usage provenance, process observation, pins, immutable tree fingerprints and exclusive per-identity lifecycle locks. Unclassified, active, changed, pinned or evidence-incomplete identities remain protected. No second managed-build garbage collector is introduced.

### Docker

`config/docker-storage-hygiene.v1.json` authorizes only age-filtered cleanup of stopped containers, unused images, builder cache and unused networks after seven days. Volume cleanup is not an available operation. Both policy and runtime plan fail if a volume command enters the operation set. Named volumes are preserved.

### Host logs

The commit-bound host installer owns the canonical journald and rsyslog retention files. Journald is limited to 512 MiB persistent and 256 MiB runtime storage, preserves 20 GiB free space and retains at most seven days. Rsyslog files rotate when they reach 100 MiB, retain three compressed rotations and are checked hourly.

## Pressure response

`config/storage-pressure.v1.json` triggers maintenance at any of these conditions:

- root filesystem use at or above 55 percent;
- available root filesystem space at or below 800 GiB;
- growth at or above 10 GiB per hour.

The pressure watcher requests only the declared managed-Cargo, worktree-target and Docker services. Each service performs its own independent safety checks. A pressure signal is not deletion authority by itself.

## Deployment

Each user-level owner retains one commit-bound installer. Managed Cargo uses `install_managed_cargo_maintenance.py`; Docker uses `install_docker_storage_hygiene.py`; worktree targets and storage pressure retain their existing installers. Each release path includes the exact commit SHA and produces a hash-bound receipt.

Root-owned log policy is installed through `scripts/install_host_health_remediation.py`, which verifies exact known transitional preimages before removing them. Root activation remains a separate explicit step.

## Rollback

Repository rollback uses the parent commit and the same commit-bound installers. User units can be reinstalled from the prior release identity without deleting state receipts. Root policy rollback uses the host-remediation transaction receipt and preserved preimages.

Cleanup effects are not generally reversible because the removed data is regenerable. Recovery consists of rebuilding Rust artifacts or downloading Docker layers again. Named Docker volumes and source repositories are outside the cleanup effect.

## Verification requirements

A release is acceptable only when:

1. focused GC, policy, installer and migration tests pass;
2. Docker plans and receipts contain no volume operation;
3. systemd units verify without target-specific diagnostics;
4. the full repository suite and contract validators pass;
5. deployment receipts bind the exact merged commit;
6. live post-readback shows successful services and active timers.
