# CI-only signed Nix cache v1

## Scope

Issue #167 evaluates cross-run reuse of the current heavy CUDA Nix derivations in
GitHub CI without changing production NixOS trust. A separate, default-deny
option can also publish the complete storage-target NixOS system closure through
the same signed **CI-only** cache. Neither mode authorizes a NixOS deployment,
production runtime cutover, boot-chain trust or physical storage changes.

## Trust domains

Production continues to be governed by
`nixos/production/trust-contract-v1.json`: only `https://cache.nixos.org/`
is a production substituter/trusted substituter, only the NixOS cache public key
is trusted, `require-sigs=true`, and `accept-flake-config=false`.

GitHub CI additionally trusts:

- cache URL: `https://commonserver.tail6dbb90.ts.net:10000/nix-cache`
- public key:
  `heim-pc-ci-cache-20260923-1:fDffoLuvBMGVo8JKRR7uY7EmJPawIsKXuB5OBswBdIo=`
- `require-sigs=true`
- `fallback=true`, so an unavailable substitute falls back to the normal local
  build instead of weakening signature verification.

No CI cache setting is added to the flake or the production NixOS trust module.

## Publisher

Publishing is performed only by
`.github/workflows/heim-pc-nix-cache-publish.yml`. It is triggered from a
successful `heim-pc-nix` `push` run whose source repository is this repository
and whose branch is `main`. The job binds GitHub environment
`ci-cache-publisher`, which is restricted to `main`.

Publication is **off by default**, including after this PR reaches `main`.
Two **independent repository-level** GitHub Actions variables delimit authority:

- `CI_NIX_CACHE_PUBLISH_ENABLED=true` admits the Main-only publisher **job**
  and its existing Ollama/llama.cpp heavy-closure publication. If unset or
  `false`, the entire job is skipped before allocating a runner or accessing
  protected publisher secrets.
- `CI_NIX_CACHE_PUBLISH_SYSTEM_CLOSURE_ENABLED=true` is a **separate**
  additional opt-in inside that job for the **complete**
  `heim-pc-storage-target` NixOS system closure. If unset or `false`, the
  job publishes **only** the existing Ollama/llama.cpp closures. Setting this
  variable alone never starts the publisher job; enabling the heavy-closure
  publisher never implicitly enables system-closure publication. Unexpected
  values are rejected instead of broadening the publication scope.

Neither variable is created or enabled by this source change. Each opt-in
requires its own separately authorized, Main-only signed publication decision;
disable it after the intended trial. Enabling either variable alone is not a
cross-run success, recovery or NixOS release claim: independent
signed-substitution, complete-closure readback and operational acceptance checks
remain mandatory.

Pull-request and fork workflows never receive the signing or upload credentials.
The publisher checks the stable GitHub workflow ID 351684660 before handling
publisher secrets. Display names are not unique, and workflow-run paths may
include a branch suffix; a deleted/recreated workflow must be reviewed and
its new ID explicitly authorized before publication can resume.
The upload SSH host and pinned host public key are configured in the existing
protected GitHub environment ci-cache-publisher as CI_CACHE_UPLOAD_SSH_HOST
and CI_CACHE_UPLOAD_SSH_HOST_KEY. They are not part of the public workflow;
both environment values must be present and the SSH host key remains pinned.
The publisher always resolves the exact Ollama and llama.cpp derivations from
the successful Main source graph and realizes their outputs. **Only** when the
second system-closure opt-in is literally `true`, it additionally evaluates
`nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel.outPath`
and builds `packages.x86_64-linux.heim-pc-storage-target-system` from that
same source. The two Nix store paths must agree exactly and match the bounded
`/nix/store/…-nixos-system-heim-pc-…` path contract; any mismatch aborts.
The publisher copies the recursively complete closures of **all selected
outputs** into a local `file://` binary cache signed with the dedicated Nix
key, then uploads only those signed cache files. Recursive copy is required
because a Nix binary-cache store must contain every referenced closure path.
The separate system opt-in never changes the CI signing key, upload principal,
append-only policy or the production NixOS trust contract.

The SSH public key installed on `commonserver` is forced through:

`rrsync -wo -no-del -no-overwrite /home/alex/heim-pc-ci-cache`

This makes the publisher write-only, prevents deletion, and refuses overwriting
existing cache objects.

Before copying or uploading any cache payload, the publisher derives the exact
Ed25519 public key from its decoded signing secret using Nix itself and compares
the full name-and-public-material value against the consumer-trusted
CI_NIX_CACHE_PUBLIC_KEY. A rotated secret with the same key name but different
key material aborts publication before any upload. Neither the secret nor the
derived public key is printed. Regression tests check both workflow ordering and
the behavior of distinct same-name signing keys under a real Nix CLI.

## Failure behavior

- Cache miss: Nix builds locally.
- Cache unavailable/substitution transfer failure: `fallback=true` permits the
  ordinary source build.
- Invalid or untrusted signature: `require-sigs=true` prevents acceptance.
  The consumer workflow runs an independent ephemeral **HTTP substituter**
  probe. It locally builds an ordinary input-addressed reference-free
  derivation, publishes it under an untrusted test key, verifies the narinfo is
  not content-addressed and carries exactly that signature, removes the output,
  disables local builds, and requires the specific Nix "not signed by any of the keys in
  trusted-public-keys" diagnostic while the output remains absent. A positive control
  then trusts only the ephemeral test public key in addition to the official
  key and must substitute the same output successfully with local builds still
  disabled. Direct `nix copy --from` is deliberately not used as
  signature-trust evidence.
- Publisher failure: the existing `heim-pc-nix` gates remain authoritative;
  no gate is removed, renamed, skipped, or made optional.

The invalid-signature probe tests Nix signature mechanics only. It is not
evidence of cross-run reuse.

After upload, this job copies the **complete remote closure of every selected
output**—including the system-closure path **only when separately enabled**—
into a new, empty temporary binary cache with local builds and fallback
disabled. Nix 2.35.2 accepts untrusted signatures during cache-to-cache copy,
so that step alone does not establish authenticity. The subsequent
`nix store verify` checks both NAR contents and signatures for every
transitive path under the exact trusted CI public key; only then may the job
compare complete closure identities and publish its success receipt.
The readback disables Nix's
negative narinfo lookup cache (TTL 0) so pre-upload misses cannot hide newly
published paths. Production trust and the separate cross-run performance
acceptance contract stay unchanged.

## Rotation and revocation

The server upload path is append-only, so key rotation uses a **new cache
namespace/path** and a new named Nix key plus upload key; existing narinfo files
are never overwritten in place. The new endpoint/public key must be reviewed in
CI before consumers switch. Revocation removes the corresponding GitHub
environment secrets and server-side authorized-key entry, then removes the old
CI endpoint/public key. Production trust is not changed during either
operation.

## Feasibility decision

Continue only when two independent runs for the same derivations show:

1. a cold or miss run completes through the unchanged gates,
2. after the successful Main-only publisher run, a manually dispatched
   independent `heim-pc-nix` run for the same Main revision substitutes the
   exact Ollama/llama.cpp outputs from the signed CI cache,
3. invalid signatures are rejected,
4. wall-clock reduction is material relative to observed run variance.

When the **system-closure** opt-in is separately authorized, the successful
publisher readback must additionally include the exact expected storage-target
system path and **every transitive path**, with valid signatures in the fresh
isolated consumer store. This is a CI-only signed-cache proof—not a complete
installed-system attestation, boot-chain verification or external restore.
Production signing, EFI/TPM/LUKS/storage changes and physical NixOS cutover
remain subject to their independent fail-closed release and recovery gates.

Otherwise remove the CI-only cache configuration and accept the original CI
latency instead of expanding infrastructure complexity.
