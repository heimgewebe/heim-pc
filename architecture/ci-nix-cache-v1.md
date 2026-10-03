# CI-only signed Nix cache v1

## Scope

Issue #167 evaluates cross-run reuse of the current heavy CUDA Nix derivations in
GitHub CI without changing production NixOS trust. The cache is a CI-only
optimization. It does not authorize a NixOS deployment or production runtime
cutover.

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

Pull-request and fork workflows never receive the signing or upload credentials.
The publisher resolves the exact Ollama and llama.cpp derivations from the
successful Main source graph, realizes those outputs, copies their closures
recursively into a local `file://` binary cache signed with the dedicated Nix
key, then uploads only those signed cache files. Recursive copy is required
because a Nix binary-cache store must also contain the referenced closure paths.

The SSH public key installed on `commonserver` is forced through:

`rrsync -wo -no-del -no-overwrite /home/alex/heim-pc-ci-cache`

This makes the publisher write-only, prevents deletion, and refuses overwriting
existing cache objects.

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

Otherwise remove the CI-only cache configuration and accept the original CI
latency instead of expanding infrastructure complexity.