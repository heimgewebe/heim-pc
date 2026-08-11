# Data Contracts: Canonical Source

**This repository is a consumer, not an owner, of data contracts.**

All JSON schemas that define the structure of `state/` and `config/` files are
centrally managed in `heimgewebe/metarepo`. Local copies are intentionally not
authoritative.

## Resolver contract

`python3 scripts/validate_contracts.py` accepts exactly one explicit Metarepo
source. Ambient environment variables and sibling directories are never source
authority.

### Git checkout

Use an explicit repository root. Pin the expected commit whenever a caller
already has an immutable revision, as CI does:

```bash
python3 scripts/validate_contracts.py \
  --metarepo-source ../_metarepo \
  --metarepo-expected-commit 0123456789abcdef0123456789abcdef01234567
```

The validator verifies that `remote.origin.url` identifies
`heimgewebe/metarepo`, records the exact 40-hex `HEAD`, and fails closed if the
checkout is dirty. A deliberately dirty local developer checkout can be used
only with the explicit `--allow-dirty-metarepo-for-development` flag. That flag
is never inferred from environment or checkout layout.

### Detached archive or approved offline cache

A non-Git source is accepted only through `--metarepo-manifest`. The manifest
binds the source to repository identity, commit, source kind, a relative content
root, and SHA-256 for every schema the consumer may use:

```json
{
  "schema_version": 1,
  "repository": "heimgewebe/metarepo",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "source_kind": "detached_archive",
  "source_root": "content",
  "schemas": {
    "contracts/heim-pc/config/zones.schema.json": "<64-hex-sha256>"
  }
}
```

`source_kind` is either `detached_archive` or `offline_cache`. `source_root`
must remain below the manifest directory. A consumed schema that is absent from
the manifest, has a mismatching hash, escapes the source root, or changes during
validation is rejected.

Create a manifest-bound archive from an explicit, pinned Metarepo checkout with
the canonical producer shipped by Metarepo:

```bash
python3 ../_metarepo/scripts/contracts/emit_source_manifest.py \
  --source ../_metarepo \
  --out-dir /path/to/contract-source \
  --consumer heim-pc \
  --source-kind detached_archive \
  --expected-commit 0123456789abcdef0123456789abcdef01234567
```

The producer binds committed Git-object bytes and the complete local schema
resource closure. `--verify` re-proves an existing archive against the same
explicit Metarepo source without rewriting it.

Consume the resulting archive through the same heim-pc validator:

```bash
python3 scripts/validate_contracts.py \
  --metarepo-manifest /path/to/contract-source/metarepo-contract-source.v1.json \
  --metarepo-expected-commit 0123456789abcdef0123456789abcdef01234567
```

## Deterministic validation receipt

Every successful run emits one canonical JSON receipt. `--receipt PATH` writes
the same payload to a file. The receipt contains:

- contract repository identity, source kind, commit, and dirty state;
- manifest SHA-256 for archive/cache sources;
- every consumed schema path and SHA-256;
- the heim-pc consumer `HEAD` and dirty state;
- every validated consumer artifact path and SHA-256.

No timestamp or machine-local source path is part of the receipt, so identical
inputs produce identical provenance payloads. Before success is reported, Git
sources are rechecked for `HEAD`, dirty-projection, and consumed-schema
movement; manifest sources are rehashed against the bound schema bytes.

## CI

`.github/workflows/heim-pc-validate.yml` checks out one exact Metarepo commit as
`_metarepo` and validates both supported resolver routes against that same
revision:

1. the explicit Git checkout via `--metarepo-source`;
2. a freshly emitted and verified detached archive via `--metarepo-manifest`.

The checkout layout alone has no authority. Both routes remain bound to
`METAREPO_REF`, so a pin movement is an explicit reviewed change.

Local schemas must not be added back. If the canonical Metarepo source is
missing or cannot be identity-bound, validation fails closed instead of falling
back to another repository contract.
