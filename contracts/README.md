# Data Contracts: Canonical Source

**This repository is a consumer, not an owner, of data contracts.**

All JSON schemas that define the structure of the `state/` and `config/` files are centrally managed in the `heimgewebe/metarepo` repository. This ensures a single source of truth for data interchange across the entire Heimgewebe ecosystem.

## Validation

The CI pipeline in this repository (`.github/workflows/webmaschine-validate.yml`) is configured to:
1.  Check out a fresh copy of the `heimgewebe/metarepo`.
2.  Validate all local data files against the canonical schemas found there.

Local schemas have been intentionally removed to prevent architectural drift. Do not add them back.
