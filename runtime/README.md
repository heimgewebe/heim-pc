---
id: runtime.readme
role: reality
status: canonical
last_reviewed: 2026-09-12
depends_on: []
verifies_with: []
---

# Runtime Zone

This directory contains observational knowledge and reality outputs (e.g. current state, drift observations, logs, and generated artifacts that reflect the current state of the system).

Documents in this zone should follow the canonical schema with the `role: reality`.

## Program inventory boundary

`program-inventory-summary.md` and `program-inventory.v1.json` are reviewable point-in-time observations of the program surface. Their embedded `observed_at` timestamp defines their authority; they do not establish present runtime after that timestamp. Large raw CSV/TXT inventories stay local under `~/.local/share/heim-utilities/program-inventory/` and are not committed.
