---
id: docmeta.schema
role: norm
status: canonical
last_reviewed: 2026-02-28
depends_on: []
verifies_with: []
---

# Documentation Meta Schema

This document defines the schema for the YAML frontmatter required in all canonical documentation within this repository.
This pattern ensures consistency, clear ownership, and machine-verifiable metadata across different documentation zones.

## Frontmatter Fields

Every canonical document must start with a YAML frontmatter block enclosed by `---`.

*   **`id`** (string): A unique identifier for the document (e.g., `model`, `security`).
*   **`role`** (string): The purpose of the document within the repository. Must be one of:
    *   `norm`: Defines how things *should* be (Architecture, Policies).
    *   `reality`: Describes how things *are* currently implemented or observed (Current State, Drift).
    *   `action`: Describes processes and actionable steps.
    *   `runbooks`: Step-by-step guides for specific tasks.
*   **`status`** (string): The current state of the document. Must be:
    *   `canonical`: The document is actively maintained and considered the source of truth.
*   **`last_reviewed`** (string, YYYY-MM-DD): The date the document was last reviewed for accuracy. Used in conjunction with `manifest/review-policy.yaml`.
*   **`depends_on`** (list of strings): The `id`s of other documents that this document relies on. If those change, this document might need review.
*   **`verifies_with`** (list of strings): Paths to scripts (relative to repo root) that programmatically verify the assertions made in the document.

## Related Components

*   **Manifest (`manifest/repo-index.yaml`)**: Acts as the single source of truth for which documents are considered canonical and which zone they belong to. Manifest uses `canonical_docs` to list documents relative to the zone path. The manifest is the single source of truth; SYSTEM_MAP is generated from it, and checks enforce invariants.
*   **Review Policy (`manifest/review-policy.yaml`)**: Configures the maximum allowed age for the `last_reviewed` date.
*   **System Map (`SYSTEM_MAP.md`)**: Automatically generated index based on the manifest and document frontmatter.
