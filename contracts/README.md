# Webmaschine Contracts

This directory contains data contracts and schemas for webmaschine state files.

## Purpose

Contracts ensure that the JSON structure of state files remains stable and predictable across:
- Different scanning tool versions
- Multiple machines
- Heimgewebe system integrations

## State File Schemas

### state/index.json

The KI-Index provides quick orientation for AI systems.

**Schema**: `webmaschine.state.index.schema.json`

**Key fields**:
- `machine`: Machine identification (name, roots, hub)
- `hotspots`: Important filesystem areas
- `repos`: Repository summary counts
- `artifacts`: Pointers to large data files
- `metadata`: Version, timestamps, notes

### state/repos.json

Repository tracking and activity metrics.

**Schema**: `webmaschine.state.repos.schema.json`

**Key fields**:
- `repositories`: Array of repository objects
- `summary`: Aggregated counts by type/zone
- `metadata`: Scan information

### state/uncertainties.json

Drift detection and uncertainty tracking.

**Schema**: `webmaschine.state.uncertainties.schema.json`

**Key fields**:
- `uncertainties`: Array of detected issues
- `summary`: Counts by category/severity
- `metadata`: Scan information

## Versioning

State files use semantic versioning in `metadata.schema_version`:
- Major version: Breaking changes to structure
- Minor version: Backward-compatible additions
- Patch version: Documentation/clarifications

Current version: **1.0**

## Validation

Schemas can be validated using standard JSON Schema validators:

```bash
# Using ajv-cli
ajv validate -s contracts/webmaschine.state.index.schema.json -d state/index.json

# Using Python jsonschema
python3 -c "import json, jsonschema; \
  schema = json.load(open('contracts/webmaschine.state.index.schema.json')); \
  data = json.load(open('state/index.json')); \
  jsonschema.validate(data, schema)"
```

## Future Work

- Add formal JSON Schema files for each state file type
- Link to canonical contracts in `heimgewebe/metarepo`
- Add contract validation to CI pipeline
- Define backward compatibility guarantees

## References

- [JSON Schema](https://json-schema.org/)
- [Semantic Versioning](https://semver.org/)
- Heimgewebe Metarepo: (TODO: add link when available)
