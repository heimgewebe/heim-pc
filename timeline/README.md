# Timeline README
#
# This directory contains chronological filesystem change data.
# The data is stored in JSONL (JSON Lines) format for efficient
# streaming and processing.

## Format

Each line is a JSON object representing an event:

```json
{"timestamp": "2024-12-18T15:26:00Z", "type": "file_added", "path": "/home/alex/repos/new-project/README.md", "size": 1234}
{"timestamp": "2024-12-18T15:27:00Z", "type": "file_modified", "path": "/home/alex/vault-gewebe/notes.md", "size": 5678}
{"timestamp": "2024-12-18T15:28:00Z", "type": "repo_commit", "path": "/home/alex/repos/lenskit", "commit": "abc123"}
```

## Event Types

* `file_added` - New file detected
* `file_modified` - File content or metadata changed
* `file_deleted` - File removed
* `file_moved` - File relocated
* `repo_commit` - Git repository activity
* `zone_change` - Zone configuration updated

## Usage

The timeline can be processed with standard JSONL tools:

```bash
# Count events by type
cat fs.timeline.jsonl | jq -r '.type' | sort | uniq -c

# Filter by date range
cat fs.timeline.jsonl | jq 'select(.timestamp >= "2024-12-01")'

# Find large file additions
cat fs.timeline.jsonl | jq 'select(.type == "file_added" and .size > 100000000)'
```

## Compression

Timeline files can be compressed after a certain age or size:

```bash
gzip fs.timeline.2024-11.jsonl
```

Compressed files are kept but not actively updated.
