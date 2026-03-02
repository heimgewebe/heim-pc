import sys
import os
import re

# Pre-compile regex for performance
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Add repo root to sys.path to resolve scripts.lib
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, repo_root)

from scripts.lib.docmeta import parse_repo_index, parse_frontmatter

def main():
    manifest_path = os.path.join(repo_root, "manifest", "repo-index.yaml")
    if not os.path.exists(manifest_path):
        print(f"ERROR: Manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, "r") as f:
        manifest_data = parse_repo_index(f.read())

    errors = 0
    doc_ids = set()
    graph = {}

    # Check Zones & Docs
    for zone, zone_data in manifest_data.get("zones", {}).items():
        zone_path = os.path.join(repo_root, zone_data.get("path", ""))
        if not os.path.isdir(zone_path) and zone_data.get("path"):
            print(f"ERROR: Zone path {zone_data['path']} for zone '{zone}' does not exist.", file=sys.stderr)
            errors += 1

        for doc_name in zone_data.get("canonical_docs", []):
            full_doc_path = os.path.join(zone_path, doc_name)
            display_path = os.path.join(zone_data.get("path", ""), doc_name)

            if not os.path.exists(full_doc_path):
                print(f"ERROR: Document listed in manifest not found: {display_path}", file=sys.stderr)
                errors += 1
                continue

            with open(full_doc_path, "r") as df:
                frontmatter = parse_frontmatter(df.read())

            if not frontmatter:
                print(f"ERROR: Missing or invalid frontmatter in {display_path}", file=sys.stderr)
                errors += 1
                continue

            doc_id = frontmatter.get("id")
            if not doc_id:
                print(f"ERROR: Missing 'id' in frontmatter of {display_path}", file=sys.stderr)
                errors += 1
            else:
                if doc_id in doc_ids:
                    print(f"ERROR: Duplicate document ID found: {doc_id} in {display_path}", file=sys.stderr)
                    errors += 1
                doc_ids.add(doc_id)

            status = frontmatter.get("status")
            if status != "canonical":
                print(f"ERROR: Status must be 'canonical' for {display_path}, found '{status}'", file=sys.stderr)
                errors += 1

            role = frontmatter.get("role")
            if role not in ("norm", "reality", "action", "runbooks"):
                print(f"ERROR: Invalid role '{role}' in {display_path}", file=sys.stderr)
                errors += 1

            last_reviewed = frontmatter.get("last_reviewed")
            if not last_reviewed or not DATE_PATTERN.match(str(last_reviewed)):
                print(f"ERROR: Invalid or missing last_reviewed date (must be YYYY-MM-DD) in {display_path}", file=sys.stderr)
                errors += 1

            depends_on = frontmatter.get("depends_on", [])
            if isinstance(depends_on, str):
                depends_on = [depends_on]
            graph[doc_id] = depends_on

            verifies_with = frontmatter.get("verifies_with", [])
            if isinstance(verifies_with, str):
                verifies_with = [verifies_with]
            for script in verifies_with:
                if script and not os.path.exists(os.path.join(repo_root, script)):
                    print(f"ERROR: Verification script {script} listed in {display_path} does not exist.", file=sys.stderr)
                    errors += 1

    # Check dependencies and cycles
    def has_cycle(node, visited, stack):
        visited.add(node)
        stack.add(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                if has_cycle(neighbor, visited, stack):
                    return True
            elif neighbor in stack:
                return True
        stack.remove(node)
        return False

    visited_nodes = set()
    for doc_id, deps in graph.items():
        for dep in deps:
            if dep not in doc_ids:
                print(f"ERROR: Document '{doc_id}' depends on non-existent document ID: {dep}", file=sys.stderr)
                errors += 1

        if doc_id not in visited_nodes:
            if has_cycle(doc_id, visited_nodes, set()):
                print(f"ERROR: Cycle detected involving document '{doc_id}'", file=sys.stderr)
                errors += 1

    # Check Checks
    for check in manifest_data.get("checks", []):
        if not os.path.exists(os.path.join(repo_root, check)):
            print(f"ERROR: Check script {check} listed in manifest does not exist.", file=sys.stderr)
            errors += 1

    if errors > 0:
        print(f"\nFound {errors} errors in repo-index consistency.", file=sys.stderr)
        sys.exit(1)

    print("Repo-index consistency check passed.")

if __name__ == "__main__":
    main()
