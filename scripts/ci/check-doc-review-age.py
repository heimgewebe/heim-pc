import sys
import os
import re
from datetime import datetime

REVIEW_POLICY_FIELD_PATTERN = re.compile(r"^([a-zA-Z0-9_]+):\s*(.*)$")

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, repo_root)

from scripts.lib.docmeta import parse_repo_index, parse_frontmatter

def load_review_policy(policy_path):
    policy = {"default_review_cycle_days": 90, "mode": "warn"}
    warnings = 0
    if not os.path.exists(policy_path):
        print(f"WARN: Policy not found at {policy_path}, using defaults.", file=sys.stderr)
        return policy, warnings

    with open(policy_path, "r", encoding="utf-8", errors="strict") as f:
        for line in f:
            if not line.strip() or line.strip().startswith("#"):
                continue
            match = REVIEW_POLICY_FIELD_PATTERN.match(line.strip())
            if match:
                key = match.group(1)
                val = match.group(2).strip()
                val_norm = val.strip().strip('"').strip("'")
                if key == "default_review_cycle_days":
                    try:
                        policy[key] = int(val_norm)
                    except ValueError:
                        print(f"WARN: Invalid default_review_cycle_days '{val}', falling back to 90.", file=sys.stderr)
                        warnings += 1
                        policy[key] = 90
                elif key == "mode":
                    mode_norm = val_norm.lower()
                    if mode_norm in ("warn", "fail"):
                        policy[key] = mode_norm
                    else:
                        print(f"WARN: Invalid mode '{val}', falling back to 'warn'.", file=sys.stderr)
                        warnings += 1
                        policy[key] = "warn"
                else:
                    print(f"WARN: Unknown key in review-policy.yaml: '{key}'", file=sys.stderr)
                    warnings += 1
    return policy, warnings

def main():
    policy_path = os.environ.get("REVIEW_POLICY_PATH", os.path.join(repo_root, "manifest", "review-policy.yaml"))
    policy, policy_warnings = load_review_policy(policy_path)
    max_days = policy["default_review_cycle_days"]
    mode = policy["mode"]

    print(f"Policy parsed with {policy_warnings} warnings. Max review age: {max_days} days. Mode: {mode}.")

    manifest_path = os.path.join(repo_root, "manifest", "repo-index.yaml")
    if not os.path.exists(manifest_path):
        print(f"ERROR: Manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8", errors="strict") as f:
        manifest_data = parse_repo_index(f.read())

    warnings = policy_warnings
    errors = 0
    now = datetime.now()

    for zone, zone_data in manifest_data.get("zones", {}).items():
        zone_path = zone_data.get("path", "")
        for doc_name in zone_data.get("canonical_docs", []):
            full_doc_path = os.path.join(repo_root, zone_path, doc_name)
            display_path = os.path.join(zone_path, doc_name)

            if not os.path.exists(full_doc_path):
                continue

            with open(full_doc_path, "r", encoding="utf-8", errors="strict") as df:
                frontmatter = parse_frontmatter(df.read())

            last_reviewed_str = frontmatter.get("last_reviewed")
            if not last_reviewed_str:
                msg = f"Missing 'last_reviewed' in {display_path}"
                print(f"WARN: {msg}", file=sys.stderr)
                warnings += 1
                continue

            try:
                last_reviewed = datetime.strptime(str(last_reviewed_str), "%Y-%m-%d")
                age_days = (now - last_reviewed).days
                if age_days > max_days:
                    msg = f"Document {display_path} review age ({age_days} days) exceeds policy ({max_days} days)."
                    if mode == "fail":
                        print(f"ERROR: {msg}", file=sys.stderr)
                        errors += 1
                    else:
                        print(f"WARN: {msg}", file=sys.stderr)
                        warnings += 1
            except ValueError:
                msg = f"Invalid 'last_reviewed' format in {display_path}. Expected YYYY-MM-DD, got '{last_reviewed_str}'"
                print(f"WARN: {msg}", file=sys.stderr)
                warnings += 1

    if mode == "fail" and errors > 0:
        print(f"\nFailed: {errors} review age violations found.", file=sys.stderr)
        sys.exit(1)

    print(f"\nReview Age Check complete. {warnings} warnings, {errors} errors.")

if __name__ == "__main__":
    main()
