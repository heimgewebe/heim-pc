import sys
import os
import re
from datetime import datetime

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, repo_root)

from scripts.lib.docmeta import parse_repo_index, parse_frontmatter

def load_review_policy(policy_path):
    policy = {"default_review_cycle_days": 90, "mode": "warn"}
    if not os.path.exists(policy_path):
        return policy

    with open(policy_path, "r") as f:
        for line in f:
            match = re.match(r"^([a-zA-Z0-9_]+):\s*(.*)$", line.strip())
            if match:
                key = match.group(1)
                val = match.group(2)
                if key == "default_review_cycle_days":
                    try:
                        policy[key] = int(val)
                    except ValueError:
                        pass
                elif key == "mode":
                    policy[key] = val
    return policy

def main():
    policy_path = os.environ.get("REVIEW_POLICY_PATH", os.path.join(repo_root, "manifest", "review-policy.yaml"))
    policy = load_review_policy(policy_path)
    max_days = policy["default_review_cycle_days"]
    mode = policy["mode"]

    manifest_path = os.path.join(repo_root, "manifest", "repo-index.yaml")
    if not os.path.exists(manifest_path):
        print(f"ERROR: Manifest not found at {manifest_path}")
        sys.exit(1)

    with open(manifest_path, "r") as f:
        manifest_data = parse_repo_index(f.read())

    warnings = 0
    errors = 0
    now = datetime.now()

    for zone, zone_data in manifest_data.get("zones", {}).items():
        for doc_path in zone_data.get("docs", []):
            full_doc_path = os.path.join(repo_root, doc_path)
            if not os.path.exists(full_doc_path):
                continue

            with open(full_doc_path, "r") as df:
                frontmatter = parse_frontmatter(df.read())

            last_reviewed_str = frontmatter.get("last_reviewed")
            if not last_reviewed_str:
                msg = f"Missing 'last_reviewed' in {doc_path}"
                print(f"WARN: {msg}")
                warnings += 1
                continue

            try:
                last_reviewed = datetime.strptime(last_reviewed_str, "%Y-%m-%d")
                age_days = (now - last_reviewed).days
                if age_days > max_days:
                    msg = f"Document {doc_path} review age ({age_days} days) exceeds policy ({max_days} days)."
                    if mode == "fail":
                        print(f"ERROR: {msg}")
                        errors += 1
                    else:
                        print(f"WARN: {msg}")
                        warnings += 1
            except ValueError:
                msg = f"Invalid 'last_reviewed' format in {doc_path}. Expected YYYY-MM-DD, got '{last_reviewed_str}'"
                print(f"WARN: {msg}")
                warnings += 1

    if mode == "fail" and errors > 0:
        print(f"\nFailed: {errors} review age violations found.")
        sys.exit(1)

    print(f"\nReview Age Check complete. {warnings} warnings, {errors} errors.")

if __name__ == "__main__":
    main()
