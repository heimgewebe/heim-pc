"""Run the existing Grabowski worktree-hygiene Grip on a bounded systemd cycle.

Keep the job-retention scanner separate: its protected historical job archives
must not prevent worktree hygiene from functioning.
"""
import importlib.util
import json
import sys
from pathlib import Path

REPOSITORIES = (
    "/home/alex/repos/grabowski",
    "/home/alex/repos/heim-pc",
    "/home/alex/repos/commonthing",
    "/home/alex/repos/commonworld",
    "/home/alex/repos/magic",
    "/home/alex/repos/repoground",
    "/home/alex/repos/kleinanzeiger",
    "/home/alex/repos/schauwerk",
)
ROOTS = (
    "/home/alex/repos/.grabowski-worktrees",
    "/home/alex/repos/.grabowski-review-snapshots",
)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("expected exactly one pinned retention-runner path")
    script = Path(sys.argv[1]).resolve(strict=True)
    repos = [path for path in REPOSITORIES if Path(path).is_dir()]
    roots = [path for path in ROOTS if Path(path).is_dir()]
    if not repos or not roots:
        raise RuntimeError("no configured repository or worktree root available")
    spec = importlib.util.spec_from_file_location("grabowski_retention_native", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned Grabowski retention module cannot be loaded")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    result = runtime._apply_periodic_worktree_hygiene(
        repositories=repos,
        owner_id="grabowski-primary",
        allowed_checkout_roots=roots,
        max_actions=2,
    )
    receipts = result["receipts"]
    print(json.dumps({
        "status": result["status"],
        "completed": result["completed"],
        "actions": result["actions"],
        "repositories_checked": len(repos),
        "archived": sum(len(r.get("output", {}).get("archived", [])) for r in receipts),
        "cleaned": sum(len(r.get("output", {}).get("cleaned", [])) for r in receipts),
        "blocked": sum(r.get("status") == "blocked" for r in receipts),
    }, sort_keys=True))
    return 0 if result["status"] == "passed" and result["completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
