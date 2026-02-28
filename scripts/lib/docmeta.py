import re
from typing import Dict, Any

def parse_frontmatter(file_content: str) -> Dict[str, Any]:
    """
    Parses a simple YAML frontmatter block enclosed by '---'.
    Minimal line-based parser.
    """
    frontmatter = {}
    lines = file_content.splitlines()
    in_frontmatter = False
    current_list_key = None

    for line in lines:
        stripped = line.strip()
        if stripped == "---":
            if not in_frontmatter:
                in_frontmatter = True
                continue
            else:
                break

        if not in_frontmatter:
            continue

        if not stripped or stripped.startswith("#"):
            continue

        # Check for list items first
        if stripped.startswith("- "):
            if current_list_key is not None:
                item = stripped[2:].strip().strip("'\"")
                if item:
                    frontmatter[current_list_key].append(item)
            continue

        # Parse key-value pairs
        match = re.match(r"^([a-zA-Z0-9_-]+):\s*(.*)$", line)
        if match:
            key = match.group(1)
            value_str = match.group(2).strip()

            # Handle empty lists e.g., '[]'
            if value_str == "[]":
                frontmatter[key] = []
                current_list_key = key
            elif not value_str:
                frontmatter[key] = []
                current_list_key = key
            else:
                frontmatter[key] = value_str.strip("'\"")
                current_list_key = None

    return frontmatter

def parse_repo_index(manifest_content: str) -> Dict[str, Any]:
    """
    Parses manifest/repo-index.yaml line-based to extract zones and checks.
    Returns: {"zones": {"norm": {"path": "...", "docs": [...]}, ...}, "checks": [...]}
    """
    result = {"zones": {}, "checks": []}
    lines = manifest_content.splitlines()

    current_section = None
    current_zone = None
    current_key = None

    for line in lines:
        if not line.strip() or line.strip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if indent == 0:
            if stripped == "zones:":
                current_section = "zones"
            elif stripped == "checks:":
                current_section = "checks"
            else:
                current_section = None
            continue

        if current_section == "zones":
            if indent == 2 and stripped.endswith(":"):
                current_zone = stripped[:-1]
                if current_zone not in result["zones"]:
                    result["zones"][current_zone] = {"path": "", "docs": []}
            elif indent == 4 and current_zone:
                if stripped.startswith("path:"):
                    result["zones"][current_zone]["path"] = stripped.split("path:", 1)[1].strip()
                elif stripped == "docs:":
                    current_key = "docs"
                elif current_key == "docs" and stripped.startswith("- "):
                    # The array isn't empty! It is populated directly here.
                    pass
            elif indent == 6 and current_zone and current_key == "docs" and stripped.startswith("- "):
                doc_path = stripped[2:].strip()
                if doc_path:
                    result["zones"][current_zone]["docs"].append(doc_path)
            # Handle indentation 6 (or whatever is present for list items inside zones)
            # Actually, `docs:` is indent 4, and `- ...` is indent 6.
        elif current_section == "checks":
            if indent == 2 and stripped.startswith("- "):
                check_path = stripped[2:].strip()
                if check_path:
                    result["checks"].append(check_path)

    return result
