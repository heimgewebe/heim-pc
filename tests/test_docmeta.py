from __future__ import annotations

import pytest

from scripts.lib.docmeta import parse_frontmatter, parse_repo_index


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("", {}),
        ("# No frontmatter\n", {}),
        ("---\nnot-a-field\n---\n", {}),
        ("---\nid: unterminated", {"id": "unterminated"}),
    ],
)
def test_parse_frontmatter_characterizes_missing_and_malformed_blocks(
    content: str, expected: dict[str, object]
) -> None:
    assert parse_frontmatter(content) == expected


def test_parse_frontmatter_preserves_unicode_and_crlf_lists() -> None:
    content = (
        "---\r\n"
        "id: übersicht\r\n"
        "title: \"Grüße 世界\"\r\n"
        "depends_on:\r\n"
        "  - café\r\n"
        "  - 東京\r\n"
        "---\r\n"
        "# Körper\r\n"
    )

    assert parse_frontmatter(content) == {
        "id": "übersicht",
        "title": "Grüße 世界",
        "depends_on": ["café", "東京"],
    }


def test_parse_frontmatter_duplicate_fields_use_the_last_value() -> None:
    content = "---\nid: first\nid: second\nstatus: draft\nstatus: canonical\n---\n"

    assert parse_frontmatter(content) == {
        "id": "second",
        "status": "canonical",
    }


def test_parse_repo_index_preserves_declared_unicode_order_across_line_endings() -> None:
    content = (
        "zones:\r\n"
        "  zeta:\r\n"
        "    path: døk\r\n"
        "    canonical_docs:\r\n"
        "      - überblick.md\r\n"
        "      - 東京.md\r\n"
        "  alpha:\r\n"
        "    path: docs\r\n"
        "    canonical_docs:\r\n"
        "      - first.md\r\n"
        "checks:\r\n"
        "  - scripts/β-check.py\r\n"
    )

    result = parse_repo_index(content)

    assert list(result["zones"]) == ["zeta", "alpha"]
    assert result["zones"]["zeta"] == {
        "path": "døk",
        "canonical_docs": ["überblick.md", "東京.md"],
    }
    assert result["checks"] == ["scripts/β-check.py"]
