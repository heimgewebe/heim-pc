from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest


def test_repo_index_accepts_unicode_document_metadata(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
    write_repo_index: Callable[[Path, list[str]], Path],
    frontmatter_document: Callable[..., str],
) -> None:
    root = tmp_path / "repo"
    write_repo_index(root, ["überblick.md"])
    write_utf8(
        root / "docs" / "überblick.md",
        frontmatter_document(doc_id="übersicht", body="# Grüße 世界"),
    )
    module = load_script_module("scripts/ci/check_repo_index_consistency.py")
    monkeypatch.setattr(module, "repo_root", str(root))

    module.main()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == "Repo-index consistency check passed.\n"


def test_repo_index_reports_malformed_frontmatter_duplicates_and_dates_in_order(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
    write_repo_index: Callable[[Path, list[str]], Path],
    frontmatter_document: Callable[..., str],
) -> None:
    root = tmp_path / "repo"
    write_repo_index(root, ["missing.md", "first.md", "second.md"])
    write_utf8(root / "docs" / "missing.md", "---\nnot-a-field\n---\n")
    write_utf8(
        root / "docs" / "first.md",
        frontmatter_document(doc_id="duplicate", last_reviewed="2026-02-30"),
    )
    write_utf8(
        root / "docs" / "second.md",
        frontmatter_document(doc_id="duplicate", last_reviewed="2026-2-03"),
    )
    module = load_script_module("scripts/ci/check_repo_index_consistency.py")
    monkeypatch.setattr(module, "repo_root", str(root))

    with pytest.raises(SystemExit) as raised:
        module.main()

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "ERROR: Missing or invalid frontmatter in docs/missing.md",
        (
            "ERROR: Invalid or missing last_reviewed date "
            "(must be a valid date in YYYY-MM-DD format) in docs/first.md"
        ),
        "ERROR: Duplicate document ID found: duplicate in docs/second.md",
        (
            "ERROR: Invalid or missing last_reviewed date "
            "(must be a valid date in YYYY-MM-DD format) in docs/second.md"
        ),
        "",
        "Found 4 errors in repo-index consistency.",
    ]
