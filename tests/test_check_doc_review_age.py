from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import pytest


def test_review_policy_fallbacks_have_stable_atomic_warnings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
) -> None:
    policy_path = write_utf8(
        tmp_path / "review-policy.yaml",
        (
            "default_review_cycle_days: never\n"
            "mode: explode\n"
            "extra_key: Grüße\n"
        ),
    )
    module = load_script_module("scripts/ci/check-doc-review-age.py")

    policy, warnings = module.load_review_policy(str(policy_path))

    assert policy == {"default_review_cycle_days": 90, "mode": "warn"}
    assert warnings == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        (
            "WARN: Invalid default_review_cycle_days 'never', "
            "falling back to 90."
        ),
        "WARN: Invalid mode 'explode', falling back to 'warn'.",
        "WARN: Unknown key in review-policy.yaml: 'extra_key'",
    ]


def test_review_age_main_reports_missing_invalid_and_stale_docs_in_manifest_order(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
    write_repo_index: Callable[[Path, list[str]], Path],
    frontmatter_document: Callable[..., str],
) -> None:
    root = tmp_path / "repo"
    write_repo_index(
        root,
        ["missing.md", "invalid.md", "stale.md", "überblick.md"],
    )
    write_utf8(
        root / "docs" / "missing.md",
        frontmatter_document(doc_id="missing", last_reviewed=None),
    )
    write_utf8(
        root / "docs" / "invalid.md",
        frontmatter_document(doc_id="invalid", last_reviewed="2026-02-30"),
    )
    write_utf8(
        root / "docs" / "stale.md",
        frontmatter_document(doc_id="stale", last_reviewed="2026-01-01"),
    )
    write_utf8(
        root / "docs" / "überblick.md",
        frontmatter_document(doc_id="übersicht", last_reviewed="2026-08-01"),
    )
    policy_path = write_utf8(
        root / "manifest" / "review-policy.yaml",
        "default_review_cycle_days: 30\nmode: fail\n",
    )
    module = load_script_module("scripts/ci/check-doc-review-age.py")
    monkeypatch.setattr(module, "repo_root", str(root))
    monkeypatch.setenv("REVIEW_POLICY_PATH", str(policy_path))

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 8, 1, tzinfo=tz)

    monkeypatch.setattr(module, "datetime", FixedDateTime)

    with pytest.raises(SystemExit) as raised:
        module.main()

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == (
        "Policy parsed with 0 warnings. Max review age: 30 days. Mode: fail.\n"
    )
    assert captured.err.splitlines() == [
        "WARN: Missing 'last_reviewed' in docs/missing.md",
        (
            "WARN: Invalid 'last_reviewed' format in docs/invalid.md. "
            "Expected YYYY-MM-DD, got '2026-02-30'"
        ),
        (
            "ERROR: Document docs/stale.md review age (212 days) "
            "exceeds policy (30 days)."
        ),
        "",
        "Failed: 1 review age violations found.",
    ]
