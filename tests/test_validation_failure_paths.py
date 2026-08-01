from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest


def test_json_failure_diagnostics_follow_sorted_unique_file_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
) -> None:
    module = load_script_module("scripts/validate_syntax.py")
    first = write_utf8(tmp_path / "a.json", "{")
    second = write_utf8(tmp_path / "z.json", "{")
    messages: list[str] = []
    monkeypatch.setattr(module.utils, "log_error", messages.append)

    assert module.validate_json(["*.json", "**/*.json"], str(tmp_path)) is True
    assert messages == [
        (
            f"Error parsing JSON {first}: Expecting property name enclosed "
            "in double quotes: line 1 column 2 (char 1)"
        ),
        (
            f"Error parsing JSON {second}: Expecting property name enclosed "
            "in double quotes: line 1 column 2 (char 1)"
        ),
    ]


def test_yaml_failure_diagnostics_are_atomic_and_deterministically_ordered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
    real_yaml_module: Any,
) -> None:
    module = load_script_module("scripts/validate_syntax.py")
    module.yaml = real_yaml_module
    module.utils.yaml = real_yaml_module
    first = write_utf8(tmp_path / "a.yml", "root: [\n")
    second = write_utf8(tmp_path / "z.yml", "root: [\n")
    messages: list[str] = []
    monkeypatch.setattr(module.utils, "log_error", messages.append)

    assert module.validate_yaml(["*.yml", "**/*.yml"], str(tmp_path)) is True
    assert len(messages) == 2
    assert messages[0].startswith(f"Error parsing YAML {first}:")
    assert messages[1].startswith(f"Error parsing YAML {second}:")
