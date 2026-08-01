from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest


def test_validate_zones_reports_schema_failure_as_one_stable_diagnostic(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
    real_yaml_module: Any,
) -> None:
    config = write_utf8(tmp_path / "zones.yml", "{}\n")
    schema = write_utf8(
        tmp_path / "zones.schema.json",
        json.dumps({"type": "object", "required": ["zones"]}),
    )
    module = load_script_module("scripts/validate_contracts.py")
    module.utils.yaml = real_yaml_module

    assert module.validate_zones(str(config), str(schema)) is False

    captured = capsys.readouterr()
    assert captured.out == (
        f"Validating {config} against canonical JSON schema {schema}...\n"
    )
    assert captured.err == (
        f"::error::Validation Error in {config}: 'zones' is a required property\n"
    )


def test_validate_state_file_reports_json_and_schema_failures_atomically(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    data_root = tmp_path / "data"
    schema_root = tmp_path / "schemas"
    write_utf8(data_root / "state" / "broken.json", "{")
    write_utf8(
        schema_root / "state" / "schema.json",
        json.dumps({"type": "object", "required": ["version"]}),
    )

    assert (
        module.validate_state_file(
            "state/broken.json",
            "state/schema.json",
            str(data_root),
            str(schema_root),
        )
        is False
    )
    first = capsys.readouterr()
    assert first.err == (
        "::error::Error processing state/broken.json: "
        "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)\n"
    )

    write_utf8(data_root / "state" / "broken.json", "{}")
    assert (
        module.validate_state_file(
            "state/broken.json",
            "state/schema.json",
            str(data_root),
            str(schema_root),
        )
        is False
    )
    second = capsys.readouterr()
    assert second.err == (
        "::error::Validation Error in state/broken.json: "
        "'version' is a required property\n"
    )
