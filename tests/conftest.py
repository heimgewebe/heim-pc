from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def load_script_module(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], Any]:
    counter = itertools.count()
    monkeypatch.syspath_prepend(str(REPO_ROOT / "scripts"))

    def load(relative_path: str) -> Any:
        script_path = REPO_ROOT / relative_path
        module_name = (
            "_heim_pc_test_"
            + script_path.stem.replace("-", "_")
            + "_"
            + str(next(counter))
        )
        spec = importlib.util.spec_from_file_location(module_name, script_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load {script_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    return load


@pytest.fixture
def write_utf8() -> Callable[[Path, str], Path]:
    def write(path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", errors="strict")
        return path

    return write


@pytest.fixture
def write_repo_index(
    write_utf8: Callable[[Path, str], Path],
) -> Callable[[Path, list[str]], Path]:
    def write(root: Path, documents: list[str]) -> Path:
        lines = [
            "zones:",
            "  norm:",
            "    path: docs",
            "    canonical_docs:",
        ]
        lines.extend(f"      - {name}" for name in documents)
        lines.append("checks:")
        return write_utf8(
            root / "manifest" / "repo-index.yaml",
            "\n".join(lines) + "\n",
        )

    return write


@pytest.fixture
def frontmatter_document() -> Callable[..., str]:
    def build(
        *,
        doc_id: str = "example",
        role: str = "norm",
        status: str = "canonical",
        last_reviewed: str | None = "2026-08-01",
        depends_on: tuple[str, ...] = (),
        verifies_with: tuple[str, ...] = (),
        body: str = "# Example",
    ) -> str:
        lines = [
            "---",
            f"id: {doc_id}",
            f"role: {role}",
            f"status: {status}",
        ]
        if last_reviewed is not None:
            lines.append(f"last_reviewed: {last_reviewed}")
        lines.extend(
            [
                "depends_on: [" + ", ".join(depends_on) + "]",
                "verifies_with: [" + ", ".join(verifies_with) + "]",
                "---",
                "",
                body,
                "",
            ]
        )
        return "\n".join(lines)

    return build


@pytest.fixture
def real_yaml_module() -> Any:
    return yaml
