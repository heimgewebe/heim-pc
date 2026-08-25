#!/usr/bin/env python3
"""Canonical local-first document text extraction CLI for the heim-pc."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "manifest" / "document-text-engine-policy.v1.json"
CONTRACT_PATH = REPO_ROOT / "manifest" / "document-text-contract.v1.json"
DOCLING_READINESS_PATH = (
    Path.home() / ".local" / "state" / "heim-pc" / "document-text-engine" / "docling-readiness.v1.json"
)


class DocumentTextError(RuntimeError):
    """A bounded document-text operation could not be completed safely."""

    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def load_policy() -> dict[str, Any]:
    policy = _load_json(POLICY_PATH)
    if policy.get("schema_version") != 1 or policy.get("kind") != "heim_pc_document_text_engine_policy":
        raise ValueError("document text policy identity mismatch")
    invariants = policy.get("invariants")
    if not isinstance(invariants, dict):
        raise ValueError("document text policy invariants must be an object")
    required_true = (
        "default_path_zero_incremental_cost",
        "default_path_local_only",
    )
    for key in required_true:
        if invariants.get(key) is not True:
            raise ValueError(f"document text policy invariant {key} must remain true")
    required_false = (
        "network_access_allowed",
        "metered_or_cloud_use_allowed",
        "automatic_docling_use_allowed",
        "source_content_persisted_by_engine",
        "extracted_text_persisted_by_engine",
    )
    for key in required_false:
        if invariants.get(key) is not False:
            raise ValueError(f"document text policy invariant {key} must remain false")
    limits = policy.get("limits")
    if not isinstance(limits, dict):
        raise ValueError("document text policy limits must be an object")
    for key in (
        "max_source_bytes",
        "max_output_bytes",
        "max_pages",
        "process_timeout_seconds",
        "max_stderr_bytes",
    ):
        value = limits.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"document text policy limit {key} must be a positive integer")
    languages = policy.get("languages")
    if not isinstance(languages, dict) or languages.get("default") not in languages.get("allowed", []):
        raise ValueError("document text policy languages are invalid")
    routing = policy.get("routing")
    if not isinstance(routing, dict):
        raise ValueError("document text policy routing must be an object")
    probe_minimum = routing.get("text_layer_probe_min_non_whitespace_chars")
    if (
        not isinstance(probe_minimum, int)
        or isinstance(probe_minimum, bool)
        or probe_minimum <= 0
    ):
        raise ValueError("document text text-layer probe minimum must be a positive integer")
    supported_inputs = policy.get("supported_inputs")
    if (
        not isinstance(supported_inputs, list)
        or set(supported_inputs) != {"pdf", "png", "jpeg", "tiff"}
        or any(not isinstance(item, str) for item in supported_inputs)
    ):
        raise ValueError("document text supported_inputs must match the implemented v1 input kinds")
    return policy


def load_contract() -> dict[str, Any]:
    contract = _load_json(CONTRACT_PATH)
    if contract.get("schema_version") != 1 or contract.get("kind") != "heim-pc.document-text":
        raise ValueError("document text result contract identity mismatch")
    return contract


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tool_name(policy: dict[str, Any], role: str) -> str:
    tools = policy.get("tools")
    if not isinstance(tools, dict) or not isinstance(tools.get(role), str):
        raise ValueError(f"document text policy tool {role} is missing")
    return str(tools[role])


def _stderr_evidence(value: bytes, maximum: int) -> dict[str, Any]:
    bounded = value[:maximum]
    return {
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "bounded_bytes": len(bounded),
        "truncated": len(value) > maximum,
    }


def _run(
    argv: Sequence[str],
    *,
    policy: dict[str, Any],
    operation: str,
) -> subprocess.CompletedProcess[bytes]:
    timeout = int(policy["limits"]["process_timeout_seconds"])
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C.UTF-8"},
        )
    except subprocess.TimeoutExpired as exc:
        raise DocumentTextError(
            "extraction_failed",
            f"{operation} exceeded the bounded process timeout",
            details={"timeout_seconds": timeout},
        ) from exc
    except OSError as exc:
        raise DocumentTextError(
            "route_unavailable",
            f"{operation} could not start the required local process",
            details={
                "error_type": type(exc).__name__,
                "errno": exc.errno,
            },
        ) from exc
    return completed


def _require_tool(policy: dict[str, Any], role: str) -> str:
    name = _tool_name(policy, role)
    executable = shutil.which(name)
    if executable is None:
        raise DocumentTextError(
            "route_unavailable",
            f"required local tool is unavailable: {name}",
            details={"role": role, "tool": name},
        )
    return executable


def _source_kind(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".png":
        return "png"
    if suffix in {".jpg", ".jpeg"}:
        return "jpeg"
    if suffix in {".tif", ".tiff"}:
        return "tiff"
    raise DocumentTextError(
        "unsupported_input",
        "document type is not supported by the local v1 contract",
        details={"suffix": suffix or None},
    )


def _source_candidate(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate


def _open_source(raw_path: str, policy: dict[str, Any]) -> tuple[int, str, os.stat_result, str]:
    candidate = _source_candidate(raw_path)
    input_type = _source_kind(candidate)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except FileNotFoundError as exc:
        raise DocumentTextError("input_invalid", "source file does not exist") from exc
    except OSError as exc:
        raise DocumentTextError(
            "input_invalid",
            "source file cannot be opened safely",
            details={"error_type": type(exc).__name__, "errno": exc.errno},
        ) from exc
    try:
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            raise DocumentTextError("input_invalid", "source must be a regular file")
        maximum = int(policy["limits"]["max_source_bytes"])
        if source_stat.st_size <= 0:
            raise DocumentTextError("input_invalid", "source file is empty")
        if source_stat.st_size > maximum:
            raise DocumentTextError(
                "input_too_large",
                "source file exceeds the bounded v1 size limit",
                details={"source_bytes": source_stat.st_size, "max_source_bytes": maximum},
            )
        return descriptor, input_type, source_stat, candidate.suffix.casefold()
    except BaseException:
        os.close(descriptor)
        raise


def _snapshot_source(
    raw_path: str,
    policy: dict[str, Any],
    directory: Path,
) -> tuple[Path, str, os.stat_result, str]:
    descriptor, input_type, before, suffix = _open_source(raw_path, policy)
    snapshot = directory / f"source{suffix}"
    digest = hashlib.sha256()
    destination = -1
    copied = 0
    maximum = int(policy["limits"]["max_source_bytes"])
    try:
        destination = os.open(
            snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            copied += len(chunk)
            if copied > maximum:
                raise DocumentTextError(
                    "input_too_large",
                    "source file exceeded the bounded v1 size limit while snapshotting",
                    details={"max_source_bytes": maximum},
                )
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                if written <= 0:
                    raise DocumentTextError(
                        "input_invalid",
                        "private source snapshot write made no progress",
                    )
                view = view[written:]
        os.fsync(destination)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or copied != before.st_size
        ):
            raise DocumentTextError(
                "input_invalid",
                "source content changed while the private snapshot was captured",
            )
    except DocumentTextError:
        raise
    except OSError as exc:
        raise DocumentTextError(
            "input_invalid",
            "private source snapshot could not be created safely",
            details={"error_type": type(exc).__name__, "errno": exc.errno},
        ) from exc
    finally:
        if destination >= 0:
            os.close(destination)
        os.close(descriptor)
    return snapshot, input_type, before, digest.hexdigest()


def _read_output(path: Path, maximum: int) -> tuple[str, int, bool]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        payload = handle.read(maximum + 1)
    truncated = len(payload) > maximum or size > maximum
    emitted = payload[:maximum]
    return emitted.decode("utf-8", errors="replace"), size, truncated


def _pdf_page_count(path: Path, policy: dict[str, Any]) -> int | None:
    executable = shutil.which(_tool_name(policy, "pdf_info"))
    if executable is None:
        return None
    completed = _run([executable, str(path)], policy=policy, operation="pdfinfo")
    if completed.returncode != 0:
        return None
    text = completed.stdout.decode("utf-8", errors="replace")
    match = re.search(r"^Pages:\s+(\d+)\s*$", text, flags=re.MULTILINE)
    if match is None:
        return None
    return int(match.group(1))


def _probe_pdf_text_layer(path: Path, policy: dict[str, Any]) -> bool | None:
    executable = shutil.which(_tool_name(policy, "pdf_text"))
    if executable is None:
        return None
    max_pages = int(policy["limits"]["max_pages"])
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-probe-") as directory:
        output = Path(directory) / "probe.txt"
        completed = _run(
            [
                executable,
                "-f",
                "1",
                "-l",
                str(max_pages),
                "-layout",
                str(path),
                str(output),
            ],
            policy=policy,
            operation="pdftotext-probe",
        )
        if completed.returncode != 0 or not output.exists():
            return None
        minimum = int(policy["routing"]["text_layer_probe_min_non_whitespace_chars"])
        current_non_whitespace = 0
        saw_page_boundary = False
        with output.open("r", encoding="utf-8", errors="replace") as handle:
            for chunk in iter(lambda: handle.read(65536), ""):
                for character in chunk:
                    if character == "\f":
                        saw_page_boundary = True
                        if current_non_whitespace < minimum:
                            return False
                        current_non_whitespace = 0
                    elif not character.isspace():
                        current_non_whitespace += 1
        if current_non_whitespace:
            return current_non_whitespace >= minimum
        return True if saw_page_boundary else False


def _tesseract_languages(policy: dict[str, Any]) -> dict[str, Any]:
    name = _tool_name(policy, "image_ocr")
    executable = shutil.which(name)
    if executable is None:
        return {"status": "unavailable", "tool": name, "installed": []}
    completed = _run([executable, "--list-langs"], policy=policy, operation="tesseract-language-readiness")
    if completed.returncode != 0:
        return {"status": "unavailable", "tool": name, "installed": []}
    lines = completed.stdout.decode("utf-8", errors="replace").splitlines()
    installed = sorted({line.strip() for line in lines[1:] if line.strip()})
    required = policy["languages"].get("required_installed", [])
    missing = sorted(set(required).difference(installed))
    return {
        "status": "ready" if not missing else "degraded",
        "tool": name,
        "installed": installed,
        "required": required,
        "missing": missing,
    }


def _docling_readiness(policy: dict[str, Any]) -> dict[str, Any]:
    name = _tool_name(policy, "structured_optional")
    executable = shutil.which(name)
    if executable is None:
        return {
            "status": "unavailable",
            "tool": name,
            "reason": "executable_missing",
            "automatic_use": False,
        }
    try:
        receipt = _load_json(DOCLING_READINESS_PATH)
    except (OSError, ValueError, json.JSONDecodeError):
        return {
            "status": "unattested",
            "tool": name,
            "reason": "explicit_offline_readiness_receipt_missing",
            "automatic_use": False,
        }
    valid = (
        receipt.get("schema_version") == 1
        and receipt.get("kind") == "heim_pc.document_text.docling_readiness"
        and receipt.get("status") == "ready"
        and receipt.get("network_required") is False
    )
    return {
        "status": "ready" if valid else "unattested",
        "tool": name,
        "reason": None if valid else "readiness_receipt_invalid",
        "automatic_use": False,
    }


def doctor(policy: dict[str, Any]) -> dict[str, Any]:
    tool_roles = ("pdf_text", "pdf_info", "pdf_ocr", "image_ocr")
    tools: dict[str, dict[str, Any]] = {}
    for role in tool_roles:
        name = _tool_name(policy, role)
        executable = shutil.which(name)
        tools[role] = {
            "tool": name,
            "available": executable is not None,
            "executable": executable,
        }
    languages = _tesseract_languages(policy)
    routes = {
        "pdf_text_layer": (
            tools["pdf_text"]["available"] and tools["pdf_info"]["available"]
        ),
        "pdf_ocr": (
            tools["pdf_text"]["available"]
            and tools["pdf_info"]["available"]
            and tools["pdf_ocr"]["available"]
            and tools["image_ocr"]["available"]
            and languages["status"] == "ready"
        ),
        "image_ocr": tools["image_ocr"]["available"] and languages["status"] == "ready",
    }
    return {
        "schema_version": 1,
        "kind": "heim-pc.document-text-doctor",
        "operation": "doctor",
        "status": "ready" if all(routes.values()) else "degraded",
        "routes": routes,
        "tools": tools,
        "languages": languages,
        "docling": _docling_readiness(policy),
        "network_access_authorized": False,
        "cloud_or_metered_use_authorized": False,
        "does_not_establish": [
            "source_file_access",
            "future_tool_availability",
            "extraction_correctness",
            "docling_model_readiness_without_valid_receipt",
        ],
    }


def _inspect_snapshot(
    source: Path,
    input_type: str,
    source_stat: os.stat_result,
    source_sha256: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    pages: int | None = None
    text_layer: bool | None = None
    if input_type == "pdf":
        pages = _pdf_page_count(source, policy)
        maximum_pages = int(policy["limits"]["max_pages"])
        if pages is not None and pages > maximum_pages:
            raise DocumentTextError(
                "input_too_large",
                "PDF exceeds the bounded v1 page limit",
                details={"pages": pages, "max_pages": maximum_pages},
            )
        text_layer = _probe_pdf_text_layer(source, policy) if pages is not None else None
        method = "pdftotext" if text_layer is True else "ocrmypdf_then_pdftotext"
    else:
        method = "tesseract"
    readiness = doctor(policy)
    if method == "pdftotext":
        route_ready = bool(readiness["routes"]["pdf_text_layer"])
    elif method == "ocrmypdf_then_pdftotext":
        route_ready = bool(readiness["routes"]["pdf_ocr"])
    else:
        route_ready = bool(readiness["routes"]["image_ocr"])
    return {
        "schema_version": 1,
        "kind": "heim-pc.document-text-inspection",
        "operation": "inspect",
        "status": "ready" if route_ready else "route_unavailable",
        "source_sha256": source_sha256,
        "source_bytes": source_stat.st_size,
        "input_type": input_type,
        "pages": pages,
        "text_layer_detected": text_layer,
        "recommended_method": method,
        "route_ready": route_ready,
        "docling": readiness["docling"],
        "does_not_establish": [
            "extraction_correctness",
            "layout_fidelity",
            "document_authenticity",
        ],
    }


def inspect_source(raw_path: str, policy: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-source-") as directory:
        source, input_type, source_stat, source_sha256 = _snapshot_source(
            raw_path, policy, Path(directory)
        )
        return _inspect_snapshot(source, input_type, source_stat, source_sha256, policy)


def _extract_pdftotext(source: Path, policy: dict[str, Any]) -> tuple[str, int, bool]:
    executable = _require_tool(policy, "pdf_text")
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-pdf-") as directory:
        output = Path(directory) / "text.txt"
        completed = _run(
            [
                executable,
                "-f",
                "1",
                "-l",
                str(int(policy["limits"]["max_pages"])),
                "-layout",
                str(source),
                str(output),
            ],
            policy=policy,
            operation="pdftotext",
        )
        if completed.returncode != 0 or not output.exists():
            raise DocumentTextError(
                "extraction_failed",
                "pdftotext failed",
                details={
                    "returncode": completed.returncode,
                    "stderr_evidence": _stderr_evidence(
                        completed.stderr, int(policy["limits"]["max_stderr_bytes"])
                    ),
                },
            )
        return _read_output(output, int(policy["limits"]["max_output_bytes"]))


def _extract_ocr_pdf(source: Path, policy: dict[str, Any], language: str) -> tuple[str, int, bool]:
    ocrmypdf = _require_tool(policy, "pdf_ocr")
    _require_tool(policy, "image_ocr")
    _require_tool(policy, "pdf_text")
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-ocrpdf-") as directory:
        rendered = Path(directory) / "ocr.pdf"
        completed = _run(
            [
                ocrmypdf,
                "--skip-text",
                "--rotate-pages",
                "--deskew",
                "--jobs",
                "1",
                "--optimize",
                "0",
                "--output-type",
                "pdf",
                "-l",
                language,
                str(source),
                str(rendered),
            ],
            policy=policy,
            operation="ocrmypdf",
        )
        if completed.returncode != 0 or not rendered.exists():
            raise DocumentTextError(
                "extraction_failed",
                "OCRmyPDF failed",
                details={
                    "returncode": completed.returncode,
                    "stderr_evidence": _stderr_evidence(
                        completed.stderr, int(policy["limits"]["max_stderr_bytes"])
                    ),
                },
            )
        return _extract_pdftotext(rendered, policy)


def _extract_tesseract(source: Path, policy: dict[str, Any], language: str) -> tuple[str, int, bool]:
    executable = _require_tool(policy, "image_ocr")
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-image-") as directory:
        output_base = Path(directory) / "ocr"
        completed = _run(
            [executable, str(source), str(output_base), "-l", language, "txt"],
            policy=policy,
            operation="tesseract",
        )
        output = output_base.with_suffix(".txt")
        if completed.returncode != 0 or not output.exists():
            raise DocumentTextError(
                "extraction_failed",
                "Tesseract failed",
                details={
                    "returncode": completed.returncode,
                    "stderr_evidence": _stderr_evidence(
                        completed.stderr, int(policy["limits"]["max_stderr_bytes"])
                    ),
                },
            )
        return _read_output(output, int(policy["limits"]["max_output_bytes"]))


def _validate_language(language: str, policy: dict[str, Any]) -> str:
    allowed = policy["languages"].get("allowed", [])
    if language not in allowed:
        raise DocumentTextError(
            "input_invalid",
            "requested OCR language is not allowlisted by the local policy",
            details={"language": language, "allowed": allowed},
        )
    return language


def validate_extract_result(result: dict[str, Any]) -> None:
    contract = load_contract()
    required = contract.get("required_fields", [])
    if not isinstance(required, list):
        raise ValueError("document text contract required_fields must be an array")
    missing = [field for field in required if field not in result]
    if missing:
        raise DocumentTextError(
            "extraction_failed",
            "document text result violates its result contract",
            details={"missing_fields": missing},
        )
    if result.get("schema_version") != 1 or result.get("kind") != contract.get("kind"):
        raise DocumentTextError("extraction_failed", "document text result identity mismatch")


def extract_source(raw_path: str, policy: dict[str, Any], *, language: str) -> dict[str, Any]:
    language = _validate_language(language, policy)
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-source-") as directory:
        source, input_type, source_stat, source_sha256 = _snapshot_source(
            raw_path, policy, Path(directory)
        )
        inspection = _inspect_snapshot(
            source, input_type, source_stat, source_sha256, policy
        )
        if inspection["status"] != "ready":
            raise DocumentTextError(
                "route_unavailable",
                "recommended local extraction route is not currently ready",
                details={"method": inspection["recommended_method"]},
            )
        method = str(inspection["recommended_method"])
        if method == "pdftotext":
            text, text_bytes, truncated = _extract_pdftotext(source, policy)
            result_language: str | None = None
        elif method == "ocrmypdf_then_pdftotext":
            text, text_bytes, truncated = _extract_ocr_pdf(source, policy, language)
            result_language = language
        elif method == "tesseract":
            text, text_bytes, truncated = _extract_tesseract(source, policy, language)
            result_language = language
        else:
            raise DocumentTextError(
                "route_unavailable",
                "inspection selected an unsupported extraction route",
            )
        result = {
            "schema_version": 1,
            "kind": "heim-pc.document-text",
            "source_sha256": source_sha256,
            "input_type": input_type,
            "method": method,
            "language": result_language,
            "pages": inspection["pages"],
            "text": text,
            "text_bytes": text_bytes,
            "truncated": truncated,
            "warnings": ["output_truncated_to_policy_limit"] if truncated else [],
        }
        validate_extract_result(result)
        return result


def _error_payload(operation: str, error: DocumentTextError) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "heim-pc.document-text-error",
        "operation": operation,
        "status": "blocked",
        "error": {
            "code": error.code,
            "message": str(error),
            "details": error.details,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("doctor", help="Report local route readiness without downloading anything")
    inspect_parser = subparsers.add_parser("inspect", help="Inspect one local document and select a route")
    inspect_parser.add_argument("source")
    extract_parser = subparsers.add_parser("extract", help="Extract text through the selected local route")
    extract_parser.add_argument("source")
    extract_parser.add_argument("--language", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy()
        if args.operation == "doctor":
            payload = doctor(policy)
        elif args.operation == "inspect":
            payload = inspect_source(args.source, policy)
        else:
            language = args.language or str(policy["languages"]["default"])
            payload = extract_source(args.source, policy, language=language)
    except DocumentTextError as exc:
        print(json.dumps(_error_payload(args.operation, exc), ensure_ascii=False, sort_keys=True))
        return 2
    except OSError as exc:
        payload = _error_payload(
            args.operation,
            DocumentTextError(
                "local_io_error",
                "local filesystem or process operation failed",
                details={"error_type": type(exc).__name__, "errno": exc.errno},
            ),
        )
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 3
    except (ValueError, json.JSONDecodeError) as exc:
        payload = _error_payload(
            args.operation,
            DocumentTextError(
                "contract_invalid",
                "document text contract or local runtime state is invalid",
                details={"error_type": type(exc).__name__},
            ),
        )
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 3
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
