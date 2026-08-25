from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import tempfile
from contextlib import redirect_stdout
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "document_text_engine.py"
SPEC = importlib.util.spec_from_file_location("document_text_engine", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engine)


class DocumentTextEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = engine.load_policy()

    def _file(self, directory: str, name: str, payload: bytes = b"payload") -> Path:
        path = Path(directory) / name
        path.write_bytes(payload)
        return path

    def test_policy_is_local_zero_cost_and_bounded(self) -> None:
        invariants = self.policy["invariants"]
        self.assertIs(invariants["default_path_zero_incremental_cost"], True)
        self.assertIs(invariants["default_path_local_only"], True)
        self.assertIs(invariants["network_access_allowed"], False)
        self.assertIs(invariants["metered_or_cloud_use_allowed"], False)
        self.assertIs(invariants["automatic_docling_use_allowed"], False)
        self.assertGreater(self.policy["limits"]["max_source_bytes"], 0)
        self.assertGreater(self.policy["limits"]["max_output_bytes"], 0)

    def test_contract_has_only_implemented_automatic_methods(self) -> None:
        contract = engine.load_contract()
        self.assertEqual(
            contract["methods"],
            ["pdftotext", "ocrmypdf_then_pdftotext", "tesseract"],
        )
        self.assertNotIn("docling", contract["methods"])

    def test_unsupported_file_type_blocks_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._file(directory, "notes.docx")
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine.inspect_source(str(path), self.policy)
        self.assertEqual(caught.exception.code, "unsupported_input")

    def test_symlink_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            real = self._file(directory, "image.png")
            link = Path(directory) / "link.png"
            link.symlink_to(real)
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine.inspect_source(str(link), self.policy)
        self.assertEqual(caught.exception.code, "input_invalid")

    def test_pdf_with_text_layer_selects_pdftotext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "document.pdf")
            with (
                mock.patch.object(engine, "_pdf_page_count", return_value=2),
                mock.patch.object(engine, "_probe_pdf_text_layer", return_value=True),
                mock.patch.object(
                    engine,
                    "doctor",
                    return_value={
                        "routes": {"pdf_text_layer": True, "pdf_ocr": True, "image_ocr": True},
                        "docling": {"status": "unattested"},
                    },
                ),
            ):
                result = engine.inspect_source(str(source), self.policy)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["recommended_method"], "pdftotext")
        self.assertIs(result["text_layer_detected"], True)
        self.assertEqual(result["pages"], 2)

    def test_scanned_pdf_selects_ocrmypdf_then_pdftotext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "scan.pdf")
            with (
                mock.patch.object(engine, "_pdf_page_count", return_value=1),
                mock.patch.object(engine, "_probe_pdf_text_layer", return_value=False),
                mock.patch.object(
                    engine,
                    "doctor",
                    return_value={
                        "routes": {"pdf_text_layer": True, "pdf_ocr": True, "image_ocr": True},
                        "docling": {"status": "unattested"},
                    },
                ),
            ):
                result = engine.inspect_source(str(source), self.policy)
        self.assertEqual(result["recommended_method"], "ocrmypdf_then_pdftotext")
        self.assertEqual(result["status"], "ready")

    def test_image_selects_tesseract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png")
            with mock.patch.object(
                engine,
                "doctor",
                return_value={
                    "routes": {"pdf_text_layer": True, "pdf_ocr": True, "image_ocr": True},
                    "docling": {"status": "unattested"},
                },
            ):
                result = engine.inspect_source(str(source), self.policy)
        self.assertEqual(result["recommended_method"], "tesseract")
        self.assertEqual(result["status"], "ready")
        self.assertIsNone(result["pages"])

    def test_page_limit_blocks_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "huge.pdf")
            with mock.patch.object(
                engine,
                "_pdf_page_count",
                return_value=self.policy["limits"]["max_pages"] + 1,
            ):
                with self.assertRaises(engine.DocumentTextError) as caught:
                    engine.inspect_source(str(source), self.policy)
        self.assertEqual(caught.exception.code, "input_too_large")

    def test_extract_binds_exact_source_hash_and_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png", b"exact-source")
            expected_sha256 = engine.file_sha256(source)

            def fake_inspect(snapshot, input_type, source_stat, source_sha256, policy):
                self.assertNotEqual(snapshot, source)
                self.assertEqual(snapshot.read_bytes(), b"exact-source")
                self.assertEqual(input_type, "png")
                self.assertEqual(source_stat.st_size, len(b"exact-source"))
                self.assertEqual(source_sha256, expected_sha256)
                return {
                    "status": "ready",
                    "source_sha256": source_sha256,
                    "recommended_method": "tesseract",
                    "pages": None,
                }

            with (
                mock.patch.object(engine, "_inspect_snapshot", side_effect=fake_inspect),
                mock.patch.object(engine, "_extract_tesseract", return_value=("hello", 5, False)),
            ):
                result = engine.extract_source(str(source), self.policy, language="deu+eng")
        self.assertEqual(result["kind"], "heim-pc.document-text")
        self.assertEqual(result["source_sha256"], expected_sha256)
        self.assertEqual(result["method"], "tesseract")
        self.assertEqual(result["text"], "hello")
        self.assertEqual(result["text_bytes"], 5)
        self.assertIs(result["truncated"], False)

    def test_extract_refuses_unready_route(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png")
            with mock.patch.object(
                engine,
                "_inspect_snapshot",
                return_value={
                    "status": "route_unavailable",
                    "source_sha256": engine.file_sha256(source),
                    "recommended_method": "tesseract",
                    "pages": None,
                },
            ):
                with self.assertRaises(engine.DocumentTextError) as caught:
                    engine.extract_source(str(source), self.policy, language="deu+eng")
        self.assertEqual(caught.exception.code, "route_unavailable")


    def test_text_layer_probe_accepts_even_short_real_text_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "short.pdf")

            def fake_run(argv, *, policy, operation):
                Path(argv[-1]).write_text("X\n", encoding="utf-8")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine.shutil, "which", return_value="/usr/bin/pdftotext"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
            ):
                self.assertIs(engine._probe_pdf_text_layer(source, self.policy), True)

    def test_extract_uses_private_snapshot_across_a_b_a_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png", b"A-content")
            expected_sha256 = engine.file_sha256(source)

            def fake_inspect(snapshot, input_type, source_stat, source_sha256, policy):
                self.assertNotEqual(snapshot, source)
                self.assertEqual(snapshot.read_bytes(), b"A-content")
                return {
                    "status": "ready",
                    "source_sha256": source_sha256,
                    "recommended_method": "tesseract",
                    "pages": None,
                }

            def replace_path_a_b_a(snapshot, *_args, **_kwargs):
                replacement_b = Path(directory) / "replacement-b.png"
                replacement_a = Path(directory) / "replacement-a.png"
                replacement_b.write_bytes(b"B-content")
                replacement_a.write_bytes(b"A-content")
                os.replace(replacement_b, source)
                os.replace(replacement_a, source)
                return snapshot.read_text(encoding="utf-8"), len(b"A-content"), False

            with (
                mock.patch.object(engine, "_inspect_snapshot", side_effect=fake_inspect),
                mock.patch.object(engine, "_extract_tesseract", side_effect=replace_path_a_b_a),
            ):
                result = engine.extract_source(str(source), self.policy, language="deu+eng")
            self.assertEqual(source.read_bytes(), b"A-content")
        self.assertEqual(result["source_sha256"], expected_sha256)
        self.assertEqual(result["text"], "A-content")

    def test_private_snapshot_is_mode_0600_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png", b"snapshot-bytes")
            snapshot_dir = Path(directory) / "snapshot"
            snapshot_dir.mkdir()
            snapshot, input_type, source_stat, source_sha256 = engine._snapshot_source(
                str(source), self.policy, snapshot_dir
            )
            self.assertEqual(input_type, "png")
            self.assertEqual(source_stat.st_size, len(b"snapshot-bytes"))
            self.assertEqual(source_sha256, engine.file_sha256(source))
            self.assertEqual(snapshot.read_bytes(), b"snapshot-bytes")
            self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)


    def test_snapshot_blocks_growth_past_source_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png", b"A")
            snapshot_dir = Path(directory) / "snapshot"
            snapshot_dir.mkdir()
            policy = json.loads(json.dumps(self.policy))
            policy["limits"]["max_source_bytes"] = 5
            with mock.patch.object(engine.os, "read", side_effect=[b"1234", b"5678"]):
                with self.assertRaises(engine.DocumentTextError) as caught:
                    engine._snapshot_source(str(source), policy, snapshot_dir)
        self.assertEqual(caught.exception.code, "input_too_large")
        self.assertEqual(caught.exception.details["max_source_bytes"], 5)

    def test_undeclared_webp_input_is_not_silently_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.webp")
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine.inspect_source(str(source), self.policy)
        self.assertEqual(caught.exception.code, "unsupported_input")

    def test_text_layer_probe_routes_mixed_pdf_to_ocr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "mixed.pdf")

            def fake_run(argv, *, policy, operation):
                Path(argv[-1]).write_text("text page\f\f", encoding="utf-8")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine.shutil, "which", return_value="/usr/bin/pdftotext"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
            ):
                self.assertIs(engine._probe_pdf_text_layer(source, self.policy), False)

    def test_pdf_routes_require_pdfinfo_for_page_bound(self) -> None:
        fake_which = {
            "pdftotext": "/usr/bin/pdftotext",
            "ocrmypdf": "/usr/bin/ocrmypdf",
            "tesseract": "/usr/bin/tesseract",
        }
        with (
            mock.patch.object(engine.shutil, "which", side_effect=lambda name: fake_which.get(name)),
            mock.patch.object(
                engine,
                "_tesseract_languages",
                return_value={"status": "ready", "installed": ["deu", "eng"]},
            ),
            mock.patch.object(engine, "_docling_readiness", return_value={"status": "unattested", "automatic_use": False}),
        ):
            result = engine.doctor(self.policy)
        self.assertIs(result["routes"]["pdf_text_layer"], False)
        self.assertIs(result["routes"]["pdf_ocr"], False)
        self.assertIs(result["routes"]["image_ocr"], True)
        self.assertEqual(result["status"], "degraded")

    def test_inspect_does_not_probe_pdf_when_page_bound_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "unknown-pages.pdf")
            with (
                mock.patch.object(engine, "_pdf_page_count", return_value=None),
                mock.patch.object(engine, "_probe_pdf_text_layer") as probe,
                mock.patch.object(
                    engine,
                    "doctor",
                    return_value={
                        "routes": {"pdf_text_layer": False, "pdf_ocr": False, "image_ocr": True},
                        "docling": {"status": "unattested"},
                    },
                ),
            ):
                result = engine.inspect_source(str(source), self.policy)
        probe.assert_not_called()
        self.assertEqual(result["status"], "route_unavailable")
        self.assertIsNone(result["pages"] )

    def test_stderr_evidence_never_returns_raw_stderr(self) -> None:
        evidence = engine._stderr_evidence(b"/private/example/secret-path", 8)
        self.assertEqual(evidence["bytes"], len(b"/private/example/secret-path"))
        self.assertEqual(len(evidence["sha256"]), 64)
        self.assertIs(evidence["truncated"], True)
        self.assertNotIn("/private", json.dumps(evidence))

    def test_output_reader_truncates_at_policy_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._file(directory, "text.txt", b"abcdef")
            text, original_bytes, truncated = engine._read_output(path, 3)
        self.assertEqual(text, "abc")
        self.assertEqual(original_bytes, 6)
        self.assertIs(truncated, True)

    def test_doctor_does_not_authorize_docling_or_cloud(self) -> None:
        fake_which = {
            "pdftotext": "/usr/bin/pdftotext",
            "pdfinfo": "/usr/bin/pdfinfo",
            "ocrmypdf": "/usr/bin/ocrmypdf",
            "tesseract": "/usr/bin/tesseract",
            "docling": "/usr/bin/docling",
        }
        with (
            mock.patch.object(engine.shutil, "which", side_effect=lambda name: fake_which.get(name)),
            mock.patch.object(
                engine,
                "_tesseract_languages",
                return_value={"status": "ready", "installed": ["deu", "eng"]},
            ),
            mock.patch.object(engine, "_docling_readiness", return_value={"status": "unattested", "automatic_use": False}),
        ):
            result = engine.doctor(self.policy)
        self.assertEqual(result["status"], "ready")
        self.assertIs(result["network_access_authorized"], False)
        self.assertIs(result["cloud_or_metered_use_authorized"], False)
        self.assertIs(result["docling"]["automatic_use"], False)

    def test_spawn_os_error_redacts_executable_path(self) -> None:
        sensitive = "/private/tool/secret-name"
        with mock.patch.object(
            engine.subprocess,
            "run",
            side_effect=FileNotFoundError(2, "No such file", sensitive),
        ):
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine._run([sensitive], policy=self.policy, operation="probe")
        rendered = json.dumps(
            {"message": str(caught.exception), "details": caught.exception.details}
        )
        self.assertNotIn(sensitive, rendered)
        self.assertEqual(caught.exception.details["error_type"], "FileNotFoundError")
        self.assertEqual(caught.exception.details["errno"], 2)

    def test_main_redacts_raw_os_error_path(self) -> None:
        sensitive = "/private/customer/secret-document.png"
        output = io.StringIO()
        with (
            mock.patch.object(
                engine,
                "inspect_source",
                side_effect=PermissionError(13, "Permission denied", sensitive),
            ),
            redirect_stdout(output),
        ):
            returncode = engine.main(["inspect", sensitive])
        rendered = output.getvalue()
        payload = json.loads(rendered)
        self.assertEqual(returncode, 3)
        self.assertNotIn(sensitive, rendered)
        self.assertEqual(payload["error"]["code"], "local_io_error")
        self.assertEqual(payload["error"]["details"]["error_type"], "PermissionError")
        self.assertEqual(payload["error"]["details"]["errno"], 13)

    def test_cli_error_is_machine_readable(self) -> None:
        payload = engine._error_payload(
            "inspect",
            engine.DocumentTextError("unsupported_input", "nope"),
        )
        encoded = json.dumps(payload)
        self.assertIn('"status": "blocked"', encoded)
        self.assertEqual(payload["error"]["code"], "unsupported_input")


if __name__ == "__main__":
    unittest.main()
