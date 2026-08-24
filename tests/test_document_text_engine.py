from __future__ import annotations

import importlib.util
import json
import tempfile
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
            inspection = {
                "status": "ready",
                "source_sha256": engine.file_sha256(source),
                "recommended_method": "tesseract",
                "pages": None,
            }
            with (
                mock.patch.object(engine, "inspect_source", return_value=inspection),
                mock.patch.object(engine, "_extract_tesseract", return_value=("hello", 5, False)),
            ):
                result = engine.extract_source(str(source), self.policy, language="deu+eng")
        self.assertEqual(result["kind"], "heim-pc.document-text")
        self.assertEqual(result["source_sha256"], inspection["source_sha256"])
        self.assertEqual(result["method"], "tesseract")
        self.assertEqual(result["text"], "hello")
        self.assertEqual(result["text_bytes"], 5)
        self.assertIs(result["truncated"], False)

    def test_extract_refuses_unready_route(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png")
            with mock.patch.object(
                engine,
                "inspect_source",
                return_value={
                    "status": "route_unavailable",
                    "source_sha256": "x",
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

    def test_extract_blocks_when_source_changes_after_route_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png", b"before")
            inspection = {
                "status": "ready",
                "source_sha256": engine.file_sha256(source),
                "recommended_method": "tesseract",
                "pages": None,
            }

            def mutate_then_return(*_args, **_kwargs):
                source.write_bytes(b"after")
                return "text", 4, False

            with (
                mock.patch.object(engine, "inspect_source", return_value=inspection),
                mock.patch.object(engine, "_extract_tesseract", side_effect=mutate_then_return),
            ):
                with self.assertRaises(engine.DocumentTextError) as caught:
                    engine.extract_source(str(source), self.policy, language="deu+eng")
        self.assertEqual(caught.exception.code, "input_invalid")

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
