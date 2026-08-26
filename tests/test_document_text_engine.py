from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import struct
import sys
import tempfile
import time
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
        self.original_source_root = engine.SOURCE_ROOT

    def tearDown(self) -> None:
        engine.SOURCE_ROOT = self.original_source_root

    def _file(self, directory: str, name: str, payload: bytes = b"payload") -> Path:
        engine.SOURCE_ROOT = Path(directory).resolve()
        path = Path(directory) / name
        path.write_bytes(payload)
        return path

    def _classic_tiff(self, pages: int) -> bytes:
        self.assertGreater(pages, 0)
        payload = bytearray(b"II*\x00" + struct.pack("<I", 8))
        for index in range(pages):
            next_offset = 8 + (index + 1) * 6 if index + 1 < pages else 0
            payload.extend(struct.pack("<HI", 0, next_offset))
        return bytes(payload)

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

    def test_source_outside_approved_root_is_rejected_without_path_echo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            approved = base / "approved"
            approved.mkdir()
            outside = base / "outside.png"
            outside.write_bytes(b"outside")
            engine.SOURCE_ROOT = approved.resolve()
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine.inspect_source(str(outside), self.policy)
        self.assertEqual(caught.exception.code, "source_not_authorized")
        self.assertNotIn(str(outside), str(caught.exception))

    def test_sensitive_source_areas_are_rejected(self) -> None:
        protected = (
            ".cache/document.pdf",
            ".local/share/Trash/document.pdf",
            ".ssh/document.pdf",
            ".gnupg/document.pdf",
            ".password-store/document.pdf",
            ".thunderbird/profile/document.pdf",
            ".mozilla/firefox/profile/document.pdf",
            ".config/google-chrome/Default/document.pdf",
            ".config/BraveSoftware/Brave-Browser/Default/document.pdf",
            ".local/share/keyrings/document.pdf",
            "node_modules/document.pdf",
            ".venv/document.pdf",
            "venv/document.pdf",
            "dist/document.pdf",
            "build/document.pdf",
            "target/document.pdf",
            "__pycache__/document.pdf",
            ".mypy_cache/document.pdf",
            ".pytest_cache/document.pdf",
        )
        with tempfile.TemporaryDirectory() as directory:
            engine.SOURCE_ROOT = Path(directory).resolve()
            for relative in protected:
                with self.subTest(relative=relative):
                    with self.assertRaises(engine.DocumentTextError) as caught:
                        engine.inspect_source(str(Path(directory) / relative), self.policy)
                    self.assertEqual(caught.exception.code, "source_not_authorized")

    def test_configured_source_excludes_are_enforced_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            engine.SOURCE_ROOT = root
            secret = root / "secret" / "document.pdf"
            backup = root / "personal-backup" / "document.pdf"
            secret.parent.mkdir()
            backup.parent.mkdir()
            secret.write_bytes(b"secret")
            backup.write_bytes(b"backup")
            config = root / "heim-pc.yml"
            config.write_text(
                "excludes:\n"
                "  - pattern: '*/secret/*'\n"
                + f"  - pattern: '{root}/personal-backup/*'\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(engine, "CONFIG_PATH", config),
                mock.patch.object(engine.os, "open", wraps=os.open) as tracked_open,
            ):
                for source in (secret, backup):
                    with self.subTest(source=source.name):
                        with self.assertRaises(engine.DocumentTextError) as caught:
                            engine._open_source(str(source), self.policy)
                        self.assertEqual(caught.exception.code, "source_not_authorized")
            tracked_open.assert_not_called()

    def test_parent_symlink_cannot_escape_approved_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            approved = base / "approved"
            outside = base / "outside"
            approved.mkdir()
            outside.mkdir()
            (outside / "page.png").write_bytes(b"outside")
            (approved / "escape").symlink_to(outside, target_is_directory=True)
            engine.SOURCE_ROOT = approved.resolve()
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine.inspect_source(str(approved / "escape" / "page.png"), self.policy)
        self.assertEqual(caught.exception.code, "source_not_authorized")

    def test_symlink_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            real = self._file(directory, "image.png")
            link = Path(directory) / "link.png"
            link.symlink_to(real)
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine.inspect_source(str(link), self.policy)
        self.assertEqual(caught.exception.code, "input_invalid")

    def test_fifo_source_is_rejected_without_blocking_for_a_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine.SOURCE_ROOT = Path(directory).resolve()
            source = Path(directory) / "blocked.pdf"
            os.mkfifo(source)
            started = time.monotonic()
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine._open_source(str(source), self.policy)
            elapsed = time.monotonic() - started
        self.assertEqual(caught.exception.code, "input_invalid")
        self.assertLess(elapsed, 1.0)

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

    def test_single_page_tiff_establishes_page_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.tiff", self._classic_tiff(1))
            with mock.patch.object(
                engine,
                "doctor",
                return_value={
                    "routes": {"pdf_text_layer": True, "pdf_ocr": True, "image_ocr": True},
                    "docling": {"status": "unattested"},
                },
            ):
                result = engine.inspect_source(str(source), self.policy)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["recommended_method"], "tesseract")
        self.assertEqual(result["pages"], 1)
        self.assertIs(result["page_bound_established"], True)

    def test_tiff_page_limit_blocks_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pages = self.policy["limits"]["max_pages"] + 1
            source = self._file(directory, "many-pages.tiff", self._classic_tiff(pages))
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine.inspect_source(str(source), self.policy)
        self.assertEqual(caught.exception.code, "input_too_large")
        self.assertEqual(caught.exception.details["pages"], pages)

    def test_unparseable_tiff_page_bound_is_unready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "unbounded.tiff", b"II+\x00" + b"\x00" * 12)
            with mock.patch.object(
                engine,
                "doctor",
                return_value={
                    "routes": {"pdf_text_layer": True, "pdf_ocr": True, "image_ocr": True},
                    "docling": {"status": "unattested"},
                },
            ):
                result = engine.inspect_source(str(source), self.policy)
        self.assertEqual(result["status"], "route_unavailable")
        self.assertIsNone(result["pages"] )
        self.assertIs(result["page_bound_established"], False)

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

            def fake_run(argv, *, policy, operation, file_size_limit_bytes=None):
                Path(argv[-1]).write_text("X\n", encoding="utf-8")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine.shutil, "which", return_value="/usr/bin/pdftotext"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
            ):
                self.assertIs(engine._probe_pdf_text_layer(source, self.policy), True)

    def test_text_layer_probe_applies_process_time_output_bound(self) -> None:
        maximum = int(self.policy["limits"]["max_output_bytes"])
        observed: list[int | None] = []
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "bounded-probe.pdf")

            def fake_run(argv, *, policy, operation, file_size_limit_bytes=None):
                observed.append(file_size_limit_bytes)
                Path(argv[-1]).write_text("text layer", encoding="utf-8")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine.shutil, "which", return_value="/usr/bin/pdftotext"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
            ):
                result = engine._probe_pdf_text_layer(source, self.policy)
        self.assertEqual(observed, [maximum])
        self.assertIs(result, True)

    def test_text_layer_probe_treats_output_cap_as_unknown(self) -> None:
        maximum = int(self.policy["limits"]["max_output_bytes"])
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "capped-probe.pdf")

            def fake_run(argv, *, policy, operation, file_size_limit_bytes=None):
                self.assertEqual(file_size_limit_bytes, maximum)
                Path(argv[-1]).write_bytes(b"x" * maximum)
                return mock.Mock(returncode=-25, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine.shutil, "which", return_value="/usr/bin/pdftotext"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
            ):
                result = engine._probe_pdf_text_layer(source, self.policy)
        self.assertIsNone(result)

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

            def fake_run(argv, *, policy, operation, file_size_limit_bytes=None):
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
            mock.patch.object(
                engine,
                "_docling_readiness",
                return_value={"status": "unattested", "automatic_use": False},
            ),
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
                        "routes": {"pdf_text_layer": True, "pdf_ocr": True, "image_ocr": True},
                        "docling": {"status": "unattested"},
                    },
                ),
            ):
                result = engine.inspect_source(str(source), self.policy)
        probe.assert_not_called()
        self.assertEqual(result["status"], "route_unavailable")
        self.assertIsNone(result["pages"] )
        self.assertIs(result["page_bound_established"], False)

    def test_stderr_evidence_never_returns_raw_stderr(self) -> None:
        evidence = engine._stderr_evidence(b"/private/example/secret-path", 8)
        self.assertEqual(evidence["bytes"], len(b"/private/example/secret-path"))
        self.assertEqual(len(evidence["sha256"]), 64)
        self.assertIs(evidence["truncated"], True)
        self.assertNotIn("/private", json.dumps(evidence))

    def test_run_discards_excess_stderr_while_preserving_evidence(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["limits"]["max_stderr_bytes"] = 128
        payload_size = 65536
        completed = engine._run(
            [
                sys.executable,
                "-c",
                f"import sys; sys.stderr.buffer.write(b'x' * {payload_size}); sys.exit(7)",
            ],
            policy=policy,
            operation="stderr-bound-test",
        )
        evidence = engine._process_stderr_evidence(completed, 128)
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(len(completed.stderr), 128)
        self.assertEqual(evidence["bytes"], payload_size)
        self.assertEqual(evidence["bounded_bytes"], 128)
        self.assertIs(evidence["truncated"], True)
        self.assertEqual(len(evidence["sha256"]), 64)

    def test_run_kills_descendant_processes_on_timeout(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["limits"]["process_timeout_seconds"] = 1
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant-survived.txt"
            grandchild = (
                "import pathlib,sys,time; "
                "time.sleep(2); "
                "pathlib.Path(sys.argv[1]).write_text('survived', encoding='utf-8')"
            )
            parent = (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]]); "
                "time.sleep(10)"
            )
            with self.assertRaises(engine.DocumentTextError) as caught:
                engine._run(
                    [sys.executable, "-c", parent, str(marker), grandchild],
                    policy=policy,
                    operation="process-tree-timeout-test",
                )
            time.sleep(1.5)
            survived = marker.exists()
        self.assertEqual(caught.exception.code, "extraction_failed")
        self.assertFalse(survived)

    def test_tmpfs_sandbox_command_uses_private_user_mount_namespace(self) -> None:
        fake_which = {"unshare": "/usr/bin/unshare", "mount": "/usr/bin/mount"}
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            with mock.patch.object(
                engine.shutil, "which", side_effect=lambda name: fake_which.get(name)
            ):
                command = engine._tmpfs_sandbox_command(["/usr/bin/tool", "arg"], work, 4096)
        self.assertEqual(command[0], "/usr/bin/unshare")
        self.assertIn("--map-root-user", command)
        self.assertIn("--mount", command)
        self.assertIn("private", command)
        self.assertIn(engine.INTERNAL_TMPFS_EXEC_OPERATION, command)
        self.assertIn("4096", command)
        self.assertIn("/usr/bin/mount", command)

    def test_tmpfs_sandbox_command_keeps_rendered_pdf_inside_quota_until_export(self) -> None:
        fake_which = {"unshare": "/usr/bin/unshare", "mount": "/usr/bin/mount"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            budget = root / "budget"
            budget.mkdir()
            exported = root / "ocr.pdf"
            with mock.patch.object(
                engine.shutil, "which", side_effect=lambda name: fake_which.get(name)
            ):
                command = engine._tmpfs_sandbox_command(
                    ["/usr/bin/tool", str(budget / "ocr.pdf")],
                    budget,
                    4096,
                    export_relative_path="ocr.pdf",
                    export_path=exported,
                )
        self.assertIn("--export", command)
        export_index = command.index("--export")
        self.assertEqual(command[export_index + 1], "ocr.pdf")
        self.assertEqual(command[export_index + 2], str(exported))
        self.assertEqual(command[-1], str(budget / "ocr.pdf"))

    def test_internal_tmpfs_exec_mounts_exact_quota_before_exec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            mounted = mock.Mock(returncode=0)
            with (
                mock.patch.object(engine.subprocess, "run", return_value=mounted) as run,
                mock.patch.object(engine.os, "execvpe", side_effect=OSError(2, "missing")) as execvpe,
            ):
                result = engine._exec_bounded_tmpfs(
                    [str(work), "4096", "/usr/bin/mount", "--", "/usr/bin/tool", "arg"]
                )
        self.assertEqual(result, 127)
        mount_argv = run.call_args.args[0]
        self.assertEqual(mount_argv[0], "/usr/bin/mount")
        self.assertIn("size=4096,mode=700,nosuid,nodev", mount_argv)
        execvpe.assert_called_once()

    def test_export_file_releases_quota_source_before_destination_growth(self) -> None:
        payload = b"0123456789"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            budget = root / "budget"
            budget.mkdir()
            source = budget / "ocr.pdf"
            destination = root / "exported.pdf"
            source.write_bytes(payload)
            source_sizes_at_write: list[int] = []
            real_pwrite = os.pwrite

            def tracked_pwrite(fd, data, offset):
                source_sizes_at_write.append(source.stat().st_size)
                return real_pwrite(fd, data, offset)

            with mock.patch.object(engine.os, "pwrite", side_effect=tracked_pwrite):
                engine._export_file_releasing_source(source, destination, 4096)
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(source_sizes_at_write, [0])
            self.assertEqual(source.stat().st_size, 0)

    def test_internal_tmpfs_exec_exports_rendered_pdf_after_success(self) -> None:
        payload = b"%PDF-exported"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "budget"
            work.mkdir()
            source = work / "ocr.pdf"
            source.write_bytes(payload)
            destination = root / "ocr.pdf"
            calls = [mock.Mock(returncode=0), mock.Mock(returncode=0)]
            with mock.patch.object(engine.subprocess, "run", side_effect=calls) as run:
                result = engine._exec_bounded_tmpfs(
                    [
                        str(work),
                        "4096",
                        "/usr/bin/mount",
                        "--export",
                        "ocr.pdf",
                        str(destination),
                        "--",
                        "/usr/bin/tool",
                    ]
                )
            self.assertEqual(result, 0)
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(source.stat().st_size, 0)
            self.assertEqual(run.call_count, 2)

    def test_run_rejects_transient_create_unlink_burst_under_tmpfs_quota(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["limits"]["process_timeout_seconds"] = 5
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            script = (
                "from pathlib import Path; import os; "
                "root=Path(os.environ['TMPDIR']); "
                "first=root/'first.bin'; second=root/'second.bin'; "
                "first.write_bytes(b'x' * 4096); "
                "second.write_bytes(b'y' * 4096); "
                "first.unlink(); second.unlink()"
            )
            completed = engine._run(
                [sys.executable, "-c", script],
                policy=policy,
                operation="temporary-storage-burst-test",
                temporary_directory=work,
                temporary_storage_limit_bytes=4096,
            )
        self.assertNotEqual(completed.returncode, 0)

    def test_run_charges_scratch_and_rendered_output_to_one_tmpfs_quota(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["limits"]["process_timeout_seconds"] = 5
        quota = 1024 * 1024
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            script = (
                "from pathlib import Path; import os; "
                "root=Path(os.environ['TMPDIR']); "
                "(root/'scratch.bin').write_bytes(b'x' * 614400); "
                "(root/'ocr.pdf').write_bytes(b'y' * 614400)"
            )
            completed = engine._run(
                [sys.executable, "-c", script],
                policy=policy,
                operation="temporary-storage-rendered-test",
                temporary_directory=work,
                temporary_storage_limit_bytes=quota,
            )
        self.assertNotEqual(completed.returncode, 0)

    def test_output_reader_truncates_at_policy_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._file(directory, "text.txt", b"abcdef")
            text, original_bytes, truncated = engine._read_output(path, 3)
        self.assertEqual(text, "abc")
        self.assertEqual(original_bytes, 6)
        self.assertIs(truncated, True)

    def test_output_reader_truncates_at_valid_utf8_boundary(self) -> None:
        payload = "abéZ".encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = self._file(directory, "text.txt", payload)
            text, original_bytes, truncated = engine._read_output(path, 3)
        self.assertEqual(text, "ab")
        self.assertNotIn("\ufffd", text)
        self.assertLessEqual(len(text.encode("utf-8")), 3)
        self.assertEqual(original_bytes, len(payload))
        self.assertIs(truncated, True)

    def test_run_enforces_file_size_limit_during_child_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "child-output.txt"
            completed = engine._run(
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b'x' * 4096)",
                    str(output),
                ],
                policy=self.policy,
                operation="bounded-output-test",
                file_size_limit_bytes=65,
            )
            size = output.stat().st_size
        self.assertEqual(size, 65)
        self.assertNotEqual(completed.returncode, 0)

    def test_pdftotext_applies_process_time_output_bound(self) -> None:
        maximum = int(self.policy["limits"]["max_output_bytes"])
        observed: list[int | None] = []
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "text.pdf")

            def fake_run(argv, *, policy, operation, file_size_limit_bytes=None):
                observed.append(file_size_limit_bytes)
                Path(argv[-1]).write_text("bounded", encoding="utf-8")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine, "_require_tool", return_value="/usr/bin/pdftotext"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
            ):
                text, _size, truncated = engine._extract_pdftotext(source, self.policy)
        self.assertEqual(observed, [maximum])
        self.assertEqual(text, "bounded")
        self.assertIs(truncated, False)

    def test_pdftotext_marks_limit_termination_as_truncated(self) -> None:
        maximum = int(self.policy["limits"]["max_output_bytes"])
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "text.pdf")

            def fake_run(argv, *, policy, operation, file_size_limit_bytes=None):
                self.assertEqual(file_size_limit_bytes, maximum)
                Path(argv[-1]).write_bytes(b"x" * maximum)
                return mock.Mock(returncode=-25, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine, "_require_tool", return_value="/usr/bin/pdftotext"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
            ):
                text, output_bytes, truncated = engine._extract_pdftotext(source, self.policy)
        self.assertEqual(len(text.encode("utf-8")), maximum)
        self.assertEqual(output_bytes, maximum)
        self.assertIs(truncated, True)

    def test_ocrmypdf_bounds_rendered_pdf_and_scratch_with_one_aggregate_quota(self) -> None:
        maximum = int(self.policy["limits"]["max_source_bytes"])
        observed: list[tuple[object, ...]] = []
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "scan.pdf")

            def fake_run(
                argv,
                *,
                policy,
                operation,
                file_size_limit_bytes=None,
                temporary_directory=None,
                temporary_storage_limit_bytes=None,
                sandbox_export_relative_path=None,
                sandbox_export_path=None,
            ):
                observed.append(
                    (
                        file_size_limit_bytes,
                        temporary_directory,
                        temporary_storage_limit_bytes,
                        sandbox_export_relative_path,
                        sandbox_export_path,
                        Path(argv[-1]),
                    )
                )
                Path(sandbox_export_path).write_bytes(b"%PDF-bounded")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine, "_require_tool", return_value="/usr/bin/tool"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
                mock.patch.object(
                    engine, "_extract_pdftotext", return_value=("ocr text", 8, False)
                ),
            ):
                result = engine._extract_ocr_pdf(source, self.policy, "deu+eng")
        self.assertEqual(result, ("ocr text", 8, False))
        self.assertEqual(len(observed), 1)
        (
            file_limit,
            temporary_directory,
            directory_limit,
            export_relative,
            export_path,
            command_output,
        ) = observed[0]
        self.assertEqual(file_limit, maximum)
        self.assertEqual(directory_limit, maximum)
        self.assertIsNotNone(temporary_directory)
        assert isinstance(temporary_directory, Path)
        self.assertEqual(command_output, temporary_directory / "ocr.pdf")
        self.assertEqual(export_relative, "ocr.pdf")
        self.assertIsNotNone(export_path)
        assert isinstance(export_path, Path)
        with self.assertRaises(ValueError):
            export_path.relative_to(temporary_directory)

    def test_tesseract_applies_process_time_output_bound(self) -> None:
        maximum = int(self.policy["limits"]["max_output_bytes"])
        observed: list[int | None] = []
        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "page.png")

            def fake_run(argv, *, policy, operation, file_size_limit_bytes=None):
                observed.append(file_size_limit_bytes)
                Path(str(argv[2]) + ".txt").write_text("bounded", encoding="utf-8")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(engine, "_require_tool", return_value="/usr/bin/tesseract"),
                mock.patch.object(engine, "_run", side_effect=fake_run),
            ):
                text, _size, truncated = engine._extract_tesseract(source, self.policy, "deu+eng")
        self.assertEqual(observed, [maximum])
        self.assertEqual(text, "bounded")
        self.assertIs(truncated, False)

    def test_tmpfs_sandbox_readiness_rejects_failed_runtime_probe(self) -> None:
        tools = {"unshare": "/usr/bin/unshare", "mount": "/usr/bin/mount"}
        with (
            mock.patch.object(engine, "_tmpfs_sandbox_tools", return_value=tools),
            mock.patch.object(
                engine,
                "_tmpfs_sandbox_command",
                return_value=["/usr/bin/unshare", "probe"],
            ),
            mock.patch.object(
                engine,
                "_run",
                return_value=mock.Mock(returncode=1, stdout=b"", stderr=b""),
            ) as run,
        ):
            readiness = engine._tmpfs_sandbox_readiness(self.policy)
        self.assertEqual(readiness["status"], "unavailable")
        self.assertEqual(readiness["reason"], "runtime_probe_failed")
        self.assertEqual(readiness["returncode"], 1)
        self.assertLessEqual(
            run.call_args.kwargs["policy"]["limits"]["process_timeout_seconds"], 5
        )

    def test_tmpfs_sandbox_readiness_accepts_successful_runtime_probe(self) -> None:
        tools = {"unshare": "/usr/bin/unshare", "mount": "/usr/bin/mount"}
        with (
            mock.patch.object(engine, "_tmpfs_sandbox_tools", return_value=tools),
            mock.patch.object(
                engine,
                "_tmpfs_sandbox_command",
                return_value=["/usr/bin/unshare", "probe"],
            ),
            mock.patch.object(
                engine,
                "_run",
                return_value=mock.Mock(returncode=0, stdout=b"", stderr=b""),
            ) as run,
        ):
            readiness = engine._tmpfs_sandbox_readiness(self.policy)
        self.assertEqual(readiness["status"], "ready")
        self.assertIsNone(readiness["reason"])
        self.assertEqual(readiness["probe"], "user_mount_namespace")
        self.assertLessEqual(
            run.call_args.kwargs["policy"]["limits"]["process_timeout_seconds"], 5
        )

    def test_doctor_isolates_tesseract_readiness_failure_from_text_pdf_route(self) -> None:
        fake_which = {
            "pdftotext": "/usr/bin/pdftotext",
            "pdfinfo": "/usr/bin/pdfinfo",
            "ocrmypdf": "/usr/bin/ocrmypdf",
            "tesseract": "/usr/bin/tesseract",
        }
        with (
            mock.patch.object(engine.shutil, "which", side_effect=lambda name: fake_which.get(name)),
            mock.patch.object(
                engine,
                "_run",
                side_effect=engine.DocumentTextError(
                    "route_unavailable",
                    "tesseract readiness failed without leaking process details",
                ),
            ),
            mock.patch.object(
                engine,
                "_docling_readiness",
                return_value={"status": "unattested", "automatic_use": False},
            ),
        ):
            readiness = engine.doctor(self.policy)
        self.assertEqual(readiness["status"], "degraded")
        self.assertIs(readiness["routes"]["pdf_text_layer"], True)
        self.assertIs(readiness["routes"]["pdf_ocr"], False)
        self.assertIs(readiness["routes"]["image_ocr"], False)
        self.assertEqual(readiness["languages"]["status"], "unavailable")
        self.assertEqual(readiness["languages"]["reason"], "readiness_probe_failed")
        self.assertEqual(readiness["languages"]["error_code"], "route_unavailable")

        with tempfile.TemporaryDirectory() as directory:
            source = self._file(directory, "text.pdf")
            with (
                mock.patch.object(engine, "_pdf_page_count", return_value=1),
                mock.patch.object(engine, "_probe_pdf_text_layer", return_value=True),
                mock.patch.object(engine, "doctor", return_value=readiness),
            ):
                inspection = engine.inspect_source(str(source), self.policy)
        self.assertEqual(inspection["status"], "ready")
        self.assertEqual(inspection["recommended_method"], "pdftotext")

    def test_doctor_does_not_mark_pdf_ocr_ready_when_sandbox_probe_fails(self) -> None:
        fake_which = {
            "pdftotext": "/usr/bin/pdftotext",
            "pdfinfo": "/usr/bin/pdfinfo",
            "ocrmypdf": "/usr/bin/ocrmypdf",
            "tesseract": "/usr/bin/tesseract",
        }
        sandbox = {
            "status": "unavailable",
            "reason": "runtime_probe_failed",
            "tools": {"unshare": "/usr/bin/unshare", "mount": "/usr/bin/mount"},
            "enforcement": "private_tmpfs_quota",
            "probe": "user_mount_namespace",
        }
        with (
            mock.patch.object(engine.shutil, "which", side_effect=lambda name: fake_which.get(name)),
            mock.patch.object(
                engine,
                "_tesseract_languages",
                return_value={"status": "ready", "installed": ["deu", "eng"]},
            ),
            mock.patch.object(engine, "_tmpfs_sandbox_readiness", return_value=sandbox),
            mock.patch.object(
                engine,
                "_docling_readiness",
                return_value={"status": "unattested", "automatic_use": False},
            ),
        ):
            result = engine.doctor(self.policy)
        self.assertEqual(result["status"], "degraded")
        self.assertIs(result["routes"]["pdf_text_layer"], True)
        self.assertIs(result["routes"]["pdf_ocr"], False)
        self.assertIs(result["routes"]["image_ocr"], True)
        self.assertEqual(result["temporary_storage_sandbox"]["reason"], "runtime_probe_failed")

    def test_doctor_does_not_authorize_docling_or_cloud(self) -> None:
        fake_which = {
            "pdftotext": "/usr/bin/pdftotext",
            "pdfinfo": "/usr/bin/pdfinfo",
            "ocrmypdf": "/usr/bin/ocrmypdf",
            "tesseract": "/usr/bin/tesseract",
            "docling": "/usr/bin/docling",
        }
        sandbox = {
            "status": "ready",
            "reason": None,
            "tools": {"unshare": "/usr/bin/unshare", "mount": "/usr/bin/mount"},
            "enforcement": "private_tmpfs_quota",
            "probe": "user_mount_namespace",
        }
        with (
            mock.patch.object(engine.shutil, "which", side_effect=lambda name: fake_which.get(name)),
            mock.patch.object(
                engine,
                "_tesseract_languages",
                return_value={"status": "ready", "installed": ["deu", "eng"]},
            ),
            mock.patch.object(engine, "_tmpfs_sandbox_readiness", return_value=sandbox),
            mock.patch.object(
                engine,
                "_docling_readiness",
                return_value={"status": "unattested", "automatic_use": False},
            ),
        ):
            result = engine.doctor(self.policy)
        self.assertEqual(result["status"], "ready")
        self.assertIs(result["network_access_authorized"], False)
        self.assertIs(result["cloud_or_metered_use_authorized"], False)
        self.assertIs(result["docling"]["automatic_use"], False)
        self.assertEqual(result["temporary_storage_sandbox"]["status"], "ready")

    def test_spawn_os_error_redacts_executable_path(self) -> None:
        sensitive = "/private/tool/secret-name"
        with mock.patch.object(
            engine.subprocess,
            "Popen",
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
