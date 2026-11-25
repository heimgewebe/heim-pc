"""Offline tests for Nabu's OAuth and typed Grabowski MCP integration."""
from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest import TestCase, mock
from unittest import IsolatedAsyncioTestCase


ROOT = Path(__file__).resolve().parents[1] / "nabu"
try:
    import aiohttp
except ImportError:
    # Host Python is smaller than HA's container Python.
    sys.modules["aiohttp"] = SimpleNamespace(
        ClientSession=object, ClientError=type("ClientError", (Exception,), {}),
        ClientTimeout=lambda **values: values,
    )


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


grabowski = load("grabowski_client")
chatgpt = load("chatgpt_client")
login = load("siwc_login")


class GrabowskiContractTests(TestCase):
    def test_read_operation_is_narrow(self):
        self.assertEqual(grabowski.read_request("status")[0], "grabowski_status")
        self.assertEqual(grabowski.read_request("tasks")[0], "grabowski_task_list")
        self.assertEqual(grabowski.read_request("task", "deadbeef1234567")[0], "grabowski_task_status")
        for task_id in ("", "/tmp/passwd", "task; rm -rf", "http://localhost"):
            with self.subTest(task_id=task_id), self.assertRaises(ValueError):
                grabowski.read_request("task", task_id)
        with self.assertRaises(ValueError):
            grabowski.read_request("terminal_run")

    def test_sse_and_json_rpc_are_receipt_bound(self):
        value = {"jsonrpc": "2.0", "id": 1,
                 "result": {"structuredContent": {"healthy": True}}}
        raw = "event: message\ndata: " + json.dumps(value) + "\n\n"
        self.assertEqual(grabowski.parse_mcp_response(raw), {"healthy": True})
        self.assertEqual(grabowski.parse_mcp_response(json.dumps(value)), {"healthy": True})
        with self.assertRaises(grabowski.GrabowskiUnavailable):
            grabowski.parse_mcp_response('{"jsonrpc":"2.0","id":2,"result":{}}')
        with self.assertRaises(grabowski.GrabowskiUnavailable):
            grabowski.parse_mcp_response(
                '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"blocked"}}'
            )

    def test_malformed_messages_are_rejected_not_crashing(self):
        for raw in ("[1, 2]", '{"jsonrpc":"2.0","id":1,"error":"blocked"}',
                    '{"jsonrpc":"2.0","id":1,"result":null}',
                    'data: "text"\n\n'):
            with self.subTest(raw=raw), self.assertRaises(grabowski.GrabowskiUnavailable):
                grabowski.parse_mcp_response(raw)

    def test_summary_never_includes_secrets(self):
        result = {"healthy": True, "secret": "NEVER", "runtime": {"release_id": "r"},
                  "tool_contract": {"registered_tool_count": 208}}
        data = grabowski.compact_result("status", result)
        self.assertNotIn("NEVER", json.dumps(data))
        self.assertEqual(data["registered_tools"], 208)


    def test_qwen_task_selection_with_goo_id_is_normalized_to_obligation(self):
        obligation_id = "goo-nabu-chatgpt-grabowski-20261122"
        operation, actual_id = grabowski.normalize_read_operation(
            "task", obligation_id
        )
        self.assertEqual((operation, actual_id), ("obligation", obligation_id))
        name, args = grabowski.read_request(operation, obligation_id=actual_id)
        self.assertEqual(name, "grip_run")
        self.assertEqual(args["name"], "operator-obligation-status")
        self.assertFalse(args["allow_mutation"])
        self.assertEqual(args["parameters"], {"obligation_id": obligation_id})
        self.assertEqual(
            grabowski.normalize_read_operation("task", "deadbeef1234567"),
            ("task", ""),
        )
        self.assertEqual(
            grabowski.normalize_read_operation("obligation", "",
                                               obligation_id),
            ("obligation", obligation_id),
        )
        with self.assertRaises(ValueError):
            grabowski.read_request(
                *grabowski.normalize_read_operation("task", "goo-/bad")
            )

    def test_obligation_status_is_exact_read_only_and_bounded(self):
        obligation_id = "goo-nabu-1234567890abcdef1234"
        name, args = grabowski.read_request(
            "obligation", obligation_id=obligation_id
        )
        self.assertEqual(name, "grip_run")
        self.assertEqual(args["name"], "operator-obligation-status")
        self.assertFalse(args["allow_mutation"])
        self.assertEqual(args["parameters"], {"obligation_id": obligation_id})
        answer = {"status": "passed", "output": {
            "obligation_id": obligation_id, "state": "open",
            "work_complete": False, "continuation_required": True,
            "missing_acceptance_ids": ["dispatch"],
            "recommended_next_action": "continue", "private": "NOT_FOR_NABU",
        }}
        summary = grabowski.compact_result("obligation", answer)
        self.assertEqual(summary["obligation_id"], obligation_id)
        self.assertEqual(summary["state"], "open")
        self.assertEqual(summary["missing_acceptance_ids"], ["dispatch"])
        self.assertFalse(summary["work_complete"])
        self.assertNotIn("NOT_FOR_NABU", json.dumps(summary))

    def test_obligation_status_rejects_invalid_ids_and_unconfirmed_results(self):
        for obligation_id in ("", "goo-", "goo-/tmp/passwd", "task123", "goo-" + "x" * 200):
            with self.subTest(obligation_id=obligation_id), self.assertRaises(ValueError):
                grabowski.read_request("obligation", obligation_id=obligation_id)
        for result in ({}, {"status": "passed"}, {"status": "blocked", "output": {
            "obligation_id": "goo-nabu-1234567890abcdef1234", "work_complete": True,
            "continuation_required": False}}, {"status": "passed", "output": {
            "obligation_id": "goo-nabu-1234567890abcdef1234",
            "work_complete": "yes", "continuation_required": False}}):
            with self.subTest(result=result), self.assertRaises(grabowski.GrabowskiUnavailable):
                grabowski.compact_result("obligation", result)



class ChatGPTBrowserVoiceTests(TestCase):
    """Browser handoff must remain fixed and never impersonate a Voice E2E."""

    def test_success_uses_only_fixed_chatgpt_url_and_grabowski_task(self):
        self.assertEqual(
            grabowski.CHATGPT_BROWSER_ARGV,
            ("/run/current-system/sw/bin/kstart", "--desktopfile", "nabu-chatgpt", "--",
             "/home/alex/.nix-profile/bin/google-chrome", "--profile-directory=Default",
             "https://chatgpt.com/?mode=voice"),
        )
        task_id = "d" * 24
        replies = [
            {"task": {"task_id": task_id, "launcher": {"returncode": 0}}},
            {"task_id": task_id, "state": "completed"},
        ]
        with mock.patch.object(grabowski, "mcp_call",
                               new=mock.AsyncMock(side_effect=replies)) as call:
            result = asyncio.run(grabowski.start_chatgpt_browser_voice(object()))
        self.assertEqual(result["status"], "start_completed")
        self.assertEqual(result["task_id"], task_id)
        for key in ("browser_login_verified", "microphone_verified",
                    "chatgpt_voice_active_verified"):
            self.assertIs(result[key], False)
        first = call.call_args_list[0]
        self.assertEqual(first.args[1], "grabowski_task_start")
        start = first.args[2]
        self.assertEqual(start["host"], "heim-pc")
        self.assertEqual(start["argv"], list(grabowski.CHATGPT_BROWSER_ARGV))
        self.assertEqual(start["resume_policy"], "never")
        self.assertEqual(call.call_args_list[1].args[1], "grabowski_task_status")
        self.assertEqual(call.call_args_list[1].args[2]["task_id"], task_id)

    def test_voice_and_text_reuse_existing_personal_chrome_profile(self):
        voice = grabowski.chatgpt_voice_launch_args()["argv"]
        text = grabowski.chatgpt_text_launch_args("Status")["argv"]
        self.assertEqual(voice[:-1], text[:-1])
        self.assertEqual(voice[:-1], [
            "/run/current-system/sw/bin/kstart", "--desktopfile", "nabu-chatgpt", "--",
            "/home/alex/.nix-profile/bin/google-chrome", "--profile-directory=Default",
        ])
        self.assertNotIn("xdg-open", " ".join(voice + text))
        self.assertNotIn("--guest", voice + text)
        self.assertFalse(any(arg.startswith("--user-data-dir") for arg in voice + text))
        self.assertNotIn("--new-window", voice + text)
        self.assertTrue(grabowski.is_fixed_chatgpt_text_launch(
            grabowski.chatgpt_text_launch_args("Status")
        ))

    def test_no_valid_launch_receipt_means_no_success(self):
        for reply in ({}, {"task": {"task_id": "not-a-task", "launcher": {"returncode": 0}}},
                      {"task": {"task_id": "f" * 24, "launcher": {"returncode": 1}}}):
            with self.subTest(reply=reply), mock.patch.object(
                grabowski, "mcp_call", new=mock.AsyncMock(return_value=reply),
            ) as call:
                with self.assertRaises(grabowski.GrabowskiUnavailable):
                    asyncio.run(grabowski.start_chatgpt_browser_voice(object()))
                self.assertEqual(call.call_count, 1)

    def test_failed_or_unknown_execution_does_not_claim_browser_open(self):
        for state in ("failed", "timed_out", "outcome_unknown"):
            replies = [
                {"task": {"task_id": "f" * 24, "launcher": {"returncode": 0}}},
                {"task_id": "f" * 24, "state": state},
            ]
            with self.subTest(state=state), mock.patch.object(
                grabowski, "mcp_call", new=mock.AsyncMock(side_effect=replies),
            ):
                with self.assertRaises(grabowski.GrabowskiUnavailable):
                    asyncio.run(grabowski.start_chatgpt_browser_voice(object()))

    def test_other_task_status_cannot_confirm_voice_launch(self):
        replies = [
            {"task": {"task_id": "f" * 24, "launcher": {"returncode": 0}}},
            {"task_id": "e" * 24, "state": "completed"},
        ]
        with mock.patch.object(
            grabowski, "mcp_call", new=mock.AsyncMock(side_effect=replies),
        ):
            with self.assertRaises(grabowski.GrabowskiUnavailable):
                asyncio.run(grabowski.start_chatgpt_browser_voice(object()))

    def test_launching_is_not_confused_with_complete_or_authenticated_voice(self):
        replies = [
            {"task": {"task_id": "e" * 24, "launcher": {"returncode": 0}}},
            {"task_id": "e" * 24, "state": "running"},
        ]
        with mock.patch.object(
            grabowski, "mcp_call", new=mock.AsyncMock(side_effect=replies),
        ):
            result = asyncio.run(grabowski.start_chatgpt_browser_voice(object()))
        self.assertEqual(result["status"], "start_requested")
        self.assertFalse(result["chatgpt_voice_active_verified"])

class ChatGPTBrowserTextTests(TestCase):
    """Sending a desktop link cannot be confused with sending a chat message."""

    def test_prefill_url_is_canonical_and_encodes_user_text(self):
        from urllib.parse import parse_qs, urlsplit
        question = "Prüfe: Büro & Haus? #Grabowski + Nabu"
        url = grabowski.chatgpt_text_url(question)
        self.assertEqual(urlsplit(url).scheme, "https")
        self.assertEqual(urlsplit(url).hostname, "chatgpt.com")
        self.assertEqual(parse_qs(urlsplit(url).query), {"prompt": [question]})
        self.assertNotIn("& Haus", url)
        self.assertTrue(grabowski.is_fixed_chatgpt_text_launch(
            grabowski.chatgpt_text_launch_args(question)
        ))
        self.assertEqual(grabowski.chatgpt_text_url(None), "https://chatgpt.com/")
        self.assertTrue(grabowski.is_fixed_chatgpt_text_launch(
            grabowski.chatgpt_text_launch_args()
        ))

    def test_no_arbitrary_url_or_command_is_permitted(self):
        valid = grabowski.chatgpt_text_launch_args("Test")
        failures = [
            dict(valid, argv=["/bin/sh", *valid["argv"][1:]]),
            dict(valid, argv=[*valid["argv"][:-2], "--profile-directory=Profile 1", valid["argv"][-1]]),
            dict(valid, argv=[*valid["argv"][:-2], "--profile-directory=Profile 2", valid["argv"][-1]]),
            dict(valid, argv=["/run/current-system/sw/bin/xdg-open", valid["argv"][-1]]),
            dict(valid, argv=[*valid["argv"][:-1], "https://evil.example/?prompt=Test"]),
            dict(valid, argv=[*valid["argv"][:-1], "https://chatgpt.com/?mode=voice"]),
            dict(valid, argv=[*valid["argv"][:-1], "https://chatgpt.com/?prompt=Test&x=1"]),
            dict(valid, argv=[*valid["argv"][:-1], "https://chatgpt.com/?prompt=%4eabu"]),
            dict(valid, argv=valid["argv"][4:]),  # direct Chrome task is not allowed
            dict(valid, argv=[*valid["argv"][:2], "other-app", *valid["argv"][3:]]),
            dict(valid, resource_keys=["repo.heim-pc"]),
        ]
        for args in failures:
            with self.subTest(args=args):
                self.assertFalse(grabowski.is_fixed_chatgpt_text_launch(args))
        for text in ("", "  ", "Prüfen\nSystem", "\x00", "\t", "x" * 5100):
            with self.subTest(text=text), self.assertRaises(ValueError):
                grabowski.chatgpt_text_url(text)

    def test_verifier_rejects_invalid_drafts_that_generator_refuses(self):
        for encoded in ("", "%00", "%0A", "x" * 5000):
            with self.subTest(payload=encoded[:16]):
                launch = grabowski.chatgpt_text_launch_args(None)
                launch["argv"][-1] = grabowski.CHATGPT_TEXT_PREFIX + encoded
                self.assertFalse(grabowski.is_fixed_chatgpt_text_launch(launch))

    def test_text_start_receipt_does_not_claim_chat_submission(self):
        task_id = "a" * 24
        reply = [
            {"task": {"task_id": task_id, "launcher": {"returncode": 0}}},
            {"task_id": task_id, "state": "completed"},
        ]
        with mock.patch.object(grabowski, "mcp_call",
                               new=mock.AsyncMock(side_effect=reply)) as call:
            result = asyncio.run(
                grabowski.start_chatgpt_browser_text(object(), "Schreib ChatGPT!")
            )
        self.assertEqual(result["status"], "browser_opened")
        self.assertTrue(result["text_prefill_requested"])
        for key in ("composer_prefill_verified", "message_sent_verified",
                    "chatgpt_login_verified", "chatgpt_response_verified"):
            self.assertIs(result[key], False)
        self.assertIn("Senden", result["message"])
        self.assertEqual(call.call_args_list[0].args[1], "grabowski_task_start")
        self.assertEqual(
            call.call_args_list[0].args[2],
            grabowski.chatgpt_text_launch_args("Schreib ChatGPT!")
        )
        self.assertEqual(call.call_args_list[1].args[1], "grabowski_task_status")

    def test_blank_open_and_unconfirmed_status(self):
        with mock.patch.object(grabowski, "mcp_call", new=mock.AsyncMock(
            side_effect=[
                {"task": {"task_id": "b" * 24, "launcher": {"returncode": 0}}},
                {"task_id": "b" * 24, "state": "running"},
            ]
        )):
            result = asyncio.run(grabowski.start_chatgpt_browser_text(object()))
        self.assertEqual(result["status"], "browser_open_requested")
        self.assertFalse(result["text_prefill_requested"])
        self.assertFalse(result["message_sent_verified"])


class ChatGPTLocalReceiptTests(TestCase):
    def test_receipt_bound_to_exact_fresh_nonce(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipts.json"
            nonce = "ab" * 12
            now = 1795425000
            with mock.patch.object(grabowski, "CHATGPT_SENDER_RECEIPTS_PATH", path), \
                 mock.patch.object(grabowski.time, "time", return_value=now):
                for entry, expected in (
                    ({"stage": "message_sent", "at": now}, "message_sent"),
                    ({"stage": "message_sent", "at": now - 1}, None),
                    ({"stage": "message_sent", "at": now + 16}, None),
                    ({"stage": "message_sent", "at": True}, None),
                    ({"stage": "unknown", "at": now}, None),
                    ({"stage": "send_unconfirmed", "at": now}, "send_unconfirmed"),
                ):
                    path.write_text(json.dumps({nonce: entry}))
                    self.assertEqual(grabowski._read_sender_receipt(nonce, now), expected)
                    self.assertIsNone(grabowski._read_sender_receipt("cd" * 12, now))
                path.write_text("not JSON")
                self.assertIsNone(grabowski._read_sender_receipt(nonce, now))

    def test_confirmed_send_survives_lost_browser_start_receipt_without_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "key"
            key.write_text("ab" * 32)
            path = Path(folder) / "receipts.json"
            nonce = "cd" * 12
            now = 1795425000
            path.write_text(json.dumps({nonce: {"stage": "message_sent", "at": now}}))
            with mock.patch.object(grabowski, "CHATGPT_SENDER_KEY_PATH", key), \
                 mock.patch.object(grabowski, "CHATGPT_SENDER_RECEIPTS_PATH", path), \
                 mock.patch.object(grabowski.time, "time", return_value=now), \
                 mock.patch.object(grabowski.secrets, "token_hex", return_value=nonce), \
                 mock.patch.object(grabowski, "_start_chatgpt_desktop", new=mock.AsyncMock(
                     side_effect=grabowski.GrabowskiUnavailable("lost start receipt"))) as start:
                result = asyncio.run(grabowski.start_chatgpt_browser_text(object(), "Nabu-Test"))
                self.assertEqual(start.await_count, 1)
                self.assertIsNone(result["task_id"])
                self.assertFalse(result["browser_start_verified"])
                self.assertTrue(result["message_sent_verified"])
                self.assertFalse(result["chatgpt_response_verified"])
                self.assertEqual(result["status"], "message_sent")

    def test_click_attempt_or_unconfirmed_is_not_send_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "key"
            key.write_text("ab" * 32)
            path = Path(folder) / "receipts.json"
            nonce = "cd" * 12
            now = 1795425000
            path.write_text(json.dumps({nonce: {"stage": "send_unconfirmed", "at": now}}))
            with mock.patch.object(grabowski, "CHATGPT_SENDER_KEY_PATH", key), \
                 mock.patch.object(grabowski, "CHATGPT_SENDER_RECEIPTS_PATH", path), \
                 mock.patch.object(grabowski.time, "time", return_value=now), \
                 mock.patch.object(grabowski.secrets, "token_hex", return_value=nonce), \
                 mock.patch.object(grabowski, "_start_chatgpt_desktop", new=mock.AsyncMock(
                     return_value=("a" * 24, "completed"))) as start:
                result = asyncio.run(grabowski.start_chatgpt_browser_text(object(), "Nabu-Test"))
                self.assertEqual(start.await_count, 1)
                self.assertTrue(result["browser_start_verified"])
                self.assertFalse(result["message_sent_verified"])
                self.assertEqual(result["status"], "send_unconfirmed")
                path.write_text(json.dumps({nonce: {"stage": "click_attempted", "at": now}}))
                self.assertEqual(asyncio.run(grabowski._wait_sender_receipt(nonce, now, seconds=0)),
                                 "click_attempted")

    def test_confirmed_receipt_returns_before_slow_launch_reply(self):
        async def exercise():
            stopped = asyncio.Event()
            async def slow_start(*args):
                try:
                    await asyncio.sleep(120)
                finally:
                    stopped.set()
            with mock.patch.object(grabowski, "_start_chatgpt_desktop",
                                   new=mock.AsyncMock(side_effect=slow_start)) as start, \
                 mock.patch.object(grabowski, "_wait_sender_receipt",
                                   new=mock.AsyncMock(return_value="message_sent")):
                result = await asyncio.wait_for(grabowski._launch_signed_text(
                    object(), {}, "cd" * 12, 1795425000), timeout=1)
                self.assertEqual(result, (None, None, "message_sent"))
                self.assertEqual(start.await_count, 1)
                self.assertTrue(stopped.is_set())
        asyncio.run(exercise())

    def test_absent_receipt_preserves_ambiguous_error_and_never_retries(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "key"
            key.write_text("ab" * 32)
            with mock.patch.object(grabowski, "CHATGPT_SENDER_KEY_PATH", key), \
                 mock.patch.object(grabowski, "CHATGPT_SENDER_RECEIPTS_PATH", Path(folder) / "missing"), \
                 mock.patch.object(grabowski, "_start_chatgpt_desktop", new=mock.AsyncMock(
                     side_effect=grabowski.GrabowskiUnavailable("lost start receipt"))) as start:
                with self.assertRaisesRegex(grabowski.GrabowskiUnavailable, "lost start receipt"):
                    asyncio.run(grabowski.start_chatgpt_browser_text(object(), "Nabu-Test"))
                self.assertEqual(start.await_count, 1)


class ChatGPTSignedSenderTests(TestCase):
    """Only an installation-local fresh signed Nabu link may auto-submit."""

    def test_signed_url_is_canonical_and_exactly_bound_to_request(self):
        from urllib.parse import parse_qs, urlsplit
        with tempfile.TemporaryDirectory() as root:
            key = Path(root) / "sender.key"
            key.write_text("ab" * 32 + "\n", encoding="ascii")
            with mock.patch.object(grabowski, "CHATGPT_SENDER_KEY_PATH", key), \
                 mock.patch.object(grabowski.time, "time", return_value=1795425000), \
                 mock.patch.object(grabowski.secrets, "token_hex", return_value="cd" * 12):
                question = "Prüfe Grabowski, aber ändere nichts."
                launch = grabowski.chatgpt_text_launch_args(question)
                fields = parse_qs(urlsplit(launch["argv"][-1]).query)
                self.assertEqual(fields["prompt"], [question])
                self.assertEqual(fields["nabu_ts"], ["1795425000"])
                self.assertEqual(fields["nabu_nonce"], ["cd" * 12])
                self.assertEqual(len(fields["nabu_sig"][0]), 64)
                self.assertTrue(grabowski.is_fixed_chatgpt_text_launch(launch))

                original = launch["argv"][-1]
                for bogus in (
                    original.replace("Pr%C3%BCfe", "L%C3%B6sche"),
                    original.replace("nabu_nonce=" + "cd" * 12, "nabu_nonce=" + "ce" * 12),
                    original.replace(fields["nabu_sig"][0], "f" * 64),
                    original + "&nabu_send=1",
                ):
                    with self.subTest(bogus=bogus[-30:]):
                        invalid = dict(launch, argv=[*launch["argv"][:-1], bogus])
                        self.assertFalse(grabowski.is_fixed_chatgpt_text_launch(invalid))

    def test_expired_and_wrong_key_rejected_without_retry(self):
        with tempfile.TemporaryDirectory() as root:
            key = Path(root) / "sender.key"
            key.write_text("12" * 32 + "\n", encoding="ascii")
            with mock.patch.object(grabowski, "CHATGPT_SENDER_KEY_PATH", key), \
                 mock.patch.object(grabowski.time, "time", return_value=1795425000), \
                 mock.patch.object(grabowski.secrets, "token_hex", return_value="56" * 12):
                launch = grabowski.chatgpt_text_launch_args("Frag ChatGPT nach Projektstatus")
            with mock.patch.object(grabowski, "CHATGPT_SENDER_KEY_PATH", key), \
                 mock.patch.object(grabowski.time, "time", return_value=1795425300):
                self.assertFalse(grabowski.is_fixed_chatgpt_text_launch(launch))
            key.write_text("13" * 32 + "\n", encoding="ascii")
            with mock.patch.object(grabowski, "CHATGPT_SENDER_KEY_PATH", key), \
                 mock.patch.object(grabowski.time, "time", return_value=1795425000):
                self.assertFalse(grabowski.is_fixed_chatgpt_text_launch(launch))

    def test_absent_sender_key_retains_manual_handoff(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(grabowski, "CHATGPT_SENDER_KEY_PATH", Path(root) / "missing"):
                link = grabowski.chatgpt_text_launch_args("Schreib ChatGPT")
                self.assertNotIn("nabu_sig", link["argv"][-1])
                self.assertTrue(grabowski.is_fixed_chatgpt_text_launch(link))


class OAuthContractTests(TestCase):
    def test_private_storage_and_host_identity_are_stable(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            login.save_private(path, {"access_token": "private"})
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            self.assertEqual(login.load_private(path)["access_token"], "private")
            a = login.host_id_for(path)
            b = login.host_id_for(path)
            self.assertEqual(a, b)
            self.assertTrue(a.startswith("urn:uuid:"))

    def test_http_json_uses_stdlib_post_and_rejects_errors(self):
        from urllib.error import HTTPError

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"ok":true}'

        with mock.patch.object(login, "urlopen", return_value=Response()) as opener:
            status, data = login.http_json(
                login.TOKEN_URL, data={"grant_type": "authorization_code", "code": "test"},
                timeout=10,
            )
            request = opener.call_args.args[0]
            self.assertEqual(status, 200)
            self.assertEqual(data, {"ok": True})
            self.assertEqual(request.get_method(), "POST")
            self.assertIn(b"code=test", request.data)
            self.assertEqual(
                request.get_header("Content-type"), "application/x-www-form-urlencoded"
            )
        with mock.patch.object(login, "urlopen", side_effect=HTTPError(
            login.TOKEN_URL, 429, "Too many requests", {}, None,
        )):
            status, body = login.http_json(login.TOKEN_URL, data={"code": "secret"})
            self.assertEqual((status, body), (429, {}))

    def test_reauth_fallback_never_includes_id_token(self):
        from urllib.parse import parse_qs, urlsplit

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            login.save_private(path, {
                "client_id": "oaiapp_test",
                "id_token": "THIS_MUST_NOT_BE_EXPOSED",
                "subject": "account123",
            })
            opened = []
            with mock.patch.object(login.webbrowser, "open",
                                   side_effect=lambda url: opened.append(url) or False):
                with mock.patch.object(login.HTTPServer, "handle_request", return_value=None):
                    with mock.patch("builtins.print"):
                        with self.assertRaises(RuntimeError):
                            login.sign_in(path)
            self.assertEqual(len(opened), 1)
            self.assertNotIn("THIS_MUST_NOT_BE_EXPOSED", opened[0])
            self.assertNotIn("id_token_hint", parse_qs(urlsplit(opened[0]).query))
            self.assertEqual(parse_qs(urlsplit(opened[0]).query)["client_id"], ["oaiapp_test"])

    def test_id_token_nonce_issuer_and_audience_are_checked(self):
        import base64
        import hashlib

        # Non-production test fixture: generated RSA-2048 key, no actual user key.
        n_b64 = ("0H5P9R2QEdjsBXHs92jYYm0905dH8YHWZ0-3WMGOuk4ic1NFAKu8XgZEmZW97nnZNhzCMrVJAGJe0iJtXVGy_MYDbT8qS-kB7g1e353e-uf69IT_00g_-MX-vri7oZJfGAVdDY0jSWbJnj_0QZpaV02ZRLozZWUKnJkJ6OdAB1Qj0TL6-p7i4_T9XjaBdQky7QuF1jBTzOEaAc3CMLi0FmUKYVwLRBEEqLqgtesgn1ADhW0A1-yLnn5_ZNOAyDGz0L51Gnumas-jZdLJTvGQ8R7L9YeiBdDMgkAvRKhbWIl7tIZTe8OZz3oMKrpnQb6JVLurUtttIXe9_qSyQRFSmQ")
        d_b64 = ("PYUn_sHMYxfI_QpSy-ZKAzEMz0SSW_bd1vo0taHXha3MiI8Hi10hZfUfhNokgxu9NjRiMShA9DYSmJrD_oc-80tSc4fx6RhGE4Iqfn1M8GhHKqOcATIOfk-eDZTg-JoCKUpb3MXKpbwIvgNNBZaQFba2BQuUYtTfvrmBrRGfWQm4Fe3SUlVFD9pdY7XG6diPdVkMA6hpyS-8YXGO_UsJ03ELaJdKfqx-50jMrLu88Vme8pTCLiljn248pY1iFdjVm-JNxfG1cQr1Q7yXNoJfojsiYVNmOM0c92z1RNNRQ951_u2s1A2y4jAckHKz9hSZ9-QcHtHP5xK-bQ2YA7nzCQ")
        def dec(s):
            return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")
        def b64(data):
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
        n, d = dec(n_b64), dec(d_b64)
        key_bytes = (n.bit_length() + 7) // 8
        head = b64(json.dumps({"alg": "RS256", "kid": "test"}, separators=(",", ":")).encode())
        payload = b64(json.dumps({
            "iss": login.ISSUER, "aud": "oaiapp_test", "sub": "account-123",
            "exp": int(time.time()) + 600, "nonce": "N123",
        }, separators=(",", ":")).encode())
        signed = (head + "." + payload).encode()
        digest = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(signed).digest()
        em = b"\x00\x01" + b"\xff" * (key_bytes - len(digest) - 3) + b"\x00" + digest
        sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(key_bytes, "big")
        issued = head + "." + payload + "." + b64(sig)
        metadata = {"issuer": login.ISSUER,
                    "jwks_uri": login.ISSUER + "/.well-known/jwks.json"}
        keys = {"keys": [{"kid": "test", "kty": "RSA",
                          "alg": "RS256", "n": n_b64, "e": "AQAB"}]}
        with mock.patch.object(login, "http_json",
                               side_effect=[(200, metadata), (200, keys)] * 5):
            self.assertEqual(login.validate_id_token(issued, "oaiapp_test", "N123")["sub"], "account-123")
            with self.assertRaises(ValueError):
                login.validate_id_token(issued, "oaiapp_test", "WRONG")
            with self.assertRaises(ValueError):
                login.validate_id_token(issued, "wrong_client", "N123")
            with self.assertRaises(ValueError):
                tampered = issued[:-3] + "AAA"
                login.validate_id_token(tampered, "oaiapp_test", "N123")


class DummyBody:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_any(self):
        for chunk in self.chunks:
            yield chunk

    async def read(self, size):
        return self.chunks[0]


class DummyResponse:
    def __init__(self, status, data=None, chunks=None):
        self.status = status
        self._data = data
        self.content = DummyBody(chunks or [])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    def raise_for_status(self):
        return None

    async def json(self):
        return self._data


class DummySession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return next(self.responses)


class GrabowskiStreamTests(IsolatedAsyncioTestCase):
    async def test_split_sse_response_is_read_to_completion(self):
        payload = {"jsonrpc": "2.0", "id": 1,
                   "result": {"structuredContent": {"healthy": True}}}
        raw = ("event: message\r\ndata: " + json.dumps(payload) +
               "\r\n\r\n").encode("utf-8")
        response = DummyResponse(200, chunks=[raw[:18], raw[18:42], raw[42:]])
        result = await grabowski.mcp_call(
            DummySession([response]), "grabowski_status",
            {"view": "minimal", "reason": "read", "user_intent": "read"},
        )
        self.assertEqual(result, {"healthy": True})


class GrabowskiReadChallengeTests(IsolatedAsyncioTestCase):
    async def test_read_only_tool_completes_grabowski_challenge_without_retry(self):
        original_args = {
            "view": "minimal", "limit": 5,
            "reason": "Nabu-Assist: aktuelle Grabowski-Aufgaben",
            "user_intent": "Nabu fragt den bestehenden Grabowski-Operator nach dem Zustand",
        }
        challenge = "a" * 64
        first = {"jsonrpc": "2.0", "id": 1, "result": {
            "isError": True,
            "content": [{"type": "text", "text": (
                "fresh intent-bound transport verification required; "
                "call grip_run for transport-roundtrip with action=execute, "
                "challenge_receipt_sha256=" + challenge
            )}],
        }}
        second = {"jsonrpc": "2.0", "id": 1, "result": {
            "structuredContent": {
                "status": "passed", "output": {
                    "state": "executed",
                    "target_result": {"tasks": [{"task_id": "example", "state": "completed"}]},
                },
            },
        }}
        sse = lambda obj: (
            "event: message\r\ndata: " + json.dumps(obj) + "\r\n\r\n"
        ).encode("utf-8")
        session = DummySession([
            DummyResponse(200, chunks=[sse(first)]),
            DummyResponse(200, chunks=[sse(second)]),
        ])
        got = await grabowski.mcp_call(session, "grabowski_task_list", original_args)
        self.assertEqual(got["tasks"][0]["task_id"], "example")
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(session.calls[0][1]["json"]["params"]["name"], "grabowski_task_list")
        step2 = session.calls[1][1]["json"]["params"]
        self.assertEqual(step2["name"], "grip_run")
        self.assertEqual(step2["arguments"]["parameters"]["target_arguments"], original_args)
        self.assertEqual(step2["arguments"]["parameters"]["challenge_receipt_sha256"], challenge)
        self.assertEqual(step2["arguments"]["allow_mutation"], False)


    async def test_obligation_read_uses_exact_transport_challenge(self):
        obligation_id = "goo-nabu-1234567890abcdef1234"
        name, original_args = grabowski.read_request(
            "obligation", obligation_id=obligation_id
        )
        challenge = "a" * 64
        first = {"jsonrpc": "2.0", "id": 1, "result": {
            "isError": True,
            "content": [{"type": "text", "text": (
                "fresh intent-bound transport verification required; "
                "challenge_receipt_sha256=" + challenge
            )}],
        }}
        status = {
            "status": "passed",
            "output": {
                "obligation_id": obligation_id, "state": "open",
                "work_complete": False, "continuation_required": True,
            },
        }
        second = {"jsonrpc": "2.0", "id": 1, "result": {
            "structuredContent": {"status": "passed", "output": {
                "state": "executed", "target_result": status,
            }},
        }}
        encode = lambda obj: ("data: " + json.dumps(obj) + "\n\n").encode("utf-8")
        session = DummySession([
            DummyResponse(200, chunks=[encode(first)]),
            DummyResponse(200, chunks=[encode(second)]),
        ])
        got = await grabowski.mcp_call(session, name, original_args)
        self.assertEqual(grabowski.compact_result("obligation", got)["state"], "open")
        self.assertEqual(len(session.calls), 2)
        first_params = session.calls[0][1]["json"]["params"]
        self.assertEqual(first_params["arguments"], original_args)
        second_params = session.calls[1][1]["json"]["params"]
        self.assertEqual(second_params["name"], "grip_run")
        roundtrip = second_params["arguments"]
        self.assertEqual(roundtrip["name"], "transport-roundtrip")
        self.assertFalse(roundtrip["allow_mutation"])
        self.assertEqual(roundtrip["parameters"]["action"], "execute")
        self.assertEqual(roundtrip["parameters"]["challenge_receipt_sha256"], challenge)
        self.assertEqual(roundtrip["parameters"]["target_tool_name"], name)
        self.assertEqual(roundtrip["parameters"]["target_arguments"], original_args)

    async def test_challenge_does_not_admit_other_grips(self):
        challenge = "a" * 64
        failure = {"jsonrpc": "2.0", "id": 1, "result": {
            "isError": True,
            "content": [{"type": "text", "text":
                "fresh intent-bound transport verification required; "
                "challenge_receipt_sha256=" + challenge}],
        }}
        session = DummySession([DummyResponse(
            200, chunks=[("data: " + json.dumps(failure) + "\n\n").encode()]
        )])
        with self.assertRaises(grabowski.GrabowskiUnavailable):
            await grabowski.mcp_call(session, "grip_run", {
                "name": "operator-obligation-close",
                "parameters": {"obligation_id": "goo-nabu-1234567890abcdef1234"},
                "allow_mutation": False,
            })
        self.assertEqual(len(session.calls), 1)


class BrowserVoiceTransportChallengeTests(IsolatedAsyncioTestCase):
    async def test_exact_voice_browser_start_completes_challenge_once(self):
        challenge = "b" * 64
        first = {"jsonrpc": "2.0", "id": 1, "result": {
            "isError": True, "content": [{"type": "text", "text":
                "fresh intent-bound transport verification required; "
                "challenge_receipt_sha256=" + challenge}],
        }}
        target = {"task": {"task_id": "d" * 24, "launcher": {"returncode": 0}}}
        second = {"jsonrpc": "2.0", "id": 1, "result": {
            "structuredContent": {"status": "passed", "output": {
                "state": "executed", "target_result": target,
            }},
        }}
        encode = lambda obj: ("data: " + json.dumps(obj) + "\n\n").encode()
        session = DummySession([
            DummyResponse(200, chunks=[encode(first)]),
            DummyResponse(200, chunks=[encode(second)]),
        ])
        args = grabowski.chatgpt_voice_launch_args()
        result = await grabowski.mcp_call(session, "grabowski_task_start", args)
        self.assertEqual(result, target)
        self.assertEqual(len(session.calls), 2)
        roundtrip = session.calls[1][1]["json"]["params"]
        self.assertEqual(roundtrip["name"], "grip_run")
        self.assertEqual(roundtrip["arguments"]["parameters"]["target_arguments"], args)
        self.assertEqual(roundtrip["arguments"]["parameters"]["challenge_receipt_sha256"], challenge)
        self.assertTrue(roundtrip["arguments"]["allow_mutation"])

    async def test_no_generic_mutation_via_transport_challenge(self):
        challenge = "c" * 64
        denied = {"jsonrpc": "2.0", "id": 1, "result": {
            "isError": True, "content": [{"type": "text", "text":
                "fresh intent-bound transport verification required; "
                "challenge_receipt_sha256=" + challenge}],
        }}
        response = lambda: DummyResponse(
            200, chunks=[("data: " + json.dumps(denied) + "\n\n").encode()]
        )
        illegal = grabowski.chatgpt_voice_launch_args()
        illegal["argv"][-2] = "--profile-directory=Profile 1"
        for name, args in (
            ("grabowski_task_start", illegal),
            ("grabowski_terminal_run", {"argv": ["echo", "hello"]}),
        ):
            with self.subTest(name=name), self.assertRaises(grabowski.GrabowskiUnavailable):
                session = DummySession([response()])
                await grabowski.mcp_call(session, name, args)
            self.assertEqual(len(session.calls), 1)


class ChatGPTTextTransportChallengeTests(IsolatedAsyncioTestCase):
    async def test_only_canonical_text_draft_qualifies_for_mutating_roundtrip(self):
        challenge = "c" * 64
        err = {"jsonrpc": "2.0", "id": 1, "result": {
            "isError": True, "content": [{"type": "text", "text":
                "fresh intent-bound transport verification required; "
                "challenge_receipt_sha256=" + challenge}],
        }}
        accepted = {"jsonrpc": "2.0", "id": 1, "result": {
            "structuredContent": {"status": "passed", "output": {
                "state": "executed", "target_result": {
                    "task": {"task_id": "e" * 24, "launcher": {"returncode": 0}}
                },
            }},
        }}
        encode = lambda obj: ("data: " + json.dumps(obj) + "\n\n").encode()
        session = DummySession([
            DummyResponse(200, chunks=[encode(err)]),
            DummyResponse(200, chunks=[encode(accepted)]),
        ])
        bound = grabowski.chatgpt_text_launch_args("Nabu: Bitte teste den Status")
        answer = await grabowski.mcp_call(session, "grabowski_task_start", bound)
        self.assertEqual(answer["task"]["task_id"], "e" * 24)
        self.assertEqual(len(session.calls), 2)
        roundtrip = session.calls[1][1]["json"]["params"]["arguments"]
        self.assertTrue(roundtrip["allow_mutation"])
        self.assertEqual(roundtrip["parameters"]["target_arguments"], bound)
        self.assertEqual(roundtrip["parameters"]["challenge_receipt_sha256"], challenge)
        self.assertEqual(session.calls[0][1]["timeout"], {"total": 20, "connect": 4})
        self.assertEqual(session.calls[1][1]["timeout"], {"total": 60, "connect": 4})
        invalid = dict(bound, argv=[*bound["argv"][:-1], "https://chatgpt.com/c/fake"])
        denied = DummySession([DummyResponse(200, chunks=[encode(err)])])
        with self.assertRaises(grabowski.GrabowskiUnavailable):
            await grabowski.mcp_call(denied, "grabowski_task_start", invalid)
        self.assertEqual(len(denied.calls), 1)


    async def test_lost_browser_receipt_reports_uncertainty_without_retry(self):
        challenge = "c" * 64
        denied = {"jsonrpc": "2.0", "id": 1, "result": {
            "isError": True, "content": [{"type": "text", "text":
                "fresh intent-bound transport verification required; "
                "challenge_receipt_sha256=" + challenge}],
        }}

        class LostReceipt(DummyResponse):
            async def __aenter__(self):
                raise TimeoutError("receipt not delivered")

        session = DummySession([
            DummyResponse(200, chunks=[("data: " + json.dumps(denied) + "\n\n").encode()]),
            LostReceipt(200),
        ])
        with self.assertRaisesRegex(grabowski.GrabowskiUnavailable, "möglicherweise ausgelöst"):
            await grabowski.mcp_call(session, "grabowski_task_start",
                                     grabowski.chatgpt_text_launch_args("Status"))
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(session.calls[1][1]["timeout"]["total"], 60)


class GrabowskiDispatchTests(IsolatedAsyncioTestCase):
    def test_only_bounded_self_status_is_executable(self):
        legitimate = (
            "Prüfe jetzt nur seinen Gesundheitsstatus und wie viele MCP-Werkzeuge registriert sind.",
            "Fertig, wenn Healthy-Wert und Werkzeuganzahl belegt sind.",
        )
        self.assertTrue(grabowski._bounded_operator_status_request(*legitimate))
        self.assertTrue(grabowski._bounded_operator_status_request(
            "Kontrolliere seinen aktuellen Status und berichte Anzahl der registrierten Tools",
            "Status und Toolanzahl stehen fest",
        ))
        for objective, acceptance in (
            ("Starte einen Deploy und lösche alte Logs.",
             "Fertig, wenn die Produktion umgestellt ist."),
            ("Prüfe den Heim-PC-Status morgen.", "Liefere einen aktuellen Statusreport."),
            ("Prüfe den Grabowski-Status und deploye", legitimate[1]),
            ("Prüfe den Grabowski Status und die registrierten MCP Werkzeuge",
             "Fertig wenn Status healthy ist und Werkzeuganzahl belegt ist"),
            ("Prüfe den Grabowski-Status; rm -rf /", legitimate[1]),
            (legitimate[0], "Sichere eine Datenbank und belege Status"),
        ):
            with self.subTest(objective=objective):
                self.assertFalse(grabowski._bounded_operator_status_request(
                    objective, acceptance
                ))

    async def test_bounded_status_executes_once_and_reads_completed(self):
        from unittest.mock import AsyncMock
        import hashlib

        objective = "Prüfe jetzt nur seinen Gesundheitsstatus und wie viele MCP-Werkzeuge registriert sind."
        acceptance = "Fertig, wenn Healthy-Wert und Werkzeuganzahl belegt sind."
        obligation_id = "goo-nabu-" + hashlib.sha256(
            (objective + "\n" + acceptance).encode()
        ).hexdigest()[:20]
        begin = {"status": "passed", "receipt": {"status": "passed"},
                 "output": {"state": "challenge_pending",
                            "challenge_receipt_sha256": "a" * 64}}
        opened = {"status": "passed", "output": {
            "state": "executed", "target_result": {
                "status": "passed", "receipt_sha256": "b" * 64,
                "output": {"obligation_id": obligation_id, "state": "open"},
            }}}
        checked = {"healthy": False, "tool_contract": {"registered_tool_count": 208}}
        close_begin = {"status": "passed", "receipt": {"status": "passed"},
                       "output": {"state": "challenge_pending",
                                  "challenge_receipt_sha256": "c" * 64}}
        close_finish = {"status": "passed", "output": {
            "state": "executed", "target_result": {
                "status": "passed", "receipt_sha256": "d" * 64,
            }}}
        readback = {"status": "passed", "output": {
            "obligation_id": obligation_id, "state": "completed",
            "work_complete": True, "continuation_required": False,
            "missing_acceptance_ids": [],
        }}
        replies = [begin, opened, checked, close_begin, close_finish, readback]
        with mock.patch.object(
            grabowski, "mcp_call", new=AsyncMock(side_effect=replies)
        ) as invoke:
            data = await grabowski.register_obligation(
                object(), objective, acceptance
            )
        self.assertEqual(invoke.await_count, 6)
        self.assertEqual(data["status"], "completed_process_only")
        self.assertEqual(data["obligation_id"], obligation_id)
        self.assertEqual(data["receipt_sha256"], "d" * 64)
        self.assertEqual(data["completion_scope"], "process_only")
        self.assertFalse(data["healthy"])
        self.assertEqual(data["registered_tools"], 208)
        calls = invoke.await_args_list
        self.assertEqual(calls[2].args[1], "grabowski_status")
        first_close = calls[3].args[2]["parameters"]["target_arguments"]
        final_close = calls[4].args[2]["parameters"]["target_arguments"]
        self.assertEqual(first_close, final_close)
        self.assertEqual(first_close["name"], "operator-obligation-close")
        self.assertEqual(first_close["parameters"]["outcome"], "completed")
        self.assertFalse(
            first_close["parameters"]["closure_classification"]["convergence_required"]
        )
        self.assertEqual(calls[5].args[2]["name"], "operator-obligation-status")

    async def test_bounded_status_bad_read_never_closes(self):
        from unittest.mock import AsyncMock
        import hashlib

        objective = "Prüfe jetzt nur seinen Gesundheitsstatus und wie viele MCP-Werkzeuge registriert sind."
        acceptance = "Fertig, wenn Healthy-Wert und Werkzeuganzahl belegt sind."
        obligation_id = "goo-nabu-" + hashlib.sha256(
            (objective + "\n" + acceptance).encode()
        ).hexdigest()[:20]
        begin = {"status": "passed", "receipt": {"status": "passed"},
                 "output": {"state": "challenge_pending",
                            "challenge_receipt_sha256": "a" * 64}}
        opened = {"status": "passed", "output": {
            "state": "executed", "target_result": {
                "status": "passed", "receipt_sha256": "b" * 64,
                "output": {"obligation_id": obligation_id, "state": "open"},
            }}}
        with mock.patch.object(grabowski, "mcp_call", new=AsyncMock(
            side_effect=[begin, opened, {"healthy": True, "tool_contract": {}}]
        )) as invoke:
            result = await grabowski.register_obligation(
                object(), objective, acceptance
            )
        self.assertEqual(result["status"], "registered_execution_unconfirmed")
        self.assertEqual(invoke.await_count, 3)

    async def test_bounded_status_failed_close_not_retried(self):
        from unittest.mock import AsyncMock
        import hashlib

        objective = "Prüfe jetzt nur seinen Gesundheitsstatus und wie viele MCP-Werkzeuge registriert sind."
        acceptance = "Fertig, wenn Healthy-Wert und Werkzeuganzahl belegt sind."
        obligation_id = "goo-nabu-" + hashlib.sha256(
            (objective + "\n" + acceptance).encode()
        ).hexdigest()[:20]
        begin = {"status": "passed", "receipt": {"status": "passed"},
                 "output": {"state": "challenge_pending",
                            "challenge_receipt_sha256": "a" * 64}}
        opened = {"status": "passed", "output": {
            "state": "executed", "target_result": {
                "status": "passed", "receipt_sha256": "b" * 64,
                "output": {"obligation_id": obligation_id, "state": "open"},
            }}}
        checked = {"healthy": True, "tool_contract": {"registered_tool_count": 208}}
        close_begin = {"status": "passed", "receipt": {"status": "passed"},
                       "output": {"state": "challenge_pending",
                                  "challenge_receipt_sha256": "c" * 64}}
        with mock.patch.object(grabowski, "mcp_call", new=AsyncMock(
            side_effect=[begin, opened, checked, close_begin,
                         grabowski.GrabowskiUnavailable("unknown outcome")]
        )) as invoke:
            result = await grabowski.register_obligation(
                object(), objective, acceptance
            )
        self.assertEqual(result["status"], "registered_execution_unconfirmed")
        self.assertEqual(invoke.await_count, 5)

    async def test_bounded_status_replayed_completion_does_not_rerun(self):
        from unittest.mock import AsyncMock
        import hashlib

        objective = "Prüfe jetzt nur seinen Gesundheitsstatus und wie viele MCP-Werkzeuge registriert sind."
        acceptance = "Fertig, wenn Healthy-Wert und Werkzeuganzahl belegt sind."
        obligation_id = "goo-nabu-" + hashlib.sha256(
            (objective + "\n" + acceptance).encode()
        ).hexdigest()[:20]
        begin = {"status": "passed", "receipt": {"status": "passed"},
                 "output": {"state": "challenge_pending",
                            "challenge_receipt_sha256": "a" * 64}}
        replay = {"status": "passed", "output": {
            "state": "executed", "target_result": {
                "status": "passed", "receipt_sha256": "b" * 64,
                "output": {"obligation_id": obligation_id, "state": "completed",
                           "work_complete": True, "completion_scope": "process_only"},
            }}}
        with mock.patch.object(grabowski, "mcp_call", new=AsyncMock(
            side_effect=[begin, replay]
        )) as invoke:
            result = await grabowski.register_obligation(
                object(), objective, acceptance
            )
        self.assertEqual(result["status"], "completed_process_only")
        self.assertEqual(invoke.await_count, 2)

    async def test_operator_obligation_uses_exact_single_use_target(self):
        from unittest.mock import AsyncMock
        accepted = {
            "status": "passed",
            "output": {"state": "challenge_pending",
                       "challenge_receipt_sha256": "a" * 64},
            "receipt": {"status": "passed"},
        }
        finished = {
            "status": "passed",
            "output": {"state": "executed",
                       "target_result": {"status": "passed", "receipt_sha256": "b" * 64}},
        }
        with mock.patch.object(grabowski, "mcp_call",
                               new=AsyncMock(side_effect=[accepted, finished])) as f:
            result = await grabowski.register_obligation(
                object(), "Prüfe den Heim-PC-Status morgen.",
                "Liefere einen aktuellen, belegten Statusreport.",
            )
        self.assertEqual(result["status"], "registered_not_executed")
        self.assertEqual(result["receipt_sha256"], "b" * 64)
        self.assertEqual(f.await_count, 2)
        first = f.await_args_list[0].args[2]["parameters"]
        second = f.await_args_list[1].args[2]["parameters"]
        self.assertEqual(first["action"], "begin")
        self.assertEqual(second["action"], "execute")
        self.assertEqual(first["target_arguments"], second["target_arguments"])
        self.assertEqual(second["challenge_receipt_sha256"], "a" * 64)
        self.assertEqual(first["target_arguments"]["parameters"]["acceptance"][0]["id"], "result")

    async def test_grabowski_does_not_claim_blocked_effect(self):
        from unittest.mock import AsyncMock
        accepted = {
            "status": "passed",
            "output": {"state": "challenge_pending",
                       "challenge_receipt_sha256": "a" * 64},
            "receipt": {"status": "passed"},
        }
        blocked = {
            "status": "passed",
            "output": {"state": "executed",
                       "target_result": {"status": "blocked", "output": {"error": "denied"}}},
        }
        with mock.patch.object(grabowski, "mcp_call",
                               new=AsyncMock(side_effect=[accepted, blocked])):
            with self.assertRaises(grabowski.GrabowskiUnavailable):
                await grabowski.register_obligation(
                    object(), "Prüfe den aktuellen Laufzeitstatus.",
                    "Liefere eine belegte aktuelle Runtime-Einschätzung.",
                )

    async def test_invalid_work_does_not_call_grabowski(self):
        from unittest.mock import AsyncMock
        with mock.patch.object(grabowski, "mcp_call", new=AsyncMock()) as f:
            with self.assertRaises(ValueError):
                await grabowski.register_obligation(object(), "x", "not enough")
            self.assertEqual(f.await_count, 0)


class ChatGPTToolTests(IsolatedAsyncioTestCase):
    async def test_without_auth_never_calls_openai(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "missing.json"
            session = DummySession([])
            with self.assertRaises(chatgpt.ChatGPTUnavailable):
                await chatgpt.chatgpt_answer(session, "Frage", path)
            self.assertEqual(session.calls, [])

    async def test_success_requires_completed_and_streams(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            login.save_private(path, {
                "client_id": "oaiapp_test", "model_slug": "example-model",
                "access_token": "private", "refresh_token": "refresh",
                "scopes": ["chatgpt.tokens.use.direct"], "plan_usage_enabled": True,
                "expires_in": 3600, "saved_at_unix": int(time.time()),
            })
            event = lambda data: ("event: message\ndata: " + json.dumps(data) + "\n\n").encode()
            response = DummyResponse(200, chunks=[
                event({"type": "response.output_text.delta", "delta": "Test "}),
                event({"type": "response.output_text.delta", "delta": "bestanden."}),
                event({"type": "response.completed"}),
            ])
            session = DummySession([response])
            result = await chatgpt.chatgpt_answer(session, "Hallo", path)
            self.assertEqual(result["answer"], "Test bestanden.")
            self.assertEqual(session.calls[0][1]["json"]["store"], False)
            self.assertEqual(session.calls[0][1]["json"]["stream"], True)
            self.assertNotIn("max_output_tokens", session.calls[0][1]["json"])
            self.assertNotIn("private", json.dumps(result))

    async def test_stream_preserves_unicode_across_network_chunks(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            login.save_private(path, {
                "client_id": "oaiapp_test", "model_slug": "example-model",
                "access_token": "private", "refresh_token": "refresh",
                "scopes": ["chatgpt.tokens.use.direct"], "plan_usage_enabled": True,
                "expires_in": 3600, "saved_at_unix": int(time.time()),
            })
            event = lambda data: (
                "data: " + json.dumps(data, ensure_ascii=False) + "\n\n"
            ).encode("utf-8")
            answer = event({"type": "response.output_text.delta", "delta": "Grüße"})
            cut = answer.index("ü".encode("utf-8")) + 1
            chunks = [answer[:cut], answer[cut:], event({"type": "response.completed"})]
            result = await chatgpt.chatgpt_answer(
                DummySession([DummyResponse(200, chunks=chunks)]), "Hallo", path
            )
            self.assertEqual(result["answer"], "Grüße")
            self.assertNotIn("\ufffd", result["answer"])

    async def test_incomplete_and_failed_are_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            login.save_private(path, {
                "client_id": "oaiapp_test", "model_slug": "example-model",
                "access_token": "private", "refresh_token": "refresh",
                "scopes": ["chatgpt.tokens.use.direct"], "plan_usage_enabled": True,
                "expires_in": 3600, "saved_at_unix": int(time.time()),
            })
            for events in (['{"type":"response.output_text.delta","delta":"Hallo"}'],
                           ['{"type":"response.failed","response":{"error":{"code":"usage_limit"}}}'],
                           ['{"type":"response.failed","response":null}']):
                response = DummyResponse(
                    200, chunks=[("data: " + raw + "\n\n").encode() for raw in events],
                )
                with self.subTest(events=events), self.assertRaises(chatgpt.ChatGPTUnavailable):
                    await chatgpt.chatgpt_answer(DummySession([response]), "Hallo", path)

    async def test_final_event_without_blank_line_terminator_completes(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            login.save_private(path, {
                "client_id": "oaiapp_test", "model_slug": "example-model",
                "access_token": "private", "refresh_token": "refresh",
                "scopes": ["chatgpt.tokens.use.direct"], "plan_usage_enabled": True,
                "expires_in": 3600, "saved_at_unix": int(time.time()),
            })
            response = DummyResponse(200, chunks=[
                b'data: {"type":"response.output_text.delta","delta":"Fertig"}\n\n',
                b'data: {"type":"response.completed"}',
            ])
            result = await chatgpt.chatgpt_answer(DummySession([response]), "Hallo", path)
            self.assertEqual(result["answer"], "Fertig")

    async def test_rotating_refresh_token_is_persisted(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "auth.json"
            login.save_private(path, {
                "client_id": "oaiapp_test", "model_slug": "example-model",
                "access_token": "old", "refresh_token": "refresh_old",
                "scopes": ["chatgpt.tokens.use.direct"], "plan_usage_enabled": True,
                "expires_in": 1, "saved_at_unix": 1,
            })
            session = DummySession([DummyResponse(200, data={
                "access_token": "new", "refresh_token": "refresh_new",
                "expires_in": 3600, "scope": "chatgpt.tokens.use.direct",
            })])
            record = await chatgpt.authorized_session(session, path)
            self.assertEqual(record["access_token"], "new")
            self.assertEqual(login.load_private(path)["refresh_token"], "refresh_new")
            self.assertEqual(path.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    import unittest
    unittest.main()
