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

    def test_summary_never_includes_secrets(self):
        result = {"healthy": True, "secret": "NEVER", "runtime": {"release_id": "r"},
                  "tool_contract": {"registered_tool_count": 208}}
        data = grabowski.compact_result("status", result)
        self.assertNotIn("NEVER", json.dumps(data))
        self.assertEqual(data["registered_tools"], 208)


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
        metadata = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"issuer": login.ISSUER,
                          "jwks_uri": login.ISSUER + "/.well-known/jwks.json"},
        )
        keys = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"keys": [{"kid": "test", "kty": "RSA",
                                    "alg": "RS256", "n": n_b64, "e": "AQAB"}]},
        )
        with mock.patch.object(login.requests, "get", side_effect=[metadata, keys] * 5):
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


class GrabowskiDispatchTests(IsolatedAsyncioTestCase):
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
            self.assertNotIn("private", json.dumps(result))

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
                           ['{"type":"response.failed","response":{"error":{"code":"usage_limit"}}}']):
                response = DummyResponse(
                    200, chunks=[("data: " + raw + "\n\n").encode() for raw in events],
                )
                with self.subTest(events=events), self.assertRaises(chatgpt.ChatGPTUnavailable):
                    await chatgpt.chatgpt_answer(DummySession([response]), "Hallo", path)

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