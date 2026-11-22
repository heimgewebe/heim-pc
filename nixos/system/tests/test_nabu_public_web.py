"""Offline security contract tests for Nabu's public WebRead tool."""
from __future__ import annotations

import ast
import asyncio
import ipaddress
from pathlib import Path
import re
import socket
from types import SimpleNamespace
import unittest
from urllib.parse import urlsplit, urljoin


SOURCE = Path(__file__).resolve().parents[1] / "nabu" / "llm.py"


class Resolver:
    answers = [{"host": "8.8.8.8"}]

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return self.answers

    async def close(self):
        return None


class FakeResponse:
    def __init__(self, url, status=200, headers=None, content=b"<p>Public text</p>"):
        self.url = url
        self.status = status
        self.headers = headers or {"content-type": "text/html"}
        self.charset = "utf-8"
        self.content = SimpleNamespace(read=self._read)
        self.chunks = list(content) if isinstance(content, (tuple, list)) else [content]

    async def _read(self, maximum):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > maximum:
            self.chunks.insert(0, chunk[maximum:])
        return chunk[:maximum]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def raise_for_status(self):
        if self.status >= 400:
            raise ValueError("HTTP response error")


class FakeSession:
    responses = []
    requests = []

    def __init__(self, **kwargs):
        self.connector = kwargs["connector"]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def get(self, url, *, allow_redirects):
        assert allow_redirects is False, "Redirects must never auto-follow"
        self.requests.append(url)
        return FakeResponse(url, **self.responses.pop(0))


class Extractor:
    def feed(self, text):
        self.text = text

    def get_text(self):
        return self.text


def source_functions():
    root = ast.parse(SOURCE.read_text(encoding="utf-8"))
    chosen = []
    for node in root.body:
        if isinstance(node, ast.FunctionDef) and node.name == "public_url":
            chosen.append(node)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "read_bounded":
            chosen.append(node)
        if isinstance(node, ast.ClassDef) and node.name == "PublicResolver":
            chosen.append(node)
        if isinstance(node, ast.ClassDef) and node.name == "WebRead":
            method = next(n for n in node.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "async_call")
            method.name = "call_web_read"
            method.returns = None
            for argument in method.args.args:
                argument.annotation = None
            chosen.append(method)
    assert len(chosen) == 4, "Expected production URL/resolver/body-reader/WebRead source"
    namespace = {
        "ipaddress": ipaddress, "socket": socket, "re": re,
        "urlsplit": urlsplit, "urljoin": urljoin, "asyncio": asyncio,
        "TIMEOUT": None, "TextExtractor": Extractor,
        "message": lambda exc: SimpleNamespace(data={"error": str(exc)}, error=True),
        "ToolResult": lambda data: SimpleNamespace(data=data, error=False),
        "aiohttp": SimpleNamespace(
            abc=SimpleNamespace(AbstractResolver=object),
            resolver=SimpleNamespace(ThreadedResolver=Resolver),
            ClientError=type("ClientError", (Exception,), {}),
            TCPConnector=lambda **kwargs: kwargs,
            ClientSession=FakeSession,
        ),
    }
    module = ast.fix_missing_locations(ast.Module(body=chosen, type_ignores=[]))
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace


class PublicWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.functions = source_functions()

    def setUp(self):
        FakeSession.responses = []
        FakeSession.requests = []
        Resolver.answers = [{"host": "8.8.8.8"}]

    def test_private_and_ambiguous_numeric_hosts_are_rejected(self):
        check = self.functions["public_url"]
        for host in ("127.0.0.1", "127.1", "2130706433", "0x7f000001",
                     "0177.0.0.1", "192.168.1.1", "169.254.169.254",
                     "10.0.0.5", "[::1]", "localhost", "local.home.arpa"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                check("http://" + host + "/secret")
        self.assertEqual("https://example.org/", check("https://example.org/"))
        self.assertEqual("https://8.8.8.8/", check("https://8.8.8.8/"))

    def test_resolver_rejects_private_or_mixed_dns_answers(self):
        async def scenario():
            resolver = self.functions["PublicResolver"]()
            for addresses in (
                [{"host": "127.0.0.1"}],
                [{"host": "8.8.8.8"}, {"host": "10.0.0.1"}],
                [],
            ):
                Resolver.answers = addresses
                with self.assertRaises(ValueError):
                    await resolver.resolve("example.org")
            Resolver.answers = [{"host": "8.8.8.8"}, {"host": "1.1.1.1"}]
            self.assertEqual(2, len(await resolver.resolve("example.org")))
            await resolver.close()
        asyncio.run(scenario())

    def test_redirect_to_private_or_numeric_loopback_stops_before_request(self):
        async def scenario():
            for target in ("http://127.1/secret", "http://2130706433/private",
                           "http://192.168.1.2/admin"):
                FakeSession.responses = [{"status": 302, "headers": {"Location": target}}]
                FakeSession.requests = []
                result = await self.functions["call_web_read"](
                    None, None, SimpleNamespace(tool_args={"url": "https://example.org/"}), None
                )
                self.assertTrue(result.error, target)
                self.assertEqual(["https://example.org/"], FakeSession.requests)
        asyncio.run(scenario())

    def test_public_redirect_is_followed_once_and_text_returned(self):
        async def scenario():
            FakeSession.responses = [
                {"status": 302, "headers": {"Location": "/next"}},
                {"status": 200, "headers": {"content-type": "text/html"}},
            ]
            result = await self.functions["call_web_read"](
                None, None, SimpleNamespace(tool_args={"url": "https://example.org/"}), None
            )
            self.assertFalse(result.error)
            self.assertEqual("https://example.org/next", result.data["url"])
            self.assertEqual(["https://example.org/", "https://example.org/next"], FakeSession.requests)
        asyncio.run(scenario())


    def test_incremental_document_chunks_are_combined(self):
        async def scenario():
            FakeSession.responses = [{
                "status": 200,
                "headers": {"content-type": "text/html"},
                "content": [b"<p>First ", b"and second ", b"chunk</p>"],
            }]
            result = await self.functions["call_web_read"](
                None, None, SimpleNamespace(tool_args={"url": "https://example.org/"}), None
            )
            self.assertFalse(result.error)
            self.assertIn("First and second chunk", result.data["text"])
            self.assertEqual(["https://example.org/"], FakeSession.requests)
        asyncio.run(scenario())

    def test_bounded_reader_never_exceeds_requested_byte_limit(self):
        async def scenario():
            response = FakeResponse("https://example.org/", content=[b"abc", b"def", b"ghi"])
            self.assertEqual(b"abcde", await self.functions["read_bounded"](response.content, 5))
        asyncio.run(scenario())


    def test_live_market_index_requires_fresh_observation(self):
        root = ast.parse(SOURCE.read_text(encoding="utf-8"))
        fn = next(n for n in root.body if isinstance(n, ast.FunctionDef)
                  and n.name == "requires_live_sources")
        ns = {"re": re}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), str(SOURCE), "exec"), ns)
        live = ns["requires_live_sources"]
        for query in (
            "Wie steht der DAX gerade?", "Wie ist das Wetter in Hamburg?",
            "Vergleiche Stromtarife.", "Was hat die Bundesregierung heute beschlossen?",
        ):
            with self.subTest(query=query):
                self.assertTrue(live(query))
        for query in ("Was ist ein Regenbogen?", "Wie funktioniert der DAX?"):
            with self.subTest(query=query):
                self.assertFalse(live(query))

    def test_deep_answer_receives_facts_after_long_cookie_banner(self):
        # Execute DeepAnswer's actual production method with mocked source and
        # Ollama transport; 4.2 KB of page boilerplate preceded the fact.
        from datetime import datetime
        from zoneinfo import ZoneInfo
        import json
        root = ast.parse(SOURCE.read_text(encoding="utf-8"))
        deep = next(n for n in root.body if isinstance(n, ast.ClassDef)
                    and n.name == "DeepAnswer")
        method = next(n for n in deep.body if isinstance(n, ast.AsyncFunctionDef)
                      and n.name == "async_call")
        method.name = "call_deep"
        method.returns = None
        for arg in method.args.args:
            arg.annotation = None
        payloads = []

        class Search:
            async def async_call(self, *args):
                return SimpleNamespace(error=False, data={"results": [
                    {"title": "Public report", "url": "https://example.org/report"}]})

        class Read:
            async def async_call(self, *args):
                return SimpleNamespace(error=False, data={
                    "url": "https://example.org/report",
                    "text": ("Cookie consent and navigation. " * 150)
                    + "OFFICIAL_DATED_EVIDENCE_2026"})

        class Reply:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            def raise_for_status(self):
                pass

            async def json(self):
                return {"message": {"content": "No current claims without evidence."}}

        class Session:
            def post(self, url, *, json, timeout):
                payloads.append(json)
                return Reply()

        ns = {
            "re": re, "json": json, "datetime": datetime, "ZoneInfo": ZoneInfo,
            "WebSearch": Search, "WebRead": Read,
            "ToolInput": lambda **kwargs: SimpleNamespace(**kwargs),
            "public_url": lambda url: url,
            "requires_live_sources": lambda question: True,
            "async_get_clientsession": lambda hass: Session(),
            "aiohttp": SimpleNamespace(
                ClientTimeout=lambda **kwargs: None,
                ClientError=type("ClientError", (Exception,), {}),
            ),
            "ToolResult": lambda data: SimpleNamespace(data=data, error=False),
            "message": lambda exc: SimpleNamespace(data={"error": str(exc)}, error=True),
        }
        exec(compile(ast.fix_missing_locations(
            ast.Module(body=[method], type_ignores=[])), str(SOURCE), "exec"), ns)
        result = asyncio.run(ns["call_deep"](
            None, None, SimpleNamespace(tool_args={
                "question": "Was hat die Bundesregierung heute beschlossen?"}), None))
        self.assertFalse(result.error, result.data)
        self.assertIn("OFFICIAL_DATED_EVIDENCE_2026",
                      payloads[0]["messages"][1]["content"])
        self.assertEqual(["https://example.org/report"],
                         result.data["source_urls"])


if __name__ == "__main__":
    unittest.main()