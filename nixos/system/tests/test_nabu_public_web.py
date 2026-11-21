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
        self.body = content

    async def _read(self, maximum):
        return self.body[:maximum]

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
        if isinstance(node, ast.ClassDef) and node.name == "PublicResolver":
            chosen.append(node)
        if isinstance(node, ast.ClassDef) and node.name == "WebRead":
            method = next(n for n in node.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "async_call")
            method.name = "call_web_read"
            method.returns = None
            for argument in method.args.args:
                argument.annotation = None
            chosen.append(method)
    assert len(chosen) == 3, "Expected production URL/resolver/WebRead source"
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


if __name__ == "__main__":
    unittest.main()