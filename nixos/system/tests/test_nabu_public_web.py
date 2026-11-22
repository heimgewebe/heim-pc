"""Offline security contract tests for Nabu's public WebRead tool."""
from __future__ import annotations

import ast
import asyncio
from datetime import datetime
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import socket
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urljoin, quote, parse_qs
from zoneinfo import ZoneInfo


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
        self.max_field_size = kwargs.get("max_field_size")
        self.__class__.last_field_limit = self.max_field_size

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
        if isinstance(node, ast.ClassDef) and node.name == "TextExtractor":
            chosen.append(node)
        if isinstance(node, ast.FunctionDef) and node.name in (
                "relevant_source_excerpt", "search_subject_terms",
                "relevant_search_hits", "normalize_today_news_query"):
            chosen.append(node)
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
    assert len(chosen) == 9, "Expected URL/resolver/body reader/WebRead and evidence helpers"
    namespace = {
        "ipaddress": ipaddress, "socket": socket, "re": re,
        "HTMLParser": HTMLParser, "datetime": datetime,
        "urlsplit": urlsplit, "urljoin": urljoin, "asyncio": asyncio,
        "TIMEOUT": None,
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


    def test_websearch_fallback_rejects_poisoned_rss(self):
        """Source order is subject-validated, not whatever Bing RSS returned."""
        root = ast.parse(SOURCE.read_text(encoding="utf-8"))
        klass = next(x for x in root.body
                     if isinstance(x, ast.ClassDef) and x.name == "WebSearch")
        method = next(x for x in klass.body
                      if isinstance(x, ast.AsyncFunctionDef) and x.name == "async_call")
        method.name = "call_web_search"
        method.returns = None
        for argument in method.args.args:
            argument.annotation = None
        requests = []

        class SearchSession:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            def get(self, url, *, params):
                requests.append(url)
                if urlsplit(url).hostname == "html.duckduckgo.com":
                    return FakeResponse(url, status=202, content=b"anti-bot page")
                if urlsplit(url).hostname == "www.bing.com":
                    return FakeResponse(url, content=(
                        b"<rss><channel><item><title>YouTube</title>"
                        b"<link>https://www.youtube.com/</link>"
                        b"<description>Videos about other topics</description>"
                        b"</item></channel></rss>"))
                if urlsplit(url).hostname == "de.wikipedia.org":
                    return FakeResponse(url, content=json.dumps({
                        "pages": [
                            {"title": "Weltgesundheitsorganisation",
                             "key": "Weltgesundheitsorganisation",
                             "excerpt": "WHO and its Director-General"},
                            {"title": "Ebay Kleinanzeigen", "key": "Ebay_Kleinanzeigen",
                             "excerpt": "Unrelated offers"},
                        ]}).encode("utf-8"))
                self.fail("No unrelated provider should be requested")

        class Soup:
            def __init__(self, value, *_args):
                self.value = (value.decode("utf-8", errors="replace")
                              if isinstance(value, bytes) else value)

            def select(self, _selector):
                return []

            def get_text(self, *_args, **_kwargs):
                return self.value

        ns = {
            "aiohttp": SimpleNamespace(
                ClientSession=SearchSession,
                TCPConnector=lambda **kwargs: None,
                ClientError=type("ClientError", (Exception,), {})),
            "PublicResolver": lambda: None,
            "TIMEOUT": None, "BeautifulSoup": Soup,
            "re": re, "json": json, "quote": quote,
            "urlsplit": urlsplit, "parse_qs": parse_qs, "ET": ET,
            "asyncio": asyncio,
            "read_bounded": self.functions["read_bounded"],
            "search_subject_terms": self.functions["search_subject_terms"],
            "relevant_search_hits": self.functions["relevant_search_hits"],
            "ToolResult": lambda data: SimpleNamespace(data=data, error=False),
            "message": lambda exc: SimpleNamespace(data={"error": str(exc)}, error=True),
        }
        exec(compile(ast.fix_missing_locations(
            ast.Module(body=[method], type_ignores=[])), str(SOURCE), "exec"), ns)
        result = asyncio.run(ns["call_web_search"](
            None, None, SimpleNamespace(tool_args={
                "query": "Direktor der Weltgesundheitsorganisation WHO 2026"}), None))
        self.assertFalse(result.error, result.data)
        self.assertIn("Wikipedia", result.data["source"])
        self.assertEqual(
            ["https://de.wikipedia.org/wiki/Weltgesundheitsorganisation"],
            [x["url"] for x in result.data["results"]])
        self.assertEqual(3, len(requests))

    def test_unrelated_search_provider_results_are_not_evidence(self):
        keep = self.functions["relevant_search_hits"]
        noisy = [
            {"title": "YouTube", "url": "https://www.youtube.com/"},
            {"title": "Wer – Rechtschreibung", "url": "https://www.duden.de/rechtschreibung/wer"},
            {"title": "Nagelpilz behandeln", "excerpt": "Hilfreiche Behandlung",
             "url": "https://example.com/nagelpilz"},
            {"title": "Ebay Kleinanzeigen", "url": "https://example.com/ebay"},
        ]
        self.assertEqual([], keep(
            "Direktor der Weltgesundheitsorganisation WHO 2026", noisy))
        self.assertEqual([], keep(
            "Wer hat die Bundesregierung heute geleitet?", noisy))

    def test_relevant_search_provider_hits_keep_real_topic(self):
        keep = self.functions["relevant_search_hits"]
        official = {
            "title": "WHO Director-General",
            "excerpt": "Leadership and role at the World Health Organization",
            "url": "https://www.who.int/director-general/",
        }
        other = {"title": "Unrelated PowerPoint assistance",
                 "url": "https://example.org/ppt"}
        self.assertEqual([official], keep(
            "WHO Leitung 2026 Direktor", [other, official]))
        self.assertEqual([{
            "title": "Kindergeld Anspruch Regeln 2026",
            "url": "https://familienportal.de/leistungen/kindergeld"
        }], keep("Kindergeld Regeln 2026", [
            {"title": "Kindergeld Anspruch Regeln 2026",
             "url": "https://familienportal.de/leistungen/kindergeld"}]))

    def test_short_subject_anchors_keep_eu_vw_oil_without_false_eu_matches(self):
        keep = self.functions["relevant_search_hits"]
        for short, title in (
            ("EU", "EU Leitung"),
            ("VW", "VW Preisentwicklung"),
            ("Öl", "Ölpreis heute"),
        ):
            with self.subTest(subject=short):
                matched = {"title": title, "url": "https://example.org/facts"}
                unrelated = {"title": "Heute alles neu",
                             "url": "https://example.org/blog"}
                self.assertEqual([matched],
                                 keep(f"{short} Preis 2026", [unrelated, matched]))

    def test_specific_role_page_precedes_generic_organization_page(self):
        keep = self.functions["relevant_search_hits"]
        generic = {"title": "WHO", "url": "https://www.who.int/about"}
        director = {"title": "WHO Director-General",
                    "url": "https://www.who.int/director-general"}
        self.assertEqual([director, generic],
                         keep("WHO Leitung 2026 Direktor", [generic, director]))

    def test_cookie_gdpr_topic_sections_are_not_discarded(self):
        parser = self.functions["TextExtractor"]()
        parser.feed(
            "<html><body><section id='gdpr-information'>"
            "<p>Rechtsgrundlage: Art. 6 DSGVO.</p></section>"
            "<div class='cookie-consent'>Cookie notice</div></body></html>"
        )
        self.assertIn("Art. 6 DSGVO", parser.get_text())
        self.assertNotIn("Cookie notice", parser.get_text())

    def test_long_public_csp_header_reader_limit(self):
        async def scenario():
            FakeSession.responses = [{
                "status": 200,
                "headers": {"content-type": "text/html",
                            "content-security-policy": "default-src 'self'; " * 500},
            }]
            result = await self.functions["call_web_read"](
                None, None, SimpleNamespace(tool_args={
                    "url": "https://example.org/"}), None)
            self.assertFalse(result.error, result.data)
            self.assertEqual(32768, FakeSession.last_field_limit)
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


    def test_main_article_survives_long_navigation_and_consent_overlay(self):
        async def scenario():
            html = (
                "<html><body><header>" + "Navigation Links " * 1400
                + "</header><div class='cookie-consent'>"
                + "Consent notice " * 1000
                + "</div><main><article><header><h1>Offizieller Bericht</h1></header>"
                + "<p>Ergebnis: die Leitung wurde neu besetzt.</p></article></main>"
                + "<footer>Impressum Footer</footer></body></html>"
            )
            FakeSession.responses = [{
                "status": 200,
                "headers": {"content-type": "text/html"},
                "content": html.encode("utf-8"),
            }]
            result = await self.functions["call_web_read"](
                None, None, SimpleNamespace(tool_args={
                    "url": "https://example.org/report"}), None)
            self.assertFalse(result.error, result.data)
            self.assertIn("Leitung wurde neu besetzt", result.data["text"])
            self.assertIn("Offizieller Bericht", result.data["text"])
            self.assertNotIn("Consent notice", result.data["text"])
            self.assertNotIn("Navigation Links", result.data["text"])
        asyncio.run(scenario())

    def test_query_excerpts_recover_middle_fact_after_long_article(self):
        async def scenario():
            html = (
                "<main><article><h1>Bericht zur Institutsleitung</h1><p>"
                + ("Hintergrund ohne aktualisierte Details. " * 900)
                + "</p><h2>Institutsleitung seit November</h2>"
                + "<p>Die neue Institutsleitung ist Dr. Beispiel. "
                + "Die Entscheidung wurde bestätigt.</p><p>"
                + ("Weitere allgemeine Hintergrundinformationen. " * 750)
                + "</p></article></main>"
            )
            FakeSession.responses = [{
                "status": 200,
                "headers": {"content-type": "text/html"},
                "content": html.encode("utf-8"),
            }]
            result = await self.functions["call_web_read"](
                None, None, SimpleNamespace(tool_args={
                    "url": "https://example.org/report",
                    "question": "Wer leitet die Institutsleitung?"}), None)
            self.assertFalse(result.error, result.data)
            excerpt = result.data["text"]
            self.assertLessEqual(len(excerpt), 6000)
            self.assertIn("Dr. Beispiel", excerpt)
            self.assertIn("Bericht zur Institutsleitung", excerpt)
        asyncio.run(scenario())

    def test_direct_webread_remains_8k_bounded(self):
        async def scenario():
            html = "<main><article>" + ("Wissenschaftlicher Hintergrund. " * 2500) + "</article></main>"
            FakeSession.responses = [{
                "status": 200,
                "headers": {"content-type": "text/html"},
                "content": html.encode(),
            }]
            result = await self.functions["call_web_read"](
                None, None, SimpleNamespace(tool_args={
                    "url": "https://example.org/report"}), None)
            self.assertFalse(result.error)
            self.assertLessEqual(len(result.data["text"]), 8000)
        asyncio.run(scenario())


class NewsSearchBundlingTests(unittest.TestCase):
    """Current-news search itself reads sources, preventing model tool fanout."""

    def bundled(self, hits, news=True, unreadable=()):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        klass = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                     and n.name == "WebSearch")
        call = next(n for n in klass.body if isinstance(n, ast.AsyncFunctionDef)
                    and n.name == "async_call")
        helper = next(n for n in ast.walk(call) if isinstance(n, ast.AsyncFunctionDef)
                      and n.name == "search_result")
        calls = []

        class Reader:
            async def async_call(self, _hass, tool, _context):
                url = tool.tool_args["url"]
                calls.append(url)
                return SimpleNamespace(error=url in unreadable, data={
                    "url": url, "text": "A dated, readable article. " * 40,
                })

        ns = {
            "query": "Nachrichten heute", "is_news": news,
            "hass": None, "llm_context": None, "asyncio": asyncio,
            "urlsplit": urlsplit, "re": re,
            "aiohttp": SimpleNamespace(ClientError=type("ClientError", (Exception,), {})),
            "ToolInput": lambda **kw: SimpleNamespace(**kw),
            "ToolResult": lambda data: SimpleNamespace(data=data, error=False),
            "WebRead": Reader,
        }
        exec(compile(ast.fix_missing_locations(ast.Module(
            body=[helper], type_ignores=[])), str(SOURCE), "exec"), ns)
        async def execute():
            ns["news_deadline"] = asyncio.get_running_loop().time() + 25
            return await ns["search_result"]("DuckDuckGo", hits)

        result = asyncio.run(execute())
        return result.data, calls

    def test_news_reads_three_distinct_sources_and_skips_failed_read(self):
        hits = [{"title": name, "url": "https://" + host + ".example/article"}
                for name, host in (("A", "a"), ("A duplicate", "a"),
                                   ("B", "b"), ("C", "c"), ("D", "d"))]
        failed = hits[2]["url"]
        data, calls = self.bundled(hits, unreadable=(failed,))
        self.assertEqual(["A", "C", "D"],
                         [s["title"] for s in data["read_sources"]])
        self.assertEqual([hits[i]["url"] for i in (0, 2, 3, 4)], calls)
        self.assertEqual("read", data["source_read_status"])
        self.assertEqual([x["url"] for x in data["read_sources"]],
                         [x["url"] for x in data["results"]])
        self.assertTrue(all(len(s["text"]) > 350 for s in data["read_sources"]))

    def test_unreadable_news_is_not_labeled_read(self):
        hits = [{"title": "Paywall", "url": "https://a.example/article"}]
        data, _ = self.bundled(hits, unreadable=(hits[0]["url"],))
        self.assertEqual([], data["read_sources"])
        self.assertEqual([], data["results"])
        self.assertEqual("unavailable", data["source_read_status"])

    def test_long_signed_source_url_remains_exact_after_read(self):
        long_url = "https://news.example/story/" + ("a" * 710) + "?sig=abc123"
        data, calls = self.bundled([{"title": "News", "url": long_url}])
        self.assertEqual([long_url], calls)
        self.assertEqual("read", data["source_read_status"])
        self.assertEqual(long_url, data["read_sources"][0]["url"])
        self.assertEqual(long_url, data["results"][0]["url"])

    def test_generic_websearch_has_no_extra_reads(self):
        hits = [{"title": "WHO", "url": "https://who.int/about"}]
        data, calls = self.bundled(hits, news=False)
        self.assertEqual([], calls)
        self.assertEqual(hits, data["results"])
        self.assertNotIn("read_sources", data)


    def search_with_provider_fallback(self, query, failed_urls=()):
        """Execute production WebSearch with fake providers and real relevance filter."""
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        klass = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                     and n.name == "WebSearch")
        method = next(n for n in klass.body if isinstance(n, ast.AsyncFunctionDef)
                      and n.name == "async_call")
        method.name = "call_search"
        method.returns = None
        for arg in method.args.args:
            arg.annotation = None
        provider_calls, read_calls = [], []

        class Anchor:
            def get(self, key, default=""):
                return "https://ddg.example/news" if key == "href" else default

            def get_text(self, *args, **kwargs):
                return query

        class Item:
            def select_one(self, selector):
                return Anchor() if selector == "a.result__a" else None

        class Soup:
            def __init__(self, body, *_args):
                self.body = body

            def select(self, selector):
                return [Item()] if selector == ".result" and self.body == b"ddg" else []

            def get_text(self, *_args, **_kwargs):
                return ""

        class Session:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                pass

            def get(self, url, *, params):
                provider_calls.append(url)
                host = urlsplit(url).hostname
                if host == "html.duckduckgo.com":
                    return FakeResponse(url, content=b"ddg")
                if host == "www.bing.com":
                    return FakeResponse(url, content=(
                        "<rss><channel><item><title>Nachrichten heute</title>"
                        "<link>https://bing.example/report</link>"
                        "<description>Nachrichten der Welt heute</description>"
                        "</item></channel></rss>"
                    ).encode())
                if host == "news.google.com":
                    return FakeResponse(url, content=(
                        "<rss><channel><item><title>Nachrichten heute</title>"
                        "<link>https://news.example/report</link>"
                        "<description>Nachrichten der Welt heute</description>"
                        "</item></channel></rss>"
                    ).encode())
                self.fail("Unexpected provider: " + str(host))

        class Reader:
            async def async_call(self, hass, tool, context):
                url = tool.tool_args["url"]
                read_calls.append(url)
                return SimpleNamespace(error=url in failed_urls, data={
                    "url": url, "text": "Dated article content. " * 45,
                })

        functions = source_functions()

        class FakeDateTime:
            @staticmethod
            def now(_zone):
                return datetime(2026, 11, 22)

        ns = {
            "aiohttp": SimpleNamespace(
                ClientSession=Session,
                TCPConnector=lambda **kwargs: None,
                ClientError=type("ClientError", (Exception,), {})),
            "PublicResolver": lambda: None, "TIMEOUT": None,
            "BeautifulSoup": Soup, "re": re, "json": json, "quote": quote,
            "urlsplit": urlsplit, "parse_qs": parse_qs,
            "ET": ET, "asyncio": asyncio,
            "read_bounded": functions["read_bounded"],
            "search_subject_terms": functions["search_subject_terms"],
            "relevant_search_hits": functions["relevant_search_hits"],
            "normalize_today_news_query": functions["normalize_today_news_query"],
            "datetime": FakeDateTime, "ZoneInfo": ZoneInfo,
            "ToolInput": lambda **kw: SimpleNamespace(**kw),
            "ToolResult": lambda data: SimpleNamespace(data=data, error=False),
            "WebRead": Reader,
            "message": lambda error: SimpleNamespace(
                error=True, data={"error": str(error)}),
        }
        exec(compile(ast.fix_missing_locations(ast.Module(
            body=[method], type_ignores=[])), str(SOURCE), "exec"), ns)
        result = asyncio.run(ns["call_search"](
            None, None, SimpleNamespace(tool_args={"query": query}), None))
        return result.data, provider_calls, read_calls

    def test_todays_news_discards_model_invented_past_calendar(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "normalize_today_news_query")
        ns = {"re": re}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), str(SOURCE), "exec"), ns)
        normal = ns["normalize_today_news_query"]
        today = datetime(2026, 11, 22)
        for original in ("Nachrichten Schlagzeilen heute 15. Februar 2026",
                         "Nachrichten heute 11. Juni 2026",
                         "Nachrichten heute 2026-02-11"):
            with self.subTest(query=original):
                corrected = normal(original, today)
                self.assertIn("22.11.2026", corrected)
                self.assertNotIn("Februar", corrected)
                self.assertNotIn("Juni", corrected)
                self.assertNotIn("2026-02-11", corrected)
        historical = "Nachrichten vom 15. Februar 2026"
        self.assertEqual(historical, normal(historical, today))
        self.assertIn("normalize_today_news_query(", SOURCE.read_text(encoding="utf-8"))

    def test_news_websearch_rewrites_invented_model_calendar(self):
        data, _, _ = self.search_with_provider_fallback(
            "Nachrichten Schlagzeilen heute 15. Februar 2026")
        self.assertIn("22.11.2026", data["query"])
        self.assertNotIn("Februar", data["query"])
        self.assertNotIn("15.", data["query"])
        self.assertEqual("DuckDuckGo", data["source"])
        self.assertEqual("read", data["source_read_status"])

    def test_today_without_news_intent_preserves_direct_search_results(self):
        for query in ("Ölpreis heute", "Öffnungszeiten heute"):
            with self.subTest(query=query):
                data, providers, reads = self.search_with_provider_fallback(query)
                self.assertEqual("DuckDuckGo", data["source"])
                self.assertEqual([], reads)
                self.assertNotIn("read_sources", data)
                self.assertEqual(1, len(data["results"]))
                self.assertEqual(1, len(providers))

    def test_failed_news_first_provider_continues_to_bing(self):
        data, providers, reads = self.search_with_provider_fallback(
            "Nachrichten heute",
            failed_urls=("https://ddg.example/news",))
        self.assertEqual("Bing RSS", data["source"])
        self.assertEqual("read", data["source_read_status"])
        self.assertEqual(["https://ddg.example/news",
                          "https://bing.example/report"], reads)
        self.assertEqual(2, len(providers))
        self.assertEqual(["https://bing.example/report"],
                         [x["url"] for x in data["read_sources"]])

    def test_all_news_providers_unreadable_yields_no_sourced_claim(self):
        urls = ("https://ddg.example/news", "https://bing.example/report",
                "https://news.example/report")
        data, providers, reads = self.search_with_provider_fallback(
            "Schlagzeilen Nachrichten heute", failed_urls=urls)
        self.assertEqual("unavailable", data["source"])
        self.assertEqual("unavailable", data["source_read_status"])
        self.assertEqual([], data["results"])
        self.assertEqual([], data["read_sources"])
        self.assertEqual(list(urls), reads)
        self.assertEqual(3, len(providers))


if __name__ == "__main__":
    unittest.main()