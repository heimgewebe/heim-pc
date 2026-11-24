"""Offline tests for Nabu's dedicated Open-Meteo weather tool."""
from __future__ import annotations

import ast
import asyncio
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "nabu" / "llm.py"

FORECAST = {
    "current": {"temperature_2m": 6.6, "apparent_temperature": 3.2,
                "weather_code": 61, "wind_speed_10m": 18.4},
    "daily": {
        "time": ["2026-11-24", "2026-11-25", "2026-11-26"],
        "weather_code": [61, 3, 71],
        "temperature_2m_min": [2.1, -0.6, -3.4],
        "temperature_2m_max": [7.4, 5.0, 0.2],
        "precipitation_sum": [4.26, 0.0, 1.0],
        "precipitation_probability_max": [90, 10, 60],
    },
}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def raise_for_status(self):
        return None

    async def json(self, content_type=None):
        return self.payload


class FakeSession:
    responses: list = []
    requests: list = []

    def __init__(self, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def get(self, url, params=None):
        self.requests.append((url, params))
        return FakeResponse(self.responses.pop(0))


def load():
    root = ast.parse(SOURCE.read_text(encoding="utf-8"))
    chosen = []
    for node in root.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in ("WEATHER_CODES", "WEEKDAYS", "HOME_WORDS")
                for t in node.targets):
            chosen.append(node)
        if isinstance(node, ast.FunctionDef) and node.name in ("spoken_number", "weather_report"):
            chosen.append(node)
        if isinstance(node, ast.ClassDef) and node.name == "WeatherForecast":
            method = next(n for n in node.body
                          if isinstance(n, ast.AsyncFunctionDef) and n.name == "async_call")
            method.name = "call_weather"
            method.returns = None
            for argument in method.args.args:
                argument.annotation = None
            chosen.append(method)
    assert len(chosen) == 6, "Expected weather constants, helpers and tool call"
    namespace = {
        "datetime": datetime, "asyncio": asyncio,
        "WEATHER_TIMEOUT": None,
        "message": lambda exc: SimpleNamespace(data={"error": str(exc)}, error=True),
        "ToolResult": lambda data: SimpleNamespace(data=data, error=False),
        "aiohttp": SimpleNamespace(ClientSession=FakeSession,
                                   ClientError=type("ClientError", (Exception,), {})),
    }
    module = ast.fix_missing_locations(ast.Module(body=chosen, type_ignores=[]))
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace


class WeatherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = load()

    def setUp(self):
        FakeSession.responses = []
        FakeSession.requests = []

    def call(self, args, hass=None):
        hass = hass or SimpleNamespace(config=SimpleNamespace(latitude=53.55, longitude=10.0))
        return asyncio.run(self.ns["call_weather"](
            None, hass, SimpleNamespace(tool_args=args), None))

    def test_spoken_numbers_for_german_tts(self):
        n = self.ns["spoken_number"]
        self.assertEqual("7", n(6.6))
        self.assertEqual("minus 3", n(-3.4))
        self.assertEqual("0", n(-0.3))
        self.assertEqual("4,3", n(4.26, 1))
        self.assertEqual("0", n(-0.04, 1))
        self.assertIsNone(n(None))

    def test_report_is_short_and_speakable(self):
        report = self.ns["weather_report"]("Hamburg", FORECAST)
        self.assertEqual(
            "In Hamburg sind es gerade 7 Grad, gefühlt 3, leichter Regen, "
            "Wind 18 Kilometer pro Stunde. Heute leichter Regen, 2 bis 7 Grad, "
            "Regenrisiko 90 Prozent, 4,3 Millimeter. Morgen bedeckt, minus 1 bis "
            "5 Grad, Regenrisiko 10 Prozent.", report["zusammenfassung"])
        self.assertEqual(["heute", "morgen", "Donnerstag"], [d["tag"] for d in report["tage"]])
        self.assertEqual("leichter Schneefall", report["tage"][2]["lage"])

    def test_empty_forecast_is_an_error_not_a_guess(self):
        with self.assertRaises(ValueError):
            self.ns["weather_report"]("Hamburg", {})

    def test_named_place_is_geocoded_first(self):
        FakeSession.responses = [
            {"results": [{"name": "Wien", "latitude": 48.2, "longitude": 16.37}]}, FORECAST]
        result = self.call({"location": "Wien"})
        self.assertFalse(result.error)
        self.assertEqual("Wien", result.data["ort"])
        self.assertIn("geocoding-api.open-meteo.com", FakeSession.requests[0][0])
        self.assertEqual("48.2", FakeSession.requests[1][1]["latitude"])

    def test_missing_location_uses_home_assistant_home(self):
        FakeSession.responses = [FORECAST]
        result = self.call({})
        self.assertFalse(result.error)
        self.assertEqual("zu Hause", result.data["ort"])
        self.assertEqual(1, len(FakeSession.requests))
        self.assertEqual("53.55", FakeSession.requests[0][1]["latitude"])

    def test_unknown_place_reports_error(self):
        FakeSession.responses = [{"results": []}]
        result = self.call({"location": "Nirgendwohausen"})
        self.assertTrue(result.error)
        self.assertIn("nicht gefunden", result.data["error"])


if __name__ == "__main__":
    unittest.main()
