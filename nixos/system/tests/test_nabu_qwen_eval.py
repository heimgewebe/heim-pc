"""Offline invariants for the synthetic Nabu Qwen benchmark; never invoke Ollama."""
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "scripts/nabu_qwen_eval.py"
SPEC = importlib.util.spec_from_file_location("nabu_qwen_eval", MODULE)
assert SPEC is not None and SPEC.loader is not None
nabu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nabu)


class NabuQwenEvalTest(unittest.TestCase):
    def test_exactly_one_hundred_frozen_distinct_cases(self):
        cases, _ = nabu.validate_fixture()
        self.assertEqual(100, len(cases))
        self.assertEqual(10, len({x["family"] for x in cases}))
        self.assertEqual(100, len({x["id"] for x in cases}))
        self.assertEqual(100, len({x["prompt"].casefold() for x in cases}))
        self.assertEqual(7, sum(x["critical"] for x in cases))

    def test_actual_public_nabu_tool_prompt_is_included(self):
        prompt = nabu.registered_nabu_prompt()
        self.assertIn("WICHTIG: Bei heute/aktuell/neueste", prompt)
        self.assertIn("WICHTIG: Eine konkrete Aktion hat immer Vorrang", prompt)
        self.assertIn("nabu_web__play_music", prompt)
        self.assertIn("nabu_web__search", prompt)

    def test_same_input_same_digest(self):
        a, tools = nabu.validate_fixture()
        b, other = nabu.validate_fixture()
        self.assertEqual(nabu.digest(a), nabu.digest(b))
        self.assertEqual(nabu.digest(tools), nabu.digest(other))
        self.assertEqual(11, len(tools))

    def test_reject_null_music_parameters(self):
        self.assertFalse(nabu.valid_arguments("nabu_web__play_music", {"media_id": None}))
        self.assertFalse(nabu.valid_arguments("nabu_web__play_music", {"artist": None}))
        self.assertTrue(nabu.valid_arguments("nabu_web__play_music", {}))
        self.assertTrue(nabu.valid_arguments("nabu_web__play_music", {"media_id": "Bakerman"}))
        self.assertFalse(nabu.valid_arguments("nabu_web__play_music", {"media_type": "wrong"}))

    def test_reject_wrong_or_missing_arguments(self):
        self.assertFalse(nabu.valid_arguments("nabu_web__search", {"query": ""}))
        self.assertFalse(nabu.valid_arguments("nabu_web__grabowski_request", {"objective": "test"}))
        self.assertFalse(nabu.valid_arguments("nabu_web__grabowski", {"operation": "delete"}))
        self.assertFalse(nabu.valid_arguments("nabu_web__browser", {"operation": "shell"}))
        self.assertFalse(nabu.valid_arguments("climate__HassClimateSetTemperature", {"temperature": 21}))
        self.assertTrue(nabu.valid_arguments("climate__HassClimateSetTemperature", {"area": "Flur", "temperature": 21}))

    def test_browser_operation_specific_required_arguments(self):
        good = nabu.valid_arguments
        self.assertFalse(good("nabu_web__browser", {"operation": "open"}))
        self.assertFalse(good("nabu_web__browser", {"operation": "open", "url": ""}))
        self.assertTrue(good("nabu_web__browser", {"operation": "open", "url": "https://example.com"}))
        self.assertTrue(good("nabu_web__browser", {"operation": "open", "url": "http://a"}))
        self.assertFalse(good("nabu_web__browser", {"operation": "click"}))
        self.assertTrue(good("nabu_web__browser", {"operation": "click", "target": "More information"}))
        self.assertFalse(good("nabu_web__browser", {"operation": "type", "target": "Suche"}))
        self.assertFalse(good("nabu_web__browser", {"operation": "type", "value": "Wetter"}))
        self.assertTrue(good("nabu_web__browser", {"operation": "type", "target": "Suche", "value": "Wetter"}))
        self.assertTrue(good("nabu_web__browser", {"operation": "scroll"}))
        self.assertTrue(good("nabu_web__browser", {"operation": "inspect"}))

    def test_multiple_calls_are_recorded_and_unexpected_action_fails(self):
        case = next(x for x in nabu.cases() if x["id"] == "music-01")
        message = {"tool_calls": [
            {"function": {"name": "nabu_web__play_music", "arguments": {"media_id": "Bakerman"}}},
            {"function": {"name": "intent__HassTurnOn", "arguments": {"name": "Licht"}}},
        ]}
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(nabu, "validate_fixture", return_value=([case], [])), \
                 patch.object(nabu, "model_identity", return_value={"name": nabu.MODEL, "digest": "a" * 64}), \
                 patch.object(nabu, "chat", return_value=({"message": message, "load_duration": 0}, 0.1)):
                self.assertEqual(0, nabu.run("run", nabu.MODEL, 30, Path(temp)))
            results = list(Path(temp).glob("*.jsonl"))
            self.assertEqual(1, len(results))
            rows = [json.loads(line) for line in results[0].read_text().splitlines()]
            case_result = next(x for x in rows if x.get("record") == "case")
            self.assertEqual(2, len(case_result["tool_calls"]))
            self.assertFalse(case_result["pass"])
            self.assertTrue(case_result["critical"])
            summary = next(Path(temp).glob("*.summary.json"))
            self.assertEqual(1, json.loads(summary.read_text())["critical_failures"])

    def test_critical_no_action_and_ambiguous_device(self):
        cases = {x["id"]: x for x in nabu.cases()}
        self.assertTrue(nabu.score(cases["answer-01"], "answer", {}, "Leistung ist ..."))
        self.assertFalse(nabu.score(cases["answer-01"], "nabu_web__play_music", {}, ""))
        self.assertFalse(nabu.score(cases["device-10"], "intent__HassTurnOn", {"name": "Licht"}, ""))
        self.assertTrue(nabu.score(cases["device-10"], "answer", {}, "Welches Licht meinst du?"))
        self.assertFalse(nabu.score(cases["device-10"], "answer", {}, "Erledigt."))

    def test_empty_answer_is_not_success(self):
        case = nabu.cases()[0]
        self.assertFalse(nabu.score(case, "answer", {}, ""))

    def test_fresh_deep_alternative_only_in_one_explicit_case(self):
        cases = {x["id"]: x for x in nabu.cases()}
        self.assertTrue(nabu.score(cases["fresh-10"], "nabu_web__deep_answer", {"question": "Energiepolitik?"}, ""))
        self.assertFalse(nabu.score(cases["fresh-01"], "nabu_web__deep_answer", {"question": "Wetter?"}, ""))

    def test_check_never_touches_ollama(self):
        with patch.object(nabu, "http_json", side_effect=AssertionError("Network not allowed")):
            self.assertEqual(0, nabu.run("check", nabu.MODEL, 95, Path("/unused")))


if __name__ == "__main__":
    unittest.main()
