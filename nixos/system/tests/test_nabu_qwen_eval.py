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
        self.assertIn("Für aktuelle Ereignisse, Preise", prompt)
        self.assertIn("Eine konkret gewünschte Aktion hat Vorrang", prompt)
        self.assertIn("nabu_web__play_music", prompt)
        self.assertIn("nabu_web__search", prompt)
        self.assertIn("nabu_web__weather", prompt)

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

    def test_chatgpt_text_is_default_and_voice_needs_explicit_mode(self):
        good = nabu.valid_arguments
        self.assertTrue(good("nabu_web__chatgpt", {"question": "Frag Grabowski nach seinen Aufgaben"}))
        self.assertTrue(good("nabu_web__chatgpt", {"mode": "browser_chat", "question": "Test"}))
        self.assertTrue(good("nabu_web__chatgpt", {"mode": "browser_voice"}))
        self.assertFalse(good("nabu_web__chatgpt", {"mode": "browser_voice", "question": "Test"}))
        self.assertTrue(good("nabu_web__chatgpt", {"mode": "answer", "question": "Test"}))
        self.assertFalse(good("nabu_web__chatgpt", {"mode": "answer"}))
        self.assertFalse(good("nabu_web__chatgpt", {"mode": "delete", "question": "Test"}))

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

    def test_browser_operation_must_match_user_intent(self):
        browser = {x["id"]: x for x in nabu.cases() if x["family"] == "browser"}
        self.assertFalse(nabu.score(browser["browser-01"], "nabu_web__browser",
                                    {"operation": "inspect"}, ""))
        self.assertTrue(nabu.score(browser["browser-01"], "nabu_web__browser",
                                   {"operation": "open", "url": "https://example.com"}, ""))
        self.assertFalse(nabu.score(browser["browser-08"], "nabu_web__browser",
                                    {"operation": "inspect"}, ""))
        self.assertTrue(nabu.score(browser["browser-08"], "nabu_web__browser",
                                   {"operation": "type", "target": "Suchfeld", "value": "Wetter"}, ""))

    def test_unexpected_first_device_call_counts_as_critical(self):
        case = next(x for x in nabu.cases() if x["id"] == "fresh-01")
        message = {"tool_calls": [
            {"function": {"name": "intent__HassTurnOn", "arguments": {"name": "Licht"}}}
        ]}
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(nabu, "validate_fixture", return_value=([case], [])), \
                 patch.object(nabu, "model_identity", return_value={"name": nabu.MODEL, "digest": "b" * 64}), \
                 patch.object(nabu, "chat", return_value=({"message": message, "load_duration": 0}, 0.1)):
                self.assertEqual(0, nabu.run("run", nabu.MODEL, 30, Path(temp)))
            jsonl = next(Path(temp).glob("*.jsonl"))
            rows = [json.loads(line) for line in jsonl.read_text().splitlines()]
            got = next(x for x in rows if x.get("record") == "case")
            self.assertEqual(["intent__HassTurnOn"], got["unrequested_effectful_tools"])
            self.assertFalse(got["pass"])
            self.assertTrue(got["critical"])
            summary = next(Path(temp).glob("*.summary.json"))
            self.assertEqual(1, json.loads(summary.read_text())["critical_failures"])

    def test_scroll_fixture_matches_real_browser_direction(self):
        case = next(c for c in nabu.cases() if c["id"] == "browser-09")
        # Browser.async_call implements scrollBy(0,650): downward only.
        self.assertIn("nach unten", case["prompt"])
        self.assertEqual("scroll", case["expected_arguments"]["operation"])

    def test_grabowski_operation_specific_id_contract(self):
        good = nabu.valid_arguments
        self.assertTrue(good("nabu_web__grabowski", {"operation": "status"}))
        self.assertTrue(good("nabu_web__grabowski", {"operation": "tasks"}))
        self.assertFalse(good("nabu_web__grabowski", {"operation": "task"}))
        self.assertFalse(good("nabu_web__grabowski", {"operation": "obligation"}))
        self.assertFalse(good("nabu_web__grabowski", {"operation": "task", "task_id": "short"}))
        self.assertTrue(good("nabu_web__grabowski", {"operation": "task", "task_id": "1234567890abcdef"}))
        self.assertTrue(good("nabu_web__grabowski", {"operation": "task", "task_id": "goo-12345678"}))
        self.assertFalse(good("nabu_web__grabowski", {"operation": "task", "task_id": "goo-short"}))
        self.assertTrue(good("nabu_web__grabowski", {"operation": "obligation", "obligation_id": "goo-12345678"}))
        self.assertFalse(good("nabu_web__grabowski", {"operation": "obligation", "obligation_id": "wrong"}))

    def test_grabowski_operation_matches_question(self):
        status = {c["id"]: c for c in nabu.cases() if c["family"] == "operator_status"}
        self.assertFalse(nabu.score(status["operator_status-01"],
                                    "nabu_web__grabowski", {"operation": "tasks"}, ""))
        self.assertTrue(nabu.score(status["operator_status-01"],
                                   "nabu_web__grabowski", {"operation": "status"}, ""))
        self.assertFalse(nabu.score(status["operator_status-03"],
                                    "nabu_web__grabowski", {"operation": "status"}, ""))
        self.assertTrue(nabu.score(status["operator_status-03"],
                                   "nabu_web__grabowski", {"operation": "tasks"}, ""))

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

    def test_one_model_analyses_directly_and_fetches_fresh_sources(self):
        cases = {x["id"]: x for x in nabu.cases()}
        self.assertTrue(nabu.score(cases["deep-01"], "answer", {},
                                   "Bei Wärmepumpen sind diese Bedingungen wichtig."))
        self.assertFalse(nabu.score(cases["deep-01"], "nabu_web__deep_answer",
                                    {"question": "Wärmepumpen?"}, ""))
        self.assertTrue(nabu.score(cases["fresh-10"], "nabu_web__search",
                                   {"query": "Energiepolitik 2026"}, ""))
        self.assertFalse(nabu.score(cases["fresh-10"], "answer", {},
                                    "Aktuelle Beschlüsse ohne Quelle."))

    def test_default_request_uses_versioned_assist_profile(self):
        profile_path = ROOT / "nixos/system/nabu/assist_profile/profile.json"
        expected = json.loads(profile_path.read_text())["ollama"]["options"]
        self.assertEqual(expected["model"], nabu.MODEL)
        addendum = profile_path.with_name("prompt-addendum.txt").read_text().strip()
        with patch.object(nabu, "http_json", return_value={}) as request:
            nabu.chat(nabu.MODEL, "Test", [], [], 30)
        payload = request.call_args.args[1]
        self.assertEqual(expected["model"], payload["model"])
        self.assertEqual(expected["think"], payload["think"])
        self.assertEqual(expected["num_ctx"], payload["options"]["num_ctx"])
        self.assertEqual(f'{expected["keep_alive"]}s', payload["keep_alive"])
        self.assertNotIn("num_predict", payload["options"])
        self.assertEqual(1, payload["messages"][0]["content"].count(addendum))

    def test_unrequested_chatgpt_handoff_is_critical(self):
        case = next(x for x in nabu.cases() if x["id"] == "answer-01")
        message = {"tool_calls": [
            {"function": {"name": "nabu_web__chatgpt",
                          "arguments": {"question": "Test"}}}
        ]}
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(nabu, "validate_fixture", return_value=([case], [])), \
                 patch.object(nabu, "model_identity", return_value={"name": nabu.MODEL, "digest": "c" * 64}), \
                 patch.object(nabu, "chat", return_value=({"message": message}, 0.1)):
                self.assertEqual(0, nabu.run("run", nabu.MODEL, 30, Path(temp)))
            rows = [json.loads(line) for line in next(Path(temp).glob("*.jsonl")).read_text().splitlines()]
            result = next(x for x in rows if x.get("record") == "case")
            self.assertEqual(["nabu_web__chatgpt"], result["unrequested_effectful_tools"])
            self.assertTrue(result["critical"])
            self.assertFalse(result["pass"])

    def test_check_never_touches_ollama(self):
        with patch.object(nabu, "http_json", side_effect=AssertionError("Network not allowed")):
            self.assertEqual(0, nabu.run("check", nabu.MODEL, 95, Path("/unused")))


if __name__ == "__main__":
    unittest.main()