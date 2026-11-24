"""Static contract regression tests for Nabu's single local conversation model."""
from __future__ import annotations

import ast
from pathlib import Path
import unittest

SRC = Path(__file__).resolve().parents[1] / "nabu" / "llm.py"
EXPECTED = [
    "WeatherForecast", "WebSearch", "WebRead", "Browser", "PlayMusic",
    "GrabowskiStatus", "GrabowskiRequest", "ChatGPTAnswer",
]


class SingleModelContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SRC.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.code)
        cls.api = next(n for n in cls.tree.body if isinstance(n, ast.FunctionDef)
                       and n.name == "async_get_tools")
        cls.llm = next(n for n in ast.walk(cls.api)
                       if isinstance(n, ast.Call)
                       and isinstance(n.func, ast.Name) and n.func.id == "LLMTools")
        cls.prompt = ast.literal_eval(next(k.value for k in cls.llm.keywords
                                           if k.arg == "prompt"))

    def test_exactly_eight_tools_without_second_model(self):
        tools = next(k.value for k in self.llm.keywords if k.arg == "tools")
        self.assertEqual(EXPECTED, [call.func.id for call in tools.elts])
        names = [n.name for n in self.tree.body if isinstance(n, ast.ClassDef)]
        self.assertNotIn("DeepAnswer", names)
        self.assertNotIn("nabu_web__deep_answer", self.code)
        self.assertNotIn("nabu-qwen3-14b-q6", self.code)
        self.assertNotIn("mistral-small", self.code)

    def test_direct_action_takes_priority_over_gruendlich(self):
        for phrase in ("gib dir Mühe", "überlege gründlich", "prüf das gründlich",
                       "Eine konkret gewünschte Aktion hat Vorrang",
                       "Home-Assistant-Gerätewerkzeuge", "nabu_web__play_music"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.prompt)

    def test_ambiguous_light_requires_a_room_before_action(self):
        for phrase in ("Schalte das Licht an", "Licht aus",
                       "In welchem Raum?", "intent__HassTurnOn",
                       "intent__HassTurnOff", "ohne area",
                       "Zustand erst nach positivem Werkzeugergebnis",
                       "ohne Toolaufruf", "Wir sind im Wohnzimmer",
                       "area=Wohnzimmer"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.prompt)

    def test_source_first_without_model_switch(self):
        for phrase in ("nabu_web__search", "nabu_web__read_page",
                       "Amtsinhaber", "tatsächlich gelesene URLs"):
            self.assertIn(phrase, self.prompt)
        self.assertNotIn("Zweitmodell", self.prompt)
        self.assertNotIn("nabu_web__deep_answer", self.prompt)

    def test_weather_uses_dedicated_tool_not_web_search(self):
        self.assertIn("Für Wetter, Temperatur, Regen", self.prompt)
        self.assertIn("nabu_web__weather", self.prompt)
        self.assertIn("nicht im Web suchen", self.prompt)
        self.assertNotIn("Ereignisse, Wetter", self.prompt)

    def test_no_unverified_success_claims(self):
        for phrase in ("Bei Werkzeugfehlern nie Erfolg",
                       "Eine angenommene Service-Anfrage",
                       "Bei mehrdeutigem Gerätenamen frage"):
            self.assertIn(phrase, self.prompt)

    def test_optional_chatgpt_only_when_explicit(self):
        self.assertIn("Auf ausdrücklichen Wunsch nach ChatGPT", self.prompt)
        self.assertIn("sonst ausschließlich mit dem lokalen Modell", self.prompt)


if __name__ == "__main__":
    unittest.main()
