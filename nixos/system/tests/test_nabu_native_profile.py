"""Offline contracts for the native Nabu recovery profile.

Behavior is additionally exercised in the installed Home Assistant handler.
No Home Assistant or Ollama dependency is needed for this test.
"""
import hashlib
import json
from pathlib import Path
import unittest

PROFILE = Path(__file__).resolve().parents[1] / "nabu/assist_profile"


class NabuNativeProfileTests(unittest.TestCase):
    def test_file_identities(self):
        data = json.loads((PROFILE / "profile.json").read_text())
        for name, expected in data["files"].items():
            with self.subTest(name=name):
                content = (PROFILE / name).read_bytes()
                self.assertEqual(len(content), expected["bytes"])
                self.assertEqual(hashlib.sha256(content).hexdigest(), expected["sha256"])

    def test_ollama_cache_uses_existing_persistent_model_mount(self):
        data = json.loads((PROFILE / "profile.json").read_text())
        cache = data["ollama"]["server_cache"]
        self.assertEqual(cache["unit"], "heimgewebe-assist-ollama.service")
        self.assertEqual(cache["quadlet"], "~/.config/containers/systemd/heimgewebe-assist-ollama.container")
        env = cache["environment"]
        self.assertEqual(env, {"OLLAMA_FLASH_ATTENTION": "1",
                               "OLLAMA_KV_CACHE_TYPE": "q8_0",
                               "CUDA_CACHE_PATH": "/root/.ollama/cuda-cache"})
        mount = cache["persistent_mount"]
        self.assertEqual(mount["source"], "~/.local/share/heimgewebe/assist/ollama")
        self.assertEqual(mount["target"], "/root/.ollama")
        self.assertEqual(Path(env["CUDA_CACHE_PATH"]).relative_to(mount["target"]),
                         Path(cache["cache_relative_directory"]))
        self.assertEqual(data["ollama"]["options"]["keep_alive"], 600)
        self.assertEqual(data["ollama"]["options"]["num_ctx"], 16384)
        self.assertNotIn("OLLAMA_KV_CACHE_TYPE", data["ollama"]["options"])

    def test_projector_color_target_is_not_master_or_laser(self):
        grammar = (PROFILE / "native_commands.yaml").read_text()
        block = grammar.split("  HassLightSet:", 1)[1].split("  HassTurnOff:", 1)[0]
        self.assertIn('(Projektor|Lichtprojektor) [(im Wohnzimmer|im Wohnraum) ]', block)
        self.assertIn('name: "Projektor Hintergrund"', block)
        self.assertNotIn('name: "Projektor"', block)
        self.assertNotIn('Lasersterne', block)
        handler = (PROFILE / "native_intent_scripts.yaml").read_text().split(
            "NabuProjectorDifferentColor:", 1
        )[1]
        self.assertIn("entity_id: light.wohnzimmer_projektor_background", handler)
        self.assertIn("+ 120) % 360", handler)
        self.assertIn("error: true", handler)
        self.assertNotIn("wohnzimmer_projektor_master", handler)
        self.assertNotIn("wohnzimmer_projektor_laser", handler)

    def test_music_handler_retained(self):
        script = (PROFILE / "native_intent_scripts.yaml").read_text().split(
            "NabuProjectorDifferentColor:", 1
        )[0]
        self.assertIn("action: media_player.media_stop", script)
        self.assertIn("entity_id: media_player.nabu_musik_motu", script)


if __name__ == "__main__":
    unittest.main()
