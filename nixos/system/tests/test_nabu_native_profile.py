"""Offline contracts for the native Nabu recovery profile.

Behavior is additionally exercised in the installed Home Assistant handler.
No Home Assistant or Ollama dependency is needed for this test.
"""
import hashlib
import importlib.util
import sys
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
        )[1].split("NabuPlayRadio:", 1)[0]
        self.assertIn("entity_id: light.wohnzimmer_projektor_background", handler)
        self.assertIn("+ 120) % 360", handler)
        self.assertLess(handler.index("accepted: false"), handler.index("action: light.turn_on"))
        self.assertGreater(handler.index("accepted: true"), handler.index("action: light.turn_on"))
        self.assertIn("action_response.accepted | default(false)", handler)
        self.assertIn("Ich konnte die Projektorfarbe nicht ändern.", handler)
        self.assertNotIn("wohnzimmer_projektor_master", handler)
        self.assertNotIn("wohnzimmer_projektor_laser", handler)

    def test_music_handler_retained(self):
        script = (PROFILE / "native_intent_scripts.yaml").read_text().split(
            "NabuProjectorDifferentColor:", 1
        )[0]
        self.assertIn("action: media_player.media_stop", script)
        self.assertIn("entity_id: media_player.nabu_musik_motu", script)

    def test_music_presets_retain_shared_radio_default_and_verified_playlist(self):
        scripts = (PROFILE / "native_intent_scripts.yaml").read_text()
        radio = scripts.split("NabuPlayRadio:", 1)[1].split("NabuPlayRelaxedMusic:", 1)[0]
        relaxed = scripts.split("NabuPlayRelaxedMusic:", 1)[1]
        spec = importlib.util.spec_from_file_location("nabu_profile_radio", PROFILE.parent / "radio.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            self.assertIn('media_id: "' + module.DEFAULT_STATION.uri + '"', radio)
        finally:
            sys.modules.pop(spec.name, None)
        self.assertIn("media_type: radio", radio)
        self.assertIn('media_id: "Entspannter Sonntagmorgen"', relaxed)
        self.assertIn("media_type: playlist", relaxed)
        for block in (radio, relaxed):
            self.assertEqual(block.count("action: music_assistant.play_media"), 1)
            self.assertIn("entity_id: media_player.nabu_musik_motu", block)
            self.assertIn("enqueue: replace", block)
            self.assertIn("['unknown', 'unavailable']", block)
            self.assertLess(block.index("accepted: false"), block.index("action: music_assistant.play_media"))
            self.assertGreater(block.index("accepted: true"), block.index("action: music_assistant.play_media"))
            self.assertEqual(block.count("response_variable: result"), 2)
            self.assertIn("action_response.accepted | default(false)", block)
            self.assertIn("Ich konnte", block)
            self.assertIn("Ich starte", block)

    def test_music_presets_do_not_duplicate_generic_start_or_capture_free_text(self):
        grammar = (PROFILE / "native_commands.yaml").read_text()
        radio = grammar.split("  NabuPlayRadio:", 1)[1].split("  NabuPlayRelaxedMusic:", 1)[0]
        relaxed = grammar.split("  NabuPlayRelaxedMusic:", 1)[1]
        self.assertNotIn("NabuPlayAnyMusic:", grammar)
        self.assertIn("(Radio|Internetradio|Deutschlandfunk)", radio)
        self.assertIn("entspannte Musik", relaxed)
        for block in (radio, relaxed):
            self.assertNotIn("{", block)
            self.assertNotIn("cooles", block)
            self.assertNotIn("Schlafzimmer", block)


if __name__ == "__main__":
    unittest.main()
