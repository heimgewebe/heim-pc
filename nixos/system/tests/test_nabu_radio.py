"""Regression tests for Nabu's spoken radio station resolution."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "nabu" / "radio.py"
SPEC = importlib.util.spec_from_file_location("nabu_radio", SRC)
radio = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = radio
SPEC.loader.exec_module(radio)


class RadioResolution(unittest.TestCase):
    def test_catalog_has_unique_ids_and_no_stream_urls(self):
        ids = [s.uuid for s in radio.STATIONS]
        self.assertGreaterEqual(len(ids), 15)
        self.assertLessEqual(len(ids), 30)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn("http", SRC.read_text(encoding="utf-8"))

    def test_spoken_stations_and_genres(self):
        cases = {
            "Radio": "Deutschlandfunk", "Deutschlandfunk": "Deutschlandfunk",
            "NDR Info": "NDR Info", "N D R Info": "NDR Info",
            "Jazzradio": "FIP Jazz", "Jazz Radio": "FIP Jazz",
            "Klassikradio": "Klassik Radio", "Rockradio": "Rock Antenne",
            "Popradio": "SWR3", "elektronische Musik": "Sunshine Live",
            "Hip-Hop-Radio": "bigFM Oldschool Rap und Hip-Hop",
            "Kinderradio": "Radio Teddy", "Weltmusikradio": "FIP Monde",
        }
        for spoken, title in cases.items():
            with self.subTest(spoken=spoken):
                self.assertEqual(title, radio.resolve_radio(spoken).title)

    def test_mislabelled_artist_type_still_selects_station(self):
        self.assertEqual("Deutschlandfunk", radio.resolve_radio("Deutschlandfunk", "artist").title)

    def test_bare_genre_needs_explicit_radio_type(self):
        self.assertIsNone(radio.resolve_radio("Jazz"))
        self.assertEqual("FIP Jazz", radio.resolve_radio("Jazz", "radio").title)

    def test_empty_radio_request_uses_default(self):
        self.assertEqual(radio.DEFAULT_STATION, radio.resolve_radio("", "radio"))
        self.assertEqual(radio.DEFAULT_STATION, radio.resolve_radio("irgendwas", "radio"))
        self.assertIsNone(radio.resolve_radio(""))
        self.assertIsNone(radio.resolve_radio("irgendwas"))

    def test_other_broadcasters_inforadio_is_not_deutschlandfunk(self):
        self.assertIsNone(radio.resolve_radio("Inforadio", "radio"))

    def test_music_requests_stay_with_qobuz(self):
        for args in (("Radio Ga Ga",), ("Radiohead", "artist"), ("Radio", "track"),
                     ("Radio", None, "Rammstein"), ("Bakerman", None, "Laid Back"),
                     ("Rock", "album")):
            with self.subTest(args=args):
                self.assertIsNone(radio.resolve_radio(*args))

    def test_unknown_station_is_left_to_directory_search(self):
        self.assertIsNone(radio.resolve_radio("Radio Nordseewelle", "radio"))


if __name__ == "__main__":
    unittest.main()
