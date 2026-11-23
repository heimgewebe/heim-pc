"""Curated RadioBrowser stations and spoken-name resolution for Nabu."""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Station:
    title: str
    uuid: str
    aliases: tuple[str, ...] = ()
    genres: tuple[str, ...] = ()

    @property
    def uri(self) -> str:
        return f"radiobrowser://radio/{self.uuid}"


# RadioBrowser IDs instead of stream URLs: the directory keeps moved streams current.
STATIONS = (
    Station("Deutschlandfunk", "1c3e8be2-5b14-4933-bad3-87cbc227cba4", ("dlf",), ("nachrichten", "news")),
    Station("Deutschlandfunk Kultur", "10f16cf6-bc45-4b67-8f17-9758f249a61a", ("dlf kultur",), ("kultur",)),
    Station("Deutschlandfunk Nova", "0e1a47cb-f16d-4169-851a-5985c6133055", ("dlf nova",), ("wissen",)),
    Station("NDR Info", "9648702b-0601-11e8-ae97-52543be04c81"),
    Station("NDR Kultur", "aa673098-04d9-468d-98e7-97b694964f64"),
    Station("1LIVE", "b2cbd1fd-275d-432a-8b20-37dcb3572315", ("eins live", "einslive")),
    Station("SWR3", "240d28b9-7858-48d2-a816-9cf8e1875fe8", ("swr drei",), ("pop",)),
    Station("Bayern 3", "0de82079-04e7-407b-b616-e0726eba5244", ("bayern drei",)),
    Station("Klassik Radio", "ffd351fe-219e-4c6e-b14f-9c2e02fbe45e", (), ("klassik", "klassische musik")),
    Station("BR-Klassik", "29010f42-faef-4a9e-b15c-3ad1613b45cb", ("br klassik", "bayern klassik")),
    Station("FIP", "7b6aca3d-dfa3-47dd-9f57-820b04c3f339", (), ("eklektisch",)),
    Station("FIP Jazz", "5b9ceedf-eb85-11e9-a96c-52543be04c81", (), ("jazz",)),
    Station("FIP Electro", "b809226c-eb82-11e9-a96c-52543be04c81", (), ("electro", "elektro")),
    Station("FIP Monde", "a373697c-730a-455c-903a-447d7c26aa6a", (), ("weltmusik", "world")),
    Station("FIP Reggae", "84764bda-eb7e-11e9-a96c-52543be04c81", (), ("reggae",)),
    Station("SomaFM Groove Salad", "960cf833-0601-11e8-ae97-52543be04c81", ("groove salad",), ("chillout", "lounge")),
    Station("SomaFM Drone Zone", "960eb2e9-0601-11e8-ae97-52543be04c81", ("drone zone",), ("ambient",)),
    Station("SomaFM Indie Pop Rocks", "96394224-0601-11e8-ae97-52543be04c81", ("indie pop rocks",), ("indiepop",)),
    Station("FluxFM", "961591c6-0601-11e8-ae97-52543be04c81", ("flux fm",), ("indie", "alternative")),
    Station("Rock Antenne", "097a7899-d8d7-4cde-a6a2-a0a2d4edb069", (), ("rock",)),
    Station("Radio Bob", "9618c8c0-0601-11e8-ae97-52543be04c81", ("radio bob classic rock",), ("classic rock",)),
    Station("Sunshine Live", "960d063e-0601-11e8-ae97-52543be04c81", ("sunshine",), ("elektronisch", "dance", "house")),
    Station("Sunshine Live Techno", "9627c2e6-0601-11e8-ae97-52543be04c81", (), ("techno",)),
    Station("bigFM Oldschool Rap und Hip-Hop", "0ee149d6-e190-11e9-a8ba-52543be04c81", ("bigfm hip hop",), ("hip hop", "rap")),
    Station("Radio Teddy", "9612e37f-0601-11e8-ae97-52543be04c81", (), ("kinder",)),
    Station("WDR Cosmo", "9630fc1e-0601-11e8-ae97-52543be04c81", ("cosmo",)),
    Station("BBC World Service", "598c4d0e-6b06-43fb-bff4-717c591213a9", ("bbc world",)),
    Station("BBC Radio 1", "f30d2b8b-7206-48ae-a83d-d0145ae18468", ("bbc one", "bbc 1")),
    Station("80s80s", "1b762b21-2ec6-412a-a231-fa34a96f4f99", ("eighties",), ("achtziger", "80er", "oldies")),
    Station("Radio Paradise", "9617a958-0601-11e8-ae97-52543be04c81", (), ("gemischt",)),
)
DEFAULT_STATION = STATIONS[0]
GENERIC_RADIO = ("radio", "internetradio", "irgendein radio", "irgendeinen sender", "radiosender", "live radio")
SPOKEN_GENRES = {"elektronische musik": "elektronisch", "elektronischer musik": "elektronisch"}


def compact(value: str) -> str:
    text = value.casefold().replace("ä", "ae").replace("ö", "oe").replace("ü", "ue").replace("ß", "ss")
    return re.sub(r"[^a-z0-9]", "", text)


def _indexes() -> tuple[dict[str, Station], dict[str, Station]]:
    names: dict[str, Station] = {}
    genres: dict[str, Station] = {}
    for station in STATIONS:
        for name in (station.title, *station.aliases):
            names[compact(name)] = station
        for genre in station.genres:
            key = compact(genre)
            genres[key] = station
            for form in (f"{key}radio", f"radio{key}", f"{key}sender", f"{key}musikradio"):
                names.setdefault(form, station)
    for spoken, genre in SPOKEN_GENRES.items():
        names[compact(spoken)] = genres[compact(genre)]
    for generic in GENERIC_RADIO:
        names[compact(generic)] = DEFAULT_STATION
    return names, genres


NAMES, GENRES = _indexes()


def resolve_radio(name: str, media_type: str | None = None, artist: str = "") -> Station | None:
    """Return a curated station, leaving songs, albums and artist requests to Qobuz."""
    if artist or media_type in ("track", "album"):
        return None
    key = compact(name)
    if media_type == "radio" and key in ("", "irgendwas", "irgendeinemusik", "irgendeiner"):
        return DEFAULT_STATION
    return NAMES.get(key) or (GENRES.get(key) if media_type == "radio" else None)
