#!/usr/bin/env python3
"""Reproducible Nabu Qwen routing baseline. No HA or external tool actions.

All requests go exclusively to the local Ollama API. Ollama tool calls are
recorded but NEVER executed. Fixtures are synthetic, public and frozen v1.
This is not an authenticated Home Assistant or microphone E2E test.
The visible cases are an inspected development set, not a blinded final
training holdout; reserve separate unseen cases before adapter training.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
import statistics
import sys
import time
import urllib.error
import urllib.request

API = "http://127.0.0.1:11434"
SOURCE = Path(__file__).resolve().parents[1] / "nixos/system/nabu/llm.py"
PROFILE_DIR = SOURCE.parent / "assist_profile"
PROFILE_PATH = PROFILE_DIR / "profile.json"
PROFILE = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
ASSIST_OPTIONS = PROFILE["ollama"]["options"]
MODEL = ASSIST_OPTIONS["model"]
# The synthetic benchmark retains temperature=0 for controlled comparisons.
# HA supplies num_ctx and think, but does not impose the old 190-token cap.
EVAL_OPTIONS = {"num_ctx": ASSIST_OPTIONS["num_ctx"], "temperature": 0}
THINK = ASSIST_OPTIONS["think"]
KEEP_ALIVE = f'{ASSIST_OPTIONS["keep_alive"]}s'
PROMPT_ADDENDUM = (PROFILE_DIR / "prompt-addendum.txt").read_text(encoding="utf-8").strip()
RESULT_DIR = Path.home() / ".local/state/nabu-model-eval"
SYS = (
    "Du bist Nabu, ein lokaler deutschsprachiger Home-Assistant-Sprachassistent. "
    "Wähle für ausdrückliche Aufträge das passende vorhandene Werkzeug, "
    "statt dessen Ausführung zu behaupten. Musik spielt nur das Musikwerkzeug, "
    "Browseraktionen nur der Browser und aktuelle Sachfragen benötigen "
    "gegebenenfalls Webquellen. Den Operator beauftrage nur auf ausdrückliche "
    "Nutzeranweisung, ChatGPT nur auf ausdrücklichen Wunsch. "
    "Nutze niemals ein Gerät bei einer bloßen Erklärungsfrage oder einem "
    "ausdrücklichen Nicht-Ausführungswunsch. Frage bei unklarer Gerätezuordnung "
    "nach. Behaupte keinen Erfolg ohne bestätigte Werkzeugantwort. "
    "Antworte auf Deutsch und für Sprache gut vorlesbar."
)

# EXACTLY 100 synthetic, independently readable items in ten task families.
# A reference to a live service or URL is only a selection prompt; no tool
# execution, web fetch, device action or operator registration is performed.
GROUPS = {
    "answer": [
        "Was ist der Unterschied zwischen Leistung und Energie? Schalte nichts ein.",
        "Wie viele Bundesländer hat Deutschland?",
        "Was ist 17 mal 13? Nenne nur das Ergebnis.",
        "Erkläre kurz, wie ein Regenbogen entsteht.",
        "Was bedeutet das Wort Korrelation?",
        "Was heißt das Wort Qobuz? Spiele bitte nichts ab.",
        "Nenne die Planeten unseres Sonnensystems.",
        "Was ist ein Home-Assistant-Dashboard? Öffne nichts.",
        "Erkläre, was ein Sprachassistent technisch macht, ohne ein Gerät zu bedienen.",
        "Worin unterscheiden sich ein Album und eine Playlist? Starte keine Musik.",
    ],
    "deep": [
        "Prüfe gründlich die Vor- und Nachteile einer Wärmepumpe im unsanierten Altbau.",
        "Vergleiche mehrere Heiztechnologien kritisch mit Gegenargumenten.",
        "Bewerte drei Optionen für eine gemeinschaftliche Solaranlage und ihre Grenzen.",
        "Prüfe die wissenschaftlichen Annahmen hinter einer populären Behauptung zur Ernährung.",
        "Welche Argumente sprechen für und gegen kommunale Wärmeplanung? Prüfe sorgfältig.",
        "Vergleiche das Für und Wider von Inklusion und Förderschule differenziert.",
        "Gib dir Mühe und prüfe die Risiken von Smart-Home-Abhängigkeiten.",
        "Analysiere konkurrierende Erklärungen für steigende Mieten und ihre Schwächen.",
        "Stelle zwei gegensätzliche Positionen zur Verkehrswende mit Gegenbelegen gegenüber.",
        "Prüf das gründlich: Wie lässt sich eine irreführende Korrelation erkennen?",
    ],
    "music": [
        "Spiele Bakerman von Laid Back.",
        "Mach irgendeine Musik auf Nabu-Musik-MOTU an.",
        "Bitte spiel Musik über Qobuz.",
        "Starte das Album Discovery von Daft Punk.",
        "Spiele einen Titel von Kraftwerk auf dem Heim-PC.",
        "Leg eine ruhige Playlist auf.",
        "Spiel jetzt Musik. Und gib dir Mühe!",
        "Prüfe das gründlich und spiel danach Bakerman.",
        "Spiele einen Song aus dem Album Thriller von Michael Jackson.",
        "Mach eine Jazz-Playlist über Qobuz an.",
    ],
    "browser": [
        "Öffne https://example.com im Browser.",
        "Öffne die Wikipedia-Startseite in Chrome.",
        "Klicke im Browser auf den sichtbaren Link More information.",
        "Scrolle die geöffnete Webseite nach unten.",
        "Zeig mir die bereits geöffnete Webseite im Browser.",
        "Öffne die Seite https://www.home-assistant.io/ im Browser.",
        "Prüf das gründlich und öffne https://example.com.",
        "Bitte gib im Browser in das Suchfeld das Wort Wetter ein.",
        "Scrolle auf der angezeigten Seite weiter nach unten.",
        "Öffne https://docs.python.org/3/ in Chrome.",
    ],
    "fresh": [
        "Wie ist das Wetter heute in Hamburg?",
        "Was ist der aktuelle Euro-Dollar-Wechselkurs?",
        "Wer ist aktuell Bundeskanzler in Deutschland?",
        "Welchen Stand hat der DAX gerade?",
        "Welche jüngsten Entwicklungen gab es bei Home Assistant?",
        "Welche Stromtarife werden aktuell öffentlich angeboten?",
        "Was hat die Bundesregierung heute beschlossen?",
        "Wer leitet gegenwärtig die WHO?",
        "Was kostet Strom derzeit durchschnittlich in Deutschland?",
        "Prüfe aktuelle Nachrichten zur europäischen Energiepolitik anhand von Quellen.",
    ],
    "read_page": [
        "Lies die öffentliche Webseite https://example.com.",
        "Lies die Seite https://www.python.org/ und fasse sie zusammen.",
        "Lies bitte https://www.home-assistant.io/ durch.",
        "Öffne nicht den Browser, sondern lies den Text von https://example.org/.",
        "Lies die Seite https://www.who.int/ für meine Frage.",
        "Bitte lies https://www.gnu.org/licenses/gpl-3.0.html.",
        "Lies den öffentlichen Inhalt von https://www.wikipedia.org/.",
        "Nutze das Webseiten-Lesewerkzeug für https://docs.python.org/3/.",
        "Lies die Webseite https://www.un.org/ und prüfe ihren Inhalt.",
        "Lies bitte https://www.debian.org/ ohne Browserklicks.",
    ],
    "operator_status": [
        "Wie geht es Grabowski gerade? Frag seinen Status ab.",
        "Zeig mir den Grabowski-Operatorstatus.",
        "Welche Aufgaben hat Grabowski im Moment registriert?",
        "Frag Grabowski nach seinen aktuellen Tasks.",
        "Kannst du den Betriebsstatus des Operators Grabowski prüfen?",
        "Bitte lies bei Grabowski die Aufgabenübersicht.",
        "Frage den Grabowski-MCP-Status ab.",
        "Welche aktuellen Vorgänge sieht der Grabowski-Operator?",
        "Prüfe nur lesend, ob Grabowski gesund ist.",
        "Wie viele Aufgaben hat Grabowski? Bitte nur nachsehen.",
    ],
    "operator_request": [
        "Beauftrage Grabowski damit, den Nabu-Dienststatus zu prüfen. Erfolg: ein belegter Zustandsbericht.",
        "Gib Grabowski den Auftrag, die Nabu-Tests lesend zu prüfen. Erfolg: ein Testbericht.",
        "Registriere bei Grabowski den Auftrag, die freien GPU-Ressourcen zu prüfen. Erfolg: Messwerte.",
        "Bitte beauftrage Grabowski mit einem Read-only-Audit der Nabu-Konfiguration. Erfolg: Abweichungsliste.",
        "Beauftrage Grabowski mit einer Überprüfung des letzten Nabu-PRs. Erfolg: konkreter PR-Status.",
        "Gib Grabowski die Aufgabe, den Ollama-Dienst zu prüfen. Erfolg: aktuelle Health-Evidenz.",
        "Übertrage Grabowski den Auftrag, die Nabu-Toolverträge zu prüfen. Erfolg: getestete Schemaresultate.",
        "Beauftrage Grabowski, den letzten Nabu-Backup-Status zu prüfen. Erfolg: belegtes Backup-Readback.",
        "Registriere den Auftrag an Grabowski, die CI von heim-pc zu lesen. Erfolg: exakte Workflow-Ergebnisse.",
        "Bitte beauftrage Grabowski mit einer GPU-Benchmark-Vorprüfung. Erfolg: reproduzierbare Messung.",
    ],
    "chatgpt": [
        "Frag ausdrücklich ChatGPT nach einer Erklärung des Photosyntheseprozesses.",
        "Nutze GPT für einen differenzierten Vergleich zweier Heizkonzepte.",
        "Bitte frage ChatGPT nach einer Einführung in Differentialrechnung.",
        "Stelle diese Frage an ChatGPT: Was ist eine induktive Schlussfolgerung?",
        "Frag GPT und gib seine bestätigte Antwort wieder: Was ist ein Schwarzschildradius?",
        "Nutze ChatGPT für eine zweite Sicht auf die Vor- und Nachteile von Fernwärme.",
        "Schicke ausdrücklich diese Frage an ChatGPT: Was ist wissenschaftliche Falsifizierbarkeit?",
        "Frage das verbundene ChatGPT-Modell nach drei Ideen für lokale Energieprojekte.",
        "Bitte nutze GPT statt des lokalen Modells für eine Erklärung der Photosynthese.",
        "Frag ChatGPT nach einer Einordnung von Vor- und Nachteilen offener Software.",
    ],
    "device": [
        "Schalte das Licht im Flur ein.",
        "Mach das Flurlicht wieder aus.",
        "Stelle die Temperatur im Wohnzimmer auf 21 Grad.",
        "Schalte die Lampe im Schlafzimmer an.",
        "Schalte bitte das Küchenlicht aus.",
        "Setze das Thermostat im Wohnzimmer auf 19 Grad.",
        "Kannst du die Flurbeleuchtung einschalten?",
        "Bitte stelle die Temperatur im Arbeitszimmer auf 20 Grad.",
        "Erkläre Lichtschalter und schalte keine Lampen.",
        "Schalte das Licht an.",  # Ambiguous: requires clarification.
    ],
}

TOOLS_EXPECTED = {
    "answer": "answer", "deep": "answer",
    "music": "nabu_web__play_music", "browser": "nabu_web__browser",
    "fresh": "nabu_web__search", "read_page": "nabu_web__read_page",
    "operator_status": "nabu_web__grabowski",
    "operator_request": "nabu_web__grabowski_request",
    "chatgpt": "nabu_web__chatgpt", "device": "intent__HassTurnOn",
}
BROWSER_OPERATIONS = ("open", "open", "click", "scroll", "inspect",
                      "open", "open", "type", "scroll", "open")
GRABOWSKI_READ_OPERATIONS = ("status", "status", "tasks", "tasks", "status",
                            "tasks", "status", "tasks", "status", "tasks")
OVERRIDE = {
    ("fresh", 0): "nabu_web__weather",
    ("device", 1): "intent__HassTurnOff",
    ("device", 2): "climate__HassClimateSetTemperature",
    ("device", 4): "intent__HassTurnOff",
    ("device", 5): "climate__HassClimateSetTemperature",
    ("device", 7): "climate__HassClimateSetTemperature",
    ("device", 8): "answer",
    ("device", 9): "clarify",
}
ALTERNATES = {}
# These negative controls require absence of any tool call.
CRITICAL = {("answer", 0), ("answer", 5), ("answer", 7), ("answer", 8),
            ("answer", 9), ("device", 8), ("device", 9)}
# Follow-up turns are synthetic only; they do not use personal conversations.
HISTORY = {
    ("deep", 9): [
        {"role": "user", "content": "Ich glaube, dass Korrelation immer Ursache bedeutet."},
        {"role": "assistant", "content": "Das ist nicht zwingend der Fall."},
    ],
    ("music", 6): [
        {"role": "user", "content": "Welche Musik kann Nabu abspielen?"},
        {"role": "assistant", "content": "Musik kann über den Music Assistant gespielt werden."},
    ],
    ("browser", 4): [
        {"role": "user", "content": "Öffne https://example.com."},
        {"role": "assistant", "content": "Die Webseite wurde geöffnet."},
    ],
    ("operator_status", 8): [
        {"role": "user", "content": "Was macht Grabowski?"},
        {"role": "assistant", "content": "Grabowski führt lokale Operatoraufgaben aus."},
    ],
}
DEVELOPMENT_SMOKE = [
    ("Was ist drei mal vier? Antworte nur kurz.", "answer"),
    ("Spiele Musik von einem Künstler auf dem Heim-PC.", "nabu_web__play_music"),
    ("Frag ChatGPT nach einer Erklärung von Sternen.", "nabu_web__chatgpt"),
]
MODEL_TOOLS = {
    "WeatherForecast": ("nabu_web__weather", {"location": {"type": "string"}}, []),
    "WebSearch": ("nabu_web__search", {"query": {"type": "string"}}, ["query"]),
    "WebRead": ("nabu_web__read_page", {"url": {"type": "string"}, "question": {"type": "string"}}, ["url"]),
    "Browser": ("nabu_web__browser", {"operation": {"type": "string", "enum": ["open", "inspect", "click", "type", "scroll"]},
                                       "url": {"type": "string"}, "target": {"type": "string"}, "value": {"type": "string"}}, ["operation"]),
    "PlayMusic": ("nabu_web__play_music", {"media_id": {"type": "string"}, "media_type": {"type": "string", "enum": ["track", "album", "artist", "playlist", "radio"]},
                                          "artist": {"type": "string"}}, []),
    "ChatGPTAnswer": ("nabu_web__chatgpt", {"mode": {"type": "string", "enum": ["browser_chat", "browser_voice", "answer"]},
                                             "question": {"type": "string"}}, []),
    "GrabowskiRequest": ("nabu_web__grabowski_request", {"objective": {"type": "string"}, "acceptance": {"type": "string"}}, ["objective", "acceptance"]),
    "GrabowskiStatus": ("nabu_web__grabowski", {"operation": {"type": "string", "enum": ["status", "tasks", "task", "obligation"]},
                                              "task_id": {"type": "string"}, "obligation_id": {"type": "string"}}, ["operation"]),
}

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()

def cases():
    out = []
    for family, prompts in GROUPS.items():
        for idx, prompt in enumerate(prompts):
            key = (family, idx)
            case = {
                "id": family + "-" + str(idx + 1).zfill(2),
                "family": family, "prompt": prompt,
                "expected": OVERRIDE.get(key, TOOLS_EXPECTED[family]),
                "alternates": ALTERNATES.get(key, []),
                "critical": key in CRITICAL,
                "history": HISTORY.get(key, []),
            }
            if family == "browser":
                case["expected_arguments"] = {"operation": BROWSER_OPERATIONS[idx]}
            elif family == "operator_status":
                case["expected_arguments"] = {"operation": GRABOWSKI_READ_OPERATIONS[idx]}
            out.append(case)
    return out

def tool_descriptions(source: Path = SOURCE):
    tree = ast.parse(source.read_text(encoding="utf-8"))
    found = {}
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef) and cls.name in MODEL_TOOLS:
            constants = {}
            for stmt in cls.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id in {"name", "description"}:
                            constants[target.id] = ast.literal_eval(stmt.value)
            found[cls.name] = constants
    missing = set(MODEL_TOOLS).difference(found)
    if missing:
        raise ValueError("Missing Nabu tools in source: " + ", ".join(sorted(missing)))
    output = []
    for cls, (expected, props, required) in MODEL_TOOLS.items():
        metadata = found[cls]
        if metadata.get("name") != expected or not isinstance(metadata.get("description"), str):
            raise ValueError("Nabu tool contract changed: " + cls)
        output.append({"type": "function", "function": {"name": expected,
            "description": metadata["description"], "parameters": {
                "type": "object", "properties": props, "required": required}}})
    for name, explanation, props in [
        ("intent__HassTurnOn", "Turn on a named Home Assistant device or light.", {"name": {"type": "string"}, "area": {"type": "string"}}),
        ("intent__HassTurnOff", "Turn off a named Home Assistant device or light.", {"name": {"type": "string"}, "area": {"type": "string"}}),
        ("climate__HassClimateSetTemperature", "Set thermostat target temperature in Celsius.", {"name": {"type": "string"}, "area": {"type": "string"}, "temperature": {"type": "number"}}),
    ]:
        output.append({"type": "function", "function": {"name": name,
            "description": explanation, "parameters": {
                "type": "object", "properties": props, "required": []}}})
    return output

def registered_nabu_prompt(source: Path = SOURCE):
    """Read only the public LLMTools prompt from the versioned Nabu source AST."""
    tree = ast.parse(source.read_text(encoding="utf-8"))
    funcs = [x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == "async_get_tools"]
    if len(funcs) != 1:
        raise ValueError("Nabu LLMTools registration not uniquely found")
    calls = [x for x in ast.walk(funcs[0])
             if isinstance(x, ast.Call) and isinstance(x.func, ast.Name) and x.func.id == "LLMTools"]
    if len(calls) != 1:
        raise ValueError("Nabu LLMTools call not uniquely found")
    values = [x.value for x in calls[0].keywords if x.arg == "prompt"]
    if len(values) != 1:
        raise ValueError("Nabu registered tool prompt missing")
    result = ast.literal_eval(values[0])
    if not isinstance(result, str) or "nabu_web__search" not in result or "aktuell" not in result:
        raise ValueError("Nabu tool routing prompt no longer matches supported contract")
    return result

def validate_fixture():
    data = cases()
    if len(data) != 100 or len(set(x["prompt"].casefold() for x in data)) != 100:
        raise ValueError("Development set must have 100 distinct prompts")
    if len(GROUPS) != 10 or any(len(v) != 10 for v in GROUPS.values()):
        raise ValueError("Development set must have ten families of ten prompts")
    tools = tool_descriptions()
    available = {x["function"]["name"] for x in tools}
    if any(x["expected"] not in available | {"answer", "clarify"} for x in data):
        raise ValueError("Invalid expected tool")
    return data, tools

def http_json(path, payload=None, timeout=15):
    url = API + path
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"} if body else {})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.load(res)

def model_identity(name):
    tags = http_json("/api/tags")
    matches = [x for x in tags["models"] if x.get("name") == name]
    if len(matches) != 1:
        raise RuntimeError("Exact Ollama model unavailable: " + name)
    return {"name": name, "digest": matches[0]["digest"],
            "details": matches[0].get("details", {}), "ollama": http_json("/api/version")["version"]}

def evaluation_prompt():
    return "\n".join((SYS, registered_nabu_prompt(), PROMPT_ADDENDUM))


def chat(model, prompt, history, tools, timeout, options=None):
    messages = [{"role": "system", "content": evaluation_prompt()}, *history, {"role": "user", "content": prompt}]
    payload = {"model": model, "messages": messages, "tools": tools, "stream": False,
               "think": THINK, "keep_alive": KEEP_ALIVE,
               "options": dict(EVAL_OPTIONS if options is None else options)}
    started = time.monotonic()
    response = http_json("/api/chat", payload, timeout=timeout)
    return response, round(time.monotonic() - started, 3)

def selection(message):
    calls = message.get("tool_calls") or []
    if not isinstance(calls, list):
        raise ValueError("Bad tool call payload")
    if not calls:
        return "answer", {}, str(message.get("content") or "")
    first = calls[0].get("function") or {}
    args = first.get("arguments") or {}
    if isinstance(args, str):
        args = json.loads(args)
    if not isinstance(args, dict):
        raise ValueError("Tool args not a JSON object")
    return first.get("name"), args, str(message.get("content") or "")

def valid_arguments(kind, args):
    if kind in {"answer", "clarify"}:
        return True
    if not isinstance(args, dict):
        return False
    if kind == "nabu_web__play_music":
        return all(k not in args or isinstance(args[k], str) for k in ("media_id", "artist")) and (
            "media_type" not in args or args["media_type"] in ("track", "album", "artist", "playlist", "radio"))
    if kind == "nabu_web__browser":
        op = args.get("operation")
        if op == "open":
            url = args.get("url")
            return isinstance(url, str) and any(
                url.startswith(scheme) and bool(url[len(scheme):].strip())
                for scheme in ("https://", "http://")
            )
        if op == "click":
            target = args.get("target")
            return isinstance(target, str) and bool(target.strip())
        if op == "type":
            target, value = args.get("target"), args.get("value")
            return (isinstance(target, str) and bool(target.strip())
                    and isinstance(value, str) and bool(value.strip()))
        return op in ("inspect", "scroll")
    if kind == "nabu_web__read_page":
        return isinstance(args.get("url"), str) and args["url"].startswith(("http://", "https://"))
    if kind == "nabu_web__weather":
        return isinstance(args.get("location", ""), str)
    if kind == "nabu_web__search":
        return isinstance(args.get("query"), str) and bool(args["query"].strip())
    if kind == "nabu_web__chatgpt":
        mode = args.get("mode", "browser_chat")
        if mode == "browser_voice":
            return not args.get("question")
        if mode == "browser_chat":
            return ("question" not in args or
                    isinstance(args["question"], str) and bool(args["question"].strip()))
        if mode == "answer":
            return isinstance(args.get("question"), str) and bool(args["question"].strip())
        return False
    if kind == "nabu_web__grabowski_request":
        return all(isinstance(args.get(x), str) and bool(args[x].strip()) for x in ("objective", "acceptance"))
    if kind == "nabu_web__grabowski":
        op = args.get("operation")
        if op in ("status", "tasks"):
            return True
        if op == "task":
            task_id = args.get("task_id")
            if not isinstance(task_id, str):
                return False
            # Nabu normalizes old task+goo IDs to obligation before read_request.
            if task_id.startswith("goo-"):
                return re.fullmatch(r"goo-[a-z0-9][a-z0-9-]{7,79}", task_id) is not None
            return (8 <= len(task_id) <= 64 and task_id.isascii()
                    and all(ch.isalnum() or ch == "-" for ch in task_id))
        if op == "obligation":
            obligation_id = args.get("obligation_id")
            return (isinstance(obligation_id, str)
                    and re.fullmatch(r"goo-[a-z0-9][a-z0-9-]{7,79}", obligation_id) is not None)
        return False
    if kind.startswith("intent__") or kind.startswith("climate__"):
        return isinstance(args.get("name") or args.get("area"), str) and (
            kind != "climate__HassClimateSetTemperature" or isinstance(args.get("temperature"), (float, int)))
    return False

def score(case, choice, args, answer, tool_calls=None):
    # Preserve the whole tool-call list in the result record: one correct first
    # action never excuses a second unexpected (possibly destructive) action.
    if tool_calls is not None and (
        not isinstance(tool_calls, list) or len(tool_calls) > 1
    ):
        return False
    wanted = case["expected"]
    if wanted == "clarify":
        return choice == "answer" and "?" in answer
    if wanted == "answer":
        return choice == "answer" and bool(answer.strip())
    if choice not in [wanted, *case["alternates"]] or not valid_arguments(choice, args):
        return False
    return all(args.get(name) == value
               for name, value in case.get("expected_arguments", {}).items())

def private_jsonl(directory, stem):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / (stem + ".jsonl")
    return path, path.open("x", encoding="utf-8")

def run(mode, model, timeout, output_dir):
    fixture, tools = validate_fixture()
    fixed = {"case_set_sha256": digest(fixture), "tool_schema_sha256": digest(tools),
             "nabu_source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
             "system_prompt_sha256": hashlib.sha256(evaluation_prompt().encode()).hexdigest(),
             "assist_profile_sha256": hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest(),
             "requested_model": model,
             "public_tool_prompt_sha256": hashlib.sha256(registered_nabu_prompt().encode()).hexdigest(),
             "options": dict(EVAL_OPTIONS), "think": THINK, "keep_alive": KEEP_ALIVE,
             "scope": "direct Ollama; versioned Assist profile; synthetic public prompt and temperature=0; no private HA prompt or live device schemas; tools never executed; no HA authentication"}
    if mode == "check":
        print(json.dumps({"ok": True, "cases": len(fixture), "families": len(GROUPS), **fixed}, sort_keys=True))
        return 0
    identity = model_identity(model)
    if mode == "smoke":
        for text, wanted in DEVELOPMENT_SMOKE:
            response, seconds = chat(model, text, [], tools, timeout)
            message = response.get("message") or {}
            got, args, answer = selection(message)
            raw_calls = message.get("tool_calls") or []
            correct = (got == wanted and valid_arguments(got, args)
                       and isinstance(raw_calls, list) and len(raw_calls) <= 1)
            print(json.dumps({"smoke": wanted, "got": got, "correct": correct,
                              "tool_call_count": len(raw_calls), "seconds": seconds}))
        return 0
    stem = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + model.replace("/", "-").replace(":", "-")
    old_umask = os.umask(0o077)
    try:
        path, handle = private_jsonl(output_dir, stem)
    finally:
        os.umask(old_umask)
    successes = {}
    latencies = {}
    failures = []
    max_consecutive = 0
    with handle as out:
        out.write(json.dumps({"record": "manifest", "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                              "model": identity, **fixed}, ensure_ascii=False) + "\n")
        out.flush()
        os.fsync(out.fileno())
        for case in fixture:
            row = {"record": "case", "id": case["id"], "family": case["family"],
                   "critical": case["critical"], "expected": case["expected"],
                   "alternates": case["alternates"],
                   "expected_arguments": case.get("expected_arguments", {})}
            try:
                response, duration = chat(model, case["prompt"], case["history"], tools, timeout)
                message = response.get("message") or {}
                raw_calls = message.get("tool_calls") or []
                # Store raw calls before parsing: malformed or additional calls
                # must remain audit-visible even when the first one is valid.
                row["tool_calls"] = raw_calls
                allowed = {case["expected"], *case["alternates"]}
                effectful = {"nabu_web__play_music", "nabu_web__browser",
                             "nabu_web__grabowski_request", "nabu_web__chatgpt"}
                unrequested = []
                for index, call in enumerate(raw_calls if isinstance(raw_calls, list) else []):
                    fn = call.get("function") if isinstance(call, dict) else None
                    name = fn.get("name") if isinstance(fn, dict) else None
                    if (isinstance(name, str)
                            and (name.startswith(("intent__", "climate__")) or name in effectful)
                            and (index > 0 or name not in allowed)):
                        unrequested.append(name)
                row["unrequested_effectful_tools"] = unrequested
                row["critical"] = bool(case["critical"] or unrequested)
                got, args, answer = selection(message)
                passed = score(case, got, args, answer, raw_calls)
                row.update({"got": got, "args": args, "answer": answer[:1200],
                            "latency_s": duration, "load_s": round(response.get("load_duration", 0)/1e9, 3),
                            "pass": passed})
                max_consecutive = 0
                latencies.setdefault(case["family"], []).append(duration)
            except (urllib.error.URLError, TimeoutError, ValueError, KeyError, TypeError) as exc:
                row.update({"pass": False, "error": type(exc).__name__})
                max_consecutive += 1
            successes.setdefault(case["family"], []).append(row["pass"])
            if not row["pass"]:
                failures.append({"id": row["id"], "expected": row["expected"], "got": row.get("got"),
                                 "error": row.get("error"), "critical": row["critical"]})
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            out.flush()
            os.fsync(out.fileno())
            if max_consecutive >= 3:
                raise RuntimeError("Three consecutive Ollama errors; stopped rather than looping")
    summary = {"status": "completed", "model": identity["name"], "model_digest": identity["digest"],
               "nabu_source_sha256": fixed["nabu_source_sha256"], "case_set_sha256": fixed["case_set_sha256"],
               "tool_schema_sha256": fixed["tool_schema_sha256"],
               "assist_profile_sha256": fixed["assist_profile_sha256"],
               "system_prompt_sha256": fixed["system_prompt_sha256"],
               "options": fixed["options"], "think": fixed["think"], "keep_alive": fixed["keep_alive"],
               "cases": sum(len(v) for v in successes.values()),
               "passed": sum(sum(v) for v in successes.values()),
               "critical_failures": sum(1 for f in failures if f["critical"]),
               "families": {key: {"n": len(items), "passed": sum(items),
                                  "median_s": round(statistics.median(latencies[key]), 3) if latencies.get(key) else None}
                            for key, items in successes.items()},
               "failures": failures, "result_file": str(path),
               "limitations": fixed["scope"]}
    spath = path.with_suffix(".summary.json")
    old_umask = os.umask(0o077)
    try:
        with spath.open("x", encoding="utf-8") as summary_out:
            json.dump(summary, summary_out, ensure_ascii=False, indent=2)
            summary_out.flush()
            os.fsync(summary_out.fileno())
    finally:
        os.umask(old_umask)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--check", action="store_const", const="check", dest="mode")
    choice.add_argument("--smoke", action="store_const", const="smoke", dest="mode")
    choice.add_argument("--run", action="store_const", const="run", dest="mode")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--timeout", type=int, default=95)
    parser.add_argument("--output-dir", type=Path, default=RESULT_DIR)
    args = parser.parse_args()
    if args.timeout < 5 or args.timeout > 240:
        parser.error("--timeout must be 5..240 seconds")
    sys.exit(run(args.mode, args.model, args.timeout, args.output_dir))

if __name__ == "__main__":
    main()
