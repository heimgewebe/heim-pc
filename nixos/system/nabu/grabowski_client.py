"""Small, bounded client for the existing Grabowski MCP operator.

The caller chooses an operation, never an arbitrary tool name, path or command.
The server remains the sole authority for admission, mutations and receipts.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import time
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import aiohttp

MCP_ENDPOINT = "http://127.0.0.1:18181/mcp"
MAX_RESPONSE_BYTES = 256_000
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


class GrabowskiUnavailable(RuntimeError):
    """A request was not confirmed by Grabowski; do not claim success."""


# A normal browser session owns ChatGPT authentication and plugin permissions.
# Nabu's anonymous CDP browser and OAuth answer tool remain separate.
CHATGPT_HOME_URL = "https://chatgpt.com/"
CHATGPT_TEXT_PREFIX = CHATGPT_HOME_URL + "?prompt="
CHATGPT_VOICE_URL = CHATGPT_HOME_URL + "?mode=voice"
# The new Nabu profile is intentionally distinct from the user's Default.
# KDE hands the application to its desktop lifecycle, also on a cold start.
# Running Chrome directly inside a bounded task kills a new browser at timeout.
# Keep the exact dedicated profile and URL; never fall back to xdg-open.
CHATGPT_BROWSER_BIN = "/home/alex/.nix-profile/bin/google-chrome"
CHATGPT_BROWSER_PROFILE = "Profile 1"
CHATGPT_BROWSER_PROFILE_ARG = "--profile-directory=" + CHATGPT_BROWSER_PROFILE
CHATGPT_BROWSER_PREFIX = ("/run/current-system/sw/bin/kstart", "--desktopfile",
                          "nabu-chatgpt", "--", CHATGPT_BROWSER_BIN,
                          CHATGPT_BROWSER_PROFILE_ARG)
CHATGPT_BROWSER_ARGV = (*CHATGPT_BROWSER_PREFIX, CHATGPT_VOICE_URL)
MAX_CHATGPT_PROMPT_URL_BYTES = 4800
CHATGPT_SENDER_KEY_PATH = Path("/config/.nabu-chatgpt-autosend.key")


def _sender_key() -> bytes | None:
    """Private per-installation sender key; missing extension keeps manual mode."""
    try:
        raw = CHATGPT_SENDER_KEY_PATH.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as exc:
        raise GrabowskiUnavailable("Nabu-Sendesignatur nicht lesbar") from exc
    if re.fullmatch(r"[0-9a-f]{64}", raw) is None:
        raise GrabowskiUnavailable("Nabu-Sendesignatur ist ungueltig")
    return bytes.fromhex(raw)


def _autosend_signature(key: bytes, ts: int, nonce: str, prompt: str) -> str:
    value = "nabu-send-v1\n" + str(ts) + "\n" + nonce + "\n" + prompt
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def chatgpt_text_url(question: str | None) -> str:
    """Build one bounded ChatGPT composer deep link without arbitrary URLs."""
    if question is None:
        return CHATGPT_HOME_URL
    if not isinstance(question, str) or not question.strip():
        raise ValueError("Für einen ChatGPT-Textauftrag ist Text erforderlich")
    question = question.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in question):
        raise ValueError("ChatGPT-Textauftrag enthält Steuerzeichen")
    encoded = quote(question, safe="")
    if len(encoded.encode("ascii")) > MAX_CHATGPT_PROMPT_URL_BYTES:
        raise ValueError("ChatGPT-Textauftrag ist für einen Browserlink zu lang")
    url = CHATGPT_TEXT_PREFIX + encoded
    key = _sender_key()
    if key is not None:
        ts = int(time.time())
        nonce = secrets.token_hex(12)
        sig = _autosend_signature(key, ts, nonce, question)
        url += f"&nabu_ts={ts}&nabu_nonce={nonce}&nabu_sig={sig}"
        if len(url.encode("ascii")) > MAX_CHATGPT_PROMPT_URL_BYTES + len(CHATGPT_TEXT_PREFIX):
            raise ValueError("Signierter ChatGPT-Browserlink ist zu lang")
    return url


def chatgpt_text_launch_args(question: str | None = None) -> dict:
    """Open ChatGPT only in the dedicated persistent Nabu Chrome profile."""
    return {
        "host": "heim-pc",
        "argv": [*CHATGPT_BROWSER_PREFIX, chatgpt_text_url(question)],
        "runtime_seconds": 60,
        "resume_policy": "never",
        "resource_keys": [],
        "reason": "Nabu: ChatGPT-Textchat im Desktopbrowser oeffnen",
        "user_intent": "Nutzer uebergibt ChatGPT einen Textauftrag ueber Nabu",
    }


def is_fixed_chatgpt_text_launch(args: dict) -> bool:
    """Admit only exact canonical Nabu drafts and signed short-lived sends."""
    if not isinstance(args, dict):
        return False
    argv = args.get("argv")
    if (not isinstance(argv, list) or len(argv) != len(CHATGPT_BROWSER_PREFIX) + 1
            or argv[:-1] != list(CHATGPT_BROWSER_PREFIX)):
        return False
    url = argv[-1]
    if url == CHATGPT_HOME_URL:
        valid_url = True
    elif isinstance(url, str) and url.startswith(CHATGPT_TEXT_PREFIX):
        try:
            if len(url.encode("ascii")) > MAX_CHATGPT_PROMPT_URL_BYTES + len(CHATGPT_TEXT_PREFIX):
                return False
            parsed = urlsplit(url)
            entries = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            names = [key for key, _ in entries]
            # The verifier must enforce the constructor's restrictions too.
            prompt_text = entries[0][1] if names and names[0] == "prompt" else ""
            if not prompt_text or any(ord(char) < 32 or ord(char) == 127 for char in prompt_text):
                return False
            valid_url = False
            if (parsed.scheme == "https" and parsed.netloc == "chatgpt.com"
                    and parsed.path == "/" and not parsed.fragment):
                if names == ["prompt"]:
                    prompt = entries[0][1]
                    valid_url = url == CHATGPT_TEXT_PREFIX + quote(prompt.strip(), safe="")
                elif names == ["prompt", "nabu_ts", "nabu_nonce", "nabu_sig"]:
                    prompt, ts_text, nonce, signature = (item[1] for item in entries)
                    key = _sender_key()
                    if (key is not None and prompt == prompt.strip() and prompt
                            and re.fullmatch(r"[0-9]{10}", ts_text)
                            and re.fullmatch(r"[a-f0-9]{24}", nonce)
                            and re.fullmatch(r"[a-f0-9]{64}", signature)):
                        ts = int(ts_text)
                        if -15 <= int(time.time()) - ts <= 180:
                            digest = _autosend_signature(key, ts, nonce, prompt)
                            canonical = (CHATGPT_TEXT_PREFIX + quote(prompt, safe="")
                                         + f"&nabu_ts={ts_text}&nabu_nonce={nonce}"
                                         + f"&nabu_sig={signature}")
                            valid_url = (hmac.compare_digest(digest, signature)
                                         and url == canonical)
        except (TypeError, ValueError, GrabowskiUnavailable):
            return False
    else:
        return False
    if not valid_url:
        return False
    expected = {
        "host": "heim-pc",
        "argv": [*CHATGPT_BROWSER_PREFIX, url],
        "runtime_seconds": 60,
        "resume_policy": "never",
        "resource_keys": [],
        "reason": "Nabu: ChatGPT-Textchat im Desktopbrowser oeffnen",
        "user_intent": "Nutzer uebergibt ChatGPT einen Textauftrag ueber Nabu",
    }
    return args == expected

def chatgpt_voice_launch_args() -> dict:
    """Immutable allowlisted effect: start only the ChatGPT Voice desktop URL."""
    return {
        "host": "heim-pc",
        "argv": list(CHATGPT_BROWSER_ARGV),
        "runtime_seconds": 60,
        "resume_policy": "never",
        "resource_keys": [],
        "reason": "Nabu: ChatGPT Live im normalen Desktopbrowser oeffnen",
        "user_intent": "Nutzer fordert ChatGPT Voice mit bestehenden ChatGPT-Plugins",
    }


async def _start_chatgpt_desktop(session: aiohttp.ClientSession, launch_args: dict) -> tuple[str, str | None]:
    """Verify one browser-start task without reading ChatGPT content or cookies."""
    result = await mcp_call(session, "grabowski_task_start", launch_args)
    task = result.get("task") if isinstance(result, dict) else None
    launcher = task.get("launcher") if isinstance(task, dict) else None
    if (not isinstance(task, dict)
            or not isinstance(task.get("task_id"), str)
            or re.fullmatch(r"[0-9a-f]{24}", task["task_id"]) is None
            or not isinstance(launcher, dict) or launcher.get("returncode") != 0):
        raise GrabowskiUnavailable("Grabowski hat keinen gueltigen Browser-Startbeleg geliefert")
    task_id = task["task_id"]
    # The start receipt alone does not prove a visible, authenticated Voice session.
    try:
        observed = await mcp_call(session, "grabowski_task_status", {
            "task_id": task_id,
            "reason": "Nabu: exakten Browser-Startstatus pruefen",
            "user_intent": "Nutzer moechte ChatGPT Live im Browser nutzen",
        })
    except GrabowskiUnavailable:
        observed = {}
    if observed and observed.get("task_id") != task_id:
        raise GrabowskiUnavailable("Browser-Startstatus gehoert zu einer anderen Aufgabe")
    state = observed.get("state")
    if state in ("failed", "timed_out", "cancelled", "interrupted", "outcome_unknown"):
        raise GrabowskiUnavailable("Der ChatGPT-Browserstart wurde nicht erfolgreich abgeschlossen")
    return task_id, state


async def start_chatgpt_browser_voice(session: aiohttp.ClientSession) -> dict:
    """Open Voice only on explicit request; browser activation is not proven."""
    task_id, state = await _start_chatgpt_desktop(session, chatgpt_voice_launch_args())
    return {
        "status": "start_completed" if state == "completed" else "start_requested",
        "task_id": task_id,
        "voice_url": CHATGPT_VOICE_URL,
        "browser_login_verified": False,
        "microphone_verified": False,
        "chatgpt_voice_active_verified": False,
        "message": ("ChatGPT Live wurde im normalen Desktopbrowser angefordert. "
                    "Anmeldung und Sprachmodus gegebenenfalls im Browser bestaetigen."),
    }


async def start_chatgpt_browser_text(
    session: aiohttp.ClientSession, question: str | None = None,
) -> dict:
    """Open the text composer with Nabu's user-authored message; no output extraction."""
    launch = chatgpt_text_launch_args(question)
    task_id, state = await _start_chatgpt_desktop(session, launch)
    return {
        "status": "browser_opened" if state == "completed" else "browser_open_requested",
        "task_id": task_id,
        "mode": "browser_chat",
        "text_prefill_requested": question is not None,
        "auto_send_requested": "&nabu_sig=" in launch["argv"][-1],
        "composer_prefill_verified": False,
        "message_sent_verified": False,
        "chatgpt_login_verified": False,
        "chatgpt_response_verified": False,
        "message": (
            "ChatGPT-Textchat im normalen Desktopbrowser angefordert. "
            + ("Automatischer Sendeklick ist angefordert; pruefe die Nachricht im Browser. "
               if "&nabu_sig=" in launch["argv"][-1] else
               "Pruefe den Entwurf und klicke auf Senden. "
               if question is not None else
               "Gib den Auftrag im ChatGPT-Eingabefeld ein. ")
            + "Ein abgeschickter ChatGPT-Auftrag ist noch nicht bestaetigt."
        ),
    }


def parse_mcp_response(raw: str, request_id: int = 1) -> dict:
    """Extract the exact matching JSON-RPC result from JSON or MCP SSE."""
    messages = []
    try:
        messages.append(json.loads(raw))
    except json.JSONDecodeError:
        for line in raw.splitlines():
            if line.startswith("data:"):
                try:
                    messages.append(json.loads(line[5:].strip()))
                except json.JSONDecodeError:
                    continue
    for message in messages:
        if not isinstance(message, dict) or message.get("id") != request_id:
            continue
        if "error" in message:
            err = message["error"]
            text = err.get("message", "MCP-Fehler") if isinstance(err, dict) else err
            raise GrabowskiUnavailable(str(text)[:250])
        result = message.get("result")
        if not isinstance(result, dict):
            raise GrabowskiUnavailable("Ungültige MCP-Antwort von Grabowski")
        if result.get("isError"):
            raise GrabowskiUnavailable("Grabowski hat den Aufruf abgewiesen")
        if isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        for item in result.get("content") or []:
            if isinstance(item, dict) and item.get("type") == "text":
                try:
                    parsed = json.loads(item["text"])
                    if isinstance(parsed, dict):
                        return parsed
                except (KeyError, TypeError, json.JSONDecodeError):
                    pass
        return result
    raise GrabowskiUnavailable("Keine bestätigte MCP-Antwort von Grabowski")


async def mcp_call(session: aiohttp.ClientSession, name: str, args: dict,
                   *, endpoint: str = MCP_ENDPOINT, timeout_seconds: int = 20) -> dict:
    """Invoke a fixed call; success requires a matching server result."""
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }
    try:
        async with session.post(
            endpoint, headers=MCP_HEADERS, json=payload,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds, connect=4),
        ) as response:
            response.raise_for_status()
            chunks = []
            total = 0
            async for part in response.content.iter_any():
                total += len(part)
                if total > MAX_RESPONSE_BYTES:
                    raise GrabowskiUnavailable("MCP-Antwort über dem Größenlimit")
                chunks.append(part)
            raw_response = b"".join(chunks).decode("utf-8", errors="replace")
            try:
                return parse_mcp_response(raw_response)
            except GrabowskiUnavailable:
                # Grabowski's native transport challenges some read-only tools.
                # Never retry the original request: only execute its exact
                # already-issued challenge, with all target arguments unchanged.
                allowed = {"grabowski_status", "grabowski_task_list", "grabowski_task_status"}
                fixed_obligation_read = (
                    name == "grip_run"
                    and args.get("name") == "operator-obligation-status"
                    and args.get("allow_mutation") is False
                    and isinstance(args.get("parameters"), dict)
                    and set(args["parameters"]) == {"obligation_id"}
                    and isinstance(args["parameters"]["obligation_id"], str)
                    and re.fullmatch(r"goo-[a-z0-9][a-z0-9-]{7,79}",
                                     args["parameters"]["obligation_id"]) is not None
                )
                # The sole browser write capability is an exact, bounded ChatGPT
                # desktop launch. Never generalize it to arbitrary commands.
                fixed_browser_launch = (
                    name == "grabowski_task_start"
                    and (args == chatgpt_voice_launch_args()
                         or is_fixed_chatgpt_text_launch(args))
                )
                if ((name not in allowed and not fixed_obligation_read
                     and not fixed_browser_launch)
                        or "fresh intent-bound transport verification required" not in raw_response):
                    raise
                match = re.search(r"challenge_receipt_sha256=([0-9a-f]{64})", raw_response)
                if not match:
                    raise
                verified = await mcp_call(session, "grip_run", {
                    "name": "transport-roundtrip",
                    "parameters": {
                        "action": "execute",
                        "challenge_receipt_sha256": match.group(1),
                        "target_tool_name": name,
                        "target_arguments": args,
                    },
                    "allow_mutation": fixed_browser_launch,
                    "reason": ("Nabu: fest gebundenen ChatGPT-Browserstart verifizieren"
                               if fixed_browser_launch else
                               "Nabu: bereits gebundene read-only-Verifikationsanfrage ausführen"),
                    "user_intent": ("Nabu öffnet auf ausdrücklichen Wunsch ChatGPT im Browser"
                                    if fixed_browser_launch else
                                    "Nabu liest vom Benutzer verlangte Grabowski-Daten"),
                }, endpoint=endpoint, timeout_seconds=60 if fixed_browser_launch else 20)
                output = verified.get("output") or {}
                if (verified.get("status") != "passed" or output.get("state") != "executed"
                        or not isinstance(output.get("target_result"), dict)):
                    raise GrabowskiUnavailable("Grabowski hat die Read-only-Verifikation nicht bestätigt")
                return output["target_result"]
    except (aiohttp.ClientError, TimeoutError) as exc:
        if timeout_seconds == 60:
            # The bound browser launch may already have executed before the
            # receipt reaches us. Do not retry or misreport it as not started.
            raise GrabowskiUnavailable(
                "ChatGPT-Browserstart möglicherweise ausgelöst; Bestätigung fehlt. "
                "Bitte Browser prüfen, nicht automatisch erneut senden."
            ) from exc
        raise GrabowskiUnavailable("Grabowski derzeit nicht erreichbar; Aktion nicht bestätigt") from exc


def normalize_read_operation(
    operation: str, task_id: str = "", obligation_id: str = "",
) -> tuple[str, str]:
    """Correct a Qwen task selection when the supplied ID is an obligation ID."""
    if operation == "task" and isinstance(task_id, str) and task_id.startswith("goo-"):
        return "obligation", task_id
    return operation, obligation_id


def read_request(operation: str, task_id: str = "", obligation_id: str = "") -> tuple[str, dict]:
    """Hard-coded read-only API exposed to Nabu, no arbitrary MCP passthrough."""
    intent = "Nabu fragt den bestehenden Grabowski-Operator nach dem Zustand"
    if operation == "status":
        return "grabowski_status", {
            "view": "minimal",
            "reason": "Nabu-Assist: Operatorstatus",
            "user_intent": intent,
        }
    if operation == "tasks":
        return "grabowski_task_list", {
            "view": "minimal", "limit": 5,
            "reason": "Nabu-Assist: aktuelle Grabowski-Aufgaben",
            "user_intent": intent,
        }
    if operation == "task":
        if not isinstance(task_id, str) or not 8 <= len(task_id) <= 64 or not all(
            ch.isascii() and (ch.isalnum() or ch == "-") for ch in task_id
        ):
            raise ValueError("Ungültige Grabowski-Task-ID")
        return "grabowski_task_status", {
            "task_id": task_id,
            "reason": "Nabu-Assist: exakte Grabowski-Task prüfen",
            "user_intent": intent,
        }
    if operation == "obligation":
        if not isinstance(obligation_id, str) or not re.fullmatch(
            r"goo-[a-z0-9][a-z0-9-]{7,79}", obligation_id
        ):
            raise ValueError("Ungültige Grabowski-Obligation-ID")
        return "grip_run", {
            "name": "operator-obligation-status",
            "parameters": {"obligation_id": obligation_id},
            "allow_mutation": False,
            "reason": "Nabu-Assist: exakten Grabowski-Auftragsfortschritt lesen",
            "user_intent": "Nabu fragt den Status eines zuvor registrierten Auftrags ab",
        }
    raise ValueError("Unbekannter Grabowski-Leseauftrag")


def compact_result(operation: str, result: dict) -> dict:
    """Keep spoken results bounded and never relay raw private tool inventories."""
    if operation == "status":
        return {
            "healthy": result.get("healthy"),
            "mode": result.get("mode"),
            "release": (result.get("runtime") or {}).get("release_id"),
            "registered_tools": (result.get("tool_contract") or {}).get("registered_tool_count"),
        }
    if operation == "tasks":
        tasks = result.get("tasks") or []
        return {
            "total_matching": result.get("total_matching"),
            "tasks": [
                {k: t.get(k) for k in ("task_id", "state", "host", "recommended_next_action")}
                for t in tasks[:5] if isinstance(t, dict)
            ],
        }
    if operation == "task":
        return {
            k: result.get(k) for k in
            ("task_id", "host", "state", "attempt", "recommended_next_action",
             "lifecycle_receipt_sha256")
        }
    if operation == "obligation":
        output = result.get("output")
        if (result.get("status") != "passed" or not isinstance(output, dict)
                or not isinstance(output.get("obligation_id"), str)
                or not isinstance(output.get("work_complete"), bool)
                or not isinstance(output.get("continuation_required"), bool)):
            raise GrabowskiUnavailable("Grabowski hat den Auftragsstatus nicht bestätigt")
        return {
            "obligation_id": output["obligation_id"],
            "state": output.get("state"),
            "work_complete": output["work_complete"],
            "continuation_required": output["continuation_required"],
            "missing_acceptance_ids": output.get("missing_acceptance_ids", [])[:8],
            "recommended_next_action": str(output.get("recommended_next_action") or "")[:160],
        }
    raise ValueError("Ungültiges Operationsergebnis")



_STATUS_OBJECTIVE_WORDS = frozenset("""
pruefe ueberpruefe kontrolliere checke ermittle bitte jetzt einmal nur den des die der
seinen seinem aktuellen lokalen status gesundheitsstatus zustand erreichbarkeit von
grabowski operators operator und wie viele anzahl registrierten registriert
mcp werkzeuge tools bereitstehen sind berichte ob er ohne systemaenderungen vorzunehmen
""".split())
_STATUS_ACCEPTANCE_WORDS = frozenset("""
fertig wenn status und toolanzahl werkzeuganzahl healthy wert belegt sind
stehen fest erfolg erfolgreich die der registrierten mcp werkzeuge
tools anzahl ist belegbar beweise nachgewiesen berichtet
""".split())


def _status_words(value: str) -> set[str] | None:
    if not isinstance(value, str) or not value or len(value) > 260:
        return None
    value = value.casefold().translate(str.maketrans({
        "ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
    }))
    if re.fullmatch(r"[a-z0-9 ,.!?\-]+", value) is None:
        return None
    return set(re.findall(r"[a-z0-9]+", value))


def _bounded_operator_status_request(objective: str, acceptance: str) -> bool:
    """Never guess authority to run non-status work from spoken text."""
    o, a = _status_words(objective), _status_words(acceptance)
    return bool(
        o and a and len(acceptance) <= 180
        and o <= _STATUS_OBJECTIVE_WORDS and a <= _STATUS_ACCEPTANCE_WORDS
        and o & {"pruefe", "ueberpruefe", "kontrolliere", "checke", "ermittle"}
        and o & {"status", "gesundheitsstatus", "zustand", "erreichbarkeit"}
        and o & {"werkzeuge", "tools"}
        and a & {"healthy", "status"}
        and a & {"werkzeuganzahl", "toolanzahl", "werkzeuge", "tools"}
        # A measured Healthy value may be false. Never auto-complete a
        # predicate that requires the operator to BE healthy.
        and ("healthy" not in a or ("wert" in a and "ist" not in a))
        and ("belegt" in a or {"stehen", "fest"} <= a)
    )


async def _close_status_only(session: aiohttp.ClientSession, params: dict,
                             *, endpoint: str) -> dict:
    """Exactly one authorized Grabowski close; no automatic mutation retry."""
    target = {
        "name": "operator-obligation-close", "parameters": params,
        "allow_mutation": True,
        "reason": "Nabu: ausgeführten Statusauftrag schließen",
        "user_intent": "Nabu schließt einen erfolgreichen read-only Auftrag",
    }
    reason = "Nabu: nur die vorab gebundene Statusprüfung schließen"
    begin = await mcp_call(session, "grip_run", {
        "name": "transport-roundtrip",
        "parameters": {
            "action": "begin", "target_tool_name": "grip_run",
            "target_arguments": target,
        },
        "allow_mutation": True, "reason": "Nabu: Abschlussbindung",
        "user_intent": reason,
    }, endpoint=endpoint)
    payload = begin.get("output") or {}
    challenge = payload.get("challenge_receipt_sha256")
    if (begin.get("status") != "passed"
            or (begin.get("receipt") or {}).get("status") != "passed"
            or payload.get("state") != "challenge_pending"
            or not isinstance(challenge, str)
            or re.fullmatch(r"[0-9a-f]{64}", challenge) is None):
        raise GrabowskiUnavailable("Statusabschluss ist nicht gebunden")
    response = await mcp_call(session, "grip_run", {
        "name": "transport-roundtrip",
        "parameters": {
            "action": "execute", "challenge_receipt_sha256": challenge,
            "target_tool_name": "grip_run", "target_arguments": target,
        },
        "allow_mutation": True, "reason": "Nabu: gebundener Statusabschluss",
        "user_intent": reason,
    }, endpoint=endpoint)
    output = response.get("output") or {}
    work = output.get("target_result")
    if (response.get("status") != "passed" or output.get("state") != "executed"
            or not isinstance(work, dict) or work.get("status") != "passed"):
        raise GrabowskiUnavailable("Grabowski hat den Statusabschluss nicht bestätigt")
    return work


async def _execute_status_only(session: aiohttp.ClientSession,
                               obligation_id: str, *, endpoint: str) -> dict:
    """Observe actual Grabowski status; verify a process-only close via readback."""
    status = await mcp_call(session, "grabowski_status", {
        "view": "minimal", "reason": "Nabu: aktuellen Operatorstatus prüfen",
        "user_intent": "Grabowski-Gesundheit und Werkzeuge ermitteln",
    }, endpoint=endpoint)
    contract = status.get("tool_contract")
    healthy = status.get("healthy")
    count = contract.get("registered_tool_count") if isinstance(contract, dict) else None
    if type(healthy) is not bool or type(count) is not int or not 0 <= count <= 100_000:
        raise GrabowskiUnavailable("Grabowski-Status wurde nicht bestätigt")
    evidence_hash = hashlib.sha256(json.dumps(
        {"healthy": healthy, "registered_tools": count},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    completed = await _close_status_only(session, {
        "obligation_id": obligation_id, "outcome": "completed",
        "evidence": [{
            "acceptance_id": "result", "status": "passed", "source": "runtime",
            "reference": "grabowski_status:minimal", "sha256": evidence_hash,
        }],
        "closure_classification": {
            "convergence_required": False, "reason": "process_only",
        },
    }, endpoint=endpoint)
    receipt = completed.get("receipt_sha256")
    if not isinstance(receipt, str) or re.fullmatch(r"[0-9a-f]{64}", receipt) is None:
        raise GrabowskiUnavailable("Grabowski-Abschlussreceipt fehlt")
    name, args = read_request("obligation", obligation_id=obligation_id)
    readback = compact_result(
        "obligation", await mcp_call(session, name, args, endpoint=endpoint)
    )
    if (readback["obligation_id"] != obligation_id
            or readback["state"] != "completed"
            or readback["work_complete"] is not True
            or readback["continuation_required"] is not False
            or readback["missing_acceptance_ids"]):
        raise GrabowskiUnavailable("Grabowski-Abschlussreadback stimmt nicht")
    return {
        "status": "completed_process_only", "obligation_id": obligation_id,
        "receipt_sha256": receipt, "completion_scope": "process_only",
        "healthy": healthy, "registered_tools": count,
        "next": "Reine Grabowski-Statusprüfung abgeschlossen; keine Systemänderung",
    }


async def register_obligation(session: aiohttp.ClientSession,
                              objective: str, acceptance: str,
                              *, endpoint: str = MCP_ENDPOINT) -> dict:
    """Register one durable work request, not code execution.

    Existing Grabowski transport-roundtrip binds the exact target to a
    single-use challenge. A lost execution result must never be retried.
    """
    if not isinstance(objective, str) or not 12 <= len(objective.strip()) <= 600:
        raise ValueError("Grabowski-Auftrag muss konkret und begrenzt sein")
    if not isinstance(acceptance, str) or not 12 <= len(acceptance.strip()) <= 500:
        raise ValueError("Ein überprüfbares Erfolgskriterium ist erforderlich")
    objective = objective.strip()
    acceptance = acceptance.strip()
    obligation_id = "goo-nabu-" + hashlib.sha256(
        (objective + "\n" + acceptance).encode("utf-8")
    ).hexdigest()[:20]
    intent = "Nabu übergibt auf ausdrücklichen Benutzerauftrag Arbeit an Grabowski"
    target_args = {
        "name": "operator-obligation-open",
        "parameters": {
            "obligation_id": obligation_id,
            "objective": objective,
            "acceptance": [{"id": "result", "description": acceptance}],
        },
        "allow_mutation": True,
        "reason": "Nabu: expliziten Auftrag mit Erfolgskriterium erfassen",
        "user_intent": intent,
    }
    begin_args = {
        "name": "transport-roundtrip",
        "parameters": {
            "action": "begin",
            "target_tool_name": "grip_run",
            "target_arguments": target_args,
        },
        "allow_mutation": True,
        "reason": "Nabu: Zielaktion exakt an Transport-Challenge binden",
        "user_intent": intent,
    }
    begun = await mcp_call(session, "grip_run", begin_args, endpoint=endpoint)
    initial = begun.get("output") or {}
    receipt = begun.get("receipt") or {}
    challenge = initial.get("challenge_receipt_sha256")
    if (begun.get("status") != "passed" or receipt.get("status") != "passed"
            or initial.get("state") != "challenge_pending"
            or not isinstance(challenge, str) or len(challenge) != 64):
        raise GrabowskiUnavailable("Grabowski hat die Auftragsbindung nicht bestätigt")
    execute_args = {
        "name": "transport-roundtrip",
        "parameters": {
            "action": "execute",
            "challenge_receipt_sha256": challenge,
            "target_tool_name": "grip_run",
            "target_arguments": target_args,
        },
        "allow_mutation": True,
        "reason": "Nabu: genau einen bereits gebundenen Auftrag übergeben",
        "user_intent": intent,
    }
    # A transport failure here leaves the outcome unknown; no automatic retry.
    result = await mcp_call(session, "grip_run", execute_args, endpoint=endpoint)
    outer = result.get("output") or {}
    work_result = outer.get("target_result") or {}
    if (result.get("status") != "passed" or outer.get("state") != "executed"
            or work_result.get("status") != "passed"):
        reason = (work_result.get("output") or {}).get("error", "nicht bestätigt")
        raise GrabowskiUnavailable(f"Grabowski-Auftrag nicht angenommen: {str(reason)[:180]}")
    work_receipt = work_result.get("receipt_sha256")
    if not isinstance(work_receipt, str) or len(work_receipt) != 64:
        raise GrabowskiUnavailable("Grabowski-Auftrag ohne gültigen Empfangsbeleg")
    opened = work_result.get("output")
    if (_bounded_operator_status_request(objective, acceptance)
            and isinstance(opened, dict)
            and opened.get("obligation_id") == obligation_id):
        if (opened.get("state") == "completed"
                and opened.get("work_complete") is True
                and opened.get("completion_scope") == "process_only"):
            return {
                "status": "completed_process_only",
                "obligation_id": obligation_id,
                "receipt_sha256": work_receipt,
                "completion_scope": "process_only",
                "next": "Bereits bestätigter reiner Statusabschluss",
            }
        if opened.get("state") == "open":
            try:
                return await _execute_status_only(
                    session, obligation_id, endpoint=endpoint
                )
            except GrabowskiUnavailable:
                # A lost close response is NOT a retry authorization.
                return {
                    "status": "registered_execution_unconfirmed",
                    "obligation_id": obligation_id,
                    "receipt_sha256": work_receipt,
                    "next": "Auftrag nur lesend auf Abschluss prüfen",
                }
    return {
        "status": "registered_not_executed",
        "obligation_id": obligation_id,
        "receipt_sha256": work_receipt,
        "next": "Grabowski muss die Aufgabe noch ausführen und nachweisen",
    }
