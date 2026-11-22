"""Optional ChatGPT-plan inference for Nabu after local user-consented SIWC login.

The OAuth callback and identity verification live in siwc_login.py on the host.
Home Assistant only consumes the protected credential file and refreshes tokens.
No ChatGPT browser sessions, API keys or arbitrary tool calls are involved.
"""
from __future__ import annotations

import asyncio
import codecs
import json
import os
from pathlib import Path
import tempfile
import time

import aiohttp

CREDENTIALS = Path(os.environ.get("NABU_SIWC_CREDENTIALS", "/config/.nabu-chatgpt.json"))
TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token"
API_ROOT = "https://api.openai.com/v1"
SCOPE = "chatgpt.tokens.use.direct"
MAX_QUESTION = 5000
MAX_RESPONSE = 4000
_lock = asyncio.Lock()


class ChatGPTUnavailable(RuntimeError):
    """No proven ChatGPT response; local Nabu remains usable."""


def read_credentials(path: Path = CREDENTIALS) -> dict:
    try:
        if path.stat().st_mode & 0o077:
            raise ChatGPTUnavailable("Nabu-ChatGPT-Zugangsdaten sind nicht privat abgelegt")
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ChatGPTUnavailable(
            "ChatGPT noch nicht verbunden: zuerst siwc_login.py auf dem Heim-PC ausführen"
        ) from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ChatGPTUnavailable("Nabu-ChatGPT-Zugangsdaten nicht lesbar") from None
    if not isinstance(data, dict) or not data.get("plan_usage_enabled"):
        raise ChatGPTUnavailable("ChatGPT-Plan-Nutzung wurde nicht freigegeben")
    if SCOPE not in data.get("scopes", []):
        raise ChatGPTUnavailable("ChatGPT-Plan-Berechtigung fehlt")
    if not (data.get("client_id") and data.get("access_token")
            and data.get("model_slug")):
        raise ChatGPTUnavailable("Nabu-ChatGPT-Anmeldung unvollständig")
    return data


def save_credentials(path: Path, data: dict) -> None:
    filename = None
    try:
        fd, filename = tempfile.mkstemp(prefix=".nabu-siwc-refresh-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            os.fchmod(file.fileno(), 0o600)
            json.dump(data, file, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())
        os.replace(filename, path)
        os.chmod(path, 0o600)
    finally:
        if filename and os.path.exists(filename):
            os.unlink(filename)


async def authorized_session(session: aiohttp.ClientSession,
                             credentials_path: Path = CREDENTIALS) -> dict:
    """Serialize rotating refresh tokens within Home Assistant's process."""
    async with _lock:
        record = read_credentials(credentials_path)
        now = int(time.time())
        deadline = int(record.get("saved_at_unix", 0)) + int(record.get("expires_in", 0))
        if now < deadline - 90:
            return record
        if not record.get("refresh_token"):
            raise ChatGPTUnavailable("ChatGPT-Anmeldung abgelaufen; erneut anmelden")
        data = {
            "grant_type": "refresh_token",
            "client_id": record["client_id"],
            "refresh_token": record["refresh_token"],
            "resource": API_ROOT,
        }
        try:
            async with session.post(
                TOKEN_URL, data=data,
                timeout=aiohttp.ClientTimeout(total=20, connect=5),
            ) as response:
                if response.status != 200:
                    raise ChatGPTUnavailable(
                        f"ChatGPT-OAuth-Erneuerung nicht autorisiert ({response.status})"
                    )
                tokens = await response.json()
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise ChatGPTUnavailable("ChatGPT-OAuth-Erneuerung nicht erreichbar") from exc
        new_scopes = str(tokens.get("scope") or "").split()
        if new_scopes and SCOPE not in new_scopes:
            raise ChatGPTUnavailable("ChatGPT-Plan-Berechtigung wurde entzogen")
        if not tokens.get("access_token") or not tokens.get("refresh_token"):
            raise ChatGPTUnavailable("ChatGPT-OAuth-Erneuerung unvollständig")
        record.update({
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_in": int(tokens.get("expires_in", 3600)),
            "saved_at_unix": int(time.time()),
            "earliest_refresh_at": tokens.get("earliest_refresh_at"),
        })
        if new_scopes:
            record["scopes"] = new_scopes
        if tokens.get("id_token"):
            record["id_token"] = tokens["id_token"]
        try:
            save_credentials(credentials_path, record)
        except OSError as exc:
            # Rotated refresh token must not be lost or reused from an older file.
            raise ChatGPTUnavailable("Neue ChatGPT-Anmeldung konnte nicht sicher gespeichert werden") from exc
        return record


def extract_sse_data(event: str) -> dict | None:
    lines = [line[5:].strip() for line in event.split("\n") if line.startswith("data:")]
    if not lines:
        return None
    text = "\n".join(lines)
    if text == "[DONE]":
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        raise ChatGPTUnavailable("Ungültige ChatGPT-Stream-Antwort") from None


async def chatgpt_answer(session: aiohttp.ClientSession, question: str,
                         credentials_path: Path = CREDENTIALS) -> dict:
    if not isinstance(question, str) or not question.strip():
        raise ValueError("ChatGPT-Frage fehlt")
    record = await authorized_session(session, credentials_path)
    payload = {
        "model": record["model_slug"],
        "input": [{"role": "user", "content": question.strip()[:MAX_QUESTION]}],
        "store": False,
        "stream": True,
        "max_output_tokens": 700,
    }
    headers = {"Authorization": "Bearer " + record["access_token"]}
    output = []
    completed = False
    pending = ""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    try:
        async with session.post(
            API_ROOT + "/responses", json=payload, headers=headers,
            timeout=aiohttp.ClientTimeout(total=150, connect=8),
        ) as response:
            if response.status != 200:
                raise ChatGPTUnavailable(
                    f"ChatGPT-Inferenz nicht verfügbar (HTTP {response.status}); "
                    "Nabu bleibt lokal nutzbar"
                )
            async for chunk in response.content.iter_any():
                pending += decoder.decode(chunk)
                pending = pending.replace("\r\n", "\n")
                if len(pending) > 150_000:
                    raise ChatGPTUnavailable("ChatGPT-Antwort über dem Größenlimit")
                while "\n\n" in pending:
                    event, pending = pending.split("\n\n", 1)
                    value = extract_sse_data(event)
                    if not value:
                        continue
                    event_type = value.get("type")
                    if event_type == "response.output_text.delta":
                        output.append(str(value.get("delta", "")))
                    elif event_type == "response.completed":
                        completed = True
                    elif event_type in ("response.failed", "response.incomplete", "error"):
                        err = value.get("response", {}).get("error") or value.get("error") or {}
                        code = str(err.get("code") or event_type)[:100] if isinstance(err, dict) else event_type
                        raise ChatGPTUnavailable(f"ChatGPT-Antwort nicht abgeschlossen ({code})")
    except (aiohttp.ClientError, TimeoutError, UnicodeError) as exc:
        raise ChatGPTUnavailable("ChatGPT-Stream fehlerhaft oder unterbrochen; kein Ergebnis bestätigt") from exc
    answer = "".join(output).strip()
    if not completed or not answer:
        raise ChatGPTUnavailable("ChatGPT lieferte keine vollständig bestätigte Antwort")
    return {
        "status": "answered", "model": record["model_slug"],
        "answer": answer[:MAX_RESPONSE], "provider": "ChatGPT-Plus-OAuth",
    }