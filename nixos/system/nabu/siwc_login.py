#!/usr/bin/env python3
"""One-time Nabu "Sign in with ChatGPT" setup for a local open-source client.

Run in the Heim-PC graphical login session.  No OpenAI API key, app secret,
ChatGPT cookies or browser-profile access is involved.  Do not run in HA.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit
import uuid
import webbrowser

import requests

ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
AUTH_URL = ISSUER + "/api/accounts/authorize"
TOKEN_URL = ISSUER + "/api/accounts/oauth/token"
DISCOVERY = ISSUER + "/.well-known/openid-configuration"
SCOPE = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
DEFAULT_CREDENTIALS = (
    Path.home() / ".local/share/heimgewebe/home-assistant/.nabu-chatgpt.json"
)


def save_private(path: Path, content: dict) -> None:
    """Atomic owner-only replacement; no tokens printed or committed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".nabu-siwc-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            os.fchmod(out.fileno(), 0o600)
            json.dump(content, out, ensure_ascii=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def load_private(path: Path) -> dict:
    if not path.exists():
        return {}
    if path.stat().st_mode & 0o077:
        raise RuntimeError("Zugangsdaten-Datei darf nicht gruppen- oder weltlesbar sein")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Ungültige Zugangsdaten-Datei")
    return data


def host_id_for(credentials: Path) -> str:
    id_file = credentials.with_name(".nabu-chatgpt-host-id.json")
    data = load_private(id_file)
    if data:
        value = data.get("ext_agent_host_id", "")
        if not isinstance(value, str) or not value.startswith("urn:uuid:"):
            raise ValueError("Ungültige Nabu-Host-ID")
        return value
    value = "urn:uuid:" + str(uuid.uuid4())
    save_private(id_file, {"ext_agent_host_id": value})
    return value


def decode_b64url(value: str) -> bytes:
    """Strict RFC 4648 base64url decoding for signed OAuth/JWK fields."""
    if not isinstance(value, str) or not value or len(value) > 12000:
        raise ValueError("Ungültige signierte Tokenkodierung")
    return base64.b64decode(value + "=" * (-len(value) % 4),
                            altchars=b"-_", validate=True)


def verify_rs256(message: bytes, signature: bytes, key: dict) -> None:
    """RSASSA-PKCS1-v1_5 SHA-256 verification against the issuer's RSA JWK."""
    if key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256":
        raise ValueError("Kein unterstützter RS256-Schlüssel")
    n = int.from_bytes(decode_b64url(key["n"]), "big")
    e = int.from_bytes(decode_b64url(key["e"]), "big")
    size = (n.bit_length() + 7) // 8
    if not 256 <= size <= 1024 or e not in (3, 65537):
        raise ValueError("Ungültiger RSA-OpenAI-Schlüssel")
    if len(signature) != size or not 0 < int.from_bytes(signature, "big") < n:
        raise ValueError("Ungültige RSA-Signaturlänge")
    der_sha256_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info = der_sha256_prefix + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    recovered = pow(int.from_bytes(signature, "big"), e, n).to_bytes(size, "big")
    if not hmac.compare_digest(expected, recovered):
        raise ValueError("ID-Token-Signatur ungültig")


def validate_id_token(id_token: str, client_id: str, nonce: str) -> dict:
    """Verify OpenAI discovery issuer, JWKS key, RS256 signature and OIDC claims."""
    if not isinstance(id_token, str) or len(id_token) > 24000:
        raise ValueError("Ungültiges ID-Token")
    try:
        h, p, s = id_token.split(".")
        header = json.loads(decode_b64url(h))
        claims = json.loads(decode_b64url(p))
        signature = decode_b64url(s)
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("Ungültiges ID-Token-Format") from exc
    if not isinstance(header, dict) or header.get("alg") != "RS256":
        raise ValueError("Nur RS256-signierte ID-Tokens sind zulässig")
    if not isinstance(claims, dict) or not isinstance(header.get("kid"), str):
        raise ValueError("ID-Token-Schlüssel oder Claims fehlen")
    response = requests.get(DISCOVERY, timeout=12)
    response.raise_for_status()
    metadata = response.json()
    if metadata.get("issuer", "").rstrip("/") != ISSUER:
        raise ValueError("OAuth-Aussteller stimmt nicht mit OpenAI überein")
    jwks_uri = metadata.get("jwks_uri", "")
    if not isinstance(jwks_uri, str) or not jwks_uri.startswith(ISSUER + "/"):
        raise ValueError("OAuth-Schlüsselquelle ist nicht die erwartete OpenAI-Domain")
    keys_response = requests.get(jwks_uri, timeout=12)
    keys_response.raise_for_status()
    keys = [key for key in keys_response.json().get("keys", [])
            if isinstance(key, dict) and key.get("kid") == header["kid"]]
    if len(keys) != 1:
        raise ValueError("OpenAI-Signaturschlüssel nicht eindeutig gefunden")
    verify_rs256((h + "." + p).encode("ascii"), signature, keys[0])
    if claims.get("iss") != ISSUER:
        raise ValueError("OAuth-Aussteller ungültig")
    audience = claims.get("aud", [])
    if not (audience == client_id if isinstance(audience, str)
            else isinstance(audience, list) and client_id in audience):
        raise ValueError("ID-Token-Audience ungültig")
    now = int(time.time())
    if not isinstance(claims.get("exp"), int) or claims["exp"] <= now:
        raise ValueError("ID-Token abgelaufen")
    if isinstance(claims.get("nbf"), int) and claims["nbf"] > now:
        raise ValueError("ID-Token noch nicht gültig")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise ValueError("ID-Token-Kontoidentität fehlt")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise ValueError("OAuth-Nonce ungültig")
    return claims


def sign_in(credentials: Path, requested_model: str = "") -> None:
    old = load_private(credentials)
    client_id = old.get("client_id", "dynamic_agent_client")
    if not isinstance(client_id, str) or not client_id:
        raise ValueError("Ungültige Client-Registrierung")
    host_id = host_id_for(credentials)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    received = {}

    class Callback(BaseHTTPRequestHandler):
        def do_GET(self):
            query = urlsplit(self.path)
            if query.path != "/auth/callback":
                self.send_error(404)
                return
            values = parse_qs(query.query)
            given_state = values.get("state", [""])[0]
            if not secrets.compare_digest(given_state, state):
                self.send_error(400, "Ungültiger OAuth-Zustand")
                return
            received["error"] = values.get("error", [""])[0]
            received["code"] = values.get("code", [""])[0]
            received["client_id"] = values.get("client_id", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"Anmeldung an Nabu uebertragen. Dieses Fenster kann geschlossen werden."
            )

        def log_message(self, fmt, *args):
            # Never log a callback path containing OAuth code and state.
            pass

    server = HTTPServer(("127.0.0.1", 0), Callback)
    server.timeout = 300
    try:
        redirect_uri = f"http://127.0.0.1:{server.server_port}/auth/callback"
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": SCOPE,
            "resource": RESOURCE,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "ext_agent_host_id": host_id,
        }
        if client_id == "dynamic_agent_client":
            params["agent_name_hint"] = "Nabu"
        elif old.get("id_token"):
            params["id_token_hint"] = old["id_token"]
        url = AUTH_URL + "?" + urlencode(params)
        print("Nabu: Browseranmeldung ueber OpenAI starten (kein Passwort im Terminal).")
        if not webbrowser.open(url):
            print("Öffne die folgende Adresse im Browser auf dem Heim-PC:\n" + url)
        server.handle_request()
    finally:
        server.server_close()
    if received.get("error"):
        raise RuntimeError("ChatGPT-Anmeldung nicht autorisiert")
    if not received.get("code"):
        raise RuntimeError("Keine autorisierte Browser-Rückmeldung eingegangen")
    issued = received.get("client_id") or (client_id if client_id != "dynamic_agent_client" else "")
    if not issued or (client_id != "dynamic_agent_client" and issued != client_id):
        raise ValueError("OAuth-Client-ID fehlt oder weicht ab")
    token_response = requests.post(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "client_id": issued,
        "code": received["code"],
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "resource": RESOURCE,
    }, timeout=20)
    if token_response.status_code != 200:
        raise RuntimeError(f"OAuth-Tokenaustausch nicht erfolgreich ({token_response.status_code})")
    tokens = token_response.json()
    scopes = str(tokens.get("scope") or "").split()
    claims = validate_id_token(tokens.get("id_token", ""), issued, nonce)
    if old.get("subject") and old["subject"] != claims["sub"]:
        raise ValueError("Der angemeldete ChatGPT-Account ist nicht der bisherige Nabu-Account")
    if not tokens.get("access_token") or not tokens.get("refresh_token"):
        raise ValueError("Erforderliche OAuth-Tokens fehlen")
    allowed = "chatgpt.tokens.use.direct" in scopes
    selected_model = ""
    if allowed:
        models_response = requests.get(
            RESOURCE + "/models",
            headers={"Authorization": "Bearer " + tokens["access_token"]},
            timeout=20,
        )
        if models_response.status_code != 200:
            raise RuntimeError(
                f"Modellkatalog für diesen ChatGPT-Account nicht verfügbar ({models_response.status_code})"
            )
        entries = models_response.json().get("models") or []
        choices = [str(m["slug"]) for m in entries
                   if isinstance(m, dict) and m.get("slug") and m.get("visibility") == "list"]
        if requested_model and requested_model not in choices:
            raise ValueError("Gewähltes Modell steht diesem ChatGPT-Account nicht zur Verfügung")
        selected_model = requested_model or (old.get("model_slug") if old.get("model_slug") in choices else "")
        if not selected_model and choices:
            selected_model = choices[0]
        if not selected_model:
            raise RuntimeError("Keine sichtbaren ChatGPT-Modelle verfügbar")
    now = int(time.time())
    record = {
        "schema_version": 1, "issuer": ISSUER, "subject": claims["sub"],
        "email": claims.get("email", ""), "client_id": issued,
        "ext_agent_host_id": host_id, "model_slug": selected_model,
        "id_token": tokens["id_token"],
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "scopes": scopes,
        "token_type": tokens.get("token_type", "Bearer"),
        "expires_in": int(tokens.get("expires_in", 3600)),
        "saved_at_unix": now,
        "earliest_refresh_at": tokens.get("earliest_refresh_at"),
        "plan_usage_enabled": allowed,
    }
    save_private(credentials, record)
    print("Nabu: OAuth-Anmeldung abgeschlossen.")
    print("ChatGPT-Plan-Nutzung:", "autorisiert" if allowed else "nicht freigegeben")
    if allowed:
        print("Ausgewähltes Modell:", selected_model)
    print("Zugangsdaten bleiben privat unter:", credentials)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nabu offiziell mit ChatGPT verbinden")
    parser.add_argument("--credentials", type=Path, default=DEFAULT_CREDENTIALS)
    parser.add_argument("--model", default="", help="optional: exakter im Konto gelisteter Modell-Slug")
    args = parser.parse_args()
    try:
        sign_in(args.credentials, args.model)
    except (ValueError, RuntimeError, requests.RequestException) as err:
        print(f"Nabu-Anmeldung nicht abgeschlossen: {err}", file=sys.stderr)
        raise SystemExit(1) from None