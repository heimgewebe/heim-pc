"""Small, bounded client for the existing Grabowski MCP operator.

The caller chooses an operation, never an arbitrary tool name, path or command.
The server remains the sole authority for admission, mutations and receipts.
"""
from __future__ import annotations

import json

import aiohttp

MCP_ENDPOINT = "http://127.0.0.1:18181/mcp"
MAX_RESPONSE_BYTES = 256_000
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


class GrabowskiUnavailable(RuntimeError):
    """A request was not confirmed by Grabowski; do not claim success."""


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
        if message.get("id") != request_id:
            continue
        if "error" in message:
            err = message["error"]
            raise GrabowskiUnavailable(str(err.get("message", "MCP-Fehler"))[:250])
        result = message.get("result", {})
        if result.get("isError"):
            raise GrabowskiUnavailable("Grabowski hat den Aufruf abgewiesen")
        if isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        for item in result.get("content", []):
            if item.get("type") == "text":
                try:
                    parsed = json.loads(item["text"])
                    if isinstance(parsed, dict):
                        return parsed
                except (KeyError, TypeError, json.JSONDecodeError):
                    pass
        return result
    raise GrabowskiUnavailable("Keine bestätigte MCP-Antwort von Grabowski")


async def mcp_call(session: aiohttp.ClientSession, name: str, args: dict,
                   *, endpoint: str = MCP_ENDPOINT) -> dict:
    """Invoke a fixed call; success requires a matching server result."""
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }
    try:
        async with session.post(
            endpoint, headers=MCP_HEADERS, json=payload,
            timeout=aiohttp.ClientTimeout(total=20, connect=4),
        ) as response:
            response.raise_for_status()
            chunks = []
            total = 0
            async for part in response.content.iter_any():
                total += len(part)
                if total > MAX_RESPONSE_BYTES:
                    raise GrabowskiUnavailable("MCP-Antwort über dem Größenlimit")
                chunks.append(part)
            return parse_mcp_response(b"".join(chunks).decode("utf-8", errors="replace"))
    except (aiohttp.ClientError, TimeoutError) as exc:
        raise GrabowskiUnavailable("Grabowski derzeit nicht erreichbar; Aktion nicht bestätigt") from exc


def read_request(operation: str, task_id: str = "") -> tuple[str, dict]:
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
    raise ValueError("Ungültiges Operationsergebnis")

async def register_obligation(session: aiohttp.ClientSession,
                              objective: str, acceptance: str,
                              *, endpoint: str = MCP_ENDPOINT) -> dict:
    """Register one durable work request, not code execution.

    Existing Grabowski transport-roundtrip binds the exact target to a
    single-use challenge. A lost execution result must never be retried.
    """
    import hashlib

    if not isinstance(objective, str) or not 12 <= len(objective.strip()) <= 600:
        raise ValueError("Grabowski-Auftrag muss konkret und begrenzt sein")
    if not isinstance(acceptance, str) or not 12 <= len(acceptance.strip()) <= 500:
        raise ValueError("Ein überprüfbares Erfolgskriterium ist erforderlich")
    objective = objective.strip()
    acceptance = acceptance.strip()
    obligation_id = "goo-nabu-" + hashlib.sha256(
        (objective + "\\n" + acceptance).encode("utf-8")
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
    return {
        "status": "registered_not_executed",
        "obligation_id": obligation_id,
        "receipt_sha256": work_receipt,
        "next": "Grabowski muss die Aufgabe noch ausführen und nachweisen",
    }