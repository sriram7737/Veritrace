"""
Live Pramagent workflow demo with optional OpenAI calls.

This is intentionally small: it proves a real agent timeline without turning the
main package into an app framework.

What it demonstrates
--------------------
1. A live model turns a natural-language request into a proposed tool intent.
2. ToolGuard validates the proposed tool before any side-effect function runs.
3. Consequential payment actions escalate to HITL and do not execute silently.
4. Bad tenant and bad amount requests are blocked before execution.
5. Every Pramagent run creates a hash-chained trace in SQLite.

Safe local run:
    python examples/live_payment_agent.py --provider mock --reset-db

Live OpenAI run:
    $env:OPENAI_API_KEY="sk-..."
    python examples/live_payment_agent.py --provider openai --reset-db

Optional env-file load, without hardcoding secrets:
    python examples/live_payment_agent.py --provider openai --env-file .env.live
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from pramagent import Pramagent, Verdict
from pramagent.layers import ComplianceLayer, HITLLayer, ReliabilityLayer, Rule, SafetyLayer
from pramagent.layers import ToolGuardLayer, ToolPolicy
from pramagent.layers.tool_guard import SideEffect
from pramagent.providers import MockProvider, OpenAIProvider
from pramagent.store import SQLiteStore


ALLOWED_ENV_KEYS = {
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "OPENAI_BASE_URL",
    "OPENAI_MAX_TOKENS",
}


def load_env_file(path: str | None) -> None:
    """Load selected env keys from a simple .env/PowerShell-style file.

    Values are never printed. Existing process env vars win.
    """
    if not path:
        return
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"env file not found: {path}")
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(?:\$env:)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if key not in ALLOWED_ENV_KEYS or key in os.environ:
            continue
        if (
            (value.startswith('"') and value.endswith('"'))
            or (value.startswith("'") and value.endswith("'"))
        ):
            value = value[1:-1]
        os.environ[key] = value


def build_tool_guard() -> ToolGuardLayer:
    return ToolGuardLayer(
        policies=[
            ToolPolicy(
                name="lookup_vendor",
                side_effect=SideEffect.READ,
                action=Verdict.ALLOW,
                allowed_tenants={"finance_team", "support_team"},
                schema={
                    "type": "object",
                    "required": ["destination"],
                    "properties": {
                        "destination": {
                            "type": "string",
                            "pattern": r"acct-\d{6,}",
                        }
                    },
                    "additionalProperties": False,
                },
                detail="read-only vendor lookup",
            ),
            ToolPolicy(
                name="send_payment",
                side_effect=SideEffect.PAYMENT,
                action=Verdict.ESCALATE,
                allowed_tenants={"finance_team"},
                schema={
                    "type": "object",
                    "required": ["amount_usd", "destination", "memo"],
                    "properties": {
                        "amount_usd": {
                            "type": "number",
                            "minimum": 0.01,
                            "maximum": 5000,
                        },
                        "destination": {
                            "type": "string",
                            "pattern": r"acct-\d{6,}",
                        },
                        "memo": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 160,
                        },
                    },
                    "additionalProperties": False,
                },
                detail="payment tools require human approval",
            ),
        ]
    )


def build_provider(name: str, *, max_tokens: int):
    if name == "mock":
        return MockProvider(model="live-demo-mock")
    if name == "openai":
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is required for --provider openai")
        return OpenAIProvider(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            max_tokens=max_tokens,
            temperature=0.0,
        )
    raise ValueError(f"unsupported provider: {name}")


def build_armor(provider, db_path: str) -> tuple[Pramagent, SQLiteStore]:
    store = SQLiteStore(db_path)

    async def silent_approver(action: str, context: dict):
        return None

    armor = Pramagent(
        provider=provider,
        store=store,
        audit=store,
        compliance=ComplianceLayer(standards=["HIPAA", "PCI_DSS"]),
        safety=SafetyLayer(
            rules=[
                Rule(
                    "block_account_dump",
                    Verdict.BLOCK,
                    pattern=r"dump .*accounts?|export .*customer data|reveal .*secrets",
                )
            ]
        ),
        reliability=ReliabilityLayer(max_concurrent=5, timeout_s=30.0),
        hitl=HITLLayer(
            require_approval_for=["send_payment"],
            timeout_s=0.25,
            approver=silent_approver,
        ),
        tool_guard=build_tool_guard(),
    )
    return armor, store


def intent_prompt(request: str) -> str:
    return f"""
You are a payment-ops routing agent. Return only compact JSON.

Available tools:
- lookup_vendor(destination: acct-123456 style account id)
- send_payment(amount_usd: number, destination: acct-123456 style account id, memo: string)
- none(reason: string)

Rules:
- If the user asks to look up, verify, check, or inspect a vendor/account, use lookup_vendor.
- If the user asks to wire, pay, transfer, or send funds, use send_payment.
- Extract the amount as a number in USD.
- Extract destination as acct- followed by digits.
- Include a short memo.
- Do not invent a destination if none is present.

Return exactly this shape:
{{"tool_name":"lookup_vendor|send_payment|none","arguments":{{...}},"explanation":"short"}}

User request: {request}
""".strip()


def mock_intent(request: str) -> dict[str, Any]:
    account = re.search(r"acct-\d{6,}", request)
    amount = re.search(r"\$?\s*([0-9]+(?:\.[0-9]{1,2})?)", request)
    if re.search(r"\b(lookup|verify|check|inspect)\b", request, re.I):
        return {
            "tool_name": "lookup_vendor",
            "arguments": {"destination": account.group(0) if account else ""},
            "explanation": "read-only vendor lookup",
        }
    if re.search(r"\b(wire|pay|payment|transfer|send funds)\b", request, re.I):
        return {
            "tool_name": "send_payment",
            "arguments": {
                "amount_usd": float(amount.group(1)) if amount else 0.0,
                "destination": account.group(0) if account else "",
                "memo": "vendor payment",
            },
            "explanation": "payment request",
        }
    return {"tool_name": "none", "arguments": {}, "explanation": "no tool needed"}


async def get_tool_intent(provider_name: str, provider, request: str) -> dict[str, Any]:
    if provider_name == "mock":
        return mock_intent(request)
    result = await provider.complete(intent_prompt(request))
    return parse_json_object(result.text)


def parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.I).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.S)
        if not match:
            raise ValueError(f"model did not return JSON: {text[:200]!r}") from None
        obj = json.loads(match.group(0))
    if not isinstance(obj, dict):
        raise ValueError("model JSON intent must be an object")
    obj.setdefault("arguments", {})
    obj.setdefault("explanation", "")
    return obj


def execute_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Mock operational tools. `send_payment` is intentionally not auto-called."""
    if tool_name == "lookup_vendor":
        return {
            "tool": tool_name,
            "destination": arguments["destination"],
            "vendor_status": "known_vendor",
            "risk": "low",
            "receipt_id": f"lookup_{uuid.uuid4().hex[:10]}",
        }
    if tool_name == "send_payment":
        return {
            "tool": tool_name,
            "status": "executed",
            "amount_usd": arguments["amount_usd"],
            "destination": arguments["destination"],
            "receipt_id": f"pay_{uuid.uuid4().hex[:10]}",
        }
    return {"tool": tool_name, "status": "not_executed"}


SCENARIOS = [
    {
        "name": "read-only vendor lookup",
        "tenant_id": "finance_team",
        "request": "Verify vendor account acct-123456 before I pay the invoice.",
    },
    {
        "name": "payment requires HITL",
        "tenant_id": "finance_team",
        "request": "Wire $250.00 to acct-123456 for the vendor invoice.",
    },
    {
        "name": "wrong tenant cannot send payment",
        "tenant_id": "marketing_team",
        "request": "Wire $250.00 to acct-123456 for the vendor invoice.",
    },
    {
        "name": "oversized payment violates schema",
        "tenant_id": "finance_team",
        "request": "Wire $9000.00 to acct-123456 for the vendor invoice.",
    },
]


async def run_scenario(index: int, scenario: dict[str, str], provider_name: str, armor: Pramagent):
    session_id = f"live-payment-demo-{index}"
    print(f"\n=== {index}. {scenario['name']} ===")
    print("tenant :", scenario["tenant_id"])
    print("request:", scenario["request"])

    intent = await get_tool_intent(provider_name, armor.provider, scenario["request"])
    tool_name = str(intent.get("tool_name") or "none")
    arguments = intent.get("arguments") or {}
    print("intent :", json.dumps(intent, sort_keys=True))

    if tool_name == "none":
        print("decision: no tool proposed")
        return

    decision = armor.validate_tool(
        tool_name,
        arguments,
        tenant_id=scenario["tenant_id"],
        session_id=session_id,
        action_label=tool_name,
    )
    print("guard  :", decision.verdict.value, "-", decision.reason)

    response = await armor.run(
        scenario["request"],
        tenant_id=scenario["tenant_id"],
        session_id=session_id,
        action=tool_name,
        tool_name=tool_name,
        tool_arguments=arguments,
    )
    print("blocked:", response.blocked, response.block_reason)
    print("hitl   :", response.hitl)
    print("model  :", response.trace.provider or "not called", response.trace.provider_model)
    print("hash   :", response.trace.this_hash)

    if decision.verdict == Verdict.ALLOW and not response.blocked:
        receipt = execute_tool(tool_name, arguments)
        print("tool   :", json.dumps(receipt, sort_keys=True))
    else:
        print("tool   : not executed")


async def main() -> int:
    parser = argparse.ArgumentParser(description="Run a live Pramagent payment-agent workflow.")
    parser.add_argument("--provider", choices=["mock", "openai"], default="openai")
    parser.add_argument("--env-file", default="", help="Optional .env file to load selected OPENAI_* keys from.")
    parser.add_argument("--db", default="pramagent_live_payment_demo.db")
    parser.add_argument("--reset-db", action="store_true")
    parser.add_argument("--max-tokens", type=int, default=220)
    args = parser.parse_args()

    load_env_file(args.env_file)
    if args.reset_db and Path(args.db).exists():
        Path(args.db).unlink()

    provider = build_provider(args.provider, max_tokens=args.max_tokens)
    armor, store = build_armor(provider, args.db)

    print("Pramagent live payment-agent workflow")
    print("provider:", args.provider)
    print("db      :", args.db)
    if args.provider == "openai":
        print("model   :", os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))
    print("started :", time.strftime("%Y-%m-%d %H:%M:%S"))

    for i, scenario in enumerate(SCENARIOS, start=1):
        await run_scenario(i, scenario, args.provider, armor)

    print("\n=== audit ===")
    print("chain_valid:", store.verify_chain())
    print("traces     :", len(store.list_all()))
    print("db_path    :", args.db)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
