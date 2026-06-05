# Pramagent

[![PyPI version](https://img.shields.io/pypi/v/pramagent.svg)](https://pypi.org/project/pramagent/)
[![Python versions](https://img.shields.io/pypi/pyversions/pramagent.svg)](https://pypi.org/project/pramagent/)
[![License](https://img.shields.io/pypi/l/pramagent.svg)](https://github.com/sriram7737/pramagent/blob/main/LICENSE)
[![CI](https://github.com/sriram7737/pramagent/actions/workflows/tests.yml/badge.svg)](https://github.com/sriram7737/pramagent/actions/workflows/tests.yml)

Trust middleware for LLM agents: deterministic tool policy, HITL approvals,
and tamper-evident audit traces. **Alpha** - read the
[implementation status](https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md)
before customer-facing pilots.

![Pramagent trust stack](https://raw.githubusercontent.com/sriram7737/pramagent/main/docs/stack.png)

Pramagent wraps OpenAI, Anthropic, Gemini, Ollama, local, and
OpenAI-compatible providers with guardrails that run outside the model. The
most differentiated layer is ToolGuard: deterministic tool validation with JSON
Schema, tenant/action allow-lists, side-effect taxonomy, dangerous-chain
detection, output scanning, and HITL escalation.

## Alpha Maturity Notice

Pramagent is published as **Alpha software**. It has live smoke-test evidence
for Sepolia anchoring, S3 cold archive, local load testing, real OpenAI/Ollama
provider calls, and bundled red-team runs, but it has **not** passed an
external penetration test, SOC 2 audit, HIPAA assessment, or
regulated-production certification.

Do not treat Pramagent as bank-grade or healthcare-grade security
infrastructure. Do not claim prompt-injection immunity, production compliance,
or third-party-validated safety from the bundled benchmarks alone. Read
[Implementation status](https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md),
[Live test results](https://github.com/sriram7737/pramagent/blob/main/docs/LIVE_TEST_RESULTS.md), and
[Hardening guide](https://github.com/sriram7737/pramagent/blob/main/docs/HARDENING_GUIDE.md)
before using it in a customer-facing pilot.

## Bare Install Quickstart

This works with the base package only. No Docker, API server, or provider key is
required.

```bash
pip install pramagent
```

```python
import asyncio
from pramagent import Pramagent

async def main():
    resp = await Pramagent().run("Summarize this request", tenant_id="demo", session_id="s1")
    print(resp.output)
    print(resp.trace.this_hash)

asyncio.run(main())
```

![Pramagent bare-install terminal quickstart](https://raw.githubusercontent.com/sriram7737/pramagent/main/docs/quickstart-terminal.png)

That creates a tamper-evident trace using the deterministic mock provider.

Swap to a real OpenAI model by setting `OPENAI_API_KEY`:

```python
from pramagent import Pramagent
from pramagent.providers import OpenAIProvider

armor = Pramagent(provider=OpenAIProvider(model="gpt-4o-mini"))
```

## API And Dashboard Install

```bash
pip install "pramagent[api,dashboard,redis,postgres]"
```

From source:

```bash
git clone git@github.com:sriram7737/pramagent.git
cd Pramagent
pip install -e ".[dev,api,redis,postgres,dashboard]"
```

## CLI And Docker Quickstart

```bash
pramagent init
pramagent validate
```

Run the local stack:

```bash
cp .env.example .env
docker compose up -d
```

Open:

- API docs: `http://localhost:8080/docs`
- Dashboard: `http://localhost:8501`

Run the release sanity checks:

```bash
python -m pytest -q --tb=no
pramagent redteam --json --attacks 100
pramagent redteam --json --dynamic --attacks 200 --seed 999
```

Current local result: `402 passed, 2 warnings`.

## ToolGuard Example

```python
import asyncio

from pramagent import Pramagent, Verdict
from pramagent.layers import ToolGuardLayer, ToolPolicy
from pramagent.layers.tool_guard import SideEffect

guard = ToolGuardLayer(policies=[
    ToolPolicy(
        name="send_payment",
        side_effect=SideEffect.PAYMENT,
        action=Verdict.ESCALATE,
        allowed_tenants={"finance_team"},
        schema={
            "type": "object",
            "required": ["amount_usd", "destination"],
            "properties": {
                "amount_usd": {"type": "number", "minimum": 0.01, "maximum": 5000},
                "destination": {"type": "string", "pattern": r"acct-\d{6,}"},
            },
            "additionalProperties": False,
        },
    )
])

armor = Pramagent(tool_guard=guard)

async def main():
    decision = armor.validate_tool(
        "send_payment",
        {"amount_usd": 250.00, "destination": "acct-123456"},
        tenant_id="finance_team",
        session_id="demo",
    )
    print(decision.verdict)  # ESCALATE

    too_large = armor.validate_tool(
        "send_payment",
        {"amount_usd": 9000.00, "destination": "acct-123456"},
        tenant_id="finance_team",
        session_id="demo",
    )
    print(too_large.verdict, too_large.reason)  # BLOCK: schema violation

    wrong_tenant = armor.validate_tool(
        "send_payment",
        {"amount_usd": 250.00, "destination": "acct-123456"},
        tenant_id="marketing_team",
        session_id="demo",
    )
    print(wrong_tenant.verdict, wrong_tenant.reason)  # BLOCK: tenant mismatch

    response = await armor.run(
        "Summarize this payment request",
        tenant_id="finance_team",
        session_id="demo",
        action="send_payment",
    )
    print(response.hitl)
    print(response.trace.this_hash)

asyncio.run(main())
```

## When To Use Pramagent

- You are wrapping LLM calls or agent workflows and need audit trails, policy
  checks, HITL approvals, PII scrubbing, and provider fallback in one place.
- You want deterministic tool policy outside the model, especially for actions
  like payments, data export, account changes, or admin operations.
- You are building an internal tool or pilot where honest safety evidence
  matters more than marketing claims.
- You need tamper-evident traces with optional Sepolia anchoring and encrypted
  S3 cold archive support.

## When Not To Use Pramagent Yet

- You need certified bank-grade, healthcare-grade, or SOC2-audited production
  infrastructure today.
- You need proven jailbreak resistance against a serious red team; the bundled
  benchmark is only a deterministic smoke test, not third-party assurance.
- You need mature enterprise dashboard auth such as SSO/OIDC/RBAC.
- You need production-grade scale evidence, chaos engineering, or SLA-backed
  capacity numbers beyond the published local Docker Compose load run.
- You need billing-grade Stripe/Chargebee metering rather than the local usage
  ledger and event hooks.

## What Works Today

| Capability | Status | Notes |
|---|---|---|
| Provider adapters | Implemented | Mock, OpenAI, Anthropic, Gemini, Ollama, OpenAI-compatible/local |
| ToolGuard | Strong MVP | JSON Schema, allow-lists, side-effect taxonomy, output scanning |
| HITL | Beta | Slack callbacks, approval queues, quorum/escalation primitives, ServiceNow/PagerDuty/email/webhook notifiers |
| Audit trail | Strong MVP | SHA-256 hash chain; optional real Sepolia anchoring |
| PII redaction | Strong MVP | Context-aware patterns for common regulated data |
| Auth/rate limits/quotas | Beta | JWT/API keys, token buckets, per-tenant quotas |
| Dashboard | Prototype | Auth, tenant scoping, traces, approvals, metrics, usage page |
| Redis/Postgres backends | Beta | Wired and tested locally; needs scale/load testing |
| OpenTelemetry | Partial | Per-layer spans exist; dashboards and alerting need hardening |
| Red-team benchmark | MVP | Static and dynamic mutation modes with bypass/false-positive rates |
| Billing hooks | MVP | In-memory hash-chain usage ledger plus fail-open webhook; no Stripe/Chargebee provider yet |
| S3 cold archive | MVP | Gzip + encrypted trace archive wrapper; metadata sink hook |

## Honest Limits

- Prompt-injection defense is not complete. The bundled static corpus and
  seeded dynamic mutation smoke tests now pass, but the embedding classifier is
  optional and the project still needs larger third-party red-team sets.
- ToolGuard is a hard policy gate outside the model, but it is not a sandbox.
- Slack is the main decision-collecting HITL adapter today. ServiceNow,
  PagerDuty, email, and generic webhooks are useful notification/escalation
  adapters, but broader enterprise approval workflows are still in development.
- Dashboard auth is not SSO/OIDC/RBAC-grade.
- Ethereum anchoring is Sepolia/testnet-oriented; no mainnet runbook, verifier
  contract, HSM/KMS key-management story, or enterprise anchoring operating
  model is included yet.
- The usage ledger is local audit evidence for pilots, not an invoice-grade
  billing system.
- Redis/Postgres support exists, but the stack has not been chaos-tested or
  load-tested for high-stakes deployments.
- No external penetration test or formal compliance certification has been run.
- QuantumLayer is future research only. It is not implemented, advertised as a
  feature, or exposed as a production API.

## Optional Anchoring And Archive

```bash
pip install "pramagent[ethereum,s3]"
```

Ethereum/Sepolia anchoring submits the audit head as transaction calldata and
stores the tx hash plus block number on the trace when configured. S3 cold
archive wraps a primary store and archives pruned/erased traces as encrypted
gzip JSON while keeping metadata available for compliance reporting.

## Demo Flow

```bash
pramagent init
docker compose up -d
python -m pytest -q --tb=no
pramagent redteam --json --dynamic --attacks 200 --seed 999
```

Then use the dashboard to inspect traces, pending HITL approvals, audit status,
metrics, and per-tenant usage.

## Docs

- [Implementation status](https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md)
- [Live test results](https://github.com/sriram7737/pramagent/blob/main/docs/LIVE_TEST_RESULTS.md)
- [Hardening guide](https://github.com/sriram7737/pramagent/blob/main/docs/HARDENING_GUIDE.md)
- [More documentation](https://github.com/sriram7737/pramagent/tree/main/docs)

## Author

- [Sriram Rampelli](https://sriram7737.github.io)

## License

Apache-2.0.
