# Veritrace

Trust middleware for AI agents: deterministic tool policy, HITL approvals,
usage quotas, and tamper-evident audit traces around OpenAI, Anthropic, Gemini,
Ollama, local, and OpenAI-compatible providers.

Veritrace is a strong guardrail/audit MVP for pilots and internal tools. It is
not certified bank-grade or healthcare-grade infrastructure yet.

## Install

From PyPI, after the release is published:

```bash
pip install "veritrace[api,dashboard,redis,postgres]"
```

From source:

```bash
git clone git@github.com:sriram7737/Veritrace.git
cd Veritrace
pip install -e ".[dev,api,redis,postgres,dashboard]"
```

## Quickstart

```bash
veritrace init
veritrace validate
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
veritrace redteam --json --attacks 100
veritrace redteam --json --dynamic --attacks 200 --seed 999
```

Current local result: `356 passed, 2 warnings`.

## When To Use Veritrace

- You are wrapping LLM calls or agent workflows and need audit trails, policy
  checks, HITL approvals, PII scrubbing, and provider fallback in one place.
- You want deterministic tool policy outside the model, especially for actions
  like payments, data export, account changes, or admin operations.
- You are building an internal tool, pilot, or interview/demo project where
  honest safety evidence matters more than marketing claims.
- You need tamper-evident traces with optional Sepolia anchoring and encrypted
  S3 cold archive support.

## When Not To Use Veritrace Yet

- You need certified bank-grade, healthcare-grade, or SOC2-audited production
  infrastructure today.
- You need proven jailbreak resistance against a serious red team; the bundled
  benchmark is only a deterministic smoke test, not third-party assurance.
- You need mature enterprise dashboard auth such as SSO/OIDC/RBAC.
- You need production-grade scale evidence, chaos engineering, or SLA-backed
  capacity numbers beyond the published local Docker Compose load run.
- You need billing-grade Stripe/Chargebee metering rather than usage hooks.

## Minimal Example

```python
import asyncio

from veritrace import Veritrace, Verdict
from veritrace.layers import ToolGuardLayer, ToolPolicy
from veritrace.layers.tool_guard import SideEffect

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

armor = Veritrace(tool_guard=guard)

async def main():
    decision = armor.validate_tool(
        "send_payment",
        {"amount_usd": 250.00, "destination": "acct-123456"},
        tenant_id="finance_team",
        session_id="demo",
    )
    print(decision.verdict)  # ESCALATE

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

## What Works Today

| Capability | Status | Notes |
|---|---|---|
| Provider adapters | Implemented | Mock, OpenAI, Anthropic, Gemini, Ollama, OpenAI-compatible/local |
| ToolGuard | Strong MVP | JSON Schema, allow-lists, side-effect taxonomy, output scanning |
| HITL | Beta | Slack callbacks, approval queues, quorum/escalation primitives |
| Audit trail | Strong MVP | SHA-256 hash chain; optional real Sepolia anchoring |
| PII redaction | Strong MVP | Context-aware patterns for common regulated data |
| Auth/rate limits/quotas | Beta | JWT/API keys, token buckets, per-tenant quotas |
| Dashboard | Prototype | Auth, tenant scoping, traces, approvals, metrics, usage page |
| Redis/Postgres backends | Beta | Wired and tested locally; needs scale/load testing |
| OpenTelemetry | Partial | Per-layer spans exist; dashboards and alerting need hardening |
| Red-team benchmark | MVP | Static and dynamic mutation modes with bypass/false-positive rates |
| Billing hooks | MVP | Fail-open usage webhook; no Stripe/Chargebee ledger yet |
| S3 cold archive | MVP | Gzip + encrypted trace archive wrapper; metadata sink hook |

## Honest Limits

- Prompt-injection defense is not complete. The bundled static corpus and
  seeded dynamic mutation smoke tests now pass, but the embedding classifier is
  optional and the project still needs larger third-party red-team sets.
- ToolGuard is a hard policy gate outside the model, but it is not a sandbox.
- Dashboard auth is not SSO/OIDC/RBAC-grade.
- Redis/Postgres support exists, but the stack has not been chaos-tested or
  load-tested for high-stakes deployments.
- No external penetration test or formal compliance certification has been run.
- QuantumLayer is research/roadmap only, not a production feature.

## Optional Anchoring And Archive

```bash
pip install -e ".[ethereum,s3]"
```

Ethereum/Sepolia anchoring submits the audit head as transaction calldata and
stores the tx hash plus block number on the trace when configured. S3 cold
archive wraps a primary store and archives pruned/erased traces as encrypted
gzip JSON while keeping metadata available for compliance reporting.

## Demo Flow

```bash
veritrace init
docker compose up -d
python -m pytest -q --tb=no
veritrace redteam --json --dynamic --attacks 200 --seed 999
```

Then use the dashboard to inspect traces, pending HITL approvals, audit status,
metrics, and per-tenant usage.

## Docs

- [Deployment guide](docs/DEPLOYMENT.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Compliance mapping](docs/COMPLIANCE_MAPPING.md)
- [Red-team results](docs/REDTEAM_RESULTS.md)
- [Live test results](docs/LIVE_TEST_RESULTS.md)
- [Load-test runbook](docs/LOAD_TEST.md)
- [Load-test results](docs/LOAD_TEST_RESULTS.md)
- [Demo script](docs/DEMO_SCRIPT.md)
- [Changelog](CHANGELOG.md)
- [Design document](docs/Veritrace-Design-Document.docx)

## License

Apache-2.0.
