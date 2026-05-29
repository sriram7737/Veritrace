# Veritrace

**Trust middleware for AI agents.**

Veritrace v0.2 is a strong MVP, not mature enterprise infrastructure. It is useful for demos and low/medium-stakes internal tools today; high-stakes regulated deployment still needs distributed state, stronger classifiers, deeper tool sandboxing, and broader adversarial testing.

Most agent frameworks help you *build* an agent. None help you *trust* one in production. Veritrace is the missing layer: deterministic safety, human-in-the-loop control, tamper-evident audit trails, and production-grade reliability — wrapped around any LLM provider, in a few lines of code.

> Trust your AI the way you trust a good professional: bounded, confidential, documented, and accountable.

---

## Why

Put an agent in front of real users and three things break at once:

1. It says something it shouldn't — and there's no systematic way to stop it.
2. It collapses under concurrent load — and there's no graceful fallback.
3. Something goes wrong and you can't explain *why* — because there's no forensic trail.

In regulated industries (banking, healthcare, insurance) these aren't annoyances, they're liabilities. The EU AI Act now *mandates* tamper-proof logging for high-risk AI. Veritrace is built for exactly this.

## What it is

A composable Python middleware (optionally a FastAPI sidecar) that wraps any agent with a ten-layer trust stack. Each layer is independent and configurable. The LLM is never the last line of defense — deterministic rules, human approvals, and a cryptographic audit chain sit *outside* the model and can't be overridden by model output.

## Install

```bash
pip install -e .            # core, zero required dependencies
pip install -e ".[anthropic]"   # + Anthropic SDK-backed provider
pip install -e ".[ollama]"      # + local Ollama provider
pip install -e ".[dev]"         # + pytest
```

## 60-second example

```python
import asyncio
from veritrace import Veritrace, Verdict
from veritrace.layers import SafetyLayer, ComplianceLayer, HITLLayer, Rule
from veritrace.providers import MockProvider   # swap for OpenAIProvider / GeminiProvider / etc.

armor = Veritrace(
    provider=MockProvider(),
    compliance=ComplianceLayer(standards=["HIPAA", "PCI_DSS"]),
    safety=SafetyLayer(rules=[
        Rule("no_account_dump", Verdict.BLOCK,  pattern=r"dump .*accounts?"),
        Rule("escalate_wire",   Verdict.ESCALATE, pattern=r"transfer \$?\d+"),
    ]),
    hitl=HITLLayer(require_approval_for=["wire_transfer"], timeout_s=300),
)

resp = asyncio.run(armor.run("Summarize the caregiver notes.",
                             tenant_id="acme", session_id="s1"))
print(resp.output)            # safe, validated output
print(resp.trace.this_hash)   # tamper-evident audit hash
print(resp.hitl)              # human-in-the-loop status
```

Run the full demo:

```bash
python examples/demo.py
pytest -q
```

## Run as an HTTP service

Veritrace ships a FastAPI sidecar so any agent — in any language — can wrap its LLM calls in the trust stack without embedding the library:

```bash
pip install -e ".[api]"
uvicorn veritrace.api.app:app --port 8000
```

```bash
curl -s localhost:8000/v1/run -H 'content-type: application/json' \
     -d '{"prompt":"Summarize the notes","tenant_id":"acme","session_id":"s1"}'
```

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/health`, `/health/ready` | Liveness; readiness + audit-chain validity + auth mode |
| POST | `/v1/run` | Run one agent call through the full stack |
| POST | `/v1/tools/validate` | Validate a proposed tool call before execution |
| GET | `/v1/trace/{call_id}` | Fetch the complete immutable trace |
| GET | `/v1/audit/verify` | Verify the tamper-evident hash chain |
| GET | `/v1/metrics` | Observability snapshot |
| POST | `/v1/hitl/slack/action` | Slack approve/deny callback for HITL |
| POST | `/v1/rca/{call_id}/replay` | Deterministic decision replay |
| POST | `/v1/rca/{call_id}/counterfactual` | "What if rule X had not fired?" |
| GET | `/v1/rca/{call_id}/incident` | Human-readable incident report |
| POST | `/v1/retention/prune?older_than_days=N` | Delete traces older than N days (≥180) |
| DELETE | `/v1/tenant/{tenant_id}/traces` | GDPR right-to-erasure for own tenant |

## Slack HITL approvals

Set these env vars to turn consequential actions into real Slack approval
requests with approve/deny buttons:

```bash
SLACK_BOT_TOKEN="xoxb-..."
SLACK_SIGNING_SECRET="..."
SLACK_CHANNEL_ID="C..."
VERITRACE_PUBLIC_URL="https://your-public-url.example"
VERITRACE_HITL_TIMEOUT_S=300
uvicorn veritrace.api.app:app --port 8000
```

In the Slack app's **Interactivity & Shortcuts** settings, set the request URL
to:

```text
https://your-public-url.example/v1/hitl/slack/action
```

If Slack is not configured, HITL keeps the safe default: consequential actions
return `idle` and are not executed.

## Tool-call guardrails

Agents should validate side-effecting tool calls before execution:

```bash
curl -s localhost:8000/v1/tools/validate -H "content-type: application/json" \
  -d '{"tool_name":"wire_transfer","arguments":{"amount_usd":25,"destination_account":"acct-123456"},"tenant_id":"bank","session_id":"s1","action":"wire_transfer"}'
```

The response is a deterministic decision:

```json
{
  "verdict": "escalate",
  "reason": "payment tools require human approval",
  "side_effect": "payment"
}
```

`ToolGuardLayer` supports explicit tool registration, JSON-schema-style
argument checks, tenant/action allow-lists, per-session call limits, side-effect
labels, and an in-process decision audit log. It validates proposed calls; it
does not sandbox arbitrary tool execution yet.

## Multi-tenant security

Veritrace ships with API-key-per-tenant authentication. **The tenant is derived from the key, never from the request body** — so a holder of tenant A's key cannot fetch tenant B's trace by ID, and cannot create a trace tagged as tenant B by spoofing the body.

```bash
# Register keys at startup (env var format: "tenant1:key1,tenant2:key2")
VERITRACE_API_KEYS="bank:vt_abc...,hospital:vt_def..." \
  uvicorn veritrace.api.app:app --port 8000

# Bank's key can read bank's traces
curl localhost:8000/v1/trace/$ID -H "Authorization: Bearer vt_abc..."
# Hospital's key cannot — returns 404 (existence not leaked)
curl localhost:8000/v1/trace/$ID -H "Authorization: Bearer vt_def..."
```

Keys are stored as SHA-256 (never plaintext), looked up with constant-time comparison, and can be issued/revoked at runtime. When no keys are registered, the API runs unauthenticated (dev mode), and `/health/ready` reports `auth_enabled: false` so operators can confirm what mode they're in.

For production-style clients, exchange the bootstrap API key for a short-lived
JWT:

```bash
curl -s localhost:8000/v1/auth/token -H "content-type: application/json" \
  -d '{"api_key":"vt_abc...","ttl_s":900}'
```

Use the returned `access_token` as the bearer token on `/v1/*` endpoints. API
keys remain the bootstrap secret; JWTs are tenant-scoped and expire.

Set `VERITRACE_JWT_SECRET` in deployed environments so tokens survive process
restarts.

## Provider selection

The API sidecar defaults to the deterministic mock provider. Select providers
with `VERITRACE_PROVIDER`.

OpenAI:

```bash
set VERITRACE_PROVIDER=openai
set OPENAI_API_KEY=sk-...
set OPENAI_MODEL=gpt-4o-mini
python -m uvicorn veritrace.api.app:app --port 8000
```

OpenAI-compatible local or hosted servers, including vLLM, LM Studio, llama.cpp
server, and many compatible gateways:

```bash
set VERITRACE_PROVIDER=local
set LOCAL_LLM_BASE_URL=http://localhost:8001/v1
set LOCAL_MODEL=local-model-name
python -m uvicorn veritrace.api.app:app --port 8000
```

Gemini:

```bash
set VERITRACE_PROVIDER=gemini
set GEMINI_API_KEY=...
set GEMINI_MODEL=gemini-1.5-flash
python -m uvicorn veritrace.api.app:app --port 8000
```

Anthropic:

```bash
pip install -e ".[anthropic,api]"
set VERITRACE_PROVIDER=anthropic
set ANTHROPIC_API_KEY=sk-ant-...
set ANTHROPIC_MODEL=claude-sonnet-4-20250514
python -m uvicorn veritrace.api.app:app --port 8000
```

For local Ollama:

```bash
pip install -e ".[ollama,api]"
set VERITRACE_PROVIDER=ollama
set OLLAMA_MODEL=llama3.2:1b
python -m uvicorn veritrace.api.app:app --port 8000
```

## OpenTelemetry metrics

The in-process observability counters can be exported through OpenTelemetry:

```python
from veritrace import OpenTelemetryExporter, Veritrace

armor = Veritrace()
otel = OpenTelemetryExporter(armor.observability)
```

Install the optional dependencies with `pip install -e ".[otel]"` and configure
your normal OTel SDK/exporter for Jaeger, Honeycomb, or another backend.

## Encryption at rest

For deployments handling regulated data, `EncryptedSQLiteStore` encrypts every trace payload and every audit-chain payload with Fernet (AES-128-CBC + HMAC-SHA256). Indexed columns (`call_id`, `tenant_id`, `created_at`) stay plain so the database can still query them; everything sensitive is ciphertext on disk.

```python
from cryptography.fernet import Fernet
from veritrace.store_encrypted import EncryptedSQLiteStore

key = Fernet.generate_key()   # store in AWS Secrets Manager / Vault in production
db = EncryptedSQLiteStore("veritrace.db", key=key)
armor = Veritrace(provider=..., store=db, audit=db)
```

## Retention & GDPR erasure

`prune_older_than(cutoff_ts)` deletes traces older than the cutoff. The API endpoint enforces the EU AI Act Article 12 minimum of 180 days (~6 months) and rejects shorter windows with a 400. `delete_for_tenant(tenant_id)` implements GDPR right-to-erasure; trace records are deleted while audit-chain payloads are retained to preserve chain integrity.

## The ten layers

| # | Layer | Responsibility |
|---|-------|----------------|
| 1 | ProviderAdapter | Normalize any LLM provider; fallback chains; cost tracking |
| 2 | ComplianceLayer | PII scrubbing; GDPR/HIPAA/PCI-DSS hooks; retention & consent |
| 3 | IsolationLayer | Per-tenant session scoping; memory sandbox; injection guard |
| 4 | SafetyLayer | Pre/post classifiers; deterministic rule engine; hard overrides |
| 5 | HITLLayer | Propose-and-wait; human approval; **idle on silence** |
| 6 | ReliabilityLayer | Semaphore concurrency; bounded queue; circuit breaker; retry |
| 7 | TraceLayer | Immutable trace as a first-class field; hash-chain anchored |
| 8 | RCAEngine | Decision replay; causality graph; counterfactual analysis |
| 9 | ObservabilityLayer | SLO/SLA tracking; anomaly detection; behavior baselines |
| 10 | QuantumLayer | Post-quantum signatures; QRNG tokens; QML adapter *(future)* |

Phase 1 (this repo) ships layers 1–8 in working form, with 2/3/9/10 scaffolded.

## Repo layout

```
veritrace/
├── veritrace/
│   ├── __init__.py        # public API
│   ├── core.py            # the orchestrator — pipeline ordering lives here
│   ├── types.py           # TraceEvent, AgentResponse, Verdict, …
│   ├── providers/         # ProviderAdapter + Mock/Anthropic/Ollama/Fallback
│   ├── layers/            # Compliance (context-guarded PII), Safety, Reliability, HITL, Isolation, Observability
│   ├── audit/             # HashChainBackend (tamper-evident) + Ethereum stub
│   ├── api/               # FastAPI sidecar (HTTP service)
│   └── rca.py             # replay / causality / counterfactual / incident report
├── examples/demo.py       # runnable end-to-end demo (offline)
├── tests/                 # pytest suite: pipeline + compliance + api (20 tests)
└── docs/                  # design document + diagrams
```

## License

Apache-2.0.
