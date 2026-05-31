# Veritrace

**Trust middleware for AI agents: deterministic guardrails, HITL, tool policy, and tamper-evident traces.**

Veritrace wraps supported LLM providers in a layered safety pipeline: injection detection, tool-call guardrails, human-in-the-loop approvals, usage quotas, cryptographic audit trail, and distributed tracing — all in one composable Python library.

---

## 5-Minute Quickstart

```bash
pip install veritrace
```

```python
import asyncio
from veritrace import Veritrace, Verdict
from veritrace.layers import ToolGuardLayer, ToolPolicy
from veritrace.layers.tool_guard import SideEffect

# 1. Define which tools your agent can call and how they're classified
guard = ToolGuardLayer(policies=[
    ToolPolicy(
        name="query_database",
        side_effect=SideEffect.READ,
        schema={
            "type": "object",
            "required": ["sql"],
            "properties": {"sql": {"type": "string", "maxLength": 4096}},
            "additionalProperties": False,
        },
        max_output_bytes=65536,
    ),
    ToolPolicy(
        name="send_payment",
        side_effect=SideEffect.PAYMENT,
        action=Verdict.ESCALATE,        # always requires human approval
        allowed_tenants={"finance_team"},
        schema={
            "type": "object",
            "required": ["amount_usd", "destination"],
            "properties": {
                "amount_usd": {"type": "number", "minimum": 0.01, "maximum": 50000},
                "destination": {"type": "string", "pattern": r"acct-\d{6,}"},
            },
        },
    ),
])

# 2. Wrap your provider
armor = Veritrace(tool_guard=guard)

# 3. Run an agent call through the full trust pipeline
async def main():
    # Pre-flight tool check (before executing)
    decision = armor.validate_tool(
        "query_database",
        {"sql": "SELECT * FROM orders WHERE tenant_id = 'acme'"},
        tenant_id="acme", session_id="s1",
    )
    print(decision.verdict)   # ALLOW

    # Full pipeline: injection scan → safety → tool guard → provider → HITL → audit
    response = await armor.run(
        "Summarize this quarter's orders",
        tenant_id="acme", session_id="s1",
    )
    print(response.output)
    print(response.trace.this_hash)   # tamper-evident trace hash

asyncio.run(main())
```

---

## LangChain Integration

```python
from langchain.tools import tool
from veritrace import Veritrace
from veritrace.layers import ToolGuardLayer, ToolPolicy
from veritrace.layers.tool_guard import SideEffect

armor = Veritrace(tool_guard=ToolGuardLayer(policies=[
    ToolPolicy(name="web_search", side_effect=SideEffect.READ,
               schema={"type": "object", "required": ["query"],
                       "properties": {"query": {"type": "string", "maxLength": 512}}}),
]))

@tool
def web_search(query: str) -> str:
    """Search the web."""
    decision = armor.validate_tool("web_search", {"query": query},
                                   tenant_id="agent", session_id="run_1")
    if decision.verdict.value == "block":
        return f"[blocked: {decision.reason}]"
    # ... call real search API
    return f"Results for: {query}"
```

## CrewAI Integration

```python
from crewai import Agent, Task, Crew
from veritrace import Veritrace
from veritrace.classifier import build_classifier
from veritrace.layers import IsolationLayer

# Semantic injection detection on every crew message
iso = IsolationLayer(classifier=build_classifier(), block_on_injection=True)
armor = Veritrace(isolation=iso)

# Wrap CrewAI agent execution with Veritrace pre-screening
async def safe_crew_run(prompt: str, tenant: str, session: str):
    # Screen the inbound task description for injection
    await iso.evaluate_input(prompt, tenant_id=tenant, session_id=session)
    # ... execute crew normally
```

---

## Docker Compose (Production)

```bash
cp .env.example .env          # fill in passwords
docker compose up -d
# API:       http://localhost:8080/docs
# Dashboard: http://localhost:8501/
```

The stack includes Postgres (audit store), Redis (HITL + rate limiting), the Veritrace API, and the admin dashboard with auth.

---

## Capability Matrix

This table is intentionally conservative. "Hardened MVP" means implemented,
tested, and useful for pilots; it does not mean certified, pen-tested, or
impossible to bypass under serious adversarial pressure.

| Capability | Status | Notes |
|---|---|---|
| Prompt injection detection (regex/heuristics) | Strong MVP | Useful baseline; not complete jailbreak resistance |
| Prompt injection detection (embedding) | Beta | Optional sentence-transformers path; bypass rate is measured, not zero |
| Tool argument schema validation | Hardened MVP | JSON Schema coverage is broad, but not a sandbox by itself |
| Tool argument injection scanning | Hardened MVP | SQL, shell, path traversal, SSRF, template |
| Tool output exfiltration scanning | Hardened MVP | AWS keys, private keys, JWTs, generic secrets |
| Tool-chain attack detection | Beta | Catches known dangerous sequences; novel chains need red-team coverage |
| Side-effect severity taxonomy | Hardened MVP | read -> compute -> write -> config -> external -> payment -> destructive |
| LLM-as-judge for high-severity tools | Beta | Async and auditable; depends on provider quality and prompt design |
| Cryptographic audit trail (hash chain) | Hardened MVP | SHA-256 chain, tamper-evident, not external notarization by default |
| PII redaction (compliance) | Hardened MVP | Email, SSN, credit card, IBAN, contextual patterns |
| HITL approvals (basic) | Hardened MVP | Idle-on-silence invariant |
| HITL escalation chains | Beta | Ordered slots, per-slot timeout, escalation primitives |
| HITL multi-approver quorum | Beta | N-of-M, deny threshold |
| HITL approval audit log | Beta | Decision log exists; production persistence/runbooks still needed |
| Redis backend (HITL + rate limiting) | Beta | Connection pooling, retry, circuit breaker; needs load testing |
| Postgres store (trace + audit chain) | Beta | Connection pooling, retry, DDL; needs migration/runbook polish |
| Rate limiting (token bucket) | Hardened MVP | Per-key, configurable capacity/refill |
| Circuit breaker | Beta | Redis/Postgres/provider layers; needs chaos testing |
| OpenTelemetry distributed tracing | Partial | Per-layer spans and W3C context; dashboards/alerts not battle-tested |
| FastAPI sidecar | Hardened MVP | Auth, CORS, security headers, structured logging |
| Admin dashboard | Prototype | HTMX, auth, tenant filters; not a mature admin console |
| Embedding classifier fine-tuning | ⚠️ Manual | Expand exemplar corpus; auto-retrain planned |
| Compliance report generator (PDF/JSON/text) | ✅ Beta | Consent, purpose, retention, audit summary |
| Kubernetes Helm chart | ✅ Beta | API deployment, service, HPA, configurable values |
| Usage quotas + budget hooks | Beta | Per-tenant call/tool/spend caps + `/v1/usage`; no billing provider integration |
| Semantic safety (beyond regex) | ⚠️ Partial | Embedding classifier covers injection; output grounding planned |

---

## Architecture

```
Inbound prompt
     │
     ▼
┌─────────────────┐
│ ComplianceLayer │  PII detection + redaction
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ IsolationLayer  │  Injection heuristics + embedding classifier + size limits
│                 │  Tenant-scoped memory (Redis or in-process)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SafetyLayer    │  Pre-call rule engine + optional ML classifier
└────────┬────────┘
         │
         ▼
┌──────────────────┐
│ ToolGuardLayer   │  Policy allow-list → full JSON Schema → injection scan →
│                  │  session limits → side-effect severity → chain detection
│                  │  LLM judge (optional, for payment/destructive)
│                  │  Output validation + provenance tracking
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ReliabilityLayer  │  Semaphore concurrency + timeout + circuit breaker
│  ── Provider ──  │  MockProvider / OpenAI / Anthropic / any LLM
└────────┬─────────┘
         │
         ▼
┌─────────────────┐
│  SafetyLayer    │  Post-call rule engine (output screening)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   HITLLayer     │  Idle-on-silence → ApproverChain → QuorumApprover
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  HashChain      │  Tamper-evident trace anchoring (in-process / Postgres)
└─────────────────┘
         │
         ▼
    AgentResponse
```

Each layer emits an OpenTelemetry span. W3C traceparent propagates end-to-end.

---

## Configuration

All settings read from environment variables (prefix `VT_`). See `.env.example` for the full list.

```python
from veritrace.config import settings

print(settings.max_input_bytes)     # 65536
print(settings.redis_url)           # redis://localhost:6379/0
print(settings.validate())          # [] if all good, list of warnings otherwise

# Build backends from settings
backend = settings.redis_backend()
store   = settings.postgres_store()
```

---

## Deployment

### Docker Compose (recommended for single-node)

```bash
docker compose up -d
docker compose logs -f api
```

### Kubernetes (manual, Helm chart in progress)

```yaml
# Minimal deployment — see deploy/k8s/ for full example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: veritrace
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: api
        image: veritrace:latest
        envFrom:
        - secretRef:
            name: veritrace-secrets
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
```

### Observability

Set `VT_OTEL_ENDPOINT=http://otel-collector:4317` to ship traces to any OpenTelemetry-compatible backend (Jaeger, Honeycomb, Datadog, Grafana Tempo).

---

## Security Model

**What Veritrace defends against:**
- Prompt injection (direct and indirect via tool outputs)
- Tool-call policy evasion (tenant bypass, action bypass, schema smuggling)
- Argument-level injection (SQL, shell, path traversal, SSRF, template)
- Data exfiltration via tool outputs (AWS keys, private keys, JWTs, secrets)
- Dangerous tool-chain sequences (read→exfiltrate, read→payment, bulk mutation)
- Replay attacks (hash-chained immutable audit log)
- Session memory bleed between tenants

**What Veritrace does NOT claim to fully solve:**
- Novel injection prompts not in the exemplar corpus (expand corpus + fine-tune)
- Semantic SQL safety (LLM judge helps; not a substitute for a proper WAF)
- Physical security of the LLM provider
- Zero-day vulnerabilities in dependencies

---

## License

MIT. Enterprise support and managed SaaS available — contact the maintainers.
