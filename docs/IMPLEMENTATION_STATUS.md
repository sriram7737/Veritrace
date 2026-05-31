# Veritrace — Current Implementation Status

_Last updated for the v0.3 "Production Guardrails MVP" milestone._

This document is deliberately blunt. Veritrace is **strong trust middleware for
AI agents** — deterministic guardrails, HITL, tool policy, and tamper-evident
traces. It is **not** "bank-grade production infrastructure" yet. Use the table
below to know exactly what you are getting.

## Test status

`python -m pytest -q --tb=no` -> **336 passing, 3 xfailed** (xfail = injection paraphrases
the zero-dependency keyword classifier intentionally defers to the embedding
classifier, which is optional). No skips hiding failures.

## Status table

### Implemented (works today, covered by tests)
- Provider adapters (Mock, OpenAI, Anthropic, Gemini, Ollama, OpenAI-compatible) + fallback chain
- PII scrubbing (context-guarded patterns)
- Deterministic safety rule engine (pre/post, precedence veto)
- Isolation heuristics + size caps + tenant/session-scoped memory
- **ToolGuardLayer** — full JSON-Schema validation, arg-injection scan, output
  exfil scan, side-effect taxonomy, dangerous-chain detection, per-tenant/action
  allow-lists, decision recorded in the trace, **LLM-as-judge** tightening hook
- Slack HITL (approve/deny, signed callbacks) **+ persistent queue, escalation
  chains, N-of-M quorum, full approval audit log, PagerDuty/email/webhook adapters**
- Tamper-evident hash chain (SHA-256), optional Ethereum/Hyperledger anchoring
- RCA: replay, causality, counterfactual **+ tool-call graphs, multi-rule
  counterfactuals, critical-path** for complex agents
- JWT / API-key auth, per-tenant rate limiting, usage quotas, cross-tenant trace guard
- Usage-event hooks for billing/analytics (in-memory sink + fail-open webhook)
- SQLite + encrypted SQLite; **Postgres** store; **Redis** distributed backend
- **Migration runner** (stdlib, SQLite + Postgres)
- **Compliance reporter** — consent registry, purpose limitation, retention
  policy with legal floor, JSON/text/PDF auditor reports
- OpenTelemetry per-layer spans (Compliance, Isolation, Safety, ToolGuard,
  Provider, HITL) + W3C trace-context propagation
- FastAPI sidecar (auth, CORS, security headers, structured logging, RCA +
  retention + GDPR-erasure endpoints, `/v1/usage` quota snapshots)
- Dashboard usage page + Redis-backed dashboard rate limiting with local fallback
- Built-in red-team benchmark CLI (`veritrace redteam --json`) with bypass and
  false-positive rates
- Public red-team result/methodology doc and load-test runbook
- Syntax-health test that compiles every Python source file before release
- Small concurrency smoke test for trace uniqueness and hash-chain integrity

### MVP / needs hardening
- Usage quotas: enforced before expensive routes and integrated with rate
  limiting; webhook events exist, but there is no Stripe/Chargebee billing ledger
- Dashboard auth: tenant-scoped config, secure-cookie support, Redis-backed
  throttling, and explicit all-tenant opt-in exist; still not SSO/OIDC/RBAC-grade
- Prompt-injection defense — keyword pass is solid; embedding classifier is
  optional (needs `sentence-transformers`); bypass rate is measured by the
  red-team CLI, not zero
- Multi-process scaling — Redis backend exists; not yet load-tested at scale
- Load testing — runbook exists; no published sustained-load results yet
- RCA for complex branching agents — graph support added; heuristic, not a solver
- OTel tracing — spans emitted; Grafana dashboards are provided as config, not battle-tested

### Not implemented / out of scope for v0.3
- ServiceNow adapter
- QuantumLayer (research stub only — intentionally not built)
- Real external penetration test (must be run by a third party)
- Pilot-user production deployments

## Honest one-line

> Trust middleware for AI agents with deterministic guardrails, HITL, tool
> policy, and tamper-evident traces. Genuinely strong for interviews and early
> users; not yet certified bank-grade infrastructure.
