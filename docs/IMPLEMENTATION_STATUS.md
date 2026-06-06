# Pramagent — Current Implementation Status

_Last updated after the 2026-06-05 Slack HITL and real OpenAI workflow validation pass._

This document is deliberately blunt. Pramagent is **strong trust middleware for
AI agents** — deterministic guardrails, HITL, tool policy, and tamper-evident
traces. It is **not** "bank-grade production infrastructure" yet. Use the table
below to know exactly what you are getting.

Package status: **Alpha**. PyPI metadata, README, and release notes should keep
this maturity label until external security review and real pilot evidence
exist.

## Test status

`python -m pytest -q --tb=no` -> **421 passing**. No skips or
expected failures hiding classifier misses in the bundled suite.

Additional release harnesses:

- `python test_agent_v2.py --mock --api-url http://127.0.0.1:8010 --report test-results/test_agent_v2_full.json`
  -> **57/57 passing** across load, multi-tenant isolation, API/HTTP, and
  regression suites.
- `python examples/dynamic_feed_agent.py --provider mock --reset-db` ->
  **8/8 dynamic feed cases passing**, hash chain valid.
- `python examples/dynamic_feed_agent.py --provider ollama --ollama-model qwen2.5:1.5b --reset-db`
  -> **8/8 dynamic feed cases passing**, hash chain valid.
- Real Slack HITL UI approve/deny against the job-agent integration -> **passed**.
  Approve produced `hitl=approved` and a simulated email side effect; deny
  produced `hitl=denied` and no side effect. Both traces preserved a valid
  hash chain.
- Real OpenAI job-agent stress harness with `gpt-4o-mini`, five tenants,
  concurrency 10, per-request sessions, quota tracking, and real read-only
  public-page fetches -> **216/216 completed**, 0 provider errors, 0 circuit
  breaker trips, 0 post-safety false positives, 18 real fetches executed,
  hash chain valid.

The local pre-PyPI clean-environment check was run on Python 3.13.13. GitHub
Actions is configured to run the same suite on Python 3.10, 3.11, 3.12, and
3.13 with upgraded pip, setuptools, and wheel.

## Status table

### Implemented (works today, covered by tests)
- Provider adapters (Mock, OpenAI, Anthropic, Gemini, Ollama, OpenAI-compatible) + fallback chain
- PII scrubbing (context-guarded patterns)
- Deterministic safety rule engine (pre/post, precedence veto)
- Isolation heuristics + size caps + tenant/session-scoped memory
- **ToolGuardLayer** — Draft 2020-12 JSON Schema validation via `jsonschema`,
  arg-injection scan, output exfil scan, side-effect taxonomy, dangerous-chain
  detection, Redis/back-end-backed side-effect history and session call counters,
  per-tenant/action allow-lists, decision recorded in the trace,
  **LLM-as-judge** tightening hook
- Slack HITL (approve/deny, signed callbacks) **+ persistent queue, escalation
  chains, N-of-M quorum, full approval audit log, ServiceNow/PagerDuty/email/webhook adapters**
- Tamper-evident hash chain (SHA-256), optional real Ethereum/Sepolia anchoring
  with tx hash + block metadata, and Hyperledger fallback anchoring. Live
  Sepolia validation passed on tx
  `0x8d0d7bd15c377224acee00f397272bab1007c757080f19523cfc66c8461b5d99`.
- RCA: replay, causality, counterfactual **+ tool-call graphs, multi-rule
  counterfactuals, critical-path** for complex agents
- JWT / API-key auth, Postgres-backed persistent API-key registry, optional
  SQL-backed dashboard users with generated keys/key regeneration, per-tenant
  rate limiting, usage quotas, cross-tenant trace guard
- JWT `kid`-based signing-key rotation (`PRAMAGENT_JWT_SECRETS` +
  `PRAMAGENT_JWT_ACTIVE_KID`) with legacy single-secret compatibility
- Usage-event hooks for billing/analytics (in-memory hash-chain usage ledger,
  in-memory sink, fail-open webhook, fail-closed mode when explicitly enabled)
- SQLite + encrypted SQLite; **Postgres** store; **Redis** distributed backend
  for rate limits, memory, HITL signals, and ToolGuard side-effect history
- S3 cold archive wrapper for pruned/erased traces (gzip + encrypted JSON,
  metadata sink hook for Postgres/compliance tables). Live AWS S3
  archive/restore validation passed with a tiny fake trace.
- **Migration runner** (stdlib, SQLite + Postgres)
- **Compliance reporter** — consent registry, purpose limitation, retention
  policy with legal floor, JSON/text/PDF auditor reports
- OpenTelemetry per-layer spans (Compliance, Isolation, Safety, ToolGuard,
  Provider, HITL) + W3C trace-context propagation
- FastAPI sidecar (auth, CORS, security headers, structured logging, RCA +
  retention + GDPR-erasure endpoints, `/v1/usage` quota snapshots, and
  `/v1/usage/ledger` ledger evidence)
- Dashboard usage page, Redis-backed dashboard rate limiting with local
  fallback, no-store security headers, session revocation, optional SQL users
  with generated high-entropy dashboard keys, bcrypt key hashes, phone/email
  identities, hashed reset tokens, and CSRF protection for cookie-authenticated
  state-changing actions
- Built-in red-team benchmark CLI with static and dynamic mutation modes
  (`pramagent redteam --json --dynamic --attacks 200 --seed 999`)
- Public red-team result/methodology doc and load-test runbook
- Syntax-health test that compiles every Python source file before release
- Small concurrency smoke test for trace uniqueness and hash-chain integrity

### MVP / needs hardening
- Usage quotas: enforced before expensive routes and integrated with rate
  limiting; ledger/webhook events exist, but there is no Stripe/Chargebee
  provider, invoice reconciliation, or billing-grade metering backend
- Ethereum anchoring: Sepolia live smoke test passed; no mainnet runbook, no
  deployed verifier contract, and no production key-management story yet
- S3 cold archive: live AWS S3 archive/restore smoke test passed; needs real
  lifecycle policies, KMS/envelope encryption, and restore runbooks before
  compliance use
- Dashboard auth: tenant-scoped config, shared-key fallback, optional
  SQLite/Postgres users, generated dashboard keys, bcrypt key hashes, key
  regeneration tokens, secure-cookie support, CSRF protection, Redis-backed
  throttling, and explicit all-tenant opt-in exist; still not SSO/OIDC/RBAC-grade
  and no email/SMS delivery provider is wired yet
- HITL adapters: Slack collects approve/deny decisions. ServiceNow,
  PagerDuty, email, and generic webhooks are notification/escalation adapters;
  broader enterprise approval workflows are not complete.
- Prompt-injection defense — keyword pass catches the bundled static corpus and
  seeded dynamic mutation smoke tests; embedding classifier is optional (needs
  `sentence-transformers`); third-party and novel red-team sets are still
  required before high-stakes claims
- Multi-process scaling — Redis backend exists and ToolGuard chain state can be
  shared across workers; still not load-tested at 50+ tenant / 10k+ daily-call
  scale
- Load testing — authenticated local Docker Compose/Postgres/Redis 10-minute
  run passed with 12,000 requests, 0 errors, 0 HTTP 5xx; still not chaos/SLA
  testing
- RCA for complex branching agents — graph support added; heuristic, not a solver
- OTel tracing — spans emitted; Grafana dashboards are provided as config, not battle-tested

### Not implemented / out of scope for the current alpha
- SSO/OIDC/RBAC dashboard auth and email-verification delivery
- QuantumLayer (future research only; intentionally not built or exposed)
- Real external penetration test (must be run by a third party)
- 200-500 call run with full production side effects such as real email sends
  or third-party scraper providers. Current heavy run executes real read-only
  fetches only.
- Pilot-user production deployments

## Latest Workflow Evidence

2026-06-05 job-agent stress harness with real OpenAI:

- Model: `gpt-4o-mini`
- Calls: 216 across five tenants, concurrency 10, per-request sessions
- Real tools: 18 read-only `fetch_public_page` calls executed against
  `https://example.com`; SSRF variants were blocked before any network call
- Quotas: per-tenant call/cost tracking enabled; 0 quota blocks at the configured limits
- Provider health: 0 provider errors, 0 circuit-breaker trips
- Safety quality: 0 post-safety false positives, 0 sentinel outputs in non-blocked responses
- Cost: `$0.00674850` total, approximately `$0.031` per 1,000 calls
  under this workload, with 2,142 prompt tokens and 10,712 completion tokens
- Latency: avg 1261.19 ms, p50 1180.77 ms, p95 3104.49 ms, p99 4207.98 ms, max 4293.46 ms
- Audit: hash chain valid

2026-06-05 real Slack HITL UI test:

- Approve path: `hitl=approved`, simulated email side effect recorded, trace hash
  `ff70c2adb3ed15b434bb6c63f8bb23b634b9840815d2b6e49e2bfa237681d08c`
- Deny path: `hitl=denied`, no side effect executed, trace hash
  `d9bd6d07070b6391401a0ac24dcd24cae760435a206d5b3425038ff37e395064`

These runs are strong beta evidence for the middleware. They are still not a
formal pen-test, a third-party red-team, or a production SLA/load guarantee.

## Honest one-line

> Trust middleware for AI agents with deterministic guardrails, HITL, tool
> policy, and tamper-evident traces. Genuinely strong for interviews and early
> users; not yet certified bank-grade infrastructure.
