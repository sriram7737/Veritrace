# Veritrace Hardening Guide

This guide is intentionally blunt. Veritrace is useful guardrail and audit
middleware today, but regulated production use needs more proof, stronger
controls, and third-party validation.

## What This Pass Added

- In-memory hash-chain usage ledger for pilot metering evidence.
- `/v1/usage/ledger` API endpoint for tenant-scoped ledger inspection.
- Explicit fail-open/fail-closed behavior for usage event sinks.
- ServiceNow notify-only HITL adapter for ITSM/on-call escalation.
- Updated docs that distinguish MVP evidence from billing-grade or
  compliance-grade guarantees.

## Release Gates Before Public Claims

Run these before any public release announcement:

```bash
python -m pytest -q --tb=no
python -m compileall veritrace tests
veritrace redteam --json --dynamic --attacks 200 --seed 999
```

Then validate the optional systems you plan to claim:

- Sepolia anchoring with a burner wallet and testnet ETH.
- S3 archive/restore with a tiny fake trace and a scoped test bucket.
- Docker Compose stack with Postgres, Redis, API, and dashboard.

Publish the exact tx hash, S3 archive smoke result, red-team numbers, and test
count in `docs/LIVE_TEST_RESULTS.md`.

## Safety Hardening

Do next:

- Expand the red-team corpus with third-party jailbreak sets, indirect prompt
  injection, tool-output poisoning, delimiter attacks, and multi-step tool
  chains.
- Track bypass rate and false-positive rate per release in
  `docs/REDTEAM_RESULTS.md`.
- Add an optional stronger semantic judge for high-risk deployments.
- Keep ToolGuard as the deterministic gate: schema validation, side-effect
  taxonomy, tenant/action allow-lists, and HITL escalation should remain outside
  the model.

Do not claim:

- "Unbreakable" prompt defense.
- Bank/healthcare-grade safety without an external assessment.
- Production semantic safety from the bundled smoke benchmark alone.

## Billing And Usage

Current state:

- Quotas are enforced before expensive calls and tool validations.
- Usage events can be sent to a webhook.
- The local usage ledger is hash-chained evidence, not invoice reconciliation.

Next:

- Add a persistent Postgres usage ledger.
- Add Stripe/Chargebee webhook ingestion and idempotency keys.
- Add reconciliation jobs that compare local usage events to billing-provider
  usage records.
- Add dashboard views for usage by tenant, model, action, and billing period.

## HITL And ITSM

Current state:

- Slack can collect decisions.
- ServiceNow, PagerDuty, email, and webhooks can notify humans.
- Quorum/escalation primitives exist.

Next:

- Persist approval queues in Redis/Postgres for multi-worker deployments.
- Add escalation policies with owner rotation and timeout handoff.
- Add approval evidence exports: who approved, when, context hash, and final
  action.
- Add SSO/OIDC/RBAC for dashboard and approval admin workflows.

## Observability And Operations

Current state:

- Per-layer OpenTelemetry spans exist.
- Docker Compose, Redis, Postgres, and basic Grafana config exist.
- Load-test runbook exists.

Next:

- Publish repeatable 10-minute and 60-minute load results.
- Add alert thresholds for block-rate spikes, HITL timeout spikes, quota-store
  failures, provider fallback rate, and audit anchoring failures.
- Add chaos tests for Redis/Postgres outages and provider timeouts.
- Maintain an incident-response runbook with rollback and data-export steps.

## Compliance Evidence

Current state:

- Compliance mapping docs exist.
- Retention, erasure, consent, purpose limitation, S3 archive, and audit export
  primitives exist.

Next:

- Map controls to NIST AI RMF, ISO 42001, SOC 2, HIPAA, and EU AI Act in one
  evidence table.
- Add field-level redaction policies by tenant.
- Add tiered retention by tenant, data class, and legal hold.
- Use immutable external storage for audit exports where required.
- Get an external pen test before claiming regulated production readiness.

## Honest Positioning

Use this:

> Trust middleware for AI agents with deterministic guardrails, HITL, tool
> policy, and tamper-evident traces.

Avoid this until externally proven:

> Certified production trust infrastructure for banks and hospitals.
