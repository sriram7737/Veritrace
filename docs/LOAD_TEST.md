# Load-test Runbook

Veritrace has deterministic unit/concurrency smoke tests in CI and a first
local smoke-load result in `LOAD_TEST_RESULTS.md`. Use this runbook to generate
proper Docker/Postgres/Redis numbers for a pilot environment.

## Start Stack

```bash
cp .env.example .env
docker compose up -d --build
Invoke-RestMethod http://localhost:8080/health/ready | ConvertTo-Json
```

## Smoke Load With hey

Install `hey`, then run:

```bash
hey -n 1000 -c 25 -m POST `
  -H "Content-Type: application/json" `
  -d '{"prompt":"load test","tenant_id":"load","session_id":"s1"}' `
  http://localhost:8080/v1/run
```

Record:

- Requests/sec
- p50/p95/p99 latency
- HTTP 429 rate
- HTTP 5xx rate
- Postgres CPU/memory
- Redis CPU/memory

## HITL Path

Use a consequential action and verify the dashboard still responds while
approval requests are pending:

```powershell
Invoke-RestMethod `
  -Method POST `
  -Uri "http://localhost:8080/v1/run" `
  -ContentType "application/json" `
  -Body '{"prompt":"Please execute the transfer","tenant_id":"bank","session_id":"demo","action":"wire_transfer"}'
```

## Pass Criteria For A Pilot

- No 5xx responses during a 10-minute steady load.
- p95 latency remains under the pilot target.
- Rate limiting returns 429 instead of degrading the API.
- Dashboard `/usage`, `/metrics`, `/traces`, and `/approvals` remain reachable.
- Hash-chain verification stays true after the run.

This is still not chaos engineering or an SLA. It is the minimum load evidence
to avoid hand-wavy production claims.
