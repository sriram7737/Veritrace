# Load-test Results

Last refreshed: 2026-06-01

## Docker Compose Sustained Load

Environment:

- Windows local development machine
- Docker Desktop 4.74.0 / Docker Engine 29.4.3
- `docker compose --env-file .env.load -p veritrace_load up -d --build`
- Services: API, dashboard, Redis 7, Postgres 16
- Target: `POST /v1/run`
- Auth: enabled via `VERITRACE_API_KEYS`, with Bearer auth on load requests.

Result:

```json
{
  "mode": "docker compose sustained authenticated load",
  "duration_s": 600.214,
  "target_rps": 20,
  "concurrency_cap": 25,
  "requests_started": 12000,
  "results_recorded": 12000,
  "observed_rps": 19.99,
  "status_counts": {
    "200": 6096,
    "429": 5904
  },
  "http_5xx": 0,
  "errors": 0,
  "p50_ms": 60.38,
  "p95_ms": 66.76,
  "p99_ms": 68.74
}
```

Post-run checks:

```json
{
  "api_ready": {
    "status": "ready",
    "chain_valid": true,
    "traces": 6096,
    "auth_enabled": true,
    "jwt_enabled": true,
    "usage_quota_enabled": false
  },
  "audit_verify": {
    "chain_valid": true,
    "records": 6096
  },
  "dashboard_pages": {
    "/": 200,
    "/traces": 200,
    "/approvals": 200,
    "/metrics": 200,
    "/usage": 200
  },
  "log_scan": "no ERROR/Traceback/FATAL/PANIC patterns in API, dashboard, Postgres, or Redis logs for the test window"
}
```

Post-run container snapshot:

```text
veritrace_load-dashboard-1   5.11% CPU   58.16MiB
veritrace_load-api-1         1.27% CPU   87.9MiB
veritrace_load-postgres-1    0.00% CPU   25.39MiB
veritrace_load-redis-1       0.53% CPU   4.832MiB
```

Interpretation:

- The stack stayed healthy for a 10-minute local Docker Compose run.
- Rate limiting returned `429` under pressure instead of producing `5xx`.
- API auth was enabled and dashboard pages remained reachable with the
  dashboard key.
- API, dashboard, Redis, and Postgres remained healthy after the run.
- This is still a single-machine smoke/load test, not an SLA, chaos test, or
  production capacity benchmark.

## Local API Smoke Load

Environment:

- Windows local development machine
- `uvicorn veritrace.api.app:app --host 127.0.0.1 --port 8090`
- Default local app configuration
- No Docker Compose, Redis, Postgres, or external provider load

Result:

```json
{
  "mode": "local uvicorn smoke load, not docker compose",
  "requests": 250,
  "concurrency": 25,
  "elapsed_s": 1.293,
  "requests_per_second": 193.3,
  "status_counts": {
    "200": 60,
    "429": 190
  },
  "p50_ms": 66.33,
  "p95_ms": 204.29,
  "p99_ms": 274.58
}
```

Interpretation:

- The API stayed up under this small concurrent smoke load.
- Rate limiting returned `429` instead of degrading into `5xx`.
- This is not a production load test and should not be used for SLA claims.
- Superseded by the Docker Compose sustained load result above.
