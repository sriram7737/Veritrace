# Load-test Results

Last refreshed: 2026-05-31

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
- The Docker Compose/Postgres/Redis path in `LOAD_TEST.md` still needs a real
  run on a machine with Docker installed.

