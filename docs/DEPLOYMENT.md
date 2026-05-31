# Veritrace Deployment Guide

## One-command local (Docker Compose)
```bash
veritrace init           # generates .env with secrets + starter config
docker compose up -d     # Postgres + Redis + API + dashboard
# API:       http://localhost:8080/docs
# Dashboard: http://localhost:8501/
veritrace validate       # checks config + Redis/Postgres connectivity
```

## Local without Docker (dev)
```bash
pip install -e ".[dev,api,redis,postgres,otel,encrypted]"
python -m pytest -q  # 344 passing, 3 xfailed
uvicorn veritrace.api.app:app --port 8080
```

## Schema migrations
```python
from veritrace.backends.migrations import MigrationRunner, MIGRATIONS
MigrationRunner(sqlite_path="veritrace.db").run(MIGRATIONS)      # dev
MigrationRunner(dsn="postgresql://...").run(MIGRATIONS)          # prod
```

## Tenant usage quotas
Set any of these env vars to enable quota enforcement. Omit them to leave quotas disabled.

```bash
VT_QUOTA_CALLS=10000
VT_QUOTA_TOOL_VALIDATIONS=50000
VT_QUOTA_COST_USD=100.00
VT_QUOTA_WINDOW_S=86400
```

The API returns HTTP 429 when a tenant exceeds a quota and exposes current
window usage at `GET /v1/usage`.

## Usage analytics / billing webhook
Set `VT_BILLING_WEBHOOK_URL` to emit fail-open JSON usage events for calls,
tool validations, cost records, and quota blocks. This is a pilot integration
hook, not a durable billing ledger.

```bash
VT_BILLING_WEBHOOK_URL=https://billing.example.com/veritrace/events
VT_BILLING_WEBHOOK_SECRET=shared-secret
VT_BILLING_WEBHOOK_TIMEOUT_S=2.0
```

## Dashboard scope
The dashboard is still a lightweight admin UI, not an enterprise IAM system.
Use these env vars to keep it honest in pilots:

```bash
VT_DASHBOARD_TENANT=tenant_a        # "*" means super-admin
VT_DASHBOARD_ALLOW_SUPER_ADMIN=false
VT_DASHBOARD_SECURE_COOKIE=true     # set true behind TLS
```

All-tenant dashboard access is ignored unless both `VT_DASHBOARD_TENANT=*` and
`VT_DASHBOARD_ALLOW_SUPER_ADMIN=true` are set.

## Dashboard rate limiting and usage page
The dashboard uses Redis-backed per-IP rate limiting when
`VT_DASHBOARD_REDIS_URL` or `VT_REDIS_URL` is configured, and falls back to a
local in-process bucket for development.

```bash
VT_DASHBOARD_REDIS_URL=redis://:password@redis:6379/1
VT_DASHBOARD_RL_CAPACITY=60
VT_DASHBOARD_RL_REFILL=60
```

The dashboard exposes `/usage` for per-tenant calls, tool validations, tracked
cost, quota remaining, and configured usage-event sinks. It is a visibility
surface for quotas, not a billing ledger.

## Optional Ethereum/Sepolia anchoring
Install the optional dependency:

```bash
pip install -e ".[ethereum]"
```

Use `EthereumBackend` with a Sepolia RPC URL and private key. Veritrace records
the transaction hash in `trace.anchor_tx_id` and the block in
`trace.anchor_block_number`.

```python
from veritrace import Veritrace
from veritrace.audit import EthereumBackend

audit = EthereumBackend(
    rpc_url="https://sepolia.infura.io/v3/...",
    private_key="0x...",
)
armor = Veritrace(audit=audit)
```

This is still testnet anchoring. Use a dedicated wallet, minimal funds, and a
real secret manager. Do not put private keys in `.env` for production.

## Optional S3 cold archive
Install the optional dependency:

```bash
pip install -e ".[s3]"
```

Wrap a hot store so retention/erasure flows archive old traces to S3 as
encrypted gzip JSON before deleting them from the primary store:

```python
from veritrace.store import SQLiteStore
from veritrace.store_s3 import S3ColdArchiveStore

store = S3ColdArchiveStore(
    SQLiteStore("veritrace.db"),
    bucket="my-veritrace-audit-archive",
    encryption_key="...",  # Fernet key; use KMS/envelope encryption in prod
)
```

The wrapper exposes `archive_metadata()` and accepts a `metadata_sink` callback
so deployments can persist S3 URI, hash, tenant, and timestamp metadata in
Postgres for auditor lookup.

## Kubernetes (Helm)
```bash
kubectl create secret generic veritrace-secrets \
  --from-literal=VT_API_KEY=... --from-literal=VT_JWT_SECRET=... \
  --from-literal=VT_REDIS_URL=redis://... --from-literal=VT_POSTGRES_DSN=postgresql://...
helm install veritrace deploy/helm/veritrace \
  --set image.tag=0.3.0 --set otel.endpoint=http://otel-collector:4317
```
Includes readiness/liveness probes, HorizontalPodAutoscaler (3–10 replicas), and
secret-based config. Point `otel.endpoint` at any OTLP collector (Jaeger,
Honeycomb, Datadog, Grafana Tempo) for distributed traces.

## Cloud notes
- **Postgres**: any managed PG (RDS, Cloud SQL, Neon). Set `VT_POSTGRES_DSN`.
- **Redis**: any managed Redis (ElastiCache, Memorystore, Upstash). Set `VT_REDIS_URL`.
- Both fail open to local backends if unreachable, so a cache blip won't take the API down.
