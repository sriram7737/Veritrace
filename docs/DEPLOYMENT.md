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
python -m pytest -q  # 307 passing
uvicorn veritrace.api.app:app --port 8080
```

## Schema migrations
```python
from veritrace.backends.migrations import MigrationRunner, MIGRATIONS
MigrationRunner(sqlite_path="veritrace.db").run(MIGRATIONS)      # dev
MigrationRunner(dsn="postgresql://...").run(MIGRATIONS)          # prod
```

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
