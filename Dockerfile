# ── Stage 1: build deps ──────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY veritrace/ veritrace/
COPY README.md ./

# Install with all optional extras
RUN pip install --no-cache-dir --prefix=/install \
    ".[api,redis,postgres]"

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY veritrace/ veritrace/
COPY pyproject.toml .

# Non-root user for security
RUN useradd -r -u 1001 -g root veritrace \
    && chown -R 1001:0 /app
USER 1001

# Default: run the FastAPI sidecar
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VT_HOST=0.0.0.0 \
    VT_PORT=8080 \
    VT_LOG_LEVEL=info

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${VT_PORT}/health || exit 1

CMD ["sh", "-c", "python -m uvicorn veritrace.api.app:app --host ${VT_HOST} --port ${VT_PORT} --log-level ${VT_LOG_LEVEL}"]
