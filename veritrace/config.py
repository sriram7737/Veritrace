"""
veritrace.config
================
Centralized configuration via Pydantic Settings.

All environment variables are prefixed VT_ and can be overridden by a .env
file in the working directory. Import ``settings`` for the singleton; call
``Settings()`` to create an isolated instance in tests.

Usage
-----
    from veritrace.config import settings

    armor = Veritrace(
        isolation=IsolationLayer(max_input_bytes=settings.max_input_bytes),
        ...
    )

    # In FastAPI startup:
    backend = RedisBackend.from_url(settings.redis_url)

Environment variables
---------------------
VT_REDIS_URL              redis://localhost:6379/0
VT_POSTGRES_DSN           postgresql://veritrace:secret@localhost/veritrace
VT_MAX_INPUT_BYTES        65536
VT_MAX_OUTPUT_BYTES       65536
VT_RATE_LIMIT_CAPACITY    100
VT_RATE_LIMIT_REFILL      10          tokens/second
VT_INJECTION_THRESHOLD    0.65        cosine similarity for embedding classifier
VT_BREAKER_THRESHOLD      5           failures before circuit opens
VT_BREAKER_COOLDOWN_S     30.0
VT_POOL_MAX_CONNECTIONS   10
VT_LOG_LEVEL              info
VT_API_KEY                (required in production)
VT_SIGNING_KEY            (required in production)
VT_JWT_SECRET             change-me-in-production
VT_OTEL_ENDPOINT          (optional OTLP gRPC endpoint)
VT_OTEL_SERVICE_NAME      veritrace
VT_HITL_SLACK_TOKEN       (optional)
VT_HITL_SLACK_CHANNEL     (optional)
VT_HITL_TIMEOUT_S         300
VT_CHAIN_WINDOW           10
"""
from __future__ import annotations

import os
from typing import Optional


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    val = os.environ.get(key, "").lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    return default


class Settings:
    """
    Immutable configuration snapshot.

    Reads from environment at construction time. Use the module-level
    ``settings`` singleton in application code; construct a fresh ``Settings()``
    in tests to pick up monkeypatched env vars.
    """

    def __init__(self) -> None:
        # ── networking / backends ──────────────────────────────────────────────
        self.redis_url: str = _env(
            "VT_REDIS_URL", "redis://localhost:6379/0")
        self.postgres_dsn: str = _env(
            "VT_POSTGRES_DSN", "postgresql://veritrace:veritrace@localhost/veritrace")

        # ── isolation / safety ────────────────────────────────────────────────
        self.max_input_bytes: int  = _env_int("VT_MAX_INPUT_BYTES",  64 * 1024)
        self.max_output_bytes: int = _env_int("VT_MAX_OUTPUT_BYTES", 64 * 1024)
        self.injection_threshold: float = _env_float("VT_INJECTION_THRESHOLD", 0.65)
        self.block_on_injection: bool   = _env_bool("VT_BLOCK_ON_INJECTION", True)

        # ── rate limiting ─────────────────────────────────────────────────────
        self.rate_limit_capacity: float = _env_float("VT_RATE_LIMIT_CAPACITY", 100.0)
        self.rate_limit_refill:   float = _env_float("VT_RATE_LIMIT_REFILL",   10.0)

        # ── circuit breaker ───────────────────────────────────────────────────
        self.breaker_threshold:  int   = _env_int("VT_BREAKER_THRESHOLD", 5)
        self.breaker_cooldown_s: float = _env_float("VT_BREAKER_COOLDOWN_S", 30.0)

        # ── connection pool ───────────────────────────────────────────────────
        self.pool_max_connections: int = _env_int("VT_POOL_MAX_CONNECTIONS", 10)

        # ── tool guard ────────────────────────────────────────────────────────
        self.chain_window: int = _env_int("VT_CHAIN_WINDOW", 10)

        # ── HITL ──────────────────────────────────────────────────────────────
        self.hitl_timeout_s:      float = _env_float("VT_HITL_TIMEOUT_S", 300.0)
        self.hitl_slack_token:    str   = _env("VT_HITL_SLACK_TOKEN")
        self.hitl_slack_channel:  str   = _env("VT_HITL_SLACK_CHANNEL")

        # ── auth / security ───────────────────────────────────────────────────
        self.api_key:      str = _env("VT_API_KEY")
        self.signing_key:  str = _env("VT_SIGNING_KEY")
        self.jwt_secret:   str = _env("VT_JWT_SECRET", "change-me-in-production")
        self.session_ttl:  int = _env_int("VT_SESSION_TTL_S", 3600)

        # ── observability ─────────────────────────────────────────────────────
        self.log_level:          str = _env("VT_LOG_LEVEL", "info")
        self.otel_endpoint:      str = _env("VT_OTEL_ENDPOINT")
        self.otel_service_name:  str = _env("VT_OTEL_SERVICE_NAME", "veritrace")

    def is_production(self) -> bool:
        """True when critical secrets are set (not defaults)."""
        return bool(self.api_key) and self.jwt_secret != "change-me-in-production"

    def validate(self) -> list[str]:
        """Return list of configuration warnings. Empty = all good."""
        warnings = []
        if not self.api_key:
            warnings.append("VT_API_KEY is not set — API is unauthenticated")
        if self.jwt_secret == "change-me-in-production":
            warnings.append("VT_JWT_SECRET is using the default value — insecure in production")
        if not self.signing_key:
            warnings.append("VT_SIGNING_KEY is not set — audit chain cannot be verified")
        if not self.redis_url.startswith("redis"):
            warnings.append("VT_REDIS_URL does not look like a Redis URL")
        return warnings

    def redis_backend(self):
        """Construct a RedisBackend from current settings. Returns None if URL empty."""
        if not self.redis_url:
            return None
        try:
            from .backends.redis_backend import RedisBackend
            return RedisBackend.from_url(
                self.redis_url,
                max_connections=self.pool_max_connections,
                breaker_threshold=self.breaker_threshold,
                breaker_cooldown_s=self.breaker_cooldown_s,
            )
        except Exception:
            return None

    def postgres_store(self):
        """Construct a PostgresStore from current settings. Returns None if DSN empty."""
        if not self.postgres_dsn:
            return None
        try:
            from .store_postgres import PostgresStore
            return PostgresStore.from_dsn(
                self.postgres_dsn,
                max_pool_size=self.pool_max_connections,
                breaker_threshold=self.breaker_threshold,
                breaker_cooldown_s=self.breaker_cooldown_s,
            )
        except Exception:
            return None

    def __repr__(self) -> str:
        safe_redis = self.redis_url.split("@")[-1] if "@" in self.redis_url else self.redis_url
        return (
            f"Settings(redis={safe_redis!r}, "
            f"max_input={self.max_input_bytes}, "
            f"rate_limit={self.rate_limit_capacity}/{self.rate_limit_refill}tok/s, "
            f"production={self.is_production()})"
        )


# ── module-level singleton ────────────────────────────────────────────────────
settings = Settings()
