"""
pramagent.auth
==============
API-key-per-tenant authentication for the HTTP service.

Why this exists
---------------
Without authentication, the tenant guard on the store is moot: any caller can
claim to be any tenant. A request must arrive with a key, that key must map to
a tenant, and every downstream check uses that *server-determined* tenant — not
a tenant id the caller asserts in the body.

Key handling
------------
Keys are never compared in plain text and never logged. The registry stores the
SHA-256 of each key. Lookups iterate all entries with `secrets.compare_digest`
to prevent timing-based key recovery. Keys are presented in the
`Authorization: Bearer <key>` header.

This is the minimum useful authentication, not the maximum. Production
deployments would layer JWTs with short TTLs, per-key scopes/roles, key
rotation, and an audit log of key issuance. The interface here is small enough
to swap out for any of those without touching the rest of the codebase.
"""
from __future__ import annotations

import base64
import json
import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Optional

log = logging.getLogger(__name__)


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


class APIKeyRegistry:
    """Maps API keys to tenants. Keys are stored as SHA-256, never plain text."""

    def __init__(self) -> None:
        # hashed_key -> tenant_id
        self._keys: dict[str, str] = {}

    def add_key(self, tenant_id: str, key: str) -> None:
        """Register an existing key for a tenant."""
        self._keys[_hash_key(key)] = tenant_id

    def issue_key(self, tenant_id: str) -> str:
        """Generate a new random key for a tenant and return it (plain text,
        one time only — store it on the caller side immediately)."""
        key = "pramagent_" + secrets.token_urlsafe(32)
        self.add_key(tenant_id, key)
        return key

    def revoke_key(self, key: str) -> bool:
        return self._keys.pop(_hash_key(key), None) is not None

    def tenant_for_key(self, presented: str) -> Optional[str]:
        """Constant-time lookup. Returns the tenant_id or None."""
        if not presented:
            return None
        target = _hash_key(presented)
        # iterate every entry so timing reveals nothing about presence
        match: Optional[str] = None
        for hashed, tenant in self._keys.items():
            if secrets.compare_digest(hashed, target):
                match = tenant
        return match

    def __len__(self) -> int:
        return len(self._keys)


class PostgresAPIKeyRegistry(APIKeyRegistry):
    """Postgres-backed API-key registry with the same interface as
    ``APIKeyRegistry``.

    Schema:

    ``pramagent_api_keys(hashed_key, tenant_id, created_at, revoked_at)``

    The plain API key is still returned only once from ``issue_key``. Postgres
    stores only the SHA-256 hash, tenant, creation timestamp, and revocation
    timestamp.
    """

    _DDL = """
    CREATE TABLE IF NOT EXISTS pramagent_api_keys (
        hashed_key TEXT PRIMARY KEY,
        tenant_id  TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        revoked_at TIMESTAMPTZ NULL
    );
    CREATE INDEX IF NOT EXISTS pramagent_api_keys_tenant
        ON pramagent_api_keys(tenant_id);
    CREATE INDEX IF NOT EXISTS pramagent_api_keys_active
        ON pramagent_api_keys(revoked_at)
        WHERE revoked_at IS NULL;
    """

    def __init__(self, dsn: str, *, connect=None) -> None:
        if not dsn:
            raise ValueError("Postgres API key DSN must not be empty")
        self._dsn = dsn
        self._connect = connect
        self._init_schema()

    @classmethod
    def from_dsn(cls, dsn: str) -> "PostgresAPIKeyRegistry":
        return cls(dsn)

    def _connection(self):
        if self._connect is not None:
            return self._connect(self._dsn)
        try:
            import psycopg2  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "psycopg2 is required for PostgresAPIKeyRegistry; "
                "install pramagent[postgres]"
            ) from exc
        return psycopg2.connect(self._dsn)

    def _run(self, fn):
        conn = self._connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    return fn(cur)
        finally:
            try:
                conn.close()
            except Exception:
                log.warning("failed to close registry connection")

    def _init_schema(self) -> None:
        self._run(lambda cur: cur.execute(self._DDL))

    def add_key(self, tenant_id: str, key: str) -> None:
        hashed = _hash_key(key)

        def _fn(cur):
            cur.execute(
                """
                INSERT INTO pramagent_api_keys (hashed_key, tenant_id)
                VALUES (%s, %s)
                ON CONFLICT (hashed_key) DO UPDATE
                SET tenant_id = EXCLUDED.tenant_id,
                    revoked_at = NULL
                """,
                (hashed, tenant_id),
            )

        self._run(_fn)

    def issue_key(self, tenant_id: str) -> str:
        key = "pramagent_" + secrets.token_urlsafe(32)
        self.add_key(tenant_id, key)
        return key

    def revoke_key(self, key: str) -> bool:
        hashed = _hash_key(key)

        def _fn(cur):
            cur.execute(
                """
                UPDATE pramagent_api_keys
                SET revoked_at = now()
                WHERE hashed_key = %s AND revoked_at IS NULL
                """,
                (hashed,),
            )
            return cur.rowcount > 0

        return bool(self._run(_fn))

    def tenant_for_key(self, presented: str) -> Optional[str]:
        if not presented:
            return None
        hashed = _hash_key(presented)

        def _fn(cur):
            cur.execute(
                """
                SELECT tenant_id
                FROM pramagent_api_keys
                WHERE hashed_key = %s AND revoked_at IS NULL
                """,
                (hashed,),
            )
            row = cur.fetchone()
            return row[0] if row else None

        tenant = self._run(_fn)
        return tenant if isinstance(tenant, str) and tenant else None

    def __len__(self) -> int:
        def _fn(cur):
            cur.execute(
                "SELECT COUNT(*) FROM pramagent_api_keys WHERE revoked_at IS NULL"
            )
            row = cur.fetchone()
            return int(row[0]) if row else 0

        return self._run(_fn)


class JWTError(ValueError):
    pass


class JWTManager:
    """Small HS256 JWT issuer/verifier for tenant-scoped API tokens.

    Supports ``kid``-based key rotation while retaining the original single
    secret constructor. New tokens include the active ``kid`` in the header;
    verification accepts tokens signed by any registered, non-retired key.
    """

    def __init__(
        self,
        secret: str | dict[str, str],
        *,
        issuer: str = "pramagent",
        active_kid: str | None = None,
    ) -> None:
        self.issuer = issuer
        if isinstance(secret, dict):
            if not secret:
                raise ValueError("JWT secret registry must not be empty")
            self._secrets = {
                str(kid): value.encode("utf-8")
                for kid, value in secret.items()
                if kid and value
            }
            if not self._secrets:
                raise ValueError("JWT secret registry must contain non-empty keys")
            self.active_kid = active_kid or next(iter(self._secrets))
            if self.active_kid not in self._secrets:
                raise ValueError("active_kid must exist in JWT secret registry")
            self.secret = self._secrets[self.active_kid]
        else:
            if not secret:
                raise ValueError("JWT secret must not be empty")
            self.active_kid = active_kid or "default"
            self.secret = secret.encode("utf-8")
            self._secrets = {self.active_kid: self.secret}

    @classmethod
    def from_env(
        cls,
        *,
        env_var: str = "PRAMAGENT_JWT_SECRETS",
        fallback_secret: str = "",
        issuer: str = "pramagent",
    ) -> "JWTManager":
        """Build from env.

        ``PRAMAGENT_JWT_SECRETS`` format:
            ``kid1:secret1,kid2:secret2``

        ``PRAMAGENT_JWT_ACTIVE_KID`` chooses the signing key. If unset, the
        first listed key signs new tokens. ``fallback_secret`` preserves the
        existing single-secret deployment path.
        """
        raw = os.environ.get(env_var, "").strip()
        if raw:
            secrets_by_kid: dict[str, str] = {}
            for pair in raw.split(","):
                if ":" not in pair:
                    continue
                kid, value = pair.split(":", 1)
                kid = kid.strip()
                value = value.strip()
                if kid and value:
                    secrets_by_kid[kid] = value
            if secrets_by_kid:
                return cls(
                    secrets_by_kid,
                    issuer=issuer,
                    active_kid=os.environ.get("PRAMAGENT_JWT_ACTIVE_KID") or None,
                )
        return cls(fallback_secret, issuer=issuer)

    def rotate(self, kid: str, secret: str, *, activate: bool = True) -> None:
        """Register a new signing secret and optionally make it active."""
        if not kid or not secret:
            raise ValueError("kid and secret must be non-empty")
        self._secrets[kid] = secret.encode("utf-8")
        if activate:
            self.active_kid = kid
            self.secret = self._secrets[kid]

    def retire(self, kid: str) -> bool:
        """Stop accepting tokens signed by ``kid``.

        The active signing key cannot be retired without rotating first.
        """
        if kid == self.active_kid:
            raise ValueError("cannot retire active JWT key")
        return self._secrets.pop(kid, None) is not None

    def issue(self, tenant_id: str, *, ttl_s: int = 900) -> str:
        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT", "kid": self.active_kid}
        payload = {
            "iss": self.issuer,
            "sub": tenant_id,
            "tenant_id": tenant_id,
            "iat": now,
            "exp": now + int(ttl_s),
        }
        signing_input = ".".join([
            _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ])
        sig = hmac.new(self.secret, signing_input.encode("ascii"), hashlib.sha256).digest()
        return f"{signing_input}.{_b64url_encode(sig)}"

    def tenant_for_token(self, token: str, *, now: Optional[int] = None) -> Optional[str]:
        try:
            payload = self.verify(token, now=now)
        except JWTError:
            return None
        tenant = payload.get("tenant_id") or payload.get("sub")
        return tenant if isinstance(tenant, str) and tenant else None

    def verify(self, token: str, *, now: Optional[int] = None) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTError("malformed token")
        signing_input = f"{parts[0]}.{parts[1]}"
        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception as exc:
            raise JWTError("malformed header") from exc
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise JWTError("unsupported token header")
        kid = header.get("kid")
        if kid is not None:
            if not isinstance(kid, str):
                raise JWTError("invalid key id")
            secret = self.secret if kid == self.active_kid else self._secrets.get(kid)
            if secret is None:
                raise JWTError("unknown key id")
        else:
            secret = self.secret
        expected = hmac.new(
            secret, signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        try:
            supplied = _b64url_decode(parts[2])
        except Exception as exc:
            raise JWTError("malformed signature") from exc
        if not hmac.compare_digest(expected, supplied):
            raise JWTError("invalid signature")

        try:
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception as exc:
            raise JWTError("malformed payload") from exc
        if payload.get("iss") != self.issuer:
            raise JWTError("invalid issuer")
        exp = payload.get("exp")
        if not isinstance(exp, int):
            raise JWTError("missing expiration")
        if (int(time.time()) if now is None else now) >= exp:
            raise JWTError("token expired")
        return payload


def load_registry_from_env(
    env_var: str = "PRAMAGENT_API_KEYS",
) -> APIKeyRegistry:
    """Build a registry from an env var formatted as 'tenant1:key1,tenant2:key2'.

    Returns an empty registry if the variable is unset. Useful for the demo
    server; real deployments load keys from a secret manager.
    """
    dsn = os.environ.get("PRAMAGENT_API_KEY_DSN", "").strip()
    reg: APIKeyRegistry
    if dsn:
        reg = PostgresAPIKeyRegistry.from_dsn(dsn)
    else:
        reg = APIKeyRegistry()
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return reg
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        tenant, key = pair.split(":", 1)
        reg.add_key(tenant.strip(), key.strip())
    return reg
