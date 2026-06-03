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
import os
import secrets
import time
from typing import Optional


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


class JWTError(ValueError):
    pass


class JWTManager:
    """Small HS256 JWT issuer/verifier for tenant-scoped API tokens."""

    def __init__(self, secret: str, *, issuer: str = "pramagent") -> None:
        if not secret:
            raise ValueError("JWT secret must not be empty")
        self.secret = secret.encode("utf-8")
        self.issuer = issuer

    def issue(self, tenant_id: str, *, ttl_s: int = 900) -> str:
        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT"}
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
        expected = hmac.new(
            self.secret, signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        try:
            supplied = _b64url_decode(parts[2])
        except Exception as exc:
            raise JWTError("malformed signature") from exc
        if not hmac.compare_digest(expected, supplied):
            raise JWTError("invalid signature")

        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception as exc:
            raise JWTError("malformed payload") from exc
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise JWTError("unsupported token header")
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
