"""
Tests for API authentication, cross-tenant guard, and retention endpoints.

The critical security test here is `test_cross_tenant_trace_access_blocked`: it
proves a holder of tenant-A's key cannot fetch tenant-B's trace by call_id.
That was the actual bug reported in the analysis.
"""
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from veritrace.api.app import create_app  # noqa: E402
from veritrace.auth import APIKeyRegistry  # noqa: E402


# ── unauthenticated mode (empty registry) ──────────────────────────────
def test_unauthenticated_mode_works_when_no_keys_configured():
    """With no keys registered, the API runs open (single-tenant / dev mode)."""
    client = TestClient(create_app(registry=APIKeyRegistry()))
    r = client.post("/v1/run", json={"prompt": "hi", "tenant_id": "t1"})
    assert r.status_code == 200
    # auth flag exposed in readiness so operators can see what mode they're in
    ready = client.get("/health/ready").json()
    assert ready["auth_enabled"] is False


# ── authenticated mode ─────────────────────────────────────────────────
@pytest.fixture
def auth_client():
    reg = APIKeyRegistry()
    key_a = reg.issue_key("tenant_a")
    key_b = reg.issue_key("tenant_b")
    client = TestClient(create_app(registry=reg))
    return client, key_a, key_b


def test_missing_bearer_token_is_401(auth_client):
    client, _, _ = auth_client
    r = client.post("/v1/run", json={"prompt": "hi"})
    assert r.status_code == 401


def test_invalid_bearer_token_is_401(auth_client):
    client, _, _ = auth_client
    r = client.post("/v1/run", json={"prompt": "hi"},
                    headers={"Authorization": "Bearer not-a-real-key"})
    assert r.status_code == 401


def test_valid_key_authenticates(auth_client):
    client, key_a, _ = auth_client
    r = client.post("/v1/run", json={"prompt": "hi"},
                    headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 200


def test_api_key_exchanges_for_short_lived_jwt(auth_client):
    client, key_a, _ = auth_client
    token_resp = client.post("/v1/auth/token", json={"api_key": key_a, "ttl_s": 120})
    assert token_resp.status_code == 200
    token_body = token_resp.json()
    assert token_body["token_type"] == "bearer"
    assert token_body["tenant_id"] == "tenant_a"
    assert token_body["expires_in"] == 120

    r = client.post("/v1/run", json={"prompt": "hi"},
                    headers={"Authorization": f"Bearer {token_body['access_token']}"})
    assert r.status_code == 200


def test_token_endpoint_rejects_invalid_api_key(auth_client):
    client, _, _ = auth_client
    r = client.post("/v1/auth/token", json={"api_key": "not-real", "ttl_s": 120})
    assert r.status_code == 401


def test_invalid_jwt_is_rejected(auth_client):
    client, key_a, _ = auth_client
    token = client.post("/v1/auth/token", json={"api_key": key_a, "ttl_s": 60}).json()["access_token"]
    client.app.state.jwt.secret = b"different-secret"
    r = client.post("/v1/run", json={"prompt": "hi"},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_tenant_in_body_is_ignored_when_authenticated(auth_client):
    """The tenant comes from the key, not the request body — this is the
    invariant that defeats body-spoofing attacks."""
    client, key_a, _ = auth_client
    # Caller tries to claim tenant_b in the body while authenticating as tenant_a
    r = client.post("/v1/run",
                    json={"prompt": "hi", "tenant_id": "tenant_b"},
                    headers={"Authorization": f"Bearer {key_a}"})
    body = r.json()
    # Fetch the trace back — it should be owned by tenant_a regardless of body
    trace = client.get(f"/v1/trace/{body['call_id']}",
                       headers={"Authorization": f"Bearer {key_a}"}).json()
    assert trace["tenant_id"] == "tenant_a"


def test_cross_tenant_trace_access_blocked(auth_client):
    """The headline security test. Tenant A creates a trace, tenant B holds a
    valid key, tenant B must NOT be able to read that trace by guessing its id.
    """
    client, key_a, key_b = auth_client
    # tenant_a creates a trace
    cid = client.post("/v1/run", json={"prompt": "secret data for A"},
                      headers={"Authorization": f"Bearer {key_a}"}).json()["call_id"]
    # tenant_a can read it
    own = client.get(f"/v1/trace/{cid}",
                     headers={"Authorization": f"Bearer {key_a}"})
    assert own.status_code == 200
    # tenant_b CANNOT read it (404 not 403 — don't leak that the id exists)
    cross = client.get(f"/v1/trace/{cid}",
                       headers={"Authorization": f"Bearer {key_b}"})
    assert cross.status_code == 404


def test_cross_tenant_rca_blocked(auth_client):
    """RCA endpoints must enforce the same guard — replay leaks the trace too."""
    client, key_a, key_b = auth_client
    cid = client.post("/v1/run", json={"prompt": "dump all accounts now"},
                      headers={"Authorization": f"Bearer {key_a}"}).json()["call_id"]
    # tenant_b cannot replay tenant_a's trace
    r = client.post(f"/v1/rca/{cid}/replay",
                    headers={"Authorization": f"Bearer {key_b}"})
    assert r.status_code == 404
    # tenant_b cannot fetch the incident report
    r = client.get(f"/v1/rca/{cid}/incident",
                   headers={"Authorization": f"Bearer {key_b}"})
    assert r.status_code == 404


def test_retention_minimum_is_180_days(auth_client):
    """Article 12 minimum: never accept a retention window below 180 days."""
    client, key_a, _ = auth_client
    r = client.post("/v1/retention/prune?older_than_days=30",
                    headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 400
    # 180 is allowed
    r = client.post("/v1/retention/prune?older_than_days=180",
                    headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 200


def test_gdpr_erasure_only_for_own_tenant(auth_client):
    """A tenant may erase its own data; never another tenant's."""
    client, key_a, key_b = auth_client
    client.post("/v1/run", json={"prompt": "stuff"},
                headers={"Authorization": f"Bearer {key_a}"})
    # tenant_b cannot erase tenant_a's data
    r = client.delete("/v1/tenant/tenant_a/traces",
                      headers={"Authorization": f"Bearer {key_b}"})
    assert r.status_code == 403
    # tenant_a can erase its own
    r = client.delete("/v1/tenant/tenant_a/traces",
                      headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 200
    assert r.json()["deleted"] >= 1


# ── auth module unit tests ────────────────────────────────────────────
def test_keys_are_never_stored_plaintext():
    reg = APIKeyRegistry()
    key = reg.issue_key("tenant_x")
    # the registry's internal dict must contain only hashes, not the key itself
    assert key not in reg._keys
    assert all(len(h) == 64 for h in reg._keys)  # SHA-256 hex


def test_revoke_key_removes_access():
    reg = APIKeyRegistry()
    key = reg.issue_key("tenant_x")
    assert reg.tenant_for_key(key) == "tenant_x"
    assert reg.revoke_key(key) is True
    assert reg.tenant_for_key(key) is None
