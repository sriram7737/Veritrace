import pytest

dashboard = pytest.importorskip("deploy.dashboard.app")
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.requests import Request  # noqa: E402


@pytest.mark.asyncio
async def test_dashboard_approval_scope_allows_same_tenant(monkeypatch):
    async def fake_get(path, params=None):
        assert path == "/hitl/pending"
        return {"items": [{"request_id": "req-1", "tenant_id": "tenant_a"}]}

    monkeypatch.setattr(dashboard, "_get", fake_get)
    ctx = dashboard.AuthContext("alice", "tenant_a")

    await dashboard._require_pending_approval_scope("req-1", ctx)


@pytest.mark.asyncio
async def test_dashboard_approval_scope_blocks_cross_tenant(monkeypatch):
    async def fake_get(path, params=None):
        return {"items": [{"request_id": "req-1", "tenant_id": "tenant_b"}]}

    monkeypatch.setattr(dashboard, "_get", fake_get)
    ctx = dashboard.AuthContext("alice", "tenant_a")

    with pytest.raises(HTTPException) as exc:
        await dashboard._require_pending_approval_scope("req-1", ctx)

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_dashboard_approval_scope_404_for_unknown_request(monkeypatch):
    async def fake_get(path, params=None):
        return {"items": []}

    monkeypatch.setattr(dashboard, "_get", fake_get)
    ctx = dashboard.AuthContext("alice", "tenant_a")

    with pytest.raises(HTTPException) as exc:
        await dashboard._require_pending_approval_scope("missing", ctx)

    assert exc.value.status_code == 404


def test_dashboard_api_key_auth_can_be_tenant_scoped(monkeypatch):
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_TENANT", "tenant_a")
    request = Request({
        "type": "http",
        "headers": [(b"x-api-key", b"secret")],
    })

    ctx = dashboard._get_auth(request)

    assert ctx is not None
    assert ctx.username == "api_key_user"
    assert ctx.tenant == "tenant_a"


def test_dashboard_upstream_auth_uses_bearer_and_legacy_header(monkeypatch):
    monkeypatch.setattr(dashboard, "PRAMAGENT_API_KEY", "secret")

    headers = dashboard._upstream_headers()

    assert headers["Authorization"] == "Bearer secret"
    assert headers["X-API-Key"] == "secret"


def test_dashboard_super_admin_requires_explicit_opt_in():
    assert dashboard._normalize_dashboard_tenant("*", False) == "default"
    assert dashboard._normalize_dashboard_tenant("*", True) == "*"
    assert dashboard._normalize_dashboard_tenant("tenant_a", False) == "tenant_a"


def test_dashboard_redis_rate_limit_blocks_after_burst(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.store = {}

        def get(self, key):
            return self.store.get(key)

        def set(self, key, value, ex=None):
            self.store[key] = value

    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_REDIS_URL", "redis://fake")
    monkeypatch.setattr(dashboard, "_redis_client", FakeRedis())
    monkeypatch.setattr(dashboard, "_RL_CAPACITY", 1.0)
    monkeypatch.setattr(dashboard, "_RL_REFILL_S", 1000.0)

    assert dashboard._redis_rate_limit("127.0.0.1") is True
    with pytest.raises(HTTPException) as exc:
        dashboard._redis_rate_limit("127.0.0.1")

    assert exc.value.status_code == 429


def test_dashboard_login_cookie_uses_configured_tenant_and_secure_flag(monkeypatch):
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_TENANT", "tenant_a")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_SECURE_COOKIE", True)
    client = TestClient(dashboard.app)

    response = client.post(
        "/login",
        data={"username": "alice", "password": "secret"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie
    token = response.cookies["pramagent_session"]
    payload = dashboard._verify(token)
    assert payload["sub"] == "alice"
    assert payload["tenant"] == "tenant_a"


def test_dashboard_usage_page_is_tenant_scoped(monkeypatch):
    async def fake_get(path, params=None):
        if path == "/usage":
            assert params == {"tenant_id": "tenant_a"}
            return {
                "tenant_id": "tenant_a",
                "calls": 2,
                "tool_validations": 1,
                "cost_usd": 0.01,
                "limits": {"window_s": 86400},
                "remaining": {
                    "calls": 8,
                    "tool_validations": 9,
                    "cost_usd": 0.99,
                },
            }
        if path == "/metrics":
            return {"usage_event_sinks": 1, "usage_quota_enabled": True}
        raise AssertionError(path)

    monkeypatch.setattr(dashboard, "_get", fake_get)
    monkeypatch.setattr(dashboard, "_rate_limit", lambda request: None)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_TENANT", "tenant_a")
    client = TestClient(dashboard.app)

    response = client.get("/usage", headers={"X-API-Key": "secret"})

    assert response.status_code == 200
    assert "tenant_a" in response.text
    assert "Usage Event Sinks" in response.text
