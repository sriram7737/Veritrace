import pytest

dashboard = pytest.importorskip("deploy.dashboard.app")
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pramagent.dashboard_auth import SQLiteDashboardUserStore  # noqa: E402
from starlette.requests import Request  # noqa: E402


def _login_dashboard(monkeypatch, tenant: str = "tenant_a"):
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_TENANT", tenant)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_SECURE_COOKIE", False)
    dashboard._revoked_sessions.clear()
    client = TestClient(dashboard.app)
    login = client.post(
        "/login",
        data={"username": "alice", "password": "secret"},
        follow_redirects=False,
    )
    assert login.status_code == 302
    token = login.cookies["pramagent_session"]
    payload = dashboard._verify(token)
    assert payload is not None
    return client, payload["csrf"]


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


def test_dashboard_logout_revokes_session_and_protected_pages_are_no_store(monkeypatch):
    async def fake_get(path, params=None):
        if path == "/usage":
            return {"tenant_id": "tenant_a", "calls": 1, "limits": {}, "remaining": {}}
        if path == "/metrics":
            return {}
        raise AssertionError(path)

    monkeypatch.setattr(dashboard, "_get", fake_get)
    monkeypatch.setattr(dashboard, "_rate_limit", lambda request: None)
    client, csrf = _login_dashboard(monkeypatch)

    usage = client.get("/usage")
    assert usage.status_code == 200
    assert "no-store" in usage.headers["cache-control"]

    logout = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert logout.status_code == 303
    assert "pramagent_session=" in logout.headers["set-cookie"]
    assert "Max-Age=0" in logout.headers["set-cookie"]

    protected = client.get("/usage", follow_redirects=False)
    assert protected.status_code == 302
    assert protected.headers["location"] == "/login"


def test_dashboard_logout_requires_csrf_for_cookie_sessions(monkeypatch):
    async def fake_get(path, params=None):
        if path == "/usage":
            return {"tenant_id": "tenant_a", "calls": 1, "limits": {}, "remaining": {}}
        if path == "/metrics":
            return {}
        raise AssertionError(path)

    monkeypatch.setattr(dashboard, "_get", fake_get)
    monkeypatch.setattr(dashboard, "_rate_limit", lambda request: None)
    client, _ = _login_dashboard(monkeypatch)

    denied = client.post("/logout", follow_redirects=False)

    assert denied.status_code == 403
    assert client.get("/usage").status_code == 200


def test_dashboard_logout_does_not_allow_get(monkeypatch):
    client, _ = _login_dashboard(monkeypatch)

    response = client.get("/logout", follow_redirects=False)

    assert response.status_code == 405


def test_dashboard_approval_posts_require_csrf_for_cookie_sessions(monkeypatch):
    async def fake_get(path, params=None):
        assert path == "/hitl/pending"
        return {"items": [{"request_id": "req-1", "tenant_id": "tenant_a"}]}

    async def fake_post(path, json_body):
        raise AssertionError("approval should not reach upstream without CSRF")

    monkeypatch.setattr(dashboard, "_get", fake_get)
    monkeypatch.setattr(dashboard, "_post", fake_post)
    client, _ = _login_dashboard(monkeypatch)

    response = client.post("/approvals/req-1/approve")

    assert response.status_code == 403


def test_dashboard_approval_posts_accept_csrf_header(monkeypatch):
    calls = []

    async def fake_get(path, params=None):
        assert path == "/hitl/pending"
        return {"items": [{"request_id": "req-1", "tenant_id": "tenant_a"}]}

    async def fake_post(path, json_body):
        calls.append((path, json_body))
        return {"ok": True}

    monkeypatch.setattr(dashboard, "_get", fake_get)
    monkeypatch.setattr(dashboard, "_post", fake_post)
    client, csrf = _login_dashboard(monkeypatch)

    response = client.post("/approvals/req-1/approve", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    assert "Approved" in response.text
    assert calls == [("/hitl/req-1/decide", {"approved": True})]


def test_dashboard_api_key_approval_skips_csrf_for_automation(monkeypatch):
    calls = []

    async def fake_get(path, params=None):
        assert path == "/hitl/pending"
        return {"items": [{"request_id": "req-1", "tenant_id": "tenant_a"}]}

    async def fake_post(path, json_body):
        calls.append((path, json_body))
        return {"ok": True}

    monkeypatch.setattr(dashboard, "_get", fake_get)
    monkeypatch.setattr(dashboard, "_post", fake_post)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_TENANT", "tenant_a")
    client = TestClient(dashboard.app)

    response = client.post("/approvals/req-1/deny", headers={"X-API-Key": "secret"})

    assert response.status_code == 200
    assert "Denied" in response.text
    assert calls == [("/hitl/req-1/decide", {"approved": False})]


def test_dashboard_csv_export_is_tenant_scoped_and_downloadable(monkeypatch):
    async def fake_get(path, params=None):
        assert path == "/traces"
        assert params == {"limit": 10000, "tenant_id": "tenant_a"}
        return {
            "items": [
                {
                    "created_at": "2026-06-04T00:00:00Z",
                    "call_id": "call-1",
                    "this_hash": "abc",
                    "prev_hash": "000",
                    "tenant_id": "tenant_a",
                    "session_id": "s1",
                    "action": "respond",
                    "input_text": "hello",
                    "output_text": "world",
                    "blocked": False,
                    "block_reason": "",
                    "pre_verdict": "allow",
                    "post_verdict": "allow",
                    "hitl_status": "auto",
                    "provider": "mock",
                    "provider_model": "demo",
                    "provider_cost_usd": 0,
                    "total_latency_ms": 1.2,
                },
                {"tenant_id": "tenant_b", "this_hash": "blocked-by-scope"},
            ]
        }

    monkeypatch.setattr(dashboard, "_get", fake_get)
    monkeypatch.setattr(dashboard, "_rate_limit", lambda request: None)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_TENANT", "tenant_a")
    client = TestClient(dashboard.app)

    response = client.get("/export/traces.csv", headers={"X-API-Key": "secret"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert 'filename="pramagent_traces.csv"' in response.headers["content-disposition"]
    assert "no-store" in response.headers["cache-control"]
    assert "call_id" in response.text
    assert "call-1" in response.text
    assert "blocked-by-scope" not in response.text


def test_dashboard_user_store_hashes_passwords_and_resets_once(tmp_path):
    store = SQLiteDashboardUserStore(tmp_path / "dashboard-users.db")
    user = store.create_user(
        username="alice",
        email="alice@example.com",
        password="old-password",
        tenant_id="tenant_a",
        role="viewer",
    )

    assert user.tenant_id == "tenant_a"
    assert store.authenticate("alice", "wrong-password") is None
    assert store.authenticate("alice@example.com", "old-password").username == "alice"

    token = store.create_reset_token("alice@example.com", ttl_s=300)
    assert token
    assert store.reset_password(token, "new-password") is True
    assert store.reset_password(token, "another-password") is False
    assert store.authenticate("alice", "old-password") is None
    assert store.authenticate("alice", "new-password").tenant_id == "tenant_a"


def test_dashboard_signup_creates_user_session_when_enabled(tmp_path, monkeypatch):
    store = SQLiteDashboardUserStore(tmp_path / "dashboard-users.db")
    monkeypatch.setattr(dashboard, "_user_store", store)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_SIGNUP_ENABLED", True)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_SIGNUP_TENANT", "tenant_signup")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_DEFAULT_ROLE", "viewer")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_SECURE_COOKIE", False)
    monkeypatch.setattr(dashboard, "_rate_limit", lambda request: None)
    client = TestClient(dashboard.app)

    response = client.post(
        "/signup",
        data={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "strong-password",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    token = response.cookies["pramagent_session"]
    payload = dashboard._verify(token)
    assert payload["sub"] == "newuser"
    assert payload["tenant"] == "tenant_signup"
    assert payload["role"] == "viewer"
    assert store.authenticate("newuser", "strong-password") is not None


def test_dashboard_sql_user_login_takes_precedence_over_shared_key(tmp_path, monkeypatch):
    store = SQLiteDashboardUserStore(tmp_path / "dashboard-users.db")
    store.create_user(
        username="alice",
        email="alice@example.com",
        password="user-password",
        tenant_id="tenant_sql",
        role="auditor",
    )
    monkeypatch.setattr(dashboard, "_user_store", store)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_KEY", "")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_SECURE_COOKIE", False)
    monkeypatch.setattr(dashboard, "_rate_limit", lambda request: None)
    client = TestClient(dashboard.app)

    response = client.post(
        "/login",
        data={"username": "alice", "password": "user-password"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    payload = dashboard._verify(response.cookies["pramagent_session"])
    assert payload["tenant"] == "tenant_sql"
    assert payload["role"] == "auditor"


def test_dashboard_forgot_password_flow_changes_sql_user_password(tmp_path, monkeypatch):
    store = SQLiteDashboardUserStore(tmp_path / "dashboard-users.db")
    store.create_user(
        username="alice",
        email="alice@example.com",
        password="old-password",
        tenant_id="tenant_a",
    )
    monkeypatch.setattr(dashboard, "_user_store", store)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED", True)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_RESET_SHOW_TOKEN", True)
    monkeypatch.setattr(dashboard, "_rate_limit", lambda request: None)
    client = TestClient(dashboard.app)

    requested = client.post(
        "/forgot-password",
        data={"email": "alice@example.com"},
    )

    assert requested.status_code == 200
    marker = "/reset-password?token="
    assert marker in requested.text
    token = requested.text.split(marker, 1)[1].split('"', 1)[0]

    changed = client.post(
        "/reset-password",
        data={"token": token, "password": "new-password"},
    )

    assert changed.status_code == 200
    assert "Password updated" in changed.text
    assert store.authenticate("alice", "old-password") is None
    assert store.authenticate("alice", "new-password") is not None
