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
    monkeypatch.setattr(dashboard, "VT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "VT_DASHBOARD_TENANT", "tenant_a")
    request = Request({
        "type": "http",
        "headers": [(b"x-api-key", b"secret")],
    })

    ctx = dashboard._get_auth(request)

    assert ctx is not None
    assert ctx.username == "api_key_user"
    assert ctx.tenant == "tenant_a"


def test_dashboard_super_admin_requires_explicit_opt_in():
    assert dashboard._normalize_dashboard_tenant("*", False) == "default"
    assert dashboard._normalize_dashboard_tenant("*", True) == "*"
    assert dashboard._normalize_dashboard_tenant("tenant_a", False) == "tenant_a"


def test_dashboard_login_cookie_uses_configured_tenant_and_secure_flag(monkeypatch):
    monkeypatch.setattr(dashboard, "VT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "VT_DASHBOARD_TENANT", "tenant_a")
    monkeypatch.setattr(dashboard, "VT_DASHBOARD_SECURE_COOKIE", True)
    client = TestClient(dashboard.app)

    response = client.post(
        "/login",
        data={"username": "alice", "password": "secret"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie
    token = response.cookies["vt_session"]
    payload = dashboard._verify(token)
    assert payload["sub"] == "alice"
    assert payload["tenant"] == "tenant_a"
