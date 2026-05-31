"""
Veritrace Admin Dashboard
=========================
FastAPI + HTMX. No build step, no npm.

Authentication
--------------
Every request must carry one of:
  - Header  X-API-Key: <VT_DASHBOARD_KEY>
  - Cookie  vt_session=<signed JWT>  (set after /login)

JWT payload: {"sub": "<username>", "tenant": "<tenant_id_or_*>", "exp": ...}

If tenant == "*" the user sees all tenants (super-admin).
Otherwise traces, metrics, and approvals are scoped to that tenant only.

Set VT_DASHBOARD_KEY and VT_JWT_SECRET in the environment (or docker-compose).
To enable all-tenant access, set both VT_DASHBOARD_TENANT=* and
VT_DASHBOARD_ALLOW_SUPER_ADMIN=true.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Optional

import httpx
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates


def _normalize_dashboard_tenant(raw_tenant: str, allow_super_admin: bool) -> str:
    """Require an explicit opt-in before the dashboard can see every tenant."""
    if raw_tenant == "*":
        return "*" if allow_super_admin else "default"
    return raw_tenant or "default"


VT_API_URL       = os.environ.get("VT_API_URL", "http://localhost:8080")
VT_API_KEY       = os.environ.get("VT_API_KEY", "")
VT_DASHBOARD_KEY = os.environ.get("VT_DASHBOARD_KEY", VT_API_KEY)  # shared key for browser
VT_JWT_SECRET    = os.environ.get("VT_JWT_SECRET", "change-me-in-production")
VT_DASHBOARD_ALLOW_SUPER_ADMIN = os.environ.get(
    "VT_DASHBOARD_ALLOW_SUPER_ADMIN", "false"
).lower() in {"1", "true", "yes", "on"}
_VT_DASHBOARD_TENANT_RAW = os.environ.get("VT_DASHBOARD_TENANT", "default")
VT_DASHBOARD_TENANT = _normalize_dashboard_tenant(
    _VT_DASHBOARD_TENANT_RAW,
    VT_DASHBOARD_ALLOW_SUPER_ADMIN,
)
VT_DASHBOARD_SECURE_COOKIE = os.environ.get(
    "VT_DASHBOARD_SECURE_COOKIE", "false"
).lower() in {"1", "true", "yes", "on"}
SESSION_TTL_S    = int(os.environ.get("VT_SESSION_TTL_S", "3600"))

app = FastAPI(title="Veritrace Dashboard", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")


# ── minimal JWT (HS256, no external deps) ────────────────────────────────────

import base64, struct

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _sign(payload: dict) -> str:
    header  = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    body    = _b64url(json.dumps(payload).encode())
    signing_input = f"{header}.{body}".encode()
    sig = hmac.new(VT_JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(sig)}"

def _verify(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        signing_input = f"{header}.{body}".encode()
        expected = _b64url(
            hmac.new(VT_JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, sig):
            return None
        # decode payload
        padded = body + "=" * (4 - len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ── auth dependency ───────────────────────────────────────────────────────────

class AuthContext:
    def __init__(self, username: str, tenant: str):
        self.username = username
        self.tenant   = tenant          # "*" = all tenants
    def scope(self, tenant_id: str) -> bool:
        return self.tenant == "*" or self.tenant == tenant_id


def _get_auth(request: Request) -> Optional[AuthContext]:
    # 1. X-API-Key header (CLI / curl usage)
    key = request.headers.get("X-API-Key", "")
    if key and VT_DASHBOARD_KEY and hmac.compare_digest(key, VT_DASHBOARD_KEY):
        return AuthContext("api_key_user", VT_DASHBOARD_TENANT)

    # 2. Cookie session JWT
    token = request.cookies.get("vt_session", "")
    if token:
        payload = _verify(token)
        if payload:
            return AuthContext(payload.get("sub", ""), payload.get("tenant", "*"))

    return None


def require_auth(request: Request) -> AuthContext:
    ctx = _get_auth(request)
    if ctx is None:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return ctx


# ── rate limit (simple per-IP token bucket, in-process) ──────────────────────

_rl_state: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_refill)
_RL_CAPACITY    = float(os.environ.get("VT_DASHBOARD_RL_CAPACITY", "60"))
_RL_REFILL_S    = float(os.environ.get("VT_DASHBOARD_RL_REFILL", "60"))  # tokens/minute

def _rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    tokens, last = _rl_state.get(ip, (_RL_CAPACITY, now))
    tokens = min(_RL_CAPACITY, tokens + (now - last) * (_RL_CAPACITY / _RL_REFILL_S))
    if tokens < 1:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _rl_state[ip] = (tokens - 1, now)


# ── API proxy helpers ─────────────────────────────────────────────────────────

def _upstream_headers() -> dict:
    return {"X-API-Key": VT_API_KEY} if VT_API_KEY else {}


async def _get(path: str, params: Optional[dict] = None) -> dict | list:
    async with httpx.AsyncClient(base_url=VT_API_URL, timeout=10.0) as client:
        r = await client.get(path, headers=_upstream_headers(), params=params or {})
        r.raise_for_status()
        return r.json()


async def _post(path: str, json_body: dict) -> dict:
    async with httpx.AsyncClient(base_url=VT_API_URL, timeout=10.0) as client:
        r = await client.post(path, headers=_upstream_headers(), json=json_body)
        r.raise_for_status()
        return r.json()


def _filter_by_tenant(items: list, ctx: AuthContext) -> list:
    if ctx.tenant == "*":
        return items
    return [t for t in items if t.get("tenant_id") == ctx.tenant]


async def _require_pending_approval_scope(request_id: str, ctx: AuthContext) -> None:
    """Authorize approve/deny against the dashboard tenant scope."""
    if ctx.tenant == "*":
        return
    try:
        data = await _get("/hitl/pending")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    items = data if isinstance(data, list) else data.get("items", [])
    for item in items:
        rid = item.get("request_id") or item.get("id")
        if rid == request_id:
            context = item.get("context") or {}
            tenant_id = item.get("tenant_id") or context.get("tenant_id") or context.get("tenant") or ""
            if ctx.scope(tenant_id):
                return
            raise HTTPException(status_code=403, detail="Access denied")
    raise HTTPException(status_code=404, detail="Approval request not found")


# ── health (no auth) ──────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "ts": time.time()}


# ── login / logout ────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    # Password == VT_DASHBOARD_KEY (hashed compare).
    # In production replace with LDAP / OAuth / SSO lookup.
    if not VT_DASHBOARD_KEY or not hmac.compare_digest(
        hashlib.sha256(password.encode()).hexdigest(),
        hashlib.sha256(VT_DASHBOARD_KEY.encode()).hexdigest(),
    ):
        return RedirectResponse("/login?error=Invalid+credentials", status_code=302)

    # Scope the session from config. Use "*" only for a deliberate super-admin.
    payload = {
        "sub": username,
        "tenant": VT_DASHBOARD_TENANT,
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_TTL_S,
    }
    token = _sign(payload)
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(
        "vt_session", token,
        httponly=True, samesite="lax", secure=VT_DASHBOARD_SECURE_COOKIE,
        max_age=SESSION_TTL_S,
    )
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("vt_session")
    return resp


# ── overview ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def overview(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    try:
        metrics = await _get("/metrics")
    except Exception:
        metrics = {}
    try:
        traces = await _get("/traces", {"limit": 5})
    except Exception:
        traces = []
    items = traces if isinstance(traces, list) else traces.get("items", [])
    return templates.TemplateResponse("overview.html", {
        "request": request,
        "metrics": metrics,
        "recent_traces": _filter_by_tenant(items, ctx),
        "api_url": VT_API_URL,
        "user": ctx.username,
        "tenant": ctx.tenant,
    })


# ── traces ────────────────────────────────────────────────────────────────────

@app.get("/traces", response_class=HTMLResponse)
async def trace_browser(
    request: Request,
    tenant_id: str = "",
    session_id: str = "",
    blocked: str = "",
    limit: int = 50,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    # Enforce tenant scope from JWT
    effective_tenant = tenant_id if ctx.tenant == "*" else ctx.tenant
    params = {"limit": limit}
    if effective_tenant:
        params["tenant_id"] = effective_tenant
    if session_id:
        params["session_id"] = session_id
    if blocked:
        params["blocked"] = blocked
    try:
        data = await _get("/traces", params)
    except Exception as exc:
        data = {"items": [], "error": str(exc)}
    traces = data if isinstance(data, list) else data.get("items", [])
    return templates.TemplateResponse("traces.html", {
        "request": request,
        "traces": _filter_by_tenant(traces, ctx),
        "tenant_id": effective_tenant,
        "session_id": session_id,
        "blocked": blocked,
        "user": ctx.username,
        "tenant": ctx.tenant,
    })


@app.get("/traces/{trace_id}", response_class=HTMLResponse)
async def trace_detail(
    request: Request,
    trace_id: str,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    try:
        trace = await _get(f"/traces/{trace_id}")
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=404, detail="Trace not found")
    # Tenant scope check
    if not ctx.scope(trace.get("tenant_id", "")):
        raise HTTPException(status_code=403, detail="Access denied")
    return templates.TemplateResponse("trace_detail.html", {
        "request": request, "trace": trace, "user": ctx.username,
    })


# ── approvals ─────────────────────────────────────────────────────────────────

@app.get("/approvals", response_class=HTMLResponse)
async def approvals(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    try:
        data = await _get("/hitl/pending")
    except Exception as exc:
        data = {"items": [], "error": str(exc)}
    items = data if isinstance(data, list) else data.get("items", [])
    return templates.TemplateResponse("approvals.html", {
        "request": request,
        "approvals": _filter_by_tenant(items, ctx),
        "user": ctx.username,
    })


@app.post("/approvals/{request_id}/approve", response_class=HTMLResponse)
async def approve(
    request: Request,
    request_id: str,
    ctx: AuthContext = Depends(require_auth),
):
    try:
        await _require_pending_approval_scope(request_id, ctx)
        await _post(f"/hitl/{request_id}/decide", {"approved": True})
        msg, cls = "Approved", "badge-ok"
    except Exception as exc:
        msg, cls = f"Error: {exc}", "badge-block"
    return HTMLResponse(f'<span class="badge {cls}">{msg}</span>')


@app.post("/approvals/{request_id}/deny", response_class=HTMLResponse)
async def deny(
    request: Request,
    request_id: str,
    ctx: AuthContext = Depends(require_auth),
):
    try:
        await _require_pending_approval_scope(request_id, ctx)
        await _post(f"/hitl/{request_id}/decide", {"approved": False})
        msg, cls = "Denied", "badge-block"
    except Exception as exc:
        msg, cls = f"Error: {exc}", "badge-block"
    return HTMLResponse(f'<span class="badge {cls}">{msg}</span>')


# ── metrics ───────────────────────────────────────────────────────────────────

@app.get("/metrics", response_class=HTMLResponse)
async def metrics_page(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    try:
        data = await _get("/metrics")
    except Exception as exc:
        data = {"error": str(exc)}
    return templates.TemplateResponse("metrics.html", {
        "request": request, "metrics": data, "user": ctx.username,
    })


@app.get("/metrics/fragment", response_class=HTMLResponse)
async def metrics_fragment(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
):
    try:
        data = await _get("/metrics")
    except Exception as exc:
        data = {"error": str(exc)}
    return templates.TemplateResponse("metrics_fragment.html", {
        "request": request, "metrics": data,
    })


# ── export ────────────────────────────────────────────────────────────────────

@app.get("/export/traces.csv")
async def export_csv(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    """Export trace list as CSV for compliance."""
    import csv, io
    params: dict = {"limit": 10000}
    if ctx.tenant != "*":
        params["tenant_id"] = ctx.tenant
    try:
        data = await _get("/traces", params)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    traces = data if isinstance(data, list) else data.get("items", [])
    traces = _filter_by_tenant(traces, ctx)

    buf = io.StringIO()
    fieldnames = ["this_hash", "tenant_id", "session_id", "input_text",
                  "output_text", "blocked", "block_reason", "total_latency_ms",
                  "provider", "provider_model", "provider_cost_usd", "hitl_status"]
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for t in traces:
        w.writerow(t)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=veritrace_traces.csv"},
    )
