"""
veritrace.api.app
=================
A thin FastAPI sidecar that exposes the Veritrace pipeline over HTTP. This is
what turns Veritrace from a Python library into a deployable service: any agent,
in any language, can wrap its LLM calls in the full trust stack by calling these
endpoints — no need to embed the library.

Run it:
    pip install -e ".[api]"
    uvicorn veritrace.api.app:app --reload --port 8000
    # or:  python -m veritrace.api.app

Then:
    curl -s localhost:8000/v1/run -H 'content-type: application/json' \\
         -d '{"prompt":"Summarize the notes","tenant_id":"acme","session_id":"s1"}'

Endpoints
    GET  /health                         liveness
    GET  /health/ready                   readiness + audit-chain validity
    POST /v1/run                         run one agent call through the stack
    GET  /v1/trace/{call_id}             fetch the full immutable trace
    GET  /v1/audit/verify                verify the tamper-evident hash chain
    GET  /v1/metrics                     observability snapshot
    POST /v1/rca/{call_id}/replay        deterministic decision replay
    POST /v1/rca/{call_id}/counterfactual  "what if rule X had not fired?"
    GET  /v1/rca/{call_id}/incident      human-readable incident report
    GET  /v1/usage                       tenant quota snapshot
    GET  /v1/usage/ledger                tenant usage ledger evidence
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
import uuid
from urllib.parse import parse_qs
from typing import Optional

from fastapi import Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

log = logging.getLogger("veritrace.api")

from ..auth import APIKeyRegistry, JWTManager, load_registry_from_env
from ..classifier import build_classifier, build_safety_classifier
from ..core import Veritrace
from ..layers import IsolationLayer
from ..hitl.slack import (SlackApprovalError, SlackHITLApprover,
                          verify_slack_signature)
from ..layers import (ComplianceLayer, HITLLayer, ReliabilityLayer, Rule,
                      SafetyLayer, ToolGuardLayer, ToolPolicy)
from ..providers import (AnthropicProvider, GeminiProvider, MockProvider,
                         OllamaProvider, OpenAICompatibleProvider,
                         OpenAIProvider)
from ..ratelimit import TokenBucket
from ..rca import RCAEngine
from ..store import MemoryStore, SQLiteStore
from ..telemetry import configure_otel
from ..types import Verdict
from ..usage import UsageTracker


# ──────────────────────────── request / response ───────────────────────────
class RunRequest(BaseModel):
    prompt: str = Field(..., description="The input to run through the trust stack")
    tenant_id: Optional[str] = Field(
        None,
        description="Tenant id. IGNORED when API-key auth is enabled — the tenant"
                    " is derived from the key. Used only when running unauthenticated.",
    )
    session_id: str = "default"
    action: str = Field("respond", description="Action label; consequential ones gate on HITL")


class RunResponse(BaseModel):
    call_id: str
    output: str
    blocked: bool
    block_reason: str
    hitl: str
    pre_verdict: Optional[str]
    post_verdict: Optional[str]
    pii_redactions: list[str]
    provider: str
    provider_model: str
    used_fallback: bool
    this_hash: str
    prev_hash: str
    total_latency_ms: float


class CounterfactualRequest(BaseModel):
    disable_rule: str = Field(..., description="rule_id to disable in the recomputation")


class ToolValidateRequest(BaseModel):
    tool_name: str
    arguments: dict
    tenant_id: Optional[str] = Field(
        None,
        description="Ignored when API-key/JWT auth is enabled.",
    )
    session_id: str = "default"
    action: str = "tool_call"


class ToolValidateResponse(BaseModel):
    decision_id: str
    tool_name: str
    verdict: str
    reason: str
    side_effect: str
    tenant_id: str
    session_id: str
    action_label: str


class TokenRequest(BaseModel):
    api_key: str = Field(..., description="Bootstrap API key")
    ttl_s: int = Field(900, ge=60, le=3600, description="JWT lifetime in seconds")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    tenant_id: str


# ─────────────────────────── default configuration ─────────────────────────
def build_default_armor() -> Veritrace:
    """Build from env. Set VERITRACE_DB=path.db for persistent traces; unset for in-memory."""
    db_path = os.environ.get("VERITRACE_DB")
    if db_path:
        db = SQLiteStore(db_path)
        store, audit = db, db          # single object handles both
    else:
        store, audit = None, None       # Veritrace defaults to MemoryStore + HashChainBackend

    slack_approver = build_slack_approver_from_env()
    hitl_timeout = float(os.environ.get("VERITRACE_HITL_TIMEOUT_S", "2.0"))

    provider_name = os.environ.get("VERITRACE_PROVIDER", "mock").lower()
    if provider_name == "anthropic":
        provider = AnthropicProvider(
            model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
            max_tokens=int(os.environ.get("ANTHROPIC_MAX_TOKENS", "1024")),
        )
    elif provider_name == "openai":
        provider = OpenAIProvider(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            max_tokens=int(os.environ.get("OPENAI_MAX_TOKENS", "1024")),
        )
    elif provider_name in {"openai-compatible", "local", "vllm", "lmstudio"}:
        provider = OpenAICompatibleProvider(
            model=os.environ.get("OPENAI_COMPAT_MODEL", os.environ.get("LOCAL_MODEL", "local-model")),
            base_url=os.environ.get("OPENAI_COMPAT_BASE_URL", os.environ.get("LOCAL_LLM_BASE_URL", "http://localhost:8001/v1")),
            api_key=os.environ.get("OPENAI_COMPAT_API_KEY", os.environ.get("LOCAL_LLM_API_KEY", "")) or None,
            max_tokens=int(os.environ.get("OPENAI_COMPAT_MAX_TOKENS", "1024")),
        )
    elif provider_name == "gemini":
        provider = GeminiProvider(
            model=os.environ.get("GEMINI_MODEL", "gemini-1.5-flash"),
            max_tokens=int(os.environ.get("GEMINI_MAX_TOKENS", "1024")),
        )
    elif provider_name == "ollama":
        provider = OllamaProvider(
            model=os.environ.get("OLLAMA_MODEL", "llama3.2:1b"),
            host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        )
    else:
        provider = MockProvider(model="api-demo")

    # Default prompt-injection defense: embedding classifier when
    # sentence-transformers is installed, else graceful keyword fallback.
    # Wired into BOTH IsolationLayer (input scoping) and SafetyLayer (verdicts).
    kw_only = os.environ.get("VERITRACE_CLASSIFIER", "auto").lower() == "keyword"
    iso_clf = build_classifier(force_keyword_only=kw_only)
    safety_clf = build_safety_classifier(force_keyword_only=kw_only)

    return Veritrace(
        provider=provider,
        isolation=IsolationLayer(classifier=iso_clf, block_on_injection=True),
        compliance=ComplianceLayer(standards=["HIPAA", "PCI_DSS", "GDPR"]),
        safety=SafetyLayer(rules=[
            Rule("block_account_dump", Verdict.BLOCK, pattern=r"dump .*accounts?"),
            Rule("escalate_transfer", Verdict.ESCALATE, pattern=r"transfer \$?\d+"),
        ], classifier=safety_clf),
        reliability=ReliabilityLayer(max_concurrent=20, timeout_s=15.0),
        hitl=HITLLayer(
            require_approval_for=["wire_transfer", "delete_data"],
            timeout_s=hitl_timeout,
            approver=slack_approver,
        ),
        audit=audit,
        store=store,
    )


def build_slack_approver_from_env() -> Optional[SlackHITLApprover]:
    """Return a Slack approver only when all required Slack env vars are set."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL_ID")
    secret = os.environ.get("SLACK_SIGNING_SECRET")
    public_url = os.environ.get("VERITRACE_PUBLIC_URL")
    if not all([token, channel, secret, public_url]):
        return None
    return SlackHITLApprover(
        bot_token=token,
        channel_id=channel,
        signing_secret=secret,
        public_url=public_url,
    )


def build_default_tool_guard() -> ToolGuardLayer:
    """Demo-safe policies. Real deployments should register their own tools."""
    return ToolGuardLayer(policies=[
        ToolPolicy(
            name="read_record",
            side_effect="read",
            action=Verdict.ALLOW,
            schema={
                "type": "object",
                "required": ["record_id"],
                "additionalProperties": False,
                "properties": {
                    "record_id": {"type": "string", "maxLength": 128},
                },
            },
            detail="read-only lookup allowed",
        ),
        ToolPolicy(
            name="wire_transfer",
            side_effect="payment",
            action=Verdict.ESCALATE,
            allowed_actions={"wire_transfer"},
            schema={
                "type": "object",
                "required": ["amount_usd", "destination_account"],
                "additionalProperties": False,
                "properties": {
                    "amount_usd": {"type": "number", "minimum": 0.01, "maximum": 10000},
                    "destination_account": {
                        "type": "string",
                        "pattern": r"acct[-_ ][0-9]{6,18}",
                    },
                },
            },
            detail="payment tools require human approval",
        ),
    ])


# ───────────────────────────────── app factory ─────────────────────────────
def create_app(armor: Optional[Veritrace] = None,
               registry: Optional[APIKeyRegistry] = None,
               tool_guard: Optional[ToolGuardLayer] = None,
               usage_tracker: Optional[UsageTracker] = None):
    """Build the FastAPI app.

    Auth behavior:
      * If `registry` is non-empty (or VERITRACE_API_KEYS env var is set),
        every /v1 endpoint requires `Authorization: Bearer <key>`. The tenant
        is taken from the key — request bodies that assert a different tenant
        are rejected.
      * If the registry is empty, the API runs unauthenticated and the tenant
        is read from the request body (single-tenant or trusted-network mode).
    """
    from fastapi import Depends, FastAPI, Header, HTTPException

    app = FastAPI(
        title="Veritrace",
        version="0.4.2",
        description="Trust middleware for AI agents: deterministic guardrails, HITL, tool policy, tamper-evident traces.",
    )
    if os.environ.get("VT_OTEL_ENDPOINT") or os.environ.get("VT_OTEL_CONSOLE") == "1":
        configure_otel(
            service_name=os.environ.get("VT_OTEL_SERVICE_NAME", "veritrace-api"),
            endpoint=os.environ.get("VT_OTEL_ENDPOINT") or None,
        )

    # ── CORS ──────────────────────────────────────────────────────────────
    allowed_origins = [
        o.strip()
        for o in os.environ.get("VERITRACE_CORS_ORIGINS", "").split(",")
        if o.strip()
    ] or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
        expose_headers=["X-Request-Id", "Retry-After"],
    )

    # ── Security headers + structured request logging ─────────────────────
    @app.middleware("http")
    async def security_and_logging(request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        t0 = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception as exc:
            log.error("unhandled exception request_id=%s path=%s error=%r",
                      request_id, request.url.path, exc)
            raise
        latency_ms = (time.perf_counter() - t0) * 1000
        log.info(
            "request_id=%s method=%s path=%s status=%s latency_ms=%.1f",
            request_id, request.method, request.url.path,
            response.status_code, latency_ms,
        )
        # Security headers
        response.headers["X-Request-Id"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response

    app.state.armor = armor or build_default_armor()
    app.state.registry = registry if registry is not None else load_registry_from_env()
    app.state.slack_hitl = getattr(app.state.armor.hitl, "approver", None)
    app.state.tool_guard = tool_guard or build_default_tool_guard()
    app.state.usage = usage_tracker or UsageTracker.from_env()
    app.state.jwt = JWTManager(
        os.environ.get("VERITRACE_JWT_SECRET") or secrets.token_urlsafe(32)
    )
    # Rate limit: capacity tokens per key, refill rate per second.
    # Defaults: 60 requests burst, 1 req/sec sustained per tenant/IP.
    app.state.bucket = TokenBucket(
        capacity=int(os.environ.get("VERITRACE_RATE_BURST", "60")),
        refill_per_sec=float(os.environ.get("VERITRACE_RATE_PER_SEC", "1.0")),
    )
    # Tighter rate limit on expensive RCA endpoints (replay, counterfactual)
    app.state.rca_bucket = TokenBucket(
        capacity=int(os.environ.get("VERITRACE_RCA_RATE_BURST", "10")),
        refill_per_sec=float(os.environ.get("VERITRACE_RCA_RATE_PER_SEC", "0.2")),
    )

    def require_tenant(request: Request = None,
                       authorization: Optional[str] = Header(None)) -> str:
        """Resolve the tenant for this request and apply rate limiting.

        Rate-limit key: tenant when authenticated, client IP otherwise. This
        prevents one tenant (or one IP) from starving the others, and gives the
        unauthenticated mode a basic DoS floor."""
        if len(app.state.registry) == 0:
            tenant = ""
            rate_key = (request.client.host if request and request.client else "anon")
        else:
            if not authorization or not authorization.lower().startswith("bearer "):
                raise HTTPException(status_code=401, detail="missing bearer token")
            bearer = authorization.split(None, 1)[1].strip()
            tenant = app.state.registry.tenant_for_key(bearer)
            if tenant is None:
                tenant = app.state.jwt.tenant_for_token(bearer)
            if tenant is None:
                raise HTTPException(status_code=401, detail="invalid bearer token")
            rate_key = f"tenant:{tenant}"

        allowed, retry_after = app.state.bucket.allow(rate_key)
        if not allowed:
            raise HTTPException(
                status_code=429, detail="rate limit exceeded",
                headers={"Retry-After": str(int(retry_after) + 1)})
        return tenant

    def _fetch_trace(call_id: str, tenant: str):
        """Fetch a trace, enforcing tenant ownership when auth is enabled."""
        tenant_filter = tenant if tenant else None
        try:
            return app.state.armor.store.get(call_id, tenant_id=tenant_filter)
        except KeyError:
            raise HTTPException(status_code=404, detail="trace not found")
        except PermissionError:
            # do not leak existence to other tenants — return 404 not 403
            raise HTTPException(status_code=404, detail="trace not found")

    def _raise_quota(decision):
        retry_after = int(decision.retry_after_s) + 1 if decision.retry_after_s else 1
        raise HTTPException(
            status_code=429,
            detail=decision.reason or "tenant usage quota exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    def _usage_ledger_limit(limit: int) -> int:
        return max(1, min(int(limit), 500))

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/v1/auth/token", response_model=TokenResponse)
    async def issue_token(body: TokenRequest):
        if len(app.state.registry) == 0:
            raise HTTPException(status_code=400, detail="API-key auth is not enabled")
        tenant = app.state.registry.tenant_for_key(body.api_key)
        if tenant is None:
            raise HTTPException(status_code=401, detail="invalid api key")
        token = app.state.jwt.issue(tenant, ttl_s=body.ttl_s)
        return TokenResponse(
            access_token=token,
            expires_in=body.ttl_s,
            tenant_id=tenant,
        )

    @app.get("/health/ready")
    async def ready():
        a = app.state.armor
        slack = app.state.slack_hitl
        return {
            "status": "ready",
            "chain_valid": a.audit.verify_chain(),
            "traces": len(a.store.list_all()),
            "auth_enabled": len(app.state.registry) > 0,
            "jwt_enabled": len(app.state.registry) > 0,
            "slack_hitl_configured": isinstance(slack, SlackHITLApprover),
            "slack_last_error": getattr(slack, "last_error", "") if slack else "",
            "usage_quota_enabled": app.state.usage.enabled,
            "usage_event_sinks": len(getattr(app.state.usage, "event_sinks", [])),
        }

    @app.post("/v1/run", response_model=RunResponse)
    async def run(req: RunRequest, request: Request,
                  tenant: str = Depends(require_tenant)):
        a = app.state.armor
        # When auth is on, the tenant comes from the key — ignore any body assertion.
        # When auth is off, fall back to body or "default".
        effective_tenant = tenant if tenant else (req.tenant_id or "default")
        quota_decision = app.state.usage.reserve_call(effective_tenant)
        if not quota_decision.allowed:
            _raise_quota(quota_decision)
        r = await a.run(req.prompt, tenant_id=effective_tenant,
                        session_id=req.session_id, action=req.action,
                        trace_headers=dict(request.headers))
        t = r.trace
        app.state.usage.record_cost(effective_tenant, t.provider_cost_usd)
        return RunResponse(
            call_id=t.call_id, output=r.output, blocked=r.blocked,
            block_reason=r.block_reason, hitl=r.hitl,
            pre_verdict=t.pre_verdict, post_verdict=t.post_verdict,
            pii_redactions=t.pii_redactions, provider=t.provider,
            provider_model=t.provider_model, used_fallback=t.used_fallback,
            this_hash=t.this_hash, prev_hash=t.prev_hash,
            total_latency_ms=t.total_latency_ms,
        )

    @app.get("/v1/trace/{call_id}")
    async def get_trace(call_id: str, tenant: str = Depends(require_tenant)):
        return _fetch_trace(call_id, tenant).to_dict()

    @app.get("/v1/audit/verify")
    async def verify_audit(tenant: str = Depends(require_tenant)):
        a = app.state.armor
        return {"chain_valid": a.audit.verify_chain(),
                "records": len(a.audit.records())}

    @app.get("/v1/metrics")
    async def metrics(tenant: str = Depends(require_tenant)):
        report = app.state.armor.observability.report()
        report["usage_quota_enabled"] = app.state.usage.enabled
        report["usage_event_sinks"] = len(getattr(app.state.usage, "event_sinks", []))
        return report

    @app.get("/v1/usage")
    async def usage(tenant_id: str = "",
                    tenant: str = Depends(require_tenant)):
        effective_tenant = tenant if tenant else (tenant_id or "default")
        return app.state.usage.snapshot(effective_tenant).to_dict()

    @app.get("/v1/usage/ledger")
    async def usage_ledger(tenant_id: str = "",
                           limit: int = 100,
                           tenant: str = Depends(require_tenant)):
        effective_tenant = tenant if tenant else (tenant_id or "default")
        return app.state.usage.ledger_report(
            tenant_id=effective_tenant,
            limit=_usage_ledger_limit(limit),
        )

    @app.post("/v1/tools/validate", response_model=ToolValidateResponse)
    async def validate_tool(req: ToolValidateRequest,
                            tenant: str = Depends(require_tenant)):
        effective_tenant = tenant if tenant else (req.tenant_id or "default")
        quota_decision = app.state.usage.reserve_tool_validation(effective_tenant)
        if not quota_decision.allowed:
            _raise_quota(quota_decision)
        decision = await app.state.tool_guard.evaluate_async(
            req.tool_name,
            req.arguments,
            tenant_id=effective_tenant,
            session_id=req.session_id,
            action_label=req.action,
        )
        return ToolValidateResponse(**decision.to_dict())

    @app.post("/v1/hitl/slack/action")
    async def slack_hitl_action(request: Request):
        """Receive Slack approve/deny button callbacks.

        This endpoint is authenticated with Slack's signing secret, not a
        Veritrace tenant API key, because Slack posts callbacks directly.
        """
        approver = app.state.slack_hitl
        if not isinstance(approver, SlackHITLApprover):
            raise HTTPException(status_code=404, detail="Slack HITL is not configured")

        raw = await request.body()
        if not verify_slack_signature(
            signing_secret=approver.signing_secret,
            timestamp=request.headers.get("X-Slack-Request-Timestamp", ""),
            body=raw,
            signature=request.headers.get("X-Slack-Signature", ""),
        ):
            raise HTTPException(status_code=401, detail="invalid Slack signature")

        form = parse_qs(raw.decode("utf-8"))
        payload_raw = (form.get("payload") or [""])[0]
        try:
            payload = json.loads(payload_raw)
            found, decision = approver.handle_action_payload(payload)
        except (json.JSONDecodeError, SlackApprovalError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        if not found:
            return {"text": "This Veritrace approval request has expired."}
        return {"text": f"Veritrace request {decision}."}


    @app.post("/v1/rca/{call_id}/replay")
    async def rca_replay(call_id: str, request: Request,
                         tenant: str = Depends(require_tenant)):
        _require_rca_quota(tenant or "anon", request)
        _fetch_trace(call_id, tenant)  # enforce tenant ownership (404 if cross-tenant)
        engine = RCAEngine(app.state.armor.store.list_all())
        return engine.replay(call_id)

    @app.post("/v1/rca/{call_id}/counterfactual")
    async def rca_counterfactual(call_id: str, body: CounterfactualRequest,
                                 request: Request,
                                 tenant: str = Depends(require_tenant)):
        _require_rca_quota(tenant or "anon", request)
        _fetch_trace(call_id, tenant)
        engine = RCAEngine(app.state.armor.store.list_all())
        return engine.counterfactual(call_id, disable_rule=body.disable_rule)

    @app.get("/v1/rca/{call_id}/incident")
    async def rca_incident(call_id: str, request: Request,
                           tenant: str = Depends(require_tenant)):
        _require_rca_quota(tenant or "anon", request)
        _fetch_trace(call_id, tenant)
        engine = RCAEngine(app.state.armor.store.list_all())
        return {"report": engine.incident_report(call_id)}

    @app.post("/v1/retention/prune")
    async def retention_prune(older_than_days: int,
                              tenant: str = Depends(require_tenant)):
        """Prune traces older than `older_than_days`.

        Enforces the EU AI Act Article 12 floor: a retention window shorter than
        180 days is rejected (400) so audit logs are never pruned below the legal
        minimum. When auth is enabled the prune is scoped to the caller's tenant,
        so a tenant can only prune its own records.
        """
        MIN_RETENTION_DAYS = 180
        if older_than_days < MIN_RETENTION_DAYS:
            raise HTTPException(
                status_code=400,
                detail=(f"retention window of {older_than_days} days is below the "
                        f"{MIN_RETENTION_DAYS}-day minimum required for audit logs"),
            )
        cutoff_ts = time.time() - older_than_days * 86400
        store = app.state.armor.store
        scope_tenant = tenant or None
        try:
            deleted = store.prune_older_than(cutoff_ts, tenant_id=scope_tenant)
        except TypeError:
            # store predates tenant-scoped prune
            deleted = store.prune_older_than(cutoff_ts)
        return {"pruned": deleted, "older_than_days": older_than_days,
                "tenant_id": scope_tenant or "*"}

    @app.delete("/v1/tenant/{tenant_id}/traces")
    async def erase_tenant_traces(tenant_id: str,
                                  tenant: str = Depends(require_tenant)):
        """GDPR right-to-erasure: delete all traces for `tenant_id`.

        A tenant may only erase its OWN data. When auth is enabled, attempting to
        erase another tenant's data is forbidden (403). The tamper-evident audit
        hash chain is intentionally left intact — only the trace store rows are
        removed, so chain verification still succeeds.
        """
        if tenant and tenant != tenant_id:
            raise HTTPException(
                status_code=403,
                detail="a tenant may only erase its own data",
            )
        deleted = app.state.armor.store.delete_for_tenant(tenant_id)
        return {"deleted": deleted, "tenant_id": tenant_id}

    # ── dashboard-friendly routes (no auth prefix, used by admin UI) ──────────
    @app.get("/health")
    async def health_unversioned():
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics_unversioned():
        """Dashboard-friendly metrics endpoint (no auth required for internal use)."""
        report = app.state.armor.observability.report()
        report["usage_quota_enabled"] = app.state.usage.enabled
        report["usage_event_sinks"] = len(getattr(app.state.usage, "event_sinks", []))
        return report

    @app.get("/usage")
    async def usage_unversioned(tenant_id: str = "default"):
        return app.state.usage.snapshot(tenant_id).to_dict()

    @app.get("/usage/ledger")
    async def usage_ledger_unversioned(tenant_id: str = "", limit: int = 100):
        return app.state.usage.ledger_report(
            tenant_id=tenant_id,
            limit=_usage_ledger_limit(limit),
        )

    @app.get("/traces")
    async def traces_list(
        tenant_id: str = "",
        session_id: str = "",
        blocked: str = "",
        limit: int = 50,
    ):
        """Return recent traces. Dashboard uses this for the trace browser."""
        store = app.state.armor.store
        items = []
        if hasattr(store, "list_all"):
            items = store.list_all(limit=limit)
        elif hasattr(store, "_traces"):
            # MemoryStore: return sorted by recency
            all_traces = list(store._traces.values())
            all_traces.sort(key=lambda t: getattr(t, "total_latency_ms", 0), reverse=False)
            items = [t.to_dict() if hasattr(t, "to_dict") else vars(t) for t in all_traces[-limit:]]
        # filters
        if tenant_id:
            items = [t for t in items if t.get("tenant_id") == tenant_id]
        if session_id:
            items = [t for t in items if t.get("session_id") == session_id]
        if blocked == "true":
            items = [t for t in items if t.get("blocked")]
        elif blocked == "false":
            items = [t for t in items if not t.get("blocked")]
        return items[-limit:]

    @app.get("/traces/{trace_id}")
    async def trace_detail_unversioned(trace_id: str):
        store = app.state.armor.store
        try:
            result = store.get(trace_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="trace not found")
        if result is None:
            raise HTTPException(status_code=404, detail="trace not found")
        return result.to_dict() if hasattr(result, "to_dict") else vars(result)

    @app.get("/hitl/pending")
    async def hitl_pending():
        hitl = app.state.armor.hitl
        pending = []
        seen = set()

        registry = getattr(hitl, "registry", None) or getattr(
            getattr(hitl, "approver", None), "registry", None)
        registry_pending = getattr(registry, "_pending", {}) if registry is not None else {}
        for request_id, request in registry_pending.items():
            context = dict(getattr(request, "context", {}) or {})
            tenant_id = context.get("tenant_id") or context.get("tenant") or ""
            pending.append({
                "request_id": request_id,
                "action": getattr(request, "action", ""),
                "tenant_id": tenant_id,
                "context": context,
                "created_at": getattr(request, "created_at", None),
            })
            seen.add(request_id)

        if hasattr(hitl, "_pending"):
            for request_id, action in hitl._pending.items():
                if request_id in seen:
                    continue
                pending.append({
                    "request_id": request_id,
                    "action": action,
                    "tenant_id": "",
                    "context": {},
                })
        return {"items": pending}

    @app.post("/hitl/{request_id}/decide")
    async def hitl_decide(request_id: str, body: dict):
        approved = body.get("approved", False)
        hitl = app.state.armor.hitl
        registry = getattr(hitl, "registry", None) or getattr(
            getattr(hitl, "approver", None), "registry", None)
        if registry is not None:
            registry.decide(request_id, approved)
        return {"request_id": request_id, "decision": "approved" if approved else "denied"}

    def _require_rca_quota(tenant: str, request: Request) -> None:
        allowed, retry_after = request.app.state.rca_bucket.allow(tenant)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"RCA rate limit exceeded; retry after {retry_after:.1f}s",
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

    return app


# Module-level ASGI app: uvicorn veritrace.api.app:app
app = create_app()
