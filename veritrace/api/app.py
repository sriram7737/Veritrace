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
"""
from __future__ import annotations

import json
import os
import secrets
from urllib.parse import parse_qs
from typing import Optional

from fastapi import Request
from pydantic import BaseModel, Field

from ..auth import APIKeyRegistry, JWTManager, load_registry_from_env
from ..core import Veritrace
from ..hitl.slack import (SlackApprovalError, SlackHITLApprover,
                          verify_slack_signature)
from ..layers import (ComplianceLayer, HITLLayer, ReliabilityLayer, Rule,
                      SafetyLayer)
from ..providers import (AnthropicProvider, GeminiProvider, MockProvider,
                         OllamaProvider, OpenAICompatibleProvider,
                         OpenAIProvider)
from ..ratelimit import TokenBucket
from ..rca import RCAEngine
from ..store import MemoryStore, SQLiteStore
from ..types import Verdict


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

    return Veritrace(
        provider=provider,
        compliance=ComplianceLayer(standards=["HIPAA", "PCI_DSS", "GDPR"]),
        safety=SafetyLayer(rules=[
            Rule("block_account_dump", Verdict.BLOCK, pattern=r"dump .*accounts?"),
            Rule("escalate_transfer", Verdict.ESCALATE, pattern=r"transfer \$?\d+"),
        ]),
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


# ───────────────────────────────── app factory ─────────────────────────────
def create_app(armor: Optional[Veritrace] = None,
               registry: Optional[APIKeyRegistry] = None):
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
        version="0.1.0",
        description="Verifiable trust infrastructure for production AI agents.",
    )
    app.state.armor = armor or build_default_armor()
    app.state.registry = registry if registry is not None else load_registry_from_env()
    app.state.slack_hitl = getattr(app.state.armor.hitl, "approver", None)
    app.state.jwt = JWTManager(
        os.environ.get("VERITRACE_JWT_SECRET") or secrets.token_urlsafe(32)
    )
    # Rate limit: capacity tokens per key, refill rate per second.
    # Defaults: 60 requests burst, 1 req/sec sustained per tenant/IP.
    app.state.bucket = TokenBucket(
        capacity=int(os.environ.get("VERITRACE_RATE_BURST", "60")),
        refill_per_sec=float(os.environ.get("VERITRACE_RATE_PER_SEC", "1.0")),
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
        }

    @app.post("/v1/run", response_model=RunResponse)
    async def run(req: RunRequest, tenant: str = Depends(require_tenant)):
        a = app.state.armor
        # When auth is on, the tenant comes from the key — ignore any body assertion.
        # When auth is off, fall back to body or "default".
        effective_tenant = tenant if tenant else (req.tenant_id or "default")
        r = await a.run(req.prompt, tenant_id=effective_tenant,
                        session_id=req.session_id, action=req.action)
        t = r.trace
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
        return app.state.armor.observability.report()

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
    async def rca_replay(call_id: str, tenant: str = Depends(require_tenant)):
        _fetch_trace(call_id, tenant)  # 404 if missing or wrong tenant
        return RCAEngine(app.state.armor.store.list_all()).replay(call_id)

    @app.post("/v1/rca/{call_id}/counterfactual")
    async def rca_counterfactual(call_id: str, body: CounterfactualRequest,
                                 tenant: str = Depends(require_tenant)):
        _fetch_trace(call_id, tenant)
        return RCAEngine(app.state.armor.store.list_all()).counterfactual(
            call_id, disable_rule=body.disable_rule)

    @app.get("/v1/rca/{call_id}/incident")
    async def rca_incident(call_id: str, tenant: str = Depends(require_tenant)):
        _fetch_trace(call_id, tenant)
        return {"report": RCAEngine(app.state.armor.store.list_all()).incident_report(call_id)}

    # ── retention / GDPR erasure ────────────────────────────────────────
    @app.post("/v1/retention/prune")
    async def prune(older_than_days: int = 180,
                    tenant: str = Depends(require_tenant)):
        """Delete traces older than `older_than_days` (default 180 = ~6 months,
        the EU AI Act Article 12 minimum). Respect the minimum: never accept a
        value below 180."""
        if older_than_days < 180:
            raise HTTPException(
                status_code=400,
                detail="retention minimum is 180 days (EU AI Act Article 12)")
        import time
        cutoff = time.time() - older_than_days * 86400
        deleted = app.state.armor.store.prune_older_than(cutoff)
        return {"deleted": deleted, "cutoff_ts": cutoff}

    @app.delete("/v1/tenant/{tenant_id}/traces")
    async def erase_tenant(tenant_id: str,
                           tenant: str = Depends(require_tenant)):
        """GDPR right-to-erasure. With auth enabled, callers may only erase
        their own tenant's data."""
        if tenant and tenant != tenant_id:
            raise HTTPException(status_code=403, detail="cannot erase another tenant")
        deleted = app.state.armor.store.delete_for_tenant(tenant_id)
        return {"deleted": deleted, "tenant_id": tenant_id,
                "note": "audit chain payloads retained for integrity; trace records erased"}

    return app


# module-level app for `uvicorn veritrace.api.app:app`
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
