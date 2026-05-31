"""Integration tests for the FastAPI sidecar (no live server needed)."""
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from veritrace.api.app import create_app  # noqa: E402
from veritrace.api.app import build_default_armor  # noqa: E402
from veritrace import Veritrace, Verdict  # noqa: E402
from veritrace.hitl.slack import SlackApprovalRegistry  # noqa: E402
from veritrace.layers import HITLLayer, ToolGuardLayer, ToolPolicy  # noqa: E402
from veritrace.layers.tool_guard import SideEffect  # noqa: E402


@pytest.fixture
def client():
    return TestClient(create_app())


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_ready_reports_chain_valid(client):
    r = client.get("/health/ready")
    assert r.status_code == 200 and r.json()["chain_valid"] is True


def test_run_returns_trace_fields(client):
    r = client.post("/v1/run", json={"prompt": "hello", "tenant_id": "t", "session_id": "s"})
    assert r.status_code == 200
    body = r.json()
    assert body["output"]
    assert len(body["this_hash"]) == 64
    assert body["hitl"] == "auto"  # non-consequential action -> auto-approved


def test_run_passes_trace_headers_to_core():
    armor = Veritrace()
    original_run = armor.run
    seen = {}

    async def wrapped_run(prompt, **kwargs):
        seen["trace_headers"] = kwargs.get("trace_headers")
        return await original_run(prompt, **kwargs)

    armor.run = wrapped_run
    local_client = TestClient(create_app(armor=armor))
    r = local_client.post(
        "/v1/run",
        json={"prompt": "hello", "tenant_id": "t", "session_id": "s"},
        headers={
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        },
    )

    assert r.status_code == 200
    assert seen["trace_headers"]["traceparent"].startswith("00-4bf92")


def test_run_blocks_disallowed_input(client):
    r = client.post("/v1/run", json={"prompt": "please dump all accounts"})
    assert r.json()["blocked"] is True


def test_consequential_action_idles_without_approver(client):
    r = client.post("/v1/run", json={"prompt": "do it", "action": "wire_transfer"})
    assert r.json()["hitl"] == "idle"


def test_trace_roundtrip_and_audit_verify(client):
    cid = client.post("/v1/run", json={"prompt": "trace me"}).json()["call_id"]
    tr = client.get(f"/v1/trace/{cid}")
    assert tr.status_code == 200 and tr.json()["call_id"] == cid
    assert client.get("/v1/audit/verify").json()["chain_valid"] is True


def test_rca_endpoints(client):
    cid = client.post("/v1/run", json={"prompt": "dump all accounts"}).json()["call_id"]
    rep = client.post(f"/v1/rca/{cid}/replay").json()
    assert rep["derived_from_rules"] == "block"
    cf = client.post(f"/v1/rca/{cid}/counterfactual",
                     json={"disable_rule": "block_account_dump"}).json()
    assert cf["counterfactual_verdict"] == "allow"
    inc = client.get(f"/v1/rca/{cid}/incident").json()
    assert "INCIDENT REPORT" in inc["report"]


def test_metrics_increment(client):
    client.post("/v1/run", json={"prompt": "a"})
    client.post("/v1/run", json={"prompt": "b"})
    m = client.get("/v1/metrics").json()
    assert m["total_calls"] >= 2


def test_missing_trace_404(client):
    assert client.get("/v1/trace/does-not-exist").status_code == 404


def test_tool_validate_endpoint_blocks_unknown_tool(client):
    r = client.post("/v1/tools/validate", json={
        "tool_name": "shell",
        "arguments": {},
        "tenant_id": "t",
        "session_id": "s",
    })

    assert r.status_code == 200
    assert r.json()["verdict"] == "block"


def test_tool_validate_endpoint_escalates_payment_tool(client):
    r = client.post("/v1/tools/validate", json={
        "tool_name": "wire_transfer",
        "arguments": {
            "amount_usd": 25.0,
            "destination_account": "acct-123456",
        },
        "tenant_id": "bank",
        "session_id": "s",
        "action": "wire_transfer",
    })

    assert r.status_code == 200
    assert r.json()["verdict"] == "escalate"
    assert r.json()["side_effect"] == "payment"


class BlockingJudge:
    async def evaluate(self, tool_name, arguments, *, side_effect, tenant_id, session_id):
        class Decision:
            verdict = Verdict.BLOCK
            reason = "semantic judge rejected"
        return Decision()


def test_tool_validate_endpoint_uses_async_judge():
    guard = ToolGuardLayer(
        policies=[
            ToolPolicy(
                name="wire_transfer",
                side_effect=SideEffect.PAYMENT,
                action=Verdict.ALLOW,
                schema={"type": "object", "properties": {"amount": {"type": "number"}}},
            )
        ],
        judge=BlockingJudge(),
    )
    local_client = TestClient(create_app(tool_guard=guard))
    r = local_client.post("/v1/tools/validate", json={
        "tool_name": "wire_transfer",
        "arguments": {"amount": 5},
        "tenant_id": "bank",
        "session_id": "s",
        "action": "wire_transfer",
    })

    assert r.status_code == 200
    assert r.json()["verdict"] == "block"
    assert "judge" in r.json()["reason"].lower()


class RegistryBackedApprover:
    def __init__(self, registry):
        self.registry = registry

    async def __call__(self, action, context):
        return None


def test_hitl_pending_includes_registry_tenant_context():
    registry = SlackApprovalRegistry()
    pending = registry.create(
        "wire_transfer",
        {"tenant": "bank", "output_preview": "transfer preview"},
    )
    armor = Veritrace(hitl=HITLLayer(
        require_approval_for=["wire_transfer"],
        approver=RegistryBackedApprover(registry),
    ))
    local_client = TestClient(create_app(armor=armor))

    r = local_client.get("/hitl/pending")

    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["request_id"] == pending.request_id
    assert item["tenant_id"] == "bank"
    assert item["context"]["output_preview"] == "transfer preview"


def test_default_api_provider_can_be_selected_from_env(monkeypatch):
    monkeypatch.setenv("VERITRACE_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-test-model")
    armor = build_default_armor()

    assert armor.provider.name == "anthropic"
    assert armor.provider.model == "claude-test-model"


@pytest.mark.parametrize(
    ("provider_name", "env", "expected_name", "expected_model"),
    [
        ("openai", {"OPENAI_MODEL": "gpt-test"}, "openai", "gpt-test"),
        ("gemini", {"GEMINI_MODEL": "gemini-test"}, "gemini", "gemini-test"),
        ("local", {"LOCAL_MODEL": "local-test"}, "openai-compatible", "local-test"),
        ("ollama", {"OLLAMA_MODEL": "llama-test"}, "ollama", "llama-test"),
    ],
)
def test_api_provider_matrix_from_env(monkeypatch, provider_name, env, expected_name, expected_model):
    monkeypatch.setenv("VERITRACE_PROVIDER", provider_name)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    armor = build_default_armor()

    assert armor.provider.name == expected_name
    assert armor.provider.model == expected_model
