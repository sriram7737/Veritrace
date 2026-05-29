"""Integration tests for the FastAPI sidecar (no live server needed)."""
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from veritrace.api.app import create_app  # noqa: E402
from veritrace.api.app import build_default_armor  # noqa: E402


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
