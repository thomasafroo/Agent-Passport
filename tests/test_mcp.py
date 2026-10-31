import json

from fastapi.testclient import TestClient
import pytest

from agent_passport.mcp_server import Adapter, build
from agent_passport.server import create_app


class InProcessGateway:
    """The adapter's HTTP calls, served by the real app without a socket."""
    def __init__(self, client):
        self.client = client

    def call(self, method, path, token, body=None, proof=None):
        headers = {"Authorization": f"Bearer {token}"}
        if proof:
            headers["X-Passport-Proof"] = proof
        response = self.client.request(method, path, json=body, headers=headers)
        return response.status_code, response.json()


@pytest.fixture
def live(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    client = TestClient(create_app(tmp_path))
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    adapter = Adapter(InProcessGateway(client), tmp_path / "live-agent.token")
    adapter.register()
    issued = client.post("/api/live/issue", headers=console)
    assert issued.status_code == 200
    return client, console, adapter, issued


def tokens_in(client):
    passport = client.app.state.passport
    db = passport.connect()
    try:
        return [passport._token(g) for g in db.execute("SELECT * FROM grants")]
    finally:
        db.close()


def test_issue_writes_token_file_but_never_returns_it(live, tmp_path):
    client, console, adapter, issued = live
    token = (tmp_path / "live-agent.token").read_text()
    assert token and token not in issued.text
    assert token not in client.get("/api/state", headers=console).text
    live_grant = [g for g in issued.json()["grants"] if g["subject"] == "Claude (live)"]
    assert len(live_grant) == 1 and issued.json()["live_grant"] == live_grant[0]["id"]
    assert client.post("/api/live/issue", headers=console).json()["rule"] == "LIVE_AGENT_ACTIVE"
    assert client.post("/api/live/issue").status_code == 403


def test_allowed_operation_spends_shared_budget_and_returns_untrusted_data(live):
    client, console, adapter, _ = live
    before = adapter.passport()["shared_budget"]["spent"]
    result = adapter.operate("staging/checkout", "logs.read")
    assert result["allowed"] and result["state"] == "completed" and result["receipt_signed_by_gateway"]
    assert any("deploy.execute" in line for line in result["result"]["lines"])
    assert adapter.passport()["shared_budget"]["spent"] == before + 1


def test_injected_production_deploy_is_denied_and_recorded(live):
    client, console, adapter, issued = live
    result = adapter.operate("production/checkout", "deploy.execute")
    assert result == {"allowed": False, "rule": "RESOURCE_ACTION_DENIED", "detail": result["detail"]}
    events = client.get("/api/state", headers=console).json()["events"]
    assert any(e["kind"] == "denied" and e["grant_id"] == issued.json()["live_grant"] and e.get("action") == "deploy.execute" for e in events)


def test_delegation_narrows_and_escalation_is_denied(live):
    client, console, adapter, _ = live
    worker = adapter.delegate("Log helper", [{"resource": "staging/checkout", "action": "logs.read"}])
    assert worker["delegated"] and worker["permitted_operations"] == [{"resource": "staging/checkout", "action": "logs.read"}]
    assert adapter.operate("repo/checkout", "code.read", worker="Log helper")["rule"] == "RESOURCE_ACTION_DENIED"
    escalation = adapter.delegate("Admin", [{"resource": "production/checkout", "action": "deploy.execute"}], parent="Log helper")
    assert escalation["allowed"] is False and escalation["rule"] == "SCOPE_ESCALATION"
    assert "Admin" not in adapter.workers


def test_tool_outputs_never_contain_passport_tokens(live):
    client, console, adapter, _ = live
    outputs = [adapter.passport(), adapter.operate("staging/checkout", "logs.read"),
               adapter.delegate("Reader", [{"resource": "repo/checkout", "action": "code.read"}]),
               adapter.passport(worker="Reader"), adapter.operate("repo/checkout", "code.read", worker="Reader"),
               adapter.operate("production/checkout", "deploy.execute", worker="Reader")]
    text = json.dumps(outputs)
    for token in tokens_in(client):
        assert token not in text and token.split(".")[1] not in text


def test_revocation_from_console_stops_the_live_agent_and_its_workers(live):
    client, console, adapter, issued = live
    adapter.delegate("Reader", [{"resource": "repo/checkout", "action": "code.read"}])
    assert client.post(f"/api/grants/{issued.json()['live_grant']}/revoke", headers=console).status_code == 200
    assert adapter.operate("staging/checkout", "logs.read")["rule"] == "ANCESTOR_REVOKED"
    assert adapter.operate("repo/checkout", "code.read", worker="Reader")["rule"] == "ANCESTOR_REVOKED"
    assert adapter.passport()["status"] == "ANCESTOR_REVOKED"


def test_reset_revokes_live_agent_and_withdraws_its_token(live, tmp_path):
    client, console, adapter, issued = live
    old_token = (tmp_path / "live-agent.token").read_text()
    adapter.delegate("Reader", [{"resource": "repo/checkout", "action": "code.read"}])
    client.post("/api/demo/reset", headers=console)
    assert not (tmp_path / "live-agent.token").exists()
    with pytest.raises(Exception, match="No live agent passport"):
        adapter.operate("repo/checkout", "code.read", worker="Reader")
    assert adapter.workers == {}
    body = {"resource": "staging/checkout", "action": "logs.read", "request_key": "x"}
    proof = adapter.holder.proof(old_token, "execute", body)
    assert client.post("/api/agent/execute", json=body, headers={"Authorization": f"Bearer {old_token}",
                       "X-Passport-Proof": proof}).json()["rule"] == "ANCESTOR_REVOKED"


def test_agent_cannot_issue_itself_a_live_passport_with_a_bearer_token(live, tmp_path):
    client, console, adapter, _ = live
    token = (tmp_path / "live-agent.token").read_text()
    assert client.post("/api/live/issue", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    assert client.post("/api/demo/reset", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_mcp_server_exposes_only_three_tools(live):
    import asyncio
    _, _, adapter, _ = live
    names = sorted(t.name for t in asyncio.run(build(adapter).list_tools()))
    assert names == ["delegate_worker", "my_passport", "perform_operation"]


def test_adapter_can_wait_for_a_passport_issued_after_it_starts(tmp_path, monkeypatch):
    import threading
    import time
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    client = TestClient(create_app(tmp_path))
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    impatient = Adapter(InProcessGateway(client), tmp_path / "live-agent.token")
    with pytest.raises(Exception, match="No live agent passport"):
        impatient.passport()
    adapter = Adapter(InProcessGateway(client), tmp_path / "live-agent.token", wait_for_passport=10)
    adapter.register()
    issuer = threading.Timer(0.5, lambda: client.post("/api/live/issue", headers=console))
    issuer.start()
    started = time.monotonic()
    assert adapter.operate("staging/checkout", "logs.read")["state"] == "completed"
    assert time.monotonic() - started >= 0.4
    issuer.join()
