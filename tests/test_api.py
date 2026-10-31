import hashlib
import subprocess
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from agent_passport.server import create_app
from agent_passport.broker import OnePasswordCredentials, CredentialUnavailable


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    return TestClient(create_app(tmp_path))


def headers(client):
    return {"x-passport-console": client.get("/api/session").json()["console_token"]}


def test_console_requires_session_and_agent_cannot_revoke(client):
    assert client.post("/api/demo/step").status_code == 403
    root = client.app.state.passport.create_run()
    assert client.post(f"/api/grants/{root['grant']['id']}/revoke", headers={"Authorization": f"Bearer {root['token']}"}).status_code == 403
    assert client.get("/api/state", headers=headers(client)).status_code == 200


def test_foreign_origin_and_dns_rebinding_rejected(client):
    assert client.get("/api/session", headers={"Origin":"https://attacker.example"}).status_code == 403
    assert client.get("/api/session", headers={"Host":"attacker.example"}).status_code == 400


def test_actual_chunked_request_size_is_bounded(client):
    body = (b"x" * 10000 for _ in range(2))
    response = client.post("/api/agent/execute", content=body, headers={"Content-Type":"application/json"})
    assert response.status_code == 413


def test_page_and_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Agents can multiply" in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/assets/app.js").status_code == 200


def test_agent_api_checks_identity_schema_and_scopes(client):
    body = {"resource":"staging/checkout", "action":"logs.read", "request_key":"api"}
    assert client.post("/api/agent/execute", json=body).status_code == 401
    root = client.app.state.passport.create_run()
    auth = {"Authorization": f"Bearer {root['token']}"}
    response = client.post("/api/agent/execute", json=body, headers=auth)
    assert response.status_code == 200 and response.json()["state"] == "completed"
    assert client.post("/api/agent/execute", json={**body, "cost":0}, headers=auth).status_code == 422
    assert client.post("/api/agent/execute", json={**body, "resource":"production/checkout"}, headers=auth).json()["rule"] == "RESOURCE_ACTION_DENIED"


def test_scenario_and_evidence_api(client):
    auth = headers(client)
    for _ in range(4): assert client.post("/api/demo/step", headers=auth).status_code == 200
    state = client.get("/api/state", headers=auth).json()
    assert state["metrics"]["unrelated_branch_completed"]
    evidence = client.get("/api/evidence", headers=auth).json()
    assert len(evidence["receipts"]) == 3


def test_1password_subprocess_uses_fixed_argv_without_shell(monkeypatch):
    captured = {}
    monkeypatch.setattr("agent_passport.broker.shutil.which", lambda name: "/trusted/op")
    def run(args, **kwargs):
        captured.update(args=args, kwargs=kwargs)
        return SimpleNamespace(returncode=0, stdout="test-secret", stderr="")
    monkeypatch.setattr("agent_passport.broker.subprocess.run", run)
    assert OnePasswordCredentials("op://Demo/Fixture/key").resolve() == "test-secret"
    assert captured["args"] == ["/trusted/op", "read", "op://Demo/Fixture/key", "--no-newline"]
    assert not captured["kwargs"].get("shell")


@pytest.mark.parametrize("failure", ["exit", "timeout", "missing"])
def test_1password_failure_does_not_leak_stdout_or_stderr(monkeypatch, failure):
    monkeypatch.setattr("agent_passport.broker.shutil.which", lambda name: None if failure == "missing" else "/trusted/op")
    def run(*args, **kwargs):
        if failure == "timeout": raise subprocess.TimeoutExpired("op", 20, output="SECRET")
        return SimpleNamespace(returncode=1, stdout="SECRET", stderr="SECRET")
    monkeypatch.setattr("agent_passport.broker.subprocess.run", run)
    with pytest.raises(CredentialUnavailable) as error:
        OnePasswordCredentials("op://Demo/Fixture/key").resolve()
    assert "SECRET" not in str(error.value)
