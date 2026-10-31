"""Holder binding: a key-bound passport is useless without its holder's private key."""
import json

from fastapi.testclient import TestClient
import pytest

from agent_passport.broker import Executor
from agent_passport.core import (Passport, Denied, Holder, PROOF_WINDOW, b64, delegate_fields,
                                 execute_fields, request_digest, token_digest, verify_receipt)
from agent_passport.demo import LOGS, Demo
from agent_passport.mcp_server import Adapter
from agent_passport.server import create_app

LOG_READ = ("staging/checkout", "logs.read")


@pytest.fixture
def engine(tmp_path):
    return Passport(tmp_path)


def assert_denied(rule, fn):
    with pytest.raises(Denied) as error:
        fn()
    assert error.value.rule == rule


def bound_run(engine, **kwargs):
    holder = Holder()
    return {**engine.create_run(holder_key=holder.public_key, **kwargs), "holder": holder}


def bound_child(engine, parent, scopes=LOGS, name="Worker"):
    holder = Holder()
    expires = parent["grant"]["expires"]
    proof = parent["holder"].proof(parent["token"], "delegate", delegate_fields(name, scopes, expires, holder.public_key))
    return {**engine.delegate(parent["token"], name, scopes, expires, holder.public_key, proof), "holder": holder}


def execute(engine, agent, key="k", holder=None, resource="staging/checkout", action="logs.read", **proof_args):
    holder = holder or agent["holder"]
    proof = holder.proof(agent["token"], "execute", execute_fields(resource, action, key), **proof_args)
    return Executor(engine).execute(agent["token"], resource, action, key, proof)


def test_bound_passport_rejects_bearer_token_alone_and_records_it(engine):
    root = bound_run(engine)
    assert_denied("PROOF_REQUIRED", lambda: Executor(engine).execute(root["token"], *LOG_READ, "stolen"))
    assert_denied("PROOF_REQUIRED", lambda: engine.inspect(root["token"]))
    assert_denied("PROOF_REQUIRED", lambda: engine.delegate(root["token"], "Thief", LOGS, root["grant"]["expires"], Holder().public_key))
    snapshot = engine.snapshot(root["run_id"])
    assert [e["rule"] for e in snapshot["events"] if e["kind"] == "denied"] == ["PROOF_REQUIRED"] * 3
    assert snapshot["run"]["spent"] == snapshot["run"]["reserved"] == 0


def test_bound_passport_works_with_its_holder_key(engine):
    root = bound_run(engine)
    assert execute(engine, root)["state"] == "completed"
    assert engine.inspect(root["token"], root["holder"].proof(root["token"], "inspect", {}))["state"] == "active"
    assert root["grant"]["cnf"] == root["holder"].public_key


def test_thief_signing_with_own_key_is_rejected(engine):
    root = bound_run(engine)
    assert_denied("PROOF_INVALID", lambda: execute(engine, root, holder=Holder()))


def test_proof_is_bound_to_token_operation_and_exact_request(engine):
    root = bound_run(engine); other = bound_run(engine)
    fields = execute_fields(*LOG_READ, "k")
    # Proof for a different token, even one signed by the right key.
    wrong_token = root["holder"].proof(other["token"], "execute", fields)
    assert_denied("PROOF_INVALID", lambda: engine.reserve(root["token"], *LOG_READ, "k", wrong_token))
    # Proof for a different resource/action or idempotency key.
    for changed in [execute_fields("repo/checkout", "code.read", "k"), execute_fields(*LOG_READ, "other-key")]:
        proof = root["holder"].proof(root["token"], "execute", changed)
        assert_denied("PROOF_INVALID", lambda: engine.reserve(root["token"], *LOG_READ, "k", proof))
    # A proof for reading the passport cannot authorize an operation or a delegation.
    inspect_proof = root["holder"].proof(root["token"], "inspect", {})
    assert_denied("PROOF_INVALID", lambda: engine.reserve(root["token"], *LOG_READ, "k", inspect_proof))
    assert_denied("PROOF_INVALID", lambda: engine.delegate(root["token"], "W", LOGS, root["grant"]["expires"], Holder().public_key, inspect_proof))


def test_delegation_proof_covers_the_child_key(engine):
    root = bound_run(engine); intended, attacker = Holder(), Holder()
    expires = root["grant"]["expires"]
    proof = root["holder"].proof(root["token"], "delegate", delegate_fields("W", LOGS, expires, intended.public_key))
    assert_denied("PROOF_INVALID", lambda: engine.delegate(root["token"], "W", LOGS, expires, attacker.public_key, proof))


def test_proof_cannot_be_replayed_but_a_fresh_retry_is_idempotent(engine):
    root = bound_run(engine)
    proof = root["holder"].proof(root["token"], "execute", execute_fields(*LOG_READ, "k"))
    first = Executor(engine).execute(root["token"], *LOG_READ, "k", proof)
    assert first["state"] == "completed"
    assert_denied("PROOF_REPLAYED", lambda: Executor(engine).execute(root["token"], *LOG_READ, "k", proof))
    retry = execute(engine, root, key="k")
    assert retry["duplicate"] and retry["operation_id"] == first["operation_id"]
    assert engine.snapshot(root["run_id"])["run"]["spent"] == 1


def test_stale_future_and_non_finite_timestamps_are_rejected(tmp_path):
    now = [10_000.0]
    engine = Passport(tmp_path, clock=lambda: now[0])
    root = bound_run(engine)
    assert_denied("PROOF_STALE", lambda: execute(engine, root, key="old", now=now[0] - PROOF_WINDOW - 1))
    assert_denied("PROOF_STALE", lambda: execute(engine, root, key="future", now=now[0] + PROOF_WINDOW + 1))
    assert execute(engine, root, key="edge", now=now[0] - PROOF_WINDOW)["state"] == "completed"
    for iat in [float("nan"), float("inf"), True, "10000"]:
        body = {"ath": token_digest(root["token"]), "op": "execute", "iat": iat, "jti": "j" * 32,
                "req": request_digest("execute", execute_fields(*LOG_READ, "odd"))}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        proof = b64(payload) + "." + b64(root["holder"].key.sign(payload))
        assert_denied("PROOF_INVALID", lambda: engine.reserve(root["token"], *LOG_READ, "odd", proof))


def test_used_nonces_are_pruned_only_after_they_can_no_longer_be_fresh(tmp_path):
    now = [10_000.0]
    engine = Passport(tmp_path, clock=lambda: now[0])
    root = bound_run(engine)
    proof = root["holder"].proof(root["token"], "execute", execute_fields(*LOG_READ, "k"), now=now[0])
    engine.reserve(root["token"], *LOG_READ, "k", proof)
    now[0] += PROOF_WINDOW  # still fresh: the replay check must still hold
    assert_denied("PROOF_REPLAYED", lambda: engine.reserve(root["token"], *LOG_READ, "k", proof))
    now[0] += PROOF_WINDOW + 1  # stale now, so pruning cannot reopen it
    execute(engine, root, key="prune", now=now[0])
    assert_denied("PROOF_STALE", lambda: engine.reserve(root["token"], *LOG_READ, "k", proof))


@pytest.mark.parametrize("proof", ["", "x", "a.b.c", "!!!.???", "x" * 3000, None])
def test_malformed_proofs_fail_closed(engine, proof):
    root = bound_run(engine)
    rule = "PROOF_REQUIRED" if proof is None else "PROOF_INVALID"
    assert_denied(rule, lambda: engine.reserve(root["token"], *LOG_READ, "k", proof))


def test_binding_cannot_be_dropped_by_delegation(engine):
    root = bound_run(engine)
    expires = root["grant"]["expires"]
    proof = root["holder"].proof(root["token"], "delegate", delegate_fields("Bearer child", LOGS, expires, None))
    assert_denied("BINDING_REQUIRED", lambda: engine.delegate(root["token"], "Bearer child", LOGS, expires, None, proof))
    for bad in ["not-a-key", "A" * 10, 7]:
        proof = root["holder"].proof(root["token"], "delegate", delegate_fields("W", LOGS, expires, bad))
        assert_denied("HOLDER_KEY_INVALID", lambda: engine.delegate(root["token"], "W", LOGS, expires, bad, proof))
    assert_denied("HOLDER_KEY_INVALID", lambda: engine.create_run(holder_key="not-a-key"))


def test_each_child_has_its_own_key(engine):
    root = bound_run(engine); worker = bound_child(engine, root)
    assert worker["grant"]["cnf"] != root["grant"]["cnf"]
    assert_denied("PROOF_INVALID", lambda: execute(engine, worker, holder=root["holder"]))
    assert execute(engine, worker)["state"] == "completed"


def test_unbound_parent_may_issue_bound_child(engine):
    root = engine.create_run(); holder = Holder()
    child = engine.delegate(root["token"], "Bound", LOGS, root["grant"]["expires"], holder.public_key)
    assert_denied("PROOF_REQUIRED", lambda: Executor(engine).execute(child["token"], *LOG_READ, "k"))
    assert execute(engine, {**child, "holder": holder})["state"] == "completed"


def test_revocation_and_scope_still_apply_with_a_valid_proof(engine):
    root = bound_run(engine); worker = bound_child(engine, root)
    assert_denied("RESOURCE_ACTION_DENIED", lambda: execute(engine, worker, resource="repo/checkout", action="code.read"))
    engine.revoke(worker["grant"]["id"])
    assert_denied("ANCESTOR_REVOKED", lambda: execute(engine, worker, key="after"))


def test_receipt_attests_the_holder_key(engine):
    root = bound_run(engine)
    receipt = execute(engine, root)["receipt"]
    assert receipt["body"]["cnf"] == root["holder"].public_key and verify_receipt(receipt, engine.public_key)


def test_existing_database_upgrades_and_old_tokens_still_verify(tmp_path):
    engine = Passport(tmp_path); old = engine.create_run()
    db = engine.connect()
    try:
        db.execute("DROP TABLE proofs")
        db.execute("ALTER TABLE grants DROP COLUMN holder_key")
    finally:
        db.close()
    upgraded = Passport(tmp_path)
    assert Executor(upgraded).execute(old["token"], *LOG_READ, "k")["state"] == "completed"
    assert "cnf" not in upgraded.snapshot(old["run_id"])["grants"][0]
    assert execute(upgraded, bound_run(upgraded))["state"] == "completed"


def test_demo_binds_every_agent_and_records_the_replay(engine):
    demo = Demo(engine, Executor(engine))
    for _ in range(4): demo.step()
    snapshot = demo.snapshot()
    assert all(g.get("cnf") for g in snapshot["grants"])
    assert len({g["cnf"] for g in snapshot["grants"]}) == len(snapshot["grants"])
    log_reader = demo.agents["Log reader"]["grant"]["id"]
    assert any(e["rule"] == "PROOF_REQUIRED" and e["grant_id"] == log_reader for e in snapshot["events"])
    assert snapshot["metrics"]["unrelated_branch_completed"]
    report = demo.fork()["metrics"]["fork"]
    assert report["completed"] == report["available_before"] == 21 and report["spent_after"] == 24


def test_http_agent_api_requires_proof_header_for_bound_passports(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    client = TestClient(create_app(tmp_path))
    root = bound_run(client.app.state.passport)
    body = {"resource": "staging/checkout", "action": "logs.read", "request_key": "api"}
    auth = {"Authorization": f"Bearer {root['token']}"}
    assert client.post("/api/agent/execute", json=body, headers=auth).json()["rule"] == "PROOF_REQUIRED"
    proof = root["holder"].proof(root["token"], "execute", body)
    assert client.post("/api/agent/execute", json=body, headers={**auth, "X-Passport-Proof": proof}).json()["state"] == "completed"
    # An integer expiry from a client still matches the gateway's float-parsed value.
    child = Holder(); expires = int(root["grant"]["expires"])
    delegation = {"subject": "W", "scopes": LOGS, "expires": expires, "holder_key": child.public_key}
    proof = root["holder"].proof(root["token"], "delegate", delegate_fields("W", LOGS, expires, child.public_key))
    response = client.post("/api/agent/delegate", json=delegation, headers={**auth, "X-Passport-Proof": proof})
    assert response.status_code == 200 and response.json()["grant"]["cnf"] == child.public_key


class _Gateway:
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
    return client, console, tmp_path


def test_live_passport_requires_a_running_adapter(live):
    client, console, tmp_path = live
    assert client.post("/api/live/issue", headers=console).json()["rule"] == "ADAPTER_NOT_CONNECTED"
    assert not (tmp_path / "live-agent.token").exists()


def test_stolen_live_token_file_authorizes_nothing(live):
    client, console, tmp_path = live
    adapter = Adapter(_Gateway(client), tmp_path / "live-agent.token"); adapter.register()
    client.post("/api/live/issue", headers=console)
    assert adapter.operate("staging/checkout", "logs.read")["state"] == "completed"
    # Everything on disk: the token and the public key. Neither lets a thief act.
    stolen = (tmp_path / "live-agent.token").read_text()
    public = (tmp_path / "live-agent.pub").read_text()
    assert public == adapter.holder.public_key and "PRIVATE" not in public
    body = {"resource": "staging/checkout", "action": "logs.read", "request_key": "thief"}
    auth = {"Authorization": f"Bearer {stolen}"}
    assert client.post("/api/agent/execute", json=body, headers=auth).json()["rule"] == "PROOF_REQUIRED"
    forged = Holder().proof(stolen, "execute", body)
    assert client.post("/api/agent/execute", json=body, headers={**auth, "X-Passport-Proof": forged}).json()["rule"] == "PROOF_INVALID"
    assert client.get("/api/agent/passport", headers=auth).json()["rule"] == "PROOF_REQUIRED"
    # No private key material was written anywhere in the state directory.
    private = adapter.holder.key.private_bytes_raw()
    assert all(private not in path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())


def test_adapter_workers_are_bound_to_their_own_keys(live):
    client, console, tmp_path = live
    adapter = Adapter(_Gateway(client), tmp_path / "live-agent.token"); adapter.register()
    client.post("/api/live/issue", headers=console)
    adapter.delegate("Reader", [{"resource": "repo/checkout", "action": "code.read"}])
    token, holder = adapter.workers["Reader"]
    assert holder.public_key != adapter.holder.public_key
    body = {"resource": "repo/checkout", "action": "code.read", "request_key": "w"}
    assert client.post("/api/agent/execute", json=body, headers={"Authorization": f"Bearer {token}"}).json()["rule"] == "PROOF_REQUIRED"
    assert adapter.operate("repo/checkout", "code.read", worker="Reader")["state"] == "completed"
    assert adapter.passport(worker="Reader")["bound_to_adapter_key"]


def test_restarted_adapter_cannot_use_a_passport_bound_to_the_old_process(live):
    client, console, tmp_path = live
    first = Adapter(_Gateway(client), tmp_path / "live-agent.token"); first.register()
    client.post("/api/live/issue", headers=console)
    restarted = Adapter(_Gateway(client), tmp_path / "live-agent.token"); restarted.register()
    with pytest.raises(Exception, match="different adapter key"):
        restarted.operate("staging/checkout", "logs.read")
    client.post("/api/demo/reset", headers=console)
    client.post("/api/live/issue", headers=console)
    assert restarted.operate("staging/checkout", "logs.read")["state"] == "completed"
