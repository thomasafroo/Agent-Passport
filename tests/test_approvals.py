"""Step-up operator approval for high-risk operations."""
import copy
import json
import threading

from fastapi.testclient import TestClient
import pytest

from agent_passport.broker import Executor
from agent_passport.core import (APPROVAL_REQUEST_TTL, APPROVAL_TTL, Denied, Holder, Passport, delegate_fields,
                                 execute_fields, verify_receipt)
from agent_passport.mcp_server import Adapter
from agent_passport.server import create_app
from scripts.approve import main as approve_cli
from scripts.verify_evidence import verify

CONFIG = ("staging/checkout", "config.write")
LOG_READ = ("staging/checkout", "logs.read")
REASON = "Change ticket reviewed; staging only, rollback ready."


class CountingService:
    """Records every call that crosses the dispatch boundary."""
    def __init__(self):
        self.calls = []
        self.lock = threading.Lock()

    def execute(self, credential, resource, action, operation_id=None):
        with self.lock:
            self.calls.append(operation_id)
        return {"resource": resource, "action": action, "synthetic": True}


@pytest.fixture
def clock():
    return [10_000.0]


@pytest.fixture
def engine(tmp_path, clock):
    return Passport(tmp_path, clock=lambda: clock[0])


@pytest.fixture
def service():
    return CountingService()


@pytest.fixture
def executor(engine, service):
    return Executor(engine, service=service)


def assert_denied(rule, fn):
    with pytest.raises(Denied) as error:
        fn()
    assert error.value.rule == rule


def run_of(engine, root):
    return engine.snapshot(root["run_id"])["run"]


def pending(engine, executor, budget=3, key="change"):
    root = engine.create_run(budget=budget)
    result = executor.execute(root["token"], *CONFIG, key)
    return root, result


def test_pending_reserve_holds_a_unit_and_never_dispatches(engine, executor, service):
    root, result = pending(engine, executor)
    assert result["state"] == "awaiting_approval" and result["rule"] == "APPROVAL_REQUIRED" and not result["duplicate"]
    assert result["result"] is None and result["receipt"] is None
    assert run_of(engine, root)["reserved"] == 1 and run_of(engine, root)["spent"] == 0
    oid = result["operation_id"]
    # Neither the executor nor a direct dispatch can move it before a decision.
    assert engine.dispatch(oid) is False
    assert_denied("OPERATION_STATE", lambda: executor.execute_reserved({"id": oid}))
    retry = executor.execute(root["token"], *CONFIG, "change")
    assert retry["duplicate"] and retry["state"] == "awaiting_approval" and retry["operation_id"] == oid
    assert service.calls == [] and run_of(engine, root)["reserved"] == 1
    assert [o["id"] for o in engine.pending_approvals(root["run_id"])] == [oid]
    # Waiting is not an unresolved effect: reconciliation does not apply to it.
    assert engine.unresolved(root["run_id"]) == []
    kinds = [e["kind"] for e in engine.snapshot(root["run_id"])["events"]]
    assert kinds[-2:] == ["reserved", "awaiting_approval"]


def test_approval_alone_runs_nothing_and_the_retry_runs_once(engine, executor, service):
    root, result = pending(engine, executor)
    oid = result["operation_id"]
    decision = engine.decide_approval(oid, "approve", REASON, "On-call")
    assert decision["state"] == "approved" and service.calls == []
    done = executor.execute(root["token"], *CONFIG, "change")
    assert done["state"] == "completed" and done["operation_id"] == oid and service.calls == [oid]
    again = executor.execute(root["token"], *CONFIG, "change")
    assert again["duplicate"] and again["state"] == "completed" and service.calls == [oid]
    run = run_of(engine, root)
    assert run["spent"] == 1 and run["reserved"] == 0
    # The operation receipt is bound to the exact approval it was dispatched under.
    evidence = engine.evidence(root["run_id"])
    assert evidence["receipts"][0]["body"]["approval"]
    assert verify(evidence, engine.public_key)["approvals"] == 1
    assert engine.pending_approvals(root["run_id"]) == []


def test_concurrent_retries_after_approval_execute_once(engine, executor, service):
    root, result = pending(engine, executor)
    engine.decide_approval(result["operation_id"], "approve", REASON)
    barrier, states = threading.Barrier(8), []

    def retry():
        barrier.wait()
        states.append(executor.execute(root["token"], *CONFIG, "change")["state"])

    threads = [threading.Thread(target=retry) for _ in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert service.calls == [result["operation_id"]]
    assert states.count("completed") >= 1 and set(states) <= {"completed", "dispatched"}
    assert run_of(engine, root)["spent"] == 1 and run_of(engine, root)["reserved"] == 0


def test_denial_returns_the_unit_once(engine, executor, service):
    root, result = pending(engine, executor, budget=1)
    oid = result["operation_id"]
    # The pool is exhausted while the request waits.
    assert_denied("BUDGET_EXHAUSTED", lambda: executor.execute(root["token"], *LOG_READ, "other"))
    denied = engine.decide_approval(oid, "deny", REASON)
    assert denied["state"] == "approval_denied" and denied["receipt"]["body"]["decision"] == "denied"
    assert denied["receipt"]["body"]["expires"] is None
    assert run_of(engine, root)["reserved"] == 0
    assert_denied("OPERATION_STATE", lambda: engine.decide_approval(oid, "deny", REASON))
    assert_denied("OPERATION_STATE", lambda: engine.decide_approval(oid, "approve", REASON))
    retry = executor.execute(root["token"], *CONFIG, "change")
    assert retry["duplicate"] and retry["state"] == "approval_denied" and retry["rule"] == "APPROVAL_DENIED"
    assert engine.dispatch(oid) is False and service.calls == []
    run = run_of(engine, root)
    assert run["reserved"] == 0 and run["spent"] == 0
    # The returned unit is usable again.
    assert executor.execute(root["token"], *LOG_READ, "after")["state"] == "completed"


def test_lapsed_approval_returns_the_unit_once_and_never_runs(engine, executor, service, clock):
    root, result = pending(engine, executor)
    oid = result["operation_id"]
    engine.decide_approval(oid, "approve", REASON)
    clock[0] += APPROVAL_TTL
    assert engine.pending_approvals(root["run_id"]) == []  # the listing sweeps
    assert run_of(engine, root)["reserved"] == 0
    engine.pending_approvals(root["run_id"])
    retry = executor.execute(root["token"], *CONFIG, "change")
    assert retry["state"] == "approval_lapsed" and retry["rule"] == "APPROVAL_LAPSED"
    assert service.calls == [] and engine.dispatch(oid) is False
    events = engine.snapshot(root["run_id"])["events"]
    assert [e["kind"] for e in events].count("approval_lapsed") == 1
    run = run_of(engine, root)
    assert run["reserved"] == 0 and run["spent"] == 0


def test_lapse_found_at_dispatch_returns_the_unit_once(engine, executor, service, clock):
    root, result = pending(engine, executor)
    oid = result["operation_id"]
    engine.decide_approval(oid, "approve", REASON)
    clock[0] += APPROVAL_TTL + 1
    # A trusted executor reaching the operation directly still cannot use a lapsed approval.
    assert_denied("APPROVAL_LAPSED", lambda: engine.dispatch(oid))
    assert engine.dispatch(oid) is False
    assert engine.operation(oid)["state"] == "approval_lapsed" and service.calls == []
    assert run_of(engine, root)["reserved"] == 0


def test_undecided_request_lapses_and_cannot_then_be_approved(engine, executor, service, clock):
    root, result = pending(engine, executor)
    clock[0] += APPROVAL_REQUEST_TTL
    assert_denied("OPERATION_STATE", lambda: engine.decide_approval(result["operation_id"], "approve", REASON))
    assert engine.operation(result["operation_id"])["state"] == "approval_lapsed"
    assert run_of(engine, root)["reserved"] == 0 and service.calls == []


def test_concurrent_approve_and_deny_apply_once(engine, executor):
    root, result = pending(engine, executor)
    barrier, results = threading.Barrier(8), []

    def decide(decision):
        barrier.wait()
        try:
            results.append(engine.decide_approval(result["operation_id"], decision, REASON)["state"])
        except Denied as e:
            results.append(e.rule)

    threads = [threading.Thread(target=decide, args=(["approve", "deny"][i % 2],)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert results.count("OPERATION_STATE") == 7
    winner = next(r for r in results if r != "OPERATION_STATE")
    assert run_of(engine, root)["reserved"] == (1 if winner == "approved" else 0)
    assert len(engine.evidence(root["run_id"])["approvals"]) == 1


def test_revocation_after_approval_cancels_dispatch_and_returns_the_unit_once(engine, executor, service):
    root = engine.create_run(budget=3)
    worker = engine.delegate(root["token"], "Config worker", [{"resource": CONFIG[0], "action": CONFIG[1]}], root["grant"]["expires"])
    oid = executor.execute(worker["token"], *CONFIG, "change")["operation_id"]
    engine.decide_approval(oid, "approve", REASON)
    engine.revoke(worker["grant"]["id"])
    assert_denied("ANCESTOR_REVOKED", lambda: executor.execute(worker["token"], *CONFIG, "change"))
    assert engine.operation(oid)["state"] == "cancelled" and service.calls == []
    assert_denied("ANCESTOR_REVOKED", lambda: executor.execute(worker["token"], *CONFIG, "change"))
    assert engine.dispatch(oid) is False
    run = run_of(engine, root)
    assert run["reserved"] == 0 and run["spent"] == 0


def test_revocation_found_at_direct_dispatch(engine, executor, service):
    root = engine.create_run(budget=3)
    worker = engine.delegate(root["token"], "Config worker", [{"resource": CONFIG[0], "action": CONFIG[1]}], root["grant"]["expires"])
    oid = executor.execute(worker["token"], *CONFIG, "change")["operation_id"]
    engine.decide_approval(oid, "approve", REASON)
    engine.revoke(root["grant"]["id"])  # an ancestor, not the worker itself
    assert_denied("ANCESTOR_REVOKED", lambda: engine.dispatch(oid))
    assert engine.operation(oid)["state"] == "cancelled" and run_of(engine, root)["reserved"] == 0
    assert service.calls == []


def test_revoked_before_decision_cannot_be_approved(engine, executor):
    root, result = pending(engine, executor)
    engine.revoke(root["grant"]["id"])
    assert_denied("OPERATION_STATE", lambda: engine.decide_approval(result["operation_id"], "approve", REASON))
    assert run_of(engine, root)["reserved"] == 0
    assert_denied("OPERATION_STATE", lambda: engine.decide_approval(result["operation_id"], "deny", REASON))
    assert run_of(engine, root)["reserved"] == 0


def test_retry_after_approval_still_needs_a_fresh_holder_proof(engine, service, executor, clock):
    holder = Holder()
    root = engine.create_run(budget=3, holder_key=holder.public_key)
    fields = execute_fields(*CONFIG, "change")
    oid = executor.execute(root["token"], *CONFIG, "change", holder.proof(root["token"], "execute", fields, now=clock[0]))["operation_id"]
    decision = engine.decide_approval(oid, "approve", REASON)
    assert decision["receipt"]["body"]["cnf"] == holder.public_key
    assert_denied("PROOF_REQUIRED", lambda: executor.execute(root["token"], *CONFIG, "change"))
    assert_denied("PROOF_INVALID", lambda: executor.execute(root["token"], *CONFIG, "change", Holder().proof(root["token"], "execute", fields, now=clock[0])))
    assert engine.operation(oid)["state"] == "approved" and service.calls == []
    assert executor.execute(root["token"], *CONFIG, "change", holder.proof(root["token"], "execute", fields, now=clock[0]))["state"] == "completed"
    assert service.calls == [oid]


def test_an_approval_is_bound_to_its_exact_operation(engine, executor, service):
    root = engine.create_run(budget=3)
    first = executor.execute(root["token"], *CONFIG, "first")["operation_id"]
    second = executor.execute(root["token"], *CONFIG, "second")["operation_id"]
    engine.decide_approval(first, "approve", REASON)
    # Forge an approval row for the second operation from the first operation's signed approval.
    db = engine.connect()
    try:
        row = db.execute("SELECT * FROM approvals WHERE operation_id=?", (first,)).fetchone()
        db.execute("INSERT INTO approvals VALUES(?,?,?,?,0,?)", (second, row["run_id"], "approved", row["expires"], row["receipt"]))
        db.execute("UPDATE operations SET state='approved' WHERE id=?", (second,))
    finally:
        db.close()
    assert_denied("APPROVAL_INVALID", lambda: executor.execute(root["token"], *CONFIG, "second"))
    assert engine.operation(second)["state"] == "cancelled"
    assert executor.execute(root["token"], *CONFIG, "first")["state"] == "completed"
    assert service.calls == [first]
    run = run_of(engine, root)
    assert run["spent"] == 1 and run["reserved"] == 0


@pytest.mark.parametrize("decision,reason,rule", [("allow", REASON, "DECISION_INVALID"), ("approved", REASON, "DECISION_INVALID"),
                                                  ("approve", "", "REASON_REQUIRED"), ("approve", "too short", "REASON_REQUIRED"),
                                                  ("approve", "x" * 501, "REASON_REQUIRED"), ("deny", None, "REASON_REQUIRED")])
def test_decisions_need_a_valid_verdict_and_reason(engine, executor, decision, reason, rule):
    root, result = pending(engine, executor)
    assert_denied(rule, lambda: engine.decide_approval(result["operation_id"], decision, reason))
    assert engine.operation(result["operation_id"])["state"] == "awaiting_approval"
    assert_denied("OPERATION_UNKNOWN", lambda: engine.decide_approval("op_missing", "approve", REASON))


def test_pairs_outside_the_policy_are_unchanged(engine, executor, service, tmp_path):
    root = engine.create_run()
    result = executor.execute(root["token"], *LOG_READ, "plain")
    assert result["state"] == "completed" and "rule" not in result and "approval" not in result["receipt"]["body"]
    assert not any(e["kind"] == "awaiting_approval" for e in engine.snapshot(root["run_id"])["events"])
    # The policy is server configuration: an operator who lists no pairs gates nothing.
    ungated = Passport(tmp_path / "ungated", approval_required=())
    other = ungated.create_run()
    assert Executor(ungated, service=service).execute(other["token"], *CONFIG, "x")["state"] == "completed"


def test_approval_receipts_verify_offline_and_tampering_fails(engine, executor):
    root, result = pending(engine, executor)
    approval = engine.decide_approval(result["operation_id"], "approve", REASON, "On-call")["receipt"]
    body = approval["body"]
    assert body["type"] == "approval" and body["decision"] == "approved" and body["decided_by"] == "On-call"
    assert body["reason"] == REASON and body["chain"] == [root["grant"]["id"]] and body["resource"] == CONFIG[0]
    assert verify_receipt(approval, engine.public_key)
    executor.execute(root["token"], *CONFIG, "change")
    evidence = engine.evidence(root["run_id"])
    assert verify(evidence, engine.public_key)["approvals"] == 1
    altered = copy.deepcopy(evidence); altered["approvals"][0]["body"]["decided_by"] = "Someone else"
    with pytest.raises(ValueError, match="approval"):
        verify(altered, engine.public_key)
    # Dropping the approval that an operation receipt cites is detected.
    dropped = copy.deepcopy(evidence); dropped["approvals"] = []
    with pytest.raises(ValueError, match="approval"):
        verify(dropped, engine.public_key)
    foreign = copy.deepcopy(evidence); foreign["approvals"][0]["body"]["run_id"] = "run_other"
    with pytest.raises(ValueError):
        verify(foreign, engine.public_key)


def test_approvals_receipts_reconciliations_and_checkpoints_cannot_stand_in_for_each_other(engine, executor):
    root, result = pending(engine, executor)
    engine.decide_approval(result["operation_id"], "approve", REASON)
    executor.execute(root["token"], *CONFIG, "change")
    evidence = engine.evidence(root["run_id"])
    approval, receipt = evidence["approvals"][0], evidence["receipts"][0]
    checkpoint = engine.checkpoint(root["run_id"])
    swaps = [("receipts", approval), ("reconciliations", approval), ("approvals", receipt), ("approvals", checkpoint)]
    for field, item in swaps:
        forged = copy.deepcopy(evidence)
        forged[field] = forged.get(field, []) + [item]
        with pytest.raises(ValueError):
            verify(forged, engine.public_key)
    with pytest.raises(ValueError):
        verify(evidence, engine.public_key, [approval])


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    return TestClient(create_app(tmp_path))


def test_only_the_console_session_can_list_or_decide(client):
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    state = client.post("/api/demo/config", headers=console).json()
    assert state["run"]["reserved"] == 1
    [waiting] = client.get("/api/approvals", headers=console).json()["approvals"]
    oid = waiting["id"]
    assert waiting["state"] == "awaiting_approval" and waiting["subject"] == "Config worker"
    worker = client.app.state.demo.agents["Config worker"]
    body = {"decision": "approve", "reason": REASON}
    for headers in ({"Authorization": f"Bearer {worker['token']}"},
                    {"Authorization": f"Bearer {worker['token']}", "x-passport-console": worker["token"]},
                    {"x-passport-console": "guess"}, {}):
        assert client.post(f"/api/approvals/{oid}", json=body, headers=headers).status_code == 403
        assert client.get("/api/approvals", headers=headers).status_code == 403
    for path in ("/api/agent/approve", f"/api/agent/approvals/{oid}"):
        assert client.post(path, json=body, headers={"Authorization": f"Bearer {worker['token']}"}).status_code in (404, 405)
    assert client.app.state.passport.operation(oid)["state"] == "awaiting_approval"
    assert client.post(f"/api/approvals/{oid}", json={**body, "extra": 1}, headers=console).status_code == 422
    assert client.post(f"/api/approvals/{oid}", json={**body, "reason": "short"}, headers=console).json()["rule"] == "REASON_REQUIRED"
    decided = client.post(f"/api/approvals/{oid}", json=body, headers=console)
    assert decided.status_code == 200 and decided.json()["receipt"]["body"]["decided_by"] == "Local operator"
    assert client.post(f"/api/approvals/{oid}", json=body, headers=console).status_code == 404
    # The scripted worker's retry with the same key picks up the decision and runs once.
    after = client.post("/api/demo/config", headers=console).json()
    assert after["run"]["spent"] == 1 and after["run"]["reserved"] == 0
    evidence = client.get("/api/evidence", headers=console).json()
    assert evidence["approvals"][0]["body"]["operation_id"] == oid
    assert verify(evidence, evidence["public_key"])["approvals"] == 1
    # The next request is a new operation, waiting again.
    client.post("/api/demo/config", headers=console)
    assert [o["id"] for o in client.get("/api/approvals", headers=console).json()["approvals"]] != [oid]


def test_scripted_story_is_unchanged(client):
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    for _ in range(4):
        state = client.post("/api/demo/step", headers=console).json()
    assert state["metrics"]["unrelated_branch_completed"]
    report = client.post("/api/demo/fork", headers=console).json()["metrics"]["fork"]
    assert report["completed"] == report["available_before"] == 21 and report["spent_after"] == 24


class InProcessGateway:
    def __init__(self, client):
        self.client = client

    def call(self, method, path, token, body=None, proof=None):
        headers = {"Authorization": f"Bearer {token}"}
        if proof:
            headers["X-Passport-Proof"] = proof
        response = self.client.request(method, path, json=body, headers=headers)
        return response.status_code, response.json()


def tokens_in(client):
    passport = client.app.state.passport
    db = passport.connect()
    try:
        return [passport._token(g) for g in db.execute("SELECT * FROM grants")]
    finally:
        db.close()


def test_mcp_surfaces_the_pending_state_without_tokens_and_picks_up_the_decision(client, tmp_path):
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    adapter = Adapter(InProcessGateway(client), tmp_path / "live-agent.token")
    adapter.register()
    assert client.post("/api/live/issue", headers=console).status_code == 200
    adapter.delegate("Config helper", [{"resource": CONFIG[0], "action": CONFIG[1]}])
    outputs = [adapter.operate(*CONFIG), adapter.operate(*CONFIG)]
    first, second = outputs
    assert first["state"] == "awaiting_approval" and first["approval_required"] and not first["allowed"]
    assert "approval" in first["detail"] and "same arguments" in first["detail"]
    assert second["operation_id"] == first["operation_id"]  # the same arguments retry the same operation
    # A worker's request with the same pair is a separate operation.
    outputs.append(adapter.operate(*CONFIG, worker="Config helper"))
    assert outputs[-1]["operation_id"] != first["operation_id"]
    assert client.post(f"/api/approvals/{first['operation_id']}", json={"decision": "approve", "reason": REASON}, headers=console).status_code == 200
    outputs.append(adapter.operate(*CONFIG))
    assert outputs[-1]["state"] == "completed" and outputs[-1]["operation_id"] == first["operation_id"]
    outputs.append(adapter.operate(*CONFIG))
    assert outputs[-1]["state"] == "awaiting_approval" and outputs[-1]["operation_id"] != first["operation_id"]
    worker_op = outputs[2]["operation_id"]
    assert client.post(f"/api/approvals/{worker_op}", json={"decision": "deny", "reason": REASON}, headers=console).status_code == 200
    outputs.append(adapter.operate(*CONFIG, worker="Config helper"))
    assert outputs[-1]["state"] == "approval_denied" and outputs[-1]["operation_id"] == worker_op and not outputs[-1]["allowed"]
    outputs.append(adapter.passport())
    text = json.dumps(outputs)
    for token in tokens_in(client):
        assert token not in text and token.split(".")[1] not in text


def test_cli_lists_and_decides(tmp_path, capsys):
    engine = Passport(tmp_path)
    root = engine.create_run()
    oid = Executor(engine, service=CountingService()).execute(root["token"], *CONFIG, "cli")["operation_id"]
    assert approve_cli(["--state-dir", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["awaiting"][0]["id"] == oid
    assert approve_cli([oid, "--decision", "approve", "--reason", "short", "--state-dir", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().err)["rule"] == "REASON_REQUIRED"
    assert approve_cli([oid, "--decision", "deny", "--reason", REASON, "--operator", "On-call", "--state-dir", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["receipt"]["body"]["decided_by"] == "On-call"
    assert engine.pending_approvals() == [] and engine.snapshot(root["run_id"])["run"]["reserved"] == 0
