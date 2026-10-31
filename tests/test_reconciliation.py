"""Operator reconciliation of unknown and crash-stranded operations."""
import copy
import json
import threading

from fastapi.testclient import TestClient
import pytest

from agent_passport.broker import Executor
from agent_passport.core import Passport, Denied, STRANDED_AFTER, verify_receipt
from agent_passport.server import create_app
from scripts.reconcile import main as reconcile_cli
from scripts.verify_evidence import verify

LOG_READ = ("staging/checkout", "logs.read")
REASON = "Upstream access log shows no request reached the service."


class UncertainService:
    def execute(self, *args):
        raise TimeoutError("unknown upstream effect")


@pytest.fixture
def clock():
    return [10_000.0]


@pytest.fixture
def engine(tmp_path, clock):
    return Passport(tmp_path, clock=lambda: clock[0])


def assert_denied(rule, fn):
    with pytest.raises(Denied) as error:
        fn()
    assert error.value.rule == rule


def unknown_op(engine, budget=1, key="timeout"):
    root = engine.create_run(budget=budget)
    result = Executor(engine, service=UncertainService()).execute(root["token"], *LOG_READ, key)
    assert result["state"] == "unknown"
    return root, result["operation_id"]


def run_of(engine, root):
    return engine.snapshot(root["run_id"])["run"]


def test_unknown_operation_keeps_its_unit_until_an_operator_decides(engine, clock):
    root, oid = unknown_op(engine)
    clock[0] += 3000  # within the grant's expiry, the pool stays exhausted
    assert_denied("BUDGET_EXHAUSTED", lambda: Executor(engine).execute(root["token"], *LOG_READ, "new"))
    clock[0] += 30 * 86400  # time alone never refunds, even long after the grant expired
    assert run_of(engine, root)["reserved"] == 1
    assert [o["id"] for o in engine.unresolved(root["run_id"])] == [oid]


def test_not_executed_returns_the_unit_with_a_signed_decision(engine):
    root, oid = unknown_op(engine)
    result = engine.reconcile(oid, "not_executed", REASON)
    assert result["state"] == "reconciled_not_executed"
    assert run_of(engine, root)["reserved"] == 0 and run_of(engine, root)["spent"] == 0
    body = result["receipt"]["body"]
    assert body["type"] == "reconciliation" and body["previous_state"] == "unknown" and body["cost"] == 0
    assert body["reason"] == REASON and body["decided_by"] == "Local operator"
    assert verify_receipt(result["receipt"], engine.public_key)
    altered = copy.deepcopy(result["receipt"]); altered["body"]["outcome"] = "reconciled_completed"
    assert not verify_receipt(altered, engine.public_key)
    event = engine.snapshot(root["run_id"])["events"][-1]
    assert event["kind"] == "reconciled" and event["rule"] == "RECONCILED_NOT_EXECUTED" and event["operation_id"] == oid
    assert Executor(engine).execute(root["token"], *LOG_READ, "after")["state"] == "completed"


def test_completed_consumes_the_unit(engine):
    root, oid = unknown_op(engine, budget=2)
    assert engine.reconcile(oid, "completed", REASON)["receipt"]["body"]["cost"] == 1
    run = run_of(engine, root)
    assert run["spent"] == 1 and run["reserved"] == 0


def test_retry_after_reconciliation_never_executes_again(engine):
    root, oid = unknown_op(engine, budget=2)
    engine.reconcile(oid, "not_executed", REASON)
    retry = Executor(engine).execute(root["token"], *LOG_READ, "timeout")
    assert retry["duplicate"] and retry["operation_id"] == oid and retry["state"] == "reconciled_not_executed"
    assert run_of(engine, root)["spent"] == 0


def test_a_decision_is_final(engine):
    root, oid = unknown_op(engine, budget=2)
    engine.reconcile(oid, "not_executed", REASON)
    assert_denied("OPERATION_STATE", lambda: engine.reconcile(oid, "completed", REASON))
    assert run_of(engine, root)["spent"] == 0 and run_of(engine, root)["reserved"] == 0


def test_settled_operations_cannot_be_reconciled(engine):
    root = engine.create_run()
    completed = Executor(engine).execute(root["token"], *LOG_READ, "done")
    assert_denied("OPERATION_STATE", lambda: engine.reconcile(completed["operation_id"], "not_executed", REASON))
    assert_denied("OPERATION_UNKNOWN", lambda: engine.reconcile("op_missing", "not_executed", REASON))


@pytest.mark.parametrize("outcome,reason,rule", [("refund", REASON, "OUTCOME_INVALID"), ("failed", REASON, "OUTCOME_INVALID"),
                                                 ("not_executed", "", "REASON_REQUIRED"), ("not_executed", "short", "REASON_REQUIRED"),
                                                 ("not_executed", "x" * 501, "REASON_REQUIRED"), ("not_executed", None, "REASON_REQUIRED")])
def test_decisions_need_a_valid_outcome_and_a_recorded_basis(engine, outcome, reason, rule):
    root, oid = unknown_op(engine)
    assert_denied(rule, lambda: engine.reconcile(oid, outcome, reason))
    assert run_of(engine, root)["reserved"] == 1


def test_stranded_reservation_is_guarded_while_it_may_be_in_flight(engine, clock):
    root = engine.create_run(budget=1)
    op = engine.reserve(root["token"], *LOG_READ, "crashed")
    assert not engine.unresolved(root["run_id"])[0]["reconcilable"]
    assert_denied("OPERATION_IN_FLIGHT", lambda: engine.reconcile(op["id"], "not_executed", REASON))
    clock[0] += STRANDED_AFTER
    assert engine.unresolved(root["run_id"])[0]["reconcilable"]
    engine.reconcile(op["id"], "not_executed", REASON)
    # A late executor finding the reservation can no longer dispatch it.
    assert engine.dispatch(op["id"]) is False
    assert run_of(engine, root)["reserved"] == 0


def test_stranded_dispatch_cannot_be_settled_after_a_decision(engine, clock):
    root = engine.create_run(budget=1)
    op = engine.reserve(root["token"], *LOG_READ, "inflight")
    assert engine.dispatch(op["id"])
    clock[0] += STRANDED_AFTER
    engine.reconcile(op["id"], "completed", REASON)
    assert_denied("OPERATION_STATE", lambda: engine.settle(op["id"], "failed", {}))
    run = run_of(engine, root)
    assert run["spent"] == 1 and run["reserved"] == 0


def test_concurrent_decisions_apply_once(engine):
    root, oid = unknown_op(engine, budget=2)
    barrier, results = threading.Barrier(8), []

    def decide(outcome):
        barrier.wait()
        try:
            results.append(engine.reconcile(oid, outcome, REASON)["state"])
        except Denied as e:
            results.append(e.rule)

    threads = [threading.Thread(target=decide, args=(["completed", "not_executed"][i % 2],)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert sorted(results).count("OPERATION_STATE") == 7
    run = run_of(engine, root)
    assert run["reserved"] == 0 and run["spent"] in (0, 1)


def test_reconciliations_are_exported_and_verify_offline(engine):
    root, oid = unknown_op(engine)
    engine.reconcile(oid, "not_executed", REASON)
    evidence = engine.evidence(root["run_id"])
    assert len(evidence["reconciliations"]) == 1
    assert verify(evidence, engine.public_key)["reconciliations"] == 1
    evidence["reconciliations"][0]["body"]["previous_state"] = "reserved"
    with pytest.raises(ValueError, match="reconciliation"):
        verify(evidence, engine.public_key)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    return TestClient(create_app(tmp_path))


def test_only_the_console_can_reconcile(client):
    app = client.app
    demo, engine = app.state.demo, app.state.passport
    # An unknown operation inside the console's current run.
    coordinator = demo.agents["Coordinator"]
    from agent_passport.core import execute_fields
    proof = coordinator["holder"].proof(coordinator["token"], "execute", execute_fields(*LOG_READ, "timeout"))
    oid = Executor(engine, service=UncertainService()).execute(coordinator["token"], *LOG_READ, "timeout", proof)["operation_id"]
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    body = {"outcome": "not_executed", "reason": REASON}
    bearer = {"Authorization": f"Bearer {coordinator['token']}"}
    assert client.post(f"/api/operations/{oid}/reconcile", json=body, headers=bearer).status_code == 403
    assert client.get("/api/operations/unresolved", headers=bearer).status_code == 403
    assert client.post("/api/agent/reconcile", json=body, headers=bearer).status_code in (404, 405)
    assert [o["id"] for o in client.get("/api/operations/unresolved", headers=console).json()["operations"]] == [oid]
    assert client.post(f"/api/operations/{oid}/reconcile", json={**body, "extra": 1}, headers=console).status_code == 422
    response = client.post(f"/api/operations/{oid}/reconcile", json=body, headers=console)
    assert response.status_code == 200 and response.json()["state"] == "reconciled_not_executed"
    assert client.post(f"/api/operations/{oid}/reconcile", json=body, headers=console).status_code == 404
    assert client.get("/api/evidence", headers=console).json()["reconciliations"][0]["body"]["operation_id"] == oid


def test_cli_lists_and_decides(tmp_path, capsys):
    engine = Passport(tmp_path)
    root, oid = unknown_op(engine)
    assert reconcile_cli(["--state-dir", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["unresolved"][0]["id"] == oid
    assert reconcile_cli([oid, "--outcome", "not_executed", "--reason", "short", "--state-dir", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().err)["rule"] == "REASON_REQUIRED"
    assert reconcile_cli([oid, "--outcome", "not_executed", "--reason", REASON, "--operator", "On-call", "--state-dir", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["receipt"]["body"]["decided_by"] == "On-call"
    assert engine.unresolved() == []
