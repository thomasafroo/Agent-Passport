"""Reconciliation from the upstream's own effect record, with fencing for missing effects."""
import copy
import hashlib
import json
import sqlite3

from fastapi.testclient import TestClient
import pytest

from agent_passport.broker import CredentialUnavailable, DemoCredentials, EffectFenced, EffectLog, Executor, FixtureService
from agent_passport.core import Passport, Denied, STRANDED_AFTER, canonical, execute_fields, verify_receipt
from agent_passport.server import create_app
from scripts.reconcile import main as reconcile_cli
from scripts.verify_evidence import verify

LOG_READ = ("staging/checkout", "logs.read")
KEY_DIGEST = hashlib.sha256(DemoCredentials().resolve().encode()).hexdigest()


class TimeoutAfterEffect(FixtureService):
    """The effect lands upstream, then the response is lost."""
    def execute(self, credential, resource, action, operation_id=None):
        super().execute(credential, resource, action, operation_id)
        raise TimeoutError("response lost after the effect")


class TimeoutBeforeEffect(FixtureService):
    """The request never reaches the upstream, but the executor cannot tell."""
    def execute(self, credential, resource, action, operation_id=None):
        raise TimeoutError("request lost before the effect")


class NoLookup:
    def execute(self, *args):
        raise TimeoutError("unknown")


@pytest.fixture
def clock():
    return [10_000.0]


@pytest.fixture
def engine(tmp_path, clock):
    return Passport(tmp_path, clock=lambda: clock[0])


@pytest.fixture
def effects(tmp_path):
    return EffectLog(tmp_path / "fixture-effects.db")


def rows(effects):
    db = sqlite3.connect(effects.path)
    try:
        return {r[0]: r[1] for r in db.execute("SELECT operation_id, state FROM effects")}
    finally:
        db.close()


def unknown_op(engine, service, budget=2, key="timeout"):
    root = engine.create_run(budget=budget)
    result = Executor(engine, service=service).execute(root["token"], *LOG_READ, key)
    assert result["state"] == "unknown"
    return root, result["operation_id"]


def balance(engine, root):
    run = engine.snapshot(root["run_id"])["run"]
    return run["spent"], run["reserved"]


def assert_denied(rule, fn):
    with pytest.raises(Denied) as error:
        fn()
    assert error.value.rule == rule


def test_completed_operations_leave_an_effect_record_under_their_id(engine):
    root = engine.create_run()
    executor = Executor(engine)
    oid = executor.execute(root["token"], *LOG_READ, "k")["operation_id"]
    assert rows(executor.service.effects) == {oid: "applied"}


def test_upstream_idempotency_applies_an_id_once(effects):
    service = FixtureService(KEY_DIGEST, effects)
    credential = DemoCredentials().resolve()
    first = service.execute(credential, *LOG_READ, "op_same")
    assert service.execute(credential, *LOG_READ, "op_same") == first
    assert rows(effects) == {"op_same": "applied"}


def test_lost_response_after_the_effect_reconciles_as_completed(engine, effects):
    service = TimeoutAfterEffect(KEY_DIGEST, effects)
    root, oid = unknown_op(engine, service)
    assert balance(engine, root) == (0, 1)
    result = Executor(engine, service=service).resolve(oid)
    assert result["state"] == "reconciled_completed" and balance(engine, root) == (1, 0)
    body = result["receipt"]["body"]
    assert body["basis"]["found"] and body["decided_by"] == "Upstream effect lookup" and body["cost"] == 1
    expected = hashlib.sha256(canonical(FixtureService._respond(*LOG_READ))).hexdigest()
    assert body["basis"]["result_digest"] == expected
    assert verify_receipt(result["receipt"], engine.public_key)


def test_lost_request_is_fenced_then_returned(engine, effects):
    service = TimeoutBeforeEffect(KEY_DIGEST, effects)
    root, oid = unknown_op(engine, service)
    result = Executor(engine, service=service).resolve(oid)
    assert result["state"] == "reconciled_not_executed" and balance(engine, root) == (0, 0)
    assert result["receipt"]["body"]["basis"] == {"source": "upstream_effect_record", "found": False}
    # The delayed request finally arrives upstream. The fence refuses it, so the refund stays sound.
    with pytest.raises(EffectFenced):
        FixtureService(KEY_DIGEST, effects).execute(DemoCredentials().resolve(), *LOG_READ, oid)
    assert rows(effects) == {oid: "fenced"}


def test_crash_after_the_effect_is_found_once_the_stranded_guard_passes(engine, effects, clock):
    service = FixtureService(KEY_DIGEST, effects)
    root = engine.create_run(budget=1)
    op = engine.reserve(root["token"], *LOG_READ, "crash")
    assert engine.dispatch(op["id"])
    service.execute(DemoCredentials().resolve(), *LOG_READ, op["id"])  # the executor then dies before settling
    executor = Executor(engine, service=service)
    assert_denied("OPERATION_IN_FLIGHT", lambda: executor.resolve(op["id"]))
    assert rows(effects) == {op["id"]: "applied"}
    clock[0] += STRANDED_AFTER
    assert executor.resolve(op["id"])["state"] == "reconciled_completed"
    assert_denied("OPERATION_STATE", lambda: engine.settle(op["id"], "completed", {}))
    assert balance(engine, root) == (1, 0)


def test_the_in_flight_guard_writes_no_fence(engine, effects):
    root = engine.create_run(budget=1)
    op = engine.reserve(root["token"], *LOG_READ, "young")
    assert_denied("OPERATION_IN_FLIGHT", lambda: Executor(engine, service=FixtureService(KEY_DIGEST, effects)).resolve(op["id"]))
    assert rows(effects) == {}
    # The executor can still finish normally.
    assert Executor(engine, service=FixtureService(KEY_DIGEST, effects)).execute_reserved(op)["state"] == "completed"


def test_a_lookup_decision_is_final(engine, effects):
    service = TimeoutBeforeEffect(KEY_DIGEST, effects)
    root, oid = unknown_op(engine, service)
    executor = Executor(engine, service=service)
    executor.resolve(oid)
    assert_denied("OPERATION_STATE", lambda: executor.resolve(oid))
    assert_denied("OPERATION_STATE", lambda: engine.reconcile(oid, "completed", "Second opinion from an operator."))
    retry = Executor(engine, service=service).execute(root["token"], *LOG_READ, "timeout")
    assert retry["duplicate"] and retry["state"] == "reconciled_not_executed"


class BrokenProvider:
    mode = "synthetic"

    def resolve(self, *pair):
        raise CredentialUnavailable("secret-bearing detail")


@pytest.mark.parametrize("make,rule", [
    (lambda effects: (NoLookup(), None), "LOOKUP_UNSUPPORTED"),
    (lambda effects: (TimeoutBeforeEffect(KEY_DIGEST, effects), BrokenProvider()), "LOOKUP_FAILED"),
    (lambda effects: (TimeoutBeforeEffect("0" * 64, effects), None), "LOOKUP_FAILED"),
])
def test_failed_lookups_keep_the_unit_and_write_no_fence(engine, effects, make, rule):
    service, provider = make(effects)
    root, oid = unknown_op(engine, service)
    with pytest.raises(Denied) as error:
        Executor(engine, provider=provider, service=service).resolve(oid)
    assert error.value.rule == rule and "secret" not in error.value.detail
    assert balance(engine, root) == (0, 1) and rows(effects) == {}


def test_a_mismatched_record_is_not_trusted(engine, effects):
    service = TimeoutBeforeEffect(KEY_DIGEST, effects)
    root, oid = unknown_op(engine, service)
    FixtureService(KEY_DIGEST, effects).execute(DemoCredentials().resolve(), "repo/checkout", "code.read", oid)
    assert_denied("EFFECT_MISMATCH", lambda: Executor(engine, service=service).resolve(oid))
    assert balance(engine, root) == (0, 1)


def test_lookup_reconciliations_verify_offline_and_the_basis_is_signed(engine, effects):
    service = TimeoutAfterEffect(KEY_DIGEST, effects)
    root, oid = unknown_op(engine, service)
    Executor(engine, service=service).resolve(oid)
    evidence = engine.evidence(root["run_id"])
    assert verify(evidence, engine.public_key)["reconciliations"] == 1
    altered = copy.deepcopy(evidence); altered["reconciliations"][0]["body"]["basis"]["found"] = False
    with pytest.raises(ValueError, match="reconciliation"):
        verify(altered, engine.public_key)


def test_only_the_console_can_request_a_lookup(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    app = create_app(tmp_path)
    client = TestClient(app)
    demo, engine = app.state.demo, app.state.passport
    coordinator = demo.agents["Coordinator"]
    proof = coordinator["holder"].proof(coordinator["token"], "execute", execute_fields(*LOG_READ, "timeout"))
    service = TimeoutBeforeEffect(KEY_DIGEST, app.state.executor.service.effects)
    oid = Executor(engine, service=service).execute(coordinator["token"], *LOG_READ, "timeout", proof)["operation_id"]
    bearer = {"Authorization": f"Bearer {coordinator['token']}"}
    assert client.post(f"/api/operations/{oid}/lookup", headers=bearer).status_code == 403
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    assert client.post("/api/operations/op_missing/lookup", headers=console).status_code == 404
    response = client.post(f"/api/operations/{oid}/lookup", headers=console)
    assert response.status_code == 200 and response.json()["state"] == "reconciled_not_executed"
    assert client.post(f"/api/operations/{oid}/lookup", headers=console).status_code == 404


def test_cli_lookup(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    engine = Passport(tmp_path)
    root, oid = unknown_op(engine, TimeoutAfterEffect(KEY_DIGEST, EffectLog(tmp_path / "fixture-effects.db")))
    with pytest.raises(SystemExit):
        reconcile_cli([oid, "--lookup", "--outcome", "completed", "--state-dir", str(tmp_path)])
    capsys.readouterr()
    assert reconcile_cli([oid, "--lookup", "--state-dir", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "reconciled_completed"
    assert reconcile_cli([oid, "--lookup", "--state-dir", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().err)["rule"] == "OPERATION_STATE"
