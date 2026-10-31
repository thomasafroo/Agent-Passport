from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import copy
import json
import threading

import pytest

from agent_passport.broker import Executor, CredentialUnavailable
from agent_passport.core import Passport, Denied, verify_receipt, unb64, b64, canonical
from agent_passport.demo import LOGS, CODE, Demo


@pytest.fixture
def engine(tmp_path):
    return Passport(tmp_path)


def child(engine, root, scopes=LOGS, name="Worker", expires=None):
    return engine.delegate(root["token"], name, scopes, expires or root["grant"]["expires"])


def call(engine, agent, key="test"):
    return Executor(engine).execute(agent["token"], "staging/checkout", "logs.read", key)


def assert_denied(rule, fn):
    with pytest.raises(Denied) as error:
        fn()
    assert error.value.rule == rule


def test_signed_identity_rejects_changed_subject(engine):
    root = engine.create_run()
    body, signature = root["token"].split(".")
    claims = json.loads(unb64(body)); claims["subject"] = "Admin"
    assert_denied("IDENTITY_INVALID", lambda: Executor(engine).execute(b64(canonical(claims)) + "." + signature, "staging/checkout", "logs.read", "x"))


@pytest.mark.parametrize("token", ["", "broken", "a.b.c", "!!!.???", None, "x" * 13000])
def test_malformed_tokens_fail_closed(engine, token):
    assert_denied("IDENTITY_INVALID", lambda: engine.reserve(token, "staging/checkout", "logs.read", "x"))


def test_other_issuer_is_not_trusted(engine, tmp_path):
    other = Passport(tmp_path / "other")
    assert_denied("IDENTITY_INVALID", lambda: call(engine, other.create_run()))


@pytest.mark.parametrize("scopes", [[{"resource":"production/checkout","action":"deploy.execute"}], CODE,
                                   [{"resource":"staging/checkout","action":"*"}],
                                   [{"resource":"staging/*","action":"logs.read"}]])
def test_delegation_can_only_shrink(engine, scopes):
    root = engine.create_run(); worker = child(engine, root)
    assert_denied("SCOPE_ESCALATION", lambda: child(engine, worker, scopes))
    assert engine.snapshot(root["run_id"])["events"][-1]["kind"] == "denied"


def test_pairs_are_not_cartesian_products(engine):
    root = engine.create_run()
    assert_denied("RESOURCE_ACTION_DENIED", lambda: Executor(engine).execute(root["token"], "repo/checkout", "logs.read", "x"))


def test_child_cannot_extend_expiry(engine):
    root = engine.create_run()
    assert_denied("EXPIRY_ESCALATION", lambda: child(engine, root, expires=root["grant"]["expires"] + 1))


def test_expiry_is_enforced_after_restart(tmp_path):
    engine = Passport(tmp_path, clock=lambda: 1000)
    root = engine.create_run(ttl=5)
    restarted = Passport(tmp_path, clock=lambda: 1005)
    assert_denied("GRANT_EXPIRED", lambda: call(restarted, root))


def test_revocation_cascades_but_sibling_completes(engine):
    root = engine.create_run(); compromised = child(engine, root); grandchild = child(engine, compromised)
    sibling = child(engine, root, name="Unaffected")
    engine.revoke(compromised["grant"]["id"])
    assert_denied("ANCESTOR_REVOKED", lambda: call(engine, grandchild))
    assert_denied("ANCESTOR_REVOKED", lambda: child(engine, compromised))
    assert call(engine, sibling)["state"] == "completed"
    states = {g["id"]: g["state"] for g in engine.snapshot(root["run_id"])["grants"]}
    assert states[grandchild["grant"]["id"]] == "revoked"
    assert states[sibling["grant"]["id"]] == "active"


def test_queued_work_is_rechecked_and_refunded(engine):
    root = engine.create_run(); worker = child(engine, root)
    op = engine.reserve(worker["token"], "staging/checkout", "logs.read", "queued")
    engine.revoke(root["grant"]["id"])
    assert_denied("ANCESTOR_REVOKED", lambda: engine.dispatch(op["id"]))
    run = engine.snapshot(root["run_id"])["run"]
    assert run["reserved"] == run["spent"] == 0
    assert engine.dispatch(op["id"]) is False


def test_queued_expiry_refunds(tmp_path):
    now = [1000]
    engine = Passport(tmp_path, clock=lambda: now[0]); root = engine.create_run(ttl=5)
    op = engine.reserve(root["token"], "staging/checkout", "logs.read", "queued")
    now[0] = 1006
    assert_denied("GRANT_EXPIRED", lambda: engine.dispatch(op["id"]))
    assert engine.snapshot(root["run_id"])["run"]["reserved"] == 0


def test_concurrent_forks_cannot_multiply_budget(engine):
    root = engine.create_run(budget=10)
    agents = [child(engine, root, name=f"Fork {i}") for i in range(64)]
    def work(agent):
        try: return call(engine, agent)["state"]
        except Denied as e: return e.rule
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(work, agents))
    assert results.count("completed") == 10
    assert results.count("BUDGET_EXHAUSTED") == 54
    run = engine.snapshot(root["run_id"])["run"]
    assert run["spent"] == 10 and run["reserved"] == 0


def process_reserve(args):
    directory, token, index = args
    engine = Passport(directory)
    try:
        engine.reserve(token, "staging/checkout", "logs.read", str(index))
        return "reserved"
    except Denied as e:
        return e.rule


def test_budget_is_shared_across_processes(engine):
    root = engine.create_run(budget=7)
    with ProcessPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(process_reserve, [(str(engine.directory), root["token"], i) for i in range(30)]))
    assert results.count("reserved") == 7
    assert results.count("BUDGET_EXHAUSTED") == 23


def test_concurrent_retries_execute_once(engine):
    root = engine.create_run()
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: call(engine, root, "same-key"), range(50)))
    assert len({r["operation_id"] for r in results}) == 1
    assert engine.snapshot(root["run_id"])["run"]["spent"] == 1


def test_key_is_bound_to_exact_operation(engine):
    root = engine.create_run(); call(engine, root)
    assert_denied("IDEMPOTENCY_CONFLICT", lambda: Executor(engine).execute(root["token"], "repo/checkout", "code.read", "test"))


def test_revoked_retry_does_not_return_cached_result(engine):
    root = engine.create_run(); call(engine, root)
    engine.revoke(root["grant"]["id"])
    assert_denied("ANCESTOR_REVOKED", lambda: call(engine, root))


def test_crash_reservation_survives_restart(engine):
    root = engine.create_run(budget=1)
    engine.reserve(root["token"], "staging/checkout", "logs.read", "crashed")
    restarted = Passport(engine.directory)
    assert_denied("BUDGET_EXHAUSTED", lambda: call(restarted, root, "new"))
    duplicate = call(restarted, root, "crashed")
    assert duplicate["state"] == "reserved" and duplicate["duplicate"]


def test_known_failure_refunds_without_leaking_secret(engine):
    class BrokenProvider:
        def resolve(self): raise CredentialUnavailable("sensitive-secret-in-error")
    root = engine.create_run(budget=1)
    result = Executor(engine, provider=BrokenProvider()).execute(root["token"], "staging/checkout", "logs.read", "failure")
    assert result["state"] == "failed"
    assert "sensitive-secret" not in json.dumps(result)
    assert engine.snapshot(root["run_id"])["run"]["reserved"] == 0
    assert call(engine, root, "retry-new-key")["state"] == "completed"


def test_unknown_effect_retains_budget_and_disables_retry(engine):
    class UncertainService:
        def execute(self, *args): raise TimeoutError("unknown upstream effect")
    root = engine.create_run(budget=1)
    result = Executor(engine, service=UncertainService()).execute(root["token"], "staging/checkout", "logs.read", "timeout")
    assert result["state"] == "unknown"
    assert engine.snapshot(root["run_id"])["run"]["reserved"] == 1
    assert call(engine, root, "timeout")["state"] == "unknown"
    assert_denied("BUDGET_EXHAUSTED", lambda: call(engine, root, "new"))


def test_revocation_does_not_undo_dispatched_operation(engine):
    root = engine.create_run(); op = engine.reserve(root["token"], "staging/checkout", "logs.read", "inflight")
    assert engine.dispatch(op["id"])
    engine.revoke(root["grant"]["id"])
    engine.settle(op["id"], "completed", {"done": True})
    assert engine.snapshot(root["run_id"])["run"]["spent"] == 1


def test_only_one_dispatch_and_settlement(engine):
    root = engine.create_run(); op = engine.reserve(root["token"], "staging/checkout", "logs.read", "x")
    assert engine.dispatch(op["id"]) is True
    assert engine.dispatch(op["id"]) is False
    engine.settle(op["id"], "failed", {})
    assert_denied("OPERATION_STATE", lambda: engine.settle(op["id"], "failed", {}))
    assert engine.snapshot(root["run_id"])["run"]["reserved"] == 0


def test_signed_receipts_detect_alteration(engine):
    root = engine.create_run(); receipt = call(engine, root)["receipt"]
    assert verify_receipt(receipt, engine.public_key)
    changed = copy.deepcopy(receipt); changed["body"]["resource"] = "production/checkout"
    assert not verify_receipt(changed, engine.public_key)


def test_snapshot_contains_no_bearer_tokens_or_credentials(engine):
    root = engine.create_run(); call(engine, root)
    data = json.dumps(engine.evidence(root["run_id"]))
    assert root["token"] not in data
    assert "synthetic-staging-key" not in data


def test_demo_completes_and_fork_results_are_actual(engine):
    demo = Demo(engine, Executor(engine))
    for _ in range(4): demo.step()
    snapshot = demo.snapshot()
    assert snapshot["phase"] == "finished"
    assert snapshot["metrics"]["unrelated_branch_completed"]
    assert {e["rule"] for e in snapshot["events"]} >= {"SCOPE_ESCALATION", "RESOURCE_ACTION_DENIED", "ANCESTOR_REVOKED"}
    report = demo.fork()["metrics"]["fork"]
    assert report["completed"] == report["available_before"] == 21
    assert report["denied"] == 11
    assert report["spent_after"] == report["budget"] == 24


def test_invalid_scope_types_are_rejected(engine):
    root = engine.create_run()
    for scope in [[], None, [{"resource": {}, "action": "logs.read"}], [{}]]:
        assert_denied("SCOPE_INVALID", lambda: child(engine, root, scope))


def test_depth_limit(engine):
    root = engine.create_run(); last = root
    for _ in range(8): last = child(engine, last)
    assert_denied("DELEGATION_LIMIT", lambda: child(engine, last))


def test_concurrent_revoke_orders_with_reservations(engine):
    root = engine.create_run(budget=100); barrier = threading.Barrier(17)
    def reserve(index):
        barrier.wait()
        try: return engine.reserve(root["token"], "staging/checkout", "logs.read", str(index))
        except Denied: return None
    with ThreadPoolExecutor(max_workers=17) as pool:
        futures = [pool.submit(reserve, i) for i in range(16)]
        barrier.wait(); engine.revoke(root["grant"]["id"])
        queued = [f.result() for f in futures]
    for op in filter(None, queued):
        assert_denied("ANCESTOR_REVOKED", lambda: engine.dispatch(op["id"]))
    assert engine.snapshot(root["run_id"])["run"]["reserved"] == 0


def test_concurrent_first_start_uses_one_complete_key(tmp_path):
    barrier = threading.Barrier(12)
    def initialize(_):
        barrier.wait()
        return Passport(tmp_path).public_key
    with ThreadPoolExecutor(max_workers=12) as pool:
        keys = list(pool.map(initialize, range(12)))
    assert len(set(keys)) == 1


def test_manual_containment_does_not_break_story(engine):
    demo = Demo(engine, Executor(engine)); demo.step()
    engine.revoke(demo.agents["Log reader"]["grant"]["id"])
    demo.step(); demo.step()
    assert demo.step()["metrics"]["unrelated_branch_completed"]


def test_manual_patch_revocation_never_claims_success(engine):
    demo = Demo(engine, Executor(engine)); demo.step(); demo.step(); demo.step()
    engine.revoke(demo.agents["Patch worker"]["grant"]["id"])
    result = demo.step()
    assert not result["metrics"]["unrelated_branch_completed"]
    assert "did not complete" in result["message"]
