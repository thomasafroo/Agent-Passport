"""Cross-feature authorization behavior, with synthetic upstreams only."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from agent_passport.broker import Executor
from agent_passport.core import Denied, Passport

CONFIG = ("staging/checkout", "config.write")
REASON = "Operator reviewed the staging change request."


class Service:
    def __init__(self):
        self.calls = []

    def execute(self, credential, resource, action, operation_id=None):
        self.calls.append(operation_id)
        return {"synthetic": True}


@pytest.mark.parametrize("approved", [False, True])
def test_owner_cut_withdraws_all_waiting_work_once_and_preserves_other_owners(tmp_path, approved):
    engine = Passport(tmp_path)
    owner = engine.provision_owner("departing", "Departing operator")["owner"]["id"]
    service = Service()
    executor = Executor(engine, service=service)
    roots = [engine.create_run(owner=owner, budget=1) for _ in range(2)]
    other = engine.create_run(budget=1)
    unaffected = executor.execute(other["token"], *CONFIG, "change")["operation_id"]
    waiting = []
    for root in roots:
        worker = engine.delegate(root["token"], "Worker", [{"resource": CONFIG[0], "action": CONFIG[1]}], root["grant"]["expires"])
        oid = executor.execute(worker["token"], *CONFIG, "change")["operation_id"]
        if approved:
            engine.decide_approval(oid, "approve", REASON)
        waiting.append((root, worker, oid))
    engine.deprovision_owner(owner)
    # Immediate cancellation, without relying on a listing, retry, or expiry sweep.
    for root, worker, oid in waiting:
        assert engine.operation(oid)["state"] == "cancelled"
        run = engine.snapshot(root["run_id"])["run"]
        assert (run["reserved"], run["spent"]) == (0, 0)
        for decision in ("approve", "deny"):
            with pytest.raises(Denied) as error:
                engine.decide_approval(oid, decision, REASON)
            assert error.value.rule == "OPERATION_STATE"
        assert engine.dispatch(oid) is False
    engine.deprovision_owner(owner)
    engine.reactivate_owner(owner)
    engine.pending_approvals()
    for root, worker, oid in waiting:
        with pytest.raises(Denied) as error:
            executor.execute(worker["token"], *CONFIG, "change")
        assert error.value.rule == "OWNER_DEPROVISIONED"
        snapshot = engine.snapshot(root["run_id"])
        assert (snapshot["run"]["reserved"], snapshot["run"]["spent"]) == (0, 0)
        assert len([e for e in snapshot["events"] if e.get("operation_id") == oid and e["rule"] == "OWNER_DEPROVISIONED"]) == 1
    assert service.calls == []
    assert engine.operation(unaffected)["state"] == "awaiting_approval"
    engine.decide_approval(unaffected, "approve", REASON)
    assert executor.execute(other["token"], *CONFIG, "change")["state"] == "completed"
    assert service.calls == [unaffected]


def test_approval_and_owner_cut_race_never_leaves_dispatchable_work(tmp_path):
    engine = Passport(tmp_path)
    root = engine.create_run(budget=1)
    oid = engine.reserve(root["token"], *CONFIG, "race")["id"]
    barrier = threading.Barrier(2)

    def approve():
        barrier.wait()
        try:
            engine.decide_approval(oid, "approve", REASON)
            return "approved"
        except Denied as error:
            return error.rule

    def cut():
        barrier.wait()
        engine.deprovision_owner(root["grant"]["owner"])

    with ThreadPoolExecutor(2) as pool:
        decision, deprovision = pool.submit(approve), pool.submit(cut)
        assert decision.result() in {"approved", "OPERATION_STATE"}
        deprovision.result()
    assert engine.operation(oid)["state"] == "cancelled"
    assert engine.dispatch(oid) is False
    assert engine.snapshot(root["run_id"])["run"]["reserved"] == 0


def test_approved_dispatch_racing_owner_cut_obeys_commit_order(tmp_path):
    engine = Passport(tmp_path)
    root = engine.create_run(budget=1)
    oid = engine.reserve(root["token"], *CONFIG, "race")["id"]
    engine.decide_approval(oid, "approve", REASON)
    barrier = threading.Barrier(2)

    def dispatch():
        barrier.wait()
        return engine.dispatch(oid)

    def cut():
        barrier.wait()
        engine.deprovision_owner(root["grant"]["owner"])

    with ThreadPoolExecutor(2) as pool:
        dispatched, deprovision = pool.submit(dispatch), pool.submit(cut)
        admitted = dispatched.result()
        deprovision.result()
    assert engine.operation(oid)["state"] == ("dispatched" if admitted else "cancelled")
    assert engine.snapshot(root["run_id"])["run"]["reserved"] == int(admitted)
    if admitted:
        engine.settle(oid, "completed", {"synthetic": True})
        assert engine.snapshot(root["run_id"])["run"]["spent"] == 1
    assert engine.dispatch(oid) is False
