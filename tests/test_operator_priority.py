"""An operator's cut gets the write lock ahead of sustained agent traffic.

SQLite does not queue writers fairly. Without the operator gate, tight reservation loops can
keep a revoke or deprovision waiting until the shared pool is empty. These tests pin the
gate's behavior: while an operator holds it, no new agent transaction starts; at most one
transaction per agent that had already passed it commits first; a crashed holder releases it;
and a gate that stays held fails an agent's transaction instead of letting it skip the gate.
"""
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from agent_passport import core
from agent_passport.core import Passport


LOG_READ = ("staging/checkout", "logs.read")
SCOPE = [{"resource": LOG_READ[0], "action": LOG_READ[1]}]

# Waits for "go" on stdin so every worker starts together, then reserves in a tight loop, with no
# pause, until denied. Prints "ready" once reservations flow.
WORKER = """
import sys
from agent_passport.core import Denied, Passport
engine, token, name = Passport(sys.argv[1]), sys.argv[2], sys.argv[3]
sys.stdin.readline()
for n in range(100000):
    try:
        engine.reserve(token, "staging/checkout", "logs.read", f"{name}-{n}")
    except Denied as e:
        print(e.rule, flush=True)
        break
    if n == 2:
        print("ready", flush=True)
"""

HOLDER = """
import sys, time
from agent_passport.core import OperatorGate
with OperatorGate(sys.argv[1]).hold():
    print("held", flush=True)
    time.sleep(120)
"""


def reserved_events(engine, run_id):
    return [e for e in engine.snapshot(run_id)["events"] if e["kind"] == "reserved"]


def start_workers(engine, root, count):
    workers = [engine.delegate(root["token"], f"Worker {i}", SCOPE, engine.clock() + 600) for i in range(count)]
    procs = [subprocess.Popen([sys.executable, "-c", WORKER, str(engine.directory), w["token"], f"w{i}"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) for i, w in enumerate(workers)]
    # Release all workers at once, so slow interpreter start-up cannot let early ones drain the pool.
    for p in procs:
        assert p.stdin is not None
        p.stdin.write("go\n")
        p.stdin.flush()
    for p in procs:
        assert p.stdout is not None and p.stdout.readline().strip() == "ready"
    return procs


def finish(procs):
    rules = []
    for p in procs:
        out, _ = p.communicate(timeout=60)
        rules.append(out.strip())
    return rules


def test_agent_transaction_waits_while_an_operator_holds_the_gate(tmp_path):
    engine = Passport(tmp_path)
    root = engine.create_run()
    done = threading.Event()

    def reserve():
        engine.reserve(root["token"], *LOG_READ, "k")
        done.set()

    with engine.gate.hold():
        t = threading.Thread(target=reserve)
        t.start()
        assert not done.wait(0.3)
        assert reserved_events(engine, root["run_id"]) == []
    assert done.wait(10)
    t.join()
    assert len(reserved_events(engine, root["run_id"])) == 1


def test_gate_that_stays_held_fails_the_agent_closed(tmp_path, monkeypatch):
    engine = Passport(tmp_path)
    root = engine.create_run()
    monkeypatch.setattr(core, "BUSY_TIMEOUT", 0.2)
    with engine.gate.hold():
        with pytest.raises(sqlite3.OperationalError):
            engine.reserve(root["token"], *LOG_READ, "k")
    assert reserved_events(engine, root["run_id"]) == []
    assert engine.snapshot(root["run_id"])["run"]["reserved"] == 0
    # Once released, the same request goes through normally.
    assert engine.reserve(root["token"], *LOG_READ, "k")["state"] == "reserved"


def test_crashed_holder_in_another_process_releases_the_gate(tmp_path):
    engine = Passport(tmp_path)
    root = engine.create_run()
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(engine.gate.path)], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "held"
        done = threading.Event()
        t = threading.Thread(target=lambda: (engine.reserve(root["token"], *LOG_READ, "k"), done.set()))
        t.start()
        assert not done.wait(0.3), "another process's gate must hold back this process's agents"
    finally:
        holder.kill()
        holder.wait()
    assert done.wait(10), "the OS must release the gate of a process that died holding it"
    t.join()


def test_operator_gate_admits_only_transactions_already_in_flight(tmp_path):
    engine = Passport(tmp_path)
    root = engine.create_run(budget=1000)
    procs = start_workers(engine, root, 4)
    try:
        with engine.gate.hold():
            at_hold = len(reserved_events(engine, root["run_id"]))
            time.sleep(0.5)
            settled = len(reserved_events(engine, root["run_id"]))
            time.sleep(0.5)
            # Each worker can have at most one transaction past the gate; none starts afterwards.
            assert settled - at_hold <= len(procs)
            assert len(reserved_events(engine, root["run_id"])) == settled
        engine.revoke(root["grant"]["id"])
    finally:
        rules = finish(procs)
    assert rules == ["ANCESTOR_REVOKED"] * len(procs)


@pytest.mark.parametrize("cut", ["revoke", "deprovision"])
def test_cut_under_unpaced_agent_processes_is_prompt_and_linearized(tmp_path, cut):
    engine = Passport(tmp_path)
    dana = engine.provision_owner("dana", "Dana")["owner"]
    root = engine.create_run(budget=1000, owner=dana["id"])
    procs = start_workers(engine, root, 8)
    try:
        started = time.monotonic()
        if cut == "revoke":
            engine.revoke(root["grant"]["id"])
        else:
            engine.deprovision_owner(dana["id"])
        waited = time.monotonic() - started
    finally:
        rules = finish(procs)
    # Every worker was stopped by the cut, not by an empty pool.
    expected = "ANCESTOR_REVOKED" if cut == "revoke" else "OWNER_DEPROVISIONED"
    assert rules == [expected] * len(procs)
    events = engine.snapshot(root["run_id"])["events"]
    cut_seq = next(e["seq"] for e in events if e["kind"] in ("revoked", "deprovisioned"))
    assert all(e["seq"] < cut_seq for e in events if e["kind"] == "reserved")
    run = engine.snapshot(root["run_id"])["run"]
    assert run["spent"] + run["reserved"] < run["budget"]
    # Generous for slow CI runners; without the gate the cut could wait out the 30-second busy timeout.
    assert waited < 10

