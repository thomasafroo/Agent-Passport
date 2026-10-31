"""Reproducible local measurements; not a distributed revocation claim."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.core import Passport, Denied, Holder, execute_fields
from agent_passport.broker import Executor
from agent_passport.demo import LOGS


def main():
    with tempfile.TemporaryDirectory() as directory:
        engine = Passport(directory); executor = Executor(engine)
        root = engine.create_run(budget=10)
        agents = [engine.delegate(root["token"], f"Fork {i}", LOGS, root["grant"]["expires"]) for i in range(100)]
        latencies = []
        def work(agent):
            start = time.perf_counter_ns()
            try:
                result = executor.execute(agent["token"], "staging/checkout", "logs.read", "attempt")["state"]
            except Denied as e:
                result = e.rule
            return result, (time.perf_counter_ns() - start) / 1e6
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=32) as pool: results = list(pool.map(work, agents))
        concurrent_ms = (time.perf_counter() - start) * 1000
        counts = {status: sum(r[0] == status for r in results) for status in sorted({r[0] for r in results})}
        assert counts == {"BUDGET_EXHAUSTED":90, "completed":10}
        latency_root = engine.create_run(budget=250)
        for i in range(200):
            start = time.perf_counter_ns()
            op = engine.reserve(latency_root["token"], "staging/checkout", "logs.read", str(i))
            latencies.append((time.perf_counter_ns() - start) / 1e6)
            engine.dispatch(op["id"]); engine.settle(op["id"], "completed", {})
        # Same measurement for a key-bound passport. The proof is signed before the timer starts;
        # the timed call includes proof verification and the single-use nonce write.
        holder = Holder(); bound_root = engine.create_run(budget=250, holder_key=holder.public_key)
        bound_latencies = []
        for i in range(200):
            proof = holder.proof(bound_root["token"], "execute", execute_fields("staging/checkout", "logs.read", str(i)))
            start = time.perf_counter_ns()
            op = engine.reserve(bound_root["token"], "staging/checkout", "logs.read", str(i), proof)
            bound_latencies.append((time.perf_counter_ns() - start) / 1e6)
            engine.dispatch(op["id"]); engine.settle(op["id"], "completed", {})
        revoke_latencies = []
        for _ in range(30):
            branch = engine.delegate(latency_root["token"], "Revocation probe", LOGS, latency_root["grant"]["expires"])
            start = time.perf_counter_ns(); engine.revoke(branch["grant"]["id"])
            try: engine.reserve(branch["token"], "staging/checkout", "logs.read", "after-revoke")
            except Denied as e: assert e.rule == "ANCESTOR_REVOKED"
            else: raise AssertionError("Revocation failed")
            revoke_latencies.append((time.perf_counter_ns() - start) / 1e6)
        # Deliberately broken check-then-act model: all threads read before any writes.
        barrier = threading.Barrier(32); naive = {"spent":0}; lock = threading.Lock()
        def unsafe(_):
            allowed = naive["spent"] < 10
            barrier.wait()
            if allowed:
                with lock: naive["spent"] += 1
        with ThreadPoolExecutor(max_workers=32) as pool: list(pool.map(unsafe, range(32)))
        def summary(samples):
            ordered = sorted(samples)
            return {"samples":len(samples), "median_ms":round(statistics.median(samples),3), "p95_ms":round(ordered[int(len(ordered)*.95)-1],3), "max_ms":round(max(samples),3)}
        report = {"environment":{"python":platform.python_version(),"os":platform.platform(),"storage":"local SQLite WAL, synchronous default","worker_threads":32},
                  "protected":{"agents":100,"budget":10,"outcomes":counts,"elapsed_ms":round(concurrent_ms,2)},
                  "naive_check_then_act":{"workers":32,"budget":10,"actual_spent":naive["spent"],"scheduling":"barrier forces worst-case concurrent reads; deliberately unsafe comparison"},
                  "authorization_and_reservation":summary(latencies), "bound_authorization_and_reservation":summary(bound_latencies), "revoke_call_to_observed_denial":summary(revoke_latencies),
                  "limits":"Single host. Includes local DB opening, transaction and audit costs. No network partitions or distributed caches. Timing is not a guaranteed latency bound."}
        destination = Path("artifacts/benchmark.json"); destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
