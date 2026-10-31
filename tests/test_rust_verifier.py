"""The Rust verifier in verifier-rs/ must reach the same verdict as scripts/verify_evidence.py.

Evidence comes from the Python engine. Each case runs both command-line verifiers on the
same files and compares exit codes, reports, and failure messages. The tests are skipped
when cargo is unavailable, unless AGENT_PASSPORT_RUST_VERIFIER names a built binary or
AGENT_PASSPORT_REQUIRE_RUST is set.
"""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys

import pytest

from agent_passport.broker import Executor
from agent_passport.core import Passport, b64, canonical

ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "verifier-rs"
PYTHON_VERIFIER = ROOT / "scripts" / "verify_evidence.py"
LOG_READ = ("staging/checkout", "logs.read")
REASON = "Upstream access log shows no request reached the service."
# Text that canonical() must escape: curly quotes, arrow, emoji (surrogate pair), DEL, line separator.
UNICODE_DETAIL = "Untrusted \u2018instruction\u2019 \u2192 denied \U0001F600 caf\u00e9 \x7f \u2028 \"q\" \\ /"


@pytest.fixture(scope="module")
def rust_verifier():
    configured = os.environ.get("AGENT_PASSPORT_RUST_VERIFIER")
    if configured:
        return Path(configured)
    cargo = shutil.which("cargo")
    if cargo is None:
        # CI sets AGENT_PASSPORT_REQUIRE_RUST so a missing toolchain cannot pass as a skip.
        assert not os.environ.get("AGENT_PASSPORT_REQUIRE_RUST"), "cargo is required but not installed"
        pytest.skip("cargo is not installed")
    build = subprocess.run([cargo, "build", "--release", "--locked", "--quiet", "--manifest-path", str(CRATE / "Cargo.toml")],
                           capture_output=True, text=True, timeout=900)
    assert build.returncode == 0, build.stderr
    name = "verify-evidence.exe" if sys.platform == "win32" else "verify-evidence"
    return CRATE / "target" / "release" / name


class UncertainService:
    def execute(self, *args):
        raise TimeoutError("unknown upstream effect")


@pytest.fixture
def scenario(tmp_path):
    """One run with operations, unicode text, a reconciliation and two checkpoints, plus a second run."""
    engine = Passport(tmp_path / "state")
    root = engine.create_run()
    run_id = root["run_id"]
    for i in range(2):
        Executor(engine).execute(root["token"], *LOG_READ, f"op-{i}")
    early = engine.checkpoint(run_id)
    with engine.transaction() as db:
        engine.event(db, run_id, "injected", root["grant"]["id"], "FIXTURE", UNICODE_DETAIL)
    unknown = Executor(engine, service=UncertainService()).execute(root["token"], *LOG_READ, "uncertain")
    assert unknown["state"] == "unknown"
    engine.reconcile(unknown["operation_id"], "not_executed", REASON)
    late = engine.checkpoint(run_id)
    other = engine.create_run()
    Executor(engine).execute(other["token"], *LOG_READ, "other-op")
    evidence = engine.evidence(run_id)
    assert evidence["reconciliations"] and len(evidence["receipts"]) >= 2
    assert any(e["detail"] == UNICODE_DETAIL for e in evidence["events"])
    return {"engine": engine, "run_id": run_id, "evidence": evidence, "checkpoints": [early, late],
            "other_evidence": engine.evidence(other["run_id"]), "other_checkpoint": engine.checkpoint(other["run_id"]),
            "tmp": tmp_path}


def run_cli(command):
    result = subprocess.run(command, capture_output=True, timeout=120)
    stdout, stderr = result.stdout.decode("utf-8"), result.stderr.decode("utf-8", "replace")
    if result.returncode == 0:
        return 0, json.loads(stdout)
    return result.returncode, stderr.strip().splitlines()[-1] if stderr.strip() else ""


def compare(rust_verifier, tmp, evidence, key, checkpoints=None, ascii_only=False):
    """Run both verifiers on the same files and require the same outcome."""
    evidence_file = tmp / "evidence.json"
    evidence_file.write_text(json.dumps(evidence, ensure_ascii=ascii_only, indent=2), encoding="utf-8")
    key_file = tmp / "issuer-public-key.txt"
    key_file.write_text(key + "\n", encoding="utf-8")
    args = [str(evidence_file), "--public-key-file", str(key_file)]
    if checkpoints is not None:
        witness = tmp / "witness.jsonl"
        witness.write_text("".join(json.dumps(c) + "\n" for c in checkpoints), encoding="utf-8")
        args += ["--checkpoints", str(witness)]
    python = run_cli([sys.executable, str(PYTHON_VERIFIER), *args])
    rust = run_cli([str(rust_verifier), *args])
    assert rust == python
    return python


def expect_failure(outcome, message):
    code, detail = outcome
    assert code == 1 and detail == f"Verification failed: {message}", outcome


def rechain(events, start=0):
    """What a database owner without the issuer key can still do: recompute every hash."""
    previous = events[start - 1]["hash"] if start else "0" * 64
    for event in events[start:]:
        event["previous"] = previous
        body = {k: v for k, v in event.items() if k not in {"seq", "hash"}}
        event["hash"] = previous = hashlib.sha256(canonical(body)).hexdigest()
    return events


def sign(engine, body):
    return {"body": body, "signature": b64(engine.key.sign(canonical(body)))}


def test_valid_evidence_gives_identical_reports(rust_verifier, scenario):
    s, key = scenario, scenario["engine"].public_key
    code, report = compare(rust_verifier, s["tmp"], s["evidence"], key)
    assert isinstance(report, dict)
    assert code == 0 and report["reconciliations"] == 1 and report["anchored_events"] == 0
    code, report = compare(rust_verifier, s["tmp"], s["evidence"], key, s["checkpoints"])
    assert isinstance(report, dict)
    assert code == 0 and report["checkpoints"] == 2
    assert report["anchored_events"] == s["checkpoints"][1]["body"]["size"]
    # ASCII-escaped and UTF-8 exports of the same evidence verify alike.
    assert compare(rust_verifier, s["tmp"], s["evidence"], key, s["checkpoints"], ascii_only=True) == (code, report)


def test_changed_and_reordered_events_fail_alike(rust_verifier, scenario):
    s, key = scenario, scenario["engine"].public_key
    changed = copy.deepcopy(s["evidence"]); changed["events"][1]["detail"] = "Changed"
    expect_failure(compare(rust_verifier, s["tmp"], changed, key), "Event chain is altered or reordered")
    reordered = copy.deepcopy(s["evidence"]); reordered["events"].reverse()
    expect_failure(compare(rust_verifier, s["tmp"], reordered, key), "Event chain is altered or reordered")
    unicode = copy.deepcopy(s["evidence"])
    event = next(e for e in unicode["events"] if e["detail"] == UNICODE_DETAIL)
    event["detail"] = UNICODE_DETAIL.replace("\U0001F600", "\U0001F601")
    expect_failure(compare(rust_verifier, s["tmp"], unicode, key), "Event chain is altered or reordered")


def test_dropped_suffix_passes_unanchored_and_fails_with_a_checkpoint(rust_verifier, scenario):
    s, key = scenario, scenario["engine"].public_key
    dropped = copy.deepcopy(s["evidence"]); dropped["events"].pop()
    code, report = compare(rust_verifier, s["tmp"], dropped, key)
    assert isinstance(report, dict)
    assert code == 0 and "completeness" in report["limitation"]
    expect_failure(compare(rust_verifier, s["tmp"], dropped, key, s["checkpoints"]),
                   "Evidence is missing events that a checkpoint covers")


def test_recomputed_chain_fails_only_with_a_checkpoint(rust_verifier, scenario):
    s, key = scenario, scenario["engine"].public_key
    rewritten = copy.deepcopy(s["evidence"]); rewritten["events"][1]["detail"] = "Rewritten"
    rechain(rewritten["events"])
    assert compare(rust_verifier, s["tmp"], rewritten, key)[0] == 0
    expect_failure(compare(rust_verifier, s["tmp"], rewritten, key, s["checkpoints"]),
                   "Event history differs from a checkpoint")


def test_altered_receipts_fail_alike(rust_verifier, scenario):
    s, key = scenario, scenario["engine"].public_key
    altered = copy.deepcopy(s["evidence"]); altered["receipts"][0]["body"]["outcome"] = "failed"
    expect_failure(compare(rust_verifier, s["tmp"], altered, key), "Invalid receipt signature")
    altered = copy.deepcopy(s["evidence"]); altered["receipts"][0]["signature"] = altered["receipts"][1]["signature"]
    expect_failure(compare(rust_verifier, s["tmp"], altered, key), "Invalid receipt signature")
    altered = copy.deepcopy(s["evidence"]); altered["reconciliations"][0]["body"]["previous_state"] = "reserved"
    expect_failure(compare(rust_verifier, s["tmp"], altered, key), "Invalid reconciliation signature")


def test_signed_statements_cannot_pose_as_each_other(rust_verifier, scenario):
    s, key = scenario, scenario["engine"].public_key
    receipt, reconciliation = s["evidence"]["receipts"][0], s["evidence"]["reconciliations"][0]
    expect_failure(compare(rust_verifier, s["tmp"], s["evidence"], key, [receipt]), "Invalid checkpoint signature")
    expect_failure(compare(rust_verifier, s["tmp"], s["evidence"], key, [reconciliation]), "Invalid checkpoint signature")
    for kind, imposter, message in [("receipts", s["checkpoints"][0], "Invalid receipt signature"),
                                    ("receipts", reconciliation, "Invalid receipt signature"),
                                    ("reconciliations", receipt, "Invalid reconciliation signature"),
                                    ("reconciliations", s["checkpoints"][0], "Invalid reconciliation signature")]:
        posed = copy.deepcopy(s["evidence"]); posed[kind].append(imposter)
        expect_failure(compare(rust_verifier, s["tmp"], posed, key), message)


def test_wrong_key_fails_alike(rust_verifier, scenario):
    s = scenario
    stranger = Passport(s["tmp"] / "stranger")
    expect_failure(compare(rust_verifier, s["tmp"], s["evidence"], stranger.public_key), "Issuer does not match pinned key")
    claimed = copy.deepcopy(s["evidence"]); claimed["public_key"] = stranger.public_key
    expect_failure(compare(rust_verifier, s["tmp"], claimed, stranger.public_key), "Invalid receipt signature")
    foreign = sign(stranger, copy.deepcopy(s["checkpoints"][1]["body"]))
    expect_failure(compare(rust_verifier, s["tmp"], s["evidence"], s["engine"].public_key, [foreign]),
                   "Invalid checkpoint signature")


def test_other_runs_statements_fail_alike(rust_verifier, scenario):
    s, key = scenario, scenario["engine"].public_key
    expect_failure(compare(rust_verifier, s["tmp"], s["evidence"], key, [s["other_checkpoint"]]),
                   "The witness file holds no checkpoint for this run")
    mixed = copy.deepcopy(s["evidence"]); mixed["receipts"].append(s["other_evidence"]["receipts"][0])
    expect_failure(compare(rust_verifier, s["tmp"], mixed, key), "Receipt belongs to another run")
    # A witness file holding several runs keeps only this run's checkpoints.
    code, report = compare(rust_verifier, s["tmp"], s["evidence"], key, [s["other_checkpoint"], *s["checkpoints"]])
    assert isinstance(report, dict)
    assert code == 0 and report["checkpoints"] == 2


def test_checkpoint_size_rules_match(rust_verifier, scenario):
    s, key, engine = scenario, scenario["engine"].public_key, scenario["engine"]
    body = s["checkpoints"][1]["body"]
    for size, message in [(True, "Checkpoint size is invalid"), (-1, "Checkpoint size is invalid"),
                          (1.0, "Checkpoint size is invalid"), ("3", "Checkpoint size is invalid"),
                          (10 ** 30, "Evidence is missing events that a checkpoint covers"),
                          (body["size"] - 1, "Event history differs from a checkpoint")]:
        forged = sign(engine, {**body, "size": size})
        expect_failure(compare(rust_verifier, s["tmp"], s["evidence"], key, [forged]), message)
    empty = sign(engine, {**body, "size": 0, "head": "0" * 64})
    code, report = compare(rust_verifier, s["tmp"], s["evidence"], key, [empty])
    assert isinstance(report, dict)
    assert code == 0 and report["anchored_events"] == 0


def awkward_values(seed=7):
    """Values whose canonical form depends on Python's number and string rules."""
    rng = random.Random(seed)
    floats = [0.1, 1e16, 1e15, 1e-4, 1e-5, -0.0, 5e-324, 1.7976931348623157e308, 2.5e-7, 1793432275.123,
              9007199254740993.0, 123456789.0, 0.30000000000000004, math.inf, -math.inf, math.nan]
    floats += [struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))[0] for _ in range(300)]
    floats += [rng.uniform(-1e6, 1e6) for _ in range(100)] + [10.0 ** rng.randint(-30, 30) for _ in range(50)]
    return {
        "floats": floats,
        "ints": [0, -1, 2 ** 53 + 1, -(2 ** 63), 10 ** 40, int("9" * 300)],
        "text": ["\u0000\u001f\u007f\u0080\u00ff", "\ud800 lone", "\U0010FFFF", "\ufeff\u2028\u2029", "tab\tnew\nline"],
        "nested": {"\U0001F600": 1, "\uffff": 2, "\u00e9": 3, "Z": 4, "a": [None, True, False, [], {}]},
        "\U0001F680 key": "sorted by code point",
    }


def test_canonicalization_matches_python_on_awkward_values(rust_verifier, scenario):
    """The engine hashes these with Python's canonical(); a Rust mismatch would break the chain."""
    s, engine = scenario, scenario["engine"]
    with engine.transaction() as db:
        engine.event(db, s["run_id"], "fixture", None, "FIXTURE", "awkward values", payload=awkward_values())
    evidence = engine.evidence(s["run_id"])
    assert evidence["events"][-1]["payload"]["ints"][-1] == int("9" * 300)
    # A lone surrogate cannot be written as UTF-8, so this export uses \u escapes.
    code, report = compare(rust_verifier, s["tmp"], evidence, engine.public_key, s["checkpoints"], ascii_only=True)
    assert isinstance(report, dict)
    assert code == 0 and report["head"] == evidence["events"][-1]["hash"]
    for seed in range(1, 4):
        variant = copy.deepcopy(evidence)
        variant["events"][-1]["payload"] = awkward_values(seed)
        rechain(variant["events"])
        code, report = compare(rust_verifier, s["tmp"], variant, engine.public_key, ascii_only=True)
        assert isinstance(report, dict)
        assert code == 0 and report["head"] == variant["events"][-1]["hash"]


def test_python_type_quirks_match(rust_verifier, scenario):
    s, key = scenario, scenario["engine"].public_key
    shaped = copy.deepcopy(s["evidence"]); shaped["receipts"] = {}; shaped["reconciliations"] = ""
    code, report = compare(rust_verifier, s["tmp"], shaped, key)
    assert isinstance(report, dict)
    assert code == 0 and report["receipts"] == 0 and report["reconciliations"] == 0
    missing = copy.deepcopy(s["evidence"]); del missing["receipts"]
    expect_failure(compare(rust_verifier, s["tmp"], missing, key), "'receipts'")
    keyed = copy.deepcopy(s["evidence"]); keyed["receipts"] = {"not": "a receipt"}
    expect_failure(compare(rust_verifier, s["tmp"], keyed, key), "Invalid receipt signature")
    retyped = copy.deepcopy(s["evidence"]); retyped["run"]["id"] = [s["run_id"]]
    expect_failure(compare(rust_verifier, s["tmp"], retyped, key), "Receipt belongs to another run")
    nulled = copy.deepcopy(s["evidence"]); nulled["events"][0]["previous"] = None
    expect_failure(compare(rust_verifier, s["tmp"], nulled, key), "Event chain is altered or reordered")
    # Uncaught Python exceptions and Rust's matching failures both exit 1.
    for broken in [[], {"public_key": key, "events": [1]}, {"public_key": key, "events": {"k": 1}}]:
        assert compare_codes(rust_verifier, s["tmp"], broken, key) == 1


def compare_codes(rust_verifier, tmp, evidence, key):
    evidence_file = tmp / "broken.json"
    evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
    args = [str(evidence_file), f"--public-key={key}"]
    codes = {subprocess.run(cmd, capture_output=True, timeout=120).returncode
             for cmd in ([sys.executable, str(PYTHON_VERIFIER), *args], [str(rust_verifier), *args])}
    assert len(codes) == 1, codes
    return codes.pop()


def test_committed_live_runs_give_identical_reports(rust_verifier):
    runs = ROOT / "docs" / "live-runs"
    cases = [("run1", "issuer-public-key.txt", None), ("run2", "issuer-public-key.txt", None),
             ("run4", "run4-issuer-public-key.txt", None)]
    cases += [(f"run{n}", "run5-9-issuer-public-key.txt", f"run{n}-checkpoint.jsonl") for n in range(5, 10)]
    for run, key, witness in cases:
        args = [str(runs / f"{run}-evidence.json"), "--public-key-file", str(runs / key)]
        if witness:
            args += ["--checkpoints", str(runs / witness)]
        python = run_cli([sys.executable, str(PYTHON_VERIFIER), *args])
        assert python[0] == 0 and run_cli([str(rust_verifier), *args]) == python, run


def test_approval_checks_match(rust_verifier, scenario):
    s, engine = scenario, scenario["engine"]
    root = engine.create_run()
    executor = Executor(engine)
    pair = ("staging/checkout", "config.write")
    for name, decision in [("allowed", "approve"), ("refused", "deny")]:
        oid = executor.execute(root["token"], *pair, name)["operation_id"]
        engine.decide_approval(oid, decision, REASON)
        executor.execute(root["token"], *pair, name)
    evidence = engine.evidence(root["run_id"])
    key = engine.public_key
    code, report = compare(rust_verifier, s["tmp"], evidence, key)
    assert isinstance(report, dict)
    assert code == 0 and report["approvals"] == 2
    approved = next(i for i, r in enumerate(evidence["approvals"]) if r["body"]["decision"] == "approved")
    changed = copy.deepcopy(evidence); changed["approvals"][approved]["body"]["reason"] = "tampered"
    expect_failure(compare(rust_verifier, s["tmp"], changed, key), "Invalid approval signature")
    for field, value, message in [("run_id", "other", "Approval belongs to another run"),
                                  ("decision", "invalid", "Invalid approval signature"),
                                  ("operation_id", "other", "Receipt cites an approval missing from the evidence")]:
        changed = copy.deepcopy(evidence)
        body = {**changed["approvals"][approved]["body"], field: value}
        changed["approvals"][approved] = sign(engine, body)
        expect_failure(compare(rust_verifier, s["tmp"], changed, key), message)


def test_lifecycle_and_owner_checks_match(rust_verifier, scenario):
    s, engine = scenario, scenario["engine"]
    evidence = s["evidence"]
    owner = next(g["owner"] for g in evidence["grants"] if g["parent"] is None)
    engine.deprovision_owner(owner)
    engine.reactivate_owner(owner)
    evidence = engine.evidence(s["run_id"])
    key = engine.public_key
    code, report = compare(rust_verifier, s["tmp"], evidence, key, s["checkpoints"])
    assert isinstance(report, dict)
    assert code == 0 and report["lifecycle"] == 3
    for field in ("active", "epoch", "runs", "actor"):
        changed = copy.deepcopy(evidence); changed["lifecycle"][1]["body"][field] = "tampered"
        expect_failure(compare(rust_verifier, s["tmp"], changed, key), "Invalid lifecycle signature")
    for kind, field, message in [("receipts", "owner", "Receipt belongs to another owner"),
                                 ("reconciliations", "owner", "Reconciliation belongs to another owner"),
                                 ("lifecycle", "owner_id", "Lifecycle receipt belongs to another owner")]:
        for missing in (False, True):
            changed = copy.deepcopy(evidence)
            body = changed[kind][0]["body"]
            if missing:
                del body[field]
            else:
                body[field] = "another-owner"
            changed[kind][0] = sign(engine, body)
            expect_failure(compare(rust_verifier, s["tmp"], changed, key), "'owner_id'" if missing and kind == "lifecycle" else message)
    for target, source, message in [("receipts", "lifecycle", "Invalid receipt signature"),
                                    ("reconciliations", "lifecycle", "Invalid reconciliation signature"),
                                    ("lifecycle", "receipts", "Invalid lifecycle signature"),
                                    ("lifecycle", "reconciliations", "Invalid lifecycle signature"),
                                    ("approvals", "lifecycle", "Invalid approval signature")]:
        changed = copy.deepcopy(evidence); changed[target].append(evidence[source][0])
        expect_failure(compare(rust_verifier, s["tmp"], changed, key), message)
    changed = copy.deepcopy(evidence)
    changed["grants"] = []
    changed["receipts"] = changed["reconciliations"] = []
    expect_failure(compare(rust_verifier, s["tmp"], changed, key), "Lifecycle receipt belongs to another owner")


@pytest.mark.parametrize("kind,value", [("approvals", None), ("approvals", [None]), ("approvals", [{}]),
                                      ("lifecycle", None), ("lifecycle", [None]), ("grants", [None]),
                                      ("events", [1])])
def test_malformed_new_collections_match_without_tracebacks(rust_verifier, scenario, kind, value):
    s, key = scenario, scenario["engine"].public_key
    changed = copy.deepcopy(s["evidence"]); changed[kind] = value
    code, detail = compare(rust_verifier, s["tmp"], changed, key)
    assert code == 1 and isinstance(detail, str) and detail.startswith("Verification failed:")


def test_missing_and_substituted_approvals_match(rust_verifier, scenario):
    s, engine = scenario, scenario["engine"]
    root = engine.create_run()
    executor = Executor(engine)
    pair = ("staging/checkout", "config.write")
    oid = executor.execute(root["token"], *pair, "approved")["operation_id"]
    engine.decide_approval(oid, "approve", REASON)
    executor.execute(root["token"], *pair, "approved")
    evidence, key = engine.evidence(root["run_id"]), engine.public_key
    dropped = copy.deepcopy(evidence); dropped["approvals"] = []
    expect_failure(compare(rust_verifier, s["tmp"], dropped, key), "Receipt cites an approval missing from the evidence")
    for field, imposter, message in [("receipts", evidence["approvals"][0], "Invalid receipt signature"),
                                    ("reconciliations", evidence["approvals"][0], "Invalid reconciliation signature"),
                                    ("approvals", evidence["receipts"][0], "Invalid approval signature")]:
        changed = copy.deepcopy(evidence); changed[field].append(imposter)
        expect_failure(compare(rust_verifier, s["tmp"], changed, key), message)
