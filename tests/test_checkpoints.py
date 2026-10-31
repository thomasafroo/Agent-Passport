"""Signed checkpoints anchor the event chain against suffix removal and wholesale rewriting."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

from fastapi.testclient import TestClient
import pytest

from agent_passport.broker import Executor
from agent_passport.core import Passport, Denied, b64, canonical, verify_receipt
from agent_passport.server import create_app
from scripts.checkpoint import main as checkpoint_cli, witness
from scripts.verify_evidence import load_checkpoints, verify

LOG_READ = ("staging/checkout", "logs.read")


@pytest.fixture
def engine(tmp_path):
    return Passport(tmp_path / "state")


def run_with_ops(engine, count=2):
    root = engine.create_run()
    for i in range(count):
        Executor(engine).execute(root["token"], *LOG_READ, f"op-{i}")
    return root


def rechain(events, start=0):
    """What a database owner without the issuer key can still do: recompute every hash."""
    previous = events[start - 1]["hash"] if start else "0" * 64
    for event in events[start:]:
        event["previous"] = previous
        body = {k: v for k, v in event.items() if k not in {"seq", "hash"}}
        event["hash"] = previous = hashlib.sha256(canonical(body)).hexdigest()
    return events


def test_checkpoint_signs_the_current_size_and_head(engine):
    root = run_with_ops(engine)
    evidence = engine.evidence(root["run_id"])
    checkpoint = engine.checkpoint(root["run_id"])
    body = checkpoint["body"]
    assert body["type"] == "checkpoint" and body["size"] == len(evidence["events"])
    assert body["head"] == evidence["events"][-1]["hash"]
    assert verify_receipt(checkpoint, engine.public_key)
    result = verify(evidence, engine.public_key, [checkpoint])
    assert result["anchored_events"] == body["size"] and result["unanchored_events"] == 0
    with pytest.raises(Denied) as error:
        engine.checkpoint("run_missing")
    assert error.value.rule == "RUN_UNKNOWN"


def test_dropped_suffix_is_detected_only_with_a_checkpoint(engine):
    root = run_with_ops(engine)
    checkpoint = engine.checkpoint(root["run_id"])
    evidence = engine.evidence(root["run_id"])
    evidence["events"].pop()
    assert verify(evidence, engine.public_key)["valid"]  # the documented limitation without an anchor
    with pytest.raises(ValueError, match="missing events"):
        verify(evidence, engine.public_key, [checkpoint])


def test_recomputed_chain_is_detected_only_with_a_checkpoint(engine):
    root = run_with_ops(engine)
    checkpoint = engine.checkpoint(root["run_id"])
    evidence = engine.evidence(root["run_id"])
    evidence["events"][1]["detail"] = "Rewritten by the database owner"
    rechain(evidence["events"])
    assert verify(evidence, engine.public_key)["valid"]
    with pytest.raises(ValueError, match="differs from a checkpoint"):
        verify(evidence, engine.public_key, [checkpoint])


def test_events_after_a_checkpoint_are_reported_unanchored(engine):
    root = run_with_ops(engine, count=1)
    checkpoint = engine.checkpoint(root["run_id"])
    Executor(engine).execute(root["token"], *LOG_READ, "later")
    evidence = engine.evidence(root["run_id"])
    result = verify(evidence, engine.public_key, [checkpoint])
    assert result["unanchored_events"] == len(evidence["events"]) - checkpoint["body"]["size"] > 0
    assert "after it are unanchored" in result["limitation"]
    # Rewriting only the unanchored tail is not detected. That is the boundary of the claim.
    evidence["events"][-1]["detail"] = "Rewritten tail"
    rechain(evidence["events"], start=checkpoint["body"]["size"])
    assert verify(evidence, engine.public_key, [checkpoint])["valid"]


def test_forged_or_misapplied_checkpoints_fail(engine, tmp_path):
    root = run_with_ops(engine)
    evidence = engine.evidence(root["run_id"])
    good = engine.checkpoint(root["run_id"])
    other_issuer = Passport(tmp_path / "other")
    other_run = other_issuer.create_run()
    with pytest.raises(ValueError, match="checkpoint signature"):
        verify(evidence, engine.public_key, [other_issuer.checkpoint(other_run["run_id"])])
    altered = copy.deepcopy(good); altered["body"]["size"] -= 1
    with pytest.raises(ValueError, match="checkpoint signature"):
        verify(evidence, engine.public_key, [altered])
    with pytest.raises(ValueError, match="another run"):
        verify(evidence, engine.public_key, [engine.checkpoint(engine.create_run()["run_id"])])
    # A signed operation receipt is not a checkpoint, and a checkpoint is not a receipt.
    with pytest.raises(ValueError, match="checkpoint signature"):
        verify(evidence, engine.public_key, [evidence["receipts"][0]])
    posing = copy.deepcopy(evidence); posing["receipts"].append(good)
    with pytest.raises(ValueError, match="receipt signature"):
        verify(posing, engine.public_key)


@pytest.mark.parametrize("size", [True, -1, 1.0, "2"])
def test_malformed_checkpoint_sizes_fail(engine, size):
    root = run_with_ops(engine)
    evidence = engine.evidence(root["run_id"])
    body = {**engine.checkpoint(root["run_id"])["body"], "size": size}
    signed = {"body": body, "signature": b64(engine.key.sign(canonical(body)))}
    with pytest.raises(ValueError, match="size is invalid"):
        verify(evidence, engine.public_key, [signed])


def test_witness_refuses_to_extend_a_rewritten_history(engine, tmp_path):
    root = run_with_ops(engine)
    path = tmp_path / "witness" / "witness.jsonl"
    witness(engine, root["run_id"], path)
    Executor(engine).execute(root["token"], *LOG_READ, "later")
    witness(engine, root["run_id"], path)
    first, second = [c["body"]["size"] for c in load_checkpoints(path, root["run_id"])]
    assert second > first
    before = path.read_bytes()
    # The database owner deletes the latest events and recomputes nothing: history went backwards.
    db = sqlite3.connect(engine.path)
    db.execute("DELETE FROM events WHERE seq=(SELECT MAX(seq) FROM events WHERE run_id=?)", (root["run_id"],))
    db.commit(); db.close()
    with pytest.raises(ValueError, match="missing events"):
        witness(engine, root["run_id"], path)
    assert path.read_bytes() == before


def test_witness_refuses_a_replaced_issuer(engine, tmp_path):
    root = run_with_ops(engine)
    path = tmp_path / "witness.jsonl"
    witness(engine, root["run_id"], path)
    (engine.directory / "issuer.key").unlink()
    replaced = Passport(engine.directory)
    # Old receipts and the witnessed checkpoint both stop verifying under the new key.
    with pytest.raises(ValueError, match="signature"):
        witness(replaced, root["run_id"], path)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_cli_witnesses_and_verifier_uses_the_witness_file(tmp_path, capsys):
    state = tmp_path / "state"
    engine = Passport(state)
    root = run_with_ops(engine)
    path = tmp_path / "witness.jsonl"
    assert checkpoint_cli(["--state-dir", str(state), "--witness", str(path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["witnessed"] and out["run_id"] == root["run_id"]
    assert checkpoint_cli(["--state-dir", str(tmp_path / "empty"), "--witness", str(path)]) == 1
    assert json.loads(capsys.readouterr().err)["rule"] == "RUN_UNKNOWN"

    evidence = engine.evidence(root["run_id"])
    export, key = tmp_path / "evidence.json", tmp_path / "key.txt"
    key.write_text(engine.public_key, encoding="utf-8")
    script = Path(__file__).resolve().parents[1] / "scripts" / "verify_evidence.py"
    command = [sys.executable, str(script), str(export), "--public-key-file", str(key), "--checkpoints", str(path)]
    export.write_text(json.dumps(evidence), encoding="utf-8")
    checked = subprocess.run(command, capture_output=True, text=True)
    assert checked.returncode == 0 and json.loads(checked.stdout)["unanchored_events"] == 0
    evidence["events"].pop()
    export.write_text(json.dumps(evidence), encoding="utf-8")
    checked = subprocess.run(command, capture_output=True, text=True)
    assert checked.returncode == 1 and "missing events" in checked.stderr
    empty = tmp_path / "empty-witness.jsonl"; empty.write_text("", encoding="utf-8")
    command[-1] = str(empty)
    checked = subprocess.run(command, capture_output=True, text=True)
    assert checked.returncode == 1 and "no checkpoint for this run" in checked.stderr


def test_only_the_console_can_request_a_checkpoint(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    app = create_app(tmp_path)
    client = TestClient(app)
    coordinator = app.state.demo.agents["Coordinator"]
    assert client.post("/api/checkpoint", headers={"Authorization": f"Bearer {coordinator['token']}"}).status_code == 403
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    checkpoint = client.post("/api/checkpoint", headers=console).json()["checkpoint"]
    evidence = client.get("/api/evidence", headers=console).json()
    assert checkpoint["body"]["run_id"] == evidence["run"]["id"]
    assert verify(evidence, evidence["public_key"], [checkpoint])["anchored_events"] == checkpoint["body"]["size"]
