import base64
import copy
import json
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
import pytest

from agent_passport.core import Passport
from agent_passport.broker import Executor
from scripts.verify_evidence import verify


def evidence(tmp_path):
    engine = Passport(tmp_path)
    root = engine.create_run()
    Executor(engine).execute(root["token"], "staging/checkout", "logs.read", "test")
    return engine.evidence(root["run_id"]), engine.public_key


def test_export_verifies_offline(tmp_path):
    data, key = evidence(tmp_path)
    assert verify(data, key)["receipts"] == 1


def test_changed_or_reordered_event_fails(tmp_path):
    data, key = evidence(tmp_path)
    changed = copy.deepcopy(data); changed["events"][1]["detail"] = "Changed"
    with pytest.raises(ValueError): verify(changed, key)
    data["events"].reverse()
    with pytest.raises(ValueError): verify(data, key)


def test_receipt_mutation_and_wrong_trust_anchor_fail(tmp_path):
    data, key = evidence(tmp_path)
    with pytest.raises(ValueError): verify(data, "wrong-key")
    data["receipts"][0]["body"]["outcome"] = "failed"
    with pytest.raises(ValueError): verify(data, key)


def test_unanchored_tail_truncation_is_explicit_limit(tmp_path):
    data, key = evidence(tmp_path)
    data["events"].pop()
    assert verify(data, key)["valid"]
    assert "completeness" in verify(data, key)["limitation"]


def test_cli_verifies_utf8_browser_export(tmp_path):
    engine = Passport(tmp_path / "state")
    root = engine.create_run()
    with engine.transaction() as db:
        engine.event(db, root["run_id"], "injected", root["grant"]["id"], "FIXTURE", "Untrusted ‘instruction’ → denied")
    data = engine.evidence(root["run_id"])
    export = tmp_path / "browser-export.json"
    export.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    script = Path(__file__).resolve().parents[1] / "scripts" / "verify_evidence.py"
    result = subprocess.run([sys.executable, str(script), str(export), f"--public-key={engine.public_key}"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_cli_accepts_issuer_key_that_starts_with_dash(tmp_path):
    # Unpadded URL-safe base64 keys begin with "-" about 1 time in 64; argparse must not read one as a flag.
    state = tmp_path / "state"; state.mkdir()
    while True:
        private = Ed25519PrivateKey.generate()
        public = base64.urlsafe_b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip("=")
        if public.startswith("-"):
            break
    (state / "issuer.key").write_bytes(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    engine = Passport(state)
    assert engine.public_key == public
    root = engine.create_run()
    Executor(engine).execute(root["token"], "staging/checkout", "logs.read", "dash-key")
    export = tmp_path / "evidence.json"
    export.write_text(json.dumps(engine.evidence(root["run_id"])), encoding="utf-8")
    key_file = tmp_path / "issuer-public-key.txt"; key_file.write_text(public + "\n")
    script = Path(__file__).resolve().parents[1] / "scripts" / "verify_evidence.py"
    for flags in ([f"--public-key={public}"], ["--public-key-file", str(key_file)]):
        result = subprocess.run([sys.executable, str(script), str(export), *flags], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("document", [[], None, {"public_key": "KEY", "events": [None], "receipts": [], "run": {}}])
def test_cli_reports_malformed_evidence_as_a_failed_verification(tmp_path, document):
    export = tmp_path / "evidence.json"
    export.write_text(json.dumps(document), encoding="utf-8")
    script = Path(__file__).resolve().parents[1] / "scripts" / "verify_evidence.py"
    result = subprocess.run([sys.executable, str(script), str(export), "--public-key=KEY"], capture_output=True, text=True)
    assert result.returncode == 1 and result.stderr.startswith("Verification failed") and "Traceback" not in result.stderr
