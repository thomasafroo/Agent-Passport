import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from agent_passport.core import Passport, canonical
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
    result = subprocess.run([sys.executable, str(script), str(export), "--public-key", engine.public_key], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
