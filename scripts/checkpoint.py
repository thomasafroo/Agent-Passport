"""Operator tool: sign a checkpoint of a run's event chain and append it to a witness file.

A checkpoint is only an anchor while a copy lives somewhere the database owner cannot rewrite:
another machine, a printed hash, a message to a colleague. The default witness file sits beside
the state directory for convenience and protects nothing until it is copied elsewhere.

Before appending, every checkpoint already in the witness file for this run must still match the
log. A rewritten or shortened history is refused, and the witness file is left unchanged.

    python scripts/checkpoint.py
    python scripts/verify_evidence.py EVIDENCE.json --public-key-file KEY.txt --checkpoints artifacts/witness.jsonl
"""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.broker import passport_from_environment
from agent_passport.core import Denied
from scripts.verify_evidence import load_checkpoints, verify


def witness(passport, run_id, path):
    path = Path(path)
    previous = load_checkpoints(path, run_id) if path.exists() else []
    checkpoint = passport.checkpoint(run_id)
    # The export is read after the checkpoint and may hold later events; a checkpoint covers a prefix.
    verify(passport.evidence(run_id), passport.public_key, [*previous, checkpoint])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(checkpoint, separators=(",", ":")) + "\n")
    return checkpoint


def latest_run(passport):
    db = passport.connect()
    try:
        row = db.execute("SELECT id FROM runs ORDER BY created DESC, rowid DESC LIMIT 1").fetchone()
    finally:
        db.close()
    if not row:
        raise Denied("RUN_UNKNOWN", "No run exists yet.")
    return row[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sign a checkpoint of a run's event chain and append it to a witness file.")
    parser.add_argument("--run", help="Run ID. Defaults to the most recently created run.")
    parser.add_argument("--witness", default="artifacts/witness.jsonl")
    parser.add_argument("--state-dir", default=os.environ.get("PASSPORT_STATE_DIR", ".state"))
    args = parser.parse_args(argv)
    try:
        # Sign with the gateway's issuer key, including one held in 1Password.
        passport = passport_from_environment(args.state_dir)
    except ValueError as error:
        print(json.dumps({"witnessed": False, "error": str(error)}, indent=2), file=sys.stderr)
        return 2
    try:
        checkpoint = witness(passport, args.run or latest_run(passport), args.witness)
    except Denied as error:
        print(json.dumps(error.as_dict(), indent=2), file=sys.stderr)
        return 1
    except ValueError as error:
        print(json.dumps({"witnessed": False, "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps({"witnessed": True, "witness": str(args.witness), **checkpoint["body"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
