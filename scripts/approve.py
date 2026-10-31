"""Operator tool: list operations waiting for approval, and approve or deny one.

High-risk resource/action pairs (operator policy, never agent input) reserve a unit and wait.
Nothing approves them automatically. An approval is single-use, bound to the exact operation,
and lapses if the agent does not retry within the approval window; the agent's retry with the
same request key is what dispatches it, after the full chain is checked again.

    python scripts/approve.py
    python scripts/approve.py OPERATION_ID --decision approve --reason "Change ticket 4411 reviewed."
    python scripts/approve.py OPERATION_ID --decision deny --reason "No change window today."
"""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.broker import passport_from_environment
from agent_passport.core import Denied


def main(argv=None):
    parser = argparse.ArgumentParser(description="List operations awaiting approval, or record a signed approve/deny decision.")
    parser.add_argument("operation", nargs="?", help="Operation ID to decide. Omit to list waiting operations.")
    parser.add_argument("--decision", choices=["approve", "deny"])
    parser.add_argument("--reason", help="The basis for the decision, 10 to 500 characters.")
    parser.add_argument("--operator", default="Local operator")
    parser.add_argument("--state-dir", default=os.environ.get("PASSPORT_STATE_DIR", ".state"))
    args = parser.parse_args(argv)
    try:
        passport = passport_from_environment(args.state_dir)
    except ValueError as error:
        print(str(error), file=sys.stderr)  # fixed configuration messages only
        return 2
    if not args.operation:
        print(json.dumps({"awaiting": passport.pending_approvals()}, indent=2))
        return 0
    if not args.decision or not args.reason:
        parser.error("deciding an operation requires --decision and --reason")
    try:
        result = passport.decide_approval(args.operation, args.decision, args.reason, args.operator)
    except Denied as error:
        print(json.dumps(error.as_dict(), indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
