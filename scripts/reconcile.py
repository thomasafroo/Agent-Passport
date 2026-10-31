"""Operator tool: list operations still holding budget, and record a signed decision about one.

Nothing here runs automatically. An unknown or crash-stranded operation keeps its unit until
an operator states what happened upstream. The issuer signs that statement; it is not proof
of the upstream effect.

    python scripts/reconcile.py
    python scripts/reconcile.py OPERATION_ID --outcome not_executed --reason "Upstream log shows no request arrived."
"""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.core import Passport, Denied


def main(argv=None):
    parser = argparse.ArgumentParser(description="List operations still holding budget, or record a signed operator decision about one.")
    parser.add_argument("operation", nargs="?", help="Operation ID to decide. Omit to list unresolved operations.")
    parser.add_argument("--outcome", choices=["completed", "not_executed"])
    parser.add_argument("--reason", help="The evidence for the decision, 10 to 500 characters.")
    parser.add_argument("--operator", default="Local operator")
    parser.add_argument("--state-dir", default=os.environ.get("PASSPORT_STATE_DIR", ".state"))
    args = parser.parse_args(argv)
    passport = Passport(args.state_dir)
    if not args.operation:
        print(json.dumps({"unresolved": passport.unresolved()}, indent=2))
        return 0
    if not args.outcome or not args.reason:
        parser.error("deciding an operation requires --outcome and --reason")
    try:
        result = passport.reconcile(args.operation, args.outcome, args.reason, args.operator)
    except Denied as error:
        print(json.dumps(error.as_dict(), indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
