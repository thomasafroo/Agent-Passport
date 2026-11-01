"""Operator tool: list operations still holding budget, and record a signed decision about one.

Nothing here runs automatically. An unknown or crash-stranded operation keeps its unit until
an operator states what happened upstream. The issuer signs that statement; it is not proof
of the upstream effect.

    python scripts/reconcile.py
    python scripts/reconcile.py OPERATION_ID --outcome not_executed --reason "Upstream log shows no request arrived."
    python scripts/reconcile.py OPERATION_ID --lookup

--lookup asks the upstream's own effect record instead of an operator. A missing record is
fenced first, so the operation can never apply afterwards.
"""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.broker import Executor, backend_from_environment, passport_from_environment, uses_1password
from agent_passport.core import Denied


def main(argv=None):
    parser = argparse.ArgumentParser(description="List operations still holding budget, or record a signed operator decision about one.")
    parser.add_argument("operation", nargs="?", help="Operation ID to decide. Omit to list unresolved operations.")
    parser.add_argument("--outcome", choices=["completed", "not_executed"])
    parser.add_argument("--reason", help="The evidence for the decision, 10 to 500 characters.")
    parser.add_argument("--operator", default="Local operator")
    parser.add_argument("--lookup", action="store_true", help="Decide from the upstream's effect record instead of an operator statement.")
    parser.add_argument("--state-dir", default=os.environ.get("PASSPORT_STATE_DIR", ".state"))
    args = parser.parse_args(argv)
    try:
        # Sign with the same issuer key as the gateway, including one held in 1Password.
        backend = backend_from_environment() if uses_1password() else None
        passport = passport_from_environment(args.state_dir, backend)
    except ValueError as error:
        print(str(error), file=sys.stderr)  # fixed configuration messages only
        return 2
    if not args.operation:
        print(json.dumps({"unresolved": passport.unresolved()}, indent=2))
        return 0
    if args.lookup and (args.outcome or args.reason):
        parser.error("--lookup takes its outcome and basis from the upstream; omit --outcome and --reason")
    if not args.lookup and (not args.outcome or not args.reason):
        parser.error("deciding an operation requires --outcome and --reason, or --lookup")
    try:
        if args.lookup:
            result = Executor.from_environment(passport, backend).resolve(args.operation)
        else:
            result = passport.reconcile(args.operation, args.outcome, args.reason, args.operator)
    except Denied as error:
        print(json.dumps(error.as_dict(), indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
