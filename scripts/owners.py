"""Operator tool: manage the accountable owners that root passports are issued on behalf of.

Deactivating an owner voids every grant in every run issued for them, at the next reservation or
dispatch. Reactivating permits new issuance only; grants from before the deactivation stay void.
Each change is signed as a lifecycle receipt and recorded in each affected run's ledger.

    python scripts/owners.py list
    python scripts/owners.py add USER_NAME --display-name "Dana Example" [--external-id ID]
    python scripts/owners.py deactivate OWNER
    python scripts/owners.py reactivate OWNER

OWNER is an owner ID, user name, or external ID.
"""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.core import Passport, Denied


def main(argv=None):
    parser = argparse.ArgumentParser(description="List, provision, deactivate or reactivate accountable owners.")
    parser.add_argument("--state-dir", default=os.environ.get("PASSPORT_STATE_DIR", ".state"))
    parser.add_argument("--operator", default="Local operator", help="Who is making the change; recorded in the signed receipt.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List owners and how many runs were issued for each.")
    add = commands.add_parser("add", help="Provision a new, active owner.")
    add.add_argument("user_name")
    add.add_argument("--display-name", required=True)
    add.add_argument("--external-id")
    for name, text in (("deactivate", "Deprovision an owner. Every grant issued for them stops working."),
                       ("reactivate", "Allow new issuance for an owner. Old grants stay void.")):
        commands.add_parser(name, help=text).add_argument("owner", help="Owner ID, user name, or external ID.")
    args = parser.parse_args(argv)
    passport = Passport(args.state_dir)
    try:
        if args.command == "list":
            result = {"owners": passport.owners()}
        elif args.command == "add":
            result = passport.provision_owner(args.user_name, args.display_name, args.external_id, args.operator)
        else:
            owner = passport.find_owner(args.owner)
            result = passport.set_owner_active(owner["id"], args.command == "reactivate", args.operator)
    except Denied as error:
        print(json.dumps(error.as_dict(), indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
