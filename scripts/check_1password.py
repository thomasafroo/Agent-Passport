"""Opt-in live credential lookup. Prints no credential or CLI output."""
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.core import Passport, verify_receipt
from agent_passport.broker import Executor


def main():
    if not os.environ.get("PASSPORT_OP_REFERENCE"):
        print("Configure PASSPORT_OP_REFERENCE and PASSPORT_FIXTURE_KEY_SHA256 first. See docs/1password.md.")
        return 2
    with tempfile.TemporaryDirectory() as directory:
        passport = Passport(directory)
        try:
            executor = Executor.from_environment(passport)
        except ValueError:
            print("Invalid fixture configuration. See docs/1password.md.")
            return 2
        root = passport.create_run(budget=1)
        result = executor.execute(root["token"], "staging/checkout", "logs.read", "integration-check")
        verified = verify_receipt(result["receipt"], passport.public_key)
        print(f"Provider: {executor.provider.mode}; outcome: {result['state']}; receipt valid: {verified}")
        return 0 if result["state"] == "completed" and verified else 1


if __name__ == "__main__": sys.exit(main())
