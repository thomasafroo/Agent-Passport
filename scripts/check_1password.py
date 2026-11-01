"""Opt-in live credential lookup. Prints no credential or CLI output."""
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.core import verify_receipt
from agent_passport.broker import Executor, backend_from_environment, passport_from_environment


def main():
    if not (os.environ.get("PASSPORT_OP_REFERENCE") or os.environ.get("PASSPORT_OP_REFERENCES")):
        print("Configure PASSPORT_OP_REFERENCE (or PASSPORT_OP_REFERENCES) and the fixture digest first. See docs/1password.md.")
        return 2
    with tempfile.TemporaryDirectory() as directory:
        try:
            backend = backend_from_environment()
            # With PASSPORT_ISSUER_KEY_REFERENCE set, this also resolves the issuer key (memory only).
            passport = passport_from_environment(directory, backend)
            executor = Executor.from_environment(passport, backend)
        except ValueError as error:
            print(f"Invalid configuration: {error} See docs/1password.md.")
            return 2
        root = passport.create_run(budget=1)
        result = executor.execute(root["token"], "staging/checkout", "logs.read", "integration-check")
        verified = verify_receipt(result["receipt"], passport.public_key)
        print(f"Provider: {executor.provider.mode}; issuer key: {passport.issuer_key_source}; "
              f"outcome: {result['state']}; receipt valid: {verified}")
        return 0 if result["state"] == "completed" and verified else 1


if __name__ == "__main__": sys.exit(main())
