"""Only this trusted executor sees upstream credentials."""
import hashlib
import hmac
import os
import shutil
import subprocess

from .core import Denied


class CredentialUnavailable(Exception):
    pass


class DemoCredentials:
    mode = "synthetic"

    def resolve(self):
        return "synthetic-staging-key-not-a-real-secret"


class OnePasswordCredentials:
    mode = "1password-cli"

    def __init__(self, reference):
        if not reference.startswith("op://") or "\n" in reference:
            raise ValueError("A configured op:// secret reference is required")
        self.reference = reference

    def resolve(self):
        executable = shutil.which("op")
        if not executable:
            raise CredentialUnavailable("1Password CLI is not installed.")
        try:
            result = subprocess.run([executable, "read", self.reference, "--no-newline"],
                                    capture_output=True, text=True, timeout=20, check=False)
            if result.returncode or not result.stdout:
                raise CredentialUnavailable("1Password could not resolve the configured credential.")
            return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            # Never forward CLI stdout/stderr or exception text: they may contain secrets.
            raise CredentialUnavailable("1Password credential resolution failed.") from None


class FixtureService:
    """Synthetic service with a credential check, not a real production integration."""
    def __init__(self, expected_sha256):
        self.expected_sha256 = expected_sha256

    def execute(self, credential, resource, action):
        actual = hashlib.sha256(credential.encode()).hexdigest()
        if not hmac.compare_digest(actual, self.expected_sha256):
            raise CredentialUnavailable("The fixture service rejected the configured credential.")
        if action == "logs.read" and resource == "staging/checkout":
            return {"service": "checkout", "environment": "staging", "lines": [
                "14:02:11 INFO deployment=8f2a1 region=us-west-2",
                "14:02:13 WARN payment pool wait exceeded 250ms",
                "14:02:14 ERROR checkout timeout: pool exhausted (max=8)"], "synthetic": True}
        if action == "code.read" and resource == "repo/checkout":
            return {"file": "services/checkout/pool.py", "finding": "Pool limit is 8; staging concurrency is 32.", "synthetic": True}
        if action == "patch.propose" and resource == "repo/checkout":
            return {"proposal": "Align staging pool size with worker concurrency; add a saturation test.", "merged": False, "synthetic": True}
        raise CredentialUnavailable("No fixture adapter is registered for this operation.")


class Executor:
    def __init__(self, passport, provider=None, service=None):
        self.passport = passport
        self.provider = provider or DemoCredentials()
        self.service = service or FixtureService(hashlib.sha256(DemoCredentials().resolve().encode()).hexdigest())

    @classmethod
    def from_environment(cls, passport):
        reference = os.environ.get("PASSPORT_OP_REFERENCE")
        if not reference:
            return cls(passport)
        expected = os.environ.get("PASSPORT_FIXTURE_KEY_SHA256", "")
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise ValueError("Set PASSPORT_FIXTURE_KEY_SHA256 to the fixture credential's SHA-256 digest")
        return cls(passport, OnePasswordCredentials(reference), FixtureService(expected))

    def execute(self, token, resource, action, request_key):
        op = self.passport.reserve(token, resource, action, request_key)
        if op["duplicate"]:
            import json
            return {"operation_id": op["id"], "state": op["state"], "duplicate": True,
                    "result": json.loads(op["result"]) if op["result"] else None,
                    "receipt": json.loads(op["receipt"]) if op["receipt"] else None}
        return self.execute_reserved(op)

    def execute_reserved(self, op):
        if not self.passport.dispatch(op["id"]):
            raise Denied("OPERATION_STATE", "Operation already dispatched or cancelled.")
        try:
            credential = self.provider.resolve()
        except CredentialUnavailable:
            return self.passport.settle(op["id"], "failed", {"error": "Credential unavailable before service execution."})
        try:
            result = self.service.execute(credential, op["resource"], op["action"])
        except CredentialUnavailable:
            return self.passport.settle(op["id"], "failed", {"error": "Fixture rejected the request before any effect."})
        except Exception:
            return self.passport.settle(op["id"], "unknown", {"error": "Service outcome uncertain; reservation retained."})
        finally:
            # Python cannot guarantee erasure of immutable strings from process memory.
            credential = None
        return self.passport.settle(op["id"], "completed", result)
