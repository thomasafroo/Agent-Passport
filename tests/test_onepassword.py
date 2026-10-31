"""1Password SDK provider, per-operation reference mapping, and issuer key from a reference.

Mocked only: the SDK client and the CLI are replaced. Nothing here touches a real account.
"""
import asyncio
import base64
import hashlib
import json
import logging
import sys
from types import ModuleType, SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
import pytest

from agent_passport.broker import (CredentialUnavailable, Executor, OnePasswordCLI, OnePasswordCredentials, OnePasswordSDK,
                                   backend_from_environment, load_reference_map, passport_from_environment)
from agent_passport.core import CATALOG, Passport, b64, verify_receipt
from agent_passport.server import create_app

SECRET = "fixture-key-value-for-tests"
LEAK = "LEAKED-SDK-DETAIL-0123456789"
TOKEN = "ops_fake-service-account-token-for-tests"
REFS = {("staging/checkout", "logs.read"): "op://Test Vault/Logs/credential",
        ("repo/checkout", "code.read"): "op://Test Vault/Code/credential",
        ("repo/checkout", "patch.propose"): "op://Test Vault/Patch/credential",
        ("staging/checkout", "config.write"): "op://Test Vault/Config/credential"}
VARS = ("PASSPORT_OP_REFERENCE", "PASSPORT_OP_REFERENCES", "PASSPORT_OP_PROVIDER", "PASSPORT_ISSUER_KEY_REFERENCE",
        "PASSPORT_FIXTURE_KEY_SHA256", "OP_SERVICE_ACCOUNT_TOKEN")
FIXED = {"1Password credential resolution failed.", "1Password credential resolution timed out.",
         "1Password could not resolve the configured credential."}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in VARS:
        monkeypatch.delenv(name, raising=False)


class FakeSDK:
    """Stands in for onepassword.Client.authenticate and client.secrets.resolve (both async)."""

    def __init__(self, secrets=None, fail=None):
        self.secrets_by_reference = secrets if secrets is not None else {}
        self.fail = fail
        self.auth_calls, self.resolved, self.loops = [], [], []

    async def authenticate(self, auth, integration_name, integration_version):
        self.auth_calls.append({"auth": auth, "integration_name": integration_name, "integration_version": integration_version})
        if self.fail == "auth":
            raise Exception(f"authentication failed for token {auth}: {LEAK}")
        return SimpleNamespace(secrets=SimpleNamespace(resolve=self.resolve))

    async def resolve(self, secret_reference):
        self.loops.append(asyncio.get_running_loop())
        self.resolved.append(secret_reference)
        if self.fail == "resolve":
            raise Exception(f"no item matched {secret_reference}; value was {SECRET}; {LEAK}")
        if self.fail == "rate":
            raise RateLimitExceededException(f"rate limited: {LEAK}")
        if self.fail == "slow":
            await asyncio.sleep(30)
        if self.fail == "empty":
            return ""
        if self.fail == "type":
            return {"leak": LEAK}
        return self.secrets_by_reference.get(secret_reference, SECRET)


class RateLimitExceededException(Exception):
    pass


def sdk(fake, **kwargs):
    return OnePasswordSDK(TOKEN, client_factory=fake.authenticate, **kwargs)


@pytest.fixture
def fake_onepassword(monkeypatch):
    """Install a fake `onepassword` module so the real import path in OnePasswordSDK is exercised."""
    fake = FakeSDK()
    module = ModuleType("onepassword")
    module.Client = SimpleNamespace(authenticate=fake.authenticate)
    monkeypatch.setitem(sys.modules, "onepassword", module)
    return fake


def test_sdk_success_authenticates_once_with_the_service_account_token():
    fake = FakeSDK()
    provider = sdk(fake)
    assert provider.mode == "1password-sdk"
    assert provider.read("op://Test Vault/Logs/credential") == SECRET
    assert provider.read("op://Test Vault/Code/credential") == SECRET
    assert fake.auth_calls == [{"auth": TOKEN, "integration_name": "Agent Passport", "integration_version": "0.1.0"}]
    assert fake.resolved == ["op://Test Vault/Logs/credential", "op://Test Vault/Code/credential"]
    assert TOKEN not in repr(provider)


def test_sdk_runs_on_its_own_loop_from_inside_a_running_event_loop():
    fake = FakeSDK()
    provider = sdk(fake)

    async def caller():
        # The executor is synchronous; here it is called from a thread whose loop is running.
        caller_loop = asyncio.get_running_loop()
        return caller_loop, provider.read("op://Test Vault/Logs/credential")

    caller_loop, value = asyncio.run(caller())
    assert value == SECRET
    assert fake.loops and fake.loops[0] is not caller_loop


def test_executor_inside_a_running_loop_completes_through_the_sdk(tmp_path):
    engine = Passport(tmp_path)
    executor = Executor(engine, OnePasswordCredentials(REFS, sdk(FakeSDK())))
    executor.service.expected_sha256 = digest(SECRET)
    root = engine.create_run(budget=1)

    async def agent():
        return executor.execute(root["token"], "repo/checkout", "code.read", "in-loop")

    assert asyncio.run(agent())["state"] == "completed"


@pytest.mark.parametrize("fail", ["auth", "resolve", "rate", "slow", "empty", "type"])
def test_sdk_failures_raise_fixed_messages_without_chained_detail(fail):
    fake = FakeSDK(fail=fail)
    provider = sdk(fake)
    provider.TIMEOUT = 0.2
    with pytest.raises(CredentialUnavailable) as error:
        provider.read("op://Test Vault/Logs/credential")
    assert str(error.value) in FIXED
    assert error.value.__context__ is None and error.value.__cause__ is None
    for value in (LEAK, SECRET, TOKEN):
        assert value not in str(error.value) and value not in repr(error.value)


def test_sdk_failure_detail_never_reaches_results_events_receipts_or_http(tmp_path, monkeypatch, fake_onepassword, caplog):
    caplog.set_level(logging.DEBUG)
    fake_onepassword.fail = "resolve"
    monkeypatch.setenv("PASSPORT_OP_PROVIDER", "sdk")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
    monkeypatch.setenv("PASSPORT_OP_REFERENCE", "op://Test Vault/Logs/credential")
    monkeypatch.setenv("PASSPORT_FIXTURE_KEY_SHA256", digest(SECRET))
    client = TestClient(create_app(tmp_path))
    assert client.get("/health").json()["credential_mode"] == "1password-sdk"
    root = client.app.state.passport.create_run(budget=2)
    response = client.post("/api/agent/execute", json={"resource": "staging/checkout", "action": "logs.read", "request_key": "k"},
                           headers={"Authorization": f"Bearer {root['token']}"})
    assert response.status_code == 200 and response.json()["state"] == "failed"
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    evidence = client.app.state.passport.evidence(root["run_id"])
    surfaces = [response.text, json.dumps(evidence), client.get("/api/evidence", headers=console).text,
                client.get("/health").text, caplog.text]
    for surface in surfaces:
        for value in (LEAK, SECRET, TOKEN):
            assert value not in surface
    assert evidence["run"]["reserved"] == 0  # a known pre-effect failure refunds


def test_sdk_success_end_to_end_reports_mode_in_health_and_evidence(tmp_path, monkeypatch, fake_onepassword):
    monkeypatch.setenv("PASSPORT_OP_PROVIDER", "sdk")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
    monkeypatch.setenv("PASSPORT_OP_REFERENCE", "op://Test Vault/Logs/credential")
    monkeypatch.setenv("PASSPORT_FIXTURE_KEY_SHA256", digest(SECRET))
    client = TestClient(create_app(tmp_path))
    root = client.app.state.passport.create_run(budget=1)
    response = client.post("/api/agent/execute", json={"resource": "staging/checkout", "action": "logs.read", "request_key": "k"},
                           headers={"Authorization": f"Bearer {root['token']}"})
    assert response.json()["state"] == "completed" and SECRET not in response.text and TOKEN not in response.text
    console = {"x-passport-console": client.get("/api/session").json()["console_token"]}
    assert client.get("/api/evidence", headers=console).json()["credential_mode"] == "1password-sdk"
    assert fake_onepassword.auth_calls[0]["auth"] == TOKEN


def test_agents_cannot_choose_the_provider_or_a_reference(tmp_path):
    client = TestClient(create_app(tmp_path))
    root = client.app.state.passport.create_run()
    auth = {"Authorization": f"Bearer {root['token']}"}
    body = {"resource": "staging/checkout", "action": "logs.read", "request_key": "x"}
    for extra in ({"provider": "sdk"}, {"reference": "op://Other/Item/field"}, {"credential_mode": "1password-sdk"}):
        assert client.post("/api/agent/execute", json={**body, **extra}, headers=auth).status_code == 422


def test_provider_selection_is_operator_configuration(monkeypatch, fake_onepassword):
    assert isinstance(backend_from_environment({}), OnePasswordCLI)
    assert isinstance(backend_from_environment({"PASSPORT_OP_PROVIDER": "cli"}), OnePasswordCLI)
    assert isinstance(backend_from_environment({"PASSPORT_OP_PROVIDER": "sdk", "OP_SERVICE_ACCOUNT_TOKEN": TOKEN}), OnePasswordSDK)
    with pytest.raises(ValueError):
        backend_from_environment({"PASSPORT_OP_PROVIDER": "connect"})
    with pytest.raises(ValueError) as error:
        backend_from_environment({"PASSPORT_OP_PROVIDER": "sdk"})
    assert "OP_SERVICE_ACCOUNT_TOKEN" in str(error.value)


def test_missing_sdk_package_fails_closed_at_startup(monkeypatch):
    monkeypatch.setitem(sys.modules, "onepassword", None)  # makes `import onepassword` raise ImportError
    with pytest.raises(ValueError) as error:
        OnePasswordSDK(TOKEN)
    assert TOKEN not in str(error.value)


@pytest.mark.parametrize("reference", ["vault/item/field", "op://Vault/Item/field\n", "op://Vault/Item\r/field", "op://a\0b", None])
def test_sdk_rejects_bad_references_before_any_lookup(reference):
    fake = FakeSDK()
    with pytest.raises(ValueError):
        sdk(fake).read(reference)
    assert fake.resolved == [] and fake.auth_calls == []


# Scope-to-reference mapping

def write_map(tmp_path, data, raw=None):
    path = tmp_path / "references.json"
    path.write_text(raw if raw is not None else json.dumps(data), encoding="utf-8")
    return str(path)


def full_map():
    return {f"{r} {a}": ref for (r, a), ref in REFS.items()}


def test_reference_map_parses_every_catalog_pair(tmp_path):
    references, digests = load_reference_map(write_map(tmp_path, full_map()))
    assert references == REFS and set(digests) == CATALOG


@pytest.mark.parametrize("mutate,expect", [
    (lambda m: m.pop("repo/checkout patch.propose"), "does not map: repo/checkout patch.propose"),
    (lambda m: m.update({"production/checkout deploy.execute": "op://Test Vault/Deploy/credential"}), "not in the operation catalog"),
    (lambda m: m.update({"staging/checkout code.read": "op://Test Vault/Mixed/credential"}), "not in the operation catalog"),
    (lambda m: m.update({"staging/checkout  logs.read": "op://Test Vault/Logs/credential"}), "not in the operation catalog"),
    (lambda m: m.update({"repo/checkout code.read": "https://example.invalid/secret"}), "not a single-line op:// reference"),
    (lambda m: m.update({"repo/checkout code.read": "op://Test Vault/Code/credential\nop://Other/x/y"}), "not a single-line op:// reference"),
    (lambda m: m.update({"repo/checkout code.read": 7}), "not a single-line op:// reference"),
    (lambda m: m.update({"repo/checkout code.read": {"reference": "op://V/I/f", "url": "x"}}), "needs only reference"),
    (lambda m: m.update({"repo/checkout code.read": {"reference": "op://V/I/f", "sha256": "abc"}}), "SHA-256 hex digest"),
])
def test_reference_map_validation_fails_closed(tmp_path, mutate, expect):
    mapping = full_map()
    mutate(mapping)
    with pytest.raises(ValueError) as error:
        load_reference_map(write_map(tmp_path, mapping))
    assert expect in str(error.value)


@pytest.mark.parametrize("raw", ["not json", "[]", '{"staging/checkout logs.read": "op://a/b/c", "staging/checkout logs.read": "op://a/b/c"}'])
def test_malformed_or_duplicated_map_fails_closed(tmp_path, raw):
    with pytest.raises(ValueError):
        load_reference_map(write_map(tmp_path, None, raw))


def test_missing_map_file_fails_closed(tmp_path):
    with pytest.raises(ValueError):
        load_reference_map(str(tmp_path / "absent.json"))


def test_bad_map_stops_server_startup(tmp_path, monkeypatch):
    mapping = full_map()
    mapping.pop("repo/checkout code.read")
    monkeypatch.setenv("PASSPORT_OP_REFERENCES", write_map(tmp_path, mapping))
    monkeypatch.setenv("PASSPORT_FIXTURE_KEY_SHA256", digest(SECRET))
    with pytest.raises(ValueError):
        create_app(tmp_path / "state")


def test_single_and_mapped_references_together_are_ambiguous(tmp_path, monkeypatch):
    monkeypatch.setenv("PASSPORT_OP_REFERENCES", write_map(tmp_path, full_map()))
    monkeypatch.setenv("PASSPORT_OP_REFERENCE", "op://Test Vault/Logs/credential")
    monkeypatch.setenv("PASSPORT_FIXTURE_KEY_SHA256", digest(SECRET))
    with pytest.raises(ValueError):
        Executor.from_environment(Passport(tmp_path / "state"))


class RecordingBackend:
    mode = "1password-cli"

    def __init__(self, values):
        self.values, self.reads = values, []

    def read(self, reference):
        self.reads.append(reference)
        return self.values[reference]


def test_executor_resolves_only_the_dispatched_pairs_reference(tmp_path, monkeypatch):
    values = {ref: f"key-for-{pair[1]}" for pair, ref in REFS.items()}
    mapping = {f"{r} {a}": {"reference": ref, "sha256": digest(values[ref])} for (r, a), ref in REFS.items()}
    monkeypatch.setenv("PASSPORT_OP_REFERENCES", write_map(tmp_path, mapping))
    backend = RecordingBackend(values)
    engine = Passport(tmp_path / "state")
    executor = Executor.from_environment(engine, backend)
    root = engine.create_run(budget=3)
    for pair in [("repo/checkout", "code.read"), ("staging/checkout", "logs.read")]:
        before = list(backend.reads)
        assert executor.execute(root["token"], *pair, "key-" + pair[1])["state"] == "completed"
        assert backend.reads[len(before):] == [REFS[pair]]
    # A forbidden pair is denied before any reference is resolved.
    with pytest.raises(Exception):
        executor.execute(root["token"], "production/checkout", "deploy.execute", "deny")
    assert backend.reads == [REFS[("repo/checkout", "code.read")], REFS[("staging/checkout", "logs.read")]]


def test_a_key_for_one_pair_is_rejected_by_another_pairs_verifier(tmp_path, monkeypatch):
    # Every reference resolves to the log reader's key; the code pair's verifier refuses it.
    values = {ref: "key-for-logs.read" for ref in REFS.values()}
    mapping = {f"{r} {a}": {"reference": ref, "sha256": digest(f"key-for-{a}")} for (r, a), ref in REFS.items()}
    monkeypatch.setenv("PASSPORT_OP_REFERENCES", write_map(tmp_path, mapping))
    engine = Passport(tmp_path / "state")
    executor = Executor.from_environment(engine, RecordingBackend(values))
    root = engine.create_run(budget=2)
    assert executor.execute(root["token"], "staging/checkout", "logs.read", "a")["state"] == "completed"
    assert executor.execute(root["token"], "repo/checkout", "code.read", "b")["state"] == "failed"


def test_mapped_cli_uses_fixed_argv_for_the_dispatched_reference(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("agent_passport.broker.shutil.which", lambda name: "/trusted/op")

    def run(args, **kwargs):
        calls.append(args)
        assert not kwargs.get("shell")
        return SimpleNamespace(returncode=0, stdout=SECRET, stderr="")
    monkeypatch.setattr("agent_passport.broker.subprocess.run", run)
    monkeypatch.setenv("PASSPORT_OP_REFERENCES", write_map(tmp_path, full_map()))
    monkeypatch.setenv("PASSPORT_FIXTURE_KEY_SHA256", digest(SECRET))
    engine = Passport(tmp_path / "state")
    executor = Executor.from_environment(engine)
    assert executor.provider.mode == "1password-cli"
    root = engine.create_run(budget=1)
    assert executor.execute(root["token"], "repo/checkout", "patch.propose", "p")["state"] == "completed"
    assert calls == [["/trusted/op", "read", REFS[("repo/checkout", "patch.propose")], "--no-newline"]]


# Issuer key from a reference

def raw_key():
    key = Ed25519PrivateKey.generate()
    return key, key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


class KeyBackend:
    mode = "1password-sdk"

    def __init__(self, value=None, fail=False):
        self.value, self.fail, self.reads = value, fail, []

    def read(self, reference):
        self.reads.append(reference)
        if self.fail:
            raise CredentialUnavailable("1Password credential resolution failed.")
        return self.value


KEY_REF = {"PASSPORT_ISSUER_KEY_REFERENCE": "op://Test Vault/Issuer/key"}


def state_bytes(directory):
    return b"".join(p.read_bytes() for p in directory.rglob("*") if p.is_file())


def test_issuer_key_from_reference_signs_and_never_touches_disk(tmp_path):
    key, raw = raw_key()
    encoded = b64(raw)
    state = tmp_path / "state"
    passport = passport_from_environment(state, KeyBackend(encoded), KEY_REF)
    assert passport.public_key == Passport(tmp_path / "other", issuer_key=key).public_key
    assert passport.issuer_key_source == "1password-sdk"
    root = passport.create_run(budget=1)
    result = Executor(passport).execute(root["token"], "staging/checkout", "logs.read", "k")
    assert verify_receipt(result["receipt"], passport.public_key)
    assert not (state / "issuer.key").exists() and not list(state.glob("issuer-*"))
    contents = state_bytes(state)
    assert raw not in contents and encoded.encode() not in contents


def test_padded_issuer_key_is_accepted(tmp_path):
    key, raw = raw_key()
    passport = passport_from_environment(tmp_path, KeyBackend(b64(raw) + "="), KEY_REF)
    assert passport.public_key == Passport(tmp_path / "other", issuer_key=key).public_key


def test_unresolvable_issuer_key_fails_closed_without_generating_a_file(tmp_path):
    with pytest.raises(ValueError) as error:
        passport_from_environment(tmp_path / "state", KeyBackend(fail=True), KEY_REF)
    assert "refusing to start" in str(error.value)
    assert not (tmp_path / "state").exists() or not list((tmp_path / "state").glob("issuer*"))


@pytest.mark.parametrize("value", [b64(b"\x01" * 31), b64(b"\x01" * 33), b64(b"\x01" * 64), "", "not base64!" * 4,
                                   base64.b64encode(b"\xfb" * 32).decode(), b64(b"\x01" * 32) + "\n"])
def test_issuer_key_with_wrong_length_or_encoding_fails(tmp_path, value):
    with pytest.raises(ValueError) as error:
        passport_from_environment(tmp_path / "state", KeyBackend(value), KEY_REF)
    assert value.strip() == "" or value.strip() not in str(error.value)
    assert not (tmp_path / "state").exists() or not list((tmp_path / "state").glob("issuer*"))


def test_server_startup_fails_when_issuer_key_cannot_be_resolved(tmp_path, monkeypatch, fake_onepassword):
    fake_onepassword.fail = "resolve"
    monkeypatch.setenv("PASSPORT_OP_PROVIDER", "sdk")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
    monkeypatch.setenv("PASSPORT_ISSUER_KEY_REFERENCE", "op://Test Vault/Issuer/key")
    with pytest.raises(ValueError) as error:
        create_app(tmp_path / "state")
    assert LEAK not in str(error.value) and TOKEN not in str(error.value)
    assert not (tmp_path / "state" / "issuer.key").exists()


def test_server_uses_issuer_key_from_sdk_and_reports_its_source(tmp_path, monkeypatch, fake_onepassword):
    key, raw = raw_key()
    fake_onepassword.secrets_by_reference = {"op://Test Vault/Issuer/key": b64(raw)}
    monkeypatch.setenv("PASSPORT_OP_PROVIDER", "sdk")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
    monkeypatch.setenv("PASSPORT_ISSUER_KEY_REFERENCE", "op://Test Vault/Issuer/key")
    state = tmp_path / "state"
    client = TestClient(create_app(state))
    health = client.get("/health").json()
    assert health == {"status": "ok", "credential_mode": "synthetic", "issuer_key": "1password-sdk"}
    assert client.app.state.passport.public_key == Passport(tmp_path / "other", issuer_key=key).public_key
    assert not (state / "issuer.key").exists() and raw not in state_bytes(state)
    assert b64(raw) not in client.get("/health").text


def test_file_issuer_key_stays_the_default(tmp_path):
    passport = passport_from_environment(tmp_path, environ={})
    assert passport.issuer_key_source == "file" and (tmp_path / "issuer.key").exists()


@pytest.mark.parametrize("script", ["approve", "owners"])
def test_new_operator_scripts_use_the_configured_issuer(tmp_path, monkeypatch, capsys, script):
    from scripts.approve import main as approve
    from scripts.owners import main as owners
    key, raw = raw_key()
    backend = KeyBackend(b64(raw))
    monkeypatch.setenv("PASSPORT_ISSUER_KEY_REFERENCE", KEY_REF["PASSPORT_ISSUER_KEY_REFERENCE"])
    monkeypatch.setattr("agent_passport.broker.backend_from_environment", lambda *args: backend)
    state = tmp_path / "state"
    engine = Passport(state, issuer_key=key)
    root = engine.create_run()
    if script == "approve":
        oid = engine.reserve(root["token"], "staging/checkout", "config.write", "config")["id"]
        result = approve(["--state-dir", str(state), oid, "--decision", "approve", "--reason", "Operator reviewed the change."])
    else:
        result = owners(["--state-dir", str(state), "deactivate", root["grant"]["owner"]])
    assert result == 0
    output = capsys.readouterr().out
    assert verify_receipt(json.loads(output)["receipt"], engine.public_key)
    assert not (state / "issuer.key").exists()
    assert raw not in state_bytes(state) and b64(raw).encode() not in state_bytes(state)
    assert b64(raw) not in output


@pytest.mark.parametrize("script", ["approve", "owners"])
def test_new_operator_scripts_fail_closed_on_issuer_lookup_failure(tmp_path, monkeypatch, capsys, script):
    from scripts.approve import main as approve
    from scripts.owners import main as owners
    monkeypatch.setenv("PASSPORT_ISSUER_KEY_REFERENCE", KEY_REF["PASSPORT_ISSUER_KEY_REFERENCE"])
    monkeypatch.setattr("agent_passport.broker.backend_from_environment", lambda *args: KeyBackend(fail=True))
    state = tmp_path / "state"
    result = approve(["--state-dir", str(state)]) if script == "approve" else owners(["--state-dir", str(state), "list"])
    assert result == 2 and "refusing to start" in capsys.readouterr().err
    assert not state.exists()


def test_generate_issuer_key_script_prints_a_loadable_key_and_writes_nothing(tmp_path, monkeypatch, capsys):
    from scripts.generate_issuer_key import main
    monkeypatch.chdir(tmp_path)
    assert main() == 0
    captured = capsys.readouterr()
    value = captured.out.strip()
    passport = passport_from_environment(tmp_path / "state", KeyBackend(value), KEY_REF)
    assert passport.public_key in captured.err and value not in captured.err
    assert [p.name for p in tmp_path.iterdir()] == ["state"]
