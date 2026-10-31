"""Property-based tests of the enforcement invariants in AGENTS.md.

Each property states an invariant over generated inputs and checks it against the real engine,
not a mock. A passing property means no counterexample was found in the examples tried; it is not
a proof. See docs/security-testing.md.
"""
from collections import Counter
import copy
import hashlib
import itertools
import json
import shutil
import tempfile

from hypothesis import assume, given, settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule
import pytest

from agent_passport.broker import CredentialUnavailable, Executor
from agent_passport.core import (CATALOG, UNRESOLVED, Denied, Holder, Passport, b64, canonical, delegate_fields,
                                 execute_fields, request_digest, token_digest, unb64)
from scripts.verify_evidence import MALFORMED, verify

PAIRS = sorted(CATALOG)


def scaled(n):
    """Scale an example count with the active profile (60 examples by default)."""
    return max(n, settings().max_examples * n // 60)


def denial(fn):
    """Run fn and return the Denied rule, or None if it succeeded."""
    try:
        fn()
    except Denied as error:
        return error.rule
    return None


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    return Passport(tmp_path_factory.mktemp("properties"))


# --- Scope attenuation -------------------------------------------------------------------------

RESOURCES = ["staging/checkout", "repo/checkout", "production/checkout", "staging/*", "repo/*", "*", "",
             "Staging/checkout", "staging/checkout ", "r" * 100, "r" * 101]
ACTIONS = ["logs.read", "code.read", "patch.propose", "deploy.execute", "logs.*", "*", "", "a" * 100, "a" * 101]
NON_STRINGS = st.one_of(st.none(), st.booleans(), st.integers(), st.lists(st.text(max_size=3), max_size=2),
                        st.dictionaries(st.text(max_size=3), st.integers(), max_size=2))


def field(names):
    return st.one_of(st.sampled_from(names), st.text(max_size=6), NON_STRINGS)


catalog_entry = st.sampled_from(PAIRS).map(lambda p: {"resource": p[0], "action": p[1]})
odd_entry = st.one_of(
    st.fixed_dictionaries({"resource": field(RESOURCES), "action": field(ACTIONS)}),
    # Accepted shapes the HTTP layer forbids but the engine must still normalize safely.
    st.fixed_dictionaries({"resource": st.sampled_from(RESOURCES), "action": st.sampled_from(ACTIONS),
                           "extra": st.text(max_size=4)}),
    st.fixed_dictionaries({"resource": st.sampled_from(RESOURCES)}),
    st.fixed_dictionaries({"action": st.sampled_from(ACTIONS)}),
    NON_STRINGS, st.text(max_size=8))
scope_request = st.one_of(
    st.lists(catalog_entry, min_size=1, max_size=4),
    st.lists(st.one_of(catalog_entry, odd_entry), max_size=22),
    NON_STRINGS)


def oracle(request):
    """Independent restatement of a valid request: 1-20 entries, each with bounded string fields."""
    if not isinstance(request, list) or not 1 <= len(request) <= 20:
        return None
    pairs = set()
    for entry in request:
        if not isinstance(entry, dict) or "resource" not in entry or "action" not in entry:
            return None
        pair = (entry["resource"], entry["action"])
        if not all(isinstance(v, str) and 1 <= len(v) <= 100 for v in pair):
            return None
        pairs.add(pair)
    return pairs


def granted_pairs(result):
    return {(s["resource"], s["action"]) for s in result["grant"]["scopes"]}


def attempt_delegate(engine, parent, request, parent_pairs):
    """Delegate and check the outcome against the oracle. Returns the child, or None if denied."""
    expected = oracle(request)
    try:
        child = engine.delegate(parent["token"], "Worker", request, parent["grant"]["expires"])
    except Denied as error:
        if expected is None:
            assert error.rule == "SCOPE_INVALID"
        else:
            assert error.rule == "SCOPE_ESCALATION" and not expected <= parent_pairs
        return None
    pairs = granted_pairs(child)
    assert expected is not None, "an invalid scope request was accepted"
    # Exactly the requested pairs: normalization never adds or widens a pair.
    assert pairs == expected and pairs <= parent_pairs
    return child


@settings(max_examples=scaled(80))
@given(parent_request=scope_request, child_request=scope_request)
def test_delegation_never_widens_resource_action_pairs(engine, parent_request, child_request):
    root = engine.create_run(budget=1000)
    parent = attempt_delegate(engine, root, parent_request, set(CATALOG))
    if parent is None:
        return
    child = attempt_delegate(engine, parent, child_request, granted_pairs(parent))
    if child is not None:
        assert granted_pairs(child) <= granted_pairs(parent) <= set(CATALOG)


@settings(max_examples=scaled(40))
@given(scopes=st.lists(st.sampled_from(PAIRS), min_size=1, unique=True))
def test_pairs_never_combine_as_a_cartesian_product(engine, scopes):
    root = engine.create_run(budget=1000)
    agent = engine.delegate(root["token"], "Worker", [{"resource": r, "action": a} for r, a in scopes],
                            root["grant"]["expires"])
    granted = granted_pairs(agent)
    resources, actions = {r for r, _ in granted}, {a for _, a in granted}
    for index, pair in enumerate(itertools.product(resources, actions)):
        rule = denial(lambda: engine.reserve(agent["token"], *pair, f"k{index}"))
        assert (rule is None) == (pair in granted)
        if rule is not None:
            assert rule == "RESOURCE_ACTION_DENIED"


@settings(max_examples=scaled(60))
@given(scopes=st.lists(st.sampled_from(PAIRS), min_size=1, unique=True),
       resource=field(RESOURCES), action=field(ACTIONS))
def test_reservation_is_allowed_only_for_a_granted_pair(engine, scopes, resource, action):
    root = engine.create_run(budget=1000)
    agent = engine.delegate(root["token"], "Worker", [{"resource": r, "action": a} for r, a in scopes],
                            root["grant"]["expires"])
    rule = denial(lambda: engine.reserve(agent["token"], resource, action, "k"))
    bounded = all(isinstance(v, str) and 1 <= len(v) <= 100 for v in (resource, action))
    if not bounded:
        assert rule == "REQUEST_INVALID"
    elif (resource, action) in set(scopes):
        assert rule is None
    else:
        assert rule == "RESOURCE_ACTION_DENIED"


# --- Shared budget, retries and outcomes ------------------------------------------------------

class CountingService:
    """Fixture upstream that records every call and returns a chosen outcome."""
    def __init__(self, calls, key, outcome):
        self.calls, self.key, self.outcome = calls, key, outcome

    def execute(self, credential, resource, action, operation_id=None):
        self.calls[self.key] += 1
        if self.outcome == "timeout":
            raise TimeoutError("effect unknown")
        if self.outcome == "reject":
            raise CredentialUnavailable("rejected before any effect")
        return {"ok": True}


class SharedBudgetMachine(RuleBasedStateMachine):
    """Random delegate/reserve/dispatch/settle/revoke/retry/reconcile sequences over one tree.

    The model is an independent restatement of the documented rules; every engine result is
    compared with it, and invariants are read from the database itself.
    """

    @initialize(budget=st.integers(1, 6))
    def start(self, budget):
        self.directory = tempfile.mkdtemp(prefix="passport-machine-")
        self.now = 1_000_000.0
        self.engine = Passport(self.directory, clock=lambda: self.now)
        root = self.engine.create_run(budget=budget, ttl=3600)
        self.run_id, self.budget, self.expires = root["run_id"], budget, root["grant"]["expires"]
        self.agents = [{"token": root["token"], "id": root["grant"]["id"], "parent": None, "pairs": set(CATALOG), "depth": 0}]
        self.revoked = set()
        self.ops = {}        # operation id -> {"agent", "key", "pair", "state", "created"}
        self.by_key = {}     # (agent index, request key) -> operation id
        self.spent = self.reserved = 0
        self.dispatches = Counter()
        self.calls = Counter()

    def teardown(self):
        shutil.rmtree(getattr(self, "directory", ""), ignore_errors=True)

    def chain_rule(self, index):
        while index is not None:
            if self.agents[index]["id"] in self.revoked:
                return "ANCESTOR_REVOKED"
            if self.expires <= self.now:
                return "GRANT_EXPIRED"
            index = self.agents[index]["parent"]
        return None

    def expected_reservation(self, agent, key, pair):
        """('denied', rule) | ('duplicate', op id) | ('new', None), in the engine's check order."""
        rule = self.chain_rule(agent)
        if rule:
            return "denied", rule
        if pair not in self.agents[agent]["pairs"]:
            return "denied", "RESOURCE_ACTION_DENIED"
        existing = self.by_key.get((agent, key))
        if existing:
            if self.ops[existing]["pair"] != pair:
                return "denied", "IDEMPOTENCY_CONFLICT"
            return "duplicate", existing
        if self.spent + self.reserved >= self.budget:
            return "denied", "BUDGET_EXHAUSTED"
        return "new", None

    def record_new(self, agent, key, pair, oid):
        assert oid not in self.ops
        self.ops[oid] = {"agent": agent, "key": key, "pair": pair, "state": "reserved", "created": self.now}
        self.by_key[(agent, key)] = oid
        self.reserved += 1

    def apply_settlement(self, oid, outcome):
        self.ops[oid]["state"] = outcome
        if outcome != "unknown":
            self.reserved -= 1
            self.spent += outcome == "completed"

    @precondition(lambda self: len(self.agents) < 10)
    @rule(data=st.data())
    def delegate(self, data):
        parent = data.draw(st.integers(0, len(self.agents) - 1), label="parent")
        pairs = data.draw(st.lists(st.sampled_from(PAIRS), min_size=1, unique=True), label="pairs")
        expected = self.chain_rule(parent)
        if not expected and not set(pairs) <= self.agents[parent]["pairs"]:
            expected = "SCOPE_ESCALATION"
        if not expected and self.agents[parent]["depth"] >= 8:
            expected = "DELEGATION_LIMIT"
        try:
            child = self.engine.delegate(self.agents[parent]["token"], "Worker",
                                         [{"resource": r, "action": a} for r, a in pairs], self.expires)
        except Denied as error:
            assert error.rule == expected
            return
        assert expected is None and set(pairs) <= self.agents[parent]["pairs"]
        assert child["grant"]["run_id"] == self.run_id
        self.agents.append({"token": child["token"], "id": child["grant"]["id"], "parent": parent, "pairs": set(pairs),
                            "depth": self.agents[parent]["depth"] + 1})

    @rule(data=st.data())
    def reserve(self, data):
        agent = data.draw(st.integers(0, len(self.agents) - 1), label="agent")
        key = data.draw(st.sampled_from(["k0", "k1", "k2", "k3"]), label="key")
        pair = data.draw(st.sampled_from(PAIRS), label="pair")
        kind, value = self.expected_reservation(agent, key, pair)
        try:
            op = self.engine.reserve(self.agents[agent]["token"], pair[0], pair[1], key)
        except Denied as error:
            assert (kind, value) == ("denied", error.rule)
            return
        if kind == "duplicate":
            # A retry returns the original operation and reserves nothing.
            assert op["duplicate"] and op["id"] == value and op["state"] == self.ops[value]["state"]
        else:
            assert kind == "new" and not op["duplicate"]
            self.record_new(agent, key, pair, op["id"])

    @rule(data=st.data(), outcome=st.sampled_from(["ok", "timeout", "reject"]))
    def execute(self, data, outcome):
        """The full executor path: a retried key must never reach the upstream again."""
        agent = data.draw(st.integers(0, len(self.agents) - 1), label="agent")
        key = data.draw(st.sampled_from(["k0", "k1", "k2", "k3"]), label="key")
        pair = data.draw(st.sampled_from(PAIRS), label="pair")
        kind, value = self.expected_reservation(agent, key, pair)
        service = CountingService(self.calls, (agent, key), outcome)
        try:
            result = Executor(self.engine, service=service).execute(self.agents[agent]["token"], pair[0], pair[1], key)
        except Denied as error:
            assert (kind, value) == ("denied", error.rule)
            return
        if kind == "duplicate":
            assert result["duplicate"] and result["operation_id"] == value
            return
        assert kind == "new"
        oid = result["operation_id"]
        self.record_new(agent, key, pair, oid)
        self.dispatches[oid] += 1
        self.ops[oid]["state"] = "dispatched"
        settled = {"ok": "completed", "timeout": "unknown", "reject": "failed"}[outcome]
        assert result["state"] == settled
        self.apply_settlement(oid, settled)

    @precondition(lambda self: self.ops)
    @rule(data=st.data())
    def dispatch(self, data):
        oid = data.draw(st.sampled_from(sorted(self.ops)), label="operation")
        op = self.ops[oid]
        rule = self.chain_rule(op["agent"])
        try:
            dispatched = self.engine.dispatch(oid)
        except Denied as error:
            assert op["state"] == "reserved" and error.rule == rule
            op["state"] = "cancelled"
            self.reserved -= 1
            return
        assert dispatched == (op["state"] == "reserved" and rule is None)
        if dispatched:
            op["state"] = "dispatched"
            self.dispatches[oid] += 1

    @precondition(lambda self: self.ops)
    @rule(data=st.data(), outcome=st.sampled_from(["completed", "failed", "unknown"]))
    def settle(self, data, outcome):
        oid = data.draw(st.sampled_from(sorted(self.ops)), label="operation")
        rule = denial(lambda: self.engine.settle(oid, outcome, {"outcome": outcome}))
        if self.ops[oid]["state"] != "dispatched":
            assert rule == "OPERATION_STATE"
            return
        assert rule is None
        self.apply_settlement(oid, outcome)

    @rule(data=st.data())
    def revoke(self, data):
        agent = data.draw(st.integers(0, len(self.agents) - 1), label="agent")
        self.engine.revoke(self.agents[agent]["id"])
        self.revoked.add(self.agents[agent]["id"])

    @rule(seconds=st.integers(0, 400))
    def advance_clock(self, seconds):
        self.now += seconds

    @precondition(lambda self: self.ops)
    @rule(data=st.data(), outcome=st.sampled_from(["completed", "not_executed"]))
    def reconcile(self, data, outcome):
        oid = data.draw(st.sampled_from(sorted(self.ops)), label="operation")
        op = self.ops[oid]
        rule = denial(lambda: self.engine.reconcile(oid, outcome, "Operator checked the upstream record."))
        if op["state"] not in UNRESOLVED:
            assert rule == "OPERATION_STATE"
        elif op["state"] != "unknown" and self.now - op["created"] < 300:
            # Elapsed time alone never settles anything, and a young reservation may still be running.
            assert rule == "OPERATION_IN_FLIGHT"
        else:
            assert rule is None
            op["state"] = "reconciled_" + outcome
            self.reserved -= 1
            self.spent += outcome == "completed"

    @invariant()
    def budget_is_one_shared_row(self):
        db = self.engine.connect()
        try:
            runs = db.execute("SELECT * FROM runs").fetchall()
            grant_runs = {r[0] for r in db.execute("SELECT DISTINCT run_id FROM grants")}
            states = Counter(r[0] for r in db.execute("SELECT state FROM operations"))
        finally:
            db.close()
        # Every descendant draws from the root's single row; no child row ever exists.
        assert len(runs) == 1 and grant_runs == {self.run_id}
        run = runs[0]
        assert run["budget"] == self.budget
        assert run["spent"] + run["reserved"] <= run["budget"]
        assert (run["spent"], run["reserved"]) == (self.spent, self.reserved)
        # Unknown outcomes and unsettled reservations keep holding their unit.
        assert run["reserved"] == sum(states[s] for s in UNRESOLVED)
        assert run["spent"] == states["completed"] + states["reconciled_completed"]
        assert states == Counter(op["state"] for op in self.ops.values())

    @invariant()
    def nothing_executes_twice(self):
        assert all(count == 1 for count in self.dispatches.values())
        assert all(count == 1 for count in self.calls.values())


SharedBudgetMachine.TestCase.settings = settings(max_examples=scaled(30), stateful_step_count=30)
TestSharedBudget = SharedBudgetMachine.TestCase


# --- Token and holder-proof parsing ------------------------------------------------------------

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
junk_token = st.one_of(
    st.text(max_size=300), st.text(alphabet=B64 + ".=+/!", max_size=300), st.binary(max_size=100),
    st.none(), st.integers(), st.lists(st.text(max_size=5), max_size=3), st.dictionaries(st.text(max_size=3), st.text(max_size=3), max_size=2),
    st.tuples(st.binary(max_size=200), st.binary(max_size=80)).map(lambda p: b64(p[0]) + "." + b64(p[1])),
    st.just("x" * 12001))


@settings(max_examples=scaled(100))
@given(token=junk_token)
def test_arbitrary_tokens_never_authenticate(engine, token):
    for call in (lambda: engine.inspect(token), lambda: engine.reserve(token, *PAIRS[0], "k"),
                 lambda: engine.delegate(token, "W", [{"resource": PAIRS[0][0], "action": PAIRS[0][1]}], 2e9)):
        assert denial(call) == "IDENTITY_INVALID"


def mutations(value):
    """Byte-level edits of a token or proof string: substitute, insert, delete, truncate, swap."""
    # Draw positions independently of the value's length, which varies between runs.
    index = st.integers(0, 4095).map(lambda i: i % len(value))
    char = st.sampled_from(B64 + ".=+/!~ \x00é")
    return st.one_of(
        st.tuples(index, char).map(lambda t: value[:t[0]] + t[1] + value[t[0] + 1:]),
        st.tuples(index, char).map(lambda t: value[:t[0]] + t[1] + value[t[0]:]),
        index.map(lambda i: value[:i] + value[i + 1:]),
        index.map(lambda i: value[:i]),
        st.just(".".join(reversed(value.split(".")))),
        st.just(value + "." + value.split(".")[1])).filter(lambda m: m != value)


def decoded(value):
    try:
        return [unb64(part) for part in value.split(".")]
    except ValueError:
        return None


@settings(max_examples=scaled(150))
@given(data=st.data())
def test_mutated_tokens_never_authenticate_different_content(engine, data):
    root = engine.create_run()
    mutated = data.draw(mutations(root["token"]))
    try:
        result = engine.inspect(mutated)
    except Denied as error:
        assert error.rule == "IDENTITY_INVALID"
        return
    # Only a different spelling of the very same signed bytes can get here (see the xfail below).
    assert decoded(mutated) == decoded(root["token"])
    assert result["grant"]["id"] == root["grant"]["id"]


@pytest.mark.xfail(strict=True, reason="GAP: unb64 accepts non-canonical base64 (unused trailing bits, extra '=' "
                   "padding, '+'/'/' alphabet), so several distinct token strings authenticate the same grant. "
                   "No authority is gained, but any future token-string denylist or log correlation would be bypassable.")
def test_only_the_canonical_token_spelling_authenticates(engine):
    root = engine.create_run()
    payload, signature = root["token"].split(".")
    variants = [payload + "." + signature + "=", payload + "=." + signature]
    for c in B64:
        spelled = signature[:-1] + c
        if c != signature[-1] and unb64(spelled) == unb64(signature):
            variants.append(payload + "." + spelled)
    for variant in variants:
        assert denial(lambda: engine.inspect(variant)) == "IDENTITY_INVALID", variant


json_scalar = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True), st.text(max_size=20))
json_value = st.recursive(json_scalar, lambda inner: st.one_of(st.lists(inner, max_size=3),
                                                               st.dictionaries(st.text(max_size=5), inner, max_size=3)),
                          max_leaves=8)


def sql_bindable(value):
    return not isinstance(value, (list, dict)) and not (isinstance(value, int) and not -2**63 <= value < 2**63)


@settings(max_examples=scaled(100))
@given(claims=st.one_of(json_value, st.dictionaries(st.sampled_from(["v", "issuer", "id", "run_id", "parent", "subject",
                                                                      "scopes", "expires", "depth", "cnf"]),
                                                     st.one_of(st.none(), st.integers(), st.floats(allow_nan=False),
                                                               st.text(max_size=20)))).filter(
    lambda c: not (isinstance(c, dict) and not sql_bindable(c.get("id")))))
def test_issuer_signed_claims_must_match_the_stored_grant(engine, claims):
    """Even with the issuer's signature, claims that are not the stored grant's exact bytes are refused.

    Ids are limited to SQL-bindable scalars. A list, object or out-of-range integer id makes sqlite
    raise ProgrammingError or OverflowError instead of Denied; reaching that needs the issuer's
    private key, so it is a robustness note, not an agent-reachable path.
    """
    payload = canonical(claims)
    token = b64(payload) + "." + b64(engine.key.sign(payload))
    assert denial(lambda: engine.inspect(token)) == "IDENTITY_INVALID"


@pytest.fixture(scope="module")
def bound(engine):
    holder = Holder()
    return {**engine.create_run(budget=1000, holder_key=holder.public_key), "holder": holder}


junk_proof = st.one_of(
    st.text(max_size=300), st.text(alphabet=B64 + ".=", max_size=300), st.binary(max_size=50), st.integers(),
    st.lists(st.text(max_size=3), max_size=2), st.just("p" * 2001),
    st.tuples(st.binary(max_size=200), st.binary(min_size=64, max_size=64)).map(lambda p: b64(p[0]) + "." + b64(p[1])))


@settings(max_examples=scaled(100))
@given(proof=junk_proof)
def test_arbitrary_holder_proofs_are_refused(engine, bound, proof):
    assert denial(lambda: engine.inspect(bound["token"], proof)) == "PROOF_INVALID"
    assert denial(lambda: engine.reserve(bound["token"], *PAIRS[0], "junk", proof)) == "PROOF_INVALID"


@settings(max_examples=scaled(100))
@given(data=st.data())
def test_mutated_holder_proofs_are_refused_and_never_replay(engine, bound, data):
    proof = bound["holder"].proof(bound["token"], "inspect", {})
    mutated = data.draw(mutations(proof))
    rule = denial(lambda: engine.inspect(bound["token"], mutated))
    if rule is None:
        # A respelling of the same signed bytes carries the same nonce, so the original now replays.
        assert decoded(mutated) == decoded(proof)
        assert denial(lambda: engine.inspect(bound["token"], proof)) == "PROOF_REPLAYED"
    else:
        assert rule == "PROOF_INVALID"
        assert denial(lambda: engine.inspect(bound["token"], proof)) is None


@settings(max_examples=scaled(150))
@given(body=st.one_of(json_value, st.fixed_dictionaries({
    "ath": st.one_of(st.text(max_size=70), json_scalar), "op": st.one_of(st.sampled_from(["inspect", "execute", "delegate"]), json_scalar),
    "req": st.one_of(st.text(max_size=70), json_scalar), "iat": st.one_of(json_scalar, st.floats(), st.just(1e300)),
    "jti": st.one_of(st.text(min_size=14, max_size=66), json_scalar)})))
def test_holder_signed_garbage_bodies_never_authorize(engine, bound, body):
    """A compromised holder can sign anything; malformed bodies must still be refused cleanly."""
    payload = canonical(body)
    proof = b64(payload) + "." + b64(bound["holder"].key.sign(payload))
    assert denial(lambda: engine.inspect(bound["token"], proof)) in {"PROOF_INVALID", "PROOF_STALE"}


@settings(max_examples=scaled(40))
@given(iat_offset=st.floats(-10_000, 10_000), op=st.sampled_from(["inspect", "execute", "delegate"]))
def test_a_proof_authorizes_only_its_own_operation_and_window(engine, bound, iat_offset, op):
    fields = {"inspect": {}, "execute": execute_fields(*PAIRS[0], "k"),
              "delegate": delegate_fields("W", [{"resource": PAIRS[0][0], "action": PAIRS[0][1]}], 1.0, None)}[op]
    proof = bound["holder"].proof(bound["token"], op, fields, now=engine.clock() + iat_offset)
    rule = denial(lambda: engine.inspect(bound["token"], proof))
    if op != "inspect":
        assert rule == "PROOF_INVALID"
    elif abs(iat_offset) > 60 + 1:
        assert rule == "PROOF_STALE"
    elif abs(iat_offset) < 60 - 1:
        assert rule is None
    body = json.loads(unb64(proof.split(".")[0]))
    assert body["ath"] == token_digest(bound["token"]) and body["req"] == request_digest(op, fields)


# --- Agent HTTP API ----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def api(tmp_path_factory):
    from fastapi.testclient import TestClient
    import os
    previous = os.environ.pop("PASSPORT_OP_REFERENCE", None)
    try:
        from agent_passport.server import create_app
        app = create_app(tmp_path_factory.mktemp("api"))
    finally:
        if previous is not None:
            os.environ["PASSPORT_OP_REFERENCE"] = previous
    client = TestClient(app)  # raise_server_exceptions: any unhandled error fails the test
    coordinator = app.state.demo.agents["Coordinator"]
    return client, coordinator["token"]


header_text = st.text(st.characters(min_codepoint=0x20, max_codepoint=0x7e), max_size=120)


@settings(max_examples=scaled(80))
@given(data=st.data(), path=st.sampled_from(["/api/agent/execute", "/api/agent/delegate", "/api/agent/passport"]),
       use_real_token=st.booleans(), body=json_value)
def test_agent_api_never_errors_on_hostile_input(api, data, path, use_real_token, body):
    client, token = api
    auth = "Bearer " + token if use_real_token else data.draw(header_text, label="authorization")
    headers = {"Authorization": auth, "x-passport-proof": data.draw(header_text, label="proof")}
    if path == "/api/agent/passport":
        response = client.get(path, headers=headers)
    else:
        response = client.post(path, headers=headers, content=json.dumps(body))
    # The coordinator is key-bound and no valid proof is generated, so nothing may succeed either.
    assert response.status_code in {401, 403, 413, 422}, response.text


# --- Offline evidence verifier -----------------------------------------------------------------

@pytest.fixture(scope="module")
def signed(tmp_path_factory):
    """Evidence with a delegated chain, completed, failed, unknown and reconciled operations."""
    now = [2_000_000.0]
    engine = Passport(tmp_path_factory.mktemp("evidence"), clock=lambda: now[0])
    root = engine.create_run()
    worker = engine.delegate(root["token"], "Worker", [{"resource": PAIRS[0][0], "action": PAIRS[0][1]}], root["grant"]["expires"])
    calls = Counter()
    for key, outcome in [("done", "ok"), ("lost", "timeout"), ("refused", "reject"), ("lost-2", "timeout")]:
        Executor(engine, service=CountingService(calls, key, outcome)).execute(worker["token"], *PAIRS[0], key)
    unknown = [o["id"] for o in engine.unresolved(root["run_id"])]
    engine.reconcile(unknown[0], "not_executed", "Operator confirmed no upstream effect.")
    engine.reconcile(unknown[1], "completed", "Operator confirmed the upstream effect.")
    engine.reserve(worker["token"], *PAIRS[0], "pending")
    checkpoint = engine.checkpoint(root["run_id"])
    evidence = engine.evidence(root["run_id"])
    assert evidence["receipts"] and evidence["reconciliations"] and verify(evidence, engine.public_key, [checkpoint])
    return evidence, engine.public_key, checkpoint


def leaf_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaf_paths(item, prefix + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaf_paths(item, prefix + (index,))
    else:
        yield prefix


def container(document, path):
    for key in path[:-1]:
        document = document[key]
    return document


def covered(path):
    """What the verifier actually checks, discovered from scripts/verify_evidence.py.

    Covered: every event field except seq (hash chain), every receipt and reconciliation body
    field and signature, the issuer key, and the run id (bound by receipt bodies). Not covered:
    event seq, the run counters, the grants list, policy, server_time and anything else unsigned.
    """
    top = path[0]
    if top == "events":
        return path[2] != "seq"
    if top in ("receipts", "reconciliations"):
        return path[2] in ("body", "signature")
    if top == "run":
        return path[1] == "id"
    return top == "public_key"


replacement = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=10),
                        st.lists(st.integers(), max_size=2), st.dictionaries(st.text(max_size=3), st.integers(), max_size=2))
REJECTED = (ValueError, KeyError, TypeError)


@settings(max_examples=scaled(200))
@given(data=st.data())
def test_single_field_evidence_mutations_are_rejected_exactly_where_covered(signed, data):
    evidence, key, _ = signed
    path = data.draw(st.sampled_from(sorted(leaf_paths(evidence), key=repr)), label="path")
    changed = copy.deepcopy(evidence)
    parent, last = container(changed, path), path[-1]
    if data.draw(st.booleans(), label="delete") and isinstance(parent, dict):
        del parent[last]
    else:
        new = data.draw(replacement, label="value")
        assume(canonical(new) != canonical(parent[last]))
        parent[last] = new
    if covered(path):
        with pytest.raises(REJECTED):
            verify(changed, key)
    else:
        assert verify(changed, key)["valid"]


@settings(max_examples=scaled(60))
@given(data=st.data())
def test_checkpoint_mutations_are_rejected(signed, data):
    evidence, key, checkpoint = signed
    path = data.draw(st.sampled_from(sorted(leaf_paths(checkpoint), key=repr)), label="path")
    changed = copy.deepcopy(checkpoint)
    parent = container(changed, path)
    new = data.draw(replacement, label="value")
    assume(canonical(new) != canonical(parent[path[-1]]))
    parent[path[-1]] = new
    with pytest.raises(REJECTED):
        verify(evidence, key, [changed])


@settings(max_examples=scaled(40))
@given(data=st.data())
def test_list_edits_match_the_documented_completeness_limits(signed, data):
    """Dropping receipts or an event suffix is invisible without a checkpoint; a covered suffix is not."""
    evidence, key, checkpoint = signed
    changed = copy.deepcopy(evidence)
    kind = data.draw(st.sampled_from(["drop_receipt", "duplicate_receipt", "drop_reconciliation", "drop_suffix", "drop_inner_event", "swap_events"]))
    events = changed["events"]
    if kind in ("drop_receipt", "duplicate_receipt", "drop_reconciliation"):
        items = changed["reconciliations" if kind == "drop_reconciliation" else "receipts"]
        index = data.draw(st.integers(0, len(items) - 1))
        if kind == "duplicate_receipt":
            items.append(copy.deepcopy(items[index]))
        else:
            del items[index]
        assert verify(changed, key)["valid"]
        assert verify(changed, key, [checkpoint])["valid"]  # checkpoints anchor events, not receipts
    elif kind == "drop_suffix":
        keep = data.draw(st.integers(0, len(events) - 1))
        del events[keep:]
        assert verify(changed, key)["valid"]
        with pytest.raises(ValueError):
            verify(changed, key, [checkpoint])
    else:
        index = data.draw(st.integers(0, len(events) - 2))
        if kind == "drop_inner_event":
            del events[index]
        else:
            events[index], events[index + 1] = events[index + 1], events[index]
        with pytest.raises(ValueError):
            verify(changed, key)


@settings(max_examples=scaled(150))
@given(document=st.one_of(json_value, st.fixed_dictionaries(
    {"public_key": st.just("KEY"), "events": json_value, "receipts": json_value, "run": json_value},
    optional={"reconciliations": json_value})), checkpoints=st.one_of(st.just(()), st.lists(json_value, max_size=2)))
def test_verifier_fails_closed_on_arbitrary_documents(document, checkpoints):
    """Malformed evidence must raise an error the CLI reports as a failed verification.

    Found by this property: non-object evidence or events raised AttributeError, which the CLI
    did not catch, so it printed a traceback instead of "Verification failed".
    """
    try:
        result = verify(document, "KEY", checkpoints)
    except MALFORMED:
        return
    # Without the issuer key nothing signed can be forged, so only an empty, unsigned history passes.
    assert result["receipts"] == result["reconciliations"] == result["checkpoints"] == 0


def test_event_hash_covers_everything_but_seq(signed):
    evidence, key, _ = signed
    event = evidence["events"][1]
    body = {k: v for k, v in event.items() if k not in {"seq", "hash"}}
    assert hashlib.sha256(canonical(body)).hexdigest() == event["hash"]
