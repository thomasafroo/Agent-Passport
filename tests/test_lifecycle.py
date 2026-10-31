"""Accountable owners: deprovisioning an owner voids every grant issued on their behalf, online."""
import copy
import json
import threading
import time

from fastapi.testclient import TestClient
import pytest

from agent_passport.broker import Executor
from agent_passport.core import DEFAULT_OWNER, Passport, Denied, verify_receipt
from agent_passport.server import create_app
from scripts.owners import main as owners_cli
from scripts.verify_evidence import verify

LOG_READ = ("staging/checkout", "logs.read")
LOGS = [{"resource": "staging/checkout", "action": "logs.read"}]
USER = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
REASON = "Upstream access log shows no request reached the service."


class UncertainService:
    def execute(self, *args):
        raise TimeoutError("unknown upstream effect")


@pytest.fixture
def clock():
    return [10_000.0]


@pytest.fixture
def engine(tmp_path, clock):
    return Passport(tmp_path, clock=lambda: clock[0])


def assert_denied(rule, fn):
    with pytest.raises(Denied) as error:
        fn()
    assert error.value.rule == rule


def owner(engine, name="dana"):
    return engine.provision_owner(name, name.title() + " Example", "idp-" + name)["owner"]


def child(engine, parent, name="Worker"):
    return engine.delegate(parent["token"], name, LOGS, parent["grant"]["expires"])


def run_of(engine, root):
    return engine.snapshot(root["run_id"])["run"]


def test_owner_is_signed_into_claims_and_inherited_by_descendants(engine):
    dana = owner(engine)
    root = engine.create_run(owner=dana["id"])
    worker = child(engine, root)
    assert root["grant"]["owner"] == worker["grant"]["owner"] == dana["id"]
    receipt = Executor(engine).execute(worker["token"], *LOG_READ, "k")["receipt"]
    assert receipt["body"]["owner"] == dana["id"] and verify_receipt(receipt, engine.public_key)
    assert engine.snapshot(root["run_id"])["owner"]["user_name"] == "dana"


def test_default_owner_is_created_on_demand(engine):
    root = engine.create_run()
    assert root["grant"]["owner"] == DEFAULT_OWNER["id"]
    assert [o["id"] for o in engine.owners()] == [DEFAULT_OWNER["id"]]
    assert [r["body"]["change"] for r in engine.lifecycle()] == ["provisioned"]
    engine.create_run()
    assert len(engine.owners()) == 1 and len(engine.lifecycle()) == 1


def test_deprovisioning_voids_every_run_of_that_owner_only(engine):
    dana, sam = owner(engine, "dana"), owner(engine, "sam")
    runs = [engine.create_run(owner=dana["id"]) for _ in range(2)]
    deep = runs[1]
    for depth in range(4):
        deep = child(engine, deep, f"Level {depth}")
    other = engine.create_run(owner=sam["id"])
    result = engine.deprovision_owner(dana["id"], "Offboarding")
    assert result["owner"]["active"] is False and result["owner"]["deprovisioned_at"] is not None
    assert set(result["receipt"]["body"]["runs"]) == {r["run_id"] for r in runs}
    for agent in (runs[0], runs[1], deep):
        assert_denied("OWNER_DEPROVISIONED", lambda: Executor(engine).execute(agent["token"], *LOG_READ, "after"))
        assert_denied("OWNER_DEPROVISIONED", lambda: child(engine, agent, "Escape"))
    assert Executor(engine).execute(other["token"], *LOG_READ, "after")["state"] == "completed"
    for root in runs:
        snapshot = engine.snapshot(root["run_id"])
        assert {g["state"] for g in snapshot["grants"]} == {"deprovisioned"}
        assert not any(g["directly_revoked"] for g in snapshot["grants"])
        assert snapshot["run"]["reserved"] == 0
        assert any(e["kind"] == "deprovisioned" and e["rule"] == "OWNER_DEPROVISIONED" for e in snapshot["events"])
    assert {g["state"] for g in engine.snapshot(other["run_id"])["grants"]} == {"active"}
    assert not any(e["kind"] == "deprovisioned" for e in engine.snapshot(other["run_id"])["events"])
    assert engine.inspect(deep["token"])["state"] == "OWNER_DEPROVISIONED"


def test_queued_reservation_is_cancelled_once_with_a_refund(engine):
    dana = owner(engine)
    root = engine.create_run(budget=2, owner=dana["id"])
    queued = engine.reserve(root["token"], *LOG_READ, "queued")
    assert run_of(engine, root)["reserved"] == 1
    engine.deprovision_owner(dana["id"])
    assert_denied("OWNER_DEPROVISIONED", lambda: engine.dispatch(queued["id"]))
    run = run_of(engine, root)
    assert run["reserved"] == 0 and run["spent"] == 0
    assert engine.dispatch(queued["id"]) is False
    assert run_of(engine, root)["reserved"] == 0
    # The same key cannot reach the cancelled record either; the chain is checked first.
    assert_denied("OWNER_DEPROVISIONED", lambda: engine.reserve(root["token"], *LOG_READ, "queued"))


def test_dispatched_and_unknown_operations_keep_their_units(engine, clock):
    dana = owner(engine)
    root = engine.create_run(budget=3, owner=dana["id"])
    unknown = Executor(engine, service=UncertainService()).execute(root["token"], *LOG_READ, "timeout")
    assert unknown["state"] == "unknown"
    inflight = engine.reserve(root["token"], *LOG_READ, "inflight")
    assert engine.dispatch(inflight["id"])
    engine.deprovision_owner(dana["id"])
    clock[0] += 30 * 86400
    run = run_of(engine, root)
    assert run["reserved"] == 2 and run["spent"] == 0
    assert {o["id"] for o in engine.unresolved(root["run_id"])} == {unknown["operation_id"], inflight["id"]}
    # The trusted executor still records what it dispatched before the cut.
    assert engine.settle(inflight["id"], "completed", {"ok": True})["receipt"]["body"]["owner"] == dana["id"]
    # Only an operator decision returns the unknown unit.
    engine.reconcile(unknown["operation_id"], "not_executed", REASON)
    run = run_of(engine, root)
    assert run["reserved"] == 0 and run["spent"] == 1


def test_reactivation_does_not_revive_old_grants(engine):
    dana = owner(engine)
    old = engine.create_run(owner=dana["id"])
    worker = child(engine, old)
    engine.deprovision_owner(dana["id"])
    assert_denied("OWNER_DEPROVISIONED", lambda: engine.create_run(owner=dana["id"]))
    reactivated = engine.reactivate_owner(dana["id"])
    assert reactivated["owner"]["active"] and reactivated["receipt"]["body"]["change"] == "reactivated"
    # Same clock, same owner, active again: the old roots were issued under an earlier epoch.
    for agent in (old, worker):
        assert_denied("OWNER_DEPROVISIONED", lambda: Executor(engine).execute(agent["token"], *LOG_READ, "again"))
    assert {g["state"] for g in engine.snapshot(old["run_id"])["grants"]} == {"deprovisioned"}
    assert [e["rule"] for e in engine.snapshot(old["run_id"])["events"] if e["kind"] in ("deprovisioned", "reactivated")] == ["OWNER_DEPROVISIONED", "OWNER_REACTIVATED"]
    fresh = engine.create_run(owner=dana["id"])
    assert Executor(engine).execute(child(engine, fresh)["token"], *LOG_READ, "new")["state"] == "completed"
    # A second cut voids the new issuance too.
    engine.deprovision_owner(dana["id"]); engine.reactivate_owner(dana["id"])
    assert_denied("OWNER_DEPROVISIONED", lambda: Executor(engine).execute(fresh["token"], *LOG_READ, "later"))


def test_repeated_changes_are_no_ops(engine):
    dana = owner(engine)
    root = engine.create_run(owner=dana["id"])
    assert engine.deprovision_owner(dana["id"])["receipt"]
    assert engine.deprovision_owner(dana["id"])["receipt"] is None
    assert engine.owner(dana["id"])["epoch"] == 1
    assert [e["kind"] for e in engine.snapshot(root["run_id"])["events"]].count("deprovisioned") == 1
    assert [r["body"]["change"] for r in engine.lifecycle(dana["id"])] == ["provisioned", "deprovisioned"]


@pytest.mark.parametrize("call,rule", [
    (lambda e: e.provision_owner("", "Name"), "OWNER_INVALID"),
    (lambda e: e.provision_owner("x" * 101, "Name"), "OWNER_INVALID"),
    (lambda e: e.provision_owner("bad\nname", "Name"), "OWNER_INVALID"),
    (lambda e: e.provision_owner("ok", "Name", ""), "OWNER_INVALID"),
    (lambda e: e.set_owner_active("own_missing", False), "OWNER_UNKNOWN"),
    (lambda e: e.set_owner_active(DEFAULT_OWNER["id"], "false"), "OWNER_INVALID"),
    (lambda e: e.create_run(owner="own_missing"), "OWNER_UNKNOWN"),
])
def test_invalid_owner_requests_are_denied(engine, call, rule):
    engine.create_run()
    assert_denied(rule, lambda: call(engine))


def test_user_name_and_external_id_are_unique(engine):
    owner(engine, "dana")
    assert_denied("OWNER_CONFLICT", lambda: engine.provision_owner("dana", "Other"))
    assert_denied("OWNER_CONFLICT", lambda: engine.provision_owner("other", "Other", "idp-dana"))


def test_concurrent_deprovision_and_reservations_are_linearized(tmp_path):
    engine = Passport(tmp_path)
    dana = owner(engine)
    root = engine.create_run(budget=1000, owner=dana["id"])
    workers = [child(engine, root, f"Worker {i}") for i in range(8)]
    barrier, lock, admitted, denials = threading.Barrier(len(workers) + 1), threading.Lock(), [], []

    def reserve(worker, index):
        barrier.wait()
        for n in range(120):
            try:
                op = engine.reserve(worker["token"], *LOG_READ, f"{index}-{n}")
                with lock: admitted.append(op["id"])
            except Denied as e:
                with lock: denials.append(e.rule)
                return

    threads = [threading.Thread(target=reserve, args=(w, i)) for i, w in enumerate(workers)]
    for t in threads: t.start()
    barrier.wait()
    time.sleep(0.02)
    engine.deprovision_owner(dana["id"])
    for t in threads: t.join()
    assert denials == ["OWNER_DEPROVISIONED"] * len(workers)
    events = engine.snapshot(root["run_id"])["events"]
    cut = next(e["seq"] for e in events if e["kind"] == "deprovisioned")
    reserved = [e for e in events if e["kind"] == "reserved"]
    assert admitted and {e["operation_id"] for e in reserved} == set(admitted)
    assert all(e["seq"] < cut for e in reserved)
    assert run_of(engine, root)["reserved"] == len(admitted)


def test_lifecycle_receipts_verify_offline_and_tampering_fails(engine):
    dana = owner(engine)
    root = engine.create_run(owner=dana["id"])
    Executor(engine).execute(root["token"], *LOG_READ, "k")
    engine.deprovision_owner(dana["id"], "Offboarding")
    engine.reactivate_owner(dana["id"], "Rehire")
    evidence = engine.evidence(root["run_id"])
    assert [r["body"]["change"] for r in evidence["lifecycle"]] == ["provisioned", "deprovisioned", "reactivated"]
    assert evidence["lifecycle"][1]["body"]["runs"] == [root["run_id"]] and evidence["lifecycle"][1]["body"]["actor"] == "Offboarding"
    assert verify(evidence, engine.public_key)["lifecycle"] == 3
    for field, value in (("active", True), ("epoch", 0), ("runs", []), ("actor", "Someone else")):
        altered = copy.deepcopy(evidence); altered["lifecycle"][1]["body"][field] = value
        with pytest.raises(ValueError, match="lifecycle"):
            verify(altered, engine.public_key)
    dropped = copy.deepcopy(evidence); dropped["events"] = [e for e in dropped["events"] if e["kind"] != "deprovisioned"]
    with pytest.raises(ValueError, match="chain"):
        verify(dropped, engine.public_key)


def test_signed_types_cannot_stand_in_for_each_other(engine, clock):
    dana = owner(engine)
    root = engine.create_run(budget=3, owner=dana["id"])
    Executor(engine).execute(root["token"], *LOG_READ, "done")
    oid = Executor(engine, service=UncertainService()).execute(root["token"], *LOG_READ, "timeout")["operation_id"]
    engine.reconcile(oid, "not_executed", REASON)
    engine.deprovision_owner(dana["id"])
    evidence = engine.evidence(root["run_id"])
    lifecycle, reconciliation, operation = evidence["lifecycle"][0], evidence["reconciliations"][0], evidence["receipts"][0]
    checkpoint = engine.checkpoint(root["run_id"])
    for target, receipt in (("receipts", lifecycle), ("reconciliations", lifecycle), ("lifecycle", reconciliation),
                            ("lifecycle", operation), ("lifecycle", checkpoint)):
        swapped = copy.deepcopy(evidence); swapped[target].append(receipt)
        with pytest.raises(ValueError):
            verify(swapped, engine.public_key)
    with pytest.raises(ValueError, match="checkpoint"):
        verify(evidence, engine.public_key, [lifecycle])
    other = engine.provision_owner("sam", "Sam Example")["receipt"]
    foreign = copy.deepcopy(evidence); foreign["lifecycle"].append(other)
    with pytest.raises(ValueError, match="another owner"):
        verify(foreign, engine.public_key)


def test_existing_database_upgrades_and_tokens_without_owner_still_work(tmp_path):
    engine = Passport(tmp_path)
    created = engine.create_run()
    with engine.transaction() as db:
        db.execute("UPDATE grants SET owner=NULL, owner_epoch=NULL")
        legacy = engine._token(db.execute("SELECT * FROM grants WHERE id=?", (created["grant"]["id"],)).fetchone())
    db = engine.connect()
    try:
        db.execute("DROP TABLE lifecycle")
        db.execute("DROP TABLE owners")
        db.execute("ALTER TABLE grants DROP COLUMN owner_epoch")
        db.execute("ALTER TABLE grants DROP COLUMN owner")
    finally:
        db.close()
    assert "owner" not in json.loads(__import__("base64").urlsafe_b64decode(legacy.split(".")[0] + "=="))
    upgraded = Passport(tmp_path)
    assert Executor(upgraded).execute(legacy, *LOG_READ, "k")["state"] == "completed"
    snapshot = upgraded.evidence(created["run_id"])
    assert "owner" not in snapshot["grants"][0] and snapshot["owner"] is None and snapshot["lifecycle"] == []
    assert "owner" not in snapshot["receipts"][0]["body"]
    assert verify(snapshot, upgraded.public_key)["valid"]
    # An unowned legacy run is unaffected by any owner's lifecycle, and new runs get an owner.
    fresh = upgraded.create_run()
    upgraded.deprovision_owner(fresh["grant"]["owner"])
    assert Executor(upgraded).execute(legacy, *LOG_READ, "k2")["state"] == "completed"
    assert_denied("OWNER_DEPROVISIONED", lambda: Executor(upgraded).execute(fresh["token"], *LOG_READ, "k"))


def test_cli_lists_adds_deactivates_and_reactivates(tmp_path, capsys):
    state = ["--state-dir", str(tmp_path)]
    assert owners_cli(state + ["add", "dana", "--display-name", "Dana Example", "--external-id", "idp-7"]) == 0
    added = json.loads(capsys.readouterr().out)
    assert added["owner"]["active"] and added["receipt"]["body"]["change"] == "provisioned"
    root = Passport(tmp_path).create_run(owner=added["owner"]["id"])
    assert owners_cli(state + ["--operator", "HR offboarding", "deactivate", "idp-7"]) == 0
    assert json.loads(capsys.readouterr().out)["receipt"]["body"]["actor"] == "HR offboarding"
    assert_denied("OWNER_DEPROVISIONED", lambda: Executor(Passport(tmp_path)).execute(root["token"], *LOG_READ, "k"))
    assert owners_cli(state + ["reactivate", "dana"]) == 0
    assert json.loads(capsys.readouterr().out)["owner"]["active"]
    assert owners_cli(state + ["list"]) == 0
    assert json.loads(capsys.readouterr().out)["owners"][0]["runs"] == 1
    assert owners_cli(state + ["deactivate", "nobody"]) == 1
    assert json.loads(capsys.readouterr().err)["rule"] == "OWNER_UNKNOWN"
    assert owners_cli(state + ["add", "dana", "--display-name", "Again"]) == 1
    assert json.loads(capsys.readouterr().err)["rule"] == "OWNER_CONFLICT"


# ---------- SCIM-shaped HTTP surface ----------

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSPORT_OP_REFERENCE", raising=False)
    return TestClient(create_app(tmp_path))


def console(client):
    return {"x-passport-console": client.get("/api/session").json()["console_token"]}


def new_user(name="dana", **extra):
    return {"schemas": [USER], "userName": name, "displayName": name.title() + " Example", **extra}


def deactivate(value=False, path=True):
    op = {"op": "replace", "path": "active", "value": value} if path else {"op": "Replace", "value": {"active": value}}
    return {"schemas": [PATCH], "Operations": [op]}


def test_scim_rejects_bearer_tokens_agent_passports_and_missing_session(client):
    auth = console(client)
    coordinator = client.app.state.demo.agents["Coordinator"]
    bearer = {"Authorization": f"Bearer {coordinator['token']}"}
    for method, path, body in (("post", "/scim/v2/Users", new_user()), ("get", "/scim/v2/Users", None),
                               ("get", f"/scim/v2/Users/{DEFAULT_OWNER['id']}", None),
                               ("patch", f"/scim/v2/Users/{DEFAULT_OWNER['id']}", deactivate()),
                               ("delete", f"/scim/v2/Users/{DEFAULT_OWNER['id']}", None)):
        send = getattr(client, method) if body is None else (lambda p, **kw: client.request(method.upper(), p, json=body, **kw))
        assert send(path).status_code == 403
        assert send(path, headers=bearer).status_code == 403
        assert send(path, headers={**auth, "Authorization": "Bearer scim-secret"}).status_code == 403
    assert client.app.state.passport.owner(DEFAULT_OWNER["id"])["active"]
    assert len(client.app.state.passport.owners()) == 1
    for path in ("/api/agent/owners", "/api/agent/scim/v2/Users"):
        assert client.post(path, json=new_user(), headers=bearer).status_code in (404, 405)
    assert client.post(f"/api/owners/{DEFAULT_OWNER['id']}/deactivate", headers=bearer).status_code == 403


def test_scim_create_list_get_patch_and_delete(client):
    auth = console(client)
    created = client.post("/scim/v2/Users", json=new_user(externalId="idp-1"), headers={**auth, "Content-Type": "application/scim+json"})
    assert created.status_code == 201 and created.headers["content-type"].startswith("application/scim+json")
    user = created.json()
    assert user["userName"] == "dana" and user["active"] is True and user["externalId"] == "idp-1"
    assert created.headers["location"] == f"/scim/v2/Users/{user['id']}"
    assert client.post("/scim/v2/Users", json=new_user(), headers=auth).status_code == 409
    listed = client.get("/scim/v2/Users", headers=auth).json()
    assert listed["totalResults"] == 2 and {r["userName"] for r in listed["Resources"]} == {"dana", "local-operator"}
    filtered = client.get("/scim/v2/Users", params={"filter": 'userName eq "dana"'}, headers=auth).json()
    assert [r["id"] for r in filtered["Resources"]] == [user["id"]]
    assert client.get("/scim/v2/Users", params={"filter": 'displayName co "a"'}, headers=auth).status_code == 400
    assert client.get("/scim/v2/Users/own_missing", headers=auth).status_code == 404

    engine = client.app.state.passport
    root = engine.create_run(owner=user["id"])
    patched = client.patch(f"/scim/v2/Users/{user['id']}", json=deactivate(False), headers=auth)
    assert patched.status_code == 200 and patched.json()["active"] is False
    assert patched.json()["urn:agent-passport:scim:owner"]["runs"] == 1
    assert_denied("OWNER_DEPROVISIONED", lambda: Executor(engine).execute(root["token"], *LOG_READ, "k"))
    assert client.patch(f"/scim/v2/Users/{user['id']}", json=deactivate(True, path=False), headers=auth).json()["active"] is True
    assert_denied("OWNER_DEPROVISIONED", lambda: Executor(engine).execute(root["token"], *LOG_READ, "k"))

    assert client.delete(f"/scim/v2/Users/{user['id']}", headers=auth).status_code == 204
    after = client.get(f"/scim/v2/Users/{user['id']}", headers=auth).json()
    assert after["active"] is False and after["urn:agent-passport:scim:owner"]["epoch"] == 2
    assert client.delete(f"/scim/v2/Users/{user['id']}", headers=auth).status_code == 204
    assert client.delete("/scim/v2/Users/own_missing", headers=auth).status_code == 404
    assert [r["body"]["actor"] for r in engine.lifecycle(user["id"])] == ["SCIM (local console session)"] * 4


@pytest.mark.parametrize("body", [
    new_user(password="secret"), new_user(active=False), new_user(active="true"), new_user(userName=""),
    {"schemas": ["urn:example:other"], "userName": "x", "displayName": "X"}, {"userName": "x", "displayName": "X"},
    new_user(userName="x" * 101), new_user(externalId=7),
])
def test_scim_create_validates_strictly(client, body):
    assert client.post("/scim/v2/Users", json=body, headers=console(client)).status_code == 422
    assert len(client.app.state.passport.owners()) == 1


@pytest.mark.parametrize("operation", [
    {"op": "replace", "path": "active", "value": "false"}, {"op": "replace", "path": "active", "value": 0},
    {"op": "add", "path": "active", "value": False}, {"op": "remove", "path": "active"},
    {"op": "replace", "path": "displayName", "value": "X"}, {"op": "replace", "value": False},
    {"op": "replace", "value": {"active": False, "displayName": "X"}}, {"op": "replace", "path": "active", "value": False, "extra": 1},
])
def test_scim_patch_accepts_only_replace_of_active(client, operation):
    response = client.patch(f"/scim/v2/Users/{DEFAULT_OWNER['id']}", json={"schemas": [PATCH], "Operations": [operation]}, headers=console(client))
    assert response.status_code == 422
    assert client.app.state.passport.owner(DEFAULT_OWNER["id"])["active"]


def test_console_deactivation_voids_the_scripted_tree_and_reset_reissues(client):
    auth = console(client)
    client.post("/api/demo/step", headers=auth)
    state = client.post(f"/api/owners/{DEFAULT_OWNER['id']}/deactivate", headers=auth).json()
    assert state["owner"]["active"] is False and {g["state"] for g in state["grants"]} == {"deprovisioned"}
    assert state["owners"][0]["id"] == DEFAULT_OWNER["id"] and not state["owners"][0]["active"]
    assert client.post("/api/owners/own_missing/deactivate", headers=auth).status_code == 404
    old = client.app.state.demo.agents["Log reader"]
    reset = client.post("/api/demo/reset", headers=auth).json()
    assert reset["owner"]["active"] and {g["state"] for g in reset["grants"]} == {"active"}
    engine = client.app.state.passport
    assert [r["body"]["change"] for r in engine.lifecycle()] == ["provisioned", "deprovisioned", "reactivated"]
    assert engine.inspect(old["token"], old["holder"].proof(old["token"], "inspect", {}))["state"] == "OWNER_DEPROVISIONED"
    for _ in range(4):
        assert client.post("/api/demo/step", headers=auth).status_code == 200
    assert client.get("/api/state", headers=auth).json()["metrics"]["unrelated_branch_completed"]
