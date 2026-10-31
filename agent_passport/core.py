"""Transactional authorization, shared budgets, and signed evidence.

The SQLite write lock is the linearization point for reservation and revocation.
An upstream call runs outside that lock; a reservation is not proof of an effect.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption


POLICY = "passport/1"
CATALOG = {("staging/checkout", "logs.read"), ("repo/checkout", "code.read"),
           ("repo/checkout", "patch.propose"), ("staging/checkout", "config.write")}
PROOF_WINDOW = 60  # seconds a holder proof's timestamp may differ from the gateway clock
# A reserved or dispatched operation younger than this may still be running in an executor.
# This is an in-flight guard for the operator, not a refund timer: nothing settles without a decision.
STRANDED_AFTER = 300
UNRESOLVED = ("reserved", "dispatched", "unknown")
RECONCILED = {"completed": ("reconciled_completed", "RECONCILED_COMPLETED"),
              "not_executed": ("reconciled_not_executed", "RECONCILED_NOT_EXECUTED")}
# Operator policy: pairs that need a human decision before dispatch. Server configuration only;
# no agent request, passport claim or delegation can add or remove an entry.
APPROVAL_REQUIRED = frozenset({("staging/checkout", "config.write")})
APPROVAL_TTL = 300  # an approval not consumed by a dispatch within this many seconds lapses
APPROVAL_REQUEST_TTL = 900  # a request no operator decided within this many seconds lapses
# Both states sit before the dispatch boundary: nothing has been sent upstream.
AWAITING = ("awaiting_approval", "approved")
APPROVAL_DECISIONS = {"approve": ("approved", "approved", "OPERATOR_APPROVED"),
                      "deny": ("approval_denied", "denied", "OPERATOR_DENIED")}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def execute_fields(resource, action, request_key):
    return {"resource": resource, "action": action, "request_key": request_key}


def delegate_fields(subject, scopes, expires, holder_key):
    if isinstance(expires, (int, float)) and not isinstance(expires, bool):
        expires = float(expires)
    return {"subject": subject, "scopes": scopes, "expires": expires, "holder_key": holder_key}


def request_digest(operation, fields):
    return hashlib.sha256(canonical({"op": operation, "fields": fields})).hexdigest()


class Holder:
    """Client side of a key-bound passport. The private key never leaves this object.

    Each request carries a proof signed by this key and bound to the token, the operation,
    the exact request fields, a timestamp and a single-use nonce.
    """

    def __init__(self, key=None):
        self.key = key or Ed25519PrivateKey.generate()
        self.public_key = b64(self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def proof(self, token, operation, fields, now=None, nonce=None):
        body = {"ath": token_digest(token), "op": operation, "req": request_digest(operation, fields),
                "iat": time.time() if now is None else now, "jti": nonce or uuid.uuid4().hex}
        payload = canonical(body)
        return b64(payload) + "." + b64(self.key.sign(payload))


def valid_public_key(value):
    try:
        if not isinstance(value, str) or not 40 <= len(value) <= 64:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(unb64(value))
        return True
    except (ValueError, TypeError):
        return False


class Denied(Exception):
    def __init__(self, rule, detail):
        self.rule, self.detail = rule, detail
        super().__init__(detail)

    def as_dict(self):
        return {"allowed": False, "rule": self.rule, "detail": self.detail}


def verify_receipt(receipt, public_key):
    """Trust public_key out of band; never trust a key supplied by the receipt."""
    try:
        Ed25519PublicKey.from_public_bytes(unb64(public_key)).verify(
            unb64(receipt["signature"]), canonical(receipt["body"]))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


class Passport:
    def __init__(self, directory, clock=time.time, issuer_key=None, approval_required=APPROVAL_REQUIRED):
        """issuer_key: an operator-supplied Ed25519PrivateKey (for example resolved from 1Password).

        When given, it is used as is and nothing about it is written to the state directory.
        Otherwise the issuer key is read from, or created once in, `directory/issuer.key`.
        """
        self.directory = Path(directory)
        self.approval_required = frozenset(approval_required)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "passport.db"
        self.clock = clock
        if issuer_key is not None:
            if not isinstance(issuer_key, Ed25519PrivateKey):
                raise TypeError("issuer_key must be an Ed25519 private key")
            self.key, self.issuer_key_source = issuer_key, "supplied"
        else:
            self.key, self.issuer_key_source = self._file_key(), "file"
        self.public_key = b64(self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self._initialize_schema()

    def _file_key(self):
        key_path = self.directory / "issuer.key"
        if not key_path.exists():
            key = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            temporary = self.directory / ("issuer-" + uuid.uuid4().hex + ".tmp")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
                f.flush()
                os.fsync(f.fileno())
            try:
                # Publish a complete key atomically, without replacing another issuer.
                os.link(temporary, key_path)
            except FileExistsError:
                pass
            finally:
                temporary.unlink()
        return Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())

    def _initialize_schema(self):
        db = self.connect()
        try:
            # Journal-mode transitions may return BUSY immediately despite busy_timeout.
            # Bound startup retries; authorization transactions never fall back to allow.
            for attempt in range(100):
                try:
                    db.execute("PRAGMA journal_mode=WAL")
                    break
                except sqlite3.OperationalError as error:
                    if error.sqlite_errorcode not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} or attempt == 99:
                        raise
                    time.sleep(0.01)
            db.executescript("""
              CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, budget INTEGER NOT NULL CHECK(budget>0),
                spent INTEGER NOT NULL DEFAULT 0 CHECK(spent>=0),
                reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved>=0),
                created REAL NOT NULL, CHECK(spent+reserved<=budget));
              CREATE TABLE IF NOT EXISTS grants (
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
                parent TEXT REFERENCES grants(id), subject TEXT NOT NULL,
                scopes TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
                depth INTEGER NOT NULL, created REAL NOT NULL, holder_key TEXT);
              CREATE TABLE IF NOT EXISTS operations (
                id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id),
                request_key TEXT NOT NULL, digest TEXT NOT NULL, resource TEXT NOT NULL,
                action TEXT NOT NULL, state TEXT NOT NULL, result TEXT, receipt TEXT,
                created REAL NOT NULL, UNIQUE(grant_id,request_key));
              CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
                body TEXT NOT NULL, hash TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS reconciliations (
                operation_id TEXT PRIMARY KEY REFERENCES operations(id),
                run_id TEXT NOT NULL REFERENCES runs(id), receipt TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS proofs (
                grant_id TEXT NOT NULL REFERENCES grants(id), jti TEXT NOT NULL,
                expires REAL NOT NULL, PRIMARY KEY(grant_id, jti));
              CREATE TABLE IF NOT EXISTS approvals (
                operation_id TEXT PRIMARY KEY REFERENCES operations(id),
                run_id TEXT NOT NULL REFERENCES runs(id),
                decision TEXT NOT NULL CHECK(decision IN ('approved','denied')),
                expires REAL, used INTEGER NOT NULL DEFAULT 0, receipt TEXT NOT NULL);
              CREATE INDEX IF NOT EXISTS operations_state ON operations(state);
            """)
            # Databases created before holder binding lack the column. Their grants stay
            # unbound bearer passports, so existing tokens keep verifying unchanged.
            if "holder_key" not in {row[1] for row in db.execute("PRAGMA table_info(grants)")}:
                try:
                    db.execute("ALTER TABLE grants ADD COLUMN holder_key TEXT")
                except sqlite3.OperationalError as error:
                    if "duplicate column" not in str(error):
                        raise
        finally:
            db.close()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=30000")
        return db

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def event(self, db, run_id, kind, grant_id, rule, detail, **extra):
        previous = db.execute("SELECT hash FROM events WHERE run_id=? ORDER BY seq DESC LIMIT 1", (run_id,)).fetchone()
        body = {"time": self.clock(), "kind": kind, "grant_id": grant_id, "rule": rule,
                "detail": detail, "previous": previous[0] if previous else "0" * 64, **extra}
        digest = hashlib.sha256(canonical(body)).hexdigest()
        db.execute("INSERT INTO events(run_id,body,hash) VALUES(?,?,?)", (run_id, canonical(body).decode(), digest))

    def _claims(self, g):
        claims = {"v": 1, "issuer": self.public_key, "id": g["id"], "run_id": g["run_id"],
                  "parent": g["parent"], "subject": g["subject"], "scopes": json.loads(g["scopes"]),
                  "expires": g["expires"], "depth": g["depth"]}
        if g["holder_key"]:
            # Confirmation key: only the holder of the matching private key may present this passport.
            claims["cnf"] = g["holder_key"]
        return claims

    def _token(self, g):
        payload = canonical(self._claims(g))
        return b64(payload) + "." + b64(self.key.sign(payload))

    def _authenticate(self, db, token):
        try:
            if not isinstance(token, str) or len(token) > 12000:
                raise ValueError()
            payload, signature = token.split(".")
            raw = unb64(payload)
            self.key.public_key().verify(unb64(signature), raw)
            claims = json.loads(raw)
            g = db.execute("SELECT * FROM grants WHERE id=?", (claims["id"],)).fetchone()
            if g is None or canonical(self._claims(g)) != raw:
                raise ValueError()
            return g
        except (InvalidSignature, ValueError, KeyError, TypeError, UnicodeError):
            raise Denied("IDENTITY_INVALID", "The passport signature or issuer is invalid.") from None

    def _verify_proof(self, db, g, token, proof, operation, fields):
        """A key-bound passport is useless without a fresh proof from its holder key."""
        if not g["holder_key"]:
            return
        if proof is None:
            raise Denied("PROOF_REQUIRED", "This passport is bound to a holder key. A bearer token alone is not accepted.")
        try:
            if not isinstance(proof, str) or len(proof) > 2000:
                raise ValueError()
            payload, signature = proof.split(".")
            raw = unb64(payload)
            Ed25519PublicKey.from_public_bytes(unb64(g["holder_key"])).verify(unb64(signature), raw)
            body = json.loads(raw)
            if not isinstance(body, dict) or set(body) != {"ath", "op", "req", "iat", "jti"}:
                raise ValueError()
            iat, jti = body["iat"], body["jti"]
            if type(iat) not in (int, float) or not math.isfinite(iat):
                raise ValueError()
            if not isinstance(jti, str) or not 16 <= len(jti) <= 64:
                raise ValueError()
            if body["ath"] != token_digest(token) or body["op"] != operation or body["req"] != request_digest(operation, fields):
                raise ValueError()
        except (InvalidSignature, ValueError, KeyError, TypeError, UnicodeError):
            raise Denied("PROOF_INVALID", "The holder proof does not match this passport's key, token, or request.") from None
        now = self.clock()
        if abs(now - iat) > PROOF_WINDOW:
            raise Denied("PROOF_STALE", f"A holder proof must be signed within {PROOF_WINDOW} seconds of the gateway clock.")
        # A row past twice the window can never match a fresh proof again.
        db.execute("DELETE FROM proofs WHERE expires < ?", (now,))
        try:
            db.execute("INSERT INTO proofs(grant_id,jti,expires) VALUES(?,?,?)", (g["id"], jti, iat + 2 * PROOF_WINDOW))
        except sqlite3.IntegrityError:
            raise Denied("PROOF_REPLAYED", "This holder proof was already used. Sign a new proof for each request.") from None

    def _chain(self, db, g):
        chain = []
        while g:
            chain.append(g["id"])
            if g["revoked"]:
                raise Denied("ANCESTOR_REVOKED", f"Grant {g['id']} was revoked; this branch has no authority.")
            if g["expires"] <= self.clock():
                raise Denied("GRANT_EXPIRED", f"Grant {g['id']} has reached its expiry.")
            g = db.execute("SELECT * FROM grants WHERE id=?", (g["parent"],)).fetchone() if g["parent"] else None
        return chain

    @staticmethod
    def _scopes(scopes):
        try:
            if not isinstance(scopes, list) or not 1 <= len(scopes) <= 20:
                raise ValueError()
            normalized = sorted(set((s["resource"], s["action"]) for s in scopes))
            if any(not isinstance(v, str) or not 1 <= len(v) <= 100 for pair in normalized for v in pair):
                raise ValueError()
            return normalized
        except (ValueError, KeyError, TypeError):
            raise Denied("SCOPE_INVALID", "Provide exact resource/action pairs; no wildcards.") from None

    def create_run(self, budget=24, ttl=3600, holder_key=None):
        if type(budget) is not int or not 1 <= budget <= 1000 or not 0 < ttl <= 86400:
            raise Denied("LIMIT_INVALID", "Budget must be 1–1000 units; expiry must be within one day.")
        if holder_key is not None and not valid_public_key(holder_key):
            raise Denied("HOLDER_KEY_INVALID", "A holder key must be a raw Ed25519 public key.")
        run, grant = "run_" + uuid.uuid4().hex[:12], "g_" + uuid.uuid4().hex[:12]
        scopes = [{"resource": r, "action": a} for r, a in sorted(CATALOG)]
        with self.transaction() as db:
            db.execute("INSERT INTO runs(id,budget,created) VALUES(?,?,?)", (run, budget, self.clock()))
            db.execute("INSERT INTO grants(id,run_id,parent,subject,scopes,expires,revoked,depth,created,holder_key) VALUES(?,?,?,?,?,?,0,0,?,?)",
                       (grant, run, None, "Coordinator", canonical(scopes).decode(), self.clock() + ttl, self.clock(), holder_key))
            g = db.execute("SELECT * FROM grants WHERE id=?", (grant,)).fetchone()
            self.event(db, run, "issued", grant, "ROOT_AUTHORIZED", f"One shared pool of {budget} operation units.")
            return {"run_id": run, "grant": self._claims(g), "token": self._token(g)}

    def delegate(self, token, subject, scopes, expires, holder_key=None, proof=None):
        denial = None
        with self.transaction() as db:
            parent = self._authenticate(db, token)
            try:
                self._verify_proof(db, parent, token, proof, "delegate", delegate_fields(subject, scopes, expires, holder_key))
                self._chain(db, parent)
                if not isinstance(subject, str) or not 1 <= len(subject.strip()) <= 60:
                    raise Denied("SUBJECT_INVALID", "An agent name must be 1–60 characters.")
                requested = self._scopes(scopes)
                allowed = self._scopes(json.loads(parent["scopes"]))
                if not set(requested) <= set(allowed):
                    raise Denied("SCOPE_ESCALATION", "A child cannot receive a resource/action pair absent from its parent.")
                if not isinstance(expires, (float, int)) or not self.clock() < expires <= parent["expires"]:
                    raise Denied("EXPIRY_ESCALATION", "A child must expire no later than its parent, and after now.")
                if holder_key is not None and not valid_public_key(holder_key):
                    raise Denied("HOLDER_KEY_INVALID", "A holder key must be a raw Ed25519 public key.")
                if holder_key is None and parent["holder_key"]:
                    raise Denied("BINDING_REQUIRED", "A child of a key-bound passport must be bound to its own holder key.")
                count = db.execute("SELECT count(*) FROM grants WHERE run_id=?", (parent["run_id"],)).fetchone()[0]
                if parent["depth"] >= 8 or count >= 150:
                    raise Denied("DELEGATION_LIMIT", "This demo permits depth 8 and 150 agents per run.")
                gid = "g_" + uuid.uuid4().hex[:12]
                normalized = [{"resource": r, "action": a} for r, a in requested]
                db.execute("INSERT INTO grants(id,run_id,parent,subject,scopes,expires,revoked,depth,created,holder_key) VALUES(?,?,?,?,?,?,0,?,?,?)",
                           (gid, parent["run_id"], parent["id"], subject.strip(), canonical(normalized).decode(), expires, parent["depth"] + 1, self.clock(), holder_key))
                g = db.execute("SELECT * FROM grants WHERE id=?", (gid,)).fetchone()
                self.event(db, parent["run_id"], "delegated", gid, "SCOPE_ATTENUATED", f"{subject.strip()} inherits the same budget pool.")
                result = {"grant": self._claims(g), "token": self._token(g)}
            except Denied as e:
                denial = e
                self.event(db, parent["run_id"], "denied", parent["id"], e.rule, e.detail)
        if denial:
            raise denial
        return result

    def revoke(self, gid):
        """Trusted control-plane operation; never exposed on the agent endpoint."""
        with self.transaction() as db:
            g = db.execute("SELECT * FROM grants WHERE id=?", (gid,)).fetchone()
            if not g:
                raise Denied("GRANT_UNKNOWN", "Unknown grant.")
            db.execute("UPDATE grants SET revoked=1 WHERE id=?", (gid,))
            self.event(db, g["run_id"], "revoked", gid, "BRANCH_REVOKED", "Every descendant will fail its next authorization check.")

    def reserve(self, token, resource, action, request_key, proof=None):
        """Cost is always one unit, determined here, never supplied by the agent."""
        denial = None
        with self.transaction() as db:
            g = self._authenticate(db, token)
            # Settle lapsed or orphaned approvals first, so a retry sees their final state.
            self._sweep_approvals(db, g["run_id"])
            try:
                self._verify_proof(db, g, token, proof, "execute", execute_fields(resource, action, request_key))
                self._chain(db, g)
                if not all(isinstance(s, str) and 1 <= len(s) <= 100 for s in [resource, action, request_key]):
                    raise Denied("REQUEST_INVALID", "Resource, action and idempotency key must be bounded strings.")
                if (resource, action) not in self._scopes(json.loads(g["scopes"])):
                    raise Denied("RESOURCE_ACTION_DENIED", f"{action} on {resource} is outside this passport's exact scope.")
                digest = hashlib.sha256(canonical({"resource": resource, "action": action})).hexdigest()
                old = db.execute("SELECT * FROM operations WHERE grant_id=? AND request_key=?", (g["id"], request_key)).fetchone()
                if old:
                    if old["digest"] != digest:
                        raise Denied("IDEMPOTENCY_CONFLICT", "This key is already bound to a different operation.")
                    return {**dict(old), "duplicate": True}
                changed = db.execute("UPDATE runs SET reserved=reserved+1 WHERE id=? AND spent+reserved<budget", (g["run_id"],)).rowcount
                if not changed:
                    raise Denied("BUDGET_EXHAUSTED", "All descendants share this pool; no operation units remain.")
                oid = "op_" + uuid.uuid4().hex
                gated = (resource, action) in self.approval_required
                db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,NULL,NULL,?)", (oid, g["id"], request_key, digest, resource, action,
                                                                                    "awaiting_approval" if gated else "reserved", self.clock()))
                self.event(db, g["run_id"], "reserved", g["id"], "BUDGET_RESERVED", "One unit reserved atomically.", operation_id=oid)
                if gated:
                    self.event(db, g["run_id"], "awaiting_approval", g["id"], "APPROVAL_REQUIRED",
                               f"{action} on {resource} needs an operator's approval. Nothing is dispatched until then.",
                               operation_id=oid, resource=resource, action=action)
                result = {**dict(db.execute("SELECT * FROM operations WHERE id=?", (oid,)).fetchone()), "duplicate": False}
            except Denied as e:
                denial = e
                self.event(db, g["run_id"], "denied", g["id"], e.rule, e.detail, resource=resource, action=action)
        if denial:
            raise denial
        return result

    def dispatch(self, oid):
        """Recheck at dequeue. Returns False if another worker already dispatched."""
        denial = None
        with self.transaction() as db:
            op = db.execute("SELECT * FROM operations WHERE id=?", (oid,)).fetchone()
            if not op or op["state"] not in ("reserved", "approved"):
                return False
            g = db.execute("SELECT * FROM grants WHERE id=?", (op["grant_id"],)).fetchone()
            try:
                self._chain(db, g)
                if op["state"] == "approved":
                    self._consume_approval(db, op, g)
                db.execute("UPDATE operations SET state='dispatched' WHERE id=?", (oid,))
            except Denied as e:
                denial = e
                lapsed = e.rule == "APPROVAL_LAPSED"
                db.execute("UPDATE operations SET state=? WHERE id=?", ("approval_lapsed" if lapsed else "cancelled", oid))
                db.execute("UPDATE runs SET reserved=reserved-1 WHERE id=?", (g["run_id"],))
                self.event(db, g["run_id"], "approval_lapsed" if lapsed else "denied", g["id"], e.rule,
                           "Queued operation cancelled before dispatch." if op["state"] == "reserved"
                           else "Approved operation cancelled before dispatch. It never ran; its unit was returned.", operation_id=oid)
        if denial:
            raise denial
        return True

    def settle(self, oid, outcome, result):
        """Only the trusted executor can settle. Unknown outcomes retain the unit."""
        if outcome not in {"completed", "failed", "unknown"}:
            raise ValueError("Invalid outcome")
        with self.transaction() as db:
            op = db.execute("SELECT * FROM operations WHERE id=?", (oid,)).fetchone()
            if not op or op["state"] != "dispatched":
                raise Denied("OPERATION_STATE", "Only a dispatched operation may be settled once.")
            g = db.execute("SELECT * FROM grants WHERE id=?", (op["grant_id"],)).fetchone()
            chain, cursor = [], g
            while cursor:
                chain.append(cursor["id"])
                cursor = db.execute("SELECT * FROM grants WHERE id=?", (cursor["parent"],)).fetchone() if cursor["parent"] else None
            body = {"operation_id": oid, "grant_id": g["id"], "run_id": g["run_id"], "chain": chain,
                    "request_digest": op["digest"], "resource": op["resource"], "action": op["action"],
                    "outcome": outcome, "result_digest": hashlib.sha256(canonical(result)).hexdigest(),
                    "policy": POLICY, "cost": 1, "time": self.clock()}
            if g["holder_key"]:
                body["cnf"] = g["holder_key"]
            approval = db.execute("SELECT receipt FROM approvals WHERE operation_id=? AND decision='approved'", (oid,)).fetchone()
            if approval:
                # Binds this receipt to the operator approval it was dispatched under.
                body["approval"] = hashlib.sha256(canonical(json.loads(approval[0])["body"])).hexdigest()
            receipt = {"body": body, "signature": b64(self.key.sign(canonical(body)))}
            db.execute("UPDATE operations SET state=?,result=?,receipt=? WHERE id=?", (outcome, canonical(result).decode(), canonical(receipt).decode(), oid))
            if outcome != "unknown":
                db.execute("UPDATE runs SET reserved=reserved-1,spent=spent+? WHERE id=?", (int(outcome == "completed"), g["run_id"]))
            self.event(db, g["run_id"], outcome, g["id"], {"completed": "EXECUTED", "failed": "REFUNDED", "unknown": "OUTCOME_UNKNOWN"}[outcome], {"completed": "One operation completed. One unit consumed.", "failed": "Known pre-effect failure. Reserved unit returned.", "unknown": "Outcome uncertain. Unit retained; automatic retry disabled."}[outcome], operation_id=oid)
            return {"operation_id": oid, "state": outcome, "result": result, "receipt": receipt}

    def unresolved(self, run_id=None):
        """Operations still holding a unit: unknown outcomes and crash-stranded reservations."""
        db = self.connect()
        try:
            rows = db.execute(f"""SELECT o.id, o.grant_id, g.run_id, g.subject, o.resource, o.action, o.state, o.created
                                  FROM operations o JOIN grants g ON g.id=o.grant_id
                                  WHERE o.state IN ({",".join("?" * len(UNRESOLVED))}) AND (? IS NULL OR g.run_id=?)
                                  ORDER BY o.created""", (*UNRESOLVED, run_id, run_id)).fetchall()
            now = self.clock()
            return [{**dict(r), "age_seconds": round(now - r["created"], 1),
                     "reconcilable": r["state"] == "unknown" or now - r["created"] >= STRANDED_AFTER} for r in rows]
        finally:
            db.close()

    def reconcile(self, oid, outcome, reason, operator="Local operator", basis=None):
        """Trusted operator decision about an operation whose effect the executor could not settle.

        Never exposed on the agent API and never invoked on a timer. The operator attests what
        happened upstream; the issuer signs that statement. The receipt records a decision,
        not proof of the upstream effect.
        """
        if outcome not in RECONCILED:
            raise Denied("OUTCOME_INVALID", "Reconcile as completed or not_executed.")
        if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
            raise Denied("REASON_REQUIRED", "Record the basis for this decision in 10 to 500 characters.")
        if not isinstance(operator, str) or not 1 <= len(operator.strip()) <= 60:
            raise Denied("OPERATOR_INVALID", "Name the deciding operator in 1 to 60 characters.")
        state, rule = RECONCILED[outcome]
        with self.transaction() as db:
            op = db.execute("SELECT * FROM operations WHERE id=?", (oid,)).fetchone()
            if not op:
                raise Denied("OPERATION_UNKNOWN", "Unknown operation.")
            if op["state"] not in UNRESOLVED:
                raise Denied("OPERATION_STATE", "Only an operation still holding a unit can be reconciled, and only once.")
            now = self.clock()
            if op["state"] != "unknown" and now - op["created"] < STRANDED_AFTER:
                raise Denied("OPERATION_IN_FLIGHT", f"A {op['state']} operation may still be running. Wait {STRANDED_AFTER} seconds from reservation before deciding it was stranded.")
            g = db.execute("SELECT * FROM grants WHERE id=?", (op["grant_id"],)).fetchone()
            chain, cursor = [], g
            while cursor:
                chain.append(cursor["id"])
                cursor = db.execute("SELECT * FROM grants WHERE id=?", (cursor["parent"],)).fetchone() if cursor["parent"] else None
            body = {"type": "reconciliation", "operation_id": oid, "grant_id": g["id"], "run_id": g["run_id"],
                    "chain": chain, "request_digest": op["digest"], "resource": op["resource"], "action": op["action"],
                    "previous_state": op["state"], "outcome": state, "reason": reason.strip(),
                    "decided_by": operator.strip(), "policy": POLICY, "cost": int(outcome == "completed"), "time": now}
            if basis is not None:
                # Trusted executor code only, such as an upstream effect lookup; never agent input.
                body["basis"] = basis
            receipt = {"body": body, "signature": b64(self.key.sign(canonical(body)))}
            # The guarded update makes a concurrent dispatch, settlement or second decision impossible.
            changed = db.execute(f"UPDATE operations SET state=? WHERE id=? AND state IN ({','.join('?' * len(UNRESOLVED))})",
                                 (state, oid, *UNRESOLVED)).rowcount
            if not changed:
                raise Denied("OPERATION_STATE", "Only an operation still holding a unit can be reconciled, and only once.")
            db.execute("INSERT INTO reconciliations VALUES(?,?,?)", (oid, g["run_id"], canonical(receipt).decode()))
            db.execute("UPDATE runs SET reserved=reserved-1,spent=spent+? WHERE id=?", (int(outcome == "completed"), g["run_id"]))
            verdict = "Unit consumed." if outcome == "completed" else "Unit returned to the shared pool."
            self.event(db, g["run_id"], "reconciled", g["id"], rule,
                       f"{operator.strip()} decided a {op['state']} operation {state.replace('reconciled_', '').replace('_', ' ')}. {verdict} Basis: {reason.strip()}",
                       operation_id=oid)
            return {"operation_id": oid, "state": state, "receipt": receipt}

    # ---- Operator approval of high-risk operations --------------------------------------------
    #
    # An approval-required operation reserves its unit like any other, then waits in
    # awaiting_approval. Only an operator decision moves it on; an approval is single-use, bound
    # to the exact operation, and short-lived. Both waiting states are before the dispatch
    # boundary, so returning the unit on denial, lapse or revocation never refunds an effect.

    def _lineage(self, db, g):
        chain = []
        while g:
            chain.append(g["id"])
            g = db.execute("SELECT * FROM grants WHERE id=?", (g["parent"],)).fetchone() if g["parent"] else None
        return chain

    def _withdraw(self, db, op, run_id, state, kind, rule, detail):
        """Return the unit of an operation that never crossed the dispatch boundary. Applies once."""
        changed = db.execute("UPDATE operations SET state=? WHERE id=? AND state=?", (state, op["id"], op["state"])).rowcount
        if changed:
            db.execute("UPDATE runs SET reserved=reserved-1 WHERE id=?", (run_id,))
            self.event(db, run_id, kind, op["grant_id"], rule, detail, operation_id=op["id"])
        return bool(changed)

    def _sweep_approvals(self, db, run_id=None):
        """Withdraw waiting operations that can no longer be dispatched: a lapsed approval or
        request, or a revoked or expired chain. Runs inside the caller's write transaction."""
        now = self.clock()
        rows = db.execute(f"""SELECT o.*, g.run_id AS run_id, a.expires AS approval_expires
                              FROM operations o JOIN grants g ON g.id=o.grant_id
                              LEFT JOIN approvals a ON a.operation_id=o.id
                              WHERE o.state IN ({",".join("?" * len(AWAITING))}) AND (? IS NULL OR g.run_id=?)""",
                          (*AWAITING, run_id, run_id)).fetchall()
        for op in rows:
            g = db.execute("SELECT * FROM grants WHERE id=?", (op["grant_id"],)).fetchone()
            try:
                self._chain(db, g)
            except Denied as e:
                self._withdraw(db, op, op["run_id"], "cancelled", "denied", e.rule,
                               "An operation awaiting dispatch lost its authority. It never ran; its unit was returned.")
                continue
            if op["state"] == "approved" and (op["approval_expires"] is None or op["approval_expires"] <= now):
                self._withdraw(db, op, op["run_id"], "approval_lapsed", "approval_lapsed", "APPROVAL_LAPSED",
                               f"The approval was not used within {APPROVAL_TTL} seconds. The operation never ran; its unit was returned.")
            elif op["state"] == "awaiting_approval" and now - op["created"] >= APPROVAL_REQUEST_TTL:
                self._withdraw(db, op, op["run_id"], "approval_lapsed", "approval_lapsed", "APPROVAL_LAPSED",
                               f"No operator decided within {APPROVAL_REQUEST_TTL} seconds. The operation never ran; its unit was returned.")

    def _consume_approval(self, db, op, g):
        """At dispatch: the approval must exist, be unused, unexpired, and bound to exactly this operation."""
        row = db.execute("SELECT * FROM approvals WHERE operation_id=?", (op["id"],)).fetchone()
        if row and row["decision"] == "approved" and not row["used"] and row["expires"] is not None and row["expires"] <= self.clock():
            raise Denied("APPROVAL_LAPSED", f"The approval was not used within {APPROVAL_TTL} seconds.")
        try:
            if not row or row["decision"] != "approved" or row["used"] or row["expires"] is None:
                raise ValueError()
            receipt = json.loads(row["receipt"])
            body = receipt["body"]
            if not verify_receipt(receipt, self.public_key) or body["type"] != "approval" or body["decision"] != "approved":
                raise ValueError()
            if (body["operation_id"], body["grant_id"], body["request_digest"], body["resource"], body["action"], body["chain"]) != \
                    (op["id"], g["id"], op["digest"], op["resource"], op["action"], self._lineage(db, g)):
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise Denied("APPROVAL_INVALID", "No unused operator approval is bound to this exact operation.") from None
        if not db.execute("UPDATE approvals SET used=1 WHERE operation_id=? AND used=0", (op["id"],)).rowcount:
            raise Denied("APPROVAL_INVALID", "This approval was already used.")

    def pending_approvals(self, run_id=None):
        """Operations waiting for an operator decision, or approved and not yet dispatched."""
        with self.transaction() as db:
            self._sweep_approvals(db, run_id)
            rows = db.execute(f"""SELECT o.id, o.grant_id, g.run_id, g.subject, o.resource, o.action, o.state, o.created,
                                         a.expires AS approval_expires
                                  FROM operations o JOIN grants g ON g.id=o.grant_id
                                  LEFT JOIN approvals a ON a.operation_id=o.id
                                  WHERE o.state IN ({",".join("?" * len(AWAITING))}) AND (? IS NULL OR g.run_id=?)
                                  ORDER BY o.created""", (*AWAITING, run_id, run_id)).fetchall()
            now = self.clock()
            return [{**dict(r), "age_seconds": round(now - r["created"], 1),
                     "lapses_in": round((r["approval_expires"] if r["state"] == "approved" else r["created"] + APPROVAL_REQUEST_TTL) - now, 1)}
                    for r in rows]

    def decide_approval(self, oid, decision, reason, operator="Local operator"):
        """Trusted operator decision on a waiting high-risk operation.

        Never exposed on the agent API, never accepted from a passport, never made by a timer.
        Approval does not dispatch: the agent's retry with the same key does, after the full
        chain and holder proof are checked again. Denial returns the unit, which is sound
        because the operation never crossed the dispatch boundary.
        """
        if decision not in APPROVAL_DECISIONS:
            raise Denied("DECISION_INVALID", "Decide approve or deny.")
        if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
            raise Denied("REASON_REQUIRED", "Record the basis for this decision in 10 to 500 characters.")
        if not isinstance(operator, str) or not 1 <= len(operator.strip()) <= 60:
            raise Denied("OPERATOR_INVALID", "Name the deciding operator in 1 to 60 characters.")
        state, verdict, rule = APPROVAL_DECISIONS[decision]
        denial = None
        with self.transaction() as db:
            op = db.execute("SELECT * FROM operations WHERE id=?", (oid,)).fetchone()
            if not op:
                raise Denied("OPERATION_UNKNOWN", "Unknown operation.")
            g = db.execute("SELECT * FROM grants WHERE id=?", (op["grant_id"],)).fetchone()
            # A revoked or expired chain, or a lapsed request, is withdrawn before any decision.
            self._sweep_approvals(db, g["run_id"])
            op = db.execute("SELECT * FROM operations WHERE id=?", (oid,)).fetchone()
            if op["state"] != "awaiting_approval":
                denial = Denied("OPERATION_STATE", f"Only an operation awaiting approval can be decided, and only once. This one is {op['state']}.")
            else:
                now = self.clock()
                body = {"type": "approval", "operation_id": oid, "grant_id": g["id"], "run_id": g["run_id"],
                        "chain": self._lineage(db, g), "request_digest": op["digest"], "resource": op["resource"],
                        "action": op["action"], "decision": verdict, "reason": reason.strip(), "decided_by": operator.strip(),
                        "expires": now + APPROVAL_TTL if verdict == "approved" else None, "policy": POLICY, "time": now}
                if g["holder_key"]:
                    body["cnf"] = g["holder_key"]
                receipt = {"body": body, "signature": b64(self.key.sign(canonical(body)))}
                # The guarded update makes a concurrent second decision impossible.
                if not db.execute("UPDATE operations SET state=? WHERE id=? AND state='awaiting_approval'", (state, oid)).rowcount:
                    raise Denied("OPERATION_STATE", "Only an operation awaiting approval can be decided, and only once.")
                db.execute("INSERT INTO approvals(operation_id,run_id,decision,expires,used,receipt) VALUES(?,?,?,?,0,?)",
                           (oid, g["run_id"], verdict, body["expires"], canonical(receipt).decode()))
                if verdict == "denied":
                    db.execute("UPDATE runs SET reserved=reserved-1 WHERE id=?", (g["run_id"],))
                outcome = (f"Approved for one dispatch within {APPROVAL_TTL} seconds." if verdict == "approved"
                           else "The operation will not run. Its unit was returned to the shared pool.")
                self.event(db, g["run_id"], state, g["id"], rule,
                           f"{operator.strip()} {verdict} {op['action']} on {op['resource']}. {outcome} Basis: {reason.strip()}",
                           operation_id=oid)
                result = {"operation_id": oid, "state": state, "receipt": receipt}
        if denial:
            raise denial
        return result

    def operation(self, oid):
        """Trusted read of one operation record, for the executor."""
        db = self.connect()
        try:
            row = db.execute("SELECT * FROM operations WHERE id=?", (oid,)).fetchone()
            return dict(row) if row else None
        finally:
            db.close()

    def snapshot(self, run_id, include_receipts=False):
        db = self.connect()
        try:
            db.execute("BEGIN")
            run = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if not run:
                raise Denied("RUN_UNKNOWN", "Unknown run.")
            grants = []
            for g in db.execute("SELECT * FROM grants WHERE run_id=? ORDER BY created,id", (run_id,)):
                state = "active"
                try:
                    self._chain(db, g)
                except Denied as e:
                    state = "revoked" if e.rule == "ANCESTOR_REVOKED" else "expired"
                grants.append({**self._claims(g), "state": state, "directly_revoked": bool(g["revoked"])})
            events = [{"seq": e["seq"], "hash": e["hash"], **json.loads(e["body"])} for e in db.execute("SELECT * FROM events WHERE run_id=? ORDER BY seq", (run_id,))]
            result = {"run": dict(run), "grants": grants, "events": events, "public_key": self.public_key, "policy": POLICY, "server_time": self.clock()}
            if include_receipts:
                result["receipts"] = [json.loads(r[0]) for r in db.execute("SELECT receipt FROM operations WHERE grant_id IN (SELECT id FROM grants WHERE run_id=?) AND receipt IS NOT NULL", (run_id,))]
                result["reconciliations"] = [json.loads(r[0]) for r in db.execute("SELECT receipt FROM reconciliations WHERE run_id=? ORDER BY rowid", (run_id,))]
                result["approvals"] = [json.loads(r[0]) for r in db.execute("SELECT receipt FROM approvals WHERE run_id=? ORDER BY rowid", (run_id,))]
            return result
        finally:
            db.close()

    def inspect(self, token, proof=None):
        """An agent may read its own claims and its pool's balance. Never returns a token."""
        denial = None
        # A write transaction, because a holder proof's nonce is consumed here.
        with self.transaction() as db:
            g = self._authenticate(db, token)
            try:
                self._verify_proof(db, g, token, proof, "inspect", {})
            except Denied as e:
                denial = e
                self.event(db, g["run_id"], "denied", g["id"], e.rule, e.detail)
            if not denial:
                try:
                    self._chain(db, g)
                    state = "active"
                except Denied as e:
                    state = e.rule
                run = db.execute("SELECT budget,spent,reserved FROM runs WHERE id=?", (g["run_id"],)).fetchone()
                result = {"grant": self._claims(g), "state": state,
                          "budget": {"limit": run["budget"], "spent": run["spent"], "reserved": run["reserved"],
                                     "available": run["budget"] - run["spent"] - run["reserved"]}}
        if denial:
            raise denial
        return result

    def evidence(self, run_id):
        return self.snapshot(run_id, include_receipts=True)

    def checkpoint(self, run_id):
        """Sign the size and head hash of a run's event chain.

        A checkpoint only anchors anything once a copy is held where the database owner cannot
        rewrite it. It attests what the issuer's log contained when signed, not that the log
        is truthful, and it says nothing about events appended afterwards.
        """
        db = self.connect()
        try:
            db.execute("BEGIN")
            if not db.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone():
                raise Denied("RUN_UNKNOWN", "Unknown run.")
            size = db.execute("SELECT COUNT(*) FROM events WHERE run_id=?", (run_id,)).fetchone()[0]
            head = db.execute("SELECT hash FROM events WHERE run_id=? ORDER BY seq DESC LIMIT 1", (run_id,)).fetchone()
        finally:
            db.close()
        body = {"type": "checkpoint", "run_id": run_id, "size": size, "head": head[0] if head else "0" * 64,
                "policy": POLICY, "time": self.clock()}
        return {"body": body, "signature": b64(self.key.sign(canonical(body)))}
