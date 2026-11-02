"""The GitHub upstream adapter against a local HTTP server that behaves like GitHub's issues API.

The live path is `scripts/check_github.py`; nothing here reaches GitHub.
"""
import hashlib
import http.server
import json
import socket
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest

from agent_passport.broker import EffectLog, Executor, FixtureService, OnePasswordCredentials
from agent_passport.core import Denied, Passport, canonical, verify_receipt
from agent_passport.github import PAIR, GitHubIssues, check_repo, marker

REPO = "octo-demo/agent-passport-sandbox"
TOKEN = "github_pat_FAKE-TOKEN-never-real-0123456789"
FIXTURE_KEY = "fixture-key-not-a-secret"
LOGIN = "passport-bot"


class FakeGitHub:
    """Issues API subset: POST/GET /repos/{repo}/issues and GET /user, with injectable faults."""

    def __init__(self):
        self.issues, self.requests = [], []
        self.fail_create = None   # an HTTP status to answer POST with
        self.create_then = None   # an HTTP status to answer after the issue is created anyway
        self.delay = 0.0
        self.list_lag = 0        # list calls that still omit the newest issue, as GitHub's list can
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body, headers=None):
                data = json.dumps(body).encode()
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _authorized(self):
                fake.requests.append((self.command, self.path, self.headers.get("Authorization")))
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self._send(401, {"message": "Bad credentials"})
                    return False
                return True

            def do_GET(self):
                if not self._authorized():
                    return
                url = urlparse(self.path)
                if url.path == "/user":
                    return self._send(200, {"login": LOGIN})
                if url.path == f"/repos/{REPO}/issues":
                    query = parse_qs(url.query)
                    page, size = int(query["page"][0]), int(query["per_page"][0])
                    mine = [i for i in fake.issues if i["user"]["login"] == query["creator"][0]]
                    if fake.list_lag:
                        fake.list_lag -= 1
                        mine = mine[:-1]
                    return self._send(200, mine[(page - 1) * size:page * size])
                self._send(404, {"message": "Not Found"})

            def do_POST(self):
                if not self._authorized():
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if fake.delay:
                    time.sleep(fake.delay)
                if fake.fail_create:
                    return self._send(fake.fail_create, {"message": f"refused, token was {TOKEN}"},
                                      {"Location": "http://127.0.0.1:1/elsewhere"} if fake.fail_create in (301, 307, 308) else None)
                number = len(fake.issues) + 1
                fake.issues.append({"number": number, "html_url": f"https://github.com/{REPO}/issues/{number}",
                                    "title": body["title"], "body": body["body"], "user": {"login": LOGIN}})
                if fake.create_then:
                    return self._send(fake.create_then, {"message": "Server Error"})
                self._send(201, fake.issues[-1])

        class Server(http.server.ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass  # a client that timed out closes before the answer; that is the point of the test

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class PairCredentials:
    """Each pair resolves its own credential, as with a 1Password reference map."""
    mode = "1password-sdk"

    def __init__(self):
        self.resolved = []

    def resolve(self, resource=None, action=None):
        self.resolved.append((resource, action))
        return TOKEN if (resource, action) == PAIR else FIXTURE_KEY


@pytest.fixture
def github():
    fake = FakeGitHub()
    yield fake
    fake.close()


@pytest.fixture
def engine(tmp_path):
    return Passport(tmp_path)


def make_executor(engine, api, timeout=2.0):
    fixture = FixtureService(hashlib.sha256(FIXTURE_KEY.encode()).hexdigest(), EffectLog(engine.directory / "fixture-effects.db"))
    return Executor(engine, PairCredentials(), GitHubIssues(REPO, fixture, api=api, timeout=timeout))


def balance(engine, root):
    run = engine.snapshot(root["run_id"])["run"]
    return run["spent"], run["reserved"]


def surfaces(engine, root, *results):
    return json.dumps([engine.evidence(root["run_id"]), engine.snapshot(root["run_id"]), *results], default=str)


def test_completed_issue_carries_the_operation_marker_and_spends_one_unit(engine, github):
    root = engine.create_run(budget=2)
    result = make_executor(engine, github.url).execute(root["token"], *PAIR, "propose-1")
    assert result["state"] == "completed"
    assert result["result"] == {"issue": 1, "url": f"https://github.com/{REPO}/issues/1", "repository": REPO, "synthetic": False}
    assert verify_receipt(result["receipt"], engine.public_key)
    assert marker(result["operation_id"]) in github.issues[0]["body"]
    assert balance(engine, root) == (1, 0)
    assert TOKEN not in surfaces(engine, root, result)


def test_a_retry_with_the_same_key_files_no_second_issue(engine, github):
    root = engine.create_run(budget=3)
    executor = make_executor(engine, github.url)
    first = executor.execute(root["token"], *PAIR, "propose-1")
    again = executor.execute(root["token"], *PAIR, "propose-1")
    assert again["duplicate"] and again["operation_id"] == first["operation_id"]
    assert len(github.issues) == 1 and balance(engine, root) == (1, 0)


def test_other_operations_still_reach_the_fixture_with_their_own_credential(engine, github):
    root = engine.create_run(budget=2)
    executor = make_executor(engine, github.url)
    result = executor.execute(root["token"], "staging/checkout", "logs.read", "logs-1")
    assert result["state"] == "completed" and result["result"]["synthetic"] is True
    assert isinstance(executor.provider, PairCredentials)
    assert github.requests == [] and executor.provider.resolved == [("staging/checkout", "logs.read")]


@pytest.mark.parametrize("status", [401, 403, 404, 422, 429, 301, 307])
def test_definite_refusals_are_refunded_without_upstream_text(engine, github, status):
    github.fail_create = status
    root = engine.create_run(budget=1)
    result = make_executor(engine, github.url).execute(root["token"], *PAIR, "propose-1")
    assert result["state"] == "failed" and balance(engine, root) == (0, 0)
    assert github.issues == []
    assert "refused, token" not in surfaces(engine, root, result) and TOKEN not in surfaces(engine, root, result)


def test_a_redirect_is_never_followed_with_the_token(engine, github):
    second = FakeGitHub()
    try:
        github.fail_create = 307
        root = engine.create_run(budget=1)
        executor = make_executor(engine, github.url)
        assert executor.execute(root["token"], *PAIR, "propose-1")["state"] == "failed"
        assert second.requests == []
    finally:
        second.close()


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_5xx_is_uncertain_and_keeps_the_unit(engine, github, status):
    github.fail_create = status
    root = engine.create_run(budget=1)
    result = make_executor(engine, github.url).execute(root["token"], *PAIR, "propose-1")
    assert result["state"] == "unknown" and balance(engine, root) == (0, 1)


def test_a_timeout_after_sending_is_uncertain_and_keeps_the_unit(engine, github):
    github.delay = 1.5
    root = engine.create_run(budget=1)
    result = make_executor(engine, github.url, timeout=0.3).execute(root["token"], *PAIR, "propose-1")
    assert result["state"] == "unknown" and balance(engine, root) == (0, 1)


def test_a_refused_connection_is_known_not_to_have_reached_github(engine):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = f"http://127.0.0.1:{probe.getsockname()[1]}"
    root = engine.create_run(budget=1)
    # Windows retries a refused SYN for about two seconds before reporting it.
    result = make_executor(engine, closed, timeout=10.0).execute(root["token"], *PAIR, "propose-1")
    assert result["state"] == "failed" and balance(engine, root) == (0, 0)


def test_lookup_settles_a_lost_response_from_the_issue_github_recorded(engine, github):
    github.create_then = 502  # GitHub created the issue, then the answer was lost
    root = engine.create_run(budget=1)
    executor = make_executor(engine, github.url)
    oid = executor.execute(root["token"], *PAIR, "propose-1")["operation_id"]
    assert balance(engine, root) == (0, 1)
    reconciled = executor.resolve(oid)
    assert reconciled["state"] == "reconciled_completed" and balance(engine, root) == (1, 0)
    expected = canonical({"issue": 1, "url": f"https://github.com/{REPO}/issues/1", "repository": REPO, "synthetic": False})
    assert reconciled["receipt"]["body"]["basis"]["result_digest"] == hashlib.sha256(expected).hexdigest()
    assert TOKEN not in surfaces(engine, root, reconciled)


def test_absence_without_a_fence_changes_nothing_and_leaves_an_operator_decision(engine, github):
    github.fail_create = 503  # no issue was created, but the gateway cannot know that
    root = engine.create_run(budget=1)
    executor = make_executor(engine, github.url)
    oid = executor.execute(root["token"], *PAIR, "propose-1")["operation_id"]
    for _ in range(2):
        with pytest.raises(Denied) as error:
            executor.resolve(oid)
        assert error.value.rule == "LOOKUP_INCONCLUSIVE"
        assert balance(engine, root) == (0, 1)
        assert engine.operation(oid)["state"] == "unknown"
    decided = engine.reconcile(oid, "not_executed", "Checked the repository by hand; no issue for this operation.")
    assert decided["state"] == "reconciled_not_executed" and balance(engine, root) == (0, 0)


def test_list_lag_after_a_lost_answer_is_inconclusive_until_the_issue_appears(engine, github):
    github.create_then = 502
    root = engine.create_run(budget=1)
    executor = make_executor(engine, github.url)
    oid = executor.execute(root["token"], *PAIR, "propose-1")["operation_id"]
    github.list_lag = 1
    with pytest.raises(Denied) as error:
        executor.resolve(oid)
    assert error.value.rule == "LOOKUP_INCONCLUSIVE" and balance(engine, root) == (0, 1)
    assert executor.resolve(oid)["state"] == "reconciled_completed" and balance(engine, root) == (1, 0)


def test_a_marker_copied_into_another_accounts_issue_is_not_an_effect(engine, github):
    github.fail_create = 503
    root = engine.create_run(budget=1)
    executor = make_executor(engine, github.url)
    oid = executor.execute(root["token"], *PAIR, "propose-1")["operation_id"]
    github.issues.append({"number": 9, "html_url": "x", "title": "copy", "body": marker(oid), "user": {"login": "someone-else"}})
    with pytest.raises(Denied) as error:
        executor.resolve(oid)
    assert error.value.rule == "LOOKUP_INCONCLUSIVE" and balance(engine, root) == (0, 1)


def test_a_failed_lookup_is_lookup_failed_and_keeps_the_unit(engine, github):
    github.fail_create = 503
    root = engine.create_run(budget=1)
    executor = make_executor(engine, github.url)
    oid = executor.execute(root["token"], *PAIR, "propose-1")["operation_id"]
    assert isinstance(executor.service, GitHubIssues)
    executor.service.api = "http://127.0.0.1:1"
    with pytest.raises(Denied) as error:
        executor.resolve(oid)
    assert error.value.rule == "LOOKUP_FAILED" and balance(engine, root) == (0, 1)


@pytest.mark.parametrize("repo", ["", "owner", "owner/", "/repo", "owner/repo/extra", "-owner/repo", "owner/..",
                                  "owner/repo?x=1", "owner/re po", "https://github.com/owner/repo"])
def test_malformed_repositories_are_refused(repo):
    with pytest.raises(ValueError):
        check_repo(repo)


def test_github_configuration_requires_a_reference_map(tmp_path):
    with pytest.raises(ValueError, match="PASSPORT_OP_REFERENCES"):
        Executor.from_environment(Passport(tmp_path), environ={"PASSPORT_GITHUB_REPO": REPO, "PASSPORT_OP_REFERENCE": "op://V/I/f",
                                                                "PASSPORT_FIXTURE_KEY_SHA256": "0" * 64})


def test_github_configuration_needs_no_fixture_digest_for_its_pair(tmp_path):
    references = {"staging/checkout logs.read": {"reference": "op://V/Log/password", "sha256": "1" * 64},
                  "repo/checkout code.read": {"reference": "op://V/Code/password", "sha256": "2" * 64},
                  "repo/checkout patch.propose": "op://V/GitHub/token",
                  "staging/checkout config.write": {"reference": "op://V/Config/password", "sha256": "3" * 64}}
    path = tmp_path / "references.json"
    path.write_text(json.dumps(references), encoding="utf-8")
    executor = Executor.from_environment(Passport(tmp_path / "state"), backend=PairCredentials(),
                                         environ={"PASSPORT_GITHUB_REPO": REPO, "PASSPORT_OP_REFERENCES": str(path)})
    assert executor.upstream == f"github:{REPO}"
    assert isinstance(executor.service, GitHubIssues) and isinstance(executor.provider, OnePasswordCredentials)
    assert executor.service.api == "https://api.github.com"
    assert executor.provider.reference_for(*PAIR) == "op://V/GitHub/token"


def test_the_default_executor_reports_the_fixture_upstream(tmp_path):
    assert Executor(Passport(tmp_path)).upstream == "fixture"


class MappedBackend:
    """A 1Password backend stand-in that resolves the references in the test map."""
    mode = "1password-sdk"

    def read(self, reference):
        return TOKEN if reference.endswith("/GitHub/token") else FIXTURE_KEY


def test_the_live_check_script_passes_against_a_github_shaped_server(tmp_path, github, monkeypatch, capsys):
    import agent_passport.broker as broker
    import scripts.check_github as check
    from scripts.verify_evidence import verify

    key = hashlib.sha256(FIXTURE_KEY.encode()).hexdigest()
    references: dict[str, object] = {f"{r} {a}": {"reference": f"op://V/{a}/password", "sha256": key}
                  for r, a in [("staging/checkout", "logs.read"), ("repo/checkout", "code.read"), ("staging/checkout", "config.write")]}
    references["repo/checkout patch.propose"] = "op://V/GitHub/token"
    path = tmp_path / "references.json"
    path.write_text(json.dumps(references), encoding="utf-8")
    monkeypatch.setenv("PASSPORT_GITHUB_REPO", REPO)
    monkeypatch.setenv("PASSPORT_OP_REFERENCES", str(path))
    monkeypatch.setattr(check, "ROOT", tmp_path)
    monkeypatch.setattr(check, "backend_from_environment", MappedBackend)
    monkeypatch.setattr(broker, "GitHubIssues", lambda repo, fallback: GitHubIssues(repo, fallback, api=github.url))
    monkeypatch.setattr(check, "LOOKUP_WAIT", 0)
    github.list_lag = 2  # observed live: the lost-answer issue was missing from the list right after creation

    assert check.main() == 0
    output = capsys.readouterr().out
    assert "reconciled_completed; inconclusive first: 2 time(s)" in output
    assert "operation still unknown, reserved units 1 -> 1" in output and "spent 2, reserved 0 of 3" in output
    assert TOKEN not in output and len(github.issues) == 2
    evidence = json.loads((tmp_path / "artifacts" / "github-check-evidence.json").read_text(encoding="utf-8"))
    assert verify(evidence, (tmp_path / "artifacts" / "github-check-public-key.txt").read_text().strip())["reconciliations"] == 2
    assert TOKEN not in json.dumps(evidence)
