"""A real upstream for one operation: `patch.propose` on `repo/checkout` files a GitHub issue.

Operator configuration only. The repository comes from PASSPORT_GITHUB_REPO at startup, the API
origin is fixed, the issue text is fixed by this module, and the token is the dispatched pair's
own 1Password reference. An agent names only the catalog pair, as for every other operation.

GitHub's REST API has no idempotency key for issue creation and no way to fence an ID, which
shapes every outcome rule here:

- Only failures that provably happened before GitHub could act are refunded: DNS failure, a
  refused connection, a failed certificate check, or a 3xx/4xx answer, which GitHub sends
  without creating the issue. Everything else, including a timeout, a reset, a 5xx and an
  unreadable 201, is `unknown` and keeps its unit.
- An effect lookup can find an issue the token's own account filed with this operation's marker,
  which settles the operation as completed. Not finding one proves nothing: the request may still
  be in transit, and GitHub cannot be told to refuse it later. That lookup changes nothing and the
  operator decides by hand.
"""
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .core import canonical


PAIR = ("repo/checkout", "patch.propose")
API = "https://api.github.com"
REPO_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}")
TITLE = "Agent Passport: proposed fix for staging checkout pool exhaustion"
PROPOSAL = "Align staging pool size with worker concurrency; add a saturation test."
LOOKUP_PAGES = 10  # 1,000 issues by the token's account; beyond that a lookup is inconclusive


class UpstreamRejected(Exception):
    """The upstream refused the request before any effect. Safe to refund."""


class EffectUnfenced(Exception):
    """No effect was found, but the upstream cannot fence the ID, so absence proves nothing."""


def check_repo(value):
    if not isinstance(value, str) or not REPO_PATTERN.fullmatch(value) or value.split("/")[1] in {".", ".."}:
        raise ValueError("PASSPORT_GITHUB_REPO must be OWNER/REPOSITORY")
    return value


def marker(operation_id):
    return f"<!-- agent-passport-operation: {operation_id} {PAIR[0]} {PAIR[1]} -->"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the token must reach only the configured origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubIssues:
    """Routes PAIR to GitHub and every other operation to `fallback` (the fixture service)."""

    def __init__(self, repo, fallback, api=API, timeout=15.0):
        self.repo = check_repo(repo)
        self.fallback = fallback
        self.api = api.rstrip("/")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    @property
    def label(self):
        return f"github:{self.repo}"

    def _request(self, credential, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.api + path, data=data, method=method, headers={
            "Accept": "application/vnd.github+json", "Authorization": f"Bearer {credential}",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "agent-passport/0.1",
            **({"Content-Type": "application/json"} if data else {})})
        with self._opener.open(request, timeout=self.timeout) as response:
            return response.status, response.read()

    def execute(self, credential, resource, action, operation_id=None):
        if (resource, action) != PAIR:
            return self.fallback.execute(credential, resource, action, operation_id)
        if not operation_id:
            raise UpstreamRejected("A GitHub effect needs an operation ID to be found later.")
        body = {"title": TITLE, "body": f"{PROPOSAL}\n\nFiled by Agent Passport operation `{operation_id}`. "
                                         f"The incident is synthetic; no code was changed.\n\n{marker(operation_id)}"}
        outcome, status, raw = None, 0, b""
        try:
            status, raw = self._request(credential, "POST", f"/repos/{self.repo}/issues", body)
        except urllib.error.HTTPError as error:
            # Only 3xx/4xx is a definite refusal; GitHub may have acted before answering 5xx.
            outcome = "rejected" if error.code < 500 else "uncertain"
        except urllib.error.URLError as error:
            # urllib wraps connect and send failures. Only these show the request never left.
            before = isinstance(error.reason, (socket.gaierror, ConnectionRefusedError, ssl.SSLCertVerificationError))
            outcome = "rejected" if before else "uncertain"
        except Exception:
            outcome = "uncertain"
        # Fixed messages, raised outside the handlers: no upstream text or token is chained.
        if outcome == "rejected":
            raise UpstreamRejected("GitHub refused the request before creating anything.")
        if outcome == "uncertain":
            raise RuntimeError("GitHub's outcome is uncertain.")
        try:
            issue = json.loads(raw)
            result = {"issue": int(issue["number"]), "url": str(issue["html_url"]), "repository": self.repo, "synthetic": False}
        except (ValueError, KeyError, TypeError):
            result = None
        if status != 201 or result is None:
            raise RuntimeError("GitHub's outcome is uncertain.")
        return result

    def lookup(self, credential, operation_id, resource=None, action=None):
        if (resource, action) != PAIR:
            return self.fallback.lookup(credential, operation_id, resource, action)
        failed, found = False, None
        try:
            login = json.loads(self._request(credential, "GET", "/user")[1])["login"]
            found = self._find(credential, login, operation_id)
        except Exception:
            failed = True
        if failed:
            raise UpstreamRejected("GitHub's issue list could not be read.")
        if found is None:
            raise EffectUnfenced("No issue carries this operation's marker, and GitHub cannot fence the ID.")
        return {"state": "applied", "resource": PAIR[0], "action": PAIR[1], "result": canonical(found).decode()}

    def _find(self, credential, login, operation_id):
        tag = marker(operation_id)
        for page in range(1, LOOKUP_PAGES + 1):
            query = urllib.parse.urlencode({"state": "all", "creator": login, "per_page": 100, "page": page})
            issues = json.loads(self._request(credential, "GET", f"/repos/{self.repo}/issues?{query}")[1])
            for issue in issues:
                # The creator filter runs on GitHub; check it again so a marker copied into another
                # account's issue is never taken as this executor's effect.
                if issue.get("user", {}).get("login") == login and tag in (issue.get("body") or ""):
                    return {"issue": int(issue["number"]), "url": str(issue["html_url"]), "repository": self.repo, "synthetic": False}
            if len(issues) < 100:
                return None
        return None
