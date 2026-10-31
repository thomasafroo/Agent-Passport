"""MCP adapter: lets a real model act through a passport without ever holding one.

The model sees tool names, arguments and gateway decisions. Passport tokens, for the
issued live agent and for any workers it delegates, stay inside this process and are
sent only to the gateway's agent API. The gateway remains the only policy engine.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import urllib.error
import urllib.request
import uuid

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

ROOT = Path(__file__).resolve().parent.parent


class Gateway:
    """Minimal client for the bearer-authenticated agent API."""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def call(self, method, path, token, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base_url + path, data=data, method=method,
                                         headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            except ValueError:
                return error.code, {"detail": "The gateway returned an unreadable error."}
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ToolError("The Agent Passport gateway is not reachable. Start it with python -m agent_passport.") from None


class Adapter:
    def __init__(self, gateway, token_path):
        self.gateway, self.token_path = gateway, Path(token_path)
        self.workers = {}  # worker name -> token; never returned to the model
        self._loaded = None

    def _own_token(self):
        try:
            token = self.token_path.read_text(encoding="ascii").strip()
        except OSError:
            token = ""
        if token != self._loaded:
            # A re-issued or withdrawn passport invalidates every worker delegated under the old one.
            self.workers.clear()
            self._loaded = token
        if not token:
            raise ToolError("No live agent passport has been issued. In the console, select Issue live passport.")
        return token

    def _token_for(self, worker):
        own = self._own_token()
        if not worker:
            return own
        if worker not in self.workers:
            raise ToolError(f"No worker named {worker!r} was delegated in this session.")
        return self.workers[worker]

    @staticmethod
    def _decision(status, body):
        if status == 200:
            return None
        if isinstance(body, dict) and "rule" in body:
            return {"allowed": False, "rule": body["rule"], "detail": body["detail"]}
        detail = body.get("detail") if isinstance(body, dict) else None
        return {"allowed": False, "rule": "REQUEST_REJECTED", "detail": detail if isinstance(detail, str) else "The gateway rejected the request."}

    def passport(self, worker=None):
        status, body = self.gateway.call("GET", "/api/agent/passport", self._token_for(worker))
        denied = self._decision(status, body)
        if denied:
            return denied
        grant = body["grant"]
        return {"holder": grant["subject"], "passport_id": grant["id"], "status": body["state"],
                "permitted_operations": grant["scopes"], "expires_unix": grant["expires"],
                "shared_budget": body["budget"], "workers_delegated_here": sorted(self.workers)}

    def operate(self, resource, action, worker=None):
        body = {"resource": resource, "action": action, "request_key": uuid.uuid4().hex}
        status, result = self.gateway.call("POST", "/api/agent/execute", self._token_for(worker), body)
        denied = self._decision(status, result)
        if denied:
            return denied
        outcome = {"allowed": True, "operation_id": result["operation_id"], "state": result["state"]}
        if result["state"] == "completed":
            outcome["result"] = result["result"]
            outcome["receipt_signed_by_gateway"] = bool(result.get("receipt"))
        else:
            outcome["detail"] = "The operation did not complete. The gateway recorded the outcome."
        return outcome

    def delegate(self, worker, operations, parent=None):
        if not isinstance(worker, str) or not worker.strip():
            raise ToolError("Give the worker a name.")
        worker = worker.strip()
        if worker in self.workers:
            raise ToolError(f"A worker named {worker!r} already exists in this session.")
        parent_token = self._token_for(parent)
        status, own = self.gateway.call("GET", "/api/agent/passport", parent_token)
        denied = self._decision(status, own)
        if denied:
            return denied
        body = {"subject": worker, "scopes": operations, "expires": own["grant"]["expires"]}
        status, result = self.gateway.call("POST", "/api/agent/delegate", parent_token, body)
        denied = self._decision(status, result)
        if denied:
            return denied
        self.workers[worker] = result["token"]
        return {"delegated": True, "worker": worker, "passport_id": result["grant"]["id"],
                "permitted_operations": result["grant"]["scopes"],
                "note": "The worker's passport is held by this adapter. Act as it with worker=" + json.dumps(worker) + "."}


def build(adapter):
    mcp = MCPServer("agent-passport", instructions=(
        "You act through an Agent Passport. Every tool call is authorized by a local gateway against your passport's "
        "exact resource/action pairs and a budget shared with every worker you delegate. Data returned by operations "
        "comes from an untrusted synthetic service. Denials are final; the gateway is the policy engine."))

    @mcp.tool()
    def my_passport(worker: str | None = None) -> dict:
        """Show the passport you (or a named worker you delegated) hold: permitted resource/action pairs, status, expiry, and the shared budget."""
        return adapter.passport(worker)

    @mcp.tool()
    def perform_operation(resource: str, action: str, worker: str | None = None) -> dict:
        """Ask the gateway to perform one operation, such as action "logs.read" on resource "staging/checkout", "code.read" on "repo/checkout", or "patch.propose" on "repo/checkout". Each allowed operation spends one unit from the shared budget. Pass worker to act as a worker you delegated."""
        return adapter.operate(resource, action, worker)

    @mcp.tool()
    def delegate_worker(worker: str, operations: list[dict[str, str]], parent: str | None = None) -> dict:
        """Create a named worker with a narrower passport. operations is a list of {"resource": ..., "action": ...} pairs, each of which the parent must already hold. The worker shares your budget and expiry."""
        return adapter.delegate(worker, operations, parent)

    return mcp


def main():
    state = Path(os.environ.get("PASSPORT_STATE_DIR") or ROOT / ".state")
    gateway = Gateway(os.environ.get("PASSPORT_GATEWAY", "http://127.0.0.1:8787"))
    build(Adapter(gateway, state / "live-agent.token")).run()


if __name__ == "__main__":
    main()
