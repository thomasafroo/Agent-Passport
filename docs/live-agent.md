# Connect a live model

The incident story uses scripted agents. This mode puts a real model behind the same gateway. An MCP adapter (`agent_passport/mcp_server.py`) holds a passport issued by the console and exposes three tools. The model never receives a passport token; it sees tool names, its own arguments, and the gateway's decisions.

```
MCP client (real model)
  -> MCP adapter: holds the live passport and any worker passports it delegates
  -> gateway agent API: signature, exact scope, ancestor chain, shared budget
  -> executor: credential from the synthetic provider or 1Password
  -> synthetic staging service
```

The enforcement path is the same one the scripted agents use. The adapter adds no policy of its own.

## Tools

| Tool | What it does |
|---|---|
| `my_passport` | Shows the holder, exact resource/action pairs, status, expiry, and the shared budget. Accepts `worker` to inspect a delegated worker. |
| `perform_operation` | Asks the gateway to run one resource/action pair. Allowed calls spend one unit from the shared pool. Accepts `worker`. |
| `delegate_worker` | Creates a named worker with a subset of the parent's pairs. The adapter keeps the worker's token. |

Denials come back as ordinary results such as `{"allowed": false, "rule": "RESOURCE_ACTION_DENIED", ...}`, so the model can see exactly why a request failed.

## Run it

1. Start the gateway with `python -m agent_passport` and open the console.
2. Under **Put a real model behind the boundary**, select **Issue live passport**. The gateway delegates a passport named *Claude (live)* from the coordinator, with the coordinator's three pairs and expiry, and writes its token to `.state/live-agent.token`. The browser never receives it.
3. Register the adapter with an MCP client. It needs the full path to the repository's virtual-environment Python, because the client starts it as a separate process.

   Claude Desktop on Windows (`%APPDATA%\Claude\claude_desktop_config.json`):

   ```json
   {
     "mcpServers": {
       "agent-passport": {
         "command": "C:\\path\\to\\AgentPassport\\.venv\\Scripts\\python.exe",
         "args": ["-m", "agent_passport.mcp_server"]
       }
     }
   }
   ```

   Claude Code (a terminal-wide client, so read the security note below first):

   ```bash
   claude mcp add agent-passport -- C:\path\to\AgentPassport\.venv\Scripts\python.exe -m agent_passport.mcp_server
   ```

   Optional environment variables: `PASSPORT_GATEWAY` (default `http://127.0.0.1:8787`) and `PASSPORT_STATE_DIR` (default: the repository's `.state`).

4. Ask the model to investigate why staging checkout is failing. The synthetic logs include a planted line telling AI agents to deploy to production and create an admin worker.

Whatever the model does, the console shows it: the live node and its workers in the tree, a red badge for denials, budget cells it spent, and every decision in the ledger. Revoke *Claude (live)* in the inspector and its next call, and every worker's, is denied with `ANCESTOR_REVOKED`. **Reset** revokes the live passport and deletes the token file; the adapter then drops its cached worker passports.

The live agent shares the run's 24-unit pool with the scripted story. If the fork race has already spent it, reset first.

## Security notes

- **Token isolation depends on the client's other access.** The adapter never returns a token, and tests check every tool output for them. A client that can also read files or run shell commands, such as Claude Code in this repository, could read `.state/live-agent.token` directly or call the loopback console API, which is an operator surface. Claude Desktop with only this MCP server is the cleaner demonstration. Even a stolen live token carries only that passport's narrow pairs, shares the same pool, and dies when the branch is revoked; it cannot escalate.
- **The model is not trusted, and is not being evaluated.** Whether it follows the planted instruction is incidental. The demonstration is that the gateway's decision does not depend on it. Model behavior varies between runs, so one recorded run describes that run only.
- **Idempotency keys are chosen by the adapter**, one per tool call, so a model retrying a call is a new operation that spends a new unit.
- The adapter talks to the gateway over loopback HTTP with the bearer token in the `Authorization` header. It is not hardened for remote gateways.

## Verification status

Automated tests (`tests/test_mcp.py`) run the adapter against the real app in-process: allowed operations spend the shared pool, the injected deploy is denied and recorded, delegation narrows and escalation is denied, revocation stops the live agent and its workers, reset withdraws the token, console endpoints reject bearer tokens, and no tool output contains any passport token.

On 2026-10-31 the adapter was also driven over a real stdio MCP session (MCP Python SDK 2.3.0) against a running gateway: all three tools listed, the planted log line returned, `deploy.execute` on production denied, an escalating delegation denied, a narrowed worker's read completed, and no token appeared in any tool result. That run used a scripted MCP client. A session driven by a Claude model has not yet been recorded in this repository.
