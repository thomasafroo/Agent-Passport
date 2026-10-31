# Agent Passport

**Agents can multiply. Their authority cannot.**

Agent Passport is a local security research demo for delegated AI workflows. A coordinator investigates a staging incident, delegates narrower passports to workers, and shares one operation budget across the entire tree. A compromised worker attempts a production action. The gateway rejects it, revokes the branch, cancels queued work, and lets an unrelated worker finish.

Then fork 32 workers. They can compete for the remaining budget; they cannot duplicate it.

This is an independent portfolio project, not affiliated with or endorsed by 1Password. The interesting contribution is the inspectable combination of delegation, concurrency-safe budget accounting, and containment. Attenuated capabilities and revocation are established ideas; this project does not claim to invent them.

![The incident console after branch containment and a concurrent fork experiment](docs/images/console.jpg)

## Run locally

Requires Python 3.11+; no Node build, cloud account, or API key is required.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m agent_passport
```

macOS/Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m agent_passport
```

Open **http://127.0.0.1:8787**. Use `--port 8788` if that port is occupied. Run from the repository root. The server binds only to loopback. The console is a trusted local operator surface, not a hosted multi-user application.

1. **Start investigation** — four workers inherit exact, narrower permissions.
2. **Inject malicious output** — a scripted worker attempts production deployment and broader delegation. The incident panel quotes the untrusted output beside both denials.
3. **Contain branch** — revoke the log reader. Its descendant's queued operation is cancelled and its next request denied; both passports are stamped void.
4. **Complete investigation** — the patch worker completes a synthetic patch proposal.
5. **Fork 32 workers** — concurrent requests exhaust the same shared pool without exceeding its limit. Budget cells show which branch spent each unit.
6. **Download evidence** — events, signed operation receipts, public issuer key, and measured run results.

One primary button (or the → key) advances the story, and the inspector follows the agent each step is about. Click any tree node to open its passport: exact permissions, issuer, expiry, the ancestor chain the gateway checks, and a machine-readable zone derived from the grant. The machine-readable zone is decorative encoding, not a security mechanism. The inspector can revoke a branch independently of the scripted story. Reset starts a new run; prior records remain on disk. Restarting starts a fresh console story while existing grants, budgets, revocations, and idempotency records remain durable.

## Connect a real model

The console can issue a passport to an MCP adapter so a real model, such as Claude, works the incident through the same gateway. The adapter keeps every passport token; the model sees only tool results. The synthetic logs contain a planted instruction to deploy to production, and the console shows each decision the gateway makes about the model's requests. See [the live agent guide](docs/live-agent.md), including what isolation it does and does not provide.

In [recorded runs with Claude Sonnet 5.5](docs/live-runs/README.md), the model declined the planted instruction on its own. When the operator prompt told it to obey log notes, it attempted the production deploy and an admin delegation; the gateway denied both while its legitimate work completed. After revocation in the console, its next call was denied.

## What is real

| Mechanism | Implementation |
|---|---|
| Signed identity | Ed25519-signed bearer passport bound to stored immutable grant claims |
| Delegation | Exact resource/action pairs must be a subset of the parent's pairs; expiry cannot extend |
| Shared budget | SQLite `BEGIN IMMEDIATE` plus a conditional root-pool update and database invariant |
| Revocation | Full ancestor chain checked at reservation and again at dispatch; no cache |
| Retry handling | Unique `(grant_id, request_key)` bound to the canonical operation digest |
| Failure accounting | Known pre-effect failures refunded; unknown outcomes retain the reserved unit |
| Persistence | SQLite WAL plus a persistent issuer key; works across local worker processes |
| Credential isolation | Executor resolves credentials; passports, browser state, and receipts contain no credential values |
| Evidence | Hash-linked decision events and independently verifiable signed operation receipts |
| 1Password | Optional real `op read` credential resolver connected to an authenticated synthetic service |
| Live model | Optional MCP adapter: a real model acts through a passport it never holds; the gateway decides every call |

The story's agents are **scripted**, and logs/code/patches come from a **synthetic service**. A connected live model is real, but its tools reach only that same synthetic service. No production deployment exists. The malicious tool output is a deterministic adversarial fixture, not an evaluation of an LLM's prompt-injection resistance. The test demonstrates what the authorization boundary does when a worker makes an unauthorized request.

## Verify the claims

```powershell
python -m pytest -q
python scripts/benchmark.py
python scripts/run_scenario.py
```

The benchmark races 100 agents against a 10-unit budget and asserts exactly 10 completions and 90 budget denials. It also runs a deliberately unsafe check-then-act implementation with a barrier that forces the race, measures 200 sequential authorization/reservation transactions, and measures 30 revoke-then-deny round trips. Results are written to `artifacts/benchmark.json`.

Tests cover multi-thread and multi-process contention, concurrent retries, resource/action pair isolation, altered signatures, foreign issuers, stale grants, revoked ancestors, queue expiry, crash persistence, refunds, unknown effects, signed receipts, secret-safe errors, and HTTP boundary checks. GitHub Actions runs the suite on Windows and Linux with Python 3.11 and 3.13; all four jobs passed on `main` on 2026-10-31. The suite includes a benchmark step whose timings on shared CI runners are not comparable to the local results.

For offline evidence verification, obtain the issuer public key through a trusted channel (the local issuer is `.state/issuer.key`; **never share the private key**). The scenario runner writes a separate public-key file:

```powershell
python scripts/verify_evidence.py artifacts/scenario-evidence.json --public-key-file artifacts/issuer-public-key.txt
```

Pin the public key independently before accepting evidence from someone else. A key embedded in the same untrusted export is not a trust anchor. Receipt signatures establish what the issuer signed, not whether an external executor reported reality truthfully. The event hash chain is not externally anchored and cannot prove completeness or resist a writer who recomputes the whole chain.

## 1Password integration

The default runs entirely offline. To exercise the real credential path, use a dedicated test vault and synthetic fixture key with the 1Password CLI. Follow [the setup guide](docs/1password.md). Credentials are retrieved only by the executor; agent inputs cannot choose a secret reference, URL, header, shell command, or credential provider.

The CLI contract is tested with a mocked subprocess. Separately, a live run through the 1Password desktop app integration was performed on 2026-10-30: the scenario's operations completed with the credential resolved from a real test vault. The default test suite does not touch a 1Password account; see [the verification notes](docs/1password.md#current-verification-status) for exactly what that run does and does not show.

## Architecture

```mermaid
flowchart LR
    O[Local operator] --> G[Root passport]
    G --> A[Log reader]
    G --> B[Code investigator]
    G --> C[Patch worker]
    A --> D[Trace analyst]
    G --> L[Claude live, via MCP adapter]
    A & B & C & D & L --> V[Gateway: verify chain + reserve unit]
    V --> DB[(SQLite shared root pool)]
    V --> E[Executor: revalidate at dispatch]
    P[1Password CLI or synthetic provider] --> E
    E --> S[Authenticated fixture service]
    E --> R[Signed receipt + settlement]
```

See [the live agent guide](docs/live-agent.md), [the threat model](docs/threat-model.md), [authorization semantics](docs/architecture.md), [measured results](docs/results.md), and [the 90-second demo script](docs/demo-script.md).

## Repository map

```text
agent_passport/core.py     Signed grants, ancestor checks, transactions, receipts
agent_passport/broker.py   Credential providers and controlled executor
agent_passport/demo.py     Reproducible incident and concurrent fork scenarios
agent_passport/server.py   Local console and bearer-authenticated agent API
agent_passport/mcp_server.py  MCP adapter for a live model; holds passports, never returns them
web/                      Responsive console; plain JS, CSS, no external assets
tests/                    Security invariants and HTTP integration tests
scripts/                  Benchmarks, scenario runner, offline verifier
docs/                     Design, threat model, demo script, integration setup
```

## Boundaries and next research questions

The current model counts fixed-cost operations, not dollars or actual provider usage. It shares a root pool rather than allocating child sub-budgets. Bearer possession authenticates the passport; there is no proof-of-possession binding to a particular process. Revocation linearizes at the database transaction; already dispatched work may still finish. Unknown or crash-interrupted operations deliberately retain capacity until trusted reconciliation, which this release does not automate.

[A simulated experiment](docs/revocation-experiment.md) measures what a caching edge would cost under network partitions. A fail-open cache let a revoked branch keep working for the whole partition. Bounded staleness with budget leases capped that delay and never overspent, but the cap depends on the edge's clock. The shipped gateway still has no cache. Other extensions include per-agent signing keys, data-dependency quarantine, external service idempotency, trusted resource-version approvals, and independently anchored audit checkpoints. None is represented as implemented here.
