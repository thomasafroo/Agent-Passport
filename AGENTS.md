# Working on Agent Passport

This is a local security research project, not a marketing-only mockup. Preserve the distinction between scripted agents/synthetic service data and real authorization enforcement.

## Commands

- Install: `python -m pip install -r requirements.lock -e ".[dev]"`
- Run: `python -m agent_passport` (loopback port 8787)
- Test: `python -m pytest -q`
- Lint and type check: `python -m ruff check .` and `python -m pyright` (run from the activated `.venv` so pyright resolves its packages)
- Property tests at higher volume: set `HYPOTHESIS_PROFILE=fuzz` before `python -m pytest -q tests/test_properties.py`
- Fuzz verifier and token/proof parsing: `python scripts/fuzz.py all --examples 20000`; see `docs/security-testing.md`
- Measure: `python scripts/benchmark.py`
- Reproduce incident: `python scripts/run_scenario.py`
- Verify evidence offline: `python scripts/verify_evidence.py EVIDENCE.json --public-key-file KEY.txt [--checkpoints WITNESS.jsonl]`
- Independent Rust verifier (same verdicts; see `docs/rust-verifier.md`): `cargo test` and `cargo run --release -- EVIDENCE.json --public-key-file KEY.txt [--checkpoints WITNESS.jsonl]` in `verifier-rs/`
- Checkpoint the event chain: `python scripts/checkpoint.py [--run RUN_ID] [--witness PATH]`
- Reconcile unresolved operations: `python scripts/reconcile.py` lists them; add `OPERATION_ID --outcome completed|not_executed --reason "..."`, or `OPERATION_ID --lookup`
- Approve or deny high-risk operations: `python scripts/approve.py` lists them; add `OPERATION_ID --decision approve|deny --reason "..."`
- Manage accountable owners: `python scripts/owners.py list|add USER_NAME --display-name NAME|deactivate OWNER|reactivate OWNER`; the console also serves a SCIM-shaped subset at `/scim/v2/Users` (console session only)
- Revocation experiment (simulation): `python scripts/revocation_experiment.py`
- Record a live-model run (needs a running gateway and the `claude` CLI; costs API usage): `python scripts/record_live_run.py --name NAME [--require-mode synthetic|1password-cli]`
- Live 1Password check (opt-in, real lookup): `python scripts/check_1password.py`; see `docs/1password.md`
- Generate an issuer key for `PASSPORT_ISSUER_KEY_REFERENCE` (prints it once, writes nothing): `python scripts/generate_issuer_key.py`

Use the repository's `.venv` when available. No frontend build is required. Reload the browser after changes to `web/`.

## Invariants

- Every descendant uses its root's shared budget row. Never copy remaining budget into a child.
- Resource/action pairs must attenuate as pairs; do not create a Cartesian product of independent allowlists.
- Verify the full ancestor chain at reservation and dispatch. Never replace online revocation with signature checks alone.
- Deprovisioning an owner is an online check at reservation and dispatch, never a rewrite of descendant rows, and it is irreversible for existing grants: reactivation permits only new issuance. Owner management stays on operator surfaces (console session, local scripts), never on the agent API or behind a bearer token.
- Agents cannot set cost, choose secret references or upstream URLs, refund operations, or settle outcomes.
- Unknown effects and crash-stranded operations retain capacity. A timeout is not evidence of a safe refund.
- Only an operator reconciles unresolved operations, once, with a recorded basis and a signed receipt. Never settle by elapsed time, and never expose reconciliation on the agent API.
- An effect lookup may return a unit only after the upstream has fenced the operation ID. "Not found" without a fence is not evidence that nothing happened.
- Only the operator approves approval-required operations, once, with a reason and a signed receipt, through the console session or the local script. Never on the agent API, by a bearer passport, or by elapsed time. An approval is single-use, bound to the exact operation and chain, and short-lived; dispatch still rechecks the chain. A waiting operation's unit returns only in the transaction that makes its dispatch impossible.
- Retries with the same grant/key must not execute again. Keys are bound to an exact operation digest.
- A key-bound passport needs a fresh, single-use holder proof on every agent request. Delegation cannot drop or redirect the binding. Holder private keys stay in process memory and never reach disk, logs, or tool output.
- `.state/`, credentials, bearer tokens, and private keys must stay out of Git and user-facing output.
- Keep live 1Password verification separate from mocked CLI and SDK tests. Do not claim it ran unless it did.
- The 1Password backend, the per-operation reference map, and the issuer key reference are operator configuration read at startup. A malformed map or an unresolvable issuer key stops startup; never fall back to a file key. SDK failures map to fixed messages and must not chain the SDK exception.
- Receipts attest issuer statements. Unanchored event hashes do not prove completeness. A checkpoint anchors only the prefix it covers, only through a witness copy outside the database owner's reach, and never comes from the evidence it checks. Never append a checkpoint over a history that no longer matches the witness.
- The MCP adapter must never return a passport token, for the live agent or any worker, in a tool result. Live-agent tokens go to `.state/live-agent.token`, never to the browser.
- Do not describe a live-model session as recorded unless one was actually run with a model; scripted MCP clients are not models. Recorded sessions live in `docs/live-runs/` with their signed evidence.

Read `docs/architecture.md` and `docs/threat-model.md` before changing enforcement. Add regression tests for security behavior changes and report measured results without turning local timings into distributed guarantees.
