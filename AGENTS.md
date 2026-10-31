# Working on Agent Passport

This is a local security research project, not a marketing-only mockup. Preserve the distinction between scripted agents/synthetic service data and real authorization enforcement.

## Commands

- Install: `python -m pip install -r requirements.lock -e ".[dev]"`
- Run: `python -m agent_passport` (loopback port 8787)
- Test: `python -m pytest -q`
- Measure: `python scripts/benchmark.py`
- Reproduce incident: `python scripts/run_scenario.py`

Use the repository's `.venv` when available. No frontend build is required. Reload the browser after changes to `web/`.

## Invariants

- Every descendant uses its root's shared budget row. Never copy remaining budget into a child.
- Resource/action pairs must attenuate as pairs; do not create a Cartesian product of independent allowlists.
- Verify the full ancestor chain at reservation and dispatch. Never replace online revocation with signature checks alone.
- Agents cannot set cost, choose secret references or upstream URLs, refund operations, or settle outcomes.
- Unknown effects and crash-stranded operations retain capacity. A timeout is not evidence of a safe refund.
- Retries with the same grant/key must not execute again. Keys are bound to an exact operation digest.
- `.state/`, credentials, bearer tokens, and private keys must stay out of Git and user-facing output.
- Keep live 1Password verification separate from mocked CLI tests. Do not claim it ran unless it did.
- Receipts attest issuer statements. Unanchored event hashes do not prove completeness.
- The MCP adapter must never return a passport token, for the live agent or any worker, in a tool result. Live-agent tokens go to `.state/live-agent.token`, never to the browser.
- Do not describe a live-model session as recorded unless one was actually run with a model; scripted MCP clients are not models. Recorded sessions live in `docs/live-runs/` with their signed evidence.

Read `docs/architecture.md` and `docs/threat-model.md` before changing enforcement. Add regression tests for security behavior changes and report measured results without turning local timings into distributed guarantees.
