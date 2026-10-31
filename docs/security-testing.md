# Security testing

The example-based tests pin specific attacks. The property tests in `tests/test_properties.py` state the enforcement invariants from `AGENTS.md` over generated inputs and check them against the real engine, SQLite database and HTTP app. Static analysis and a dependency audit run in CI.

## Properties checked

| Property | What is generated | What must hold |
|---|---|---|
| Pair attenuation | Parent and child scope requests from the catalog, wildcard and near-miss strings, over-long and empty strings, non-string fields, missing and extra keys, non-list values | A child is granted exactly the requested pairs, always a subset of its parent's pairs; invalid shapes are `SCOPE_INVALID`, anything else outside the parent is `SCOPE_ESCALATION` |
| No Cartesian product | Random subsets of the catalog | For every resource x action combination of a grant, reservation succeeds only for a granted pair |
| Exact reservation scope | A granted subset and arbitrary resource/action values | Allowed iff the pair is granted; unbounded or non-string input is `REQUEST_INVALID` |
| Shared budget (stateful) | Random sequences of delegate, reserve, executor calls (completed, timeout, rejected), dispatch, settle (completed, failed, unknown), revoke, clock advance and reconcile across one tree | Every engine result matches an independent model; one `runs` row exists and every grant points at it; `spent + reserved <= budget`; `reserved` equals the count of reserved, dispatched and unknown operations; a retried key returns the original operation and reserves nothing; no operation dispatches, and no key reaches the upstream, twice; nothing is reconciled while it may still be in flight |
| Token parsing | Arbitrary text, bytes, non-strings, base64 pairs, oversized strings, and character-level edits of a valid token | Only `Denied("IDENTITY_INVALID")` is raised; a mutated token authenticates only if it decodes to the same signed bytes (see findings) |
| Issuer-signed foreign claims | Arbitrary JSON signed with the real issuer key | Refused unless the bytes equal the stored grant's claims |
| Holder proofs | Arbitrary strings, edits of a fresh proof, and arbitrary bodies signed with the real holder key | Only `PROOF_INVALID` or `PROOF_STALE`; an accepted respelling consumes the same nonce, so the original then replays; a proof authorizes only its own operation and time window |
| Agent HTTP API | Random `Authorization` and proof headers and JSON bodies on the three agent endpoints | A 401, 403, 413 or 422; never a server error and never success without a valid proof |
| Evidence verifier | One change or deletion at any leaf of real evidence with delegated, completed, failed, unknown, reconciled and pending operations; checkpoint field changes; list edits; arbitrary documents | Rejected exactly where the content is hashed or signed (below); list edits behave as documented; malformed documents raise only errors the CLI reports as a failed verification |

### What the verifier covers

A change to any of these is rejected: every event field except `seq` (the hash chain), every field of an operation receipt or reconciliation body and its signature, every checkpoint field, the issuer key, and the run id (bound by receipt bodies).

These are not checked, and a change to them still verifies: event `seq`, the `run` counters (`budget`, `spent`, `reserved`, `created`), the whole `grants` list (including state, revocation flags and scopes), `policy`, `server_time`, and any extra top-level keys. Dropping or duplicating a receipt or reconciliation verifies with or without a checkpoint, because checkpoints anchor events, not receipts. Dropping an event suffix verifies unless a checkpoint covers it. The tests assert this behavior so that a change to it is deliberate.

## Running

```
python -m pytest -q                                   # includes the properties at the default profile
HYPOTHESIS_PROFILE=fuzz python -m pytest -q tests/test_properties.py   # 50x the examples
python scripts/fuzz.py all --examples 20000            # verifier, token and proof targets
python scripts/fuzz.py verify --seed 1 --examples 5000 # reproducible run
```

Profiles live in `tests/conftest.py`: `dev` (default), `ci` (no example database, prints a reproduction blob) and `fuzz`. `scripts/fuzz.py --atheris` hands one target to atheris/libFuzzer through Hypothesis's `fuzz_one_input`. atheris is not in the dev extra and has not been run here.

## Static analysis in CI

- `ruff check .`: pyflakes, syntax and import errors, and bugbear. The compact one-line style (E701, E702) is not enforced. Tests may pass loop-local lambdas to `assert_denied` (B023), because it calls them before the loop advances. Scripts may import after setting `sys.path` (E402).
- `pyright` in basic mode. The engine binds `result` in a `try` block and raises a recorded denial before returning it, which pyright cannot follow, so `reportPossiblyUnboundVariable` is a warning rather than an error.
- CodeQL with the `security-extended` Python queries, on every push and weekly.
- `pip-audit` against the exact pins in `requirements.lock`, on every push and weekly. It fails the job. With exact pins, an advisory is actionable: raise the pin, or record in `.github/workflows/audit.yml` why the code is unreachable. It runs as a separate job so the tests still report. PYSEC-2026-3552, the PKCS#7 decryption oracle in `cryptography` before 50, is ignored this way: only Ed25519 signing and raw key serialization are used. Raising the pin is still the fix.

## Findings

- **Non-canonical base64 is accepted.** `unb64` decodes leniently: unused trailing bits, extra `=` padding and the `+`/`/` alphabet. So several different strings authenticate as the same token, and a holder proof can be respelled the same way. No authority is gained: the signed bytes are identical, a proof's nonce still stops a replay, and a proof binds to the exact token string. But anything later keyed on the token string, such as a denylist or log correlation, could be bypassed. `test_only_the_canonical_token_spelling_authenticates` is a strict xfail that will pass once tokens are re-encoded and compared on parse.
- **Fixed: the verifier CLI crashed on malformed documents.** Evidence that was not a JSON object, or that held non-object events, raised `AttributeError`, which the CLI did not catch. It printed a traceback instead of "Verification failed". It still exited non-zero and accepted nothing. The CLI now catches `MALFORMED`, and a regression test covers it.
- **Robustness note, not agent-reachable.** A token signed by the real issuer whose `id` claim is a list, an object or an integer outside 64 bits makes SQLite raise `ProgrammingError` or `OverflowError` instead of `Denied`. Producing such a token needs the issuer's private key.

## Limits

A passing property means no counterexample turned up in the examples tried. It does not prove the property. The stateful model restates the documented rules, so a rule that is wrong in both the code and the model goes unnoticed. The properties run in one process against one SQLite file. Concurrency and multi-process races are covered by the thread and process tests, not here. Holder-bound grants appear in the parsing properties, not in the budget state machine. Fuzzing is limited by its generators and, without atheris, gets no coverage feedback.
