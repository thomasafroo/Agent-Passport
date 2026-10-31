# Security testing

The example-based tests pin specific attacks. The property tests in `tests/test_properties.py` state the enforcement invariants from `AGENTS.md` over generated inputs and check them against the real engine, SQLite database and HTTP app. Static analysis and a dependency audit run in CI.

## Properties checked

| Property | What is generated | What must hold |
|---|---|---|
| Pair attenuation | Parent and child scope requests from the catalog, wildcard and near-miss strings, over-long and empty strings, non-string fields, missing and extra keys, non-list values | A child is granted exactly the requested pairs, always a subset of its parent's pairs; invalid shapes are `SCOPE_INVALID`, anything else outside the parent is `SCOPE_ESCALATION` |
| No Cartesian product | Random subsets of the catalog | For every resource x action combination of a grant, reservation succeeds only for a granted pair |
| Exact reservation scope | A granted subset and arbitrary resource/action values | Allowed iff the pair is granted; unbounded or non-string input is `REQUEST_INVALID` |
| Shared budget (stateful) | Random sequences of delegate, reserve, executor calls (completed, timeout, rejected), dispatch, settle (completed, failed, unknown), revoke, approve/deny, approval listing, deprovision/reactivate, clock advance and reconcile across one tree | Every result matches an independent model with the default approval policy enabled; one root pool exists; `spent + reserved <= budget`; `reserved` counts unresolved and waiting/approved operations; retries reserve nothing; no operation dispatches, and no key reaches the upstream, twice; old grants stay void after reactivation |
| Token parsing | Arbitrary text, bytes, non-strings, base64 pairs, oversized strings, and character-level edits of a valid token | Every mutated token is refused with `IDENTITY_INVALID`, including alternate spellings of the same bytes |
| Issuer-signed foreign claims | Arbitrary JSON signed with the real issuer key | Refused unless the bytes equal the stored grant's claims |
| Holder proofs | Arbitrary strings, edits of a fresh proof, and arbitrary bodies signed with the real holder key | Mutated proofs are `PROOF_INVALID` and do not consume the nonce; malformed signed bodies are invalid or stale; a canonical proof authorizes only its own operation and time window |
| Agent HTTP API | Random `Authorization` and proof headers and JSON bodies on the three agent endpoints | A 401, 403, 413 or 422; never a server error and never success without a valid proof |
| Evidence verifier | One change or deletion at any leaf of real evidence with delegated, completed, failed, unknown, reconciled and pending operations; checkpoint field changes; list edits; arbitrary documents | Rejected exactly where the content is hashed or signed (below); list edits behave as documented; malformed documents raise only errors the CLI reports as a failed verification |

### What the verifier covers

A change to any of these is rejected: every event field except `seq` (the hash chain), every signed operation, reconciliation, approval or lifecycle body and signature, every checkpoint field, the issuer key, and the run id (bound by receipt bodies). Root-owner selection is cross-checked against signed operation, reconciliation and lifecycle statements. An operation receipt's approval citation must resolve to the approved body for that operation.

These are not authenticated: event `seq`, the `run` counters (`budget`, `spent`, `reserved`, `created`), grant state, revocation flags and scopes, `policy`, `server_time`, and extra top-level keys. The grants collection is unsigned; owner/parent edits fail only when they change the selected root owner and contradict signed statements. Dropping or duplicating an operation receipt or reconciliation verifies with or without a checkpoint, because checkpoints anchor events, not receipt completeness. Dropping a cited approval fails. Dropping an event suffix verifies unless a checkpoint covers it. Tests assert these limits.

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
- `pip-audit` against the exact pins in `requirements.lock`, on every push and weekly. It fails the job and runs separately so tests still report. The integration pins `cryptography` 50.0.2 and removes the PYSEC-2026-3552 ignore; the workflow's exact audit command reported no known vulnerabilities locally on 2026-10-31.

## Findings

- **Fixed: non-canonical token and proof spelling.** Authentication re-encodes both decoded parts and compares them with the input. Extra padding, unused trailing bits, alternate alphabets and ignored characters are refused with `IDENTITY_INVALID` or `PROOF_INVALID`; an invalid proof does not consume its nonce. The former strict xfail now passes, and mutation properties require every changed token or proof to fail. General `unb64` receipt/evidence parsing remains compatible; the Rust verifier parses evidence, not agent tokens or holder proofs.
- **Fixed: the verifier CLI crashed on malformed documents.** Evidence that was not a JSON object, or that held non-object events, raised `AttributeError`, which the CLI did not catch. It printed a traceback instead of "Verification failed". It still exited non-zero and accepted nothing. The CLI now catches `MALFORMED`, and a regression test covers it.
- **Robustness note, not agent-reachable.** A token signed by the real issuer whose `id` claim is a list, an object or an integer outside 64 bits makes SQLite raise `ProgrammingError` or `OverflowError` instead of `Denied`. Producing such a token needs the issuer's private key.

## Limits

A passing property means no counterexample turned up in the examples tried. It does not prove the property. The stateful model restates the documented rules, so a rule that is wrong in both the code and the model goes unnoticed. The properties run in one process against one SQLite file. Concurrency and multi-process races are covered by the thread and process tests, not here. Holder-bound grants appear in the parsing properties, not in the budget state machine. Fuzzing is limited by its generators and, without atheris, gets no coverage feedback.
