# A real upstream: GitHub issues

Every other operation in this project reaches a synthetic fixture service. With `PASSPORT_GITHUB_REPO` set, one operation, `patch.propose` on `repo/checkout`, files a real issue in a GitHub repository instead. Its token comes from 1Password through the operation's own reference.

The point is not the issue. The fixture upstream was built to be ideal: it takes the operation ID as an idempotency key and can fence an ID so that a late delivery is refused. GitHub can do neither, which is true of most real APIs. This adapter shows what the gateway's rules do against an upstream that doesn't cooperate.

## What changes, and what does not

- **Agents see nothing new.** The catalog, scopes, requests and holder proofs are the same. An agent names only the pair. The repository, the fixed API origin (`https://api.github.com`), the issue's title and body, and the token reference are all operator configuration or executor code.
- **Content is fixed.** The issue text is a constant proposal, plus a visible line and a hidden marker naming the operation ID. No agent-supplied text reaches GitHub.
- **The token stays in the executor.** It is resolved only after dispatch has rechecked the ancestor chain, sent only as an `Authorization` header to the configured origin, and never appears in results, events, receipts or the console. Redirects are never followed, so the token cannot be forwarded to another host.
- **Budget, retries and revocation are unchanged.** A retry with the same key returns the recorded operation and files no second issue.

## Outcome rules

GitHub has no idempotency key for issue creation, so the executor sends each operation once and classifies what it learns:

| What happened | Outcome | Unit |
|---|---|---|
| `201 Created` with a readable issue | `completed` | spent |
| `3xx` or `4xx` (bad token, no access, validation, rate limit, redirect) | `failed` | returned |
| DNS failure, refused connection, failed certificate check | `failed` | returned |
| `5xx`, timeout, reset, unreadable `201` | `unknown` | **retained** |

Only failures that show GitHub never acted are refunded. A `5xx` or a timeout after sending is not such evidence: GitHub may have created the issue before the answer was lost.

## Effect lookup without a fence

`python scripts/reconcile.py OPERATION_ID --lookup` (or the console's lookup) asks GitHub for the operation. It reads the token's own account with `GET /user`, then lists the repository's issues created by that account (up to 1,000), looking for the operation's marker.

```text
issue found      reconciled completed; the receipt's basis carries the issue's digest
no issue found   LOOKUP_INCONCLUSIVE; nothing changes; decide by hand
lookup fails     LOOKUP_FAILED; nothing changes
```

The fixture would fence the ID before a "not found" became a refund. GitHub cannot, so "not found" is not evidence that nothing happened. The request could still be in transit and apply later, after its unit was returned and spent again. That is the invariant AGENTS.md states, and here it costs availability: the unit stays reserved until an operator checks the repository and records `--outcome not_executed` with a reason.

GitHub's issue list is eventually consistent, and the first live run showed why that matters. An issue created about a second earlier, carrying the right marker, was missing from the list, so the lookup was inconclusive and the unit stayed reserved (see [Verification status](#verification-status)). Had absence been treated as evidence, the gateway would have refunded a unit whose issue exists. An inconclusive lookup changes nothing, so asking again later is safe; the live check repeats it a few times.

The creator check runs on GitHub and again in the adapter, so a marker pasted into another account's issue is never taken as this executor's effect. Anyone who controls the token's own account could still file a matching issue by hand. The receipt attests what GitHub reported, not independent proof.

## Setup

1. **A throwaway repository.** Create an empty public or private repository you are happy to fill with test issues, for example `YOUR_NAME/agent-passport-sandbox`.
2. **A fine-grained personal access token** (GitHub → Settings → Developer settings → Fine-grained tokens), scoped to **only that repository**, with **Issues: Read and write** and nothing else. Metadata read-only is added automatically. Give it a short expiry. Save it straight into the test vault as a new item, for example a password item titled `GitHub issues`; never paste it into a terminal, file, or chat.
3. **A reference map** covering the whole catalog, kept outside the repository. The GitHub pair takes a bare reference, because GitHub authenticates that token itself and no fixture digest applies. The other three pairs keep their fixture items and digests, as in [the 1Password guide](1password.md#map-each-operation-to-its-own-reference):

```json
{
  "staging/checkout logs.read":    {"reference": "op://Agent Passport Demo/Log reader/password",   "sha256": "<digest>"},
  "repo/checkout code.read":       {"reference": "op://Agent Passport Demo/Code reader/password",  "sha256": "<digest>"},
  "repo/checkout patch.propose":   "op://Agent Passport Demo/GitHub issues/password",
  "staging/checkout config.write": {"reference": "op://Agent Passport Demo/Config writer/password", "sha256": "<digest>"}
}
```

4. **Configure and run the live check** in the shell that holds the 1Password authentication. To exercise the SDK, use a read-only service account limited to the test vault (see [the 1Password guide](1password.md#a-read-only-service-account-limited-to-one-test-vault)):

```powershell
$env:PASSPORT_OP_PROVIDER = 'sdk'            # or 'cli'
# OP_SERVICE_ACCOUNT_TOKEN set through your secret-management workflow, never typed here
$env:PASSPORT_OP_REFERENCES = 'C:\path\outside\the\repo\references.json'
$env:PASSPORT_GITHUB_REPO = 'YOUR_NAME/agent-passport-sandbox'
python scripts/check_github.py
```

The check files **two real issues** and prints only the provider, upstream, outcomes, issue URL and budget:

```text
1 completed:    an ordinary dispatch files an issue; the unit is spent
2 lost answer:  the issue is filed but the check discards GitHub's answer and records unknown;
                the lookup finds it by marker and settles it as completed (it may be
                inconclusive first while GitHub's list catches up; each miss changes nothing)
3 lost request: the check records unknown without sending anything; the lookup returns
                LOOKUP_INCONCLUSIVE and that operation keeps its unit; the operator then decides
Budget: spent 2, reserved 0 of 3
```

It exits non-zero unless all three behave that way. Evidence goes to `artifacts/github-check-evidence.json` with its public key beside it:

```powershell
python scripts/verify_evidence.py artifacts/github-check-evidence.json --public-key-file artifacts/github-check-public-key.txt
```

With the same variables, `python -m agent_passport` runs the console story against GitHub, and the header reads, for example, **1Password SDK, GitHub issues in YOUR_NAME/agent-passport-sandbox**. The patch worker's step files a real issue.

Configuration fails closed. A malformed repository name stops startup, and so does `PASSPORT_GITHUB_REPO` without `PASSPORT_OP_REFERENCES`, so the fixture key and the GitHub token can never share a reference.

## Verification status

**Automated tests run against a local GitHub-shaped HTTP server; live runs are recorded below.** `tests/test_github_upstream.py` runs the real request code against that server: success and marker, retry without a second issue, every refusal class, redirect not followed, `5xx` and timeout retained, refused connection refunded, lookup after a lost answer, inconclusive lookup on absence, a copied marker from another account ignored, failed lookup, configuration errors, list lag after a lost answer, and the live-check script end to end with offline evidence verification. The token is scanned for in every surface.

**First live attempt, 2026-11-02 (Windows 11, `1password-sdk` with a read-only service account, `thomasafroo/Agent-Passport-Sandbox`):** the 1Password SDK resolved the GitHub token through the service account, and the completed case filed [issue #1](https://github.com/thomasafroo/Agent-Passport-Sandbox/issues/1) with a valid receipt. The lost-answer case filed [issue #2](https://github.com/thomasafroo/Agent-Passport-Sandbox/issues/2) with the correct marker, but its single immediate lookup was `LOOKUP_INCONCLUSIVE`: the issue was not yet in GitHub's list. Listed again shortly afterwards with the same creator filter, it was there. The unit stayed reserved and nothing was refunded, so the rule held, but the check failed its own expectation (spent 1, reserved 1 of 3). The check now repeats an inconclusive lookup a few times and checks each operation's own state.

**Live run, 2026-11-02 (same configuration): passed.** The completed case filed [issue #3](https://github.com/thomasafroo/Agent-Passport-Sandbox/issues/3) with a valid receipt. The lost-answer case filed [issue #4](https://github.com/thomasafroo/Agent-Passport-Sandbox/issues/4); its first lookup was again `LOOKUP_INCONCLUSIVE` with the unit kept, and the next one found the marker and reconciled it as completed. The lost-request case was `LOOKUP_INCONCLUSIVE` with its unit kept, then reconciled `not_executed` by the operator. Final budget: spent 2, reserved 0 of 3. Both the Python and the Rust verifier accept the exported evidence (9 events, 3 operation receipts, 2 reconciliations), and it contains no token:

```powershell
python scripts/verify_evidence.py docs/github-runs/run1-evidence.json --public-key-file docs/github-runs/run1-issuer-public-key.txt
```

Each issue's hidden marker names the operation ID in the evidence: #3 `op_20d4fc5b…` (completed), #4 `op_24d72b51…` (reconciled completed). The lost-request operation `op_3705a331…` has no issue. The first attempt's issues #1 and #2 remain in the repository; its evidence was not kept.

This is a scripted check, not a model session. The lost answer and lost request are produced by the check settling an operation as `unknown` itself, not by real network faults.

## What this does not show

- Exactly-once delivery to GitHub. The gateway dispatches once and never retries an uncertain request, but it cannot make GitHub idempotent.
- That an issue in the repository came from this gateway. The marker identifies the operation, and the creator check limits it to the token's account; it is not a signature.
- Anything about the token's own authority. A compromised executor holds the token and can do whatever its fine-grained permissions allow, which is why it is limited to one throwaway repository and to issues.
