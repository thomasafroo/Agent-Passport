# Threat model

## What the attacker controls

An agent may be compromised by untrusted tool output. It can send any request, leak or share its passport token, retry, fork, create narrower descendants, and race other workers. It can choose an arbitrary operation key and request forbidden resource/action pairs. It cannot modify the gateway code, SQLite database, issuer key, server configuration, or executor.

A live model connected through the MCP adapter is treated the same way: untrusted, able to request anything, and holding no token. The adapter is trusted local code that keeps the passports and forwards calls; it adds no policy.

The browser is the local human operator console. It can issue the scripted root and revoke branches. It is not an untrusted agent sandbox. Anyone who can access the loopback service locally has operator access. The session header prevents ordinary cross-origin browser mutation; it is not human authentication.

## Claims and evidence

| Claim | Evidence |
|---|---|
| Forks cannot duplicate a root budget | 64-worker thread test; independent-process reservation test; 100-agent benchmark; stateful property test of random delegate/reserve/settle/revoke/reconcile sequences against one shared row (`tests/test_properties.py`) |
| Child scopes cannot expand | Exact-pair and wildcard rejection tests; property tests over random and malformed scope requests, including the no-Cartesian-product check |
| Expiry cannot expand or be forgotten on restart | Child expiry and persisted expiry tests |
| Revocation cuts descendants, not siblings | Chain revocation and sibling completion tests |
| Queued jobs are not grandfathered in | Dequeue revocation and expiry tests |
| Retries cannot double-spend a key | 50 concurrent retries; durable crash reservation test; stateful property test counting upstream calls per key |
| Unknown effects cannot trigger free retries | Unknown-outcome capacity retention test; stateful property test of unit retention for unknown and unsettled operations |
| Agent requests do not obtain the provider credential | Snapshot/receipt redaction tests and fixed fixture response surface |
| Modified passports and receipts are rejected | Signature and foreign-issuer tests; property tests of arbitrary and mutated tokens, issuer-signed foreign claims, and single-field evidence mutations |
| A live model's tool results never contain passport tokens | MCP adapter output scan across every tool, including delegated workers |
| Reset withdraws a live agent | Reset revokes the live branch, deletes its token file, and the adapter drops worker passports |
| A stolen key-bound token authorizes nothing without its holder key | Missing, forged, replayed, stale, non-finite, and request-mismatched proof tests; stolen live token file test over HTTP; property tests of arbitrary, mutated and holder-signed malformed proofs |
| Delegation cannot drop or redirect holder binding | Bearer-child and swapped-child-key tests |
| No holder private key reaches disk | State-directory scan for the adapter's private key bytes |
| Unresolved operations are settled only by an operator decision | Time-advance retention test; agent-API and bearer-token rejection of reconcile routes |
| A reconciliation applies once and is never re-executed | Concurrent-decision, retry-after-decision, late dispatch and late settlement tests |
| Reconciliations are signed and verifiable offline | Reconciliation receipt tamper and evidence verifier tests |
| An upstream effect lookup settles an unresolved operation only from the upstream's record | Lost-response, lost-request, crash-after-effect and mismatched-record tests |
| A refunded operation can never apply upstream later | Fence test: a late delivery of a reconciled ID is refused before any effect |
| Failed or premature lookups change nothing | Unsupported, credential-failure, rejected-credential and in-flight tests check the unit is retained and no fence is written |
| A witnessed checkpoint detects a removed suffix or a recomputed chain | Suffix-drop and full-rechain tests that pass without a checkpoint and fail with one |
| A witness file is never extended over a rolled-back or rewritten history | Deleted-event and replaced-issuer tests that leave the witness file unchanged |
| Checkpoints, reconciliations, approvals, lifecycle and operation receipts cannot stand in for each other | Cross-type substitution tests |
| Hostile agent input is refused, never a server error | Property tests of the agent HTTP API and of token and proof parsing; `scripts/fuzz.py` for longer runs |
| The verifier rejects every change to hashed or signed content | Single-field mutation property over events, receipts, reconciliations and checkpoints; unsigned fields it does not check are listed in `docs/security-testing.md` |
| 1Password SDK failures never reveal SDK exception text, the token, or the secret | Mocked SDK failures (auth, missing item, rate limit, timeout, empty and non-text values) carrying a fake secret and token; scans of the exception, result, events, receipts, `/api/evidence`, `/health`, and logs; no chained exception |
| The SDK path works from a thread that already runs an event loop | Provider and executor called inside `asyncio.run`; the lookup runs on the provider's own loop |
| Agents cannot choose the backend or a secret reference | Extra `provider`/`reference`/`credential_mode` fields rejected with 422; selection read only from operator environment |
| Each operation resolves only its own mapped reference | Recording backend sees exactly the dispatched pair's reference; a denied pair resolves nothing; one pair's key fails another pair's verifier |
| A malformed reference map stops startup | Missing, unknown, mixed, duplicated, non-`op://`, multi-line, and unreadable map tests; server startup test |
| An issuer key from 1Password fails closed and never reaches disk | Unresolvable and wrong-length/encoding keys stop startup without creating a key file; state-directory scan for the raw and encoded key after signing |
| An approval-required operation never dispatches without an operator approval | Pending-reserve test: no dispatch, no service call, retries stay pending |
| Only the operator approves; agents, bearer passports and timers cannot | Bearer, passport-as-console-header and missing-session rejection of approval routes; no agent-API route; lapse tests show time only withdraws |
| An approval runs its operation at most once, and only that operation | Approve-then-retry, concurrent retry, concurrent approve/deny and copied-approval tests |
| Revocation after approval still stops dispatch | Revoke-after-approval tests through the agent retry and through direct dispatch |
| Denied, lapsed and revoked waiting operations return their unit exactly once, and never run | Deny, approval-lapse, request-lapse and revocation tests with service-call counts and pool totals |
| Approval retries still need the holder key | Missing and forged proof on the post-approval retry |
| Approvals are signed and verifiable offline | Approval tamper, foreign-run and dropped-approval verifier tests |
| A model sees an approval wait without any token | MCP output scan across pending, retried, approved and denied operations |
| Deprovisioning an owner voids every grant issued for them, in every run, and only theirs | Root and depth-4 descendant denial across two runs; another owner's run completes |
| Deprovisioning is online and linearized with reservation | Concurrent deactivate-versus-reserve test: no reservation event follows the deactivation event |
| Deprovisioning refunds only work that never dispatched | Queued reservation cancelled once with a refund; dispatched and unknown operations keep their units |
| Reactivating an owner does not revive old grants | Same-clock reactivation test; new issuance works; a second cut voids it again |
| Owner lifecycle changes are signed and verifiable offline | Lifecycle receipt tamper, foreign-owner and cross-type substitution tests |
| Owner provisioning is not reachable by agents or bearer tokens | SCIM routes refuse agent passports, any `Authorization` header, and a missing console session |
| Pre-owner databases and tokens keep working | Migration test with dropped owner tables and columns |

## Explicit non-claims

- This is not a sandbox for arbitrary code. A local agent with access to `.state` or the operator environment can bypass these boundaries. An MCP client that also has file or shell access, such as a coding agent in this repository, can read the live token file or reach the loopback console API.
- Unbound passports are bearer credentials and can be stolen or shared. Holder binding moves the secret from the token to a private key; it does not protect a key held by a compromised holder. A process that can read the adapter's memory, as the same operating-system user can, can take its key.
- Holder keys are registered through the operator's `.state` directory. A local process that can write there before issuance can substitute its own key, and anything that can reach the loopback console API has operator access. Binding defeats a copied token file, not a compromised operator environment.
- A shared pool provides a ceiling, not fairness. A worker can consume all remaining allowed operations.
- Signed tokens alone do not revoke anything. Revocation depends on online durable state checks.
- Already dispatched operations can finish after revocation. Effects cannot be undone.
- Revocation and deprovisioning are ordered, not prompt. SQLite does not queue writers fairly, so under sustained agent reservations an operator's revoke or deprovision can wait for the write lock. It waits at most the 30-second busy timeout and then fails rather than being applied; no reservation is ever ordered after it commits. A CI run observed eight tight reservation loops hold it off until the shared pool was empty.
- No distributed-cache, network-partition, or clock-skew bound has been established. The server wall clock is trusted.
- No automatic recovery of crash-stranded reservations is implemented. Capacity stays held until an operator reconciles it, by stating the outcome or by asking the fixture upstream's effect record. A reconciliation receipt records the operator's statement or the upstream's report; it is not independent evidence of the effect, and a wrong decision misstates the budget by one unit. Lookup soundness rests on the fixture's atomic effect recording and fencing, which a real upstream would have to provide.
- An approval records that a named local operator approved one exact operation; it does not authenticate that person, and anyone with loopback console access can approve. The operator sees the operation's agent, resource and action, not its downstream consequences, and an approval is only as good as that judgement. The approval-required list is a fixed local policy, not a risk engine.
- The fixture service has no production side effects. There is no claim of exactly-once execution against an arbitrary external API.
- No LLM attack-resistance or universal prompt-injection prevention claim is made. The fixture explicitly issues malicious requests to test the gateway, and a live model's choice to follow or ignore the planted log line is not measured or relied on.
- There is no data-flow tracking or quarantine of downstream outputs from a compromised worker.
- Hash-linked events without a witnessed checkpoint are not a tamper-proof audit ledger. With one, only the prefix it covers is anchored, and only as well as the witness copy is kept out of the database owner's reach. The issuer key holder can sign a checkpoint of any history it likes.
- An owner is an operator-entered record, not a verified identity. There is no identity-provider integration, no SCIM bearer authentication, and no conformant SCIM server: the `/scim/v2/Users` routes are a SCIM-shaped subset behind the local console session. Whoever has operator access can provision, deprovision or reactivate any owner.
- Deprovisioning cannot recall work that already crossed the dispatch boundary, and it does not revoke the provider credential or anything the owner holds outside this gateway. Legacy grants issued before owners existed have no owner and are unaffected by it.
- A lifecycle receipt's list of affected runs is the issuer's statement at commit time, not an independently checked completeness claim.
- There is no public hosting, user login, per-tenant isolation, rate limiter, retention policy, or production denial-of-service protection.
- The private key is stored locally in a file. POSIX mode is restricted at creation; on Windows, protection relies on inherited user-directory ACLs. This is not HSM-backed key storage.
- Loading the issuer key from 1Password (`PASSPORT_ISSUER_KEY_REFERENCE`) removes the file copy, not the key: it stays in the gateway's process memory, and anything that can read that memory or holds a token able to read the item can sign as the issuer.
- The per-operation reference map limits what each operation fetches, not what the executor process could fetch. A compromised executor still holds the service account token (or the CLI session) and can read every item that token can read. Only the token's vault permissions bound that.
- The 1Password SDK path is covered by mocked tests only and has not been run against a live account. The service account token sits in the gateway's process memory and environment for the life of the process.

## Deployment boundary

Run on loopback with synthetic data. Do not expose the local control plane on a network. A hosted version needs explicit user authentication, tenant-scoped admin rights, runtime isolation for agents, managed key storage, rate/size limits, durable retention and audit anchoring, and an adapter-specific outcome reconciliation design.
