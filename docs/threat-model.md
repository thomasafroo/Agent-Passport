# Threat model

## What the attacker controls

An agent may be compromised by untrusted tool output. It can send any request, share its bearer token, retry, fork, create narrower descendants, and race other workers. It can choose an arbitrary operation key and request forbidden resource/action pairs. It cannot modify the gateway code, SQLite database, issuer key, server configuration, or executor.

The browser is the local human operator console. It can issue the scripted root and revoke branches. It is not an untrusted agent sandbox. Anyone who can access the loopback service locally has operator access. The session header prevents ordinary cross-origin browser mutation; it is not human authentication.

## Claims and evidence

| Claim | Evidence |
|---|---|
| Forks cannot duplicate a root budget | 64-worker thread test; independent-process reservation test; 100-agent benchmark |
| Child scopes cannot expand | Exact-pair and wildcard rejection tests |
| Expiry cannot expand or be forgotten on restart | Child expiry and persisted expiry tests |
| Revocation cuts descendants, not siblings | Chain revocation and sibling completion tests |
| Queued jobs are not grandfathered in | Dequeue revocation and expiry tests |
| Retries cannot double-spend a key | 50 concurrent retries; durable crash reservation test |
| Unknown effects cannot trigger free retries | Unknown-outcome capacity retention test |
| Agent requests do not obtain the provider credential | Snapshot/receipt redaction tests and fixed fixture response surface |
| Modified passports and receipts are rejected | Signature and foreign-issuer tests |

## Explicit non-claims

- This is not a sandbox for arbitrary code. A local agent with access to `.state` or the operator environment can bypass these boundaries.
- Bearer passports can be stolen or shared. Signatures authenticate issuer statements, not the runtime presenting them.
- A shared pool provides a ceiling, not fairness. A worker can consume all remaining allowed operations.
- Signed tokens alone do not revoke anything. Revocation depends on online durable state checks.
- Already dispatched operations can finish after revocation. Effects cannot be undone.
- No distributed-cache, network-partition, or clock-skew bound has been established. The server wall clock is trusted.
- No automatic recovery of crash-stranded reservations is implemented. Capacity stays held rather than risking duplicated effects.
- The fixture service has no production side effects. There is no claim of exactly-once execution against an arbitrary external API.
- No LLM attack-resistance or universal prompt-injection prevention claim is made. The fixture explicitly issues malicious requests to test the gateway.
- There is no data-flow tracking or quarantine of downstream outputs from a compromised worker.
- Hash-linked events without a trusted checkpoint are not a tamper-proof audit ledger.
- There is no public hosting, user login, per-tenant isolation, rate limiter, retention policy, or production denial-of-service protection.
- The private key is stored locally in a file. POSIX mode is restricted at creation; on Windows, protection relies on inherited user-directory ACLs. This is not HSM-backed key storage.

## Deployment boundary

Run on loopback with synthetic data. Do not expose the local control plane on a network. A hosted version needs explicit user authentication, tenant-scoped admin rights, runtime isolation for agents, managed key storage, rate/size limits, durable retention and audit anchoring, and an adapter-specific outcome reconciliation design.
