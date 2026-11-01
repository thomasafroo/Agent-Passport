# Independent Rust verifier

`verifier-rs/` is a second, independently written implementation of `scripts/verify_evidence.py`. It shares no code with the Python engine. Its purpose is to show that the evidence format can be checked without trusting this repository's Python, and to catch places where the Python verifier's behavior depends on Python itself rather than on the format.

It is a library crate (`agent_passport_verifier`) plus a command-line binary, `verify-evidence`. The library does no I/O and builds for `wasm32-unknown-unknown`.

## Run it

```text
cd verifier-rs
cargo test
cargo run --release -- ../docs/live-runs/run5-evidence.json --public-key-file ../docs/live-runs/run5-9-issuer-public-key.txt --checkpoints ../docs/live-runs/run5-checkpoint.jsonl
```

The arguments, output and exit codes are those of the Python script: `EVIDENCE.json`, then `--public-key-file KEY.txt` or `--public-key=KEY` (keys are unpadded URL-safe base64 and can begin with `-`, so pass them with `=`), and optionally `--checkpoints WITNESS.jsonl`. A valid file prints the same JSON report (`valid`, `events`, `receipts`, `reconciliations`, `approvals`, `lifecycle`, `head`, `checkpoints`, `anchored_events`, `unanchored_events`, `limitation`) and exits 0. A failure prints `Verification failed: ...` on stderr and exits 1. A usage error exits 2.

Dependencies are `ed25519-dalek` 2.2.0 and `sha2` 0.10.9 from crates.io, pinned exactly in `Cargo.toml` and locked in `Cargo.lock`. Argument parsing is hand-written to avoid further dependencies.

## What it checks

The same checks as `verify_evidence.py`, in the same order, with the same failure messages:

1. The evidence's `public_key` equals the independently pinned key: `Issuer does not match pinned key`.
2. Each event's `previous` is the previous event's hash (zeros for the first), and its `hash` is the SHA-256 of the canonical event body without `seq` and `hash`: `Event chain is altered or reordered`.
3. The first root grant supplies the owner to compare with signed statements; legacy exports without an owner use null. Each approval has a valid signature, `type: approval`, an approved or denied decision, and the current run ID. Approved bodies are indexed by operation ID and their canonical SHA-256 digest.
4. Each operation receipt has a valid Ed25519 signature and no `type`, so another signed statement cannot pose as one. It belongs to the current run and owner. If it cites an approval, that operation's approved body must be present with the cited digest.
5. Each reconciliation has a valid signature, `type: reconciliation`, and the current run and owner. Each lifecycle receipt has a valid signature, `type: lifecycle`, and the root's non-null owner ID.
6. With a witness file, every non-blank line is parsed and the entries for this run are kept (`The witness file holds no checkpoint for this run` if none). Each must have a valid signature and `type` equal to `checkpoint` (`Invalid checkpoint signature`), belong to the run, have a non-negative integer `size` that is not a boolean (`Checkpoint size is invalid`), not cover more events than the export holds (`Evidence is missing events that a checkpoint covers`), and have a `head` equal to the hash at position `size` (`Event history differs from a checkpoint`).

Cross-tests also cover approved and denied requests, missing or substituted approval citations, deprovisioning and reactivation evidence, altered and missing owner fields, cross-type substitutions, and malformed approval, lifecycle, grant and event collections. Both CLIs report malformed structures as verification failures without a traceback. All committed live-run evidence remains compatible.

`tests/test_rust_verifier.py` generates evidence with the Python engine and runs both command-line verifiers on the same files: valid evidence with unicode event text, a reconciliation and two checkpoints, then a changed event, reordered events, a dropped suffix with and without a checkpoint, a fully recomputed chain with and without a checkpoint, altered receipts and reconciliations, receipts, reconciliations and checkpoints posing as one another, a wrong key, statements from another run, forged checkpoint sizes, awkward numbers and strings, and the committed live runs. It requires identical exit codes, reports and messages. It is skipped when `cargo` is not installed, except in CI. `cargo test` checks every `docs/live-runs` export against its committed key, runs 5 to 9 with their checkpoints.

## Reproducing Python's canonical bytes

Event hashes and signatures cover `canonical(value)`, which is `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` applied to what `json.loads` produced. Python never hashes the bytes it read: it parses them into Python objects and writes those back. Hashing the raw text, or keeping raw number text, would therefore disagree with Python whenever the export is not already in canonical form (for example `1.10`, `1E2`, `-0`, a pretty-printed or `ensure_ascii=False` export, or duplicate keys). The Rust verifier instead models the Python objects with its own JSON parser and serialiser (`src/pyjson.rs`) rather than `serde_json`, because `serde_json` cannot represent several things Python accepts:

- **Strings** are sequences of code points (`Vec<u32>`), not Rust `String`, because Python accepts lone surrogates such as `"\ud800"`. A high surrogate escape followed by a low one is joined into one code point, as Python's scanner does. Output escapes everything outside printable ASCII as lowercase `\uXXXX`, including DEL (0x7f), with surrogate pairs above U+FFFF; `/` is not escaped.
- **Keys** are sorted by code point, which is Python's `str` ordering. It differs from UTF-16 order for characters above U+FFFF. Duplicate keys keep the first position and the last value, like a Python dict.
- **Integers** have arbitrary precision. They are stored as digits and written back verbatim, with `-0` written as `0`. Literals over 4300 digits are rejected, as CPython 3.11+ rejects them by default.
- **Floats** (any number with a fraction or exponent) are parsed to the nearest double and written with Python's `float.__repr__` rules: the shortest digits that round-trip (Rust's `{:e}` formatting produces the same digits as CPython's dtoa), exponent form when the decimal exponent is below -4 or at least 16 (`1e+16`, `1e-05`, two-digit minimum exponent), otherwise positional with `.0` on integral values (`1000000000000000.0`, `100.0`). `NaN`, `Infinity` and `-Infinity` are accepted and written as Python writes them, and literals that overflow become `Infinity`.
- **Base64** follows `unb64`: unpadded URL-safe input is re-padded, and decoding follows CPython's non-strict `binascii.a2b_base64` loop, which skips characters outside the alphabet, also accepts `+` and `/`, stops after a completed padding sequence and accepts non-zero trailing bits. Non-ASCII input is rejected.

The verification logic (`src/verify.rs`) follows Python's semantics on unexpected types too, so the verdict matches on malformed input as well as well-formed: iterating an empty object or string yields nothing, `"type" in body` is a substring test when `body` is a string, `==` treats `1`, `1.0` and `true` as equal, key files are stripped with Python's `str.strip()` whitespace set, and witness files are split with `str.splitlines()` boundaries (which include U+2028 and U+0085).

## Known divergences

- **Messages for malformed input.** Check failures and modeled `KeyError`, `TypeError` and `AttributeError` failures match Python's messages. JSON syntax errors and invalid UTF-8 can have different wording. Both CLIs fail with exit code 1 for these malformed inputs.
- **Nesting depth.** Rust rejects containers nested more than 2000 deep. Python's limit depends on the interpreter and platform (CPython 3.13 on Windows parses 2000 levels and fails before 5000). Evidence nested between the two limits is accepted only by Python. Issuer-generated evidence is nested a few levels deep.
- **Ed25519 edge cases.** Python uses OpenSSL through `cryptography`; Rust uses `ed25519-dalek`'s default `verify`. Both reject non-canonical `s` and compare the recomputed `R` by its encoding (cofactorless). They could in principle differ on deliberately malformed public keys, such as non-canonical point encodings. The key is pinned by the verifier, not taken from the evidence, so this matters only if the pinned key itself was crafted that way.

## What it does not prove

The same limits as the Python verifier, and nothing more:

- Signatures attest issuer statements, not execution truth. A reconciliation attests an operator's decision, not the upstream effect.
- Approval receipts attest a local operator's decision, not its correctness; lifecycle receipts attest provisioning changes, not verified human identity. Owner matching does not authenticate the unsigned grants collection or prove lifecycle completeness.
- The key must be pinned independently. The evidence's own `public_key` is compared with the pinned key, never trusted.
- An unanchored event chain cannot prove completeness or prevent wholesale rewriting. Checkpoints anchor only the prefix they cover, only as far as the witness copy is independent of the issuer, and they never come from the evidence being checked. Events after the latest checkpoint are reported as unanchored.
- The issuer key holder can sign a checkpoint of any history, so a checkpoint shows what the issuer's log contained when it was witnessed, not that it was truthful.

Agreement between two implementations shows that the format is specified tightly enough to verify twice. It does not make either one correct about anything the format does not cover.

## WebAssembly

The library compiles for the browser target:

```text
rustup target add wasm32-unknown-unknown
cd verifier-rs
cargo build --target wasm32-unknown-unknown --lib
```

The CLI is behind the default `cli` feature and the library has no filesystem access; its entry points take bytes or text (`verify_bytes`, `verify_text`). The web console does not use it yet. To wire it in, a small `wasm-bindgen` wrapper crate (or a `cdylib` with an exported function taking the evidence, key and witness text and returning the report JSON or failure message) could be built with `wasm-pack`, and the console could then verify an export in the browser against a key the operator pastes in. The pinned key would still have to come from the operator, never from the page or the export, and the same limitations would apply.
