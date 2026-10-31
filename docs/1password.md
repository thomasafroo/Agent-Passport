# Exercise the real 1Password credential path

The default uses a clearly labeled synthetic key. The optional provider resolves an operator-configured `op://` reference using the installed 1Password CLI or, optionally, the official 1Password Python SDK with a service account (see [Choose a backend](#choose-a-backend-cli-or-sdk)). Operations can each have their own reference, and the issuer signing key can also come from 1Password. The executor uses the resolved credential to authenticate to the in-process synthetic staging service. No secret is returned to the browser or an agent.

This is a real credential lookup paired with a fixture service, not a production integration or an official 1Password product.

## Setup

This is the path used for the recorded live run on Windows.

1. Install the [1Password desktop app](https://1password.com/downloads/) and the [official 1Password CLI](https://developer.1password.com/docs/cli/get-started/) (`winget install AgileBits.1Password.CLI`).
2. In the app, turn on Windows Hello (Settings > Security) and **Integrate with 1Password CLI** (Settings > Developer). Run `op signin` and approve the prompt; `op whoami` alone does not trigger sign-in.
3. Create a dedicated test vault and let 1Password generate a synthetic key, so it is never typed or displayed. Do not use a production credential.

```powershell
op vault create "Agent Passport Demo"
op item create --category=password --title="Staging fixture" --vault="Agent Passport Demo" --generate-password="32,letters,digits"
```

4. Configure the reference and the SHA-256 hex digest of that key. The digest is the fixture service's verifier; it is not a 1Password access token. This computes it without printing the key (PowerShell 7):

```powershell
$env:PASSPORT_OP_REFERENCE = 'op://Agent Passport Demo/Staging fixture/password'
$bytes = [Text.Encoding]::UTF8.GetBytes((op read $env:PASSPORT_OP_REFERENCE --no-newline))
$env:PASSPORT_FIXTURE_KEY_SHA256 = -join ([Security.Cryptography.SHA256]::HashData($bytes) | ForEach-Object { $_.ToString('x2') })
Remove-Variable bytes
python -m agent_passport
```

Run the check and the server in the same shell that holds these variables. With desktop app integration, 1Password authorizes each terminal session separately, so sign in from that same terminal; another shell, or a coding agent's shell, does not inherit the authorization. If `op` is not recognized right after installation, the shell predates the PATH change: open a new terminal, or reload PATH in the current one:

```powershell
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
```

Because this digest comes from the same vault item, the fixture check proves the retrieval round trip, not an independent upstream service. To model an independent verifier, store a key you generated elsewhere and compute its digest from that original copy.

If using a service account instead of desktop authentication, set `OP_SERVICE_ACCOUNT_TOKEN` in the executor environment through your secret-management workflow. Do not paste it into chat, commit it, put it in agent instructions, or include it in shell arguments. The app does not store this token. 1Password documents that Connect environment variables take precedence over a service-account token; choose one authentication configuration deliberately.

The console header badge should read **1Password CLI, fixture service**. Start the investigation. Successful log/code actions show that retrieval succeeded and the fixture accepted the key. A wrong key, unauthenticated CLI, unavailable CLI, or timeout produces a generic pre-effect failure and refunds the reservation. The console does not display CLI output.

For an isolated integration check without starting a server:

```powershell
python scripts/check_1password.py
```

This performs one real credential lookup and one authorized fixture operation. It prints only provider mode, outcome, and receipt verification status. It exits unsuccessfully on a failed lookup or mismatch.

## Current verification status

The command invocation, missing-CLI handling, failed-command handling, timeout redaction, and fixture authentication are covered by automated tests with a mocked subprocess.

**Live run, 2026-10-30 (Windows 11, 1Password CLI 2.41.1, desktop app integration):** the console ran in `1password-cli` mode against a dedicated test vault holding a generated, synthetic key. The log reader, code investigator, and patch worker operations each completed, which requires `op read` to return the key and the fixture service to accept its SHA-256 digest. Gateway state recorded `credential_mode: 1password-cli` and three `EXECUTED` operations.

What this demonstrates: real retrieval from a 1Password account by the executor, with no credential reaching agents, the browser, or receipts. What it does not: the fixture digest was derived from the same vault item, so the check proves an end-to-end retrieval round trip, not an independent upstream service. A service-account configuration was exercised separately on 2026-10-31; see below.

**Service account, 2026-10-31:** `python scripts/check_1password.py` was run with `OP_SERVICE_ACCOUNT_TOKEN` set in the operator's shell, and `op whoami` reported the service-account user type. The check reported provider `1password-cli`, outcome `completed`, and a valid receipt: one real lookup through a service account and one authorized fixture operation. The console story and live-model runs have not been run under a service account. The token was not shared with this project's files, logs, or chat.

**Live model run, 2026-10-31:** a Claude Sonnet 5.5 session drove the MCP adapter while the gateway ran in `1password-cli` mode. Its three operations completed, each resolving the credential through `op read` from the test vault. The model never saw the credential. See [run 4](live-runs/README.md#run-4-1password-credential-mode-holder-bound-passport). Re-run `python scripts/check_1password.py` in your own environment before relying on it.

## Choose a backend: CLI or SDK

The operator picks how references are resolved with `PASSPORT_OP_PROVIDER`. Agents cannot choose or see it; the agent API rejects any extra request field.

```text
PASSPORT_OP_PROVIDER=cli   default; `op read` as above (desktop app integration or a service account)
PASSPORT_OP_PROVIDER=sdk   the official 1Password Python SDK, authenticated with OP_SERVICE_ACCOUNT_TOKEN
```

Any other value stops startup. `/health`, `/api/evidence`, and `check_1password.py` report the mode as `1password-cli` or `1password-sdk`.

**Verification status of the SDK path: mocked tests only; not yet run against a live account.** The CLI live runs above say nothing about it.

The SDK is an optional extra pinned to `onepassword-sdk==0.4.2` (also in the dev extra and `requirements.lock`; it installs from a prebuilt wheel on Windows x64, macOS, and Linux x64/arm64, and pulls in nothing beyond pydantic):

```powershell
python -m pip install -e ".[onepassword]"
```

Set `OP_SERVICE_ACCOUNT_TOKEN` in the operator's environment through your secret-management workflow, never in shell arguments, files in this repository, or agent instructions. The provider reads it once at startup and keeps it in process memory.

The provider calls `Client.authenticate(auth=<token>, integration_name="Agent Passport", integration_version="0.1.0")` once, then `client.secrets.resolve(<reference>)` for each lookup, with a 20-second timeout. Both SDK calls are coroutines while the executor is synchronous, and the executor may be called from a thread that already runs an event loop, where `asyncio.run` raises and `run_until_complete` is illegal. The provider therefore owns one private event loop on a daemon thread and submits each lookup to it with `run_coroutine_threadsafe`. That works the same from FastAPI's worker threads, from inside a running loop, and from the scripts, and lets one authenticated client be reused rather than authenticating on every operation. A failed lookup drops the client so the next one authenticates again.

Error discipline matches the CLI provider. A reference that does not start with `op://`, or contains a newline, carriage return, or NUL, is rejected before any lookup. Every SDK failure (authentication, missing item, rate limit, timeout, empty or non-text value) becomes a generic `CredentialUnavailable` with a fixed message, raised outside the exception handler so the SDK's exception is not even chained to it. No SDK exception text, token, or secret reaches agents, receipts, events, logs, or HTTP responses; the regression tests put a fake secret and token into the SDK's exception text and scan each of those surfaces. A missing token or a missing SDK package stops startup.

## Map each operation to its own reference

By default one reference (`PASSPORT_OP_REFERENCE`) serves every operation. Instead, `PASSPORT_OP_REFERENCES` can name a JSON file that maps each catalog resource/action pair to its own reference:

```json
{
  "staging/checkout logs.read":    {"reference": "op://Agent Passport Demo/Log reader/password",   "sha256": "<digest>"},
  "repo/checkout code.read":       {"reference": "op://Agent Passport Demo/Code reader/password",  "sha256": "<digest>"},
  "repo/checkout patch.propose":   {"reference": "op://Agent Passport Demo/Patch writer/password", "sha256": "<digest>"},
  "staging/checkout config.write": {"reference": "op://Agent Passport Demo/Config writer/password", "sha256": "<digest>"}
}
```

A value may also be a bare reference string, in which case that pair's fixture verifier falls back to `PASSPORT_FIXTURE_KEY_SHA256`. The `sha256` is the fixture service's verifier for that pair's key, computed as in Setup step 4; it is not a 1Password token.

Startup fails closed unless every catalog pair is mapped exactly once, no other pair appears (including mixed pairs such as `staging/checkout code.read`), every reference is a single-line `op://` reference, and every digest is lowercase SHA-256 hex. Setting both `PASSPORT_OP_REFERENCE` and `PASSPORT_OP_REFERENCES` is refused as ambiguous. Keep the file outside the repository; it holds references, not secrets, but it is operator configuration.

The executor resolves only the reference for the operation it is dispatching, after reservation and the ancestor-chain check. A denied request resolves nothing. Lookups during operator reconciliation use the reference of the operation being reconciled.

### A read-only service account limited to one test vault

1. Create a dedicated vault (as in Setup) and one generated item per operation:

```powershell
op vault create "Agent Passport Demo"
op item create --category=password --title="Log reader" --vault="Agent Passport Demo" --generate-password="32,letters,digits"
op item create --category=password --title="Code reader" --vault="Agent Passport Demo" --generate-password="32,letters,digits"
op item create --category=password --title="Patch writer" --vault="Agent Passport Demo" --generate-password="32,letters,digits"
```

2. Create a service account that can only read items in that vault. The token is shown once; save it straight into 1Password, not a file:

```powershell
op service-account create "Agent Passport executor" --vault "Agent Passport Demo:read_items" --expires-in 7d
```

Service accounts cannot be granted the built-in Personal, Private, or Employee vaults, and `read_items` is the default permission. Do not add `write_items` or `share_items`.

3. Write the mapping file with each item's digest, set `PASSPORT_OP_PROVIDER=sdk` (or keep `cli`), `OP_SERVICE_ACCOUNT_TOKEN`, and `PASSPORT_OP_REFERENCES`, then run `python scripts/check_1password.py` and `python -m agent_passport` from that shell.

What this buys, exactly: each operation fetches only its own credential, so a fault or confusion in one operation's path cannot pull another operation's key through the executor's normal flow, and the vault boundary keeps everything outside the test vault out of reach of the token. What it does not buy: a compromised executor process still holds the service account token, so the mapping limits what each operation fetches, not what the process could fetch. Such a process can read every item the service account can read, which is why the account is read-only and limited to one vault that holds nothing else.

## Load the issuer key from 1Password

By default the issuer's Ed25519 private key is created once in `.state/issuer.key`. Set `PASSPORT_ISSUER_KEY_REFERENCE` to an `op://` reference to load it through the configured backend (`PASSPORT_OP_PROVIDER`, same as operations) instead.

Format: the raw 32-byte Ed25519 private key, base64url-encoded without line breaks (43 characters; one trailing `=` is accepted). Generate one with:

```powershell
python scripts/generate_issuer_key.py
```

It prints the private value alone on stdout and `Issuer public key (pin this): ...` on stderr, and writes nothing to disk. Paste the value into the password field of a new item in the test vault in the 1Password app, then clear the terminal and its scrollback. Do not redirect stdout to a file in the repository or `artifacts/`. Keep the public key for `verify_evidence.py --public-key-file`.

When the reference is configured:

- Startup resolves it, or stops. There is no fallback to `.state/issuer.key` or to generating a new key.
- A value that is not exactly 32 bytes of base64url is rejected without echoing it.
- Nothing about the key is written to the state directory; tests scan it for the raw and encoded key.
- The server, `reconcile.py`, and `checkpoint.py` all load it the same way, so every receipt and checkpoint is signed by the same issuer. `/health` reports `issuer_key` as `file`, `1password-cli`, or `1password-sdk`.
- Passports and receipts issued under a previous key stop verifying against the new one. Switch keys on a fresh state directory.

The key still lives in the gateway's process memory for as long as it runs, as the file key does; Python cannot reliably erase it. Holding it in 1Password removes the copy on disk and puts access under 1Password's audit and revocation, not under process isolation. Anything that can read the gateway's memory, or that holds a token able to read the item, can sign as the issuer.

Mocked tests only; this path has not been run against a live account.

Official references: [`op read`](https://developer.1password.com/docs/cli/reference/commands/read/), [service accounts with the CLI](https://developer.1password.com/docs/service-accounts/use-with-1password-cli/), the [Python SDK](https://github.com/1password/onepassword-sdk-python), and [`op service-account create`](https://developer.1password.com/docs/cli/reference/management-commands/service-account/). The CLI provider uses `op read <reference> --no-newline`, with captured stdout and a 20-second timeout.
