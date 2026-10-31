# Exercise the real 1Password credential path

The default uses a clearly labeled synthetic key. The optional provider resolves a fixed `op://` reference using the installed 1Password CLI. The executor uses the resolved credential to authenticate to the in-process synthetic staging service. No secret is returned to the browser or an agent.

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

Run the check and the server in the same shell that holds these variables. If `op` is not recognized right after installation, the shell predates the PATH change: open a new terminal, or reload PATH in the current one:

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

What this demonstrates: real retrieval from a 1Password account by the executor, with no credential reaching agents, the browser, or receipts. What it does not: the fixture digest was derived from the same vault item, so the check proves an end-to-end retrieval round trip, not an independent upstream service. A service-account configuration has not been exercised. Re-run `python scripts/check_1password.py` in your own environment before relying on it.

Official references: [`op read`](https://developer.1password.com/docs/cli/reference/commands/read/) and [service accounts with the CLI](https://developer.1password.com/docs/service-accounts/use-with-1password-cli/). The provider uses `op read <reference> --no-newline`, with captured stdout and a 20-second timeout.
