# Exercise the real 1Password credential path

The default uses a clearly labeled synthetic key. The optional provider resolves a fixed `op://` reference using the installed 1Password CLI. The executor uses the resolved credential to authenticate to the in-process synthetic staging service. No secret is returned to the browser or an agent.

This is a real credential lookup paired with a fixture service, not a production integration or an official 1Password product.

## Setup

1. Install the [official 1Password CLI](https://developer.1password.com/docs/cli/get-started/).
2. Create a dedicated test vault/item with a high-entropy synthetic API key. Do not use a production credential. Copy its secret reference.
3. Authenticate the CLI using the desktop integration, or a service account restricted to that test vault. The service-account token belongs only in the trusted executor environment.
4. Configure the reference and the SHA-256 hex digest of the fixture key. The digest is the fixture service's verifier; it is not a 1Password access token.

PowerShell:

```powershell
$env:PASSPORT_OP_REFERENCE = 'op://Agent Passport Demo/Staging fixture/api key'
# Input is hidden and never put in shell history. Use the SAME synthetic key stored in the item.
$fixtureKey = Read-Host 'Synthetic fixture key' -AsSecureString
$fixtureText = [System.Net.NetworkCredential]::new('', $fixtureKey).Password
$fixtureBytes = [System.Text.Encoding]::UTF8.GetBytes($fixtureText)
$fixtureSha = [System.Security.Cryptography.SHA256]::Create()
$env:PASSPORT_FIXTURE_KEY_SHA256 = ([BitConverter]::ToString($fixtureSha.ComputeHash($fixtureBytes))).Replace('-', '').ToLowerInvariant()
$fixtureSha.Dispose()
Remove-Variable fixtureKey, fixtureText, fixtureBytes
python -m agent_passport
```

If using a service account instead of desktop authentication, set `OP_SERVICE_ACCOUNT_TOKEN` in the executor environment through your secret-management workflow. Do not paste it into chat, commit it, put it in agent instructions, or include it in shell arguments. The app does not store this token. 1Password documents that Connect environment variables take precedence over a service-account token; choose one authentication configuration deliberately.

The console header should read **1PASSWORD CLI · FIXTURE SERVICE**. Start the investigation. Successful log/code actions show that retrieval succeeded and the fixture accepted the key. A wrong key, unauthenticated CLI, unavailable CLI, or timeout produces a generic pre-effect failure and refunds the reservation. The console does not display CLI output.

For an isolated integration check without starting a server:

```powershell
python scripts/check_1password.py
```

This performs one real credential lookup and one authorized fixture operation. It prints only provider mode, outcome, and receipt verification status. It exits unsuccessfully on a failed lookup or mismatch.

## Current verification status

The command invocation, missing-CLI handling, failed-command handling, timeout redaction, and fixture authentication are covered by automated tests. Live account access has not been verified in this repository's initial local build. Run the integration check in your configured environment before describing the project as a demonstrated live 1Password integration.

Official references: [`op read`](https://developer.1password.com/docs/cli/reference/commands/read/) and [service accounts with the CLI](https://developer.1password.com/docs/service-accounts/use-with-1password-cli/). The provider uses `op read <reference> --no-newline`, with captured stdout and a 20-second timeout.
