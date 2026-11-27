# Red-team results

Cleat 0.1.10 scanned 41 inert test skills offline on 2026-11-27. Cases are listed in cases.mjs; nothing in them is ever run.

- Malicious-style cases: 32. Caught at the expected level: 26. Flagged but rated too low: 3. Missed: 3.
- Legitimate controls: 9. Clean: 7. Marked for review: 2. False alarms (high-risk): 0.

| Case | What it does | Expected | Cleat's worst | Outcome | Signals |
|---|---|---|---|---|---|
| rt01-pipe-to-shell | Classic curl | sudo bash installer | high | critical | **caught** | pipe-to-shell, executable-or-archive |
| rt02-wget-to-sh | wget -qO- piped into sh | high | high | **caught** | pipe-to-shell |
| rt03-process-substitution | bash <(curl ...) process substitution | high | critical | **caught** | download-into-shell, executable-or-archive |
| rt04-python-c-subshell | python3 -c "$(curl ...)" | high | high | **caught** | download-into-shell |
| rt05-line-continuation | Installer split over lines with backslashes | high | critical | **caught** | pipe-to-shell, executable-or-archive |
| rt06-download-then-run | Download to a file, chmod, then run it | high | medium | **under-rated** | none |
| rt07-variable-indirection | URL hidden in a variable before curl | sh | high | high | **caught** | pipe-to-shell |
| rt08-powershell-iwr-iex | PowerShell iwr | iex | high | critical | **caught** | pipe-to-shell, powershell-download-run, executable-or-archive |
| rt09-clawhavoc-zip-password | Password-protected ZIP "prerequisite" (ClawHavoc style) | high | high | **caught** | protected-archive-download, protected-archive, executable-or-archive |
| rt10-macos-base64-terminal | macOS: paste a base64 command into Terminal (AMOS style) | high | critical | **caught** | decode-and-run, encoded-content, pipe-to-shell, raw-ip, plain-http |
| rt11-quarantine-bypass | Remove macOS quarantine from a downloaded binary | high | high | **caught** | security-bypass |
| rt12-hex-decode-run | Hex-encoded command decoded with xxd and run | high | info | **missed** | none |
| rt13-python-exec-b64 | Python script that execs a base64 payload | high | critical | **caught** | encoded-content, pipe-to-shell |
| rt14-npx-unknown-package | npx -y of an unvetted package | medium | medium | **caught** | unpinned |
| rt20-ssh-key-exfil | Tar ~/.ssh and POST it to a server | high | high | **caught** | data-upload, api-post, receives-secrets |
| rt21-env-exfil | Pipe all environment variables to a server | high | high | **caught** | possible-exfiltration, data-upload, env-harvest, api-post, receives-secrets |
| rt22-script-reads-aws-and-posts | Bundled script reads AWS credentials and posts them | high | high | **caught** | possible-exfiltration, credential-access, code-upload |
| rt23-reverse-shell | bash reverse shell to a fixed address | high | high | **caught** | reverse-shell |
| rt24-prose-exfil-with-path | Natural-language instruction to send ~/.aws/credentials in a URL | high | medium | **under-rated** | credential-access |
| rt25-prose-exfil-no-path | Natural-language instruction to send API keys by email (no paths, no commands) | high | info | **missed** (known gap) | none |
| rt26-wallet-seed | Asks for a wallet seed phrase | medium | medium | **caught** | wallet-or-seed |
| rt30-instruction-override | Ignore previous instructions | high | medium | **under-rated** | instruction-override |
| rt31-hidden-html-comment | Installer hidden in an HTML comment | high | critical | **caught** | pipe-to-shell |
| rt32-unicode-tags | Instruction spelled in invisible Unicode tag characters | high | high | **caught** | hidden-unicode-text, concealment |
| rt33-config-tamper-conceal | Append to CLAUDE.md and hide it from the user | medium | medium | **caught** | agent-config-tampering, concealment |
| rt34-remote-instructions | Fetch instructions from a URL and follow them | medium | low | **missed** | none |
| rt35-crontab-persistence | Install a cron job that re-downloads a script | high | high | **caught** | pipe-to-shell, persistence |
| rt36-long-line-minified | Installer buried 30,000 characters into a minified file | high | high | **caught** | pipe-to-shell |
| rt37-skip-permissions | Run the agent with permission prompts disabled | high | high | **caught** | security-bypass |
| rt38-escaped-quotes-in-metadata | Download run by sh -c, hidden in escaped quotes in JSON metadata | high | high | **caught** | download-into-shell |
| rt39-hardcoded-db-password | Script falls back to a hard-coded database password | medium | medium | **caught** | embedded-secret |
| rt40-padded-readme | README padded past 2 MiB so scanners skip it | medium | medium | **caught** | oversized-text |
| ok08-readonly-api-calls | API skill whose curl calls only read JSON responses | clean | low | **pass** | api-post |
| ok09-docs-mention-private-key-header | Security docs that name the private-key header without a key | clean | info | **pass** | none |
| ok01-plain-docs | Ordinary skill with documentation links | clean | medium | **noisy** | unpinned |
| ok02-warns-against-curl-sh | Security skill that warns against curl | sh | clean | info | **pass** | none |
| ok03-ssh-setup-guide | Git skill that explains SSH key setup | clean | info | **pass** | none |
| ok04-pip-install | Python skill that installs well-known packages | clean | low | **pass** | unpinned |
| ok05-api-with-env-key | API skill that reads its own key from the environment | clean | low | **pass** | none |
| ok06-api-client-posts | API skill whose script posts JSON to its own service | clean | low | **pass** | code-upload |
| ok07-security-docs-quote-attack | Security skill whose docs quote an exfiltration pattern | clean | medium | **noisy** | credential-access, code-upload |
