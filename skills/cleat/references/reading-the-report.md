# Reading a Cleat report

## Severity

| Level | Meaning |
|---|---|
| critical | Remote content is run as code and there is a second strong warning sign. Treat as hostile until proven otherwise. |
| high | Could give someone else control of the machine or its secrets. Needs a person to review before use. |
| medium | Unusual or risky, with innocent explanations. Worth a look. |
| low | Normal for many skills, listed so nothing is hidden. |
| info | Recorded for completeness. |

The verdict is `high-risk` when anything is high or critical, `review` when the
worst item is medium, and `no-red-flags` otherwise.

## How a link is used (`usage`)

| Value | Meaning |
|---|---|
| execute | The skill downloads this and runs it as code in one step. |
| download | The skill fetches this with a command, or sends data to it. |
| instruction | The skill tells the agent to go and read or follow this. |
| mention | A plain link with no instruction attached. |

A link takes the most serious usage found anywhere in the skill.

## Where a reference was hidden (`hidden`)

| Value | Meaning |
|---|---|
| html-comment | Inside an HTML or Markdown comment. Invisible when the file is rendered, visible to an agent. |
| base64 | Inside a base64 blob that decodes to readable text. |
| unicode-tags | Spelled out in invisible Unicode tag characters. |

A hidden reference is never rated below medium.

## Flags on links

| Flag | Plain meaning |
|---|---|
| paste-site | Hosted on a paste or snippet site. Anyone can post there and replace it later. |
| url-shortener | The real destination is hidden and can be changed. |
| tunnel-or-collector | A temporary tunnel or request-catching service, often used to receive stolen data. |
| chat-webhook | A chat webhook that can receive data. |
| raw-ip | A bare IP address instead of a named site. |
| lookalike-domain | Non-Latin characters that can imitate a trusted name. |
| credentials-in-url | A username or password in the link, sometimes used to disguise the host. |
| plain-http | Not encrypted, so content can be altered in transit. |
| unusual-port | Not a normal web port. |
| executable-or-archive | Points at a script, installer or archive. |
| mutable-git-ref | Follows a branch, tag or "latest", so the file can change under the same link. |
| receives-data | The skill sends data to this address. Normal for an API. |
| receives-secrets | The skill sends stored keys, passwords or environment variables to this address. |
| local-address | A local or private address, usually a development server. Not fetched. |
| refused-target | Cleat would not fetch it because it resolves to a private or local address. |
| unreachable | Could not be retrieved, so its content is unknown. |
| redirects-elsewhere | Ends up on a different site from the one written in the skill. |
| redirects-www | Only adds or removes "www." on the same site, over HTTPS at both ends. Shown for information; it does not raise the rating. |
| downgrade | Redirects from an encrypted link to an unencrypted one. |
| binary-download | Binary content. Fingerprinted but not readable. |
| truncated | Larger than the size cap. Only the first part was inspected. |

## Flags on packages

| Flag | Plain meaning |
|---|---|
| unpinned | No exact version, so a future release changes what gets installed or run. |
| git-source | Installed from a git repository instead of a registry. |
| package-not-found | No such package on the public registry. Whoever registers the name controls it. |

### What skill installer commands do

For a skill installer such as `npx skills`, the package entry also lists what
each command does, because the package name alone does not tell you which
skill ends up on your machine:

- **INSTALLS A SKILL: owner/repo, skill name**: the command names what it will
  install. Check that repository before approving.
- **INSTALLS A SKILL: target chosen later**: the command holds a placeholder
  such as `<owner/repo@skill>`, so the agent fills in the target at run time.
  Nobody reviewed that target in advance.
- **for all projects (-g)** and **without asking for confirmation (-y)**: the
  install reaches beyond the current project and skips the prompt where you
  would normally approve it.
- **SEARCH only**: looks skills up; installs nothing.
- **[EXAMPLE in the docs ...]**: the command sits under a lead-in such as "For
  example:" or "Example response:". It shows what a user might see, not a step
  the agent is told to take. Cleat recognises this from the wording around the
  command, so treat the label as a hint.

## Flags on text (skill files and remote content)

| Flag | Plain meaning |
|---|---|
| pipe-to-shell | Downloads something and runs it immediately. |
| download-into-shell | Runs the output of a download as shell code. |
| powershell-download-run | The PowerShell version of the same thing. |
| decode-and-run | Decodes hidden content and executes it. |
| reverse-shell | Opens a remote control channel. |
| security-bypass | Switches off a built-in protection. |
| instruction-override | Text that tries to replace the agent's instructions. |
| concealment | Tells the agent to hide something from the person. |
| credential-access | Touches where keys, passwords or tokens are stored. |
| env-harvest | Collects environment variables. |
| data-upload | Sends local data to a server. |
| possible-exfiltration | Reads secrets and sends data out in the same file. |
| persistence | Sets something up to keep running afterwards. |
| agent-config-tampering | Changes the agent's standing instructions or settings. |
| protected-archive | Uses a password-protected archive, which blocks inspection. |
| wallet-or-seed | Mentions cryptocurrency wallet secrets. |
| custom-package-index | Installs from a non-default registry. |
| encoded-content | A base64 blob that decodes to readable text. |
| hidden-unicode-text | Invisible characters that spell out text. |
| invisible-characters | Zero-width or direction-control characters. |
| dynamic-url | A link whose host is built at run time and cannot be listed in advance. |
| symlink | A symbolic link, which can pull in files from outside the skill. |
| not-inspected | A binary or very large file. Fingerprinted but not read. |
| long-lines | Very long lines that were only partly inspected. |

In a skill's own visible text, `instruction-override` and `concealment` are
rated one or two levels lower than in remote or hidden content. Skills that
warn about attacks often quote these phrases. In remote content they keep full
weight.

## Changes reported by `verify`

| Type | Meaning |
|---|---|
| remote-changed | The content behind a link differs from the locked fingerprint. `detail.newFlags` lists red flags that are new. `detail.diff` gives added and removed line counts and a sample of added lines. |
| remote-appeared | A link that failed on lock day now serves content. That content has never been reviewed. |
| remote-unreachable | A link that worked on lock day now fails. |
| redirect-changed | The link now lands somewhere else. |
| new-reference | The skill now points at something it did not point at before. |
| reference-removed | A locked reference is no longer in the skill. |
| skill-files-changed | The skill's own files were edited, added or removed. |
| package-updated | An unpinned package has a newer version than on lock day. |
| package-disappeared | A package that existed is gone from the registry. |
| package-appeared | A package name that did not exist has now been registered. |
| package-content-changed | Same version number, different contents. |

A changed link is rated by how the skill uses it: high for execute and
download, medium for instruction, low for mention. New red flags raise it, and
a change behind a commit-pinned link is always at least high, because that
content should be fixed.
