# Cleat in six screens

Real output from Cleat 0.1.4, captured on 24 November 2026. The only edits:
long sections are cut where marked, and file paths are shortened (`~/cleat`,
`~/my-project`). Every host ending in `.example` is fake, and the test skill in
screens 2 and 3 is a deliberate fake that ships with the repository.

Each section has a short caption and a line you can read over the screen in a
video.

## 1. Install

![Installing Cleat with npx skills add](01-install.png)

**What's happening:** Cleat installs like any other agent skill, with one
command. The `skills` installer copies it into the project's skills folder,
here for Claude Code.

**Narration:** "Cleat is a skill, so you install it the same way as any other.
One command, no account, no dependencies."

## 2. Scan: the verdict

![A Cleat scan of a fake malicious skill showing HIGH RISK](02-scan-verdict.png)

**What's happening:** Cleat scans a test skill without running it. The verdict
comes first: high risk. Below it, a count of everything the skill reaches for:
six outside links, one package, and two references hidden from a normal read.
The most dangerous link was hidden in base64, and another runs a script from a
paste site. *(Cut after the first two links.)*

**Narration:** "Point Cleat at a skill before you install it. It reads every
file, and tells you in one line whether a person needs to look first."

## 3. Scan: what a person can't see

![Cleat findings for base64, invisible Unicode and pipe-to-shell](03-scan-hidden.png)

**What's happening:** The part of the report that matters most. Cleat decoded
a base64 blob that hides a download-and-run command, found an instruction
written in invisible Unicode characters that an agent can read but a person
can't see, and flagged a command that pipes a downloaded script straight into
a shell. *(First three findings shown.)*

**Narration:** "This is what a normal read misses. A command hidden in base64.
An instruction in invisible characters. Cleat shows you both, in plain text."

## 4. Lock: record what you reviewed

![Cleat locking the doc-helper skill](04-lock.png)

**What's happening:** A clean skill, `doc-helper`, tells the agent to read
setup notes hosted online. After review, `lock` fetches those notes read-only
and saves a fingerprint of them and of the skill's own files.
*(The standard limits section is cut.)*

**Narration:** "Once you've reviewed a skill, lock it. Cleat fingerprints the
skill and everything it points to."

## 5. Verify: nothing has changed

![Cleat verify reporting UNCHANGED](05-verify-unchanged.png)

**What's happening:** Run straight after locking, `verify` fetches the notes
again and compares. Everything matches.

**Narration:** "Check again whenever you like. Unchanged means everything still
matches what you reviewed."

## 6. Verify: the content moved

![Cleat verify reporting DRIFT DETECTED with a new pipe-to-shell](06-verify-drift.png)

**What's happening:** The skill's own file has not changed, but the notes it
links to have. Someone added a line telling the agent to download and run an
installer. Cleat reports the drift, flags the new pipe-to-shell command, shows
the exact lines added, and exits with code 1, so a CI build stops.

For this screen the notes live on this repository's
[`demo-remote` branch](https://github.com/baulintech/cleat/tree/demo-remote),
and the change was a real commit made after locking. The installer host is
fake.

**Narration:** "This is the attack nobody sees. The skill didn't change. The
page it trusts did. Cleat catches it, shows you the new line, and fails the
build."

## Reproduce

The demo skill is in [`docs/demo/doc-helper`](../demo/doc-helper/SKILL.md).
Screens 2 and 3 use `test/fixtures/remote-loader-skill`.
