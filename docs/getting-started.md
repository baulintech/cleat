# Getting started with Cleat

This guide shows you how to check an AI agent skill before you install it, and
how to notice if it changes afterwards. You don't need to be a security
specialist. If you use Claude Code, Codex, Cursor or another coding agent that
reads `SKILL.md` files, you can follow it.

Cleat is a free, open-source agent skill scanner. It never runs the skill it is
checking. It reads the skill's files, lists everything the skill reaches for
outside itself, and looks at what those links serve today.

## What you need

- **Node.js 18 or newer.** Check by running `node --version` in a terminal. If
  you see a number from 18 up, you're ready. If not, install Node from
  [nodejs.org](https://nodejs.org).
- **A coding agent** such as Claude Code, Codex or Cursor. Cleat works without
  one too (see [Without an agent](#without-an-agent)).

Nothing else: no account, no API key, no packages.

## 1. Install Cleat

```bash
npx skills add https://github.com/baulintech/cleat --skill cleat
```

The installer asks which agents to add Cleat to. Pick the one you use.

## 2. Check a skill before you install it

Get a copy of the skill **without installing it**. The safest way is to copy
its files into a scratch folder:

```bash
git clone --depth 1 https://github.com/someone/some-skills ./downloads/some-skills
```

This only copies files. Don't run any setup or install step the skill's own
instructions suggest yet.

Then ask your agent, in plain English:

> Use Cleat to check the skill in ./downloads/some-skills/the-skill before I install it.

The agent runs Cleat, reads the result and explains it to you.

## 3. Read the verdict

Every report starts with one of three verdicts.

| Verdict | What it means | What to do |
|---|---|---|
| **High risk** | Something could give another person control of your computer or your secrets, such as a script that is downloaded and run straight away. | Don't install it until you, or someone you trust, has read the items Cleat lists. |
| **Review needed** | Something is unusual, but there may be an innocent reason. | Read the listed items. Many are normal for skills that talk to an online service. |
| **No red flags found** | Cleat found nothing it recognises as risky. | This is not a guarantee of safety. Cleat can't see what a skill does when it runs. |

Each item in the report says where it is (file and line), what it is, and why
it matters. Items marked **hidden** were found in places you wouldn't see
when reading the file normally: HTML comments, base64 text or invisible
Unicode characters.

For every flag and severity level, see
[Reading a Cleat report](../skills/cleat/references/reading-the-report.md).

## 4. Lock the skill once you decide to use it

> Lock the external references of the skill in .claude/skills/the-skill.

Cleat saves a fingerprint of the skill's files and of everything its links
served at that moment. The lockfile goes in a `.cleat` folder. If you work in a
project with version control, commit it.

A lock records what you reviewed. It doesn't approve the skill.

## 5. Check for changes later

> Have any of my installed skills drifted since I locked them?

Cleat compares the skill with its lock and reports anything new or changed:
a link that now serves different content, a new link, or edited files.
If it says **drift detected**, read the changes before you keep using the skill.

Run this check whenever a skill updates, and every so often in between. The
content behind a link can change even when the skill's own files haven't.

### Check automatically in CI

`verify` exits with code 1 when something important has changed, so it can
stop a build:

```yaml
- run: node .claude/skills/cleat/scripts/cleat.mjs verify .claude/skills/the-skill
```

Change both paths to wherever your agent keeps its skills.

## Without an agent

Cleat is a single Node.js script. Run it directly from the folder where the
installer put Cleat:

```bash
node path/to/cleat/scripts/cleat.mjs scan   path/to/skill
node path/to/cleat/scripts/cleat.mjs lock   path/to/skill
node path/to/cleat/scripts/cleat.mjs verify path/to/skill
```

Add `--offline` to check the files without fetching any links, and `--json`
for machine-readable output. Run with `--help` for every option.

## Try it on the test skill

The repository includes a deliberately malicious-looking test skill with fake
hosts. Scanning it shows what a high-risk report looks like:

```bash
git clone --depth 1 https://github.com/baulintech/cleat
cd cleat
node skills/cleat/scripts/cleat.mjs scan test/fixtures/remote-loader-skill --offline
```

## Common questions

**Cleat says its own folder is high risk.** That's expected. Its rule file
contains the patterns it searches for, so they match. The source is short and
has no dependencies if you want to read it.

**"No SKILL.md ... this does not look like a skill".** Point Cleat at the folder that
contains the skill's `SKILL.md` file, not at the repository that holds it.

**"Not locked: ... over the safety limit".** The skill links to more places than
Cleat fetches in one run (500 by default). That's unusual. Raise the limit with
`--max-fetch`, or use `--allow-partial` if you accept that some links won't be
checked.

**Does Cleat send my skills anywhere?** No. The only network requests are to
the links the skill itself contains, made read-only through a fetcher that
refuses private and local addresses.

**Is a clean result safe?** Not necessarily. A server can show Cleat one thing
and your agent another, and Cleat can't see behaviour that only appears when a
skill runs. Use it alongside your own review, not instead of it.

## Learn more

- [README](../README.md): how Cleat works and how it stays safe
- [Threat model](../skills/cleat/references/threat-model.md)
- [The study behind Cleat](https://doi.org/10.5281/zenodo.24209170): 355
  popular agent skills, and how often they reach for unpinned outside content
- [OWASP AST05: Untrusted External Instructions](https://owasp.github.io/www-project-agentic-skills-top-10/ast05.html)
