# Threat model

## The problem

A skill's behaviour is decided by more than the files in its folder. When a
skill says "download this", "install that" or "read the guide at this address",
part of its behaviour lives on someone else's server. Three things follow.

1. **A clean skill can deliver a hostile payload.** The skill file contains
   nothing malicious, only a pointer. Scanners that read the skill see nothing
   wrong.
2. **The payload can change after review.** The owner of the remote content can
   replace it at any time. The skill's files do not change, so file hashes and
   lockfiles that cover only the skill folder stay green.
3. **The chain can be long.** A fetched page can point at further pages.

OWASP lists this as AST05, Untrusted External Instructions, in the Agentic
Skills Top 10, and recommends recording a content hash for every external
document at review time and re-verifying it later. Cleat is a small,
dependency-free implementation of that advice.

## What Cleat does

- **Inventory.** Every file in the skill folder is hashed. Text files are
  searched for URLs, download commands, and package installs. Files that cannot
  be read (binary, very large, symbolic links) are listed as not inspected.
  Nothing is skipped silently.
- **Hidden references.** Cleat also looks inside HTML and Markdown comments,
  base64 blobs that decode to readable text, and invisible Unicode tag
  characters, and removes zero-width characters before searching so that a
  split-up URL is still found.
- **Safe fetch.** Each link is retrieved read-only (see below), fingerprinted,
  and checked for red flags. Hosts that the fetched page links onward to are
  recorded.
- **Package check.** npm and PyPI names are looked up on the public registry to
  record the newest version and to catch names that do not exist.
- **Lock and verify.** The fingerprints are saved. A later run reports what
  moved, graded by how the skill uses the thing that moved.

## What the fetcher guarantees

The URLs in a skill under review are chosen by a possible attacker, so the
fetcher is the most sensitive part of the tool.

- Only `http` and `https`, only `GET`, no cookies, no stored state.
- URLs carrying a username or password are refused.
- The destination address is checked at connect time, inside the DNS lookup
  used for the connection. Private, loopback, link-local, carrier-grade NAT,
  cloud metadata, multicast and reserved ranges are refused for IPv4 and IPv6,
  including IPv4 addresses embedded in IPv6. Because the check happens on the
  address actually used, a name that resolves to a public address for the
  check and a private one for the connection (DNS rebinding) is also refused.
- Redirects are followed by hand, at most five, and every hop goes through the
  same checks.
- Responses are capped at 1 MiB and 15 seconds. Compressed transfer is not
  requested, so there is nothing to inflate.
- Nothing fetched is executed, imported, rendered or written to disk by the
  fetcher. The lock command saves normalised text snapshots as `.txt` files,
  capped at 256 KiB each, for later diffing.
- HTML is reduced to text with linear-time code, not regular expressions, so a
  page crafted to make a parser slow cannot stall the scan.

## What the report guarantees

- Text copied from the skill or a remote page is cut to one line, stripped of
  control characters, capped in length, and labelled as untrusted.
- The skill's instructions tell the agent to treat those quotations as
  evidence and never to act on them.

## What Cleat does not do

- **It does not run the skill.** Behaviour that only appears at run time is
  outside its view. A sandbox that runs the skill and watches it is a different
  and complementary tool.
- **It cannot defeat cloaking.** A server can answer a scanner with one thing
  and an agent with another, based on address, timing or headers. A clean
  result means nothing was found from where Cleat stood.
- **It is not a full malware scanner.** The red-flag rules catch well-known
  shapes. A carefully worded instruction in plain English can pass them.
- **It does not follow chains.** Onward links in fetched pages are recorded by
  host but not fetched in this version.
- **It does not use proxies.** It connects directly. On a network that requires
  a proxy, fetches fail and the report says so.
- **Pages that change on every visit will show as changed.** The diff sample
  in the verify result is there so a person can judge.

## State on disk

`<state-dir>/<skill-name>-<folder-id>.lock.json`, where the folder id is a short
hash of the skill folder's path relative to the project. A lock is tied to one
folder: two skills with the same name keep separate locks, and a lock read for
the wrong folder is refused.

```json
{
  "cleat": 1,
  "lockedAt": "2026-11-13T09:00:00.000Z",
  "skill": { "name": "example", "folder": ".claude/skills/example", "treeSha256": "...", "files": { "SKILL.md": "..." } },
  "references": [
    {
      "id": "url:https://example.org/install.sh",
      "kind": "url",
      "usage": "execute",
      "severity": "high",
      "immutable": false,
      "fetch": {
        "ok": true, "status": 200, "finalUrl": "https://example.org/install.sh",
        "sha256": "...", "normSha256": "...", "flags": [], "onwardHosts": []
      }
    },
    {
      "id": "npm:some-tool",
      "kind": "package",
      "pinned": false,
      "registry": { "found": true, "latest": "1.4.2", "integrity": "sha512-..." }
    }
  ]
}
```

`<state-dir>/snapshots/<skill-name>-<folder-id>/<id-hash>.txt` holds the normalised text
behind each link on lock day. These files contain third-party content. Commit
them only if you want line-level diffs to be reproducible by others.
