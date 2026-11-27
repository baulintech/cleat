# Red-team QA suite

Inert test skills that copy techniques used by real malicious agent skills,
plus legitimate skills as controls. Cleat scans them all on every test run.

- **Inert by design.** Every host ends in `.invalid` (reserved, never
  resolves) or uses `203.0.113.x` (reserved for documentation). The cases are
  written to a temporary folder, scanned offline, and deleted. Nothing in them
  is ever run.
- **Based on published reports.** Each case names its source in `basis`
  (Koi Security's ClawHavoc report, Snyk's ToxicSkills study, Palo Alto Unit
  42, Tencent AIG), or "Common shell-installer abuse" for long-known patterns.
- **Honest about misses.** Cases Cleat does not catch yet stay in the suite.
  `RESULTS.md` shows every outcome, and `IMPROVEMENTS.md` lists what to fix.

## Files

| File | What it is |
|---|---|
| `cases.mjs` | The cases: what each one does, its source, and what a good scanner should report |
| `run.mjs` | Scans every case and prints or writes the results |
| `baseline.json` | Each case's outcome for the current release |
| `RESULTS.md` | The latest results table |
| `results/<version>.md` | The results table for each release, kept for before and after comparisons |
| `history.csv` | One line per recorded run: date, version, counts and what changed |
| `IMPROVEMENTS.md` | Gaps found, and proposed fixes, in priority order |

## Outcomes

| Outcome | Meaning |
|---|---|
| caught | Reached the severity a good scanner should give it |
| under-rated | Flagged for review, but rated lower than it deserves |
| missed | Nothing at medium or above |
| pass | Legitimate control, no warning at medium or above |
| noisy | Legitimate control marked for review (medium) |
| false-alarm | Legitimate control called high-risk |

## Running it

```bash
node qa/redteam/run.mjs                        # table in the terminal
node qa/redteam/run.mjs --record "what changed"  # keep this run in results/ and history.csv
npm test                                       # includes test/redteam.test.mjs
```

`test/redteam.test.mjs` fails if any case does worse than `baseline.json`, or
if a legitimate control is called high-risk. When a fix improves a case,
update `baseline.json` and record the run with `--record` in the same commit.

## Limits

These are copies of techniques, not the original malware, and they are scanned
offline, so remote content is not checked. A separate run against real
published samples is planned.
