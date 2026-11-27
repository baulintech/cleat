#!/usr/bin/env node
// Runs Cleat over the red-team cases and reports what it caught.
//
//   node qa/redteam/run.mjs                    print a table
//   node qa/redteam/run.mjs --json             print the results as JSON
//   node qa/redteam/run.mjs --md FILE          also write a markdown report
//   node qa/redteam/run.mjs --record "note"    keep this run: results/<version>.md,
//                                              RESULTS.md and a line in history.csv
//
// Cases are written to a temporary folder, scanned offline and removed.
// Nothing in them is ever run.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { CASES } from './cases.mjs';
import { VERSION } from '../../skills/cleat/scripts/lib/util.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = process.env.CLEAT_CLI || join(here, '..', '..', 'skills', 'cleat', 'scripts', 'cleat.mjs');
const RANK = { none: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };

export function runCase(c, root) {
  const dir = join(root, c.id);
  for (const [rel, body] of Object.entries(c.files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  const r = spawnSync(process.execPath, [CLI, 'scan', dir, '--offline', '--json'], {
    encoding: 'utf8', env: { ...process.env, CLEAT_NO_BANNER: '1' },
  });
  if (r.status === 2 || !r.stdout) throw new Error(`${c.id}: cleat could not run\n${r.stderr}`);
  const j = JSON.parse(r.stdout);
  const worst = j.summary.maxSeverity || 'none';
  const ids = [...new Set([
    ...j.findings.map((f) => f.id),
    ...j.references.flatMap((ref) => (ref.flags || []).map((f) => f.id)),
    ...(j.packages || []).flatMap((p) => (p.flags || []).map((f) => f.id)),
  ])];
  let outcome;
  if (c.expect === 'clean') outcome = RANK[worst] >= RANK.high ? 'false-alarm' : RANK[worst] >= RANK.medium ? 'noisy' : 'pass';
  else if (RANK[worst] >= RANK[c.expect]) outcome = 'caught';
  else if (RANK[worst] >= RANK.medium) outcome = 'under-rated';
  else outcome = 'missed';
  return { id: c.id, title: c.title, technique: c.technique, basis: c.basis, expect: c.expect,
    knownGap: !!c.gap, verdict: j.summary.verdict, worst, outcome, signals: ids };
}

export function runAll() {
  const root = mkdtempSync(join(tmpdir(), 'cleat-redteam-'));
  try { return CASES.map((c) => runCase(c, root)); } finally { rmSync(root, { recursive: true, force: true }); }
}

function tally(results) {
  const bad = results.filter((r) => r.expect !== 'clean');
  const ok = results.filter((r) => r.expect === 'clean');
  const n = (arr, o) => arr.filter((r) => r.outcome === o).length;
  return { malicious: bad.length, caught: n(bad, 'caught'), underRated: n(bad, 'under-rated'), missed: n(bad, 'missed'),
    controls: ok.length, pass: n(ok, 'pass'), noisy: n(ok, 'noisy'), falseAlarms: n(ok, 'false-alarm') };
}

function markdown(results, t) {
  const rows = results.map((r) => `| ${r.id} | ${r.title} | ${r.expect} | ${r.worst} | **${r.outcome}**${r.knownGap ? ' (known gap)' : ''} | ${r.signals.join(', ') || 'none'} |`);
  return `# Red-team results\n\nCleat ${VERSION} scanned ${results.length} inert test skills offline on ${new Date().toISOString().slice(0, 10)}. Cases are listed in cases.mjs; nothing in them is ever run.\n\n` +
    `- Malicious-style cases: ${t.malicious}. Caught at the expected level: ${t.caught}. Flagged but rated too low: ${t.underRated}. Missed: ${t.missed}.\n` +
    `- Legitimate controls: ${t.controls}. Clean: ${t.pass}. Marked for review: ${t.noisy}. False alarms (high-risk): ${t.falseAlarms}.\n\n` +
    `| Case | What it does | Expected | Cleat's worst | Outcome | Signals |\n|---|---|---|---|---|---|\n${rows.join('\n')}\n`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const results = runAll();
  const t = tally(results);
  if (process.argv.includes('--json')) console.log(JSON.stringify({ tally: t, results }, null, 2));
  else {
    for (const r of results) console.log(`${r.outcome.padEnd(12)} ${r.worst.padEnd(9)} ${r.id.padEnd(34)} ${r.signals.join(',')}`);
    console.log('\n' + JSON.stringify(t));
  }
  const mi = process.argv.indexOf('--md');
  if (mi > 0) writeFileSync(process.argv[mi + 1], markdown(results, t));
  // --record "what changed": keep this run. Writes results/<version>.md and
  // RESULTS.md, and adds a line to history.csv, so every release's numbers stay.
  const ri = process.argv.indexOf('--record');
  if (ri > 0) {
    const note = (process.argv[ri + 1] || '').replace(/"/g, "'");
    const md = markdown(results, t);
    writeFileSync(join(here, 'results', `${VERSION}.md`), md);
    writeFileSync(join(here, 'RESULTS.md'), md);
    const hist = join(here, 'history.csv');
    const head = 'date,version,malicious,caught,under_rated,missed,controls,clean,review,false_alarms,note\n';
    const row = [new Date().toISOString().slice(0, 10), VERSION, t.malicious, t.caught, t.underRated, t.missed,
      t.controls, t.pass, t.noisy, t.falseAlarms, `"${note}"`].join(',') + '\n';
    writeFileSync(hist, (existsSync(hist) ? readFileSync(hist, 'utf8') : head) + row);
  }
}
