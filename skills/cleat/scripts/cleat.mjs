#!/usr/bin/env node
// Cleat: see what a skill reaches outside itself, and notice when it moves.
// Zero dependencies. Needs Node 18 or newer.
import { resolve, dirname, join } from 'node:path';
import { stat } from 'node:fs/promises';
import { scanSkill } from './lib/scan.mjs';
import { writeLock, readLock, compare } from './lib/lock.mjs';
import { renderScan, renderVerify } from './lib/report.mjs';
import { SEVERITIES, rank, VERSION } from './lib/util.mjs';

const HELP = `cleat ${VERSION}

Usage:
  node cleat.mjs scan   <skill-folder>   List and check everything the skill reaches outside itself
  node cleat.mjs lock   <skill-folder>   Scan, then record what was found in a lockfile
  node cleat.mjs verify <skill-folder>   Scan again and report what changed since the lock

Options:
  --json             Print the full result as JSON instead of text
  --offline          Do not fetch anything (inventory and local checks only)
  --state-dir DIR    Where lockfiles and snapshots live (default: ./.cleat, or the
                     nearest .cleat folder above the skill)
  --no-snapshots     Lock without saving copies of remote text (no line-level diff later)
  --max-fetch N      Safety limit on links fetched in one run (default 500). Every link
                     the agent acts on is fetched, riskiest first, up to this limit
  --max-mentions N   Most plain mentions to fetch (default 40)
  --allow-partial    Let lock save a baseline even when the safety limit left links
                     the agent acts on unfetched (they will not be checked by verify)
  --timeout MS       Time limit per link in milliseconds (default 15000)
  --fail-on LEVEL    Exit 1 at or above this severity: ${SEVERITIES.join(', ')}
                     (default: high for scan, medium for verify)

Exit codes: 0 nothing at or above the threshold, 1 something was, 2 the command could not run.

Cleat only reads. It never runs the skill it is checking and never executes
anything it downloads.
`;

function parseArgs(argv) {
  const args = { _: [] };
  const takesValue = new Set(['--state-dir', '--max-fetch', '--max-mentions', '--timeout', '--fail-on']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (takesValue.has(a)) {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      args[a.slice(2)] = argv[++i];
    } else if (a.startsWith('--')) {
      args[a.slice(2)] = true;
    } else {
      args._.push(a);
    }
  }
  return args;
}

function positiveInt(value, name, fallback) {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new Error(`--${name} must be a positive whole number`);
  return n;
}

// Without --state-dir: use ./.cleat if it exists, otherwise the nearest .cleat
// folder above the skill (so verify works from anywhere in the project),
// otherwise create ./.cleat.
async function findStateDir(skillDir) {
  const here = resolve('.cleat');
  if ((await stat(here).catch(() => null))?.isDirectory()) return here;
  for (let d = resolve(skillDir); ; d = dirname(d)) {
    const candidate = join(d, '.cleat');
    if ((await stat(candidate).catch(() => null))?.isDirectory()) return candidate;
    if (dirname(d) === d) return here;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [command, target] = args._;
  if (args.help || !command) {
    process.stdout.write(HELP);
    return command || args.help ? 0 : 2;
  }
  if (!['scan', 'lock', 'verify'].includes(command)) throw new Error(`Unknown command "${command}". Use scan, lock or verify.`);
  if (!target) throw new Error(`Give the skill folder to ${command}, for example: node cleat.mjs ${command} ./skills/my-skill`);
  const dir = resolve(target);
  const info = await stat(dir).catch(() => null);
  if (!info?.isDirectory()) throw new Error(`"${target}" is not a folder. Point Cleat at the folder that contains SKILL.md.`);
  if (args['fail-on'] !== undefined && !SEVERITIES.includes(args['fail-on'])) {
    throw new Error(`--fail-on must be one of: ${SEVERITIES.join(', ')}`);
  }

  const stateDir = args['state-dir'] ? resolve(args['state-dir']) : await findStateDir(dir);
  const { report, snapshots } = await scanSkill(dir, {
    offline: Boolean(args.offline),
    maxFetch: positiveInt(args['max-fetch'], 'max-fetch', 500),
    maxMentions: positiveInt(args['max-mentions'], 'max-mentions', 40),
    timeoutMs: positiveInt(args.timeout, 'timeout', 15000),
  });

  if (command === 'scan') {
    process.stdout.write(args.json ? JSON.stringify(report, null, 2) + '\n' : renderScan(report));
    return rank(report.summary.maxSeverity) >= rank(args['fail-on'] || 'high') ? 1 : 0;
  }

  if (command === 'lock') {
    if (report.summary.offline) throw new Error('Cannot lock in offline mode: there would be no remote fingerprints to compare against later.');
    const partial = report.summary.skippedByLimit.actedOn;
    if (partial && !args['allow-partial']) {
      throw new Error(`Not locked: ${partial} link(s) the agent acts on were not fetched because this skill is over the ${positiveInt(args['max-fetch'], 'max-fetch', 500)}-fetch safety limit, so the baseline would be incomplete. Raise the limit with --max-fetch, or pass --allow-partial to lock anyway (those links will not be checked by verify).`);
    }
    const written = await writeLock(stateDir, report, snapshots, { saveSnapshots: !args['no-snapshots'] });
    if (args.json) {
      process.stdout.write(JSON.stringify({ lockfile: written.file, snapshots: written.snapshots, sameNameElsewhere: written.sameNameElsewhere, partial, report }, null, 2) + '\n');
    } else {
      process.stdout.write(renderScan(report, { minSeverity: 'medium' }));
      process.stdout.write(`\nLocked ${report.references.length} link(s) and ${report.packages.length} package(s) in ${written.file}\n`);
      if (written.sameNameElsewhere.length) {
        process.stdout.write(`Note: another skill called "${report.skill.name}" is also locked, from ${written.sameNameElsewhere.join(', ')}. Each folder keeps its own lock, so check you meant this one.\n`);
      }
      if (partial) {
        process.stdout.write(`Warning: partial lock. ${partial} link(s) the agent acts on were not fetched and will not be checked by verify.\n`);
      }
      if (report.summary.verdict === 'high-risk') {
        process.stdout.write('Note: a lock records what was there when you looked. It does not make a risky skill safe.\n');
      }
    }
    return 0;
  }

  const { lock, elsewhere } = await readLock(stateDir, report);
  if (!lock) {
    const hint = elsewhere.length
      ? ` A skill with the same name is locked from ${elsewhere.join(', ')}. If this skill moved or is a different skill using that name, review it and run "lock" for this folder.`
      : ' Run "lock" first.';
    throw new Error(`No lockfile for "${report.skill.name}" in this folder, under ${stateDir}.${hint}`);
  }
  if (report.summary.offline) throw new Error('Cannot verify in offline mode.');
  const result = await compare(lock, report, snapshots, stateDir);
  if (args.json) {
    process.stdout.write(JSON.stringify({ lockedAt: lock.lockedAt, checkedAt: report.generatedAt, ...result, summary: report.summary }, null, 2) + '\n');
  } else {
    process.stdout.write(renderVerify(report, result, lock));
  }
  return rank(result.maxSeverity) >= rank(args['fail-on'] || 'medium') && result.changes.length ? 1 : 0;
}

main().then(
  (code) => { process.exitCode = code; },
  (err) => {
    process.stderr.write(`cleat: ${err.message}\n`);
    process.exitCode = 2;
  },
);
