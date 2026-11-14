#!/usr/bin/env node
// Cleat: see what a skill reaches outside itself, and notice when it moves.
// Zero dependencies. Needs Node 18 or newer.
import { resolve, dirname, join, basename } from 'node:path';
import { stat, readdir, realpath } from 'node:fs/promises';
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
  --state-dir DIR    Where lockfiles and snapshots live (default: the nearest
                     .cleat folder above the skill, otherwise ./.cleat)
  --no-snapshots     Lock without saving copies of remote text (no line-level diff later)
  --max-fetch N      Safety limit on links fetched in one run (default 500). Every link
                     the agent acts on is fetched, riskiest first, up to this limit
  --max-mentions N   Most plain mentions to fetch (default 40)
  --allow-partial    Let lock save a baseline even when the safety limit left links
                     the agent acts on unfetched (they will not be checked by verify)
  --timeout MS       Time limit per link in milliseconds (default 15000)
  --fail-on LEVEL    Exit 1 at or above this severity: ${SEVERITIES.join(', ')}
                     (default: high for scan, medium for verify)
  --version          Print the version and exit

Exit codes: 0 nothing at or above the threshold, 1 something was, 2 the command could not run.

Cleat only reads. It never runs the skill it is checking and never executes
anything it downloads.
`;

function parseArgs(argv) {
  const args = { _: [] };
  const takesValue = new Set(['--state-dir', '--max-fetch', '--max-mentions', '--timeout', '--fail-on']);
  const flags = new Set(['--json', '--offline', '--no-snapshots', '--allow-partial', '--help', '--version']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (takesValue.has(a)) {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      args[a.slice(2)] = argv[++i];
    } else if (flags.has(a)) {
      args[a.slice(2)] = true;
    } else if (a === '-h') {
      args.help = true;
    } else if (a.startsWith('-')) {
      const name = a.split('=')[0];
      if (takesValue.has(name)) throw new Error(`Write ${name} and its value as two words, for example: ${name} 100`);
      throw new Error(`Unknown option "${a}". Run with --help to see the options.`);
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

// One spelling for every path. Folders above the last part are resolved
// through symlinks, so /var and /private/var on macOS (or a symlinked home
// folder) give the same lock. The last part is kept as written, because skill
// installers often make the skill folder itself a symlink and locks are named
// after the folder the user pointed at.
async function canonical(p) {
  const abs = resolve(p);
  const parent = dirname(abs);
  if (parent === abs) return abs;
  const real = await realpath(parent).catch(() => null);
  return join(real ?? (await canonical(parent)), basename(abs));
}

const isDir = async (p) => (await stat(p).catch(() => null))?.isDirectory() ?? false;

// Without --state-dir: the nearest .cleat folder above the skill, so lock and
// verify agree wherever they are run from. Only if there is none, ./.cleat
// (created by lock if needed). The skill's location decides, not the current
// folder, so a stray .cleat elsewhere cannot hide the project's lock.
async function findStateDir(skillDir) {
  for (let d = skillDir; ; d = dirname(d)) {
    const candidate = join(d, '.cleat');
    if (await isDir(candidate)) return candidate;
    if (dirname(d) === d) break;
  }
  return canonical('.cleat');
}

const isSkillFile = (name) => /^skill\.md$/i.test(name);

// A folder without SKILL.md is not a skill. Scanning it would report "no red
// flags", which reads as a clean result, so refuse and say what to point at.
async function requireSkillFile(dir, target) {
  const entries = await readdir(dir, { withFileTypes: true });
  if (entries.some((e) => e.isFile() && isSkillFile(e.name))) return;
  const skills = [];
  for (const e of entries.filter((x) => x.isDirectory())) {
    const inner = await readdir(join(dir, e.name)).catch(() => []);
    if (inner.some(isSkillFile)) skills.push(e.name);
  }
  if (skills.length) {
    const shown = skills.slice(0, 5).map((n) => join(target, n)).join(', ');
    throw new Error(`"${target}" has no SKILL.md of its own, but ${skills.length} folder(s) inside it do: ${shown}${skills.length > 5 ? ', ...' : ''}. Run Cleat on each skill folder.`);
  }
  throw new Error(`No SKILL.md in "${target}", so this does not look like a skill. Point Cleat at the folder that contains SKILL.md.`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [command, target] = args._;
  if (args.version) {
    process.stdout.write(`cleat ${VERSION}\n`);
    return 0;
  }
  if (args.help || !command) {
    process.stdout.write(HELP);
    return command || args.help ? 0 : 2;
  }
  if (!['scan', 'lock', 'verify'].includes(command)) throw new Error(`Unknown command "${command}". Use scan, lock or verify.`);
  if (!target) throw new Error(`Give the skill folder to ${command}, for example: node cleat.mjs ${command} ./skills/my-skill`);
  const dir = await canonical(target);
  const info = await stat(dir).catch(() => null);
  if (!info?.isDirectory()) throw new Error(`"${target}" is not a folder. Point Cleat at the folder that contains SKILL.md.`);
  await requireSkillFile(dir, target);
  if (args['fail-on'] !== undefined && !SEVERITIES.includes(args['fail-on'])) {
    throw new Error(`--fail-on must be one of: ${SEVERITIES.join(', ')}`);
  }

  const stateDir = args['state-dir'] ? await canonical(args['state-dir']) : await findStateDir(dir);
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
