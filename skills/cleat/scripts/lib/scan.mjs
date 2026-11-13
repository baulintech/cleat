// Orchestrates a scan: inventory the skill, safely fetch what it points to,
// check the remote content, and grade every reference.
import { resolve, basename } from 'node:path';
import { walkSkill, buildInventory, skillName, assessUrl, USAGE_ORDER } from './extract.mjs';
import { safeFetch, normaliseText } from './safefetch.mjs';
import { scanContent } from './flags.mjs';
import { maxSeverity, rank, pool, excerpt, VERSION } from './util.mjs';

const ONWARD_URL = /\bhttps?:\/\/[^\s<>"'`)\]\\]+/gi;
const ACTIVE = new Set(['execute', 'download', 'instruction']);

export const LIMITATIONS = [
  'Cleat reads and fingerprints content. It never runs the skill, so behaviour that only appears at run time is out of scope.',
  'A server can show a scanner one thing and an agent another. A clean result means "nothing found from here", not "safe".',
  'Pages that change on every visit (dates, counters) will show as changed. Read the diff before deciding.',
  'Pattern rules catch known shapes of attack. A carefully worded instruction in plain English can still get through.',
];

function onwardHosts(text, ownHost) {
  const hosts = new Set();
  let count = 0;
  for (const m of text.matchAll(ONWARD_URL)) {
    count++;
    try {
      const host = new URL(m[0]).hostname.toLowerCase();
      if (host && host !== ownHost) hosts.add(host);
    } catch { /* not a URL */ }
    if (hosts.size >= 25) break;
  }
  return { hosts: [...hosts].sort(), count };
}

async function fetchReference(ref, fetcher, fetchOpts) {
  const res = await fetcher(ref.url, fetchOpts);
  const out = {
    ok: Boolean(res.ok),
    status: res.status ?? null,
    finalUrl: res.finalUrl || ref.url,
    redirects: (res.redirects || []).map((r) => r.to),
    contentType: res.contentType || null,
    bytes: res.bytes ?? null,
    truncated: Boolean(res.truncated),
    sha256: res.sha256 || null,
    normSha256: res.normSha256 || null,
    isText: Boolean(res.isText),
    error: res.error || null,
    flags: [],
    onwardHosts: [],
    onwardLinks: 0,
  };
  let norm = null;
  if (res.isText && typeof res.text === 'string') {
    norm = normaliseText(res.text, res.contentType || '');
    out.flags = scanContent(norm).map((f) => ({
      id: f.id, severity: f.severity, why: f.why, count: f.count,
      line: f.samples[0]?.line, excerpt: f.samples[0]?.excerpt,
    }));
    const onward = onwardHosts(norm, ref.host);
    out.onwardHosts = onward.hosts;
    out.onwardLinks = onward.count;
  }
  return { fetch: out, norm };
}

function gradeAfterFetch(ref) {
  const f = ref.fetch;
  if (!f || f.skipped) return;
  const add = (id, severity, why) => ref.flags.push({ id, severity, why });
  const active = ACTIVE.has(ref.usage);
  if (!f.ok) {
    if (/^refused/.test(f.error || '')) {
      add('refused-target', 'high', `Cleat refused to fetch this: ${excerpt(f.error, 120)}. A skill has no good reason to point at a private or local address.`);
    } else if (active) {
      add('unreachable', 'medium', `Could not be retrieved (${excerpt(f.error || 'no response', 80)}), so what it serves could not be checked.`);
    }
  } else {
    let finalHost = ref.host;
    try { finalHost = new URL(f.finalUrl).hostname; } catch { /* keep original */ }
    if (finalHost !== ref.host) add('redirects-elsewhere', active ? 'medium' : 'low', `Redirects to a different site (${finalHost}).`);
    if (ref.url.startsWith('https:') && f.finalUrl.startsWith('http:')) add('downgrade', 'medium', 'Redirects from an encrypted link to an unencrypted one.');
    if (f.truncated) add('truncated', 'low', `Only the first ${f.bytes} bytes were inspected.`);
    if (!f.isText && (ref.usage === 'execute' || ref.usage === 'download')) add('binary-download', 'medium', 'Binary content. Cleat fingerprints it but cannot read what it does.');
  }
  let severity = assessUrl(ref);
  const remote = maxSeverity(f.flags.map((x) => x.severity));
  if (rank(remote) >= rank('high') && ref.usage !== 'mention') {
    severity = ref.usage === 'execute' ? 'critical' : maxSeverity(severity, 'high');
  } else if (rank(remote) >= rank('medium') && active) {
    severity = maxSeverity(severity, 'medium');
  }
  ref.severity = severity;
}

async function lookupPackage(ref, fetcher, fetchOpts) {
  let url;
  if (ref.ecosystem === 'npm') url = `https://registry.npmjs.org/${ref.name.replace('/', '%2F')}/latest`;
  else if (ref.ecosystem === 'pypi') url = `https://pypi.org/pypi/${encodeURIComponent(ref.name)}/json`;
  else return null;
  const res = await fetcher(url, { ...fetchOpts, maxBytes: 8 * 1024 * 1024 });
  if (res.status === 404) return { found: false };
  if (!res.ok || typeof res.text !== 'string') return { error: res.error || 'lookup failed' };
  try {
    const data = JSON.parse(res.text);
    if (ref.ecosystem === 'npm') {
      return { found: true, latest: String(data.version || ''), integrity: data.dist?.integrity || data.dist?.shasum || null };
    }
    return { found: true, latest: String(data.info?.version || ''), integrity: null };
  } catch {
    return { error: 'registry reply was not valid JSON' };
  }
}

export const SKIP_SAFETY = 'over the safety limit';
export const SKIP_MENTION = 'over the limit for plain mentions';

const bySeverity = (a, b) =>
  rank(b.severity) - rank(a.severity) ||
  USAGE_ORDER.indexOf(b.usage || 'mention') - USAGE_ORDER.indexOf(a.usage || 'mention') ||
  String(a.id || a.file).localeCompare(String(b.id || b.file));

// Returns { report, snapshots }. `snapshots` maps reference id to the
// normalised remote text, for diffing later. It is kept out of the report.
export async function scanSkill(dir, opts = {}) {
  const {
    offline = false,
    fetcher = safeFetch,
    maxFetch = 500, // safety ceiling on fetches per run, whatever the links are used for
    maxMentions = 40, // plain mentions do not steer the agent, so fewer of them are fetched
    maxBytes = 1024 * 1024,
    timeoutMs = 15000,
    _fetchReserved = false, // tests only
  } = opts;
  const root = resolve(dir);
  const { files, notes, treeSha256 } = await walkSkill(root);
  if (!files.some((f) => /^skill\.md$/i.test(f.path))) {
    notes.push('No SKILL.md at the top of this folder. Check that this is the skill directory.');
  }
  const inventory = buildInventory(files);
  const name = skillName(files, basename(root));
  const snapshots = new Map();
  const fetchOpts = { maxBytes, timeoutMs };

  // Every link the agent acts on is fetched, riskiest first, up to the safety
  // ceiling. Plain mentions get a smaller allowance of their own.
  const queue = [];
  let mentions = 0;
  const ordered = [...inventory.urls].sort(bySeverity);
  // Links the agent acts on always come before plain mentions, so mentions never use up the safety limit.
  for (const ref of [...ordered.filter((r) => r.usage !== 'mention'), ...ordered.filter((r) => r.usage === 'mention')]) {
    if (offline) ref.fetch = { skipped: 'offline' };
    else if (ref.templated) ref.fetch = { skipped: 'template URL, filled in at run time' };
    else if (ref.reserved && !_fetchReserved) ref.fetch = { skipped: 'reserved or local host' };
    else if (queue.length >= maxFetch) ref.fetch = { skipped: SKIP_SAFETY };
    else if (ref.usage === 'mention' && mentions >= maxMentions) ref.fetch = { skipped: SKIP_MENTION };
    else {
      queue.push(ref);
      if (ref.usage === 'mention') mentions++;
    }
  }
  const skippedByLimit = {
    actedOn: inventory.urls.filter((r) => r.usage !== 'mention' && r.fetch?.skipped === SKIP_SAFETY).length,
    mentions: inventory.urls.filter((r) => r.usage === 'mention' && [SKIP_SAFETY, SKIP_MENTION].includes(r.fetch?.skipped)).length,
  };
  if (skippedByLimit.actedOn) {
    notes.push(`${skippedByLimit.actedOn} link(s) the agent acts on were not fetched: this skill has more links than the ${maxFetch}-fetch safety limit. They are not covered by a lock. Raise the limit with --max-fetch if you expect a skill this large.`);
  }
  if (skippedByLimit.mentions) {
    notes.push(`${skippedByLimit.mentions} plain mention(s) were not fetched (limit ${maxMentions}, raise it with --max-mentions). Mentions do not tell the agent to do anything.`);
  }

  await pool(queue, 4, async (ref) => {
    const { fetch, norm } = await fetchReference(ref, fetcher, fetchOpts);
    ref.fetch = fetch;
    if (norm !== null) snapshots.set(ref.id, norm);
  });
  for (const ref of inventory.urls) gradeAfterFetch(ref);

  if (!offline) {
    const lookups = inventory.packages.filter((p) => p.source === 'registry' && ['npm', 'pypi'].includes(p.ecosystem)).slice(0, 30);
    await pool(lookups, 4, async (ref) => {
      ref.registry = await lookupPackage(ref, fetcher, fetchOpts);
      if (ref.registry?.found === false) {
        ref.flags.push({
          id: 'package-not-found', severity: 'high',
          why: 'No package with this name exists on the public registry. Whoever registers the name next decides what gets installed.',
        });
        ref.severity = maxSeverity(ref.severity, 'high');
      }
    });
  }
  for (const ref of inventory.packages) if (ref.registry === undefined) ref.registry = null;

  const references = inventory.urls.sort(bySeverity);
  const packages = inventory.packages.sort(bySeverity);
  const findings = inventory.findings.sort(bySeverity);
  const worst = maxSeverity(references.map((r) => r.severity), packages.map((p) => p.severity), findings.map((f) => f.severity));
  const verdict = rank(worst) >= rank('high') ? 'high-risk' : rank(worst) >= rank('medium') ? 'review' : 'no-red-flags';
  const count = (usage) => references.filter((r) => r.usage === usage).length;

  const report = {
    tool: { name: 'cleat', version: VERSION },
    generatedAt: new Date().toISOString(),
    skill: {
      name,
      dir: root,
      treeSha256,
      files: files.map(({ path, kind, bytes, sha256, reason, target }) => ({ path, kind, bytes, sha256, reason, target })),
    },
    summary: {
      verdict,
      maxSeverity: worst,
      offline,
      references: { total: references.length, execute: count('execute'), download: count('download'), instruction: count('instruction'), mention: count('mention') },
      packages: packages.length,
      fetched: references.filter((r) => r.fetch && !r.fetch.skipped && r.fetch.ok).length,
      unreachable: references.filter((r) => r.fetch && !r.fetch.skipped && !r.fetch.ok).length,
      hidden: references.filter((r) => r.hidden.length).length + packages.filter((p) => p.hidden.length).length,
      findings: findings.length,
      skippedByLimit,
    },
    references,
    packages,
    findings,
    notes,
    limitations: LIMITATIONS,
  };
  return { report, snapshots };
}
