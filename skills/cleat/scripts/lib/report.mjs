// Plain-text rendering. ASCII only, so it prints correctly on any console.
// Anything copied from the skill or from a remote page is marked "untrusted":
// it is evidence to show a person, never an instruction to follow.
import { rank, excerpt } from './util.mjs';

const TAG = (s) => `[${s.toUpperCase()}]`.padEnd(11);
const VERDICT = {
  'high-risk': 'HIGH RISK. Do not install or run this skill until a person has reviewed the items below.',
  review: 'REVIEW NEEDED. Nothing conclusive, but some items deserve a look before you trust this skill.',
  'no-red-flags': 'NO RED FLAGS FOUND. This is not a guarantee of safety. See the limits at the end.',
};
const where = (o) => `${o.file}:${o.line}${o.hidden ? ` (hidden in ${o.hidden})` : ''}`;
const quote = (text) => `      untrusted> ${excerpt(text, 180)}`;

function fetchLine(f) {
  if (!f) return '      fetch: not attempted';
  if (f.skipped) return `      fetch: skipped (${f.skipped})`;
  if (!f.ok) return `      fetch: FAILED (${excerpt(f.error || 'no response', 100)})`;
  const hash = f.normSha256 ? f.normSha256.slice(0, 16) : 'n/a';
  const moved = f.redirects.length ? `, after ${f.redirects.length} redirect(s) to ${excerpt(f.finalUrl, 100)}` : '';
  return `      fetch: ${f.status} ${excerpt(f.contentType || 'unknown type', 40)}, ${f.bytes} bytes, fingerprint ${hash}${moved}`;
}

export function renderScan(report, { minSeverity = 'info' } = {}) {
  const s = report.summary;
  const out = [];
  out.push(`Cleat report for skill "${report.skill.name}"`);
  out.push(`Folder: ${report.skill.dir}`);
  out.push('');
  out.push(`Verdict: ${VERDICT[s.verdict]}`);
  out.push('');
  const r = s.references;
  out.push(`Outside links: ${r.total}  (run as code: ${r.execute}, downloaded: ${r.download}, agent told to read: ${r.instruction}, plain mentions: ${r.mention})`);
  out.push(`Packages installed or run: ${s.packages}`);
  out.push(`References hidden from a normal read: ${s.hidden}`);
  if (s.offline) out.push('Offline mode: nothing was fetched, so remote content was not checked.');
  else out.push(`Fetched ${s.fetched} link(s) successfully, ${s.unreachable} failed.`);

  const refs = report.references.filter((x) => rank(x.severity) >= rank(minSeverity));
  if (refs.length) {
    out.push('', '--- Links ---');
    for (const ref of refs) {
      out.push('', `${TAG(ref.severity)}${ref.usage.toUpperCase()}  ${excerpt(ref.url, 200)}`);
      out.push(`      found in: ${ref.occurrences.slice(0, 3).map(where).join(', ')}${ref.occurrences.length > 3 ? `, and ${ref.occurrences.length - 3} more` : ''}`);
      for (const flag of ref.flags) out.push(`      - ${flag.why}`);
      if (ref.usage === 'execute') out.push('      - The skill runs this content as code.');
      if (ref.immutable) out.push('      - Pinned to a specific commit, so the content should not change.');
      out.push(fetchLine(ref.fetch));
      for (const flag of ref.fetch?.flags || []) {
        out.push(`      remote content ${TAG(flag.severity).trim()} ${flag.id}: ${flag.why}`);
        if (flag.excerpt) out.push(quote(flag.excerpt));
      }
      if (ref.fetch?.onwardHosts?.length && ref.usage !== 'mention') {
        out.push(`      links onward to: ${ref.fetch.onwardHosts.slice(0, 6).map((h) => excerpt(h, 60)).join(', ')}${ref.fetch.onwardHosts.length > 6 ? ', ...' : ''}`);
      }
    }
  }

  const pkgs = report.packages.filter((x) => rank(x.severity) >= rank(minSeverity));
  if (pkgs.length) {
    out.push('', '--- Packages ---');
    for (const pkg of pkgs) {
      out.push('', `${TAG(pkg.severity)}${pkg.exec ? 'RUNS' : 'INSTALLS'}  ${pkg.ecosystem}: ${excerpt(pkg.specs.join(', '), 160)}`);
      out.push(`      found in: ${pkg.occurrences.slice(0, 3).map(where).join(', ')}`);
      for (const flag of pkg.flags) out.push(`      - ${flag.why}`);
      const reg = pkg.registry;
      if (reg?.found) out.push(`      registry: exists, newest version ${excerpt(reg.latest, 40)}`);
      else if (reg?.error) out.push(`      registry: lookup failed (${excerpt(reg.error, 80)})`);
    }
  }

  const findings = report.findings.filter((x) => rank(x.severity) >= rank(minSeverity));
  if (findings.length) {
    out.push('', '--- Inside the skill files ---');
    for (const f of findings) {
      out.push('', `${TAG(f.severity)}${f.id}  ${f.file}${f.line ? `:${f.line}` : ''}${f.layer ? ` (inside ${f.layer})` : ''}${f.count > 1 ? `  x${f.count}` : ''}`);
      out.push(`      - ${f.why}`);
      if (f.excerpt) out.push(quote(f.excerpt));
    }
  }

  if (report.notes.length) {
    out.push('', '--- Notes ---');
    for (const note of report.notes) out.push(`  - ${note}`);
  }
  out.push('', '--- Limits ---');
  for (const limit of report.limitations) out.push(`  - ${limit}`);
  return out.join('\n') + '\n';
}

export function renderVerify(report, result, lock) {
  const out = [];
  out.push(`Cleat verify for skill "${report.skill.name}"`);
  out.push(`Locked: ${lock.lockedAt}   Checked: ${report.generatedAt}`);
  out.push('');
  const gap = result.unchecked
    ? `Not compared: ${result.unchecked} link(s) could not be fetched this time (unreachable, reserved, templated or over a fetch limit).`
    : null;
  if (!result.changes.length) {
    out.push(gap ? 'UNCHANGED, as far as could be checked.' : 'UNCHANGED. Everything this skill points to matches what was locked.');
    if (gap) out.push(gap);
    return out.join('\n') + '\n';
  }
  const serious = result.changes.filter((c) => rank(c.severity) >= rank('medium')).length;
  out.push(serious
    ? `DRIFT DETECTED. ${serious} change(s) need review before you keep using this skill.`
    : 'Minor changes only. Nothing that needs action.');
  for (const c of result.changes) {
    out.push('', `${TAG(c.severity)}${c.type}  ${excerpt(c.id, 200)}`);
    out.push(`      - ${c.what}`);
    for (const flag of c.detail?.newFlags || []) {
      out.push(`      new red flag ${flag.id}: ${flag.why}`);
      if (flag.excerpt) out.push(quote(flag.excerpt));
    }
    for (const line of c.detail?.diff?.addedSample || []) out.push(`      added  ${quote(line).trim()}`);
  }
  if (gap) out.push('', gap);
  out.push('', 'If you have reviewed these changes and accept them, run "lock" again to record the new state.');
  return out.join('\n') + '\n';
}
