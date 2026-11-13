// Lockfile: a record of what a skill pointed to, and what was there, on the
// day it was reviewed. `compare` reports what has moved since.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { maxSeverity, rank, sha256, excerpt } from './util.mjs';

const SNAPSHOT_CAP = 256 * 1024;
const snapshotName = (id) => `${sha256(id).slice(0, 16)}.txt`;
const lockPath = (stateDir, name) => join(stateDir, `${name}.lock.json`);
const snapshotDir = (stateDir, name) => join(stateDir, 'snapshots', name);

export function buildLock(report) {
  return {
    cleat: 1,
    tool: report.tool,
    lockedAt: report.generatedAt,
    skill: {
      name: report.skill.name,
      treeSha256: report.skill.treeSha256,
      files: Object.fromEntries(report.skill.files.map((f) => [f.path, f.sha256])),
    },
    references: [
      ...report.references.map((r) => ({
        id: r.id,
        kind: 'url',
        url: r.url,
        usage: r.usage,
        severity: r.severity,
        immutable: r.immutable,
        fetch: r.fetch.skipped
          ? { skipped: r.fetch.skipped }
          : {
              ok: r.fetch.ok, status: r.fetch.status, finalUrl: r.fetch.finalUrl,
              contentType: r.fetch.contentType, bytes: r.fetch.bytes, truncated: r.fetch.truncated,
              sha256: r.fetch.sha256, normSha256: r.fetch.normSha256, error: r.fetch.error,
              flags: r.fetch.flags.map((f) => f.id).sort(), onwardHosts: r.fetch.onwardHosts,
            },
      })),
      ...report.packages.map((p) => ({
        id: p.id,
        kind: 'package',
        ecosystem: p.ecosystem,
        name: p.name,
        specs: p.specs,
        pinned: p.pinned,
        exec: p.exec,
        severity: p.severity,
        registry: p.registry,
      })),
    ],
  };
}

export async function writeLock(stateDir, report, snapshots, { saveSnapshots = true } = {}) {
  const name = report.skill.name;
  await mkdir(stateDir, { recursive: true });
  const file = lockPath(stateDir, name);
  await writeFile(file, JSON.stringify(buildLock(report), null, 2) + '\n');
  let saved = 0;
  if (saveSnapshots && snapshots.size) {
    const dir = snapshotDir(stateDir, name);
    await mkdir(dir, { recursive: true });
    for (const [id, text] of snapshots) {
      await writeFile(join(dir, snapshotName(id)), text.slice(0, SNAPSHOT_CAP));
      saved++;
    }
  }
  return { file, snapshots: saved };
}

export async function readLock(stateDir, name) {
  const file = lockPath(stateDir, name);
  let raw;
  try {
    raw = await readFile(file, 'utf8');
  } catch {
    return null;
  }
  const lock = JSON.parse(raw);
  if (lock.cleat !== 1 || !Array.isArray(lock.references)) throw new Error(`${file} is not a Cleat lockfile this version understands.`);
  return lock;
}

async function diffAgainstSnapshot(stateDir, name, id, current) {
  let previous;
  try {
    previous = await readFile(join(snapshotDir(stateDir, name), snapshotName(id)), 'utf8');
  } catch {
    return null;
  }
  const before = new Set(previous.split('\n'));
  const now = current.slice(0, SNAPSHOT_CAP).split('\n');
  const after = new Set(now);
  const added = now.filter((line) => !before.has(line));
  let removed = 0;
  for (const line of before) if (!after.has(line)) removed++;
  return { added: added.length, removed, addedSample: added.slice(0, 8).map((l) => excerpt(l, 200)) };
}

const BY_USAGE = { execute: 'high', download: 'high', instruction: 'medium', mention: 'low' };

// Returns { changes: [{ id, type, severity, what, detail? }], maxSeverity }.
export async function compare(lock, report, snapshots, stateDir) {
  const changes = [];
  const push = (id, type, severity, what, detail) => changes.push({ id, type, severity, what, ...(detail ? { detail } : {}) });
  const name = report.skill.name;

  // The skill's own files
  const before = lock.skill.files;
  const after = Object.fromEntries(report.skill.files.map((f) => [f.path, f.sha256]));
  const edited = Object.keys(after).filter((p) => p in before && before[p] !== after[p]);
  const created = Object.keys(after).filter((p) => !(p in before));
  const deleted = Object.keys(before).filter((p) => !(p in after));
  if (edited.length || created.length || deleted.length) {
    push('skill', 'skill-files-changed', 'medium',
      `The skill's own files changed since it was locked (${edited.length} edited, ${created.length} added, ${deleted.length} removed). Review the skill again, then re-lock.`,
      { edited, added: created, removed: deleted });
  }

  const locked = new Map(lock.references.map((r) => [r.id, r]));
  const current = new Map([...report.references, ...report.packages].map((r) => [r.id, r]));

  for (const [id, ref] of current) {
    if (locked.has(id)) continue;
    const severity = maxSeverity(ref.severity, ref.usage === 'mention' ? 'low' : 'medium');
    push(id, 'new-reference', severity, `New ${ref.kind === 'package' ? 'package' : 'link'} that was not there when the skill was locked (${ref.usage}).`);
  }
  for (const id of locked.keys()) {
    if (!current.has(id)) push(id, 'reference-removed', 'info', 'No longer referenced by the skill.');
  }

  for (const [id, old] of locked) {
    const ref = current.get(id);
    if (!ref) continue;

    if (old.kind === 'package') {
      const was = old.registry;
      const now = ref.registry;
      if (!was || !now || was.error || now.error) continue;
      if (was.found && now.found === false) {
        push(id, 'package-disappeared', 'high', 'This package existed when locked and is now gone from the registry. Whoever re-registers the name controls it.');
      } else if (was.found === false && now.found) {
        push(id, 'package-appeared', 'high', `This package did not exist when locked and now does (version ${excerpt(now.latest, 40)}). Someone has registered the name.`);
      } else if (was.found && now.found && old.pinned === false && was.latest !== now.latest) {
        push(id, 'package-updated', ref.exec ? 'medium' : 'low',
          `Unpinned package moved from ${excerpt(was.latest, 40)} to ${excerpt(now.latest, 40)}. The skill will now install the new version.`);
      } else if (was.found && now.found && was.latest === now.latest && was.integrity && now.integrity && was.integrity !== now.integrity) {
        push(id, 'package-content-changed', 'high', `Version ${excerpt(now.latest, 40)} has different contents from when it was locked, under the same version number.`);
      }
      continue;
    }

    const was = old.fetch || {};
    const now = ref.fetch || {};
    if (was.skipped || now.skipped) continue;
    const base = BY_USAGE[ref.usage] || 'low';

    if (was.ok && !now.ok) {
      push(id, 'remote-unreachable', ref.usage === 'mention' ? 'info' : 'medium', `Was reachable when locked, now fails (${excerpt(now.error || 'no response', 80)}).`);
      continue;
    }
    if (!was.ok && now.ok) {
      push(id, 'remote-appeared', maxSeverity(base, 'medium'), 'Was unreachable when locked and now serves content. Content that turns up after review has not been reviewed.');
      continue;
    }
    if (!was.ok && !now.ok) continue;

    if (was.finalUrl !== now.finalUrl) {
      push(id, 'redirect-changed', maxSeverity(base, 'medium'), `Now leads to ${excerpt(now.finalUrl, 120)} instead of ${excerpt(was.finalUrl, 120)}.`);
    }
    if (was.normSha256 !== now.normSha256) {
      const newFlags = now.flags.filter((f) => !(was.flags || []).includes(f.id));
      const newHosts = (now.onwardHosts || []).filter((h) => !(was.onwardHosts || []).includes(h));
      let severity = base;
      if (old.immutable) severity = maxSeverity(severity, 'high');
      if (newFlags.length) severity = ref.usage === 'execute' ? 'critical' : maxSeverity(severity, 'high');
      else if (newHosts.length && ref.usage !== 'mention') severity = maxSeverity(severity, 'medium');
      const diff = snapshots.has(id) ? await diffAgainstSnapshot(stateDir, name, id, snapshots.get(id)) : null;
      const parts = ['The content behind this link has changed since it was locked.'];
      if (old.immutable) parts.push('The link is pinned to a commit, so it should never change.');
      if (newFlags.length) parts.push(`New red flags: ${newFlags.map((f) => f.id).join(', ')}.`);
      if (newHosts.length) parts.push(`Now links onward to: ${newHosts.slice(0, 5).map((h) => excerpt(h, 60)).join(', ')}.`);
      if (diff) parts.push(`${diff.added} line(s) added, ${diff.removed} removed.`);
      push(id, 'remote-changed', severity, parts.join(' '), {
        newFlags: newFlags.map((f) => ({ id: f.id, severity: f.severity, why: f.why, excerpt: f.excerpt })),
        newOnwardHosts: newHosts,
        diff,
      });
    }
  }

  changes.sort((a, b) => rank(b.severity) - rank(a.severity) || a.id.localeCompare(b.id));
  // Links that could not be fetched this time were not compared with anything.
  const unchecked = report.references.filter((r) => !r.fetch || r.fetch.skipped || !r.fetch.ok).length;
  return { changes, maxSeverity: maxSeverity(changes.map((c) => c.severity)), unchecked };
}
