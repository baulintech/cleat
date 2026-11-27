// Shared helpers. No dependencies.
import { createHash } from 'node:crypto';

export const VERSION = '0.1.8';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
export const rank = (s) => Math.max(0, SEVERITIES.indexOf(s));
export const maxSeverity = (...list) =>
  list.flat().reduce((a, b) => (rank(b) > rank(a) ? b : a), 'info');
export const bump = (s, n = 1) =>
  SEVERITIES[Math.min(SEVERITIES.length - 1, rank(s) + n)];

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');

// One-line, length-capped, control-character-free copy of untrusted text.
export function excerpt(value, max = 160) {
  const flat = String(value)
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return flat.length > max ? flat.slice(0, max - 3) + '...' : flat;
}

// Offset to line-number lookup for a block of text.
export function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  const lineOf = (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const lineText = (n) => {
    if (n < 1 || n > starts.length) return '';
    const end = n < starts.length ? starts[n] - 1 : text.length;
    return text.slice(starts[n - 1], end).replace(/\r$/, '');
  };
  const startOf = (n) => starts[Math.min(Math.max(n, 1), starts.length) - 1];
  return { lineOf, lineText, startOf, count: starts.length };
}

// Line continuation: a trailing backslash, or PowerShell's space-backtick.
// A Markdown code fence or inline code at the end of a line does not count.
export const CONTINUES = /(?:\\|\s`)\s*$/;

// A command split over several lines with trailing "\" (or PowerShell "`")
// is one command. Returns the joined text for the group containing line n.
export function logicalLine(idx, n, max = 8000) {
  const continues = (s) => CONTINUES.test(s);
  let first = n;
  while (first > 1 && continues(idx.lineText(first - 1))) first--;
  let last = n;
  while (last < idx.count && continues(idx.lineText(last))) last++;
  const parts = [];
  for (let i = first; i <= last; i++) {
    parts.push(idx.lineText(i).replace(CONTINUES, ' '));
  }
  return parts.join(' ').slice(0, max);
}

// Run async jobs with a small concurrency limit, preserving order.
export async function pool(items, limit, worker) {
  const out = new Array(items.length);
  let next = 0;
  const run = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await worker(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return out;
}
