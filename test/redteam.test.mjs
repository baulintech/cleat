// Red-team QA: inert copies of real attack techniques, plus legitimate controls.
// Fails if any case does worse than the recorded baseline, so a change that
// stops Cleat catching something (or starts a false alarm) is noticed.
// Full table: node qa/redteam/run.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runAll } from '../qa/redteam/run.mjs';

const ORDER = { missed: 0, 'under-rated': 1, caught: 2, 'false-alarm': 0, noisy: 1, pass: 2 };
const { outcomes } = JSON.parse(readFileSync(new URL('../qa/redteam/baseline.json', import.meta.url), 'utf8'));

test('red-team suite: no case does worse than the baseline', () => {
  const results = runAll();
  assert.deepEqual(results.map((r) => r.id).sort(), Object.keys(outcomes).sort(), 'every case needs a baseline entry');
  const worse = results.filter((r) => ORDER[r.outcome] < ORDER[outcomes[r.id]]);
  assert.deepEqual(worse.map((r) => `${r.id}: ${outcomes[r.id]} -> ${r.outcome}`), []);
  const better = results.filter((r) => ORDER[r.outcome] > ORDER[outcomes[r.id]]);
  if (better.length) console.log(`Improved (update qa/redteam/baseline.json): ${better.map((r) => r.id).join(', ')}`);
});

test('red-team suite: no legitimate control is called high-risk', () => {
  const alarms = runAll().filter((r) => r.outcome === 'false-alarm');
  assert.deepEqual(alarms.map((r) => r.id), []);
});
