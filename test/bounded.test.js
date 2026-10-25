import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bounded } from '../src/bounded.js';

test('bounded empties a Map or Set that has reached its limit and leaves a smaller one alone', () => {
  const m = new Map();
  for (const k of 'abc') bounded(m, 3).set(k, 1);
  assert.deepEqual([...m.keys()], ['a', 'b', 'c']);
  bounded(m, 3).set('d', 1);
  assert.deepEqual([...m.keys()], ['d']);
  const s = new Set();
  for (let i = 0; i < 7; i++) bounded(s, 3).add(i);
  assert.deepEqual([...s], [6]);
});
