import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { render } from '../scripts/tokens.mjs';
import { TOKENS } from '../src/tokens.js';

test('src/tokens.js matches the installed @dunn.dev/reference; run npm run tokens', () => {
  assert.equal(readFileSync(new URL('../src/tokens.js', import.meta.url), 'utf8'), render());
});

test('every custom property the page reads is defined, and none is carried unread', () => {
  const src = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
  const read = new Set([...src.matchAll(/var\((--[\w-]+)\)/g)].map((m) => m[1]));
  const defined = new Set([...TOKENS.matchAll(/(--[\w-]+):/g)].map((m) => m[1]));
  for (const n of read) assert.ok(defined.has(n), `${n} is read but not defined`);
  for (const n of defined) assert.ok(read.has(n) || TOKENS.includes(`var(${n})`), `${n} is carried but unread`);
});
