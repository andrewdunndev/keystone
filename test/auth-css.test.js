import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { render } from '../scripts/auth-css.mjs';
import { AUTH_CSS } from '../src/auth-css.js';

const pkg = new URL('../node_modules/@dunn.dev/reference/auth/auth.standalone.css', import.meta.url);

test('src/auth-css.js matches the installed @dunn.dev/reference; run npm run auth-css', () => {
  assert.equal(readFileSync(new URL('../src/auth-css.js', import.meta.url), 'utf8'), render());
  assert.equal(AUTH_CSS, readFileSync(pkg, 'utf8'));
});

test('the generator refuses a stylesheet that could close the style element or load a resource', () => {
  for (const bad of ['a{}</style><b>', 'a{content:"\\3c"}', 'a{background:url(x)}', '@import "x";', 'a{content:"é"}']) {
    assert.throws(() => render(bad), /auth-css/, bad);
  }
});
