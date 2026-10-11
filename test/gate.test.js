import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker from '../src/index.js';
import { derivedKey, parseSet, policyTag } from '../src/jwk.js';
import { format, parseCidr, parseIp } from '../src/origin.js';

const FX = JSON.parse(readFileSync(new URL('./tangd-fixture.json', import.meta.url)));
const fx = FX['P-256'];
const setText = (extra = {}) => JSON.stringify({ keys: [fx.sig, fx.exch], ...extra });
const APPROVERS = ['ops@example.org', 'oncall@example.org'];
const call = (path, init = {}, e = {}) => worker.fetch(new Request('http://w' + path, init), e, { waitUntil() {} });

test('parseCidr: IPv4 /8 to /32 and IPv6 /16 to /128, host bits zero, never v4-mapped or in 240.0.0.0/4', () => {
  for (const ok of ['10.0.0.0/8', '192.0.2.7/32', '203.0.113.0/24', '239.255.255.255/32', '2001::/16', '2001:db8::/32', '2001:db8::1/128', '::fffe:0:0/95']) {
    assert.doesNotThrow(() => parseCidr(ok), ok);
  }
  const bad = {
    '10.0.0.0/7': /\/8 to \/32/, '192.0.2.0/33': /\/8 to \/32/, '2000::/15': /\/16 to \/128/, '2001:db8::/129': /\/16 to \/128/,
    '192.0.2.1/24': /write 192\.0\.2\.0\/24$/, '2001:db8::1/64': /write 2001:db8::\/64$/, '2001:db8:1::/16': /write 2001::\/16$/,
    '::ffff:192.0.2.0/120': /v4-mapped/, '::ffff:c000:200/120': /v4-mapped/, '::ffff:0:0/96': /v4-mapped/,
    '240.0.0.0/8': /240\.0\.0\.0\/4/, '255.255.255.255/32': /240\.0\.0\.0\/4/,
    '192.0.2.0': /not an address/, 'x/24': /not an address/, '192.0.2.0/024x': /not an address/, '1::2::3/64': /not an address/,
  };
  for (const [s, why] of Object.entries(bad)) assert.throws(() => parseCidr(s), why, s);
  for (const s of [24, null, undefined, {}]) assert.throws(() => parseCidr(s), /not an address/);
  assert.deepEqual(parseCidr('192.0.2.0/24'), { v: 4, n: 0xc0000200n, len: 24 });
});

test('format writes RFC 5952 text, and parseIp folds both v4-mapped forms to IPv4', () => {
  const cases = { '2001:db8:0:0:1:0:0:1': '2001:db8::1:0:0:1', '2001:0:0:1:0:0:0:1': '2001:0:0:1::1', '0:0:0:0:0:0:0:0': '::',
    '0:0:0:0:0:0:0:1': '::1', '1:0:0:0:0:0:0:0': '1::', '2001:db8:0:1:1:1:1:1': '2001:db8:0:1:1:1:1:1', '2001:DB8::': '2001:db8::' };
  for (const [ip, want] of Object.entries(cases)) assert.equal(format(parseIp(ip)), want, ip);
  const v4 = parseIp('192.0.2.7');
  assert.deepEqual(v4, { v: 4, n: 0xc0000207n });
  assert.deepEqual(parseIp('::ffff:192.0.2.7'), v4);
  assert.deepEqual(parseIp('::FFFF:c000:207'), v4);
  assert.equal(parseIp('::192.0.2.7').v, 6);
  assert.equal(parseIp('64:ff9b::192.0.2.7').v, 6);
  for (const bad of ['1.2.3.256', '::ffff:1.2.3.256', '1::2::3', '1.2.3', '', null, '1:2:3:4:5:6:7:8:9']) assert.equal(parseIp(bad), null, bad);
});

test('parseSet takes allow and approvers, refuses unknown members, empty or long lists, and unsafe addresses', async () => {
  const s = parseSet(setText({ allow: ['192.0.2.0/24', '2001:db8::/48'], approvers: APPROVERS }));
  assert.deepEqual(s.allow, ['192.0.2.0/24', '2001:db8::/48']);
  assert.deepEqual(s.approvers, APPROVERS);
  assert.equal(s.nets.length, 2);
  assert.deepEqual(Object.keys(parseSet(setText())), ['sign', 'exch', 'curve']);
  assert.doesNotThrow(() => parseSet(setText({ allow: Array.from({ length: 32 }, (_, i) => `198.51.100.${i}/32`) })));
  assert.doesNotThrow(() => parseSet(setText({ approvers: ['a@example.org', 'b@example.org', 'c@example.org', 'd@example.org', 'e@example.org'] })));
  const bad = [
    { note: 1 }, { allow: [] }, { approvers: [] }, { allow: null }, { approvers: 'ops@example.org' },
    { allow: Array.from({ length: 33 }, (_, i) => `198.51.100.${i}/32`) },
    { approvers: ['a@example.org', 'b@example.org', 'c@example.org', 'd@example.org', 'e@example.org', 'f@example.org'] },
    { allow: ['192.0.2.1/24'] }, { approvers: ['ops@example.org', 'OPS@example.org'] },
    ...['ops', 'a@b', 'a b@example.org', 'x@example.org\r\nBcc: y@example.org', '"x"@example.org', 'x,y@example.org', 'x;y@example.org',
      'é@example.org', 'x@example.o', 'x@exa_mple.org', 'x@example.org>', '<x@example.org', 'x\\y@example.org', 7].map((a) => ({ approvers: [a] })),
  ];
  for (const extra of bad) assert.throws(() => parseSet(setText(extra)), JSON.stringify(extra));
  const errs = [], log = console.error;
  console.error = (...a) => errs.push(a.join(' '));
  try {
    assert.equal((await call('/gs/adv', {}, { TANG_KEY_GS: setText({ note: fx.exch.d }) })).status, 500);
    assert.equal(errs.length, 1);
    assert.ok(errs[0].includes('TANG_KEY_GS') && !errs[0].includes(fx.exch.d.slice(0, 8)));
  } finally { console.error = log; }
});

test('the policy and approve keys are HKDF keys of d that differ from each other and between sets', async () => {
  const mac = async (exch, info) => Buffer.from(await crypto.subtle.sign('HMAC', await derivedKey(exch, info), new Uint8Array(8))).toString('hex');
  const policy = await mac(fx.exch, 'keystone-policy-v1');
  assert.equal(policy, await mac(fx.exch, 'keystone-policy-v1'));
  assert.notEqual(policy, await mac(fx.exch, 'keystone-approve-v1'));
  assert.notEqual(policy, await mac(FX['P-521'].exch, 'keystone-policy-v1'));
  assert.equal(await policyTag(parseSet(setText())), null);
  const a = await policyTag(parseSet(setText({ approvers: APPROVERS })));
  assert.notEqual(a, await policyTag(parseSet(setText({ approvers: APPROVERS.slice(1) }))));
  assert.notEqual(a, await policyTag(parseSet(setText({ allow: ['192.0.2.0/24'], approvers: APPROVERS }))));
});

test('adv carries the version and policy headers only when probed, and is otherwise byte-identical to an ungated set', async () => {
  const e = { TANG_KEY_PLAIN: setText(), TANG_KEY_GATED: setText({ allow: ['192.0.2.0/24'], approvers: APPROVERS }), CF_VERSION_METADATA: { id: 'v-1' } };
  // ECDSA signatures differ per signing, so the gated set is compared with itself and, signature aside, with the plain one.
  const dump = async (r) => [r.status, [...r.headers].sort().join('|'), await r.text()];
  const unsigned = ([status, headers, body]) => [status, headers, { ...JSON.parse(body), signature: null }];
  const gated = await dump(await call('/gated/adv', {}, e));
  assert.deepEqual(unsigned(gated), unsigned(await dump(await call('/plain/adv', {}, e))));
  assert.deepEqual(await dump(await call('/gated/adv', { headers: { 'keystone-probe': 'yes' } }, e)), gated);
  const probe = { headers: { 'keystone-probe': '1' } };
  let r = await call('/plain/adv', probe, e);
  assert.equal(r.headers.get('keystone-version'), 'v-1');
  assert.equal(r.headers.get('keystone-policy'), null);
  r = await call('/gated/adv', probe, e);
  assert.equal(r.headers.get('keystone-version'), 'v-1');
  assert.equal(r.headers.get('keystone-policy'), await policyTag(parseSet(e.TANG_KEY_GATED)));
  r = await call('/gated/adv', probe, { TANG_KEY_GATED: e.TANG_KEY_GATED });
  assert.equal(r.headers.get('keystone-version'), null);
});
