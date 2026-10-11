import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker, { resetAlertState } from '../src/index.js';
import { derivedKey, parseSet, policyTag } from '../src/jwk.js';
import { format, parseCidr, parseIp } from '../src/origin.js';

const FX = JSON.parse(readFileSync(new URL('./tangd-fixture.json', import.meta.url)));
const fx = FX['P-256'];
const setText = (extra = {}) => JSON.stringify({ keys: [fx.sig, fx.exch], ...extra });
const APPROVERS = ['ops@example.org', 'oncall@example.org'];
const call = (path, init = {}, e = {}) => worker.fetch(new Request('http://w' + path, init), e, { waitUntil() {} });
const logged = [];
console.log = (line) => logged.push(JSON.parse(line));
const errors = [];
console.error = (...a) => errors.push(a.join(' '));

const kv = () => {
  const m = new Map();
  return {
    m, get: async (k) => m.get(k) ?? null, put: async (k, v) => void m.set(k, v), delete: async (k) => void m.delete(k),
    list: async ({ prefix }) => ({ keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })) }),
  };
};
let sent = [];
const subjects = () => sent.map((m) => m.raw.match(/^Subject: (.*)$/m)[1]);
const alerting = () => ({ UNLOCKS: kv(), ALERT: { send: async (m) => { sent.push(m); } }, ALERT_FROM: 'keystone@example.org', ALERT_TO: 'me@example.org' });
// A fresh isolate: alert state, logs and mail cleared.
const fresh = (e) => { resetAlertState(); logged.length = 0; errors.length = 0; sent = []; return e; };

async function rec(e, name, { ip, asn = 64500, headers = {}, body = fx.client, cf = {} } = {}) {
  const pending = [];
  const req = new Request(`https://tang.example.org/${name}/rec/${fx.kid}`, {
    method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body),
    headers: { 'content-type': 'application/jwk+json', ...(ip && { 'CF-Connecting-IP': ip }), ...headers },
  });
  Object.defineProperty(req, 'cf', { value: { asn, country: 'US', ...cf } });
  const r = await worker.fetch(req, e, { waitUntil: (p) => pending.push(p) });
  await Promise.all(pending);
  return r;
}
// Counts ECDH derivations, the only use of a set's exchange key.
function spyDerive() {
  const subtle = crypto.subtle, real = subtle.deriveBits, spy = { n: 0 };
  subtle.deriveBits = function (...a) { spy.n++; return real.apply(this, a); };
  spy.restore = () => { delete subtle.deriveBits; };
  return spy;
}
const refusedReply = async (r) => {
  assert.equal(r.status, 403);
  assert.equal(await r.text(), 'origin not admitted\n');
  assert.equal(r.headers.get('cache-control'), 'no-store');
};

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
  fresh();
  assert.equal((await call('/gs/adv', {}, { TANG_KEY_GS: setText({ note: fx.exch.d }) })).status, 500);
  assert.equal(errors.length, 1);
  assert.ok(errors[0].includes('TANG_KEY_GS') && !errors[0].includes(fx.exch.d.slice(0, 8)));
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

test('allow admits its prefixes at the /24 and /48 bounds, v4-mapped addresses included; a set with neither field admits all', async () => {
  const e = fresh({ TANG_KEY_PIN: setText({ allow: ['192.0.2.0/24', '2001:db8:1::/48', '10.0.0.0/8'] }), TANG_KEY_OPEN: setText() });
  for (const ip of ['192.0.2.0', '192.0.2.255', '::ffff:192.0.2.9', '::ffff:c000:209', '2001:db8:1::', '2001:db8:1:ffff:ffff:ffff:ffff:ffff']) {
    assert.equal((await rec(e, 'pin', { ip })).status, 200, ip);
  }
  for (const ip of ['192.0.1.255', '192.0.3.0', '2001:db8::1', '2001:db8:2::', '::192.0.2.9', '::a00:1']) await refusedReply(await rec(e, 'pin', { ip }));
  for (const opts of [{}, { ip: '240.0.0.1' }, { ip: '192.0.2.9', asn: 13335 }, { ip: 'nope' }]) {
    assert.equal((await rec(e, 'open', opts)).status, 200, JSON.stringify(opts));
  }
});

test('no address, 240.0.0.0/4 and AS13335 are refused even inside allow; kid, origin, body, admission run in that order', async () => {
  const e = fresh({ TANG_KEY_PIN: setText({ allow: ['192.0.2.0/24'] }) });
  for (const opts of [{}, { ip: 'nope' }, { ip: '240.0.0.1' }, { ip: '255.255.255.255' }, { ip: '192.0.2.9', asn: 13335 }]) {
    await refusedReply(await rec(e, 'pin', opts));
  }
  const spy = spyDerive();
  try {
    const kid = await worker.fetch(new Request(`https://tang.example.org/pin/rec/nope`, { method: 'POST', body: '{' }), e, { waitUntil() {} });
    assert.equal(kid.status, 404);
    await refusedReply(await rec(e, 'pin', { ip: '240.0.0.1', body: '{' }));
    assert.equal((await rec(e, 'pin', { ip: '198.51.100.9', body: '{' })).status, 400);
    await refusedReply(await rec(e, 'pin', { ip: '198.51.100.9' }));
    assert.equal(spy.n, 0);
    assert.equal((await rec(e, 'pin', { ip: '192.0.2.9' })).status, 200);
    assert.ok(spy.n > 0);
  } finally { spy.restore(); }
});

test('a refused origin never reaches ECDH, for every way of being refused', async () => {
  const e = fresh({ ...alerting(), TANG_KEY_PIN: setText({ allow: ['192.0.2.0/24'] }), TANG_KEY_ASK: setText({ approvers: APPROVERS }),
    GATE: { idFromName: () => assert.fail('Gate touched'), get: () => assert.fail('Gate touched') } });
  const spy = spyDerive();
  try {
    await refusedReply(await rec(e, 'pin', { ip: '198.51.100.9' }));
    await refusedReply(await rec(e, 'pin', { ip: '192.0.2.9', asn: 13335 }));
    await refusedReply(await rec(e, 'ask', { ip: '198.51.100.9', headers: { 'keystone-probe': '1' } }));
    await refusedReply(await rec(e, 'ask', {}));
    assert.equal(spy.n, 0);
  } finally { spy.restore(); }
});

test('a refusal mails a refused alert under the alert caps, logs once a minute, and never marks the source seen', async () => {
  mock.timers.enable({ apis: ['Date'], now: Date.parse('2026-10-01T00:00:00Z') });
  try {
    const e = fresh({ ...alerting(), TANG_KEY_PIN: setText({ allow: ['192.0.2.0/24'] }) });
    await rec(e, 'pin', { ip: '198.51.100.9' });
    await rec(e, 'pin', { ip: '198.51.100.10' });
    assert.deepEqual(subjects(), ['keystone: refused a recovery request from a new source for pin']);
    assert.match(sent[0].raw, /no key was released/);
    assert.deepEqual(logged, [{ event: 'refused', name: 'pin', ip: '198.51.100.9', asn: 64500, country: 'US', why: 'allow' }]);
    mock.timers.tick(60001);
    await rec(e, 'pin', { ip: '198.51.100.9', headers: { 'keystone-probe': '1' } });
    assert.equal(logged.length, 2);
    assert.equal(logged[1].why, 'allow');
    mock.timers.tick(3600 * 1000);
    await rec(e, 'pin', { ip: '203.0.113.9', headers: { 'keystone-probe': '1' } });
    assert.equal(sent.length, 1);
    e.TANG_KEY_PIN = setText({ allow: ['198.51.100.0/24'] });
    assert.equal((await rec(e, 'pin', { ip: '198.51.100.9' })).status, 200);
    assert.equal(subjects()[1], 'keystone: recovery request from a new source for pin');
    const quiet = fresh({ TANG_KEY_PIN: setText({ allow: ['192.0.2.0/24'] }) });
    await refusedReply(await rec(quiet, 'pin', { ip: '198.51.100.9' }));
    assert.equal(logged.length, 1);
  } finally { mock.timers.reset(); }
});

test('approvers without GATE, ALERT or ALERT_FROM fail closed: 403, one error per set per isolate; allow still admits', async () => {
  const full = { ...alerting(), GATE: {}, TANG_KEY_ASK: setText({ allow: ['192.0.2.0/24'], approvers: APPROVERS }) };
  for (const missing of ['GATE', 'ALERT', 'ALERT_FROM']) {
    const e = fresh({ ...full, [missing]: undefined });
    await refusedReply(await rec(e, 'ask', { ip: '198.51.100.9' }));
    await refusedReply(await rec(e, 'ask', { ip: '203.0.113.9' }));
    assert.equal(errors.length, 1, missing);
    assert.match(errors[0], /^ask: approvals unavailable/);
    assert.equal(sent.length, 0);
    assert.equal((await rec(e, 'ask', { ip: '192.0.2.9' })).status, 200);
  }
});
