import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker, { resetAlertState } from '../src/index.js';
import { derivedKey, parseSet, policyTag } from '../src/jwk.js';
import { format, parseCidr, parseIp, unadmittable } from '../src/origin.js';
import { Gate, approveKey, sign } from '../src/gate.js';

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

async function rec(e, name, { ip, asn = 64500, headers = {}, body = fx.client, cf = {}, base = 'https://tang.example.org' } = {}) {
  const pending = [];
  const req = new Request(`${base}/${name}/rec/${fx.kid}`, {
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

test('an allow-only set without GATE says so to a probed adv; with GATE, and unprobed, it does not', async () => {
  const gateHeader = async (e, headers) => (await call('/ask/adv', { headers }, e)).headers.get('keystone-gate');
  const full = gateEnv({ TANG_KEY_ASK: setText({ allow: ['192.0.2.0/24'] }) });
  const e = fresh({ ...full, GATE: undefined });
  assert.equal(await gateHeader(e, { 'keystone-probe': '1' }), 'unavailable');
  assert.equal(await gateHeader(e, {}), null);
  assert.equal(await gateHeader(full, { 'keystone-probe': '1' }), null);
  assert.equal(await gateHeader(fresh({ TANG_KEY_ASK: setText() }), { 'keystone-probe': '1' }), null);
});

test('approvers without GATE, ALERT or ALERT_FROM fail closed: 403, one error per set per isolate, a probed adv says so; allow still admits', async () => {
  const gateHeader = async (e, headers) => (await call('/ask/adv', { headers }, e)).headers.get('keystone-gate');
  for (const missing of ['GATE', 'ALERT', 'ALERT_FROM']) {
    const full = gateEnv({ TANG_KEY_ASK: setText({ allow: ['192.0.2.0/24'], approvers: APPROVERS }) });
    const e = fresh({ ...full, [missing]: undefined });
    assert.equal(await gateHeader(e, { 'keystone-probe': '1' }), 'unavailable', missing);
    assert.equal(await gateHeader(e, {}), null);
    assert.equal(await gateHeader(full, { 'keystone-probe': '1' }), null);
    await refusedReply(await rec(e, 'ask', { ip: '198.51.100.9' }));
    await refusedReply(await rec(e, 'ask', { ip: '203.0.113.9' }));
    assert.equal(errors.length, 1, missing);
    assert.match(errors[0], /^ask: approvals unavailable/);
    assert.equal(sent.length, 0);
    assert.equal(full.misses, 0);
    assert.equal((await rec(e, 'ask', { ip: '192.0.2.9' })).status, 200);
  }
});

// The Gate on a Map-backed storage that clones like the real one; e.store is that storage, e.misses counts calls. Calls
// into the Gate are serialized except while it awaits a send, as the runtime's input gate does.
function store() {
  const m = new Map(), c = structuredClone;
  return {
    m, get: async (k) => c(m.get(k)), put: async (k, v) => void m.set(k, c(v)),
    delete: async (k) => { for (const x of [].concat(k)) m.delete(x); },
    list: async ({ prefix = '' } = {}) => new Map([...m].filter(([k]) => k.startsWith(prefix)).sort().map(([k, v]) => [k, c(v)])),
  };
}
function gateEnv(extra = {}) {
  const e = { ...alerting(), TANG_KEY_ASK: setText({ approvers: APPROVERS }), ...extra };
  let gate = Promise.resolve(), release;
  const acquire = async () => { const prev = gate; let r; gate = new Promise((x) => { r = x; }); await prev; release = r; };
  const alert = { send: async (m) => { release(); try { return await e.ALERT.send(m); } finally { await acquire(); } } };
  const storage = store(), g = new Gate({ storage }, new Proxy(e, { get: (t, k) => (k === 'ALERT' ? alert : t[k]) }));
  for (const m of ['miss', 'view', 'decide']) {
    const real = g[m].bind(g);
    g[m] = async (...a) => { if (m === 'miss') e.misses++; await acquire(); try { return await real(...a); } finally { release(); } };
  }
  e.misses = 0;
  e.GATE = { idFromName: (n) => (assert.equal(n, 'gate'), n), get: () => g };
  e.store = storage;
  return fresh(e);
}
const T0 = Date.parse('2026-10-01T00:00:00Z');
const withClock = (fn) => async () => {
  mock.timers.enable({ apis: ['Date'], now: T0 });
  try { await fn(); } finally { mock.timers.reset(); }
};
const pending = (e, origin, name = 'ask') => e.store.m.get(`p:${name}:${origin}`);
const link = async (e, origin, { a = APPROVERS[0], name = 'ask', key = approveKey(fx.exch), p = pending(e, origin, name) } = {}) =>
  `/${name}/approve/${await sign(key, name, { o: origin, p: p.pid, e: p.expires, a })}`;
const open = (e, path, init = {}) => worker.fetch(new Request(`https://tang.example.org${path}`, init), e, { waitUntil() {} });
const post = (e, path, form, headers = {}) => open(e, path, {
  method: 'POST', body: typeof form === 'string' ? form : new URLSearchParams(form).toString(),
  headers: { origin: 'https://tang.example.org', 'content-type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '203.0.113.50', ...headers },
});
const HOME = '198.51.100.9', NET = '198.51.100.0/24';

test('a miss on a set with approvers is held: one pending, a cached answer, and a GET that shows it and changes nothing', withClock(async () => {
  const e = gateEnv();
  await refusedReply(await rec(e, 'ask', { ip: HOME, cf: { asOrganization: 'Example <ISP>', city: 'Springfield', colo: 'ORD' } }));
  await refusedReply(await rec(e, 'ask', { ip: '198.51.100.77' }));
  assert.equal(e.misses, 1);
  const p = pending(e, NET);
  assert.deepEqual([p.state, p.created, p.expires, p.info.org, p.info.base], ['open', T0, T0 + 12 * 3600e3, 'Example <ISP>', 'https://tang.example.org']);
  assert.deepEqual(logged, [{ event: 'held', name: 'ask', origin: NET, asn: '64500', country: 'US' }]);
  mock.timers.tick(5001);
  await refusedReply(await rec(e, 'ask', { ip: HOME }));
  assert.equal(e.misses, 2);
  assert.equal(pending(e, NET).pid, p.pid);
  const before = JSON.stringify([...e.store.m]);
  const r = await open(e, await link(e, NET));
  assert.equal(r.status, 200);
  assert.equal(JSON.stringify([...e.store.m]), before);
  assert.equal(r.headers.get('content-security-policy'), "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  for (const [h, v] of [['cache-control', 'no-store'], ['x-content-type-options', 'nosniff'], ['referrer-policy', 'same-origin']]) assert.equal(r.headers.get(h), v);
  assert.equal(r.headers.get('set-cookie'), null);
  const html = await r.text();
  assert.match(html, /Example &#60;ISP&#62;/);
  assert.match(html, /Springfield/);
  assert.match(html, /name="confirm"/);
  assert.match(html, /value="deny"/);
  assert.doesNotMatch(html, /<script|<link|@import|url\(|<img|src=/i);
}));

test('approve needs the page\'s Origin, a small form body and the typed name; then rec is served for 10 minutes', withClock(async () => {
  const e = gateEnv();
  await rec(e, 'ask', { ip: HOME });
  const url = await link(e, NET, { a: APPROVERS[1] });
  for (const [form, headers, status] of [
    [{ decision: 'approve' }, {}, 400], [{ decision: 'approve', confirm: 'other' }, {}, 400], [{ decision: 'maybe' }, {}, 400],
    [{ decision: 'approve', confirm: 'ask' }, { origin: 'https://evil.example' }, 403], [{ decision: 'approve', confirm: 'ask' }, { origin: 'null' }, 403],
    [{ decision: 'approve', confirm: 'ask' }, { 'content-type': 'text/plain' }, 400],
    [{ decision: 'approve', confirm: 'ask', pad: 'x'.repeat(256) }, {}, 400],
  ]) assert.equal((await post(e, url, form, headers)).status, status, JSON.stringify([form, headers]));
  const bare = await open(e, url, { method: 'POST', body: 'decision=approve&confirm=ask', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal(bare.status, 403);
  assert.equal(pending(e, NET).state, 'open');
  const r = await post(e, url, { decision: 'approve', confirm: 'ask' });
  assert.equal(r.status, 200);
  assert.match(await r.text(), /oncall@example\.org/);
  assert.deepEqual(logged.at(-1), { event: 'approved', name: 'ask', origin: NET, approver: APPROVERS[1], ip: '203.0.113.50', asn: null });
  assert.equal((await rec(e, 'ask', { ip: '198.51.100.200' })).status, 200);
  mock.timers.tick(10 * 60e3 - 1);
  assert.equal((await rec(e, 'ask', { ip: HOME })).status, 200);
  const pid = pending(e, NET).pid;
  mock.timers.tick(1);
  await refusedReply(await rec(e, 'ask', { ip: HOME }));
  assert.equal(pending(e, NET).state, 'open');
  assert.notEqual(pending(e, NET).pid, pid);
}));

test('an approval in a pending\'s last minutes still grants the full 10 minutes', withClock(async () => {
  const e = gateEnv();
  await rec(e, 'ask', { ip: HOME });
  const url = await link(e, NET);
  mock.timers.tick(12 * 3600e3 - 60e3);
  assert.equal((await post(e, url, { decision: 'approve', confirm: 'ask' })).status, 200);
  mock.timers.tick(10 * 60e3 - 1);
  assert.equal((await rec(e, 'ask', { ip: HOME })).status, 200);
  assert.equal(pending(e, NET).state, 'approved');
}));

test('a decided or replaced pending answers 409, an expired token 410; deny holds, and approve still works after it', withClock(async () => {
  const e = gateEnv();
  await rec(e, 'ask', { ip: HOME });
  const url = await link(e, NET);
  assert.equal((await post(e, url, { decision: 'deny' })).status, 200);
  assert.equal(pending(e, NET).state, 'denied');
  assert.equal((await post(e, url, { decision: 'deny' })).status, 409);
  mock.timers.tick(5001);
  const misses = e.misses;
  await refusedReply(await rec(e, 'ask', { ip: HOME }));
  await refusedReply(await rec(e, 'ask', { ip: HOME }));
  assert.equal(e.misses, misses + 1);
  assert.deepEqual(logged.filter((l) => l.event === 'refused').map((l) => l.why), ['denied']);
  assert.match(await (await open(e, url)).text(), /Denied at .*value="approve"/s);
  assert.equal((await post(e, url, { decision: 'approve', confirm: 'ask' })).status, 200);
  assert.equal((await rec(e, 'ask', { ip: HOME })).status, 200);
  assert.equal((await post(e, url, { decision: 'approve', confirm: 'ask' })).status, 409);
  assert.equal((await post(e, url, { decision: 'deny' })).status, 409);
  mock.timers.tick(10 * 60e3 + 1);
  await rec(e, 'ask', { ip: HOME });
  assert.equal((await open(e, url)).status, 409);
  assert.equal((await post(e, url, { decision: 'approve', confirm: 'ask' })).status, 409);
  const current = await link(e, NET);
  mock.timers.tick(12 * 3600e3 - 1);
  assert.equal((await open(e, current)).status, 200);
  mock.timers.tick(1);
  assert.equal((await open(e, current)).status, 410);
  assert.equal((await post(e, current, { decision: 'approve', confirm: 'ask' })).status, 410);
  const pid = pending(e, NET).pid;
  await rec(e, 'ask', { ip: HOME });
  assert.notEqual(pending(e, NET).pid, pid);
}));

test('a token tampered in any part, signed for another set, or naming a revoked set or one without approvers is 404', withClock(async () => {
  const e = gateEnv({ TANG_KEY_OTHER: setText({ approvers: APPROVERS }), TANG_KEY_PIN: setText({ allow: ['192.0.2.0/24'] }), TANG_KEY_OPEN: setText() });
  await rec(e, 'ask', { ip: HOME });
  const url = await link(e, NET);
  const [v, payload, mac] = url.split('/').pop().split('.');
  const flip = (x) => x.slice(0, -2) + (x.at(-2) === 'A' ? 'B' : 'A') + x.at(-1);
  for (const t of [`v2.${payload}.${mac}`, `v1.${flip(payload)}.${mac}`, `v1.${payload}.${flip(mac)}`, `v1.${payload}`, 'x', `${v}.${payload}.${mac}.x`]) {
    assert.equal((await open(e, `/ask/approve/${t}`)).status, 404, t);
  }
  assert.equal((await open(e, await link(e, NET, { key: approveKey(FX['P-521'].exch) }))).status, 404);
  for (const name of ['other', 'pin', 'open']) {
    assert.equal((await open(e, url.replace('/ask/', `/${name}/`))).status, 404, name);
    assert.equal((await open(e, await link(e, NET, { name, p: pending(e, NET) }))).status, name === 'other' ? 409 : 404, name);
  }
  assert.equal((await open(e, url)).status, 200);
  delete e.TANG_KEY_ASK;
  assert.equal((await open(e, url)).status, 404);
}));

test('a set takes 3 open pendings; further origins are capped until one is decided', withClock(async () => {
  const e = gateEnv({ TANG_KEY_OTHER: setText({ approvers: APPROVERS }) });
  for (const ip of ['198.51.100.1', '203.0.113.1', '192.0.2.1']) await rec(e, 'ask', { ip });
  await refusedReply(await rec(e, 'ask', { ip: '2001:db8::1' }));
  assert.equal(pending(e, '2001:db8:0::/48'), undefined);
  const misses = e.misses;
  await refusedReply(await rec(e, 'ask', { ip: '2001:db8::2' }));
  assert.equal(e.misses, misses);
  await rec(e, 'other', { ip: '2001:db8::1' });
  assert.equal(pending(e, '2001:db8:0::/48', 'other').state, 'open');
  assert.equal((await post(e, await link(e, '203.0.113.0/24'), { decision: 'deny' })).status, 200);
  mock.timers.tick(5001);
  await rec(e, 'ask', { ip: '2001:db8::1' });
  assert.equal(pending(e, '2001:db8:0::/48').state, 'open');
  const html = await (await open(e, await link(e, '2001:db8:0::/48'))).text();
  assert.match(html, /2 other origin\(s\) are asking for this set.*deny them all/s);
  mock.timers.tick(12 * 3600e3);
  await rec(e, 'ask', { ip: '203.0.113.200' });
  const h = (T0 + 12 * 3600e3) / 3600e3;
  assert.deepEqual([...e.store.m.keys()].sort(), [`m:${h}`, `m:${h}:ask`, 'p:ask:203.0.113.0/24']);
}));

test('a capped answer is cached per origin, so a granted origin is served while strangers keep the set capped', withClock(async () => {
  const e = gateEnv();
  await rec(e, 'ask', { ip: HOME });
  await post(e, await link(e, NET), { decision: 'approve', confirm: 'ask' });
  for (const ip of ['203.0.113.1', '192.0.2.1', '2001:db8::1']) await rec(e, 'ask', { ip });
  await refusedReply(await rec(e, 'ask', { ip: '2001:db8:5::1' }));
  assert.equal((await rec(e, 'ask', { ip: HOME })).status, 200);
}));

test('a probed miss never reaches the Gate, a throwing Gate fails closed, and a grant raises the served alert', withClock(async () => {
  const e = gateEnv();
  await refusedReply(await rec(e, 'ask', { ip: HOME, headers: { 'keystone-probe': '1' } }));
  assert.equal(e.misses, 0);
  e.store.get = async () => { throw new Error('storage down'); };
  await refusedReply(await rec(e, 'ask', { ip: HOME }));
  await refusedReply(await rec(e, 'ask', { ip: '203.0.113.9' }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /^ask: approvals unavailable, refusing new origins: storage down$/);
  const g = gateEnv();
  await rec(g, 'ask', { ip: HOME });
  await post(g, await link(g, NET), { decision: 'approve', confirm: 'ask' });
  sent = [];
  assert.equal((await rec(g, 'ask', { ip: HOME })).status, 200);
  assert.deepEqual(subjects(), ['keystone: recovery request from a new source for ask']);
}));

test('a probed rec outside a set\'s allow list is refused in every gate state, and mails no refusal alert where an unprobed one does', withClock(async () => {
  const probe = { 'keystone-probe': '1' };
  const gated = (extra) => gateEnv({ TANG_KEY_ASK: setText({ allow: ['192.0.2.0/24'], approvers: APPROVERS, ...extra }) });
  const approved = gated();
  await rec(approved, 'ask', { ip: HOME });
  await post(approved, await link(approved, NET), { decision: 'approve', confirm: 'ask' });
  assert.equal((await rec(approved, 'ask', { ip: HOME })).status, 200);
  const throwing = gated();
  throwing.store.get = async () => { throw new Error('storage down'); };
  const states = {
    allowOnly: fresh({ ...alerting(), TANG_KEY_ASK: setText({ allow: ['192.0.2.0/24'] }) }),
    gate: gated(),
    approved,
    unbound: fresh({ ...alerting(), GATE: undefined, TANG_KEY_ASK: setText({ allow: ['192.0.2.0/24'], approvers: APPROVERS }) }),
    throwing,
  };
  for (const [state, e] of Object.entries(states)) {
    for (const [ip, asn] of [[HOME, 64500], ['203.0.113.9', 64500], ['198.51.100.9', 13335], [undefined, 64500]]) {
      await refusedReply(await rec(e, 'ask', { ip, asn, headers: probe }));
    }
    assert.equal((await rec(e, 'ask', { ip: '192.0.2.9', headers: probe })).status, 200, `${state}: an allowed origin is served as unprobed`);
  }
  for (const [state, e] of [['allowOnly', states.allowOnly], ['gate', gated()]]) {
    for (const ip of ['198.51.100.9', undefined]) {
      sent = [];
      await rec(e, 'ask', { ip, asn: ip ? 64500 : 13335, headers: probe });
      assert.equal(sent.length, 0, `${state}: probed`);
    }
  }
  for (const [ip, asn, why] of [['198.51.100.9', 64500, 'allow'], ['198.51.100.9', 13335, 'origin']]) {
    const e = fresh({ ...alerting(), TANG_KEY_ASK: setText({ allow: ['192.0.2.0/24'] }) });
    await rec(e, 'ask', { ip, asn });
    assert.deepEqual(subjects(), ['keystone: refused a recovery request from a new source for ask'], why);
  }
}));

test('a Gate call that never answers is refused as unavailable, not left hanging', { timeout: 5000 }, async () => {
  mock.timers.enable({ apis: ['setTimeout', 'Date'], now: T0 });
  try {
    const e = gateEnv();
    e.GATE = { idFromName: () => 'gate', get: () => ({ miss: () => new Promise(() => {}) }) };
    const pending = rec(e, 'ask', { ip: HOME });
    await new Promise((r) => setImmediate(r));
    mock.timers.tick(60000);
    await refusedReply(await pending);
    assert.match(errors[0], /^ask: approvals unavailable, refusing new origins: /);
    assert.equal(sent.length, 0);
  } finally { mock.timers.reset(); }
});

const linkIn = (m) => m.raw.match(/^https:\/\/tang\.example\.org(\/[a-z0-9-]+\/approve\/\S+)\r$/m)?.[1];
const mailTo = (e, fn) => { e.ALERT = { send: fn }; return e; };
const payload = (path) => JSON.parse(Buffer.from(path.split('.')[1], 'base64url'));

test('a held origin mails each approver once, in ASCII, with their own link, and no unlock alert', withClock(async () => {
  const e = gateEnv();
  await rec(e, 'ask', { ip: HOME, cf: { asOrganization: 'Exämple\r\nBcc: x@example.net', city: 'Zürich', colo: 'ZRH', country: 'CH' } });
  mock.timers.tick(5001);
  await rec(e, 'ask', { ip: HOME });
  assert.deepEqual(sent.map((m) => [m.from, m.to]), APPROVERS.map((to) => ['keystone@example.org', to]));
  assert.deepEqual(subjects(), Array(2).fill('keystone: unlock ask from 198.51.100.0/24 (Ex?mple??Bcc: x@example.net, Z?rich)?'));
  for (const m of sent) {
    assert.match(m.raw, /^[\x00-\x7f]*$/);
    assert.doesNotMatch(m.raw, /^Bcc:/m);
    assert.match(m.raw, /nothing changes until an approver presses a button/);
    assert.match(m.raw, /any machine in 198\.51\.100\.0\/24 recover ask for 10 minutes/);
    assert.match(m.raw, /deny, and revoke the set/);
    assert.match(m.raw, /colo: ZRH/);
  }
  const [l0, l1] = sent.map(linkIn);
  assert.notEqual(l0, l1);
  const before = JSON.stringify([...e.store.m]);
  assert.equal((await open(e, l0)).status, 200);
  assert.equal(JSON.stringify([...e.store.m]), before);
  await rec(e, 'ask', { ip: '203.0.113.9' });
  assert.match(sent.at(-1).raw, /1 other origin\(s\) are asking for this set:\r\n  198\.51\.100\.0\/24  AS64500 Ex\?mple\?\?Bcc/);
  assert.equal((await post(e, l1, { decision: 'approve', confirm: 'ask' })).status, 200);
  assert.equal(logged.at(-1).approver, APPROVERS[1]);
}));

test('concurrent misses send one message per approver; a failed send is logged and retried by a miss after 5, then 10 minutes', withClock(async () => {
  const e = mailTo(gateEnv(), async (m) => { sent.push(m); await new Promise((r) => setTimeout(r, 5)); });
  await Promise.all([rec(e, 'ask', { ip: HOME }), rec(e, 'ask', { ip: '198.51.100.10' }), rec(e, 'ask', { ip: '198.51.100.11' })]);
  assert.equal(sent.length, 2);
  const tries = [], up = new Set();
  const f = mailTo(gateEnv(), async (m) => {
    tries.push(m.to);
    if (!up.has(m.to)) throw new Error('E_DESTINATION_NOT_VERIFIED');
  });
  await rec(f, 'ask', { ip: HOME });
  assert.deepEqual(tries, APPROVERS);
  assert.deepEqual(errors, APPROVERS.map((to) => `approval mail to ${to} for ask failed: E_DESTINATION_NOT_VERIFIED`));
  mock.timers.tick(5 * 60e3 - 1);
  await rec(f, 'ask', { ip: HOME });
  assert.equal(tries.length, 2);
  up.add(APPROVERS[0]);
  mock.timers.tick(5000);
  await rec(f, 'ask', { ip: HOME });
  assert.deepEqual(tries.slice(2), APPROVERS);
  mock.timers.tick(5000);
  await rec(f, 'ask', { ip: HOME });
  assert.equal(tries.length, 4);
  up.add(APPROVERS[1]);
  mock.timers.tick(10 * 60e3);
  await rec(f, 'ask', { ip: HOME });
  assert.deepEqual(tries.slice(4), [APPROVERS[1]]);
  const puts = [], put = f.store.put;
  f.store.put = async (k, v) => { puts.push(k); return put(k, v); };
  mock.timers.tick(60 * 60e3);
  await rec(f, 'ask', { ip: HOME });
  assert.equal(tries.length, 5);
  assert.deepEqual(puts, []);
  assert.deepEqual(pending(f, NET).mail.sent, { [APPROVERS[0]]: true, [APPROVERS[1]]: true });
}));

test('a capped set mails each approver one notice naming the refused origin and listing the open ones with their own links', withClock(async () => {
  const e = gateEnv();
  const origins = ['198.51.100.1', '203.0.113.1', '192.0.2.1'];
  for (const ip of origins) await rec(e, 'ask', { ip });
  sent = [];
  await rec(e, 'ask', { ip: '2001:db8::1' });
  await rec(e, 'ask', { ip: '2001:db8:7::1' });
  mock.timers.tick(5001);
  await rec(e, 'ask', { ip: '2001:db8:8::1' });
  assert.deepEqual(sent.map((m) => m.to), APPROVERS);
  assert.deepEqual(subjects(), Array(2).fill('keystone: ask has 3 origins waiting; new ones are refused'));
  assert.equal(logged.filter((l) => l.event === 'capped').length, 1);
  for (const [a, m] of sent.entries()) {
    const links = [...m.raw.matchAll(/https:\/\/tang\.example\.org(\/ask\/approve\/\S+)\r/g)].map((x) => x[1]);
    assert.equal(links.length, 3);
    for (const t of links.map(payload)) assert.deepEqual([t.e, t.a], [pending(e, t.o).expires, APPROVERS[a]]);
    assert.match(m.raw, /deny them all and revoke the set/);
    assert.match(m.raw, /so this origin was refused, as is any other new one until one is decided:\r\n\r\n  2001:db8:0::\/48  AS64500 .*\r\n\r\nThe origins waiting are not that one/);
    assert.equal((await post(e, links[a], { decision: 'deny' })).status, 200);
    assert.equal(logged.at(-1).approver, APPROVERS[a]);
  }
}));

test('a set that spends its share of 5 messages an hour per approver leaves another set\'s held host its mail', withClock(async () => {
  const five = ['a@example.org', 'b@example.org', 'c@example.org', 'd@example.org', 'e@example.org'];
  const e = gateEnv({ TANG_KEY_ASK: setText({ approvers: five }), TANG_KEY_OTHER: setText({ approvers: APPROVERS }) });
  for (const ip of ['198.51.100.1', '203.0.113.1', '192.0.2.1', '2001:db8::1']) await rec(e, 'ask', { ip });
  assert.equal(sent.length, 20);
  for (const [origin, net] of [['198.51.100.0/24', '2001:db8:1::'], ['203.0.113.0/24', '2001:db8:2::']]) {
    assert.equal((await post(e, await link(e, origin, { a: five[0] }), { decision: 'deny' })).status, 200);
    await rec(e, 'ask', { ip: `${net}1` });
    assert.equal(pending(e, `${net}/48`).state, 'open');
  }
  assert.equal(sent.length, 25);
  await rec(e, 'other', { ip: HOME });
  assert.deepEqual(sent.slice(25).map((m) => m.to), APPROVERS);
  mock.timers.tick(3600e3);
  await rec(e, 'ask', { ip: '2001:db8:2::1' });
  assert.deepEqual(sent.slice(27).map((m) => m.to), five);
}));

test('at most 40 messages an hour across all sets, notices included; held mail goes out once the hour turns', withClock(async () => {
  const five = ['a@example.org', 'b@example.org', 'c@example.org', 'd@example.org', 'e@example.org'];
  const e = gateEnv(Object.fromEntries(['ASK', 'OTHER', 'THIRD'].map((n) => [`TANG_KEY_${n}`, setText({ approvers: five })])));
  for (const name of ['ask', 'other']) for (const ip of ['198.51.100.1', '203.0.113.1', '192.0.2.1']) await rec(e, name, { ip });
  for (const ip of ['198.51.100.1', '203.0.113.1']) await rec(e, 'third', { ip });
  assert.equal(sent.length, 40);
  await rec(e, 'third', { ip: '192.0.2.1' });
  await rec(e, 'ask', { ip: '2001:db8::1' });
  assert.equal(sent.length, 40);
  assert.equal(e.store.m.get('c:ask').expires, T0 + 5 * 60e3);
  mock.timers.tick(3600e3);
  await rec(e, 'third', { ip: '192.0.2.1' });
  assert.equal(sent.length, 45);
  assert.deepEqual(sent.slice(40).map((m) => m.to), five);
  await rec(e, 'ask', { ip: '2001:db8::1' });
  assert.deepEqual(subjects().slice(45), Array(5).fill('keystone: ask has 3 origins waiting; new ones are refused'));
  assert.ok(e.store.m.get('c:ask'));
}));

test('held mail that keeps failing is retried after 5, 10, 20, 40, then every 60 minutes while the pending lives', withClock(async () => {
  let up = false, tries = 0;
  const e = mailTo(gateEnv(), async (m) => { tries++; if (!up) throw new Error('E_DESTINATION_NOT_VERIFIED'); sent.push(m); });
  await rec(e, 'ask', { ip: HOME });
  for (const wait of [5, 10, 20, 40, 60, 60]) {
    const before = tries;
    mock.timers.tick(wait * 60e3 - 5001);
    await rec(e, 'ask', { ip: HOME });
    assert.equal(tries, before, String(wait));
    mock.timers.tick(5001);
    await rec(e, 'ask', { ip: HOME });
    assert.equal(tries, before + 2, String(wait));
  }
  up = true;
  mock.timers.tick(3600e3);
  await rec(e, 'ask', { ip: HOME });
  assert.deepEqual(sent.map((m) => m.to), APPROVERS);
}));

test('a failed send is refunded to the hourly cap; a notice that never went out is retried after 5 minutes', withClock(async () => {
  const e = mailTo(gateEnv(), async () => { throw new Error('E_DESTINATION_NOT_VERIFIED'); });
  await rec(e, 'ask', { ip: HOME });
  mock.timers.tick(5 * 60e3);
  await rec(e, 'ask', { ip: HOME });
  assert.equal(errors.length, 4);
  for (const k of [`m:${T0 / 3600e3}`, `m:${T0 / 3600e3}:ask`]) assert.equal(e.store.m.get(k).n, 0);
  for (const ip of ['203.0.113.1', '192.0.2.1']) await rec(e, 'ask', { ip });
  errors.length = 0;
  await rec(e, 'ask', { ip: '2001:db8::1' });
  assert.equal(errors.length, 2);
  for (let i = 1; i <= 10; i++) {
    mock.timers.tick(5001);
    await rec(e, 'ask', { ip: `2001:db8:${i}::1` });
  }
  assert.equal(errors.length, 2);
  assert.equal(logged.filter((l) => l.event === 'capped').length, 0);
  e.ALERT = { send: async (m) => { sent.push(m); } };
  mock.timers.tick(5 * 60e3 - 10 * 5001);
  await rec(e, 'ask', { ip: '2001:db8::1' });
  assert.deepEqual(sent.map((m) => m.to), APPROVERS);
  for (const k of [`m:${T0 / 3600e3}`, `m:${T0 / 3600e3}:ask`]) assert.equal(e.store.m.get(k).n, 2);
  assert.equal(e.store.m.get('c:ask').expires, Date.now() + 12 * 3600e3);
  const g = e.GATE.get(), set = { approvers: APPROVERS };
  for (let i = 2; i < 10; i++) assert.ok(await g.budget('ask', set, T0));
  assert.equal(await g.budget('ask', set, T0), false);
  await g.budget('ask', set, T0, -1);
  assert.ok(await g.budget('ask', set, T0));
}));

test('concurrent capped misses send one notice per approver', withClock(async () => {
  const e = mailTo(gateEnv(), async (m) => { sent.push(m); await new Promise((r) => setTimeout(r, 5)); });
  for (const ip of ['198.51.100.1', '203.0.113.1', '192.0.2.1']) await rec(e, 'ask', { ip });
  sent = [];
  await Promise.all(['2001:db8::1', '2001:db8:7::1', '2001:db8:8::1'].map((ip) => rec(e, 'ask', { ip })));
  assert.deepEqual(sent.map((m) => m.to), APPROVERS);
}));

test('a send that times out keeps its unit of the hourly cap, since it may yet be delivered', withClock(async () => {
  mock.timers.reset();
  mock.timers.enable({ apis: ['Date', 'setTimeout'], now: T0 });
  let calls = 0;
  const e = mailTo(gateEnv(), () => { calls++; return new Promise(() => {}); });
  const held = rec(e, 'ask', { ip: HOME });
  for (const n of [1, 2]) {
    for (let i = 0; calls < n && i < 1000; i++) await new Promise(setImmediate);
    mock.timers.tick(10000);
  }
  await held;
  assert.deepEqual(errors, APPROVERS.map((to) => `approval mail to ${to} for ask failed: send timed out`));
  for (const k of [`m:${T0 / 3600e3}`, `m:${T0 / 3600e3}:ask`]) assert.equal(e.store.m.get(k).n, 2);
}));

test('240.0.0.0/4 is refused from its first address, as is AS13335 or a missing ASN; the alert says the origin is never admitted', async () => {
  assert.equal(unadmittable(parseIp('240.0.0.0'), 64500), true);
  assert.equal(unadmittable(parseIp('239.255.255.255'), 64500), false);
  for (const asn of [13335, undefined, null, '64500', NaN]) assert.equal(unadmittable(parseIp('192.0.2.9'), asn), true, String(asn));
  const e = fresh({ ...alerting(), TANG_KEY_PIN: setText({ allow: ['192.0.2.0/24'] }), TANG_KEY_PIN2: setText({ allow: ['192.0.2.0/24'] }) });
  await refusedReply(await rec(e, 'pin', { ip: '240.0.0.0' }));
  await refusedReply(await rec(e, 'pin', { ip: '192.0.2.9', cf: { asn: undefined } }));
  assert.equal((await rec(e, 'pin', { ip: '192.0.2.9' })).status, 200);
  await rec(e, 'pin2', { ip: '198.51.100.9' });
  const [never, moved] = sent.map((m) => m.raw);
  assert.match(never, /never admitted\. If this is the host, it must egress elsewhere\. If it is not the host/);
  assert.doesNotMatch(never, /allow list/);
  assert.match(moved, /If the host moved, add its prefix to the set's allow list\. If it is not the host/);
});

test('an approve token signed under the policy key is 404, and a policy tag is no approve-key MAC', withClock(async () => {
  const e = gateEnv();
  await rec(e, 'ask', { ip: HOME });
  assert.equal((await open(e, await link(e, NET, { key: derivedKey(fx.exch, 'keystone-policy-v1') }))).status, 404);
  assert.equal((await open(e, await link(e, NET))).status, 200);
  const bytes = new TextEncoder().encode(JSON.stringify([null, APPROVERS]));
  const mac = Buffer.from(await crypto.subtle.sign('HMAC', await approveKey(fx.exch), bytes)).toString('base64url');
  assert.notEqual(await policyTag(parseSet(setText({ approvers: APPROVERS }))), mac);
}));

test('an approve link takes GET and POST alone: PUT, DELETE, PATCH and HEAD are 405 and change nothing', withClock(async () => {
  const e = gateEnv();
  await rec(e, 'ask', { ip: HOME });
  const url = await link(e, NET), before = JSON.stringify([...e.store.m]);
  const form = { body: 'decision=approve&confirm=ask', headers: { origin: 'https://tang.example.org', 'content-type': 'application/x-www-form-urlencoded' } };
  for (const method of ['PUT', 'DELETE', 'PATCH']) assert.equal((await open(e, url, { method, ...form })).status, 405, method);
  assert.equal((await open(e, url, { method: 'HEAD' })).status, 405);
  assert.equal(JSON.stringify([...e.store.m]), before);
}));

test('the Gate holds a pending to its own expiry whatever a token says, and a mailed link expires with its pending', withClock(async () => {
  const e = gateEnv();
  await rec(e, 'ask', { ip: HOME });
  const p = pending(e, NET);
  assert.deepEqual(sent.map((m) => payload(linkIn(m)).e), [p.expires, p.expires]);
  const late = await link(e, NET, { p: { pid: p.pid, expires: p.expires + 3600e3 } });
  assert.equal((await open(e, late)).status, 200);
  mock.timers.tick(12 * 3600e3);
  assert.equal((await open(e, late)).status, 409);
  assert.equal((await post(e, late, { decision: 'approve', confirm: 'ask' })).status, 409);
  assert.equal(pending(e, NET).state, 'open');
}));

test('a send that returns after its pending was replaced leaves the new pending unmarked', withClock(async () => {
  let entered, finish, n = 0;
  const inSend = new Promise((r) => { entered = r; }), hold = new Promise((r) => { finish = r; });
  const e = mailTo(gateEnv(), async () => {
    if (n++) throw new Error('E_DESTINATION_NOT_VERIFIED');
    entered();
    await hold;
  });
  const first = rec(e, 'ask', { ip: HOME });
  await inSend;
  const old = pending(e, NET).pid;
  mock.timers.tick(12 * 3600e3);
  await rec(e, 'ask', { ip: HOME });
  assert.notEqual(pending(e, NET).pid, old);
  finish();
  await first;
  assert.deepEqual(pending(e, NET).mail.sent, {});
}));

test('approval links are https on the bare host whatever scheme and port the held rec used, and the page refuses http', withClock(async () => {
  const e = gateEnv();
  await refusedReply(await rec(e, 'ask', { ip: HOME, base: 'http://tang.example.org:8080' }));
  assert.equal(pending(e, NET).info.base, 'https://tang.example.org');
  const path = linkIn(sent[0]);
  assert.ok(path);
  const http = (init) => worker.fetch(new Request(`http://tang.example.org${path}`, init), e, { waitUntil() {} });
  assert.equal((await http()).status, 403);
  const form = { method: 'POST', body: 'decision=approve&confirm=ask', headers: { origin: 'http://tang.example.org', 'content-type': 'application/x-www-form-urlencoded' } };
  assert.equal((await http(form)).status, 403);
  assert.equal(pending(e, NET).state, 'open');
}));

test('a Gate answer other than served, held, denied or capped fails closed and is never cached', withClock(async () => {
  for (const answer of [undefined, '', 'admitted']) {
    const e = gateEnv();
    let n = 0;
    e.GATE = { idFromName: () => 'gate', get: () => ({ miss: async () => { n++; return answer; } }) };
    const spy = spyDerive();
    try {
      await refusedReply(await rec(e, 'ask', { ip: HOME }));
      await refusedReply(await rec(e, 'ask', { ip: HOME }));
      assert.equal(spy.n, 0);
    } finally { spy.restore(); }
    assert.equal(n, 2, String(answer));
    assert.match(errors[0], /^ask: approvals unavailable, refusing new origins: unexpected Gate answer/);
  }
}));

test('a link names its approver: removing them kills it, reordering keeps attribution, and an added approver is mailed', withClock(async () => {
  const e = gateEnv();
  const oncall = APPROVERS[1];
  await rec(e, 'ask', { ip: HOME });
  const [l0, l1] = sent.map(linkIn);
  e.TANG_KEY_ASK = setText({ approvers: [oncall] });
  assert.equal((await open(e, l0)).status, 404);
  assert.equal((await post(e, l0, { decision: 'deny' })).status, 404);
  e.TANG_KEY_ASK = setText({ approvers: ['new@example.org', oncall] });
  mock.timers.tick(5 * 60e3);
  sent = [];
  await rec(e, 'ask', { ip: HOME });
  assert.deepEqual(sent.map((m) => m.to), ['new@example.org']);
  const r = await post(e, l1, { decision: 'approve', confirm: 'ask' });
  assert.match(await r.text(), new RegExp(`by ${oncall.replace('.', '\\.')}\\.`));
  assert.equal(logged.at(-1).approver, oncall);
}));
