import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { p256, p521 } from '@noble/curves/nist.js';
import worker, { sourceNet, resetAlertState } from '../src/index.js';
import { b64u, thumbprint, parseSet, CURVES } from '../src/jwk.js';
import { EmailMessage } from 'cloudflare:email';

// Built by gen-fixture.mjs from stock tangd, one fixture per curve with that tangd's keys: tangd is the oracle.
const FX = JSON.parse(readFileSync(new URL('./tangd-fixture.json', import.meta.url)));
const NOBLE = { 'P-256': p256, 'P-521': p521 };
const OTHER = { 'P-256': 'P-521', 'P-521': 'P-256' };
const setOf = (f) => JSON.stringify({ keys: [f.sig, f.exch] });
const envOf = (f) => ({ TANG_KEY_LAB: setOf(f), TANG_KEY_HOST1: setOf(f) });
// fx and env are the default curve's, P-521; a test made by eachCurve runs once per curve with that curve's.
let fx = FX['P-521'], env = envOf(fx);
const eachCurve = (name, fn) => {
  for (const crv of Object.keys(CURVES)) {
    test(`${name} (${crv})`, async () => {
      fx = FX[crv]; env = envOf(fx);
      try { await fn(CURVES[crv], NOBLE[crv]); } finally { fx = FX['P-521']; env = envOf(fx); }
    });
  }
};
// The rec log line goes to console.log; tests read it here.
const logged = [];
console.log = (line) => logged.push(line);
const call = (path, init = {}, e = env) => worker.fetch(new Request('http://w' + path, init), e);
const ip = (v) => ({ 'CF-Connecting-IP': v, 'content-type': 'application/jwk+json' });
const rec = (name, kid, body, e = env) => call(`/${name}/rec/${kid}`,
  { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body), headers: { 'content-type': 'application/jwk+json' } }, e);
const decode = (x) => JSON.parse(new TextDecoder().decode(b64u.dec(x)));
const coordOf = (n, c) => b64u.enc(Uint8Array.from(n.toString(16).padStart(c.coord * 2, '0').match(/../g).map((x) => parseInt(x, 16))));

test('CURVES are P-256 and P-521 as noble defines them', () => {
  assert.deepEqual(Object.keys(CURVES), ['P-256', 'P-521']);
  for (const [crv, n] of Object.entries(NOBLE)) {
    const c = n.Point.CURVE(), k = CURVES[crv];
    assert.deepEqual([k.p, k.b, k.gx, k.gy, k.p - 3n], [c.p, c.b, c.Gx, c.Gy, c.a], crv);
    assert.equal(k.coord, n.Point.Fp.BYTES, crv);
  }
});

eachCurve('thumbprint equals tangd kid (jose jwk thp)', async () => {
  assert.equal(await thumbprint(fx.exch), fx.kid);
});

eachCurve('adv payload and protected header equal tangd', async () => {
  const r = await call('/lab/adv');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('content-type'), 'application/jose+json');
  const a = await r.json();
  assert.deepEqual(Object.keys(a), ['payload', 'protected', 'signature']);
  assert.equal(a.protected, fx.tangdAdv.protected);
  // tangd's payload bytes are spaced JSON in directory order; the signature covers whatever bytes are sent.
  const keys = (x) => decode(x).keys.sort((p, q) => p.alg.localeCompare(q.alg));
  assert.deepEqual(keys(a.payload), keys(fx.tangdAdv.payload));
});

eachCurve('adv signature is the curve\'s ES alg (P1363) over protected.payload, and tangd agrees on the scheme', async (c) => {
  const verify = async (a) => {
    assert.equal(decode(a.protected).alg, c.signAlg);
    const vk = decode(a.payload).keys.find((k) => k.alg === c.signAlg);
    const key = await crypto.subtle.importKey('jwk', { kty: vk.kty, crv: vk.crv, x: vk.x, y: vk.y, ext: true },
      { name: 'ECDSA', namedCurve: c.crv }, false, ['verify']);
    assert.equal(b64u.dec(a.signature).length, 2 * c.coord);
    return crypto.subtle.verify({ name: 'ECDSA', hash: c.signHash }, key, b64u.dec(a.signature),
      new TextEncoder().encode(`${a.protected}.${a.payload}`));
  };
  assert.ok(await verify(fx.tangdAdv));
  assert.ok(await verify(await (await call('/lab/adv')).json()));
});

eachCurve('a changed key secret is served at once, never the previous key set', async (c) => {
  const fresh = (await crypto.subtle.exportKey('jwk',
    (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: c.crv }, true, ['deriveBits'])).privateKey));
  const e = { ...env, TANG_KEY_LAB: JSON.stringify({ keys: [fx.sig, { ...fresh, alg: 'ECMR' }] }) };
  assert.equal((await rec('lab', fx.kid, fx.client, e)).status, 404);
  assert.equal((await rec('lab', await thumbprint(fresh), fx.client, e)).status, 200);
  assert.equal((await rec('lab', fx.kid, fx.client)).status, 200);
});

eachCurve('adv/<thp> answers for the signing key thumbprint alone; any other thp is 404', async () => {
  assert.equal((await call(`/lab/adv/${await thumbprint(fx.sig)}`)).status, 200);
  assert.equal((await call(`/lab/adv/${fx.kid}`)).status, 404);
  assert.equal((await call('/lab/adv/nope')).status, 404);
});

eachCurve('rec output is identical to tangd for the same key and client point', async () => {
  const r = await rec('lab', fx.kid, fx.client);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('content-type'), 'application/jwk+json');
  assert.deepEqual(await r.json(), fx.tangdRec);
  assert.deepEqual(await (await rec('lab', fx.kid, fx.leadingZero)).json(), fx.tangdRecLz);
  assert.deepEqual(await (await rec('lab', fx.kid, fx.leadingZeroY)).json(), fx.tangdRecLzY);
});

eachCurve('rec agrees with an independent multiply on random points', async (c, n) => {
  const d = BigInt('0x' + Buffer.from(b64u.dec(fx.exch.d)).toString('hex'));
  const G = n.Point.BASE;
  const points = [G, G.negate(), ...Array.from({ length: 50 }, () => G.multiply(n.Point.Fn.fromBytes(n.utils.randomSecretKey())))];
  for (const P of points) {
    const A = P.toAffine(), o = P.multiply(d).toAffine();
    const j = await (await rec('lab', fx.kid, { alg: 'ECMR', crv: c.crv, kty: 'EC', x: coordOf(A.x, c), y: coordOf(A.y, c) })).json();
    assert.equal(j.x, coordOf(o.x, c));
    assert.equal(j.y, coordOf(o.y, c));
  }
});

eachCurve('rec accepts and rejects as tangd: off-curve, zero, padded, short, above p, other curve, bad JSON; padding capped', async () => {
  for (const [name, body] of Object.entries(fx.probes)) {
    const want = fx.probeOut[name], r = await rec('lab', fx.kid, body);
    assert.equal(r.status, want.status === 200 ? 200 : 400, name);
    if (want.status === 200) assert.deepEqual(await r.json(), want.body, name);
  }
  assert.equal((await rec('lab', fx.kid, fx.pastCap)).status, 400);
  assert.equal((await rec('lab', fx.kid, { ...fx.client, x: 'A'.repeat(1000) })).status, 400);
});

eachCurve('off-curve, zero and other-curve points are refused before importKey sees them, whatever the runtime would do', async (c) => {
  const subtle = crypto.subtle, real = subtle.importKey, raw = [];
  subtle.importKey = function (format, ...rest) {
    if (format === 'raw') raw.push(rest[0]);
    return real.call(this, format, ...rest);
  };
  const y = BigInt('0x' + Buffer.from(b64u.dec(fx.client.y)).toString('hex'));
  const alien = FX[OTHER[c.crv]].client;
  try {
    for (const body of [fx.probes.offCurve, fx.probes.zero, { ...fx.client, y: coordOf((y + 1n) % c.p, c) }, alien, { ...alien, crv: c.crv }]) {
      assert.equal((await rec('lab', fx.kid, body)).status, 400);
    }
    assert.equal(raw.length, 0);
    assert.equal((await rec('lab', fx.kid, fx.client)).status, 200);
    assert.equal(raw.length, 2);
  } finally {
    delete subtle.importKey;
  }
});

eachCurve('an unusable private key fails only the requests that need it, and a corrected secret serves', async () => {
  const e = { ...env };
  e.TANG_KEY_LAB = JSON.stringify({ keys: [{ ...fx.sig, d: '!!!!' }, fx.exch] });
  await assert.rejects(call('/lab/adv', {}, e));
  assert.equal((await rec('lab', fx.kid, fx.client, e)).status, 200);
  e.TANG_KEY_LAB = JSON.stringify({ keys: [fx.sig, { ...fx.exch, d: '!!!!' }] });
  assert.equal((await call('/lab/adv', {}, e)).status, 200);
  await assert.rejects(rec('lab', fx.kid, fx.client, e));
  e.TANG_KEY_LAB = JSON.stringify({ keys: [fx.sig, fx.exch] });
  assert.equal((await call('/lab/adv', {}, e)).status, 200);
  assert.equal((await rec('lab', fx.kid, fx.client, e)).status, 200);
});

test('one Worker serves a P-256 and a P-521 set side by side, each signing and recovering on its own curve', async () => {
  const e = { TANG_KEY_A: setOf(FX['P-256']), TANG_KEY_B: setOf(FX['P-521']) };
  for (let i = 0; i < 2; i++) {
    for (const [name, crv] of [['a', 'P-256'], ['b', 'P-521']]) {
      const f = FX[crv];
      assert.equal(decode((await (await call(`/${name}/adv`, {}, e)).json()).protected).alg, CURVES[crv].signAlg);
      assert.deepEqual(await (await rec(name, f.kid, f.client, e)).json(), f.tangdRec);
      assert.equal((await rec(name, f.kid, FX[OTHER[crv]].client, e)).status, 400);
    }
  }
});

test('rec refuses bodies over 4 KiB with 413, by Content-Length and by read length', async () => {
  const big = JSON.stringify({ ...fx.client, pad: 'a'.repeat(4096) });
  assert.equal((await rec('lab', fx.kid, big)).status, 413);
  const lie = await call(`/lab/rec/${fx.kid}`, { method: 'POST', body: big, headers: { 'content-length': '10' } });
  assert.equal(lie.status, 413);
  const declared = await call(`/lab/rec/${fx.kid}`, { method: 'POST', body: JSON.stringify(fx.client), headers: { 'content-length': '5000' } });
  assert.equal(declared.status, 413);
  assert.equal((await rec('lab', fx.kid, { ...fx.client, pad: 'a'.repeat(1000) })).status, 200);
});

test('rec accepts a body of exactly 4 KiB, by Content-Length and as a stream', async () => {
  const base = JSON.stringify({ ...fx.client, pad: '' });
  const bytes = new TextEncoder().encode(JSON.stringify({ ...fx.client, pad: 'a'.repeat(4096 - base.length) }));
  assert.equal(bytes.byteLength, 4096);
  const sized = await call(`/lab/rec/${fx.kid}`, { method: 'POST', body: bytes, headers: { 'content-length': '4096' } });
  assert.equal(sized.status, 200);
  let off = 0;
  const body = new ReadableStream({ pull(c) { off < 4096 ? c.enqueue(bytes.slice(off, off += 1024)) : c.close(); } });
  assert.equal((await call(`/lab/rec/${fx.kid}`, { method: 'POST', body, duplex: 'half' })).status, 200);
});

test('rec stops reading a body without Content-Length once it passes 4 KiB', async () => {
  let pulls = 0, cancelled = false;
  const body = new ReadableStream({
    pull(c) { if (++pulls > 64) c.close(); else c.enqueue(new Uint8Array(1024).fill(0x20)); },
    cancel() { cancelled = true; },
  });
  const res = await call(`/lab/rec/${fx.kid}`, { method: 'POST', body, duplex: 'half' });
  assert.equal(res.status, 413);
  assert.ok(cancelled);
  assert.ok(pulls <= 6, `pulled ${pulls} chunks`);
  const chunks = [JSON.stringify(fx.client).slice(0, 10), JSON.stringify(fx.client).slice(10)];
  const ok = new ReadableStream({ pull(c) { chunks.length ? c.enqueue(new TextEncoder().encode(chunks.shift())) : c.close(); } });
  assert.equal((await call(`/lab/rec/${fx.kid}`, { method: 'POST', body: ok, duplex: 'half' })).status, 200);
});

test('rec with the signing key thumbprint is 404 as with any non-exchange kid', async () => {
  assert.equal((await rec('lab', await thumbprint(fx.sig), fx.client)).status, 404);
});

test('rec errors: unknown kid 404 (as tangd), GET 405', async () => {
  assert.equal(fx.badKidStatus, 404);
  assert.equal((await rec('lab', 'nope', fx.client)).status, 404);
  assert.equal((await call(`/lab/rec/${fx.kid}`)).status, 405);
});

test('kid matches S1, S384, S512 thumbprints as tangd does, not garbage', async () => {
  const canon = new TextEncoder().encode(`{"crv":"${fx.exch.crv}","kty":"${fx.exch.kty}","x":"${fx.exch.x}","y":"${fx.exch.y}"}`);
  for (const h of ['SHA-1', 'SHA-384', 'SHA-512']) {
    const kid = b64u.enc(new Uint8Array(await crypto.subtle.digest(h, canon)));
    assert.equal((await rec('lab', kid, fx.client)).status, 200, h);
  }
  assert.equal((await rec('lab', 'AAAA', fx.client)).status, 404);
});

test('revocation: a deleted key secret gives 404 on adv and rec; another set is unaffected', async () => {
  const e = { ...env };
  delete e.TANG_KEY_LAB;
  assert.equal((await call('/lab/adv', {}, e)).status, 404);
  assert.equal((await rec('lab', fx.kid, fx.client, e)).status, 404);
  assert.equal((await call('/host1/adv', {}, e)).status, 200);
});

test('a name with no secret, and odd paths, are 404', async () => {
  assert.equal((await call('/no-such-set/adv')).status, 404);
  assert.equal((await call('/')).status, 404);
  assert.equal((await call('/lab/zzz')).status, 404);
  assert.equal((await call('/lab/rec')).status, 404);
  assert.equal((await call('/lab/adv/a/b')).status, 404);
});

eachCurve('a key set is {"keys":[...]}, one signing and one ECMR private key on the signing alg\'s curve; else 500, logged by name', async (c) => {
  const alien = FX[OTHER[c.crv]];
  const { alg, ...noAlg } = fx.exch;
  const { d, ...noD } = fx.exch;
  const { x, ...noX } = fx.exch;
  const text = JSON.stringify({ keys: [fx.sig, fx.exch] });
  const bad = {
    bareArray: JSON.stringify([fx.sig, fx.exch]),
    twoSign: JSON.stringify({ keys: [fx.sig, fx.sig, fx.exch] }),
    twoSignCurves: JSON.stringify({ keys: [fx.sig, alien.sig, fx.exch] }),
    twoEcmr: JSON.stringify({ keys: [fx.sig, fx.exch, fx.exch] }),
    missingD: JSON.stringify({ keys: [fx.sig, noD] }),
    missingX: JSON.stringify({ keys: [fx.sig, noX] }),
    wrongKty: JSON.stringify({ keys: [fx.sig, { ...fx.exch, kty: 'OKP' }] }),
    wrongCrv: JSON.stringify({ keys: [fx.sig, { ...fx.exch, crv: 'P-384' }] }),
    bothP384: JSON.stringify({ keys: [{ ...fx.sig, crv: 'P-384' }, { ...fx.exch, crv: 'P-384' }] }),
    mixedExch: JSON.stringify({ keys: [fx.sig, alien.exch] }),
    mixedSign: JSON.stringify({ keys: [alien.sig, fx.exch] }),
    algOnOtherCurve: JSON.stringify({ keys: [{ ...alien.sig, alg: c.signAlg }, alien.exch] }),
    otherAlgOnThisCurve: JSON.stringify({ keys: [{ ...fx.sig, alg: alien.sig.alg, crv: c.crv }, fx.exch] }),
    missingAlg: JSON.stringify({ keys: [fx.sig, noAlg] }),
    otherAlg: JSON.stringify({ keys: [fx.sig, fx.exch, { ...fx.exch, alg: 'ECDH-ES' }] }),
    inheritedAlg: JSON.stringify({ keys: [fx.sig, fx.exch, { ...fx.exch, alg: 'constructor' }] }),
    noExch: JSON.stringify({ keys: [fx.sig] }),
    truncated: text.slice(0, -2),
    // V8 quotes the text around a syntax error; the leading x makes it one.
    unquotedD: text.replace(`"d":"${fx.exch.d}"`, `"d":x${fx.exch.d}`),
  };
  const leaks = [fx.sig.d, fx.exch.d, alien.sig.d, alien.exch.d].map((k) => k.slice(0, 8));
  const errs = []; const log = console.error; console.error = (...a) => errs.push(a.join(' '));
  try {
    assert.deepEqual(parseSet(text), { sign: fx.sig, exch: fx.exch, curve: c });
    assert.equal(parseSet(text).curve, CURVES[c.crv]);
    for (const [name, raw] of Object.entries(bad)) {
      assert.throws(() => parseSet(raw), name);
      errs.length = 0;
      const e = { TANG_KEY_BAD_SET: raw };
      assert.equal((await call('/bad-set/adv', {}, e)).status, 500, name);
      assert.equal((await rec('bad-set', fx.kid, fx.client, e)).status, 500, name);
      assert.equal(errs.length, 2, name);
      for (const m of errs) assert.ok(m.includes('TANG_KEY_BAD_SET') && !leaks.some((k) => m.includes(k)), name);
    }
  } finally { console.error = log; }
});

test('a recovery logs one rec line with the set name and source, and no key material', async () => {
  const req = new Request(`http://w/lab/rec/${fx.kid}`, { method: 'POST', body: JSON.stringify(fx.client), headers: ip('198.51.100.9') });
  Object.defineProperty(req, 'cf', { value: { asn: 64500, country: 'US' } });
  logged.length = 0;
  const r = await worker.fetch(req, env);
  assert.equal(r.status, 200);
  const out = JSON.stringify(await r.json());
  assert.equal(logged.length, 1);
  assert.deepEqual(JSON.parse(logged[0]), { event: 'rec', name: 'lab', ip: '198.51.100.9', asn: 64500, country: 'US' });
  for (const secret of [fx.sig.d, fx.exch.d, fx.client.x, out]) assert.ok(!logged[0].includes(secret));
  logged.length = 0;
  await rec('lab', fx.kid, fx.client);
  assert.deepEqual(logged.map((l) => JSON.parse(l)), [{ event: 'rec', name: 'lab', ip: null, asn: null, country: null }]);
  logged.length = 0;
  await rec('lab', 'nope', fx.client);
  await rec('lab', fx.kid, '{');
  await call('/lab/adv');
  assert.deepEqual(logged, []);
});

const kv = (lag = 0) => {
  const m = new Map();
  const ttl = new Map();
  return {
    m, ttl, reads: [],
    get: async function (k) { this.reads.push(k); const v = m.get(k) ?? null; if (lag) await new Promise((r) => setTimeout(r, lag)); return v; },
    put: async (k, v, o) => { m.set(k, v); o?.expirationTtl ? ttl.set(k, o.expirationTtl) : ttl.delete(k); },
    delete: async (k) => void m.delete(k),
    list: async ({ prefix }) => ({ keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })) }),
  };
};

// A stand-in for the send_email binding: records every message; `fail` rejects like an unverified sender would, and
// `hang` never answers.
let current;
function mailer({ fail, delay, hang } = {}) {
  const calls = [];
  current = async (msg) => {
    calls.push(msg);
    if (hang) return new Promise(() => {});
    if (delay) await new Promise((r) => setTimeout(r, delay));
    if (fail) throw Object.assign(new Error('E_SENDER_NOT_VERIFIED'), { code: 'E_SENDER_NOT_VERIFIED' });
  };
  return { calls, restore: () => { current = undefined; } };
}

const alertEnv = (extra = {}) => (resetAlertState(), {
  ...env, UNLOCKS: kv(), ALERT: { send: (m) => current(m) }, ALERT_FROM: 'alerts@alerts.example.net', ALERT_TO: 'me@example.net', ...extra,
});
const header = (raw, name) => raw.match(new RegExp(`^${name}: (.*)$`, 'm'))?.[1];
const body = (raw) => raw.split('\r\n\r\n').slice(1).join('\r\n\r\n');
async function unlock(e, ipv, cf = { asn: 64500, country: 'US' }, host = 'host1') {
  const pending = [];
  const req = new Request(`http://w/${host}/rec/${fx.kid}`, { method: 'POST', body: JSON.stringify(fx.client), headers: ip(ipv) });
  Object.defineProperty(req, 'cf', { value: cf });
  const r = await worker.fetch(req, e, { waitUntil: (p) => pending.push(p) });
  await Promise.all(pending);
  return r;
}

test('sourceNet: /24 for IPv4, /48 for IPv6, null otherwise', () => {
  assert.equal(sourceNet('203.0.113.77'), '203.0.113.0/24');
  assert.equal(sourceNet('2001:db8:1:2:3:4:5:6'), '2001:db8:1::/48');
  assert.equal(sourceNet('2001:db8:ffff::1'), '2001:db8:ffff::/48');
  assert.equal(sourceNet('2001:DB8::'), '2001:db8:0::/48');
  for (const bad of ['nope', '1.2.3.256', '1.2.3', '1::2::3', '1:2:3:4::5:6:7:8', '1:2:3:4:5:6:7', '::ffff:1.2.3.4']) assert.equal(sourceNet(bad), null, bad);
  assert.equal(sourceNet(null), null);
});

test('a new source mails once through the binding and carries no key material', async () => {
  const fm = mailer(); const e = alertEnv();
  try {
    assert.equal((await unlock(e, '198.51.100.9')).status, 200);
    assert.equal(fm.calls.length, 1);
    const m = fm.calls[0];
    assert.ok(m instanceof EmailMessage);
    assert.equal(m.from, 'alerts@alerts.example.net');
    assert.equal(m.to, 'me@example.net');
    assert.equal(header(m.raw, 'From'), 'alerts@alerts.example.net');
    assert.equal(header(m.raw, 'To'), 'me@example.net');
    assert.match(header(m.raw, 'Message-ID'), /^<[0-9a-f-]{36}@alerts\.example\.net>$/);
    assert.equal(header(m.raw, 'MIME-Version'), '1.0');
    assert.match(header(m.raw, 'Content-Type'), /^text\/plain/);
    assert.ok(!Number.isNaN(Date.parse(header(m.raw, 'Date'))));
    assert.ok(m.raw.includes('\r\n\r\n') && !/[^\r]\n/.test(m.raw));
    const text = body(m.raw);
    assert.match(text, /198\.51\.100\.0\/24/);
    assert.match(text, /64500/);
    assert.ok(!m.raw.includes(fx.exch.d) && !m.raw.includes(fx.sig.d));
    assert.ok([...e.UNLOCKS.m.keys()].some((k) => k.startsWith('seen:host1:198.51.100.0/24:64500:US')));
  } finally { fm.restore(); }
});

test('header values cannot be split by a CR or LF', async () => {
  const fm = mailer(); const e = alertEnv({ ALERT_TO: 'me@example.net\r\nBcc: x@example.org' });
  try {
    await unlock(e, '198.51.100.9');
    assert.ok(!/^Bcc:/m.test(fm.calls[0].raw));
  } finally { fm.restore(); }
});

test('a seen source, or one more address in the same /24, sends nothing', async () => {
  const fm = mailer(); const e = alertEnv();
  try {
    await unlock(e, '198.51.100.9');
    const n = fm.calls.length;
    await unlock(e, '198.51.100.9');
    await unlock(e, '198.51.100.200');
    assert.equal(fm.calls.length, n);
  } finally { fm.restore(); }
});

test('a source recorded in KV is not mailed again by a fresh isolate', async () => {
  const fm = mailer(); const e = alertEnv();
  try {
    await e.UNLOCKS.put('seen:host1:192.0.2.0/24:64501:DE', 'x');
    await unlock(e, '192.0.2.4', { asn: 64501, country: 'DE' });
    assert.equal(fm.calls.length, 0);
  } finally { fm.restore(); }
});

test('the same /24 from another ASN or country is a new source', async () => {
  const fm = mailer(); const e = alertEnv();
  try {
    await unlock(e, '198.51.100.9', { asn: 64510, country: 'FR' });
    e.UNLOCKS.m.delete('cool:host1'); resetAlertState();
    const n = fm.calls.length;
    await unlock(e, '198.51.100.9', { asn: 64511, country: 'FR' });
    e.UNLOCKS.m.delete('cool:host1'); resetAlertState();
    await unlock(e, '198.51.100.9', { asn: 64511, country: 'NL' });
    assert.equal(fm.calls.length, n * 3);
  } finally { fm.restore(); }
});

test('new sources within the cooldown send one mail and are held, not recorded as seen', async () => {
  const fm = mailer(); const e = alertEnv();
  try {
    await unlock(e, '203.0.113.1');
    const n = fm.calls.length;
    for (let i = 2; i < 10; i++) await unlock(e, `203.0.${i}.1`);
    assert.equal(fm.calls.length, n);
    assert.ok(e.UNLOCKS.m.has('held:host1:203.0.5.0/24:64500:US'));
    assert.ok(![...e.UNLOCKS.m.keys()].some((k) => k.startsWith('seen:') && k.includes('203.0.5.0')));
  } finally { fm.restore(); }
});

test('a cooled set reads KV nothing on later requests, and a fresh isolate honours the KV cooldown', async () => {
  const fm = mailer(); const e = alertEnv(); let n;
  try {
    await unlock(e, '203.0.113.1');
    await unlock(e, '203.0.2.1');
    e.UNLOCKS.reads.length = 0;
    await unlock(e, '203.0.3.1');
    await unlock(e, '203.0.3.1');
    assert.deepEqual(e.UNLOCKS.reads, []);
    resetAlertState();
    n = fm.calls.length;
    await unlock(e, '203.0.4.1');
    assert.equal(fm.calls.length, n);
    assert.ok(e.UNLOCKS.m.has('held:host1:203.0.4.0/24:64500:US'));
  } finally { fm.restore(); }
});

test('concurrent recoveries from one source send one mail, from many sources one plus held', async () => {
  const fm = mailer({ delay: 20 }); const e = alertEnv({ UNLOCKS: kv(20) });
  try {
    await Promise.all([1, 2, 3, 4, 5].map(() => unlock(e, '198.51.100.9')));
    assert.equal(fm.calls.length, 1);
    resetAlertState(); e.UNLOCKS.m.clear(); fm.calls.length = 0;
    await Promise.all([1, 2, 3, 4, 5].map((i) => unlock(e, `198.51.${i}.9`)));
    assert.equal(fm.calls.length, 1);
    assert.equal([...e.UNLOCKS.m.keys()].filter((k) => k.startsWith('held:')).length, 4);
  } finally { fm.restore(); }
});

test('an alert writes each KV key at most once, the source only after the mail is sent', async () => {
  const fm = mailer(); const e = alertEnv();
  try {
    const puts = [];
    const put = e.UNLOCKS.put;
    e.UNLOCKS.put = async (key, v, o) => { puts.push([key, o?.expirationTtl, fm.calls.length]); return put(key, v, o); };
    await unlock(e, '198.51.100.9');
    assert.deepEqual(puts.map(([k]) => k), ['cool:host1', 'seen:host1:198.51.100.0/24:64500:US']);
    assert.deepEqual(puts[1].slice(1), [undefined, 1]);
  } finally { fm.restore(); }
});

test('a KV that refuses writes still mails the first new source', async () => {
  const fm = mailer(); const e = alertEnv();
  const errs = []; const log = console.error; console.error = (...a) => errs.push(a.join(' '));
  e.UNLOCKS.put = async () => { throw new Error('KV PUT failed: 429 Too Many Requests'); };
  try {
    assert.equal((await unlock(e, '198.51.100.9')).status, 200);
    assert.equal(fm.calls.length, 1);
    assert.match(errs.join(), /429/);
  } finally { console.error = log; fm.restore(); }
});

test('a send that never answers is cut off after ten seconds and leaves the source unrecorded', { timeout: 5000 }, async () => {
  const fm = mailer({ hang: true }); const e = alertEnv();
  const errs = []; const log = console.error; console.error = (...a) => errs.push(a.join(' '));
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const done = unlock(e, '198.51.100.9');
    for (let i = 0; i < 100 && !fm.calls.length; i++) await new Promise((r) => setImmediate(r));
    assert.equal(fm.calls.length, 1);
    mock.timers.tick(9999);
    await new Promise((r) => setImmediate(r));
    assert.equal(errs.length, 0);
    mock.timers.tick(1);
    assert.equal((await done).status, 200);
    assert.equal(errs.length, 1);
    assert.match(errs[0], /timed out/);
    assert.ok([...e.UNLOCKS.m.keys()].every((k) => !k.startsWith('seen:')));
  } finally { mock.timers.reset(); console.error = log; fm.restore(); }
});

test('the mail calls a request a recovery request and does not claim an unlock', async () => {
  const fm = mailer();
  try {
    await unlock(alertEnv(), '198.51.100.9');
    const raw = fm.calls[0].raw;
    assert.doesNotMatch(body(raw), /was unlocked/);
    assert.match(body(raw), /recovery request/);
    assert.match(header(raw, 'Subject'), /recovery request/);
  } finally { fm.restore(); }
});

test('the cron digest mails held sources once, records them and clears the queue', async () => {
  const fm = mailer(); const e = alertEnv();
  try {
    await unlock(e, '203.0.113.1');
    await unlock(e, '203.0.2.1');
    await unlock(e, '203.0.3.1');
    fm.calls.length = 0;
    await worker.scheduled({}, e);
    assert.equal(fm.calls.length, 1);
    const text = body(fm.calls[0].raw);
    assert.match(text, /203\.0\.2\.0\/24/); assert.match(text, /203\.0\.3\.0\/24/);
    assert.ok([...e.UNLOCKS.m.keys()].every((k) => !k.startsWith('held:')));
    assert.ok(e.UNLOCKS.m.has('seen:host1:203.0.2.0/24:64500:US'));
    fm.calls.length = 0;
    await worker.scheduled({}, e);
    assert.equal(fm.calls.length, 0);
  } finally { fm.restore(); }
});

test('the cron digest skips held sources already seen and keeps held ones when the mail fails', async () => {
  const e = alertEnv();
  await e.UNLOCKS.put('seen:host1:192.0.2.0/24:1:US', 'x');
  await e.UNLOCKS.put('held:host1:192.0.2.0/24:1:US', JSON.stringify({ host: 'host1', net: '192.0.2.0/24', asn: 1, country: 'US', time: 't' }));
  let fm = mailer();
  try {
    await worker.scheduled({}, e);
    assert.equal(fm.calls.length, 0);
    assert.ok(!e.UNLOCKS.m.has('held:host1:192.0.2.0/24:1:US'));
  } finally { fm.restore(); }
  await e.UNLOCKS.put('held:host1:192.0.3.0/24:1:US', JSON.stringify({ host: 'host1', net: '192.0.3.0/24', asn: 1, country: 'US', time: 't' }));
  fm = mailer({ fail: true });
  try {
    await assert.rejects(worker.scheduled({}, e));
    assert.ok(e.UNLOCKS.m.has('held:host1:192.0.3.0/24:1:US'));
    assert.ok(!e.UNLOCKS.m.has('seen:host1:192.0.3.0/24:1:US'));
  } finally { fm.restore(); }
});

test('a failing alert leaves the unlock response untouched and the source unrecorded', async () => {
  const fm = mailer({ fail: true }); const e = alertEnv();
  const errs = []; const log = console.error; console.error = (...a) => errs.push(a.join(' '));
  try {
    const r = await unlock(e, '198.18.0.9');
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), (await rec('host1', fx.kid, fx.client).then((x) => x.json())));
    assert.ok([...e.UNLOCKS.m.keys()].every((k) => !k.startsWith('seen:')));
    assert.ok(errs.length === 1 && errs[0].includes('E_SENDER_NOT_VERIFIED'));
  } finally { console.error = log; fm.restore(); }
});

test('a throwing KV does not fail the unlock', async () => {
  const fm = mailer(); const e = alertEnv({ UNLOCKS: { get: async () => { throw new Error('kv down'); } } });
  const log = console.error; console.error = () => {};
  try { assert.equal((await unlock(e, '198.20.0.9')).status, 200); } finally { console.error = log; fm.restore(); }
});

test('failed and unconfigured unlocks send nothing', async () => {
  const fm = mailer();
  try {
    const e = alertEnv();
    const bad = new Request(`http://w/host1/rec/${fx.kid}`, { method: 'POST', body: '{', headers: ip('10.9.9.9') });
    assert.equal((await worker.fetch(bad, e, { waitUntil() { throw new Error('alert scheduled'); } })).status, 400);
    for (const drop of ['UNLOCKS', 'ALERT', 'ALERT_FROM', 'ALERT_TO']) {
      const x = alertEnv(); delete x[drop];
      assert.equal((await unlock(x, '198.19.0.77')).status, 200);
      assert.equal(x.UNLOCKS?.m.size ?? 0, 0);
    }
    assert.equal(fm.calls.length, 0);
  } finally { fm.restore(); }
});

test('a failed send holds the source so the cron digest retries it', async () => {
  const e = alertEnv();
  const errs = []; const log = console.error; console.error = (...a) => errs.push(a.join(' '));
  let fm = mailer({ fail: true });
  try {
    await unlock(e, '198.18.0.9');
    assert.ok(e.UNLOCKS.m.has('held:host1:198.18.0.0/24:64500:US'));
    fm.restore(); fm = mailer();
    await worker.scheduled({}, e);
    assert.equal(fm.calls.length, 1);
    assert.match(body(fm.calls[0].raw), /198\.18\.0\.0\/24/);
  } finally { console.error = log; fm.restore(); }
});

test('the digest lists at most 200 held sources per run', async () => {
  const fm = mailer(); const e = alertEnv();
  let limit;
  const list = e.UNLOCKS.list;
  e.UNLOCKS.list = async (o) => { limit = o.limit; return list(o); };
  try {
    await worker.scheduled({}, e);
    assert.equal(limit, 200);
  } finally { fm.restore(); }
});

test('a held source is kept when its counter write is refused', async () => {
  const fm = mailer(); const e = alertEnv();
  const log = console.error; console.error = () => {};
  const put = e.UNLOCKS.put;
  e.UNLOCKS.put = async (k, v, o) => { if (k.startsWith('heldn:')) throw new Error('KV PUT failed: 429 Too Many Requests'); return put(k, v, o); };
  try {
    await unlock(e, '203.0.113.1');
    await unlock(e, '198.51.100.9');
    assert.ok(e.UNLOCKS.m.has('held:host1:198.51.100.0/24:64500:US'));
  } finally { console.error = log; fm.restore(); }
});

test('held writes per set are capped within a cooldown, and another set is unaffected', async () => {
  const fm = mailer(); const e = alertEnv();
  try {
    await unlock(e, '203.0.113.1');
    for (let i = 0; i < 80; i++) await unlock(e, `10.${i}.0.1`);
    const heldKeys = () => [...e.UNLOCKS.m.keys()].filter((k) => k.startsWith('held:host1:'));
    assert.equal(heldKeys().length, 5);
    await unlock(e, '10.0.0.5', undefined, 'lab');
    assert.equal(fm.calls.length, 2);
  } finally { fm.restore(); }
});
