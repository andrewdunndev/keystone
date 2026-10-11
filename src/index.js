// Tang server (McCallum-Relyea exchange, P-256 or P-521 per key set) as a Cloudflare Worker.
// One write-once key set per name: /<name>/adv, /<name>/adv/<thp>, /<name>/rec/<kid>.
import { EmailMessage } from 'cloudflare:email';
import { b64u, kidMatches, parseSet, policyTag, secretName, NAME } from './jwk.js';
import { inCidr, parseIp, sourceNet, unadmittable } from './origin.js';

const enc = new TextEncoder();
// tangd (OpenSSL) accepts zero-padded coordinates and reduces them mod p; padding is capped at twice the field size.
const coordCap = (coord) => Math.ceil((coord * 2 * 4) / 3);
const MAX_BODY = 4096;

const toBig = (b) => BigInt('0x' + ([...b].map((x) => x.toString(16).padStart(2, '0')).join('') || '0'));
const hex = (n, coord) => n.toString(16).padStart(coord * 2, '0');
const fromHex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
const field = (p) => {
  const mod = (a) => ((a % p) + p) % p;
  const inv = (a) => {
    let r0 = p, r1 = a, t0 = 0n, t1 = 1n;
    while (r1) {
      const q = r0 / r1, r = r0 - q * r1, t = t0 - q * t1;
      r0 = r1; r1 = r; t0 = t1; t1 = t;
    }
    return mod(t0);
  };
  return { mod, inv };
};

const pub = (k, ops) => ({ alg: k.alg, crv: k.crv, key_ops: ops, kty: k.kty, x: k.x, y: k.y });

// Private keys are imported when a request first needs them, each on its own, so an unusable key fails only those requests.
const privateKey = (e, name, use) => (e.key ??= crypto.subtle.importKey('jwk',
  { kty: e.jwk.kty, crv: e.jwk.crv, x: e.jwk.x, y: e.jwk.y, d: e.jwk.d }, { name, namedCurve: e.jwk.crv }, false, [use]));

// Parsed key sets per isolate, keyed by the secret's text: a changed or deleted secret is never served stale.
const prepared = new Map();
function load(raw, secret) {
  if (!prepared.has(raw)) {
    try {
      const { sign, exch, ...gate } = parseSet(raw);
      prepared.set(raw, { ...gate, gated: !!(gate.allow || gate.approvers), sign: { jwk: sign, kids: {} }, exch: { jwk: exch, kids: {} } });
    } catch (e) {
      console.error(`${secret} is not a key set: ${e.message}`);
      return null;
    }
  }
  return prepared.get(raw);
}

// keyset's header: only then does an adv carry the version and policy headers, and a gated rec refuses a miss quietly.
const probed = (request) => request.headers.get('keystone-probe') === '1';

const reply = (status, body, type = 'text/plain') =>
  new Response(body, { status, headers: { 'content-type': type, 'cache-control': 'no-store' } });

async function advert(set, thp) {
  if (thp && !(await kidMatches(set.sign.jwk, thp, set.sign.kids))) return null;
  if (!set.adv) {
    const { signAlg, signHash } = set.curve;
    const payload = b64u.enc(enc.encode(JSON.stringify({ keys: [pub(set.sign.jwk, ['verify']), pub(set.exch.jwk, ['deriveKey'])] })));
    const prot = b64u.enc(enc.encode(`{"alg":"${signAlg}","cty":"jwk-set+json"}`));
    const sig = new Uint8Array(await crypto.subtle.sign(
      { name: 'ECDSA', hash: signHash }, await privateKey(set.sign, 'ECDSA', 'sign'), enc.encode(`${prot}.${payload}`)));
    set.adv = JSON.stringify({ payload, protected: prot, signature: b64u.enc(sig) });
  }
  return reply(200, set.adv, 'application/jose+json');
}

const coord = (s, c) => typeof s === 'string' && s.length <= coordCap(c.coord) && s.length % 4 !== 1 && /^[A-Za-z0-9_-]+$/.test(s)
  ? toBig(b64u.dec(s)) : null;

// x(dP) by WebCrypto ECDH, for a point P already known to be on curve c.
const ecdhX = async (c, d, u, v) => toBig(new Uint8Array(await crypto.subtle.deriveBits({
  name: 'ECDH',
  public: await crypto.subtle.importKey('raw', fromHex('04' + hex(u, c.coord) + hex(v, c.coord)),
    { name: 'ECDH', namedCurve: c.crv }, false, []),
}, d, c.coord * 8)));

// The body as text, or null past MAX_BODY bytes; reading stops at the cap, whatever Content-Length says.
async function readBody(request) {
  const reader = request.body?.getReader(), chunks = [];
  let n = 0;
  while (reader) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    if ((n += value.byteLength) > MAX_BODY) return reader.cancel().then(() => null, () => null);
  }
  const out = new Uint8Array(n);
  n = 0;
  for (const c of chunks) { out.set(c, n); n += c.byteLength; }
  return new TextDecoder().decode(out);
}

// The client point of a rec body, on the set's curve and reduced mod p, or the error reply. It reads public data only.
async function parseRec(set, request) {
  const c = set.curve;
  if (Number(request.headers.get('content-length')) > MAX_BODY) return reply(413, 'body too large\n');
  let jwk;
  try {
    const body = await readBody(request);
    if (body === null) return reply(413, 'body too large\n');
    jwk = JSON.parse(body);
  } catch { return reply(400, 'bad body\n'); }
  let x = jwk && coord(jwk.x, c), y = jwk && coord(jwk.y, c);
  if (!jwk || (jwk.alg !== undefined && jwk.alg !== 'ECMR') || jwk.kty !== 'EC' || jwk.crv !== c.crv || x === null || y === null) {
    return reply(400, 'bad point\n');
  }
  const { p: P, b: B } = c, { mod } = field(P);
  x %= P; y %= P;
  if (mod(y * y - x * x * x + 3n * x - B) !== 0n) return reply(400, 'point not on curve\n');
  return { x, y };
}

// ECDH yields only x(dX). With S = dG the exchange public key (its JWK import checks S against d), x(d(X+G)) = x(dX + S)
// fixes y(dX) through the x-only addition law: x(Q+S)(xS-xQ)^2 = (xS*xQ + a)(xS + xQ) + 2b - 2*yS*yQ, with a = -3.
// X = +-G gives dX = +-S directly. The client point must be on the set's curve, as tangd requires.
async function exchange(set, { x, y }) {
  const { exch, curve: c } = set;
  const { p: P, b: B, gx: GX, gy: GY } = c, { mod, inv } = field(P);
  const d = await privateKey(exch, 'ECDH', 'deriveBits');
  const xs = toBig(b64u.dec(exch.jwk.x)), ys = toBig(b64u.dec(exch.jwk.y));
  let xq, yq;
  if (x === GX) {
    xq = xs; yq = y === GY ? ys : P - ys;
  } else {
    const l = mod((GY - y) * inv(mod(GX - x))), x2 = mod(l * l - x - GX), y2 = mod(l * (x - x2) - y);
    const [q, r] = await Promise.all([ecdhX(c, d, x, y), ecdhX(c, d, x2, y2)]);
    const dx = xs - q;
    xq = q; yq = mod(((xs * q - 3n) * (xs + q) + 2n * B - r * dx * dx) % P * inv(2n * ys));
  }
  return reply(200, JSON.stringify({
    alg: 'ECMR', crv: c.crv, key_ops: ['deriveKey'], kty: 'EC',
    x: b64u.enc(fromHex(hex(xq, c.coord))), y: b64u.enc(fromHex(hex(yq, c.coord))),
  }), 'application/jwk+json');
}

// One alert per key set per hour bounds the mail a stream of new sources can cause; KV's minimum TTL is 60 s. Sources
// that arrive during the cooldown are held in KV and mailed as one digest by the cron trigger. KV takes one write a
// second per key and, on the Free plan, 1,000 writes a day per account; HELD_CAP keeps a set's worst day near 400.
const COOLDOWN = 3600;
const HELD_TTL = 7 * 86400;
const SEND_TIMEOUT = 10000;
const SEEN_MAX = 1000;
const HELD_CAP = 5;
const DIGEST_MAX = 200;
const seen = new Set();
const held = new Set();
const inflight = new Set();
const coolUntil = new Map();
const heldCount = new Map();

export function resetAlertState() {
  for (const s of [seen, held, inflight, failed]) s.clear();
  coolUntil.clear();
  loggedAt.clear();
  heldCount.clear();
}

// A plain-text message built by hand: the binding takes raw MIME, and the values are ASCII by construction (set
// names are [a-z0-9-], the rest is numeric or a country code), so CR and LF are the only characters to strip.
function mime(from, to, subject, text) {
  const line = (s) => String(s).replace(/[\r\n]+/g, ' ');
  const domain = line(from).split('@').pop();
  return [
    `From: ${line(from)}`, `To: ${line(to)}`, `Subject: ${line(subject)}`, `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@${domain}>`, 'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=us-ascii', 'Content-Transfer-Encoding: 7bit', '',
    text.replace(/\r?\n/g, '\r\n'),
  ].join('\r\n');
}

// The send_email binding only delivers to its verified destination, from an address on a domain with Email Routing
// enabled. It has no timeout of its own, so a stalled send is cut off here.
async function sendMail(env, subject, text) {
  const msg = new EmailMessage(env.ALERT_FROM, env.ALERT_TO, mime(env.ALERT_FROM, env.ALERT_TO, subject, text));
  let timer;
  const limit = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('send timed out')), SEND_TIMEOUT); });
  try {
    await Promise.race([env.ALERT.send(msg), limit]);
  } finally {
    clearTimeout(timer);
  }
}

function add(set, k) {
  if (set.size >= SEEN_MAX) set.clear();
  set.add(k);
}

// A recovery request from a (/24 or /48, ASN, country) not seen before mails once per set per cooldown. The kid is
// public, so a request proves nothing about an unlock. Sources met during the cooldown or while a mail is in flight are
// held for the digest. The set name and source are claimed before the first await so concurrent requests send one mail.
// A refused source is a source of its own, so a refusal never marks the source seen for a later recovery.
async function alertNewSource(request, env, name, refused = false) {
  const net = sourceNet(request.headers.get('CF-Connecting-IP'));
  if (!net) return;
  const { asn = '?', country = '?' } = request.cf ?? {};
  const id = `${name}:${net}:${asn}:${country}${refused ? ':refused' : ''}`;
  const key = `seen:${id}`;
  if (seen.has(key) || held.has(id) || inflight.has(key)) return;
  const hold = async () => {
    let c = heldCount.get(name);
    if (!c || c.until <= Date.now()) {
      const n = Number(await env.UNLOCKS.get(`heldn:${name}`)) || 0;
      c = heldCount.get(name);
      if (!c || c.until <= Date.now()) heldCount.set(name, c = { n, until: Date.now() + COOLDOWN * 1000 });
    }
    if (c.n >= HELD_CAP) return;
    c.n++;
    await env.UNLOCKS.put(`held:${id}`, JSON.stringify({ host: name, net, asn, country, refused, time: new Date().toISOString() }), { expirationTtl: HELD_TTL });
    add(held, id);
    await env.UNLOCKS.put(`heldn:${name}`, String(c.n), { expirationTtl: COOLDOWN });
  };
  if (inflight.has(name) || (coolUntil.get(name) ?? 0) > Date.now()) return hold();
  inflight.add(name); inflight.add(key);
  try {
    if (await env.UNLOCKS.get(key) !== null) return add(seen, key);
    const until = Number(await env.UNLOCKS.get(`cool:${name}`));
    if (until > Date.now()) { coolUntil.set(name, until); return await hold(); }
    const next = Date.now() + COOLDOWN * 1000;
    coolUntil.set(name, next);
    await env.UNLOCKS.put(`cool:${name}`, String(next), { expirationTtl: COOLDOWN }).catch(() => {});
    const facts = `source: ${net}\nASN: ${asn}\ncountry: ${country}\ntime: ${new Date().toISOString()}\n\n`;
    const [subject, text] = refused ? [`keystone: refused a recovery request from a new source for ${name}`,
      `Key set ${name} refused a recovery request from a source not seen before: the origin is not admitted, so no key ` +
      `was released.\n\n${facts}If the host moved, add its prefix to the set's allow list. If it did not, someone who knows ` +
      `the set's name is asking for it.\n`] : [`keystone: recovery request from a new source for ${name}`,
      `Key set ${name} received a recovery request from a source not seen before.\n\n${facts}` +
      `The key id is public, so this does not prove an unlock happened. If you did not expect it, ` +
      `check the host before deleting ${secretName(name)}: deleting it blocks the next boot.\n`];
    try {
      await sendMail(env, subject, text);
    } catch (e) {
      await hold().catch(() => {});
      throw e;
    }
    add(seen, key);
    await env.UNLOCKS.put(key, new Date().toISOString());
  } finally {
    inflight.delete(name); inflight.delete(key);
  }
}

// Mails the sources held during cooldowns as one digest, then records them as seen. A run takes DIGEST_MAX sources to
// stay under the Workers limit of 1,000 KV operations per invocation; the rest wait for the next run.
async function sendDigest(env) {
  const { keys } = await env.UNLOCKS.list({ prefix: 'held:', limit: DIGEST_MAX });
  const fresh = [];
  for (const { name } of keys) {
    const seenKey = `seen:${name.slice(5)}`;
    if (await env.UNLOCKS.get(seenKey) !== null) { await env.UNLOCKS.delete(name); continue; }
    const v = JSON.parse(await env.UNLOCKS.get(name) ?? 'null');
    if (v) fresh.push({ name, seenKey, ...v });
  }
  if (!fresh.length) return;
  const lines = fresh.map((v) => `${v.host}  ${v.net}  ASN ${v.asn}  ${v.country}  ${v.time}${v.refused ? '  refused' : ''}`).join('\n');
  await sendMail(env, `keystone: ${fresh.length} held recovery request source(s)`,
    `Recovery requests from sources not seen before, held during an alert cooldown:\n\n${lines}\n\n` +
    `The key id is public, so a request does not prove an unlock. Delete ${[...new Set(fresh.map((v) => secretName(v.host)))].join(', ')} only after checking the host.\n`);
  for (const v of fresh) {
    await env.UNLOCKS.put(v.seenKey, v.time);
    await env.UNLOCKS.delete(v.name);
  }
}

const alertsOn = (env) => env.UNLOCKS && env.ALERT && env.ALERT_FROM && env.ALERT_TO;

const failed = new Set();
const loggedAt = new Map();

// null when the origin is admitted, else why not. A refused origin never reaches a private key or the Gate.
async function admit(set, name, ip, request, env) {
  if (set.nets?.some((c) => inCidr(ip, c))) return null;
  if (!set.approvers) return 'allow';
  if (probed(request)) return 'probe';
  if (!env.GATE || !env.ALERT || !env.ALERT_FROM) return closed(name, 'GATE, ALERT and ALERT_FROM are not all bound');
  return closed(name, 'no Gate');
}

function closed(name, why) {
  if (!failed.has(name)) {
    failed.add(name);
    console.error(`${name}: approvals unavailable, refusing new origins: ${why}`);
  }
  return 'unavailable';
}

// Unserved recoveries all look alike to the client. A refusal alerts only for a set without approvers (or an origin
// never admitted); the log line comes once a minute per set and origin.
function refuse(request, env, ctx, name, why) {
  const ip = request.headers.get('CF-Connecting-IP');
  const key = `${name}:${sourceNet(ip) ?? ip}`;
  if ((loggedAt.get(key) ?? 0) <= Date.now()) {
    if (loggedAt.size >= SEEN_MAX) loggedAt.clear();
    loggedAt.set(key, Date.now() + 60000);
    const { asn = null, country = null } = request.cf ?? {};
    console.log(JSON.stringify({ event: 'refused', name, ip, asn, country, why }));
  }
  if ((why === 'allow' || why === 'origin') && !probed(request) && alertsOn(env)) {
    ctx.waitUntil(alertNewSource(request, env, name, true).catch((e) => console.error('refusal alert failed:', e.message)));
  }
  return reply(403, 'origin not admitted\n');
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const seg = url.pathname.split('/').filter(Boolean);
    const [name, op, arg] = seg;
    if (!name || !NAME.test(name) || seg.length > 3) return reply(404, 'not found\n');
    const secret = secretName(name), raw = env[secret];
    if (!raw) return reply(404, 'unknown key set\n');
    const set = load(raw, secret);
    if (!set) return reply(500, 'unreadable key set\n');
    if (op === 'adv') {
      if (request.method !== 'GET') return reply(405, 'method not allowed\n');
      const res = await advert(set, arg);
      if (!res) return reply(404, 'no such key\n');
      if (probed(request)) {
        if (env.CF_VERSION_METADATA?.id) res.headers.set('keystone-version', env.CF_VERSION_METADATA.id);
        const tag = await (set.tag ??= policyTag({ ...set, exch: set.exch.jwk }));
        if (tag) res.headers.set('keystone-policy', tag);
      }
      return res;
    }
    if (op === 'rec' && arg) {
      if (request.method !== 'POST') return reply(405, 'method not allowed\n');
      if (!(await kidMatches(set.exch.jwk, arg, set.exch.kids))) return reply(404, 'unknown kid\n');
      const ip = set.gated && parseIp(request.headers.get('CF-Connecting-IP'));
      if (set.gated && unadmittable(ip, request.cf?.asn)) return refuse(request, env, ctx, name, 'origin');
      const point = await parseRec(set, request);
      if (point instanceof Response) return point;
      if (set.gated) {
        const why = await admit(set, name, ip, request, env);
        if (why) return refuse(request, env, ctx, name, why);
      }
      const res = await exchange(set, point);
      // One line per recovery for the Workers logs: the source, never key material or the body.
      const { asn = null, country = null } = request.cf ?? {};
      console.log(JSON.stringify({ event: 'rec', name, ip: request.headers.get('CF-Connecting-IP'), asn, country }));
      if (alertsOn(env)) {
        ctx.waitUntil(alertNewSource(request, env, name).catch((e) => console.error('unlock alert failed:', e.message)));
      }
      return res;
    }
    return reply(404, 'not found\n');
  },
  async scheduled(event, env) {
    if (alertsOn(env)) await sendDigest(env);
  },
};
