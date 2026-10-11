// Approval of new origins for sets with approvers. One Durable Object instance holds every pending approval; only misses
// reach it. Storage keys: p:<name>:<origin> a pending, each value carrying its own `expires`.
import { DurableObject } from 'cloudflare:workers';
import { b64u, derivedKey, parseSet, secretName } from './jwk.js';

const enc = new TextEncoder();
export const PENDING_TTL = 12 * 3600 * 1000;
export const GRANT = 10 * 60 * 1000;
const OPEN_MAX = 3;

// The set's approvers and approve key as the Gate's own environment holds them, parsed once per secret text.
const loaded = new Map();
function gated(env, name) {
  const raw = env[secretName(name)];
  if (!loaded.has(raw)) {
    if (loaded.size >= 100) loaded.clear();
    const { exch, approvers } = parseSet(raw);
    if (!approvers) throw new Error(`${name} has no approvers`);
    loaded.set(raw, { approvers, key: approveKey(exch) });
  }
  return loaded.get(raw);
}

export const approveKey = (exch) => derivedKey(exch, 'keystone-approve-v1');

// v1.<payload>.<mac>: the payload is {o: origin, p: pid, e: expiry, a: approver index}, and the MAC, under the set's
// approve key, covers "<name>.<payload>" so a token names one set.
export async function sign(key, name, body) {
  const payload = b64u.enc(enc.encode(JSON.stringify(body)));
  return `v1.${payload}.${b64u.enc(new Uint8Array(await crypto.subtle.sign('HMAC', await key, enc.encode(`${name}.${payload}`))))}`;
}

// The payload of a token whose MAC verifies, else null. The MAC is checked before anything is parsed.
export async function verify(key, name, token) {
  const m = /^v1\.([A-Za-z0-9_-]{1,512})\.([A-Za-z0-9_-]{43})$/.exec(token);
  if (!m || !(await crypto.subtle.verify('HMAC', await key, b64u.dec(m[2]), enc.encode(`${name}.${m[1]}`)))) return null;
  return JSON.parse(new TextDecoder().decode(b64u.dec(m[1])));
}

export class Gate extends DurableObject {
  // For an origin outside the set's allow list: 'served' while a grant runs, 'denied', 'capped', or 'held' with a
  // pending opened if none is live.
  async miss(name, origin, info) {
    gated(this.env, name);
    const s = this.ctx.storage, now = Date.now(), key = `p:${name}:${origin}`;
    const p = await s.get(key);
    if (p?.expires > now) {
      if (p.state === 'denied') return 'denied';
      if (p.state === 'open') return 'held';
      if (p.grantUntil > now) return 'served';
    }
    await this.prune(now);
    if ((await this.open(name, now)).length >= OPEN_MAX) return 'capped';
    await s.put(key, { pid: crypto.randomUUID(), state: 'open', created: now, expires: now + PENDING_TTL, info });
    console.log(JSON.stringify({ event: 'held', name, origin, asn: info.asn, country: info.country }));
    return 'held';
  }

  // The pending a token names, null unless it is still the current one, and the set's other open origins.
  async view(name, origin, pid) {
    const now = Date.now(), p = await this.ctx.storage.get(`p:${name}:${origin}`);
    const others = (await this.open(name, now)).filter((o) => o.origin !== origin);
    return { p: p?.pid === pid && p.expires > now ? p : null, others };
  }

  // Approve takes an open or denied pending, deny an open one; anything else changes nothing and answers 409.
  async decide(name, origin, pid, decision, by) {
    const s = this.ctx.storage, now = Date.now(), key = `p:${name}:${origin}`, p = await s.get(key);
    const live = p?.pid === pid && p.expires > now;
    if (!live || !(p.state === 'open' || (decision === 'approve' && p.state === 'denied'))) return { status: 409, p: live ? p : null };
    p.state = decision === 'approve' ? 'approved' : 'denied';
    p.decided = { at: now, ...by };
    if (decision === 'approve') p.grantUntil = now + GRANT;
    await s.put(key, p);
    return { status: 200, p };
  }

  async open(name, now) {
    const prefix = `p:${name}:`;
    return [...(await this.ctx.storage.list({ prefix }))]
      .filter(([, p]) => p.state === 'open' && p.expires > now).map(([k, p]) => ({ origin: k.slice(prefix.length), ...p }));
  }

  async prune(now) {
    const dead = [...(await this.ctx.storage.list())].filter(([, v]) => v.expires <= now).map(([k]) => k);
    for (let i = 0; i < dead.length; i += 128) await this.ctx.storage.delete(dead.slice(i, i + 128));
  }
}
