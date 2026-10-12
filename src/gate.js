// Approval of new origins for sets with approvers, and the mail it and the unlock alerts send. One Durable Object
// instance holds every pending approval, so the mail cap has one point of serialization; only misses reach it. Storage
// keys, each value carrying its own `expires`: p:<name>:<origin> a pending, c:<name> a capped notice sent, m:<hour> the
// messages sent that hour.
import { EmailMessage } from 'cloudflare:email';
import { DurableObject } from 'cloudflare:workers';
import { b64u, derivedKey, parseSet, secretName } from './jwk.js';

const enc = new TextEncoder();
export const PENDING_TTL = 12 * 3600 * 1000;
export const GRANT = 10 * 60 * 1000;
const OPEN_MAX = 3;
const MAIL_MAX = 20;
const RETRY = 5 * 60 * 1000;
const RETRY_MAX = 3600 * 1000;
const SEND_TIMEOUT = 10000;

// A plain-text message built by hand: the binding takes raw MIME and every value is ASCII by construction, so CR and
// LF are the only characters to strip.
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

// The send_email binding delivers only to verified Email Routing destinations, from an address on a zone with Email
// Routing enabled. It has no timeout of its own, so a stalled send is cut off here.
export async function send(env, to, subject, text) {
  const msg = new EmailMessage(env.ALERT_FROM, to, mime(env.ALERT_FROM, to, subject, text));
  let timer;
  const limit = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('send timed out')), SEND_TIMEOUT); });
  try {
    await Promise.race([env.ALERT.send(msg), limit]);
  } finally {
    clearTimeout(timer);
  }
}

const ascii = (s) => String(s).replace(/[^\x20-\x7e]/g, '?');
const when = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');
const about = (o) => ascii(`${o.origin}  AS${o.info.asn} ${o.info.org}  ${o.info.city}, ${o.info.country}  since ${when(o.created)}`);

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

// v1.<payload>.<mac>: the payload is {o: origin, p: pid, e: expiry, a: approver address}, and the MAC, under the set's
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

const due = (p, to) => !p.mail.sent[to];
const retryAt = (m) => m.at + Math.min(RETRY_MAX, RETRY * 2 ** (m.tries - 1));

export class Gate extends DurableObject {
  // For an origin outside the set's allow list: 'served' while a grant runs, 'denied', 'capped', or 'held' with a
  // pending opened if none is live.
  async miss(name, origin, info) {
    const set = gated(this.env, name);
    const s = this.ctx.storage, now = Date.now(), key = `p:${name}:${origin}`;
    const p = await s.get(key);
    if (p?.expires > now) {
      if (p.state === 'denied') return 'denied';
      if (p.state === 'open') {
        if (set.approvers.some((to) => due(p, to)) && retryAt(p.mail) <= now) {
          Object.assign(p.mail, { at: now, tries: p.mail.tries + 1 });
          await s.put(key, p);
          await this.mail(name, origin, set, now);
        }
        return 'held';
      }
      if (p.grantUntil > now) return 'served';
    }
    await this.prune(now);
    const open = await this.open(name, now);
    if (open.length >= OPEN_MAX) {
      if (!((await s.get(`c:${name}`))?.expires > now)) await this.notice(name, set, open, now, { origin, info, created: now });
      return 'capped';
    }
    const mail = { at: now, tries: 1, sent: {} };
    await s.put(key, { pid: crypto.randomUUID(), state: 'open', created: now, expires: now + PENDING_TTL, info, mail });
    console.log(JSON.stringify({ event: 'held', name, origin, asn: info.asn, country: info.country }));
    await this.mail(name, origin, set, now);
    return 'held';
  }

  // One message per approver not yet reached, each with its own link. State is written before each send is awaited,
  // so concurrent misses send once; a failed send is retried by a later miss, backing off from RETRY to RETRY_MAX.
  async mail(name, origin, set, now) {
    const s = this.ctx.storage, key = `p:${name}:${origin}`, p = await s.get(key);
    const others = (await this.open(name, now)).filter((o) => o.origin !== origin);
    const i = Object.fromEntries(Object.entries(p.info).map(([k, v]) => [k, ascii(v)])), where = `${origin} (${i.org}, ${i.city})`;
    for (const to of set.approvers) {
      if (!due(p, to) || !(await this.budget(now))) continue;
      const link = `${i.base}/${name}/approve/${await sign(set.key, name, { o: origin, p: p.pid, e: p.expires, a: to })}`;
      const text = `Key set ${name} was asked for from an origin it does not admit. The host is held: nothing changes ` +
        `until an approver presses a button on the page below.\n\nset: ${name}\norigin: ${origin}\nnetwork: AS${i.asn} ` +
        `${i.org}\nlocation: ${i.city}, ${i.country} (approximate)\ncolo: ${i.colo}\nfirst seen: ${when(p.created)}\n` +
        `expires: ${when(p.expires)}\n\n${link}\n\n` +
        (others.length ? `${others.length} other origin(s) are asking for this set:\n${others.map((o) => `  ${about(o)}`).join('\n')}\n\n` : '') +
        `Approving lets any machine in ${origin} recover ${name} for ${GRANT / 60000} minutes. If the host was not just ` +
        'moved, deny, and revoke the set.\n';
      const ok = await send(this.env, to, `keystone: unlock ${name} from ${where}?`, text).then(() => true, async (e) => {
        console.error(`approval mail to ${to} for ${name} failed: ${e.message}`);
        await this.budget(now, -1);
        return false;
      });
      const q = await s.get(key);
      if (!ok || q?.pid !== p.pid) continue;
      q.mail.sent[to] = true;
      await s.put(key, q);
    }
  }

  // Once per PENDING_TTL per set while capped: each approver gets the open pendings with their own links. The marker is
  // claimed before the sends so concurrent misses send once, and dropped if nothing went out.
  async notice(name, set, open, now, refused) {
    const s = this.ctx.storage, key = `c:${name}`;
    await s.put(key, { expires: now + PENDING_TTL });
    let any = false;
    for (const to of set.approvers) {
      if (!(await this.budget(now))) break;
      const items = await Promise.all(open.map(async (o) =>
        `  ${about(o)}\n  ${o.info.base}/${name}/approve/${await sign(set.key, name, { o: o.origin, p: o.pid, e: o.expires, a: to })}`));
      try {
        await send(this.env, to, `keystone: ${name} has ${open.length} origins waiting; new ones are refused`,
          `Key set ${name} already holds ${open.length} origins awaiting a decision, so this origin was refused, as is any ` +
          `other new one until one is decided:\n\n  ${about(refused)}\n\nThe origins waiting are not that one; denying one ` +
          `frees a slot for it:\n\n${items.join('\n\n')}\n\nIf you did not move the host, deny them all and revoke the set.\n`);
        any = true;
      } catch (e) {
        console.error(`capped notice to ${to} for ${name} failed: ${e.message}`);
        await this.budget(now, -1);
      }
    }
    if (any) console.log(JSON.stringify({ event: 'capped', name, open: open.length }));
    else await s.delete(key);
  }

  // MAIL_MAX messages an hour across every set, counted before the send and refunded (d = -1) when it fails.
  async budget(now, d = 1) {
    const hour = Math.floor(now / 3600000), key = `m:${hour}`, m = (await this.ctx.storage.get(key)) ?? { n: 0, expires: (hour + 1) * 3600000 };
    if (d > 0 && m.n >= MAIL_MAX) return false;
    m.n += d;
    await this.ctx.storage.put(key, m);
    return true;
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
