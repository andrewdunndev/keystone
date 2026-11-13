// The alerts a recovery from a new source causes, the hourly digest of held sources, and the Worker-version notice.
import { send } from './gate.js';
import { secretName } from './jwk.js';
import { sourceNet } from './origin.js';
import { bounded } from './bounded.js';

// One alert per key set per hour bounds the mail a stream of new sources can cause; KV's minimum TTL is 60 s. Sources
// that arrive during the cooldown are held in KV and mailed as one digest by the cron trigger. KV takes one write a
// second per key and, on the Free plan, 1,000 writes a day per account; HELD_CAP keeps a set's worst day near 400.
const COOLDOWN = 3600;
const HELD_TTL = 7 * 86400;
export const SEEN_MAX = 1000;
const HELD_CAP = 5;
const DIGEST_MAX = 200;
const seen = new Set();
const held = new Set();
const inflight = new Set();
const coolUntil = new Map();
const heldCount = new Map();

export function resetAlerts() {
  for (const s of [seen, held, inflight]) s.clear();
  coolUntil.clear();
  heldCount.clear();
}

const sendMail = (env, subject, text) => send(env, env.ALERT_TO, subject, text);

const add = (set, k) => bounded(set, SEEN_MAX).add(k);

// A recovery request from a (/24 or /48, ASN, country) not seen before mails once per set per cooldown. The kid is
// public, so a request proves nothing about an unlock. Sources met during the cooldown or while a mail is in flight are
// held for the digest. The set name and source are claimed before the first await so concurrent requests send one mail.
// A refused source is a source of its own, so a refusal never marks the source seen for a later recovery.
export async function alertNewSource(request, env, name, ip, refused = false) {
  const net = sourceNet(ip);
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
      `was released.\n\n${facts}` + (refused === 'origin'
        ? 'Origins on Cloudflare\'s own network (WARP, Worker egress), with no ASN, or in 240.0.0.0/4 (Pseudo IPv4) are never ' +
          'admitted. If this is the host, it must egress elsewhere.'
        : 'If the host moved, add its prefix to the set\'s allow list.') +
      ` If it is not the host, someone who knows the set's name is asking for it.\n`] : [`keystone: recovery request from a new source for ${name}`,
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
export async function sendDigest(env) {
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

// Mails when the version serving the cron trigger differs from the last seen. One uploaded before the last seen is a rollback.
export async function versionChange(env) {
  const { id, timestamp } = env.CF_VERSION_METADATA ?? {};
  if (!id) return;
  const last = JSON.parse(await env.UNLOCKS.get('serving') ?? 'null');
  if (last?.id === id) return;
  if (last) {
    const back = timestamp < last.timestamp;
    await sendMail(env, back ? 'keystone: rolled back to an earlier Worker version' : 'keystone: a new Worker version is serving',
      `Worker version ${id}, uploaded ${timestamp}, serves in place of ${last.id}, uploaded ${last.timestamp}.\n\n` + (back
        ? 'A version serves the secrets it was deployed with, so a set revoked or a policy edited since is live again. ' +
          'Plan keyset deploy over the whole key store to see which; --apply redeploys from the current secrets.\n'
        : 'If you did not deploy it, check the Worker\'s deployments in Cloudflare.\n'));
  }
  await env.UNLOCKS.put('serving', JSON.stringify({ id, timestamp }));
}
