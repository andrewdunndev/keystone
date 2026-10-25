import { readFileSync } from 'node:fs';
import worker from '../src/index.js';

// Built by gen-fixture.mjs from stock tangd, one fixture per curve with that tangd's keys: tangd is the oracle.
export const FX = JSON.parse(readFileSync(new URL('./tangd-fixture.json', import.meta.url)));

export const setOf = (f, extra = {}) => JSON.stringify({ keys: [f.sig, f.exch], ...extra });

export { be } from './hex.mjs';

export const kv = (lag = 0) => {
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

// A recovery request for fx's client key, with the connecting address and the Cloudflare request properties set.
export async function rec(e, name, { fx, ip, asn = 64500, headers = {}, body = fx.client, cf = {}, base = 'https://tang.example.org' }) {
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

// Polls until cond() holds or the wall-clock deadline passes, yielding to the event loop between checks.
// performance.now is not among the clocks the tests mock.
export async function until(cond, ms = 3000) {
  const end = performance.now() + ms;
  while (!cond() && performance.now() < end) await new Promise((r) => setImmediate(r));
}
