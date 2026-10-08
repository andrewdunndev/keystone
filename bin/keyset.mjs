#!/usr/bin/env node
// Mint, check, deploy and revoke write-once key sets. deploy and revoke only plan unless given --apply, and nothing is
// ever deleted except the one set `revoke <name> --apply` names. Private keys reach stdout only from `new`.
import { spawn } from 'node:child_process';
import { realpathSync, rmSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { constants, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { b64u, thumbprint, parseSet, secretName, NAME, CURVES } from '../src/jwk.js';

const WRANGLER = fileURLToPath(new URL('../node_modules/.bin/wrangler', import.meta.url));
const USAGE = `usage: keyset new [--curve P-256|P-521, default P-521] > set
       keyset check <url> <name> < set
       keyset deploy --url <base> [--new <name>]... [--apply] [-- <wrangler args>] < {"TANG_KEY_<NAME>": set | null, ...}
       keyset revoke <name> --url <base> [--apply] [-- <wrangler args>]
`;
const enc = new TextEncoder();
const dec = new TextDecoder();
const SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];

// stdin is closed, so wrangler's confirmations take their non-interactive answer instead of prompting.
const runWrangler = (args, { capture = false, onSpawn } = {}) => new Promise((resolve, reject) => {
  const p = spawn(WRANGLER, args, { stdio: ['ignore', capture ? 'pipe' : 'inherit', 'inherit'] });
  onSpawn?.(p);
  let stdout = '';
  p.stdout?.on('data', (b) => { stdout += b; });
  p.on('error', reject);
  p.on('close', (code) => resolve({ code, stdout }));
});

const readAll = async (s) => {
  if (typeof s === 'string') return s;
  let t = '';
  for await (const c of s) t += c;
  return t;
};

const publicKey = (k, name) => crypto.subtle.importKey('jwk', { kty: k.kty, crv: k.crv, x: k.x, y: k.y },
  { name, namedCurve: k.crv }, false, name === 'ECDSA' ? ['verify'] : []);

// parseSet, then each private key imported, which checks its d against its public point.
async function loadSet(text) {
  const set = parseSet(text);
  for (const [k, name, use] of [[set.sign, 'ECDSA', 'sign'], [set.exch, 'ECDH', 'deriveBits']]) {
    await crypto.subtle.importKey('jwk', { kty: k.kty, crv: k.crv, x: k.x, y: k.y, d: k.d }, { name, namedCurve: k.crv }, false, [use])
      .catch(() => { throw new Error(`the ${k.alg} private key does not match its public key`); });
  }
  set.thp = { sign: await thumbprint(set.sign), exch: await thumbprint(set.exch) };
  set.roles = `ECMR ${set.thp.exch},${set.curve.signAlg} ${set.thp.sign}`;
  return set;
}

// The advertised keys as "alg thumbprint" pairs, comparable with set.roles; null when the adv carries a private key.
async function advertised(jws) {
  const { keys } = JSON.parse(dec.decode(b64u.dec(jws.payload)));
  if (keys.some((k) => 'd' in k)) return null;
  return (await Promise.all(keys.map(async (k) => `${k.alg} ${await thumbprint(k)}`))).sort().join();
}

const base = (url) => url.replace(/\/+$/, '');

// One set against the live Worker: its adv is signed by the set's signing key and advertises exactly the set's public
// keys, and a recovery of a fresh point R = rG answers with x(rS), S the set's exchange key. Throws on any mismatch.
async function check(url, name, set, { fetch }) {
  const res = await fetch(`${base(url)}/${name}/adv`);
  if (res.status !== 200) throw new Error(`adv ${name}: HTTP ${res.status}`);
  const jws = await res.json();
  const { crv, coord, signHash } = set.curve;
  const vk = await publicKey(set.sign, 'ECDSA');
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: signHash }, vk, b64u.dec(jws.signature), enc.encode(`${jws.protected}.${jws.payload}`))) {
    throw new Error(`adv ${name}: the signature does not verify with the set's signing key`);
  }
  if (await advertised(jws) !== set.roles) throw new Error(`adv ${name}: the advertised keys are not the set's`);

  const r = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: crv }, true, ['deriveBits']);
  const { x, y } = await crypto.subtle.exportKey('jwk', r.publicKey);
  const rep = await fetch(`${base(url)}/${name}/rec/${set.thp.exch}`, {
    method: 'POST',
    headers: { 'content-type': 'application/jwk+json' },
    body: JSON.stringify({ alg: 'ECMR', crv, key_ops: ['deriveKey'], kty: 'EC', x, y }),
  });
  if (rep.status !== 200) throw new Error(`rec ${name}: HTTP ${rep.status}`);
  const got = (await rep.json())?.x;
  const want = b64u.enc(new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: await publicKey(set.exch, 'ECDH') }, r.privateKey, coord * 8)));
  if (got !== want) throw new Error(`rec ${name}: the reply is not the set's exchange key applied to the request`);
  return [`OK  adv ${name}: signed by ${set.thp.sign}, advertising the set's keys`, `OK  rec ${name}: exchange key ${set.thp.exch} answers`];
}

const args = (argv, options) => {
  const cut = argv.includes('--') ? argv.indexOf('--') : argv.length;
  const { values, positionals } = parseArgs({ args: argv.slice(0, cut), options, allowPositionals: true });
  return { o: values, pos: positionals, extra: argv.slice(cut + 1) };
};

// The set name a secret holds, or null unless the secret is TANG_KEY_<NAME> for a valid name.
const nameOf = (secret) => {
  const name = secret.replace(/^TANG_KEY_/, '').toLowerCase().replace(/_/g, '-');
  return NAME.test(name) && secretName(name) === secret ? name : null;
};

// The secret names of the Worker that wrangler targets with `extra`, or null when wrangler gives no list.
async function secrets(io, extra) {
  const { code, stdout } = await io.wrangler(['secret', 'list', '--format', 'json', ...extra], { capture: true });
  try { return code === 0 ? new Set(JSON.parse(stdout).map((s) => s.name)) : null; } catch { return null; }
}

async function deploy(argv, io) {
  const { o, pos, extra } = args(argv, { url: { type: 'string' }, apply: { type: 'boolean' }, new: { type: 'string', multiple: true } });
  if (!o.url || pos.length) throw new Error(`deploy takes --url and stdin\n${USAGE}`);
  let input;
  try { input = JSON.parse(await readAll(io.stdin)); } catch { input = null; }
  if (input?.constructor !== Object) throw new Error('stdin is not a JSON object of TANG_KEY_<NAME> secrets');
  const news = new Set(o.new);
  const sets = [], tombs = [];
  let refused = 0;
  const say = (verdict, what, why) => {
    if (verdict === 'REFUSE') refused++;
    io.stdout.write(`${verdict.padEnd(7)} ${what}: ${why}\n`);
  };
  for (const [secret, value] of Object.entries(input)) {
    const name = nameOf(secret);
    if (!name) { say('REFUSE', secret, 'not TANG_KEY_<NAME> for a set name [a-z0-9-]{1,63}'); continue; }
    news.delete(name);
    if (value === null || (typeof value === 'string' && value.trim() === 'null')) {
      if (o.new?.includes(name)) say('REFUSE', name, 'null marks a revoked set; --new names only freshly minted sets');
      else tombs.push({ name, secret });
      continue;
    }
    try {
      const raw = typeof value === 'string' ? value : JSON.stringify(value);
      sets.push({ name, secret, set: await loadSet(raw), text: JSON.stringify(JSON.parse(raw)), isNew: o.new?.includes(name) });
    } catch (e) { say('REFUSE', name, e.message); }
  }
  for (const name of news) say('REFUSE', name, '--new names a set absent from stdin');

  // --url and the wrangler target are named apart, so the target's secrets must agree with what --url serves.
  const listed = o.apply || io.env.CLOUDFLARE_API_TOKEN ? await secrets(io, extra) : null;
  for (const { name, secret, set, isNew } of sets) {
    const res = await io.fetch(`${base(o.url)}/${name}/adv`).catch(() => null);
    const held = listed?.has(secret);
    if (res?.status === 404) {
      if (!isNew) say('REFUSE', name, 'absent (never deployed, or revoked); --new only for a freshly minted set');
      else if (held) say('REFUSE', name, `absent at --url, yet the wrangler target holds ${secret}`);
      else say('new', name, `absent; will be created, signing key ${set.thp.sign}`);
    } else if (res?.status !== 200) say('REFUSE', name, res ? `adv answered HTTP ${res.status}` : 'adv unreachable');
    else if (isNew) say('REFUSE', name, 'live; --new names only absent sets');
    else if (await res.json().then(advertised).catch(() => null) !== set.roles) say('REFUSE', name, 'live with other keys; a live set is never rewritten, rotate to a new name');
    else if (listed && !held) say('REFUSE', name, `live at --url, yet the wrangler target lacks ${secret}`);
    else say('ok', name, 'live and unchanged');
  }
  // A null value is a tombstone: the set was revoked, and a Worker version rolled back past the revoke serves it again
  // while the target's secret list no longer shows it. A deploy from the current secrets drops it.
  for (const { name, secret } of tombs) {
    const res = await io.fetch(`${base(o.url)}/${name}/adv`).catch(() => null);
    const kept = listed?.has(secret);
    if (res?.status === 404 && !kept) say('revoked', name, '404');
    else if (kept) say('REFUSE', name, res?.status === 404 ? `absent at --url, yet the wrangler target holds ${secret}` : `revoked ${name} is a live secret; run keyset revoke ${name}`);
    else if (res?.status !== 200) say('REFUSE', name, res ? `adv answered HTTP ${res.status}` : 'adv unreachable');
    else if (!listed) say('REFUSE', name, `revoked ${name} is served; cannot tell rollback from live secret without the target's secret list`);
    else say('REVOKED-LIVE', name, 'served by a rolled-back version; --apply redeploys from current secrets to drop it');
  }

  if (listed) for (const s of [...listed].filter((s) => s.startsWith('TANG_KEY_') && !(s in input)).sort()) say('drift', s, 'live, absent from stdin; left in place');
  else if (o.apply) say('REFUSE', 'wrangler target', 'wrangler secret list gave no list to match --url against');
  else if (io.env.CLOUDFLARE_API_TOKEN) io.stdout.write('drift report failed: wrangler secret list gave no list\n');
  else io.stdout.write('drift report skipped: CLOUDFLARE_API_TOKEN is unset\n');

  if (refused) {
    io.stderr.write(`${refused} refused${o.apply ? '; nothing deployed' : ''}\n`);
    return 1;
  }
  if (!o.apply) return 0;

  const dir = await mkdtemp(join(tmpdir(), 'keyset-'));
  let code, child;
  // A signal while wrangler runs removes the secrets file before keyset exits, and stops wrangler too.
  const onSignal = (sig) => {
    rmSync(dir, { recursive: true, force: true });
    child?.kill(sig);
    io.process.exit(128 + constants.signals[sig]);
  };
  for (const sig of SIGNALS) io.process.on(sig, onSignal);
  try {
    const file = join(dir, 'secrets.json');
    await writeFile(file, JSON.stringify(Object.fromEntries(sets.filter((s) => s.isNew).map((s) => [s.secret, s.text]))), { mode: 0o600, flag: 'wx' });
    ({ code } = await io.wrangler(['deploy', '--secrets-file', file, ...extra], { onSpawn: (p) => { child = p; } }));
  } finally {
    for (const sig of SIGNALS) io.process.off(sig, onSignal);
    await rm(dir, { recursive: true, force: true });
  }
  if (code !== 0) throw new Error(`wrangler deploy exited ${code}`);

  let failed = 0;
  for (const { name, set } of sets) {
    for (let i = 1; ; i++) {
      try {
        io.stdout.write((await check(o.url, name, set, io)).join('\n') + '\n');
        break;
      } catch (e) {
        if (i < io.tries) { await io.wait(); continue; }
        io.stderr.write(`FAIL ${e.message}\n`);
        failed++;
        break;
      }
    }
  }
  for (const { name } of tombs) {
    let status;
    const adv = () => io.fetch(`${base(o.url)}/${name}/adv`).then((r) => r.status, () => 'unreachable');
    for (let i = 1; (status = await adv()) !== 404 && i < io.tries; i++) await io.wait();
    if (status === 404) io.stdout.write(`OK  revoked ${name}: 404\n`);
    else {
      io.stderr.write(`FAIL revoked ${name}: adv answered ${status} after the deploy\n`);
      failed++;
    }
  }
  return failed ? 1 : 0;
}

async function revoke(argv, io) {
  const { o, pos: [name, ...more], extra } = args(argv, { url: { type: 'string' }, apply: { type: 'boolean' } });
  if (!o.url || !NAME.test(name ?? '') || more.length) throw new Error(`revoke takes one set name and --url\n${USAGE}`);
  const secret = secretName(name);
  const adv = () => io.fetch(`${base(o.url)}/${name}/adv`).then((r) => r.status, () => 'unreachable');
  const status = await adv();
  if (!o.apply) {
    io.stdout.write(`would delete ${secret} (adv ${name}: ${status})\n`);
    return 0;
  }
  // --url and the wrangler target are named apart: the set must be live at the one and held by the other.
  if (status !== 200) throw new Error(`adv ${name}: ${status} at --url, not live; nothing deleted`);
  const listed = await secrets(io, extra);
  if (!listed) throw new Error('wrangler secret list gave no list; nothing deleted');
  if (!listed.has(secret)) {
    throw new Error(`the wrangler target does not hold ${secret}, yet --url serves ${name}: likely a rolled-back Worker version; `
      + `nothing deleted. To drop it, keyset deploy --apply with "${secret}": null (a tombstone)`);
  }
  io.stdout.write(`deleting ${secret} (adv ${name}: ${status})\n`);
  const { code } = await io.wrangler(['secret', 'delete', secret, ...extra]);
  if (code !== 0) throw new Error(`wrangler secret delete exited ${code}`);
  for (let i = 0; i < io.tries; i++) {
    if (await adv() === 404) {
      io.stdout.write(`OK  adv ${name}: 404, revoked; keep ${name} in your key store as a null entry (a tombstone) so every deploy proves it stays revoked\n`);
      return 0;
    }
    await io.wait();
  }
  throw new Error(`adv ${name} still answers after ${io.tries} tries`);
}

async function mint(argv, io) {
  const { o, pos, extra } = args(argv, { curve: { type: 'string', default: 'P-521' } });
  const c = CURVES[o.curve];
  if (!c || pos.length || extra.length) throw new Error(`new takes --curve P-256 or P-521, or nothing for P-521\n${USAGE}`);
  const key = async (algo, uses, alg, ops) => {
    const { privateKey } = await crypto.subtle.generateKey({ name: algo, namedCurve: c.crv }, true, uses);
    const { d, x, y } = await crypto.subtle.exportKey('jwk', privateKey);
    return { alg, crv: c.crv, d, key_ops: ops, kty: 'EC', x, y };
  };
  const sig = await key('ECDSA', ['sign', 'verify'], c.signAlg, ['sign', 'verify']);
  const exch = await key('ECDH', ['deriveBits'], 'ECMR', ['deriveKey']);
  io.stdout.write(JSON.stringify({ keys: [sig, exch] }) + '\n');
  io.stderr.write(`${await thumbprint(sig)}\n`);
  return 0;
}

export async function main(argv, io = {}) {
  io = {
    fetch: globalThis.fetch,
    wrangler: runWrangler,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    env: process.env,
    process,
    tries: 30,
    wait: () => new Promise((r) => setTimeout(r, 2000)),
    ...io,
  };
  const [verb, ...rest] = argv;
  try {
    if (verb === 'new') return await mint(rest, io);
    if (verb === 'deploy') return await deploy(rest, io);
    if (verb === 'revoke') return await revoke(rest, io);
    if (verb === 'check' && rest.length === 2 && NAME.test(rest[1])) {
      const set = await loadSet(await readAll(io.stdin));
      try {
        io.stdout.write((await check(rest[0], rest[1], set, io)).join('\n') + '\n');
        return 0;
      } catch (e) {
        io.stderr.write(`FAIL ${e.message}\n`);
        return 1;
      }
    }
    io.stderr.write(USAGE);
    return 2;
  } catch (e) {
    io.stderr.write(`keyset: ${e.message}\n`);
    return 1;
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
