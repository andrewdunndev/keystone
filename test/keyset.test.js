import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import worker from '../src/index.js';
import { b64u, parseSet, thumbprint } from '../src/jwk.js';
import { main } from '../bin/keyset.mjs';

const URL = 'https://tang.example';
console.log = () => {};
const enc = new TextEncoder();

// Every private key minted here; no run of check, deploy or revoke may print one.
const privates = [];
const mint = async (...flags) => {
  const r = await main(['new', ...flags], { stdout: { write: (s) => { mint.out = s; } }, stderr: { write: (s) => { mint.err = s; } } });
  assert.equal(r, 0);
  for (const k of JSON.parse(mint.out).keys) privates.push(k.d);
  return { text: mint.out.trim(), thp: mint.err.trim() };
};
const A = await mint(), B = await mint(), C = await mint(), D = await mint('--curve', 'P-256');
// One stock pair per curve, built by gen-fixture.mjs: P-521 from tangd-keygen, P-256 from jose.
const FX = JSON.parse(readFileSync(`${import.meta.dirname}/tangd-fixture.json`, 'utf8'));
const stock = Object.fromEntries(Object.entries(FX).map(([crv, f]) => [crv, JSON.stringify({ keys: [f.sig, f.exch] })]));
for (const f of Object.values(FX)) privates.push(f.sig.d, f.exch.d);

const toWorker = (env) => (url, init) => worker.fetch(new Request(url, init), env, { waitUntil() {} });

// keyset in-process: stdio captured, fetch routed to the real Worker holding `live`, wrangler faked and recorded.
async function run(argv, { live = {}, stdin = '', fetch = toWorker(live), wrangler = async () => ({ code: 0, stdout: '' }), env = {}, proc } = {}) {
  const out = [], err = [], calls = [];
  const code = await main(argv, {
    stdin, env, tries: 3, wait: async () => {},
    stdout: { write: (s) => out.push(s) },
    stderr: { write: (s) => err.push(s) },
    fetch,
    wrangler: async (args, opts) => { calls.push(args); return wrangler(args, opts); },
    ...(proc && { process: proc }),
  });
  const r = { code, out: out.join(''), err: err.join(''), calls };
  for (const d of privates) assert.ok(!r.out.includes(d) && !r.err.includes(d), 'private key printed');
  return r;
}
// A wrangler stand-in for the Worker whose secrets are `target`: lists them, deletes one, or takes a
// `deploy --secrets-file`, recording the file as it saw it in `seen` and, with `install`, adding its sets.
const cf = (target, { seen = [], install = true, deployCode = 0 } = {}) => async (args) => {
  if (args[0] === 'secret' && args[1] === 'list') {
    return { code: 0, stdout: JSON.stringify(Object.keys(target).map((name) => ({ name, type: 'secret_text' }))) };
  }
  if (args[0] === 'secret' && args[1] === 'delete') {
    delete target[args[2]];
    return { code: 0, stdout: '' };
  }
  assert.deepEqual(args.slice(0, 2), ['deploy', '--secrets-file']);
  const file = args[2];
  seen.push({ file, args, mode: statSync(file).mode & 0o777, dirMode: statSync(dirname(file)).mode & 0o777, body: JSON.parse(readFileSync(file, 'utf8')) });
  if (install) Object.assign(target, seen.at(-1).body);
  if (deployCode === 'throw') throw new Error('spawn failed');
  return { code: deployCode, stdout: '' };
};
const deploy = (stdin, flags = [], opts = {}) => run(['deploy', '--url', URL, ...flags], { stdin: JSON.stringify(stdin), ...opts });

// Answers adv with a payload re-signed by `set`'s signing key, or rec with `recBody`; anything else goes to the Worker.
const forge = (live, { payload, set, recBody } = {}) => async (url, init) => {
  if (recBody && url.includes('/rec/')) return new Response(JSON.stringify(recBody), { headers: { 'content-type': 'application/jwk+json' } });
  const res = await toWorker(live)(url, init);
  if (!payload || !url.endsWith('/adv')) return res;
  const jws = await res.json();
  jws.payload = b64u.enc(enc.encode(JSON.stringify(payload)));
  const { sign, curve } = parseSet(set);
  const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: curve.crv, x: sign.x, y: sign.y, d: sign.d },
    { name: 'ECDSA', namedCurve: curve.crv }, false, ['sign']);
  jws.signature = b64u.enc(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: curve.signHash }, key, enc.encode(`${jws.protected}.${jws.payload}`))));
  return new Response(JSON.stringify(jws), { headers: { 'content-type': 'application/jose+json' } });
};

test('new prints one set that parseSet accepts, with jose-style alg and key_ops, and its signing thumbprint on stderr', async () => {
  assert.equal(A.text.split('\n').length, 1);
  const { sign, exch } = parseSet(A.text);
  assert.deepEqual([sign.alg, sign.key_ops, exch.alg, exch.key_ops], ['ES512', ['sign', 'verify'], 'ECMR', ['deriveKey']]);
  assert.equal(A.thp, await thumbprint(sign));
  assert.notEqual(A.text, B.text);
});

test('check passes on the live set the Worker serves from new\'s output', async () => {
  const r = await run(['check', URL, 'a-1'], { live: { TANG_KEY_A_1: A.text }, stdin: A.text });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^OK +adv a-1: signed by .*\nOK +rec a-1: .*\n$/);
});

test('new mints P-521 (ES512) by default, and --curve picks P-256 (ES256) or P-521', async () => {
  const curveOf = (text) => { const { sign, exch, curve } = parseSet(text); return [sign.alg, sign.crv, exch.crv, curve.crv]; };
  assert.deepEqual(curveOf(A.text), ['ES512', 'P-521', 'P-521', 'P-521']);
  assert.deepEqual(curveOf(D.text), ['ES256', 'P-256', 'P-256', 'P-256']);
  assert.deepEqual(curveOf((await mint('--curve', 'P-521')).text), ['ES512', 'P-521', 'P-521', 'P-521']);
  assert.deepEqual(curveOf((await mint('--curve=P-256')).text), ['ES256', 'P-256', 'P-256', 'P-256']);
  assert.equal(D.thp, await thumbprint(parseSet(D.text).sign));
});

test('new refuses any other curve, a missing curve, and extra arguments, printing no key', async () => {
  for (const argv of [['--curve', 'P-384'], ['--curve', 'p-256'], ['--curve', 'P256'], ['--curve', 'constructor'], ['--curve', ''],
    ['--curve'], ['--alg', 'ES256'], ['x'], ['--', 'x']]) {
    const r = await run(['new', ...argv]);
    assert.equal(r.code, 1, argv.join(' '));
    assert.equal(r.out, '', argv.join(' '));
    assert.match(r.err, /^keyset: /, argv.join(' '));
  }
});

test('a P-256 and a P-521 set check against the Worker, and fail against each other', async () => {
  const live = { TANG_KEY_A_1: A.text, TANG_KEY_D_1: D.text };
  for (const [name, set] of [['a-1', A], ['d-1', D]]) {
    const r = await run(['check', URL, name], { live, stdin: set.text });
    assert.equal(r.code, 0, r.err);
  }
  for (const [name, set] of [['a-1', D], ['d-1', A]]) {
    const r = await run(['check', URL, name], { live, stdin: set.text });
    assert.equal(r.code, 1);
    assert.match(r.err, new RegExp(`^FAIL adv ${name}: `));
  }
});

test('stock pairs, P-521 from tangd-keygen and P-256 from jose, deploy as new sets in one stdin map and check', async () => {
  const live = {}, seen = [];
  let r = await deploy({ TANG_KEY_T_1: stock['P-521'], TANG_KEY_T_2: stock['P-256'] }, ['--new', 't-1', '--new', 't-2'], { live });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /^new +t-1: absent/m);
  assert.match(r.out, /^new +t-2: absent/m);
  r = await deploy({ TANG_KEY_T_1: stock['P-521'], TANG_KEY_T_2: JSON.parse(stock['P-256']) }, ['--apply', '--new', 't-1', '--new', 't-2'],
    { live, wrangler: cf(live, { seen }) });
  assert.equal(r.code, 0, r.err);
  for (const n of ['t-1', 't-2']) assert.match(r.out, new RegExp(`^OK +adv ${n}:.*\\nOK +rec ${n}:`, 'm'));
  r = await deploy({ TANG_KEY_T_1: stock['P-521'], TANG_KEY_T_2: stock['P-256'] }, [], { live });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /^ok +t-1: live and unchanged$/m);
  assert.match(r.out, /^ok +t-2: live and unchanged$/m);
  for (const [name, crv] of [['t-1', 'P-521'], ['t-2', 'P-256']]) {
    r = await run(['check', URL, name], { live, stdin: stock[crv] });
    assert.equal(r.code, 0, r.err);
  }
});

test('check fails on another set, an absent name, and a set whose private key does not match', async () => {
  const live = { TANG_KEY_A_1: A.text };
  let r = await run(['check', URL, 'a-1'], { live, stdin: B.text });
  assert.equal(r.code, 1);
  assert.match(r.err, /^FAIL adv a-1: the signature does not verify/);
  r = await run(['check', URL, 'b-1'], { live, stdin: B.text });
  assert.equal(r.code, 1);
  assert.match(r.err, /HTTP 404/);
  const keys = JSON.parse(A.text).keys;
  r = await run(['check', URL, 'a-1'], { live, stdin: JSON.stringify({ keys: [{ ...keys[0], d: JSON.parse(B.text).keys[0].d }, keys[1]] }) });
  assert.equal(r.code, 1);
  assert.match(r.err, /ES512 private key does not match/);
});

test('check fails on a tampered adv signature', async () => {
  const live = { TANG_KEY_A_1: A.text };
  const fetch = async (url, init) => {
    const res = await toWorker(live)(url, init);
    if (!url.endsWith('/adv')) return res;
    const jws = await res.json();
    const sig = b64u.dec(jws.signature);
    sig[10] ^= 1;
    return new Response(JSON.stringify({ ...jws, signature: b64u.enc(sig) }));
  };
  const r = await run(['check', URL, 'a-1'], { stdin: A.text, fetch });
  assert.equal(r.code, 1);
  assert.match(r.err, /signature does not verify/);
});

test('check fails on an adv that advertises other keys or a private key, even when signed by the set', async () => {
  const live = { TANG_KEY_A_1: A.text };
  const pub = ({ d, ...k }) => k;
  const [sig, exch] = JSON.parse(A.text).keys;
  for (const keys of [[pub(sig), pub(JSON.parse(B.text).keys[1])], [pub(sig)], [pub(sig), exch], [{ ...pub(sig), alg: 'ECMR' }, { ...pub(exch), alg: 'ES512' }]]) {
    const r = await run(['check', URL, 'a-1'], { stdin: A.text, fetch: forge(live, { payload: { keys }, set: A.text }) });
    assert.equal(r.code, 1);
    assert.match(r.err, /^FAIL adv a-1: the advertised keys are not the set's/);
  }
  const r = await run(['check', URL, 'a-1'], { stdin: A.text, fetch: forge(live, { payload: { keys: [pub(sig), pub(exch)] }, set: A.text }) });
  assert.equal(r.code, 0, r.err);
});

test('check fails when rec answers with the exchange key itself or another point', async () => {
  const live = { TANG_KEY_A_1: A.text };
  const [, exch] = JSON.parse(A.text).keys;
  for (const recBody of [{ alg: 'ECMR', crv: 'P-521', key_ops: ['deriveKey'], kty: 'EC', x: exch.x, y: exch.y }, JSON.parse(B.text).keys[1]]) {
    const r = await run(['check', URL, 'a-1'], { stdin: A.text, fetch: forge(live, { recBody }) });
    assert.equal(r.code, 1);
    assert.match(r.err, /^FAIL rec a-1: /);
  }
});

test('deploy plan: an unchanged live set is ok, as a string or an object, and the drift report is skipped without a token', async () => {
  const live = { TANG_KEY_A_1: A.text };
  for (const v of [A.text, JSON.parse(A.text)]) {
    const r = await deploy({ TANG_KEY_A_1: v }, [], { live });
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /^ok +a-1: live and unchanged$/m);
    assert.match(r.out, /drift report skipped: CLOUDFLARE_API_TOKEN is unset/);
    assert.equal(r.calls.length, 0);
  }
});

test('deploy plan refuses to rewrite a live set', async () => {
  const r = await deploy({ TANG_KEY_A_1: B.text }, [], { live: { TANG_KEY_A_1: A.text } });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +a-1: live with other keys/m);
});

test('deploy plan: an absent set is new only with --new; --new on a live or missing set refuses', async () => {
  const live = { TANG_KEY_A_1: A.text };
  let r = await deploy({ TANG_KEY_B_1: B.text }, [], { live });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +b-1: absent \(never deployed, or revoked\); --new only for a freshly minted set$/m);
  r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: B.text }, ['--new', 'b-1'], { live });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /^new +b-1: absent/m);
  assert.match(r.out, /^ok +a-1:/m);
  r = await deploy({ TANG_KEY_A_1: A.text }, ['--new', 'a-1'], { live });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +a-1: live; --new names only absent sets/m);
  r = await deploy({ TANG_KEY_A_1: A.text }, ['--new', 'c-1'], { live });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +c-1: --new names a set absent from stdin/m);
});

test('deploy plan refuses keys that are not TANG_KEY_<NAME>, sets parseSet rejects, and adv answers other than 200 or 404', async () => {
  for (const key of ['SERVER_1', 'TANG_KEY_server_1', 'TANG_KEY_', 'TANG_KEY_A-1', `TANG_KEY_${'A'.repeat(64)}`, 'FOO']) {
    const r = await deploy({ [key]: A.text }, ['--new', 'server-1']);
    assert.equal(r.code, 1, key);
    assert.match(r.out, new RegExp(`^REFUSE +${key}: not TANG_KEY_<NAME>`, 'm'), key);
  }
  let r = await deploy({ TANG_KEY_A_1: { keys: [JSON.parse(A.text).keys[0]] } }, ['--new', 'a-1']);
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +a-1: want one signing key \(ES256 or ES512\) and one ECMR key$/m);
  r = await deploy({ TANG_KEY_A_1: A.text }, [], { fetch: async () => new Response('', { status: 500 }) });
  assert.match(r.out, /^REFUSE +a-1: adv answered HTTP 500$/m);
  r = await deploy({ TANG_KEY_A_1: A.text }, [], { fetch: async () => { throw new Error('down'); } });
  assert.match(r.out, /^REFUSE +a-1: adv unreachable$/m);
  for (const stdin of ['[]', 'null', '{', '"x"']) {
    r = await run(['deploy', '--url', URL], { stdin });
    assert.equal(r.code, 1);
    assert.match(r.err, /stdin is not a JSON object/);
  }
});

test('deploy reports live TANG_KEY_ secrets missing from stdin when a token is set, and never deletes them', async () => {
  const list = [{ name: 'TANG_KEY_A_1', type: 'secret_text' }, { name: 'TANG_KEY_OLD', type: 'secret_text' }, { name: 'OTHER', type: 'secret_text' }];
  const r = await deploy({ TANG_KEY_A_1: A.text }, ['--', '--env', 'x'], {
    live: { TANG_KEY_A_1: A.text }, env: { CLOUDFLARE_API_TOKEN: 't' },
    wrangler: async (args, opts) => (opts?.capture ? { code: 0, stdout: JSON.stringify(list) } : assert.fail(args.join(' '))),
  });
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(r.calls, [['secret', 'list', '--format', 'json', '--env', 'x']]);
  assert.match(r.out, /^drift +TANG_KEY_OLD: live, absent from stdin; left in place$/m);
  assert.doesNotMatch(r.out, /drift +(TANG_KEY_A_1|OTHER)/);
});

test('deploy --apply refuses before running wrangler deploy when any set is refused', async () => {
  const live = { TANG_KEY_A_1: A.text };
  const r = await deploy({ TANG_KEY_A_1: B.text, TANG_KEY_C_1: C.text }, ['--apply', '--new', 'c-1'], { live, wrangler: cf({ ...live }) });
  assert.equal(r.code, 1);
  assert.deepEqual(r.calls, [['secret', 'list', '--format', 'json']]);
  assert.match(r.err, /nothing deployed/);
});

test('deploy --apply writes only the new sets to a 0600 file in a 0700 dir, removes it, deploys, then checks every set', async () => {
  const live = { TANG_KEY_A_1: A.text }, seen = [];
  const r = await deploy({ TANG_KEY_A_1: JSON.parse(A.text), TANG_KEY_B_1: B.text }, ['--apply', '--new', 'b-1', '--', '--env', 'x'],
    { live, wrangler: cf(live, { seen }) });
  assert.equal(r.code, 0, r.err);
  assert.equal(seen.length, 1);
  const [{ file, args, mode, dirMode, body }] = seen;
  assert.deepEqual(args.slice(3), ['--env', 'x']);
  assert.equal(mode, 0o600);
  assert.equal(dirMode, 0o700);
  assert.deepEqual(body, { TANG_KEY_B_1: B.text });
  assert.ok(!existsSync(dirname(file)));
  for (const n of ['a-1', 'b-1']) assert.match(r.out, new RegExp(`^OK +adv ${n}:.*\\nOK +rec ${n}:`, 'm'));
});

test('deploy --apply removes the secrets file when wrangler fails or throws, and deploys nothing further', async () => {
  for (const deployCode of [1, 'throw']) {
    const seen = [];
    const r = await deploy({ TANG_KEY_B_1: B.text }, ['--apply', '--new', 'b-1'], { wrangler: cf({}, { seen, install: false, deployCode }) });
    assert.equal(r.code, 1);
    assert.equal(seen.length, 1);
    assert.ok(!existsSync(seen[0].file) && !existsSync(dirname(seen[0].file)));
    assert.doesNotMatch(r.out, /^OK/m);
  }
});

test('a signal during deploy --apply removes the secrets file, stops wrangler and exits 128+signo', async () => {
  for (const [sig, no] of [['SIGINT', 2], ['SIGTERM', 15], ['SIGHUP', 1]]) {
    const handlers = new Map(), killed = [], exits = [], seen = {};
    const proc = { on: (s, f) => handlers.set(s, f), off: (s, f) => handlers.get(s) === f && handlers.delete(s), exit: (c) => exits.push(c) };
    const wrangler = async (args, opts) => {
      if (args[0] !== 'deploy') return cf({})(args, opts);
      opts.onSpawn({ kill: (s) => killed.push(s) });
      seen.installed = [...handlers.keys()].sort();
      handlers.get(sig)?.(sig);
      seen.removed = !existsSync(dirname(args[2]));
      return { code: null, stdout: '' };
    };
    const r = await deploy({ TANG_KEY_B_1: B.text }, ['--apply', '--new', 'b-1'], { wrangler, proc });
    assert.deepEqual(seen, { installed: ['SIGHUP', 'SIGINT', 'SIGTERM'], removed: true });
    assert.deepEqual(killed, [sig]);
    assert.deepEqual(exits, [128 + no]);
    assert.equal(handlers.size, 0);
    assert.equal(r.code, 1);
  }
});

test('deploy --apply fails when the deployed Worker does not serve a set afterwards', async () => {
  const live = {};
  const r = await deploy({ TANG_KEY_B_1: B.text }, ['--apply', '--new', 'b-1'], { live, wrangler: cf({}, { install: false }) });
  assert.equal(r.code, 1);
  assert.match(r.err, /^FAIL adv b-1: HTTP 404$/m);
});

test('revoke plans without wrangler; --apply deletes exactly the named secret and waits for adv 404', async () => {
  const live = { TANG_KEY_A_1: A.text, TANG_KEY_B_1: B.text };
  let r = await run(['revoke', 'a-1', '--url', URL], { live });
  assert.equal(r.code, 0);
  assert.equal(r.out, 'would delete TANG_KEY_A_1 (adv a-1: 200)\n');
  assert.deepEqual(r.calls, []);
  r = await run(['revoke', 'a-1', '--url', URL, '--apply', '--', '--env', 'x'], { live, wrangler: cf(live) });
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.calls, [['secret', 'list', '--format', 'json', '--env', 'x'], ['secret', 'delete', 'TANG_KEY_A_1', '--env', 'x']]);
  assert.match(r.out, /^OK +adv a-1: 404, revoked; keep a-1 in your key store as a null entry \(a tombstone\) so every deploy proves it stays revoked$/m);
  assert.deepEqual(Object.keys(live), ['TANG_KEY_B_1']);
});

test('revoke --apply fails when adv never answers 404, or wrangler fails; a bad name runs nothing', async () => {
  const live = { TANG_KEY_A_1: A.text };
  let r = await run(['revoke', 'a-1', '--url', URL, '--apply'], { live, wrangler: cf({ ...live }) });
  assert.equal(r.code, 1);
  assert.match(r.err, /adv a-1 still answers after 3 tries/);
  const list = cf(live);
  r = await run(['revoke', 'a-1', '--url', URL, '--apply'], { live, wrangler: async (args, o) => (args[1] === 'list' ? list(args, o) : { code: 1, stdout: '' }) });
  assert.equal(r.code, 1);
  assert.match(r.err, /wrangler secret delete exited 1/);
  for (const argv of [['revoke', 'A_1', '--url', URL, '--apply'], ['revoke', '--url', URL, '--apply'], ['revoke', 'a-1', 'b-1', '--url', URL, '--apply']]) {
    r = await run(argv, { live });
    assert.equal(r.code, 1);
    assert.deepEqual(r.calls, []);
  }
});

test('deploy --apply refuses when the wrangler target disagrees with --url, or gives no secret list', async () => {
  const live = { TANG_KEY_A_1: A.text };
  const other = { TANG_KEY_A_1: A.text, TANG_KEY_B_1: B.text };
  let r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: B.text }, ['--apply', '--new', 'b-1', '--', '--env', 'y'], { live, wrangler: cf(other) });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +b-1: absent at --url, yet the wrangler target holds TANG_KEY_B_1$/m);
  assert.ok(!r.calls.some((a) => a[0] === 'deploy'));
  r = await deploy({ TANG_KEY_A_1: A.text }, ['--apply'], { live, wrangler: cf({ TANG_KEY_B_1: B.text }) });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +a-1: live at --url, yet the wrangler target lacks TANG_KEY_A_1$/m);
  assert.ok(!r.calls.some((a) => a[0] === 'deploy'));
  for (const fail of [async () => ({ code: 1, stdout: '' }), async () => ({ code: 0, stdout: 'not json' })]) {
    r = await deploy({ TANG_KEY_A_1: A.text }, ['--apply'], { live, wrangler: async (args, o) => (args[0] === 'deploy' ? assert.fail('deployed') : fail(args, o)) });
    assert.equal(r.code, 1);
    assert.match(r.out, /^REFUSE +wrangler target: wrangler secret list gave no list/m);
  }
});

test('revoke --apply deletes nothing when the wrangler target disagrees with --url, naming a rollback and the tombstone fix', async () => {
  const live = { TANG_KEY_A_1: A.text };
  let r = await run(['revoke', 'a-1', '--url', URL, '--apply'], { live, wrangler: cf({ TANG_KEY_B_1: B.text }) });
  assert.equal(r.code, 1);
  assert.match(r.err, /the wrangler target does not hold TANG_KEY_A_1, yet --url serves a-1: likely a rolled-back Worker version; nothing deleted\. To drop it, keyset deploy --apply with "TANG_KEY_A_1": null \(a tombstone\)/);
  assert.deepEqual(r.calls, [['secret', 'list', '--format', 'json']]);
  r = await run(['revoke', 'a-1', '--url', URL, '--apply'], { live, wrangler: async () => ({ code: 1, stdout: '' }) });
  assert.equal(r.code, 1);
  assert.match(r.err, /wrangler secret list gave no list; nothing deleted/);
  assert.equal(r.calls.length, 1);
  r = await run(['revoke', 'b-1', '--url', URL, '--apply'], { live, wrangler: cf({ TANG_KEY_B_1: B.text }) });
  assert.equal(r.code, 1);
  assert.match(r.err, /adv b-1: 404 at --url, not live; nothing deleted/);
  assert.deepEqual(r.calls, []);
});

test('deploy: a null value is a tombstone; a revoked set answering 404 is reported, never written or counted new', async () => {
  const live = { TANG_KEY_A_1: A.text }, seen = [];
  let r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: null }, [], { live });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /^revoked b-1: 404$/m);
  assert.doesNotMatch(r.out, /^new/m);
  r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: null }, ['--apply'], { live, wrangler: cf({ ...live }, { seen }) });
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(seen.map((s) => s.body), [{}]);
  assert.match(r.out, /^OK +revoked b-1: 404$/m);
  r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: 'null' }, [], { live });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /^revoked b-1: 404$/m);
});

test('deploy --apply with only tombstones still redeploys, from an empty secrets file, to drop a rolled-back set', async () => {
  const live = { TANG_KEY_B_1: B.text }, seen = [];
  const store = cf({}, { seen });
  const wrangler = async (args, o) => {
    if (args[0] === 'deploy') delete live.TANG_KEY_B_1;
    return store(args, o);
  };
  const r = await deploy({ TANG_KEY_B_1: null }, ['--apply'], { live, wrangler });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^REVOKED-LIVE b-1: /m);
  assert.deepEqual(seen.map((s) => s.body), [{}]);
  assert.match(r.out, /^OK +revoked b-1: 404$/m);
});

test('deploy --apply drops a revoked set a rolled-back version serves, and fails unless it answers 404 afterwards', async () => {
  for (const drops of [true, false]) {
    const live = { TANG_KEY_A_1: A.text, TANG_KEY_B_1: B.text }, target = { TANG_KEY_A_1: A.text }, seen = [];
    const store = cf(target, { seen });
    const wrangler = async (args, o) => {
      if (args[0] === 'deploy' && drops) delete live.TANG_KEY_B_1;
      return store(args, o);
    };
    let r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: null }, [], { live, wrangler, env: { CLOUDFLARE_API_TOKEN: 't' } });
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /^REVOKED-LIVE b-1: served by a rolled-back version; --apply redeploys from current secrets to drop it$/m);
    assert.ok(!r.calls.some((a) => a[0] === 'deploy'));
    r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: null }, ['--apply'], { live, wrangler });
    assert.ok(r.calls.some((a) => a[0] === 'deploy'));
    assert.deepEqual(seen.map((s) => s.body), [{}]);
    if (drops) {
      assert.equal(r.code, 0, r.err);
      assert.match(r.out, /^OK +revoked b-1: 404$/m);
    } else {
      assert.equal(r.code, 1);
      assert.match(r.err, /^FAIL revoked b-1: adv answered 200 after the deploy$/m);
    }
  }
});

test('deploy refuses a tombstone the wrangler target still holds, one served with no secret list, and --new on one', async () => {
  const live = { TANG_KEY_A_1: A.text, TANG_KEY_B_1: B.text };
  let r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: null }, ['--apply'], { live, wrangler: cf({ ...live }) });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +b-1: revoked b-1 is a live secret; run keyset revoke b-1$/m);
  assert.ok(!r.calls.some((a) => a[0] === 'deploy'));
  r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_C_1: null }, ['--apply'], { live, wrangler: cf({ TANG_KEY_A_1: A.text, TANG_KEY_C_1: C.text }) });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +c-1: absent at --url, yet the wrangler target holds TANG_KEY_C_1$/m);
  assert.ok(!r.calls.some((a) => a[0] === 'deploy'));
  r = await deploy({ TANG_KEY_A_1: A.text, TANG_KEY_B_1: null }, [], { live });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +b-1: revoked b-1 is served; cannot tell rollback from live secret without the target's secret list$/m);
  r = await deploy({ TANG_KEY_C_1: null }, ['--new', 'c-1'], { live });
  assert.equal(r.code, 1);
  assert.match(r.out, /^REFUSE +c-1: null marks a revoked set; --new names only freshly minted sets$/m);
  assert.doesNotMatch(r.out, /absent from stdin/);
});
