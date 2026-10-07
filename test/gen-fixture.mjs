// Builds test/tangd-fixture.json from stock tangd, one fixture per curve: P-521 keys from tangd-keygen's defaults, P-256
// keys from jose. Needs tang (/usr/libexec/tangd, /usr/libexec/tangd-keygen) and jose on PATH. The fixture is gitignored
// and rebuilt before each test run.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { p256, p521 } from '@noble/curves/nist.js';
import { b64u, CURVES } from '../src/jwk.js';

const NOBLE = { 'P-256': p256, 'P-521': p521 };
const OTHER = { 'P-256': 'P-521', 'P-521': 'P-256' };
const read = (dir, file) => JSON.parse(readFileSync(join(dir, file)));
const KEYS = {
  'P-521': (dir) => {
    execFileSync('/usr/libexec/tangd-keygen', [dir, 'sig', 'exch']);
    const keys = [read(dir, 'sig.jwk'), read(dir, 'exch.jwk')];
    for (const k of keys) if (k.crv !== 'P-521') throw new Error(`tangd-keygen made a ${k.crv} key, not P-521`);
    return keys;
  },
  'P-256': (dir) => [[{ alg: 'ES256' }, 'sig.jwk'], [{ alg: 'ECMR', crv: 'P-256' }, 'exch.jwk']].map(([tmpl, file]) => {
    execFileSync('jose', ['jwk', 'gen', '-i', JSON.stringify(tmpl), '-o', join(dir, file)]);
    return read(dir, file);
  }),
};

const be = (n, len) => Uint8Array.from(n.toString(16).padStart(len * 2, '0').match(/../g).map((x) => parseInt(x, 16)));
const bytes = (n) => Math.ceil(n.toString(16).length / 2);
const randPoint = (n) => n.Point.BASE.multiply(n.Point.Fn.fromBytes(n.utils.randomSecretKey())).toAffine();

function fixture(crv) {
  const { coord: COORD, signAlg } = CURVES[crv], n = NOBLE[crv], p = n.Point.Fp.ORDER;
  // A coordinate below 2^TOP has a leading zero byte.
  const TOP = BigInt(8 * (COORD - 1));
  const dir = mkdtempSync(join(tmpdir(), 'tangfx-'));
  const [sig, exch] = KEYS[crv](dir);
  const kid = execFileSync('jose', ['jwk', 'thp', '-i-'], { input: JSON.stringify(exch) }).toString().trim();

  const tangd = (req) => {
    const r = spawnSync('/usr/libexec/tangd', [dir], { input: req });
    const [head, ...rest] = r.stdout.toString().split('\r\n\r\n');
    const body = rest.join('\r\n\r\n');
    return { status: +head.split(' ')[1], body: body ? JSON.parse(body) : null };
  };
  const post = (path, json) =>
    tangd(`POST ${path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/jwk+json\r\nContent-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}`);
  const jwkOf = (x, y, c = crv) => ({ alg: 'ECMR', crv: c, key_ops: ['deriveKey'], kty: 'EC', x: b64u.enc(x), y: b64u.enc(y) });

  const pt = randPoint(n);
  const client = jwkOf(be(pt.x, COORD), be(pt.y, COORD));
  let lz;
  do lz = randPoint(n); while (lz.x >> TOP);
  const other = OTHER[crv], oc = CURVES[other].coord, op = randPoint(NOBLE[other]);

  // Inputs whose tangd status the Worker must reproduce.
  const probes = {
    offCurve: { ...client, y: client.x },
    longCoord: jwkOf(be(pt.x, COORD + 1), be(pt.y, COORD)),
    atCap: jwkOf(be(pt.x, 2 * COORD), be(pt.y, COORD)),
    shortCoord: jwkOf(be(lz.x, COORD).slice(1), be(lz.y, COORD)),
    zero: jwkOf(be(0n, COORD), be(0n, COORD)),
    aboveP: jwkOf(be(pt.x + p, Math.max(COORD, bytes(pt.x + p))), be(pt.y, COORD)),
    yAboveP: jwkOf(be(pt.x, COORD), be(pt.y + p, Math.max(COORD, bytes(pt.y + p)))),
    wrongCrv: { ...client, crv: other },
    otherCurve: jwkOf(be(op.x, oc), be(op.y, oc), other),
    otherPoint: jwkOf(be(op.x, oc), be(op.y, oc)),
    badLen: { ...client, x: 'AAAAA' },
    algSign: { ...client, alg: signAlg },
    noAlg: (({ alg, ...c }) => c)(client),
    notJson: '{not json',
  };
  const probeOut = {};
  for (const [name, body] of Object.entries(probes)) {
    probeOut[name] = post(`/rec/${kid}`, typeof body === 'string' ? body : JSON.stringify(body));
  }
  // Client points whose recovered x, then y, has a leading zero byte: tangd pads them to COORD bytes.
  const d = BigInt('0x' + Buffer.from(b64u.dec(exch.d)).toString('hex'));
  const leading = (axis) => {
    let q;
    do q = randPoint(n); while (n.Point.fromAffine(q).multiply(d).toAffine()[axis] >> TOP);
    return jwkOf(be(q.x, COORD), be(q.y, COORD));
  };
  const leadingZero = leading('x'), leadingZeroY = leading('y');
  // Padding past the Worker's cap: tangd's status is recorded, the Worker refuses it.
  const pastCap = jwkOf(be(pt.x, 2 * COORD + 1), be(pt.y, COORD));
  const pastCapStatus = post(`/rec/${kid}`, JSON.stringify(pastCap)).status;

  const rec = post(`/rec/${kid}`, JSON.stringify(client));
  const recLz = post(`/rec/${kid}`, JSON.stringify(leadingZero));
  const recLzY = post(`/rec/${kid}`, JSON.stringify(leadingZeroY));
  const adv = tangd('GET /adv HTTP/1.1\r\nHost: x\r\n\r\n');
  const badKid = post('/rec/nope', JSON.stringify(client));
  rmSync(dir, { recursive: true });
  if (rec.status !== 200 || adv.status !== 200) throw new Error(`${crv}: tangd rec ${rec.status} adv ${adv.status}`);
  console.log(crv, 'fixture from tangd, kid', kid, 'probes', Object.entries(probeOut).map(([k, v]) => `${k}=${v.status}`).join(' '),
    'pastCap', pastCapStatus);
  return {
    sig, exch, kid, client, leadingZero, leadingZeroY, probes, probeOut, pastCap, pastCapStatus, badKidStatus: badKid.status,
    tangdRec: rec.body, tangdRecLz: recLz.body, tangdRecLzY: recLzY.body, tangdAdv: adv.body,
  };
}

writeFileSync(new URL('./tangd-fixture.json', import.meta.url),
  JSON.stringify(Object.fromEntries(Object.keys(CURVES).map((crv) => [crv, fixture(crv)])), null, 1));
