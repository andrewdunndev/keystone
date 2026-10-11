// Addresses and prefixes as { v: 4 | 6, n: BigInt, len }. A v4-mapped IPv6 address (::ffff:a.b.c.d) folds to IPv4.
const BITS = { 4: 32, 6: 128 };
const PREFIX = { 4: [8, 32], 6: [16, 128] };
const MAPPED = 0xffffn;
const CLASS_E = 0xf0000000n;

function quad(s) {
  const p = s.split('.');
  if (p.length !== 4 || !p.every((x) => /^\d{1,3}$/.test(x) && +x <= 255)) return null;
  return p.reduce((n, x) => (n << 8n) | BigInt(x), 0n);
}

// An address as written, IPv6 left unfolded; null when it is neither family.
function parse(s) {
  s = typeof s === 'string' ? s.trim().toLowerCase() : '';
  if (!s.includes(':')) {
    const n = quad(s);
    return n === null ? null : { v: 4, n };
  }
  const tail = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const n = quad(tail[2]);
    if (n === null) return null;
    s = `${tail[1]}${(n >> 16n).toString(16)}:${(n & 0xffffn).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const [a, b] = halves.map((h) => (h ? h.split(':') : []));
  if (b && a.length + b.length > 7) return null;
  const groups = b ? [...a, ...Array(8 - a.length - b.length).fill('0'), ...b] : a;
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return { v: 6, n: groups.reduce((n, g) => (n << 16n) | BigInt(`0x${g}`), 0n) };
}

export function parseIp(s) {
  const a = parse(s);
  return a?.v === 6 && a.n >> 32n === MAPPED ? { v: 4, n: a.n & 0xffffffffn } : a;
}

const groups = (n) => Array.from({ length: 8 }, (_, i) => ((n >> BigInt(112 - 16 * i)) & 0xffffn).toString(16));

// RFC 5952 text: the first longest run of two or more zero groups becomes ::.
export function format({ v, n }) {
  if (v === 4) return [24n, 16n, 8n, 0n].map((s) => (n >> s) & 255n).join('.');
  const g = groups(n);
  let run = [0, 0];
  for (let i = 0; i < 8; i++) {
    let j = i;
    while (j < 8 && g[j] === '0') j++;
    if (j - i > run[1] - run[0]) run = [i, j];
    i = j;
  }
  return run[1] - run[0] < 2 ? g.join(':') : `${g.slice(0, run[0]).join(':')}::${g.slice(run[1]).join(':')}`;
}

// An allow entry; throws naming what is wrong and, for set host bits, the canonical form.
export function parseCidr(s) {
  const m = typeof s === 'string' ? /^([^/]+)\/(\d{1,3})$/.exec(s) : null;
  const a = m && parse(m[1]);
  if (!a) throw new Error(`allow entry ${JSON.stringify(String(s).slice(0, 64))} is not an address/prefix`);
  const len = +m[2], [lo, hi] = PREFIX[a.v], host = BigInt(BITS[a.v] - len);
  if (len < lo || len > hi) throw new Error(`allow entry ${s}: IPv${a.v} prefixes run /${lo} to /${hi}`);
  if (a.v === 6 && len >= 96 && a.n >> 32n === MAPPED) throw new Error(`allow entry ${s} is v4-mapped; write it as IPv4`);
  if (a.v === 4 && a.n >= CLASS_E) throw new Error(`allow entry ${s} overlaps 240.0.0.0/4`);
  const net = (a.n >> host) << host;
  if (net !== a.n) throw new Error(`allow entry ${s} has host bits set; write ${format({ v: a.v, n: net })}/${len}`);
  return { v: a.v, n: net, len };
}

export const inCidr = (a, c) => a.v === c.v && a.n >> BigInt(BITS[c.v] - c.len) === c.n >> BigInt(BITS[c.v] - c.len);

// The /24 (IPv4) or /48 (IPv6) an address sits in; null when it is neither.
export function sourceNet(ip) {
  const a = parseIp(ip);
  if (!a) return null;
  return a.v === 4 ? `${format({ v: 4, n: (a.n >> 8n) << 8n })}/24` : `${groups(a.n).slice(0, 3).join(':')}::/48`;
}

// AS13335 is Cloudflare's own egress (WARP, Workers): an origin there, in 240.0.0.0/4 or with no address is never admitted.
export const unadmittable = (a, asn) => !a || (a.v === 4 && a.n >= CLASS_E) || asn === 13335;
