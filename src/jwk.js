// The key set format, in WebCrypto and standard JS so any runtime can load it: one signing key and one ECMR exchange
// key, private JWKs on one curve: ES256 with P-256 (as `jose jwk gen` writes them) or ES512 with P-521 (as
// tangd-keygen writes them).
const enc = new TextEncoder();
// Each curve is y^2 = x^3 - 3x + b over GF(p), with base point G = (gx, gy) and coordinates of `coord` bytes.
export const CURVES = Object.freeze({
  __proto__: null,
  'P-256': Object.freeze({
    crv: 'P-256', coord: 32, signAlg: 'ES256', signHash: 'SHA-256',
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  }),
  'P-521': Object.freeze({
    crv: 'P-521', coord: 66, signAlg: 'ES512', signHash: 'SHA-512',
    p: (1n << 521n) - 1n,
    b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
    gx: 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
    gy: 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
  }),
});

export const b64u = {
  enc(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const p = str.replace(/-/g, '+').replace(/_/g, '/');
    const s = atob(p + '='.repeat((4 - (p.length % 4)) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  },
};

const canonical = (jwk) => enc.encode(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`);
const digest = async (h, jwk) => b64u.enc(new Uint8Array(await crypto.subtle.digest(h, canonical(jwk))));

// RFC 7638 thumbprint (SHA-256) of an EC public JWK; matches `jose jwk thp`.
export const thumbprint = (jwk) => digest('SHA-256', jwk);

// tangd accepts a thumbprint hashed with any of these (older clevis sends S1); WebCrypto has no SHA-224.
// Each digest has its own base64url length, so a kid names the one hash worth computing. `cache` holds one key's digests.
const THP_HASH = { 27: 'SHA-1', 43: 'SHA-256', 64: 'SHA-384', 86: 'SHA-512' };

export async function kidMatches(jwk, kid, cache = {}) {
  const h = THP_HASH[kid.length];
  return !!h && await (cache[h] ??= digest(h, jwk)) === kid;
}

// A set named <name> lives in the secret TANG_KEY_<NAME>: upper-cased, '-' -> '_'.
export const NAME = /^[a-z0-9-]{1,63}$/;
export const secretName = (name) => `TANG_KEY_${name.toUpperCase().replace(/-/g, '_')}`;

const ROLE = { __proto__: null, ES256: 'sign', ES512: 'sign', ECMR: 'exch' };
const SIGN_CURVE = { __proto__: null, ES256: CURVES['P-256'], ES512: CURVES['P-521'] };
const PRIVATE = ['x', 'y', 'd'];

// {"keys":[...]} holding exactly one signing key and one ECMR key, private EC JWKs with their alg, both on the signing
// alg's curve; anything else throws. The set comes back with its CURVES entry. Messages never quote the text, which
// carries private keys.
export function parseSet(text) {
  let keys;
  try { keys = JSON.parse(text)?.keys; } catch { throw new Error('not JSON'); }
  if (!Array.isArray(keys)) throw new Error('not a {"keys":[...]} object');
  const set = {};
  for (const k of keys) {
    const role = ROLE[k?.alg];
    if (!role) throw new Error('a key is neither ES256, ES512 nor ECMR');
    if (set[role]) throw new Error(`more than one ${role === 'sign' ? 'signing' : 'ECMR'} key`);
    if (k.kty !== 'EC' || !PRIVATE.every((f) => typeof k[f] === 'string' && k[f])) {
      throw new Error(`the ${k.alg} key is not an EC private key`);
    }
    set[role] = k;
  }
  if (!set.sign || !set.exch) throw new Error('want one signing key (ES256 or ES512) and one ECMR key');
  const curve = SIGN_CURVE[set.sign.alg];
  for (const k of [set.sign, set.exch]) {
    if (k.crv !== curve.crv) throw new Error(`the ${k.alg} key is not on ${curve.crv}, the curve of ${set.sign.alg}`);
  }
  return { sign: set.sign, exch: set.exch, curve };
}
