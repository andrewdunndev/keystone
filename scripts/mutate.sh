#!/bin/bash
# Mutation check: every mutant of src/ and bin/ must fail the suite. Run from the repo root after npm ci.
set -u
export NODE_OPTIONS=--disable-warning=ExperimentalWarning
root=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -r src bin test package.json "$work"/
ln -s "$root/node_modules" "$work/node_modules"
cd "$work"
node --import ./test/register.mjs test/gen-fixture.mjs >/dev/null || exit 1
node --import ./test/register.mjs --test test/*.test.js >/dev/null || { echo "baseline suite fails"; exit 1; }

survived=0
mutant() {
  local f=${3:-src/index.js}
  cp "$root"/src/*.js src/; cp "$root"/bin/*.mjs bin/
  sed -i "$2" "$f"
  if [ "$(< "$root/$f")" = "$(< "$f")" ]; then
    echo "NOT APPLIED  $1"; survived=$((survived + 1)); return
  fi
  if timeout 120 node --import ./test/register.mjs --test test/*.test.js >/dev/null 2>&1; then
    echo "SURVIVED     $1"; survived=$((survived + 1))
  else
    echo "killed       $1"
  fi
}

mutant "X+G built from -G" 's/const l = mod((GY - y)/const l = mod((P - GY - y)/'
mutant "second ECDH on X, not X+G" 's/ecdhX(c, d, x2, y2)/ecdhX(c, d, x, y)/'
mutant "+-G answered by the general path" 's/if (x === GX) {/if (false) {/'
mutant "+-G answer with the sign flipped" 's/yq = y === GY ? ys : P - ys;/yq = y === GY ? P - ys : ys;/'
mutant "y negated" 's/xq = q; yq = mod(/xq = q; yq = P - mod(/'
mutant "a = +3 in y recovery" 's/(xs \* q - 3n)/(xs * q + 3n)/'
mutant "rec y leading zero dropped" "s|fromHex(hex(yq, c.coord))|fromHex(hex(yq, c.coord).replace(/^00/, ''))|"
mutant "rec x leading zero dropped" "s|fromHex(hex(xq, c.coord))|fromHex(hex(xq, c.coord).replace(/^00/, ''))|"
mutant "client point imported on P-384" "s/{ name: 'ECDH', namedCurve: c.crv }, false, \\[\\]/{ name: 'ECDH', namedCurve: 'P-384' }, false, []/"
mutant "no x mod-p reduction" 's/  x %= P; y/  y/'
mutant "no y mod-p reduction" 's/x %= P; y %= P;/x %= P;/'
mutant "on-curve check left to importKey" '/!== 0n) return reply(400, .point not on curve/d'
mutant "sign with SHA-384" "s/hash: signHash }, await privateKey/hash: 'SHA-384' }, await privateKey/"
mutant "adv header names ES256 whatever the curve" 's/{"alg":"${signAlg}"/{"alg":"ES256"/'
mutant "signature over payload only" 's/enc.encode(`${prot}.${payload}`)/enc.encode(payload)/'
mutant "key cache keyed by secret name" 's/prepared.has(raw)/prepared.has(secret)/; s/prepared.set(raw,/prepared.set(secret,/; s/prepared.get(raw)/prepared.get(secret)/'
mutant "revoked set not 404" "s/reply(404, 'unknown key set/reply(200, 'x/"
mutant "unreadable set not 500" "s/reply(500, 'unreadable key set/reply(404, 'x/"
mutant "no coordinate length cap" 's/ \&\& s.length <= coordCap(c.coord)//'
mutant "coordinate cap at one field size" 's/Math.ceil((coord \* 2 \* 4) \/ 3)/Math.ceil((coord * 4) \/ 3)/'
mutant "coordinate cap one character short" 's/Math.ceil((coord \* 2 \* 4) \/ 3)/Math.ceil((coord * 2 * 4) \/ 3) - 1/'
mutant "coordinates padded to 32 bytes" 's/padStart(coord \* 2,/padStart(64,/'
mutant "ECDH output truncated to 32 bytes" 's/}, d, c.coord \* 8)));/}, d, 256)));/'
mutant "rec on P-521 whatever the set's curve" "s/import { b64u, kidMatches,/import { CURVES, b64u, kidMatches,/; s/const { exch, curve: c } = set;/const { exch } = set, c = CURVES['P-521'];/"
mutant "rec skips the crv-equals-set check" 's/ || jwk.crv !== c.crv//'
mutant "rec reply names P-521 whatever the set's curve" "s/alg: 'ECMR', crv: c.crv,/alg: 'ECMR', crv: 'P-521',/"
mutant "kid matches SHA-256 only" "s/^const THP_HASH = .*/const THP_HASH = { 43: 'SHA-256' };/" src/jwk.js
mutant "kid length names the wrong hash" "s/43: 'SHA-256'/43: 'SHA-384'/" src/jwk.js
mutant "kid cache ignores the hash" 's/cache\[h\] ??=/cache.any ??=/' src/jwk.js
mutant "kid cache shared across keys" 's/cache\[h\] ??=/kidMatches[h] ??=/' src/jwk.js
mutant "inverted thumbprint comparison" 's/=== kid;/!== kid;/' src/jwk.js
mutant "bare array accepted" 's/keys = JSON.parse(text)?.keys;/keys = JSON.parse(text); keys = Array.isArray(keys) ? keys : keys?.keys;/' src/jwk.js
mutant "a second signing key accepted" "s/if (set\[role\]) throw/if (set[role] \&\& role !== 'sign') throw/" src/jwk.js
mutant "wrong curve accepted" 's/if (k.crv !== curve.crv) throw/if (false) throw/' src/jwk.js
mutant "mixed-curve set accepted" 's/for (const k of \[set.sign, set.exch\])/for (const k of [set.sign])/' src/jwk.js
mutant "alg/curve mismatch accepted" 's/const curve = SIGN_CURVE\[set.sign.alg\];/const curve = CURVES[set.sign.crv];/' src/jwk.js
mutant "ES512 on P-256" "s/ES512: CURVES\['P-521'\]/ES512: CURVES['P-256']/" src/jwk.js
mutant "P-521 coordinates of 65 bytes" 's/coord: 66/coord: 65/' src/jwk.js
mutant "P-256 b off by one" 's/27d2604bn,/27d2604cn,/' src/jwk.js
mutant "missing alg accepted" "s/ROLE\[k?.alg\]/ROLE[k?.alg ?? 'ECMR']/" src/jwk.js
mutant "missing d accepted" "s/\['x', 'y', 'd'\]/['x', 'y']/" src/jwk.js
mutant "missing x accepted" "s/\['x', 'y', 'd'\]/['y', 'd']/" src/jwk.js
mutant "wrong kty accepted" "s/k.kty !== 'EC' || //" src/jwk.js
mutant "inherited alg names a role" 's/__proto__: null, //' src/jwk.js
mutant "JSON error quotes the set" "s/catch { throw new Error('not JSON'); }/catch (e) { throw e; }/" src/jwk.js
mutant "imported key shared across keys" 's/(e.key ??= /(privateKey.key ??= /'
mutant "adv/<thp> unchecked" 's/if (thp \&\& !(await kidMatches/if (false \&\& !(await kidMatches/'
mutant "rec accepts the signing key's kid" 's/(await kidMatches(exch.jwk, kid, exch.kids))/(await kidMatches(exch.jwk, kid, exch.kids) || await kidMatches(set.sign.jwk, kid, set.sign.kids))/'
mutant "no 1-mod-4 coordinate reject" 's/ \&\& s.length % 4 !== 1//'
mutant "no body cap on read length" 's/if ((n += value.byteLength) > MAX_BODY) return/n += value.byteLength; if (false) return/'
mutant "body cap checked after the full read" 's/if ((n += value.byteLength) > MAX_BODY) return reader.cancel().then(() => null, () => null);/n += value.byteLength;/; s/if (done) break;/if (done) { if (n > MAX_BODY) return null; break; }/'
mutant "no Content-Length cap" 's/if (Number(request.headers.get(.content-length.)) > MAX_BODY)/if (false)/'
mutant "read-length cap rejects exactly 4 KiB" 's/byteLength) > MAX_BODY) return/byteLength) >= MAX_BODY) return/'
mutant "Content-Length cap rejects exactly 4 KiB" 's/)) > MAX_BODY) return reply(413/)) >= MAX_BODY) return reply(413/'
mutant "client alg not checked" 's/(jwk.alg !== undefined \&\& jwk.alg !== .ECMR.) || //'
mutant "adv imports the exchange key" "s/^  if (thp \&\& .* return null;\$/&\n  await privateKey(set.exch, 'ECDH', 'deriveBits');/"
mutant "rec imports the signing key" "s/^  const { exch, curve: c } = set;\$/&\n  await privateKey(set.sign, 'ECDSA', 'sign');/"

mutant "refused recovery logged and alerted" 's/      if (res.status !== 200) return res;//'
mutant "seen source mailed again" 's/if (await env.UNLOCKS.get(key) !== null) return add(seen, key);//'
mutant "KV cooldown ignored" 's/    if (until > Date.now()) {.*//'
mutant "in-isolate cooldown ignored" 's/ || (coolUntil.get(name) ?? 0) > Date.now()//'
mutant "concurrent requests do not claim the set" 's/  inflight.add(name); inflight.add(key);//'
mutant "source recorded before the send" "s/^    try {\$/    await env.UNLOCKS.put(key, 'pending', { expirationTtl: 300 });\\n&/"
mutant "a refused cooldown write stops the mail" '/`cool:/s/\.catch(() => {})//'
mutant "record not made permanent after the send" 's/    await env.UNLOCKS.put(key, new Date().toISOString());//'
mutant "digest mails an already seen source" 's/if (await env.UNLOCKS.get(seenKey) !== null) {[^}]*}//'
mutant "digest forgets the held queue" 's/    await env.UNLOCKS.delete(v.name);//'
mutant "failed send is not held for the digest" 's/      await hold().catch(() => {});//'
mutant "digest list unbounded" 's/, limit: DIGEST_MAX//'
mutant "held writes uncapped" 's/    if (c.n >= HELD_CAP) return;//'
mutant "mail claims an unlock" 's/received a recovery request/was unlocked/'
mutant "alert failure escapes to the response path" 's/\.catch((e) => console.error(.unlock alert failed:., e.message))//'
mutant "source key drops the ASN" 's/`${name}:${net}:${asn}:${country}`/`${name}:${net}:${country}`/'
mutant "source is the full IPv4 address" "s|\${v4.slice(0, 3).join('.')}.0/24|\${ip}|"
mutant "IPv6 source is a /64" 's/groups.slice(0, 3)/groups.slice(0, 4)/'
mutant "send has no timeout" 's/Promise.race(\[env.ALERT.send(msg), limit\])/env.ALERT.send(msg)/'
mutant "message addressed to the sender" 's/new EmailMessage(env.ALERT_FROM, env.ALERT_TO,/new EmailMessage(env.ALERT_FROM, env.ALERT_FROM,/'
mutant "envelope sender is the recipient" 's/new EmailMessage(env.ALERT_FROM, env.ALERT_TO,/new EmailMessage(env.ALERT_TO, env.ALERT_TO,/'
mutant "header values not stripped of CR and LF" 's/const line = (s) => String(s).replace(.*/const line = (s) => String(s);/'
mutant "body keeps bare LF line ends" 's/    text.replace(.*/    text,/'
mutant "no Message-ID header" 's/Message-ID: <[^>]*>/X-Id: 1/'
mutant "no MIME-Version header" "s/'MIME-Version: 1.0'/'X-V: 1'/"
mutant "alerts on without the binding" 's/env.UNLOCKS \&\& env.ALERT \&\& /env.UNLOCKS \&\& /'

k=bin/keyset.mjs
mutant "deploy rewrites a live set" 's/\.catch(() => null) !== set\.roles)/.catch(() => null) === null)/' $k
mutant "deploy creates an absent set without --new" "s/if (!isNew) say('REFUSE'/if (false) say('REFUSE'/" $k
mutant "deploy hints --new for a revoked set" "s/'absent (never deployed, or revoked); --new only for a freshly minted set'/'absent; pass --new to create it'/" $k
mutant "deploy --new on a live set" "s/else if (isNew) say('REFUSE'/else if (false) say('REFUSE'/" $k
mutant "deploy --new absent from stdin" '/--new names a set absent from stdin/d' $k
mutant "deploy accepts a non-TANG_KEY_ name" 's/ \&\& secretName(name) === secret//' $k
mutant "deploy --new over a secret the wrangler target holds" 's/else if (held) say/else if (false) say/' $k
mutant "deploy ok on a set the wrangler target lacks" 's/else if (listed \&\& !held) say/else if (false) say/' $k
mutant "deploy --apply without the wrangler target's list" "/else if (o.apply) say('REFUSE', 'wrangler target'/d" $k
mutant "apply skips the plan guards" 's/^  if (refused) {$/  if (refused \&\& !o.apply) {/' $k
mutant "plans act without --apply" 's/if (!o.apply) return 0;/if (false) return 0;/' $k
mutant "revoke plan acts" 's/^  if (!o.apply) {$/  if (false) {/' $k
mutant "secrets file not removed" '/await rm(dir, /d' $k
mutant "a signal leaves the secrets file" '/    rmSync(dir, /d' $k
mutant "a signal is not forwarded to wrangler" '/    child?.kill(sig);/d' $k
mutant "a signal exits 1, not 128+signo" 's/exit(128 + constants.signals\[sig\])/exit(1)/' $k
mutant "no SIGHUP handler" "s/, 'SIGHUP'\]/]/" $k
mutant "signal handlers left installed" '/io.process.off(sig, onSignal)/d' $k
mutant "secrets file mode not 0600" 's/mode: 0o600/mode: 0o644/' $k
mutant "secrets file rewrites live sets" 's/sets.filter((s) => s.isNew).map((s) => \[s.secret, s.text\])/sets.map((s) => [s.secret, s.text])/' $k
mutant "apply skips the check after deploy" 's/^  for (const { name, set } of sets) {$/  for (const { name, set } of []) {/' $k
mutant "tombstone written to the secrets file" 's/sets.filter((s) => s.isNew).map((s) => \[s.secret, s.text\])/[...sets.filter((s) => s.isNew), ...tombs].map((s) => [s.secret, s.text ?? null])/' $k
mutant "apply skips the tombstone 404 check" 's/^  for (const { name } of tombs) {$/  for (const { name } of []) {/' $k
mutant "deploy over a tombstone the target holds" 's/    else if (kept) say/    else if (false) say/' $k
mutant "served tombstone passes without a secret list" 's/    else if (!listed) say/    else if (false) say/' $k
mutant "apply skipped when only tombstones need fixing" 's/if (!o.apply) return 0;/if (!o.apply || !sets.some((s) => s.isNew)) return 0;/' $k
mutant "apply skipped when stdin holds only tombstones" 's/if (!o.apply) return 0;/if (!o.apply || !sets.length) return 0;/' $k
mutant "a \"null\" string is not a tombstone" "s/ || (typeof value === 'string' \&\& value.trim() === 'null')//" $k
mutant "deploy --new on a tombstone" "s/if (o.new?.includes(name)) say('REFUSE'/if (false) say('REFUSE'/" $k
mutant "revoke deletes a set not live at --url" 's/if (status !== 200) throw/if (false) throw/' $k
mutant "revoke deletes a secret the wrangler target lacks" 's/if (!listed.has(secret)) {/if (false) {/' $k
mutant "revoke apply skips the 404 poll" 's/if (await adv() === 404) {/if (true) {/' $k
mutant "revoke omits the tombstone reminder" 's/, revoked; keep .* stays revoked/, revoked/' $k
mutant "check skips the signature verification" 's/if (!await crypto.subtle.verify(/if (false \&\& !await crypto.subtle.verify(/' $k
mutant "check accepts an adv carrying a private key" "s/if (keys.some((k) => 'd' in k)) return null;//" $k
mutant "rec proof compares against S, not ECDH(r, S)" 's/if (got !== want)/if (got !== set.exch.x)/' $k
mutant "a set's private key need not match its public key" 's/\.catch(() => { throw new Error(`the ${k.alg} private key does not match its public key`); });/.catch(() => {});/' $k
mutant "a failed check prints the exchange private key" 's/the reply is not the set/${set.exch.d} the reply is not the set/' $k
mutant "check verifies the adv with SHA-256" "s/hash: signHash }, vk,/hash: 'SHA-256' }, vk,/" $k
mutant "check expects ES256 whatever the curve" 's/,${set.curve.signAlg} ${set.thp.sign}/,ES256 ${set.thp.sign}/' $k
mutant "rec proof point always on P-256" "s/namedCurve: crv }, true, \\['deriveBits'\\]/namedCurve: 'P-256' }, true, ['deriveBits']/" $k
mutant "rec proof truncated to 32 bytes" 's/r.privateKey, coord \* 8)/r.privateKey, 256)/' $k
mutant "keyset new defaults to P-256" "s/default: 'P-521'/default: 'P-256'/" $k
mutant "keyset new takes a bad --curve as P-521" "s/const c = CURVES\\[o.curve\\];/const c = CURVES[o.curve] ?? CURVES['P-521'];/" $k
mutant "keyset new ignores --curve for the keys" "s/namedCurve: c.crv }, true, uses/namedCurve: 'P-521' }, true, uses/" $k
mutant "keyset new labels the signing key ES512 always" "s/c.signAlg, \\['sign'/'ES512', ['sign'/" $k
mutant "keyset new takes extra arguments" 's/if (!c || pos.length || extra.length) throw/if (!c) throw/' $k

echo "survived: $survived"
[ "$survived" -eq 0 ]
