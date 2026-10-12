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
mutant "bare array accepted" 's/const keys = obj?.keys;/const keys = Array.isArray(obj) ? obj : obj?.keys; if (Array.isArray(obj)) obj = { keys };/' src/jwk.js
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
mutant "unknown member accepted" 's/if (Object.keys(obj).some((m) => !MEMBERS.includes(m))) throw/if (false) throw/' src/jwk.js
mutant "empty list accepted" 's/!Array.isArray(v) || !v.length || /!Array.isArray(v) || /' src/jwk.js
mutant "33 allow entries accepted" 's/const ALLOW_MAX = 32;/const ALLOW_MAX = 33;/' src/jwk.js
mutant "6 approvers accepted" 's/const APPROVERS_MAX = 5;/const APPROVERS_MAX = 6;/' src/jwk.js
mutant "approver pattern unchecked" 's/ \&\& APPROVER.test(x)//' src/jwk.js
mutant "non-ASCII approver accepted" 's/ \&\& \/^\[\\x21-\\x7e\]+\$\/.test(x)//' src/jwk.js
mutant "repeated approver accepted" 's/if (new Set(a.map((x) => x.toLowerCase())).size !== a.length) throw/if (false) throw/' src/jwk.js
mutant "approver repeat case-sensitive" 's/new Set(a.map((x) => x.toLowerCase()))/new Set(a)/' src/jwk.js
mutant "allow entries unparsed" 's/\.map(parseCidr);/;/' src/jwk.js
mutant "policy tag ignores approvers" 's/JSON.stringify(\[set.allow ?? null, set.approvers ?? null\])/JSON.stringify([set.allow ?? null])/' src/jwk.js
mutant "derived keys ignore their purpose" "s/info: enc.encode(info)/info: enc.encode('keystone')/" src/jwk.js
o=src/origin.js
mutant "IPv4 prefix floor /7" 's/4: \[8, 32\]/4: [7, 32]/' $o
mutant "IPv6 prefix floor /15" 's/6: \[16, 128\]/6: [15, 128]/' $o
mutant "v4-mapped prefix accepted" 's/if (a.v === 6 \&\& len >= 96 \&\& a.n >> 32n === MAPPED) throw/if (false) throw/' $o
mutant "240.0.0.0/4 prefix accepted" 's/if (a.v === 4 \&\& a.n >= CLASS_E) throw/if (false) throw/' $o
mutant "host bits accepted" 's/if (net !== a.n) throw/if (false) throw/' $o
mutant "v4-mapped address not folded" 's/a?.v === 6 \&\& a.n >> 32n === MAPPED ?/false ?/' $o
mutant "dotted IPv6 tail unparsed" 's/^  if (tail) {$/  if (false) {/' $o
mutant "a single zero group compressed" 's/run\[1\] - run\[0\] < 2 ?/run[1] - run[0] < 1 ?/' $o
mutant "the last longest zero run compressed" 's/if (j - i > run\[1\] - run\[0\])/if (j - i >= run[1] - run[0])/' $o
mutant "imported key shared across keys" 's/(e.key ??= /(privateKey.key ??= /'
mutant "adv/<thp> unchecked" 's/if (thp \&\& !(await kidMatches/if (false \&\& !(await kidMatches/'
mutant "rec accepts the signing key's kid" 's/(await kidMatches(set.exch.jwk, arg, set.exch.kids))/(await kidMatches(set.exch.jwk, arg, set.exch.kids) || await kidMatches(set.sign.jwk, arg, set.sign.kids))/'
mutant "no 1-mod-4 coordinate reject" 's/ \&\& s.length % 4 !== 1//'
mutant "no body cap on read length" 's/if ((n += value.byteLength) > cap) return/n += value.byteLength; if (false) return/'
mutant "body cap checked after the full read" 's/if ((n += value.byteLength) > cap) return reader.cancel().then(() => null, () => null);/n += value.byteLength;/; s/if (done) break;/if (done) { if (n > cap) return null; break; }/'
mutant "no Content-Length cap" 's/if (Number(request.headers.get(.content-length.)) > MAX_BODY)/if (false)/'
mutant "read-length cap rejects exactly 4 KiB" 's/byteLength) > cap) return/byteLength) >= cap) return/'
mutant "Content-Length cap rejects exactly 4 KiB" 's/)) > MAX_BODY) return reply(413/)) >= MAX_BODY) return reply(413/'
mutant "client alg not checked" 's/(jwk.alg !== undefined \&\& jwk.alg !== .ECMR.) || //'
mutant "adv imports the exchange key" "s/^  if (thp \&\& .* return null;\$/&\n  await privateKey(set.exch, 'ECDH', 'deriveBits');/"
mutant "rec imports the signing key" "s/^  const { exch, curve: c } = set;\$/&\n  await privateKey(set.sign, 'ECDSA', 'sign');/"

mutant "malformed body reaches the exchange" 's/      if (point instanceof Response) return point;//'
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
mutant "source key drops the ASN" 's/${name}:${net}:${asn}:${country}${refused/${name}:${net}:${country}${refused/'
mutant "source is the full IPv4 address" 's|format({ v: 4, n: (a.n >> 8n) << 8n })}/24|format(a)}/24|' src/origin.js
mutant "IPv6 source is a /64" 's/groups(a.n).slice(0, 3)/groups(a.n).slice(0, 4)/' src/origin.js
mutant "send has no timeout" 's/Promise.race(\[env.ALERT.send(msg), limit\])/env.ALERT.send(msg)/' src/gate.js
mutant "message addressed to the sender" 's/new EmailMessage(env.ALERT_FROM, to,/new EmailMessage(env.ALERT_FROM, env.ALERT_FROM,/' src/gate.js
mutant "envelope sender is the recipient" 's/new EmailMessage(env.ALERT_FROM, to,/new EmailMessage(to, to,/' src/gate.js
mutant "alert addressed to the sender" 's/=> send(env, env.ALERT_TO,/=> send(env, env.ALERT_FROM,/'
mutant "header values not stripped of CR and LF" 's/const line = (s) => String(s).replace(.*/const line = (s) => String(s);/' src/gate.js
mutant "body keeps bare LF line ends" 's/    text.replace(.*/    text,/' src/gate.js
mutant "no Message-ID header" 's/Message-ID: <[^>]*>/X-Id: 1/' src/gate.js
mutant "no MIME-Version header" "s/'MIME-Version: 1.0'/'X-V: 1'/" src/gate.js
mutant "alerts on without the binding" 's/env.UNLOCKS \&\& env.ALERT \&\& /env.UNLOCKS \&\& /'
mutant "adv headers without the probe" 's/      if (probed(request)) {/      if (true) {/'
mutant "no version header" "/res.headers.set('keystone-version'/d"
mutant "no policy header" "/if (tag) res.headers.set('keystone-policy', tag);/d"
mutant "origin check skipped" 's/      if (set.gated \&\& unadmittable(ip, request.cf?.asn)) return refuse/      if (false) return refuse/'
mutant "admission skipped" 's/        const why = await admit(set, name, ip, request, env);/        const why = null;/'
mutant "allow miss served" "s/if (!set.approvers) return 'allow';/if (!set.approvers) return null;/"
mutant "fail-closed error on every request" 's/  if (!failed.has(name)) {/  if (true) {/'
mutant "refusal logged on every request" "s/  if (why !== 'held' \&\& (loggedAt.get(key) ?? 0) <= Date.now()) {/  if (why !== 'held') {/"
mutant "a held origin logged as refused" "s/  if (why !== 'held' \&\& (loggedAt/  if ((loggedAt/"
mutant "refusal never alerts" "s/if ((why === 'allow' || why === 'origin') \&\& /if (false \&\& /"
mutant "held and failed-closed requests alert" "s/(why === 'allow' || why === 'origin')/(why !== 'probe')/"
mutant "a probed refusal alerts" 's/ \&\& !probed(request) \&\& alertsOn(env)/ \&\& alertsOn(env)/'
mutant "a refusal marks the source seen" "s/\${refused ? ':refused' : ''}//"
mutant "a probed miss reaches the Gate" "s/  if (probed(request)) return 'probe';//"
mutant "fail-closed checks GATE alone" 's/^const gateBound = (env) => env.GATE \&\& env.ALERT \&\& env.ALERT_FROM;/const gateBound = (env) => env.GATE;/'
mutant "a probed adv hides an unbound Gate" "/res.headers.set('keystone-gate', 'unavailable');/d"
mutant "an ungated set's adv reports the Gate" "s/if (set.approvers \&\& !gateBound(env)) res.headers.set/if (!gateBound(env)) res.headers.set/"
mutant "Gate answers not cached" 's/  if ((answered.get(at)?.until ?? 0) > now)/  if (false)/'
mutant "capped answers cached per set" "s/answered.set(at,/answered.set(why === 'capped' ? name : at,/; s/  if ((answered.get(at)?.until ?? 0) > now) return answered.get(at).why;/  for (const k of [at, name]) if ((answered.get(k)?.until ?? 0) > now) return answered.get(k).why;/"
mutant "answers cached for a minute" 's/const ANSWER_TTL = 5000;/const ANSWER_TTL = 60000;/'
mutant "a decision leaves the cached answer" '/  answered.delete(`${name} ${t.o}`);/d'
mutant "a grant refused" "s/  if (why === 'served') return null;/  if (false) return null;/"
mutant "token expiry not enforced" 's/  if (t.e <= Date.now()) return page(410/  if (false) return page(410/'
mutant "token live at its expiry" 's/if (t.e <= Date.now())/if (t.e < Date.now())/'
mutant "a POST from anywhere decides" "s/  if (request.headers.get('Origin') !== new URL(request.url).origin) return page(403/  if (false) return page(403/"
mutant "any method decides" "s/if (request.method !== 'GET' \&\& request.method !== 'POST') return reply(405/if (false) return reply(405/"
mutant "the approval page over http" "s|  if (new URL(request.url).protocol !== 'https:') return reply(403|  if (false) return reply(403|"
mutant "links follow the request scheme and port" 's|base: `https://${new URL(request.url).hostname}`,|base: new URL(request.url).origin,|'
mutant "a removed approver's link works" 's/if (!t || !set.approvers.includes(t.a)) return/if (!t) return/'
mutant "an unexpected Gate answer admits" "/  if (!\['held', 'denied', 'capped'\].includes(why)) return closed/d"
mutant "an origin refusal advises allow" "s/(refused === 'origin'/(false/"
mutant "approve without the typed name" "s/ || (decision === 'approve' \&\& form.get('confirm') !== name)//"
mutant "any content type read as a form" 's/ ? await readBody(request, 256) : null;/ \&\& false ? 0 : await readBody(request, 256);/'
mutant "form body capped at 4 KiB" 's/await readBody(request, 256)/await readBody(request)/'
mutant "a GET decides" "s/    const { p, others } = await gate(env).view(name, t.o, t.p);/    await gate(env).decide(name, t.o, t.p, 'approve', { a: t.a }); const { p, others } = await gate(env).view(name, t.o, t.p);/"
mutant "approve route on a set without approvers" 's/if (op === .approve. \&\& arg \&\& set.approvers)/if (op === "approve" \&\& arg)/'
mutant "no CSP on the page" "/'content-security-policy': /d"
mutant "page sends the referrer anywhere" "s/'referrer-policy': 'same-origin'/'referrer-policy': 'unsafe-url'/"
mutant "page values unescaped" 's/^const esc = (s) => String(s).replace(.*/const esc = (s) => String(s);/'
g=src/gate.js
mutant "a denied origin reopened" "s/      if (p.state === 'denied') return 'denied';//" $g
mutant "a held origin reopened" "s/      if (p.state === 'open') {/      if (false) {/" $g
mutant "a grant never ends" "s/      if (p.grantUntil > now) return 'served';/      if (p.grantUntil) return 'served';/" $g
mutant "a grant live at its end" 's/if (p.grantUntil > now)/if (p.grantUntil >= now)/' $g
mutant "a grant of 11 minutes" 's/export const GRANT = 10 \* 60 \* 1000;/export const GRANT = 11 * 60 * 1000;/' $g
mutant "a pending lives 13 hours" 's/export const PENDING_TTL = 12 \* 3600 \* 1000;/export const PENDING_TTL = 13 * 3600 * 1000;/' $g
mutant "an expired pending kept" 's/    if (p?.expires > now) {/    if (p) {/' $g
mutant "4 open pendings per set" 's/const OPEN_MAX = 3;/const OPEN_MAX = 4;/' $g
mutant "decided pendings count toward the cap" "s/.filter((\[, p\]) => p.state === 'open' \&\& p.expires > now)/.filter(([, p]) => p.expires > now)/" $g
mutant "expired entries never pruned" 's/    await this.prune(now);//' $g
mutant "a replaced pending decided" 's/const live = p?.pid === pid \&\& p.expires > now;/const live = !!p \&\& p.expires > now;/' $g
mutant "an expired pending decided" 's/const live = p?.pid === pid \&\& p.expires > now;/const live = p?.pid === pid;/' $g
mutant "deny on a denied pending" "s/!(p.state === 'open' || (decision === 'approve' \&\& p.state === 'denied'))/!(p.state === 'open' || p.state === 'denied')/" $g
mutant "approve on an approved pending" "s/(decision === 'approve' \&\& p.state === 'denied')/(decision === 'approve')/" $g
mutant "a late grant cut at the pending's expiry" 's/, expires: Math.max(p.expires, now + GRANT) });/ });/' $g
mutant "a replaced pending shown" 's/return { p: p?.pid === pid \&\& p.expires > now ? p : null, others };/return { p, others };/' $g
mutant "an expired pending shown" 's/p?.pid === pid \&\& p.expires > now ? p : null/p?.pid === pid ? p : null/' $g
mutant "the approve key is the policy key" "s/'keystone-approve-v1'/'keystone-policy-v1'/" $g
mutant "other origins include this one" 's/.filter((o) => o.origin !== origin)/.filter(() => true)/' $g
mutant "the token MAC ignores the set name" 's/enc.encode(`${name}.${payload}`)/enc.encode(payload)/' $g
mutant "the token MAC unchecked" 's/if (!m || !(await crypto.subtle.verify(/if (!m || false \&\& !(await crypto.subtle.verify(/' $g
mutant "held mail resent on every miss" 's/if (set.approvers.some((to) => due(p, to)) \&\& retryAt(p.mail) <= now)/if (true)/' $g
mutant "a fully mailed pending rewritten on a held miss" 's/if (set.approvers.some((to) => due(p, to)) \&\& /if (true \&\& /' $g
mutant "an added approver never mailed" 's/set.approvers.some((to) => due(p, to))/Object.values(p.mail.sent).includes(false)/' $g
mutant "a failed send retried after a minute" 's/const RETRY = 5 \* 60 \* 1000;/const RETRY = 60 * 1000;/' $g
mutant "a retry does not restart the clock" 's/Object.assign(p.mail, { at: now, tries: p.mail.tries + 1 });/p.mail.tries++;/' $g
mutant "a retry not counted" 's/Object.assign(p.mail, { at: now, tries: p.mail.tries + 1 });/p.mail.at = now;/' $g
mutant "no backoff" 's/Math.min(RETRY_MAX, RETRY \* 2 \*\* (m.tries - 1))/RETRY/' $g
mutant "backoff past an hour" 's/^const RETRY_MAX = 3600 \* 1000;/const RETRY_MAX = 7200 * 1000;/' $g
mutant "a delivered message never recorded" 's/      q.mail.sent\[to\] = true;//' $g
mutant "a failed send recorded as delivered" 's/if (!ok || q?.pid !== p.pid) continue;/if (q?.pid !== p.pid) continue;/' $g
mutant "a stale send marks the new pending" 's/if (!ok || q?.pid !== p.pid) continue;/if (!ok || !q) continue;/' $g
mutant "a failed send keeps its unit" '/approval mail to ${to} for ${name} failed/{n;d;}' $g
mutant "a failed notice keeps its unit" '/capped notice to ${to} for ${name} failed/{n;d;}' $g
mutant "a refund refused at the cap" 's/if (d > 0 \&\& m.n >= MAIL_MAX)/if (m.n >= MAIL_MAX)/' $g
mutant "a notice marker kept when none went out" 's/    else await s.delete(key);//' $g
mutant "a failed send escapes the Gate" 's/console.error(`approval mail to/throw e; console.error(`approval mail to/' $g
mutant "one link for every approver" 's/{ o: origin, p: p.pid, e: p.expires, a: to }/{ o: origin, p: p.pid, e: p.expires, a: set.approvers[0] }/' $g
mutant "a mail link outlives its pending" 's/{ o: origin, p: p.pid, e: p.expires, a: to }/{ o: origin, p: p.pid, e: p.expires + 1e9, a: to }/' $g
mutant "a notice link outlives its pending" 's/{ o: o.origin, p: o.pid, e: o.expires, a: to }/{ o: o.origin, p: o.pid, e: o.expires + 1e9, a: to }/' $g
mutant "mail values not folded to ASCII" 's/^const ascii = (s) => String(s).replace(.*/const ascii = (s) => String(s);/' $g
mutant "other origins left out of the mail" 's/(others.length ? /(false ? /' $g
mutant "a notice on every capped miss" 's/      if (!((await s.get(`c:${name}`))?.expires > now)) await this.notice/      await this.notice/' $g
mutant "notice links signed for approver 0" 's/{ o: o.origin, p: o.pid, e: o.expires, a: to }/{ o: o.origin, p: o.pid, e: o.expires, a: set.approvers[0] }/' $g
mutant "a notice leaves out the refused origin" 's/  ${about(refused)}//' $g
mutant "21 messages an hour" 's/const MAIL_MAX = 20;/const MAIL_MAX = 21;/' $g
mutant "notices outside the cap" 's/      if (!(await this.budget(now))) break;//' $g
mutant "approval mail outside the cap" 's/      if (!due(p, to) || !(await this.budget(now))) continue;/      if (!due(p, to)) continue;/' $g
o=src/origin.js
mutant "allow match ignores the prefix length" 's/a.n >> BigInt(BITS\[c.v\] - c.len) === c.n >> BigInt(BITS\[c.v\] - c.len)/a.n === c.n/' $o
mutant "allow matches across families" 's/(a, c) => a.v === c.v \&\& /(a, c) => /' $o
mutant "AS13335 admitted" 's/ || asn === 13335//' $o
mutant "240.0.0.0/4 address admitted" 's/ || (a.v === 4 \&\& a.n >= CLASS_E)//' $o
mutant "240.0.0.0 admitted" 's/(a.v === 4 \&\& a.n >= CLASS_E) || !Number/(a.v === 4 \&\& a.n > CLASS_E) || !Number/' $o
mutant "a missing ASN admitted" 's/ || !Number.isInteger(asn)//' $o
mutant "no address admitted" 's/=> !a || /=> /' $o

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
mutant "secrets file rewrites live sets" 's/sets.filter((s) => s.isNew || s.policy).map((s) => \[s.secret, s.text\])/sets.map((s) => [s.secret, s.text])/' $k
mutant "secrets file omits a policy edit" 's/sets.filter((s) => s.isNew || s.policy)/sets.filter((s) => s.isNew)/' $k
mutant "policy edit planned as ok" "s/else if (res.headers.get('keystone-policy') !== set.tag) {/else if (false) {/" $k
mutant "policy write skips the version gate" 's/if (writes.length \&\& (o.apply || io.env.CLOUDFLARE_API_TOKEN))/if (false)/' $k
mutant "split deployment taken as one version" 's/versions?.length === 1 \&\& versions\[0\].percentage === 100 \&\& //' $k
mutant "version mismatch accepted" 's/else if (version !== live) say/else if (false) say/' $k
mutant "check ignores the live policy" "/the live policy is not the set's/d" $k
mutant "a 403 skipped for an ungated set" 's/if (rep.status === 403 \&\& set.tag)/if (rep.status === 403)/' $k
mutant "keyset sends no probe header" 's/{ headers: PROBE }/{}/' $k
mutant "apply skips the check after deploy" 's/^  for (const { name, set } of sets) {$/  for (const { name, set } of []) {/' $k
mutant "tombstone written to the secrets file" 's/sets.filter((s) => s.isNew || s.policy).map((s) => \[s.secret, s.text\])/[...sets.filter((s) => s.isNew), ...tombs].map((s) => [s.secret, s.text ?? null])/' $k
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
mutant "check passes an unbound Gate" "/=== 'unavailable') throw new Error/d" $k
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
