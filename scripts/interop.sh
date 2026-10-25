#!/bin/bash
# clevis interop against `wrangler dev` with sets minted by keyset (a-1 on P-521, b-1 on P-256), then revocation, then
# the origin gate over https: clevis held, approved from the local mail, then decrypting. Run from the repo root after
# npm ci, with tang, clevis, jose and curl, on deploy/wrangler.toml (copied from the example when absent), so the bindings
# are the shipped ones. `interop.sh luks` adds, as root in a throwaway container with clevis-luks, cryptsetup, socat and
# python3, a cross-check with stock tangd on the same keys and a LUKS2 bind and unlock.
set -u
luks=${1:-}
W=http://127.0.0.1:8787 T=http://127.0.0.1:8788
cfg=deploy/wrangler.toml gcfg=deploy/wrangler.gate.toml vars=deploy/.dev.vars copied=
for f in $vars $gcfg; do [ -e $f ] && { echo "$f exists; move it aside first"; exit 1; }; done
[ -e $cfg ] || { cp deploy/wrangler.toml.example $cfg; copied=1; }
curl -s -o /dev/null $W/ && { echo "$W is taken"; exit 1; }
work=$(mktemp -d) pid=
# wrangler dev runs as its own process group, workerd included; only that group is stopped.
stop() { [ -n "$pid" ] && kill -- -"$pid" 2>/dev/null && wait "$pid" 2>/dev/null; pid=; }
trap 'stop; rm -f $vars $gcfg; [ -n "$copied" ] && rm -f $cfg; rm -rf "$work"' EXIT
keyset() { node bin/keyset.mjs "$@"; }
keyset new > "$work/a-1.json" 2> "$work/a-1.thp"
keyset new --curve P-256 > "$work/b-1.json" 2> "$work/b-1.thp"
devvars() { for n in "$@"; do echo "TANG_KEY_$(echo $n | tr a-z- A-Z_)='$(cat "$work/$n.json")'"; done > $vars; }
# worker [config] [http|https]
worker() {
  stop; sleep 1
  WRANGLER_SEND_METRICS=false setsid nohup node_modules/.bin/wrangler dev --config "${1:-$cfg}" --port 8787 --ip 127.0.0.1 \
    --local-protocol "${2:-http}" --persist-to "$work/state" > "$work/wrangler.log" 2>&1 < /dev/null &
  pid=$!
  for _ in $(seq 60); do curl -sk -o /dev/null "${2:-http}://127.0.0.1:8787/" && return; sleep 1; done
  echo "wrangler dev did not start"; tail -5 "$work/wrangler.log"; exit 1
}
tangd() { setsid socat TCP-LISTEN:8788,reuseaddr,fork,bind=127.0.0.1 EXEC:"/usr/libexec/tangd $work/tangd" </dev/null >/dev/null 2>&1 & sleep 0.5; }
thp() { curl -s "$1/adv" | jose fmt -j- -g payload -y -o- | jose fmt -j- -g keys -A -g 0 -o- | jose jwk thp -i-; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
runs() { "$@" > /dev/null 2>&1 && echo yes || echo no; }
sorted() { python3 -c 'import json,sys;j=json.load(sys.stdin);print(sorted(j["keys"],key=lambda k:k["alg"]) if "keys" in j else json.dumps(j,sort_keys=True))'; }
ok() { if [ "$2" = "$3" ]; then echo "PASS  $1 ($3)"; else echo "FAIL  $1 (want $2, got $3)"; fails=$((fails + 1)); fi; }
fails=0

echo "== keyset check, clevis encrypt/decrypt"
devvars a-1 b-1; worker
for n in a-1 b-1; do
  keyset check $W $n < "$work/$n.json"; ok "keyset check $n" 0 "$?"
  thp=$(thp $W/$n)
  ok "$n adv thp equals keyset new's" "$(cat "$work/$n.thp")" "$thp"
  echo -n "secret $n" | clevis encrypt tang "{\"url\":\"$W/$n\",\"thp\":\"$thp\"}" > "$work/$n.jwe"
  ok "clevis decrypt $n" "secret $n" "$(clevis decrypt < "$work/$n.jwe")"
done

if [ "$luks" = luks ]; then
  echo "== cross-check: a-1's keys served by stock tangd"
  mkdir "$work/tangd"
  jose fmt -j- -g keys -g 0 -o "$work/tangd/sig.jwk" < "$work/a-1.json"
  jose fmt -j- -g keys -g 1 -o "$work/tangd/exch.jwk" < "$work/a-1.json"
  K=$(jose jwk thp -i "$work/tangd/exch.jwk")
  C=$(jose jwk gen -i '{"alg":"ECMR","crv":"P-521"}' | jose jwk pub -i- -o-)
  tangd
  ok "tangd adv payload equals Worker adv payload (decoded, sorted)" \
    "$(curl -s $W/a-1/adv | jose fmt -j- -g payload -y -o- | sorted)" "$(curl -s $T/adv | jose fmt -j- -g payload -y -o- | sorted)"
  ok "tangd rec equals Worker rec for one client point" \
    "$(curl -s -X POST -d "$C" $W/a-1/rec/$K | sorted)" "$(curl -s -X POST -d "$C" $T/rec/$K | sorted)"

  echo "== LUKS2 bind and unlock, tangd stopped"
  pkill -f 'socat TCP-LISTEN:8788'; ok "no tangd running" 1 "$(pgrep -f /usr/libexec/tangd >/dev/null; echo $?)"
  truncate -s 64M "$work/vol.img"; echo -n escrowpass > "$work/pass"
  # a container's /dev does not gain loop nodes made after it started
  n=$(losetup -f | sed 's|^/dev/loop\([0-9]*\).*|\1|'); [ -b /dev/loop$n ] || mknod /dev/loop$n b 7 $n
  vol=$(losetup --show /dev/loop$n "$work/vol.img")
  cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$vol" "$work/pass"
  clevis luks bind -y -d "$vol" -k "$work/pass" tang "{\"url\":\"$W/a-1\",\"thp\":\"$(cat "$work/a-1.thp")\"}"
  clevis luks list -d "$vol"
  n0=$(grep -c 'POST /a-1/rec' "$work/wrangler.log"); r0=$(grep -c '"event":"rec","name":"a-1"' "$work/wrangler.log")
  clevis luks unlock -d "$vol" -n ks-unlock; ok "clevis luks unlock via Worker" 0 "$?"
  ok "mapping active" 0 "$(cryptsetup status ks-unlock >/dev/null; echo $?)"
  ok "Worker served the rec POST" 1 "$(( $(grep -c 'POST /a-1/rec' "$work/wrangler.log") - n0 ))"
  ok "Worker logged one rec line" 1 "$(( $(grep -c '"event":"rec","name":"a-1"' "$work/wrangler.log") - r0 ))"
  cryptsetup close ks-unlock 2>/dev/null
fi

echo "== revocation: a-1's secret removed, restart"
devvars b-1; worker
ok "/a-1/adv" 404 "$(code $W/a-1/adv)"
ok "clevis decrypt a-1" no "$(runs clevis decrypt < "$work/a-1.jwe")"
ok "clevis decrypt b-1" "secret b-1" "$(clevis decrypt < "$work/b-1.jwe")"
keyset check $W a-1 < "$work/a-1.json" 2> "$work/check.err"; ok "keyset check a-1" 1 "$?"
ok "keyset check a-1 names the 404" yes "$(runs grep 'HTTP 404' "$work/check.err")"

if [ "$luks" = luks ]; then
  ok "clevis luks unlock" no "$(runs clevis luks unlock -d "$vol" -n ks-revoked)"
  cryptsetup close ks-revoked 2>/dev/null
  devvars a-1 b-1; worker
  clevis luks unlock -d "$vol" -n ks-restored; ok "unlock after restoring the secret" 0 "$?"
  cryptsetup close ks-restored 2>/dev/null
  losetup -d "$vol"
fi

echo "== origin gate over https: clevis held, approved from the mailed link, then decrypting"
# The example config with ALERT and ALERT_FROM bound; ALERT_TO stays unset, so the only mail is the approval.
sed -e 's/^# \[\[send_email\]\]$/[[send_email]]/' -e 's/^# name = "ALERT"$/name = "ALERT"/' -e 's/^# \[vars\]$/[vars]/' \
  -e 's/^# ALERT_FROM = /ALERT_FROM = /' $cfg > $gcfg
ok "gate config binds ALERT and ALERT_FROM" 2 "$(grep -cE '^(name = "ALERT"|ALERT_FROM = )' $gcfg)"
keyset new 2> "$work/g-1.thp" | node -e 'const s = JSON.parse(require("fs").readFileSync(0));
  console.log(JSON.stringify({ ...s, allow: ["192.0.2.0/24"], approvers: ["ops@example.org"] }))' > "$work/g-1.json"
devvars g-1; worker $gcfg https
G=https://127.0.0.1:8787
# clevis's curl trusts the dev server's self-signed certificate, issued for 127.0.0.1, through CURL_CA_BUNDLE.
node -e 'const s = require("tls").connect(8787, "127.0.0.1", { rejectUnauthorized: false }, () => {
  const b64 = s.getPeerCertificate().raw.toString("base64").match(/.{1,64}/g).join("\n");
  console.log(`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`); s.end(); })' > "$work/dev.pem"
export CURL_CA_BUNDLE="$work/dev.pem"
echo -n "secret g-1" | clevis encrypt tang "{\"url\":\"$G/g-1\",\"thp\":\"$(cat "$work/g-1.thp")\"}" > "$work/g-1.jwe"
ok "clevis encrypt g-1" 0 "$?"
# A booting host: clevis retries until the approval lands or a minute passes.
( for _ in $(seq 30); do timeout 15 clevis decrypt < "$work/g-1.jwe" > "$work/g-1.out" 2>/dev/null && exit 0; sleep 2; done; exit 1 ) &
boot=$!
mail=
for _ in $(seq 30); do mail=$(grep -o '/[^ ]*\.eml' "$work/wrangler.log" | tail -1); [ -n "$mail" ] && break; sleep 1; done
ok "the held rec mailed the approver" yes "$(runs test -s "$mail")"
ok "g-1 held" yes "$(runs grep -q '"event":"held","name":"g-1"' "$work/wrangler.log")"
ok "clevis decrypt g-1 before approval" no "$(runs test -s "$work/g-1.out")"
link=$(grep -o 'https://[^ ]*/g-1/approve/[^ ]*' "$mail" 2>/dev/null | tr -d '\r')
ap=$G/${link#https://*/}
ok "approval page" 200 "$(code "$ap")"
ok "approve with the typed name" 200 "$(code -H "Origin: $G" --data 'decision=approve&confirm=g-1' "$ap")"
wait $boot
ok "clevis decrypt g-1 after approval" "secret g-1" "$(cat "$work/g-1.out")"

echo "failures: $fails"
[ "$fails" -eq 0 ]
