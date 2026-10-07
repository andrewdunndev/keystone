![hero](hero.svg)

# keystone

A Tang server for clevis network-bound disk encryption, running as a Cloudflare Worker.
It speaks the protocol of stock `tangd`: one signing and one ECMR exchange key per set, on P-521 or P-256.

## Routes

One Worker serves many named key sets, each under its own path segment (`[a-z0-9-]`, up to 63 characters):

| Route | Method | Answer |
|---|---|---|
| `/<name>/adv` | GET | the set's advertisement (JWS over its public keys) |
| `/<name>/adv/<thp>` | GET | the same, when `<thp>` is the signing key's thumbprint; 404 otherwise |
| `/<name>/rec/<kid>` | POST | McCallum-Relyea recovery, when `<kid>` names the exchange key; 404 otherwise |

A clevis pin uses `{"url":"https://tang.example/<name>","thp":"<signing key thumbprint>"}`.
Over HTTPS, the initramfs needs name resolution and a CA bundle, or clevis cannot reach keystone at boot.

## Key sets

A set lives only in the Worker secret `TANG_KEY_<NAME>`, `<NAME>` being the path segment upper-cased with `-` becoming
`_`. Its value is `{"keys":[<signing key>,<ECMR key>]}`: exactly those two private JWKs, each with `alg`, on one
curve: P-521 with ES512, or P-256 with ES256. A missing secret answers 404; a malformed one answers 500 and logs the
secret's name, never its value.

Sets are write-once: a name keeps its keys for life.

### Curves

P-521 is the default, as in stock `tangd-keygen`, whose key pairs deploy as sets. In practice it needs Workers Paid:
on Workers, `rec` measured 7 ms CPU median and up to 12 ms cold, past the Free plan's 10 ms limit. P-256
(`keyset new --curve P-256`) fits the Free plan: up to 6 ms cold.

### Lifecycle

`keyset` (`bin/keyset.mjs`) plans unless given `--apply`, prints private keys only from `new`, and deletes only the one
set `revoke` names. Arguments after `--` go to wrangler; name the deploy config there, as `deploy --apply` redeploys the
Worker from it. The first deployment is a plain `wrangler deploy`.

```sh
keyset() { node bin/keyset.mjs "$@"; }        # after npm ci
keyset new | pass insert -m tang/server-1     # stderr: the pin's thp
pass tang/server-1 | jq -R '{TANG_KEY_SERVER_1: .}' |
  keyset deploy --url https://tang.example --new server-1 --apply -- --config deploy/wrangler.toml
pass tang/server-1 | keyset check https://tang.example server-1
keyset revoke server-1 --url https://tang.example --apply -- --config deploy/wrangler.toml
```

`deploy` plans each set as `ok` (live, same keys), `new` (absent, named by `--new`), `revoked` (a `null` tombstone,
404) or `REFUSE`, applies only when nothing is refused, then checks every set. `--apply`, here and in
`revoke`, refuses when `wrangler secret list` disagrees
with what `--url` serves. With `CLOUDFLARE_API_TOKEN` set, a plan reports live sets missing from its input. Each check
sends a real `rec`, which can raise an alert and marks its source seen.
Stock tooling works too: a `tangd-keygen` pair in `{"keys":[...]}`, then `wrangler secret put`.

### Rotation

1. Mint, deploy with `--new` and check the next name, say `server-2`.
2. `clevis luks bind -d <dev> tang '{"url":"https://tang.example/server-2","thp":"<thp>"}'`.
3. Reboot; check the disk unlocks through the new slot.
4. `clevis luks unbind -d <dev> -s <old slot>`.
5. Revoke `server-1` as above.
6. Replace its keys in your key store with `null` and never deploy them: they still open disk copies taken before
   step 4.

## Unlock alerts

When a `rec` succeeds from a source new to that set, keystone mails one alert through a Cloudflare Email Workers
`send_email` binding; the Worker holds no mail credential. A source is the client's /24 (IPv4) or /48 (IPv6) with its
ASN and country. Alerts are off unless all of these are bound:

- `UNLOCKS`: a Workers KV namespace for seen sources, cooldowns and held sources.
- `ALERT`: `send_email = [{ name = "ALERT", destination_address = "you@example.org" }]`,
  a verified Email Routing destination address.
- `ALERT_FROM`, `ALERT_TO`: vars; `ALERT_TO` is that destination, `ALERT_FROM` an address on an Email Routing
  domain.
- An hourly cron trigger, for the digest.

A failed alert is logged and never changes the unlock. Each set sends at most one alert an hour; up to five sources
met in the cooldown are held for the next digest.

Every successful `rec` logs one JSON line, `{"event":"rec","name":…,"ip":…,"asn":…,"country":…}`, without key
material; the example `wrangler.toml` enables Workers Logs.

## Security model

- Private keys sit in Worker secrets, which cannot be read back once written.
- Revocation is the control: deleting `TANG_KEY_<NAME>` makes the set's routes answer 404, and its disks stop
  unlocking. `rec` answers any client, as in `tangd`.
- Worker versions carry their secrets: a rollback past a revoke serves the revoked set again, unseen by `wrangler
  secret list`. Never roll back across a revoke; tombstones make every deploy detect and drop it.
- Whoever controls the Cloudflare account controls the keys: protect it like the disks themselves.
- `adv` is public by design, as in `tangd`: it carries only public keys.
- Availability: on the Free plan every request counts toward the daily Workers quota. A flood can exhaust it, and bound
  hosts fall back to their passphrase until it resets; a WAF rate limit mitigates.
- The alert is a tripwire, not an audit log: Workers Logs records every successful `rec`.

## Test

Stock `tangd` is the oracle: on fresh keys of each curve every run, the Worker must match its advertisements,
recoveries and verdicts on malformed points.

```sh
npm ci && npm test             # needs tang and jose
npm run mutate                 # each mutant must fail the suite
bash scripts/interop.sh        # clevis and revocation against wrangler dev
bash scripts/interop.sh luks   # as root: adds tangd and a LUKS2 unlock
```
