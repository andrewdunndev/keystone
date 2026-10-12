# Setup

A key set is one signing key and one exchange key on one curve. A pin's `thp` is the thumbprint of the set's signing key.

## Prerequisites

- A Cloudflare account and a zone on Cloudflare DNS for the Worker's hostname.
- Node 22.15 or later, git, `jq` and `jose` where `keyset` runs, and `clevis` on each host to bind.
- An offline store for key sets, such as `pass`.

```sh
git clone --branch <tag> https://gitlab.com/dunn.dev/keystone.git
cd keystone && npm ci
export KEYSTONE="$PWD"
keyset() { node "$KEYSTONE/bin/keyset.mjs" "$@"; }
```

Authenticate with `npx wrangler login`, or set `CLOUDFLARE_API_TOKEN` (the "Edit Cloudflare Workers" template, plus KV Storage: Edit for alerts). `keyset` runs wrangler non-interactively, so with more than one account set `CLOUDFLARE_ACCOUNT_ID`.

## Quickstart

1. Copy the example config and set the route to your hostname.

   ```sh
   cp "$KEYSTONE/deploy/wrangler.toml.example" "$KEYSTONE/deploy/wrangler.toml"
   ```

2. Deploy the Worker.

   ```sh
   npx wrangler deploy --config "$KEYSTONE/deploy/wrangler.toml"
   ```

3. Confirm the Worker holds no sets; this prints 404.

   ```sh
   curl -s -o /dev/null -w '%{http_code}\n' https://tang.example.org/server-1/adv
   ```

4. Mint a set. The key goes to stdout and the `thp` to stderr. On the Free plan add `--curve P-256`.

   ```sh
   keyset new | pass insert -m tang/server-1
   ```

5. Deploy it. Without `--apply` the command only plans.

   ```sh
   pass tang/server-1 | jq -R '{TANG_KEY_SERVER_1: .}' |
     keyset deploy --url https://tang.example.org --new server-1 --apply -- --config "$KEYSTONE/deploy/wrangler.toml"
   ```

   `keyset` deploys, then checks the advertisement signature and a real recovery.

6. Bind the disk. This reads the `thp` from the live advertisement.

   ```sh
   curl -s https://tang.example.org/server-1/adv | jose fmt -j- -g payload -y -o- |
     jose fmt -j- -g keys -A -g 0 -o- | jose jwk thp -i-
   sudo clevis luks bind -d /dev/sdXN tang '{"url":"https://tang.example.org/server-1","thp":"<thp>"}'
   ```

7. Build the initramfs. It needs network, DNS and a CA bundle to reach the Worker.

   Fedora and RHEL (dracut):

   ```sh
   sudo dnf install clevis clevis-luks clevis-dracut
   echo 'kernel_cmdline="rd.neednet=1"' | sudo tee /etc/dracut.conf.d/clevis.conf
   sudo dracut -f
   ```

   Debian and Ubuntu (initramfs-tools):

   ```sh
   sudo apt install clevis clevis-luks clevis-initramfs
   sudo update-initramfs -u
   ```

   `lsinitrd` and `lsinitramfs` list the image. If it lacks a CA bundle or DNS libraries, add them: on Fedora put `install_items+=" /etc/pki/tls/certs/ca-bundle.crt "` in a file under `/etc/dracut.conf.d` and rerun `dracut -f`. On Debian set `GRUB_CMDLINE_LINUX="ip=dhcp"` in `/etc/default/grub`, run `update-grub`.

8. Reboot. The disk unlocks without a passphrase.

## Rotate and revoke

Keys are write-once: `keyset` refuses different keys under a live name, so rotation uses a new name.

1. Mint `server-2`; deploy it with `--new`.
2. Bind a new slot: `clevis luks bind -d <dev> tang '{"url":"https://tang.example.org/server-2","thp":"<thp>"}'`.
3. Reboot; the disk must unlock.
4. Remove the old slot: `clevis luks unbind -d <dev> -s <slot>` (`clevis luks list -d <dev>` shows slots).
5. Revoke the old set.

   ```sh
   keyset revoke server-1 --url https://tang.example.org --apply -- --config "$KEYSTONE/deploy/wrangler.toml"
   ```

6. In your key store, replace `server-1` with `null`. Its keys still open copies of the disk taken before step 4.

Keep the key store offline; it is as sensitive as the disks.

A deploy can take the whole store as one JSON object of secret names to sets, with `null` for a revoked set (a tombstone). Sets left out show as drift. After rotating to `server-2`:

```sh
jq -n --arg s2 "$(pass tang/server-2)" \
  '{TANG_KEY_SERVER_1: null, TANG_KEY_SERVER_2: $s2}' |
  keyset deploy --url https://tang.example.org --apply -- --config "$KEYSTONE/deploy/wrangler.toml"
```

The plan labels each set `ok`, `new`, `policy`, `revoked` or `REFUSE` and applies only when nothing is refused. A null entry that is still served shows as `REVOKED-LIVE`, and `--apply` redeploys from current secrets to drop it. The drift report lists live sets missing from the input; a plan runs it only when `CLOUDFLARE_API_TOKEN` is set.

`--apply` refuses when the wrangler target's secrets disagree with `--url`. `keyset` prints private keys only from `new` and deletes only the set `revoke` names. `deploy --apply` redeploys the Worker from the config given after `--`. Each check sends a real `rec`, which can raise an alert and marks its source seen.

To upgrade, update the clone and run `npm ci`. To move to a new hostname, change the route. Either way, redeploy with `npx wrangler deploy --config "$KEYSTONE/deploy/wrangler.toml"`; secrets persist. Then plan `keyset deploy` against the new `--url`: every set should read `ok`.

## Alerts

When a `rec` succeeds from a new source, keystone mails one alert through a Cloudflare Email Workers `send_email` binding. A source is the client's /24 or /48 with its ASN and country. A failed alert is logged and never changes the unlock. Each set sends at most one alert an hour; up to five sources met meanwhile wait for the hourly digest.

1. Create the namespace: `npx wrangler kv namespace create UNLOCKS`.
2. Enable Email Routing on a zone in the same account and verify the destination address.
3. Uncomment all four blocks in `deploy/wrangler.toml`: the `UNLOCKS` namespace id, the `ALERT` binding, `ALERT_FROM` and `ALERT_TO`, and the hourly cron. `ALERT_FROM` must be on the Email Routing zone.
4. Redeploy.

## Origin gate

A set may name who can recover it. A set with neither field answers any client.

- `allow`: 1 to 32 prefixes, IPv4 `/8` to `/32` or IPv6 `/16` to `/128`, host bits zero. An origin inside one is served unattended.
- `approvers`: 1 to 5 addresses. Any other origin's `rec` is held and each approver is mailed a link to approve or deny it. Approval lets any machine in that /24 or /48 recover the set for 10 minutes; the held host is served within about 15 seconds. Removing an approver retires their links.

Both fields live in the set's secret beside its keys. Edit them in the key store, then deploy; the plan reads `policy`.

```sh
entry=$(pass tang/server-1 | jq -ce '.allow = ["198.51.100.7/32"] | .approvers = ["you@example.org"]') &&
  printf '%s\n' "$entry" | pass insert -m -f tang/server-1
pass tang/server-1 | jq -R '{TANG_KEY_SERVER_1: .}' |
  keyset deploy --url https://tang.example.org --apply -- --config "$KEYSTONE/deploy/wrangler.toml"
```

- Pin every family the host can egress on, its IPv4 /32 and its delegated IPv6 prefix, since clevis may use either at boot. Approval covers a renumber or a visit.
- A set with `approvers` alone holds every origin, so each unlock needs an approval.
- Approvals need `GATE` (declared in the example config), `ALERT` and `ALERT_FROM`. Leave `destination_address` off the `ALERT` binding and verify every approver as an Email Routing destination. Without them, a set with approvers refuses every new origin and `check` fails.
- A set holds 3 origins at a time; a fourth is refused and the approvers get one notice naming it and listing the three. At most 20 messages an hour go out across all sets.
- Turn Pseudo IPv4 off for the zone. With it on, IPv6 clients arrive as 240.0.0.0/4 addresses, which are refused.
- `deploy` rewrites a live set only when its keys match stdin and one Worker version, the one `--url` serves, takes all traffic. `check` from outside `allow` prints `SKIP rec`.

## Reference

| Route | Method | Answer |
|---|---|---|
| `/<name>/adv` | GET | the advertisement, a JWS over the set's public keys |
| `/<name>/adv/<thp>` | GET | the same when `<thp>` is the signing key's thumbprint, else 404 |
| `/<name>/rec/<kid>` | POST | key recovery when `<kid>` names the exchange key, else 404; 403 for an origin a gated set does not admit |
| `/<name>/approve/<token>` | GET, POST | the approval page a held origin's mail links to; 404 for a set without approvers |

A name is `[a-z0-9-]`, up to 63 characters. A set lives in the Worker secret `TANG_KEY_<NAME>`, with the name upper-cased and `-` becoming `_`. Its value is `{"keys":[<signing key>,<exchange key>]}`: exactly two private JWKs, each with `alg`, on one curve, optionally with `allow` and `approvers`. Any other member or an empty list makes the set malformed. A missing secret answers 404. A malformed one answers 500 and logs the secret's name, never its value.

Every successful `rec` logs one JSON line with the name, IP, ASN and country, and no key material. A refused one logs a `refused` line at most once a minute per set and origin.

### Curves

| Curve | Signing alg | Measured CPU for `rec` |
|---|---|---|
| P-521 (default) | ES512 | 7 ms median, up to 12 ms cold |
| P-256 | ES256 | up to 6 ms cold |

The Free plan allows 10 ms of CPU per request, so P-521 needs Workers Paid.
