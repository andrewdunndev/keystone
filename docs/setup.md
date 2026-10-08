# Setup

A key set is one signing key and one exchange key on one curve. A pin's `thp` is the thumbprint of the set's signing key, which clevis checks against the advertisement it fetches.

## Prerequisites

- A Cloudflare account and a zone on Cloudflare DNS for the Worker's hostname.
- Node 22.15 or later, git, `jq` and `jose` where `keyset` runs.
- `clevis` on each host to bind.
- A store for key sets kept offline, such as `pass`.

```sh
git clone --branch <tag> https://gitlab.com/dunn.dev/keystone.git
cd keystone && npm ci
export KEYSTONE="$PWD"
keyset() { node "$KEYSTONE/bin/keyset.mjs" "$@"; }
```

Authenticate with `npx wrangler login`, or set `CLOUDFLARE_API_TOKEN` with Workers Scripts: Edit and Workers Routes: Edit, plus Workers KV Storage: Edit for alerts.

## Quickstart

1. Copy the example config and set the route to your hostname.

   ```sh
   cp deploy/wrangler.toml.example deploy/wrangler.toml
   ```

2. Deploy the Worker. Cloudflare creates the DNS record and certificate.

   ```sh
   npx wrangler deploy --config deploy/wrangler.toml
   ```

3. Confirm the Worker answers and holds no sets. This must print 404.

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
     keyset deploy --url https://tang.example.org --new server-1 --apply -- --config deploy/wrangler.toml
   ```

   `keyset` deploys, then checks the advertisement signature and a real recovery. Arguments after `--` go to wrangler.

6. Bind the disk. This reads the `thp` from the live advertisement.

   ```sh
   curl -s https://tang.example.org/server-1/adv | jose fmt -j- -g payload -y -o- |
     jose fmt -j- -g keys -A -g 0 -o- | jose jwk thp -i-
   sudo clevis luks bind -d /dev/sdXN tang '{"url":"https://tang.example.org/server-1","thp":"<thp>"}'
   ```

7. Build the initramfs. It needs a network, DNS resolution and a CA bundle to reach the Worker over HTTPS.

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

   Dracut defaults to DHCP. On Debian, add `ip=dhcp` to the kernel command line. `lsinitrd` and `lsinitramfs` list the image, to check it carries a CA bundle and DNS resolver libraries.

8. Reboot. The disk unlocks without a passphrase.

## Rotate and revoke

Sets are write-once: `keyset` refuses to deploy different keys to a live name, so rotation uses a new name.

1. Mint `server-2` and deploy it with `--new`.
2. Bind a new slot: `clevis luks bind -d <dev> tang '{"url":"https://tang.example.org/server-2","thp":"<thp>"}'`.
3. Reboot and confirm the disk unlocks.
4. Remove the old slot: `clevis luks unbind -d <dev> -s <slot>`. `clevis luks list -d <dev>` shows the slots.
5. Revoke the old set.

   ```sh
   keyset revoke server-1 --url https://tang.example.org --apply -- --config deploy/wrangler.toml
   ```

6. In your key store, replace `server-1` with `null`. Its keys still open copies of the disk taken before step 4.

Keep live sets offline: the key store is as sensitive as the disks. `keyset deploy` and `keyset check` compare the stored sets with what is served.

Every deploy takes the whole store as one JSON object of secret names to sets, with `null` for revoked sets:

```sh
jq -n --arg s2 "$(pass tang/server-2)" --arg s3 "$(pass tang/server-3)" \
  '{TANG_KEY_SERVER_1: null, TANG_KEY_SERVER_2: $s2, TANG_KEY_SERVER_3: $s3}' |
  keyset deploy --url https://tang.example.org --apply -- --config deploy/wrangler.toml
```

The plan labels each set `ok`, `new`, `revoked` or `REFUSE`, and applies only when nothing is refused. A null entry that is still served, as after a rollback, shows as `REVOKED-LIVE`, and `--apply` redeploys from current secrets to drop it. The drift report lists live sets missing from the input. A plan runs it only when `CLOUDFLARE_API_TOKEN` is set.

Each check sends a real `rec`, which can raise an alert.

To upgrade, update the clone, run `npm ci` and redeploy with `npx wrangler deploy --config deploy/wrangler.toml` or `keyset deploy --apply`. Secrets persist.

## Alerts

When a `rec` succeeds from a source new to that set, keystone mails one alert through a Cloudflare Email Workers `send_email` binding, so the Worker holds no mail credential. A source is the client's /24 (IPv4) or /48 (IPv6) with its ASN and country. A failed alert never changes the unlock. Each set sends at most one alert an hour, and up to five sources met meanwhile are held for the hourly digest.

1. Create the namespace: `npx wrangler kv namespace create UNLOCKS`.
2. Enable Email Routing on a zone in the same account, and verify the destination address.
3. Uncomment all four blocks in `deploy/wrangler.toml`: the `UNLOCKS` namespace id, the `ALERT` binding, `ALERT_FROM` and `ALERT_TO`, and the hourly cron. `ALERT_FROM` must be on the Email Routing zone.
4. Redeploy.

## Reference

| Route | Method | Answer |
|---|---|---|
| `/<name>/adv` | GET | the advertisement, a JWS over the set's public keys |
| `/<name>/adv/<thp>` | GET | the same when `<thp>` is the signing key's thumbprint, else 404 |
| `/<name>/rec/<kid>` | POST | key recovery when `<kid>` names the exchange key, else 404 |

A name is `[a-z0-9-]`, up to 63 characters. A set lives in the Worker secret `TANG_KEY_<NAME>`, with the name upper-cased and `-` becoming `_`. Its value is `{"keys":[<signing key>,<exchange key>]}`: exactly two private JWKs, each with `alg`, on one curve. A missing secret answers 404. A malformed one answers 500 and logs the secret's name, never its value.

Every successful `rec` logs one JSON line with the name, IP, ASN and country, and no key material.

### Curves

| Curve | Signing alg | Measured CPU for `rec` |
|---|---|---|
| P-521 (default) | ES512 | 7 ms median, up to 12 ms cold |
| P-256 | ES256 | up to 6 ms cold |

The Free plan allows 10 ms of CPU per request, so P-521 needs Workers Paid.
