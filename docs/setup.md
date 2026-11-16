# Setup

A key set is a signing key and an exchange key. Its `thp` is the signing key's thumbprint.

## Prerequisites

- A Cloudflare account and a zone on Cloudflare DNS for the Worker's hostname.
- Node (the version `package.json` names), git and `jq` where you run `keyset`.
- `clevis` on each host to bind.

```sh
sudo dnf install clevis clevis-luks clevis-dracut         # Fedora and RHEL
sudo apt install clevis clevis-luks clevis-initramfs      # Debian and Ubuntu
```

## Quickstart

1. Clone keystone and define `keyset`.

   ```sh
   git clone --branch <tag> https://gitlab.com/dunn.dev/keystone.git
   cd keystone && npm ci
   export KEYSTONE="$PWD"
   keyset() { node "$KEYSTONE/bin/keyset.mjs" "$@"; }
   ```

2. Log in to Cloudflare. For CI, [use an API token](operate.md#authentication).

   ```sh
   npx wrangler login
   ```

3. Copy the example config and set its route to your hostname.

   ```sh
   cp "$KEYSTONE/deploy/wrangler.toml.example" "$KEYSTONE/deploy/wrangler.toml"
   ```

4. Deploy the Worker.

   ```sh
   npx wrangler deploy --config "$KEYSTONE/deploy/wrangler.toml"
   ```

5. Mint a set into your offline key store. On the Free plan add `--curve P-256`.

   ```sh
   keyset new | pass insert -m tang/server-1
   ```

6. Deploy the set. Without `--apply` the command only plans.

   ```sh
   pass tang/server-1 | jq -R '{TANG_KEY_SERVER_1: .}' |
     keyset deploy --url https://tang.example.org --new server-1 --apply -- --config "$KEYSTONE/deploy/wrangler.toml"
   ```

7. On the host, bind the disk. This reads the `thp` from the live advertisement.

   ```sh
   curl -s https://tang.example.org/server-1/adv | jose fmt -j- -g payload -y -o- |
     jose fmt -j- -g keys -A -g 0 -o- | jose jwk thp -i-
   echo
   sudo clevis luks bind -d /dev/sdXN tang '{"url":"https://tang.example.org/server-1","thp":"<thp>"}'
   ```

8. Rebuild the initramfs with network up. On Fedora and RHEL:

   ```sh
   echo 'kernel_cmdline="rd.neednet=1"' | sudo tee /etc/dracut.conf.d/clevis.conf
   sudo dracut -f
   ```

   Debian and Ubuntu need a CA bundle hook: see [Initramfs](operate.md#initramfs).

9. Reboot. The disk unlocks without a passphrase.

## Next

- [Rotate and revoke](operate.md#rotate-and-revoke) a key set; the same section covers upgrades.
- [Alerts](operate.md#alerts) on new unlock sources, and the [origin gate](operate.md#origin-gate).
- [Routes and curves](operate.md#reference). The [architecture](/architecture/) draws each mechanism.
