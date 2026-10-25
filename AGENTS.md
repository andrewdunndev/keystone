# keystone

A Tang server (P-521 or P-256, per key set) as a Cloudflare Worker, and `keyset`, which mints, checks, deploys and
revokes its key sets.

## Layout

- `src/jwk.js`: the key set format: base64url, thumbprints, kid matching, `parseSet`, the set name rule and its
  `TANG_KEY_<NAME>` secret. The format lives here alone; the Worker and keyset import it.
- `src/index.js`: the Worker: `/<name>/adv`, `/<name>/rec/<kid>` and its admission, `/<name>/approve/<token>`, unlock
  alerts.
- `src/origin.js`: addresses, prefixes and the /24 or /48 an origin is keyed by.
- `src/bounded.js`: the empty-at-limit rule for the Worker's and the Gate's per-isolate caches.
- `src/gate.js`: the `Gate` Durable Object holding pending approvals, approval tokens, and the mail.
- `src/auth-css.js`: the approval pages' stylesheet, generated from `@dunn.dev/reference` by `scripts/auth-css.mjs` (`npm run auth-css`).
- `bin/keyset.mjs`: `new`, `check`, `deploy`, `revoke`. `main(argv, io)` takes fetch, the wrangler runner, stdio and process
  injected, so tests run it in-process.
- `test/worker.test.js`: the Worker against a fixture `test/gen-fixture.mjs` builds from stock tangd before each run.
- `test/keyset.test.js`: keyset against the real Worker through an injected fetch, wrangler faked.
- `test/gate.test.js`: the origin gate, the Gate on a Map-backed storage, approval and mail.
- `test/auth-css.test.js`, `test/bounded.test.js`: the generated stylesheet is current; the bounded caches.
- `test/helpers.mjs`: the `kv`, fixture, set-builder and `rec` helpers the suites share; `test/register.mjs` and the `cloudflare-*.mjs` files stand in for the Workers-only modules; `test/hex.mjs` is a byte helper.
- `deploy/wrangler.toml.example`: the shipped Worker config, copied to the git-ignored `deploy/wrangler.toml`; interop and CI dry-runs use it.
- `site/`: the Astro site at keystone.dunn.dev, built and deployed apart from the Worker.
- `scripts/mutate.sh`: sed mutants of `src/` and `bin/`; each must apply and fail the suite.
- `scripts/interop.sh`: keyset and stock clevis against `wrangler dev`, then revocation, then the origin gate; `luks`
  adds, as root, a tangd cross-check and a LUKS2 bind and unlock.

## Rules

- Keys are write-once and named: rotation is a new name, and only a set's `allow` and `approvers` are rewritten live.
  Every keyset verb plans unless given `--apply`; only `keyset revoke <name> --apply` deletes, one set at a time.
- Private keys are never printed, logged or written, except by `keyset new` to stdout and in the 0600 secrets file
  `deploy --apply` hands wrangler and removes.
- No real hostnames, domains or accounts anywhere: examples use reserved example domains and `server-1`.

## Commands

Test, mutation, interop and release steps are in [CONTRIBUTING.md](CONTRIBUTING.md); `.deviations.yaml` holds the reference-check waivers.
