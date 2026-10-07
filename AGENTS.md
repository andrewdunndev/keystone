# keystone

A Tang server (P-521 or P-256, per key set) as a Cloudflare Worker, and `keyset`, which mints, checks, deploys and
revokes its key sets.

## Layout

- `src/jwk.js`: the key set format: base64url, thumbprints, kid matching, `parseSet`, the set name rule and its
  `TANG_KEY_<NAME>` secret. The format lives here alone; the Worker and keyset import it.
- `src/index.js`: the Worker: `/<name>/adv`, `/<name>/rec/<kid>`, unlock alerts.
- `bin/keyset.mjs`: `new`, `check`, `deploy`, `revoke`. `main(argv, io)` takes fetch, the wrangler runner, stdio and process
  injected, so tests run it in-process.
- `test/worker.test.js`: the Worker against a fixture `test/gen-fixture.mjs` builds from stock tangd before each run.
- `test/keyset.test.js`: keyset against the real Worker through an injected fetch, wrangler faked.
- `scripts/mutate.sh`: sed mutants of `src/` and `bin/`; each must apply and fail the suite.
- `scripts/interop.sh`: keyset and stock clevis against `wrangler dev`, then revocation; `luks` adds, as root, a tangd
  cross-check and a LUKS2 bind and unlock.

## Rules

- Sets are write-once and named: rotation is a new name, and nothing rewrites a live set. Every keyset verb plans
  unless given `--apply`; only `keyset revoke <name> --apply` deletes, one set at a time.
- Private keys are never printed, logged or written, except by `keyset new` to stdout and in the 0600 secrets file
  `deploy --apply` hands wrangler and removes.
- No real hostnames, domains or accounts anywhere: examples use `https://tang.example` and `server-1`.

## Commands

```sh
npm ci
npm test                       # needs tang and jose for the fixture
npm run mutate
bash scripts/interop.sh        # needs clevis; `luks` as root in a throwaway container
```

`just test`, `just mutate` and `just interop` wrap these; `mise.toml` pins node and just. CI (`.gitlab-ci.yml`, Fedora)
runs `test` (npm test, npm run mutate) and `interop` on merge requests, the default branch and tags, beside the
estate catalog's `reference-check`, which fails on any unwaived reference finding; `.deviations.yaml` holds the
waivers. On a tag, the catalog's `release-create` publishes the tag's `CHANGELOG.md` entry as the GitLab release.
