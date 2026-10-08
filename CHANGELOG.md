# Changelog

## Unreleased

- `docs/setup.md`, `SECURITY.md`, `CONTRIBUTING.md`, and `deploy/wrangler.toml.example` (checked in CI with `wrangler deploy --dry-run`).

## v0.1.0 - 2026-10-07

First release. keystone is a Tang server for clevis network-bound disk
encryption, running as a Cloudflare Worker. It speaks the protocol of
stock `tangd` on P-521 or P-256, chosen per key set.

The compatibility contract is the key set format and its secret name.
Later versions keep reading every set this one reads, from the same
secret, on the same routes; changing that is a breaking release:

- A set lives only in the Worker secret `TANG_KEY_<NAME>`, `<NAME>`
  being the path segment (`[a-z0-9-]`, up to 63 characters) upper-cased
  with `-` becoming `_`.
- Its value is `{"keys":[<signing key>,<ECMR key>]}`: exactly two
  private JWKs, each with `alg`, on one curve: P-521 with ES512, or
  P-256 with ES256. Any other curve or alg, or a mixed set, is refused.
- A set is served at `/<name>/adv`, `/<name>/adv/<thp>` and
  `/<name>/rec/<kid>`.
- Sets are write-once: a name keeps its keys for life, and rotation is
  a new name.

In this release:

- One Worker serves many named sets. The exchange runs on the runtime's
  native WebCrypto ECDH.
- `keyset` mints, checks, deploys and revokes sets. Every verb plans
  unless given `--apply`; `deploy` refuses to change a live set, and
  only `revoke` deletes, one set at a time. `keyset new` mints P-521,
  as stock `tangd-keygen` does, or P-256 with `--curve P-256`; a
  `tangd-keygen` pair deploys as a set.
- P-521 needs Workers Paid in practice (`rec` up to 12 ms CPU against
  the Free plan's 10 ms limit); P-256 fits the Free plan.
- An unlock alert mails once when a `rec` succeeds from a source not
  seen before for that set, through a Cloudflare Email Workers binding,
  with an hourly digest for sources met during the cooldown. Alerts are
  off unless their bindings are set.
- A `null` value in `deploy`'s input is a tombstone: every deploy proves
  that revoked set answers 404, and drops it when a rollback serves it.
- Never roll a Worker back across a revoke: versions carry their
  secrets, so the revoked set is served again while `wrangler secret
  list` shows nothing.
- `rec` answers any client, as `tangd` does; there is no allow list.
  Revocation is the control.
- Tested against stock tooling: `tangd` is the oracle for every
  advertisement and recovery in the unit suite, every mutant of `src/`
  and `bin/` must fail that suite, and CI drives stock clevis against
  the Worker with `keyset`-minted sets: encrypt, decrypt, then
  revocation. `scripts/interop.sh luks`, run as root, adds a LUKS2 bind
  and unlock.
