# Contributing

Merge requests go to GitLab at https://gitlab.com/dunn.dev/keystone. There is no DCO and no CLA.

## Tests

The suite uses stock `tangd` as the oracle: on fresh keys of each curve, the Worker must match its advertisements, recoveries and verdicts on malformed points. It needs Fedora with `tang` and `jose` (CI uses `quay.io/fedora/fedora:44`) and Node 22.15 or later.

```sh
dnf -y install tang jose nodejs npm
npm ci
npm test
npm run mutate
```

`npm run mutate` applies sed mutants to `src/` and `bin/`. Every mutant must fail the suite, and the run must report `survived: 0`.

The interop job runs `keyset` and clevis against `wrangler dev`, then revocation:

```sh
dnf -y install tang jose clevis curl procps-ng util-linux-core nodejs npm
bash scripts/interop.sh
```

`bash scripts/interop.sh luks`, as root in a throwaway container, adds a LUKS2 bind and unlock.

## Releases

1. Add a `## vX.Y.Z - date` entry to `CHANGELOG.md`, replacing "Unreleased".
2. Set `version` in `package.json` to match.
3. Commit, then create an annotated tag `vX.Y.Z` and push it.

The tag pipeline publishes the entry as the GitLab release.
