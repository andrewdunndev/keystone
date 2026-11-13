#!/usr/bin/env bash
# Offline check that the installed wrangler still has the subcommands and flags bin/keyset.mjs and the deploy dry run below use. It does not check the JSON shapes keyset parses.
# Needs deploy/wrangler.toml and node_modules; takes no network and no credentials.
set -euo pipefail
cd "$(dirname "$0")/.."

W=node_modules/.bin/wrangler
export WRANGLER_SEND_METRICS=false
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# subcommand words, then the flags or usage words the script requires in its help
has() {
  local flags=("${@: -1}") cmd=("${@:1:$#-1}") help
  help=$("$W" "${cmd[@]}" --help 2>&1) || { echo "wrangler ${cmd[*]} --help failed" >&2; exit 1; }
  for f in ${flags[0]}; do
    grep -q -- "$f" <<<"$help" || { echo "wrangler ${cmd[*]} lacks $f" >&2; exit 1; }
  done
}

has secret list '--format'
has secret delete '<key>'
has deployments status '--json'
has deploy '--secrets-file --dry-run --config --outdir'

printf '{"TANG_KEY_CONTRACT":"fake"}' >"$tmp/secrets.json"
"$W" deploy --dry-run --config deploy/wrangler.toml --secrets-file "$tmp/secrets.json" --outdir "$tmp/out"
