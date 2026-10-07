test:
    npm test

mutate:
    npm run mutate

# `just interop luks` adds the root-only tangd and LUKS2 checks
interop *mode:
    bash scripts/interop.sh {{mode}}
