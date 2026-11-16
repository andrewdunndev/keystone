---
title: Rollback
num: 8
fig: 08-rollback
---

## Revoked set

Each Worker version keeps the secrets it deployed with, so a rollback across a revoke serves the revoked set again. `keyset deploy` flags it REVOKED-LIVE, and `--apply` builds a version that drops it.
