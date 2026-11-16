---
title: Origin gate
num: 12
---

## Allow

A set's secret may carry `allow` prefixes and `approvers` addresses. Origins inside `allow` are served at once; others get 403 unless approvers exist.

## Approve

The Gate, a Durable Object, opens a pending per origin and mails each approver a link. Approving admits that origin for 10 minutes; a pending lapses after 12 hours.

## Refuse

A set holds 3 pendings; a fourth origin is refused. Cloudflare's network, origins without an ASN and 240.0.0.0/4 are never admitted; `keystone-probe` requests are served only from `allow`.

## Unavailable

Without the `GATE` binding, approval links answer 503 and adv carries `keystone-gate: unavailable`. A failed mail is retried on a later request, after 5 minutes at first.
