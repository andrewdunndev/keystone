---
title: Binding
num: 2
fig: 02-binding
---

## Check

clevis checks the advertisement against the pinned thp, the signing key's thumbprint. A forged advertisement fails the bind.

## Wrap

It picks a random c and computes K = c·S, with S the exchange public key. K wraps a new slot passphrase.

## Keep

The header keeps C = c·G, the kid and the advertisement. c and K are discarded.
