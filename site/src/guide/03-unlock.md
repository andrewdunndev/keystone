---
title: Unlock
num: 3
fig: 03-unlock
---

## Blind

At boot clevis reads C and sends X = C + e·G to rec, with e fresh.

## Answer

The Worker returns Y = s·X, with s the exchange private key.

## Recover

The host computes K = Y − e·S = s·C, which equals the bind's c·S, and K unwraps the passphrase. The Worker sees only X.
