---
title: A key set
num: 5
fig: 05-key-set
part:
  roman: II
  title: Key sets
  claim: What a set holds and how it changes.
---

## Layout

The set `server-1` lives in the secret `TANG_KEY_SERVER_1`. Routes: `/server-1/adv`, `/server-1/adv/<thp>` and `POST /server-1/rec/<kid>`. The signing key (ES512 on P-521, ES256 on P-256) signs adv; the exchange key answers rec.
