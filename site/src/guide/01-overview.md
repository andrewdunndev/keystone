---
title: Overview
num: 1
fig: 01-overview
part:
  roman: I
  title: Protocol
  claim: Bind and unlock.
---

## Requests

clevis reaches the Worker through Cloudflare's edge and makes two requests per set: adv returns the signed public keys, rec recovers a key. A set is one signing key and one exchange key in the secret `TANG_KEY_<NAME>`.
