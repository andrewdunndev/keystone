---
title: keyset deploy
num: 9
fig: 09-deploy
---

## Plan

`keyset deploy` reads the key store on stdin and gives each entry a verdict against the live Worker.

## Refuse

Any REFUSE stops the run with exit 1; without `--apply` it ends at the plan.

## Apply

`--apply` uploads through wrangler, then checks each set's adv and a real rec, and each tombstone for 404. Commands: [Install](/setup/).
