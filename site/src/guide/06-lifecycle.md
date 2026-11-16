---
title: Lifecycle
num: 6
fig: 06-lifecycle
---

## Revoke

`keyset new` mints a set offline, `deploy --new` makes it live, `revoke` deletes its secret. Its adv answers 404 and its disks stop unlocking.

## Tombstone

The store keeps null under the name, and every deploy checks it still answers 404.

## Names

`keyset` refuses new keys under a live name.
