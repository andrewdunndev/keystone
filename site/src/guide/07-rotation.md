---
title: Rotation
num: 7
fig: 07-rotation
---

## Slots

A LUKS header holds a passphrase slot and one clevis slot per bound set.

## Swap

Bind `server-2` in a second slot, reboot, then unbind and revoke `server-1`.

## Copies

A header copy taken before the unbind still opens with `server-1`'s keys, so the store swaps them for the tombstone.
