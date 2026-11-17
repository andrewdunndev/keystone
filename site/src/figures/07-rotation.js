/* 07 rotation: bind the new set, reboot, unbind and revoke the old one. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'The LUKS header holds a passphrase slot, a clevis slot for server-2 and a removed dashed slot for server-1; at keystone server-1 answers 404 and server-2 is live. Below, a dashed copy of the disk taken before the unbind still holds its server-1 slot, and the key store keeps null for that name.';
  const s = kit.svg(mount, 'Rotating a key set', alt);
  const f = sheet(s, kit, 3);
  const SX = 44, SW = 330, H = 44, RX = 470, RW = 226;
  f.zone(24, 36, 370, 232, 'LUKS header', { from: 1 });
  f.part(SX, 76, SW, H, 'passphrase', null, { from: 1 });
  f.part(SX, 136, SW, H, 'clevis: server-1', null, { from: 1, until: 2 });
  f.part(SX, 136, SW, H, 'clevis: server-1', null, { from: 2, ghost: true });
  f.part(SX, 196, SW, H, 'clevis: server-2', null, { from: 2 });
  f.part(RX, 136, RW, H, 'server-1 · live', null, { from: 1, until: 2 });
  f.part(RX, 136, RW, H, 'server-1 · 404', null, { from: 2, ghost: true });
  f.part(RX, 196, RW, H, 'server-2 · live', null, { from: 2 });
  f.flow([[SX + SW, 158], [RX, 158]], { from: 1, until: 2 });
  f.flow([[SX + SW, 218], [RX, 218]], { from: 2 });
  f.zone(24, 300, 370, 140, 'copy before the unbind', { from: 3, ghost: true });
  f.part(SX, 358, SW, H, 'clevis: server-1', null, { from: 3 });
  f.part(RX, 358, RW, H, 'key store: null', null, { from: 3, hot: true });
  f.flow([[SX + SW, 380], [RX, 380]], { from: 3, faint: true });
  return { n: 3, update: f.update, enter: f.enter, exit: f.exit, alts: [
    'The LUKS header holds a passphrase slot and a clevis slot bound to server-1, which is live at keystone.',
    'A clevis slot bound to server-2 is added, the host reboots to prove it, and the server-1 slot is unbound; server-1 is then revoked and answers 404.',
    alt,
  ] };
}
