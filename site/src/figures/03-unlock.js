/* 03 unlock: at boot clevis blinds the stored point, the Worker multiplies
   it by the exchange private key, and clevis removes the blinding. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Two lifelines, the disk host and keystone. The host sends X = C + e·G to rec, the Worker returns Y = s·X, and the host computes K = Y − e·S, which equals s·C and unwraps the LUKS slot passphrase.';
  const s = kit.svg(mount, 'Unlocking at boot', alt);
  const f = sheet(s, kit, 3);
  const L = 140, R = 580;
  f.part(40, 40, 200, 56, 'disk host', 'initramfs · clevis', { from: 1 });
  f.part(480, 40, 200, 56, 'keystone', 'exchange key s', { from: 1 });
  f.line(L, 96, L, 480, 'centerline', { from: 1 });
  f.line(R, 96, R, 480, 'centerline', { from: 1 });
  f.flow([[L, 190], [R, 190]], { from: 1, packet: 'X' });
  f.note(360, 168, 'X = C + e·G', { from: 1, anchor: 'middle' });
  f.flow([[R, 310], [L, 310]], { from: 2, packet: 'Y' });
  f.note(360, 288, 'Y = s·X', { from: 2, anchor: 'middle' });
  f.note(L + 16, 372, 'K = Y − e·S = s·C', { from: 3 });
  f.part(40, 410, 200, 52, 'LUKS slot opens', null, { from: 3, hot: true });
  return { n: 3, update: f.update, alts: [
    'The host sends X = C + e·G, the stored point blinded by a fresh e, to the rec route.',
    'The Worker returns Y = s·X, multiplied by the exchange private key s.',
    alt,
  ] };
}
