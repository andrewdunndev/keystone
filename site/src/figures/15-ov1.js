/* 15 ov1: keystone at a glance, in seven numbered steps. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Seven steps: 1, the owner deploys a key set per disk to keystone, a Worker on a Cloudflare account; 2, the computer binds its encrypted disk once to its key set; 3, at boot the computer asks keystone, sending only a blinded value; 4, keystone reads that key set; 5, it answers with the missing half of the key; 6, the computer opens the disk with no passphrase typed, and keystone never sees the disk; 7, if the computer is stolen, the owner deletes its key set before it next starts, keystone refuses it, and the disk stays locked.';
  const s = kit.svg(mount, 'keystone at a glance', alt);
  const f = sheet(s, kit, 1);
  const at = i => [0.08 + i * 0.09, 0.2 + i * 0.09];
  f.part(24, 60, 170, 56, 'owner', null, { at: [0, 0.15] });
  f.part(275, 60, 170, 56, 'keystone', 'a Cloudflare Worker', { at: [0, 0.15], hot: true });
  f.part(526, 60, 170, 56, 'key sets', 'one per disk', { at: [0, 0.15] });
  f.part(24, 190, 170, 66, 'computer at boot', 'initramfs · clevis', { at: [0, 0.15] });
  f.part(24, 380, 170, 56, 'the disk', 'LUKS', { at: [0, 0.15] });
  const nb = (i, x, y) => f.add(f.dim.nb(s, x, y, i), { at: at(i - 1) });
  f.flow([[194, 88], [275, 88]], { at: at(0) }); nb(1, 234, 88);
  f.flow([[194, 206], [300, 206], [300, 116]], { at: at(1) }); nb(2, 247, 206);
  f.flow([[194, 222], [350, 222], [350, 116]], { at: at(2) }); nb(3, 272, 222);
  f.flow([[445, 88], [526, 88]], { at: at(3) }); nb(4, 486, 88);
  f.flow([[400, 116], [400, 238], [194, 238]], { at: at(4) }); nb(5, 300, 238);
  f.flow([[109, 256], [109, 380]], { at: at(5) }); nb(6, 109, 318);
  f.flow([[109, 60], [109, 32], [611, 32], [611, 60]], { at: at(6) }); nb(7, 360, 32);
  f.table(268, 310, 'the seven steps', [
    ['1', 'owner deploys a key set per disk to keystone'],
    ['2', 'computer binds its disk once to its key set'],
    ['3', 'computer asks at boot, blinded value only'],
    ['4', 'keystone reads that key set'],
    ['5', 'keystone answers with the missing half'],
    ['6', 'computer opens the disk, no passphrase typed'],
    ['7', 'owner deletes the key set if it is stolen'],
  ], { at: [0.7, 1], widths: [28, 400] });
  return { n: 1, update: f.update, alt: alt };
}
