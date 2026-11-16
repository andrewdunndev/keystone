/* 14 quickstart: the seven steps from an empty account to a disk that
   unlocks at boot. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'The quickstart in seven steps, read left to right then right to left: 1 wrangler deploy the Worker; 2 curl, which answers 404 because there are no sets yet; 3 keyset new mints a set into the key store; 4 keyset deploy --new, which checks adv and rec; 5 clevis luks bind with the thp from the adv; 6 rebuild the initramfs with network, DNS and a CA bundle; 7 reboot, with no passphrase prompt.';
  const s = kit.svg(mount, 'The quickstart in seven steps', alt);
  const f = sheet(s, kit, 1);
  const W = 192, H = 64, xs = [24, 264, 504];
  const at = i => [i * 0.12, i * 0.12 + 0.2];
  const cells = [
    [0, 60, '1 wrangler deploy', null], [1, 60, '2 curl', '404, no sets yet'], [2, 60, '3 keyset new', null],
    [2, 200, '4 keyset deploy', '--new · checks adv, rec'], [1, 200, '5 clevis luks bind', 'thp from the adv'], [0, 200, '6 rebuild initramfs', 'net · DNS · CA'],
    [0, 340, '7 reboot', 'no passphrase'],
  ];
  cells.forEach(([c, y, t, sub], i) => f.part(xs[c], y, W, H, t, sub, { at: at(i), hot: i === 6 }));
  const mid = y => y + H / 2;
  f.flow([[xs[0] + W, mid(60)], [xs[1], mid(60)]], { at: at(1) });
  f.flow([[xs[1] + W, mid(60)], [xs[2], mid(60)]], { at: at(2) });
  f.flow([[xs[2] + W / 2, 124], [xs[2] + W / 2, 200]], { at: at(3) });
  f.flow([[xs[2], mid(200)], [xs[1] + W, mid(200)]], { at: at(4) });
  f.flow([[xs[1], mid(200)], [xs[0] + W, mid(200)]], { at: at(5) });
  f.flow([[xs[0] + W / 2, 264], [xs[0] + W / 2, 340]], { at: at(6) });
  return { n: 1, update: f.update, alt: alt };
}
