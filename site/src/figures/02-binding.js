/* 02 binding: clevis verifies the advertisement, derives K from the
   exchange public key, and keeps only public values in the LUKS header. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'clevis fetches the key set\'s signed advertisement from the Worker, checks its signature against the pinned thumbprint, derives K from the exchange public key and a fresh random c, and keeps only public values in the LUKS header: C, the kid and the advertisement. c and K are discarded, and K wraps a new slot passphrase.';
  const s = kit.svg(mount, 'Binding a disk to a key set', alt);
  const f = sheet(s, kit, 3);
  const H = 64, W = 170, xs = [24, 270, 516], Y = 130, Y2 = 330;
  f.part(xs[0], Y, W, H, 'keystone', 'serves adv', { from: 1 });
  f.part(xs[1], Y, W, H, 'verify', 'against pinned thp', { from: 1 });
  f.flow([[xs[0] + W, Y + H / 2], [xs[1], Y + H / 2]], { from: 1, until: 2, packet: 'adv' });
  f.flow([[xs[0] + W, Y + H / 2], [xs[1], Y + H / 2]], { from: 2 });
  f.part(xs[2], Y, W, H, 'derive', 'K = c·S, C = c·G', { from: 2 });
  f.flow([[xs[1] + W, Y + H / 2], [xs[2], Y + H / 2]], { from: 2 });
  f.part(xs[2], Y2, W, H, 'LUKS header', 'C · kid · adv', { from: 3, hot: true });
  f.flow([[xs[2] + W / 2, Y + H], [xs[2] + W / 2, Y2]], { from: 3 });
  f.chip(xs[1], Y2, W, H, 'c and K discarded', { from: 3 });
  f.flow([[xs[2] + 24, Y + H], [xs[2] + 24, 262], [xs[1] + W / 2, 262], [xs[1] + W / 2, Y2]], { from: 3, faint: true });
  return { n: 3, update: f.update, enter: f.enter, exit: f.exit, alts: [
    'The Worker serves the signed advertisement to clevis, which verifies its signature against the pinned thumbprint.',
    'clevis picks a random c and derives K = c·S from the exchange public key S in the advertisement.',
    alt,
  ] };
}
