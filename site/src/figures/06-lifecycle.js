/* 06 lifecycle: minted, live, revoked, tombstone; a live name takes no new keys. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Four states stacked top to bottom. A set is minted by keyset new, goes live when deployed with --new and answers adv 200, is revoked when its secret is deleted and answers adv 404, and becomes a tombstone, a null entry in the deploy input, which every later deploy proves answers 404. A dashed part beside the live set shows that new keys under the same name are refused, so rotation uses server-2.';
  const s = kit.svg(mount, 'Life of a key set', alt);
  const f = sheet(s, kit, 3);
  const X = 140, W = 200, H = 60, cx = X + W / 2;
  f.part(X, 40, W, H, 'minted', 'keyset new', { from: 1 });
  f.part(X, 160, W, H, 'live', 'adv 200', { from: 1 });
  f.part(X, 280, W, H, 'revoked', 'adv 404', { from: 1 });
  f.part(X, 400, W, H, 'tombstone', 'null', { from: 2 });
  f.flow([[cx, 100], [cx, 160]], { from: 1 });
  f.flow([[cx, 220], [cx, 280]], { from: 1 });
  f.flow([[cx, 340], [cx, 400]], { from: 2 });
  f.note(cx + 16, 135, 'deploy --new', { from: 1, until: 3 });
  f.note(cx + 16, 255, 'revoke', { from: 1, until: 3 });
  f.note(cx + 16, 375, 'null entry', { from: 2 });
  f.part(440, 160, 250, H, 'new keys, same name', 'REFUSE · rotate to server-2', { from: 3, ghost: true });
  f.flow([[440, 190], [340, 190]], { from: 3, faint: true });
  return { n: 3, update: f.update, alts: [
    'A set is minted, deployed with --new so it is live and answers adv 200, then revoked when its secret is deleted, and answers adv 404.',
    'The deploy input then holds null under that name, a tombstone, and every later deploy checks that it still answers 404.',
    alt,
  ] };
}
