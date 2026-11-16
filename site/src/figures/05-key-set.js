/* 05 key set: one Worker secret holds a signing key and an exchange key;
   the signing key answers the two adv routes and the exchange key rec. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'One Worker secret, TANG_KEY_SERVER_1, drawn as a slab with two keys standing on it on one curve, P-521 or P-256. The signing key, ES512, answers GET /server-1/adv and GET /server-1/adv/<thp>. The exchange key, ECMR, answers POST /server-1/rec/<kid>.';
  const s = kit.svg(mount, 'A key set', alt);
  const f = sheet(s, kit, 1);
  const { iso } = kit;
  const cam = iso.camera({ ox: 300, oy: 300, k: 2.5 });
  const slab = iso.box(cam, { x: 0, y: 0, z: 0, w: 130, d: 70, h: 14 });
  f.add(slab, { at: [0, 0.25] });
  const a = iso.box(cam, { x: 14, y: 14, z: 14, w: 36, d: 42, h: 40, cls: 'hot' });
  const b = iso.box(cam, { x: 80, y: 14, z: 14, w: 36, d: 42, h: 40 });
  f.add(a, { at: [0.2, 0.5], apart: [0, -70] });
  f.add(b, { at: [0.35, 0.65], apart: [0, -70] });
  const [ax, ay] = cam.project(32, 35, 54), [bx, by] = cam.project(98, 35, 54), [sx, sy] = cam.project(65, 70, 7);
  f.callout(ax, ay, 250, 60, ['signing key', 'ES512 · P-521', 'GET /server-1/adv', 'GET /server-1/adv/<thp>'], { at: [0.6, 0.85], anchor: 'end' });
  f.callout(bx, by, 470, 60, ['exchange key', 'ECMR · P-521', 'POST /server-1/rec/<kid>'], { at: [0.7, 0.9] });
  f.callout(sx, sy, 280, 470, ['TANG_KEY_SERVER_1'], { at: [0.8, 1], anchor: 'end' });
  return { n: 1, update: f.update, alt: alt };
}
