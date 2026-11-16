/* 01 overview: the disk host reaches the keystone Worker through
   Cloudflare's edge, and the Worker reads each key set from its own secret. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Four isometric solids in a row on one sheet. The disk host, running initramfs with clevis and LUKS, sends a request over HTTPS to Cloudflare\'s edge, where a WAF rate limit can sit. The edge passes it to keystone, the Worker, which answers adv and rec. The Worker reads the key sets, three slabs held as Worker secrets named TANG_KEY_<NAME>. The edge, Worker and secrets sit inside one dashed plate, the Cloudflare account.';
  const s = kit.svg(mount, 'keystone and the path to it', alt);
  const f = sheet(s, kit, 1);
  const { iso, motion } = kit;
  const cam = iso.camera({ ox: 100, oy: 140, k: 1.5 });
  const B = 50, STEP = 130, Z = 0;
  const wireG = f.el('g', {}, s);
  const route = [];
  [0, 1, 2].forEach(i => route.push([i * STEP + B, B / 2, Z], [(i + 1) * STEP, B / 2, Z]));
  const pts = route.map(p => cam.project(...p));
  const path = f.el('path', { d: 'M' + pts.map(p => p.map(v => v.toFixed(1)).join(',')).join('L'), class: 'wire', pathLength: 1 }, wireG);
  f.add(wireG, { ramp: false, at: [0.3, 0.6] }, p => motion.drawIn([path], p));
  f.add(iso.plate(cam, { x: STEP - 20, y: -20, w: 2 * STEP + B + 40, d: B + 40 }), { at: [0, 0.2] });
  [[0, 40, ''], [1, 34, ''], [2, 52, 'hot']].forEach(([i, h, cls], k) => {
    f.add(iso.box(cam, { x: i * STEP, y: 0, z: Z, w: B, d: B, h, cls }), { at: [0.05 + k * 0.1, 0.3 + k * 0.1], apart: [0, -36] });
  });
  [0, 1, 2].forEach(i => f.add(iso.box(cam, { x: 3 * STEP, y: 0, z: i * 14, w: B, d: B, h: 10 }), { at: [0.35 + i * 0.05, 0.6 + i * 0.05], apart: [0, -30] }));
  const lab = (i, h, lines, ex, ey, at) => {
    const [px, py] = cam.project(i * STEP + B / 2, B / 2, h);
    f.callout(px, py, ex, ey, lines, { at });
  };
  lab(0, 40, ['disk host', 'initramfs · clevis'], 56, 56, [0.6, 0.8]);
  lab(1, 34, ['cloudflare edge', 'WAF rate limit'], 230, 56, [0.65, 0.85]);
  lab(2, 52, ['keystone', 'adv · rec'], 440, 56, [0.7, 0.9]);
  lab(3, 38, ['worker secrets', 'TANG_KEY_<NAME>'], 560, 210, [0.75, 0.95]);
  const [zx, zy] = cam.project(3 * STEP + B + 20, B + 20, 0);
  f.add(f.text(s, zx + 4, zy + 24, 'cloudflare account', 'view-title', 'end'), { at: [0.8, 1] });
  const pk = f.el('g', { class: 'packet' }, s);
  f.el('rect', { x: -7, y: -7, width: 14, height: 14, class: 'packet-box' }, pk);
  f.add(pk, { ramp: false, at: [0.5, 1] }, p => { motion.travel(pk, path, p); if (p >= 1) pk.style.opacity = '0'; });
  return { n: 1, update: f.update, alt: alt };
}
