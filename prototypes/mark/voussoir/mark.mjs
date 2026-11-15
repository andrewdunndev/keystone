/* Keystone's mark: one voussoir, the wedge stone that locks an arch, drawn
   the way a cairn stone is drawn. Rings up the side, a convex-hull outline,
   back-face-culled quads toned by their normal, the cairn projection and the
   cairn tones. One primitive where the cairn stacks four.

   node mark.mjs  writes mark.svg (64 px and up) and favicon.svg (16 to 32 px)
   beside itself. */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/* the stone: length across the picture at the extrados (top) and at the
   intrados (foot), depth into the picture, height, corner radii, yaw (near
   -45 lays the length across the picture), the dressed arris, surface jitter */
export const stone = { top: 170, foot: 84, d: 64, h: 176, r: [8, 6, 9, 7], yaw: -18, arris: 4, jitter: 0.02 };

/* colours: the cairn's table, light only */
const palette = { white: '#ffffff', e500: '#404040', e600: '#0a0a0a', m400: '#4a6741' };
const mix = (a, b, pct) => {
  const c = (h, i) => parseInt(h.slice(1 + i * 2, 3 + i * 2), 16);
  return '#' + [0, 1, 2].map(i =>
    Math.round(c(a, i) * pct / 100 + c(b, i) * (1 - pct / 100)).toString(16).padStart(2, '0')).join('');
};
const lit = (top, dark, k) => ({ top, left: mix(dark, top, k[0]), right: mix(dark, top, k[1]), shade: mix(dark, top, k[2]) });
const body = lit(palette.white, palette.e600, [7, 16, 30]);
const moss = lit(palette.m400, palette.e600, [18, 36, 55]);
export const tones = {
  stone: body, cap: moss, edge: palette.e500, cast: palette.e600, castOpacity: 0.14,
  small: { stone: [body.top, mix(palette.e600, palette.white, 24)], cap: [moss.top, moss.right], edge: palette.e500, width: 1 },
};

const deg = Math.PI / 180;
const unit = v => Math.round(Math.min(1, Math.max(0, v)) * 100) / 100;
const jitter = k => (((Math.sin(k * 91.7 + 3.31) * 24631.19) % 1) + 1) % 1 - 0.5;

/* rings up the side as [rise, inset]: the foot arris, the foot, the
   shoulder, the top arris; the wedge widens between foot and shoulder */
const profile = s => [[0, s.arris], [s.arris, 0], [s.h - s.arris, 0], [s.h, s.arris]];
const halfLength = (s, rise) => (s.foot + (s.top - s.foot) * rise / s.h) / 2;

const plan = (s, rise, inset, arc) => {
  const a = halfLength(s, rise) - inset, b = s.d / 2 - inset;
  const c = Math.cos(s.yaw * deg), n = Math.sin(s.yaw * deg);
  const pts = [];
  [[1, 1], [-1, 1], [-1, -1], [1, -1]].forEach(([sx, sy], q) => {
    const rc = Math.min(Math.max(s.r[q] - inset, 1), a, b);
    for (let k = 0; k <= arc; k++) {
      const t = (q * 90 + (k * 90) / arc) * deg, g = 1 + s.jitter * jitter(q * 3 + k);
      const X = (sx * (a - rc) + rc * Math.cos(t)) * g, Y = (sy * (b - rc) + rc * Math.sin(t)) * g;
      pts.push([X * c - Y * n, X * n + Y * c]);
    }
  });
  return pts;
};

const hull = pts => {
  const p = [...pts].sort((m, n) => m[0] - n[0] || m[1] - n[1]);
  const cross = (o, a, b) => (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
  const half = list => list.reduce((h, q) => {
    while (h.length >= 2 && cross(h[h.length - 2], h[h.length - 1], q) <= 0) h.pop();
    h.push(q);
    return h;
  }, []).slice(0, -1);
  return [...half(p), ...half([...p].reverse())];
};

/* elevation is the camera's angle above the ground, 30 as the cairn's */
export function voussoir(s = stone, { elevation = 30, arc = 2 } = {}) {
  const sE = Math.sin(elevation * deg), cE = Math.cos(elevation * deg);
  const project = (x, y, z) => [x * Math.SQRT1_2 - y * Math.SQRT1_2, (x * Math.SQRT1_2 + y * Math.SQRT1_2) * sE - z * cE];
  const view = [cE * Math.SQRT1_2, cE * Math.SQRT1_2, sE];
  const rings = profile(s).map(([rise, inset]) => plan(s, rise, inset, arc).map(w => ({ w, z: rise })));
  const at = q => project(q.w[0], q.w[1], q.z);
  const faces = [];
  for (let j = 0; j < rings.length - 1; j++) {
    const lo = rings[j], hi = rings[j + 1], n = lo.length;
    for (let k = 0; k < n; k++) {
      const A = lo[k], B = lo[(k + 1) % n], C = hi[(k + 1) % n], D = hi[k];
      const u = [C.w[0] - A.w[0], C.w[1] - A.w[1], C.z - A.z], v = [D.w[0] - B.w[0], D.w[1] - B.w[1], D.z - B.z];
      const nx = u[1] * v[2] - u[2] * v[1], ny = u[2] * v[0] - u[0] * v[2], nz = u[0] * v[1] - u[1] * v[0];
      const len = Math.hypot(nx, ny, nz);
      if (len < 1e-6 || (nx * view[0] + ny * view[1] + nz * view[2]) / len <= 0) continue;
      const theta = Math.atan2(ny, nx) / deg, rise = nz / len;
      faces.push({ pts: [A, B, C, D].map(at), s: unit((90 - theta) / 90), t: unit(rise * 0.85), k: unit(-rise * 0.7) });
    }
  }
  const projected = rings.flatMap(r => r.map(at));
  /* the overhanging extrados, cast onto the ground by a light from the left */
  const shadow = plan(s, s.h, 0, arc).map(([x, y]) => project(x + 7, y - 7, 0));
  return { faces, top: rings[rings.length - 1].map(at), outline: hull(projected), shadow };
}

const bounds = pts => ({
  minX: Math.min(...pts.map(p => p[0])), maxX: Math.max(...pts.map(p => p[0])),
  minY: Math.min(...pts.map(p => p[1])), maxY: Math.max(...pts.map(p => p[1])),
});
const fmt = (p, d = 1) => p.map(v => v.toFixed(d)).join(',');
const points = (pts, d = 1) => pts.map(p => fmt(p, d)).join(' ');
const path = (pts, d = 1) => 'M' + pts.map(p => fmt(p, d)).join('L') + 'Z';

/* the stone fitted into box (x, y, w, h) of a 64-unit canvas */
function fitted(box) {
  const solid = voussoir();
  const [bx, by, bw, bh] = box;
  const b = bounds(solid.outline);
  const k = Math.min(bw / (b.maxX - b.minX), bh / (b.maxY - b.minY));
  const ox = bx + (bw - (b.maxX - b.minX) * k) / 2 - b.minX * k;
  const oy = by + (bh - (b.maxY - b.minY) * k) / 2 - b.minY * k;
  return { ...solid, fit: pts => pts.map(([x, y]) => [x * k + ox, y * k + oy]) };
}

const open = label =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"${label ? ` role="img" aria-label="${label}"` : ' aria-hidden="true"'}>`;

const label = 'keystone: one wedge stone, moss on its top';

/* 16 to 32 px (favicon, header): flat sides in the stone's side tone, the
   moss top and an edge one screen pixel wide at any size */
export const small = (id = 'keystone') => {
  const { top, outline, fit } = fitted([3, 3, 58, 58]);
  const c = r => `${id}-${r}`, t = tones.small;
  const body = `<path class="${c('s0')}" d="${path(fit(outline), 1)}"/>` +
    `<polygon class="${c('c1')}" points="${points(fit(top), 1)}"/>` +
    `<path class="${c('e')}" d="${path(fit(outline), 1)}" vector-effect="non-scaling-stroke"/>`;
  const r = k => `.${c(k)}`;
  const css = `${r('s0')}{fill:${t.stone[1]}}${r('c1')}{fill:${t.cap[0]}}` +
    `${r('e')}{fill:none;stroke:${t.edge};stroke-width:${t.width};stroke-linejoin:round}`;
  return `${open(label)}<style>${css}</style>${body}</svg>\n`;
};

/* 64 px and up (avatar, hero, social card): faceted, the extrados moss */
export const glyph = (edge = 1) => {
  const t = tones, b = t.stone;
  const { faces, top, outline, shadow, fit } = fitted([2, 2, 60, 60]);
  const byTone = new Map();
  for (const f of faces) {
    const tone = f.k > 0.15 ? b.shade : f.t > 0.3 ? t.cap.top : f.s > 0.5 ? b.right : b.left;
    byTone.set(tone, [...(byTone.get(tone) ?? []), path(fit(f.pts), 1)]);
  }
  const parts = [
    `<polygon points="${points(fit(shadow), 1)}" fill="${t.cast}" fill-opacity="${t.castOpacity / 2}"/>`,
    `<path d="${path(fit(outline), 1)}" fill="${b.left}"/>`,
  ];
  for (const [tone, d] of byTone)
    parts.push(`<path d="${d.join('')}" fill="${tone}" stroke="${tone}" stroke-width="0.25" stroke-linejoin="round"/>`);
  parts.push(`<polygon points="${points(fit(top), 1)}" fill="${t.cap.top}"/>`);
  parts.push(`<path d="${path(fit(outline), 1)}" fill="none" stroke="${t.edge}" stroke-width="${edge}" stroke-linejoin="round"/>`);
  return `${open(label)}${parts.join('')}</svg>\n`;
};

const here = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(here, 'mark.svg'), glyph());
writeFileSync(join(here, 'favicon.svg'), small());
