#!/usr/bin/env node
/* keystone's mark, direction "keyed": one keystone wedge standing on its
   narrow bed, a keyhole bored through its face. Drawn in cairn's language
   (the same projection, tones and stroke logic as cairn/site src/brand) from
   its own geometry. Writes mark.svg (64 px and up) and favicon.svg (16-32 px). */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const palette = { white: '#ffffff', e500: '#404040', e600: '#0a0a0a', m400: '#4a6741' };

const mix = (a, b, pct) => {
  const c = (h, i) => parseInt(h.slice(1 + i * 2, 3 + i * 2), 16);
  return '#' + [0, 1, 2].map(i =>
    Math.round(c(a, i) * pct / 100 + c(b, i) * (1 - pct / 100)).toString(16).padStart(2, '0')).join('');
};
const lit = (top, dark, k) =>
  ({ top, left: mix(dark, top, k[0]), right: mix(dark, top, k[1]), shade: mix(dark, top, k[2]) });

/* the keystone is the arch's one coloured stone, as the capstone is the
   cairn's; the bore is the same body lit from a darker top */
const moss = lit(palette.m400, palette.e600, [18, 36, 55]);
export const tones = {
  body: moss, bore: lit(mix(palette.e600, palette.m400, 34), palette.e600, [18, 36, 55]),
  edge: palette.e500, cast: palette.e600, castOpacity: 0.14,
  small: { body: [moss.top, moss.left, moss.right], hole: palette.white, edge: palette.e500, width: 1 },
};

/* the wedge: widths at the top and the bed, height, depth through the arch,
   yaw (near -45 turns the face square to the viewer) */
export const wedge = { wt: 222, wb: 150, h: 174, d: 86, yaw: -30 };
/* the keyhole: bore radius, its centre up the face, the slot's neck and
   foot as fractions of the radius, the slot's foot up the face, arc samples;
   bore is the hole's depth (d bores through) and lip how far in its walls stay lit */
export const key = { r: 31, cz: 0.6, neck: 0.42, foot: 0.64, zb: 0.17, arc: 12, bore: wedge.d, lip: 22 };

const deg = Math.PI / 180;
const unit = v => Math.round(Math.min(1, Math.max(0, v)) * 100) / 100;

/* the keyhole outline on the face, counter-clockwise in (u, z) */
const profile = (scale = 1, slot = 1) => {
  const r = key.r * scale, zc = key.cz * wedge.h, a = key.neck * r * slot, b = key.foot * r * slot, zb = (key.cz - (key.cz - key.zb) * scale) * wedge.h;
  const t0 = -Math.acos(a / r), t1 = Math.PI + Math.acos(a / r);
  const pts = [];
  for (let k = 0; k <= key.arc; k++) {
    const t = t0 + ((t1 - t0) * k) / key.arc;
    pts.push([r * Math.cos(t), zc + r * Math.sin(t)]);
  }
  pts.push([-b, zb], [b, zb]);
  return pts;
};

export function keystone({ elevation = 30, keyScale = 1, keySlot = 1 } = {}) {
  const sE = Math.sin(elevation * deg), cE = Math.cos(elevation * deg);
  const project = (x, y, z) => [x * Math.SQRT1_2 - y * Math.SQRT1_2, (x * Math.SQRT1_2 + y * Math.SQRT1_2) * sE - z * cE];
  const view = [cE * Math.SQRT1_2, cE * Math.SQRT1_2, sE];
  const c = Math.cos(wedge.yaw * deg), n = Math.sin(wedge.yaw * deg);
  const world = ([u, v, z]) => [u * c - v * n, u * n + v * c, z];
  const at = p => project(...world(p));

  /* a lit face from local corners; its normal is turned to agree with
     `out`, a local direction away from the material, then culled */
  const face = (local, out) => {
    const [A, B, C, D] = local.map(world), o = world(out);
    const u = [C[0] - A[0], C[1] - A[1], C[2] - A[2]], v = [D[0] - B[0], D[1] - B[1], D[2] - B[2]];
    let nx = u[1] * v[2] - u[2] * v[1], ny = u[2] * v[0] - u[0] * v[2], nz = u[0] * v[1] - u[1] * v[0];
    if (nx * o[0] + ny * o[1] + nz * o[2] < 0) { nx = -nx; ny = -ny; nz = -nz; }
    const len = Math.hypot(nx, ny, nz);
    if (len < 1e-6 || (nx * view[0] + ny * view[1] + nz * view[2]) / len <= 0) return null;
    const theta = Math.atan2(ny, nx) / deg, rise = nz / len;
    const depth = local.reduce((s, p) => { const w = world(p); return s + w[0] * view[0] + w[1] * view[1] + w[2] * view[2]; }, 0) / 4;
    return { pts: local.map(at), s: unit((90 - theta) / 90), t: unit(rise * 0.85), k: unit(-rise * 0.7), depth };
  };

  const W = wedge, hw = z => (W.wb + ((W.wt - W.wb) * z) / W.h) / 2;
  const corner = (su, sv, top) => [su * hw(top ? W.h : 0), (sv * W.d) / 2, top ? W.h : 0];
  const block = [
    [[corner(-1, -1, 1), corner(1, -1, 1), corner(1, 1, 1), corner(-1, 1, 1)], [0, 0, 1]],
    [[corner(-1, -1, 0), corner(1, -1, 0), corner(1, 1, 0), corner(-1, 1, 0)], [0, 0, -1]],
    [[corner(-1, 1, 0), corner(1, 1, 0), corner(1, 1, 1), corner(-1, 1, 1)], [0, 1, 0]],
    [[corner(-1, -1, 0), corner(1, -1, 0), corner(1, -1, 1), corner(-1, -1, 1)], [0, -1, 0]],
    [[corner(1, -1, 0), corner(1, 1, 0), corner(1, 1, 1), corner(1, -1, 1)], [1, 0, 0]],
    [[corner(-1, -1, 0), corner(-1, 1, 0), corner(-1, 1, 1), corner(-1, -1, 1)], [-1, 0, 0]],
  ].map(([q, out]) => face(q, out)).filter(Boolean);
  const corners = [0, 1].flatMap(top => [[-1, -1], [1, -1], [1, 1], [-1, 1]].map(([su, sv]) => at(corner(su, sv, top))));
  const top = [[-1, -1], [1, -1], [1, 1], [-1, 1]].map(([su, sv]) => at(corner(su, sv, 1)));

  /* the keyhole: its opening on the face, the lit lip of the bore's walls
     turned into the hole, and its back opening (daylight where it overlaps
     the front; the dark of the bore elsewhere) */
  const o = profile(keyScale, keySlot), fv = W.d / 2, bv = fv - key.bore, lv = fv - Math.min(key.bore, key.lip);
  const opening = o.map(([u, z]) => at([u, fv, z]));
  const walls = o.map((p, i) => {
    const q = o[(i + 1) % o.length], du = q[0] - p[0], dz = q[1] - p[1];
    return face([[p[0], fv, p[1]], [q[0], fv, q[1]], [q[0], lv, q[1]], [p[0], lv, p[1]]], [-dz, 0, du]);
  }).filter(Boolean).sort((a, b) => a.depth - b.depth);
  const back = o.map(([u, z]) => at([u, bv, z])), through = key.bore >= W.d;

  /* the stone's shadow on the ground: the head's footprint, cast a little
     to the right as the cairn's stones cast theirs */
  const shadow = [[-1, -1], [1, -1], [1, 1], [-1, 1]].map(([su, sv]) => {
    const [x, y] = world(corner(su, sv, 1));
    return project(x + 7, y - 7, 0);
  });

  return { faces: block, top, outline: hull(corners), opening, walls, back, through, shadow, bounds: bounds(corners) };
}

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

export const bounds = pts => ({
  minX: Math.min(...pts.map(p => p[0])), maxX: Math.max(...pts.map(p => p[0])),
  minY: Math.min(...pts.map(p => p[1])), maxY: Math.max(...pts.map(p => p[1])),
});
const fmt = (p, d = 1) => p.map(v => v.toFixed(d)).join(',');
const points = (pts, d = 1) => pts.map(p => fmt(p, d)).join(' ');
const path = (pts, d = 1) => 'M' + pts.map(p => fmt(p, d)).join('L') + 'Z';

/* the stone fitted into box (x, y, w, h) of a 64-unit canvas */
function fitted(box, opts) {
  const k9 = keystone(opts);
  const [bx, by, bw, bh] = box, b = k9.bounds;
  const k = Math.min(bw / (b.maxX - b.minX), bh / (b.maxY - b.minY));
  const ox = bx + (bw - (b.maxX - b.minX) * k) / 2 - b.minX * k;
  const oy = by + (bh - (b.maxY - b.minY) * k) / 2 - b.minY * k;
  const fit = pts => pts.map(([x, y]) => [x * k + ox, y * k + oy]);
  return { ...k9, fit };
}

const open = label =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"${label ? ` role="img" aria-label="${label}"` : ' aria-hidden="true"'}>`;

const toneOf = (b, f) => (f.k > 0.15 ? b.shade : f.t > 0.3 ? b.top : f.s > 0.5 ? b.right : b.left);

/* 64 px and up (avatar, hero, social card): faceted, the bore lit at its
   lip, dark beyond, daylight where it opens through */
export const glyph = (id = 'keystone', edge = 1, label = 'keystone: a keystone wedge with a keyhole bored through its face') => {
  const t = tones, { faces, top, outline, opening, walls, back, through, shadow, fit } = fitted([2, 2, 60, 60]);
  const byTone = (list, b) => {
    const m = new Map();
    for (const f of list) { const tone = toneOf(b, f); m.set(tone, [...(m.get(tone) ?? []), path(fit(f.pts), 1)]); }
    return [...m].map(([tone, d]) => `<path d="${d.join('')}" fill="${tone}" stroke="${tone}" stroke-width="0.25" stroke-linejoin="round"/>`).join('');
  };
  const hole = path(fit(opening), 1), rim = path(fit(outline), 1);
  /* daylight: where the back opening shows through the front, the stone is
     masked away and the page shows */
  const day = through
    ? `<mask id="${id}-day" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64"><rect width="64" height="64" fill="#fff"/>` +
      `<g clip-path="url(#${id}-bore)"><path d="${path(fit(back), 1)}" fill="#000"/></g></mask>`
    : '';
  const stone = [
    `<path d="${rim}" fill="${t.body.left}"/>`,
    byTone(faces, t.body),
    `<polygon points="${points(fit(top), 1)}" fill="${t.body.top}"/>`,
    `<g clip-path="url(#${id}-bore)"><path d="${hole}" fill="${t.bore.shade}"/>` +
      walls.map(f => `<path d="${path(fit(f.pts), 1)}" fill="${toneOf(t.bore, f)}" stroke="${toneOf(t.bore, f)}" stroke-width="0.25" stroke-linejoin="round"/>`).join('') +
    `</g>`,
    `<path d="${rim}" fill="none" stroke="${t.edge}" stroke-width="${edge}" stroke-linejoin="round"/>`,
  ].join('');
  const parts = [
    `<polygon points="${points(fit(shadow), 1)}" fill="${t.cast}" fill-opacity="${t.castOpacity / 2}"/>`,
    `<g${through ? ` mask="url(#${id}-day)"` : ''}>${stone}</g>`,
    `<path d="${hole}" fill="none" stroke="${t.edge}" stroke-width="${edge * 0.75}" stroke-linejoin="round"/>`,
  ];
  return `${open(label)}<defs><clipPath id="${id}-bore"><path d="${hole}"/></clipPath>${day}</defs>${parts.join('')}</svg>\n`;
};

/* 16 to 32 px (favicon, header): three flat tones, the keyhole punched
   white, an edge one screen pixel wide at any size */
export const small = (id = 'keystone', label = 'keystone: a keystone wedge, keyed') => {
  const { faces, top, outline, opening, fit } = fitted([3, 3, 58, 58], { keyScale: 1.55, keySlot: 1.3 });
  const t = tones.small, c = r => `${id}-${r}`;
  const front = faces.find(f => f.k <= 0.15 && f.t <= 0.3 && f.s <= 0.5);
  const outlineD = path(fit(outline), 1);
  const css = `.${c('b2')}{fill:${t.body[2]}}.${c('b1')}{fill:${t.body[1]}}.${c('b0')}{fill:${t.body[0]}}.${c('h')}{fill:${t.hole}}` +
    `.${c('e')}{fill:none;stroke:${t.edge};stroke-width:${t.width};stroke-linejoin:round}`;
  return `${open(label)}<style>${css}</style>` +
    `<path class="${c('b2')}" d="${outlineD}"/>` +
    (front ? `<path class="${c('b1')}" d="${path(fit(front.pts), 1)}"/>` : '') +
    `<polygon class="${c('b0')}" points="${points(fit(top), 1)}"/>` +
    `<path class="${c('h')}" d="${path(fit(opening), 1)}"/>` +
    `<path class="${c('e')}" d="${outlineD}" vector-effect="non-scaling-stroke"/></svg>\n`;
};

const here = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(here, 'mark.svg'), glyph());
writeFileSync(join(here, 'favicon.svg'), small());
