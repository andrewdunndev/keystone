#!/usr/bin/env node
/* keystone mark, direction "arch": a small isometric arch whose crown is the
   keystone. Projection, tones and stroke logic follow cairn's src/brand
   (elevation 30, lit faces toned by normal, one moss accent, #404040 edges);
   the geometry is its own. Writes mark.svg (64 px and up) and favicon.svg
   (16 to 32 px) beside this file. */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/* ---- palette and tones, the estate's table ---- */
const palette = { white: '#ffffff', e500: '#404040', e600: '#0a0a0a', m400: '#4a6741' };
const mix = (a, b, pct) => {
  const c = (h, i) => parseInt(h.slice(1 + i * 2, 3 + i * 2), 16);
  return '#' + [0, 1, 2].map(i => Math.round(c(a, i) * pct / 100 + c(b, i) * (1 - pct / 100)).toString(16).padStart(2, '0')).join('');
};
const lit = (top, dark, k) => ({ top, left: mix(dark, top, k[0]), right: mix(dark, top, k[1]), shade: mix(dark, top, k[2]) });
const stone = lit(palette.white, palette.e600, [7, 16, 30]);
const moss = lit(palette.m400, palette.e600, [18, 36, 55]);
const tones = {
  stone, key: moss, edge: palette.e500, cast: palette.e600, castOpacity: 0.14,
  small: { stone: [stone.top, mix(palette.e600, palette.white, 24)], key: [moss.top, moss.right], edge: palette.e500, width: 1 },
};

/* ---- the arch, in world units ----
   span runs along u, depth along v, z up; the arch centre sits at z = spring.
   yaw turns u into world x/y (-45 lays the span flat across the picture). */
const arch = {
  ro: 100, ri: 57, depth: 46, yaw: -38, spring: 84,
  key: 22,           // keystone half-angle, degrees
  proud: [8, 6],     // the keystone stands this far outside and inside the ring
  chamfer: 4,        // front and back bevel, world units
  seat: 1.5,         // voussoirs sit this far into the piers, as cairn stones rest
  arc: 14,           // degrees per segment along the ring
};
const deg = Math.PI / 180;

/* a cross-section in (u, z), counter-clockwise seen from the front */
const voussoir = (a0, a1, [po, pi] = [0, 0]) => {
  const n = Math.max(2, Math.round((a1 - a0) / arch.arc));
  const at = (r, a) => [r * Math.cos(a * deg), arch.spring + r * Math.sin(a * deg)];
  const pts = [];
  for (let k = 0; k <= n; k++) pts.push(at(arch.ro + po, a0 + ((a1 - a0) * k) / n));   // extrados, a0 -> a1
  for (let k = n; k >= 0; k--) pts.push(at(arch.ri - pi, a0 + ((a1 - a0) * k) / n));   // intrados, back
  return pts;
};
const pier = (side) => {
  const u0 = side * arch.ri, u1 = side * arch.ro, lo = Math.min(u0, u1), hi = Math.max(u0, u1);
  return [[lo, 0], [hi, 0], [hi, arch.spring + arch.seat], [lo, arch.spring + arch.seat]];
};

/* stones, with which one carries the moss */
const k = arch.key;
const stones = [
  { name: 'pier-left', section: pier(-1) },
  { name: 'pier-right', section: pier(1) },
  { name: 'voussoir-left', section: voussoir(90 + k, 180) },
  { name: 'voussoir-right', section: voussoir(0, 90 - k) },
  { name: 'keystone', section: voussoir(90 - k, 90 + k, arch.proud), key: true },
];

/* ---- geometry ---- */
const sub = (a, b) => a.map((v, i) => v - b[i]);
const dot = (a, b) => a.reduce((s, v, i) => s + v * b[i], 0);
const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
const norm = (a) => { const l = Math.hypot(...a); return a.map(v => v / l); };

/* inset a simple polygon along its vertex normals (inward for CCW) */
const inset = (poly, by) => poly.map((p, i) => {
  const a = poly[(i + poly.length - 1) % poly.length], b = poly[(i + 1) % poly.length];
  const e1 = norm([p[0] - a[0], p[1] - a[1], 0]), e2 = norm([b[0] - p[0], b[1] - p[1], 0]);
  const n1 = [e1[1], -e1[0]], n2 = [e2[1], -e2[0]];   // outward normals of a CCW polygon
  const n = norm([n1[0] + n2[0], n1[1] + n2[1], 0]);
  const cosHalf = Math.max(0.5, dot(n, [n1[0], n1[1], 0]));
  return [p[0] - (n[0] * by) / cosHalf, p[1] - (n[1] * by) / cosHalf];
});

export function build({ elevation = 30 } = {}) {
  const sE = Math.sin(elevation * deg), cE = Math.cos(elevation * deg);
  const cy = Math.cos(arch.yaw * deg), sy = Math.sin(arch.yaw * deg);
  const U = [cy, sy, 0], V = [-sy, cy, 0];
  const world = (u, v, z) => [u * U[0] + v * V[0], u * U[1] + v * V[1], z];
  const project = ([x, y, z]) => [(x - y) * Math.SQRT1_2, (x + y) * Math.SQRT1_2 * sE - z * cE];
  const view = [cE * Math.SQRT1_2, cE * Math.SQRT1_2, sE];
  const unit = (v) => Math.round(Math.min(1, Math.max(0, v)) * 100) / 100;

  const d = arch.depth / 2, c = arch.chamfer;
  const profile = [[d, c], [d - c, 0], [-d + c, 0], [-d, c]];   // [v, inset], front to back

  const solids = stones.map((s) => {
    const rings = profile.map(([v, by]) => inset(s.section, by).map(([u, z]) => world(u, v, z)));
    const n = s.section.length, verts = rings.flat();
    const id = (j, k) => j * n + (k % n);
    const faces = [];
    const push = (ids) => {
      const P = ids.map(i => verts[i]);
      let nrm = [0, 0, 0];   // Newell's method, any simple polygon
      for (let i = 0; i < P.length; i++) {
        const a = P[i], b = P[(i + 1) % P.length];
        nrm = nrm.map((v, j) => v + cross(a, b)[j]);
      }
      if (Math.hypot(...nrm) < 1e-9) return;
      nrm = norm(nrm);
      const centre = P.reduce((a, p) => a.map((v, i) => v + p[i] / P.length), [0, 0, 0]);
      const solidCentre = verts.reduce((a, p) => a.map((v, i) => v + p[i] / verts.length), [0, 0, 0]);
      if (dot(nrm, sub(centre, solidCentre)) < 0) nrm = nrm.map(v => -v);
      const visible = dot(nrm, view) > 0.06;
      const theta = Math.atan2(nrm[1], nrm[0]) / deg, rise = nrm[2];
      faces.push({ ids, pts: P.map(project), visible, s: unit((90 - theta) / 90), t: unit(rise * 0.85), k: unit(-rise * 0.7) });
    };
    push(rings[0].map((_, k) => id(0, k)));                                   // front cap
    push(rings[rings.length - 1].map((_, k) => id(rings.length - 1, k)).reverse());   // back cap
    for (let j = 0; j < rings.length - 1; j++)
      for (let k = 0; k < n; k++) push([id(j, k), id(j, k + 1), id(j + 1, k + 1), id(j + 1, k)]);

    /* silhouette: edges between a visible and a culled face, chained to loops */
    const edgeUse = new Map();
    for (const f of faces)
      for (let i = 0; i < f.ids.length; i++) {
        const a = f.ids[i], b = f.ids[(i + 1) % f.ids.length], key = a < b ? `${a}-${b}` : `${b}-${a}`;
        edgeUse.set(key, [...(edgeUse.get(key) ?? []), f.visible]);
      }
    const silhouette = [...edgeUse].filter(([, u]) => u.length === 2 && u[0] !== u[1]).map(([k]) => k.split('-').map(Number));
    const loops = chain(silhouette).map(loop => loop.map(i => project(verts[i])));
    const front = faces[0];
    const centre = verts.reduce((a, p) => a.map((v, i) => v + p[i] / verts.length), [0, 0, 0]);
    return { name: s.name, key: !!s.key, faces: faces.filter(f => f.visible), front, loops, depth: dot(centre, view), all: verts.map(project) };
  }).sort((a, b) => a.depth - b.depth);

  /* pier footprints darkened onto the ground, offset as cairn's base shadow */
  const shadows = stones.filter(s => s.name.startsWith('pier')).map(s =>
    s.section.filter(([, z]) => z === 0).flatMap(([u]) => [d, -d].map(v => world(u, v, 0)))
      .map(([x, y]) => [x + 7, y - 7, 0]).map(project));
  const hullShadows = shadows.map(hull);
  return { solids, shadows: hullShadows, all: solids.flatMap(s => s.all) };
}

function chain(edges) {
  const adj = new Map();
  for (const [a, b] of edges) { adj.set(a, [...(adj.get(a) ?? []), b]); adj.set(b, [...(adj.get(b) ?? []), a]); }
  const used = new Set(), loops = [];
  for (const [a, b] of edges) {
    const k0 = a < b ? `${a}-${b}` : `${b}-${a}`;
    if (used.has(k0)) continue;
    const loop = [a]; let prev = a, cur = b; used.add(k0);
    while (cur !== a) {
      loop.push(cur);
      const next = (adj.get(cur) ?? []).find(n => { const k = n < cur ? `${n}-${cur}` : `${cur}-${n}`; return n !== prev && !used.has(k); });
      if (next === undefined) break;
      used.add(next < cur ? `${next}-${cur}` : `${cur}-${next}`);
      prev = cur; cur = next;
    }
    loops.push(loop);
  }
  return loops;
}

const hull = (pts) => {
  const p = [...pts].sort((m, n) => m[0] - n[0] || m[1] - n[1]);
  const cr = (o, a, b) => (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
  const half = (list) => list.reduce((h, q) => {
    while (h.length >= 2 && cr(h[h.length - 2], h[h.length - 1], q) <= 0) h.pop();
    h.push(q); return h;
  }, []).slice(0, -1);
  return [...half(p), ...half([...p].reverse())];
};

/* ---- fitting and SVG ---- */
const bounds = (pts) => ({
  minX: Math.min(...pts.map(p => p[0])), maxX: Math.max(...pts.map(p => p[0])),
  minY: Math.min(...pts.map(p => p[1])), maxY: Math.max(...pts.map(p => p[1])),
});
const fmt = (p, d = 1) => p.map(v => v.toFixed(d)).join(',');
const points = (pts, d = 1) => pts.map(p => fmt(p, d)).join(' ');
const path = (pts, d = 1) => 'M' + pts.map(p => fmt(p, d)).join('L') + 'Z';
const paths = (loops, d = 1) => loops.map(l => path(l, d)).join('');

function fitted(box) {
  const g = build();
  const [bx, by, bw, bh] = box;
  const b = bounds(g.all);
  const k = Math.min(bw / (b.maxX - b.minX), bh / (b.maxY - b.minY));
  const ox = bx + (bw - (b.maxX - b.minX) * k) / 2 - b.minX * k;
  const oy = by + (bh - (b.maxY - b.minY) * k) / 2 - b.minY * k;
  const fit = (pts) => pts.map(([x, y]) => [x * k + ox, y * k + oy]);
  return { ...g, fit };
}

const open = (label) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"${label ? ` role="img" aria-label="${label}"` : ' aria-hidden="true"'}>`;

/* 16 to 32 px: flat faces, a white front, an edge one screen pixel wide */
export const small = (id = 'keystone', label = 'keystone: a stone arch, its moss keystone at the crown') => {
  const { solids, fit } = fitted([3, 3, 58, 58]);
  const c = (r) => `${id}-${r}`;
  const body = solids.map(s => {
    const m = s.key ? 'c' : 's';
    const sides = s.faces.map(f => path(fit(f.pts), 1)).join('');
    return `<path class="${c(m + '0')}" d="${sides}"/>` +
      (s.front.visible ? `<polygon class="${c(m + '1')}" points="${points(fit(s.front.pts), 1)}"/>` : '') +
      `<path class="${c('e')}" d="${paths(s.loops.map(fit), 1)}" vector-effect="non-scaling-stroke"/>`;
  }).join('');
  const t = tones.small, r = (k) => `.${c(k)}`;
  const css = `${r('s1')}{fill:${t.stone[0]}}${r('s0')}{fill:${t.stone[1]};stroke:${t.stone[1]};stroke-width:0.3}` +
    `${r('c1')}{fill:${t.key[0]}}${r('c0')}{fill:${t.key[1]};stroke:${t.key[1]};stroke-width:0.3}` +
    `${r('e')}{fill:none;stroke:${t.edge};stroke-width:${t.width};stroke-linejoin:round;stroke-linecap:round}`;
  return `${open(label)}<style>${css}</style>${body}</svg>\n`;
};

/* 64 px and up: faceted, lit by normal, a ground shadow under the piers */
export const glyph = (edge = 1, label = 'keystone: a stone arch, its moss keystone at the crown') => {
  const t = tones;
  const { solids, shadows, fit } = fitted([2, 2, 60, 60]);
  const ground = shadows.map(s => `<polygon points="${points(fit(s), 1)}" fill="${t.cast}" fill-opacity="${t.castOpacity / 2}"/>`).join('');
  const body = solids.map(s => {
    const b = s.key ? t.key : t.stone;
    const byTone = new Map();
    for (const f of s.faces) {
      const tone = f.k > 0.15 ? b.shade : f.t > 0.3 ? b.top : f.s > 0.5 ? b.right : b.left;
      byTone.set(tone, [...(byTone.get(tone) ?? []), path(fit(f.pts), 1)]);
    }
    const parts = [];
    for (const [tone, d] of byTone)
      parts.push(`<path d="${d.join('')}" fill="${tone}" stroke="${tone}" stroke-width="0.25" stroke-linejoin="round"/>`);
    parts.push(`<path d="${paths(s.loops.map(fit), 1)}" fill="none" stroke="${t.edge}" stroke-width="${edge}" stroke-linejoin="round" stroke-linecap="round"/>`);
    return `<g>${parts.join('')}</g>`;
  }).join('');
  return `${open(label)}${ground}${body}</svg>\n`;
};

const here = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(here, 'mark.svg'), glyph());
writeFileSync(join(here, 'favicon.svg'), small());
console.log('wrote mark.svg favicon.svg');
