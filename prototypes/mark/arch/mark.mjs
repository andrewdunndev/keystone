#!/usr/bin/env node
/* keystone mark, direction "arch": a flat-faced isometric arch whose crown is
   the moss keystone. Projection (elevation 30), tones and the #404040 edge
   follow cairn's src/brand; each stone is a prism with a handful of flat
   faces, so the glyph stays crisp at any size. Writes mark.svg (64 px and
   up), favicon.svg (16 to 32 px) and hero.svg (the keystone drops into the
   crown) beside this file. */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/* ---- palette and tones, the estate's table ---- */
const palette = { white: '#ffffff', e500: '#404040', e600: '#0a0a0a', m400: '#4a6741' };
const mix = (a, b, pct) => {
  const c = (h, i) => parseInt(h.slice(1 + i * 2, 3 + i * 2), 16);
  return '#' + [0, 1, 2].map(i => Math.round(c(a, i) * pct / 100 + c(b, i) * (1 - pct / 100)).toString(16).padStart(2, '0')).join('');
};
/* a body lit from the front: the front elevation, faces that look up, faces
   that look along the span, and the shaded faces inside the opening */
const lit = (front, dark, k) => ({ front, up: mix(dark, front, k[0]), side: mix(dark, front, k[1]), shade: mix(dark, front, k[2]) });
const stone = lit(palette.white, palette.e600, [7, 16, 30]);
const moss = lit(palette.m400, palette.e600, [18, 36, 55]);
const tones = {
  stone, key: moss, edge: palette.e500,
  small: { stone: [stone.front, mix(palette.e600, palette.white, 24)], key: [moss.front, moss.side], edge: palette.e500, width: 1 },
};

/* ---- the arch, in world units: span along u, depth along v, z up ----
   ro, ri: ring radii; pier: springing height; key: keystone half-angle;
   proud: how far the keystone stands outside and inside the ring; perSide:
   voussoirs each side; facets: extrados chords per voussoir; cull: how
   square-on a face must be to draw */
const large = { ro: 100, ri: 62, pier: 70, depth: 44, yaw: -24, key: 20, proud: [10, 5], perSide: 2, cull: 0 };
const small = { ro: 100, ri: 40, pier: 40, depth: 34, yaw: -24, key: 32, proud: [16, 10], perSide: 1, facets: 2, cull: 0 };
const deg = Math.PI / 180;

/* cross-sections in (u, z), counter-clockwise seen from the front, each edge
   tagged with the face it extrudes: out (extrados or outer wall), in (the
   opening), joint (a bed; drawn only where it faces the slot, since the
   stone that covers it paints over the rest). Painted in order: piers, then
   the ring upward, the keystone just before the right crown stone so that
   stone covers the keystone's joint face where they meet. */
function sections(a) {
  const at = (r, ang) => [r * Math.cos(ang * deg), a.pier + r * Math.sin(ang * deg)];
  const wedge = (name, a0, a1, [po, pi] = [0, 0], upper = 'hidden', lower = 'hidden', facets = a.facets ?? 1) => {
    const outer = Array.from({ length: facets + 1 }, (_, f) => at(a.ro + po, a0 + ((a1 - a0) * f) / facets));
    return { name, pts: [...outer, at(a.ri - pi, a1), at(a.ri - pi, a0)], tags: [...Array(facets).fill('out'), upper, 'in', lower] };
  };
  const k = a.key, step = (90 - k) / a.perSide, out = [
    { name: 'pier-left', pts: [[-a.ro, 0], [-a.ri, 0], [-a.ri, a.pier], [-a.ro, a.pier]], tags: ['hidden', 'in', 'hidden', 'out'] },
    { name: 'pier-right', pts: [[a.ri, 0], [a.ro, 0], [a.ro, a.pier], [a.ri, a.pier]], tags: ['hidden', 'out', 'hidden', 'in'] },
  ];
  for (let i = 0; i < a.perSide; i++) {
    const crown = i === a.perSide - 1;
    out.push(wedge(`left-${i}`, 180 - (i + 1) * step, 180 - i * step, [0, 0], 'hidden', crown ? 'joint' : 'hidden'));
    if (crown) out.push({ ...wedge('keystone', 90 - k, 90 + k, a.proud, 'joint', 'joint', 1), key: true });
    out.push(wedge(`right-${i}`, i * step, (i + 1) * step, [0, 0], crown ? 'joint' : 'hidden', 'hidden'));
  }
  return out;
}

/* ---- projection ---- */
const norm2 = ([x, y]) => { const l = Math.hypot(x, y); return [x / l, y / l]; };
const hull = (pts) => {
  const p = [...pts].sort((m, n) => m[0] - n[0] || m[1] - n[1]);
  const cr = (o, a, b) => (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
  const half = (list) => list.reduce((h, q) => {
    while (h.length >= 2 && cr(h[h.length - 2], h[h.length - 1], q) <= 0) h.pop();
    h.push(q); return h;
  }, []).slice(0, -1);
  return [...half(p), ...half([...p].reverse())];
};

export function build(a, elevation = 30) {
  const sE = Math.sin(elevation * deg), cE = Math.cos(elevation * deg);
  const th = a.yaw * deg, U = [Math.cos(th), Math.sin(th)], V = [-Math.sin(th), Math.cos(th)];
  const world = (u, v, z) => [u * U[0] + v * V[0], u * U[1] + v * V[1], z];
  const project = ([x, y, z]) => [(x - y) * Math.SQRT1_2, (x + y) * Math.SQRT1_2 * sE - z * cE];
  const view = [cE * Math.SQRT1_2, cE * Math.SQRT1_2, sE];
  const dU = U[0] * view[0] + U[1] * view[1];   // how much a face along +u shows
  const d = a.depth / 2;
  const solids = sections(a).map((s) => {
    const n = s.pts.length;
    const front = s.pts.map(([u, z]) => world(u, d, z)), back = s.pts.map(([u, z]) => world(u, -d, z));
    const faces = [{ pts: front.map(project), tone: 'front' }];
    s.pts.forEach((p, i) => {
      const q = s.pts[(i + 1) % n], tag = s.tags[i];
      if (tag === 'hidden') return;
      const [nu, nz] = norm2([q[1] - p[1], p[0] - q[0]]);   // outward normal of a CCW section
      if (nu * dU + nz * sE < a.cull) return;
      const tone = tag === 'in' ? 'shade' : nz > 0.3 ? 'up' : 'side';
      faces.push({ pts: [front[i], front[(i + 1) % n], back[(i + 1) % n], back[i]].map(project), tone });
    });
    const all = [...front, ...back];
    return { name: s.name, key: !!s.key, faces, hull: hull(all.map(project)), all: all.map(project) };
  });
  return { solids, all: solids.flatMap(s => s.all) };
}

/* ---- fitting and SVG ---- */
const bounds = (pts) => ({
  minX: Math.min(...pts.map(p => p[0])), maxX: Math.max(...pts.map(p => p[0])),
  minY: Math.min(...pts.map(p => p[1])), maxY: Math.max(...pts.map(p => p[1])),
});
const fmt = (p, d = 1) => p.map(v => v.toFixed(d)).join(',');
const points = (pts, d = 1) => pts.map(p => fmt(p, d)).join(' ');
const path = (pts, d = 1) => 'M' + pts.map(p => fmt(p, d)).join('L') + 'Z';

function fitted(a, box) {
  const g = build(a);
  const [bx, by, bw, bh] = box;
  const b = bounds(g.all);
  const k = Math.min(bw / (b.maxX - b.minX), bh / (b.maxY - b.minY));
  const ox = bx + (bw - (b.maxX - b.minX) * k) / 2 - b.minX * k;
  const oy = by + (bh - (b.maxY - b.minY) * k) / 2 - b.minY * k;
  const fit = (pts) => pts.map(([x, y]) => [x * k + ox, y * k + oy]);
  return { ...g, fit, k };
}

const LABEL = 'keystone: a stone arch, its moss keystone at the crown';
const open = (label, viewBox = '0 0 64 64') =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}"${label ? ` role="img" aria-label="${label}"` : ' aria-hidden="true"'}>`;

/* 16 to 32 px: a white front, one grey for every depth face, an edge one
   screen pixel wide around each stone */
export const small_ = (id = 'keystone', label = LABEL) => {
  const { solids, fit } = fitted(small, [3, 3, 58, 58]);
  const c = (r) => `${id}-${r}`;
  const body = solids.map(s => {
    const m = s.key ? 'c' : 's';
    const sides = s.faces.slice(1).map(f => path(fit(f.pts), 1)).join('');
    return (sides ? `<path class="${c(m + '0')}" d="${sides}"/>` : '') +
      `<polygon class="${c(m + '1')}" points="${points(fit(s.faces[0].pts), 1)}"/>` +
      `<path class="${c('e')}" d="${path(fit(s.hull), 1)}" vector-effect="non-scaling-stroke"/>`;
  }).join('');
  const t = tones.small, r = (k) => `.${c(k)}`;
  const css = `${r('s1')}{fill:${t.stone[0]}}${r('s0')}{fill:${t.stone[1]}}${r('c1')}{fill:${t.key[0]}}${r('c0')}{fill:${t.key[1]}}` +
    `${r('e')}{fill:none;stroke:${t.edge};stroke-width:${t.width};stroke-linejoin:miter}`;
  return `${open(label)}<style>${css}</style>${body}</svg>\n`;
};

/* 64 px and up: flat faces toned by where they look, seams at half the
   edge weight, the stone's silhouette at full weight */
const stoneMarkup = (s, fit, edge) => {
  const b = s.key ? tones.key : tones.stone;
  const fills = s.faces.map(f => `<polygon points="${points(fit(f.pts), 1)}" fill="${b[f.tone]}"/>`).join('');
  const seams = s.faces.slice(1).map(f => path(fit(f.pts), 1)).join('');
  return `<g>${fills}` +
    (seams ? `<path d="${seams}" fill="none" stroke="${tones.edge}" stroke-width="${edge / 2}" stroke-linejoin="miter"/>` : '') +
    `<polygon points="${points(fit(s.hull), 1)}" fill="none" stroke="${tones.edge}" stroke-width="${edge}" stroke-linejoin="miter"/></g>`;
};

export const glyph = (edge = 0.5, label = LABEL) => {
  const { solids, fit } = fitted(large, [2, 2, 60, 60]);
  return `${open(label)}${solids.map(s => stoneMarkup(s, fit, edge)).join('')}</svg>\n`;
};

/* the hero: the keystone starts lifted over its dashed landing, falls
   accelerating, lands, rocks once and settles, as cairn's stones do; it plays
   once, and reduced motion shows the finished still */
export const hero = (edge = 0.5, label = LABEL, still = false) => {
  const lift = 14, head = 16;
  const { solids, fit } = fitted(large, [2, head, 60, 60]);
  const key = solids.find(s => s.key);
  const land = `<polygon class="land" points="${points(fit(key.hull), 1)}" fill="none" stroke="${tones.key.front}" stroke-width="0.6" stroke-dasharray="1.6 1.2" stroke-linejoin="round"${still ? ' style="opacity:1"' : ''}/>`;
  const css = `.key{transform-box:fill-box;transform-origin:50% 100%;animation:key-drop 820ms linear 400ms both}` +
    `.land{opacity:0;animation:key-land 820ms linear 400ms both}` +
    `@keyframes key-drop{0%{transform:translateY(-${lift}px);animation-timing-function:cubic-bezier(.5,0,1,.6)}` +
    `56%{transform:translateY(0);animation-timing-function:ease-out}70%{transform:translateY(.35px) rotate(-.6deg);animation-timing-function:ease-in-out}` +
    `86%{transform:translateY(-.15px) rotate(.3deg);animation-timing-function:ease-in-out}100%{transform:none}}` +
    `@keyframes key-land{0%,50%{opacity:1}62%,100%{opacity:0}}` +
    `@media (prefers-reduced-motion:reduce){.key,.land{animation:none}}`;
  const body = solids.map(s => s.key
    ? `${land}<g class="key"${still ? ` transform="translate(0 -${lift})"` : ''}>${stoneMarkup(s, fit, edge)}</g>`
    : stoneMarkup(s, fit, edge)).join('');
  return `${open(label, `0 0 64 ${64 + head}`)}<style>${css}</style>${body}</svg>\n`;
};

const here = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(here, 'mark.svg'), glyph());
writeFileSync(join(here, 'favicon.svg'), small_());
writeFileSync(join(here, 'hero.svg'), hero());
if (process.argv[2]) writeFileSync(process.argv[2], hero(0.5, LABEL, true));
console.log('wrote mark.svg favicon.svg hero.svg');
