#!/usr/bin/env node
/* keystone mark, direction "arch": an isometric stone arch whose crown is
   the moss keystone. Projection (elevation 30), tones and the #404040 edge
   follow cairn's src/brand. At 64 px and up every stone is a rounded slab
   of many faces, toned by normal; at 16 to 32 px each is a flat prism.
   Writes mark.svg, favicon.svg and hero.svg (the keystone drops into the
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
/* a body lit from above, as cairn's stones are: faces that look up carry the
   stone's own colour, faces turned left and right sink toward dark, faces
   that look down sink furthest */
const lit = (top, dark, k) => ({ top, left: mix(dark, top, k[0]), right: mix(dark, top, k[1]), shade: mix(dark, top, k[2]) });
const stone = lit(palette.white, palette.e600, [7, 16, 30]);
const moss = lit(palette.m400, palette.e600, [18, 36, 55]);
/* the large form's ramp: each step k% of the way from a body's top toward
   dark, cairn's table (stone 7 16 30, moss 18 36 55) with steps between */
const ramp = (top, ks) => ks.map(k => mix(palette.e600, top, k));
const tones = {
  stone: ramp(palette.white, [0, 4, 7, 11, 16, 22, 30, 38]),
  key: ramp(palette.m400, [0, 10, 18, 27, 36, 45, 55, 63]),
  edge: palette.e500, cast: palette.e600, castOpacity: 0.14,
  small: { stone: [stone.top, mix(palette.e600, palette.white, 24)], key: [moss.top, moss.left], edge: palette.e500, width: 1 },
};

/* ---- the arch, in world units: span along u, depth along v, z up ----
   ro, ri: ring radii; pier: springing height; key: keystone half-angle;
   proud: how far the keystone stands outside and inside the ring; perSide:
   voussoirs each side; facets: extrados chords per voussoir */
const large = { ro: 100, ri: 60, pier: 72, depth: 44, yaw: -24, key: 15, proud: [7, 4], perSide: 3, courses: [0.46, 0.54], arc: 2 };
const small = { ro: 100, ri: 54, pier: 66, depth: 28, yaw: -24, key: 19, proud: [10, 5], perSide: 1, facets: 2 };
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
    const faces = [{ pts: front.map(project) }];
    s.pts.forEach((p, i) => {
      const q = s.pts[(i + 1) % n], tag = s.tags[i];
      if (tag === 'hidden') return;
      const [nu, nz] = norm2([q[1] - p[1], p[0] - q[0]]);   // outward normal of a CCW section
      if (nu * dU + nz * sE <= 0) return;
      faces.push({ pts: [front[i], front[(i + 1) % n], back[(i + 1) % n], back[i]].map(project) });
    });
    const all = [...front, ...back];
    return { name: s.name, key: !!s.key, faces, hull: hull(all.map(project)), all: all.map(project) };
  });
  return { solids, all: solids.flatMap(s => s.all) };
}

/* ---- the large form: every stone a rounded slab ----
   A slab is rings stacked along its own height axis H, each ring a rounded
   rectangle across X and Y set in by the profile (foot, belly, shoulder,
   top); quads join the rings and the end rings cap it. A voussoir's height
   runs out from the intrados, its X follows the joint planes and its
   corners stay square; a pier course stands on z. Seeded noise moves
   corners, radii, rings and the slope of the top, so no two stones match. */
const noise = (seed, k) => {
  let h = Math.imul(seed + 0x9e37, 0x85ebca6b) ^ Math.imul(k + 0x2c1b, 0xc2b2ae35);
  h = Math.imul(h ^ (h >>> 15), 0x27d4eb2f);
  return ((h ^ (h >>> 13)) >>> 0) / 4294967296 - 0.5;
};
const v3 = {
  add: (...terms) => terms.reduce((o, [k, w]) => o.map((c, i) => c + k * w[i]), [0, 0, 0]),
  cross: (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]],
  dot: (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2],
};
const newell = (poly) => {
  const n = [0, 0, 0];
  poly.forEach((p, i) => {
    const q = poly[(i + 1) % poly.length];
    n[0] += (p[1] - q[1]) * (p[2] + q[2]); n[1] += (p[2] - q[2]) * (p[0] + q[0]); n[2] += (p[0] - q[0]) * (p[1] + q[1]);
  });
  const l = Math.hypot(...n);
  return l < 1e-9 ? null : n.map(c => c / l);
};

function slab(s, arc) {
  const Y = v3.dot(v3.cross(s.X, s.Y), s.H) < 0 ? s.Y.map(c => -c) : s.Y;
  const m = Math.min(...s.half(s.h / 2)), steps = s.square ? 0 : arc;
  const loops = s.rings.map(([f, g]) => {
    const rise = f * s.h, inset = g * m, [A, B] = s.half(rise).map((v, i) => v - (i || !s.square ? inset : 0)), pts = [];
    [[1, 1], [-1, 1], [-1, -1], [1, -1]].forEach(([sx, sy], q) => {
      const rc = s.square ? 0 : Math.min(Math.max(s.r[q] * m - inset, 1), A, B);
      for (let k = 0; k <= steps; k++) {
        const t = (q * 90 + (k * 90) / (steps || 1)) * deg, grow = 1 + 0.07 * noise(s.seed, q * 5 + k);
        const x = (sx * (A - rc) + rc * Math.cos(t)) * (s.square ? 1 : grow), y = (sy * (B - rc) + rc * Math.sin(t)) * grow;
        pts.push(v3.add([1, s.O], [x, s.X], [y, Y], [rise + f * (s.tilt[0] * x + s.tilt[1] * y), s.H]));
      }
    });
    return pts;
  });
  const polys = [[...loops[0]].reverse(), loops[loops.length - 1]];
  for (let j = 0; j < loops.length - 1; j++) {
    const lo = loops[j], hi = loops[j + 1], n = lo.length;
    for (let k = 0; k < n; k++) polys.push([lo[k], lo[(k + 1) % n], hi[(k + 1) % n], hi[k]]);
  }
  return { polys, all: loops.flat(), belly: loops[1] };
}

/* which step of the ramp a face takes, from its world normal: faces that
   look up take the top; around the belly the step deepens as the face turns
   from the light (front left) to the right; chamfers that lean up lighten,
   those that lean down sink toward the underside */
const toneOf = ([x, y, z]) => {
  if (z > 0.6) return 0;
  const s = Math.min(Math.max((70 - Math.atan2(y, x) / deg) / 100, 0), 1);
  const k = 6 + 30 * s - (z > 0 ? 22 : 40) * z;
  const ks = [4, 7, 11, 16, 22, 30, 38];
  return 1 + ks.reduce((b, v, i) => Math.abs(v - k) < Math.abs(ks[b] - k) ? i : b, 0);
};

export function carve(a, elevation = 30) {
  const sE = Math.sin(elevation * deg), cE = Math.cos(elevation * deg);
  const th = a.yaw * deg, U = [Math.cos(th), Math.sin(th), 0], V = [-Math.sin(th), Math.cos(th), 0], Z = [0, 0, 1];
  const project = ([x, y, z]) => [(x - y) * Math.SQRT1_2, (x + y) * Math.SQRT1_2 * sE - z * cE];
  const view = [cE * Math.SQRT1_2, cE * Math.SQRT1_2, sE];
  const at = (u, v, z) => v3.add([u, U], [v, V], [z, Z]);
  const d = a.depth / 2, w = (a.ro - a.ri) / 2;
  const vary = (seed, k, by) => 1 + by * noise(seed, k);
  /* each stone its own: corner radii, the slope of its top, and where its
     rings sit (foot, lower and upper belly, shoulder, top) */
  const shape = (seed) => ({
    seed, r: [0, 1, 2, 3].map(q => 0.42 + 0.3 * noise(seed, 40 + q)),
    tilt: [0.05 * noise(seed, 50), 0.05 * noise(seed, 51)],
    rings: [[0, 0.12 + 0.06 * noise(seed, 60)], [0.2 + 0.06 * noise(seed, 61), 0.01], [0.48 + 0.08 * noise(seed, 62), 0],
      [0.74 + 0.06 * noise(seed, 63), 0.04 + 0.02 * noise(seed, 64)], [1, 0.18 + 0.06 * noise(seed, 65)]],
  });
  const slabs = [];
  /* the piers, each in courses from the ground to the springing, each course
     turned a few degrees its own way */
  [-1, 1].forEach((side) => {
    let z = 0;
    a.courses.forEach((share, c) => {
      const seed = (side > 0 ? 20 : 10) + c, h = share * a.pier * vary(seed, 1, 0.08), turn = 10 * deg * noise(seed, 5);
      const top = c === a.courses.length - 1 ? a.pier : z + h;
      slabs.push({ name: `pier-${side > 0 ? 'right' : 'left'}-${c}`, ...shape(seed), O: at(side * (a.ri + w), 1.2 * noise(seed, 2), z),
        H: Z, X: v3.add([Math.cos(turn), U], [Math.sin(turn), V]), Y: v3.add([-Math.sin(turn), U], [Math.cos(turn), V]),
        h: top - z, half: () => [w * vary(seed, 3, 0.05), d * vary(seed, 4, 0.06)] });
      z = top;
    });
  });
  /* the ring: square at the joints so neighbours close on one plane,
     chamfered front and back; the keystone stands proud at the crown */
  const ring = (name, a0, a1, [po, pi], seed, key = false) => {
    const mid = ((a0 + a1) / 2) * deg, half = ((a1 - a0) / 2) * deg, r0 = a.ri - pi;
    const er = v3.add([Math.cos(mid), U], [Math.sin(mid), Z]), et = v3.add([-Math.sin(mid), U], [Math.cos(mid), Z]);
    slabs.push({ name, key, a0, a1, square: true, ...shape(seed), O: v3.add([1, at(0, 0, a.pier)], [r0, er]),
      H: er, X: et, Y: V, h: a.ro + po - r0, half: (rise) => [(r0 + rise) * Math.tan(half), d] });
  };
  const step = (90 - a.key) / a.perSide;
  for (let i = 0; i < a.perSide; i++) {
    ring(`left-${i}`, 180 - (i + 1) * step, 180 - i * step, [0, 0], 30 + i);
    ring(`right-${i}`, i * step, (i + 1) * step, [0, 0], 40 + i);
  }
  ring('keystone', 90 - a.key, 90 + a.key, a.proud, 7, true);

  /* painted far to near by contact: a course before what stands on it, and
     at each joint of the ring the stone the joint faces away from first */
  const after = new Map(slabs.map(s => [s.name, new Set()]));
  [['left', 'left-0'], ['right', 'right-0']].forEach(([side, springer]) => {
    a.courses.forEach((_, c) => { if (c) after.get(`pier-${side}-${c}`).add(`pier-${side}-${c - 1}`); });
    after.get(springer).add(`pier-${side}-${a.courses.length - 1}`);
  });
  const chain = slabs.filter(s => s.a0 !== undefined).sort((p, q) => q.a0 - p.a0);
  chain.slice(1).forEach((q, j) => {
    const p = chain[j], phi = p.a0 * deg, t = v3.add([Math.sin(phi), U], [-Math.cos(phi), Z]);
    if (v3.dot(t, view) > 0) after.get(q.name).add(p.name); else after.get(p.name).add(q.name);
  });
  const solids = slabs.map((s) => {
    const { polys, all, belly } = slab(s, a.arc);
    const faces = polys.flatMap((p) => {
      const n = newell(p);
      return n && v3.dot(n, view) > 1e-3 ? [{ pts: p.map(project), tone: toneOf(n) }] : [];
    });
    const centre = all.reduce((c, p) => c.map((v, i) => v + p[i] / all.length), [0, 0, 0]);
    const flat = all.map(project);
    /* a course on the ground casts its belly onto the ground, down and to the right */
    const cast = s.O[2] === 0 ? hull([...belly, ...belly.map(([x, y]) => [x + 10, y - 10, 0])].map(([x, y]) => project([x, y, 0]))) : null;
    return { name: s.name, key: s.key, faces, cast, hull: hull(flat), all: flat, depth: v3.dot(centre, view) };
  });
  const order = [], rest = new Set(solids);
  while (rest.size) {
    const ready = [...rest].filter(s => ![...after.get(s.name)].some(n => [...rest].some(r => r.name === n)));
    const next = ready.sort((p, q) => p.depth - q.depth)[0];
    order.push(next); rest.delete(next);
  }
  const casts = order.filter(s => s.cast).map(s => s.cast);
  return { solids: order, casts, all: [...order.flatMap(s => s.all), ...casts.flat()] };
}

/* ---- fitting and SVG ---- */
const bounds = (pts) => ({
  minX: Math.min(...pts.map(p => p[0])), maxX: Math.max(...pts.map(p => p[0])),
  minY: Math.min(...pts.map(p => p[1])), maxY: Math.max(...pts.map(p => p[1])),
});
const fmt = (p, d = 1) => p.map(v => v.toFixed(d)).join(',');
const points = (pts, d = 1) => pts.map(p => fmt(p, d)).join(' ');
const path = (pts, d = 1) => 'M' + pts.map(p => fmt(p, d)).join('L') + 'Z';

function fitted(a, box, make = build) {
  const g = make(a);
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
    `${r('e')}{fill:none;stroke:${t.edge};stroke-width:${t.width};stroke-linejoin:round}`;
  return `${open(label)}<style>${css}</style>${body}</svg>\n`;
};

/* 64 px and up: the silhouette filled first, then one path per step of the
   ramp so faces of a step share a fill and leave no seam, each drawn with a
   hair of its own colour over the joins to the next; then the silhouette's
   edge, cairn's weight and round join */
const stoneMarkup = (s, fit, edge) => {
  const b = s.key ? tones.key : tones.stone, outline = path(fit(s.hull), 1), byTone = new Map();
  for (const f of s.faces) byTone.set(f.tone, (byTone.get(f.tone) ?? '') + path(fit(f.pts), 1));
  const fills = [...byTone.keys()].sort((p, q) => p - q).map(t =>
    `<path d="${byTone.get(t)}" fill="${b[t]}" stroke="${b[t]}" stroke-width="0.2" stroke-linejoin="round"/>`).join('');
  return `<g><path d="${outline}" fill="${b[2]}"/>${fills}` +
    `<path d="${outline}" fill="none" stroke="${tones.edge}" stroke-width="${edge}" stroke-linejoin="round"/></g>`;
};

/* the piers' cast on the ground: one flat tone, no blur */
const castMarkup = (casts, fit) =>
  `<path d="${casts.map(c => path(fit(c), 1)).join('')}" fill="${tones.cast}" fill-opacity="${tones.castOpacity}"/>`;

export const glyph = (edge = 1, label = LABEL) => {
  const { solids, casts, fit } = fitted(large, [2, 2, 60, 60], carve);
  return `${open(label)}${castMarkup(casts, fit)}${solids.map(s => stoneMarkup(s, fit, edge)).join('')}</svg>\n`;
};

/* the hero: mark.svg's geometry on a canvas with headroom above, so the
   settled frame is the mark. The keystone starts lifted clear of its dashed
   landing, which lies under the stones and shows only in the gap; it falls
   accelerating, lands, rocks once and settles, as cairn's stones do; it
   plays once, and reduced motion shows the finished still */
export const heroFrame = () => {
  const { solids, fit } = fitted(large, [2, 2, 60, 60], carve);
  const kb = bounds(fit(solids.find(s => s.key).hull));
  const lift = Math.ceil(kb.maxY - kb.minY) + 3;
  return { lift, head: Math.ceil(lift - kb.minY + 2) };
};
export const hero = (edge = 1, label = LABEL, still = false) => {
  const { lift, head } = heroFrame();
  const { solids, casts, fit } = fitted(large, [2, 2, 60, 60], carve);
  const key = solids.find(s => s.key);
  const land = `<polygon class="keystone-land" points="${points(fit(key.hull), 1)}" fill="none" stroke="${tones.key[0]}" stroke-width="0.6" stroke-dasharray="1.6 1.2" stroke-linejoin="round"${still ? ' style="opacity:1"' : ''}/>`;
  const css = `.keystone-key{transform-box:fill-box;transform-origin:50% 100%;animation:keystone-drop 900ms linear 400ms both}` +
    `.keystone-land{opacity:0;animation:keystone-land 900ms linear 400ms both}` +
    `@keyframes keystone-drop{0%{transform:translateY(-${lift}px) rotate(-1deg);animation-timing-function:cubic-bezier(.5,0,1,.6)}` +
    `58%{transform:translateY(0) rotate(-.4deg);animation-timing-function:ease-out}71%{transform:translateY(-.9px) rotate(.5deg);animation-timing-function:ease-in-out}` +
    `85%{transform:translateY(0) rotate(-.15deg);animation-timing-function:ease-in-out}100%{transform:none}}` +
    `@keyframes keystone-land{0%,52%{opacity:1}62%,100%{opacity:0}}` +
    `@media (prefers-reduced-motion:reduce){.keystone-key,.keystone-land{animation:none}}`;
  const body = solids.map(s => s.key
    ? `<g class="keystone-key"${still ? ` transform="translate(0 -${lift})"` : ''}>${stoneMarkup(s, fit, edge)}</g>`
    : stoneMarkup(s, fit, edge)).join('');
  return `${open(label, `0 -${head} 64 ${64 + head}`)}<style>${css}</style>${castMarkup(casts, fit)}${land}${body}</svg>\n`;
};

const here = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(here, 'mark.svg'), glyph());
writeFileSync(join(here, 'favicon.svg'), small_());
writeFileSync(join(here, 'hero.svg'), hero());
if (process.argv[2]) writeFileSync(process.argv[2], hero(1, LABEL, true));
console.log('wrote mark.svg favicon.svg hero.svg');
