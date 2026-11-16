/* keystone mark: an isometric stone arch whose crown is the moss keystone.
   Elevation 30; tones and the #404040 edge follow cairn's src/brand. At 64 px
   and up each stone is a rounded slab of many faces toned by normal; below
   that each is a flat prism. */


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
export const tones = {
  stone: ramp(palette.white, [0, 4, 7, 11, 16, 22, 30, 38]),
  key: ramp(palette.m400, [0, 10, 18, 27, 36, 45, 55, 63]),
  edge: palette.e500, cast: palette.e600, castOpacity: 0.14,
  small: { width: 1 },
};

/* ---- the arch, in world units: span along u, depth along v, z up ----
   ro, ri: ring radii; pier: springing height; key: keystone half-angle;
   proud: how far the keystone stands outside and inside the ring; perSide:
   voussoirs each side; facets: extrados chords per voussoir; hew: the
   ranges each stone draws its corner facets and tool strokes from, and how
   deep its strokes, lumps and chips cut */
export const large = { ro: 100, ri: 60, pier: 72, depth: 44, yaw: -24, key: 15, proud: [7, 4], perSide: 3, courses: [0.33, 0.33, 0.34], hew: { facets: [1, 4], strokes: [1, 3], scale: 1 } };
const small = { ...large, depth: 40, perSide: 2, courses: [0.5, 0.5], hew: { facets: [1, 1], strokes: [0, 1], scale: 0.5 } };
export const deg = Math.PI / 180;

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
  /* a hewn hint: every corner no neighbour shares moves a seeded hair, so
     joints still close and each stone sits a little off true */
  const secs = sections(a), key = ([u, z]) => `${u.toFixed(3)},${z.toFixed(3)}`, seen = new Map();
  secs.forEach(s => s.pts.forEach(p => seen.set(key(p), (seen.get(key(p)) ?? 0) + 1)));
  const rough = a.rough ?? 0;
  const solids = secs.map((s, i) => ({ ...s, pts: s.pts.map((p, j) => seen.get(key(p)) > 1 ? p
    : [p[0] + rough * noise(70 + i, 2 * j), p[1] + rough * noise(70 + i, 2 * j + 1)]) })).map((s) => {
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
   runs out from the intrados and its X follows the joint planes; a pier
   course stands on z. Every stone is hewn by the same rule from its own seed,
   so each wears, facets and chips differently and no two stones match. */
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
  const m = Math.min(...s.half(s.h / 2));
  const R = s.a0 === undefined ? s.rings : [[0, s.rings[0][1]], [0.027, s.rings[0][1] * 0.5], [0.1, s.rings[0][1] * 0.134], ...s.rings.slice(1, -1), [0.9, s.rings[4][1] * 0.134], [0.973, s.rings[4][1] * 0.5], s.rings[4]];
  const loops = R.map(([f, g], j) => {
    const rise = f < 0.4 ? f * Math.min(s.h, s.hr) : f > 0.6 ? s.h - (1 - f) * Math.min(s.h, s.hr) : f * s.h, inset = g * m, pts = [];
    const [A, B] = s.half(rise).map((v, i) => v - inset + s.lump * m * (i ? 0.07 * noise(s.seed, 500 + j) : -0.06 * (noise(s.seed, 520 + j) + 0.5)));
    const put = (x, y) => pts.push(v3.add([1, s.O], [x, s.X], [y, Y], [rise + f * (s.tilt[0] * x + s.tilt[1] * y), s.H]));
    const grow = (q) => 1 + 0.1 * noise(s.seed, q % 4 * 5);
    /* corner q as a circle of radius rc; a chip pushes it in and flattens it */
    const corner = (q) => {
      const [sx, sy] = [[1, 1], [-1, 1], [-1, -1], [1, -1]][q % 4], chip = s.chips.find(c => c.q === q % 4 && f >= c.f[0] && f <= c.f[1]);
      const rc = Math.min(Math.max(s.r[q % 4] * m * (1 + 0.5 * s.lump * noise(s.seed, 600 + j * 4 + q % 4)) - inset, 1) + (chip ? chip.e * m : 0), A, B);
      return { chip, at: (t) => [sx * (A - rc) + rc * Math.cos(t * deg), sy * (B - rc) + rc * Math.sin(t * deg)] };
    };
    for (let q = 0; q < 4; q++) {
      const c = corner(q), a0 = c.at(q * 90), a1 = c.at(q * 90 + 90);
      for (let k = 0; k <= arc; k++) {
        const w = k / arc, gr = grow(q) * (1 - w) + grow(q + 1) * w;
        const [x, y] = c.chip ? [a0[0] + (a1[0] - a0[0]) * w, a0[1] + (a1[1] - a0[1]) * w] : c.at(q * 90 + w * 90);
        put(x * gr, y * gr);
      }
      /* the face on to the next corner, dressed in shallow tool strokes */
      const b = corner(q + 1).at(q * 90 + 90), nx = Math.round(Math.cos((q + 1) * 90 * deg)), ny = Math.round(Math.sin((q + 1) * 90 * deg));
      for (let k = 1; k <= s.wave.n; k++) {
        const w = k / (s.wave.n + 1), o = s.wave.amp * m * (0.3 + noise(s.seed, 100 + q * 10 + k) + 0.4 * noise(s.seed, 300 + j * 40 + q * 10 + k));
        put((a1[0] + (b[0] - a1[0]) * w + nx * o) * grow(q + 1), (a1[1] + (b[1] - a1[1]) * w + ny * o) * grow(q + 1));
      }
    }
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
  /* each stone hewn its own way, all from its seed: how worn it is (its
     corner radii and the round of its ends, one corner often left crisp),
     how many facets dress a corner, the tool strokes along its faces, a chip
     or two off a corner at its top, foot or along its length, the slope of
     its top, and where its rings sit (foot, lower and upper belly, shoulder,
     top) */
  const shape = (seed) => {
    const u = (k) => noise(seed, k) + 0.5, wear = u(70), crisp = Math.floor(u(71) * 6), pick = (k, [lo, hi]) => lo + Math.floor(u(k) * (hi - lo + 1)), sc = a.hew.scale;
    return {
      seed, hr: a.pier * a.courses[0],
      r: [0, 1, 2, 3].map(q => q === crisp ? 0.08 : Math.min(Math.max(0.22 + 0.5 * wear + 0.3 * noise(seed, 40 + q), 0.12), 0.8)),
      facets: pick(72, a.hew.facets),
      wave: { n: pick(73, a.hew.strokes), amp: sc * (0.04 + 0.1 * u(74)) }, lump: sc * (0.3 + 0.7 * u(82)),
      chips: Array.from({ length: Math.floor(u(75) * 2.6) }, (_, c) => ({
        q: Math.floor(u(76 + c) * 4), e: sc * (0.12 + 0.18 * u(78 + c)), f: [[0.55, 1], [0, 0.45], [0, 1]][Math.floor(u(80 + c) * 3)] })),
      tilt: [0.08 * noise(seed, 50), 0.08 * noise(seed, 51)],
      rings: [[0, 0.05 + 0.12 * wear + 0.04 * noise(seed, 60)], [0.2 + 0.06 * noise(seed, 61), 0.01], [0.48 + 0.08 * noise(seed, 62), 0],
        [0.74 + 0.06 * noise(seed, 63), 0.04 + 0.02 * noise(seed, 64)], [1, 0.08 + 0.13 * wear + 0.04 * noise(seed, 65)]],
    };
  };
  const slabs = [];
  /* the piers, each in courses from the ground to the springing, hewn
     by the same rule as the ring stones */
  [-1, 1].forEach((side) => {
    let z = 0;
    a.courses.forEach((share, c) => {
      const seed = (side > 0 ? 20 : 10) + c;
      const top = c === a.courses.length - 1 ? a.pier : z + share * a.pier;
      slabs.push({ name: `pier-${side > 0 ? 'right' : 'left'}-${c}`, ...shape(seed), O: at(side * (a.ri + w), 0, z),
        H: Z, X: U, Y: V, h: top - z, half: () => [w, d] });
      z = top;
    });
  });
  /* the ring: each stone hewn round its joint planes, so the joints read as
     dressed grooves; the keystone stands proud at the crown */
  const ring = (name, a0, a1, [po, pi], seed, key = false) => {
    const mid = ((a0 + a1) / 2) * deg, half = ((a1 - a0) / 2) * deg, r0 = a.ri - pi;
    const er = v3.add([Math.cos(mid), U], [Math.sin(mid), Z]), et = v3.add([-Math.sin(mid), U], [Math.cos(mid), Z]);
    slabs.push({ name, key, a0, a1, ...shape(seed), O: v3.add([1, at(0, 0, a.pier)], [r0, er]),
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
    const { polys, all, belly } = slab(s, s.facets);
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
export const bounds = (pts) => ({
  minX: Math.min(...pts.map(p => p[0])), maxX: Math.max(...pts.map(p => p[0])),
  minY: Math.min(...pts.map(p => p[1])), maxY: Math.max(...pts.map(p => p[1])),
});
export const fmt = (p, d = 1) => p.map(v => v.toFixed(d)).join(',');
export const points = (pts, d = 1) => pts.map(p => fmt(p, d)).join(' ');
export const path = (pts, d = 1) => 'M' + pts.map(p => fmt(p, d)).join('L') + 'Z';

export function fitted(a, box, make = build) {
  const g = make(a);
  const [bx, by, bw, bh] = box;
  const b = bounds(g.all);
  const k = Math.min(bw / (b.maxX - b.minX), bh / (b.maxY - b.minY));
  const ox = bx + (bw - (b.maxX - b.minX) * k) / 2 - b.minX * k;
  const oy = by + (bh - (b.maxY - b.minY) * k) / 2 - b.minY * k;
  const fit = (pts) => pts.map(([x, y]) => [x * k + ox, y * k + oy]);
  return { ...g, fit, k };
}

export const LABEL = 'keystone: a stone arch, its moss keystone at the crown';
export const open = (label, viewBox = '0 0 64 64') =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}"${label ? ` role="img" aria-label="${label}"` : ' aria-hidden="true"'}>`;

/* 16 to 32 px: the large form with fewer, chunkier stones (two courses a
   pier, two voussoirs a side), each its toned faces, a cast on the ground
   and an edge one screen pixel wide around each stone */
export const small_ = (id = 'keystone', label = LABEL) => {
  const { solids, casts, fit } = fitted(small, [3, 3, 58, 58], carve);
  const c = (r) => `${id}-${r}`;
  const body = solids.map(s => {
    const b = s.key ? tones.key : tones.stone, byTone = new Map();
    s.faces.forEach(f => byTone.set(f.tone, (byTone.get(f.tone) ?? '') + path(fit(f.pts), 1)));
    return `<path class="${c(s.key ? 'k' : 's')}" d="${path(fit(s.hull), 1)}"/>` +
      [...byTone.keys()].sort((p, q) => p - q).filter(t => t !== 2).map(t => `<path fill="${b[t]}" d="${byTone.get(t)}"/>`).join('') +
      `<path class="${c('e')}" d="${path(fit(s.hull), 1)}" vector-effect="non-scaling-stroke"/>`;
  }).join('');
  const r = (k) => `.${c(k)}`;
  const css = `${r('s')}{fill:${tones.stone[2]}}${r('k')}{fill:${tones.key[2]}}` +
    `${r('e')}{fill:none;stroke:${tones.edge};stroke-width:${tones.small.width};stroke-linejoin:round}`;
  return `${open(label)}<style>${css}</style>${castMarkup(casts, fit)}${body}</svg>\n`;
};

/* the piers' cast on the ground: one flat tone, no blur */
export const castMarkup = (casts, fit) =>
  `<path d="${casts.map(c => path(fit(c), 1)).join('')}" fill="${tones.cast}" fill-opacity="${tones.castOpacity}"/>`;

