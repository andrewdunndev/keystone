/* The arch of mark.mjs drawn as cairn's home cover is, in thin wire: a
   hairline edge, a dash-dot ground plate, and stones that drop once in order. */

import { carve, fitted, large, deg, bounds, points, path, tones, open, LABEL, castMarkup } from './mark.mjs';

/* the cover's weights over the 60-unit arch: edge, seam, plate */
export const wire = { edge: 0.2, seam: 0.12, plate: 0.15, plateColor: 'rgba(22,22,22,.3)', dash: '1.9 .5 .3 .5' };

export const stoneWire = (s, fit, edge = wire.edge) => {
  const b = s.key ? tones.key : tones.stone, outline = path(fit(s.hull), 1), byTone = new Map();
  for (const f of s.faces) byTone.set(f.tone, (byTone.get(f.tone) ?? '') + path(fit(f.pts), 1));
  const fills = [...byTone.keys()].sort((p, q) => p - q).map(t =>
    `<path d="${byTone.get(t)}" fill="${b[t]}" stroke="${b[t]}" stroke-width="${wire.seam}" stroke-linejoin="round"/>`).join('');
  return `<g><path d="${outline}" fill="${b[2]}"/>${fills}` +
    `<path d="${outline}" fill="none" stroke="${tones.edge}" stroke-width="${edge}" stroke-linejoin="round" stroke-linecap="round"/></g>`;
};

/* the ground plate: the arch's footprint with a margin, set on the ground
   plane and projected as the arch is, as a dash-dot parallelogram */
const plateOf = (fit) => {
  const sE = Math.sin(30 * deg), th = large.yaw * deg, U = [Math.cos(th), Math.sin(th)], V = [-Math.sin(th), Math.cos(th)];
  const du = large.ro + 14, dv = large.depth / 2 + 16;
  return fit([[-du, -dv], [du, -dv], [du, dv], [-du, dv]].map(([u, v]) => {
    const x = u * U[0] + v * V[0], y = u * U[1] + v * V[1];
    return [(x - y) * Math.SQRT1_2, (x + y) * Math.SQRT1_2 * sE];
  }));
};

const plateMarkup = (pts, w = wire.plate) =>
  `<polygon points="${points(pts, 1)}" fill="none" stroke="${wire.plateColor}" stroke-width="${w}" stroke-dasharray="${wire.dash}" stroke-linejoin="round"/>`;

/* the arch with its piers' cast, at a given edge weight, as bare markup */
export const archBody = (edge = wire.edge, plate = false) => {
  const { solids, casts, fit } = fitted(large, [2, 2, 60, 60], carve);
  return (plate ? plateMarkup(plateOf(fit)) : '') + castMarkup(casts, fit) + solids.map(s => stoneWire(s, fit, edge)).join('');
};

/* the hero: mark's geometry plus the plate on a canvas with headroom, so the
   settled frame is the mark on its ground. The stones fall as cairn's home
   cover drops them: in order from the ground up, each course of both piers,
   then the ring from the springers to the crown, the keystone last. Each
   leads by 200 ms, lags the one below by LAG, accelerates to land at 56% of
   820 ms, lifts a hair, rocks, settles, and plays once. The piers' cast fades
   in as the first course lands. Reduced motion drops the animation and shows
   the finished frame */
const DROP = { lead: 200, lag: 260, ms: 820, land: 0.56, shade: 300 };
const rank = (name, courses, perSide) => {
  const [kind, , c] = name.split('-');
  return kind === 'pier' ? +c : kind === 'keystone' ? courses + perSide : courses + +name.split('-')[1];
};
export const hero = (label = LABEL) => {
  const { solids, casts, fit } = fitted(large, [2, 2, 60, 60], carve);
  const rk = (s) => rank(s.name, large.courses.length, large.perSide);
  const fall = (r) => 10 + 3 * r;
  const key = solids.find(s => s.key), kb = bounds(fit(key.hull));
  const plate = plateOf(fit), pb = bounds(plate);
  const x0 = Math.floor(Math.min(0, pb.minX - 1)), x1 = Math.ceil(Math.max(64, pb.maxX + 1));
  const y0 = -Math.ceil(Math.max(...solids.map(s => fall(rk(s)) - bounds(fit(s.hull)).minY)) + 2), y1 = Math.ceil(Math.max(64, pb.maxY + 1));
  const land = `<polygon class="keystone-land" style="--i:${rk(key)}" points="${points(fit(key.hull), 1)}" fill="none" stroke="${wire.plateColor}" stroke-width="${wire.plate}" stroke-dasharray="1 .8" stroke-linejoin="round"/>`;
  const { lead, lag, ms, land: at, shade } = DROP, pct = (u) => `${+(u * 100).toFixed(1)}%`;
  const delay = `calc(${lead}ms + var(--i) * ${lag}ms)`;
  const css = `.st{transform-box:fill-box;transform-origin:50% 100%;animation:st-drop ${ms}ms linear ${delay} both}` +
    `.cast{animation:st-cast ${shade}ms cubic-bezier(.215,.61,.355,1) ${lead + Math.round(at * ms)}ms both}` +
    `.keystone-land{opacity:0;animation:st-land ${ms}ms linear ${delay} both}` +
    `@keyframes st-drop{0%{opacity:0;transform:translateY(calc(var(--d) * -1px)) rotate(-2deg);animation-timing-function:cubic-bezier(.55,.09,.68,.53)}` +
    `${pct(at * 0.22)}{opacity:1}${pct(at)}{opacity:1;transform:translateY(0) rotate(-.6deg);animation-timing-function:cubic-bezier(.215,.61,.355,1)}` +
    `70%{transform:translateY(-.5px) rotate(.8deg);animation-timing-function:ease-in-out}` +
    `84%{transform:translateY(0) rotate(-.25deg);animation-timing-function:ease-in-out}` +
    `100%{opacity:1;transform:none}}` +
    `@keyframes st-cast{from{opacity:0}to{opacity:1}}` +
    `@keyframes st-land{0%,50%{opacity:1}60%,100%{opacity:0}}` +
    `@media (prefers-reduced-motion:reduce){.st,.cast,.keystone-land{animation:none}}`;
  const body = solids.map(s => `<g class="st" style="--i:${rk(s)};--d:${fall(rk(s))}">${stoneWire(s, fit)}</g>`).join('');
  return `${open(label, `${x0} ${y0} ${x1 - x0} ${y1 - y0}`)}<style>${css}</style>${plateMarkup(plate)}<g class="cast">${castMarkup(casts, fit)}</g>${land}${body}</svg>\n`;
};
