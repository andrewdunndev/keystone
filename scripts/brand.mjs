#!/usr/bin/env node
/* Redraw the keystone glyph in avatar.svg and hero.svg from the arch
   generator, write favicon.svg to the repo root and site/public, and the
   animated mark the site home embeds to site/src/brand:
     node scripts/brand.mjs
   The text cards are hand-authored; only <g id="keystone-glyph"> is
   replaced. PNGs come after, from the reference brand.sh. The avatar is
   shown down to 40 px, so its edge is heavier than the hero's. */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { carve, fitted, large, bounds, small_ } from './mark/mark.mjs';
import { archBody, hero } from './mark/hero.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { solids, fit } = fitted(large, [2, 2, 60, 60], carve);
const b = bounds(solids.flatMap(s => fit(s.all)));
const bands = {
  'avatar.svg': { box: [40, 92, 176, 100], edge: 2 },
  'hero.svg': { box: [60, 238, 440, 136], edge: 1.2 },
};
const old = /^([ \t]*)<g (?:id="keystone-glyph" )?transform="translate\([^)]*\) scale\([^)]*\)"[^>]*>[\s\S]*?<\/g>$/m;

for (const [file, { box: [x, y, w, h], edge }] of Object.entries(bands)) {
  const k = Math.min(w / (b.maxX - b.minX), h / (b.maxY - b.minY));
  const tx = file === 'hero.svg' ? x : x + (w - (b.maxX - b.minX) * k) / 2;
  const ty = y + (h - (b.maxY - b.minY) * k) / 2;
  const t = `translate(${(tx - b.minX * k).toFixed(1)} ${(ty - b.minY * k).toFixed(1)}) scale(${k.toFixed(3)})`;
  const p = join(root, file), src = readFileSync(p, 'utf8');
  if (!old.test(src)) throw new Error(`${p}: no glyph group to replace`);
  writeFileSync(p, src.replace(old, (_, indent) => `${indent}<g id="keystone-glyph" transform="${t}">${archBody(edge / k)}</g>`));
}
const favicon = small_();
writeFileSync(join(root, 'favicon.svg'), favicon);
writeFileSync(join(root, 'site/public/favicon.svg'), favicon);
writeFileSync(join(root, 'site/src/brand/hero-mark.svg'), hero());
console.log('wrote favicons, site hero mark, glyph in avatar.svg and hero.svg');
