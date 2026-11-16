import { start } from '@dunn.dev/reference/folio/walk.js';
import mark from '../brand/hero-mark.svg?raw';

start({
  figures: import.meta.glob('../figures/[0-9]*.js'),
  kit: { cover: (mount) => { if (!mount.firstElementChild) mount.innerHTML = mark; } },
});
