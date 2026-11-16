/* 10 curves: measured CPU per rec against the Free plan's 10 ms. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Measured CPU per rec on a scale from 0 to 15 ms, against the Free plan\'s limit of 10 ms. P-521, the default with ES512, takes 7 ms at the median and up to 12 ms cold, which crosses the limit. P-256 with ES256 takes up to 6 ms cold, under it.';
  const s = kit.svg(mount, 'CPU per rec by curve', alt);
  const f = sheet(s, kit, 1);
  const { wipe } = f.motion, X0 = 140, K = 32, x = ms => X0 + ms * K;
  const bar = (x1, x2, y, cls) => f.el('rect', { x: x1, y, width: x2 - x1, height: 44, class: cls }, s);
  const grow = (e, a, b) => f.add(e, { ramp: false, at: [a, b] }, p => wipe(e, p, 'x'));
  f.line(X0, 330, x(15), 330, 'rule-2', { at: [0, 0.15] });
  [0, 5, 10, 15].forEach(t => {
    f.line(x(t), 330, x(t), 338, 'tick', { at: [0, 0.15] });
    f.note(x(t), 358, t === 15 ? '15 ms' : String(t), { at: [0, 0.15], anchor: 'middle', cls: 'lab lab-2' });
  });
  f.note(X0, 100, 'P-521 · default, ES512', { at: [0.1, 0.3] });
  grow(bar(X0, x(7), 110, 'bar'), 0.15, 0.45);
  f.chip(x(7), 110, 5 * K, 44, '12 ms cold', { at: [0.4, 0.7] });
  f.note((X0 + x(7)) / 2, 138, '7 ms median', { at: [0.4, 0.6], anchor: 'middle' });
  f.note(X0, 220, 'P-256 · ES256', { at: [0.5, 0.7] });
  grow(bar(X0, x(6), 230, 'bar'), 0.55, 0.85);
  f.note((X0 + x(6)) / 2, 258, '6 ms cold', { at: [0.8, 1], anchor: 'middle' });
  f.line(x(10), 70, x(10), 330, 'centerline', { at: [0.6, 0.85] });
  f.note(x(10), 62, 'Free plan: 10 ms', { at: [0.6, 0.85], anchor: 'middle' });
  return { n: 1, update: f.update, enter: f.enter, exit: f.exit, alt: alt };
}
