/* lib: a drafting sheet over the folio kit. A figure adds parts, flows,
   notes and tables, each with the step it arrives at and the step it
   leaves at, and the sheet's update(s) is the one pure function of the
   step position. Arrivals draw strokes first, then fade; nothing is built
   or sorted after the figure is made. */

export function sheet(s, kit, n) {
  const { iso, dim, motion } = kit;
  const { el } = iso;
  const { win, drawIn, travel, assemble } = motion;
  const sh = dim.begin(s);
  const items = [];
  const END = n + 1;

  /* where an item sits in step units: the step it arrives at, over one step,
     or an explicit window inside one */
  const span = o => o.at || [(o.from || 1) - 1, o.from || 1];
  const gone = o => (o.until || END) - 1;
  const vis = (v, o) => win(v, ...span(o)) * (1 - win(v, gone(o), gone(o) + 1));
  const put = (e, q) => { e.style.opacity = q >= 1 ? '' : q.toFixed(3); };

  /* ramp: fade in over the window; otherwise the item is whole from the
     start of its window and only leaves */
  const add = (e, o = {}, fn) => {
    if (!e.parentNode) s.appendChild(e);
    items.push(v => {
      const [a, b] = span(o);
      if (o.apart) assemble([{ el: e, apart: o.apart }], win(v, a, b));
      put(e, o.ramp === false ? (v > a ? 1 : 0) * (1 - win(v, gone(o), gone(o) + 1)) : vis(v, o));
      if (fn) fn(win(v, a, b), v);
    });
    return e;
  };

  const text = (parent, x, y, str, cls = 'lab', anchor = 'start') => dim.text(parent, x, y, str, cls, { 'text-anchor': anchor });

  /* a part: a drawn outline with its name on the face; hot is the one that
     changed, ghost is what is absent or refused */
  const part = (x, y, w, h, title, sub, o = {}) => {
    const g = el('g', { class: `part${o.hot ? ' hot' : ''}${o.ghost ? ' ghost' : ''}` }, s);
    el('rect', { x, y, width: w, height: h, class: 'part-box' }, g);
    const cx = x + w / 2;
    if (sub) {
      text(g, cx, y + h / 2 - 3, title, 'lab', 'middle');
      text(g, cx, y + h / 2 + 15, sub, 'lab lab-2', 'middle');
    } else text(g, cx, y + h / 2 + 5, title, 'lab', 'middle');
    return add(g, o);
  };

  /* a zone: a centerline outline around what belongs together */
  const zone = (x, y, w, h, title, o = {}) => {
    const g = el('g', { class: 'zone' }, s);
    el('rect', { x, y, width: w, height: h, class: 'zone-box' }, g);
    if (title) text(g, x + 12, y + 20, title, 'view-title');
    return add(g, o);
  };

  /* a flow along points, arrowhead on the last, optionally with a packet
     that travels it as the line draws */
  const flow = (pts, o = {}) => {
    const g = el('g', { class: 'flow' }, s);
    const line = el('path', { d: 'M' + pts.map(p => p.join(',')).join('L'), class: o.faint ? 'wire faint' : 'wire', pathLength: 1 }, g);
    const [a, b] = pts.slice(-2);
    const t = Math.atan2(b[1] - a[1], b[0] - a[0]), c = Math.cos(t), sn = Math.sin(t);
    const head = el('path', { d: `M${b[0]},${b[1]}L${(b[0] - 8 * c - 3.2 * sn).toFixed(1)},${(b[1] - 8 * sn + 3.2 * c).toFixed(1)}L${(b[0] - 8 * c + 3.2 * sn).toFixed(1)},${(b[1] - 8 * sn - 3.2 * c).toFixed(1)}Z`, class: 'arrow' }, g);
    let pk = null;
    if (o.packet) {
      pk = el('g', { class: 'packet' }, g);
      const w = Math.max(24, o.packet.length * 8 + 14);
      el('rect', { x: -w / 2, y: -10, width: w, height: 20, class: 'packet-box' }, pk);
      text(pk, 0, 4.5, o.packet, 'packet-text', 'middle');
    }
    return add(g, { ramp: false, ...o }, p => {
      if (o.faint) { line.style.opacity = String(p); head.style.opacity = String(win(p, 0.7, 1)); } else {
        drawIn([line], win(p, 0, 0.85));
        head.style.opacity = String(win(p, 0.8, 1));
      }
      if (pk) travel(pk, line, win(p, 0.1, 1), { to: o.packetTo ?? 0.5 });
    });
  };

  /* a note on the sheet: a label with its paper halo */
  const note = (x, y, str, o = {}) => add(text(s, x, y, str, o.cls || 'lab', o.anchor || 'start'), o);

  const callout = (px, py, ex, ey, lab, o = {}) => add(dim.callout(s, px, py, ex, ey, lab, o), o);

  /* a hatched chip: a cut or a keep-out with its name */
  const chip = (x, y, w, h, str, o = {}) => {
    const g = el('g', {}, s);
    dim.hatch(sh, g, x, y, w, h);
    text(g, x + w / 2, y + h / 2 + 5, str, 'lab', 'middle');
    return add(g, o);
  };

  const table = (x, y, title, rows, o = {}) => {
    const g = el('g', {}, s);
    dim.table(g, x, y, title, rows, { widths: o.widths, rh: o.rh });
    return add(g, o);
  };

  const line = (x1, y1, x2, y2, cls, o = {}) => add(el('line', { x1, y1, x2, y2, class: cls }, s), o);

  const update = v => items.forEach(f => f(v));
  return { s, sh, el, text, part, zone, flow, note, callout, chip, table, line, add, update, win, motion, dim, iso };
}
