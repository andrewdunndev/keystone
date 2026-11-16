/* lib: the drafting sheet from the folio kit, with the three figure
   helpers this site adds: a callout, a hatched chip and a table. */

export const sheet = (s, kit, n) => {
  const f = kit.sheet(s, n);
  const { el } = kit.iso;

  const callout = (px, py, ex, ey, lab, o = {}) => f.add(kit.dim.callout(s, px, py, ex, ey, lab, o), o);

  const chip = (x, y, w, h, str, o = {}) => {
    const g = el('g', {}, s);
    kit.dim.hatch(f.sh, g, x, y, w, h);
    f.text(g, x + w / 2, y + h / 2 + 5, str, 'lab', 'middle');
    return f.add(g, o);
  };

  const table = (x, y, title, rows, o = {}) => {
    const g = el('g', {}, s);
    kit.dim.table(g, x, y, title, rows, { widths: o.widths, rh: o.rh });
    return f.add(g, o);
  };

  return { ...f, callout, chip, table };
};
