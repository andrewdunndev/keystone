/* 08 rollback: a rollback across a revoke serves the set again. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Five Worker versions in a row: 1 deploy version 1, 2 deploy --new version 2, 3 revoke version 3, 4 rollback to version 2, 5 deploy --apply version 4. server-1 answers in versions 1 and 2, answers 404 in 3, answers again after the rollback to 2 though the secret list no longer holds it, which keyset deploy reports as REVOKED-LIVE, and answers 404 in version 4, which is built from the current secrets.';
  const s = kit.svg(mount, 'Rolling back across a revoke', alt);
  const f = sheet(s, kit, 1);
  const X = i => 64 + i * 120, W = 104;
  const at = i => [0.05 + i * 0.13, 0.25 + i * 0.13];
  f.note(24, 90, 'server-1 answers', { at: [0, 0.2], cls: 'lab lab-2' });
  f.note(24, 200, 'in the secret list', { at: [0, 0.2], cls: 'lab lab-2' });
  const served = [1, 1, 0, 1, 0], listed = [1, 1, 0, 0, 0];
  for (let i = 0; i < 5; i++) {
    f.add(f.dim.nb(s, X(i) + W / 2, 52, i + 1), { at: at(i) });
    if (served[i]) f.add(f.el('rect', { x: X(i), y: 102, width: W, height: 44, class: 'bar' }, s), { at: at(i) });
    else f.chip(X(i), 102, W, 44, '404', { at: at(i) });
    if (listed[i]) f.add(f.el('rect', { x: X(i), y: 212, width: W, height: 44, class: 'bar' }, s), { at: at(i) });
    else f.add(f.el('rect', { x: X(i), y: 212, width: W, height: 44, class: 'bar cold' }, s), { at: at(i) });
  }
  f.callout(X(3) + W / 2, 146, X(3) - 16, 178, 'REVOKED-LIVE', { at: [0.75, 0.95], anchor: 'end' });
  f.table(64, 320, 'versions', [
    ['1', 'deploy', 'version 1'],
    ['2', 'deploy --new', 'version 2'],
    ['3', 'revoke', 'version 3'],
    ['4', 'rollback', 'to version 2'],
    ['5', 'deploy --apply', 'version 4'],
  ], { at: [0.55, 0.95], widths: [40, 180, 180] });
  return { n: 1, update: f.update, alt: alt };
}
