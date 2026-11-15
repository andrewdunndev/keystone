/* 13 failure: keystone unreachable leaves a typed passphrase; a revoked
   set leaves a stolen disk locked. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Two rows. When keystone is unreachable or its quota is spent, the host boots, rec gets no answer, clevis fails and LUKS asks for the passphrase, with the data intact. When a disk is stolen and its set is revoked, rec gets 404, clevis fails and LUKS stays locked from then on.';
  const s = kit.svg(mount, 'When keystone does not answer', alt);
  const f = sheet(s, kit, 1);
  const W = 124, H = 56, xs = [24, 204, 384, 564];
  const row = (y, title, cells, a) => {
    f.note(24, y - 24, title, { at: [a, a + 0.12], cls: 'lab lab-2' });
    cells.forEach(([t, o], i) => f.part(xs[i], y, W, H, t, null, { at: [a + i * 0.1, a + i * 0.1 + 0.15], ...o }));
    for (let i = 0; i < 3; i++) f.flow([[xs[i] + W, y + H / 2], [xs[i + 1], y + H / 2]], { at: [a + i * 0.1 + 0.08, a + i * 0.1 + 0.25] });
    f.note(xs[0] + W + 28, y + H / 2 - 8, 'rec', { at: [a + 0.1, a + 0.25], anchor: 'middle' });
  };
  row(100, 'keystone unreachable, or the quota spent', [['host boots'], ['keystone down', { ghost: true }], ['clevis fails'], ['passphrase']], 0);
  row(320, 'disk stolen, set revoked', [['stolen disk'], ['keystone: 404'], ['clevis fails'], ['stays locked', { hot: true }]], 0.5);
  return { n: 1, update: f.update, alt: alt };
}
