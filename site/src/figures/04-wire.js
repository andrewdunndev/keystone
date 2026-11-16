/* 04 wire: what crosses the network and what stays on the host. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Two enclosures, the disk host and keystone, with a gap between them. Four lines cross the gap: the signed advertisement comes to the host, X goes to the Worker, Y comes back, and the name, kid and address go to the Worker. Inside the host, K, C, e and the slot passphrase stay put, and s stays in the Worker.';
  const s = kit.svg(mount, 'What crosses the wire and what stays', alt);
  const f = sheet(s, kit, 1);
  f.zone(24, 40, 252, 466, 'disk host', { at: [0, 0.2] });
  f.zone(444, 40, 252, 466, 'keystone', { at: [0, 0.2] });
  const cross = [
    [110, 'signed adv', true],
    [170, 'X = C + e·G', false],
    [230, 'Y = s·X', true],
    [290, 'name, kid, address', false],
  ];
  cross.forEach(([y, lab, back], i) => {
    const a = 0.15 + i * 0.12;
    f.flow(back ? [[444, y], [276, y]] : [[276, y], [444, y]], { at: [a, a + 0.25] });
    f.note(360, y - 8, lab, { at: [a + 0.1, a + 0.3], anchor: 'middle' });
  });
  ['K = s·C', 'C', 'e', 'slot passphrase'].forEach((t, i) => f.part(44, 340 + i * 40, 212, 32, t, null, { at: [0.65 + i * 0.07, 0.8 + i * 0.07] }));
  f.part(464, 340, 212, 32, 'exchange key s', null, { at: [0.65, 0.8] });
  return { n: 1, update: f.update, alt: alt };
}
