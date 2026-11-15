/* 11 trust: who can read the key sets and who cannot. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'Inside the Cloudflare account, deploy rights, which any user or token with deploy access holds, and every Worker version both read the Worker secrets that hold the key sets. Outside it, the Cloudflare API lists only secret names and disk hosts hold only public keys, shown by dashed lines that read nothing.';
  const s = kit.svg(mount, 'Who can read the key sets', alt);
  const f = sheet(s, kit, 1);
  f.zone(24, 40, 440, 424, 'cloudflare account', { at: [0, 0.2] });
  f.part(44, 84, 196, 56, 'deploy rights', null, { at: [0.1, 0.3] });
  f.part(264, 84, 180, 56, 'worker versions', null, { at: [0.15, 0.35] });
  f.part(124, 236, 240, 60, 'key sets', 'TANG_KEY_<NAME>', { at: [0.2, 0.4], hot: true });
  f.flow([[142, 140], [142, 236]], { at: [0.35, 0.6] });
  f.flow([[354, 140], [354, 236]], { at: [0.4, 0.65] });
  f.note(152, 196, 'reads', { at: [0.55, 0.75] });
  f.note(364, 196, 'reads', { at: [0.6, 0.8] });
  f.part(520, 236, 176, 56, 'cloudflare API', null, { at: [0.5, 0.7] });
  f.flow([[520, 264], [364, 264]], { at: [0.65, 0.9], faint: true });
  f.note(436, 254, 'names only', { at: [0.8, 1], anchor: 'middle' });
  f.part(520, 380, 176, 60, 'disk hosts', 'public keys only', { at: [0.6, 0.8] });
  f.flow([[364, 286], [440, 286], [440, 410], [520, 410]], { at: [0.75, 1], faint: true });
  return { n: 1, update: f.update, alt: alt };
}
