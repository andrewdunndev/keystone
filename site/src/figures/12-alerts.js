/* 12 alerts: a new source mails one alert an hour; the rest are held for
   the digest. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'After a successful rec the Worker answers the disk host first. It then asks whether the source, a /24 or /48 network plus ASN and country, is new. A source seen before sends no mail. The first new source in an hour sends one alert through send_email; sources met meanwhile, or after a failed send, are held in KV, up to five an hour, and mailed by the hourly cron as one digest.';
  const s = kit.svg(mount, 'When keystone mails an alert', alt);
  const f = sheet(s, kit, 1);
  const H = 56, W = 168;
  f.part(24, 52, W, H, 'worker', 'rec succeeds', { at: [0, 0.15] });
  f.part(268, 52, W, H, 'new source?', '/24 or /48 + ASN', { at: [0.15, 0.3] });
  f.part(512, 52, W, H, 'send_email', null, { at: [0.35, 0.5] });
  f.part(24, 240, W, H, 'disk host', null, { at: [0.1, 0.25] });
  f.part(268, 240, W, H, 'seen: no mail', null, { at: [0.3, 0.45] });
  f.part(512, 240, W, H, 'kv: held, up to 5', null, { at: [0.55, 0.7] });
  f.part(512, 400, W, H, 'hourly cron: digest', null, { at: [0.75, 0.9] });
  f.flow([[24 + W, 80], [268, 80]], { at: [0.1, 0.25] });
  f.flow([[100, 108], [100, 240]], { at: [0.1, 0.25] });
  f.flow([[268 + W, 80], [512, 80]], { at: [0.3, 0.45] });
  f.note(474, 70, 'first', { at: [0.35, 0.5], anchor: 'middle' });
  f.flow([[326, 108], [326, 240]], { at: [0.3, 0.45] });
  f.flow([[420, 108], [416, 190], [560, 190], [560, 240]], { at: [0.5, 0.7] });
  f.note(488, 180, 'meanwhile', { at: [0.55, 0.7], anchor: 'middle' });
  f.flow([[640, 108], [640, 240]], { at: [0.55, 0.7] });
  f.note(630, 180, 'send fails', { at: [0.6, 0.75], anchor: 'end' });
  f.flow([[596, 296], [596, 400]], { at: [0.7, 0.85] });
  f.flow([[680, 428], [700, 428], [700, 80], [680, 80]], { at: [0.8, 1] });
  return { n: 1, update: f.update, alt: alt };
}
