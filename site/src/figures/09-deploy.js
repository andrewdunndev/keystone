/* 09 deploy: keyset deploy plans against the live Worker, stops on a REFUSE
   or without --apply, and otherwise uploads and checks. */
import { sheet } from './lib.js';

export default function (mount, kit) {
  const alt = 'keyset deploy in five stages: stdin, plan, gate, wrangler, check. The plan gives each set one verdict: ok, new, policy, revoked, REVOKED-LIVE, drift or REFUSE. The gate stops on any REFUSE with exit 1, and without --apply ends at the plan with exit 0. Otherwise wrangler uploads the new and policy secrets and check confirms each set\'s signed adv, its keys, a real rec, and a 404 for each null.';
  const s = kit.svg(mount, 'keyset deploy', alt);
  const f = sheet(s, kit, 3);
  const W = 112, H = 56, Y = 36, xs = [24, 164, 304, 444, 584];
  f.part(xs[0], Y, W, H, 'stdin', 'set | null', { from: 1 });
  f.part(xs[1], Y, W, H, 'plan', 'vs live', { from: 1 });
  f.part(xs[2], Y, W, H, 'gate', 'no REFUSE', { from: 2 });
  f.part(xs[3], Y, W, H, 'wrangler', 'new, policy', { from: 3 });
  f.part(xs[4], Y, W, H, 'check', 'adv · rec', { from: 3 });
  for (let i = 0; i < 4; i++) f.flow([[xs[i] + W, Y + H / 2], [xs[i + 1], Y + H / 2]], { from: i < 1 ? 1 : i < 2 ? 2 : 3 });
  f.table(24, 150, 'verdicts', [
    ['ok', 'live and unchanged'],
    ['new', 'absent, named by --new'],
    ['policy', 'allow or approvers differ'],
    ['revoked', 'null, answers 404'],
    ['REVOKED-LIVE', 'null, yet served'],
    ['drift', 'live, not in stdin'],
    ['REFUSE', '--url ≠ secret list, …'],
  ], { from: 1, widths: [124, 236] });
  f.zone(420, 150, 276, 120, 'stop', { from: 2, until: 3 });
  f.note(436, 204, 'any REFUSE: exit 1', { from: 2, until: 3 });
  f.note(436, 234, 'no --apply: exit 0, the plan', { from: 2, until: 3 });
  f.table(420, 150, 'checked', [
    ['adv', 'signed by the set\'s key'],
    ['keys', 'exactly the set\'s'],
    ['rec', 'a real exchange answers'],
    ['null', 'answers 404'],
  ], { from: 3, widths: [50, 226] });
  return { n: 3, update: f.update, alts: [
    'keyset deploy reads the key sets from stdin, one set or null per name, and the plan gives each entry a verdict against the live Worker: ok, new, policy, revoked, REVOKED-LIVE, drift or REFUSE.',
    'The gate stops on any REFUSE with exit 1; without --apply the run ends at the plan with exit 0.',
    alt,
  ] };
}
