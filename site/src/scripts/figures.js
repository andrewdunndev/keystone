/* figures: the driver. The page y picks each figure's step and a time tween
   plays it through update(s). Under reduced motion, in print and on a
   narrow screen nothing pins or plays: each step shows its finished still. */
import * as iso from '@dunn.dev/reference/folio/iso.js';
import * as dim from '@dunn.dev/reference/folio/dim.js';
import * as motion from '@dunn.dev/reference/folio/motion.js';
import * as inline from '@dunn.dev/reference/folio/inline.js';

const modules = import.meta.glob('../figures/[0-9]*.js');
const NS = 'http://www.w3.org/2000/svg';

/* an svg for a figure: 720x520, labelled by its title and final-state text */
let sid = 0;
function svg(mount, title, alt) {
  const s = document.createElementNS(NS, 'svg');
  const id = `fig${++sid}`;
  s.setAttribute('viewBox', '0 0 720 520');
  s.setAttribute('role', 'img');
  s.setAttribute('aria-labelledby', `${id}-t ${id}-d`);
  const t = document.createElementNS(NS, 'title'); t.id = `${id}-t`; t.textContent = title;
  const d = document.createElementNS(NS, 'desc'); d.id = `${id}-d`; d.textContent = alt;
  s.append(t, d);
  mount.replaceChildren(s);
  return s;
}
const kit = { iso, dim, motion, inline, svg };

const mqStill = matchMedia('print, (prefers-reduced-motion: reduce), (max-width: 860px)');
const still = () => mqStill.matches;
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

async function load(name, mount) {
  const load = modules[`../figures/${name}.js`];
  if (!load) throw new Error(`no figure ${name}`);
  return (await load()).default(mount, kit);
}

/* a figure that plays once when it comes into view */
async function once(host) {
  const mount = host.querySelector('.stage-inner');
  const fig = await load(host.dataset.fig, mount);
  const ms = fig.stepMs ? fig.stepMs.slice(1) : [];
  const tween = motion.slew(motion.STEP_MS, 0, k => ms[k - 1] ?? motion.STEP_MS);
  let seen = false;
  const frame = now => {
    tween.aim(still() ? fig.n : seen ? fig.n : 0, now);
    const live = tween.tick(now);
    fig.update(still() ? fig.n : tween.v);
    if (live) requestAnimationFrame(frame);
  };
  fig.update(still() ? fig.n : 0);
  mqStill.addEventListener('change', () => requestAnimationFrame(frame));
  new IntersectionObserver((es, io) => {
    if (!es.some(e => e.isIntersecting)) return;
    io.disconnect();
    seen = true;
    requestAnimationFrame(frame);
  }, { rootMargin: '0px 0px -20% 0px' }).observe(host);
}

/* a chapter: its steps are the [data-step] paragraphs, or the whole text */
async function chapter(el) {
  const mount = el.querySelector('.stage-inner');
  const fig = await load(el.dataset.fig, mount);
  const text = el.querySelector('.chapter-text');
  const marked = [...text.querySelectorAll('[data-step]')];
  const steps = marked.length ? marked : [text];
  if (steps.length !== fig.n) console.warn(`${el.dataset.fig}: ${fig.n} steps drawn, ${steps.length} in the text`);
  const svgEl = mount.querySelector('svg');
  const ids = [...svgEl.querySelectorAll('[id]')].map(e => e.id);
  const tween = motion.slew(motion.STEP_MS, 0, k => fig.stepMs?.[k] ?? motion.STEP_MS);
  const ch = { el, fig, steps, tween, stills: null, shown: null, seen: false };

  /* static: one finished still per step, cloned from the figure at that
     step's rest, ids suffixed so markers and hatches resolve */
  ch.build = () => {
    if (ch.stills) return;
    ch.stills = steps.map((st, k) => {
      fig.update(k + 1);
      let html = svgEl.outerHTML;
      ids.forEach(id => { html = html.replace(new RegExp(`(?<=["#\\s])${esc(id)}(?=["\\s)])`, 'g'), `${id}-s${k}`); });
      const box = document.createElement('div');
      box.innerHTML = html;
      const c = box.firstElementChild;
      const ttl = c.querySelector('title');
      if (steps.length > 1 && ttl) ttl.textContent += ` (step ${k + 1} of ${steps.length})`;
      const alt = fig.alts ? fig.alts[k] : fig.alt;
      if (alt) c.querySelector('desc').textContent = alt;
      const f = document.createElement('figure');
      f.className = 'still';
      const pan = document.createElement('div');
      pan.className = 'pan';
      pan.tabIndex = 0;
      pan.setAttribute('role', 'group');
      pan.setAttribute('aria-label', 'Figure, scrolls sideways');
      pan.appendChild(c);
      f.appendChild(pan);
      if (st === text) text.querySelector('h2').after(f); else st.before(f);
      return f;
    });
    el.classList.add('stills');
    fig.update(fig.n);
  };
  ch.drop = () => {
    if (!ch.stills) return;
    ch.stills.forEach(f => f.remove());
    ch.stills = null;
    ch.shown = null;
    el.classList.remove('stills');
  };
  return ch;
}

async function main() {
  document.querySelectorAll('figure.inline[data-kind]').forEach(f => inline.draw(f));
  document.querySelectorAll('.once[data-fig]').forEach(h => once(h).catch(e => console.warn(e)));
  const chapters = (await Promise.all([...document.querySelectorAll('.chapter[data-fig]')]
    .map(el => chapter(el).catch(e => { console.warn(e); return null; })))).filter(Boolean);
  if (!chapters.length) return;

  /* the step the page picks: a paragraph counts once its top is above 62%
     of the viewport, and the first rest holds once the chapter is in view */
  const target = ch => {
    const r = ch.el.getBoundingClientRect();
    if (r.top < innerHeight * 0.8) ch.seen = true;
    if (!ch.seen) return 0;
    let k = 1;
    ch.steps.forEach((st, i) => { if (i && st.getBoundingClientRect().top < innerHeight * 0.62) k = i + 1; });
    return k;
  };
  let queued = false;
  const frame = (now = performance.now()) => {
    queued = false;
    if (still()) return;
    let live = false;
    chapters.forEach(ch => {
      const r = ch.el.getBoundingClientRect();
      if (r.bottom < -200 || r.top > innerHeight + 200) { if (ch.tween.v === ch.tween.to) return; }
      ch.tween.aim(target(ch), now);
      if (ch.tween.tick(now)) live = true;
      if (ch.tween.v !== ch.shown) { ch.fig.update(ch.tween.v); ch.shown = ch.tween.v; }
    });
    if (live) queue();
  };
  const queue = () => { if (!queued) { queued = true; requestAnimationFrame(frame); } };
  const mode = () => {
    if (still()) chapters.forEach(ch => ch.build());
    else chapters.forEach(ch => { ch.drop(); ch.tween.snap(); ch.shown = null; });
    queue();
    if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
  };
  addEventListener('scroll', queue, { passive: true });
  addEventListener('resize', queue);
  mqStill.addEventListener('change', mode);
  mode();
  chapters.forEach(ch => { if (!still()) { ch.fig.update(0); ch.shown = 0; } });
  queue();
  /* a deep link to a step lands with the figure there, not played */
  if (!still() && location.hash) {
    addEventListener('load', () => {
      chapters.forEach(ch => { ch.seen = true; ch.tween.aim(target(ch), performance.now()); ch.tween.snap(); });
      queue();
    }, { once: true });
  }
}

main();
