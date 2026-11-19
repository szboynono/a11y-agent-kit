import { contrastRatio } from './pixels.js';

export const NONTEXT_PARTS = Object.freeze(['boundary', 'indicator', 'icon']);
export const NONTEXT_DEFAULT_MARGIN = 8;
export const NONTEXT_MAX_MARGIN = 32;
const PAIR_LIMIT = 16, SIDES = ['top', 'right', 'bottom', 'left'], UNIFORM_FRACTION = 0.9;

export const NONTEXT_SCOPE = 'Observations only, no verdict. Candidate colour pairs come from original viewport PNG pixels guided by computed border/outline/background and DOM geometry. Whether the pair is a necessary graphical object, and any inactive/essential/decorative exception, is the reviewer\'s judgement. Each emitted pair\'s contrastRequest is the existing `contrast` action that records it in the form the 1.4.11 evidence gate accepts.';

/** Runs in the page. Reads only; the element is found by selector and must still carry the observed node identity. */
export function collectNonTextFacts({ storeKey, selector, nodeId }) {
  const store = globalThis[storeKey], found = document.querySelectorAll(selector);
  if (found.length !== 1 || store.ids.get(found[0]) !== nodeId) return { changed: true };
  const el = found[0], style = getComputedStyle(el), r = el.getBoundingClientRect();
  const side = name => ({ width: Number.parseFloat(style[`border${name}Width`]), style: style[`border${name}Style`], color: style[`border${name}Color`] });
  let opacity = 1, path = null, imageOnPath = style.backgroundImage !== 'none', depth = 0;
  for (let n = el; n; n = n.parentElement) opacity *= Number.parseFloat(getComputedStyle(n).opacity);
  // The surface the element sits on: first ancestor with a non-transparent background colour, noting any image/gradient passed on the way.
  for (let n = el.parentElement; n && depth < 64; n = n.parentElement, depth++) {
    const s = getComputedStyle(n);
    if (s.backgroundImage !== 'none') imageOnPath = true;
    if (!/^rgba?\(.*,\s*0\)$|^transparent$/.test(s.backgroundColor)) { path = { tag: n.localName, color: s.backgroundColor }; break; }
  }
  const pseudo = which => { const s = getComputedStyle(el, which); return s.content !== 'none' && s.content !== 'normal'; };
  const label = el.matches('input[type=button],input[type=submit],input[type=reset]') ? el.value : el.matches('button,a,summary,[role]') ? el.innerText : '';
  const hit = r.width && r.height ? document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2) : null;
  // Painted colours of the element's own SVG shapes (computed style), so an icon colour sampled from pixels can be matched against what the icon paints.
  // A shape counts only if it is actually painted: not in a non-rendering container (defs, clipPath, mask, symbol, pattern, marker, gradients),
  // not display:none / visibility:hidden / fully transparent, and per paint not `none` or zero-opacity. Shapes that a <use> instances are not
  // resolved (the computed style of the original is not the instance's), so `indirect` marks that the colour list is unknown; `truncated` marks
  // that more svgs or shapes exist than were read. `translucent` is set when anything between the shape and the document root fades it:
  // opacity below 1 or a CSS filter on the shape, any ancestor (g, svg, wrapper, the element itself, the page), or fill-/stroke-opacity or an rgba paint below 1.
  const SHAPES = 'path,circle,ellipse,rect,polygon,polyline,line', NOT_RENDERED = 'defs,clipPath,mask,symbol,pattern,marker,linearGradient,radialGradient,filter,title,desc,metadata';
  const allSvgs = el.localName === 'svg' ? [el] : [...el.querySelectorAll('svg')], svgs = allSvgs.slice(0, 4);
  // A shape with no geometry (empty `d`, zero radius, zero-size rect) paints nothing whatever its computed fill, so it is not a painted colour.
  // A horizontal or vertical line has a zero-area box but is still painted, so only a box with neither width nor height counts as empty.
  const hasGeometry = shape => { try { const b = shape.getBBox(); return b.width > 0 || b.height > 0; } catch { return false; } };
  const allShapes = [];
  let scanned = 0, moreShapes = false;
  for (const svg of svgs) for (const shape of svg.querySelectorAll(SHAPES)) {
    if (shape.closest(NOT_RENDERED)) continue;
    if (allShapes.length >= 25 || scanned >= 512) { moreShapes = true; break; }
    scanned++;
    if (hasGeometry(shape)) allShapes.push(shape);
  }
  const shapes = allShapes.slice(0, 24);
  const fades = node => { for (let n = node, d = 0; n; n = n.parentElement, d++) { const a = getComputedStyle(n); if (d > 256 || Number.parseFloat(a.opacity) < 1 || (a.filter && a.filter !== 'none')) return true; } return false; };
  const glyph = { shapes: shapes.length, colors: [], nonSolid: false, translucent: fades(el), indirect: svgs.some(svg => svg.querySelector('use') !== null), truncated: allSvgs.length > svgs.length || allShapes.length > shapes.length || moreShapes, minStrokePx: null };
  // Painted stroke width in CSS px (not device px): the shape's stroke-width in user units times its user-space scale to the viewport (getScreenCTM),
  // so it does not include devicePixelRatio. Shapes drawn through <use> are measured from the referenced element, using the instance's scale.
  const strokeCss = (shape, scale) => { const s = getComputedStyle(shape); return s.stroke !== 'none' && Number.parseFloat(s.strokeWidth) > 0 && Number.parseFloat(s.strokeOpacity) > 0 ? Number.parseFloat(s.strokeWidth) * scale : null; };
  const noteStroke = px => { if (px !== null) glyph.minStrokePx = glyph.minStrokePx === null ? px : Math.min(glyph.minStrokePx, px); };
  const ctmScale = node => { const m = node.getScreenCTM?.(); return m ? Math.sqrt(Math.abs(m.a * m.d - m.b * m.c)) : 1; };
  const faded = new Map();
  for (const shape of shapes) {
    const s = getComputedStyle(shape);
    let shown = s.display !== 'none' && s.visibility !== 'hidden' && Number.parseFloat(s.opacity) > 0;
    for (let n = shape.parentElement; shown && n && n !== el.parentElement; n = n.parentElement) {
      const a = getComputedStyle(n);
      if (a.display === 'none' || Number.parseFloat(a.opacity) === 0) shown = false;
      if (n.localName === 'svg') break;
    }
    if (!shown) continue;
    const strokeOn = s.stroke !== 'none' && Number.parseFloat(s.strokeWidth) > 0 && Number.parseFloat(s.strokeOpacity) > 0, paints = [[s.fill, s.fillOpacity], ...(strokeOn ? [[s.stroke, s.strokeOpacity]] : [])];
    const parent = shape.parentElement;
    if (!faded.has(parent)) faded.set(parent, fades(parent));
    if (Number.parseFloat(s.opacity) < 1 || (s.filter && s.filter !== 'none') || faded.get(parent)) glyph.translucent = true;
    for (const [paint, paintOpacity] of paints) {
      if (paint === 'none' || Number.parseFloat(paintOpacity) === 0) continue;
      if (/^url\(/.test(paint) || !/^rgba?\(/.test(paint)) glyph.nonSolid = true;
      else { glyph.colors.push(paint); if (Number.parseFloat(paintOpacity) < 1 || /^rgba\(/.test(paint)) glyph.translucent = true; }
    }
    if (strokeOn) noteStroke(strokeCss(shape, ctmScale(shape)));
  }
  for (const use of svgs.flatMap(svg => [...svg.querySelectorAll('use')].slice(0, 8).map(u => [svg, u]))) {
    const [svg, u] = use, ref = (u.getAttribute('href') ?? u.getAttribute('xlink:href') ?? '').startsWith('#') ? document.getElementById((u.getAttribute('href') ?? u.getAttribute('xlink:href')).slice(1)) : null;
    if (!ref) continue;
    const vb = ref.viewBox?.baseVal, outer = svg.viewBox?.baseVal, rect = svg.getBoundingClientRect(), base = ctmScale(u);
    const fit = vb && vb.width > 0 && vb.height > 0 ? Math.min((outer?.width || rect.width) / vb.width, (outer?.height || rect.height) / vb.height) : 1;
    for (const shape of ref.matches(SHAPES) ? [ref] : [...ref.querySelectorAll(SHAPES)].slice(0, 24)) noteStroke(strokeCss(shape, base * fit));
  }
  glyph.colors = [...new Set(glyph.colors)].slice(0, 8);
  if (glyph.minStrokePx !== null) glyph.minStrokePx = Math.round(glyph.minStrokePx * 100) / 100;
  // Where the icon itself is (the SVGs' boxes) and where visible text is, so label text beside an icon is not sampled as icon strokes.
  const box = rect => ({ x: rect.x, y: rect.y, width: rect.width, height: rect.height }), iconRects = svgs.map(svg => box(svg.getBoundingClientRect())).filter(b => b.width > 0 && b.height > 0);
  const textRects = [], walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node && textRects.length < 48; node = walker.nextNode()) {
    if (!node.data.trim() || node.parentElement.closest('svg,script,style,noscript')) continue;
    const range = document.createRange();
    range.selectNodeContents(node);
    const rects = [...range.getClientRects()].map(box).filter(b => b.width > 0 && b.height > 0);
    if (!rects.length) continue;
    textRects.push(...rects);
  }
  // svg <text> (with its tspans) is not the icon: its boxes are excluded from the fallback's sampling too.
  for (const t of [...el.querySelectorAll('svg text')].slice(0, 16)) {
    const b = box(t.getBoundingClientRect());
    if (b.width > 0 && b.height > 0) textRects.push({ ...b, svgText: true });
  }
  store.many = [el];
  return { tag: el.localName, type: el.getAttribute('type'), rect: { x: r.x, y: r.y, width: r.width, height: r.height },
    viewport: { width: innerWidth, height: innerHeight },
    border: { top: side('Top'), right: side('Right'), bottom: side('Bottom'), left: side('Left') },
    outline: { style: style.outlineStyle, width: Number.parseFloat(style.outlineWidth), color: style.outlineColor, offset: Number.parseFloat(style.outlineOffset) },
    boxShadow: style.boxShadow, backgroundColor: style.backgroundColor, backgroundImage: style.backgroundImage,
    effectiveOpacity: opacity, surface: path, imageOnPath, appearance: style.appearance, borderRadius: style.borderTopLeftRadius,
    domDisabled: 'disabled' in el ? el.disabled : null, ariaDisabled: el.closest('[aria-disabled=true]') !== null, inert: el.closest('[inert]') !== null,
    focused: el === document.activeElement, focusVisible: el.matches(':focus-visible'), hasLabelText: (label || '').trim().length > 0,
    glyph, iconRects, textRects, hasRaster: el.matches('img,canvas,video,picture') || el.querySelector('img,canvas,video,picture') !== null,
    pseudoContent: pseudo('::before') || pseudo('::after'), covered: hit ? !(hit === el || el.contains(hit) || hit.contains(el)) : null };
}

// ---- pure pixel analysis ----
const hex = rgba => `#${rgba.slice(0, 3).map(v => v.toString(16).padStart(2, '0')).join('')}`;
const keyOf = rgba => rgba.join(',');
const round3 = value => Math.round(value * 1000) / 1000;

export function parseCssColor(value) {
  const m = /^rgba?\(\s*(\d+(?:\.\d+)?)[ ,]+(\d+(?:\.\d+)?)[ ,]+(\d+(?:\.\d+)?)(?:\s*[,/]\s*(\d*\.?\d+%?))?\s*\)$/.exec(value ?? '');
  if (!m) return null;
  const alpha = m[4] === undefined ? 1 : m[4].endsWith('%') ? Number.parseFloat(m[4]) / 100 : Number(m[4]);
  return { rgb: [Number(m[1]), Number(m[2]), Number(m[3])].map(Math.round), alpha };
}

const between = (a, b, c) => b.slice(0, 3).every((v, i) => v >= Math.min(a[i], c[i]) && v <= Math.max(a[i], c[i])) && keyOf(b) !== keyOf(a) && keyOf(b) !== keyOf(c);

class Cells {
  constructor() { this.pixels = []; }
  add(image, x, y) {
    if (x < 0 || y < 0 || x >= image.width || y >= image.height) return this;
    const at = (y * image.width + x) * 4;
    this.pixels.push({ x, y, rgba: [image.data[at], image.data[at + 1], image.data[at + 2], image.data[at + 3]] });
    return this;
  }
  /** Modal colour with the statistics that qualify it as a sample; `near` picks the representative pixel closest to a point. */
  mode(near) {
    const counts = new Map();
    for (const pixel of this.pixels) { const k = keyOf(pixel.rgba); (counts.get(k) ?? counts.set(k, []).get(k)).push(pixel); }
    if (!counts.size) return null;
    const [key, list] = [...counts].sort((a, b) => b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1))[0];
    const rgba = list[0].rgba, total = this.pixels.length;
    const rep = near ? list.reduce((best, p) => Math.hypot(p.x - near.x, p.y - near.y) < Math.hypot(best.x - near.x, best.y - near.y) ? p : best) : list[0];
    const maxChannelDelta = Math.max(...this.pixels.map(p => Math.max(...p.rgba.slice(0, 3).map((v, i) => Math.abs(v - rgba[i])))));
    return { key, rgba, x: rep.x, y: rep.y, count: list.length, total, distinct: counts.size, fraction: round3(list.length / total), maxChannelDelta };
  }
}

const stat = m => ({ fraction: m.fraction, distinct: m.distinct, maxChannelDelta: m.maxChannelDelta });
const side = (m, role) => ({ role, rgb: m.rgba.slice(0, 3), hex: hex(m.rgba), x: m.x, y: m.y });

function pairOf({ id, part, kind, component, adjacent, adjacentRole, sides, computed, thickness, basis, computedColor }) {
  if (component.rgba[3] !== 255 || adjacent.rgba[3] !== 255) return null;
  return { id, part, kind, ...(basis ? { basis } : {}), ...(sides ? { sides } : {}), ...(thickness ? { edgeThicknessPx: thickness } : {}),
    component: side(component, 'component'), adjacent: side(adjacent, adjacentRole),
    ratio: round3(contrastRatio(component.rgba.slice(0, 3), adjacent.rgba.slice(0, 3))),
    samples: { component: component.count, adjacent: adjacent.count },
    uniformity: { component: stat(component), adjacent: stat(adjacent) },
    ...(computed === undefined ? {} : { computedColorMatch: computed }), ...(computedColor ? { computedColor } : {}),
    contrastRequest: { action: 'contrast', foreground: { x: component.x, y: component.y }, background: { x: adjacent.x, y: adjacent.y } } };
}

/** Pixel at inward `depth` (negative = outside) of an edge, at positions `along` the middle half of that edge. */
function edgeCells(image, rect, name, depths, count = 9) {
  const x0 = Math.round(rect.x), y0 = Math.round(rect.y), x1 = Math.round(rect.x + rect.width), y1 = Math.round(rect.y + rect.height);
  const horizontal = name === 'top' || name === 'bottom', from = horizontal ? rect.x : rect.y, length = horizontal ? rect.width : rect.height;
  const alongs = [...new Set(Array.from({ length: count }, (_, i) => Math.floor(from + length * (0.25 + 0.5 * i / (count - 1)))))];
  const cells = new Cells();
  for (const depth of depths) for (const a of alongs) {
    if (name === 'top') cells.add(image, a, y0 + depth);
    else if (name === 'bottom') cells.add(image, a, y1 - 1 - depth);
    else if (name === 'left') cells.add(image, x0 + depth, a);
    else cells.add(image, x1 - 1 - depth, a);
  }
  return { cells, near: horizontal ? { x: Math.floor(from + length / 2), y: name === 'top' ? y0 : y1 - 1 } : { x: name === 'left' ? x0 : x1 - 1, y: Math.floor(from + length / 2) }, alongs };
}
const modeAt = (image, rect, name, depths) => { const e = edgeCells(image, rect, name, depths); const m = e.cells.mode(e.near); return m ? { ...m, near: e.near } : null; };
const range = (a, b) => Array.from({ length: Math.max(0, b - a + 1) }, (_, i) => a + i);

/** Sides that produced the same colour pair are one pair; its statistics are the pooled counts and the worst uniformity. */
function merge(raw, push) {
  const groups = new Map();
  for (const item of raw) {
    const k = [item.kind, item.component.key, item.adjacent.key, item.adjacentRole].join('|');
    (groups.get(k) ?? groups.set(k, []).get(k)).push(item);
  }
  const sum = (items, pick, field) => items.reduce((total, item) => total + pick(item)[field], 0);
  for (const items of groups.values()) {
    const fold = pick => ({ ...pick(items[0]), count: sum(items, pick, 'count'), total: sum(items, pick, 'total'),
      fraction: Math.min(...items.map(item => pick(item).fraction)), distinct: Math.max(...items.map(item => pick(item).distinct)),
      maxChannelDelta: Math.max(...items.map(item => pick(item).maxChannelDelta)) });
    const { kind, adjacentRole, computed, thickness } = items[0];
    push({ kind, adjacentRole, computed, thickness, sides: items.map(item => item.side), component: fold(item => item.component), adjacent: fold(item => item.adjacent) });
  }
}

function boundary(image, facts, ctx) {
  const raw = [];
  const drawn = Object.fromEntries(SIDES.map(name => [name, facts.border[name].width > 0 && !['none', 'hidden'].includes(facts.border[name].style) ? parseCssColor(facts.border[name].color) : null]));
  for (const name of SIDES) {
    const inside = Math.max(1, Math.min(ctx.margin, Math.floor((name === 'top' || name === 'bottom' ? facts.rect.height : facts.rect.width) / 2) - 1));
    const out = modeAt(image, facts.rect, name, [-1, -2]);
    if (!out) continue;
    const at = depth => modeAt(image, facts.rect, name, [depth]);
    let start = -1;
    for (let d = 0; d <= Math.min(4, inside); d++) if (at(d)?.key !== out.key) { start = d; break; }
    if (start < 0) {
      const flat = modeAt(image, facts.rect, name, [0, 1]);
      if (!flat) continue;
      raw.push({ side: name, kind: 'no-visible-edge', component: flat, adjacent: out, adjacentRole: 'outside' });
      ctx.noEdge.add(name);
      continue;
    }
    let component = at(start), end = start + 1;
    while (end <= inside && at(end)?.key === component.key) end++;
    const thickness = end - start, next = end <= inside ? modeAt(image, facts.rect, name, [end, end + 1]) : null;
    // A one-pixel run strictly between the outside colour and the next colour, not the computed border colour, is anti-aliasing of that boundary.
    const computed = drawn[name];
    if (thickness === 1 && next && between(out.rgba, component.rgba, next.rgba) && !(computed && computed.alpha === 1 && keyOf([...computed.rgb, 255]) === component.key)) {
      ctx.blended.add(name);
      raw.push({ side: name, kind: 'fill-vs-outside', component: next, adjacent: out, adjacentRole: 'outside' });
      continue;
    }
    const kind = thickness >= 4 ? 'fill-vs-outside' : 'border-vs-outside';
    const match = kind === 'border-vs-outside' && computed && computed.alpha === 1 ? keyOf([...computed.rgb, 255]) === component.key : undefined;
    raw.push({ side: name, kind, component, adjacent: out, adjacentRole: 'outside', computed: match, thickness });
    if (kind === 'border-vs-outside' && next) raw.push({ side: name, kind: 'border-vs-inside', component, adjacent: next, adjacentRole: 'inside', computed: match, thickness });
  }
  merge(raw, ctx.pushPair('boundary'));
}

function ring(image, facts, ctx, kind, band, color) {
  const raw = [];
  for (const name of SIDES) {
    const depth = s => -(s + 1);
    const component = modeAt(image, facts.rect, name, range(band[0], band[1]).map(depth));
    const outside = modeAt(image, facts.rect, name, [depth(band[1] + 1), depth(band[1] + 2)]);
    const inner = modeAt(image, facts.rect, name, [depth(band[0] - 1), depth(band[0] - 2)]);
    if (!component) continue;
    const match = color && color.alpha === 1 ? keyOf([...color.rgb, 255]) === component.key : undefined;
    if (outside) raw.push({ side: name, kind: `${kind}-vs-outside`, component, adjacent: outside, adjacentRole: 'outside', computed: match });
    if (inner) raw.push({ side: name, kind: `${kind}-vs-inside`, component, adjacent: inner, adjacentRole: 'inside', computed: match });
  }
  merge(raw, ctx.pushPair('indicator'));
}

const inRects = (rects, x, y) => rects.some(r => x + 0.5 >= r.x && x + 0.5 < r.x + r.width && y + 0.5 >= r.y && y + 0.5 < r.y + r.height);

/** Colour clusters of a pixel region. A small cluster lying between two other colours is anti-aliasing, not a component colour. */
function clusters(image, area, includeBase = false, skip = []) {
  const counts = new Map(), stride = Math.max(1, Math.ceil(Math.sqrt(((area.x1 - area.x0) * (area.y1 - area.y0)) / 40000)));
  const centre = { x: (area.x0 + area.x1) / 2, y: (area.y0 + area.y1) / 2 };
  let total = 0;
  for (let y = area.y0; y < area.y1; y += stride) for (let x = area.x0; x < area.x1; x += stride) {
    if (x < 0 || y < 0 || x >= image.width || y >= image.height || inRects(skip, x, y)) continue;
    const at = (y * image.width + x) * 4, rgba = [image.data[at], image.data[at + 1], image.data[at + 2], image.data[at + 3]], key = keyOf(rgba);
    const c = counts.get(key) ?? counts.set(key, { key, rgba, count: 0, x, y, d: Infinity }).get(key);
    c.count++; total++;
    const d = Math.hypot(x - centre.x, y - centre.y);
    if (d < c.d) { c.d = d; c.x = x; c.y = y; }
  }
  const list = [...counts.values()].sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : 1));
  if (!total) return { empty: true };
  const base = list[0], major = [...list.slice(0, 8).map(c => c.rgba), base.rgba];
  const isBlend = c => major.some((p, i) => major.some((q, j) => i < j && between(p, c.rgba, q)));
  const candidates = list.filter(c => (includeBase || c.key !== base.key) && c.count >= Math.max(3, Math.ceil(total * 0.01)));
  // Colour bounds alone cannot distinguish a solid mid-tone from anti-aliasing.
  const flat = c => ({ ...c, total, fraction: 1, distinct: 1, maxChannelDelta: 0 });
  return { base: flat(list[0]), components: candidates.slice(0, 6).map(flat), blends: candidates.filter(isBlend).length, distinct: list.length, all: list.slice(0, 256).map(flat) };
}

const CORE_BAND = 8;
const channelDelta = (a, b) => Math.max(...[0, 1, 2].map(i => Math.abs(a[i] - b[i])));

/**
 * Thin anti-aliased strokes (1-2 px) have no uniform neighbour colour: every pixel next to the stroke core is a different blend, and the
 * core itself may be several near-identical colours. The core is still an observed colour when everything touching it is the surround or a
 * blend between the surround and the core. Returns null when any neighbour is some other colour (the adjacency is then genuinely ambiguous).
 * `members` are the core-band colour keys; `core` is the representative (most contrasting) one.
 */
function coreAgainstSurround(image, area, members, core, surround, skip = []) {
  const stride = Math.max(1, Math.ceil(Math.sqrt(((area.x1 - area.x0) * (area.y1 - area.y0)) / 40000)));
  const at = (x, y) => [...image.data.subarray((y * image.width + x) * 4, (y * image.width + x) * 4 + 4)];
  // Ring 1 = touching pixels; ring 2 = one pixel further out, used only when no touching pixel is exactly the surround (a 2 px core fades through one blend row).
  for (const reach of [1, 2]) {
    const exact = new Cells(), seen = new Set();
    let total = 0, toward = 0, maxChannelDelta = 0;
    for (let y = area.y0; y < area.y1; y += stride) for (let x = area.x0; x < area.x1; x += stride) {
      if (x < 0 || y < 0 || x >= image.width || y >= image.height || inRects(skip, x, y) || !members.has(keyOf(at(x, y)))) continue;
      for (const [dx, dy] of [[-reach, 0], [reach, 0], [0, -reach], [0, reach]]) {
        const nx = x + dx, ny = y + dy;
        if (nx < 0 || ny < 0 || nx >= image.width || ny >= image.height) continue;
        const rgba = at(nx, ny), key = keyOf(rgba);
        if (members.has(key)) continue;
        total++; seen.add(key);
        maxChannelDelta = Math.max(maxChannelDelta, channelDelta(rgba, surround.rgba));
        if (key === surround.key) { toward++; exact.add(image, nx, ny); } else if (between(surround.rgba, rgba, core.rgba)) toward++;
      }
    }
    if (!total || toward / total < UNIFORM_FRACTION) return null;
    if (!exact.pixels.length) continue;
    const m = exact.mode(core);
    return { ...m, total, fraction: round3(m.count / total), distinct: seen.size, maxChannelDelta };
  }
  return null;
}

const hexOf = rgb => `#${rgb.map(v => v.toString(16).padStart(2, '0')).join('')}`;

/**
 * Stroke-core pairs for the colours the strict, touching-pixel rule could not pair, most contrasting against the surround first.
 * Deliberately narrow: a pair is returned only when the sampled core colour equals a solid colour that a painted shape of the icon actually paints
 * (so it is the icon's own full-coverage paint), and nothing fades the icon (opacity, fill-/stroke-opacity, CSS filter on the shape or any ancestor).
 * Otherwise no pair is returned and a warning says the icon needs manual checking: faded icons, icons whose painted colours cannot be listed
 * (<use>, CSS mask, background shapes, more shapes than were read), and sampled colours that no shape paints (strokes under one CSS px that never
 * reach full coverage, blends, anything else). The refusal warnings are only for an icon with no pair at all: where the original path already returned
 * a pair, the fallback adds nothing and no refusal warning is given, so that path's warnings stay what they were. Only the icon's own pixels are used: the SVG boxes when the element has any (else the element box), minus
 * visible text boxes. Returns the number of pairs added.
 */
function antialiasedCorePairs(image, facts, ctx, area, taken) {
  const glyph = facts.glyph;
  if (facts.hasRaster || facts.imageOnPath || facts.backgroundImage !== 'none' || glyph?.nonSolid || ['img', 'canvas', 'video', 'picture'].includes(facts.tag)) return 0;
  const textRects = facts.textRects ?? [], icons = facts.iconRects ?? [];
  if (icons.length) {
    const x0 = Math.min(...icons.map(r => r.x)), y0 = Math.min(...icons.map(r => r.y)), x1 = Math.max(...icons.map(r => r.x + r.width)), y1 = Math.max(...icons.map(r => r.y + r.height));
    area = { x0: Math.max(area.x0, Math.floor(x0)), y0: Math.max(area.y0, Math.floor(y0)), x1: Math.min(area.x1, Math.ceil(x1)), y1: Math.min(area.y1, Math.ceil(y1)) };
  }
  if (!(area.x1 > area.x0 && area.y1 > area.y0)) return 0;
  const found = clusters(image, area, true, textRects);
  if (found.empty) return 0;
  const surround = found.base;
  const ranked = found.all.filter(c => c.key !== surround.key && c.rgba[3] === 255 && !taken.has(c.key))
    .map(c => ({ c, ratio: contrastRatio(c.rgba.slice(0, 3), surround.rgba.slice(0, 3)) })).filter(r => r.c.count >= 2 && r.ratio > 1.05)
    .sort((a, b) => b.ratio - a.ratio || b.c.count - a.c.count);
  const textOnly = textRects.some(r => r.svgText);
  if (!ranked.length && !textOnly) return 0;
  // A refusal is reported only when nothing else was returned for the icon; next to original-path pairs it is silent.
  const refuse = (code, message, faded = false) => {
    if (ctx.pairCount()) return 0;
    if (code) ctx.warn(code, message);
    ctx.warn('icon_colour_unverified', 'No stroke-core pair is reported for this icon: its colour could not be tied to a painted solid colour. Check it manually (view the PNG at the stroke, compare with the authored colour); report it as needs-review or untested, do not invent a ratio.');
    ctx.faded = faded;
    return 0;
  };
  // Nothing left once svg <text> is excluded (an icon drawn only as text): refused, not silently empty.
  if (!ranked.length) return refuse(null, null);
  if (glyph?.translucent || facts.effectiveOpacity < 1) return refuse(null, null, true);
  const known = glyph?.colors.map(parseCssColor).filter(p => p && p.alpha === 1) ?? [], knownKeys = new Set(known.map(p => keyOf([...p.rgb, 255])));
  if (!glyph || glyph.indirect || glyph.truncated || !glyph.shapes || !known.length) {
    return refuse('painted_colour_unknown', 'The icon\'s painted colours cannot be listed (a <use> or CSS-mask/background icon, no painted SVG shape, or more shapes than were read), so a sampled stroke colour cannot be matched to a painted one.');
  }
  const used = new Set(), candidates = [];
  let unmatched = 0;
  for (const { c } of ranked.slice(0, 24)) {
    if (used.has(c.key)) continue;
    const band = found.all.filter(o => !used.has(o.key) && !taken.has(o.key) && o.key !== surround.key && o.rgba[3] === 255 && channelDelta(o.rgba, c.rgba) <= CORE_BAND);
    const mass = band.reduce((sum, o) => sum + o.count, 0);
    if (mass < 3) continue;
    const members = new Set(band.map(o => o.key)), adjacent = coreAgainstSurround(image, area, members, c, surround, textRects);
    if (!adjacent) continue;
    for (const key of members) used.add(key);
    if (!knownKeys.has(c.key)) { unmatched++; continue; }
    const component = { ...c, total: mass, fraction: round3(c.count / mass), distinct: band.length, maxChannelDelta: Math.max(...band.map(o => channelDelta(o.rgba, c.rgba))) };
    candidates.push({ kind: 'icon-vs-surround', basis: 'antialiased-core', component, adjacent, adjacentRole: 'surround', computed: true, computedColor: known.map(p => hexOf(p.rgb)).join(' ') });
  }
  // Unmatched colours next to returned pairs, or next to old-path pairs, are dropped silently (blends and anti-aliased edges are common there);
  // an icon with no pair at all is the case that needs a manual check.
  if (!candidates.length && !ctx.pairCount()) {
    const reason = unmatched ? 'its sampled colour matches no solid colour that the icon paints (a stroke thinner than one CSS px never reaches full coverage, or a blend with something else)'
      : 'no sampled colour has a single surround next to it (it touches other colours rather than the surrounding colour, or is too small), so none can be paired';
    ctx.warn('icon_colour_unverified', `No stroke-core pair is reported for this icon: ${reason}. Check it manually (view the PNG at the stroke, compare with the authored colour); report it as needs-review or untested, do not invent a ratio.`);
  }
  const chosen = candidates.slice(0, 3);
  for (const item of chosen) ctx.pushPair('icon')(item);
  return chosen.length;
}

function clusterPairs(image, facts, ctx, part, area) {
  const found = clusters(image, area, part === 'icon');
  if (found.empty) return;
  if (found.distinct > 24) ctx.warn('many_colours', 'The region has more than 24 distinct colours; only the 6 largest candidate clusters are considered.');
  if (found.blends) ctx.warn('ambiguous_cluster_colours', 'Intermediate colours may be solid regions or anti-aliasing; they are retained as candidates, without deciding which.');
  let ambiguous = false;
  const taken = new Set();
  for (const c of found.components) {
    let adjacent = found.base;
    if (part === 'icon') {
      // Only pixels touching this cluster can establish its adjacent colour.
      // The outer box ring may belong to the page behind an enclosing button.
      const cells = new Cells();
      const stride = Math.max(1, Math.ceil(Math.sqrt(((area.x1 - area.x0) * (area.y1 - area.y0)) / 40000)));
      for (let y = area.y0; y < area.y1; y += stride) for (let x = area.x0; x < area.x1; x += stride) {
        if (x < 0 || y < 0 || x >= image.width || y >= image.height) continue;
        const at = (y * image.width + x) * 4;
        if (keyOf([...image.data.subarray(at, at + 4)]) !== c.key) continue;
        for (const [dx, dy] of [[-1, 0], [1, 0], [0, -1], [0, 1]]) {
          const nx = x + dx, ny = y + dy;
          if (nx < 0 || ny < 0 || nx >= image.width || ny >= image.height) continue;
          const n = (ny * image.width + nx) * 4;
          if (keyOf([...image.data.subarray(n, n + 4)]) !== c.key) cells.add(image, nx, ny);
        }
      }
      adjacent = cells.mode();
      if (!adjacent || adjacent.fraction < UNIFORM_FRACTION) {
        ctx.warn('ambiguous_icon_adjacency', 'A candidate icon colour touches multiple colours (typically anti-aliased edges) or has no sampled neighbour, so no uniform local adjacent colour exists. Where its edge only fades toward the dominant surround and its colour equals a solid colour that the icon paints, a pair marked basis "antialiased-core" is given instead; otherwise no pair is emitted for it (see icon_colour_unverified, painted_colour_unknown, transparency).');
        ambiguous = true;
        continue;
      }
    }
    taken.add(c.key);
    ctx.pushPair(part)({ kind: part === 'icon' ? 'icon-vs-surround' : 'cluster-vs-dominant', component: c, adjacent, adjacentRole: part === 'icon' ? 'local-neighbour' : 'dominant' });
  }
  // Thin strokes can be too sparse to pass the cluster-size filter at all, so also try them when no cluster qualified.
  const core = part === 'icon' && (ambiguous || !found.components.length) ? antialiasedCorePairs(image, facts, ctx, area, taken) : 0;
  if (!found.components.length && !core) ctx.note(`${part}: one dominant colour in the region; no second colour to pair.`);
}

function parseShadows(text) {
  if (!text || text === 'none') return { rings: [], other: 0 };
  const parts = []; let depth = 0, cur = '';
  for (const ch of text) { if (ch === '(') depth++; if (ch === ')') depth--; if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch; }
  parts.push(cur);
  const rings = []; let other = 0;
  for (const part of parts.slice(0, 6)) {
    const color = /rgba?\([^)]*\)/.exec(part)?.[0], nums = (part.replace(/rgba?\([^)]*\)/, '').match(/-?\d+(?:\.\d+)?px/g) ?? []).map(Number.parseFloat);
    if (color && !/inset/.test(part) && nums.length >= 4 && nums[0] === 0 && nums[1] === 0 && nums[2] === 0 && nums[3] > 0) rings.push({ color: parseCssColor(color), spread: Math.round(nums[3]) });
    else other++;
  }
  return { rings, other };
}

/**
 * Candidate component/adjacent colour pairs from one original viewport PNG. `ax` is the compact AX node of the element (or null).
 * Never returns a verdict: pairs, uniformity, and warnings for the reviewer.
 */
export function analyzeNonText({ image, facts, part, margin = NONTEXT_DEFAULT_MARGIN, ax = null }) {
  const warnings = new Map(), notes = [], pairs = [], ctx = { margin, blended: new Set(), noEdge: new Set() };
  ctx.warn = (code, message) => { if (!warnings.has(code)) warnings.set(code, { code, message }); };
  ctx.note = text => notes.push(text);
  ctx.pairCount = () => pairs.length;
  const parts = part ? [part] : facts.tag === 'svg' || ['img', 'canvas', 'video'].includes(facts.tag) ? ['icon']
    : facts.tag === 'input' && ['checkbox', 'radio', 'range'].includes(facts.type) ? ['boundary', 'indicator'] : ['boundary'];
  ctx.pushPair = which => item => {
    if (pairs.length >= PAIR_LIMIT) { ctx.warn('pairs_truncated', `Only the first ${PAIR_LIMIT} candidate pairs are listed.`); return; }
    const pair = pairOf({ id: `p${pairs.length + 1}`, part: which, ...item });
    if (!pair) { ctx.warn('transparent_pixels', 'A sampled screenshot pixel was not opaque; no pair is reported for it.'); return; }
    const r = facts.rect, x = pair.component.x + 0.5, y = pair.component.y + 0.5;
    if (!(x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height)) {
      ctx.warn('foreground_outside_target', 'An external indicator or edge sample was omitted because its pixel centre lies outside the target box; the unchanged contrast evidence gate cannot bind it to this target.');
      return;
    }
    pairs.push(pair);
  };
  const rect = facts.rect;
  if (!(rect.width > 0 && rect.height > 0)) ctx.warn('zero_size', 'The element has no rendered box.');
  else if (rect.x < 0 || rect.y < 0 || rect.x + rect.width > image.width || rect.y + rect.height > image.height) ctx.warn('partially_offscreen', 'Part of the element lies outside the viewport PNG; only the visible edges can be sampled. Use scroll and measure again.');
  const run = () => {
    if (parts.includes('boundary')) boundary(image, facts, ctx);
    if (parts.includes('indicator')) {
      if (facts.outline.style !== 'none' && facts.outline.width > 0) {
        const lo = Math.round(facts.outline.offset), wd = Math.max(1, Math.round(facts.outline.width));
        ring(image, facts, ctx, 'outline', [lo, lo + wd - 1], parseCssColor(facts.outline.color));
      }
      const shadows = parseShadows(facts.boxShadow);
      for (const shadow of shadows.rings.slice(0, 3)) ring(image, facts, ctx, 'shadow-ring', [0, shadow.spread - 1], shadow.color);
      if (shadows.other) ctx.warn('box_shadow_not_decomposed', `${shadows.other} box-shadow layer(s) with blur, offset or inset were not decomposed; sample the region to see them.`);
      const inset = Math.max(1, Math.round(0.2 * Math.min(rect.width, rect.height)));
      clusterPairs(image, facts, ctx, 'indicator', { x0: Math.round(rect.x) + inset, y0: Math.round(rect.y) + inset, x1: Math.round(rect.x + rect.width) - inset, y1: Math.round(rect.y + rect.height) - inset });
    }
    if (parts.includes('icon')) clusterPairs(image, facts, ctx, 'icon', { x0: Math.floor(rect.x), y0: Math.floor(rect.y), x1: Math.ceil(rect.x + rect.width), y1: Math.ceil(rect.y + rect.height) });
  };
  if (!warnings.has('zero_size')) run();

  const inactive = ax?.states?.disabled === true || facts.domDisabled === true || facts.ariaDisabled || facts.inert;
  if (inactive) ctx.warn('inactive_control', `Disabled/inactive per ${[ax?.states?.disabled === true && 'the accessibility tree', facts.domDisabled === true && 'DOM disabled', facts.ariaDisabled && 'aria-disabled', facts.inert && 'inert'].filter(Boolean).join(', ')}; WCAG 1.4.11 exempts inactive user interface components.`);
  if (facts.glyph?.nonSolid) ctx.warn('icon_paint_not_solid', 'The SVG icon is painted with a gradient, pattern or non-colour paint; a single component colour does not exist, so no anti-aliased-core estimate is made for it.');
  if (facts.imageOnPath || facts.backgroundImage !== 'none') ctx.warn('gradient_or_image_background', 'The element or the surface behind it has a background image or gradient; one flat adjacent colour may not exist. Check the nonuniform pairs and view the PNG.');
  if (['img', 'canvas', 'video', 'picture'].includes(facts.tag)) ctx.warn('raster_content', 'The element is raster content; colour clusters are not a component colour model.');
  const alphas = [facts.backgroundColor, ...Object.values(facts.border).filter(b => b.width > 0 && !['none', 'hidden'].includes(b.style)).map(b => b.color), ...(facts.outline.width > 0 && facts.outline.style !== 'none' ? [facts.outline.color] : [])]
    .map(parseCssColor).filter(c => c && c.alpha < 1 && c.alpha > 0);
  if (alphas.length || facts.effectiveOpacity < 1) ctx.warn('transparency', `Semi-transparent colour or opacity ${round3(facts.effectiveOpacity)} on the element or an ancestor; the computed colour is not the rendered colour. Only the sampled PNG pixels are rendered values.`);
  // A fade (opacity, CSS filter, fill-/stroke-opacity or rgba paint on the icon or an ancestor) is the reason the icon fallback refused; the original path is not touched.
  if (ctx.faded) ctx.warn('transparency', 'The icon is faded by opacity below 1, a CSS filter, or a fill-/stroke-opacity or rgba paint on a shape or an ancestor; the computed colour is not the rendered colour, so no colour is tied to it. Only the sampled PNG pixels are rendered values.');
  if (pairs.some(p => Math.min(p.uniformity.component.fraction, p.uniformity.adjacent.fraction) < UNIFORM_FRACTION)) ctx.warn('nonuniform_region', `At least one sampled region is below ${UNIFORM_FRACTION * 100}% a single colour (see uniformity); the sample may straddle another edge, a gradient or text.`);
  if (ctx.blended.size) ctx.warn('antialias_only_edge', `The ${[...ctx.blended].join(', ')} edge(s) showed a single-pixel colour between the outside and the interior, which is anti-aliasing of the boundary; it was skipped and the interior fill is paired with the outside.`);
  if (pairs.some(p => p.computedColorMatch === false)) ctx.warn('computed_colour_mismatch', 'The sampled colour differs from the computed border/outline/SVG paint colour (blending, an overlay, text in the same box, or a theme-drawn control).');
  // Painted stroke width in CSS px (the SVG's user-space scale to the viewport, before devicePixelRatio): anti-aliasing then keeps the stroke from full coverage,
  // so any sampled pixel ratio is lighter than the authored colour. Warning only; pairs and their order are unaffected.
  if (parts.includes('icon') && facts.glyph?.minStrokePx != null && facts.glyph.minStrokePx < 1) ctx.warn('subpixel_stroke', `A painted SVG stroke is ${facts.glyph.minStrokePx} CSS px wide, under one pixel, so it never reaches full coverage: sampled pixels are lighter than the authored colour and their ratios understate it. Do not cite a pixel ratio alone; check the authored colour and view the PNG at the stroke.`);
  if (ctx.noEdge.size) ctx.warn('no_visible_edge', `No colour change was found at the ${[...ctx.noEdge].join(', ')} edge(s): the component edge there matches its surroundings (ratio 1).`);
  if (facts.hasLabelText && parts.includes('boundary')) ctx.warn('boundary_may_not_identify_component', 'The control has its own visible text label; its visual boundary may not be needed to identify it (WCAG 1.4.11 applies to graphics required to identify a component).');
  if (facts.covered) ctx.warn('covered_by_other_element', 'The element centre is covered by an unrelated element; sampled pixels may belong to that element.');
  if (facts.pseudoContent) ctx.warn('pseudo_element_content', '::before/::after generated content is present and may draw the component.');
  if (ax?.available && (ax.ignored || ['generic', 'none', 'presentation', 'GenericContainer', 'StaticText', 'image'].includes(ax.role)) && ax.states?.focusable !== true && !ax.name) {
    ctx.warn('no_component_semantics', `The accessibility tree ${ax.ignored ? 'ignores this element' : `role is ${ax.role}`}, with no name and no focus; it may be decorative, or identified by a named ancestor.`);
  }
  if (!pairs.length && !warnings.has('zero_size')) ctx.note('No candidate pair was found.');
  return { parts, pairs, warnings: [...warnings.values()], notes, sampling: { margin, pixelSource: 'original viewport PNG, 1 CSS px = 1 image px', edgePositions: 'nine points across the middle half of each edge, per depth', uniformFraction: UNIFORM_FRACTION } };
}

/** Bounded inline view of a successful measure_nontext record for the step response; the whole record stays readable by field. */
export function nonTextPreview(record, maxBytes) {
  const measured = record.result.nonText, size = value => Buffer.byteLength(JSON.stringify(value));
  const head = { evidenceId: record.evidenceId, stateId: record.after?.stateId ?? null, documentId: record.after?.documentId ?? null, target: record.result.target,
    parts: measured.parts, warnings: measured.warnings, ...(measured.notes.length ? { notes: measured.notes } : {}), scope: NONTEXT_SCOPE,
    read: { tool: 'read', evidenceId: record.evidenceId, options: { view: 'field', field: '/result/nonText' } } };
  const pairs = [];
  let used = size(head) + 64;
  for (const pair of measured.pairs) {
    used += size(pair) + 1;
    if (used > maxBytes) break;
    pairs.push(pair);
  }
  return { ...head, pairs, ...(pairs.length < measured.pairs.length ? { pairsOmitted: measured.pairs.length - pairs.length } : {}) };
}
