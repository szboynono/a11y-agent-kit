import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fixture } from './helpers.js';
import { AuditBrowser } from '../src/audit/browser.js';
import { openAuditAgent, AUDIT_PLAYBOOK_TEXT } from '../src/audit/agent.js';
import { auditActionSchema, parseAuditManifest } from '../src/audit/schema.js';
import { reviewAudit } from '../src/audit/review.js';
import { MCP_TEXT_LIMIT } from '../src/audit/projection.js';
import { analyzeNonText, parseCssColor } from '../src/audit/nontext.js';
import { contrastRatio, decodePng } from '../src/audit/pixels.js';

const page = `<!doctype html><html lang="en"><head><title>Non-text contrast</title></head><body style="background:#fff;margin:20px;font:16px sans-serif">
<input id="weak" aria-label="Weak" style="border:1px solid #ccc;background:#fff;padding:6px;width:200px">
<input id="strong" aria-label="Strong" style="border:1px solid #767676;background:#fff;padding:6px;width:200px">
<input id="dashed" aria-label="Dashed" style="border:2px dashed #777;background:#fff;padding:6px;width:200px">
<p><input id="cb" type="checkbox" checked aria-label="Checked"> <input id="cb-off" type="checkbox" aria-label="Unchecked"></p>
<div id="grad" role="img" aria-label="Gradient" style="width:200px;height:30px;background:linear-gradient(90deg,#fff,#000)"></div>
<p><button id="off" type="button" disabled style="border:1px solid #ddd;background:#fff">Unavailable</button>
<button id="text" type="button" style="border:0;background:transparent">Text only</button></p>
<svg id="icon" role="img" aria-label="Dot" width="24" height="24" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8" fill="#bbb"/></svg>
<div style="height:1400px"></div><input id="below" aria-label="Below" style="border:1px solid #ccc">
</body></html>`;

async function startBrowser(t, html = page) {
  const site = await fixture(t, html);
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: site.projectRoot, url: site.url }), { handleSignals: false });
  t.after(() => browser.close());
  await browser.start();
  return browser;
}
async function startAgent(t, html = page) {
  let agent;
  t.after(() => agent?.close());
  const site = await fixture(t, html);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, { textLimit: MCP_TEXT_LIMIT });
  return agent;
}
const measure = async (browser, selector, part) => {
  const record = await browser.execute({ action: 'measure_nontext', selector, ...(part ? { part } : {}) });
  assert.equal(record.success, true, JSON.stringify(record.error));
  return record;
};
const codes = record => record.result.nonText.warnings.map(warning => warning.code);
const kinds = (record, kind) => record.result.nonText.pairs.filter(pair => pair.kind === kind);

test('a low-contrast input border is reported as a candidate pair with coordinates, ratio, counts and uniformity', async t => {
  const browser = await startBrowser(t);
  const record = await measure(browser, '#weak');
  const [outside] = kinds(record, 'border-vs-outside');
  assert.equal(outside.component.hex, '#cccccc'); assert.equal(outside.adjacent.hex, '#ffffff'); assert.equal(outside.adjacent.role, 'outside');
  assert.equal(outside.ratio, 1.606); assert.ok(Math.abs(outside.ratio - contrastRatio([204, 204, 204], [255, 255, 255])) < 0.001);
  assert.deepEqual(outside.sides, ['top', 'right', 'bottom', 'left']);
  assert.ok(outside.samples.component >= 30 && outside.samples.adjacent >= 60);
  assert.deepEqual(outside.uniformity.component, { fraction: 1, distinct: 1, maxChannelDelta: 0 });
  assert.equal(outside.computedColorMatch, true);
  // The pixels at the reported coordinates really are those colours in the retained original PNG.
  const image = decodePng(record.pngBytes);
  const at = point => [...image.data.subarray((point.y * image.width + point.x) * 4, (point.y * image.width + point.x) * 4 + 3)];
  assert.deepEqual(at(outside.component), [204, 204, 204]); assert.deepEqual(at(outside.adjacent), [255, 255, 255]);
  assert.equal(kinds(record, 'border-vs-inside').length, 1);
  assert.deepEqual(codes(record), []);
  // Bound to node and state identity.
  assert.equal(record.result.capture.stable, true); assert.equal(record.before.stateId, record.after.stateId);
  assert.equal(record.result.target.nodeId, record.result.element.nodeId); assert.equal(record.result.target.documentId, record.after.documentId);
  assert.equal(record.result.width, record.after.viewport.width); assert.equal(record.result.nonText.screenshotSha256, createHash('sha256').update(record.pngBytes).digest('hex'));
});

test('a sufficient border is reported with its higher ratio and no warnings', async t => {
  const browser = await startBrowser(t);
  const record = await measure(browser, '#strong', 'boundary');
  const [pair] = kinds(record, 'border-vs-outside');
  assert.equal(pair.component.hex, '#767676'); assert.ok(pair.ratio >= 4.5 && pair.ratio < 4.6);
  assert.deepEqual(codes(record), []);
});

test('the output is observations only: no verdict, pass/fail or threshold judgment appears anywhere', async t => {
  const browser = await startBrowser(t);
  const record = await measure(browser, '#weak');
  const keys = new Set();
  (function walk(value) { if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) { keys.add(key); walk(child); } })(record.result.nonText);
  for (const forbidden of ['verdict', 'pass', 'passes', 'fail', 'fails', 'violation', 'conforms', 'belowThreshold', 'meetsThreshold']) assert.equal(keys.has(forbidden), false, forbidden);
  assert.match(record.result.nonText.scope, /no verdict/);
});

test('a checked checkbox reports its indicator colours, and an unchecked one only its box', async t => {
  const browser = await startBrowser(t);
  const on = await measure(browser, '#cb');
  assert.deepEqual(on.result.nonText.parts, ['boundary', 'indicator']);
  const [tick] = kinds(on, 'cluster-vs-dominant');
  assert.equal(tick.part, 'indicator'); assert.equal(tick.component.hex, '#ffffff'); assert.equal(tick.adjacent.hex, '#0075ff'); assert.equal(tick.adjacent.role, 'dominant');
  assert.ok(Math.abs(tick.ratio - contrastRatio([255, 255, 255], [0, 117, 255])) < 0.001);
  assert.equal(kinds(on, 'fill-vs-outside').length, 1, 'the filled box against its surroundings');
  const off = await measure(browser, '#cb-off');
  assert.equal(kinds(off, 'cluster-vs-dominant').length, 0);
  assert.ok(off.result.nonText.notes.some(note => /one dominant colour/.test(note)));
  assert.equal(kinds(off, 'border-vs-outside')[0].component.hex, '#767676');
  const indicatorOnly = await measure(browser, '#cb', 'indicator');
  assert.ok(indicatorOnly.result.nonText.pairs.length > 0);
  assert.ok(indicatorOnly.result.nonText.pairs.every(pair => pair.part === 'indicator'));
});

test('a background gradient or image raises a warning and nonuniform samples', async t => {
  const browser = await startBrowser(t);
  const record = await measure(browser, '#grad');
  assert.ok(codes(record).includes('gradient_or_image_background'));
  assert.ok(codes(record).includes('nonuniform_region'));
  assert.ok(record.result.nonText.pairs.some(pair => Math.min(pair.uniformity.component.fraction, pair.uniformity.adjacent.fraction) < 0.9));
});

test('a disabled control carries an inactive warning taken from the accessibility tree', async t => {
  const browser = await startBrowser(t);
  const record = await measure(browser, '#off');
  assert.ok(codes(record).includes('inactive_control'));
  assert.equal(record.result.nonText.ax.states.disabled, true);
  assert.match(record.result.nonText.warnings.find(warning => warning.code === 'inactive_control').message, /accessibility tree/);
  // The measurement itself is still reported; deciding the exception is the reviewer's.
  assert.equal(kinds(record, 'border-vs-outside')[0].component.hex, '#dddddd');
});

test('a text-bearing button warns that its boundary may not be needed, and a borderless edge is reported as no visible edge', async t => {
  const browser = await startBrowser(t);
  const record = await measure(browser, '#text');
  assert.ok(codes(record).includes('boundary_may_not_identify_component'));
  assert.ok(codes(record).includes('no_visible_edge'));
  assert.equal(kinds(record, 'no-visible-edge')[0].ratio, 1);
  assert.equal(codes(await measure(browser, '#weak')).includes('boundary_may_not_identify_component'), false);
});

test('a dashed border is nonuniform, and curved icon adjacency is explicitly qualified', async t => {
  const browser = await startBrowser(t);
  const dashed = await measure(browser, '#dashed');
  assert.ok(codes(dashed).includes('nonuniform_region'));
  const icon = await measure(browser, '#icon');
  assert.deepEqual(icon.result.nonText.parts, ['icon']);
  assert.ok(codes(icon).includes('ambiguous_icon_adjacency'));
  assert.ok(codes(icon).includes('ambiguous_cluster_colours'));
});

// A synthetic PNG-free image: white page, a #eee fill whose edge row is the anti-aliased blend #f6f6f6 (or a real #999 border).
function image(width, height, paint) {
  const data = new Uint8Array(width * height * 4);
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) data.set([...paint(x, y), 255], (y * width + x) * 4);
  return { width, height, data };
}
const facts = (extra = {}) => ({ tag: 'div', type: null, rect: { x: 10.4, y: 10.4, width: 30, height: 20 }, viewport: { width: 60, height: 50 },
  border: Object.fromEntries(['top', 'right', 'bottom', 'left'].map(side => [side, { width: 0, style: 'none', color: 'rgb(0, 0, 0)' }])),
  outline: { style: 'none', width: 0, color: 'rgb(0, 0, 0)', offset: 0 }, boxShadow: 'none', backgroundColor: 'rgb(238, 238, 238)', backgroundImage: 'none',
  effectiveOpacity: 1, surface: null, imageOnPath: false, domDisabled: null, ariaDisabled: false, inert: false, focused: false, hasLabelText: false, pseudoContent: false, covered: null, ...extra });
const inside = (x, y) => x >= 10 && x < 40 && y >= 10 && y < 30;

test('an anti-aliased one-pixel edge is not reported as a border colour; a real computed border colour is', () => {
  // The rect is at fractional coordinates, so the outermost pixel ring is a blend of page and fill.
  const blend = image(60, 50, (x, y) => inside(x, y) ? ((x === 10 || x === 39 || y === 10 || y === 29) ? [246, 246, 246] : [238, 238, 238]) : [255, 255, 255]);
  const aa = analyzeNonText({ image: blend, facts: facts(), part: 'boundary' });
  assert.ok(aa.warnings.some(warning => warning.code === 'antialias_only_edge'));
  assert.equal(aa.pairs.some(pair => pair.kind === 'border-vs-outside'), false);
  const [fill] = aa.pairs;
  assert.equal(fill.kind, 'fill-vs-outside'); assert.equal(fill.component.hex, '#eeeeee'); assert.equal(fill.adjacent.hex, '#ffffff');
  // The same single-pixel colour is a genuine border when the computed style says so.
  const border = image(60, 50, (x, y) => inside(x, y) ? ((x === 10 || x === 39 || y === 10 || y === 29) ? [246, 246, 246] : [238, 238, 238]) : [255, 255, 255]);
  const side = { width: 1, style: 'solid', color: 'rgb(246, 246, 246)' };
  const real = analyzeNonText({ image: border, facts: facts({ border: { top: side, right: side, bottom: side, left: side } }), part: 'boundary' });
  assert.equal(real.warnings.some(warning => warning.code === 'antialias_only_edge'), false);
  const [edge] = real.pairs;
  assert.equal(edge.kind, 'border-vs-outside'); assert.equal(edge.component.hex, '#f6f6f6'); assert.equal(edge.computedColorMatch, true); assert.equal(edge.edgeThicknessPx, 1);
});

test('uniformity is measured along the edge and a broken edge is flagged without hiding the dominant colour', () => {
  // The top border is #999 only for part of its length.
  const broken = image(60, 50, (x, y) => (y === 10 && x >= 10 && x < 40) ? (x % 3 === 0 ? [255, 255, 255] : [153, 153, 153]) : inside(x, y) ? [255, 255, 255] : [255, 255, 255]);
  const result = analyzeNonText({ image: broken, facts: facts({ backgroundColor: 'rgb(255, 255, 255)' }), part: 'boundary' });
  const top = result.pairs.find(pair => pair.sides?.includes('top') && pair.kind === 'border-vs-outside');
  assert.equal(top.component.hex, '#999999'); assert.ok(top.uniformity.component.fraction < 0.9 && top.uniformity.component.fraction > 0.5);
  assert.ok(result.warnings.some(warning => warning.code === 'nonuniform_region'));
});

test('semi-transparent computed colours and reduced opacity warn that the computed value is not the rendered value', () => {
  const flat = image(60, 50, () => [255, 255, 255]);
  const half = { width: 1, style: 'solid', color: 'rgba(0, 0, 0, 0.2)' };
  assert.deepEqual(parseCssColor('rgba(0, 0, 0, 0.2)'), { rgb: [0, 0, 0], alpha: 0.2 });
  const result = analyzeNonText({ image: flat, facts: facts({ border: { top: half, right: half, bottom: half, left: half }, effectiveOpacity: 0.5 }), part: 'boundary' });
  assert.ok(result.warnings.some(warning => warning.code === 'transparency'));
});

test('measuring is read-only and costs one action: the page, scroll, focus and state are unchanged', async t => {
  const browser = await startBrowser(t);
  const snapshot = () => browser.page.evaluate(key => ({ html: document.documentElement.outerHTML, scroll: [scrollX, scrollY], active: document.activeElement?.id ?? null, many: Object.hasOwn(globalThis[key] ?? {}, 'many') }), browser.storeKey);
  await browser.page.focus('#strong');
  const before = await snapshot(), first = await measure(browser, '#weak');
  const after = await snapshot();
  assert.deepEqual(after, before); assert.equal(after.many, false);
  assert.equal(first.before.stateId, first.after.stateId);
  const second = await measure(browser, '#weak');
  assert.equal(second.before.stateId, first.after.stateId, 'the state is the same as before the first call');
  assert.ok(second.pngBytes.equals(first.pngBytes), 'the same original pixels');
});

test('an element outside the viewport is refused with scroll guidance and nothing is scrolled', async t => {
  const browser = await startBrowser(t);
  const record = await browser.execute({ action: 'measure_nontext', selector: '#below' });
  assert.equal(record.success, false); assert.equal(record.error.code, 'NONTEXT_TARGET_NOT_IN_VIEWPORT');
  assert.equal(await browser.page.evaluate(() => scrollY), 0);
  await browser.execute({ action: 'scroll', x: 0, y: 1300 });
  assert.equal((await browser.execute({ action: 'measure_nontext', selector: '#below' })).success, true);
});

test('the action schema accepts the three parts and nothing else', () => {
  for (const part of [undefined, 'boundary', 'indicator', 'icon']) assert.equal(auditActionSchema.safeParse({ action: 'measure_nontext', selector: '#a', ...(part ? { part } : {}) }).success, true);
  for (const bad of [{ part: 'glyph' }, { selector: undefined }, { margin: 4 }, { selectors: ['#a'] }]) assert.equal(auditActionSchema.safeParse({ action: 'measure_nontext', selector: '#a', ...bad }).success, false);
});

test('one step call is one action, the inline preview fits the 20k cap, and the whole record pages by field', async t => {
  const agent = await startAgent(t);
  const step = await agent.request({ tool: 'step', actions: [{ action: 'measure_nontext', selector: '#weak' }] });
  assert.equal(step.success, true, JSON.stringify(step).slice(0, 400));
  assert.equal(step.budget.requestedActions, 1); assert.equal(step.budget.successfulActions, 1);
  assert.ok(Buffer.byteLength(JSON.stringify(step)) <= MCP_TEXT_LIMIT);
  const [preview] = step.measureNonText;
  assert.equal(preview.evidenceId, step.records[0].evidenceId); assert.equal(preview.pairs[0].kind, 'border-vs-outside'); assert.equal(preview.pairs[0].contrastRequest.action, 'contrast');
  assert.match(preview.scope, /no verdict/);
  const field = await agent.request({ tool: 'read', evidenceId: preview.evidenceId, options: { view: 'field', field: '/result/nonText' } });
  assert.equal(field.success, true); assert.equal(JSON.parse(field.data).pairs.length, preview.pairs.length);
  // Many measurements in one step still return every record under the cap.
  const many = await agent.request({ tool: 'step', actions: Array.from({ length: 12 }, (_, i) => ({ action: 'measure_nontext', selector: ['#weak', '#strong', '#dashed', '#grad'][i % 4] })) });
  assert.equal(many.success, true); assert.equal(many.records.length, 12);
  assert.ok(Buffer.byteLength(JSON.stringify(many)) <= MCP_TEXT_LIMIT);
});

test('the playbook stays within 120 words and names measure_nontext', () => {
  assert.ok(AUDIT_PLAYBOOK_TEXT.split(/\s+/).length <= 120);
  assert.match(AUDIT_PLAYBOOK_TEXT, /measure_nontext/);
});

async function review(agent, { evidenceId, nodeId, contrastEvidenceId, evidenceIds }) {
  const finding = { id: 'F-border', title: 'Input border has low contrast', criterionId: '1.4.11', target: { evidenceId, nodeId }, evidenceIds,
    observation: 'The input border measures about 1.6:1 against the white page in the retained PNG.', reason: 'The border identifies the text field and falls below 3:1.',
    applicability: 'Enabled text input in the main document.', exceptions: 'Not inactive, not a logo; essential presentation does not apply.', scope: 'This input in the recorded state.', method: 'visual' };
  const submitted = await agent.request({ tool: 'submit', proposal: { auditor: { name: 'Maker' }, findings: [finding] } });
  assert.equal(submitted.success, true, JSON.stringify(submitted).slice(0, 500));
  const proposal = JSON.parse(await fs.readFile(submitted.proposalReportPath, 'utf8'));
  return reviewAudit(proposal.reportPath, { reviewer: { name: 'Independent reviewer', independentOfAuditor: true }, decisions: [{
    findingId: 'F-border', verdict: 'supported', reason: 'The reviewer viewed the PNG and checked the samples.',
    checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
    prerequisiteNotes: { contrast: 'Opaque border pixel against the adjacent page background; threshold 3:1; the field is enabled.', v2: { nonTextContrast: {
      contrastEvidenceId, requiredRatio: 3, use: 'The border is the only visual boundary that identifies the text field.',
      adjacentColors: 'White page background immediately outside the border in the original PNG.', exceptions: 'The input is enabled; not a logo; not user-agent default styling (author border).' } } } }] });
}

test('a well-evidenced measure_nontext finding passes the existing 1.4.11 review gate via the pair\'s contrastRequest, and the measurement record alone does not', async t => {
  const agent = await startAgent(t);
  const first = await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#weak' }, { action: 'measure_nontext', selector: '#weak' }] });
  assert.equal(first.success, true, JSON.stringify(first).slice(0, 400));
  const [inspectId, measureId] = first.records.map(row => row.evidenceId), pair = first.measureNonText[0].pairs[0];
  assert.equal(pair.kind, 'border-vs-outside'); assert.ok(pair.ratio < 3);
  const nodeId = first.measureNonText[0].target.nodeId;
  const second = await agent.request({ tool: 'step', actions: [pair.contrastRequest] });
  assert.equal(second.success, true, JSON.stringify(second).slice(0, 400));
  const contrastId = second.records[0].evidenceId;
  const passed = await review(agent, { evidenceId: inspectId, nodeId, contrastEvidenceId: contrastId, evidenceIds: [inspectId, measureId, contrastId] });
  assert.equal(passed.confirmedFindings.length, 1, JSON.stringify(passed.verificationQueue));
  assert.equal(passed.confirmedFindings[0].evidenceGate.status, 'supported');
  assert.equal(passed.confirmedFindings[0].evidenceGate.semanticAssessment, 'reviewer-dependent');
});

test('the gap is explicit: the measure_nontext record is not itself accepted as contrast evidence', async t => {
  const agent = await startAgent(t);
  const first = await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#weak' }, { action: 'measure_nontext', selector: '#weak' }] });
  const [inspectId, measureId] = first.records.map(row => row.evidenceId), nodeId = first.measureNonText[0].target.nodeId;
  const result = await review(agent, { evidenceId: inspectId, nodeId, contrastEvidenceId: measureId, evidenceIds: [inspectId, measureId] });
  assert.equal(result.confirmedFindings.length, 0);
  assert.match(result.verificationQueue[0].missingEvidence.join(' '), /same-state target-bound original PNG/);
});

test('a measured pair at or above 3:1 cannot be confirmed as a 1.4.11 failure', async t => {
  const agent = await startAgent(t);
  const first = await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#strong' }, { action: 'measure_nontext', selector: '#strong' }] });
  const [inspectId, measureId] = first.records.map(row => row.evidenceId), pair = first.measureNonText[0].pairs[0], nodeId = first.measureNonText[0].target.nodeId;
  const second = await agent.request({ tool: 'step', actions: [pair.contrastRequest] });
  const result = await review(agent, { evidenceId: inspectId, nodeId, contrastEvidenceId: second.records[0].evidenceId, evidenceIds: [inspectId, measureId, second.records[0].evidenceId] });
  assert.equal(result.confirmedFindings.length, 0);
  assert.match(result.verificationQueue[0].missingEvidence.join(' '), /3:1 non-text threshold/);
});


test('capture leaves finite and infinite animations running and dispatches no synthetic completion', async t => {
  const browser = await startBrowser(t);
  await browser.page.evaluate(() => {
    globalThis.animationEnds = 0;
    const el = document.querySelector('#weak');
    const finite = el.animate([{ opacity: 1 }, { opacity: 0.5 }], { duration: 600000 });
    finite.onfinish = () => globalThis.animationEnds++;
    const infinite = el.animate([{ color: 'red' }, { color: 'blue' }], { duration: 600000, iterations: Infinity });
    globalThis.animations = [finite, infinite];
  });
  // An animated state may be rejected, but capture must never finish/cancel it.
  await browser.execute({ action: 'measure_nontext', selector: '#weak' });
  const actual = await browser.page.evaluate(() => ({ ends: animationEnds, states: animations.map(a => a.playState) }));
  assert.deepEqual(actual, { ends: 0, states: ['running', 'running'] });
});

test('external outline and shadow samples are omitted without relaxing target containment', () => {
  const pic = image(60, 50, (x, y) => inside(x, y) ? [255,255,255] : [80,80,80]);
  const f = facts({ outline: { style: 'solid', width: 2, offset: 1, color: 'rgb(80, 80, 80)' }, boxShadow: 'rgb(80, 80, 80) 0px 0px 0px 2px' });
  const result = analyzeNonText({ image: pic, facts: f, part: 'indicator' });
  assert.ok(result.warnings.some(w => w.code === 'foreground_outside_target'));
  assert.equal(result.pairs.length, 0);
  const boundary = analyzeNonText({ image: pic, facts: f, part: 'boundary' });
  for (const p of boundary.pairs) {
    assert.ok(p.component.x + .5 >= f.rect.x && p.component.x + .5 < f.rect.x + f.rect.width);
    assert.ok(p.component.y + .5 >= f.rect.y && p.component.y + .5 < f.rect.y + f.rect.height);
  }
});

test('solid intermediate icon colours are retained and paired only with touching pixels', () => {
  const pic = image(60, 50, (x, y) => {
    if (!inside(x,y)) return [0,0,0]; // page behind a small white control
    if (x >= 12 && x < 15 && y >= 13 && y < 20) return [0,0,0];
    if (x >= 18 && x < 38 && y >= 12 && y < 28) return [187,187,187];
    return [255,255,255];
  });
  const result = analyzeNonText({ image: pic, facts: facts(), part: 'icon' });
  const grey = result.pairs.find(p => p.component.hex === '#bbbbbb');
  assert.ok(grey, 'dominant solid grey survives the black/white/grey ambiguity');
  assert.equal(grey.adjacent.hex, '#ffffff');
  assert.ok(result.warnings.some(w => w.code === 'ambiguous_cluster_colours'));
});

test('a white glyph inside a grey button is never paired with the black page', () => {
  const pic = image(60, 50, (x,y) => x >= 8 && x < 42 && y >= 8 && y < 32
    ? x >= 20 && x < 30 && y >= 15 && y < 25 ? [255,255,255] : [187,187,187] : [0,0,0]);
  const result = analyzeNonText({ image: pic, facts: facts(), part: 'icon' });
  const glyph = result.pairs.find(p => p.component.hex === '#ffffff');
  assert.ok(glyph); assert.equal(glyph.adjacent.hex, '#bbbbbb'); assert.ok(glyph.ratio < 3);
});

// ---- thin solid-fill SVG icons (owned fixtures: strokes drawn as filled 1.5-2 px polygons at fractional coordinates, no `stroke`) ----
const strip = (x1, y1, x2, y2, w) => {
  const dx = x2 - x1, dy = y2 - y1, len = Math.hypot(dx, dy), nx = -dy / len * w / 2, ny = dx / len * w / 2;
  return `M${x1 + nx} ${y1 + ny}L${x2 + nx} ${y2 + ny}L${x2 - nx} ${y2 - ny}L${x1 - nx} ${y1 - ny}Z`;
};
const glyphs = {
  edit: [strip(8.5, 20.3, 21, 7.7, 1.6), strip(11.6, 22.4, 24.2, 9.8, 1.6), strip(21, 7.7, 24.2, 9.8, 1.6)].join(''),
  more: [strip(11, 9.2, 16.5, 15.6, 1.7), strip(16.5, 15.6, 22, 9.2, 1.7)].join(''),
  close: [strip(10.5, 6.6, 22.5, 18.4, 1.6), strip(22.5, 6.6, 10.5, 18.4, 1.6)].join(''),
  search: 'M16.5 6.3a5.5 5.5 0 1 0 .001 0ZM16.5 7.7a4.1 4.1 0 1 0 .001 0Z' + strip(20.4, 15.2, 24.6, 19.6, 1.8),
  plus: [strip(8.6, 12.9, 24.4, 12.9, 1.8), strip(16.5, 5.1, 16.5, 20.7, 1.8)].join(''),
};
const iconButton = (id, label, fill, glyph = glyphs[id], paint = `fill:${fill}`) => `<button id="${id}" type="button" aria-label="${label}" style="border:0;background:transparent;padding:0;margin:0 4px 0 0;width:33px;height:39px;display:inline-block;vertical-align:top;padding-top:6px;box-sizing:border-box"><svg width="33" height="25" viewBox="0 0 33 25" style="${paint}" aria-hidden="true"><path fill-rule="evenodd" d="${glyph}"/></svg></button>`;
const thinIcons = `<!doctype html><html lang="en"><head><title>Thin icons</title></head><body style="background:#f4f4f4;margin:0;font:16px sans-serif">
<div id="card" style="background:#fff;margin:20px;padding:10px;width:160px">${iconButton('edit', 'Edit', '#ccc')}${iconButton('more', 'More', '#ccc')}${iconButton('close', 'Close', '#ccc')}</div>
<div id="side" style="margin:20px;padding:10px;width:160px">${iconButton('search', 'Search', '#ccc')}${iconButton('plus', 'New', '#aaa')}</div></body></html>`;

test('thin solid-fill SVG icon buttons yield a stroke-core pair with the right ratio, honest warnings and a usable contrastRequest', async t => {
  const browser = await startBrowser(t, thinIcons);
  for (const [id, expected, core, surround] of [['edit', 1.61, '#cccccc', '#ffffff'], ['more', 1.61, '#cccccc', '#ffffff'], ['close', 1.61, '#cccccc', '#ffffff'], ['search', 1.46, '#cccccc', '#f4f4f4'], ['plus', 2.11, '#aaaaaa', '#f4f4f4']]) {
    const record = await measure(browser, `#${id}`, 'icon');
    const pair = kinds(record, 'icon-vs-surround').find(p => p.basis === 'antialiased-core');
    assert.ok(pair, `${id}: a stroke-core pair is returned`);
    assert.equal(pair.component.hex, core, id); assert.equal(pair.adjacent.hex, surround, id); assert.equal(pair.adjacent.role, 'surround');
    assert.ok(Math.abs(pair.ratio - expected) <= 0.15, `${id}: ${pair.ratio} is within 0.15 of ${expected}`);
    // Cross-checked against the SVG's computed solid fill; the agreement is reported, not assumed.
    assert.equal(pair.computedColorMatch, true); assert.equal(pair.computedColor, core);
    // Never presented as a clean sample: the unestablished local adjacency is flagged; the pair exists only because its colour is the painted fill.
    for (const code of ['ambiguous_icon_adjacency', 'nonuniform_region']) assert.ok(codes(record).includes(code), `${id}: ${code}`);
    assert.ok(pair.uniformity.adjacent.fraction < 0.9);
    // The pair's contrastRequest is accepted by the existing contrast action and reproduces the ratio.
    const confirmed = await browser.execute({ action: 'contrast', ...pair.contrastRequest, action: 'contrast' });
    assert.equal(confirmed.success, true, JSON.stringify(confirmed.error));
    assert.ok(Math.abs(confirmed.result.contrast.ratio - pair.ratio) < 0.001);
  }
});

test('the measured button (not just the svg) is enough, and measuring without a part picks the icon for an svg', async t => {
  const browser = await startBrowser(t, thinIcons);
  const record = await measure(browser, '#plus svg');
  assert.deepEqual(record.result.nonText.parts, ['icon']);
  assert.ok(kinds(record, 'icon-vs-surround').some(p => p.basis === 'antialiased-core' && Math.abs(p.ratio - 2.11) <= 0.15));
});

const guards = `<!doctype html><html lang="en"><head><title>Guards</title></head><body style="background:#fff;margin:20px;font:16px sans-serif">
<svg width="0" height="0"><defs><linearGradient id="g"><stop offset="0" stop-color="#000"/><stop offset="1" stop-color="#ccc"/></linearGradient></defs></svg>
${iconButton('grad', 'Gradient', '', glyphs.close, 'fill:url(#g)')}
<button id="ramp" type="button" aria-label="On gradient" style="border:0;padding:0;width:33px;height:39px;padding-top:6px;box-sizing:border-box;background:linear-gradient(90deg,#fff,#333)"><svg width="33" height="25" viewBox="0 0 33 25" style="fill:#ccc" aria-hidden="true"><path d="${glyphs.close}"/></svg></button>
<button id="raster" type="button" aria-label="Raster" style="border:0;background:#fff;padding:0"><img alt="" width="33" height="25" src="data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="33" height="25" viewBox="0 0 33 25"><path fill="#ccc" d="${glyphs.close}"/></svg>`)}"></button>
</body></html>`;

test('gradient paint, a gradient behind the icon, and raster icons get no stroke-core estimate and say why', async t => {
  const browser = await startBrowser(t, guards);
  const grad = await measure(browser, '#grad', 'icon');
  assert.equal(grad.result.nonText.pairs.some(p => p.basis), false); assert.ok(codes(grad).includes('icon_paint_not_solid'));
  const ramp = await measure(browser, '#ramp', 'icon');
  assert.equal(ramp.result.nonText.pairs.some(p => p.basis), false); assert.ok(codes(ramp).includes('gradient_or_image_background'));
  const raster = await measure(browser, '#raster', 'icon');
  assert.equal(raster.result.nonText.pairs.some(p => p.basis), false);
  const img = await measure(browser, '#raster img');
  assert.equal(img.result.nonText.pairs.some(p => p.basis), false); assert.ok(codes(img).includes('raster_content'));
});

test('a stroke core is returned only when it equals a painted solid colour; disagreement, unknown paint, fading and touching colours give no pair and a warning', () => {
  // 2 px #ccc vertical bar on white whose edges fade through varying blends (a diagonal stroke), so no single neighbour colour dominates.
  const blend = y => { const v = 215 + (y * 5) % 35; return [v, v, v]; };
  const bar = () => image(60, 50, (x, y) => !inside(x, y) ? [255, 255, 255] : x === 24 || x === 27 ? blend(y) : x === 25 || x === 26 ? [204, 204, 204] : [255, 255, 255]);
  const solid = glyph => facts({ tag: 'svg', backgroundColor: 'rgba(0, 0, 0, 0)', glyph });
  const painted = (colors, extra = {}) => ({ shapes: 1, colors, nonSolid: false, translucent: false, indirect: false, truncated: false, minStrokePx: null, ...extra });
  const agree = analyzeNonText({ image: bar(), facts: solid(painted(['rgb(204, 204, 204)'])), part: 'icon' });
  const pair = agree.pairs.find(p => p.basis === 'antialiased-core');
  assert.ok(pair); assert.equal(pair.computedColorMatch, true); assert.equal(pair.computedColor, '#cccccc');
  assert.equal(pair.computedRatio, undefined); assert.equal(pair.computedRatioColor, undefined); assert.equal(pair.subpixelStroke, undefined);
  const refused = (result, ...expected) => {
    assert.equal(result.pairs.length, 0, JSON.stringify(result.pairs.map(p => p.component.hex)));
    for (const code of ['icon_colour_unverified', ...expected]) assert.ok(result.warnings.some(w => w.code === code), `${code} in ${result.warnings.map(w => w.code)}`);
  };
  refused(analyzeNonText({ image: bar(), facts: solid(painted(['rgb(136, 136, 136)'])), part: 'icon' }));
  refused(analyzeNonText({ image: bar(), facts: solid(painted(['rgb(204, 204, 204)'], { translucent: true })), part: 'icon' }), 'transparency');
  refused(analyzeNonText({ image: bar(), facts: { ...solid(painted(['rgb(204, 204, 204)'])), effectiveOpacity: 0.5 }, part: 'icon' }), 'transparency');
  // The painted colour list is unknown (<use>, truncated, no shapes, no svg): never a pair, never a mismatch claim.
  for (const unknown of [painted([], { shapes: 0 }), painted(['rgb(204, 204, 204)'], { indirect: true }), painted(['rgb(204, 204, 204)'], { truncated: true }), undefined]) {
    const result = analyzeNonText({ image: bar(), facts: solid(unknown), part: 'icon' });
    refused(result, 'painted_colour_unknown'); assert.equal(result.warnings.some(w => w.code === 'computed_colour_mismatch'), false);
  }
  // A black pixel run touching the stroke is not a blend between the stroke and the surround: no estimate for the grey stroke (the black run itself is a stroke core).
  const touching = analyzeNonText({ image: image(60, 50, (x, y) => !inside(x, y) ? [255, 255, 255] : x === 24 ? [0, 0, 0] : x === 25 || x === 26 ? [204, 204, 204] : x === 27 ? blend(y) : [255, 255, 255]), facts: solid(undefined), part: 'icon' });
  assert.equal(touching.pairs.some(p => p.component.hex === '#cccccc'), false);
  assert.ok(touching.warnings.some(w => w.code === 'ambiguous_icon_adjacency'));
  // Next to an original-path pair the fallback is silent: no refusal reason, no icon_colour_unverified, no fade transparency (unmatched colour, unknown paint, fade).
  const crispPair = image(60, 50, (x, y) => !inside(x, y) ? [255, 255, 255] : x >= 30 && x < 36 && y >= 15 && y < 30 ? [51, 51, 51] : x === 24 || x === 27 ? blend(y) : x === 25 || x === 26 ? [204, 204, 204] : [255, 255, 255]);
  const quiet = glyph => analyzeNonText({ image: crispPair, facts: solid(glyph), part: 'icon' });
  for (const [label, glyph] of [['unmatched colour', painted(['rgb(136, 136, 136)'])], ['unknown paint', painted(['rgb(204, 204, 204)'], { indirect: true })], ['fade', painted(['rgb(204, 204, 204)'], { translucent: true })]]) {
    const result = quiet(glyph);
    assert.ok(result.pairs.length >= 1 && result.pairs.every(p => !p.basis), `${label}: original-path pairs only`);
    for (const code of ['icon_colour_unverified', 'painted_colour_unknown', 'transparency']) assert.equal(result.warnings.some(w => w.code === code), false, `${label}: ${code}`);
  }
  // A stroke under one CSS px adds the warning and nothing else: no fields on pairs, old-path pairs unchanged.
  const thin = analyzeNonText({ image: bar(), facts: solid(painted(['rgb(204, 204, 204)'], { minStrokePx: 0.6 })), part: 'icon' });
  assert.ok(thin.warnings.some(w => w.code === 'subpixel_stroke')); assert.match(thin.warnings.find(w => w.code === 'subpixel_stroke').message, /CSS px/);
  assert.equal(JSON.stringify(thin.pairs).includes('subpixelStroke'), false);
  assert.equal(analyzeNonText({ image: bar(), facts: solid(painted(['rgb(204, 204, 204)'], { minStrokePx: 1 })), part: 'icon' }).warnings.some(w => w.code === 'subpixel_stroke'), false);
});

// ---- round 2: label text beside an icon, shapes that are never painted, and strokes under one device pixel (owned fixtures) ----
const twShapes = (paint, extra = '') => `<g fill="${paint}" fill-rule="evenodd"${extra}><path d="M16 112 L104 24 L111 31 L23 119 Z"/><path d="M10 10h108v7H10z"/><circle cx="64" cy="80" r="20" fill="none" stroke="${paint}" stroke-width="7"/></g>`;
const labelled = (id, svgInner, { defs = '', text = 'Edit', bg = '' } = {}) => `<button id="${id}" type="button" aria-label="${id}" style="border:0;background:${bg || 'transparent'};padding:4px;height:40px;display:flex;align-items:center;gap:6px;color:#000;font:14px sans-serif"><svg width="24" height="24" viewBox="0 0 128 128">${defs}${svgInner}</svg>${text ? `<span>${text}</span>` : ''}</button>`;
const stroked = (id, paint, width, inner = 'M4 4H20V20H4Z M4 20 L20 4') => `<button id="${id}" type="button" aria-label="${id}" style="border:0;background:transparent;padding:4px;width:40px;height:40px"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${paint}" stroke-width="${width}" style="display:block;margin:auto"><path d="${inner}"/></svg></button>`;
const clip = '<defs><clipPath id="c"><rect width="128" height="128"/></clipPath></defs>';
const roundTwo = `<!doctype html><html lang="en"><head><title>Round two</title></head><body style="background:#fff;margin:20px;font:14px sans-serif;color:#000">
<div>${labelled('t1', twShapes('#ccc'))}${labelled('t2', twShapes('#767676'))}${labelled('t3', twShapes('#ccc', ' clip-path="url(#c)"'), { defs: clip })}</div>
<div>${labelled('t4', twShapes('#ccc'), { defs: '<defs><rect width="128" height="128"/><mask id="m"><rect width="9" height="9" fill="#fff"/></mask></defs><symbol id="sym"><rect width="9" height="9"/></symbol><g display="none"><rect width="9" height="9" fill="#f00"/></g><rect width="9" height="9" fill="#0f0" visibility="hidden"/><rect width="9" height="9" fill="none" stroke="none"/><rect width="9" height="9" fill="#00f" opacity="0"/><rect width="9" height="9" fill="#f0f" fill-opacity="0"/>', text: '' })}
${labelled('t5', '<use href="#sym2" fill="#ccc"/>', { defs: '<symbol id="sym2" viewBox="0 0 128 128"><path d="M16 112 L104 24 L111 31 L23 119 Z"/><path d="M10 10h108v7H10z"/></symbol>', text: '' })}
${labelled('t6', twShapes('#333'), { text: '' })}${labelled('t7', twShapes('#eee'), { text: '', bg: '#222' })}</div>
<div>${stroked('s1', '#555', 0.6)}${stroked('s2', '#333', 0.6)}${stroked('s3', '#333', 1, 'M4.5 4.5H19.5V19.5H4.5Z M4 20 L20 4')}
<button id="s4" type="button" aria-label="s4" style="border:0;background:transparent;padding:4px;width:40px;height:40px"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke-width="1" style="display:block;margin:auto"><path stroke="#d00" d="M4.5 4.5H19.5V12.5"/><path stroke="#00d" d="M12.5 2V22 M4 20 L20 6"/></svg></button></div>
</body></html>`;
const fallbackPairs = record => record.result.nonText.pairs.filter(p => p.basis === 'antialiased-core');
const approx = (actual, expected, tolerance = 0.05) => assert.ok(Math.abs(actual - expected) <= tolerance, `${actual} is within ${tolerance} of ${expected}`);

test('visible label text beside a thin icon is never reported as an icon pair; the icon pair is first', async t => {
  const browser = await startBrowser(t, roundTwo);
  for (const [id, core, expected] of [['t1', '#cccccc', 1.606], ['t2', '#767676', 4.542]]) {
    const record = await measure(browser, `#${id}`, 'icon');
    const pairs = record.result.nonText.pairs;
    assert.equal(pairs[0].component.hex, core, `${id}: p1 is the icon`); approx(pairs[0].ratio, expected, 0.01);
    assert.equal(pairs[0].computedColorMatch, true); assert.equal(pairs[0].adjacent.hex, '#ffffff');
    // No pair anywhere is made of the black label (or its anti-aliasing greys, which are all darker than the icon colour on white at ratio > 7).
    assert.equal(pairs.some(p => p.ratio > 7), false, `${id}: no text-ratio pair: ${pairs.map(p => `${p.component.hex}:${p.ratio}`)}`);
    assert.equal(pairs.some(p => p.component.hex === '#000000'), false);
    // The confirming action reproduces the icon, not the text.
    const confirmed = await browser.execute({ ...pairs[0].contrastRequest, action: 'contrast' });
    approx(confirmed.result.contrast.ratio, expected, 0.01);
  }
});

test('shapes inside defs, clipPath, mask, symbol or hidden by display, visibility, opacity or fill:none do not count as painted colours', async t => {
  const browser = await startBrowser(t, roundTwo);
  // The reviewer's input: a text label plus a default-black clipPath rect must not let the label pair be "verified".
  const clipped = await measure(browser, '#t3', 'icon');
  assert.equal(clipped.result.nonText.pairs[0].component.hex, '#cccccc'); assert.equal(clipped.result.nonText.pairs[0].computedColorMatch, true);
  assert.equal(clipped.result.nonText.pairs[0].computedColor, '#cccccc');
  assert.equal(clipped.result.nonText.pairs.some(p => p.component.hex === '#000000'), false);
  // Every kind of unpainted shape beside the real icon: only the real fill is a painted colour.
  const hidden = await measure(browser, '#t4', 'icon');
  const pair = fallbackPairs(hidden)[0];
  assert.equal(pair.component.hex, '#cccccc'); assert.equal(pair.computedColor, '#cccccc'); assert.equal(pair.computedColorMatch, true);
  // A <use>-instanced symbol is not resolved: the painted-colour list is unknown, so no fallback pair is returned and the icon is flagged for manual checking.
  const used = await measure(browser, '#t5', 'icon');
  assert.equal(fallbackPairs(used).length, 0);
  for (const code of ['painted_colour_unknown', 'icon_colour_unverified']) assert.ok(codes(used).includes(code), code);
  assert.equal(codes(used).includes('computed_colour_mismatch'), false);
});

test('a sub-pixel stroke gets no fallback pair, only a warning; a full-width stroke is unaffected; every returned pair matches a painted colour', async t => {
  const browser = await startBrowser(t, roundTwo);
  for (const id of ['s1', 's2']) {
    const record = await measure(browser, `#${id}`, 'icon');
    assert.equal(fallbackPairs(record).length, 0, `${id}: no fallback pair`);
    for (const code of ['subpixel_stroke', 'icon_colour_unverified']) assert.ok(codes(record).includes(code), `${id}: ${code}`);
    assert.equal(JSON.stringify(record.result.nonText).includes('computedRatio'), false);
    assert.equal(JSON.stringify(record.result.nonText).includes('subpixelStroke'), false);
  }
  const crisp = await measure(browser, '#s3', 'icon');
  assert.equal(codes(crisp).includes('subpixel_stroke'), false); assert.equal(codes(crisp).includes('icon_colour_unverified'), false);
  approx(crisp.result.nonText.pairs[0].ratio, 12.635, 0.01);
  // Two painted colours: both are returned, every returned pair agrees with a painted colour, the diagonal's blend is not returned.
  const multi = fallbackPairs(await measure(browser, '#s4', 'icon'));
  assert.deepEqual(multi.map(p => p.component.hex).sort(), ['#0000dd', '#dd0000']); assert.ok(multi.every(p => p.computedColorMatch === true));
});

test('thin dark-on-light and light-on-dark filled icons keep their true ratio and match the painted colour', async t => {
  const browser = await startBrowser(t, roundTwo);
  const dark = fallbackPairs(await measure(browser, '#t6', 'icon'))[0];
  approx(dark.ratio, 12.635, 0.01); assert.equal(dark.computedColorMatch, true); assert.equal(dark.computedRatio, undefined);
  const light = fallbackPairs(await measure(browser, '#t7', 'icon')).find(p => p.component.hex === '#eeeeee');
  approx(light.ratio, 13.713, 0.01); assert.equal(light.adjacent.hex, '#222222'); assert.equal(light.computedColorMatch, true);
});

test('text boxes are excluded from the icon estimate even when the text colour is painted, a colour no shape paints is never returned, and old-path pairs keep value, order and warnings', () => {
  // A #ccc 2 px bar (the icon) and a black 2 px bar (text), both with soft edges, side by side on white.
  const blend = y => { const v = 215 + (y * 5) % 35; return [v, v, v]; };
  const soft = (core, x0) => (x, y) => x === x0 || x === x0 + 3 ? blend(y) : x === x0 + 1 || x === x0 + 2 ? core : null;
  const within = (x, y) => x >= 10 && x < 70 && y >= 10 && y < 40;
  const bars = () => image(80, 50, (x, y) => !within(x, y) ? [255, 255, 255] : soft([204, 204, 204], 20)(x, y) ?? soft([0, 0, 0], 50)(x, y) ?? [255, 255, 255]);
  const solid = extra => facts({ tag: 'button', backgroundColor: 'rgba(0, 0, 0, 0)', rect: { x: 10, y: 10, width: 60, height: 30 }, glyph: { shapes: 1, colors: ['rgb(204, 204, 204)'], nonSolid: false, translucent: false }, ...extra });
  const text = { x: 48, y: 10, width: 10, height: 30 };
  const without = analyzeNonText({ image: bars(), facts: solid({}), part: 'icon' });
  const byRect = analyzeNonText({ image: bars(), facts: solid({ textRects: [text] }), part: 'icon' });
  // Even without text knowledge the black bar is not painted by any shape, so it is not returned; with the text box excluded the result is the same.
  assert.deepEqual(without.pairs.map(p => [p.component.hex, p.computedColorMatch]), [['#cccccc', true]]);
  for (const result of [without, byRect]) {
    assert.equal(result.pairs[0].component.hex, '#cccccc'); assert.equal(result.pairs[0].computedColorMatch, true);
    assert.equal(result.pairs.some(p => p.component.hex === '#000000'), false);
  }
  // When the text colour IS a painted colour, only the text box keeps the black bar out: without it the bar is paired, with it it is not.
  const blackPainted = extra => solid({ glyph: { shapes: 2, colors: ['rgb(204, 204, 204)', 'rgb(0, 0, 0)'], nonSolid: false, translucent: false }, ...extra });
  assert.ok(analyzeNonText({ image: bars(), facts: blackPainted({}), part: 'icon' }).pairs.some(p => p.component.hex === '#000000'), 'without the text box the black bar is an icon pair');
  const excluded = analyzeNonText({ image: bars(), facts: blackPainted({ textRects: [text] }), part: 'icon' });
  assert.equal(excluded.pairs.some(p => p.component.hex === '#000000'), false, 'the text box keeps the black bar out');
  assert.ok(excluded.pairs.some(p => p.component.hex === '#cccccc'));
  // Old-path pairs are byte-identical whether or not the fallback runs; fallback pairs only ever follow them.
  const crisp = image(80, 50, (x, y) => !within(x, y) ? [255, 255, 255] : x >= 12 && x < 18 && y >= 14 && y < 26 ? [51, 51, 51] : soft([204, 204, 204], 40)(x, y) ?? [255, 255, 255]);
  const withFallback = analyzeNonText({ image: crisp, facts: solid({}), part: 'icon' });
  const oldOnly = analyzeNonText({ image: crisp, facts: solid({ hasRaster: true }), part: 'icon' });
  const old = withFallback.pairs.filter(p => !p.basis);
  assert.ok(old.length >= 1); assert.ok(withFallback.pairs.some(p => p.basis), 'the fallback adds a pair next to the old-path pair');
  assert.deepEqual(old, oldOnly.pairs); assert.deepEqual(withFallback.pairs.slice(0, old.length), old);
  assert.equal(old[0].component.hex, '#333333'); assert.equal(old[0].adjacent.hex, '#ffffff'); assert.equal(old[0].id, 'p1');
});

// The source export omits the external-file cases listed in docs/test-coverage.md.
test('fades are found anywhere up the chain: opacity or CSS filter on a shape, group, svg, wrapper or the button, and rgba paint', async t => {
  const paint = '<path fill="#333" d="M16 112 L104 24 L111 31 L23 119 Z"/><path fill="#333" d="M10 10h108v7H10z"/>';
  const one = (id, { button = '', wrap = '', svg = '', g = '', shape = '' }) => `<div style="${wrap}"><button id="${id}" aria-label="${id}" style="border:0;background:transparent;padding:4px;height:40px;display:flex;${button}"><svg viewBox="0 0 128 128" style="width:24px;height:24px;${svg}"><g ${g}>${paint.replace(/<path /g, `<path ${shape} `)}</g></svg></button></div>`;
  const html = `<!doctype html><html lang="en"><head><title>Fades</title></head><body style="margin:20px;background:#fff">
${one('plain', {})}${one('shape-op', { shape: 'opacity=".4"' })}${one('shape-fill', { shape: 'fill-opacity=".4"' })}${one('g-op', { g: 'opacity=".4"' })}${one('g-filter', { g: 'style="filter:opacity(.4)"' })}${one('svg-op', { svg: 'opacity:.4' })}
${one('svg-filter', { svg: 'filter:grayscale(1) opacity(.4)' })}${one('wrap-op', { wrap: 'opacity:.4' })}${one('wrap-filter', { wrap: 'filter:opacity(.4)' })}${one('button-op', { button: 'opacity:.4' })}${one('button-filter', { button: 'filter:opacity(.4)' })}${one('rgba', { shape: 'style="fill:rgba(51,51,51,.4)"' })}</body></html>`;
  const browser = await startBrowser(t, html);
  const plain = await measure(browser, '#plain', 'icon');
  approx(fallbackPairs(plain)[0].ratio, 12.635, 0.01);
  for (const id of ['shape-op', 'shape-fill', 'g-op', 'g-filter', 'svg-op', 'svg-filter', 'wrap-op', 'wrap-filter', 'button-op', 'button-filter', 'rgba']) {
    const record = await measure(browser, `#${id}`, 'icon');
    assert.equal(fallbackPairs(record).length, 0, `${id}: no fallback pair`);
    assert.equal(record.result.nonText.pairs.some(p => Math.abs(p.ratio - 12.635) < 0.01), false, `${id}: the unfaded 12.635 never appears`);
    for (const code of ['transparency', 'icon_colour_unverified']) assert.ok(codes(record).includes(code), `${id}: ${code} in ${codes(record)}`);
  }
});
