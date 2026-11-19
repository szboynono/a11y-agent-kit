import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { openAuditAgent } from '../src/audit/agent.js';
import { reviewAudit } from '../src/audit/review.js';
import { REPORT_LIMITS, REPORT_CSS, REPORT_TOKENS, REPORT_CONTRAST_PAIRS, criterionName, renderBoundedAuditReportHtml, loadReportContext, normalizeAuditReport, renderAuditReportHtml, writeAuditReport } from '../src/audit/report-html.js';
import { fixture } from './helpers.js';

const SENTINEL = 'SECRET_VALUE_SENTINEL_5519';
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const finding = (id, criterionId, extra = {}) => ({
  id, title: `Title ${id}`, criterionId, target: { evidenceId: 'ev-0001', nodeId: `doc-1:${id}` }, evidenceIds: ['ev-0001'],
  observation: `Observation ${id}`, reason: `Reason ${id}`, applicability: 'a', exceptions: 'e', scope: 'This node only.', method: 'dom', ...extra,
});
const decision = (findingId, verdict = 'supported') => ({ findingId, verdict, reason: `Reviewer ${findingId}`,
  checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: verdict === 'supported' ? 'supported' : 'insufficient' } });
const coverage = ['1.1.1', '1.4.3', '1.4.10', '4.1.2'].map(id => ({ id, level: 'AA', status: 'not_tested', url: `https://www.w3.org/TR/WCAG22/#sc${id}` }));
const standard = { version: '2.2', targetLevel: 'AA', criteriaTotal: 55 };
function reviewed(findings, { confirmed = [], queue = [], rejected = [], decisions = [] } = {}) {
  const row = id => ({ ...findings.find(item => item.id === id), targetObservation: { selector: `#${id}` } });
  return { kind: 'audit-review', directEvidencePolicy: 'dom-predicates-v1', status: 'partial', runId: 'run-1', standard, coverage, auditor: { name: 'Maker' }, reviewer: { name: 'Checker' }, createdAt: '2026-10-30T00:00:00.000Z',
    manifest: { url: 'http://127.0.0.1:1/' }, reportDigest: 'sha256:abc', findings, decisions,
    confirmedFindings: confirmed.map(id => ({ ...row(id), decision: decisions.find(d => d.findingId === id) })),
    verificationQueue: queue.map(id => ({ ...row(id), decision: decisions.find(d => d.findingId === id), missingEvidence: [`Needs more for ${id}`] })),
    rejectedObservations: rejected.map(id => ({ ...row(id), decision: decisions.find(d => d.findingId === id) })) };
}

test('renders summary, SC grouping, source and status per finding, and the not-a-certification note', () => {
  const findings = [finding('a', '4.1.2', { source: 'axe', axeCandidateId: 'c1' }), finding('b', '1.4.10'), finding('c', '1.4.3'), finding('d', '1.1.1'), finding('e', '1.4.3')];
  const decisions = [decision('a'), decision('b', 'insufficient'), decision('c'), decision('d', 'rejected')];
  const html = renderAuditReportHtml(reviewed(findings, { confirmed: ['a', 'c'], queue: ['b'], rejected: ['d'], decisions }));
  assert.match(html, /^<!doctype html>\n<html lang="en">/);
  assert.match(html, /Not a conformance certification/);
  assert.match(html, /Untested scope and limits/); assert.match(html, /Screen readers .* were not used/);
  const order = ['SC 1.1.1', 'SC 1.4.3', 'SC 1.4.10', 'SC 4.1.2'].map(label => html.indexOf(label));
  assert.ok(order.every(position => position > 0) && order.join() === [...order].sort((x, y) => x - y).join(), `numeric SC order: ${order}`);
  assert.match(html, /<b>5<\/b><span>findings/); assert.match(html, /Confirmed<\/dt><dd>2<\/dd>/); assert.match(html, /Needs review<\/dt><dd>2<\/dd>/);
  assert.match(html, /Rejected<\/dt><dd>1<\/dd>/);
  assert.match(html, /axe-adopted<\/dt><dd>1<\/dd>/); assert.match(html, /agent-found<\/dt><dd>4<\/dd>/); assert.match(html, /<b>4<\/b><span>with findings/);
  const card = id => html.slice(html.indexOf(`id="f-${id}"`), html.indexOf('</article>', html.indexOf(`id="f-${id}"`)));
  assert.match(card('a'), /Confirmed/); assert.match(card('a'), /axe-adopted/); assert.match(card('a'), /<code>#a<\/code>/); assert.match(card('a'), /Observation a/);
  assert.match(card('b'), /Needs review/); assert.match(card('b'), /Review verdict<\/dt><dd>insufficient/); assert.match(card('b'), /Needs more for b/); assert.match(card('b'), /agent-found/);
  assert.match(card('d'), /Rejected by reviewer/); assert.match(card('e'), /Needs review/);
  assert.match(card('c'), /<code>ev-0001<\/code>/);
  assert.equal(/<script|<link|<iframe|https?:\/\/[^"' ]*\.(js|css)/.test(html), false);
  assert.match(html, /default-src 'none'/);
});

test('a proposal and a draft checkpoint render as needs-review with their own caveat', () => {
  const findings = [finding('a', '4.1.2')];
  const proposal = { ...reviewed(findings, { queue: ['a'] }), kind: 'audit-proposal', decisions: undefined, reviewer: undefined };
  proposal.verificationQueue[0].decision = undefined;
  const p = renderAuditReportHtml(proposal);
  assert.match(p, /awaiting review/); assert.match(p, /Needs review/); assert.equal(/Insufficient evidence<\/span>/.test(p), false);
  const checkpoint = { kind: 'audit-checkpoint-1', runId: 'r', checkpointDigest: 'sha256:cp', proposal: { auditor: { name: 'Maker' }, findings }, context: { standard } };
  const c = renderAuditReportHtml(checkpoint);
  assert.match(c, /draft checkpoint/); assert.match(c, /nothing here has been submitted/);
  assert.equal(normalizeAuditReport(checkpoint).findings[0].status, 'needs_review');
});

test('page-derived strings are escaped everywhere and unsafe links are never emitted', () => {
  const evil = '"><script>alert(1)</script><img src=x onerror=alert(2)>';
  const bad = finding('x', '4.1.2', { title: evil, observation: evil, reason: evil, scope: evil, method: evil, target: { evidenceId: evil, nodeId: evil }, evidenceIds: [evil] });
  const report = reviewed([bad], { queue: ['x'], decisions: [{ ...decision('x', 'insufficient'), reason: evil }] });
  report.verificationQueue[0].targetObservation = { selector: [evil, `a[href="javascript:alert(3)"]`] };
  report.verificationQueue[0].missingEvidence = [evil];
  Object.assign(report, { auditor: { name: evil }, reviewer: { name: evil }, runId: evil, reportDigest: evil, manifest: { url: evil }, standard: { version: evil, targetLevel: evil } });
  report.coverage = [{ id: '4.1.2', level: evil, status: 'x', url: 'javascript:alert(4)' }];
  const html = renderAuditReportHtml(report);
  assert.equal(html.includes('<script'), false); assert.equal(html.includes('<img src=x'), false);
  const tags = html.match(/<[^>]*>/g).map(tag => tag.replace(/^<\/?([a-z0-9]+)[\s\S]*$/i, '$1').toLowerCase());
  assert.deepEqual([...new Set(tags)].filter(tag => !['<!doctype html>', 'html', 'head', 'meta', 'title', 'style', 'body', 'header', 'h1', 'h2', 'h3', 'h4', 'p', 'strong', 'dl', 'dt', 'dd', 'code', 'main', 'section', 'ul', 'ol', 'li', 'b', 'article', 'span', 'small', 'a', 'footer',
    'div', 'nav', 'details', 'summary', 'table', 'caption', 'thead', 'tbody', 'tr', 'th', 'td', 'time', 'i'].includes(tag)), [], 'only fixed markup is emitted');
  assert.equal(/<[a-z]+[^>]*\s(?:on\w+|src)=[^>]*>/i.test(html.replace(/<meta[^>]*>/, '')), false);
  assert.deepEqual([...html.matchAll(/\shref="([^"]*)"/g)].map(hit => hit[1]).filter(href => !/^#[\w.:-]+$/.test(href)), [], 'only same-document fragment links');
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.equal(html.includes('javascript:alert(4)'), false); assert.equal(/<a href="(?!#)/.test(html), false);
  const safe = renderAuditReportHtml({ ...report, coverage: [{ id: '4.1.2', level: 'AA', url: 'https://www.w3.org/TR/WCAG22/#robust' }] });
  assert.match(safe, /<a href="https:\/\/www\.w3\.org\/TR\/WCAG22\/#robust" rel="noreferrer noopener">SC 4\.1\.2/);
  assert.equal(/<a href="https:\/\/www\.w3\.org[^"]*"[^>]*>[^<]*<\/a>/.test(safe), true);
});

test('long text and huge finding lists are capped', () => {
  const big = finding('big', '1.1.1', { observation: 'x'.repeat(REPORT_LIMITS.text * 20) });
  const html = renderAuditReportHtml(reviewed([big], { queue: ['big'] }));
  assert.ok(html.length < 30000); assert.match(html, /\[truncated\]/);
  const many = Array.from({ length: REPORT_LIMITS.findings + 5 }, (_, i) => finding(`m${i}`, '1.1.1'));
  const page = renderAuditReportHtml({ ...reviewed(many), verificationQueue: [] });
  assert.equal(page.match(/<article class="finding"/g).length, REPORT_LIMITS.findings);
  assert.match(page, new RegExp(`Showing the first ${REPORT_LIMITS.findings} of ${REPORT_LIMITS.findings + 5} findings`));
  assert.match(page, new RegExp(`<b>${REPORT_LIMITS.findings + 5}</b><span>findings`));
});

test('rejects files that are not audit checkpoints, proposals or reviews', () => {
  for (const value of [null, [], {}, { kind: 'audit' }, { kind: 'audit-review' }]) assert.throws(() => renderAuditReportHtml(value), { code: 'INVALID_AUDIT_REPORT' });
});

function png(width, height, pad = 0) {
  const crc = bytes => { let c = ~0; for (const b of bytes) { c ^= b; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0); } return ~c >>> 0; };
  const chunk = (type, data) => { const body = Buffer.concat([Buffer.from(type), data]), out = Buffer.alloc(body.length + 8); out.writeUInt32BE(data.length); body.copy(out, 4); out.writeUInt32BE(crc(body), body.length + 4); return out; };
  const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height); header[8] = 8; header[9] = 2;
  const raw = Buffer.alloc((width * 3 + 1) * height, 7);
  return Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), chunk('IHDR', header), chunk('IDAT', deflateSync(raw)), chunk('tEXt', Buffer.alloc(pad, 65)), chunk('IEND', Buffer.alloc(0))]);
}
async function evidenceDir(t, files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-report-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  for (const [name, value] of Object.entries(files)) await fs.writeFile(path.join(dir, name), value);
  return dir;
}
const record = (id, bytes, extra = {}) => ({ evidenceId: id, png: { sha256: createHash('sha256').update(bytes).digest('hex'), width: 2, height: 2, bytes: bytes.length, ...extra } });

test('screenshots are opt-in, verified against their SHA-256, and capped per image and in total', async t => {
  const small = png(2, 2), big = png(2, 2, REPORT_LIMITS.imageBytes), tampered = png(3, 3);
  const dir = await evidenceDir(t, {
    'ev-0001.json': JSON.stringify({ ...record('ev-0001', small), result: { nodes: [{ nodeId: 'doc-1:a', selector: '#resolved', value: SENTINEL, attributes: { value: SENTINEL } }] } }),
    'ev-0001.png': small,
    'ev-0002.json': JSON.stringify(record('ev-0002', big)), 'ev-0002.png': big,
    'ev-0003.json': JSON.stringify(record('ev-0003', small)), 'ev-0003.png': tampered,
    'ev-0004.json': JSON.stringify(record('ev-0004', small)), 'ev-0004.png': Buffer.from('not a png'),
  });
  const report = { kind: 'audit-checkpoint-1', proposal: { auditor: { name: 'M' }, findings: [finding('a', '1.4.3', { evidenceIds: ['ev-0001', 'ev-0002', 'ev-0003', 'ev-0004', '../../etc/passwd'] })] } };
  const file = path.join(dir, 'audit-checkpoint-00000001.json'); await fs.writeFile(file, JSON.stringify(report));
  const off = await loadReportContext(file, report);
  assert.equal(off.images.size, 0); assert.equal(off.selectors.get('ev-0001|doc-1:a'), '#resolved');
  const on = await loadReportContext(file, report, { screenshots: true });
  assert.deepEqual([...on.images.keys()], ['ev-0001']);
  assert.match(on.imageNotes.join(' '), /3 screenshots were not embedded/);
  const html = renderAuditReportHtml(report, on);
  assert.equal(html.match(/<img /g).length, 1); assert.ok(html.includes(small.toString('base64')));
  assert.match(html, /<code>#resolved<\/code>/);
  assert.equal(html.includes(SENTINEL), false);

  const many = Object.fromEntries(Array.from({ length: REPORT_LIMITS.images + 3 }, (_, i) => {
    const id = `ev-${String(i + 10).padStart(4, '0')}`; return [[`${id}.json`, JSON.stringify(record(id, small))], [`${id}.png`, small]];
  }).flat());
  const dir2 = await evidenceDir(t, many);
  const ids = Array.from({ length: REPORT_LIMITS.images + 3 }, (_, i) => `ev-${String(i + 10).padStart(4, '0')}`);
  const report2 = { kind: 'audit-checkpoint-1', proposal: { auditor: { name: 'M' }, findings: [finding('a', '1.4.3', { evidenceIds: ids, target: { evidenceId: ids[0], nodeId: 'n' } })] } };
  const capped = await loadReportContext(path.join(dir2, 'audit-checkpoint-00000001.json'), report2, { screenshots: true });
  assert.equal(capped.images.size, REPORT_LIMITS.images);
});

test('a screenshot cited by several findings is embedded once, and linked sidecars are ignored', async t => {
  const shot = png(2, 2), outside = await evidenceDir(t, { 'outside.png': shot, 'outside.json': JSON.stringify(record('ev-0002', shot)) });
  const dir = await evidenceDir(t, { 'ev-0001.json': JSON.stringify(record('ev-0001', shot)), 'ev-0001.png': shot });
  await fs.symlink(path.join(outside, 'outside.png'), path.join(dir, 'ev-0002.png'));
  await fs.symlink(path.join(outside, 'outside.json'), path.join(dir, 'ev-0002.json'));
  const report = { kind: 'audit-checkpoint-1', proposal: { auditor: { name: 'M' }, findings: ['a', 'b', 'c'].map(id => finding(id, '1.4.3', { evidenceIds: ['ev-0001', 'ev-0001', 'ev-0001', 'ev-0002'] })) } };
  const context = await loadReportContext(path.join(dir, 'audit-checkpoint-00000001.json'), report, { screenshots: true });
  assert.deepEqual([...context.images.keys()], ['ev-0001']);
  const html = renderAuditReportHtml(report, context);
  assert.equal(html.match(/<img /g).length, 1); assert.equal(html.split(shot.toString('base64')).length - 1, 1);
  assert.equal(html.match(/is shown under an earlier finding/g).length, 2);
});

test('redaction is preserved: only whitelisted report fields reach the HTML', () => {
  const dirty = finding('p', '3.3.2', { value: SENTINEL, html: `<input value="${SENTINEL}">`, fillValue: SENTINEL, attributes: { value: SENTINEL } });
  const report = reviewed([dirty], { queue: ['p'] });
  Object.assign(report.verificationQueue[0], { value: SENTINEL, html: SENTINEL, targetObservation: { selector: '#pw', value: SENTINEL, attributes: { value: SENTINEL } } });
  Object.assign(report, { records: [{ result: { nodes: [{ value: SENTINEL }] } }], candidates: [{ targets: [{ html: SENTINEL }] }] });
  const html = renderAuditReportHtml(report);
  assert.equal(html.includes(SENTINEL), false); assert.match(html, /<code>#pw<\/code>/);
});

// End to end with a real browser: a password field's value must never reach the HTML.
const page = `<!doctype html><html lang="en"><head><title>Report e2e</title></head><body><main><h1>Report e2e</h1>
<button id="one"></button><input id="secret" type="password" value="${SENTINEL}" aria-label="Secret"></main></body></html>`;
test('a real session renders to HTML from its checkpoint, proposal and review, and the CLI writes the file', async t => {
  let agent;
  t.after(() => agent?.close()); // registered before the fixture so it runs before the project directory is removed
  const site = await fixture(t, page);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  const step = await agent.request({ tool: 'step', actions: [{ action: 'axe' }, { action: 'screenshot' }, { action: 'snapshot' }] });
  assert.equal(step.success, true, JSON.stringify(step));
  const button = step.axe[0].candidates.find(row => row.ruleId === 'button-name');
  const mine = finding('mine', '4.1.2', { target: { evidenceId: 'ev-0003', nodeId: button.nodeId.replace(/^/, '') }, evidenceIds: ['ev-0003'] });
  const snapshot = JSON.parse(await fs.readFile(path.join(agent.directory, 'ev-0003.json'), 'utf8'));
  const secret = snapshot.result.nodes.find(node => node.attributes?.id === 'secret');
  mine.target.nodeId = secret.nodeId; mine.observation = 'The password field is present.'; mine.evidenceIds = ['ev-0002', 'ev-0003'];
  const draft = await agent.request({ tool: 'checkpoint', proposal: { auditor: { name: 'E2E maker' }, adoptAxe: 'all', findings: [mine] } });
  assert.equal(draft.success, true, JSON.stringify(draft));

  const out = path.join(site.projectRoot, 'evidence', 'report.html');
  const checkpoint = await writeAuditReport(draft.checkpoint.checkpointPath, out, { screenshots: true });
  assert.equal(checkpoint.screenshotsEmbedded, 1); assert.ok(checkpoint.findings >= 2);
  let html = await fs.readFile(out, 'utf8');
  assert.match(html, /axe-adopted/); assert.match(html, /agent-found/); assert.match(html, /<img /); assert.match(html, /<code>#one<\/code>/);
  assert.equal(html.includes(SENTINEL), false);

  const submitted = await agent.request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  const proposal = JSON.parse(await fs.readFile(submitted.proposalReportPath, 'utf8'));
  const review = await reviewAudit(proposal.reportPath, { reviewer: { name: 'E2E reviewer', independentOfAuditor: true }, decisions: proposal.findings.map(row => decision(row.id)) });
  const reviewPath = review.reportPath;
  const run = spawnSync(process.execPath, [cli, 'audit-report', reviewPath, '--out', out], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  const summary = JSON.parse(run.stdout); assert.equal(summary.source, 'reviewed'); assert.equal(summary.screenshotsEmbedded, 0);
  html = await fs.readFile(out, 'utf8');
  assert.match(html, /independently reviewed/); assert.match(html, /Confirmed|Needs review/); assert.equal(html.includes(SENTINEL), false);

  const bad = spawnSync(process.execPath, [cli, 'audit-report', reviewPath, '--out', reviewPath], { encoding: 'utf8' });
  assert.equal(bad.status, 1); assert.equal(JSON.parse(bad.stdout).errors[0].code, 'INVALID_AUDIT_REPORT');
  const usage = spawnSync(process.execPath, [cli, 'audit-report'], { encoding: 'utf8' });
  assert.equal(usage.status, 1); assert.equal(JSON.parse(usage.stdout).errors[0].code, 'USAGE');
});

// Local-only bounded delivery tests: no browser, network or model calls.
for (const size of [0, 1, 50, 51, 975]) {
  test(`bounded delivery preserves ${size} original records, exact order, counts and relative links`, () => {
    const findings = Array.from({ length: size }, (_, i) => finding(`original-${i}`, i % 2 ? '1.1.1' : '4.1.2', { source: i % 2 ? 'axe' : 'agent' }));
    const report = reviewed(findings, { confirmed: size ? ['original-0'] : [], queue: size > 1 ? ['original-1'] : [],
      rejected: size > 2 ? ['original-2'] : [], decisions: size > 1 ? [decision('original-1', 'insufficient')] : [] });
    const pages = renderBoundedAuditReportHtml(report);
    assert.equal(pages.length, 1 + Math.ceil(size / 50));
    const cards = pages.slice(1).map(page => page.html).join('\n');
    assert.deepEqual([...cards.matchAll(/<article class="finding" id="f-([^"]+)"/g)].map(hit => hit[1]), findings.map(row => row.id));
    assert.equal(new Set([...cards.matchAll(/id="f-([^"]+)"/g)].map(hit => hit[1])).size, size);
    for (const page of pages) {
      assert.ok(Buffer.byteLength(page.html, 'utf8') < 500000);
      assert.ok((page.html.match(/<article class="finding"/g) ?? []).length <= 50);
      assert.match(page.html, new RegExp(`<b>${size}</b><span>findings`));
      assert.match(page.html, new RegExp(`axe-adopted</dt><dd>${Math.floor(size / 2)}</dd>`));
      assert.match(page.html, /Not a conformance certification/);
      assert.match(page.html, /Screen readers .* were not used/);
      assert.doesNotMatch(page.html, /<script|<link|<iframe|<img/);
      const ids = new Set([...page.html.matchAll(/\sid="([^"]+)"/g)].map(hit => hit[1]));
      for (const [, href] of page.html.matchAll(/href="([^"]+)"/g)) assert.ok(pages.some(other => other.name === href) || (href.startsWith('#') && ids.has(href.slice(1))), href);
    }
    assert.equal((pages[0].html.match(/href="findings-\d+\.html"/g) ?? []).length, pages.length - 1);
    for (const page of pages.slice(1)) assert.match(page.html, /href="index.html"/);
    for (const row of findings) {
      const card = cards.split(`id="f-${row.id}"`)[1].split('</article>')[0];
      for (const text of [row.observation, row.reason, row.scope, row.method, row.target.nodeId, 'ev-0001', 'Reproduce']) assert.ok(card.includes(text), text);
    }
    if (size > 2) { assert.match(cards, /Confirmed/); assert.match(cards, /Needs review/); assert.match(cards, /Review verdict<\/dt><dd>insufficient/); assert.match(cards, /Rejected by reviewer/); }
  });
}

test('bounded byte packing measures full escaped Unicode text and refuses oversized singletons', () => {
  const text = '😀<&€"'.repeat(12000);
  const report = reviewed([finding('unicode', '4.1.2', { observation: text, value: SENTINEL }), finding('next', '1.1.1', { observation: text })]);
  const pages = renderBoundedAuditReportHtml(report);
  assert.equal(pages.length, 3, 'byte limit forces a split before the card count limit');
  for (const page of pages.slice(1)) {
    assert.ok(Buffer.byteLength(page.html) < 500000);
    assert.ok(page.html.includes('😀&lt;&amp;€&quot;'.repeat(12000)));
    assert.doesNotMatch(page.html, /\[truncated\]/); assert.ok(!page.html.includes(SENTINEL));
  }
  assert.throws(() => renderBoundedAuditReportHtml(reviewed([finding('too-big', '1.1.1', { observation: text.repeat(5) })])), /record 1 cannot fit/);
});

test('bounded screenshots keep loader caps and count embedded bytes, without omitting oversized cards', async t => {
  const small = png(2, 2), large = png(2, 2, 400000);
  const report = reviewed([finding('image', '1.1.1')]);
  const dir = await evidenceDir(t, { 'ev-0001.json': JSON.stringify(record('ev-0001', small)), 'ev-0001.png': small });
  const context = await loadReportContext(path.join(dir, 'report.json'), report, { screenshots: true });
  const pages = renderBoundedAuditReportHtml(report, context);
  assert.match(pages[1].html, /data:image\/png;base64,/);
  assert.ok(Buffer.byteLength(pages[1].html) < 500000);
  await fs.writeFile(path.join(dir, 'ev-0001.json'), JSON.stringify(record('ev-0001', large)));
  await fs.writeFile(path.join(dir, 'ev-0001.png'), large);
  const bigContext = await loadReportContext(path.join(dir, 'report.json'), report, { screenshots: true });
  assert.equal(bigContext.images.size, 1, 'within existing image cap');
  assert.throws(() => renderBoundedAuditReportHtml(report, bigContext), /cannot fit/);
});

test('bounded CLI requires a fresh directory and validates before writing; default single-file remains available', async t => {
  const dir = await evidenceDir(t, {}), input = path.join(dir, 'report.json'), out = path.join(dir, 'pages');
  const report = reviewed([finding('a', '1.1.1')]);
  await fs.writeFile(input, JSON.stringify(report));
  const invoke = (...args) => spawnSync(process.execPath, [cli, 'audit-report', input, ...args], { encoding: 'utf8' });
  assert.equal(invoke('--bounded').status, 1);
  const run = invoke('--bounded', '--out', out);
  assert.equal(run.status, 0, run.stdout + run.stderr);
  const receipt = JSON.parse(run.stdout);
  assert.equal(receipt.outPath, path.join(out, 'index.html')); assert.equal(receipt.artifacts.length, 2);
  const before = await fs.readFile(receipt.outPath);
  assert.equal(invoke('--bounded', '--out', out).status, 1);
  assert.deepEqual(await fs.readFile(receipt.outPath), before);
  const single = path.join(dir, 'single.html');
  assert.equal(invoke('--out', single).status, 0);
  assert.equal(await fs.readFile(single, 'utf8'), renderAuditReportHtml(report, await loadReportContext(input, report)));
  await fs.writeFile(input, JSON.stringify(reviewed([finding('big', '1.1.1', { observation: '&'.repeat(150000) })])));
  await assert.rejects(writeAuditReport(input, path.join(dir, 'never-created'), { bounded: true }), /cannot fit/);
  await assert.rejects(fs.stat(path.join(dir, 'never-created')), { code: 'ENOENT' });
  await assert.rejects(writeAuditReport(input, out, { bounded: true }), /cannot fit/);
  assert.deepEqual(await fs.readFile(receipt.outPath), before);
});

test('bounded limit is strict at exactly 500000 UTF-8 bytes, with no text or missing-evidence truncation', () => {
  const report = reviewed([finding('edge', '1.1.1', { observation: '' })], { queue: ['edge'], decisions: [decision('edge', 'insufficient')] });
  report.verificationQueue[0].missingEvidence = Array.from({ length: 25 }, (_, i) => `Missing item ${i}`);
  const initial = renderBoundedAuditReportHtml(report)[1].html;
  assert.match(initial, /Missing item 24/);
  const room = 500000 - Buffer.byteLength(initial);
  report.findings[0].observation = 'x'.repeat(room - 1);
  assert.equal(Buffer.byteLength(renderBoundedAuditReportHtml(report)[1].html), 499999);
  report.findings[0].observation += 'x';
  assert.throws(() => renderBoundedAuditReportHtml(report), /cannot fit/);
});

test('HTML delivery protects input and referenced originals across filesystem aliases', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'report-alias-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const input = path.join(dir, 'input.json'), bytes = JSON.stringify(reviewed([]));
  await fs.writeFile(input, bytes);
  const aliasParent = path.join(dir, 'alias'); await fs.symlink(dir, aliasParent);
  for (const kind of ['same', 'symlink', 'hardlink', 'parent']) {
    const out = kind === 'same' ? input : kind === 'parent' ? path.join(aliasParent, 'input.json') : path.join(dir, kind + '.html');
    if (kind === 'symlink') await fs.symlink(input, out);
    if (kind === 'hardlink') await fs.link(input, out);
    await assert.rejects(writeAuditReport(input, out));
    assert.equal(await fs.readFile(input, 'utf8'), bytes);
  }
  for (const name of ['audit.json', 'proposal.json', 'checkpoint.json', 'ev-0001.json', 'ev-0001.png']) {
    const target = path.join(dir, name), original = name.endsWith('.json') ? '{}' : 'original'; await fs.writeFile(target, original);
    const report = { ...reviewed([]), sourceAudit: { reportPath: path.join(dir, 'audit.json') }, sourceProposal: { reportPath: path.join(dir, 'proposal.json') }, sourceCheckpoint: { checkpointPath: path.join(dir, 'checkpoint.json') }, records: [{ evidenceId: 'ev-0001', json: { path: path.join(dir, 'ev-0001.json') }, png: { path: path.join(dir, 'ev-0001.png') } }] };
    await fs.writeFile(input, JSON.stringify(report));
    await assert.rejects(writeAuditReport(input, target));
    assert.equal(await fs.readFile(target, 'utf8'), original);
  }
  await assert.rejects(writeAuditReport(path.join(aliasParent, 'input.json'), path.join(aliasParent, 'new.html')));
  await assert.rejects(writeAuditReport(input, path.join(aliasParent, 'new-dir', 'new.html')));
  const out = path.join(dir, 'report.html');
  await writeAuditReport(input, out); await writeAuditReport(input, out);
  assert.match(await fs.readFile(out, 'utf8'), /^<!doctype html>/);
  assert.equal((await fs.readdir(dir)).some(name => name.includes('.tmp-')), false);
});

test('atomic HTML replacement cleans its exclusive temp after rename failure', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'report-write-failure-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const input = path.join(dir, 'input.json'), out = path.join(dir, 'directory.html');
  await fs.writeFile(input, JSON.stringify(reviewed([]))); await fs.mkdir(out);
  const before = await fs.readdir(dir);
  await assert.rejects(writeAuditReport(input, out));
  assert.deepEqual(await fs.readdir(dir), before);
});

for (const variant of ['small', 'extensionless', 'oversized']) {
  test(`recursive HTML protection scans ${variant} JSON references before output`, async t => {
    const dir = await evidenceDir(t, {});
    await fs.mkdir(path.join(dir, 'nested'));
    const original = path.join(dir, 'nested', 'original.png'), bytes = png(2, 2);
    const collection = path.join(dir, variant === 'extensionless' ? 'collection' : 'collection.json');
    const document = JSON.stringify({ records: [{ png: { path: original } }] });
    await fs.writeFile(original, bytes);
    await fs.writeFile(collection, document);
    if (variant === 'oversized') await fs.appendFile(collection, ' '.repeat(64 * 1024 * 1024));
    const input = path.join(dir, 'input.json');
    await fs.writeFile(input, JSON.stringify({ kind: 'audit-proposal', findings: [], sourceAudit: { reportPath: collection } }));
    const alias = path.join(dir, 'original-hardlink.html'); await fs.link(original, alias);
    const before = await fs.readdir(dir, { recursive: true });
    for (const out of [original, alias]) {
      await assert.rejects(writeAuditReport(input, out), { code: 'INVALID_AUDIT_REPORT' });
      assert.deepEqual(await fs.readFile(original), bytes);
      assert.deepEqual(await fs.readdir(dir, { recursive: true }), before, 'no owned temporary files remain');
    }
    const out = path.join(dir, 'report.html');
    if (variant === 'oversized') {
      await assert.rejects(writeAuditReport(input, out), /Cannot scan referenced JSON/);
      await assert.rejects(writeAuditReport(input, path.join(dir, 'new', 'pages'), { bounded: true }), /Cannot scan referenced JSON/);
      assert.deepEqual(await fs.readdir(dir, { recursive: true }), before, 'scan failure creates no output or directories');
    } else {
      await writeAuditReport(input, out);
      const oldHtml = await fs.readFile(out), oldInode = path.join(dir, 'old-html');
      await fs.link(out, oldInode);
      await writeAuditReport(input, out);
      assert.deepEqual(await fs.readFile(oldInode), oldHtml);
      assert.notEqual((await fs.stat(out)).ino, (await fs.stat(oldInode)).ino);
    }
  });
}

test('recursive HTML protection fails closed for invalid JSON and unreadable JSON references', async t => {
  const dir = await evidenceDir(t, {}), input = path.join(dir, 'input.json');
  const reference = path.join(dir, 'attachment');
  await fs.writeFile(input, JSON.stringify({ kind: 'audit-proposal', findings: [], records: [{ json: { path: reference } }] }));
  for (const shape of ['invalid', 'directory', 'loop']) {
    if (shape === 'invalid') await fs.writeFile(reference, '{');
    if (shape === 'directory') await fs.mkdir(reference);
    if (shape === 'loop') await fs.symlink(reference, reference);
    const before = await fs.readdir(dir);
    await assert.rejects(writeAuditReport(input, path.join(dir, 'out.html')), /Cannot scan referenced JSON/);
    assert.deepEqual(await fs.readdir(dir), before);
    await fs.rm(reference, { recursive: true });
  }
  // Missing optional JSON/PNG sidecars still permit projection-only delivery.
  await writeAuditReport(input, path.join(dir, 'out.html'));
});

test('typed checkpoint and JSON attachments are scanned after an earlier untyped reference', async t => {
  for (const key of ['checkpointPath', 'json']) {
    const dir = await evidenceDir(t, {}), input = path.join(dir, 'input.json');
    const nested = path.join(dir, 'opaque'), original = path.join(dir, 'original-record');
    const bytes = '{"original":true}';
    await fs.writeFile(original, bytes);
    await fs.writeFile(nested, JSON.stringify({ records: [{ json: { path: original } }] }));
    const typed = key === 'json' ? { json: { path: nested } } : { checkpointPath: nested };
    await fs.writeFile(input, JSON.stringify({ kind: 'audit-proposal', findings: [], other: { path: nested }, source: typed }));
    await assert.rejects(writeAuditReport(input, original), { code: 'INVALID_AUDIT_REPORT' });
    assert.equal(await fs.readFile(original, 'utf8'), bytes);
    assert.equal((await fs.readdir(dir)).some(name => name.includes('.tmp-')), false);
  }
});


test('queue verdict stays distinct from product status for all seven reviewed rows', () => {
  const findings = Array.from({ length: 12 }, (_, i) => finding(`q${i}`, '4.1.2'));
  const report = reviewed(findings, { confirmed: findings.slice(0, 5).map(f => f.id), queue: findings.slice(5).map(f => f.id),
    decisions: findings.map((f, i) => decision(f.id, i < 5 ? 'supported' : 'insufficient')) });
  const html = renderAuditReportHtml(report);
  assert.match(html, /Confirmed<\/dt><dd>5<\/dd>/); assert.match(html, /Rejected<\/dt><dd>0<\/dd>/); assert.match(html, /Needs review<\/dt><dd>7<\/dd>/);
  assert.equal((html.match(/badge s-needs_review/g) ?? []).length, 7);
  assert.equal((html.match(/Review verdict<\/dt><dd>insufficient/g) ?? []).length, 7);
  for (const f of findings.slice(5)) assert.ok(html.includes(`Reviewer ${f.id}`));
  assert.equal(normalizeAuditReport(report).findings.filter(f => f.status === 'needs_review').length, 7);
});

test('inventory and original attachment paths are separate from finding counts and escaped', () => {
  const report = reviewed([finding('adopted', '4.1.2', { source: 'axe', axeCandidateId: 'ev-0001:rule:0' })]);
  const inventory = Array.from({ length: 11 }, (_, i) => ({ observationId: `obs${i}`, evidenceId: 'ev-0001', ruleId: 'rule', ruleNodeIndex: i,
    bucket: 'violations', target: ['#x<script>'], binding: { status: 'bound', nodeId: 'doc-1:adopted' }, authorDisposition: { status: 'unresolved' } }));
  const html = renderAuditReportHtml(report, { inventory, references: [{ evidenceId: 'ev-0001', json: '../original/ev-0001.json', png: '../original/ev-0001.png', source: 'collection.records' }] });
  assert.equal((html.match(/class="inventory-row"/g) ?? []).length, 11);
  assert.match(html, /Author disposition<\/dt><dd>unresolved/); assert.match(html, /Adopted as/);
  assert.match(html, /Not explicitly linked/); assert.match(html, /DOM binding<\/dt><dd>bound/);
  assert.match(html, /not additional defects/); assert.match(html, /<b>1<\/b><span>findings/);
  assert.match(html, /relative to <code class="base">\.\.\/original\/<\/code>/); assert.match(html, /<td><code>ev-0001\.json<\/code><\/td><td><code>ev-0001\.png<\/code><\/td>/);
  assert.equal(html.includes('<script>'), false); assert.equal(html.includes('<img '), false);
  assert.match(renderAuditReportHtml(report), /Original JSON path not recorded/);
  assert.equal(renderAuditReportHtml(report).includes('class="inventory-row"'), false);
});


test('loader uses recorded collection paths relative to output and does not invent absent PNG paths', async t => {
  const dir = await evidenceDir(t, {});
  const report = reviewed([finding('a', '4.1.2')]);
  report.collection = { reportPath: 'originals/collection.json' };
  await fs.mkdir(path.join(dir, 'originals'));
  const collection = { kind: 'audit', runId: report.runId, reportPath: path.join(dir, 'originals/collection.json'), standard: { criteria: [] },
    records: [{ evidenceId: 'ev-0001', json: { path: 'record.json' }, png: { path: 'pixels.png' } }, { evidenceId: 'ev-0002' }] };
  await fs.writeFile(collection.reportPath, JSON.stringify(collection));
  const context = await loadReportContext(path.join(dir, 'reviewed.json'), report, { outputDirectory: path.join(dir, 'delivery') });
  assert.deepEqual(context.references[0], { evidenceId: 'ev-0001', json: '../originals/record.json', png: '../originals/pixels.png', source: 'collection.records' });
  assert.equal(context.references[1].json, null); assert.equal(context.references[1].png, null);
  const html = renderAuditReportHtml(report, context);
  assert.match(html, /Original PNG path not recorded/); assert.equal(html.includes('<img '), false);
  await fs.unlink(collection.reportPath);
  const missing = await loadReportContext(path.join(dir, 'reviewed.json'), report);
  assert.equal(missing.references.length, 0); assert.equal(missing.inventory.length, 0);
  assert.match(renderAuditReportHtml(report, missing), /Referenced collection unavailable/);
});

// Report layout: landmarks, headings, disclosures, tables and styling constraints, checked on the rendered markup.
function structure(html) {
  const headings = [...html.matchAll(/<h([1-6])[\s>]/g)].map(hit => Number(hit[1]));
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map(hit => hit[1]);
  return { headings, ids, idSet: new Set(ids),
    labelledby: [...html.matchAll(/aria-labelledby="([^"]+)"/g)].map(hit => hit[1]),
    hrefs: [...html.matchAll(/\shref="([^"]+)"/g)].map(hit => hit[1]) };
}

test('layout has one skip link to a single main, ordered headings, resolvable labels and links, and one disclosure per collapsed field', () => {
  const findings = [finding('a', '4.1.2', { source: 'axe', axeCandidateId: 'ev-0001:rule:0' }), finding('b', '1.4.3'), finding('c', '1.4.3')];
  const report = reviewed(findings, { confirmed: ['a'], queue: ['b'], decisions: [decision('a'), decision('b', 'insufficient')] });
  const inventory = [{ observationId: 'obs0', evidenceId: 'ev-0001', ruleId: 'rule', ruleNodeIndex: 0, bucket: 'violations', target: ['#a'], binding: { status: 'bound' } }];
  const references = [{ evidenceId: 'ev-0001', json: 'run/ev-0001.json', png: null, source: 'collection.records' }];
  const html = renderAuditReportHtml(report, { inventory, references, imageNotes: ['Screenshots were not embedded (use --screenshots).'] });
  const { headings, ids, idSet, labelledby, hrefs } = structure(html);
  assert.ok(html.indexOf('<a class="skip" href="#main">') < html.indexOf('<a ', html.indexOf('<a class="skip"') + 1), 'skip link is the first link');
  assert.equal((html.match(/<main[\s>]/g) ?? []).length, 1); assert.match(html, /<main id="main" tabindex="-1">/);
  assert.equal((html.match(/<header class="masthead">/g) ?? []).length, 1); assert.equal((html.match(/<footer/g) ?? []).length, 1);
  assert.equal(headings[0], 1); assert.equal(headings.filter(level => level === 1).length, 1);
  headings.forEach((level, i) => assert.ok(i === 0 || level <= headings[i - 1] + 1, `heading h${level} after h${headings[i - 1]}`));
  assert.equal(ids.length, idSet.size, 'unique ids');
  for (const id of labelledby) assert.ok(idSet.has(id), `aria-labelledby ${id}`);
  for (const href of hrefs) assert.ok(href.startsWith('#') ? idSet.has(href.slice(1)) : /^https:\/\/www\.w3\.org\//.test(href), href);
  // Reproduce, Why and Evidence on every card, Missing only where something is missing, plus the inventory box.
  const expected = findings.length * 3 + normalizeAuditReport(report).findings.filter(row => row.missing.length).length + 1;
  assert.equal((html.match(/<details[\s>]/g) ?? []).length, expected);
  assert.equal((html.match(/<summary>/g) ?? []).length, expected);
  assert.match(html, /<summary>Why it may fail the criterion <span class="dm">\(author&#39;s claim\)<\/span><\/summary>/);
  assert.match(html, /<details class="box"><summary>Show all 1 observation record<\/summary>/);
  for (const table of html.match(/<table>[\s\S]*?<\/table>/g)) {
    assert.match(table, /^<table><caption>/); assert.match(table, /<th scope="col">/); assert.match(table, /<th scope="row">/);
    assert.doesNotMatch(table, /<th>/);
  }
  assert.equal((html.match(/<table>/g) ?? []).length, 2);
  // Status and source are carried by text as well as colour.
  assert.match(html, /<li class="badge s-confirmed status">Confirmed<\/li>/); assert.match(html, /<span class="k">Source:<\/span> axe-adopted/);
  assert.match(html, /<div class="bar" aria-hidden="true">/);
  assert.doesNotMatch(html, /<script|<link|<iframe|@import|url\(/i);
  assert.doesNotMatch(html, /\d(?:s|d|l)?vh\b/);
  assert.match(html, /default-src 'none'; img-src data:; style-src 'unsafe-inline'/);
  assert.match(html, /<dt>Review verdict<\/dt><dd>supported<\/dd>/, 'review outcomes stay outside disclosures');
});

const luminance = hex => {
  const [r, g, b] = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255).map(c => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a, b) => { const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };

test('every drawn colour pair meets its WCAG ratio in light and dark, computed from the same tokens the CSS uses', () => {
  assert.equal(REPORT_CONTRAST_PAIRS.length, 32);
  for (const theme of ['light', 'dark']) {
    const tokens = REPORT_TOKENS[theme];
    for (const [fg, bg, role, required] of REPORT_CONTRAST_PAIRS) {
      assert.ok(tokens[fg] && tokens[bg], `${theme} ${fg}/${bg}`);
      const ratio = contrast(tokens[fg], tokens[bg]);
      assert.ok(ratio >= required, `${theme} ${role}: ${fg} on ${bg} is ${ratio.toFixed(2)}:1, needs ${required}:1`);
    }
    for (const [name, value] of Object.entries(tokens)) assert.ok(REPORT_CSS.includes(`--${name}:${value}`), `${theme} --${name}`);
  }
  assert.deepEqual(Object.keys(REPORT_TOKENS.light), Object.keys(REPORT_TOKENS.dark));
  assert.match(REPORT_CSS, /@media \(prefers-color-scheme:dark\)/); assert.match(REPORT_CSS, /@media \(forced-colors:active\)/);
  assert.match(REPORT_CSS, /@media \(prefers-reduced-motion:reduce\)/); assert.match(REPORT_CSS, /@media print\{details::details-content\{content-visibility:visible/);
  assert.ok(renderAuditReportHtml(reviewed([])).includes(REPORT_CSS));
});

test('criterion names come from the catalog, then the static WCAG table, else only the number', async () => {
  for (const file of ['wcag21-aa.json', 'wcag22-aa.json']) {
    const catalog = JSON.parse(await fs.readFile(fileURLToPath(new URL(`../src/${file}`, import.meta.url)), 'utf8'));
    for (const row of catalog.criteria) assert.ok(criterionName(row.id, row), `${file} ${row.id}`);
  }
  assert.equal(criterionName('4.1.2', {}), 'Name, Role, Value');
  assert.equal(criterionName('4.1.2', { title: 'Catalog title' }), 'Catalog title');
  assert.equal(criterionName('9.9.9', {}), null); assert.equal(criterionName('__proto__', {}), null);
  const report = reviewed([finding('a', '4.1.2'), finding('b', '9.9.9')]);
  report.coverage = [...coverage, { id: '9.9.9', level: 'AA', url: 'https://www.w3.org/TR/WCAG22/#x' }];
  const html = renderAuditReportHtml(report);
  assert.match(html, /<h3 id="sc-4\.1\.2"><a href="https:\/\/www\.w3\.org\/TR\/WCAG22\/#sc4\.1\.2" rel="noreferrer noopener">SC 4\.1\.2<\/a> <span class="sc-name">Name, Role, Value<\/span><\/h3>/);
  assert.match(html, /<h3 id="sc-9\.9\.9"><a href="[^"]+" rel="noreferrer noopener">SC 9\.9\.9<\/a><\/h3>/);
  report.coverage[3] = { ...report.coverage[3], title: '<Catalog> name' };
  assert.match(renderAuditReportHtml(report), /<span class="sc-name">&lt;Catalog&gt; name<\/span>/);
});

test('evidence source paths share a caption directory only when every path has it; otherwise rows keep full paths', () => {
  const report = reviewed([finding('a', '4.1.2')]);
  const shared = renderAuditReportHtml(report, { references: [
    { evidenceId: 'ev-0001', json: '../run/ev-0001.json', png: '../run/ev-0001.png', source: 'collection.records' },
    { evidenceId: 'ev-0002', json: '../run/ev-0002.json', png: null, source: 'collection.records' }] });
  assert.match(shared, /Source for every row: <code>collection\.records<\/code>\. File names below are relative to <code class="base">\.\.\/run\/<\/code>/);
  assert.match(shared, /<th scope="row"><code>ev-0002<\/code><\/th><td><code>ev-0002\.json<\/code><\/td><td class="na">Original PNG path not recorded<\/td>/);
  const mixed = renderAuditReportHtml(report, { references: [
    { evidenceId: 'ev-0001', json: '../run/ev-0001.json', png: '../other/ev-0001.png', source: 'collection.records' },
    { evidenceId: 'ev-0002', json: null, png: null, source: 'input report attachment metadata' }] });
  assert.match(mixed, /Each row names its source\. Paths are shown in full\./);
  assert.match(mixed, /<th scope="col">Source<\/th>/);
  assert.match(mixed, /<td><code>\.\.\/run\/ev-0001\.json<\/code><\/td><td><code>\.\.\/other\/ev-0001\.png<\/code><\/td>/);
  assert.doesNotMatch(mixed, /class="base"/);
  const flat = renderAuditReportHtml(report, { references: [{ evidenceId: 'ev-0001', json: 'ev-0001.json', png: 'ev-0001.png', source: 's' }] });
  assert.match(flat, /Paths are shown in full\./); assert.match(flat, /<code>ev-0001\.json<\/code>/);
});

test('inventory is collapsed behind derived counts and adoption links reach cards in the same document only', () => {
  const report = reviewed([finding('adopted', '4.1.2', { source: 'axe', axeCandidateId: 'ev-0001:rule:0' })]);
  const inventory = [0, 1].map(i => ({ observationId: `obs${i}`, evidenceId: 'ev-0001', ruleId: 'rule', ruleNodeIndex: i, bucket: 'violations', target: ['#x'],
    binding: { status: i ? 'unbound' : 'bound' }, authorDisposition: i ? { status: 'linked', findingIds: ['adopted'] } : { status: 'unresolved' } }));
  const html = renderAuditReportHtml(report, { inventory });
  assert.match(html, /<ul class="inv-stats" aria-label="Inventory counts"><li><b>2<\/b> observations<\/li><li><b>1<\/b> DOM-bound<\/li><li><b>1<\/b> adopted as findings<\/li><li><b>1<\/b> explicitly linked<\/li><li><b>1<\/b> disposition unresolved<\/li><\/ul>/);
  assert.ok(html.indexOf('<details class="box">') < html.indexOf('class="inventory-row"'));
  assert.doesNotMatch(html, /<details class="box" open/);
  assert.match(html, /Adopted as <a href="#f-adopted">adopted<\/a> \(from axeCandidateId\)/);
  const [, detail] = renderBoundedAuditReportHtml(report, { inventory });
  assert.match(detail.html, /Adopted as adopted \(from axeCandidateId\)/);
  assert.match(detail.html, /<article class="finding" id="f-adopted" aria-labelledby="ft-adopted">/);
  assert.match(detail.html, /<h3 id="rec-1"><span class="sc-id">SC 4\.1\.2<\/span> <span class="sc-name">Name, Role, Value<\/span><\/h3><span class="sc-meta">Level AA · original record 1 of 1<\/span>/);
});
