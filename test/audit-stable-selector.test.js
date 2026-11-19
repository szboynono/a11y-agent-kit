import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fixture } from './helpers.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { checkAudit } from '../src/audit/review.js';
import { saveAuditDocument } from '../src/audit/store.js';
import { MCP_TEXT_LIMIT } from '../src/audit/projection.js';
import { renderAuditReportHtml } from '../src/audit/report-html.js';
import { stableSelectorFor, inPageStableFields, generatedValue, usesGeneratedToken } from '../src/audit/stable-selector.js';

// Synthetic captured DOM: [tag, attributes, parent] rows -> one complete snapshot record of one state.
const DOC = 'doc-1', STATE = 'sha256:s1';
function snapshot(rows, { evidenceId = 'ev-0001', truncated = false, uncapturedAnchors } = {}) {
  const ids = new Map(rows.map((row, i) => [row.key, `${DOC}:n${String(i + 1).padStart(6, '0')}`]));
  const nodes = rows.map(row => ({ nodeId: ids.get(row.key), documentId: DOC, parentNodeId: row.parent ? ids.get(row.parent) : null,
    tag: row.tag, attributes: row.attributes ?? {}, selector: row.selector ?? `html:nth-of-type(1) > body:nth-of-type(1) > ${row.tag}:nth-of-type(${row.n ?? 1})` }));
  return { evidenceId, action: 'snapshot', success: true, before: { documentId: DOC, stateId: STATE }, after: { documentId: DOC, stateId: STATE },
    result: { nodes, truncation: { omittedVisibleElements: truncated ? 3 : 0 }, ...(uncapturedAnchors ? { uncapturedAnchors } : {}) } };
}
const target = (record, key, rows) => ({ evidenceId: record.evidenceId, nodeId: record.result.nodes[rows.findIndex(row => row.key === key)].nodeId });
const body = { key: 'body', tag: 'body', selector: 'html:nth-of-type(1) > body:nth-of-type(1)' };

test('generated ids and generated names are never used; an anchored path from a stable ancestor is used instead', () => {
  const rows = [body, { key: 'form', tag: 'form', attributes: { 'data-testid': 'profile' }, parent: 'body' },
    { key: 'select', tag: 'select', attributes: { id: 'gender_430', name: 'gender_430' }, parent: 'form', selector: '#gender_430' },
    { key: 'other', tag: 'select', attributes: { id: 'country_431' }, parent: 'body', selector: '#country_431' }];
  const record = snapshot(rows);
  assert.equal(generatedValue('gender_430'), true); assert.equal(usesGeneratedToken('#gender_430'), true);
  const fields = stableSelectorFor([record], target(record, 'select', rows));
  assert.deepEqual(fields, { stableSelector: '[data-testid="profile"] select', stableSelectorConfidence: 'anchored-path', stableSelectorCheck: 'captured-dom' });
  // No stable ancestor and a generated recorded id: abstain rather than repeat the generated id.
  assert.deepEqual(stableSelectorFor([record], target(record, 'other', rows)), {});
});

test('a node without anchors keeps a labelled positional fallback, shortened from the nearest anchored ancestor', () => {
  const rows = [body, { key: 'panel', tag: 'div', attributes: { id: 'panel' }, parent: 'body', selector: '#panel' },
    { key: 'row', tag: 'div', parent: 'panel', selector: 'html:nth-of-type(1) > body:nth-of-type(1) > div:nth-of-type(1) > div:nth-of-type(2)' },
    { key: 'row2', tag: 'div', parent: 'panel', selector: 'html:nth-of-type(1) > body:nth-of-type(1) > div:nth-of-type(1) > div:nth-of-type(1)' },
    { key: 'span', tag: 'span', parent: 'row', selector: 'html:nth-of-type(1) > body:nth-of-type(1) > div:nth-of-type(1) > div:nth-of-type(2) > span:nth-of-type(1)' },
    { key: 'span2', tag: 'span', parent: 'row2', selector: 'html:nth-of-type(1) > body:nth-of-type(1) > div:nth-of-type(1) > div:nth-of-type(1) > span:nth-of-type(1)' }];
  const record = snapshot(rows);
  assert.deepEqual(stableSelectorFor([record], target(record, 'span', rows)),
    { stableSelector: '#panel > div:nth-of-type(2) > span:nth-of-type(1)', stableSelectorConfidence: 'positional-fallback', stableSelectorCheck: 'captured-dom' });
  // A truncated capture cannot prove uniqueness, so only the recorded positional path is offered.
  const truncated = snapshot(rows, { truncated: true });
  assert.deepEqual(stableSelectorFor([truncated], target(truncated, 'span', rows)),
    { stableSelector: rows[4].selector, stableSelectorConfidence: 'positional-fallback', stableSelectorCheck: 'full-dom-at-capture' });
});

test('test ids win over aria-label and classes, and every anchor must be unique', () => {
  const rows = [body,
    { key: 'a', tag: 'button', attributes: { 'data-test-id': 'layer-add', 'aria-label': 'Add', class: 'btn icon' }, parent: 'body' },
    { key: 'b', tag: 'button', attributes: { 'data-test-id': 'dup', 'aria-label': 'Second', class: 'btn' }, parent: 'body', n: 2 },
    { key: 'c', tag: 'button', attributes: { 'data-test-id': 'dup', class: 'btn' }, parent: 'body', n: 3 },
    { key: 'd', tag: 'li', attributes: { id: 'ember1234', 'data-test': 'tool-flip' }, parent: 'body' }];
  const record = snapshot(rows), at = key => stableSelectorFor([record], target(record, key, rows));
  assert.equal(at('a').stableSelector, '[data-test-id="layer-add"]'); assert.equal(at('a').stableSelectorConfidence, 'unique-anchor');
  assert.equal(at('b').stableSelector, 'button[aria-label="Second"]', 'the shared data-test-id is not unique');
  assert.equal(at('c').stableSelectorConfidence, 'positional-fallback', 'no unique own or ancestor anchor exists');
  assert.equal(at('d').stableSelector, '[data-test="tool-flip"]', 'the generated id is skipped');
});

test('the uncaptured-anchor index rejects selectors that a hidden element would also match', () => {
  const rows = [body, { key: 'ghost', tag: 'div', attributes: { 'data-test-id': 'ghost', class: 'card' }, parent: 'body' },
    { key: 'menu', tag: 'nav', attributes: { 'data-test-id': 'menu' }, parent: 'body', n: 1 }];
  const hidden = { version: 1, elements: 1, keys: { div: 1, 'div data-test-id=ghost': 1, '* data-test-id=ghost': 1 } };
  const record = snapshot(rows, { uncapturedAnchors: hidden });
  const ghost = stableSelectorFor([record], target(record, 'ghost', rows));
  assert.notEqual(ghost.stableSelector, '[data-test-id="ghost"]');
  assert.equal(ghost.stableSelector, 'div.card'); assert.equal(ghost.stableSelectorCheck, 'full-dom-at-capture');
  assert.deepEqual(stableSelectorFor([record], target(record, 'menu', rows)),
    { stableSelector: '[data-test-id="menu"]', stableSelectorConfidence: 'unique-anchor', stableSelectorCheck: 'full-dom-at-capture' });
});

test('a selector the page checked against its full DOM wins a tie; positional in-page results stay labelled positional', () => {
  const rows = [body, { key: 'li', tag: 'li', attributes: { 'data-test-id': 'tool-flip' }, parent: 'body' }];
  const record = snapshot(rows), node = record.result.nodes[1];
  const many = { evidenceId: 'ev-0002', action: 'inspect_many', success: true, before: record.before, after: record.after,
    result: { nodes: [node], elements: [{ nodeId: node.nodeId, documentId: DOC, selector: 'li[data-test-id="tool-flip"]', selectorBasis: 'data-attribute', selectorConfidence: 'high' }] } };
  assert.deepEqual(stableSelectorFor([record, many], { evidenceId: 'ev-0002', nodeId: node.nodeId }),
    { stableSelector: 'li[data-test-id="tool-flip"]', stableSelectorConfidence: 'unique-anchor', stableSelectorCheck: 'full-dom-at-capture' });
  assert.deepEqual(inPageStableFields({ selector: '#main > div:nth-of-type(2)', basis: 'path' }), { stableSelector: '#main > div:nth-of-type(2)', stableSelectorConfidence: 'positional-fallback' });
  assert.deepEqual(inPageStableFields({ selector: '#gender_430', basis: 'axe-target' }), {});
  assert.deepEqual(inPageStableFields({ selector: 'nav a.home', basis: 'ancestor' }), { stableSelector: 'nav a.home', stableSelectorConfidence: 'anchored-path' });
});

const page = `<!doctype html><html lang="en"><head><title>Stable selectors</title></head><body><main>
<ul class="tools"><li data-test-id="tool-flip" style="cursor:pointer">Flip</li><li data-test-id="tool-rotate" style="cursor:pointer">Rotate</li></ul>
<form data-testid="profile"><select id="gender_430" name="gender_430"><option>a</option></select></form>
<div><div><span>plain one</span></div><div><span>plain two</span></div></div>
<div data-test-id="ghost" hidden>hidden copy</div><div data-test-id="ghost" class="card">Ghost</div>
<button id="unnamed"></button>
</main></body></html>`;

test('agent targets carry stableSelector in inspect rows, checkpoint/submit ACKs, the proposal report and the HTML report', async t => {
  let agent;
  t.after(() => agent?.close());
  const site = await fixture(t, page);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, startupAxe: false }, { textLimit: MCP_TEXT_LIMIT });
  const step = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'inspect', selector: '#gender_430' },
    { action: 'inspect_many', selectors: ['[data-test-id="tool-flip"]'] }] });
  assert.equal(step.success, true, JSON.stringify(step));
  const inspectRow = step.records.find(row => row.action === 'inspect');
  assert.equal(inspectRow.stableSelectorConfidence, 'anchored-path', JSON.stringify(inspectRow));
  assert.equal(inspectRow.stableSelector, 'form[data-testid="profile"] select');
  const manyRow = step.inspectMany[0].elements[0];
  assert.equal(manyRow.selector, 'li[data-test-id="tool-flip"]', 'existing selector unchanged');
  assert.deepEqual([manyRow.stableSelector, manyRow.stableSelectorConfidence], ['li[data-test-id="tool-flip"]', 'unique-anchor']);
  const snap = JSON.parse(await fs.readFile(path.join(agent.directory, 'ev-0001.json')));
  assert.equal(snap.result.uncapturedAnchors.version, 1);
  assert.ok(snap.result.uncapturedAnchors.keys['* data-test-id=ghost'] >= 1, 'the hidden copy is indexed');
  const node = match => snap.result.nodes.find(match);
  const finding = (id, n) => ({ id, title: `Finding ${id}`, criterionId: '4.1.2', target: { evidenceId: 'ev-0001', nodeId: n.nodeId }, evidenceIds: ['ev-0001'],
    observation: 'Observed in the snapshot.', reason: 'Needs review.', applicability: 'This element.', exceptions: 'None assessed.', scope: 'This element only.', method: 'dom' });
  const flip = node(n => n.attributes?.['data-test-id'] === 'tool-flip'), ghost = node(n => n.attributes?.['data-test-id'] === 'ghost');
  const plain = node(n => n.tag === 'span' && n.text === 'plain two'), unnamed = node(n => n.attributes?.id === 'unnamed');
  const proposal = { auditor: { name: 'stable selector test' }, findings: [finding('flip', flip), finding('ghost', ghost), finding('plain', plain), finding('unnamed', unnamed)] };
  const ack = await agent.request({ tool: 'checkpoint', proposal });
  assert.equal(ack.success, true, JSON.stringify(ack));
  const rows = new Map(ack.targets.rows.map(row => [row.findingId, row]));
  assert.equal(rows.get('flip').stableSelectorConfidence, 'unique-anchor');
  assert.match(rows.get('flip').stableSelector, /\[data-test-id="tool-flip"\]$/);
  assert.deepEqual(rows.get('flip').stableSelectorLive, { matches: 1, document: 'same' });
  assert.equal(rows.get('ghost').stableSelector, 'div.card', 'the hidden duplicate rules out the shared data-test-id');
  assert.equal(rows.get('plain').stableSelectorConfidence, 'positional-fallback');
  assert.equal(rows.get('unnamed').stableSelector, '#unnamed');
  assert.ok(ack.targets.note.includes('positional-fallback'));
  const submitted = await agent.request({ tool: 'submit', checkpointDigest: ack.checkpoint.checkpointDigest });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  assert.equal(submitted.targets.rows.length, 4);
  const stored = JSON.parse(await fs.readFile(submitted.proposalReportPath));
  const observed = new Map(stored.verificationQueue.map(row => [row.id, row.targetObservation]));
  assert.equal(observed.get('flip').selector, flip.selector, 'the recorded selector is unchanged');
  assert.equal(observed.get('flip').stableSelector, rows.get('flip').stableSelector);
  assert.equal(observed.get('ghost').stableSelector, 'div.card');
  assert.equal((await checkAudit(stored.reportPath)).status, 'current');
  // A document written before these fields existed still verifies; a forged stable selector does not.
  const strip = value => Object.fromEntries(Object.entries(value).filter(([key]) => !key.startsWith('stableSelector')));
  const legacy = await saveAuditDocument(agent.directory, 'audit-proposal', { ...stored, verificationQueue: stored.verificationQueue.map(row => ({ ...row, targetObservation: strip(row.targetObservation) })) });
  assert.equal((await checkAudit(legacy.reportPath)).status, 'current');
  const forged = await saveAuditDocument(agent.directory, 'audit-proposal', { ...stored, verificationQueue: stored.verificationQueue.map(row => ({ ...row, targetObservation: { ...row.targetObservation, stableSelector: 'body' } })) });
  assert.equal((await checkAudit(forged.reportPath)).status, 'error');
  const html = renderAuditReportHtml(stored);
  assert.match(html, /<summary>Reproduce <span class="dm">\(2 steps\)<\/span><\/summary><div class="db"><ol><li>Open <code>http:\/\/127\.0\.0\.1:\d+\/<\/code> and bring it to the state recorded in evidence <code>ev-0001<\/code>\.<\/li>/);
  assert.ok(html.includes('Find the element with <code>div.card</code> (unique-anchor; unique in the page&#39;s whole DOM when captured).'));
});

test('a stable selector that the live page now matches more than once is dropped from the ACK (abstain, not guess)', async t => {
  const html = `<!doctype html><html lang="en"><head><title>Live probe</title></head><body><main>
<ul><li data-test-id="tool-rotate">Rotate</li></ul>
<button id="clone" onclick="document.querySelector('ul').append(document.querySelector('li').cloneNode(true))">Clone</button>
</main></body></html>`;
  let agent;
  t.after(() => agent?.close());
  const site = await fixture(t, html);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, startupAxe: false }, { textLimit: MCP_TEXT_LIMIT });
  assert.equal((await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'click', selector: '#clone' }] })).success, true);
  const snap = JSON.parse(await fs.readFile(path.join(agent.directory, 'ev-0001.json')));
  const li = snap.result.nodes.find(n => n.attributes?.['data-test-id'] === 'tool-rotate');
  const ack = await agent.request({ tool: 'checkpoint', proposal: { auditor: { name: 'live probe test' }, findings: [{ id: 'rotate', title: 'Rotate tool', criterionId: '2.1.1',
    target: { evidenceId: 'ev-0001', nodeId: li.nodeId }, evidenceIds: ['ev-0001'], observation: 'Observed.', reason: 'Needs review.', applicability: 'This element.',
    exceptions: 'None assessed.', scope: 'This element only.', method: 'dom' }] } });
  assert.equal(ack.success, true, JSON.stringify(ack));
  const [row] = ack.targets.rows;
  assert.deepEqual(row.stableSelectorLive, { matches: 2, document: 'same' });
  assert.equal(Object.hasOwn(row, 'stableSelector'), false); assert.equal(Object.hasOwn(row, 'stableSelectorConfidence'), false);
  // The persisted draft is unchanged by the live probe: it holds the original proposal only.
  const draft = JSON.parse(await fs.readFile(ack.checkpoint.checkpointPath));
  assert.equal(JSON.stringify(draft).includes('stableSelectorLive'), false);
});
