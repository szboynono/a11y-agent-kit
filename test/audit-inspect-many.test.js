import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fixture } from './helpers.js';
import { AuditBrowser } from '../src/audit/browser.js';
import { openAuditAgent, AUDIT_PLAYBOOK_TEXT } from '../src/audit/agent.js';
import { auditActionSchema, parseAuditManifest } from '../src/audit/schema.js';
import { reviewAudit } from '../src/audit/review.js';
import { MCP_TEXT_LIMIT } from '../src/audit/projection.js';
import { compactAxNode, observationFlags } from '../src/audit/inspect-many.js';

const PASSWORD = 'PASSWORD_VALUE_SENTINEL_4417', TYPED = 'TYPED_VALUE_SENTINEL_9023';
const widgets = `<!doctype html><html lang="en"><head><title>Custom widgets</title></head><body><main><h1>Custom widgets</h1>
<div id="vol" tabindex="0" aria-label="Volume" aria-valuemin="0" aria-valuemax="10" aria-valuenow="3" style="cursor:pointer;width:80px;height:20px">|||</div>
<span id="save" onclick="void 0">Save</span>
<div role="tablist" aria-label="Sections"><div role="tab" id="tab-a" aria-selected="true" tabindex="0">Overview</div><div role="tab" id="tab-b" aria-selected="false" tabindex="-1">Details</div></div>
<div id="city" role="combobox" aria-label="City" aria-autocomplete="list" aria-expanded="false" tabindex="0"></div>
<input id="fruit" role="combobox" aria-label="Fruit" aria-autocomplete="both" aria-expanded="true" aria-controls="fruits"><ul id="fruits" role="listbox" aria-label="Fruits"></ul>
<button id="icon" type="button"><svg width="10" height="10" aria-hidden="true"></svg></button>
<input id="secret" type="password" value="${PASSWORD}" aria-label="Secret"><input id="q" aria-label="Search" value="${TYPED}">
<p id="plain">Plain text that is not interactive.</p><div id="gone" tabindex="0" style="display:none">hidden</div>
</main></body></html>`;

async function startBrowser(t, html = widgets) {
  const site = await fixture(t, html);
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: site.projectRoot, url: site.url }), { handleSignals: false });
  t.after(() => browser.close());
  await browser.start();
  return { site, browser };
}
async function startAgent(t, html = widgets, options = {}) {
  let agent;
  t.after(() => agent?.close());
  const site = await fixture(t, html);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, ...options }, { textLimit: MCP_TEXT_LIMIT });
  return agent;
}
const size = value => Buffer.byteLength(JSON.stringify(value));
const bySelector = (record, selector) => record.result.elements.find(row => row.selector === selector);

test('inspect_many reports AX role, name and state for custom widgets without role-guessing heuristics', async t => {
  const { browser } = await startBrowser(t);
  const record = await browser.execute({ action: 'inspect_many', query: 'interactive' });
  assert.equal(record.success, true, JSON.stringify(record.error));
  assert.equal(record.before.stateId, record.after.stateId);
  const slider = bySelector(record, '#vol'), button = bySelector(record, '#save');
  // A role-less div: Chrome's tree says generic, whatever the author's aria-valuenow suggests.
  assert.equal(slider.ax.role, 'generic'); assert.equal(slider.explicitRole, null); assert.equal(slider.nativeRole, 'generic');
  assert.equal(slider.aria['aria-valuenow'], '3'); assert.equal(slider.focus.tabStop, true);
  assert.deepEqual(slider.flags, ['interactiveWithoutRole']);
  assert.deepEqual(button.flags, ['interactiveWithoutRole']); assert.equal(button.focus.tabStop, false);
  assert.ok(button.matchedBy.includes('onclick'));
  const [tabA, tabB] = [bySelector(record, '#tab-a'), bySelector(record, '#tab-b')];
  assert.equal(tabA.ax.role, 'tab'); assert.equal(tabA.ax.name, 'Overview'); assert.equal(tabA.ax.states.selected, true);
  assert.equal(tabB.ax.states.selected, false); assert.equal(tabB.focus.tabStop, false); assert.equal(tabB.nativeRole, null); assert.equal(tabB.explicitRole, 'tab');
  const city = bySelector(record, '#city');
  assert.equal(city.ax.role, 'combobox'); assert.equal(city.ax.name, 'City'); assert.equal(city.ax.states.expanded, false);
  // Chrome's tree reports autocomplete only for an editable combobox; the raw attribute is always kept beside it.
  assert.equal(city.ax.states.autocomplete, undefined); assert.equal(city.aria['aria-autocomplete'], 'list');
  const fruit = bySelector(record, '#fruit');
  assert.equal(fruit.ax.role, 'combobox'); assert.equal(fruit.ax.states.autocomplete, 'both'); assert.equal(fruit.ax.states.expanded, true);
  assert.equal(fruit.aria['aria-controls'], 'fruits'); assert.deepEqual(fruit.flags, []);
  const icon = bySelector(record, '#icon');
  assert.equal(icon.ax.role, 'button'); assert.equal(icon.ax.name, ''); assert.equal(icon.nativeRole, 'button'); assert.deepEqual(icon.flags, ['noAccessibleName']);
  assert.deepEqual(bySelector(record, '#tab-a').flags, []);
  assert.equal(record.result.elements.some(row => row.selector === '#plain' || row.selector === '#gone'), false, 'plain text and hidden elements are not candidates');
  assert.equal(record.result.counts.hiddenExcluded, 1); assert.equal(record.result.counts.axUnavailable, 0);
  // Values the user typed never enter the AX rows; the password is absent everywhere.
  const search = bySelector(record, '#q');
  assert.equal(search.ax.valueOmitted, true); assert.equal(Object.hasOwn(search.ax, 'value'), false);
  assert.equal(JSON.stringify(record.result.elements).includes(TYPED), false);
  assert.equal(JSON.stringify(record).includes(PASSWORD), false);
});

test('flag rules are exact and only fire on unambiguous AX facts', () => {
  const ax = (role, name, extra = {}) => compactAxNode({ ignored: false, role: { value: role }, name: { value: name }, properties: [], ...extra });
  const facts = { explicitRole: null, nativeInteractive: false, onclickAttr: false, tabindexAttr: null, tabIndex: -1 };
  assert.deepEqual(observationFlags(ax('button', ''), facts), ['noAccessibleName']);
  assert.deepEqual(observationFlags(ax('button', 'Go'), facts), []);
  assert.deepEqual(observationFlags(ax('img', ''), facts), [], 'roles outside the named set are never flagged');
  assert.deepEqual(observationFlags(compactAxNode({ ignored: true, role: { value: 'none' }, name: { value: '' } }), facts), [], 'ignored nodes are never flagged');
  assert.deepEqual(observationFlags({ available: false }, facts), []);
  assert.deepEqual(observationFlags(ax('generic', ''), { ...facts, tabindexAttr: '0', tabIndex: 0 }), ['interactiveWithoutRole']);
  assert.deepEqual(observationFlags(ax('generic', ''), { ...facts, tabindexAttr: '-1', tabIndex: -1 }), [], 'tabindex=-1 alone declares no interaction');
  assert.deepEqual(observationFlags(ax('generic', ''), facts), [], 'cursor:pointer or text alone never flags');
  assert.deepEqual(observationFlags(ax('generic', ''), { ...facts, onclickAttr: true, explicitRole: 'presentation' }), []);
  assert.deepEqual(observationFlags(ax('generic', ''), { ...facts, onclickAttr: true, nativeInteractive: true }), []);
  const hidden = compactAxNode({ ignored: false, role: { value: 'textbox' }, name: { value: 'x' }, value: { value: 'typed' }, properties: [{ name: 'valuenow', value: { type: 'number', value: 2 } }, { name: 'focusable', value: { type: 'booleanOrUndefined', value: true } }, { name: 'controls', value: { type: 'idrefList', value: [] } }] });
  assert.deepEqual(hidden.states, { focusable: true }); assert.equal(hidden.valueOmitted, true);
});

test('selector lists resolve only unique matches and report the rest without failing the action', async t => {
  const { browser } = await startBrowser(t);
  const record = await browser.execute({ action: 'inspect_many', selectors: ['#vol', '#nope', 'div[role=tab]', '#tab-a', '#tab-a', '['] });
  assert.equal(record.success, true);
  assert.deepEqual(record.result.selectorStatus.map(row => row.status), ['ok', 'not_found', 'ambiguous', 'ok', 'ok', 'invalid_selector']);
  assert.equal(record.result.selectorStatus[2].count, 2); assert.equal(record.result.selectorStatus[4].duplicateOf, true);
  assert.deepEqual(record.result.elements.map(row => row.selector), ['#vol', '#tab-a']);
  assert.equal(record.result.nodes.length, 2);
  assert.equal(auditActionSchema.safeParse({ action: 'inspect_many', selectors: Array.from({ length: 50 }, (_, i) => `#a${i}`) }).success, true);
  for (const bad of [{ selectors: Array.from({ length: 51 }, (_, i) => `#a${i}`) }, { selectors: [] }, {}, { selectors: ['#a'], query: 'interactive' }, { query: 'everything' }, { query: 'interactive', extra: 1 }]) {
    assert.equal(auditActionSchema.safeParse({ action: 'inspect_many', ...bad }).success, false, JSON.stringify(bad).slice(0, 80));
  }
});

test('inspect_many is read-only: no DOM, attribute, focus or scroll mutation and no leftover page state', async t => {
  const { browser } = await startBrowser(t);
  await browser.page.evaluate(() => { window.__mutations = []; new MutationObserver(records => window.__mutations.push(...records.map(r => r.type))).observe(document, { subtree: true, attributes: true, childList: true, characterData: true }); });
  const snapshot = () => browser.page.evaluate(() => ({ html: document.documentElement.outerHTML, active: document.activeElement?.tagName, scroll: [scrollX, scrollY] }));
  const before = await snapshot();
  const record = await browser.execute({ action: 'inspect_many', query: 'interactive' });
  assert.equal(record.success, true);
  assert.deepEqual(await snapshot(), before);
  assert.deepEqual(await browser.page.evaluate(() => window.__mutations.splice(0)), []);
  assert.equal(await browser.page.evaluate(key => Object.hasOwn(globalThis[key], 'many'), browser.storeKey), false);
  assert.equal(record.before.keyboardOnly, true); assert.equal(record.after.inputPath, 'keyboard-only');
});

test('every row keeps the original node and document identity that inspect reports', async t => {
  const { browser } = await startBrowser(t);
  const record = await browser.execute({ action: 'inspect_many', query: 'interactive' });
  assert.equal(record.result.elements.length, record.result.nodes.length);
  assert.equal(new Set(record.result.elements.map(row => row.nodeId)).size, record.result.elements.length);
  for (const [index, row] of record.result.elements.entries()) {
    assert.equal(row.documentId, record.after.documentId);
    assert.equal(record.result.nodes[index].nodeId, row.nodeId); assert.equal(record.result.nodes[index].documentId, record.after.documentId);
    const inspected = await browser.execute({ action: 'inspect', selector: row.selector });
    assert.equal(inspected.success, true, `${row.selector}: ${JSON.stringify(inspected.error)}`);
    assert.equal(inspected.result.element.nodeId, row.nodeId, 'the stable selector re-targets the same original node');
    assert.equal(inspected.after.documentId, record.after.documentId);
  }
  assert.ok(record.result.elements.every(row => ['id', 'attribute', 'positional', 'data-attribute', 'name', 'aria-attribute', 'attributes', 'class', 'ancestor', 'path'].includes(row.selectorBasis)));
});

const manyButtons = count => `<!doctype html><html lang="en"><head><title>Many</title></head><body><main>${
  Array.from({ length: count }, (_, i) => `<button type="button" aria-label="Control number ${i + 1} with a fairly long accessible label to make rows realistic" data-slot="slot-${i + 1}">x</button>`).join('')}</main></body></html>`;

test('large results page under the MCP cap with exact nextRequest calls, bounded to the preset limit', async t => {
  const agent = await startAgent(t, manyButtons(170));
  const step = await agent.request({ tool: 'step', actions: [{ action: 'inspect_many', query: 'interactive' }] });
  assert.equal(step.success, true, JSON.stringify(step).slice(0, 500));
  assert.ok(size(step) <= MCP_TEXT_LIMIT, `step ${size(step)}`);
  const [first] = step.inspectMany;
  assert.deepEqual(first.counts, { matched: 170, returned: 150, omitted: 20, hiddenExcluded: 0, axUnavailable: 0 });
  assert.equal(first.pagination.total, 150); assert.equal(first.pagination.complete, false);
  assert.ok(first.flagRules.noAccessibleName); assert.ok(first.source);
  const seen = [...first.elements];
  let next = first.pagination.nextRequest, pages = 1;
  while (next) {
    assert.deepEqual(Object.keys(next).sort(), ['evidenceId', 'options', 'tool']);
    const response = await agent.request(next);
    assert.equal(response.success, true, JSON.stringify(response).slice(0, 400));
    assert.ok(size(response) <= MCP_TEXT_LIMIT, `page ${pages}: ${size(response)}`);
    assert.equal(response.source, undefined, 'boilerplate appears on page 1 only');
    seen.push(...response.elements); next = response.pagination.nextRequest; pages++;
  }
  assert.ok(pages >= 2 && pages < 20);
  assert.equal(seen.length, 150); assert.equal(new Set(seen.map(row => row.nodeId)).size, 150);
  const raw = JSON.parse(await fs.readFile(path.join(agent.directory, 'ev-0001.json'), 'utf8'));
  assert.deepEqual(seen.map(row => row.nodeId), raw.result.elements.map(row => row.nodeId));
  // Cursors are bound to the record and canonical.
  const bad = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'elements', cursor: 'not-a-cursor' } });
  assert.equal(bad.success, false); assert.equal(bad.error.code, 'INVALID_AUDIT_CURSOR');
  const unsupported = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'elements', offset: 3 } });
  assert.equal(unsupported.success, false); assert.equal(unsupported.error.code, 'INVALID_AUDIT_READ_OPTIONS');
  // The ordinary node and field readers still reach the full original row without paging through the compact view.
  const field = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'field', field: '/result/counts' } });
  assert.equal(field.success, true); assert.equal(JSON.parse(field.data).returned, 150);
});

test('one inspect_many call is one action against the budget, whatever the number of elements', async t => {
  const agent = await startAgent(t);
  const step = await agent.request({ tool: 'step', actions: [{ action: 'inspect_many', selectors: ['#vol', '#save', '#tab-a'] }, { action: 'inspect_many', query: 'interactive' }] });
  assert.equal(step.success, true, JSON.stringify(step).slice(0, 400));
  assert.equal(step.budget.requestedActions, 2); assert.equal(step.budget.successfulActions, 2);
  assert.equal(step.budget.remainingActions, 178);
  assert.equal(step.inspectMany.length, 2);
  assert.ok(size(step) <= MCP_TEXT_LIMIT);
});

test('a finding citing an inspect_many record passes the existing evidence gate when the evidence suffices, and not otherwise', async t => {
  const agent = await startAgent(t);
  const step = await agent.request({ tool: 'step', actions: [{ action: 'inspect_many', query: 'interactive' }] });
  assert.equal(step.success, true, JSON.stringify(step).slice(0, 400));
  const icon = step.inspectMany[0].elements.find(row => row.selector === '#icon');
  assert.deepEqual(icon.flags, ['noAccessibleName']);
  const evidenceId = step.records[0].evidenceId;
  // The native-button predicate requires a target-scoped ARIA inspect.
  const inspected = await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#icon' }] });
  assert.equal(inspected.success, true);
  const inspectId = inspected.records[0].evidenceId;
  const [bulkRecord, inspectRecord] = await Promise.all([evidenceId, inspectId].map(id => fs.readFile(path.join(agent.directory, `${id}.json`), 'utf8').then(JSON.parse)));
  assert.equal(inspectRecord.success, true);
  assert.equal(inspectRecord.result.element.nodeId, icon.nodeId);
  assert.equal(inspectRecord.after.documentId, bulkRecord.after.documentId);
  assert.equal(inspectRecord.before.stateId, inspectRecord.after.stateId);
  assert.equal(inspectRecord.after.stateId, bulkRecord.after.stateId);
  assert.match(inspectRecord.result.ariaSnapshot.trim(), /^- button(?: \[[^\]\r\n]*\])*\s*$/);
  const own = (id, criterionId, extra = {}) => ({ id, title: 'Icon-only button has an empty accessible name', criterionId, target: { evidenceId, nodeId: icon.nodeId }, evidenceIds: [evidenceId, inspectId],
    observation: `inspect_many ${evidenceId}: Chrome AX role button, name "" for ${icon.selector}.`, reason: 'A button must expose a name.', applicability: 'Native button in the main document.',
    exceptions: 'None observed.', scope: 'This node in the recorded state.', method: 'dom', ...extra });
  const submitted = await agent.request({ tool: 'submit', proposal: { auditor: { name: 'Widget maker' }, findings: [
    own('F-name', '4.1.2'), own('F-focus', '2.4.7'), own('F-no-direct', '4.1.2'), own('F-bulk-only', '4.1.2', { evidenceIds: [evidenceId] }),
  ] } });
  assert.equal(submitted.success, true, JSON.stringify(submitted).slice(0, 500));
  const proposal = JSON.parse(await fs.readFile(submitted.proposalReportPath, 'utf8'));
  const decide = finding => ({ findingId: finding.id, verdict: 'supported', reason: 'The independent reviewer checked the retained target observations.',
    checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
    ...(['F-name', 'F-bulk-only'].includes(finding.id) ? { directEvidence: {
      evidenceId: finding.id === 'F-name' ? inspectId : evidenceId, nodeIds: [icon.nodeId],
      criterionClause: 'WCAG 4.1.2 requires a programmatically determinable name for this native button.',
      explanation: finding.id === 'F-name'
        ? 'The same rendered native button has empty naming attributes and label text; its target-scoped inspect snapshot exposes a button without a name.'
        : 'The bulk AX row reports an empty name; this citation supplies no target-scoped ARIA inspect snapshot.',
    } } : {}) });
  const reviewed = await reviewAudit(proposal.reportPath, { reviewer: { name: 'Independent reviewer', independentOfAuditor: true }, decisions: proposal.findings.map(decide) });
  const confirmed = reviewed.confirmedFindings.find(row => row.id === 'F-name');
  assert.equal(confirmed?.evidenceGate.status, 'supported');
  // Observations never stand in for the visual and keyboard prerequisites of another criterion.
  assert.equal(reviewed.confirmedFindings.some(row => row.id === 'F-focus'), false);
  assert.equal(reviewed.verificationQueue.find(row => row.id === 'F-focus').evidenceGate.status, 'insufficient');
  for (const id of ['F-no-direct', 'F-bulk-only']) {
    assert.equal(reviewed.confirmedFindings.some(row => row.id === id), false);
    assert.equal(reviewed.verificationQueue.find(row => row.id === id).evidenceGate.status, 'insufficient');
  }
  // A node that is not in the cited record is refused.
  const wrong = await agent.request({ tool: 'checkpoint', proposal: { auditor: { name: 'Widget maker' }, findings: [own('F-bad', '4.1.2', { target: { evidenceId, nodeId: 'doc-x:n000001' } })] } });
  assert.equal(wrong.success, false);
});

test('the playbook stays within 120 words and names inspect_many', () => {
  assert.ok(AUDIT_PLAYBOOK_TEXT.split(/\s+/).length <= 120);
  assert.match(AUDIT_PLAYBOOK_TEXT, /inspect_many/);
});

test('a batch of previews that cannot all fit still returns every successful record with read handles', async t => {
  const agent = await startAgent(t);
  const step = await agent.request({ tool: 'step', actions: Array.from({ length: 8 }, () => ({ action: 'inspect_many', selectors: ['#icon'] })) });
  assert.equal(step.success, true, JSON.stringify(step).slice(0, 300));
  assert.equal(step.records.length, 8); assert.ok(step.records.every(row => row.success));
  assert.ok(size(step) <= MCP_TEXT_LIMIT);
  const lastId = step.records[7].evidenceId;
  const read = await agent.request({ tool: 'read', evidenceId: lastId, options: { view: 'elements' } });
  assert.equal(read.success, true); assert.equal(read.elements.length, 1);
});

test('a failed CDP session still clears the temporary element list from the page', async t => {
  const { browser } = await startBrowser(t);
  t.mock.method(browser.context, 'newCDPSession', async () => { throw new Error('injected'); });
  const record = await browser.execute({ action: 'inspect_many', selectors: ['#icon'] });
  assert.equal(record.success, false);
  assert.equal(await browser.page.evaluate(key => Object.hasOwn(globalThis[key], 'many'), browser.storeKey), false);
});
