import test from 'node:test';
import assert from 'node:assert/strict';
import AxeBuilder from '@axe-core/playwright';
import { fixture } from './helpers.js';
import { AuditBrowser, AXE_AUDIT_TAGS } from '../src/audit/browser.js';
import { parseAuditManifest } from '../src/audit/schema.js';
import { collectAudit } from '../src/audit/collect.js';
import { submitAudit, checkAudit } from '../src/audit/review.js';

const source = `<!doctype html><html lang="en"><head><title>Original axe targets</title>
<style>button{width:36px;height:32px}body{color:black;background:white}</style></head><body><main>
<h1>Original axe targets</h1><button id="one"></button><button id="two"></button>
<div class="ambiguous">First</div><div class="ambiguous">Second</div>
<button id="hidden" hidden></button><button id="far"></button>
<input id="password" type="password" value="PASSWORD_VALUE_SENTINEL_6192">
<input id="hidden-value" type="hidden" value="HIDDEN_VALUE_SENTINEL_1752">
<script>globalThis.inlinePrivate = 'INLINE_SCRIPT_SENTINEL_5148';</script>
</main></body></html>`;

async function start(t, html = source, options = {}) {
  const site = await fixture(t, html);
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: site.projectRoot, url: site.url, ...options }), { handleSignals: false });
  t.after(() => browser.close());
  await browser.start();
  return { site, browser };
}

function rawTargets(axe) {
  return Object.fromEntries(['violations', 'incomplete', 'passes', 'inapplicable'].map(disposition => [disposition,
    axe[disposition].map(rule => ({ id: rule.id, tags: rule.tags, targets: rule.nodes.map(node => node.target) }))]));
}

test('one real axe action binds multiple original nodes without focus, attribute or privacy changes', async t => {
  const { browser } = await start(t);
  assert.equal((await browser.execute({ action: 'press', key: 'Tab' })).success, true);
  const attributes = () => browser.page.evaluate(() => [...document.querySelectorAll('html,body,button,input')]
    .map(element => [element.tagName, [...element.attributes].map(attribute => [attribute.name, attribute.value])]));
  const originalAttributes = await attributes();
  const observe = browser.observe;
  let observations = 0;
  t.mock.method(browser, 'observe', function (...args) { observations++; return observe.apply(this, args); });
  const record = await browser.execute({ action: 'axe' });
  assert.equal(record.success, true, JSON.stringify(record.error));
  assert.equal(observations, 2, 'all targets share the existing final DOM observation');
  assert.deepEqual(await attributes(), originalAttributes);
  assert.equal(record.before.active.attributes.id, 'one');
  assert.deepEqual(record.after.active, record.before.active);
  assert.equal(record.after.keyboardOnly, true);
  assert.deepEqual(record.result.tags, ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']);
  const bindings = record.result.axeNodeBindings;
  assert.equal(bindings.profile, 'main-dom-axe-targets-v1');
  assert.equal(bindings.stable, true);
  assert.equal(bindings.capturedStateId, record.after.stateId);
  assert.equal(bindings.capturedStateId, record.before.stateId);
  assert.equal(bindings.capturedDocumentId, record.after.documentId);
  for (const id of ['one', 'two', 'far']) {
    const row = bindings.rows.find(row => row.ruleId === 'button-name' && row.target[0] === `#${id}`);
    assert.equal(row?.status, 'bound', `missing original binding for ${id}`);
    const original = record.result.nodes.find(node => node.nodeId === row.nodeId);
    const inspected = await browser.execute({ action: 'inspect', selector: `#${id}` });
    assert.equal(inspected.success, true);
    assert.equal(original.attributes.id, id);
    assert.equal(original.documentId, record.after.documentId);
    assert.equal(inspected.result.element.nodeId, original.nodeId);
    assert.equal(inspected.result.element.documentId, original.documentId);
    assert.equal(row.selector, original.selector);
  }
  assert.equal(new Set(record.result.nodes.map(node => node.nodeId)).size, record.result.nodes.length);
  assert.equal(bindings.totalTargets, record.result.axe.violations.concat(record.result.axe.incomplete)
    .reduce((count, rule) => count + rule.nodes.length, 0));
  assert.equal(bindings.omittedTargets, 0);
  const retained = JSON.stringify(record);
  for (const sentinel of ['INLINE_SCRIPT_SENTINEL_5148', 'PASSWORD_VALUE_SENTINEL_6192', 'HIDDEN_VALUE_SENTINEL_1752']) {
    assert.equal(retained.includes(sentinel), false, `${sentinel} must not enter new bindings`);
  }
  assert.equal(record.result.axeHtmlOmitted, true);
  assert.ok(record.result.axe.violations.flatMap(rule => rule.nodes).every(node => node.html.startsWith('[HTML omitted;')));
  // Compare every category/rule/target with the public full-default integration,
  // rather than assuming that retaining a few expected rules proves completeness.
  browser.allowAxePages = true;
  let reference;
  try { reference = await new AxeBuilder({ page: browser.page }).withTags([...AXE_AUDIT_TAGS]).analyze(); }
  finally { browser.allowAxePages = false; }
  assert.deepEqual(rawTargets(record.result.axe), rawTargets(reference));
});

test('real frame/shadow targets and real-query unsupported targets remain explicitly unbound', async t => {
  const child = '<!doctype html><html lang="en"><head><title>Frame</title></head><body><button id="inside" style="width:30px;height:30px"></button></body></html>';
  const html = source.replace('</main>', `<iframe id="frame" title="Child" srcdoc="${child.replaceAll('&', '&amp;').replaceAll('"', '&quot;')}"></iframe>
    <div id="host"></div><script>document.querySelector('#host').attachShadow({mode:'open'}).innerHTML='<button id="shadow" style="width:30px;height:30px"></button>';</script></main>`);
  const { browser } = await start(t, html, { maxElements: 5 });
  const analyze = AxeBuilder.prototype.analyze;
  const addedTargets = [['.ambiguous'], ['['], ['#not-present'], ['#hidden'], ['html'], ['#far'], [], ['#one']];
  t.mock.method(AxeBuilder.prototype, 'analyze', async function () {
    const raw = await analyze.call(this);
    // These malformed/ambiguous upstream targets exercise the defensive boundary
    // using real browser queries; they are not claimed to be axe discoveries.
    raw.incomplete.push({ id: 'synthetic-target-boundaries', nodes: addedTargets.map(target => ({ target })) });
    return raw;
  });
  const record = await browser.execute({ action: 'axe' });
  assert.equal(record.success, true, JSON.stringify(record.error));
  const bindings = record.result.axeNodeBindings;
  assert.equal(bindings.stable, true);
  const frame = bindings.rows.find(row => row.ruleId === 'button-name' && row.target.length > 1);
  assert.equal(frame?.status, 'unbound');
  assert.equal(frame.reason, 'frame_or_multiple_selector_target');
  const shadow = bindings.rows.find(row => row.ruleId === 'button-name' && Array.isArray(row.target[0]));
  assert.equal(shadow?.status, 'unbound');
  assert.equal(shadow.reason, 'shadow_or_nested_target_path');
  const rows = bindings.rows.filter(row => row.ruleId === 'synthetic-target-boundaries');
  assert.deepEqual(rows.map(row => row.reason || row.status), [
    'ambiguous_main_document_target', 'invalid_css_selector', 'not_found_in_main_document', 'not_visible',
    'outside_observed_main_body', 'outside_max_elements', 'not_a_single_css_target', 'bound',
  ]);
  assert.equal(rows.at(-1).nodeId, record.result.nodes.find(node => node.attributes.id === 'one').nodeId);
  assert.equal(record.result.nodes.some(node => ['inside', 'shadow', 'far', 'hidden'].includes(node.attributes.id)), false);
  for (const row of bindings.rows.filter(row => row.status === 'unbound')) {
    assert.equal(Object.hasOwn(row, 'nodeId'), false);
    assert.equal(Object.hasOwn(row, 'documentId'), false);
  }
  assert.ok(record.after.truncation.omittedVisibleElements > 0);
});

test('binding row cap retains every raw target and explicitly counts omitted mappings', async t => {
  const { browser } = await start(t);
  const raw = { violations: [{ id: 'bounded-upstream-row-test', nodes: Array.from({ length: 5003 }, () => ({ target: ['#one'] })) }],
    incomplete: [{ id: 'last-incomplete-row', nodes: [{ target: ['#two'] }] }], passes: [], inapplicable: [] };
  t.mock.method(AxeBuilder.prototype, 'analyze', async () => raw);
  const record = await browser.execute({ action: 'axe' });
  assert.equal(record.success, true);
  assert.equal(record.result.axeNodeBindings.stable, true);
  assert.equal(record.result.axeNodeBindings.rowLimit, 5000);
  assert.equal(record.result.axeNodeBindings.rows.length, 5000);
  assert.equal(record.result.axeNodeBindings.totalTargets, 5004);
  assert.equal(record.result.axeNodeBindings.omittedTargets, 4);
  assert.equal(record.result.nodes.length, 1);
  assert.equal(record.result.axe.violations[0].nodes.length, 5003);
  assert.equal(record.result.axe.incomplete[0].nodes.length, 1);
});

test('same-looking node replacement during real axe cannot bind the replacement as original evidence', async t => {
  const { browser } = await start(t);
  const analyze = AxeBuilder.prototype.analyze;
  t.mock.method(AxeBuilder.prototype, 'analyze', async function () {
    const raw = await analyze.call(this);
    await browser.page.evaluate(() => {
      const original = document.querySelector('#one');
      original.replaceWith(original.cloneNode(true));
    });
    return raw;
  });
  const record = await browser.execute({ action: 'axe' });
  assert.equal(record.success, true, JSON.stringify(record.error));
  assert.ok(record.result.axe.violations.some(rule => rule.id === 'button-name'));
  assert.notEqual(record.before.stateId, record.after.stateId);
  assert.equal(record.result.axeNodeBindings.stable, false);
  assert.equal(record.result.axeNodeBindings.capturedStateId, null);
  assert.equal(record.result.axeNodeBindings.capturedDocumentId, null);
  assert.deepEqual(record.result.nodes, []);
  assert.ok(record.result.axeNodeBindings.rows.some(row => row.reason === 'axe_capture_state_changed'));
  assert.ok(record.result.axeNodeBindings.rows.every(row => row.status === 'unbound' && !Object.hasOwn(row, 'nodeId')));
});

test('a successful original axe-record node can submit a DOM proposal without an inspect action', async t => {
  const site = await fixture(t, source);
  const audit = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'axe' }] });
  assert.equal(audit.status, 'collected', JSON.stringify(audit.errors));
  assert.equal(audit.records.length, 1);
  const record = audit.records[0];
  const node = record.result.nodes.find(node => node.attributes.id === 'one');
  assert.ok(node);
  const proposal = await submitAudit(audit.reportPath, { auditor: { name: 'Original-node contract test' }, findings: [{
    id: 'button-name-observation', title: 'The observed empty button has no programmatic name', criterionId: '4.1.2',
    target: { evidenceId: record.evidenceId, nodeId: node.nodeId }, evidenceIds: [record.evidenceId], method: 'dom',
    observation: 'The original rendered native button has no content, aria-label or labelledby reference.',
    reason: 'The native button role is present while its observed programmatic name is empty.',
    applicability: 'A rendered user interface button needs an exposed name.', exceptions: 'No name exception is asserted.',
    scope: 'Only this original main-document button in this recorded state.',
  }] });
  assert.equal(proposal.kind, 'audit-proposal');
  assert.equal(proposal.status, 'needs_review');
  assert.equal(proposal.confirmedFindings.length, 0, 'original-node bindings do not adjudicate candidates');
  assert.equal(proposal.verificationQueue[0].targetObservation.selector, node.selector);
  assert.equal(proposal.verificationQueue[0].evidenceGate.status, 'supported');
  assert.equal((await checkAudit(proposal.reportPath)).status, 'current');
});
