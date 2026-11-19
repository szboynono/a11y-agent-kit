import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { auditActionSchema } from '../src/audit/schema.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { openAuditSession } from '../src/audit/live.js';
import { AuditBrowser } from '../src/audit/browser.js';
import { precheckSession } from '../src/audit/precheck.js';
import { fixture } from './helpers.js';

const html = `<!doctype html><html lang="en"><head><title>Hover and focus</title>
<style>#tip { display:none } #hover:hover + #tip { display:block } #cover { position:fixed; inset:0; z-index:10 }</style></head>
<body><button id="hover">Hover</button><p id="tip">Help</p><button id="focus" tabindex="-1">Focus</button>
<button id="hidden" hidden>Hidden</button><button id="disabled" disabled>Disabled</button>
<div inert><button id="inert">Inert</button></div><div id="plain">Plain</div><button class="many">One</button><button class="many">Two</button></body></html>`;
async function open(t, content = html) {
  let agent;
  t.after(() => agent?.close());
  const site = await fixture(t, content);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  return { agent, step: async action => {
    const response = await agent.request({ tool: 'step', actions: [action] });
    assert.equal(response.records?.length, 1, JSON.stringify(response));
    return JSON.parse(await fs.readFile(path.join(agent.directory, `${response.records[0].evidenceId}.json`)));
  } };
}

test('hover/focus accept only the selector action shape', () => {
  for (const action of ['hover', 'focus']) {
    assert.equal(auditActionSchema.safeParse({ action, selector: '#focus' }).success, true);
    for (const input of [{ action }, { action, selector: '#focus', key: 'Tab' }]) assert.equal(auditActionSchema.safeParse(input).success, false);
  }
});
test('hover exposes content, retains target/provenance, and field reads expose the outcome', async t => {
  const { agent, step } = await open(t);
  const record = await step({ action: 'hover', selector: '#hover' });
  assert.equal(record.success, true); assert.equal(record.result.hovered, true);
  assert.equal(record.result.target.selector, '#hover');
  assert.equal(record.result.keyboardOnly, false); assert.equal(record.after.inputPath, 'mouse-assisted');
  assert.equal(record.after.keyboardOnly, false);
  assert.equal((await step({ action: 'inspect', selector: '#tip' })).result.element.computed.display, 'block');
  const shot = await step({ action: 'screenshot' }); assert.equal(shot.success, true);
  assert.equal((await step({ action: 'inspect', selector: '#tip' })).result.element.computed.display, 'block');
  const read = await agent.request({ tool: 'read', evidenceId: record.evidenceId, options: { view: 'field', field: '/result/hovered' } });
  assert.equal(read.success, true); assert.equal(JSON.parse(read.data), true);
  const absent = await agent.request({ tool: 'read', evidenceId: shot.evidenceId, options: { view: 'field', field: '/result/hovered' } });
  assert.equal(absent.error.code, 'AUDIT_FIELD_ABSENT');
});
test('hover/focus preserve observe errors for absent and ambiguous targets', async t => {
  const { step } = await open(t);
  for (const selector of ['#absent', '.many']) {
    const observed = await step({ action: 'inspect', selector });
    for (const action of ['hover', 'focus']) {
      const record = await step({ action, selector });
      assert.equal(record.success, false); assert.equal(record.error.code, observed.error.code);
      assert.match(record.error.message, /exactly one element/);
      assert.notEqual(record.result.hovered, true); assert.notEqual(record.result.focused, true);
    }
  }
});
test('hidden hover fails explicitly with no success result', async t => {
  const { step } = await open(t);
  const record = await step({ action: 'hover', selector: '#hidden' });
  assert.equal(record.success, false); assert.equal(record.error.code, 'AUDIT_HOVER_TARGET_NOT_VISIBLE');
  assert.equal(record.result.hovered, false);
});
test('programmatic focus records actual focus without creating a keyboard path; reset restores provenance', async t => {
  const { agent, step } = await open(t);
  const record = await step({ action: 'focus', selector: '#focus' });
  assert.equal(record.success, true); assert.equal(record.result.focused, true);
  assert.equal(record.after.active.nodeId, record.result.target.nodeId);
  assert.equal(record.after.active.documentId, record.result.target.documentId);
  assert.equal(record.result.keyboardOnly, false); assert.equal(record.after.keyboardOnly, false);
  assert.equal(record.result.inputPath, 'programmatic'); assert.equal(record.after.inputPath, 'programmatic');
  assert.equal(Object.hasOwn(record.result, 'keyboardPath'), false);
  const read = await agent.request({ tool: 'read', evidenceId: record.evidenceId, options: { view: 'field', field: '/result/focused' } });
  assert.equal(read.success, true); assert.equal(JSON.parse(read.data), true);
  const pressed = await step({ action: 'press', key: 'Tab' });
  assert.equal(pressed.result.keyboardPath.length, 1); assert.equal(pressed.after.keyboardOnly, false);
  assert.equal(pressed.after.inputPath, 'programmatic');
  const reset = await step({ action: 'reset' }); assert.equal(reset.after.keyboardOnly, true);
  assert.equal(reset.after.inputPath, 'keyboard-only');
  assert.equal((await step({ action: 'press', key: 'Tab' })).result.keyboardPath.length, 1);
});
test('hidden, disabled, inert and nonfocusable focus do not claim acquisition', async t => {
  const { step } = await open(t);
  for (const selector of ['#hidden', '#disabled', '#inert', '#plain']) {
    const record = await step({ action: 'focus', selector });
    assert.equal(record.success, false); assert.equal(record.error.code, 'AUDIT_FOCUS_NOT_ACQUIRED');
    assert.equal(record.result.focused, false); assert.equal(record.after.keyboardOnly, false);
    assert.equal(record.after.inputPath, 'programmatic'); assert.equal(Object.hasOwn(record.result, 'keyboardPath'), false);
  }
});
test('closed live sessions reject hover/focus without executing or allocating evidence', async t => {
  const site = await fixture(t, html), session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => session.finish());
  await session.finish();
  for (const action of ['hover', 'focus']) await assert.rejects(session.perform({ action, selector: '#focus' }), { code: 'AUDIT_SESSION_CLOSED' });
  assert.equal((await session.finished).records.length, 0);
});

test('covered hover fails with an execution code and false outcome', async t => {
  const { step } = await open(t, html.replace('</body>', '<div id="cover"></div></body>'));
  const record = await step({ action: 'hover', selector: '#hover' });
  assert.equal(record.success, false); assert.equal(record.error.code, 'AUDIT_HOVER_FAILED');
  assert.equal(record.result.hovered, false); assert.equal(record.after.keyboardOnly, false);
});
test('budget exhaustion retains queued hover/focus as not_run', async t => {
  const site = await fixture(t, html), session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url, maxActions: 1 });
  t.after(() => session.finish());
  const records = await Promise.all([
    session.perform({ action: 'snapshot' }), session.perform({ action: 'hover', selector: '#hover' }), session.perform({ action: 'focus', selector: '#focus' }),
  ]);
  await session.finished;
  for (const record of records.slice(1)) {
    assert.equal(record.success, false); assert.equal(record.result.status, 'not_run');
    assert.equal(record.error.code, 'AUDIT_ACTION_BUDGET_EXCEEDED');
    assert.equal(record.before, null); assert.equal(record.after, null);
    assert.equal(record.result.hovered, undefined); assert.equal(record.result.focused, undefined);
  }
});

// No browser is launched: inject observations and locator operations to exercise the retained executor.
test('local executor preserves hover/focus provenance and verifies focus identity without keyboardPath', async () => {
  for (const action of ['hover', 'focus']) for (const outcome of ['success', 'failed', 'wrong-node', 'wrong-document']) {
    const browser = Object.create(AuditBrowser.prototype);
    const target = { nodeId: 'doc:target', documentId: 'doc', selector: '#target', tag: 'button', attributes: {} };
    Object.assign(browser, { keyboardOnly: true, inputPath: 'keyboard-only', keyboardPath: [], blocked: [], navigationResponses: [] });
    browser.settle = async () => {};
    browser.observe = async () => ({ raw: { nodes: [target] }, state: {
      documentId: 'doc', stateId: 'state', keyboardOnly: browser.keyboardOnly, inputPath: browser.inputPath,
      active: { ...target, ...(outcome === 'wrong-node' ? { nodeId: 'other' } : {}), ...(outcome === 'wrong-document' ? { documentId: 'other' } : {}) },
    } });
    browser.uniqueSelector = async () => ({ element: target, locator: {
      isVisible: async () => true, hover: async () => { if (outcome === 'failed') throw Error('covered'); },
      focus: async () => {}, evaluate: async () => outcome !== 'failed',
    } });
    const record = await browser.executeOnce({ action, selector: '#target' }, 3000, {});
    assert.equal(record.success, action === 'hover' ? outcome !== 'failed' : outcome === 'success');
    assert.equal(record.result[action === 'hover' ? 'hovered' : 'focused'], record.success);
    assert.equal(record.result.inputPath, action === 'hover' ? 'mouse-assisted' : 'programmatic');
    assert.equal(record.after.inputPath, record.result.inputPath);
    assert.equal(record.after.keyboardOnly, false); assert.equal(record.result.keyboardOnly, false);
    assert.equal(Object.hasOwn(record.result, 'keyboardPath'), false); assert.deepEqual(browser.keyboardPath, []);
    const base = { evidenceId: 'ev-base', action: 'snapshot', success: true, after: record.after, result: { nodes: [target] } };
    const finding = { criterionId: '2.1.1', target: { evidenceId: base.evidenceId, nodeId: target.nodeId } };
    assert.ok(precheckSession(finding, [base, { ...record, action, evidenceId: 'ev-action' }]).some(n => n.rule === 'no-keyboard-evidence'));
  }
});

test('local adapter leaves hover/focus not_run with null states after action exhaustion', async t => {
  const site = await fixture(t, html); let dispatched = 0;
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url, maxActions: 1 }, { createBrowser: () => ({
    start: async () => ({}), close: async () => [], axeTags: [],
    execute: async () => { dispatched++; return { success: true, before: null, after: null, result: {} }; },
  }) });
  const rows = await Promise.all([{ action: 'snapshot' }, { action: 'hover', selector: '#hover' }, { action: 'focus', selector: '#focus' }].map(a => session.perform(a)));
  await session.finished;
  assert.equal(dispatched, 1);
  for (const row of rows.slice(1)) {
    assert.equal(row.result.status, 'not_run'); assert.equal(row.before, null); assert.equal(row.after, null);
    assert.equal(row.result.hovered, undefined); assert.equal(row.result.focused, undefined);
  }
  const count = session.records.length;
  for (const action of ['hover', 'focus']) await assert.rejects(session.perform({ action, selector: '#focus' }), { code: 'AUDIT_SESSION_CLOSED' });
  assert.equal(session.records.length, count); assert.equal(dispatched, 1);
});
