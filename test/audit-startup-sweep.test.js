import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { ToolError } from '../src/evidence.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { openAuditSession } from '../src/audit/live.js';
import { runStartupSweep, fitSweep, narrowViewportFor, SWEEP_LIMITS } from '../src/audit/sweep.js';
import { precheckSession } from '../src/audit/precheck.js';
import { MCP_TEXT_LIMIT } from '../src/audit/projection.js';
import { fixture } from './helpers.js';

// Five focusable elements; one unnamed button and one that removes itself on focus (focus falls to <body> mid-sequence).
const PAGE = '<!doctype html><html lang="en"><head><title>Sweep</title></head><body><a href="#a">Home</a><button id="save">Save</button>' +
  '<button class="icon"></button><input id="q" aria-label="Search"><button id="gone">X</button><div id="tool" class="tool">Flip</div><a href="#z">Last</a>' +
  "<script>document.getElementById('gone').addEventListener('focus', e => setTimeout(() => e.target.remove(), 0));</script></body></html>";

// ---- Unit: traversal logic over a fake session -------------------------------------------------------------------
const node = (id, tag = 'button', extra = {}) => ({ nodeId: `doc-1:${id}`, documentId: 'doc-1', tag, selector: `#${id}`, labelText: '', text: id, ...extra });
const BODY = { nodeId: 'doc-1:body', documentId: 'doc-1', tag: 'body', selector: 'html:nth-of-type(1) > body:nth-of-type(1)' };
function fakeSession(focusSequence, { documentAt = {}, failAt, throwAt } = {}) {
  const records = [{ evidenceId: 'ev-0001', action: 'snapshot', success: true, after: { documentId: 'doc-1', url: 'http://x/', stateId: 's0', active: BODY, viewport: { width: 1280, height: 900 } }, result: { nodes: [] } }];
  let presses = 0;
  const perform = async action => {
    const evidenceId = `ev-${String(records.length + 1).padStart(4, '0')}`;
    if (action.action === 'press' && throwAt === presses + 1) throw new ToolError('AUDIT_TEST_THROW', 'perform rejected');
    let record;
    if (action.action === 'press') {
      presses++;
      const active = focusSequence[presses - 1] ?? BODY;
      record = { evidenceId, action: 'press', arguments: { key: action.key }, success: failAt !== presses, ...(failAt === presses ? { error: { code: 'AUDIT_PRESS_FAILED' } } : {}),
        before: records.at(-1).after, after: { documentId: documentAt[presses] ?? 'doc-1', url: 'http://x/', stateId: `s${presses}`, active } };
    } else record = { evidenceId, action: action.action, arguments: action, success: true, after: { documentId: 'doc-2', url: 'http://x/', stateId: 'r', active: BODY }, ...(action.action === 'screenshot' ? { png: { path: 'x.png' } } : {}) };
    records.push(record);
    return record;
  };
  return { records: () => records, perform, actions: () => records.slice(1).map(row => row.action) };
}
const sweepWith = (fake, extra = {}) => runStartupSweep({ perform: fake.perform, records: fake.records, now: () => 0, deadline: 1e12, remainingActions: 178,
  viewport: { width: 1280, height: 900 }, viewports: [], ...extra });

test('sweep: stops on a focus cycle, reports a mid-sequence focus loss, then restores with one reset', async () => {
  const [a, b, c] = ['a', 'b', 'c'].map(id => node(id));
  const fake = fakeSession([a, b, BODY, c, BODY, a]);
  const { sweep, evidenceIds } = await sweepWith(fake);
  assert.equal(sweep.tabPresses, 6); assert.equal(sweep.distinctFocused, 3); assert.equal(sweep.stopped, 'cycle_after_document');
  assert.deepEqual(sweep.focusOrder.map(row => [row.step, row.nodeId, row.evidenceId]), [[1, a.nodeId, 'ev-0002'], [2, b.nodeId, 'ev-0003'], [4, c.nodeId, 'ev-0005']]);
  // Body after b and then a new element: lost mid-sequence. Body after c and then a seen element: end of tab order, not a loss.
  assert.deepEqual(sweep.focusLost, [{ step: 3, evidenceId: 'ev-0004', focusedTag: 'body', fromNodeId: b.nodeId, fromSelector: '#b' }]);
  assert.deepEqual(fake.actions(), ['press', 'press', 'press', 'press', 'press', 'press', 'reset']);
  assert.equal(sweep.restore.method, 'reset'); assert.equal(sweep.restore.success, true); assert.equal(sweep.restore.evidenceId, 'ev-0008');
  assert.equal(evidenceIds.length, 7);
  assert.match(sweep.abstentions[0], /narrow viewport: none declared/);
  // A direct cycle without <body> in between.
  const direct = await sweepWith(fakeSession([a, b, a]));
  assert.equal(direct.sweep.stopped, 'cycle'); assert.equal(direct.sweep.tabPresses, 3); assert.deepEqual(direct.sweep.focusLost, []);
});

test('sweep: stops when focus leaves the document, on a document change, at the limit, and on a failed press', async () => {
  const [a, b] = ['a', 'b'].map(id => node(id));
  const left = await sweepWith(fakeSession([a, BODY, BODY, b]));
  assert.equal(left.sweep.stopped, 'left_document'); assert.equal(left.sweep.tabPresses, 3); assert.deepEqual(left.sweep.focusLost, []);
  const moved = await sweepWith(fakeSession([a, b], { documentAt: { 2: 'doc-9' } }));
  assert.equal(moved.sweep.stopped, 'document_changed'); assert.equal(moved.sweep.distinctFocused, 1);
  const many = Array.from({ length: 40 }, (_, i) => node(`n${i}`));
  const capped = await sweepWith(fakeSession(many));
  assert.equal(capped.sweep.tabPresses, SWEEP_LIMITS.tabPresses); assert.equal(capped.sweep.stopped, 'limit');
  // Capped by remaining actions: at most half of them, minus the restore.
  const few = fakeSession(many), small = await sweepWith(few, { remainingActions: 10 });
  assert.equal(small.sweep.tabPresses, 4); assert.deepEqual(few.actions().slice(-1), ['reset']);
  const failed = await sweepWith(fakeSession([a, b], { failAt: 2 }));
  assert.equal(failed.sweep.stopped, 'press_failed'); assert.equal(failed.sweep.pressError, 'AUDIT_PRESS_FAILED'); assert.equal(failed.sweep.restore.success, true);
  // A thrown perform never escapes: it is reported and the summary keeps what was recorded.
  const thrown = await sweepWith(fakeSession([a, b], { throwAt: 2 }));
  assert.equal(thrown.sweep.error.code, 'AUDIT_TEST_THROW'); assert.equal(thrown.sweep.distinctFocused, 1);
  // Too few actions: abstain instead of a partial traversal.
  const none = fakeSession([a]), skipped = await sweepWith(none, { remainingActions: 4 });
  assert.equal(skipped.sweep.tabPresses, 0); assert.deepEqual(none.actions(), []); assert.match(skipped.sweep.abstentions.join(' '), /tab traversal: not enough actions/);
});

test('sweep: narrow viewport is the narrowest declared one, captured once and restored', async () => {
  assert.equal(narrowViewportFor([{ width: 1440, height: 900 }], { width: 1280, height: 900 }), null);
  assert.deepEqual(narrowViewportFor([{ width: 768, height: 1024 }, { width: 390, height: 844 }], { width: 1280, height: 900 }), { width: 390, height: 844 });
  const fake = fakeSession([node('a'), node('a')]);
  const { sweep } = await sweepWith(fake, { viewports: [{ width: 768, height: 1024 }, { width: 390, height: 844 }] });
  assert.deepEqual(fake.actions(), ['press', 'press', 'reset', 'viewport', 'screenshot', 'snapshot', 'viewport']);
  assert.deepEqual(sweep.narrow, { viewport: '390x844', screenshotEvidenceId: 'ev-0006', snapshotEvidenceId: 'ev-0007', restoredViewport: '1280x900', restoreEvidenceId: 'ev-0008', restored: true });
  assert.deepEqual(sweep.ran, ['tab traversal', 'narrow viewport']);
  assert.match(sweep.abstentions.join(' '), /768x1024: declared but not captured/);
});

test('sweep summary fits any room by dropping detail, never evidence handles', async () => {
  const many = Array.from({ length: 30 }, (_, i) => node(`element-with-a-long-identifier-${i}`, 'button', { labelText: 'A long visible label '.repeat(4) }));
  const { sweep } = await sweepWith(fakeSession(many));
  const full = { ...sweep, counted: '1 tool call and 26 actions', evidence: { first: 'ev-0002', last: 'ev-0027', count: 26 } };
  for (const room of [100_000, 3000, 1200, 600, 250]) {
    const fitted = fitSweep(full, room);
    assert.ok(Buffer.byteLength(JSON.stringify(fitted)) <= room || room < 300, `${room}: ${JSON.stringify(fitted).length}`);
    assert.deepEqual(fitted.evidence, full.evidence, String(room));
    if (room < 100_000) assert.match(fitted.omittedNote, /read its evidenceId/);
  }
  assert.equal(fitSweep(full, 100_000), full);
  const mid = fitSweep(full, 3000);
  assert.equal(mid.focusOrder.length + mid.focusOrderOmitted, 25); assert.ok(mid.focusOrder.every(row => !row.name));
});

// ---- Agent: real browser, real records -------------------------------------------------------------------------
async function startAgent(t, page = PAGE, manifest = {}, injected = {}) {
  const site = await fixture(t, page);
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, ...manifest }, injected);
  t.after(() => agent.close());
  const first = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'axe' }] });
  assert.equal(first.success, true, JSON.stringify(first));
  return { site, agent };
}
const readRecord = (agent, evidenceId) => fs.readFile(path.join(agent.directory, `${evidenceId}.json`), 'utf8').then(JSON.parse);

test('agent sweep: ordinary press records, exactly 1 tool call plus one action each, restore by reset, coverage sees them', async t => {
  const { agent, site } = await startAgent(t, PAGE, { viewports: [{ width: 390, height: 844 }] });
  const swept = await agent.startupSweep();
  assert.equal(swept.success, true, JSON.stringify(swept));
  const { sweep } = swept, budget = agent.budget();
  assert.equal(budget.toolCalls, 2);
  assert.equal(budget.requestedActions, 2 + sweep.evidence.count); assert.equal(budget.returnedActions, budget.requestedActions);
  assert.equal(sweep.counted, `1 tool call and ${sweep.evidence.count} actions`);
  // Home, Save, the unnamed icon button, Search, gone (focus falls to body), Last, body (end), Home again (cycle).
  assert.equal(sweep.stopped, 'cycle_after_document');
  assert.deepEqual(sweep.focusOrder.map(row => row.name ?? null), ['Home', 'Save', null, 'Search', 'Last']);
  assert.equal(sweep.focusOrder[1].stableSelector, '#save'); assert.equal(sweep.focusOrder[1].stableSelectorConfidence, 'unique-anchor');
  assert.equal(sweep.focusLost.length, 1); assert.equal(sweep.focusLost[0].fromSelector, '#q');
  for (const row of sweep.focusOrder) {
    const record = await readRecord(agent, row.evidenceId);
    assert.equal(record.action, 'press'); assert.deepEqual(record.arguments, { key: 'Tab' }); assert.equal(record.success, true);
    assert.equal(record.after.active.nodeId, row.nodeId); assert.ok(Object.hasOwn(record.before, 'active'));
  }
  const reset = await readRecord(agent, sweep.restore.evidenceId);
  assert.equal(reset.action, 'reset'); assert.equal(reset.success, true); assert.equal(reset.after.url, site.url);
  assert.notEqual(reset.after.documentId, reset.before.documentId); assert.equal(reset.after.active.tag, 'body');
  const shot = await readRecord(agent, sweep.narrow.screenshotEvidenceId);
  assert.equal(shot.action, 'screenshot'); assert.deepEqual(shot.after.viewport, { width: 390, height: 844 }); assert.ok(shot.png);
  const back = await readRecord(agent, sweep.narrow.restoreEvidenceId);
  assert.deepEqual(back.after.viewport, { width: 1280, height: 900 });
  assert.deepEqual(swept.coverage.keyboard, { tabPresses: sweep.tabPresses, traversal: true });
  assert.ok(swept.coverage.viewports.captured.includes('390x844'));
  // The reloaded entry state needs its own axe scan, and the hint moves past press/screenshot.
  assert.match(swept.next, /has not been axe-scanned/); assert.doesNotMatch(swept.next, /keyboard\/focus \(press/);
  // The sweep runs once; a second attempt is refused and counted like any request.
  const again = await agent.startupSweep();
  assert.equal(again.success, false); assert.equal(again.sweep.error.code, 'AUDIT_SWEEP_NOT_AT_START'); assert.equal(agent.budget().toolCalls, 3);
  // The host's first press starts from the restored document's initial focus.
  const host = await agent.request({ tool: 'step', actions: [{ action: 'press', key: 'Tab' }] });
  const press = await readRecord(agent, host.records[0].evidenceId);
  assert.equal(press.after.active.attributes.href, '#a'); assert.deepEqual(press.result.keyboardPath.length, 1);
  await agent.close();
});

test('agent sweep: a 2.1.1 claim on an element the sweep focused gets no no-keyboard-evidence note; an unreached one does', async t => {
  const { agent } = await startAgent(t);
  assert.equal((await agent.startupSweep()).success, true);
  const snapshot = await readRecord(agent, 'ev-0001');
  const nodeOf = selector => snapshot.result.nodes.find(row => row.selector === selector).nodeId;
  const finding = (id, nodeId, evidenceId = 'ev-0001') => ({ id, title: `${id} not keyboard operable`, criterionId: '2.1.1', target: { evidenceId, nodeId }, evidenceIds: [evidenceId],
    observation: 'Observed node.', reason: 'Draft reason.', applicability: 'Draft applicability.', exceptions: 'None recorded.', scope: 'This node.' });
  // An observation after the restore (new document) of an element the sweep focused also matches, by its unique #id selector.
  const after = await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#save' }] });
  const inspected = await readRecord(agent, after.records[0].evidenceId);
  assert.notEqual(inspected.after.documentId, snapshot.after.documentId);
  const proposal = { auditor: { name: 'Sweep test' }, findings: [finding('F-save', nodeOf('#save')), finding('F-tool', nodeOf('#tool')),
    finding('F-save-reloaded', inspected.result.element.nodeId, inspected.evidenceId)] };
  const draft = await agent.request({ tool: 'checkpoint', proposal });
  assert.equal(draft.success, true, JSON.stringify(draft));
  assert.deepEqual(draft.precheck.notes.filter(note => note.rule === 'no-keyboard-evidence').map(note => note.findingId), ['F-tool']);
  assert.ok(draft.precheck.notes.find(note => note.findingId === 'F-tool').basis.navigationPresses >= 5);
  assert.deepEqual(draft.precheck.notes.filter(note => note.rule === 'operation-not-tested').map(note => note.findingId), ['F-save', 'F-save-reloaded']);
  assert.ok(draft.coverage.keyboard.traversal);
  await agent.close();
});

test('precheck matches a press after a reload by equal unique #id selector, not by a different id', () => {
  const target = { nodeId: 'doc-1:n1', documentId: 'doc-1', tag: 'button', selector: '#save', attributes: {} };
  const snap = { evidenceId: 'ev-0001', action: 'snapshot', success: true, after: { documentId: 'doc-1', url: 'http://x/', active: BODY }, result: { nodes: [target] } };
  const press = selector => ({ evidenceId: 'ev-0002', action: 'press', arguments: { key: 'Tab' }, success: true, before: { documentId: 'doc-2', url: 'http://x/', active: { ...BODY, nodeId: 'doc-2:body' } },
    after: { documentId: 'doc-2', url: 'http://x/', active: { nodeId: 'doc-2:n7', documentId: 'doc-2', tag: 'button', selector } } });
  const finding = { id: 'K', criterionId: '2.1.1', target: { evidenceId: 'ev-0001', nodeId: target.nodeId } };
  assert.deepEqual(precheckSession(finding, [snap, press('#save')]), []);
  assert.deepEqual(precheckSession(finding, [snap, press('#saved')]).map(note => note.rule), ['no-keyboard-evidence']);
  assert.deepEqual(precheckSession(finding, [snap, press('#save > span')]).map(note => note.rule), ['no-keyboard-evidence']);
});

test('agent sweep failure is reported in sweep.error and never blocks the session', async t => {
  // A session whose presses reject: the sweep records the error, skips nothing else it can do, and the host continues.
  const injected = { openAuditSession: async manifest => {
    const real = await openAuditSession(manifest);
    return Object.freeze({ runId: real.runId, directory: real.directory, manifest: real.manifest, startedAt: real.startedAt, deadlineAt: real.deadlineAt,
      perform: action => action.action === 'press' ? Promise.reject(new ToolError('AUDIT_TEST_PRESS', 'press rejected')) : real.perform(action),
      observeStatus: real.observeStatus, probeSelectors: real.probeSelectors, finish: real.finish, finished: real.finished,
      get status() { return real.status; }, get records() { return real.records; } });
  } };
  const { agent } = await startAgent(t, PAGE, {}, injected);
  const swept = await agent.startupSweep();
  assert.equal(swept.success, false); assert.equal(swept.sweep.error.code, 'AUDIT_TEST_PRESS'); assert.equal(swept.sweep.tabPresses, 0);
  assert.equal(agent.status, 'open'); assert.equal(agent.budget().toolCalls, 2);
  const next = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  assert.equal(next.success, true, JSON.stringify(next));
  await agent.close();
});

// ---- MCP: start response, opt-out, bounded size ----------------------------------------------------------------
async function mcpStart(t, page, manifest) {
  const site = await fixture(t, page);
  const client = new Client({ name: 'sweep-test', version: '1' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(mcpTransport({ command: process.execPath, args: ['src/cli.js', 'serve'], stderr: 'pipe' }), { mode: 'auto' });
  const response = await client.callTool({ name: 'a11y_audit_start', arguments: { manifest: { projectRoot: site.projectRoot, url: site.url, ...manifest } } });
  const bytes = Buffer.byteLength(response.content[0].text);
  assert.ok(bytes <= MCP_TEXT_LIMIT, `${bytes} bytes`);
  assert.equal(response.structuredContent.success, true, response.content[0].text);
  return { start: response.structuredContent, bytes, request: request => client.callTool({ name: 'a11y_audit_request', arguments: { runId: response.structuredContent.runId, request } }).then(r => r.structuredContent) };
}

test('MCP start requires startupSweep:true, counts 1 extra call; default and false skip interaction', async t => {
  const on = await mcpStart(t, PAGE, { startupSweep: true, viewports: [{ width: 390, height: 844 }] });
  const { sweep } = on.start.startup;
  assert.equal(on.start.startup.ran, 'snapshot + axe'); assert.equal(on.start.startup.counted, '1 tool call and 2 actions');
  assert.equal(on.start.budget.toolCalls, 2); assert.equal(on.start.budget.requestedActions, 2 + sweep.evidence.count);
  assert.ok(sweep.tabPresses >= 5); assert.equal(sweep.distinctFocused, 5); assert.ok(sweep.narrow.screenshotEvidenceId);
  assert.equal(on.start.startup.coverage.keyboard.traversal, true);
  assert.match(on.start.next, /^startup\.sweep already ran tab traversal and narrow viewport as ordinary records/);
  // The narrow screenshot is an ordinary viewable record.
  const view = await on.request({ tool: 'view', evidenceId: sweep.narrow.screenshotEvidenceId });
  assert.equal(view.success, true, JSON.stringify(view));

  const defaults = await mcpStart(t, PAGE, {});
  assert.equal(defaults.start.startup.sweep, undefined); assert.equal(defaults.start.budget.requestedActions, 2);
  const off = await mcpStart(t, PAGE, { startupSweep: false });
  assert.equal(off.start.startup.sweep, undefined); assert.equal(off.start.budget.toolCalls, 1); assert.equal(off.start.budget.requestedActions, 2);
  // startupAxe:false skips the whole startup step, sweep included.
  const none = await mcpStart(t, PAGE, { startupAxe: false });
  assert.equal(none.start.startup, undefined); assert.equal(none.start.budget.toolCalls, 0);
});

test('cleanup survives rejected capture and soft deadline, using reserved timeouts', async () => {
  for (const mode of ['throw', 'expiry', 'failed-restore']) {
    const fake = fakeSession([node('a'), node('a')]);
    let clock = 0, viewport = '1280x900';
    const calls = [];
    const result = await sweepWith(fake, { now: () => clock, deadline: 1000, viewports: [{ width: 390, height: 844 }],
      perform: async (action, options) => {
        calls.push({ action: action.action, options });
        if (action.action === 'screenshot') {
          if (mode === 'throw') throw new ToolError('CAPTURE_REJECTED', 'capture rejected');
          clock = 1001;
        }
        if (action.action === 'viewport') viewport = `${action.width}x${action.height}`;
        const record = await fake.perform(action);
        if (mode === 'failed-restore' && options.cleanup && action.action === 'viewport') return { ...record, success: false, error: { code: 'RESTORE_FAILED' } };
        return record;
      } });
    assert.equal(viewport, '1280x900');
    assert.equal(result.sweep.complete, false);
    assert.ok(result.sweep.error);
    const back = calls.at(-1);
    assert.equal(back.action, 'viewport'); assert.equal(back.options.cleanup, true);
    assert.ok(back.options.timeoutMs > 0 && back.options.timeoutMs <= SWEEP_LIMITS.cleanupMs);
    if (mode === 'expiry') assert.equal(calls.filter(c => c.action === 'snapshot').length, 0);
  }
});

test('soft work deadline caps admission and passes remaining timeout; cleanup is separate', async () => {
  const fake = fakeSession(Array.from({ length: 10 }, (_, i) => node(`n${i}`)));
  let clock = 0;
  const calls = [];
  const { sweep } = await sweepWith(fake, { now: () => clock, perform: async (a, options) => {
    calls.push({ action: a.action, at: clock, ...options }); clock += 14000; return fake.perform(a);
  } });
  assert.deepEqual(calls.map(c => c.at), [0, 14000, 28000, 42000, 56000]);
  assert.deepEqual(calls.slice(0, 4).map(c => c.timeoutMs), [45000, 31000, 17000, 3000]);
  assert.equal(calls.at(-1).cleanup, true); assert.equal(sweep.restore.success, true);
});

test('agent cleanup after exploration expiry restores viewport; cancellation and hard deadline forbid new cleanup actions', async t => {
  for (const mode of ['expiry', 'cancel', 'hard']) {
    let clock = Date.now(), live, interrupted = false;
    const { agent } = await startAgent(t, PAGE, { viewports: [{ width: 390, height: 844 }] }, {
      now: () => clock, openAuditSession: async manifest => {
        live = await openAuditSession(manifest);
        return { ...live, get records() { return live.records; }, get status() { return interrupted ? 'closing' : live.status; },
          perform: async (action, options) => {
            const r = await live.perform(action, options);
            if (action.action === 'screenshot') {
              if (mode === 'cancel') interrupted = true;
              else clock += mode === 'hard' ? 600001 : 480001;
            }
            return r;
          } };
      } });
    const result = await agent.startupSweep();
    assert.equal(result.success, false); assert.equal(result.sweep.complete, false);
    if (mode === 'expiry') { assert.equal(result.sweep.narrow.restored, true); assert.deepEqual(live.records.at(-1).after.viewport, { width: 1280, height: 900 }); }
    else { assert.equal(result.sweep.narrow.restored, false); assert.equal(live.records.at(-1).action, 'screenshot'); }
    await agent.close();
  }
});

test('changed document on reload stays unscanned and fresh axe finds the new image', async t => {
  const page = '<!doctype html><html lang="en"><title>Reload</title><main><h1>Reload</h1><button>Save</button></main><script>if(sessionStorage.seen) document.querySelector("main").insertAdjacentHTML("beforeend", \'<img id="missing" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">\'); sessionStorage.seen="1";</script></html>';
  const { agent } = await startAgent(t, page);
  const old = await readRecord(agent, 'ev-0002');
  assert.equal(old.result.axe.violations.some(v => v.id === 'image-alt'), false);
  const swept = await agent.startupSweep();
  assert.match(swept.next, /has not been axe-scanned/);
  const inspected = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  assert.match(inspected.next, /has not been axe-scanned/);
  const fresh = await agent.request({ tool: 'step', actions: [{ action: 'axe' }] });
  const latest = await readRecord(agent, fresh.records[0].evidenceId);
  assert.notEqual(latest.after.documentId, old.after.documentId);
  assert.ok(latest.result.axe.violations.some(v => v.id === 'image-alt'));
  await agent.close();
});

test('focusable click-only widget retains operation advisory until current-document keyboard result is observed', async t => {
  const { agent } = await startAgent(t, '<!doctype html><title>Widget</title><div role="button" tabindex="0" id="save" onclick="this.textContent=\'Done\'">Save</div>');
  await agent.request({ tool: 'step', actions: [{ action: 'press', key: 'Tab' }] });
  const snap = await readRecord(agent, 'ev-0001');
  const target = snap.result.nodes.find(n => n.selector === '#save');
  const finding = { id: 'K', criterionId: '2.1.1', title: 'Cannot activate using keyboard', target: { evidenceId: snap.evidenceId, nodeId: target.nodeId } };
  const records = [snap, await readRecord(agent, 'ev-0003')];
  assert.deepEqual(precheckSession(finding, records).map(n => n.rule), ['operation-not-tested']);
  await agent.request({ tool: 'step', actions: [{ action: 'press', key: 'Enter' }] });
  const enter = await readRecord(agent, 'ev-0004');
  assert.equal(enter.after.active.text, 'Save');
  assert.deepEqual(precheckSession(finding, [...records, enter]), []);
  await agent.request({ tool: 'step', actions: [{ action: 'click', selector: '#save' }] });
  const click = await readRecord(agent, 'ev-0005');
  assert.equal(click.after.active.text, 'Done');
  const changed = { ...target, nodeId: 'new:save', documentId: 'new', tag: 'div', text: 'Delete' };
  const reload = { ...snap, evidenceId: 'reload', after: { ...snap.after, documentId: 'new' }, result: { nodes: [changed] } };
  assert.deepEqual(precheckSession({ ...finding, target: { evidenceId: 'reload', nodeId: changed.nodeId } }, [...records, enter, reload]).map(n => n.rule), ['operation-not-tested']);
  await agent.close();
});

 test('failed reset is an incomplete sweep even when the perform resolves', async () => {
  const fake = fakeSession([node('a'), node('a')]);
  const { sweep } = await sweepWith(fake, { perform: async (a, options) => {
    const r = await fake.perform(a);
    return a.action === 'reset' ? { ...r, success: false, error: { code: 'RESET_FAILED' } } : r;
  } });
  assert.equal(sweep.complete, false); assert.equal(sweep.restore.success, false); assert.equal(sweep.error.code, 'RESET_FAILED');
});

test('live cleanup watchdog stops a blocked restore without restarting browser work', async t => {
  const site = await fixture(t, PAGE);
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url });
  site.beforeResponse(() => new Promise(resolve => setTimeout(resolve, 300)));
  const restore = await session.perform({ action: 'reset' }, { cleanupTimeoutMs: 25 });
  assert.equal(restore.success, false); assert.equal(restore.error.code, 'AUDIT_CLEANUP_TIMEOUT');
  const later = await session.perform({ action: 'snapshot' });
  assert.equal(later.success, false); assert.equal(later.result.status, 'not_run');
  await session.finish();
  // Let the deliberately delayed HTTP handler finish before the fixture removes its root.
  await new Promise(resolve => setTimeout(resolve, 350));
});
