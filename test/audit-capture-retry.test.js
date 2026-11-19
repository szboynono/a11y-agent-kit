import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { AuditBrowser, CAPTURE_RETRY_POLICY } from '../src/audit/browser.js';
import { openAuditSession } from '../src/audit/live.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { fixture } from './helpers.js';

const mutating = script => `<!doctype html><html lang="en"><head><title>Mutating fixture</title></head><body><main>
<h1>Hydrating</h1><button id="go" type="button">Go</button><p id="tick">0</p>
<script>
  const tick = document.querySelector('#tick');
  ${script}
</script></main></body></html>`;

// Queue the update on the first rendered-text read. The synchronous DOM observation
// sees 0, then the microtask changes it to 1 before the separate after-observation.
const changesOnce = mutating(`
  const read = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'innerText').get;
  let queued = false;
  Object.defineProperty(tick, 'innerText', { get() {
    if (!queued) {
      queued = true;
      queueMicrotask(() => { tick.textContent = '1'; });
    }
    return read.call(this);
  } });
`);

test('a snapshot with a first-attempt DOM mutation re-captures stable evidence and succeeds as one action', async t => {
  const site = await fixture(t, changesOnce);
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => session.finish());
  const record = await session.perform({ action: 'snapshot' });
  assert.equal(record.success, true, JSON.stringify(record.error));
  assert.equal(record.captureAttempts, 2);
  assert.ok(record.captureAttempts <= 1 + CAPTURE_RETRY_POLICY.maxExtraAttempts);
  assert.equal(record.captureRetries.length, record.captureAttempts - 1);
  for (const [index, retry] of record.captureRetries.entries()) {
    assert.equal(retry.attempt, index + 1);
    assert.equal(retry.reason, 'DOM_STATE_CHANGED');
    assert.notEqual(retry.beforeStateId, retry.afterStateId, 'each retry records the changed attempt it replaced');
  }
  // Stable-state invariant: before/after come from the successful attempt.
  assert.equal(record.before.stateId, record.after.stateId);
  assert.equal(record.before.stateId, record.captureRetries[0].afterStateId);
  assert.equal(record.before.documentId, record.captureRetries[0].documentId);
  assert.equal(record.result.nodes.find(node => node.selector === '#tick')?.text, '1');
  const report = await session.finish();
  assert.equal(report.records.length, 1);
  assert.equal(report.summary.executedActions, 1, 'retries are not extra actions');
  assert.equal(report.records[0].captureAttempts, record.captureAttempts);
  t.diagnostic(JSON.stringify({ retry: record.captureRetries[0], stableStateId: record.after.stateId,
    captureAttempts: record.captureAttempts, executedActions: report.summary.executedActions }));
});

test('a page that mutates forever still fails DOM_STATE_CHANGED after the bounded attempts, within the time bound', async t => {
  const site = await fixture(t, mutating(`
    let n = 0;
    setInterval(() => { tick.textContent = String(++n); }, 5);
  `));
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => session.finish());
  const started = performance.now();
  const record = await session.perform({ action: 'snapshot' });
  const elapsed = performance.now() - started;
  assert.equal(record.success, false);
  assert.equal(record.error.code, 'DOM_STATE_CHANGED');
  assert.equal(record.captureAttempts, 1 + CAPTURE_RETRY_POLICY.maxExtraAttempts);
  assert.equal(record.captureRetries.length, CAPTURE_RETRY_POLICY.maxExtraAttempts);
  assert.notEqual(record.before.stateId, record.after.stateId, 'the failed record keeps the changed state of its last attempt');
  // The retry window is 3 s; allow for the first and last capture themselves.
  assert.ok(elapsed < CAPTURE_RETRY_POLICY.windowMs + 2500, `elapsed ${Math.round(elapsed)} ms`);
  const inspect = await session.perform({ action: 'inspect', selector: '#go' });
  assert.equal(inspect.error?.code, 'DOM_STATE_CHANGED');
  assert.equal(inspect.captureAttempts, 1 + CAPTURE_RETRY_POLICY.maxExtraAttempts);
  // A mutating action on the same page runs once: no capture retry fields at all.
  const click = await session.perform({ action: 'click', selector: '#go' });
  assert.equal(click.success, true, JSON.stringify(click.error));
  assert.equal(Object.hasOwn(click, 'captureAttempts'), false);
  assert.equal((await session.finish()).summary.executedActions, 3);
});

test('mutating actions and observe_status snapshots are never retried; read-only observations retry at most twice', async () => {
  const browser = new AuditBrowser({ url: 'http://127.0.0.1/', viewport: { width: 800, height: 600 } }, { handleSignals: false });
  let calls = 0, settles = 0;
  const changed = action => ({ success: false, before: { documentId: 'doc-1', stateId: `s${calls}a` }, after: { documentId: 'doc-1', stateId: `s${calls}b` },
    result: {}, error: { code: 'DOM_STATE_CHANGED', stage: action.action } });
  browser.executeOnce = async action => { calls++; return changed(action); };
  browser.settleForRecapture = async () => { settles++; return { settleMs: 0, domQuiet: false }; };
  const mutatingActions = [{ action: 'click', selector: '#go' }, { action: 'fill', selector: '#go', value: 'x' }, { action: 'press', key: 'Tab' },
    { action: 'navigate', path: '/' }, { action: 'reset' }, { action: 'viewport', width: 400, height: 600 }];
  for (const action of mutatingActions) {
    calls = 0; settles = 0;
    const observation = await browser.execute(action, 15000);
    assert.equal(calls, 1, `${action.action} ran once`);
    assert.equal(settles, 0);
    assert.equal(Object.hasOwn(observation, 'captureAttempts'), false);
  }
  calls = 0;
  await browser.execute({ action: 'snapshot' }, 15000, { snapshot: true });
  assert.equal(calls, 1, 'observe_status snapshots stay timed against their trigger');
  for (const action of [{ action: 'snapshot' }, { action: 'inspect', selector: '#go' }, { action: 'inspect_many', selectors: ['#go'] }]) {
    calls = 0; settles = 0;
    const observation = await browser.execute(action, 15000);
    assert.equal(calls, 3, `${action.action} attempts`);
    assert.equal(settles, 2);
    assert.equal(observation.captureAttempts, 3);
    assert.deepEqual(observation.captureRetries.map(retry => [retry.attempt, retry.beforeStateId, retry.afterStateId]), [[1, 's1a', 's1b'], [2, 's2a', 's2b']]);
    assert.equal(observation.error.code, 'DOM_STATE_CHANGED');
    assert.deepEqual([observation.before.stateId, observation.after.stateId], ['s3a', 's3b']);
  }
  // A document change or navigation response is not a settle-able in-place change.
  for (const variant of [{ after: { documentId: 'doc-2', stateId: 'x' } }, { result: { navigationResponses: [{ status: 500 }] } }]) {
    calls = 0;
    browser.executeOnce = async action => { calls++; return { ...changed(action), ...variant }; };
    assert.equal((await browser.execute({ action: 'snapshot' }, 15000)).captureAttempts, 1);
    assert.equal(calls, 1);
  }
  // Other failures are not retried; a retry never outlives the action deadline.
  calls = 0;
  browser.executeOnce = async () => { calls++; return { success: false, before: null, after: null, result: {}, error: { code: 'AUDIT_SELECTOR_NOT_FOUND' } }; };
  assert.equal((await browser.execute({ action: 'inspect', selector: '#go' }, 15000)).captureAttempts, 1);
  calls = 0;
  browser.executeOnce = async action => { calls++; return changed(action); };
  assert.equal((await browser.execute({ action: 'snapshot' }, 100)).captureAttempts, 1);
});

test('MCP start: the startup snapshot on a hydrating page succeeds with unchanged budget counters', async t => {
  const site = await fixture(t, changesOnce);
  const transport = mcpTransport({ command: process.execPath, args: ['src/cli.js', 'serve'], stderr: 'pipe' });
  const client = new Client({ name: 'capture-retry-test', version: '1' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(transport, { mode: 'auto' });
  const start = (await client.callTool({ name: 'a11y_audit_start', arguments: { manifest: { projectRoot: site.projectRoot, url: site.url } } })).structuredContent;
  assert.equal(start.success, true, JSON.stringify(start));
  const [snapshot, axe] = start.startup.records;
  assert.equal(snapshot.evidenceId, 'ev-0001');
  assert.equal(snapshot.success, true, JSON.stringify(snapshot));
  assert.equal(snapshot.captureAttempts, 2, JSON.stringify(snapshot));
  assert.equal(axe.evidenceId, 'ev-0002');
  assert.equal(start.budget.toolCalls, 1);
  assert.equal(start.budget.requestedActions, 2);
  assert.equal(start.budget.returnedActions, 2);
  assert.equal(start.budget.failedActions + start.budget.successfulActions, 2);
});

test('agent step: a re-captured snapshot is one requested, returned and successful action', async t => {
  const site = await fixture(t, changesOnce);
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  const before = agent.budget();
  const step = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  assert.equal(step.records.length, 1);
  assert.equal(step.records[0].success, true, JSON.stringify(step.records[0]));
  assert.equal(step.records[0].captureAttempts, 2);
  const after = agent.budget();
  assert.equal(after.toolCalls - before.toolCalls, 1);
  assert.equal(after.requestedActions - before.requestedActions, 1);
  assert.equal(after.returnedActions - before.returnedActions, 1);
  assert.equal(after.successfulActions - before.successfulActions, 1);
  assert.equal(after.failedActions - before.failedActions, 0);
  await agent.close();
});
