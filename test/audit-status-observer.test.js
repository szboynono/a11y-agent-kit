import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fixture } from './helpers.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { reviewAudit } from '../src/audit/review.js';
import { AuditBrowser } from '../src/audit/browser.js';
import { openStatusRecorder } from '../src/audit/status-observer.js';

for (const mode of ['live', 'absent', 'focus', 'unchanged']) test(`observe_status: ${mode}`, async t => {
  const site = await fixture(t, `<!doctype html><html lang="en"><title>Status</title><body>
    <button id="go" onclick="${mode === 'unchanged' ? '' : `setTimeout(()=>{document.querySelector('#result').textContent='2 results';${mode === 'focus' ? "document.querySelector('#result').focus()" : ''}},40)`}">Calculate</button>
    <p id="result" tabindex="-1" ${mode === 'live' ? 'role="status"' : ''}>Idle</p></body></html>`);
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  const response = await agent.request({ tool: 'step', actions: [{ action: 'observe_status', trigger: { action: 'click', selector: '#go' }, windowMs: 100, expectedText: '2 results' }] });
  assert.equal(response.success, true, JSON.stringify(response));
  assert.equal(response.budget.toolCalls, 1); assert.equal(response.budget.requestedActions, 3);
  const records = await Promise.all(response.records.map(r => fs.readFile(path.join(agent.directory, `${r.evidenceId}.json`), 'utf8').then(JSON.parse)));
  const [before, operation, after] = records, observation = operation.result.statusObservation;
  assert.equal(observation.disconnected, true);
  assert.equal(observation.noChange, mode === 'unchanged');
  assert.equal(before.after.stateId, operation.before.stateId);
  assert.equal(operation.after.stateId, after.after.stateId);
  const node = after.result.nodes.find(n => n.attributes.id === 'result');
  assert.equal(node.ancestorSemantics.complete, true);
  if (mode !== 'unchanged') {
    assert.ok(observation.mutations.some(m => m.targetNodeId === node.nodeId));
    assert.equal(observation.mutations.some(m => m.hasLiveRegionAncestor), mode === 'live');
  }
  if (mode === 'focus') assert.ok(observation.focus.some(f => f.nodeId === node.nodeId));
  if (mode !== 'absent' && mode !== 'live') { await agent.close(); return; }
  const checkpoint = await agent.request({ tool: 'checkpoint', proposal: { auditor: { name: 'Maker' }, findings: [{
    id: 'F1', title: 'Result count', criterionId: '4.1.3', target: { evidenceId: after.evidenceId, nodeId: node.nodeId },
    evidenceIds: records.map(r => r.evidenceId), observation: 'Idle changes to a count.', reason: 'Action result summary.',
    applicability: 'A compact count after Calculate.', exceptions: 'Review live semantics.', scope: 'This status only.', method: 'dom',
  }] } });
  const submitted = await agent.request({ tool: 'submit', checkpointDigest: checkpoint.checkpoint.checkpointDigest });
  const review = await reviewAudit(submitted.proposalReportPath, { reviewer: { name: 'Independent reviewer', independentOfAuditor: true }, decisions: [{ findingId: 'F1', verdict: 'supported',
    checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' }, reason: 'The original observations establish the result count.',
    prerequisiteNotes: { v2: { statusMessage: { beforeEvidenceId: before.evidenceId, operationEvidenceId: operation.evidenceId, afterEvidenceId: after.evidenceId,
      resultKind: 'status-summary', applicability: 'Compact action-result summary.', semanticReview: 'Reviewed focus away from count, complete ancestors and equivalent status presentations.' } } },
  }] });
  assert.equal(review.confirmedFindings.length, mode === 'absent' ? 1 : 0, JSON.stringify(review.verificationQueue));
  if (mode === 'live') assert.ok(JSON.stringify(review.verificationQueue).includes('live-region semantics'));
  await agent.close();
});

test('recorder causes no DOM mutations and disconnects on success and failed trigger', async t => {
  const site = await fixture(t, '<!doctype html><title>Recorder</title><button id="go">Go</button><p id="result">Idle</p>');
  const browser = new AuditBrowser({ url: site.url, viewport: { width: 800, height: 600 }, maxElements: 100 });
  await browser.start(); t.after(() => browser.close()); await browser.observe();
  const html = await browser.page.content();
  const capture = await openStatusRecorder(browser);
  const initial = await capture.finish(); assert.equal(initial.noChange, true);
  assert.equal(await browser.page.content(), html);
  await browser.page.evaluate(() => { document.querySelector('#result').textContent = 'Later'; });
  assert.equal((await capture.finish()).mutations.length, 0);
  await capture.close();
  await browser.page.evaluate(() => {
    globalThis.observerCount = 0;
    const observe = MutationObserver.prototype.observe, disconnect = MutationObserver.prototype.disconnect;
    MutationObserver.prototype.observe = function(...args) { globalThis.observerCount++; return observe.apply(this, args); };
    MutationObserver.prototype.disconnect = function(...args) { globalThis.observerCount--; return disconnect.apply(this, args); };
  });
  const result = await browser.execute({ action: 'click', selector: '#missing' }, 100, { windowMs: 50 });
  assert.equal(result.success, false);
  assert.equal(await browser.page.evaluate(() => globalThis.observerCount), 0);
});

test('post-trigger window survives actionability delays and includes inserted live semantics', async t => {
  const site = await fixture(t, `<!doctype html><title>Delayed</title><button id="go" disabled>Go</button><div id="result"></div>
    <script>setTimeout(()=>document.querySelector('#go').disabled=false,700);
    document.querySelector('#go').onclick=()=>setTimeout(()=>document.querySelector('#result').innerHTML='<span role="status">Saved</span>',150);</script>`);
  const browser = new AuditBrowser({ url: site.url, viewport: { width: 800, height: 600 }, maxElements: 100 });
  await browser.start(); t.after(() => browser.close());
  const result = await browser.execute({ action: 'click', selector: '#go' }, 3000, { windowMs: 200 });
  assert.equal(result.success, true, JSON.stringify(result.error));
  const mutation = result.result.statusObservation.mutations.find(m => m.text === 'Saved');
  assert.ok(mutation, JSON.stringify(result.result.statusObservation));
  assert.equal(mutation.hasLiveRegionAncestor, true);
  assert.equal(mutation.ancestorSemantics[0].role, 'status');
  assert.equal(mutation.targetNodeId, mutation.nodeId);
});

test('status snapshot reports truncation of its actual hidden and visible collection', async t => {
  const site = await fixture(t, '<!doctype html><title>Truncation</title><div hidden></div><div hidden></div><div hidden></div><div hidden></div><div hidden></div><button>Go</button><p>Result</p>');
  const browser = new AuditBrowser({ url: site.url, viewport: { width: 800, height: 600 }, maxElements: 5 });
  await browser.start(); t.after(() => browser.close());
  const result = await browser.execute({ action: 'snapshot' }, 3000, { snapshot: true });
  assert.equal(result.success, true);
  assert.equal(result.result.nodes.length, 5);
  assert.equal(result.result.truncation.capturedElements, 5);
  assert.equal(result.result.truncation.omittedVisibleElements, 2);
  assert.ok(result.result.truncation.omittedElements > 0);
});
