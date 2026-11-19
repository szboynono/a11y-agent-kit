import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { writeAuditArtifact, saveAuditDocument } from '../src/audit/store.js';
import { randomUUID } from 'node:crypto';
import { fixture } from './helpers.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { openAuditSession } from '../src/audit/live.js';
import { AuditBrowser } from '../src/audit/browser.js';
import { submitAudit, reviewAudit, checkAudit } from '../src/audit/review.js';

const inspect = { action: 'inspect', selector: '#status' };
const click = { action: 'click', selector: '#go' };
const wait = { action: 'wait_for', selector: '#status', condition: 'attribute', name: 'aria-busy', value: 'false', timeoutMs: 5000 };
const step = (agent, actions) => agent.request({ tool: 'step', actions });
async function field(agent, evidenceId, name) {
  let options = { view: 'field', field: name }, data = '';
  do {
    const r = await agent.request({ tool: 'read', evidenceId, options });
    assert.equal(r.success, true, JSON.stringify(r)); data += r.data; options = r.pagination.next;
  } while (options);
  return JSON.parse(data);
}

async function setup(t, { stages = 1, mode = 'honest', error = false } = {}) {
  // Test-owned barriers control the producer, never the agent's readiness decision.
  const gates = Array.from({ length: stages }, () => Promise.withResolvers());
  const seen = gates.map(() => Promise.withResolvers());
  const sampled = gates.map(() => Promise.withResolvers());
  const started = Promise.withResolvers(), entered = Promise.withResolvers();
  let terminal, waitSettled = false, heldStage = -1;
  const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const i = Number(req.url.slice(1));
    if (!Number.isInteger(i) || !gates[i]) { res.writeHead(404).end(); return; }
    if (i === 0) { terminal = `${error ? 'Error' : 'Result'} ${randomUUID()}`; started.resolve(); }
    heldStage = i; seen[i].resolve(); await gates[i].promise;
    res.end(i === stages - 1 ? terminal : `Stage ${i + 1}`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    gates.forEach(g => g.resolve()); server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const html = `<!doctype html><html lang="en"><title>Contract fixture</title><body>
  <button id="go">Calculate</button><p id="status" ${mode === 'missing' ? '' : 'aria-busy="false"'}>Idle</p>
  <script>
  const go = document.querySelector('#go'); let node = document.querySelector('#status');
  go.onclick = async () => {
    go.disabled = true;
    ${['missing', 'stale'].includes(mode) ? '' : "node.setAttribute('aria-busy', 'true');"}
    node.textContent = 'Pending';
    ${mode === 'duplicate' ? 'node.after(node.cloneNode(true));' : ''}
    for (let i = 0; i < ${stages}; i++) {
      const text = await (await fetch('http://127.0.0.1:${server.address().port}/' + i)).text();
      ${mode === 'replacement' ? 'if (i === 0) { const next = node.cloneNode(true); node.replaceWith(next); node = next; }' : ''}
      node.textContent = text;
      ${mode === 'early' ? "node.setAttribute('aria-busy', 'false');" : ''}
    }
    ${mode === 'missing' ? '' : "node.setAttribute('aria-busy', 'false');"}
  };
  </script></body></html>`;
  const site = await fixture(t, html);
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, wallSeconds: 30 }, {
    openAuditSession: async manifest => {
      // Test-only observer: acknowledge real predicate results, without changing
      // the function, arguments, returned observation or readiness decision.
      const start = AuditBrowser.prototype.start;
      const startObserver = t.mock.method(AuditBrowser.prototype, 'start', async function (...args) {
        const result = await start.apply(this, args);
        const evaluate = this.page.evaluate.bind(this.page);
        this.page.evaluate = async (fn, arg) => {
          // A new stage is announced only after its prior DOM update. Tag at
          // invocation so a delayed reply from the old stage cannot release it.
          const stage = heldStage;
          const observation = await evaluate(fn, arg);
          if (fn.name === 'readinessObservation' && arg?.selector === '#status' &&
              arg.condition === 'attribute' && arg.name === 'aria-busy' &&
              arg.value === 'false' && stage >= 0 && observation.count === 1 &&
              observation.actual === 'true' && observation.matched === false) {
            sampled[stage].resolve({ stage, ...observation });
          }
          return observation;
        };
        return result;
      });
      let session;
      try { session = await openAuditSession(manifest); }
      finally { startObserver.mock.restore(); }
      // Observe admission only; execute every action through the real browser/session.
      return { ...session, get records() { return session.records; }, perform(action) {
        const result = session.perform(action);
        if (action.action === 'wait_for') {
          void result.then(() => { waitSettled = true; }, () => { waitSettled = true; });
          entered.resolve();
        }
        return result;
      } };
    },
  });
  t.after(() => agent.close({ reason: 'interrupted' }));
  await step(agent, [{ action: 'press', key: 'Tab' }, inspect]);
  const before = await field(agent, 'ev-0002', '/result');
  return { agent, gates, seen, sampled, started, entered, before, waitSettled: () => waitSettled, terminal: () => terminal };
}

for (const [label, stages, error] of [['single stage', 1, false], ['multiple stages', 3, false], ['terminal error', 2, true]]) {
  test(`unknown result collection: ${label}`, { timeout: 20000 }, async t => {
    const c = await setup(t, { stages, error });
    const pending = step(c.agent, [click, wait, inspect]);
    await c.started.promise; await c.entered.promise;
    for (let i = 0; i < stages; i++) {
      await c.seen[i].promise;
      const sample = await c.sampled[i].promise;
      assert.equal(sample.stage, i); assert.equal(sample.matched, false);
      assert.equal(sample.actual, 'true'); assert.equal(sample.count, 1);
      assert.equal(c.waitSettled(), false, `wait must remain pending at held stage ${i}`);
      c.gates[i].resolve();
    }
    const result = await pending;
    assert.equal(result.success, true); assert.ok(result.records.every(r => r.success));
    const ready = await field(c.agent, 'ev-0004', '/result');
    const after = await field(c.agent, 'ev-0005', '/result');
    assert.equal(ready.matched, true); assert.equal(ready.actual, 'false'); assert.equal(ready.count, 1);
    assert.equal(after.element.text, c.terminal()); // Unknown until after activation; public read.
    assert.equal(after.element.attributes['aria-busy'], 'false');
    assert.equal(after.element.nodeId, c.before.element.nodeId);
    assert.equal(after.element.documentId, c.before.element.documentId);
    assert.equal(after.element.text.startsWith('Error'), error); // Terminal != business success.
    const closed = await c.agent.close();
    const audit = JSON.parse(await fs.readFile(closed.sourceAudit.reportPath));
    assert.deepEqual(audit.records.map(r => r.action), ['press', 'inspect', 'click', 'wait_for', 'inspect']);
    const [,, operation, readiness, final] = audit.records;
    assert.deepEqual({ action: readiness.action, ...readiness.arguments }, wait);
    assert.deepEqual({ action: operation.action, ...operation.arguments }, click);
    assert.deepEqual({ action: final.action, ...final.arguments }, inspect);
    assert.equal(JSON.stringify(readiness.arguments).includes(c.terminal()), false);
    for (const r of audit.records) {
      assert.equal(r.before.documentId, after.element.documentId);
      assert.equal(r.after.documentId, after.element.documentId);
    }
    assert.equal(final.before.stateId, final.after.stateId);
    assert.equal(readiness.after.stateId, final.after.stateId);
    assert.equal(audit.records[1].after.stateId, operation.before.stateId);
    assert.notEqual(operation.after.stateId, final.after.stateId);
    await assertStatusReview(audit);
    if (label === 'multiple stages') await attributeVariants(t, audit);
  });
}

async function assertStatusReview(audit, { supported = true, resultKind = 'status-summary', verdict = 'supported', omit = [], notesOverride = {} } = {}) {
  const originals = await Promise.all([audit.reportPath, ...audit.records.map(r => r.json.path)].map(p => fs.readFile(p)));
  const [before, operation, ready, after] = ['ev-0002', 'ev-0003', 'ev-0004', 'ev-0005'].map(id => audit.records.find(r => r.evidenceId === id));
  const submitted = await submitAudit(audit.reportPath, { auditor: { name: 'Synthetic fixture auditor' }, findings: [{
    id: 'F1', title: 'Result update', criterionId: '4.1.3',
    target: { evidenceId: after.evidenceId, nodeId: after.result.element?.nodeId ?? before.result.element.nodeId },
    evidenceIds: audit.records.map(r => r.evidenceId).filter(id => !omit.includes(id)), observation: 'The observed text changes.',
    reason: 'The result summarizes the operation.', applicability: 'Action result summary.',
    exceptions: 'No live semantics.', scope: 'This fixture result.',
  }] });
  // Test-authored adjudication exercises the structural gate; it is not expert gold.
  const reviewed = await reviewAudit(submitted.reportPath, { reviewer: { name: 'Synthetic fixture reviewer', independentOfAuditor: true }, decisions: [{
    findingId: 'F1', verdict, checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
    reason: 'Synthetic supported verdict for gate regression.', prerequisiteNotes: { v2: { statusMessage: {
      beforeEvidenceId: before.evidenceId, operationEvidenceId: operation.evidenceId,
      settledEvidenceId: ready.evidenceId, afterEvidenceId: after.evidenceId,
      resultKind, applicability: 'Observed status summary.', semanticReview: 'No live ancestor semantics; focus stays away.', ...notesOverride,
    } } },
  }] });
  assert.equal(reviewed.confirmedFindings.length, supported ? 1 : 0, JSON.stringify(reviewed.verificationQueue));
  assert.equal(reviewed.verificationQueue.length, supported ? 0 : 1);
  assert.equal((await checkAudit(reviewed.reportPath)).status, 'current');
  const retained = await Promise.all([audit.reportPath, ...audit.records.map(r => r.json.path)].map(p => fs.readFile(p)));
  assert.deepEqual(retained, originals, 'review/check must not change source files or originals');
}

for (const mode of ['stale', 'early', 'missing', 'duplicate', 'replacement', 'timeout']) {
  test(`contract limitation: ${mode}`, { timeout: 20000 }, async t => {
    const c = await setup(t, { mode, stages: mode === 'early' ? 2 : 1 });
    await step(c.agent, [click]); await c.started.promise;
    const action = { ...wait, timeoutMs: ['missing', 'timeout'].includes(mode) ? 100 : 5000 };
    const pending = step(c.agent, [action]); await c.entered.promise;
    if (mode === 'early') { c.gates[0].resolve(); await c.seen[1].promise; }
    if (mode === 'replacement') c.gates[0].resolve();
    const response = await pending;
    assert.equal(response.records.length, 1);
    const ready = await field(c.agent, 'ev-0004', '/result');
    const expectedError = mode === 'duplicate' ? 'AUDIT_READINESS_AMBIGUOUS'
      : ['missing', 'timeout'].includes(mode) ? 'AUDIT_READINESS_TIMEOUT' : null;
    assert.equal(response.records[0].success, !expectedError);
    assert.equal(ready.matched, !expectedError);
    if (expectedError) assert.equal(response.records[0].errorCode, expectedError);
    await step(c.agent, [inspect]);
    const after = await field(c.agent, 'ev-0005', '/result');
    if (['stale', 'early'].includes(mode)) {
      assert.equal(after.element.attributes['aria-busy'], 'false');
      assert.notEqual(after.element.text, c.terminal()); // API accepts dishonest early state.
    }
    if (mode === 'replacement') {
      assert.notEqual(after.element.nodeId, c.before.element.nodeId);
      assert.equal(after.element.documentId, c.before.element.documentId);
      assert.equal(after.element.text, c.terminal()); // Match does not bind original identity.
    }
    if (mode === 'missing') assert.equal(after.element.attributes['aria-busy'], undefined);
    const closed = await c.agent.close();
    const audit = JSON.parse(await fs.readFile(closed.sourceAudit.reportPath));
    assert.deepEqual(audit.records.map(r => r.action), ['press', 'inspect', 'click', 'wait_for', 'inspect']);
    assert.equal(audit.records[3].success, !expectedError); // Failed originals remain retained.
    if (['stale', 'early'].includes(mode)) {
      await assertStatusReview(audit); // Changed Pending/intermediate summary can structurally pass.
      await assertStatusReview(audit, { supported: false, resultKind: 'uncertain' });
      await assertStatusReview(audit, { supported: false, verdict: 'insufficient' });
    } else if (mode === 'duplicate') {
      assert.equal(audit.records[4].success, false);
      await assert.rejects(assertStatusReview(audit), { code: 'INVALID_AUDIT_EVIDENCE_REFERENCE' });
    } else await assertStatusReview(audit, { supported: false, omit: expectedError ? ['ev-0004'] : [] });
  });
}

// Rebind variants to original JSON artifacts so the structural gate, not a stale
// attachment hash, decides. The fresh positive capture above is the sole seed.
async function attributeVariants(t, original) {
  const originalBodies = new Map(original.records.map(({ json, ...body }) =>
    [body.evidenceId, JSON.stringify(body)]));
  const edits = [
    ['wrong-name', 3, 'arguments.name', 'disabled'],
    ['wrong-value', 3, 'arguments.value', 'true'],
    ['boolean-value', 3, 'arguments.value', false],
    ['wrong-condition', 3, 'arguments.condition', 'visible'],
    ['wrong-result-condition', 3, 'result.condition', 'text'],
    ['wrong-selector', 3, 'arguments.selector', '#go'],
    ['wrong-result-selector', 3, 'result.selector', '#go'],
    ['unmatched', 3, 'result.matched', false],
    ['duplicate', 3, 'result.count', 2],
    ['wrong-actual', 3, 'result.actual', 'true'],
    ['omitted', 3, 'result.actualOmitted', true],
    ['truncated', 3, 'result.actualTruncated', true],
    ['wrong-final-busy', 4, 'result.element.attributes.aria-busy', 'true'],
    ['wrong-node', 1, 'result.element.nodeId', 'other'],
    ['wrong-document', 3, 'before.documentId', 'other'],
    ['wrong-element-document', 4, 'result.element.documentId', 'other'],
    ['wrong-ready-state', 3, 'after.stateId', 'other'],
    ['wrong-before-binding', 2, 'before.stateId', 'other'],
    ['unstable-before', 1, 'before.stateId', 'other'],
    ['unstable-after', 4, 'before.stateId', 'other'],
    ['focus', 4, 'result.element.focused', true],
    ['missing-focus', 4, 'after.active', null],
    ['incomplete-ancestors', 4, 'result.element.ancestorSemantics.complete', false],
    ['live-ancestor', 4, 'result.element.ancestorSemantics.ancestors.0.attributes.aria-live', 'polite'],
    ['broken-lineage', 4, 'result.element.parentNodeId', 'other'],
    ['truncated-attributes', 4, 'result.element.attributesTruncated', ['aria-busy']],
    ['truncated-before-text', 1, 'result.element.textTruncated', true],
    ['truncated-final-text', 4, 'result.element.textTruncated', true],
    ['no-change', 4, 'result.element.text', 'Idle'],
    ['not-clicked', 2, 'result.clicked', false],
    ['complex-selector', 1, 'result.element.selector', 'body > p'],
    ['wrong-id', 4, 'result.element.attributes.id', 'other'],
    ['snapshot-before', 1, 'action', 'snapshot'],
    ['snapshot-after', 4, 'action', 'snapshot'],
  ];
  for (const key of ['condition', 'selector', 'name', 'value']) edits.push([`missing-predicate-${key}`, 3, `arguments.${key}`]);
  for (const key of ['condition', 'selector', 'matched', 'count', 'actual', 'actualOmitted', 'actualTruncated']) edits.push([`missing-result-${key}`, 3, `result.${key}`]);
  const special = ['uncited', 'failed', 'missing-reference', 'out-of-order', 'press', 'fill',
    'intervening-inspect', 'intervening-wait', 'intervening-click', 'intervening-before',
    'uncertain', 'substantive-result'];
  for (const [label, index, pointer, value] of [...edits, ...special.map(v => [v])]) await t.test(label, async () => {
    const audit = structuredClone(original), options = { supported: false };
    if (pointer) {
      const keys = pointer.split('.'), key = keys.pop();
      const obj = keys.reduce((o, k) => o[k], audit.records[index]);
      if (value === undefined) delete obj[key]; else obj[key] = value;
    }
    if (label === 'uncited') options.omit = ['ev-0004'];
    if (label === 'failed') audit.records[3].success = false;
    if (label === 'missing-reference') options.notesOverride = { settledEvidenceId: 'ev-9999' };
    if (label === 'out-of-order') audit.records.push(...audit.records.splice(3, 1));
    if (['press', 'fill'].includes(label)) {
      audit.records[2].action = label;
      audit.records[2].arguments = label === 'press' ? { key: 'Enter' } : { selector: '#go', value: 'x' };
      audit.records[2].result = label === 'press' ? {} : { filled: true };
    }
    if (label.startsWith('intervening-')) {
      const extra = structuredClone(audit.records[label === 'intervening-wait' ? 3 : 1]);
      extra.evidenceId = 'ev-0006';
      if (label === 'intervening-click') { extra.action = 'click'; extra.result = { clicked: true }; }
      audit.records.splice(label === 'intervening-before' ? 2 : 4, 0, extra);
    }
    if (['uncertain', 'substantive-result'].includes(label)) options.resultKind = label;
    const directory = path.dirname(audit.reportPath);
    for (const r of audit.records) {
      const { json: unused, ...body } = r;
      const serialized = JSON.stringify(body);
      // Most variants edit one record. Reuse the immutable attachments for the
      // others instead of rewriting the entire capture for every subtest.
      if (serialized === originalBodies.get(r.evidenceId)) continue;
      r.json = await writeAuditArtifact(directory, `${label}-${r.evidenceId}.json`, `${serialized}\n`);
    }
    const bound = await saveAuditDocument(directory, 'audit', audit);
    if (label === 'wrong-element-document') {
      await assert.rejects(assertStatusReview(bound, options), { code: 'INVALID_AUDIT_TARGET' });
    } else if (label === 'failed') {
      await assert.rejects(assertStatusReview(bound, options), { code: 'INVALID_AUDIT_EVIDENCE_REFERENCE' });
      await assertStatusReview(bound, { ...options, omit: ['ev-0004'] });
    } else await assertStatusReview(bound, options);
  });
}
