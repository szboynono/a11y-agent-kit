import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { openAuditSession } from '../src/audit/live.js';
import { submitAudit, reviewAudit, checkAudit } from '../src/audit/review.js';
import { writeAuditArtifact, saveAuditDocument } from '../src/audit/store.js';

async function capture(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'status-readiness-')));
  const html = `<!doctype html><html lang="en"><title>Status</title><body>
  <button id="go">Calculate</button><p id="status">Idle</p><script>
  go.onclick = async () => { statusNode.textContent='Pending'; await fetch('/complete'); statusNode.textContent='2 results'; };
  const statusNode=document.querySelector('#status');
  </script></body></html>`;
  await fs.writeFile(path.join(root, 'index.html'), html);
  const completion = Promise.withResolvers();
  const server = http.createServer(async (req, res) => {
    if (req.url === '/complete') { await completion.promise; res.end('done'); }
    else res.writeHead(200, { 'content-type': 'text/html' }).end(html);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { completion.resolve(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await fs.rm(root, { recursive: true, force: true }); });
  const session = await openAuditSession({ projectRoot: root, url: `http://127.0.0.1:${server.address().port}/` });
  t.after(() => session.finish());
  // Keyboard focus is established before the measured click. The server holds completion.
  await session.perform({ action: 'press', key: 'Tab' });
  const before = await session.perform({ action: 'inspect', selector: '#status' });
  const operation = await session.perform({ action: 'click', selector: '#go' });
  const pending = await session.perform({ action: 'inspect', selector: '#status' });
  assert.equal(pending.result.element.text, 'Pending');
  assert.equal(operation.after.stateId, pending.after.stateId);
  completion.resolve();
  const ready = await session.perform({ action: 'wait_for', selector: '#status', condition: 'text', expected: '2 results' });
  const after = await session.perform({ action: 'inspect', selector: '#status' });
  const audit = await session.finish();
  assert.notEqual(operation.after.stateId, after.after.stateId);
  assert.equal(ready.after.stateId, after.after.stateId);
  assert.equal(before.result.element.nodeId, after.result.element.nodeId);
  return { audit, before, operation, pending, ready, after };
}
function inputs(c) {
  const finding = { id: 'F1', title: 'Result count update', criterionId: '4.1.3',
    target: { evidenceId: c.after.evidenceId, nodeId: c.after.result.element.nodeId },
    evidenceIds: c.audit.records.map(r => r.evidenceId), observation: 'Idle becomes a result count while focus stays on Calculate.',
    reason: 'The count summarizes the completed calculation.', applicability: 'An action-result summary.', exceptions: 'No live semantics observed.', scope: 'This result count in this document.' };
  const notes = { beforeEvidenceId: c.before.evidenceId, operationEvidenceId: c.operation.evidenceId,
    settledEvidenceId: c.ready.evidenceId, afterEvidenceId: c.after.evidenceId, resultKind: 'status-summary',
    applicability: 'This is a compact status summary.', semanticReview: 'Count changes without target focus; complete ancestor chains have no live semantics.' };
  return { finding, notes };
}
async function review(c, finding, notes) {
  const submitted = await submitAudit(c.audit.reportPath, { auditor: { name: 'Fixture auditor' }, findings: [finding] });
  return reviewAudit(submitted.reportPath, { reviewer: { name: 'Fixture reviewer', independentOfAuditor: true }, decisions: [{
    findingId: 'F1', verdict: 'supported', checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
    reason: 'Reviewed this local status summary.', prerequisiteNotes: { v2: { statusMessage: notes } },
  }] });
}

test('real asynchronous trigger remains queued without readiness, and readiness passes public review/check', async t => {
  const c = await capture(t), { finding, notes } = inputs(c);
  const synchronous = { ...notes }; delete synchronous.settledEvidenceId;
  const old = await review(c, finding, synchronous);
  assert.equal(old.confirmedFindings.length, 0);
  assert.equal(old.verificationQueue.length, 1);
  const result = await review(c, finding, notes);
  assert.equal(result.confirmedFindings.length, 1, JSON.stringify(result.verificationQueue));
  assert.equal(result.verificationQueue.length, 0);
  assert.equal(result.confirmedFindings[0].evidenceGate.semanticAssessment, 'reviewer-dependent');
  assert.equal((await checkAudit(result.reportPath)).status, 'current');
});

// Rebind each tampered chain to fresh JSON artifacts, so failures exercise public
// evidence validation/review rather than merely failing an attachment hash.
test('original async chain refuses bounded tamper counterexamples', async t => {
  const original = await capture(t);
  const variants = [
    'missing-readiness', 'wrong-readiness', 'failed-readiness', 'cited-failed-readiness', 'future-readiness', 'uncited-readiness',
    'readiness-as-operation', 'wrong-selector', 'wrong-result-selector', 'nonliteral-predicate',
    'wrong-expected', 'wrong-actual', 'ambiguous', 'unmatched', 'truncated-readiness', 'omitted-readiness',
    'wrong-final-state', 'wrong-final-node', 'wrong-final-document', 'wrong-operation-document', 'wrong-readiness-document', 'wrong-after-reference', 'truncated-final-text',
    'live-ancestor', 'no-change', 'intervening-fill', 'intervening-click', 'intervening-press',
    'intervening-navigation', 'intervening-scroll', 'intervening-viewport', 'intervening-spacing',
    'failed-uncited-record', 'uncited-observation', 'unrelated-wait', 'unsupported-selector',
    'unstable-before', 'unstable-after', 'target-focus', 'uncertain-applicability',
  ];
  for (const variant of variants) await t.test(variant, async () => {
    const c = structuredClone(original), { finding, notes } = inputs(c);
    const records = c.audit.records;
    for (const key of ['before', 'operation', 'pending', 'ready', 'after']) c[key] = records.find(r => r.evidenceId === c[key].evidenceId);
    const unreference = r => { finding.evidenceIds = finding.evidenceIds.filter(id => id !== r.evidenceId); };
    if (variant === 'missing-readiness') notes.settledEvidenceId = 'ev-9999';
    if (variant === 'wrong-readiness') notes.settledEvidenceId = c.pending.evidenceId;
    if (variant === 'failed-readiness') { c.ready.success = false; unreference(c.ready); }
    if (variant === 'cited-failed-readiness') c.ready.success = false;
    if (variant === 'future-readiness') records.push(...records.splice(records.indexOf(c.ready), 1));
    if (variant === 'uncited-readiness') unreference(c.ready);
    if (variant === 'readiness-as-operation') notes.operationEvidenceId = c.ready.evidenceId;
    if (variant === 'wrong-selector') c.ready.arguments.selector = '#go';
    if (variant === 'wrong-result-selector') c.ready.result.selector = '#go';
    if (variant === 'nonliteral-predicate') c.ready.arguments.condition = c.ready.result.condition = 'visible';
    if (variant === 'wrong-expected') c.ready.arguments.expected = 'other';
    if (variant === 'wrong-actual') c.ready.result.actual = 'other';
    if (variant === 'ambiguous') c.ready.result.count = 2;
    if (variant === 'unmatched') c.ready.result.matched = false;
    if (variant === 'truncated-readiness') c.ready.result.actualTruncated = true;
    if (variant === 'omitted-readiness') c.ready.result.actualOmitted = true;
    if (variant === 'wrong-final-state') c.after.before.stateId = c.after.after.stateId = 'different-state';
    if (variant === 'wrong-final-node') { c.after.result.element.nodeId += '-other'; finding.target.nodeId = c.after.result.element.nodeId; }
    if (variant === 'wrong-final-document') {
      c.after.before.documentId += '-other'; c.after.after.documentId += '-other'; c.after.result.element.documentId += '-other';
    }
    if (variant === 'wrong-readiness-document') c.ready.before.documentId += '-other';
    if (variant === 'wrong-after-reference') notes.afterEvidenceId = c.before.evidenceId;
    if (variant === 'truncated-final-text') c.after.result.element.textTruncated = true;
    if (variant === 'wrong-operation-document') c.operation.after.documentId += '-other';
    if (variant === 'live-ancestor') c.after.result.element.ancestorSemantics.ancestors[0].attributes['aria-live'] = 'polite';
    if (variant === 'no-change') c.before.result.element.text = c.after.result.element.text;
    const mutations = { 'intervening-fill': 'fill', 'intervening-click': 'click', 'intervening-press': 'press', 'intervening-navigation': 'navigate', 'intervening-scroll': 'scroll', 'intervening-viewport': 'viewport', 'intervening-spacing': 'spacing' };
    if (mutations[variant]) c.pending.action = mutations[variant];
    if (variant === 'failed-uncited-record') { c.pending.success = false; unreference(c.pending); }
    if (variant === 'uncited-observation') unreference(c.pending);
    if (variant === 'unrelated-wait') { c.pending.action = 'wait_for'; c.pending.arguments = { ...c.ready.arguments, selector: '#go' }; c.pending.result = { ...c.ready.result, selector: '#go' }; }
    if (variant === 'unsupported-selector') c.before.result.element.selector = c.after.result.element.selector = 'html > body > p';
    if (variant === 'unstable-before') c.before.before.stateId = 'raced';
    if (variant === 'unstable-after') c.after.before.stateId = 'raced';
    if (variant === 'target-focus') c.after.result.element.focused = true;
    if (variant === 'uncertain-applicability') notes.resultKind = 'uncertain';
    const directory = path.dirname(c.audit.reportPath);
    for (const r of records) {
      const { json: unused, ...body } = r;
      r.json = await writeAuditArtifact(directory, `${variant}-${r.evidenceId}.json`, `${JSON.stringify(body)}\n`);
    }
    c.audit = await saveAuditDocument(directory, 'audit', c.audit);
    if (variant === 'cited-failed-readiness') {
      await assert.rejects(review(c, finding, notes), { code: 'INVALID_AUDIT_EVIDENCE_REFERENCE' });
      return;
    }
    const result = await review(c, finding, notes);
    assert.equal(result.confirmedFindings.length, 0, variant);
    assert.equal(result.verificationQueue.length, 1, variant);
    assert.equal(result.verificationQueue[0].evidenceGate.status, 'insufficient', variant);
    assert.equal((await checkAudit(result.reportPath)).status, 'current', variant);
  });
});
