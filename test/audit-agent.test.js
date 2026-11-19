import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { openAuditAgent, submitAuditCheckpoint } from '../src/audit/agent.js';
import { readAuditCheckpoint, recoverAuditCheckpoint } from '../src/audit/checkpoint.js';
import { checkAudit, reviewAudit, submitAudit } from '../src/audit/review.js';
import { AUDIT_TEXT_LIMIT } from '../src/audit/projection.js';
import { fixture } from './helpers.js';

const html = '<!doctype html><html lang="en"><head><title>Agent fixture</title></head><body><main><button id="unnamed"></button><button id="go" onclick="document.querySelector(\'#status\').textContent=\'2 results\'">Calculate</button><span id="status">1 result</span></main></body></html>';
const size = value => Buffer.byteLength(JSON.stringify(value));
async function record(agent, id) { return JSON.parse(await fs.readFile(path.join(agent.directory, `${id}.json`))); }
function proposal(observation, title = 'Unnamed control') {
  const node = observation.result.element ?? observation.result.nodes.find(n => n.attributes?.id === 'unnamed');
  return { auditor: { name: 'Local agent integration' }, findings: [{ id: 'F1', title, criterionId: '4.1.2',
    target: { evidenceId: observation.evidenceId, nodeId: node.nodeId }, evidenceIds: [observation.evidenceId],
    observation: 'An enabled native button has no accessible name.', reason: 'Review this captured local name observation.',
    applicability: 'Enabled button in this state.', exceptions: 'No name source present.', scope: 'Only this original target.', method: 'dom' }] };
}

test('agent saves drafts, continues actions, pages original evidence and explicitly submits a pinned checkpoint', async t => {
  const site = await fixture(t, html), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  const step = await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] });
  assert.equal(step.success, true); assert.equal(step.records.length, 1);
  assert.deepEqual(step.delivery, { checkpoint: 'none', submission: 'unsubmitted' });
  assert.equal(step.budget.toolCalls, 1); assert.equal(step.budget.requestedActions, 1);
  assert.equal(step.budget.returnedActions, 1); assert.equal(step.budget.successfulActions, 1);
  const original = await record(agent, 'ev-0001'), bytes = await fs.readFile(path.join(agent.directory, 'ev-0001.json'));
  assert.equal(original.result.element.ancestorSemantics.complete, true);
  const chain = original.result.element.ancestorSemantics.ancestors;
  assert.equal(chain.at(-1).tag, 'html'); assert.equal(chain.at(-1).parentNodeId, null);
  assert.equal(original.result.element.parentNodeId, chain[0].nodeId);
  const draft1 = await agent.request({ tool: 'checkpoint', proposal: proposal(original) });
  assert.equal(draft1.success, true); assert.equal(draft1.checkpoint.scoreable, false); assert.equal(draft1.sealed, false);
  assert.equal((await agent.request({ tool: 'step', actions: [{ action: 'click', selector: '#go' }] })).success, true);
  const draft2 = await agent.request({ tool: 'checkpoint', proposal: proposal(original, 'Revised draft title') });
  assert.deepEqual(draft2.delivery, { checkpoint: 'saved', submission: 'unsubmitted' });
  assert.equal(draft2.checkpoint.version, draft1.checkpoint.version + 1);
  assert.equal((await recoverAuditCheckpoint(agent.directory)).checkpointDigest, draft2.checkpoint.checkpointDigest);
  const ids = []; let pages = 0, options = { view: 'nodes', limit: 1, fields: ['tag', 'text', 'ancestorSemantics'] };
  do {
    const read = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options });
    assert.equal(read.success, true, JSON.stringify(read)); assert.ok(size(read) <= AUDIT_TEXT_LIMIT);
    assert.deepEqual(read.delivery, { checkpoint: 'saved', submission: 'unsubmitted' });
    assert.ok(Number.isFinite(read.budget.remainingWallMs));
    ids.push(...read.nodes.map(node => node.nodeId)); pages++;
    options = read.pagination.next;
  } while (options);
  assert.ok(pages > 1); assert.equal(new Set(ids).size, ids.length);
  const wrongRun = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'nodes', runId: 'another-run' } });
  assert.equal(wrongRun.error.code, 'AUDIT_RUN_MISMATCH');
  assert.deepEqual(wrongRun.delivery, { checkpoint: 'saved', submission: 'unsubmitted' });
  const submitted = await agent.request({ tool: 'submit', checkpointDigest: draft2.checkpoint.checkpointDigest });
  assert.equal(submitted.success, true, JSON.stringify(submitted)); assert.equal(submitted.status, 'needs_review');
  assert.deepEqual(submitted.delivery, { checkpoint: 'saved', submission: 'submitted' });
  const stored = JSON.parse(await fs.readFile(submitted.proposalReportPath));
  assert.equal(stored.sourceCheckpoint.checkpointDigest, draft2.checkpoint.checkpointDigest);
  assert.equal(stored.confirmedFindings.length, 0); assert.equal(stored.evidencePolicy, 'audit-evidence-2');
  assert.equal((await checkAudit(stored.reportPath)).status, 'current');
  assert.deepEqual(await fs.readFile(path.join(agent.directory, 'ev-0001.json')), bytes);
  const closed = await agent.close();
  assert.equal(closed.status, 'submitted');
  assert.deepEqual(closed.delivery, { checkpoint: 'saved', submission: 'submitted' });
  assert.deepEqual((await agent.request(null)).delivery, closed.delivery);
});

test('agent close drains admitted work and preserves a draft without automatic proposal promotion', async t => {
  const site = await fixture(t, html), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  const initial = await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] });
  assert.equal(initial.success, true);
  const raw = await record(agent, 'ev-0001');
  const pending = agent.request({ tool: 'checkpoint', proposal: proposal(raw) });
  const closing = agent.close();
  assert.equal((await pending).success, true);
  const closed = await closing;
  assert.equal(closed.status, 'incomplete'); assert.equal(closed.proposalAutomaticallyCreated, false);
  assert.deepEqual(closed.delivery, { checkpoint: 'saved', submission: 'unsubmitted' });
  assert.equal(closed.checkpoint.version, 1);
  assert.equal((await agent.request({ tool: 'read', evidenceId: 'ev-0001' })).error.code, 'AUDIT_AGENT_CLOSED');
  assert.equal((await fs.readdir(agent.directory)).filter(n => n.startsWith('audit-proposal-')).length, 0);
  const submitted = await submitAuditCheckpoint(closed.sourceAudit.reportPath, closed.checkpoint.checkpointPath);
  assert.equal(submitted.sourceCheckpoint.checkpointDigest, closed.checkpoint.checkpointDigest);
  assert.equal(submitted.status, 'needs_review'); assert.equal((await checkAudit(submitted.reportPath)).status, 'current');
});

test('finalization refuses exploration but permits draft saves; deadline has no automatic submission', async t => {
  const site = await fixture(t, html); let now = Date.now();
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, { now: () => now, setTimer: () => null, clearTimer: () => {} });
  t.after(() => agent.close());
  await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] });
  const original = await record(agent, 'ev-0001'); now += 490000;
  assert.equal((await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] })).error.code, 'EXPLORATION_BUDGET_EXHAUSTED');
  assert.equal(agent.budget().stage, 'finalization');
  const draft = await agent.request({ tool: 'checkpoint', proposal: proposal(original) }); assert.equal(draft.success, true);
  now += 110001;
  assert.equal((await agent.request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest })).error.code, 'HOST_WALL_BUDGET_EXHAUSTED');
  const end = await agent.close({ reason: 'wall_budget_exhausted' });
  assert.equal(end.status, 'incomplete'); assert.equal(end.checkpoint.version, 1);
  assert.deepEqual(end.delivery, { checkpoint: 'saved', submission: 'unsubmitted' });
  assert.equal(end.budget.remainingWallMs, 0); assert.equal(end.budget.stage, 'deadline');
  assert.equal((await fs.readdir(agent.directory)).filter(n => n.startsWith('audit-proposal-')).length, 0);
});

test('every malformed attempt is charged and every text result is bounded without echoing payloads', async t => {
  const site = await fixture(t, html), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  assert.equal(agent.budget().maxToolCalls, 60);
  assert.equal(agent.budget().remainingToolCalls, 60);
  const marker = 'UNTRUSTED_INPUT_SENTINEL';
  const tooLarge = await agent.request({ tool: 'read', evidenceId: 'ev-0001', unknown: marker.repeat(10000) });
  assert.equal(tooLarge.error.code, 'AGENT_REQUEST_TOO_LARGE'); assert.equal(JSON.stringify(tooLarge).includes(marker), false);
  for (let i = 1; i < 60; i++) assert.ok(size(await agent.request(null)) <= AUDIT_TEXT_LIMIT);
  const exhausted = await agent.request(null); assert.equal(exhausted.error.code, 'TOOL_BUDGET_EXHAUSTED');
  assert.equal(exhausted.budget.maxToolCalls, 60); assert.equal(exhausted.budget.remainingToolCalls, 0);
  assert.equal(exhausted.error.message, 'Every attempted request counts against the 60-call budget.');
  assert.equal(agent.budget().toolCalls, 61); assert.ok(size(exhausted) <= AUDIT_TEXT_LIMIT);
  await agent.close();
});

test('real browser status updates satisfy v2 prerequisites while the meaning stays reviewer-dependent', async t => {
  const site = await fixture(t, html), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  const step = await agent.request({ tool: 'step', actions: [
    { action: 'inspect', selector: '#status' }, { action: 'click', selector: '#go' }, { action: 'inspect', selector: '#status' },
  ] });
  assert.equal(step.success, true);
  const before = await record(agent, 'ev-0001'), after = await record(agent, 'ev-0003');
  assert.notEqual(before.after.stateId, after.after.stateId); assert.equal(before.result.element.nodeId, after.result.element.nodeId);
  const input = proposal(after); input.findings[0].criterionId = '4.1.3'; input.findings[0].evidenceIds = ['ev-0001', 'ev-0002', 'ev-0003'];
  const submitted = await agent.request({ tool: 'submit', proposal: input }); assert.equal(submitted.success, true);
  const reviewed = await reviewAudit(submitted.proposalReportPath, { reviewer: { name: 'Independent fixture reviewer', independentOfAuditor: true }, decisions: [{
    findingId: 'F1', verdict: 'supported', checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
    reason: 'The compact count summarizes the action result without moving focus; the substantive result is separate.',
    prerequisiteNotes: { v2: { statusMessage: { beforeEvidenceId: 'ev-0001', operationEvidenceId: 'ev-0002', afterEvidenceId: 'ev-0003', applicability: 'This count is an action-result status summary, not substantive content.', resultKind: 'status-summary', semanticReview: 'The original count changed while focus remained on Calculate and the complete ancestor chain has no live/status semantics.' } } },
  }] });
  assert.equal(reviewed.confirmedFindings.length, 1, JSON.stringify(reviewed.verificationQueue));
  assert.equal(reviewed.confirmedFindings[0].evidenceGate.semanticAssessment, 'reviewer-dependent');
  assert.equal((await checkAudit(reviewed.reportPath)).status, 'current'); await agent.close();
});

test('a proposal that completes after the host deadline is retained but not accepted as timely delivery', async t => {
  const site = await fixture(t, html); let now = Date.now();
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, {
    now: () => now, setTimer: () => null, clearTimer: () => {},
    submitAudit: async (...args) => { const result = await submitAudit(...args); now += 610000; return result; },
  });
  t.after(() => agent.close());
  await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] });
  const submitted = await agent.request({ tool: 'submit', proposal: proposal(await record(agent, 'ev-0001')) });
  assert.equal(submitted.success, false); assert.equal(submitted.status, 'late_proposal'); assert.equal(submitted.outOfBudget, true);
  assert.deepEqual(submitted.delivery, { checkpoint: 'none', submission: 'unsubmitted' });
  assert.equal(submitted.budget.remainingWallMs, 0);
  assert.ok(submitted.retainedProposal.reportPath); assert.equal((await agent.close()).status, 'incomplete');
});

test('interruption during pending submission retains the proposal without counting successful delivery', async t => {
  const site = await fixture(t, html), entered = Promise.withResolvers(), resume = Promise.withResolvers();
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, {
    submitAudit: async (...args) => { entered.resolve(); await resume.promise; return submitAudit(...args); },
  });
  t.after(async () => { resume.resolve(); await agent.close(); });
  await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] });
  const pending = agent.request({ tool: 'submit', proposal: proposal(await record(agent, 'ev-0001')) });
  await entered.promise;
  const closing = agent.close({ reason: 'interrupted', signal: 'SIGTERM' });
  resume.resolve();
  const submitted = await pending, end = await closing;
  assert.equal(submitted.success, false); assert.equal(submitted.status, 'interrupted_proposal');
  assert.equal(submitted.error.code, 'AUDIT_SESSION_INTERRUPTED');
  assert.deepEqual(submitted.delivery, { checkpoint: 'none', submission: 'unsubmitted' });
  assert.deepEqual(end.delivery, submitted.delivery);
  assert.equal(end.status, 'incomplete'); assert.deepEqual(end.termination, { reason: 'interrupted', signal: 'SIGTERM' });
  assert.equal((await agent.finished).status, 'incomplete');
  assert.equal((await checkAudit(submitted.retainedProposal.reportPath)).status, 'current');
  assert.equal(JSON.parse(await fs.readFile(submitted.retainedProposal.reportPath)).status, 'needs_review');
});

test('JSONL SIGTERM retains two acknowledged drafts and no proposal, with bounded response lines', async t => {
  const site = await fixture(t, html), inputDir = path.join(site.projectRoot, 'evidence'); await fs.mkdir(inputDir, { recursive: true });
  const file = path.join(inputDir, 'agent-input.json'); await fs.writeFile(file, JSON.stringify({ projectRoot: site.projectRoot, url: site.url }));
  const child = spawn(process.execPath, ['src/cli.js', 'audit-agent', file], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  let text = '', stderr = '', directory, lastDraft, draftCount = 0, chain = Promise.resolve(), callbackError;
  const rows = [];
  const handle = async row => {
    rows.push(row);
    if (row.kind !== 'audit-agent-session') {
      assert.ok(Number.isFinite(row.budget.remainingWallMs));
      assert.ok(Number.isFinite(row.budget.remainingExplorationMs));
      assert.deepEqual(row.delivery, { checkpoint: ['checkpoint', 'close'].includes(row.tool) ? 'saved' : 'none', submission: 'unsubmitted' });
    }
    if (row.kind === 'audit-agent-session') { directory = row.directory; child.stdin.write(JSON.stringify({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] }) + '\n'); }
    else if (row.tool === 'step') { const raw = JSON.parse(await fs.readFile(path.join(directory, 'ev-0001.json'))); child.stdin.write(JSON.stringify({ tool: 'checkpoint', proposal: proposal(raw) }) + '\n'); }
    else if (row.tool === 'checkpoint') {
      assert.equal(row.success, true); lastDraft = row.checkpoint; draftCount++;
      if (draftCount === 1) { const raw = JSON.parse(await fs.readFile(path.join(directory, 'ev-0001.json'))); child.stdin.write(JSON.stringify({ tool: 'checkpoint', proposal: proposal(raw, 'Second acknowledged draft') }) + '\n'); }
      else child.kill('SIGTERM');
    }
  };
  child.stderr.on('data', c => { stderr += c; });
  child.stdout.on('data', c => {
    text += c;
    for (;;) {
      const at = text.indexOf('\n'); if (at < 0) break;
      const line = text.slice(0, at); text = text.slice(at + 1);
      chain = chain.then(() => { assert.ok(Buffer.byteLength(line) <= AUDIT_TEXT_LIMIT); return handle(JSON.parse(line)); }).catch(e => { callbackError = e; child.kill('SIGKILL'); });
    }
  });
  let timer;
  const code = await Promise.race([new Promise(resolve => child.on('close', resolve)), new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`Agent CLI did not exit: ${stderr}`)), 15000); })]).finally(() => clearTimeout(timer));
  await chain; if (callbackError) throw callbackError;
  assert.equal(code, 143, stderr); assert.equal(draftCount, 2);
  const recovered = await readAuditCheckpoint(lastDraft.checkpointPath);
  assert.equal(recovered.version, 2); assert.equal(recovered.proposal.findings[0].title, 'Second acknowledged draft');
  assert.equal(rows.at(-1).status, 'incomplete'); assert.equal(rows.at(-1).proposalAutomaticallyCreated, false);
  assert.equal((await fs.readdir(directory)).filter(n => n.startsWith('audit-proposal-')).length, 0);
});

test('budget countdown uses one clock sample and agrees with stages at exact boundaries', async t => {
  const site = await fixture(t, html); let now = 1000000, samples = 0;
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, {
    now: () => { samples++; return now++; }, setTimer: () => null, clearTimer: () => {},
  });
  t.after(() => agent.close());
  for (const [at, stage, wall, exploration] of [
    [1000000, 'exploration', 600000, 480000],
    [1479999, 'exploration', 120001, 1],
    [1480000, 'finalization', 120000, 0],
    [1599999, 'finalization', 1, 0],
    [1600000, 'deadline', 0, 0],
    [1600001, 'deadline', 0, 0],
  ]) {
    now = at; samples = 0;
    const budget = agent.budget();
    assert.equal(budget.remainingWallMs, wall);
    assert.equal(samples, 1);
    assert.equal(budget.stage, stage);
    assert.equal(budget.remainingExplorationMs, exploration);
    for (const key of ['remainingWallMs', 'remainingExplorationMs']) {
      assert.ok(Number.isFinite(budget[key]) && budget[key] >= 0);
    }
  }
  const closed = await agent.close();
  assert.deepEqual(closed.delivery, { checkpoint: 'none', submission: 'unsubmitted' });
});

test('finalization submission can deliver an explicit proposal without a checkpoint and failed saves do not invent drafts', async t => {
  const site = await fixture(t, html); let now = 1000000;
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, {
    now: () => now, setTimer: () => null, clearTimer: () => {},
  });
  t.after(() => agent.close());
  const rejected = await agent.request({ tool: 'checkpoint', proposal: {} });
  assert.equal(rejected.success, false);
  assert.deepEqual(rejected.delivery, { checkpoint: 'none', submission: 'unsubmitted' });
  now += 480000;
  const blocked = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  assert.equal(blocked.error.code, 'EXPLORATION_BUDGET_EXHAUSTED');
  assert.equal(blocked.budget.stage, 'finalization');
  assert.equal(blocked.budget.remainingExplorationMs, 0);
  assert.equal(blocked.budget.remainingWallMs, 120000);
  assert.equal(blocked.budget.toolCalls, 2); assert.equal(blocked.budget.requestedActions, 0);
  now += 119999;
  const submitted = await agent.request({ tool: 'submit', proposal: { auditor: { name: 'Explicit empty fixture proposal' }, findings: [] } });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  assert.equal(submitted.budget.remainingWallMs, 1);
  assert.equal(submitted.budget.stage, 'finalization');
  assert.deepEqual(submitted.delivery, { checkpoint: 'none', submission: 'submitted' });
  assert.deepEqual((await agent.close()).delivery, submitted.delivery);
});

test('next tracks unscanned dialog, keyboard, DOM and same-origin page states', async t => {
  const page = html.replace('</main>', `<button id="open" onclick="document.querySelector('dialog').showModal()">Open</button><dialog><button id="close" onclick="this.closest('dialog').close()">Close</button></dialog></main>`);
  const site = await fixture(t, page), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  const step = actions => agent.request({ tool: 'step', actions });
  const scan = async () => {
    const r = await step([{ action: 'axe' }]);
    assert.equal(r.success, true, JSON.stringify(r));
    assert.doesNotMatch(r.next, /has not been axe-scanned/);
  };
  const unscanned = r => {
    assert.equal(r.success, true, JSON.stringify(r));
    assert.match(r.next, /has not been axe-scanned/);
    assert.match(r.next, /\{"tool":"step","actions":\[\{"action":"axe"\}\]\}/);
    assert.match(r.next, /Budget: \d+ calls, \d+ actions, \d+ seconds total/);
  };
  await scan();
  unscanned(await step([{ action: 'click', selector: '#open' }]));
  await scan();
  unscanned(await step([{ action: 'press', key: 'Escape' }]));
  await scan();
  unscanned(await step([{ action: 'click', selector: '#go' }, { action: 'snapshot' }]));
  await scan();
  // Same DOM, new URL; no study-specific pages or candidate rules.
  unscanned(await step([{ action: 'navigate', path: '/#another-page' }]));
  await scan();
  assert.doesNotMatch((await step([{ action: 'snapshot' }])).next, /has not been axe-scanned/);
  await agent.close();
});

test('next budget status thresholds use remaining calls, actions and exploration seconds', async t => {
  const site = await fixture(t, html); let now = 1000000;
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, maxToolCalls: 10 }, {
    now: () => now, setTimer: () => null, clearTimer: () => {},
  });
  t.after(() => agent.close());
  const read = () => agent.request({ tool: 'read', options: { view: 'guide' } });
  assert.match((await read()).next, /9 calls, 180 actions, 600 seconds total, 480 seconds exploration remaining; plenty left/);
  now += 75900;
  assert.match((await read()).next, /8 calls, 180 actions, 524 seconds total.*plenty left/);
  now = 1240000;
  assert.match((await read()).next, /about half left/); // Exactly half exploration time.
  now = 1000000;
  assert.match((await read()).next, /plenty left/); // Six calls.
  assert.match((await read()).next, /about half left/); // Exactly five calls.
  await read();
  assert.match((await read()).next, /finalize now/); // Three-call reserve.
  now = 1480000;
  assert.match((await read()).next, /finalize now/);

  const actionAgent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, maxActions: 2 });
  t.after(() => actionAgent.close());
  assert.match((await actionAgent.request({ tool: 'step', actions: [{ action: 'snapshot' }] })).next, /1 actions.*about half left/);
  assert.match((await actionAgent.request({ tool: 'step', actions: [{ action: 'snapshot' }] })).next, /0 actions.*finalize now/);
  await actionAgent.close();
  await agent.close();
});

test('invalid submit preserves live exploration, originals and corrected checkpoint submission', async t => {
  const site = await fixture(t, html), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] });
  const original = await record(agent, 'ev-0001'), bytes = await fs.readFile(path.join(agent.directory, 'ev-0001.json'));
  const bad = await agent.request({ tool: 'submit', proposal: {} });
  assert.equal(bad.error.code, 'INVALID_AUDIT_PROPOSAL'); assert.equal(bad.sealed, false);
  assert.equal((await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] })).success, true);
  const checkpoint = await agent.request({ tool: 'checkpoint', proposal: proposal(original) });
  assert.equal(checkpoint.success, true);
  assert.equal((await agent.request({ tool: 'submit', checkpointDigest: checkpoint.checkpoint.checkpointDigest })).success, true);
  assert.deepEqual(await fs.readFile(path.join(agent.directory, 'ev-0001.json')), bytes);
  await agent.close();
});

test('bad close reason and signal leave admission usable and allow a valid retry', async t => {
  const site = await fixture(t, html), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  for (const options of [{ reason: 'typo' }, { reason: 'interrupted', signal: 'SIGQUIT' }]) {
    await assert.rejects(agent.close(options), { code: 'INVALID_AUDIT_SESSION_FINISH' });
    assert.equal(agent.status, 'open');
    assert.equal((await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] })).success, true);
  }
  assert.equal((await agent.close({ reason: 'eof' })).success, true);
});

test('post-seal submission failure hints only retained-evidence delivery', async t => {
  const site = await fixture(t, html), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, {
    submitAudit: async () => { throw Object.assign(new Error('fixture delivery failure'), { code: 'FIXTURE_SUBMIT_FAILED' }); },
  });
  t.after(() => agent.close());
  const response = await agent.request({ tool: 'submit', proposal: { auditor: { name: 'Fixture' }, findings: [] } });
  assert.equal(response.error.code, 'FIXTURE_SUBMIT_FAILED'); assert.equal(response.sealed, true);
  assert.match(response.next, /retained evidence/); assert.doesNotMatch(response.next, /step|keep exploring|Scan it/);
  await agent.close();
});
