import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { auditAgentRequestSchema } from '../src/audit/agent.js';
import { validateAuditProposalRecords } from '../src/audit/review.js';
import { AUDIT_TEXT_LIMIT, MCP_TEXT_LIMIT, AUDIT_NODE_FIELDS } from '../src/audit/projection.js';
import { fixture } from './helpers.js';

async function host(t, limits = {}, initial) {
  const site = await fixture(t, initial ?? '<!doctype html><html lang="en"><title>Audit</title><button id="unnamed"></button></html>');
  const transport = mcpTransport({ command: process.execPath, args: ['src/cli.js', 'serve'], stderr: 'pipe' });
  const client = new Client({ name: 'audit-test', version: '1' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(transport, { mode: 'auto' });
  const call = async (name, args) => {
    const response = await client.callTool({ name, arguments: args });
    assert.ok(Buffer.byteLength(response.content[0].text) <= MCP_TEXT_LIMIT);
    assert.deepEqual(JSON.parse(response.content[0].text), response.structuredContent);
    return response.structuredContent;
  };
  const manifest = { projectRoot: site.projectRoot, url: site.url, startupAxe: false, ...limits };
  const start = await call('a11y_audit_start', { manifest });
  assert.equal(start.success, true, JSON.stringify(start));
  return { site, client, call, start, manifest, request: request => call('a11y_audit_request', { runId: start.runId, request }) };
}

test('MCP descriptions and start response give a concrete first-minute playbook', async t => {
  const h = await host(t, {});
  const { tools } = await h.client.listTools();
  for (const name of ['a11y_audit_start', 'a11y_audit_request']) {
    const description = tools.find(tool => tool.name === name).description;
    assert.match(description, /Playbook: 1\. a11y_audit_start already ran snapshot \+ axe/);
    assert.match(description, /re-scan with axe after each new state or page/);
    assert.match(description, /before writing findings there; axe sees only what is rendered/);
    assert.match(description, /adoptAxe:'all'/); assert.match(description, /what axe cannot find/);
    assert.match(description, /view:'guide'/);
    assert.ok(description.split(/\s+/).length <= 130, `${name} description has ${description.split(/\s+/).length} words`);
  }
  assert.match(h.client.getInstructions(), /Playbook: 1\. a11y_audit_start already ran .*what axe cannot find.*stopping after a few probes/);
  assert.equal(h.start.playbook.length, 5);
  assert.deepEqual(h.start.firstRequest, { runId: h.start.runId, request: { tool: 'step', actions: [{ action: 'snapshot' }, { action: 'axe' }] } });
  assert.equal(h.start.startup, undefined);
  assert.equal(h.start.budget.remainingToolCalls, 60);
  const first = await h.request(h.start.firstRequest.request);
  assert.equal(first.success, true, JSON.stringify(first));
  assert.match(first.next, /checkpoint/); assert.equal(first.budget.remainingToolCalls, 59);
});

test('MCP start runs snapshot + axe once, counts it once, and returns candidates with draftFinding', async t => {
  const h = await host(t, { startupAxe: true, startupSweep: false });
  assert.equal(h.start.startup.ran, 'snapshot + axe');
  assert.equal(h.start.startup.sweep, undefined);
  assert.equal(h.start.startup.success, true, JSON.stringify(h.start.startup));
  assert.equal(h.start.firstRequest, undefined);
  assert.equal(h.start.budget.toolCalls, 1); assert.equal(h.start.budget.requestedActions, 2); assert.equal(h.start.budget.remainingToolCalls, 59);
  assert.match(h.start.startup.counted, /1 tool call/);
  const [page] = h.start.startup.axe;
  assert.ok(page.counts.candidates >= 1);
  const unnamed = page.candidates.find(row => row.ruleId === 'button-name');
  assert.ok(unnamed, JSON.stringify(page.candidates.map(row => row.ruleId)));
  assert.deepEqual(unnamed.draftFinding, { pageUrl: unnamed.draftFinding.pageUrl, selector: '#unnamed', selectorConfidence: 'high', axeTarget: '#unnamed', stableSelector: '#unnamed', stableSelectorConfidence: 'unique-anchor', criterionId: '4.1.2', title: unnamed.help, claim: `button has no accessible name (axe button-name, ${unnamed.impact})`, evidenceIds: [unnamed.evidenceId], nodeId: unnamed.nodeId });
  assert.match(unnamed.draftFinding.pageUrl, /^http:\/\/127\.0\.0\.1:\d+\//);
  assert.ok(page.rules.some(rule => rule.ruleId === 'button-name' && rule.nodes >= 1 && rule.impact && rule.criterionIds.includes('4.1.2') && rule.firstCandidateId));
  assert.match(h.start.next, /checkpoint/);
  assert.equal(h.start.startup.coverage.version, 'coverage-1');
  assert.deepEqual(h.start.startup.coverage.keyboard, { tabPresses: 0, traversal: false });
  assert.ok(h.start.startup.coverage.axe.adoptable >= 1);
  assert.match(h.start.startup.suggestedNext[0], /^Tab through the page/);
});

test('MCP guide view returns the evidence rules without an evidenceId', async t => {
  const h = await host(t);
  const { AUDIT_EVIDENCE_GUIDANCE } = await import('../src/audit/agent.js');
  const guide = await h.request({ tool: 'read', options: { view: 'guide' } });
  assert.equal(guide.success, true, JSON.stringify(guide));
  assert.equal(guide.guide.evidence, AUDIT_EVIDENCE_GUIDANCE);
  assert.match(guide.guide.axe, /reportable as-is/);
  assert.equal((await h.request({ tool: 'read' })).error.code, 'INVALID_AGENT_REQUEST');
});

test('MCP start keeps agent defaults and explicit limits', async t => {
  for (const limits of [{}, { maxActions: 12, wallSeconds: 50 }, ...['2.1','2.2'].flatMap(version => ['A','AA'].map(targetLevel => ({ standard: { version, targetLevel } })))]) {
    const h = await host(t, limits);
    const budget = h.start.budget;
    const wallSeconds = limits.wallSeconds ?? 600;
    assert.ok(Number.isFinite(budget.remainingWallMs) && budget.remainingWallMs >= 0 && budget.remainingWallMs <= wallSeconds * 1000);
    assert.ok(Number.isFinite(budget.remainingExplorationMs) && budget.remainingExplorationMs >= 0);
    assert.equal(budget.maxActions, limits.maxActions ?? 180);
    assert.equal(Date.parse(budget.deadlineAt) - Date.parse(budget.startedAt), wallSeconds * 1000);
    assert.equal(Date.parse(budget.explorationDeadlineAt) - Date.parse(budget.startedAt), Math.min(480000, wallSeconds * 800));
    const close = await h.call('a11y_audit_close', { runId: h.start.runId });
    const report = JSON.parse(await fs.readFile(close.sourceAudit.reportPath));
    assert.deepEqual(report.manifest.standard, limits.standard ?? {version:'2.2',targetLevel:'AA'});
    assert.equal(report.coverage.length, report.standard.criteriaTotal);
  }
});

test('official MCP audit collects, reads, views, ACKs a draft and explicitly submits for review', async t => {
  const h = await host(t);
  for (const standard of [{version:'2.2',targetLevel:'AAA'},{version:'9.0',targetLevel:'AA'}]) {
    const invalid = await h.call('a11y_audit_start', {manifest:{...h.manifest,standard}});
    assert.equal(invalid.error.code, 'INVALID_AUDIT_MCP_INPUT');
  }
  const list = await h.client.listTools();
  assert.ok(list.tools.find(x => x.name === 'a11y_audit_request').inputSchema.properties.request);
  assert.equal((await h.call('a11y_audit_start', { manifest: h.manifest })).error.code, 'AUDIT_SESSION_ALREADY_STARTED');
  assert.equal((await h.call('a11y_audit_close', { runId: 'wrong' })).error.code, 'AUDIT_RUN_MISMATCH');
  assert.equal((await h.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }, { action: 'screenshot' }] })).success, true);
  const read = await h.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'nodes', limit: 1 } });
  assert.equal(read.success, true); assert.equal(read.identity.evidenceId, 'ev-0001');
  assert.deepEqual(read.delivery, { checkpoint: 'none', submission: 'unsubmitted' });
  assert.ok(Number.isFinite(read.budget.remainingWallMs));
  const view = await h.request({ tool: 'view', evidenceId: 'ev-0002' });
  assert.equal(view.success, true); assert.equal(view.image.mimeType, 'image/png');
  const raw = JSON.parse(await fs.readFile(path.join(h.start.directory, 'ev-0001.json')));
  const proposal = { auditor: { name: 'MCP fixture' }, findings: [{ id: 'F1', title: 'Unnamed button', criterionId: '4.1.2', target: { evidenceId: raw.evidenceId, nodeId: raw.result.element.nodeId }, evidenceIds: [raw.evidenceId], observation: 'Button has no name.', reason: 'Name missing.', applicability: 'Enabled button.', exceptions: 'None observed.', scope: 'This target.', method: 'dom' }] };
  const draft = await h.request({ tool: 'checkpoint', proposal });
  assert.equal(draft.success, true); assert.equal(draft.checkpoint.scoreable, false);
  assert.deepEqual(draft.delivery, { checkpoint: 'saved', submission: 'unsubmitted' });
  const submit = await h.request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest });
  assert.equal(submit.success, true, JSON.stringify(submit)); assert.equal(submit.status, 'needs_review');
  assert.deepEqual(submit.delivery, { checkpoint: 'saved', submission: 'submitted' });
  const stored = JSON.parse(await fs.readFile(submit.proposalReportPath));
  assert.equal(stored.confirmedFindings.length, 0);
  assert.equal(stored.sourceCheckpoint.checkpointDigest, draft.checkpoint.checkpointDigest);
  assert.equal((await h.request({ tool: 'read', evidenceId: 'ev-0001' })).error.code, 'AUDIT_AGENT_CLOSED');
});

test('MCP rejects changed originals and bounded malformed requests, retains drafts on close', async t => {
  const h = await host(t);
  await h.request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  const draft = await h.request({ tool: 'checkpoint', proposal: { auditor: { name: 'Fixture' }, findings: [] } });
  const file = path.join(h.start.directory, 'ev-0001.json');
  await fs.appendFile(file, ' ');
  assert.equal((await h.request({ tool: 'read', evidenceId: 'ev-0001' })).success, false);
  assert.equal((await h.request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest })).success, false);
  const bad = await h.request({ tool: 'read', evidenceId: 'ev-0001', unknown: 'x'.repeat(100000) });
  assert.equal(bad.success, false);
  const close = await h.call('a11y_audit_close', { runId: h.start.runId });
  assert.equal(close.status, 'incomplete'); assert.equal(close.proposalAutomaticallyCreated, false);
  assert.equal((await fs.readdir(h.start.directory)).some(x => x.startsWith('audit-proposal-')), false);
});

test('MCP rejects a schema-valid request above 64 KiB at the core request-size guard', async t => {
  const h = await host(t);
  assert.equal((await h.request({ tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] })).success, true);
  const original = JSON.parse(await fs.readFile(path.join(h.start.directory, 'ev-0001.json')));
  const proposal = { auditor: { name: 'MCP size-guard fixture' }, findings: [{
    id: 'F1', title: 'Unnamed button', criterionId: '4.1.2',
    target: { evidenceId: original.evidenceId, nodeId: original.result.element.nodeId },
    evidenceIds: [original.evidenceId], observation: 'o'.repeat(20000), reason: 'r'.repeat(20000),
    applicability: 'a'.repeat(20000), exceptions: 'e'.repeat(20000), scope: 'This target.', method: 'dom',
  }] };
  const request = { tool: 'checkpoint', proposal };
  // No extra keys or overlong individual fields: both protocol and proposal
  // validation accept this request, so schema rejection cannot mask the guard.
  assert.equal(auditAgentRequestSchema.safeParse(request).success, true);
  assert.deepEqual(validateAuditProposalRecords(proposal, [original]), proposal);
  assert.ok(Buffer.byteLength(JSON.stringify(request)) > AUDIT_TEXT_LIMIT);
  const rejected = await h.request(request);
  assert.equal(rejected.success, false);
  assert.equal(rejected.error.code, 'AGENT_REQUEST_TOO_LARGE');
  assert.equal((await fs.readdir(h.start.directory)).some(name => name.startsWith('audit-checkpoint-')), false);
  const small = structuredClone(request);
  for (const field of ['observation', 'reason', 'applicability', 'exceptions']) small.proposal.findings[0][field] = 'Short valid fixture text.';
  assert.ok(Buffer.byteLength(JSON.stringify(small)) < AUDIT_TEXT_LIMIT);
  assert.equal((await h.request(small)).success, true);
});

test('MCP EOF closes collection and retains acknowledged draft without promotion', async t => {
  const h = await host(t);
  const draft = await h.request({ tool: 'checkpoint', proposal: { auditor: { name: 'EOF fixture' }, findings: [] } });
  await h.client.close();
  // Client close waits for transport shutdown; verify the durable draft and absent proposal.
  assert.ok(await fs.stat(draft.checkpoint.checkpointPath));
  assert.equal((await fs.readdir(h.start.directory)).some(x => x.startsWith('audit-proposal-')), false);
});

test('MCP malformed attempts consume existing operation budget and connections are isolated', async t => {
  const a = await host(t), b = await host(t);
  assert.notEqual(a.start.runId, b.start.runId);
  assert.equal((await b.call('a11y_audit_close', { runId: a.start.runId })).error.code, 'AUDIT_RUN_MISMATCH');
  for (let i = 0; i < 60; i++) assert.equal((await a.request({ tool: 'unknown' })).error.code, 'INVALID_AGENT_REQUEST');
  assert.equal((await a.request({ tool: 'checkpoint', proposal: {} })).error.code, 'TOOL_BUDGET_EXHAUSTED');
  assert.equal((await b.request({ tool: 'checkpoint', proposal: { auditor: { name: 'Independent connection' }, findings: [] } })).success, true);
});

test('MCP rejects schema-valid oversized requests at the agent size gate', async t => {
  const h = await host(t);
  const request = { tool: 'checkpoint', proposal: { auditor: { name: 'x'.repeat(65536) }, findings: [] } };
  assert.equal(auditAgentRequestSchema.safeParse(request).success, true);
  assert.ok(Buffer.byteLength(JSON.stringify(request)) > 65536);
  const response = await h.request(request);
  assert.equal(response.success, false);
  assert.equal(response.error.code, 'AGENT_REQUEST_TOO_LARGE');
});

test('MCP advertises readiness schema and executes it through the unchanged step operation', async t => {
  const h = await host(t);
  const list = await h.client.listTools();
  const schema = list.tools.find(row => row.name === 'a11y_audit_request').inputSchema;
  assert.ok(JSON.stringify(schema).includes('wait_for'));
  const response = await h.request({ tool: 'step', actions: [{ action: 'wait_for', selector: '#unnamed', condition: 'attached' }, { action: 'snapshot' }] });
  assert.equal(response.success, true, JSON.stringify(response));
  assert.equal(response.budget.requestedActions, 2);
  const original = JSON.parse(await fs.readFile(path.join(h.start.directory, 'ev-0001.json')));
  assert.equal(original.result.matched, true); assert.equal(original.arguments.timeoutMs, 3000);
  const read = await h.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'field', field: '/result' } });
  assert.equal(read.success, true); assert.equal(JSON.parse(read.data).matched, true);
  await h.call('a11y_audit_close', { runId: h.start.runId });
});

test('MCP returned whole-node handle recovers original occurrences and preserves refusals', async t => {
  const attributes = Array.from({ length: 5 }, (_, i) => `data-own-${i}="${'x'.repeat(8192)}"`).join(' ');
  const h = await host(t, {}, `<!doctype html><html lang="en"><title>Own scratch</title><button id="unnamed" ${attributes}></button></html>`);
  await h.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'inspect', selector: '#unnamed' }] });
  for (const evidenceId of ['ev-0001', 'ev-0002']) {
    const original = JSON.parse(await fs.readFile(path.join(h.start.directory, `${evidenceId}.json`)));
    const page = await h.request({ tool: 'read', evidenceId, options: { view: 'nodes' } });
    for (const row of page.nodes) {
      assert.deepEqual(row.read, { runId: h.start.runId, view: 'field', nodeId: row.nodeId, field: '$node' });
      let options = row.read, text = '', chunks = 0;
      do {
        const part = await h.request({ tool: 'read', evidenceId, options });
        assert.equal(part.success, true);
        assert.equal(part.identity.runId, h.start.runId);
        assert.equal(part.identity.evidenceId, evidenceId);
        text += part.data; options = part.pagination.next;
        assert.ok(++chunks < 40);
      } while (options);
      const occurrences = JSON.parse(text);
      if (occurrences.some(o => o.value.attributes?.id === 'unnamed')) assert.ok(chunks > 1);
      for (const occurrence of occurrences) {
        const retained = occurrence.source.split('/').slice(1).reduce((v, k) => v[k], original);
        assert.deepEqual(occurrence.value, Object.fromEntries(AUDIT_NODE_FIELDS.filter(k => Object.hasOwn(retained, k)).map(k => [k, retained[k]])));
      }
    }
    assert.equal((await h.request({ tool: 'read', evidenceId, options: { view: 'nodes', fields: ['$node'] } })).error.code, 'INVALID_AUDIT_NODE_FIELDS');
    assert.equal((await h.call('a11y_audit_request', { runId: 'wrong', request: { tool: 'read', evidenceId, options: page.nodes[0].read } })).error.code, 'AUDIT_RUN_MISMATCH');
    await fs.appendFile(path.join(h.start.directory, `${evidenceId}.json`), ' ');
    assert.equal((await h.request({ tool: 'read', evidenceId, options: page.nodes[0].read })).success, false);
  }
  const guideReply = await h.request({ tool: 'read', options: { view: 'guide' } }); const schema = JSON.stringify(guideReply.guide ?? guideReply);
  assert.ok(schema.includes(AUDIT_NODE_FIELDS.join(', ')));
  assert.ok(schema.includes('row.read'));
  await h.call('a11y_audit_close', { runId: h.start.runId });
});

test('public MCP cap 20 refuses the 21st step before creating an action or original record', async t => {
  const h = await host(t, { maxToolCalls: 20 });
  assert.equal(h.start.budget.maxToolCalls, 20);
  assert.equal(h.start.budget.remainingToolCalls, 20);
  const schema = (await h.client.listTools()).tools.find(row => row.name === 'a11y_audit_start').inputSchema;
  assert.deepEqual(schema.properties.manifest.properties.maxToolCalls, { type: 'integer', minimum: 1, maximum: 60, default: 60 });
  for (const maxToolCalls of [0, 61, 1.5, '20']) {
    assert.equal((await h.call('a11y_audit_start', { manifest: { ...h.manifest, maxToolCalls } })).error.code, 'INVALID_AUDIT_MCP_INPUT');
  }
  assert.equal((await h.call('a11y_audit_request', { runId: h.start.runId, request: null, extra: true })).error.code, 'INVALID_AUDIT_MCP_INPUT');
  assert.equal((await h.call('a11y_audit_request', { runId: 'wrong', request: null })).error.code, 'AUDIT_RUN_MISMATCH');
  const step = { tool: 'step', actions: [{ action: 'inspect', selector: '#unnamed' }] };
  for (let n = 1; n <= 20; n++) {
    const response = await h.request(step);
    assert.equal(response.success, true);
    assert.equal(response.budget.toolCalls, n);
    assert.equal(response.budget.returnedActions, n);
    assert.equal(response.budget.remainingToolCalls, 20 - n);
  }
  const files = (await fs.readdir(h.start.directory)).filter(n => /^ev-\d+\.json$/.test(n));
  assert.equal(files.length, 20);
  const originals = await Promise.all(files.map(n => fs.readFile(path.join(h.start.directory, n))));
  const refused = await h.request(step);
  assert.equal(refused.error.code, 'TOOL_BUDGET_EXHAUSTED');
  assert.match(refused.error.message, /20-call/);
  assert.equal(refused.budget.toolCalls, 21);
  assert.equal(refused.budget.requestedActions, 20);
  assert.equal(refused.budget.returnedActions, 20);
  assert.equal(refused.budget.remainingToolCalls, 0);
  assert.deepEqual((await fs.readdir(h.start.directory)).filter(n => /^ev-\d+\.json$/.test(n)), files);
  assert.deepEqual(await Promise.all(files.map(n => fs.readFile(path.join(h.start.directory, n)))), originals);
  const closed = await h.call('a11y_audit_close', { runId: h.start.runId });
  assert.equal(closed.budget.maxToolCalls, 20);
  assert.equal(closed.budget.toolCalls, 21);
  const report = JSON.parse(await fs.readFile(closed.sourceAudit.reportPath));
  assert.equal(report.records.length, 20);
  assert.equal(Object.hasOwn(report.manifest, 'maxToolCalls'), false);
});


test('MCP exposes the collection contract before delivery', async t => {
  const h = await host(t);
  const tool = (await h.client.listTools()).tools.find(row => row.name === 'a11y_audit_request');
  const { AUDIT_EVIDENCE_GUIDANCE } = await import('../src/audit/agent.js');
  assert.equal(typeof AUDIT_EVIDENCE_GUIDANCE, 'string');
  assert.ok(AUDIT_EVIDENCE_GUIDANCE.includes('exactly consecutive inspect -> click -> wait_for'));
  assert.ok(AUDIT_EVIDENCE_GUIDANCE.includes('not business terminality'));
  assert.ok(AUDIT_EVIDENCE_GUIDANCE.split(/\s+/).length <= 300);
  // The long guidance lives behind read view:'guide'; no listing carries it.
  assert.equal(JSON.stringify(tool).includes('exactly consecutive'), false);
  assert.ok(JSON.stringify(tool).length < 12_000, `request tool listing is ${JSON.stringify(tool).length} characters`);
  const variants = tool.inputSchema.properties.request.oneOf ?? tool.inputSchema.properties.request.anyOf;
  for (const operation of ['step', 'checkpoint', 'submit']) {
    assert.match(variants.find(v => v.properties.tool.const === operation).description ?? JSON.stringify(variants.find(v => v.properties.tool.const === operation)), /view:'guide'/);
  }
  for (const request of [{ tool: 'checkpoint', proposal: null }, { tool: 'submit' },
    { tool: 'submit', proposal: { arbitrary: true } }, { tool: 'step', actions: [{ action: 'snapshot' }] }]) {
    assert.deepEqual(auditAgentRequestSchema.parse(request), request);
  }
  assert.equal(auditAgentRequestSchema.safeParse({ tool: 'submit', extra: true }).success, false);
  assert.equal(auditAgentRequestSchema.parse({ tool: 'step', actions: [{ action: 'wait_for', selector: '#observed', condition: 'attached' }] }).actions[0].timeoutMs, 3000);
});

// Synthetic first-party adjudication exercises mechanics, not independent model judgment.
// Broader counterexamples remain in audit-status-readiness and audit-policy-v2 tests.
test('MCP original delayed summary preserves delivery and independent review gates', async t => {
  const h = await host(t, {}, `<!doctype html><html lang="en"><title>Archive</title><body>
    <button id="archive">Prepare archive</button><p id="receipt">Ready to prepare</p>
    <script>document.querySelector('button').onclick=async()=>{
      document.querySelector('p').textContent='Preparing archive';
      await fetch('/'); document.querySelector('p').textContent='Archive prepared';
    };</script></body></html>`);
  const completion = Promise.withResolvers();
  h.site.beforeResponse(() => completion.promise);
  t.after(() => completion.resolve());
  const records = [];
  async function capture(action) {
    const response = await h.request({ tool: 'step', actions: [action] });
    assert.equal(response.success, true, JSON.stringify(response));
    const evidenceId = response.records[0].evidenceId;
    const read = await h.request({ tool: 'read', evidenceId, options: { view: 'field', field: '/result' } });
    assert.equal(read.success, true);
    const original = JSON.parse(await fs.readFile(path.join(h.start.directory, `${evidenceId}.json`)));
    assert.deepEqual(JSON.parse(read.data), original.result);
    assert.equal(original.success, true, JSON.stringify(original.error));
    records.push(original);
    return original;
  }
  const snapshot = await capture({ action: 'snapshot' });
  const resultNode = snapshot.result.nodes.find(node => node.tag === 'p');
  const selector = resultNode.selector;
  assert.match(selector, /^#[A-Za-z][\w-]*$/);
  const stale = await capture({ action: 'inspect', selector });
  await capture({ action: 'press', key: 'Tab' });
  const noAncestors = await capture({ action: 'snapshot' });
  const before = await capture({ action: 'inspect', selector });
  const operation = await capture({ action: 'press', key: 'Enter' });
  const pending = await capture({ action: 'inspect', selector });
  assert.equal(operation.after.stateId, pending.after.stateId);
  completion.resolve();
  // Inspect rejects a DOM mutation during capture. Wait for the fixture's
  // terminal state before collecting the stable original used by review.
  const ready = await capture({ action: 'wait_for', selector, condition: 'text', expected: 'Archive prepared' });
  const after = await capture({ action: 'inspect', selector });
  assert.notEqual(after.result.element.text, pending.result.element.text);
  assert.equal(before.after.stateId, operation.before.stateId);
  assert.notEqual(stale.after.stateId, operation.before.stateId);
  assert.notEqual(operation.after.stateId, after.after.stateId);
  assert.equal(ready.after.stateId, after.after.stateId);
  assert.equal(before.result.element.nodeId, after.result.element.nodeId);
  assert.equal(before.after.documentId, after.after.documentId);
  for (const record of [before, after]) {
    assert.equal(record.result.element.ancestorSemantics.complete, true);
    assert.equal(record.result.element.focused, false);
  }
  assert.equal(noAncestors.after.stateId, operation.before.stateId);
  assert.equal(noAncestors.result.nodes.find(node => node.nodeId === resultNode.nodeId).ancestorSemantics, undefined);
  const chain = records.map(r => r.evidenceId);
  const png = await capture({ action: 'screenshot' });
  assert.equal(png.after.stateId, after.after.stateId);
  assert.equal(png.after.documentId, after.after.documentId);
  assert.ok(png.png);
  const base = { title: 'Synthetic archive summary', criterionId: '4.1.3',
    target: { evidenceId: after.evidenceId, nodeId: after.result.element.nodeId }, evidenceIds: chain,
    observation: 'The original text changes after keyboard activation, with focus on the trigger.',
    reason: 'Test-owned classification as an operation summary.', applicability: 'Synthetic summary.',
    exceptions: 'Synthetic review of captured semantics.', scope: 'This fixture only.', method: 'keyboard' };
  const findings = [
    { ...base, id: 'keyboard' },
    { ...base, id: 'combined', method: 'combined', evidenceIds: [...chain, png.evidenceId] },
    { ...base, id: 'missing-wait' },
    { ...base, id: 'stale-before' },
    { ...base, id: 'combined-no-png', method: 'combined' },
    { ...base, id: 'visual-as-dom', criterionId: '1.4.11', method: 'dom' },
    // Original snapshot lacks inspect's ancestor chain; no original is edited.
    { ...base, id: 'absent-ancestors' },
  ];
  const draft = await h.request({ tool: 'checkpoint', proposal: { auditor: { name: 'Synthetic maker' }, findings } });
  assert.equal(draft.success, true, JSON.stringify(draft));
  assert.equal(draft.checkpoint.reviewStatus, 'needs_review');
  assert.equal(draft.checkpoint.scoreable, false);
  const submitted = await h.request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  assert.equal(submitted.status, 'needs_review');
  assert.equal(JSON.parse(await fs.readFile(submitted.proposalReportPath)).confirmedFindings.length, 0);
  const { reviewAudit, checkAudit } = await import('../src/audit/review.js');
  const decisions = findings.map(finding => {
    const notes = { beforeEvidenceId: before.evidenceId, operationEvidenceId: operation.evidenceId,
      settledEvidenceId: ready.evidenceId, afterEvidenceId: after.evidenceId, resultKind: 'status-summary',
      applicability: 'Test-authored status classification, not a model judgment.',
      semanticReview: 'Synthetic review: changed summary text, no target focus or live ancestors; not screen-reader output.' };
    if (finding.id === 'missing-wait') delete notes.settledEvidenceId;
    if (finding.id === 'stale-before') notes.beforeEvidenceId = stale.evidenceId;
    if (finding.id === 'absent-ancestors') notes.beforeEvidenceId = noAncestors.evidenceId;
    return { findingId: finding.id, verdict: 'supported',
      checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
      reason: 'Test-authored adjudication solely to exercise unchanged prerequisite gates.', prerequisiteNotes: { v2: { statusMessage: notes } } };
  });
  const reviewed = await reviewAudit(submitted.proposalReportPath, {
    reviewer: { name: 'Synthetic independent reviewer', independentOfAuditor: true }, decisions,
  });
  assert.deepEqual(reviewed.confirmedFindings.map(f => f.id).sort(), ['combined', 'keyboard']);
  assert.deepEqual(reviewed.verificationQueue.map(f => f.id).sort(), ['absent-ancestors', 'combined-no-png', 'missing-wait', 'stale-before', 'visual-as-dom']);
  for (const id of ['combined-no-png', 'visual-as-dom']) {
    assert.match(reviewed.verificationQueue.find(f => f.id === id).missingEvidence.join(' '), /PNG/);
  }
  assert.match(reviewed.verificationQueue.find(f => f.id === 'absent-ancestors').missingEvidence.join(' '), /ancestor/);
  assert.ok(reviewed.confirmedFindings.every(f => f.evidenceGate.semanticAssessment === 'reviewer-dependent'));
  assert.equal((await checkAudit(reviewed.reportPath)).status, 'current');
});

test('rejected MCP start leaves the connection restartable and errors say how to fix it', async t => {
  const site = await fixture(t, '<!doctype html><html lang="en"><title>Audit</title><button id="unnamed"></button></html>');
  const client = new Client({ name: 'audit-test', version: '1' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(mcpTransport({ command: process.execPath, args: ['src/cli.js', 'serve'], stderr: 'pipe' }), { mode: 'auto' });
  const call = async (name, args) => (await client.callTool({ name, arguments: args })).structuredContent;
  const manifest = { projectRoot: site.projectRoot, url: site.url, startupAxe: false };

  const withActions = await call('a11y_audit_start', { manifest: { ...manifest, actions: [{ action: 'snapshot' }, { action: 'axe' }, { action: 'screenshot' }] } });
  assert.equal(withActions.error.code, 'INVALID_AGENT_MANIFEST');
  assert.match(withActions.error.message, /`actions` is not accepted by a11y_audit_start/);
  assert.match(withActions.error.message, /a11y_audit_request \{tool:'step'\}/);

  const badLimit = await call('a11y_audit_start', { manifest: { ...manifest, maxActions: 999, extraSecret: 'LEAK-CANARY' } });
  assert.equal(badLimit.error.code, 'INVALID_AUDIT_MCP_INPUT');
  assert.match(badLimit.error.message, /maxActions/);
  assert.match(badLimit.error.message, /Do not send actions/);
  assert.doesNotMatch(JSON.stringify(badLimit), /LEAK-CANARY|extraSecret/);

  const before = await call('a11y_audit_request', { runId: '', request: { tool: 'inventory' } });
  assert.equal(before.error.code, 'AUDIT_RUN_MISMATCH');
  assert.match(before.error.message, /Call a11y_audit_start first/);

  const start = await call('a11y_audit_start', { manifest });
  assert.equal(start.success, true, JSON.stringify(start));
  const step = await call('a11y_audit_request', { runId: start.runId, request: { tool: 'step', actions: [{ action: 'snapshot' }] } });
  assert.equal(step.success, true, JSON.stringify(step));

  for (const runId of ['', 'default']) {
    const wrong = await call('a11y_audit_request', { runId, request: { tool: 'inventory' } });
    assert.equal(wrong.error.code, 'AUDIT_RUN_MISMATCH');
    assert.ok(wrong.error.message.includes(`"${start.runId}"`), wrong.error.message);
    assert.match(wrong.error.message, /a11y_audit_start response/);
  }
  const again = await call('a11y_audit_start', { manifest });
  assert.equal(again.error.code, 'AUDIT_SESSION_ALREADY_STARTED');
  assert.ok(again.error.message.includes(`"${start.runId}"`), again.error.message);
  assert.equal((await call('a11y_audit_close', { runId: start.runId })).success, true);
});
