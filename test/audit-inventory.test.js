import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { digest } from '../src/evidence.js';
import { deriveAuditInventory, auditInventory, writeInventoryPage } from '../src/audit/inventory.js';
import { resolveAuditStandard } from '../src/audit/schema.js';
import { openAuditAgent, auditAgentRequestSchema } from '../src/audit/agent.js';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { fixture } from './helpers.js';
const exec = promisify(execFile);
const reference = r => ({ reportPath: r.reportPath, reportDigest: r.reportDigest });
function retained(n = 4) {
  const record = { evidenceId: 'ev-0001', action: 'axe', success: true,
    after: { documentId: 'doc1', stateId: 'state1', url: 'http://localhost/', viewport: { width: 800, height: 600 } },
    result: { nodes: [], axe: { violations: [{ id: 'arbitrary-rule', tags: ['wcag412', 'wcag999', 'wcag2aa'], nodes: Array.from({ length: n }, (_, i) => ({ target: [i === 1 ? 'x'.repeat(100000) : `#item${i}`], html: 'PRIVATE_HTML', any: [{ data: 'CHECK_PAYLOAD' }] })) }],
      incomplete: [{ id: 'uncertain', tags: [], nodes: [{ target: ['#uncertain'] }] }] },
      axeNodeBindings: { stable: true, capturedDocumentId: 'doc1', capturedStateId: 'state1', omittedTargets: n,
        rows: [{ disposition: 'violations', ruleId: 'arbitrary-rule', ruleNodeIndex: 0, target: ['#item0'], status: 'unbound', reason: 'outside_max_elements' }] } } };
  const collection = { runId: 'run1', reportPath: '/original.json', reportDigest: digest('collection'), records: [record], standard: resolveAuditStandard() };
  const proposal = { ...collection, reportPath: '/proposal.json', reportDigest: digest('proposal'), auditor: { name: 'Maker' }, findings: [
    { id: 'F1', target: { evidenceId: 'ev-0001' }, evidenceIds: ['ev-0001'] },
    { id: 'WRONG', target: { evidenceId: 'ev-0002' }, evidenceIds: ['ev-0002'] },
  ] };
  return { collection, proposal, report: { ...proposal, verificationQueue: [{ id: 'F1', decision: { verdict: 'insufficient' }, evidenceGate: { status: 'insufficient' } }] } };
}
function dispositions(input) {
  return { kind: 'audit-inventory-dispositions', version: 1, revision: 1, runId: input.collection.runId,
    collection: reference(input.collection), proposal: reference(input.proposal), maker: { name: 'Maker' }, dispositions: [] };
}

test('all raw nodes across buckets/repeated states, large targets and beyond binding cap page exactly once', () => {
  const input = retained(5002), first = deriveAuditInventory(input, { limit: 200 });
  assert.equal(first.counts.observations, 5003); assert.equal(first.counts.unresolved, 5003);
  assert.equal(first.rows[1].target.truncated, true);
  const ids = []; let page = first;
  do {
    assert.ok(Buffer.byteLength(JSON.stringify(page)) <= 65536);
    assert.equal(JSON.stringify(page).includes('PRIVATE_HTML'), false);
    assert.equal(JSON.stringify(page).includes('CHECK_PAYLOAD'), false);
    ids.push(...page.rows.map(row => row.observationId));
    page = page.pagination.next ? deriveAuditInventory(input, page.pagination.next) : null;
  } while (page);
  assert.equal(ids.length, 5003); assert.equal(new Set(ids).size, 5003);
  const changed = structuredClone(input); changed.collection.records[0].after.stateId = 'changed';
  assert.throws(() => deriveAuditInventory(changed, first.pagination.next), /cursor/);
  assert.throws(() => deriveAuditInventory(input, { extra: true }), /options/);
  input.collection.records.push({ ...input.collection.records[0], evidenceId: 'ev-0002' });
  assert.equal(deriveAuditInventory(input).counts.observations, 10006);
});

test('explicit dispositions account for links/ignore/remainder while preserving incomplete and review truth', () => {
  const input = retained(), record = input.collection.records[0];
  record.before = structuredClone(record.after);
  record.result.nodes.push({ nodeId: 'uncertain-node', documentId: 'doc1', selector: '#uncertain' });
  record.result.axeNodeBindings.rows.push({ disposition: 'incomplete', ruleId: 'uncertain', ruleNodeIndex: 0,
    target: ['#uncertain'], status: 'bound', nodeId: 'uncertain-node', documentId: 'doc1', selector: '#uncertain' });
  input.proposal.findings[0].target.nodeId = 'uncertain-node';
  const rows = deriveAuditInventory(input).rows;
  const d = dispositions(input); d.dispositions = [
    { observationId: rows.at(-1).observationId, status: 'linked', findingIds: ['F1'] },
    { observationId: rows[0].observationId, status: 'ignored', reason: 'Maker deferred pending a separate investigation.' },
  ];
  const page = deriveAuditInventory({ ...input, dispositions: d });
  assert.deepEqual(page.counts, { observations: 5, unresolved: 3, linked: 1, ignored: 1 });
  assert.equal(page.rows.at(-1).bucket, 'incomplete'); assert.equal(page.rows.at(-1).semanticStatus, 'not_established');
  assert.equal(page.rows.at(-1).linkedReview[0].verdict, 'insufficient');
  const wrongNode = structuredClone(input); wrongNode.proposal.findings[0].target.nodeId = 'different-node';
  assert.throws(() => deriveAuditInventory({ ...wrongNode, dispositions: d }), /binding|node/);
  const unstable = structuredClone(input); unstable.collection.records[0].result.axeNodeBindings.stable = false;
  assert.throws(() => deriveAuditInventory({ ...unstable, dispositions: d }), /binding|node/);
  const missing = structuredClone(input); missing.collection.records[0].result.nodes = [];
  assert.throws(() => deriveAuditInventory({ ...missing, dispositions: d }), /binding|node/);
  input.report.rejectedObservations = input.report.verificationQueue; delete input.report.verificationQueue;
  assert.equal(deriveAuditInventory({ ...input, dispositions: d }).rows.at(-1).linkedReview[0].status, 'rejectedObservations');
  const legacy = structuredClone(input);
  legacy.report.kind = 'audit-review'; legacy.report.confirmedFindings = legacy.report.rejectedObservations; delete legacy.report.rejectedObservations;
  const legacyPage = deriveAuditInventory({ ...legacy, dispositions: d });
  assert.equal(legacyPage.source.reviewPolicy, 'legacy-declared');
  assert.equal(legacyPage.source.requiresReReview, true);
  assert.equal(legacyPage.rows.at(-1).linkedReview[0].status, 'verificationQueue');
  legacy.report.directEvidencePolicy = 'dom-predicates-v1';
  assert.equal(deriveAuditInventory({ ...legacy, dispositions: d }).rows.at(-1).linkedReview[0].status, 'confirmedFindings');
  for (const mutate of [
    x => x.collection.reportDigest = digest('stale'), x => x.runId = 'other', x => x.proposal.reportDigest = digest('other'),
    x => x.dispositions[0].findingIds = ['unknown'], x => x.dispositions[0].findingIds = ['WRONG'],
    x => x.dispositions[0].observationId = digest('unknown'), x => x.dispositions[1].reason = ' ',
    x => x.maker.name = '', x => x.dispositions.push(x.dispositions[0]), x => x.unexpected = true,
  ]) { const bad = structuredClone(d); mutate(bad); assert.throws(() => deriveAuditInventory({ ...input, dispositions: bad })); }
  const first = deriveAuditInventory(input, { limit: 1 });
  assert.throws(() => deriveAuditInventory({ ...input, dispositions: d }, first.pagination.next), /cursor/);
});

test('failed scans and unstable/missing bindings disclose limits and never offer invented node handles', () => {
  const input = retained(); input.collection.records[0].success = false;
  let page = deriveAuditInventory(input); assert.equal(page.counts.observations, 0);
  assert.equal(page.limitations.successfulScans, 0); assert.ok(page.limitations.count >= 2);
  input.collection.records[0].success = true;
  delete input.collection.records[0].result.axeNodeBindings;
  page = deriveAuditInventory(input); assert.ok(page.rows.every(row => row.binding.status === 'unbound' && !row.binding.nodeRead));
});

test('first-party Chromium collection: agent/CLI/retained empty proposal share nodes, preserve bytes and exclusive companions', async t => {
  const site = await fixture(t, '<!doctype html><html lang="en"><title>Inventory fixture</title><body><main><h1>Inventory</h1><button id="unnamed"></button></main></body></html>');
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }); t.after(() => agent.close().catch(() => {}));
  const stepped = await agent.request({ tool: 'step', actions: [{ action: 'axe' }] }); assert.equal(stepped.success, true);
  assert.equal(auditAgentRequestSchema.safeParse({ tool: 'inventory', options: { limit: 1 } }).success, true);
  const live = await agent.request({ tool: 'inventory' }); assert.equal(live.inventory.success, true, JSON.stringify(live));
  assert.ok(live.inventory.counts.observations > 0); assert.equal(live.budget.toolCalls, 2);
  const submitted = await agent.request({ tool: 'submit', proposal: { auditor: { name: 'Maker' }, findings: [] } });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  const reportPath = submitted.proposalReportPath;
  const before = new Map(await Promise.all((await fs.readdir(agent.directory)).map(async name => [name, await fs.readFile(path.join(agent.directory, name))])));
  const sealed = await auditInventory(reportPath);
  assert.deepEqual(sealed.rows.map(r => r.observationId), live.inventory.rows.map(r => r.observationId));
  assert.equal(sealed.counts.unresolved, sealed.counts.observations);
  assert.ok(sealed.rows.some(r => r.binding.status === 'bound'));
  assert.ok(sealed.rows.filter(r => r.binding.status === 'bound').every(r => r.binding.nodeRead));
  const { stdout } = await exec(process.execPath, ['src/cli.js', 'audit-inventory', reportPath]);
  assert.deepEqual(JSON.parse(stdout), sealed);
  const proposalReport = JSON.parse(await fs.readFile(reportPath));
  const d = { kind: 'audit-inventory-dispositions', version: 1, revision: 1, runId: sealed.source.runId,
    collection: sealed.source.collection, proposal: sealed.source.proposal, maker: { name: 'Maker' },
    dispositions: [{ observationId: sealed.rows[0].observationId, status: 'ignored', reason: 'Maker deferred this observation.' }] };
  const dispositionPath = path.join(agent.directory, 'maker-dispositions-v1.json');
  await fs.writeFile(dispositionPath, JSON.stringify(d));
  assert.equal((await auditInventory(reportPath, dispositionPath)).counts.ignored, 1);
  const limited = JSON.parse((await exec(process.execPath, ['src/cli.js', 'audit-inventory', reportPath, dispositionPath, '--limit', '1', '--write'])).stdout);
  assert.equal(limited.rows.length, 1); assert.ok(limited.companion.path);
  assert.equal(proposalReport.findings.length, 0); assert.equal(proposalReport.confirmedFindings.length, 0);
  const one = await writeInventoryPage(reportPath), two = await writeInventoryPage(reportPath);
  assert.notEqual(one.companion.path, two.companion.path);
  for (const [name, bytes] of before) assert.deepEqual(await fs.readFile(path.join(agent.directory, name)), bytes);
  await assert.rejects(auditInventory(reportPath, path.join(agent.directory, '..', 'outside.json')));
  const linked = await agent.request({ tool: 'inventory' }); assert.equal(linked.success, false, 'closed session cannot enumerate without a budget');
  await agent.close();
});


test('MCP advertises and dispatches the same bounded inventory operation without browser actions', async t => {
  const site = await fixture(t);
  const client = new Client({ name: 'inventory-fixture', version: '1' }, { capabilities: {} });
  const transport = mcpTransport({ command: process.execPath, args: ['src/cli.js', 'serve'], stderr: 'pipe' });
  t.after(() => client.close());
  await client.connect(transport, { mode: 'auto' });
  const call = async (name, args) => (await client.callTool({ name, arguments: args })).structuredContent;
  const start = await call('a11y_audit_start', { manifest: { projectRoot: site.projectRoot, url: site.url, startupAxe: false } });
  assert.equal(start.success, true);
  const advertised = (await client.listTools()).tools.find(tool => tool.name === 'a11y_audit_request');
  assert.ok(JSON.stringify(advertised.inputSchema).includes('inventory'));
  const result = await call('a11y_audit_request', { runId: start.runId, request: { tool: 'inventory', options: { limit: 1 } } });
  assert.equal(result.success, true); assert.equal(result.inventory.success, true);
  assert.equal(result.inventory.counts.observations, 0);
  assert.equal(result.inventory.limitations.successfulScans, 0);
  assert.equal(result.budget.toolCalls, 1); assert.equal(result.budget.requestedActions, 0);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= 65536);
  await call('a11y_audit_close', { runId: start.runId }); await client.close();
});


test('large linked finding lists retain the observation with explicit bounded disposition metadata', () => {
  const input = retained(1), id = deriveAuditInventory(input).rows[0].observationId;
  const record = input.collection.records[0]; record.before = structuredClone(record.after);
  record.result.nodes = [{ nodeId: 'item0', documentId: 'doc1', selector: '#item0' }];
  record.result.axeNodeBindings.rows[0] = { ...record.result.axeNodeBindings.rows[0], status: 'bound', nodeId: 'item0', documentId: 'doc1', selector: '#item0' };
  input.proposal.findings = Array.from({ length: 1000 }, (_, i) => ({ id: `${i}`.padEnd(300, 'a'), target: { evidenceId: 'ev-0001', nodeId: 'item0' }, evidenceIds: ['ev-0001'] }));
  const d = dispositions(input); d.dispositions = [{ observationId: id, status: 'linked', findingIds: input.proposal.findings.map(f => f.id) }];
  const page = deriveAuditInventory({ ...input, dispositions: d });
  assert.equal(page.success, true); assert.equal(page.counts.linked, 1);
  assert.equal(page.rows[0].authorDisposition.status, 'linked');
  assert.equal(page.rows[0].authorDisposition.truncated, true);
  assert.ok(Buffer.byteLength(JSON.stringify(page)) <= 65536);
});
