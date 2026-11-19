import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { MCP_TEXT_LIMIT, AUDIT_TEXT_LIMIT } from '../src/audit/projection.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { fixture } from './helpers.js';

// 400 unnamed buttons: the axe record and its candidates are far larger than the MCP cap.
const many = `<!doctype html><html lang="en"><title>Many</title><main>${Array.from({ length: 400 }, (_, i) => `<button id="b${i}"></button>`).join('')}</main></html>`;

async function host(t, html, manifest = {}) {
  const site = await fixture(t, html);
  const client = new Client({ name: 'compact-test', version: '1' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(mcpTransport({ command: process.execPath, args: ['src/cli.js', 'serve'], stderr: 'pipe' }), { mode: 'auto' });
  const sizes = [];
  const call = async (name, args) => {
    const response = await client.callTool({ name, arguments: args });
    const bytes = Buffer.byteLength(response.content[0].text);
    sizes.push(bytes);
    assert.ok(bytes <= MCP_TEXT_LIMIT, `${name} returned ${bytes} bytes`);
    return response.structuredContent;
  };
  const start = await call('a11y_audit_start', { manifest: { projectRoot: site.projectRoot, url: site.url, ...manifest } });
  assert.equal(start.success, true, JSON.stringify(start));
  return { client, call, start, sizes, request: request => call('a11y_audit_request', { runId: start.runId, request }) };
}

test('MCP caps every text response at 20,000 characters and pages large axe results with a cursor', async t => {
  assert.ok(MCP_TEXT_LIMIT < AUDIT_TEXT_LIMIT);
  const h = await host(t, many, { startupSweep: true });
  const [first] = h.start.startup.axe;
  assert.ok(first.counts.candidates >= 400);
  assert.ok(first.candidates.length > 0 && first.candidates.length < first.counts.candidates, 'start returns the first page only');
  assert.equal(first.pagination.complete, false);
  assert.match(first.pagination.more, /^more available: \d+ of \d+ candidates/);
  assert.ok(first.candidates.every(row => row.draftFinding?.selector && row.draftFinding.criterionId && row.draftFinding.nodeId && row.draftFinding.evidenceIds.length === 1));
  // Startup axe (1 call) + startup sweep (exactly 1 more call); 25 Tab presses hit the cap and still fit the MCP cap.
  assert.equal(h.start.budget.toolCalls, 2);
  assert.equal(h.start.startup.sweep.tabPresses, 25); assert.equal(h.start.startup.sweep.stopped, 'limit');
  assert.equal(h.start.startup.sweep.focusOrder.length + (h.start.startup.sweep.focusOrderOmitted ?? 0), 25);

  const seen = [...first.candidates];
  for (let next = first.pagination.next, pages = 0; next; pages++) {
    assert.ok(pages < 60);
    const read = await h.request({ tool: 'read', evidenceId: 'ev-0002', options: next });
    assert.equal(read.success, true, JSON.stringify(read));
    seen.push(...read.candidates); next = read.pagination.next;
    if (next) assert.match(read.pagination.more, /^more available/);
  }
  assert.equal(seen.length, first.counts.candidates);
  assert.equal(new Set(seen.map(row => row.candidateId)).size, seen.length);
  assert.ok(Math.max(...h.sizes) <= MCP_TEXT_LIMIT);
});

test('MCP pages node and field reads inside the 20,000-character cap', async t => {
  const h = await host(t, many, { startupAxe: false });
  await h.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'axe' }] });
  const nodes = await h.request({ tool: 'read', evidenceId: 'ev-0002', options: { view: 'nodes' } });
  assert.equal(nodes.success, true); assert.ok(nodes.pagination.next); assert.match(nodes.more, /^more available/);
  let field = await h.request({ tool: 'read', evidenceId: 'ev-0002', options: { view: 'field', field: '/result/axe' } });
  assert.equal(field.success, true); assert.ok(field.pagination.next);
  assert.match(field.more, /^more available/);
  for (let chunks = 0; chunks < 5 && field.pagination.next; chunks++) {
    field = await h.request({ tool: 'read', evidenceId: 'ev-0002', options: field.pagination.next });
    assert.equal(field.success, true, JSON.stringify(field));
  }
  assert.ok(Math.max(...h.sizes) <= MCP_TEXT_LIMIT);
});

test('MCP start can opt out of the automatic snapshot + axe', async t => {
  const h = await host(t, many, { startupAxe: false });
  assert.equal(h.start.startup, undefined); assert.equal(h.start.budget.toolCalls, 0);
  assert.ok(h.start.firstRequest);
});

test('a step whose rows overflow the cap gets compact rows, then a prefix with a sequential-ID note', async t => {
  // Row count drives compaction; a tiny DOM keeps the repeated snapshots cheap.
  const page = '<!doctype html><html lang="en"><title>Compact rows</title><main><button>Save</button></main></html>';
  const h = await host(t, page, { startupAxe: false });
  const step = await h.request({ tool: 'step', actions: Array.from({ length: 180 }, () => ({ action: 'snapshot' })) });
  assert.equal(step.records.length, 180); assert.equal(step.recordsOmitted, undefined);
  assert.deepEqual(Object.keys(step.records[0]), ['evidenceId', 'action', 'success']);
  assert.ok(Math.max(...h.sizes) <= MCP_TEXT_LIMIT);

  const site = await fixture(t, page);
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, { textLimit: 3000 });
  const small = await agent.request({ tool: 'step', actions: Array.from({ length: 60 }, () => ({ action: 'snapshot' })) });
  assert.equal(small.success, true, JSON.stringify(small).slice(0, 300));
  assert.ok(Buffer.byteLength(JSON.stringify(small)) <= 3000);
  assert.ok(small.recordsOmitted > 0 && small.records.length + small.recordsOmitted === 60);
  assert.match(small.recordsNote, /sequential/);
  await agent.close();
});
