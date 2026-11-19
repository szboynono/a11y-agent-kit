import test from 'node:test';
import assert from 'node:assert/strict';
import { McpServer } from '@modelcontextprotocol/server';
import { registerAuditTools } from '../src/audit/mcp.js';
import { AUDIT_PLAYBOOK_TEXT, AUDIT_EVIDENCE_GUIDANCE, AUDIT_SERVER_INSTRUCTIONS, auditAgentRequestSchema } from '../src/audit/agent.js';

async function listing(runtimeProfile) {
  const server = new McpServer({ name: 'static-listing-contract', version: '1' });
  let opened = 0;
  registerAuditTools(server, { runtimeProfile, openAgent: () => { opened++; assert.fail('Listing must not open an audit session.'); } });
  // Exercise production registration and the SDK's own JSON-schema conversion,
  // without a transport, initialization or a browser-backed audit session.
  const result = await server.server._requestHandlers.get('tools/list')({ method: 'tools/list', params: {} }, {});
  assert.equal(opened, 0);
  assert.equal(server.server._transport, undefined);
  return result.tools;
}
const variants = tool => tool.inputSchema.properties.request.oneOf ?? tool.inputSchema.properties.request.anyOf;

test('production default MCP listing fits the existing request budget and description contracts', async () => {
  const tools = await listing();
  assert.deepEqual(tools.map(tool => tool.name), ['a11y_audit_start', 'a11y_audit_request', 'a11y_audit_close']);
  const request = tools.find(tool => tool.name === 'a11y_audit_request');
  assert.ok(JSON.stringify(request).length < 12_000, `request tool listing is ${JSON.stringify(request).length} characters`);
  for (const name of ['a11y_audit_start', 'a11y_audit_request']) {
    const description = tools.find(tool => tool.name === name).description;
    assert.match(description, /Playbook: 1\. a11y_audit_start already ran snapshot \+ axe/);
    assert.match(description, /re-scan with axe after each new state or page/);
    assert.match(description, /before writing findings there; axe sees only what is rendered/);
    assert.match(description, /adoptAxe:'all'/);
    assert.match(description, /what axe cannot find/);
    assert.match(description, /view:'guide'/);
    assert.ok(description.split(/\s+/).length <= 130);
  }
  assert.match(AUDIT_SERVER_INSTRUCTIONS, /Playbook: 1\. a11y_audit_start already ran .*what axe cannot find.*stopping after a few probes/);
});

test('production listing keeps evidence guidance reachable and proposal shapes distinct', async () => {
  const request = (await listing()).find(tool => tool.name === 'a11y_audit_request');
  assert.ok(AUDIT_PLAYBOOK_TEXT.split(/\s+/).length <= 120);
  assert.match(AUDIT_PLAYBOOK_TEXT, /inspect_many/);
  assert.ok(AUDIT_EVIDENCE_GUIDANCE.split(/\s+/).length <= 300);
  assert.ok(AUDIT_EVIDENCE_GUIDANCE.includes('exactly consecutive inspect -> click -> wait_for'));
  assert.ok(AUDIT_EVIDENCE_GUIDANCE.includes('not business terminality'));
  assert.equal(JSON.stringify(request).includes('exactly consecutive'), false);
  for (const operation of ['step', 'checkpoint', 'submit']) {
    const branch = variants(request).find(value => value.properties.tool.const === operation);
    assert.match(branch.description ?? JSON.stringify(branch), /view:'guide'/);
    if (operation !== 'step') {
      const description = branch.properties.proposal.description;
      assert.ok(description.includes('proposal.findings:[{id,title,criterionId,target:{evidenceId,nodeId},evidenceIds,observation,reason,applicability,exceptions,scope,method?}]'));
      assert.match(description, /draftFinding/);
      assert.match(description, /host's findings tool only/);
      assert.match(description, /adoptAxe/);
    }
  }
});

test('actual SDK listing preserves default caps, strict request variants and readiness defaults', async () => {
  const tools = await listing(), start = tools.find(tool => tool.name === 'a11y_audit_start');
  assert.deepEqual(start.inputSchema.properties.manifest.properties.maxToolCalls, { type: 'integer', minimum: 1, maximum: 60, default: 60 });
  const request = tools.find(tool => tool.name === 'a11y_audit_request');
  assert.equal(request.inputSchema.additionalProperties, false);
  assert.deepEqual(request.inputSchema.properties.imageOutput.enum, ['path', 'inline']);
  assert.deepEqual(variants(request).map(value => value.properties.tool.const), ['step', 'read', 'inventory', 'view', 'checkpoint', 'submit']);
  for (const input of [{ tool: 'checkpoint', proposal: null }, { tool: 'submit' },
    { tool: 'submit', proposal: { arbitrary: true } }, { tool: 'step', actions: [{ action: 'snapshot' }] }]) {
    assert.deepEqual(auditAgentRequestSchema.parse(input), input);
  }
  assert.equal(auditAgentRequestSchema.safeParse({ tool: 'submit', extra: true }).success, false);
  assert.equal(auditAgentRequestSchema.parse({ tool: 'step', actions: [{ action: 'wait_for', selector: '#observed', condition: 'attached' }] }).actions[0].timeoutMs, 3000);
});

test('actual SDK trusted-profile listing retains the explicit shared-ledger contract', async () => {
  const unused = () => assert.fail('Listing must not invoke runtime operations.');
  const profile = { name: 'axe-gap-v2', version: 1, maxToolCalls: 180, explorationSeconds: 600,
    maxRequestBytes: 1048576, compactNativeReceipt: true, liveSelectorProbe: false, startedAt: 1, deadline: 600001,
    now: () => 1, reserveActions: unused, runCall: unused, validateProposal: unused, prepareSubmission: unused, budget: unused };
  const tools = await listing(profile), start = tools.find(tool => tool.name === 'a11y_audit_start');
  assert.equal(start.inputSchema.properties.manifest.properties.maxToolCalls.const, 180);
  assert.equal(start.inputSchema.properties.manifest.properties.maxToolCalls.default, 180);
  const request = tools.find(tool => tool.name === 'a11y_audit_request'), schema = JSON.stringify(request.inputSchema);
  assert.match(schema, /inspect_many requires explicit selectors/);
  assert.match(schema, /receipt query costs a call/);
  assert.match(schema, /selector-only hover\/focus each cost one shared action/);
  assert.match(request.description, /Shared ledger budget is authoritative/);
});
