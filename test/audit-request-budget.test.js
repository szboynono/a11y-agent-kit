import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { openAuditAgent, auditAgentManifestSchema } from '../src/audit/agent.js';
import { parseAuditManifest, auditActionSchema } from '../src/audit/schema.js';
import { fixture } from './helpers.js';

const proposal = { auditor: { name: 'First-party budget fixture' }, findings: [] };

test('invalid agent caps reject before executor creation and collection stays strict', async () => {
  const base = { projectRoot: process.cwd(), url: 'http://localhost/' };
  let created = 0;
  for (const maxToolCalls of [0, 61, 1.5, '20']) {
    await assert.rejects(openAuditAgent({ ...base, maxToolCalls }, { openAuditSession: () => { created++; throw new Error('executor created'); } }), { code: 'INVALID_AUDIT_MANIFEST' });
  }
  assert.equal(created, 0);
  assert.equal(auditAgentManifestSchema.parse(base).maxToolCalls, 60);
  assert.equal(auditAgentManifestSchema.safeParse({ ...base, unexpected: true }).success, false);
  assert.equal(auditActionSchema.safeParse({ action: 'snapshot', maxToolCalls: 20 }).success, false);
  for (const maxToolCalls of [undefined, 20]) {
    const stop = new Error('validated executor boundary');
    await assert.rejects(openAuditAgent({ ...base, maxToolCalls }, { openAuditSession: manifest => {
      assert.equal(Object.hasOwn(manifest, 'maxToolCalls'), false);
      assert.deepEqual(manifest, parseAuditManifest({ ...base, maxActions: 180, wallSeconds: 600 }));
      throw stop;
    } }), error => error === stop);
  }
  assert.throws(() => parseAuditManifest({ ...base, maxToolCalls: 20 }), { code: 'INVALID_AUDIT_MANIFEST' });
});

test('small cap charges malformed and queued calls; every refused operation has no side effects', async t => {
  const site = await fixture(t);
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, maxToolCalls: 3 });
  t.after(() => agent.close());
  assert.equal(agent.budget().maxToolCalls, 3);
  assert.equal((await agent.request(null)).error.code, 'INVALID_AGENT_REQUEST');
  const step = { tool: 'step', actions: [{ action: 'click', selector: '#save' }] };
  const burst = await Promise.all(Array.from({ length: 5 }, () => agent.request(step)));
  assert.deepEqual(burst.map(r => r.success), [true, true, false, false, false]);
  assert.equal(burst[1].records[0].evidenceId, 'ev-0002');
  for (const row of burst.slice(2)) assert.equal(row.error.code, 'TOOL_BUDGET_EXHAUSTED');
  const before = await fs.readdir(agent.directory);
  for (const request of [
    { tool: 'read', evidenceId: 'ev-0001' }, { tool: 'view', evidenceId: 'ev-0001' },
    { tool: 'inventory' }, { tool: 'checkpoint', proposal }, { tool: 'submit', proposal },
  ]) {
    const row = await agent.request(request);
    assert.equal(row.error.code, 'TOOL_BUDGET_EXHAUSTED');
    assert.equal(row.budget.maxToolCalls, 3); assert.equal(row.budget.remainingToolCalls, 0);
  }
  assert.deepEqual(await fs.readdir(agent.directory), before);
  const closed = await agent.close();
  assert.equal(closed.budget.toolCalls, 11); assert.equal(closed.budget.returnedActions, 2);
  assert.equal(closed.status, 'incomplete');
  const report = JSON.parse(await fs.readFile(closed.sourceAudit.reportPath));
  assert.equal(report.records.length, 2); assert.equal(Object.hasOwn(report.manifest, 'maxToolCalls'), false);
});

test('checkpoint and submission fit cap two; cap one preserves acknowledged draft on refused submit', async t => {
  const site = await fixture(t);
  for (const maxToolCalls of [1, 2]) {
    const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, maxToolCalls });
    t.after(() => agent.close());
    const draft = await agent.request({ tool: 'checkpoint', proposal });
    assert.equal(draft.success, true);
    const submitted = await agent.request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest });
    assert.equal(submitted.success, maxToolCalls === 2);
    assert.equal(submitted.budget.toolCalls, 2); assert.equal(submitted.budget.remainingToolCalls, 0);
    if (maxToolCalls === 1) {
      assert.equal(submitted.error.code, 'TOOL_BUDGET_EXHAUSTED');
      assert.deepEqual(submitted.delivery, { checkpoint: 'saved', submission: 'unsubmitted' });
      assert.equal((await fs.readdir(agent.directory)).some(n => n.startsWith('audit-proposal-')), false);
    }
    const closed = await agent.close();
    assert.equal(closed.checkpoint.checkpointDigest, draft.checkpoint.checkpointDigest);
    assert.equal(closed.status, maxToolCalls === 2 ? 'submitted' : 'incomplete');
  }
});

test('public CLI accepts agent manifest cap and exposes matching start/request/close budgets', { timeout: 15000 }, async t => {
  const site = await fixture(t);
  const dir = path.join(site.projectRoot, 'evidence'); await fs.mkdir(dir);
  const file = path.join(dir, 'agent.json');
  await fs.writeFile(file, JSON.stringify({ projectRoot: site.projectRoot, url: site.url, maxToolCalls: 1 }));
  const child = spawn(process.execPath, ['src/cli.js', 'audit-agent', file]);
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  let stdout = '', stderr = '', sent = false;
  child.stdout.on('data', chunk => {
    stdout += chunk;
    if (!sent && stdout.includes('\n')) {
      sent = true;
      child.stdin.end('null\n{"tool":"step","actions":[{"action":"snapshot"}]}\n{"command":"finish"}\n');
    }
  });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const code = await new Promise(resolve => child.on('close', resolve));
  assert.equal(code, 1, stderr);
  const rows = stdout.trim().split('\n').map(JSON.parse);
  assert.equal(rows.length, 4);
  assert.equal(rows[0].kind, 'audit-agent-session');
  assert.equal(rows[1].error.code, 'INVALID_AGENT_REQUEST');
  assert.equal(rows[2].error.code, 'TOOL_BUDGET_EXHAUSTED');
  for (const row of rows) assert.equal(row.budget.maxToolCalls, 1);
  assert.equal(rows.at(-1).budget.toolCalls, 2); assert.equal(rows.at(-1).budget.returnedActions, 0);
  assert.equal(rows.at(-1).budget.remainingToolCalls, 0);
});
