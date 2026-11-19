// First-party fixture only. Executes product commands, never a model or repair loop.
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const root = path.resolve(import.meta.dirname, '..');
const output = path.resolve(process.argv[2] ?? path.join(root, 'evidence', 'byoa-quickstart'));
await fs.mkdir(output, { recursive: true });
const site = await fs.realpath(await fs.mkdtemp(path.join(output, 'site-')));
const inputs = path.join(site, 'evidence'); await fs.mkdir(inputs);
const json = value => JSON.stringify(value);
const save = async (name, value) => { const file = path.join(inputs, name); await fs.writeFile(file, json(value)); return file; };
const html = unnamed => `<!doctype html><html lang="en"><title>First-party quickstart fixture</title><body><main>
<button id="target" ${unnamed ? '' : 'aria-label="Save"'}></button>
<button id="open-search" onclick="document.querySelector('[role=dialog]').hidden=false;document.querySelector('#search-input').focus()">Search</button>
<div role="dialog" aria-label="Search" hidden><label for="search-input">Search</label><input id="search-input"></div>
</main></body></html>`;
await fs.writeFile(path.join(site, 'index.html'), html(true));
await fs.writeFile(path.join(site, 'legacy.html'), html(false));
const server = http.createServer(async (request, response) => {
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  response.end(await fs.readFile(path.join(site, request.url === '/legacy' ? 'legacy.html' : 'index.html')));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}/`;
const cli = path.join(root, 'src/cli.js'), commands = [];
function processRun(args, input = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 45000);
    child.stdout.on('data', c => { stdout += c; }); child.stderr.on('data', c => { stderr += c; });
    child.on('error', reject); child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
    child.stdin.end(input);
  });
}
async function command(args, expected, input) {
  const r = await processRun(args, input);
  assert.equal(r.code, expected, `${args.join(' ')}: ${r.stdout} ${r.stderr}`);
  const rows = r.stdout.trim().split('\n').map(line => JSON.parse(line));
  commands.push({ command: ['node', 'src/cli.js', ...args], exitCode: r.code, statuses: rows.map(row => row.status).filter(Boolean) });
  return rows;
}
try {
  const manifest = { projectRoot: site, url, maxActions: 180, wallSeconds: 120, maxElements: 3000 };
  const manifestPath = await save('audit-manifest.json', manifest);
  const batchManifestPath = await save('batch-manifest.json', { ...manifest, actions: [{ action: 'snapshot' }, { action: 'axe' }, { action: 'inspect', selector: '#target' }] });
  const [batch] = await command(['audit', batchManifestPath, '--summary'], 0);
  const audit = JSON.parse(await fs.readFile(batch.reportPath));
  const observation = audit.records.find(record => record.action === 'inspect');
  const target = observation.result.element;
  assert.equal(target.attributes.id, 'target', 'Inspect must retain the original fixture target');
  const finding = { id: 'fixture-name', title: 'Synthetic unnamed button', criterionId: '4.1.2',
    target: { evidenceId: observation.evidenceId, nodeId: target.nodeId }, evidenceIds: [observation.evidenceId],
    observation: 'First-party fixture button has no name.', reason: 'Synthetic local naming contract.',
    applicability: 'Native button.', exceptions: 'None asserted.', scope: 'This fixture target only.', method: 'dom' };
  const findings = await save('findings.json', { auditor: { name: 'Quickstart fixture auditor' }, findings: [finding] });
  const [proposal] = await command(['audit-submit', batch.reportPath, findings, '--summary'], 1);
  const review = await save('review.json', { reviewer: { name: 'Independent fixture reviewer', independentOfAuditor: true }, decisions: [{
    findingId: finding.id, verdict: 'supported', checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
    reason: 'Synthetic review schema exercise; no human expert or model review was run.',
    directEvidence: { evidenceId: observation.evidenceId, nodeIds: [target.nodeId],
      criterionClause: '4.1.2 requires a programmatically determinable component name.',
      explanation: 'Retained native button has no naming attributes or associated label text, and its target-scoped ARIA inspect snapshot has no name.' },
  }] });
  const [reviewed] = await command(['audit-review', proposal.reportPath, review, '--summary'], 0);
  assert.equal((await command(['audit-check', reviewed.reportPath, '--summary'], 0))[0].status, 'current');
  await command(['audit-live', manifestPath, '--summary'], 0, await fs.readFile(path.join(root, 'examples/audit-live.jsonl'), 'utf8'));
  const smoke = await command(['audit-agent', manifestPath], 1, await fs.readFile(path.join(root, 'examples/audit-agent-smoke.jsonl'), 'utf8'));
  assert.equal(smoke.at(-1).status, 'incomplete');
  const draft = smoke.find(row => row.tool === 'checkpoint').checkpoint;
  await command(['audit-checkpoint-read', draft.checkpointPath], 1);
  await command(['audit-submit-checkpoint', smoke.at(-1).sourceAudit.reportPath, draft.checkpointPath], 1);

  // Interactive JSONL submit uses the actual checkpoint ACK, not a hard-coded digest.
  const child = spawn(process.execPath, [cli, 'audit-agent', manifestPath], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = new Promise((resolve, reject) => { child.on('error', reject); child.on('close', resolve); });
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity })[Symbol.asyncIterator]();
  const timer = setTimeout(() => child.kill('SIGKILL'), 45000);
  const next = async () => { const row = await lines.next(); assert.equal(row.done, false); return JSON.parse(row.value); };
  const request = async value => { child.stdin.write(`${json(value)}\n`); const row = await next(); assert.notEqual(row.success, false, json(row)); return row; };
  try {
    assert.equal((await next()).kind, 'audit-agent-session');
    await request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'screenshot' }] });
    await request({ tool: 'read', evidenceId: 'ev-0001' });
    await request({ tool: 'view', evidenceId: 'ev-0002' });
    const ack = await request({ tool: 'checkpoint', proposal: { auditor: { name: 'JSONL fixture' }, findings: [] } });
    const submitted = await request({ tool: 'submit', checkpointDigest: ack.checkpoint.checkpointDigest });
    assert.equal(submitted.status, 'needs_review');
    child.stdin.end(); await next();
    assert.equal(await exited, 0);
    commands.push({ command: ['node', 'src/cli.js', 'audit-agent', manifestPath], mode: 'interactive ACK submit', exitCode: 0 });
  } finally { clearTimeout(timer); child.stdin.end(); if (child.exitCode === null) child.kill('SIGTERM'); }

  // MCP stdio smoke sends step, read, view, checkpoint and submit. Inventory is outside this smoke.
  // The view check only verifies that the returned local PNG file is nonempty.
  const client = new Client({ name: 'quickstart-smoke', version: '1' }, { capabilities: {} });
  const transport = new StdioClientTransport({ command: process.execPath, args: [cli, 'serve'], stderr: 'pipe' });
  try {
    await client.connect(transport, { mode: 'auto' });
    const call = async (name, args) => { const result = (await client.callTool({ name, arguments: args })).structuredContent; assert.notEqual(result.success, false, json(result)); return result; };
    const start = await call('a11y_audit_start', { manifest });
    // Start already ran snapshot + axe (ev-0001, ev-0002) and returned the axe candidates inline.
    assert.equal(start.startup.success, true, json(start)); assert.ok(start.startup.axe[0].candidates[0].draftFinding, json(start.startup.axe));
    const request = request => call('a11y_audit_request', { runId: start.runId, request });
    await request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'screenshot' }] });
    await request({ tool: 'read', evidenceId: 'ev-0003' });
    const image = await request({ tool: 'view', evidenceId: 'ev-0004' }); assert.ok((await fs.stat(image.image.path)).size > 0);
    const draft = await request({ tool: 'checkpoint', proposal: { auditor: { name: 'MCP fixture' }, findings: [] } });
    await request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest });
    await call('a11y_audit_close', { runId: start.runId });
    commands.push({ command: ['node', 'src/cli.js', 'serve'], status: 'MCP handshake, start, step/read/view/checkpoint/submit, close verified' });
  } finally { await client.close(); }
  const legacy = JSON.parse(await fs.readFile(path.join(root, 'examples/manifest.json')));
  Object.assign(legacy, { projectRoot: site, url: `${url}legacy` });
  const legacyPath = await save('legacy-manifest.json', legacy);
  const [baseline] = await command(['analyze', legacyPath, '--summary'], 0);
  const [verification] = await command(['verify', baseline.reportPath, '--summary'], 0);
  assert.equal((await command(['check', verification.reportPath, '--summary'], 0))[0].status, 'current');
  const receipt = { status: 'passed', fixture: 'first-party synthetic only', modelInvoked: false, realReviewerInvoked: false,
    scope: 'CLI and generic MCP transport smoke; not an accessibility assessment or a real-model host acceptance', commands };
  await fs.writeFile(path.join(output, 'receipt.json'), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify({ ...receipt, commands: commands.length, receiptPath: path.join(output, 'receipt.json') }));
} finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
