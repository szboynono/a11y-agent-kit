import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { fixture, html } from './helpers.js';

const cliPath = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const exec = promisify(execFile);

async function cli(...args) {
  try {
    const result = await exec(process.execPath, [cliPath, ...args], { maxBuffer: 10 * 1024 * 1024 });
    return { code: 0, ...result, data: JSON.parse(result.stdout) };
  } catch (error) {
    return { code: error.code, stdout: error.stdout, stderr: error.stderr, data: JSON.parse(error.stdout) };
  }
}

test('CLI emits JSON, persists baselines, and uses nonzero failure exits', async t => {
  const app = await fixture(t, html({ broken: true }));
  const manifestPath = path.join(app.projectRoot, 'manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(app.manifest));
  const baseline = await cli('analyze', manifestPath);
  assert.equal(baseline.code, 1);
  assert.equal(baseline.data.status, 'failed');
  assert.equal(baseline.stderr, '');
  assert.equal((await cli('check', baseline.data.reportPath)).code, 0);
  const failed = await cli('verify', baseline.data.reportPath);
  assert.equal(failed.code, 1);
  assert.equal(failed.data.status, 'failed');
  await app.write(html());
  assert.equal((await cli('check', baseline.data.reportPath)).code, 1);
  const repaired = await cli('verify', baseline.data.reportPath);
  assert.equal(repaired.code, 0);
  assert.equal(repaired.data.status, 'passed');
  assert.equal((await cli('check', repaired.data.reportPath)).data.status, 'current');
  assert.equal((await cli('verify', baseline.data.reportPath, '--rules', 'label')).data.status, 'error');
  const invalidPath = path.join(app.projectRoot, 'invalid.json');
  await fs.writeFile(invalidPath, '{ invalid JSON');
  const invalid = await cli('analyze', invalidPath);
  assert.equal(invalid.code, 1);
  assert.equal(invalid.data.status, 'error');
});

test('official MCP v2 client performs stdio handshake, list, and all three calls', async t => {
  const app = await fixture(t, html({ broken: true }));
  const transport = mcpTransport({ command: process.execPath, args: [cliPath, 'serve'], stderr: 'pipe' });
  let stderr = '';
  transport.stderr.on('data', chunk => { stderr += chunk.toString(); });
  const client = new Client({ name: 'a11y-agent-kit-test', version: '1.0.0' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(transport, { mode: 'auto' });
  assert.equal(client.getServerVersion().name, 'a11y-agent-kit');
  const listed = await client.listTools();
  assert.deepEqual(new Set(listed.tools.map(tool => tool.name)), new Set(['a11y_analyze', 'a11y_verify', 'a11y_check_evidence', 'a11y_audit_start', 'a11y_audit_request', 'a11y_audit_close']));
  const scanned = await client.callTool({ name: 'a11y_analyze', arguments: app.manifest });
  assert.equal(scanned.isError, true);
  const baseline = scanned.structuredContent;
  assert.equal(baseline.status, 'failed');
  assert.deepEqual(JSON.parse(scanned.content[0].text), baseline);
  const checked = await client.callTool({ name: 'a11y_check_evidence', arguments: { reportPath: baseline.reportPath } });
  assert.equal(checked.structuredContent.status, 'current');
  await app.write(html());
  const result = await client.callTool({ name: 'a11y_verify', arguments: { baselinePath: baseline.reportPath } });
  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.status, 'passed');
  const rejected = await client.callTool({ name: 'a11y_verify', arguments: { baselinePath: baseline.reportPath, rules: ['label'] } });
  assert.equal(rejected.isError, true);
  const invalid = await client.callTool({ name: 'a11y_analyze', arguments: { ...app.manifest, rules: ['color-contrast'] } });
  assert.equal(invalid.isError, true);
  assert.equal(stderr, '', 'stdout must remain protocol-only and normal operation should be quiet');
});
