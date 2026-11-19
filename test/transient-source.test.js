import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from 'node:http';
import { analyze, checkEvidence } from '../src/index.js';
import { externalProbe } from './helpers.js';

test('restoring source bytes during a scan does not make observed writes current', async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'a11y-transient-'));
  const source = path.join(root, 'index.html');
  const original = '<!doctype html><html lang="en"><title>Original</title><button>Save</button></html>';
  const transient = '<!doctype html><html lang="en"><title>Transient</title><button data-transient="true">Save</button></html>';
  await fs.writeFile(source, original);
  let changed = false;
  const server = createServer(async (request, response) => {
    if (request.url !== '/') { response.writeHead(404).end(); return; }
    try {
      if (!changed && !externalProbe(request)) {
        changed = true;
        await fs.writeFile(source, transient);
        const served = await fs.readFile(source);
        await fs.writeFile(source, original);
        response.writeHead(200, { 'content-type': 'text/html' }).end(served);
      } else response.writeHead(200, { 'content-type': 'text/html' }).end(original);
    } catch { response.writeHead(500).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const report = await analyze({ projectRoot: root, url: `http://127.0.0.1:${server.address().port}`,
      viewport: { width: 800, height: 600 }, rules: ['button-name'],
      states: [{ id: 'transient', assertions: [{ type: 'count', selector: '[data-transient=true]', value: 1 }] }] });
    assert.equal(await fs.readFile(source, 'utf8'), original);
    assert.equal(report.states[0].assertions[0].status, 'passed');
    assert.equal(report.sourceStability.status, 'changed');
    assert.equal(report.status, 'error');
    assert.equal(report.validity, 'expired');
    assert.equal((await checkEvidence(report.reportPath)).status, 'expired');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await fs.rm(root, { recursive: true, force: true });
  }
});
