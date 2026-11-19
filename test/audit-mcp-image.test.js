import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { fixture, unwrapEnvelopedText } from './helpers.js';
import { readInlineOriginal, INLINE_IMAGE_LIMITS } from '../src/audit/mcp-image.js';
const sha = b => createHash('sha256').update(b).digest('hex');
async function host(t, html, fault) {
  const site = await fixture(t, html);
  const client = new Client({ name: 'inline-test', version: '1' }, { capabilities: {} });
  const transport = mcpTransport({ command: process.execPath, args: [...(fault ? ['--import', 'data:text/javascript,' + encodeURIComponent(`import { registerHooks } from 'node:module'; registerHooks({ load(url, context, next) { const result = next(url, context); if (url.endsWith('/src/audit/agent.js')) result.source = String(result.source).replace('await originalBytes(record.png, session.directory);', 'await originalBytes(record.png, session.directory); ' + ${JSON.stringify(fault)}); return result; } });`)] : []), 'src/cli.js', 'serve'], stderr: 'pipe' });
  let stderr = '';
  await client.connect(transport, { mode: 'auto' });
  transport.stderr?.on('data', b => { stderr += b; });
  t.after(() => client.close());
  const call = async (name, args) => {
    const r = await client.callTool({ name, arguments: args });
    assert.ok(Buffer.byteLength(r.content[0].text) <= 65536);
    assert.deepEqual(unwrapEnvelopedText(r), r.structuredContent);
    return r;
  };
  const start = (await call('a11y_audit_start', { manifest: { projectRoot: site.projectRoot, url: site.url, startupAxe: false } })).structuredContent;
  assert.equal(start.success, true);
  return { site, start, client, stderr: () => stderr,
    request: (request, imageOutput) => call('a11y_audit_request', { runId: start.runId, request, ...(imageOutput === undefined ? {} : { imageOutput }) }) };
}
const noImage = r => { assert.equal(r.content.length, 1); assert.equal(r.content.some(x => x.data), false); assert.equal(r.content[0].text.includes('iVBORw0KGgo'), false); };
test('real Chromium original through MCP stdio: opt-in identity, one call, no action, private bytes', async t => {
  const h = await host(t);
  const listed = await h.client.listTools();
  assert.deepEqual(listed.tools.find(x => x.name === 'a11y_audit_request').inputSchema.properties.imageOutput.enum, ['path', 'inline']);
  await h.request({ tool: 'step', actions: [{ action: 'screenshot' }, { action: 'snapshot' }] });
  const request = { tool: 'view', evidenceId: 'ev-0001' };
  const regular = await h.request(request); noImage(regular);
  const explicit = await h.request(request, 'path'); noImage(explicit);
  const r = await h.request(request, 'inline'), v = r.structuredContent;
  assert.equal(v.success, true, JSON.stringify(v)); assert.equal(r.content.length, 2);
  assert.equal(r.content[1].type, 'image'); assert.equal(r.content[1].mimeType, 'image/png');
  const original = await fs.readFile(v.image.path), decoded = Buffer.from(r.content[1].data, 'base64');
  assert.deepEqual(decoded, original); assert.equal(sha(decoded), v.image.sha256); assert.equal(decoded.length, v.image.bytes);
  for (const key of ['evidenceId', 'stateId', 'documentId', 'image']) assert.deepEqual(v[key], regular.structuredContent[key]);
  assert.equal(v.budget.toolCalls, explicit.structuredContent.budget.toolCalls + 1);
  for (const key of ['requestedActions', 'returnedActions', 'successfulActions']) assert.equal(v.budget[key], explicit.structuredContent.budget[key]);
  assert.equal(r.content[0].text.includes(r.content[1].data), false); assert.equal(h.stderr().includes(r.content[1].data), false);
  for (const name of await fs.readdir(h.start.directory)) if (name.endsWith('.json')) assert.equal((await fs.readFile(path.join(h.start.directory, name), 'utf8')).includes(r.content[1].data), false);
  for (const [req, mode] of [[request, 'bad'], [{ tool: 'step', actions: [{ action: 'screenshot' }] }, 'inline'], [{ tool: 'view', evidenceId: 'ev-0002' }, 'inline']]) {
    const refused = await h.request(req, mode); assert.equal(refused.structuredContent.success, false); noImage(refused);
  }
  await fs.writeFile(v.image.path, Buffer.alloc(original.length));
  const changed = await h.request(request, 'inline'); noImage(changed); assert.equal(changed.structuredContent.success, false);
  await fs.unlink(v.image.path);
  const outside = path.join(h.site.projectRoot, 'outside.png'); await fs.writeFile(outside, original); await fs.symlink(outside, v.image.path);
  const linked = await h.request(request, 'inline'); noImage(linked); assert.equal(linked.structuredContent.success, false);
});

test('real Chromium pixel-bound refusal through MCP stdio', async t => {
  const h = await host(t, '<!doctype html><title>Tall</title><div style="height:15000px">Original tall page</div>');
  await h.request({ tool: 'step', actions: [{ action: 'screenshot', fullPage: true }] });
  const r = await h.request({ tool: 'view', evidenceId: 'ev-0001' }, 'inline');
  noImage(r); assert.equal(r.structuredContent.error.code, 'INLINE_IMAGE_PIXEL_LIMIT'); assert.equal(r.structuredContent.imageOutput.delivered, false);
});

function chunk(type, data) {
  const b = Buffer.alloc(data.length + 12); b.writeUInt32BE(data.length); b.write(type, 4); data.copy(b, 8);
  let crc = 0xffffffff;
  for (const byte of b.subarray(4, b.length - 4)) { crc ^= byte; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  b.writeUInt32BE((crc ^ 0xffffffff) >>> 0, b.length - 4); return b;
}
function png(width = 1, height = 1, pad = 0) {
  const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
  return Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), chunk('IHDR', header), ...(pad ? [chunk('teSt', Buffer.alloc(pad))] : []), chunk('IDAT', deflateSync(Buffer.alloc((width * 3 + 1) * height))), chunk('IEND', Buffer.alloc(0))]);
}
test('synthetic unit boundaries and post-view reread attacks (not browser evidence)', async t => {
  const site = await fixture(t); const directory = site.projectRoot, file = path.join(directory, 'original.png');
  async function put(bytes) { await fs.writeFile(file, bytes); return { path: file, bytes: bytes.length, sha256: sha(bytes) }; }
  const valid = png(); let receipt = await put(valid);
  assert.equal((await readInlineOriginal(receipt, directory)).block.data, valid.toString('base64'));
  // Simulate mutation after agent verification using the already verified receipt.
  await fs.writeFile(file, Buffer.alloc(valid.length));
  await assert.rejects(readInlineOriginal(receipt, directory), { code: 'INLINE_IMAGE_CHANGED' });
  receipt = await put(Buffer.from('not a PNG'));
  await assert.rejects(readInlineOriginal(receipt, directory), { code: 'INLINE_IMAGE_INVALID_PNG' });
  const corrupted = Buffer.from(valid); corrupted[corrupted.length - 1] ^= 1;
  receipt = await put(corrupted); await assert.rejects(readInlineOriginal(receipt, directory), { code: 'INLINE_IMAGE_INVALID_PNG' });
  receipt = await put(valid.subarray(0, valid.length - 12)); await assert.rejects(readInlineOriginal(receipt, directory), { code: 'INLINE_IMAGE_INVALID_PNG' });
  const padded = png(1, 1, INLINE_IMAGE_LIMITS.maxBytes - valid.length - 12);
  receipt = await put(padded); assert.equal((await readInlineOriginal(receipt, directory)).block.data.length, padded.toString('base64').length);
  receipt = await put(Buffer.concat([padded, Buffer.from([0])]));
  await assert.rejects(readInlineOriginal(receipt, directory), { code: 'INLINE_IMAGE_BYTE_LIMIT' });
  receipt = await put(png(4000, 4000)); assert.deepEqual((await readInlineOriginal(receipt, directory)).dimensions, { width: 4000, height: 4000 });
  receipt = await put(png(4000, 4001)); await assert.rejects(readInlineOriginal(receipt, directory), { code: 'INLINE_IMAGE_PIXEL_LIMIT' });
  receipt = await put(valid); const other = path.join(directory, 'other'); await fs.mkdir(other);
  await assert.rejects(readInlineOriginal(receipt, other), { code: 'INLINE_IMAGE_INVALID_ARTIFACT' });
  const target = path.join(directory, 'target.png'); await fs.rename(file, target); await fs.symlink(target, file);
  await assert.rejects(readInlineOriginal(receipt, directory), { code: 'INLINE_IMAGE_INVALID_ARTIFACT' });
  await fs.unlink(file); await fs.mkdir(file); await assert.rejects(readInlineOriginal(receipt, directory), { code: 'INLINE_IMAGE_INVALID_ARTIFACT' });
});

// Test-only module hook inserts a filesystem fault immediately AFTER the real
// agent verification. Production source and registration remain unchanged.
test('MCP stdio refuses deterministic post-verification tamper, symlink and session escape', async t => {
  for (const fault of [
    "await fs.writeFile(record.png.path, Buffer.alloc(record.png.bytes));",
    "await fs.rename(record.png.path, record.png.path + '.saved'); await fs.symlink(record.png.path + '.saved', record.png.path);",
    "await fs.rename(session.directory, session.directory + '-moved'); await fs.symlink(session.directory + '-moved', session.directory);",
  ]) {
    const h = await host(t, undefined, fault);
    await h.request({ tool: 'step', actions: [{ action: 'screenshot' }] });
    const r = await h.request({ tool: 'view', evidenceId: 'ev-0001' }, 'inline');
    noImage(r); assert.equal(r.structuredContent.success, false);
    assert.match(r.structuredContent.error.code, /^INLINE_IMAGE_/);
    assert.equal(r.structuredContent.imageOutput.delivered, false);
  }
});

test('real Chromium raw-byte bound refusal through MCP stdio', async t => {
  const h = await host(t, `<!doctype html><title>Noise</title><style>body{margin:0}</style><canvas width="1280" height="900"></canvas><script>
    const c=document.querySelector('canvas').getContext('2d'), d=c.createImageData(1280,900); let n=1234567;
    for(let i=0;i<d.data.length;i+=4){for(let j=0;j<3;j++){n^=n<<13;n^=n>>>17;n^=n<<5;d.data[i+j]=n&255;}d.data[i+3]=255;} c.putImageData(d,0,0);
  </script>`);
  await h.request({ tool: 'step', actions: [{ action: 'screenshot' }] });
  const r = await h.request({ tool: 'view', evidenceId: 'ev-0001' }, 'inline');
  noImage(r); assert.equal(r.structuredContent.error.code, 'INLINE_IMAGE_BYTE_LIMIT');
  assert.ok(r.structuredContent.image.bytes > INLINE_IMAGE_LIMITS.maxBytes);
});
