import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { chromium } from 'playwright';
import { externalProbe, fixture } from './helpers.js';
import { parseAuditManifest } from '../src/audit/schema.js';
import { loadNetworkReplay, configureNetworkReplay, NETWORK_REPLAY_LIMITS } from '../src/audit/network-replay.js';
import { collectAudit } from '../src/audit/collect.js';
import { openAuditSession } from '../src/audit/live.js';
import { checkAudit } from '../src/audit/review.js';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');

// A generated two-glyph TrueType fixture: A has a 600/1000-em advance and a
// rectangular contour. No downloaded font or pre-existing evidence is read.
function syntheticFont() {
  const table = {}, head = table.head = Buffer.alloc(54), hhea = table.hhea = Buffer.alloc(36), maxp = table.maxp = Buffer.alloc(32);
  head.writeUInt32BE(0x10000, 0); head.writeUInt32BE(0x10000, 4); head.writeUInt32BE(0x5f0f3cf5, 12); head.writeUInt16BE(1000, 18); head.writeInt16BE(500, 40); head.writeInt16BE(700, 42); head.writeUInt16BE(8, 46); head.writeInt16BE(2, 48);
  hhea.writeUInt32BE(0x10000, 0); hhea.writeInt16BE(800, 4); hhea.writeInt16BE(-200, 6); hhea.writeUInt16BE(600, 10); hhea.writeInt16BE(100, 14); hhea.writeInt16BE(500, 16); hhea.writeInt16BE(1, 18); hhea.writeUInt16BE(2, 34);
  maxp.writeUInt32BE(0x10000, 0); maxp.writeUInt16BE(2, 4); maxp.writeUInt16BE(4, 6); maxp.writeUInt16BE(1, 8); maxp.writeUInt16BE(2, 14);
  const os = table['OS/2'] = Buffer.alloc(78); os.writeInt16BE(600, 2); os.writeUInt16BE(400, 4); os.writeUInt16BE(5, 6); os.writeUInt32BE(1, 42); os.write('TEST', 58); os.writeUInt16BE(0x40, 62); os.writeUInt16BE(65, 64); os.writeUInt16BE(65, 66); os.writeInt16BE(800, 68); os.writeInt16BE(-200, 70); os.writeUInt16BE(800, 74); os.writeUInt16BE(200, 76);
  table.hmtx = Buffer.alloc(8); table.hmtx.writeUInt16BE(600, 0); table.hmtx.writeUInt16BE(600, 4);
  table.loca = Buffer.from([0, 0, 0, 0, 0, 12]);
  const glyf = table.glyf = Buffer.alloc(24); glyf.writeInt16BE(1, 0); glyf.writeInt16BE(500, 6); glyf.writeInt16BE(700, 8); glyf.writeUInt16BE(3, 10); Buffer.from([49, 33, 17, 33]).copy(glyf, 14); glyf.writeInt16BE(500, 18); glyf.writeInt16BE(-500, 20); glyf.writeInt16BE(700, 22);
  const cmap = table.cmap = Buffer.alloc(44); cmap.writeUInt16BE(1, 2); cmap.writeUInt16BE(3, 4); cmap.writeUInt16BE(1, 6); cmap.writeUInt32BE(12, 8); cmap.writeUInt16BE(4, 12); cmap.writeUInt16BE(32, 14); cmap.writeUInt16BE(4, 18); cmap.writeUInt16BE(4, 20); cmap.writeUInt16BE(1, 22); cmap.writeUInt16BE(65, 26); cmap.writeUInt16BE(0xffff, 28); cmap.writeUInt16BE(65, 32); cmap.writeUInt16BE(0xffff, 34); cmap.writeInt16BE(-64, 36); cmap.writeUInt16BE(1, 38);
  const names = [[1, 'ReplaySynthetic'], [2, 'Regular'], [3, 'ReplaySynthetic 1'], [4, 'ReplaySynthetic Regular'], [5, 'Version 1.0'], [6, 'ReplaySynthetic']];
  const strings = names.map(([, value]) => Buffer.from(value, 'utf16le').swap16()), name = table.name = Buffer.alloc(6 + 12 * names.length + strings.reduce((n, value) => n + value.length, 0));
  name.writeUInt16BE(names.length, 2); name.writeUInt16BE(6 + 12 * names.length, 4); let stringOffset = 0;
  names.forEach(([id], index) => { const at = 6 + index * 12; name.writeUInt16BE(3, at); name.writeUInt16BE(1, at + 2); name.writeUInt16BE(0x409, at + 4); name.writeUInt16BE(id, at + 6); name.writeUInt16BE(strings[index].length, at + 8); name.writeUInt16BE(stringOffset, at + 10); strings[index].copy(name, 6 + 12 * names.length + stringOffset); stringOffset += strings[index].length; });
  const post = table.post = Buffer.alloc(32); post.writeUInt32BE(0x30000); post.writeInt16BE(-100, 8); post.writeUInt16BE(50, 10);
  const tags = Object.keys(table).sort(), count = tags.length, power = 2 ** Math.floor(Math.log2(count));
  const checksum = input => { let value = 0; for (let i = 0; i < input.length; i += 4) value = (value + input.readUInt32BE(i)) >>> 0; return value; };
  const chunks = [], directory = Buffer.alloc(12 + count * 16); directory.writeUInt32BE(0x10000); directory.writeUInt16BE(count, 4); directory.writeUInt16BE(power * 16, 6); directory.writeUInt16BE(Math.log2(power), 8); directory.writeUInt16BE(count * 16 - power * 16, 10);
  let offset = directory.length, headOffset;
  tags.forEach((tag, index) => { const bytes = table[tag], padded = Buffer.alloc(Math.ceil(bytes.length / 4) * 4); bytes.copy(padded); const at = 12 + index * 16; directory.write(tag, at); directory.writeUInt32BE(checksum(padded), at + 4); directory.writeUInt32BE(offset, at + 8); directory.writeUInt32BE(bytes.length, at + 12); if (tag === 'head') headOffset = offset; chunks.push(padded); offset += padded.length; });
  const font = Buffer.concat([directory, ...chunks]); font.writeUInt32BE((0xb1b0afba - checksum(font)) >>> 0, headOffset + 8); return font;
}

async function responses(t, site, entries) {
  const directory = path.join(site.projectRoot, 'network-inputs'); await fs.mkdir(directory, { recursive: true });
  const rows = [];
  for (const [index, entry] of entries.entries()) {
    const bytes = Buffer.from(entry.body), file = `body-${index}.bin`;
    await fs.writeFile(path.join(directory, file), bytes);
    rows.push({ url: entry.url, file, sha256: sha(bytes), bytes: bytes.length, status: entry.status ?? 200, contentType: entry.contentType ?? 'text/plain' });
  }
  const manifestPath = path.join(directory, 'responses.json'), bytes = Buffer.from(JSON.stringify({ schemaVersion: 1, entries: rows }));
  await fs.writeFile(manifestPath, bytes);
  return { descriptor: { manifestPath, sha256: sha(bytes) }, rows, directory };
}

async function sink(t) {
  let hits = 0, upgrades = 0;
  const server = http.createServer((req, res) => { if (!externalProbe(req)) hits++; res.writeHead(200, { 'content-type': 'text/plain', 'access-control-allow-origin': '*' }).end('REAL NETWORK MUST NOT BE USED'); });
  server.on('upgrade', (_request, socket) => { upgrades++; socket.destroy(); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return { url: `http://127.0.0.1:${server.address().port}`, get hits() { return hits; }, get upgrades() { return upgrades; } };
}

test('strict optional descriptor leaves historical normalized manifests unchanged', () => {
  const manifest = parseAuditManifest({ projectRoot: '/tmp/site', url: 'http://localhost/' });
  assert.equal(Object.hasOwn(manifest, 'networkReplay'), false);
  for (const descriptor of [{ manifestPath: 'relative.json', sha256: 'a'.repeat(64) }, { manifestPath: '/tmp/file.json', sha256: 'A'.repeat(64) }, { manifestPath: '/tmp/file.json', sha256: 'a'.repeat(64), allowNetwork: true }]) assert.throws(() => parseAuditManifest({ ...manifest, networkReplay: descriptor }), { code: 'INVALID_AUDIT_MANIFEST' });
});

test('loader rejects changed SHA/length/status, duplicate URLs and noncanonical or excluded source paths', async t => {
  const site = await fixture(t), frozen = await responses(t, site, [{ url: 'https://frozen.invalid/item', body: 'original' }]);
  const options = { projectRoot: site.projectRoot, origin: new URL(site.url).origin, descriptor: frozen.descriptor };
  await assert.rejects(loadNetworkReplay({ ...options, descriptor: { ...frozen.descriptor, sha256: '0'.repeat(64) } }), { code: 'NETWORK_REPLAY_HASH_MISMATCH' });
  const writeManifest = async entries => { const bytes = Buffer.from(JSON.stringify({ schemaVersion: 1, entries })); await fs.writeFile(frozen.descriptor.manifestPath, bytes); return { ...options, descriptor: { ...frozen.descriptor, sha256: sha(bytes) } }; };
  await assert.rejects(loadNetworkReplay(await writeManifest([{ ...frozen.rows[0], bytes: 7 }])), { code: 'NETWORK_REPLAY_LENGTH_MISMATCH' });
  await assert.rejects(loadNetworkReplay(await writeManifest([{ ...frozen.rows[0], sha256: '0'.repeat(64) }])), { code: 'NETWORK_REPLAY_HASH_MISMATCH' });
  for (const entry of [{ ...frozen.rows[0], status: 199 }, { ...frozen.rows[0], status: 600 }, { ...frozen.rows[0], status: 200.5 }, { ...frozen.rows[0], file: '../body.bin' }, { ...frozen.rows[0], url: 'https://frozen.invalid/item#part' }, { ...frozen.rows[0], headers: { cookie: 'not allowed' } }]) await assert.rejects(loadNetworkReplay(await writeManifest([entry])), { code: 'INVALID_NETWORK_REPLAY' });
  await assert.rejects(loadNetworkReplay(await writeManifest([{ ...frozen.rows[0], status: 204 }])), { code: 'INVALID_NETWORK_REPLAY_STATUS' });
  await assert.rejects(loadNetworkReplay(await writeManifest([frozen.rows[0], frozen.rows[0]])), { code: 'NETWORK_REPLAY_DUPLICATE_URL' });
  await assert.rejects(loadNetworkReplay(await writeManifest(Array.from({ length: NETWORK_REPLAY_LIMITS.maxEntries + 1 }, () => frozen.rows[0]))), { code: 'INVALID_NETWORK_REPLAY' });
  const oversized = Buffer.alloc(NETWORK_REPLAY_LIMITS.maxManifestBytes + 1, 32); await fs.writeFile(frozen.descriptor.manifestPath, oversized);
  await assert.rejects(loadNetworkReplay({ ...options, descriptor: { ...frozen.descriptor, sha256: sha(oversized) } }), { code: 'NETWORK_REPLAY_LIMIT_EXCEEDED' });
  const valid = await writeManifest(frozen.rows);
  const outside = path.join(path.dirname(site.projectRoot), 'outside-replay.json'); await fs.writeFile(outside, JSON.stringify({ schemaVersion: 1, entries: [] })); t.after(() => fs.rm(outside));
  await assert.rejects(loadNetworkReplay({ ...valid, descriptor: { manifestPath: outside, sha256: sha(await fs.readFile(outside)) } }), { code: 'NETWORK_REPLAY_OUTSIDE_PROJECT' });
  for (const relative of ['evidence/replay.json', 'node_modules/replay.json', 'dist/replay.json', 'sub/.DS_Store', 'sub/replay.log']) {
    const file = path.join(site.projectRoot, relative); await fs.mkdir(path.dirname(file), { recursive: true }); await fs.writeFile(file, '{}');
    await assert.rejects(loadNetworkReplay({ ...valid, descriptor: { manifestPath: file, sha256: sha('{}') } }), { code: 'NETWORK_REPLAY_EXCLUDED_SOURCE' });
  }
  const link = path.join(frozen.directory, 'linked.json'); await fs.symlink(frozen.descriptor.manifestPath, link);
  await assert.rejects(loadNetworkReplay({ ...valid, descriptor: { manifestPath: link, sha256: valid.descriptor.sha256 } }), { code: 'UNSAFE_NETWORK_REPLAY_PATH' });
  const bodyLink = path.join(frozen.directory, 'linked-body.bin'); await fs.symlink(path.join(frozen.directory, frozen.rows[0].file), bodyLink);
  await assert.rejects(loadNetworkReplay(await writeManifest([{ ...frozen.rows[0], file: 'linked-body.bin' }])), { code: 'UNSAFE_NETWORK_REPLAY_PATH' });
});

test('real Chromium loads an exact synthetic font, JSON, binary body and HEAD without external traffic or cookie/auth responses', async t => {
  const remote = await sink(t), site = await fixture(t, '<!doctype html><html lang="en"><title>Replay</title><body>Replay fixture</body></html>');
  const frozen = await responses(t, site, [
    { url: `${remote.url}/font.ttf?version=1`, body: syntheticFont(), contentType: 'font/ttf' },
    { url: `${remote.url}/font.css`, body: `@font-face{font-family:ReplaySynthetic;src:url('${remote.url}/font.ttf?version=1') format('truetype')}`, contentType: 'text/css' },
    { url: `${remote.url}/data.json?exact=1`, body: '{"from":"verified-local-body"}', contentType: 'application/json; charset=utf-8', status: 201 },
    { url: `${remote.url}/binary`, body: Buffer.from([0, 1, 2, 127, 255]), contentType: 'application/octet-stream', status: 206 },
    { url: `${remote.url}/navigation`, body: '<title>A fixture must not bypass navigation</title>', contentType: 'text/html' },
  ]);
  const browser = await chromium.launch({ headless: true }); t.after(() => browser.close());
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const replay = await configureNetworkReplay(context, { projectRoot: site.projectRoot, origin: new URL(site.url).origin, descriptor: frozen.descriptor });
  await context.addCookies([{ name: 'private-token', value: 'do-not-retain-or-transmit', url: remote.url }]);
  const page = await context.newPage(); await page.goto(site.url);
  const observedResponseHeaders = [];
  page.on('response', response => { if (response.url().startsWith(remote.url)) observedResponseHeaders.push(response.headers()); });
  const result = await page.evaluate(async origin => {
    const css = document.createElement('link'); css.rel = 'stylesheet'; css.href = `${origin}/font.css`; document.head.append(css); await new Promise((resolve, reject) => { css.onload = resolve; css.onerror = reject; });
    const faces = await document.fonts.load('20px ReplaySynthetic', 'AAAA');
    const text = document.createElement('span'); text.textContent = 'AAAA'; text.style.cssText = 'font-family:ReplaySynthetic;font-size:20px'; document.body.append(text);
    const json = await fetch(`${origin}/data.json?exact=1`), head = await fetch(`${origin}/data.json?exact=1`, { method: 'HEAD' }), binary = await fetch(`${origin}/binary`);
    const blocked = [];
    for (const [url, options] of [[`${origin}/missing`, {}], [`${origin}/data.json?exact=2`, {}], [`${origin}/data.json?exact=1`, { method: 'POST', body: 'not replayed' }]]) {
      try { await fetch(url, options); blocked.push(false); } catch { blocked.push(true); }
    }
    const socketClosed = await new Promise(resolve => { const socket = new WebSocket(origin.replace('http:', 'ws:') + '/socket'); socket.onclose = () => resolve(true); socket.onerror = () => resolve(true); });
    const blob = await fetch(URL.createObjectURL(new Blob(['native-blob']))).then(response => response.text());
    const data = await fetch('data:text/plain,native-data').then(response => response.text());
    return { faces: faces.map(face => face.status), width: text.getBoundingClientRect().width, json: await json.json(), status: json.status, mime: json.headers.get('content-type'), headStatus: head.status, headBody: await head.text(), headLength: head.headers.get('content-length'), binary: [...new Uint8Array(await binary.arrayBuffer())], blocked, socketClosed, blob, data };
  }, remote.url);
  assert.deepEqual(result.faces, ['loaded']); assert.equal(result.width, 48);
  assert.deepEqual(result.json, { from: 'verified-local-body' }); assert.equal(result.status, 201); assert.equal(result.mime, 'application/json; charset=utf-8');
  assert.equal(result.headStatus, 201); assert.equal(result.headBody, ''); assert.equal(Number(result.headLength), frozen.rows[2].bytes);
  assert.deepEqual(result.binary, [0, 1, 2, 127, 255]); assert.deepEqual(result.blocked, [true, true, true]); assert.equal(result.socketClosed, true); assert.equal(result.blob, 'native-blob'); assert.equal(result.data, 'native-data');
  const rawHeaders = await context.request.get(site.url); assert.equal(rawHeaders.ok(), true); // same-origin stays normal
  const replayedResponse = await page.request.get(site.url); assert.equal(replayedResponse.ok(), true);
  await assert.rejects(page.goto(`${remote.url}/navigation`));
  assert.ok(replay.snapshot().observations.some(row => row.reason === 'main_navigation_outside_origin'));
  assert.equal(remote.hits, 0); assert.equal(remote.upgrades, 0);
  assert.ok(observedResponseHeaders.length >= 5);
  assert.ok(observedResponseHeaders.every(headers => headers['access-control-allow-origin'] === '*' && !Object.hasOwn(headers, 'access-control-allow-credentials') && !Object.hasOwn(headers, 'set-cookie') && !Object.hasOwn(headers, 'www-authenticate')));
  const retained = JSON.stringify(replay.report()); assert.equal(retained.includes('do-not-retain-or-transmit'), false);
  assert.equal(retained.includes('set-cookie'), false); assert.equal(retained.includes('authorization'), false);
  replay.setPhase('cleanup'); await context.close(); await replay.drain(); replay.setPhase('closed');
  assert.equal(replay.snapshot().counts.pending, 0);
  // A second explicit profile treats the local sink as its own origin. Its WS
  // handshake must reach that origin, rather than being blanket-blocked.
  const sameOriginContext = await browser.newContext({ serviceWorkers: 'block' });
  const sameOriginReplay = await configureNetworkReplay(sameOriginContext, { projectRoot: site.projectRoot, origin: remote.url, descriptor: frozen.descriptor });
  const sameOriginPage = await sameOriginContext.newPage(); await sameOriginPage.goto(remote.url);
  await sameOriginPage.evaluate(origin => new Promise(resolve => { const socket = new WebSocket(origin.replace('http:', 'ws:') + '/same-origin'); socket.onclose = socket.onerror = () => resolve(); }), remote.url);
  assert.equal(remote.upgrades, 1);
  assert.ok(sameOriginReplay.snapshot().observations.some(row => row.reason === 'same_origin_websocket' && row.outcome === 'continued'));
  await sameOriginContext.close(); await sameOriginReplay.drain();
});

test('batch retains initialization events and per-action deltas; default mode still permits ordinary off-origin resources', async t => {
  const remote = await sink(t), site = await fixture(t, `<!doctype html><html lang="en"><title>Startup replay</title><body><output id="value">pending</output><script>fetch('${remote.url}/data').then(r=>r.text()).then(t=>document.querySelector('#value').textContent=t)</script></body></html>`);
  const frozen = await responses(t, site, [{ url: `${remote.url}/data`, body: 'from-memory' }]);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, networkReplay: frozen.descriptor, actions: [{ action: 'wait_for', selector: '#value', condition: 'text', expected: 'from-memory' }, { action: 'snapshot' }] });
  assert.equal(report.status, 'collected', JSON.stringify(report.errors)); assert.ok(report.records[1].result.visibleText.includes('from-memory'));
  assert.ok(report.networkReplay.observationLog.observations.some(row => row.phase === 'initialization' && row.outcome === 'fulfilled'));
  assert.ok(report.records[0].networkReplay.observations.some(row => row.outcome === 'fulfilled'));
  assert.equal(report.records[1].networkReplay.deltaObserved, 0);
  assert.equal(report.networkReplay.inputs.entries[0].sha256, frozen.rows[0].sha256);
  assert.equal((await checkAudit(report.reportPath)).status, 'current'); assert.equal(remote.hits, 0);
  const legacy = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'wait_for', selector: '#value', condition: 'text', expected: 'REAL NETWORK MUST NOT BE USED' }, { action: 'snapshot' }] });
  assert.equal(Object.hasOwn(legacy.manifest, 'networkReplay'), false); assert.equal(Object.hasOwn(legacy, 'networkReplay'), false);
  assert.ok(legacy.records[1].result.visibleText.includes('REAL NETWORK MUST NOT BE USED')); assert.ok(remote.hits > 0);
});

test('live uses frozen memory after local edits and source write/restore still expires the sealed report', async t => {
  const remote = await sink(t), site = await fixture(t, `<!doctype html><html lang="en"><title>Live replay</title><body><button id="load" onclick="fetch('${remote.url}/value').then(r=>r.text()).then(t=>document.querySelector('#value').textContent=t)">Load</button><output id="value">pending</output></body></html>`);
  const frozen = await responses(t, site, [{ url: `${remote.url}/value`, body: 'verified-original-memory' }]);
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url, networkReplay: frozen.descriptor }); t.after(() => session.finish());
  const file = path.join(frozen.directory, frozen.rows[0].file), original = await fs.readFile(file);
  await fs.writeFile(file, 'changed bytes');
  await session.perform({ action: 'click', selector: '#load' });
  const ready = await session.perform({ action: 'wait_for', selector: '#value', condition: 'text', expected: 'verified-original-memory' });
  assert.equal(ready.success, true, JSON.stringify(ready.error));
  const snapshot = await session.perform({ action: 'snapshot' });
  assert.ok(snapshot.result.visibleText.includes('verified-original-memory'));
  await fs.writeFile(file, original);
  const report = await session.finish(); assert.equal(report.codeFingerprint.digest, report.codeFingerprintAfterRun.digest); assert.equal(report.sourceStability.status, 'changed');
  assert.equal((await checkAudit(report.reportPath)).status, 'expired'); assert.equal(remote.hits, 0); assert.equal(report.networkReplay.observationLog.counts.fulfilledLocal, 1);
});

test('same-origin redirect chains and subresources cannot send an unfrozen request', async t => {
  const site = await fixture(t), remote = await sink(t), frozen = await responses(t, site, []);
  const server = http.createServer((req, res) => {
    if (req.url === '/first') { res.writeHead(302, { location: '/second' }).end(); return; }
    if (req.url === '/second' || req.url === '/image') { res.writeHead(307, { location: `${remote.url}/unfrozen` }).end(); return; }
    res.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html><title>Redirect guard</title><img src="/image"><p>Local page</p>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true }); t.after(() => browser.close());
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const replay = await configureNetworkReplay(context, { projectRoot: site.projectRoot, origin, descriptor: frozen.descriptor });
  const page = await context.newPage(); await page.goto(origin); await page.waitForTimeout(100);
  let navigationRejected = false;
  try { await page.goto(`${origin}/first`, { timeout: 5000 }); } catch { navigationRejected = true; }
  await context.close(); await replay.drain();
  assert.equal(remote.hits, 0, 'Neither a redirected image nor a main-document redirect may reach the off-origin server.');
  assert.equal(navigationRejected, true);
  assert.ok(replay.snapshot().observations.some(row => row.reason === 'redirect_unavailable_in_replay'));
});

test('bounded observations keep complete counters and initialization/action/cleanup requests through drain', async t => {
  const site = await fixture(t), frozen = await responses(t, site, [{ url: 'https://frozen.invalid/exact', body: 'cached' }]);
  const replay = await loadNetworkReplay({ projectRoot: site.projectRoot, origin: new URL(site.url).origin, descriptor: frozen.descriptor });
  function fake(url, fulfill = async () => {}) { return { request: () => ({ url: () => url, method: () => 'GET', resourceType: () => 'fetch', isNavigationRequest: () => false }), fulfill, continue: async () => {}, abort: async () => {} }; }
  await replay.route(fake('https://frozen.invalid/exact'));
  replay.setPhase('action'); await replay.route(fake('https://unknown.invalid/action'));
  replay.setPhase('cleanup'); let release;
  const pending = replay.route(fake('https://frozen.invalid/exact', () => new Promise(resolve => { release = resolve; })));
  assert.equal(replay.snapshot().counts.pending, 1); release(); await pending; await replay.drain();
  assert.deepEqual(replay.snapshot().observations.map(row => row.phase), ['initialization', 'action', 'cleanup']);
  for (let index = 3; index < NETWORK_REPLAY_LIMITS.maxObservations + 7; index++) await replay.route(fake(`https://unknown.invalid/${index}`));
  const full = replay.snapshot(), delta = replay.snapshot({ since: NETWORK_REPLAY_LIMITS.maxObservations });
  assert.equal(full.totalObserved, NETWORK_REPLAY_LIMITS.maxObservations + 7); assert.equal(full.observations.length, NETWORK_REPLAY_LIMITS.maxObservations); assert.equal(full.omittedCount, 7);
  assert.equal(delta.deltaObserved, 7); assert.equal(delta.observations.length, 0); assert.equal(delta.deltaOmittedCount, 7); assert.equal(full.counts.pending, 0);
});
