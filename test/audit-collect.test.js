import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { AuditBrowser } from '../src/audit/browser.js';
import { parseAuditManifest } from '../src/audit/schema.js';
import { externalProbe, fixture } from './helpers.js';
import { collectAudit, defaultAuditActions } from '../src/audit/collect.js';
import { checkAuditCollection, readAuditDocument, createAuditDirectory, writeAuditArtifact, saveAuditDocument } from '../src/audit/store.js';
import { decodePng, pixelAt, contrastRatio } from '../src/audit/pixels.js';

const html = `<!doctype html><html lang="en"><head><title>Public audit behavior fixture</title><style>
body { background:white; color:black; font:16px Arial; margin:24px; }
body[data-theme="dark"] { background:#111; color:white; }
#paragraph { font-size:20px; margin-block-end:7px; }
#solid { position:fixed; right:0; top:0; width:24px; height:24px; background:black; }
</style></head><body><main><h1>Audit behavior fixture</h1>
<button id="theme" aria-pressed="false" onclick="document.body.dataset.theme=this.getAttribute('aria-pressed')==='false'?'dark':'light';this.setAttribute('aria-pressed',String(this.getAttribute('aria-pressed')==='false'))">Theme</button>
<label for="name">Name</label><input id="name" value="initial">
<label><input id="agree" type="checkbox" checked>Agree</label>
<details id="more"><summary>More information</summary><p>Expanded detail</p></details>
<p id="paragraph">A real paragraph with a measurable font and paragraph end margin.</p>
<img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12'%3E%3Crect width='12' height='12'/%3E%3C/svg%3E">
<div id="solid"></div><a href="/#next">Next section</a><section id="next"><h2>Next</h2></section>
</main></body></html>`;
const selectorNode = (record, selector) => record.result.nodes.find(node => node.selector === selector);

test('ordinary navigation cannot follow an HTTP redirect outside its origin', async t => {
  const site = await fixture(t);
  const serve = async handler => {
    const server = http.createServer(handler);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
    return `http://127.0.0.1:${server.address().port}`;
  };
  let outsideHits = 0;
  const outside = await serve((req, res) => { if (!externalProbe(req)) outsideHits++; res.end('<title>Outside</title><body>Outside</body>'); });
  const origin = await serve((req, res) => {
    if (req.url === '/jump') res.writeHead(302, { location: outside }).end();
    else if (req.url === '/chain') res.writeHead(302, { location: '/jump' }).end();
    else if (req.url === '/local') res.writeHead(302, { location: '/ok' }).end();
    else res.setHeader('content-type', 'text/html').end('<title>Inside</title><body><a id="jump" href="/jump">Jump</a></body>');
  });
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: site.projectRoot, url: origin }));
  t.after(() => browser.close());
  await browser.start();
  assert.equal((await browser.execute({ action: 'navigate', path: '/ok' })).success, true);
  assert.equal((await browser.execute({ action: 'navigate', path: '/local' })).success, true);
  for (const action of [{ action: 'navigate', path: '/jump' }, { action: 'navigate', path: '/chain' }, { action: 'click', selector: '#jump' }]) {
    await browser.execute({ action: 'reset' });
    const result = await browser.execute(action);
    assert.equal(result.success, false);
    assert.equal(outsideHits, 0, 'No redirect hop may contact the other origin.');
    assert.ok(browser.blocked.length > 0);
  }
});

test('real collection binds state, controls, spacing, global keyboard, screenshots, pixels and full axe', async t => {
  const site = await fixture(t, html);
  const actions = [
    { action: 'snapshot' }, { action: 'screenshot' }, { action: 'contrast', foreground: { x: 1270, y: 10 }, background: { x: 1240, y: 10 } },
    { action: 'inspect', selector: '#paragraph' }, { action: 'spacing', enabled: true }, { action: 'snapshot' }, { action: 'screenshot' }, { action: 'spacing', enabled: false },
    { action: 'press', key: 'Tab' }, { action: 'screenshot' }, { action: 'click', selector: '#theme' }, { action: 'snapshot' }, { action: 'screenshot' }, { action: 'press', key: 'Tab' },
    { action: 'fill', selector: '#name', value: 'changed' }, { action: 'snapshot' }, { action: 'reset' }, { action: 'press', key: 'Tab' }, { action: 'screenshot' },
    { action: 'navigate', path: '/#next' }, { action: 'snapshot' }, { action: 'reset' }, { action: 'snapshot' }, { action: 'axe' },
  ];
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions });
  assert.equal(report.status, 'collected', JSON.stringify(report.errors));
  assert.equal(report.records.length, actions.length);
  assert.equal(report.coverage.length, 55);
  assert.ok(report.coverage.every(row => ['not_tested', 'needs_review'].includes(row.status)));
  const [snapshot, screenshot, contrast, inspect, spacing] = report.records;
  assert.ok(snapshot.result.visibleText.includes('real paragraph'));
  assert.ok(snapshot.result.ariaSnapshot.includes('button "Theme"'));
  assert.equal(selectorNode(snapshot, '#agree').checked, true);
  assert.equal(selectorNode(snapshot, '#name').value, 'initial');
  assert.equal(inspect.result.element.nodeId, selectorNode(snapshot, '#paragraph').nodeId);
  assert.equal(spacing.result.applied, true, JSON.stringify(spacing.result.failures));
  assert.deepEqual(spacing.result.requested, { lineHeight: 1.5, letterSpacingEm: 0.12, wordSpacingEm: 0.16, paragraphMarginBlockEndEm: 2 });
  assert.equal(Number.parseFloat(spacing.result.representativeParagraph.fontSize), 20);
  assert.equal(Number.parseFloat(spacing.result.representativeParagraph.marginBlockEnd), 40);
  assert.ok(spacing.result.css.includes('margin-block-end:2em!important'));
  assert.match(spacing.result.cssSha256, /^[a-f0-9]{64}$/);
  assert.notEqual(spacing.before.stateId, spacing.after.stateId);
  assert.equal(report.records[5].after.stateId, report.records[6].after.stateId);
  assert.equal(report.records[8].after.active.selector, '#theme');
  assert.equal(report.records[8].result.keyboardOnly, true);
  assert.equal(report.records[13].result.keyboardOnly, false);
  assert.equal(selectorNode(report.records[15], '#name').value, 'changed');
  assert.equal(report.records[17].after.active.selector, '#theme');
  assert.equal(report.records[17].result.keyboardOnly, true);
  assert.notEqual(report.records[16].after.documentId, snapshot.after.documentId);
  assert.notEqual(selectorNode(report.records[22], '#paragraph').nodeId, selectorNode(snapshot, '#paragraph').nodeId);
  assert.equal(snapshot.after.url, report.records[11].after.url);
  assert.notEqual(snapshot.after.stateId, report.records[11].after.stateId);
  assert.equal(selectorNode(report.records[11], '#theme').attributes['aria-pressed'], 'true');
  assert.equal(report.records[11].after.controls.find(node => node.attributes.id === 'theme').ariaPressed, 'true');
  assert.equal(screenshot.result.capture.stable, true);
  assert.equal(screenshot.after.stateId, screenshot.result.capture.beforeStateId);
  assert.equal(screenshot.after.stateId, snapshot.after.stateId);
  const png = await fs.readFile(screenshot.png.path);
  assert.equal(createHash('sha256').update(png).digest('hex'), screenshot.png.sha256);
  const image = decodePng(png);
  assert.deepEqual(pixelAt(image, 1270, 10), [0, 0, 0, 255]);
  assert.equal(contrast.result.contrast.ratio, 21);
  assert.equal(contrast.result.contrast.screenshotSha256, contrast.png.sha256);
  assert.equal(contrast.result.contrast.foreground.relativeLuminance, 0);
  assert.equal(contrast.result.contrast.background.relativeLuminance, 1);
  const axe = report.records.at(-1).result.axe;
  assert.ok(axe.violations.some(rule => rule.id === 'image-alt'), 'full WCAG tags must include rules beyond the old three');
  assert.ok(Array.isArray(axe.incomplete));
  assert.ok(axe.passes.some(rule => Array.isArray(rule.nodes)), 'retain unabridged axe pass nodes');
  assert.deepEqual(await readAuditDocument(report.reportPath), report);
  assert.equal((await checkAuditCollection(report.reportPath)).status, 'current');
  assert.equal((await fs.stat(path.dirname(report.reportPath))).mode & 0o777, 0o700);
  assert.equal((await fs.stat(report.reportPath)).mode & 0o777, 0o600);
  await site.write(`${html}<!-- source revision -->`);
  assert.equal((await checkAuditCollection(report.reportPath)).status, 'expired');
});

test('default plan samples 320px, all four spacing changes, reset and bounded Tab order', async t => {
  const site = await fixture(t, html);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url });
  assert.equal(report.status, 'collected', JSON.stringify(report.errors));
  assert.equal(report.summary.plannedActions, 29);
  assert.equal(report.records.find(record => record.action === 'viewport').after.viewport.width, 320);
  assert.equal(report.records.find(record => record.action === 'spacing').result.applied, true);
  const keys = report.records.filter(record => record.action === 'press');
  assert.equal(keys.length, 8);
  assert.ok(keys.every(record => record.result.keyboardOnly && record.result.inputPath === 'keyboard-only'));
  assert.equal(keys[0].before.active.tag, 'body');
  assert.equal(keys[0].after.active.selector, '#theme');
  assert.deepEqual(defaultAuditActions().map(action => action.action), report.plan.map(action => action.action));
});

test('action budget retains every planned action and never passes unexecuted actions', async t => {
  const site = await fixture(t, html);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, maxActions: 1, actions: [{ action: 'snapshot' }, { action: 'screenshot' }, { action: 'axe' }] });
  assert.equal(report.status, 'partial');
  assert.equal(report.summary.plannedActions, 3);
  assert.equal(report.summary.executedActions, 1);
  assert.equal(report.summary.notRunActions, 2);
  assert.equal(report.records[1].success, false);
  assert.equal(report.records[1].before, null);
  assert.equal(report.records[1].result.status, 'not_run');
  assert.equal((await checkAuditCollection(report.reportPath)).status, 'current');
});

test('wall-clock exhaustion cancels browser and retains unfinished denominator', async t => {
  const site = await fixture(t, html);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, wallSeconds: 1, actions: [{ action: 'wait', ms: 5000 }, { action: 'snapshot' }, { action: 'screenshot' }] });
  assert.equal(report.records.length, 3);
  assert.ok(report.errors.some(error => error.code === 'AUDIT_WALL_BUDGET_EXCEEDED'));
  assert.equal(report.records[2].success, false);
  assert.equal(report.records[2].result.status, 'not_run');
  assert.ok(report.summary.durationMs < 6000, 'browser wait must be cancelled when wall budget ends');
});

test('HTTP and page script failures remain visible rather than becoming successful collections', async t => {
  const site = await fixture(t, html);
  const missing = await collectAudit({ projectRoot: site.projectRoot, url: `${site.url}missing`, actions: [{ action: 'snapshot' }] });
  assert.equal(missing.status, 'error');
  assert.ok(missing.errors.some(error => error.code === 'HTTP_ERROR'));
  assert.equal(missing.records[0].success, false);
  assert.equal(missing.summary.notRunActions, 1);
  const navigation = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'navigate', path: '/missing' }] });
  assert.equal(navigation.status, 'error');
  assert.ok(navigation.errors.some(error => error.code === 'HTTP_ERROR'));
  await site.write(html.replace('</head>', '<script>throw new Error("Fixture application failed")</script></head>'));
  const script = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'snapshot' }] });
  assert.equal(script.status, 'partial');
  assert.equal(script.records[0].success, true);
  assert.ok(script.errors.some(error => error.stage === 'audit-page-script' && error.message.includes('Fixture application failed')));
});

test('standard sensitive fields and fill arguments are not copied into retained reports', async t => {
  const initialSecret = 'synthetic-password-in-html';
  const hiddenSecret = 'synthetic-hidden-token';
  const filledSecret = 'synthetic-password-filled';
  const source = html.replace('</main>', `<input id="credential" type="password" value="${initialSecret}"><input type="hidden" value="${hiddenSecret}"><script>window.exampleToken="inline-script-value";</script></main>`);
  const site = await fixture(t, source);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [
    { action: 'snapshot' }, { action: 'inspect', selector: 'body' }, { action: 'fill', selector: '#credential', value: filledSecret }, { action: 'snapshot' },
    { action: 'axe' },
  ] });
  assert.equal(report.status, 'collected', JSON.stringify(report.errors));
  const retained = JSON.stringify(report);
  for (const secret of [initialSecret, hiddenSecret, filledSecret, 'inline-script-value']) assert.equal(retained.includes(secret), false);
  assert.equal(report.records[2].arguments.value, '[omitted]');
  assert.equal(report.manifest.actions[2].value, '[omitted]');
  assert.equal(report.records[3].after.controls.find(node => node.attributes.id === 'credential').sensitiveValueOmitted, true);
  for (const record of report.records) {
    const bytes = await fs.readFile(record.json.path, 'utf8');
    for (const secret of [initialSecret, hiddenSecret, filledSecret, 'inline-script-value']) assert.equal(bytes.includes(secret), false);
  }
  assert.equal((await checkAuditCollection(report.reportPath)).status, 'current');
});

test('transient source edits are expired even after the original bytes return', async t => {
  const site = await fixture(t, html);
  site.beforeResponse(async () => {
    await site.write(`${html}<!-- transient write -->`);
    await site.write(html);
  });
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'snapshot' }] });
  assert.equal(report.codeFingerprint.digest, report.codeFingerprintAfterRun.digest);
  assert.equal(report.sourceStability.status, 'changed');
  assert.ok(report.sourceStability.eventCount > 0);
  assert.equal((await checkAuditCollection(report.reportPath)).status, 'expired');
});

test('failed fill call logs do not retain the supplied value', async t => {
  const site = await fixture(t, html.replace('</main>', '<input id="locked" type="password" hidden></main>'));
  const supplied = 'synthetic-failed-fill-value';
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [
    { action: 'fill', selector: '#locked', value: supplied }, { action: 'snapshot' },
  ] });
  assert.equal(report.status, 'partial');
  assert.equal(report.records[0].success, false);
  assert.equal(JSON.stringify(report).includes(supplied), false);
  assert.equal((await fs.readFile(report.records[0].json.path, 'utf8')).includes(supplied), false);
  assert.equal(report.records[1].success, true);
});

test('script text is omitted from direct, ancestor and rendered text observations', async t => {
  const secrets = ['synthetic-head-script-content', 'synthetic-rendered-script-content'];
  const source = `<!doctype html><html lang="en"><head><title>Script omission</title><script id="config">window.token="${secrets[0]}";</script></head><body><h1>Public title</h1><p>Public paragraph</p><script type="application/json" style="display:block">{"token":"${secrets[1]}"}</script></body></html>`;
  const site = await fixture(t, source);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [
    { action: 'inspect', selector: '#config' }, { action: 'inspect', selector: 'head' },
    { action: 'inspect', selector: 'body' }, { action: 'snapshot' },
  ] });
  assert.equal(report.status, 'collected');
  for (const secret of secrets) {
    assert.equal(JSON.stringify(report).includes(secret), false);
    for (const record of report.records) assert.equal((await fs.readFile(record.json.path, 'utf8')).includes(secret), false);
  }
  assert.ok(report.records[3].result.visibleText.includes('Public paragraph'));
});

test('reset from a fragment URL creates a fresh document and removes injected spacing', async t => {
  const site = await fixture(t, html);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: `${site.url}#next`, actions: [
    { action: 'spacing', enabled: true }, { action: 'click', selector: '#theme' },
    { action: 'reset' }, { action: 'snapshot' },
  ] });
  assert.equal(report.status, 'collected', JSON.stringify(report.errors));
  const reset = report.records[2], snapshot = report.records[3];
  assert.notEqual(reset.before.documentId, reset.after.documentId);
  assert.equal(reset.after.url, `${site.url}#next`);
  assert.equal(reset.after.spacing.enabled, false);
  assert.equal(reset.after.spacing.css, '');
  assert.equal(reset.after.keyboardOnly, true);
  assert.equal(snapshot.result.nodes.find(node => node.attributes.id === 'paragraph').computed.marginBlockEnd, '7px');
});

test('click and keyboard HTTP navigation failures retain response errors and resulting states', async t => {
  const source = '<!doctype html><html lang="en"><head><title>HTTP navigation</title></head><body><h1>HTTP navigation</h1><a id="bad" href="/missing">Missing destination</a></body></html>';
  const site = await fixture(t, source);
  for (const actions of [[{ action: 'click', selector: '#bad' }], [{ action: 'press', key: 'Tab' }, { action: 'press', key: 'Enter' }]]) {
    const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions });
    const arrival = report.records.at(-1);
    assert.equal(report.status, actions.length === 1 ? 'error' : 'partial');
    assert.equal(arrival.success, false);
    assert.equal(arrival.error.code, 'HTTP_ERROR');
    assert.equal(arrival.after.url, new URL('/missing', site.url).href);
    assert.notEqual(arrival.before.documentId, arrival.after.documentId);
    assert.ok(arrival.result.navigationResponses.some(response => response.status === 404 && response.url === arrival.after.url));
    assert.ok(report.errors.some(error => error.code === 'HTTP_ERROR'));
  }
  const okay = await fixture(t, source.replace('/missing', '/'));
  const success = await collectAudit({ projectRoot: okay.projectRoot, url: okay.url, actions: [{ action: 'press', key: 'Tab' }, { action: 'press', key: 'Enter' }] });
  assert.equal(success.status, 'collected', JSON.stringify(success.errors));
  assert.equal(success.records[1].success, true);
  assert.notEqual(success.records[1].before.documentId, success.records[1].after.documentId);
  assert.ok(success.records[1].result.navigationResponses.some(response => response.status === 200));
});

test('truncation and CSS application failures remain explicit observations', async t => {
  const site = await fixture(t, html.replace('#paragraph {', '#paragraph { line-height:99px!important;'));
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, maxElements: 4, actions: [{ action: 'snapshot' }, { action: 'spacing', enabled: true }] });
  assert.equal(report.records[0].result.nodes.length, 4);
  assert.ok(report.records[0].result.truncation.omittedVisibleElements > 0);
  assert.equal(report.records[1].result.applied, false);
  assert.ok(report.records[1].result.uncheckedElements > 0);
  assert.ok(report.coverage.every(row => row.status === 'not_tested'));
  const full = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'spacing', enabled: true }] });
  assert.equal(full.records[0].result.applied, false);
  assert.ok(full.records[0].result.failures.some(failure => failure.property === 'lineHeight' && failure.actual === '99px'));
});

test('a selected opaque pixel keeps neighborhood edge colors for independent contrast review', async t => {
  const site = await fixture(t, html);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'contrast', foreground: { x: 1256, y: 10 }, background: { x: 1240, y: 10 } }] });
  assert.equal(report.records[0].success, true);
  const measurement = report.records[0].result.contrast;
  assert.equal(measurement.ratio, 21);
  assert.equal(measurement.foreground.neighborhood.uniform, false);
  assert.equal(measurement.foreground.neighborhood.samples.length, 9);
  assert.ok(measurement.foreground.neighborhood.colors.length > 1);
  assert.equal(measurement.qualityWarnings[0].code, 'NONUNIFORM_SAMPLE_NEIGHBORHOOD');
  assert.equal(report.coverage.find(row => row.id === '1.4.3').status, 'not_tested');
});

test('missing selectors and invalid pixel coordinates leave failures with original PNG evidence', async t => {
  const site = await fixture(t, html);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'inspect', selector: '#missing' }, { action: 'contrast', foreground: { x: 2000, y: 10 }, background: { x: 1, y: 1 } }, { action: 'snapshot' }] });
  assert.equal(report.status, 'partial');
  assert.equal(report.records[0].success, false);
  assert.equal(report.records[1].success, false);
  assert.equal(report.records[1].error.code, 'PIXEL_OUT_OF_BOUNDS');
  assert.ok(report.records[1].png);
  assert.equal(report.records[2].success, true);
  await readAuditDocument(report.reportPath);
});

test('SHA, original JSON binding, cross-run attachments, symlinks and overwrite guards', async t => {
  const site = await fixture(t, html);
  const report = await collectAudit({ projectRoot: site.projectRoot, url: site.url, actions: [{ action: 'screenshot' }] });
  const record = report.records[0], originalPng = await fs.readFile(record.png.path);
  await fs.appendFile(record.png.path, 'changed');
  assert.equal((await checkAuditCollection(report.reportPath)).status, 'error');
  await fs.writeFile(record.png.path, originalPng);
  assert.equal((await checkAuditCollection(report.reportPath)).status, 'current');
  const originalJson = await fs.readFile(record.json.path);
  await fs.writeFile(record.json.path, '{}\n');
  await assert.rejects(readAuditDocument(report.reportPath), error => error.code === 'AUDIT_ARTIFACT_INTEGRITY_MISMATCH');
  await fs.writeFile(record.json.path, originalJson);
  await assert.rejects(writeAuditArtifact(path.dirname(report.reportPath), path.basename(record.json.path), originalJson), error => error.code === 'EEXIST');
  const otherId = randomUUID(), otherDirectory = await createAuditDirectory(site.projectRoot, otherId);
  const copiedRecord = { ...record };
  delete copiedRecord.json;
  copiedRecord.json = await writeAuditArtifact(otherDirectory, 'ev-0001.json', `${JSON.stringify(copiedRecord)}\n`);
  const forged = await saveAuditDocument(otherDirectory, 'audit', { ...report, runId: otherId, records: [copiedRecord] });
  await assert.rejects(readAuditDocument(forged.reportPath), error => error.code === 'AUDIT_ARTIFACT_OUTSIDE_RUN');
  const link = path.join(path.dirname(report.reportPath), 'symlink.png');
  await fs.symlink(record.png.path, link);
  const linkRecord = { ...record, png: { ...record.png, path: link } };
  delete linkRecord.json;
  linkRecord.json = await writeAuditArtifact(path.dirname(report.reportPath), 'link-record.json', `${JSON.stringify(linkRecord)}\n`);
  const linkReport = await saveAuditDocument(path.dirname(report.reportPath), 'audit', { ...report, records: [linkRecord] });
  await assert.rejects(readAuditDocument(linkReport.reportPath), error => error.code === 'UNSAFE_AUDIT_PATH');
  assert.equal(contrastRatio([0, 0, 0], [255, 255, 255]), 21);
  assert.throws(() => contrastRatio([0, 0, 0, 0], [255, 255, 255, 255]), error => error.code === 'INVALID_COLOR');
});
