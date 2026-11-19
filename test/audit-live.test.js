import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { Readable, Writable } from 'node:stream';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fixture } from './helpers.js';
import { openAuditSession } from '../src/audit/live.js';
import { runAuditSessionCli } from '../src/audit/live-cli.js';
import { checkAudit, submitAudit, reviewAudit } from '../src/audit/review.js';
import { readAuditDocument } from '../src/audit/store.js';

const html = `<!doctype html><html lang="en"><head><title>Persistent audit fixture</title><style>
body { color:black; background:white; font:16px Arial; }button { min-width:36px; min-height:24px; }
#swatch { position:fixed; right:0; top:0; width:24px; height:24px; background:black; }
</style></head><body><main><h1>Persistent audit</h1>
<button id="counter" onclick="this.textContent=String(Number(this.textContent)+1)">0</button>
<button id="unnamed"></button><p id="paragraph">One paragraph in a persistent document.</p>
<label for="password">Password</label><input id="password" type="password" value="initial-password-token">
<input id="hidden" type="hidden" value="initial-hidden-token"><div id="swatch"></div>
</main></body></html>`;
const node = (record, selector) => record.result.nodes.find(value => value.selector === selector);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('one live context supports incremental measurements without replay and seals into the existing review workflow', async t => {
  const site = await fixture(t, html); let pageRequests = 0;
  site.beforeResponse(() => { pageRequests++; });
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => session.finish());
  const initial = await session.perform({ action: 'snapshot' });
  const originalJson = await fs.readFile(initial.json.path);
  assert.equal((await fs.readdir(session.directory)).some(name => /^audit-.*\.json$/.test(name)), false, 'an unfinished session is not a sealed collection');
  await session.perform({ action: 'click', selector: '#counter' });
  const afterClick = await session.perform({ action: 'snapshot' });
  assert.equal(node(afterClick, '#counter').text, '1');
  assert.equal(node(initial, '#counter').nodeId, node(afterClick, '#counter').nodeId);
  assert.equal(initial.after.documentId, afterClick.after.documentId);
  const unnamed = await session.perform({ action: 'inspect', selector: '#unnamed' });
  assert.equal(unnamed.success, true, JSON.stringify(unnamed.error));
  assert.equal(unnamed.before.stateId, afterClick.after.stateId);
  assert.equal(unnamed.after.stateId, unnamed.before.stateId);
  assert.equal(unnamed.result.element.nodeId, node(afterClick, '#unnamed').nodeId);
  assert.equal(unnamed.result.ariaSnapshot.trim(), '- button');
  const screenshot = await session.perform({ action: 'screenshot' });
  const originalPng = await fs.readFile(screenshot.png.path);
  const measurement = await session.perform({ action: 'contrast', foreground: { x: screenshot.png.width - 10, y: 10 }, background: { x: screenshot.png.width - 40, y: 10 } });
  assert.equal(measurement.result.contrast.ratio, 21);
  assert.equal(measurement.after.documentId, initial.after.documentId);
  assert.equal(measurement.result.nodes.find(value => value.selector === '#counter').nodeId, node(initial, '#counter').nodeId);
  assert.equal(pageRequests, 1, 'measurement must not reload or replay the click');
  assert.deepEqual(await fs.readFile(initial.json.path), originalJson);
  assert.deepEqual(await fs.readFile(screenshot.png.path), originalPng);
  assert.equal(sha(originalPng), screenshot.png.sha256);
  assert.throws(() => { initial.result.nodes[0].text = 'mutated'; }, TypeError);
  const firstFinish = session.finish(), repeatedFinish = session.finish();
  assert.equal(firstFinish, repeatedFinish);
  const report = await firstFinish;
  assert.equal(await session.finished, report);
  assert.equal(session.status, 'sealed');
  assert.equal(report.status, 'collected', JSON.stringify(report.errors));
  assert.equal(report.liveSession.contextCount, 1);
  assert.equal(report.liveSession.replays, 0);
  assert.equal(report.liveSession.complete, false);
  assert.equal(report.records.length, 6);
  assert.equal((await checkAudit(report.reportPath)).status, 'current');
  assert.deepEqual(await readAuditDocument(report.reportPath), report);
  await assert.rejects(session.perform({ action: 'snapshot' }), { code: 'AUDIT_SESSION_CLOSED' });
  const target = node(afterClick, '#unnamed');
  const submitted = await submitAudit(report.reportPath, { auditor: { name: 'Live contract auditor' }, findings: [{
    id: 'L1', title: 'Unnamed button observation', criterionId: '4.1.2', target: { evidenceId: afterClick.evidenceId, nodeId: target.nodeId }, evidenceIds: [afterClick.evidenceId, unnamed.evidenceId],
    observation: 'The recorded enabled button has no name.', reason: 'Name observation for this button.', applicability: 'Enabled button.', exceptions: 'No local exception asserted.', scope: 'Only this recorded control.',
  }] });
  const reviewed = await reviewAudit(submitted.reportPath, { reviewer: { name: 'Independent live contract reviewer', independentOfAuditor: true }, decisions: [{
    findingId: 'L1', verdict: 'supported', checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
    reason: 'The retained target-scoped ARIA snapshot shows a button without a name.',
    directEvidence: { evidenceId: unnamed.evidenceId, nodeIds: [target.nodeId],
      criterionClause: '4.1.2 requires a programmatically determinable component name.', explanation: 'The inspected button has an empty name in the same state as the finding target.' },
  }] });
  assert.equal(reviewed.confirmedFindings.length, 1);
  assert.equal((await checkAudit(reviewed.reportPath)).status, 'current');
});

test('concurrent requests execute serially and finish drains already accepted actions', async t => {
  const site = await fixture(t, html), session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => session.finish());
  const first = session.perform({ action: 'click', selector: '#counter' });
  const second = session.perform({ action: 'click', selector: '#counter' });
  const third = session.perform({ action: 'snapshot' });
  const finishing = session.finish();
  const records = await Promise.all([first, second, third]);
  const report = await finishing;
  assert.deepEqual(records.map(record => record.evidenceId), ['ev-0001', 'ev-0002', 'ev-0003']);
  assert.equal(node(records[2], '#counter').text, '2');
  assert.equal(report.records.length, 3);
  assert.equal(report.summary.executedActions, 3);
  assert.equal(report.status, 'collected');
});

test('source edits that return to the original bytes still expire a live collection', async t => {
  const site = await fixture(t, html), session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => session.finish());
  await session.perform({ action: 'snapshot' });
  await site.write(`${html}<!-- transient source change -->`); await site.write(html);
  const report = await session.finish();
  assert.equal(report.codeFingerprint.digest, report.codeFingerprintAfterRun.digest);
  assert.equal(report.sourceStability.status, 'changed');
  assert.ok(report.sourceStability.eventCount > 0);
  assert.equal((await checkAudit(report.reportPath)).status, 'expired');
});

test('fill arguments, final manifest/plan, failures and sensitive browser values stay omitted', async t => {
  const site = await fixture(t, html), session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => session.finish());
  const secret = 'new-password-secret-49736', failedSecret = 'failed-fill-secret-27954';
  const filled = await session.perform({ action: 'fill', selector: '#password', value: secret });
  const failed = await session.perform({ action: 'fill', selector: '#counter', value: failedSecret });
  assert.equal(filled.arguments.value, '[omitted]');
  assert.equal(failed.success, false);
  const inspected = await session.perform({ action: 'inspect', selector: '#password' });
  assert.equal(inspected.result.element.value, '[omitted]');
  await session.perform({ action: 'inspect', selector: '#hidden' });
  await session.perform({ action: 'snapshot' });
  await session.perform({ action: 'axe' });
  const report = await session.finish(), retained = JSON.stringify(report);
  for (const value of [secret, failedSecret, 'initial-password-token', 'initial-hidden-token']) assert.equal(retained.includes(value), false, value);
  assert.deepEqual(report.manifest.actions.filter(action => action.action === 'fill').map(action => action.value), ['[omitted]', '[omitted]']);
  assert.deepEqual(report.plan.filter(action => action.action === 'fill').map(action => action.value), ['[omitted]', '[omitted]']);
  for (const record of report.records) {
    const bytes = await fs.readFile(record.json.path, 'utf8');
    assert.equal(bytes.includes(secret), false); assert.equal(bytes.includes(failedSecret), false);
  }
});

test('action exhaustion preserves accepted queued requests as not-run and seals incomplete', async t => {
  const site = await fixture(t, html), session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url, maxActions: 2 });
  t.after(() => session.finish());
  const requests = [session.perform({ action: 'snapshot' }), session.perform({ action: 'wait', ms: 25 }), session.perform({ action: 'screenshot' })];
  const records = await Promise.all(requests), report = await session.finished;
  assert.equal(report.status, 'partial');
  assert.equal(report.liveSession.termination.reason, 'action_budget_exhausted');
  assert.equal(report.summary.plannedActions, 3);
  assert.equal(report.summary.executedActions, 2);
  assert.equal(report.summary.notRunActions, 1);
  assert.equal(records[2].success, false);
  assert.equal(records[2].result.status, 'not_run');
  assert.equal(records[2].before, null);
});

test('wall budget includes host idle time and automatically releases the browser', async t => {
  const site = await fixture(t, html), opened = Date.now();
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url, wallSeconds: 1 });
  t.after(() => session.finish());
  await session.perform({ action: 'snapshot' });
  const report = await session.finished;
  assert.equal(report.status, 'partial');
  assert.equal(report.liveSession.termination.reason, 'wall_budget_exhausted');
  assert.equal(session.status, 'sealed');
  assert.ok(Date.now() - opened < 4000);
  assert.equal(report.summary.executedActions, 1);
  assert.equal((await checkAudit(report.reportPath)).status, 'current');
});

test('a running wait is interrupted by the global wall budget with later requests left not-run', async t => {
  const site = await fixture(t, html), session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url, wallSeconds: 1 });
  t.after(() => session.finish());
  const running = session.perform({ action: 'wait', ms: 5000 });
  const queued = session.perform({ action: 'snapshot' });
  const [first, second] = await Promise.all([running, queued]), report = await session.finished;
  assert.equal(first.success, false);
  assert.equal(second.result.status, 'not_run');
  assert.equal(report.records.length, 2);
  assert.equal(report.summary.executedActions, 1);
  assert.equal(report.liveSession.termination.reason, 'wall_budget_exhausted');
});

test('JSONL supports summary records, EOF/finish sealing and invalid-input incomplete outcomes', async t => {
  const site = await fixture(t, html);
  for (const ending of ['finish', 'eof', 'invalid']) {
    let content = '';
    const output = new Writable({ write(chunk, _encoding, callback) { content += chunk; callback(); } });
    const lines = ['{"action":"snapshot"}\n', ...(ending === 'finish' ? ['{"command":"finish"}\n'] : ending === 'invalid' ? ['not JSON and never echoed\n'] : [])];
    const report = await runAuditSessionCli({ manifest: { projectRoot: site.projectRoot, url: site.url }, input: Readable.from(lines), output, signals: false, summary: true });
    const events = content.trim().split('\n').map(line => JSON.parse(line));
    assert.equal(events[0].type, 'session');
    assert.equal(events.find(event => event.type === 'record').record.result, undefined);
    assert.ok(events.find(event => event.type === 'record').record.json.sha256);
    assert.equal(events.at(-1).type, 'finished');
    assert.equal(events.at(-1).sealed, true);
    assert.equal(events.at(-1).report.outputFormat, 'summary');
    assert.equal(report.liveSession.termination.reason, ending === 'finish' ? 'requested' : ending === 'eof' ? 'eof' : 'input_error');
    assert.equal(report.status, ending === 'invalid' ? 'partial' : 'collected');
    assert.equal(content.includes('not JSON and never echoed'), false);
  }
});

test('JSONL SIGINT/SIGTERM seal partial reports, remove listeners and let the child exit', async t => {
  const site = await fixture(t, html);
  await fs.mkdir(path.join(site.projectRoot, 'evidence'), { mode: 0o700 });
  const manifestPath = path.join(site.projectRoot, 'evidence', 'live-manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify({ projectRoot: site.projectRoot, url: site.url }));
  for (const [signal, expectedCode] of [['SIGINT', 130], ['SIGTERM', 143]]) {
    const child = spawn(process.execPath, ['src/audit/live-cli.js', manifestPath, '--summary'], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
    t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
    let buffer = '', stderr = '', signalled = false; const events = [];
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.stdout.on('data', chunk => {
      buffer += chunk;
      for (;;) {
        const newline = buffer.indexOf('\n'); if (newline < 0) break;
        const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
        const event = JSON.parse(line); events.push(event);
        if (event.type === 'session') child.stdin.write('{"action":"snapshot"}\n');
        if (event.type === 'record' && !signalled) { signalled = true; child.kill(signal); }
      }
    });
    let timer;
    const code = await Promise.race([new Promise(resolve => child.on('close', resolve)), new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`Live CLI did not cleanly exit: ${stderr}`)), 10000); })]).finally(() => clearTimeout(timer));
    assert.equal(code, expectedCode, stderr);
    const final = events.find(event => event.type === 'finished');
    assert.ok(final, JSON.stringify({ events, buffer, stderr, code }));
    assert.equal(final.status, 'partial');
    assert.equal(final.report.liveSession.termination.signal, signal);
    assert.equal((await checkAudit(final.report.reportPath)).status, 'current');
  }
});
