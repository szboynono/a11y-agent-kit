import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import os from 'node:os';
import { fixture, html } from './helpers.js';
import { monitorSource } from '../src/evidence.js';
import { openAuditSession } from '../src/audit/live.js';
import { checkAudit } from '../src/audit/review.js';

// Filesystem notifications can arrive late under load. This injects a delivery
// latency, and optionally a pre-run notification that the platform delivers only
// after the watch starts, without depending on load. Latency only ever grows, so
// notifications keep their order, as FSEvents delivers them.
function delayedWatch(t, { latencyMs, history }) {
  const realWatch = fs.watch;
  let historyDelivered;
  const delivered = new Promise(resolve => { historyDelivered = resolve; });
  const control = { latencyMs, historyDelivered: delivered };
  fs.watch = (root, options, listener) => {
    let closed = false;
    const deliver = (...args) => setTimeout(() => { if (!closed) listener(...args); }, control.latencyMs);
    const watcher = realWatch(root, options, deliver);
    if (history) setTimeout(() => { if (!closed) listener('rename', history); historyDelivered(); }, control.latencyMs);
    const close = watcher.close.bind(watcher);
    watcher.close = () => { closed = true; close(); };
    return watcher;
  };
  syncBuiltinESMExports();
  t.after(() => { fs.watch = realWatch; syncBuiltinESMExports(); });
  return control;
}

test('late notifications of a transient source edit still expire the sealed session', async t => {
  const site = await fixture(t, html());
  const watch = delayedWatch(t, { latencyMs: 0 });
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url }); t.after(() => session.finish());
  assert.equal((await session.perform({ action: 'snapshot' })).success, true);
  // The edit's notifications arrive well after sealing would otherwise finish.
  watch.latencyMs = 5000;
  const source = path.join(site.projectRoot, 'index.html'), original = fs.readFileSync(source);
  await site.write('<!doctype html><title>transient</title>');
  await site.write(original);
  const report = await session.finish();
  assert.equal(report.codeFingerprint.digest, report.codeFingerprintAfterRun.digest);
  assert.equal(report.sourceStability.status, 'changed', JSON.stringify(report.sourceStability));
  assert.deepEqual(report.sourceStability.changedPaths, ['index.html']);
  assert.equal((await checkAudit(report.reportPath)).status, 'expired');
});

test('a pre-run notification delivered after the watch starts does not expire stable source', async t => {
  const site = await fixture(t, html());
  const watch = delayedWatch(t, { latencyMs: 300, history: 'setup-before-run.txt' });
  const session = await openAuditSession({ projectRoot: site.projectRoot, url: site.url }); t.after(() => session.finish());
  await watch.historyDelivered;
  assert.equal((await session.perform({ action: 'snapshot' })).success, true);
  const report = await session.finish();
  assert.equal(report.status, 'collected', JSON.stringify(report.errors));
  assert.deepEqual(report.sourceStability.changedPaths, []);
  assert.equal(report.sourceStability.status, 'stable_observed');
  assert.equal((await checkAudit(report.reportPath)).status, 'current');
});

test('a source monitor that cannot confirm its marker reports unknown stability', async t => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'a11y-monitor-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'evidence'), 'not a directory');
  const monitor = monitorSource(root);
  await monitor.arm(); await monitor.settle(); monitor.close();
  const snapshot = monitor.snapshot();
  assert.equal(snapshot.status, 'unknown');
  assert.deepEqual(snapshot.errors.map(error => error.code), ['SOURCE_MONITOR_UNCONFIRMED', 'SOURCE_MONITOR_UNCONFIRMED']);
});
