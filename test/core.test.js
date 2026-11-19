import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { analyze, verify, checkEvidence, manifestSchema, SUPPORTED_RULES } from '../src/index.js';
import { digest, fingerprint } from '../src/evidence.js';
import { fixture, html } from './helpers.js';

test('real Chromium: three rule violations, source repair, and frozen verification', async t => {
  const app = await fixture(t, html({ broken: true }));
  const baseline = await analyze(app.manifest);
  assert.equal(baseline.status, 'failed');
  assert.equal(baseline.applicationBinding, 'caller-declared');
  assert.deepEqual(baseline.manifest.rules, SUPPORTED_RULES);
  assert.deepEqual(new Set(baseline.states[0].axe.violations.map(item => item.id)), new Set(SUPPORTED_RULES));
  assert.ok(baseline.states[0].axe.violations.every(item => item.nodes[0].html && item.nodes[0].target.length));
  assert.ok(baseline.states[0].axe.violations[0].nodes[0].any.length || baseline.states[0].axe.violations[0].nodes[0].none.length);
  assert.equal(baseline.versions.axeCore, '4.14.0');
  assert.equal(baseline.versions.axePlaywright, '4.14.0');
  assert.equal(baseline.versions.playwright, '1.64.1');
  assert.ok(baseline.versions.browser);
  const frozenBytes = await fs.readFile(baseline.reportPath, 'utf8');
  assert.equal((await checkEvidence(baseline.reportPath)).status, 'current');
  await analyze(app.manifest);
  assert.equal((await checkEvidence(baseline.reportPath)).status, 'current', 'new evidence must not expire old evidence');
  await app.write(html());
  assert.equal((await checkEvidence(baseline.reportPath)).status, 'expired');
  const repaired = await verify(baseline.reportPath);
  assert.equal(repaired.status, 'passed', JSON.stringify(repaired.errors));
  assert.equal(repaired.validity, 'current');
  assert.equal(repaired.contractDigest, baseline.contractDigest);
  assert.deepEqual(repaired.manifest, baseline.manifest);
  assert.equal(repaired.summary.violations, 0);
  assert.equal(repaired.summary.incomplete, 0);
  assert.equal(repaired.summary.failedAssertions, 0);
  assert.equal(repaired.baseline.reportDigest, baseline.reportDigest);
  assert.notEqual(repaired.codeFingerprint.digest, baseline.codeFingerprint.digest);
  assert.equal((await checkEvidence(repaired.reportPath)).status, 'current');
  assert.equal(await fs.readFile(baseline.reportPath, 'utf8'), frozenBytes, 'verify must not overwrite baseline');
});

test('deleted and hidden functionality cannot pass frozen assertions', async t => {
  for (const variant of ['removed', 'hidden']) {
    await t.test(variant, async t => {
      const app = await fixture(t, html({ broken: true }));
      const baseline = await analyze(app.manifest);
      await app.write(html({ [variant]: true }));
      const result = await verify(baseline.reportPath);
      assert.equal(result.status, 'failed');
      assert.equal(result.summary.violations, 0);
      assert.ok(result.summary.failedAssertions > 0);
      assert.equal(result.states[0].assertions.find(item => item.type === 'visible').status, 'failed');
    });
  }
});

test('each state has a fresh context and replays waitFor, click and press', async t => {
  const app = await fixture(t);
  app.manifest.states = [{
    id: 'activated',
    steps: [
      { action: 'waitFor', selector: '#save' },
      { action: 'click', selector: '#save' },
      { action: 'press', selector: '#save', key: 'Enter' },
    ],
    assertions: [
      { type: 'focused', selector: '#save' },
      { type: 'text', selector: '#status', value: '2' },
    ],
  }, { id: 'fresh', assertions: [{ type: 'text', selector: '#status', value: '0' }] }];
  const result = await analyze(app.manifest);
  assert.equal(result.status, 'passed');
  assert.ok(result.states[0].steps.every(step => step.status === 'passed'));
  assert.equal(result.states[1].assertions[0].actual, '0');
});

test('unreachable states retain their error and not-run assertions', async t => {
  const app = await fixture(t);
  app.manifest.states[0].steps = [{ action: 'click', selector: '#never-exists' }];
  const baseline = await analyze(app.manifest);
  assert.equal(baseline.status, 'error');
  assert.equal(baseline.states[0].reached, false);
  assert.equal(baseline.states[0].steps[0].status, 'error');
  assert.equal(baseline.states[0].assertions[0].status, 'not_run');
  assert.equal(baseline.states[0].axe, null);
  assert.equal((await verify(baseline.reportPath)).status, 'error');
});

test('HTTP errors and invalid standard CSS remain explicit errors', async t => {
  const app = await fixture(t);
  const missing = await analyze({ ...app.manifest, url: `${app.url}missing` });
  assert.equal(missing.status, 'error');
  assert.equal(missing.states[0].httpStatus, 404);
  assert.equal(missing.states[0].errors[0].code, 'HTTP_ERROR');
  const badCss = structuredClone(app.manifest);
  badCss.states[0].assertions[0].selector = 'text=Save';
  const result = await analyze(badCss);
  assert.equal(result.status, 'error');
  assert.equal(result.states[0].errors[0].stage, 'selectors');
});

test('a click navigating to HTTP 404 cannot pass even when its assertions hold', async t => {
  const app = await fixture(t, html() + '<a id="missing" href="/missing">Open missing page</a>');
  app.manifest.states = [{
    id: 'navigated',
    steps: [{ action: 'click', selector: '#missing' }],
    assertions: [{ type: 'count', selector: 'body', value: 1 }],
  }];
  const result = await analyze(app.manifest);
  assert.equal(result.status, 'error');
  assert.equal(result.states[0].httpStatus, 404);
  assert.equal(result.summary.failedAssertions, 0);
  assert.equal(result.summary.violations, 0);
  assert.ok(result.states[0].errors.some(error => error.code === 'HTTP_ERROR'));
});

test('zero axe violations without functional assertions cannot verify passed', async t => {
  const app = await fixture(t);
  app.manifest.states = [{ id: 'no-assertions' }];
  const baseline = await analyze(app.manifest);
  assert.equal(baseline.summary.violations, 0);
  assert.equal(baseline.status, 'needs_review');
  const result = await verify(baseline.reportPath);
  assert.equal(result.status, 'needs_review');
  assert.deepEqual(result.summary.statesWithoutAssertions, ['no-assertions']);
});

test('strict schemas reject unsupported inputs and URL credentials', async t => {
  const app = await fixture(t);
  const mutations = [
    manifest => { manifest.rules = ['color-contrast']; },
    manifest => { manifest.rules = ['label', 'label']; },
    manifest => { manifest.states.push(structuredClone(manifest.states[0])); },
    manifest => { manifest.states[0].assertions[0].selector = '  '; },
    manifest => { manifest.states[0].assertions.push({ type: 'count', selector: 'button', value: -1 }); },
    manifest => { manifest.url = 'https://user:password@example.com/'; },
    manifest => { manifest.url = 'not-a-url'; },
    manifest => { manifest.url = 'file:///tmp/example.html'; },
    manifest => { manifest.projectRoot = './source'; },
    manifest => { manifest.ignoreRules = ['label']; },
    manifest => { manifest.states[0].steps = [{ action: 'evaluate', selector: '#save' }]; },
    manifest => { manifest.states[0].steps = [{ action: 'click', selector: '#save', force: true }]; },
  ];
  for (const mutate of mutations) {
    const manifest = structuredClone(app.manifest);
    mutate(manifest);
    assert.equal(manifestSchema.safeParse(manifest).success, false);
    await assert.rejects(analyze(manifest), error => error.code === 'INVALID_MANIFEST');
  }
});

test('baseline manifest, rules, and report edits are detected; no verify overrides', async t => {
  const app = await fixture(t);
  const baseline = await analyze(app.manifest);
  await assert.rejects(verify(baseline.reportPath, { rules: ['label'] }), error => error.code === 'INVALID_ARGUMENTS');
  const changed = structuredClone(baseline);
  changed.manifest.rules = ['label'];
  await fs.writeFile(baseline.reportPath, JSON.stringify(changed));
  await assert.rejects(verify(baseline.reportPath), error => error.code === 'REPORT_INTEGRITY_MISMATCH');
  assert.equal((await checkEvidence(baseline.reportPath)).status, 'error');
  const { reportDigest: unused, ...payload } = changed;
  changed.reportDigest = digest(payload);
  await fs.writeFile(baseline.reportPath, JSON.stringify(changed));
  await assert.rejects(verify(baseline.reportPath), error => error.code === 'CONTRACT_MISMATCH');
});

test('fingerprints cover untracked content, ignore evidence/caches, and do not use mtimes', async t => {
  const app = await fixture(t);
  const report = await analyze(app.manifest);
  await fs.utimes(path.join(app.projectRoot, 'index.html'), new Date(), new Date());
  for (const directory of ['evidence', 'node_modules', '.git', '.project-memory', '.cache', 'dist']) {
    await fs.mkdir(path.join(app.projectRoot, directory), { recursive: true });
    await fs.writeFile(path.join(app.projectRoot, directory, 'generated.json'), 'generated');
  }
  assert.equal((await checkEvidence(report.reportPath)).status, 'current');
  const untracked = path.join(app.projectRoot, 'new-source.js');
  await fs.writeFile(untracked, 'export const count = 1;');
  assert.equal((await checkEvidence(report.reportPath)).status, 'expired');
  await fs.unlink(untracked);
  assert.equal((await checkEvidence(report.reportPath)).status, 'current');
  const reportCopy = path.join(app.projectRoot, 'outside-evidence.json');
  await fs.writeFile(reportCopy, JSON.stringify(report));
  await assert.rejects(verify(reportCopy), error => error.code === 'REPORT_OUTSIDE_PROJECT');
});

test('a source edit during navigation cannot create current or passed evidence', async t => {
  const app = await fixture(t);
  let changed = false;
  app.beforeResponse(async () => {
    if (!changed) {
      changed = true;
      await fs.writeFile(path.join(app.projectRoot, 'changed-during-run.js'), 'export const changed = true;');
    }
  });
  // A desktop host's port probe precedes the run; it must not move the edit
  // outside the browser navigation it simulates.
  assert.equal((await fetch(app.url)).status, 200);
  assert.equal(changed, false);
  const result = await analyze(app.manifest);
  assert.equal(result.status, 'error');
  assert.equal(result.validity, 'expired');
  assert.ok(result.errors.some(error => error.code === 'SOURCE_CHANGED_DURING_RUN'));
  assert.equal((await checkEvidence(result.reportPath)).status, 'expired');
});

test('source directory symlinks and evidence symlink escapes are rejected', async t => {
  const app = await fixture(t);
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-outside-'));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  await fs.writeFile(path.join(outside, 'outside.js'), 'private source');
  await fs.symlink(outside, path.join(app.projectRoot, 'linked-source'), 'dir');
  await assert.rejects(fingerprint(app.projectRoot), error => error.code === 'UNSUPPORTED_SYMLINK');
  await fs.unlink(path.join(app.projectRoot, 'linked-source'));
  await fs.symlink(outside, path.join(app.projectRoot, 'evidence'), 'dir');
  await assert.rejects(analyze(app.manifest), error => error.code === 'UNSAFE_EVIDENCE_PATH');
  assert.deepEqual(await fs.readdir(outside), ['outside.js']);
});

test('axe incomplete results are preserved and cannot pass verification', async t => {
  // Exercise an actual axe check error in Chromium, rather than replacing the scanner.
  const source = html() + `<script>
    const originalQuery = Document.prototype.querySelectorAll;
    Document.prototype.querySelectorAll = function(selector) {
      if (selector.startsWith('label[for=')) throw new Error('Fixture: label lookup unavailable');
      return originalQuery.call(this, selector);
    };
  </script>`;
  const app = await fixture(t, source);
  const baseline = await analyze(app.manifest);
  assert.ok(baseline.summary.incomplete > 0, JSON.stringify(baseline.states[0].axe));
  assert.notEqual(baseline.status, 'passed');
  const result = await verify(baseline.reportPath);
  assert.ok(result.summary.incomplete > 0);
  assert.notEqual(result.status, 'passed');
});
