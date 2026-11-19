import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { summarizeResult } from '../src/summary.js';
import { fixture, html } from './helpers.js';

const cliPath = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const exec = promisify(execFile);

async function cli(...args) {
  try {
    const result = await exec(process.execPath, [cliPath, ...args], { maxBuffer: 20 * 1024 * 1024 });
    return { code: 0, ...result, data: JSON.parse(result.stdout) };
  } catch (error) {
    if (typeof error.code !== 'number') throw error;
    return { code: error.code, stdout: error.stdout, stderr: error.stderr, data: JSON.parse(error.stdout) };
  }
}

async function writeManifest(app) {
  const manifestPath = path.join(app.projectRoot, 'manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(app.manifest));
  return manifestPath;
}

function assertNoRawAxe(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    assert.ok(!['html', 'data', 'passes', 'inapplicable'].includes(key), `Summary leaked axe field ${key}`);
    assertNoRawAxe(child);
  }
}

const metadataKeys = [
  'schemaVersion', 'kind', 'status', 'validity', 'runId', 'reportPath', 'reportDigest',
  'contractDigest', 'baseline', 'summary', 'codeFingerprint', 'versions',
  'applicationBinding', 'applicationBindingNote', 'errors', 'reviewReasons', 'limitations',
];

test('CLI summary preserves durable evidence and exit codes across source repair', async t => {
  const app = await fixture(t, html({ broken: true }));
  const manifestPath = await writeManifest(app);
  const full = await cli('analyze', manifestPath);
  assert.equal(full.code, 1);
  assert.equal(full.data.status, 'failed');
  assert.deepEqual(full.data, JSON.parse(await fs.readFile(full.data.reportPath, 'utf8')),
    'Default CLI output remains the complete durable report');
  assert.ok(full.data.states[0].axe.violations[0].nodes[0].html);
  assert.ok(Object.hasOwn(full.data.states[0].axe, 'passes'));

  const baseline = await cli('analyze', manifestPath, '--summary');
  assert.equal(baseline.code, 1);
  assert.equal(baseline.stderr, '');
  assert.equal(baseline.data.outputFormat, 'summary');
  const frozenBytes = await fs.readFile(baseline.data.reportPath, 'utf8');
  const durable = JSON.parse(frozenBytes);
  for (const key of metadataKeys) assert.deepEqual(baseline.data[key], durable[key], key);
  assert.equal(baseline.data.kind, 'analyze');
  assert.deepEqual(baseline.data.scope.rules, durable.manifest.rules);
  assert.deepEqual(baseline.data.scope.stateIds, ['initial']);
  assert.equal(baseline.data.states[0].assertionCount, durable.states[0].assertions.length);
  assert.deepEqual(baseline.data.states[0].assertions, []);
  assert.deepEqual(baseline.data.states[0].axe.violations.map(rule => rule.id),
    durable.states[0].axe.violations.map(rule => rule.id));
  const node = baseline.data.states[0].axe.violations[0].nodes[0];
  const durableNode = durable.states[0].axe.violations[0].nodes[0];
  assert.deepEqual(node.target, durableNode.target);
  assert.equal(node.failureSummary, durableNode.failureSummary);
  for (const group of ['any', 'all', 'none']) {
    assert.deepEqual(node[group].map(check => [check.id, check.message]),
      durableNode[group].map(check => [check.id, check.message]));
  }
  assertNoRawAxe(baseline.data.states[0].axe);
  assert.ok(baseline.stdout.length < JSON.stringify(durable).length,
    'This fixture produces a smaller summary, without promising a size cap');

  await app.write(html());
  const expired = await cli('check', baseline.data.reportPath, '--summary');
  assert.equal(expired.code, 1);
  assert.equal(expired.data.status, 'expired');
  assert.deepEqual(expired.data, (await cli('check', baseline.data.reportPath)).data,
    'Summary checks preserve the complete existing metadata');

  const repaired = await cli('verify', baseline.data.reportPath, '--summary');
  assert.equal(repaired.code, 0);
  assert.equal(repaired.data.status, 'passed');
  assert.equal(repaired.data.kind, 'verify');
  assert.equal(repaired.data.validity, 'current');
  assert.equal(repaired.data.contractDigest, baseline.data.contractDigest);
  assert.equal(repaired.data.baseline.reportDigest, baseline.data.reportDigest);
  const durableRepair = JSON.parse(await fs.readFile(repaired.data.reportPath, 'utf8'));
  for (const key of metadataKeys) assert.deepEqual(repaired.data[key], durableRepair[key], key);
  assert.deepEqual(durableRepair.manifest, durable.manifest);
  assert.ok(Object.hasOwn(durableRepair.states[0].axe, 'passes'));
  assertNoRawAxe(repaired.data.states[0].axe);
  assert.equal(await fs.readFile(baseline.data.reportPath, 'utf8'), frozenBytes);
  const checked = await cli('check', repaired.data.reportPath, '--summary');
  assert.equal(checked.code, 0);
  assert.equal(checked.data.status, 'current');
  assert.deepEqual(checked.data, (await cli('check', repaired.data.reportPath)).data);
});

test('CLI summary retains failed, errored and not-run assertions and run/state errors', async t => {
  const app = await fixture(t, html() + `<script>
    const originalMatches = Element.prototype.matches;
    Element.prototype.matches = function(selector) {
      if (selector === ':focus') throw new Error('Fixture: focus unavailable');
      return originalMatches.call(this, selector);
    };
  </script>`);
  app.manifest.states = [{
    id: 'assertion-failures',
    assertions: [
      { type: 'count', selector: '#save', value: 2 },
      { type: 'focused', selector: '#save' },
    ],
  }, {
    id: 'unreached',
    steps: [{ action: 'click', selector: '#does-not-exist' }],
    assertions: [{ type: 'visible', selector: '#save' }],
  }];
  const manifestPath = await writeManifest(app);
  let changed = false;
  app.beforeResponse(async () => {
    if (!changed) {
      changed = true;
      await fs.writeFile(path.join(app.projectRoot, 'changed-during-run.js'), 'export const changed = true;');
    }
  });
  const result = await cli('analyze', manifestPath, '--summary');
  assert.equal(result.code, 1);
  assert.equal(result.data.status, 'error');
  assert.equal(result.data.validity, 'expired');
  const durable = JSON.parse(await fs.readFile(result.data.reportPath, 'utf8'));
  assert.deepEqual(result.data.errors, durable.errors);
  assert.ok(result.data.errors.some(error => error.code === 'SOURCE_CHANGED_DURING_RUN'));
  assert.deepEqual(result.data.codeFingerprintAfterRun, durable.codeFingerprintAfterRun);
  assert.deepEqual(result.data.states[0].assertions.map(assertion => assertion.status), ['failed', 'error']);
  assert.deepEqual(result.data.states[0].assertions.map(assertion => assertion.index), [0, 1]);
  assert.equal(result.data.states[0].assertions[0].actual, 1);
  assert.equal(result.data.states[0].assertions[0].expected, 2);
  assert.match(result.data.states[0].assertions[1].error.message, /focus unavailable/);
  assert.equal(result.data.states[1].assertions[0].status, 'not_run');
  assert.equal(result.data.states[1].steps[0].status, 'error');
  assert.equal(result.data.states[1].steps[0].index, 0);
  assert.equal(result.data.states[1].axe, null);
  for (let index = 0; index < durable.states.length; index++) {
    assert.deepEqual(result.data.states[index].errors, durable.states[index].errors);
    assertNoRawAxe(result.data.states[index].axe);
  }
});

test('CLI summary preserves needs_review reasons, incomplete checks and limits', async t => {
  const app = await fixture(t, html() + `<script>
    const originalQuery = Document.prototype.querySelectorAll;
    Document.prototype.querySelectorAll = function(selector) {
      if (selector.startsWith('label[for=')) throw new Error('Fixture: label lookup unavailable');
      return originalQuery.call(this, selector);
    };
  </script>`);
  app.manifest.states = [{ id: 'no-assertions' }];
  const result = await cli('analyze', await writeManifest(app), '--summary');
  assert.equal(result.code, 1);
  assert.equal(result.data.status, 'needs_review');
  assert.ok(result.data.summary.incomplete > 0);
  assert.ok(result.data.states[0].axe.incomplete.length > 0);
  const durable = JSON.parse(await fs.readFile(result.data.reportPath, 'utf8'));
  assert.deepEqual(result.data.reviewReasons, durable.reviewReasons);
  assert.deepEqual(result.data.limitations, durable.limitations);
  assert.ok(result.data.reviewReasons.some(reason => reason.code === 'MISSING_FUNCTIONAL_ASSERTIONS'));
  assert.ok(result.data.reviewReasons.some(reason => reason.code === 'AXE_INCOMPLETE'));
  assert.deepEqual(result.data.states[0].axe.incomplete.map(rule => rule.id),
    durable.states[0].axe.incomplete.map(rule => rule.id));
  assertNoRawAxe(result.data.states[0].axe);
});

test('summary excludes raw check data and nested related-node HTML without changing its input', () => {
  const check = {
    id: 'label', impact: 'critical', message: 'Provide a label',
    data: { html: '<input value="private">', nested: { content: 'private page content' } },
    relatedNodes: [{ html: '<label>Private</label>', target: ['#label'] }],
  };
  const report = {
    kind: 'analyze', reportDigest: 'full-report-digest', errors: [],
    manifest: { projectRoot: '/project', url: 'http://localhost/', viewport: { width: 1, height: 1 }, rules: ['label'], states: [{ id: 'initial' }] },
    states: [{ id: 'initial', reached: true, status: 'failed', steps: [], assertions: [], errors: [], axe: {
      violations: [{ id: 'label', nodes: [{ html: '<input>', target: ['#input'], any: [check], all: [], none: [] }] }],
      incomplete: [], passes: [{ private: 'pass data' }], inapplicable: [],
    } }],
  };
  const original = structuredClone(report);
  const summary = summarizeResult(report);
  assertNoRawAxe(summary.states[0].axe);
  assert.deepEqual(summary.states[0].axe.violations[0].nodes[0].any[0].relatedNodes, [{ target: ['#label'] }]);
  assert.ok(!JSON.stringify(summary).includes('private'));
  assert.deepEqual(report, original);
});

test('CLI rejects unknown, duplicate, misplaced, or serve summary flags', async () => {
  for (const args of [
    [], ['analyze'], ['analyze', '--summary'], ['analyze', '--summary', '/manifest.json'],
    ['analyze', '/manifest.json', '--summary', '--summary'],
    ['analyze', '/manifest.json', '--unknown'], ['analyze', '/manifest.json', 'extra'],
    ['analyze', '/manifest.json', '--summary=true'], ['analyze', '', '--summary'],
    ['verify', '/report.json', '--summary', '--summary'], ['verify', '/report.json', '--rules', 'label'],
    ['check', '/report.json', '--summary', 'extra'], ['check', '/report.json', '--unknown'],
    ['serve', '--summary'], ['serve', '/report.json'], ['unknown', '/report.json', '--summary'],
  ]) {
    const result = await cli(...args);
    assert.equal(result.code, 1, JSON.stringify(args));
    assert.equal(result.data.status, 'error', JSON.stringify(args));
    assert.equal(result.data.errors[0].code, 'USAGE', JSON.stringify(args));
    assert.equal(result.stderr, '');
  }
  const invalidReport = await cli('check', '/does-not-exist/report.json', '--summary');
  assert.equal(invalidReport.code, 1);
  assert.equal(invalidReport.data.status, 'error');
  assert.ok(invalidReport.data.errors.length > 0);
});
