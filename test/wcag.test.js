import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import axe from 'axe-core';
import { analyze, verify, checkEvidence, SUPPORTED_RULES, manifestSchema } from '../src/index.js';
import { contractDigest, digest, EXECUTION_POLICY } from '../src/evidence.js';
import { standardMetadata, coverageMetadata } from '../src/wcag.js';
import { summarizeResult } from '../src/summary.js';
import { fixture, html } from './helpers.js';

const catalogBytes = await fs.readFile(new URL('../src/wcag21-aa.json', import.meta.url));
const catalog = JSON.parse(catalogBytes);
const criterionIds = catalog.criteria.map(criterion => criterion.id);
const source = 'https://www.w3.org/TR/2025/REC-WCAG21-20250506/';
const exec = promisify(execFile);
const cliPath = fileURLToPath(new URL('../src/cli.js', import.meta.url));

function assertPartialTarget(report) {
  assert.deepEqual(report.standard, standardMetadata());
  assert.equal(report.standard.targetLevel, 'AA');
  assert.deepEqual(report.standard.includedLevels, ['A', 'AA']);
  assert.equal(report.standard.conformanceStatus, 'not_assessed');
  assert.equal(report.coverage.assessment, 'partial-evidence-only');
  assert.deepEqual(report.coverage.mappedCriteriaByLevel, { A: ['4.1.2'], AA: [] });
  assert.equal(report.coverage.aaSpecificAutomatedCriteria, 0);
  assert.deepEqual(report.coverage.fullyAssessedCriteria, []);
  assert.deepEqual(report.coverage.unassessedCriteria, criterionIds);
}

async function overwriteReport(report) {
  const { reportDigest: unused, ...payload } = report;
  report.reportDigest = digest(payload);
  await fs.writeFile(report.reportPath, JSON.stringify(report));
}

function assertNoRawScanData(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    assert.ok(!['html', 'data', 'passes', 'inapplicable'].includes(key), `Summary leaked ${key}`);
    assertNoRawScanData(child);
  }
}

test('pinned WCAG 2.1 AA catalog includes exactly 30 A and 20 AA criteria', () => {
  const expectedA = '1.1.1 1.2.1 1.2.2 1.2.3 1.3.1 1.3.2 1.3.3 1.4.1 1.4.2 2.1.1 2.1.2 2.1.4 2.2.1 2.2.2 2.3.1 2.4.1 2.4.2 2.4.3 2.4.4 2.5.1 2.5.2 2.5.3 2.5.4 3.1.1 3.2.1 3.2.2 3.3.1 3.3.2 4.1.1 4.1.2'.split(' ');
  const expectedAA = '1.2.4 1.2.5 1.3.4 1.3.5 1.4.3 1.4.4 1.4.5 1.4.10 1.4.11 1.4.12 1.4.13 2.4.5 2.4.6 2.4.7 3.1.2 3.2.3 3.2.4 3.3.3 3.3.4 4.1.3'.split(' ');
  assert.equal(catalog.id, 'wcag21-aa-20250506-v1');
  assert.equal(catalog.version, '2.1');
  assert.equal(catalog.targetLevel, 'AA');
  assert.equal(catalog.normativeSource, source);
  assert.equal(catalog.sourceSha256, '233ac31974ce8575c08932ee1bd71c93879cf9b8426b2bc9b961b3ea8afb8ab6');
  assert.equal(catalog.criteriaTotal, 50);
  assert.deepEqual(catalog.levelCounts, { A: 30, AA: 20 });
  assert.deepEqual(catalog.criteria.filter(criterion => criterion.level === 'A').map(criterion => criterion.id), expectedA);
  assert.deepEqual(catalog.criteria.filter(criterion => criterion.level === 'AA').map(criterion => criterion.id), expectedAA);
  assert.equal(catalog.criteria.length, 50);
  assert.equal(new Set(criterionIds).size, 50);
  assert.ok(catalog.criteria.every(criterion => ['A', 'AA'].includes(criterion.level) && criterion.url.startsWith(`${source}#`)));
  for (const id of ['1.2.6', '2.1.3', '2.4.11', '2.5.7', '2.5.8', '3.2.6', '3.3.7', '3.3.8', '3.3.9']) {
    assert.ok(!criterionIds.includes(id), `Unexpected AAA or WCAG 2.2 criterion: ${id}`);
  }
  assert.equal(standardMetadata().rubric.catalogDigest, `sha256:${createHash('sha256').update(catalogBytes).digest('hex')}`);
});

test('selected-rule mapping agrees with installed axe 4.14 tags and credits no AA-specific criterion', () => {
  const rules = axe.getRules().filter(rule => SUPPORTED_RULES.includes(rule.ruleId));
  assert.equal(axe.version, '4.14.0');
  assert.equal(rules.length, 3);
  for (const rule of rules) {
    assert.deepEqual(rule.tags.filter(tag => /^wcag\d+$/.test(tag)), ['wcag412']);
    assert.ok(rule.tags.includes('wcag2a'));
    assert.ok(!rule.tags.includes('wcag2aa'));
    assert.deepEqual(coverageMetadata([rule.ruleId]).ruleMappings, [{
      ruleId: rule.ruleId, criterionIds: ['4.1.2'], evidence: 'partial',
    }]);
  }
});

test('a passing bounded run retains unassessed AA target and freshness has no conformance meaning', async t => {
  const app = await fixture(t);
  const report = await analyze(app.manifest);
  assert.equal(report.status, 'passed');
  assertPartialTarget(report);
  assert.equal(report.applicationBinding, 'caller-declared');
  assert.deepEqual(report.executionPolicy, EXECUTION_POLICY);
  assert.equal(report.contractDigest, contractDigest(report.manifest));
  const checked = await checkEvidence(report.reportPath);
  assert.equal(checked.status, 'current');
  assert.equal(checked.statusMeaning, 'evidence-freshness-only');
  assert.equal(checked.reportStatus, 'passed');
  assert.equal(checked.standardMetadataStatus, 'recorded');
  assert.deepEqual(checked.standard, report.standard);
  const forbiddenTargetOverride = { ...app.manifest, targetLevel: 'A' };
  assert.equal(manifestSchema.safeParse(forbiddenTargetOverride).success, false);
});

test('findings map to partial 4.1.2 evidence; verify freezes rubric and summary preserves it without raw DOM', async t => {
  const app = await fixture(t, html({ broken: true }));
  const baseline = await analyze(app.manifest);
  assert.equal(baseline.status, 'failed');
  assertPartialTarget(baseline);
  const mappings = new Map(baseline.coverage.ruleMappings.map(mapping => [mapping.ruleId, mapping]));
  assert.deepEqual(new Set(baseline.states[0].axe.violations.map(rule => rule.id)), new Set(SUPPORTED_RULES));
  for (const rule of baseline.states[0].axe.violations) {
    assert.deepEqual(mappings.get(rule.id).criterionIds, ['4.1.2']);
    assert.equal(mappings.get(rule.id).evidence, 'partial');
  }
  const compactBaseline = summarizeResult(baseline);
  assert.deepEqual(compactBaseline.standard, baseline.standard);
  assert.deepEqual(compactBaseline.coverage, baseline.coverage);
  assertNoRawScanData(compactBaseline);
  const frozenBytes = await fs.readFile(baseline.reportPath, 'utf8');
  await app.write(html());
  const repaired = await verify(baseline.reportPath);
  assert.equal(repaired.status, 'passed');
  assertPartialTarget(repaired);
  assert.deepEqual(repaired.standard, baseline.standard);
  // The actual host validator requires this exact triple, including no extra
  // keys; standard provenance belongs in an independent metadata field.
  assert.deepEqual(repaired.baseline, {
    reportPath: baseline.reportPath, runId: baseline.runId, reportDigest: baseline.reportDigest,
  });
  assert.deepEqual(repaired.baselineStandard, {
    metadataStatus: 'recorded',
    rubricId: baseline.standard.rubric.id,
    rubricDigest: baseline.standard.rubric.digest,
    conformanceStatus: 'not_assessed',
  });
  assert.deepEqual(summarizeResult(repaired).baselineStandard, repaired.baselineStandard);
  assert.equal(await fs.readFile(baseline.reportPath, 'utf8'), frozenBytes);
  const { stdout, stderr } = await exec(process.execPath, [cliPath, 'verify', baseline.reportPath, '--summary']);
  const cliResult = JSON.parse(stdout);
  assert.equal(stderr, '');
  assert.equal(cliResult.status, 'passed');
  assertPartialTarget(cliResult);
  assert.deepEqual(cliResult.baseline, repaired.baseline);
  assert.deepEqual(cliResult.baselineStandard, repaired.baselineStandard);
  assertNoRawScanData(cliResult);
});

test('rubric, source, target and mapping mismatches are rejected after recomputing report integrity', async t => {
  const app = await fixture(t);
  const baseline = await analyze(app.manifest);
  const mutations = [
    report => { report.standard.rubric.id = 'different-rubric'; },
    report => { report.standard.rubric.digest = 'sha256:other-assessment-policy'; },
    report => { report.standard.rubric.catalogDigest = 'sha256:other-catalog'; },
    report => { report.standard.rubric.policyVersion = 'different-policy'; },
    report => { report.standard.normativeSource = 'https://www.w3.org/TR/WCAG22/'; },
    report => { report.standard.normativeSourceSha256 = 'changed-source'; },
    report => { report.standard.targetLevel = 'A'; },
    report => { report.standard.conformanceStatus = 'passed'; },
    report => { report.coverage.ruleMappings[0].criterionIds = ['2.4.7']; },
    report => { report.coverage.unassessedCriteria = []; },
    report => { delete report.coverage; },
    report => { delete report.standard; },
    report => { report.standard = null; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(baseline);
    mutate(changed);
    await overwriteReport(changed);
    await assert.rejects(verify(changed.reportPath), error => error.code === 'STANDARD_MISMATCH');
    const checked = await checkEvidence(changed.reportPath);
    assert.equal(checked.status, 'error');
    assert.equal(checked.errors[0].code, 'STANDARD_MISMATCH');
  }
});

test('historical reports stay unspecified while their new verification explicitly identifies the legacy baseline', async t => {
  const app = await fixture(t);
  const baseline = await analyze(app.manifest);
  // Model the historical schema without rewriting any stored eval artifact.
  delete baseline.standard;
  delete baseline.coverage;
  await overwriteReport(baseline);
  const frozenLegacyBytes = await fs.readFile(baseline.reportPath, 'utf8');
  const checked = await checkEvidence(baseline.reportPath);
  assert.equal(checked.status, 'current');
  assert.equal(checked.statusMeaning, 'evidence-freshness-only');
  assert.equal(checked.standardMetadataStatus, 'legacy_unspecified');
  assert.equal(checked.standard, null);
  assert.ok(!Object.hasOwn(summarizeResult(baseline), 'standard'));
  const verified = await verify(baseline.reportPath);
  assert.equal(verified.status, 'passed');
  assertPartialTarget(verified);
  assert.deepEqual(verified.baselineStandard, { metadataStatus: 'legacy_unspecified' });
  assert.deepEqual(verified.baseline, {
    reportPath: baseline.reportPath, runId: baseline.runId, reportDigest: baseline.reportDigest,
  });
  assert.equal(verified.baseline.reportDigest, baseline.reportDigest);
  assert.equal(await fs.readFile(baseline.reportPath, 'utf8'), frozenLegacyBytes);
});

test('a caller can select fewer checks without lowering the fixed AA target or gaining criterion coverage', async t => {
  const app = await fixture(t);
  app.manifest.rules = ['label'];
  const report = await analyze(app.manifest);
  assert.equal(report.status, 'passed');
  assertPartialTarget(report);
  assert.deepEqual(report.coverage.ruleMappings, [{ ruleId: 'label', criterionIds: ['4.1.2'], evidence: 'partial' }]);
  assert.deepEqual(report.standard, standardMetadata());
});
