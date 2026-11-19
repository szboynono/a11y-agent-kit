import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { fixture, html } from './helpers.js';

const execute = promisify(execFile);
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
async function command(args) {
  let response;
  try { response = { ...await execute(process.execPath, [cli, ...args], { maxBuffer: 16 * 1024 * 1024, timeout: 45000 }), code: 0 }; }
  catch (error) { response = { code: error.code, stdout: error.stdout, stderr: error.stderr }; }
  assert.equal(response.stdout.trim().split('\n').length, 1, 'CLI emits exactly one JSON result');
  return { ...response, result: JSON.parse(response.stdout) };
}

test('audit CLI collects real browser evidence, submits, independently reviews and checks source freshness', async t => {
  const site = await fixture(t, html({ broken: true }));
  const inputDir = path.join(site.projectRoot, 'evidence', 'inputs');
  await fs.mkdir(inputDir, { recursive: true });
  const manifestPath = path.join(inputDir, 'manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify({
    projectRoot: site.projectRoot, url: site.url,
    actions: [{ action: 'snapshot' }, { action: 'axe' }, { action: 'inspect', selector: '#save' }, { action: 'screenshot' }],
  }));
  const collected = await command(['audit', manifestPath, '--summary']);
  assert.equal(collected.code, 0, JSON.stringify(collected.result.errors));
  assert.equal(collected.result.kind, 'audit');
  const audit = JSON.parse(await fs.readFile(collected.result.reportPath));
  assert.equal(audit.records.filter(row => row.success).length, 4);
  assert.equal(audit.coverage.length, 55);
  assert.ok(audit.records[1].result.axe.violations.some(rule => rule.id === 'button-name'));
  assert.ok(audit.records[3].png.path.endsWith('.png'));
  const observation = audit.records[2];
  assert.equal(observation.result.element.attributes.id, 'save');
  const proposalPath = path.join(inputDir, 'findings.json');
  await fs.writeFile(proposalPath, JSON.stringify({
    auditor: { name: 'CLI integration auditor' },
    findings: [{
      id: 'F01', title: 'Save button has no accessible name', criterionId: '4.1.2',
      target: { evidenceId: observation.evidenceId, nodeId: observation.result.element.nodeId },
      evidenceIds: [observation.evidenceId, audit.records[1].evidenceId], method: 'dom',
      observation: 'The native button contains only an aria-hidden plus glyph and a misspelled aria-labl attribute.',
      reason: 'The interactive component has no accessible name in its original DOM/ARIA observation.',
      applicability: 'This is an enabled native button.', exceptions: 'No alternate name is present.',
      scope: 'Only the named button in this captured initial state; no screen reader output claim.',
    }],
  }));
  const submitted = await command(['audit-submit', audit.reportPath, proposalPath, '--summary']);
  assert.equal(submitted.code, 1, 'an unreviewed proposal is unresolved');
  assert.equal(submitted.result.kind, 'audit-proposal');
  assert.equal(submitted.result.confirmedFindings.length, 0);
  assert.equal(submitted.result.verificationQueue.length, 1);
  const reviewPath = path.join(inputDir, 'review.json');
  await fs.writeFile(reviewPath, JSON.stringify({
    reviewer: { name: 'CLI integration reviewer', independentOfAuditor: true },
    decisions: [{ findingId: 'F01', verdict: 'supported',
      checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
      reason: 'The original button DOM and axe record support the local name claim; this test exercises the contract, not expert adjudication.',
      directEvidence: { evidenceId: observation.evidenceId, nodeIds: [observation.result.element.nodeId],
        criterionClause: '4.1.2 requires a programmatically determinable name for a user interface component.',
        explanation: 'The retained native button has only an aria-hidden glyph and a misspelled naming attribute; this fixture supplies direct DOM evidence.' },
    }],
  }));
  const reviewed = await command(['audit-review', submitted.result.reportPath, reviewPath, '--summary']);
  assert.equal(reviewed.code, 0, JSON.stringify(reviewed.result.errors));
  assert.equal(reviewed.result.kind, 'audit-review');
  assert.equal(reviewed.result.confirmedFindings.length, 1);
  assert.equal(reviewed.result.assessment.wholePage, 'not_assessed');
  assert.equal((await command(['audit-check', reviewed.result.reportPath, '--summary'])).result.status, 'current');
  await site.write(html());
  const expired = await command(['audit-check', reviewed.result.reportPath, '--summary']);
  assert.equal(expired.code, 1);
  assert.equal(expired.result.status, 'expired');
});

test('audit CLI rejects invalid commands and does not turn arbitrary claims into evidence', async () => {
  for (const args of [['audit'], ['audit-check', '--summary'], ['audit-review', 'a.json'], ['audit-submit', 'a.json', 'b.json', '--unexpected']]) {
    const actual = await command(args);
    assert.equal(actual.code, 1);
    assert.equal(actual.result.status, 'error');
    assert.equal(actual.result.errors[0].code, 'USAGE');
  }
});


test('audit CLI accepts each supported target and rejects unsupported selections', async t => {
  const site = await fixture(t);
  const dir = path.join(site.projectRoot, 'evidence');
  await fs.mkdir(dir, {recursive:true});
  const file = path.join(dir, 'standard-manifest.json');
  for (const standard of [undefined, ...['2.1','2.2'].flatMap(version => ['A','AA'].map(targetLevel => ({version,targetLevel}))), {version:'2.2',targetLevel:'AAA'}, {version:'9.0',targetLevel:'AA'}]) {
    await fs.writeFile(file, JSON.stringify({projectRoot:site.projectRoot,url:site.url,actions:[],...(standard ? {standard} : {})}));
    const response = await command(['audit',file]);
    if (standard?.targetLevel === 'AAA' || standard?.version === '9.0') {
      assert.notEqual(response.code,0);
    } else {
      assert.equal(response.code,0,JSON.stringify(response.result));
      assert.deepEqual(response.result.manifest.standard,standard ?? {version:'2.2',targetLevel:'AA'});
    }
  }
});

test('CLI audit accepts readiness via its manifest action schema', async t => {
  const site = await fixture(t);
  const directory = path.join(site.projectRoot, 'evidence'); await fs.mkdir(directory);
  const file = path.join(directory, 'readiness.json');
  await fs.writeFile(file, JSON.stringify({ projectRoot: site.projectRoot, url: site.url,
    actions: [{ action: 'wait_for', selector: '#status', condition: 'text', expected: '0' }, { action: 'snapshot' }] }));
  const response = await command(['audit', file, '--summary']);
  assert.equal(response.code, 0, JSON.stringify(response.result));
  const report = JSON.parse(await fs.readFile(response.result.reportPath));
  assert.equal(report.records.length, 2); assert.equal(report.records[0].result.matched, true);
  assert.equal((await command(['audit-check', report.reportPath, '--summary'])).result.status, 'current');
});
