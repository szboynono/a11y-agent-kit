import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import { digest, fingerprint } from '../src/evidence.js';
import { AUDIT_CATALOG, AUDIT_STANDARD, AUDIT_SCHEMA_VERSION, parseAuditManifest } from '../src/audit/schema.js';
import { createAuditDirectory, writeAuditArtifact, saveAuditDocument } from '../src/audit/store.js';
import { submitAudit, reviewAudit, checkAudit, summarizeAudit } from '../src/audit/review.js';

// These are contract fixtures, not browser observations or semantic gold labels.
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aN1kAAAAASUVORK5CYII=', 'base64');
const spacingCss = '* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; } p { margin-block-end: 2em !important; }';
const spacingReceipt = () => ({
  enabled: true, applied: true, failures: [], css: spacingCss,
  cssSha256: createHash('sha256').update(spacingCss).digest('hex'),
  requested: { lineHeight: 1.5, letterSpacingEm: 0.12, wordSpacingEm: 0.16, paragraphMarginBlockEndEm: 2 },
  representativeParagraph: { fontSize: '16px', marginBlockEnd: '32px', computed: { lineHeight: '24px', letterSpacing: '1.92px', wordSpacing: '2.56px' } },
});

async function collectionFixture(t, configure = () => {}) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-audit-review-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'index.html'), '<!doctype html><title>Audit fixture</title><p id="target">Example</p>');
  const runId = randomUUID();
  const directory = await createAuditDirectory(root, runId);
  const manifest = parseAuditManifest({ standard: { version: '2.1', targetLevel: 'AA' }, projectRoot: root, url: 'http://localhost:8123/' });
  const source = await fingerprint(root);
  const documentId = `doc-${randomUUID()}`;
  const node = { nodeId: `${documentId}:n000001`, documentId, selector: '#target', tag: 'p', attributes: { id: 'target' }, attributesTruncated: [], text: 'Example', textTruncated: false, labelText: '', labelTextTruncated: false, rect: { x: 0, y: 0, width: 200, height: 20 } };
  const state = (name, extra = {}) => ({
    stateId: digest({ name, documentId }), documentId, url: manifest.url, viewport: manifest.viewport,
    scroll: { x: 0, y: 0 }, active: node, controls: [], spacing: { enabled: false }, keyboardOnly: true, inputPath: 'keyboard-only', ...extra,
  });
  const initial = state('initial');
  const records = [];
  function add(action, { before = initial, after = before, result = {}, args = {}, image = false, success = true } = {}) {
    const evidenceId = `ev-${String(records.length + 1).padStart(4, '0')}`;
    const record = { evidenceId, action, arguments: args, success, before, after, result };
    if (image) record._image = true;
    records.push(record);
    return record;
  }
  function dom(observed = initial) { return add('snapshot', { before: observed, result: { nodes: [node] } }); }
  function shot(observed = initial, options = {}) {
    return add('screenshot', { before: observed, image: true, result: { nodes: [node], capture: { stable: true, beforeStateId: observed.stateId, afterStateId: observed.stateId } }, ...options });
  }
  const base = dom();
  const context = { root, directory, manifest, node, state, initial, records, add, dom, shot, base };
  configure(context);
  for (const record of records) {
    if (record._image) {
      delete record._image;
      record.png = { ...await writeAuditArtifact(directory, `${record.evidenceId}.png`, png), width: 1, height: 1 };
      if (record.result.contrast?.screenshotSha256 === 'fixture-png') record.result.contrast.screenshotSha256 = record.png.sha256;
    }
    record.json = await writeAuditArtifact(directory, `${record.evidenceId}.json`, `${JSON.stringify(record)}\n`);
  }
  const audit = await saveAuditDocument(directory, 'audit', {
    schemaVersion: AUDIT_SCHEMA_VERSION, runId, manifest, manifestDigest: digest(manifest),
    standard: AUDIT_STANDARD, applicationBinding: 'caller-declared', codeFingerprint: source, codeFingerprintAfterRun: source,
    sourceStability: { status: 'stable_observed', eventCount: 0, changedPaths: [], errors: [] },
    records, candidates: [{ id: 'candidate-1', criterionId: '1.4.5', evidenceIds: [base.evidenceId] }],
    coverage: AUDIT_CATALOG.criteria.map(criterion => ({ ...criterion, status: 'not_tested', evidenceIds: [], scope: 'partial' })),
    errors: [], status: 'collected',
  });
  return { ...context, audit };
}

function finding(fixture, extra = {}) {
  return {
    id: 'F01', title: 'A specific observation', criterionId: '1.3.1',
    target: { evidenceId: fixture.base.evidenceId, nodeId: fixture.node.nodeId }, evidenceIds: [fixture.base.evidenceId],
    observation: 'Observed local behavior.', reason: 'The reviewer must evaluate the criterion mapping.',
    applicability: 'This local target is applicable.', exceptions: 'Relevant exceptions require review.', scope: 'Only this recorded target and state.', ...extra,
  };
}
const proposal = (fixture, findings = [finding(fixture)]) => ({ auditor: { name: 'Auditor', model: 'user-selected' }, findings });
const decision = (findingId = 'F01', extra = {}) => ({
  findingId, verdict: 'supported', checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
  reason: 'The independent reviewer declares these checks supported by the raw material.', ...extra,
});
const adjudication = (decisions = [decision()], extra = {}) => ({ reviewer: { name: 'Reviewer', independentOfAuditor: true }, decisions, ...extra });

test('audit manifest is strict, bounded and defaults without inventing actions', () => {
  const input = { projectRoot: '/tmp/demo', url: 'https://example.com/' };
  const result = parseAuditManifest(input);
  assert.deepEqual(result.viewport, { width: 1280, height: 900 });
  assert.equal(result.maxActions, 120); assert.equal(result.wallSeconds, 120); assert.equal(result.maxElements, 3000);
  assert.equal(Object.hasOwn(result, 'actions'), false);
  for (const mutation of [
    { foo: 1 }, { projectRoot: 'relative' }, { url: 'https://user:secret@example.com/' },
    { actions: [{ action: 'evaluate', expression: 'document.body' }] },
    { actions: [{ action: 'navigate', path: 'javascript:alert(1)' }] },
    { actions: [{ action: 'navigate', path: 'https://other.example/' }] },
    { actions: [{ action: 'press', key: 'Tab', selector: '#target' }] },
    { actions: [{ action: 'wait', ms: 5001 }] }, { maxActions: 501 }, { maxElements: 20001 },
    { actions: [{ action: 'contrast', foreground: { x: 4096, y: 0 }, background: { x: 0, y: 0 } }] },
  ]) assert.throws(() => parseAuditManifest({ ...input, ...mutation }), { code: 'INVALID_AUDIT_MANIFEST' });
  assert.equal(parseAuditManifest({ ...input, actions: [{ action: 'navigate', path: '/next' }, { action: 'contrast', foreground: { x: 2, y: 3 }, background: { x: 0, y: 0 } }] }).actions.length, 2);
});

test('submission always remains needs_review and retains candidates and all 50 criteria', async t => {
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  assert.equal(submitted.status, 'needs_review'); assert.equal(submitted.semanticValidation, 'not_reviewed');
  assert.equal(submitted.confirmedFindings.length, 0); assert.equal(submitted.verificationQueue.length, 1);
  assert.equal(submitted.candidates.length, 1); assert.equal(submitted.coverage.length, 50);
  assert.ok(submitted.coverage.every(row => row.wholeCriterion === 'not_assessed' && row.status !== 'pass'));
  assert.equal(submitted.verificationQueue[0].targetObservation.selector, '#target');
  assert.equal((await checkAudit(submitted.reportPath)).status, 'current');
  const summary = summarizeAudit(submitted);
  assert.equal(summary.candidates.length, 1); assert.equal(summary.verificationQueue.length, 1);
});

test('independent declarations without direct semantic evidence remain needs_review', async t => {
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  const reviewed = await reviewAudit(submitted.reportPath, adjudication());
  assert.equal(reviewed.confirmedFindings.length, 0); assert.equal(reviewed.verificationQueue.length, 1); assert.equal(reviewed.semanticValidation, 'reviewer-declared');
  assert.equal(reviewed.independence.osVerified, false); assert.equal(reviewed.zeroFalsePositiveGuarantee, false);
  assert.equal(reviewed.assessment.wholePage, 'not_assessed'); assert.equal(reviewed.assessment.wholeCriteriaAssessed, 0);
  assert.equal((await checkAudit(reviewed.reportPath)).status, 'current');
});

test('missing PNG and same-URL PNG from another state cannot confirm visual claims', async t => {
  for (const wrongState of [false, true]) {
    const fixture = await collectionFixture(t, c => { if (wrongState) c.shot(c.state('expanded', { controls: [{ expanded: true }] })); });
    const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, { criterionId: '1.4.5', evidenceIds: fixture.records.map(record => record.evidenceId) })]));
    const reviewed = await reviewAudit(submitted.reportPath, adjudication());
    assert.equal(reviewed.confirmedFindings.length, 0); assert.equal(reviewed.verificationQueue.length, 1);
    assert.match(reviewed.verificationQueue[0].missingEvidence.join(' '), /same actual stateId/);
  }
});

test('a same-state PNG supports the visual evidence contract while semantics remain reviewer-declared', async t => {
  const fixture = await collectionFixture(t, c => c.shot());
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, { criterionId: '1.4.5', evidenceIds: fixture.records.map(record => record.evidenceId) })]));
  const reviewed = await reviewAudit(submitted.reportPath, adjudication());
  assert.equal(reviewed.confirmedFindings.length, 1);
});

test('text contrast requires an actual same-state calculation and explicit text/exception review', async t => {
  for (const variant of ['screenshot-only', 'wrong-image', 'wrong-ratio', 'missing-review', 'thin-stroke', 'complete']) {
    const fixture = await collectionFixture(t, c => {
      if (variant === 'screenshot-only') return c.shot();
      const sample = { x: 0, y: 0, rgb: [255, 255, 255], rgba: [255, 255, 255, 255], relativeLuminance: 1, neighborhood: { radius: 1, pixels: 1, uniform: variant !== 'thin-stroke', opaque: true } };
      c.add('contrast', {
        args: { foreground: { x: 0, y: 0 }, background: { x: 0, y: 0 } }, image: true,
        result: {
          nodes: [c.node], capture: { stable: true, beforeStateId: c.initial.stateId, afterStateId: c.initial.stateId },
          contrast: {
            foreground: sample, background: sample, ratio: variant === 'wrong-ratio' ? 2 : 1,
            formula: 'WCAG-relative-luminance-sRGB', srgbThreshold: 0.04045, coefficients: [0.2126, 0.7152, 0.0722],
            ratioOffset: 0.05, alphaPolicy: 'opaque-samples-only', screenshotSha256: variant === 'wrong-image' ? 'wrong' : 'fixture-png',
          },
        },
      });
    });
    const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, { criterionId: '1.4.3', evidenceIds: fixture.records.map(record => record.evidenceId) })]));
    const reviewed = await reviewAudit(submitted.reportPath, adjudication([decision('F01', variant === 'missing-review' ? {} : {
      prerequisiteNotes: { contrast: 'Reviewer checked that the samples describe ordinary text, its actual size, and the applicable contrast exceptions.' },
    })]));
    assert.equal(reviewed.confirmedFindings.length, ['complete', 'thin-stroke'].includes(variant) ? 1 : 0, variant);
  }
});

test('text spacing needs all four real values and target before/after PNGs', async t => {
  for (const incomplete of [true, false]) {
    let target;
    const fixture = await collectionFixture(t, c => {
      c.shot();
      const after = c.state('spacing', { spacing: { enabled: true } });
      const receipt = spacingReceipt(); if (incomplete) delete receipt.requested.paragraphMarginBlockEndEm;
      c.add('spacing', { before: c.initial, after, args: { enabled: true }, result: receipt });
      target = c.dom(after); c.shot(after);
    });
    const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, {
      criterionId: '1.4.12', target: { evidenceId: target.evidenceId, nodeId: fixture.node.nodeId }, evidenceIds: fixture.records.map(record => record.evidenceId),
    })]));
    const reviewed = await reviewAudit(submitted.reportPath, adjudication());
    assert.equal(reviewed.confirmedFindings.length, incomplete ? 0 : 1);
  }
});

test('focus visible requires a global keyboard path and same-state keyboardOnly PNG', async t => {
  for (const pathKind of ['programmatic', 'programmatic-then-press', 'unrelated-key', 'mouse-assisted', 'keyboard-only']) {
    const fixture = await collectionFixture(t, c => {
      const keyboardOnly = ['keyboard-only', 'unrelated-key'].includes(pathKind);
      c.initial.keyboardOnly = keyboardOnly; c.initial.inputPath = keyboardOnly ? 'keyboard-only' : pathKind.startsWith('programmatic') ? 'programmatic' : 'mouse-assisted';
      if (pathKind.startsWith('programmatic')) c.add('focus', { before: c.initial, after: c.initial, args: { selector: '#target' }, result: { target: c.node, focused: true, keyboardOnly: false, inputPath: 'programmatic' } });
      if (pathKind !== 'programmatic') c.add('press', {
        before: pathKind === 'unrelated-key' ? c.initial : c.state('before-tab', { active: { ...c.node, nodeId: `${c.node.documentId}:body`, selector: 'body', tag: 'body' } }),
        after: c.initial, args: { key: 'Tab' }, result: { keyboardOnly, inputPath: c.initial.inputPath },
      });
      c.shot();
    });
    const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, { criterionId: '2.4.7', evidenceIds: fixture.records.map(record => record.evidenceId) })]));
    const reviewed = await reviewAudit(submitted.reportPath, adjudication());
    assert.equal(reviewed.confirmedFindings.length, pathKind === 'keyboard-only' ? 1 : 0);
  }
});

test('reflow requires a 320px state and explicit alternative presentation and exception review', async t => {
  for (const hasNotes of [false, true]) {
    const fixture = await collectionFixture(t, c => {
      c.initial.viewport = { width: 320, height: 900 }; c.shot();
    });
    const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, { criterionId: '1.4.10', evidenceIds: fixture.records.map(record => record.evidenceId) })]));
    const reviewed = await reviewAudit(submitted.reportPath, adjudication([decision('F01', hasNotes ? { prerequisiteNotes: { alternativePresentation: 'Reviewer checked available alternate presentation.', exceptions: 'Reviewer checked relevant two-dimensional content exceptions.' } } : {})]));
    assert.equal(reviewed.confirmedFindings.length, hasNotes ? 1 : 0);
  }
});

test('all 15 original findings remain in the denominator across all review outcomes', async t => {
  const fixture = await collectionFixture(t);
  const findings = Array.from({ length: 15 }, (_, index) => finding(fixture, { id: `F${index + 1}` }));
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, findings));
  const decisions = findings.map((item, index) => decision(item.id, index < 5 ? {} : index < 10 ? { verdict: 'insufficient', missingEvidence: ['More evidence needed.'] } : { verdict: 'rejected' }));
  const reviewed = await reviewAudit(submitted.reportPath, adjudication(decisions));
  assert.equal(reviewed.findings.length, 15); assert.equal(reviewed.decisions.length, 15); assert.equal(reviewed.counts.originalFindings, 15);
  assert.equal(reviewed.confirmedFindings.length, 0); assert.equal(reviewed.verificationQueue.length, 10); assert.equal(reviewed.rejectedObservations.length, 5);
  for (const invalid of [[...decisions, decisions[0]], [...decisions.slice(1), decision('unknown')]]) {
    await assert.rejects(reviewAudit(submitted.reportPath, adjudication(invalid)), { code: 'AUDIT_REVIEW_DENOMINATOR_MISMATCH' });
  }
});

test('one insufficient prerequisite check prevents confirmation despite a supported verdict', async t => {
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  const item = decision(); item.checks.prerequisites = 'insufficient';
  const reviewed = await reviewAudit(submitted.reportPath, adjudication([item]));
  assert.equal(reviewed.confirmedFindings.length, 0); assert.equal(reviewed.verificationQueue.length, 1);
});

test('unknown targets, cross-run nodes, foreign selectors and fake screen reader claims are rejected', async t => {
  const fixture = await collectionFixture(t);
  for (const invalid of [
    finding(fixture, { criterionId: '2.4.13' }),
    finding(fixture, { evidenceIds: ['ev-9999'] }),
    finding(fixture, { target: { evidenceId: fixture.base.evidenceId, nodeId: `doc-other:n000001` } }),
    finding(fixture, { target: { evidenceId: fixture.base.evidenceId, nodeId: fixture.node.nodeId, selector: '#imposter' } }),
    finding(fixture, { method: 'screen_reader' }),
  ]) await assert.rejects(submitAudit(fixture.audit.reportPath, proposal(fixture, [invalid])));
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  await assert.rejects(reviewAudit(submitted.reportPath, adjudication(undefined, { reviewer: { name: 'auditor', independentOfAuditor: true } })), { code: 'AUDIT_REVIEW_NOT_INDEPENDENT' });
});

test('source changes expire submit, review and all derived checks', async t => {
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  const reviewed = await reviewAudit(submitted.reportPath, adjudication());
  await fs.appendFile(path.join(fixture.root, 'index.html'), '<p>changed</p>');
  await assert.rejects(submitAudit(fixture.audit.reportPath, proposal(fixture)), { code: 'AUDIT_EXPIRED' });
  await assert.rejects(reviewAudit(submitted.reportPath, adjudication()), { code: 'AUDIT_EXPIRED' });
  for (const report of [fixture.audit, submitted, reviewed]) assert.equal((await checkAudit(report.reportPath)).status, 'expired');
});

test('attachment edits invalidate original and derived evidence', async t => {
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  await fs.appendFile(fixture.base.json.path, ' ');
  assert.equal((await checkAudit(submitted.reportPath)).status, 'error');
  await assert.rejects(reviewAudit(submitted.reportPath, adjudication()));
  await assert.rejects(submitAudit(fixture.audit.reportPath, proposal(fixture)));
});

test('a review cannot substitute another intact proposal or source audit run', async t => {
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  const reviewed = await reviewAudit(submitted.reportPath, adjudication());
  const changed = structuredClone(reviewed); changed.sourceProposal.reportDigest = `sha256:${'0'.repeat(64)}`;
  const forged = await saveAuditDocument(fixture.directory, 'audit-review', changed);
  assert.equal((await checkAudit(forged.reportPath)).status, 'error');
  const other = await collectionFixture(t);
  const crossRun = { ...submitted, collection: { reportPath: other.audit.reportPath, reportDigest: other.audit.reportDigest } };
  const misplaced = await saveAuditDocument(fixture.directory, 'audit-proposal', crossRun);
  assert.equal((await checkAudit(misplaced.reportPath)).status, 'error');
});


test('direct DOM citations require the same state, real nodes and ownership context', async t => {
  const fixture = await collectionFixture(t, c => {
    c.node.parentNodeId = `${c.node.documentId}:parent`;
    c.base.result.nodes.push({ nodeId: c.node.parentNodeId, documentId: c.node.documentId, tag: 'div', attributes: {}, selector: '#parent' });
  });
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  const directEvidence = { evidenceId: fixture.base.evidenceId, nodeIds: [fixture.node.nodeId, fixture.node.parentNodeId], criterionClause: '1.3.1: relationships must be programmatically determinable or available in text.', explanation: 'Synthetic contract test of a cited parent relationship; not a semantic gold label.' };
  for (const [variant, citation, expected] of [
    ['complete-but-no-relationship-predicate', directEvidence, 0],
    ['target-only', { ...directEvidence, nodeIds: [fixture.node.nodeId] }, 0],
    ['foreign-node', { ...directEvidence, nodeIds: [...directEvidence.nodeIds, 'foreign'] }, 0],
    ['foreign-evidence', { ...directEvidence, evidenceId: 'ev-9999' }, 0],
  ]) {
    const result = await reviewAudit(submitted.reportPath, adjudication([decision('F01', { directEvidence: citation })]));
    assert.equal(result.confirmedFindings.length, expected, variant);
  }
});

test('partial submissions preserve omitted findings as unassessed and external output remains checkable', async t => {
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture), finding(fixture, { id: 'F02' })]));
  const external = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-review-output-')));
  t.after(() => fs.rm(external, { recursive: true, force: true }));
  const out = path.join(external, 'review.json');
  const reviewed = await reviewAudit(submitted.reportPath, adjudication([decision('F01', { verdict: 'rejected' })]), { out });
  assert.equal(reviewed.reportPath, out);
  assert.equal(reviewed.findings.length, 2);
  assert.equal(reviewed.decisions.length, 1);
  assert.deepEqual(reviewed.reviewProgress, { submittedDecisions: 1, unassessedFindings: 1 });
  assert.match(reviewed.verificationQueue[0].decision.reason, /UNASSESSED/);
  assert.equal((await checkAudit(out)).status, 'current');
  await assert.rejects(reviewAudit(submitted.reportPath, adjudication([]), { out }), { code: 'EEXIST' });
  const copy = path.join(external, 'TERRA-RUN');
  await fs.mkdir(copy);
  const copyPath = path.join(copy, path.basename(submitted.reportPath));
  await fs.copyFile(submitted.reportPath, copyPath);
  await assert.rejects(reviewAudit(copyPath, adjudication([])), error => error.code === 'UNSAFE_AUDIT_PATH' && /original reportPath/.test(error.message));
  const link = path.join(external, 'linked');
  await fs.symlink(copy, link);
  await assert.rejects(reviewAudit(submitted.reportPath, adjudication([]), { out: path.join(link, 'unsafe.json') }), { code: 'UNSAFE_AUDIT_PATH' });
});

test('CLI saves partial reviews with exit 2 and a durable-save message; invalid options remain errors', async t => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  const external = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-review-cli-')));
  t.after(() => fs.rm(external, { recursive: true, force: true }));
  const input = path.join(external, 'adjudication.json');
  await fs.writeFile(input, JSON.stringify(adjudication([])));
  const out = path.join(external, 'cli-review.json');
  let result;
  try { await promisify(execFile)(process.execPath, ['src/cli.js', 'audit-review', submitted.reportPath, input, '--out', out, '--summary']); }
  catch (error) { result = error; }
  assert.equal(result.code, 2);
  assert.match(result.stderr, /Partial review saved/);
  assert.equal(JSON.parse(result.stdout).reportPath, out);
  assert.equal((await checkAudit(out)).status, 'current');
  await assert.rejects(promisify(execFile)(process.execPath, ['src/cli.js', 'audit-review', submitted.reportPath, input, '--out']), error => error.code === 1 && JSON.parse(error.stdout).errors[0].code === 'USAGE');
});

const directDecision = fixture => decision('F01', { directEvidence: {
  evidenceId: fixture.base.evidenceId, nodeIds: [fixture.node.nodeId],
  criterionClause: '4.1.2 requires a programmatically determinable component name.', explanation: 'Evaluate the retained component naming fields.',
} });

test('missing-name predicates refuse named, associated, truncated and unsupported components', async t => {
  for (const [variant, configure, expected] of [
    ['unnamed-number', () => {}, 1],
    ['aria-named-button', c => { c.node.tag = 'button'; c.node.attributes['aria-label'] = 'Save'; }, 0],
    ['title', c => { c.node.attributes.title = 'Width'; }, 0],
    ['labelledby', c => { c.node.attributes['aria-labelledby'] = 'name'; }, 0],
    ['native-label-receipt', c => { c.node.labelText = 'Width'; }, 0],
    ['explicit-label', c => { c.base.result.nodes.push({ nodeId: 'label', documentId: c.node.documentId, tag: 'label', attributes: { for: 'target' } }); }, 0],
    ['wrapping-label', c => { c.node.parentNodeId = 'label'; c.base.result.nodes.push({ nodeId: 'label', documentId: c.node.documentId, tag: 'label', attributes: {} }); }, 0],
    ['missing-id-is-not-a-label-relation', c => { delete c.node.attributes.id; c.base.result.nodes.push({ nodeId: 'label', documentId: c.node.documentId, tag: 'label', attributes: {} }); }, 1],
    ['truncated-attributes', c => { c.node.attributesTruncated = ['title']; }, 0],
    ['truncated-label', c => { c.node.labelTextTruncated = true; }, 0],
    ['unsupported-input', c => { c.node.attributes.type = 'submit'; }, 0],
    ['named-button-AX', c => { c.node.tag = 'button'; c.base.action = 'inspect'; c.base.result = { element: c.node, ariaSnapshot: '- button "Save"' }; }, 0],
    ['unnamed-button-AX', c => { c.node.tag = 'button'; c.base.action = 'inspect'; c.base.result = { element: c.node, ariaSnapshot: '- button' }; }, 1],
    ['body-ARIA-is-unbound', c => { c.node.tag = 'button'; c.base.result.ariaSnapshot = '- button'; }, 0],
  ]) {
    const fixture = await collectionFixture(t, c => { c.node.tag = 'input'; c.node.attributes.type = 'number'; c.node.text = ''; configure(c); });
    const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, { criterionId: '4.1.2' })]));
    const reviewed = await reviewAudit(submitted.reportPath, adjudication([directDecision(fixture)]));
    assert.equal(reviewed.confirmedFindings.length, expected, variant);
    assert.equal((await checkAudit(reviewed.reportPath)).status, 'current', variant);
  }
});

test('exact criterion tokens and unimplemented semantic predicates cannot confirm a self-citation', async t => {
  const fixture = await collectionFixture(t);
  for (const [criterionId, clause, message] of [
    ['2.4.1', 'Not applicable: see 2.4.11 only', /exact finding criterion token/],
    ['2.4.1', 'x2.4.1 is not a criterion token', /exact finding criterion token/],
    ['2.4.1', '2.4.1 requires bypassing blocks', /No machine-checked semantic predicate/],
  ]) {
    const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, { criterionId })]));
    const d = directDecision(fixture); d.directEvidence.criterionClause = clause;
    const reviewed = await reviewAudit(submitted.reportPath, adjudication([d]));
    assert.equal(reviewed.confirmedFindings.length, 0);
    assert.ok(reviewed.verificationQueue[0].missingEvidence.some(item => message.test(item)));
  }
});

test('missing-name exposure excludes inert and aria-hidden targets and retained ancestors', async t => {
  for (const [variant, mutate, expected] of [
    ['visible-control', () => {}, 1],
    ['target-inert-empty', c => { c.node.attributes.inert = ''; }, 0],
    ['parent-inert-empty', c => { c.parent.attributes.inert = ''; }, 0],
    ['parent-aria-hidden', c => { c.parent.attributes['aria-hidden'] = 'true'; }, 0],
    ['target-aria-hidden-case', c => { c.node.attributes['aria-hidden'] = 'TRUE'; }, 0],
    ['recorded-ancestor-inert', c => { c.node.ancestorSemantics = { complete: true, ancestors: [{ attributes: { inert: '' } }] }; }, 0],
    ['recorded-ancestor-aria-hidden-case', c => { c.node.ancestorSemantics = { complete: true, ancestors: [{ attributes: { 'aria-hidden': ' TRUE ' } }] }; }, 0],
  ]) await t.test(variant, async subtest => {
    const fixture = await collectionFixture(subtest, c => {
      c.node.tag = 'input'; c.node.attributes.type = 'number'; c.node.text = ''; c.node.parentNodeId = 'parent';
      const parent = { nodeId: 'parent', documentId: c.node.documentId, tag: 'div', attributes: {} };
      c.base.result.nodes.push(parent); mutate({ ...c, parent });
    });
    const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture, [finding(fixture, { criterionId: '4.1.2' })]));
    const reviewed = await reviewAudit(submitted.reportPath, adjudication([directDecision(fixture)]));
    assert.equal(reviewed.confirmedFindings.length, expected);
    if (!expected) assert.ok(reviewed.verificationQueue[0].missingEvidence.some(item => /retained ancestor is aria-hidden or inert/.test(item)));
  });
});

test('external output rejects source and foreign runs before writing and public API forwards options', async t => {
  const fixture = await collectionFixture(t);
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  const other = await collectionFixture(t);
  for (const out of [path.join(fixture.root, 'review.json'), path.join(fixture.root, 'evidence', 'outside-run.json'), path.join(other.directory, 'foreign-review.json')]) {
    await assert.rejects(reviewAudit(submitted.reportPath, adjudication([]), { out }), { code: 'UNSAFE_AUDIT_REVIEW_OUTPUT' });
    await assert.rejects(fs.stat(out), { code: 'ENOENT' });
    assert.equal((await checkAudit(fixture.audit.reportPath)).status, 'current');
    assert.equal((await checkAudit(other.audit.reportPath)).status, 'current');
  }
  const { reviewAudit: publicReview } = await import('../src/index.js');
  const out = path.join(fixture.directory, 'explicit-review.json');
  const reviewed = await publicReview(submitted.reportPath, adjudication([]), { out });
  assert.equal(reviewed.reportPath, out);
  assert.deepEqual(reviewed.reviewProgress, { submittedDecisions: 0, unassessedFindings: 1 });
  assert.equal(reviewed.confirmedFindings.length, 0);
  assert.equal((await checkAudit(out)).status, 'current');
});

test('noncanonical malformed files and full-tree copies provide safe path diagnostics', async t => {
  const fixture = await collectionFixture(t);
  const external = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-copy-diagnostic-')));
  t.after(() => fs.rm(external, { recursive: true, force: true }));
  const malformed = path.join(external, 'text.json'); await fs.writeFile(malformed, 'not JSON');
  const checked = await checkAudit(malformed);
  assert.equal(checked.errors[0].code, 'UNSAFE_AUDIT_PATH');
  const copyRoot = path.join(external, 'copy'); await fs.mkdir(copyRoot); await fs.mkdir(path.join(copyRoot, 'evidence'));
  const copyRun = path.join(copyRoot, 'evidence', path.basename(fixture.directory)); await fs.mkdir(copyRun);
  const copy = path.join(copyRun, path.basename(fixture.audit.reportPath)); await fs.copyFile(fixture.audit.reportPath, copy);
  const copied = await checkAudit(copy);
  assert.equal(copied.errors[0].code, 'INVALID_AUDIT_DOCUMENT');
  assert.equal(copied.errors[0].details.canonicalPath, fixture.audit.reportPath);
});

test('legacy and citation-only reports recompute intact but explicitly require re-review in consumers', async t => {
  const fixture = await collectionFixture(t, c => {
    c.node.parentNodeId = 'parent';
    c.base.result.nodes.push({ nodeId: 'parent', documentId: c.node.documentId, tag: 'div', attributes: {} });
  });
  const submitted = await submitAudit(fixture.audit.reportPath, proposal(fixture));
  const d = directDecision(fixture); d.directEvidence.nodeIds.push('parent'); d.directEvidence.criterionClause = '1.3.1 relationships';
  const modern = await reviewAudit(submitted.reportPath, adjudication([d]));
  for (const policy of [undefined, 'dom-citations-v1']) {
    const old = { ...modern, status: 'reviewed', confirmedFindings: [{ ...modern.verificationQueue[0], evidenceGate: { status: 'supported', missingEvidence: [] } }],
      verificationQueue: [], counts: { ...modern.counts, confirmedFindings: 1, verificationQueue: 0 },
      coverage: modern.coverage.map(row => ({ ...row, confirmedFindingIds: row.id === '1.3.1' ? ['F01'] : [] })) };
    delete old.reviewProgress;
    delete old.confirmedFindings[0].missingEvidence;
    if (policy) old.directEvidencePolicy = policy;
    else delete old.directEvidencePolicy;
    const saved = await saveAuditDocument(fixture.directory, 'audit-review', old);
    const before = await fs.readFile(saved.reportPath);
    const checked = await checkAudit(saved.reportPath);
    assert.equal(checked.status, 'needs_review', JSON.stringify(checked.errors));
    assert.equal(checked.reviewPolicy, policy ?? 'legacy-declared');
    assert.equal(checked.requiresReReview, true);
    assert.equal(summarizeAudit(checked).report.requiresReReview, true);
    const { normalizeAuditReport, renderAuditReportHtml } = await import('../src/audit/report-html.js');
    assert.equal(normalizeAuditReport(saved).findings[0].status, 'needs_review');
    assert.match(renderAuditReportHtml(saved), /previous confirmations need re-review/);
    const { deriveAuditInventory } = await import('../src/audit/inventory.js');
    const inventory = deriveAuditInventory({ collection: fixture.audit, report: saved, proposal: submitted });
    assert.equal(inventory.source.requiresReReview, true);
    assert.deepEqual(await fs.readFile(saved.reportPath), before);
  }
});
