import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { digest, fingerprint } from '../src/evidence.js';
import { AUDIT_CATALOG, AUDIT_STANDARD, AUDIT_SCHEMA_VERSION, parseAuditManifest } from '../src/audit/schema.js';
import { AUDIT_EVIDENCE_POLICY, validateAuditEvidencePolicy } from '../src/audit/policy.js';
import { createAuditDirectory, writeAuditArtifact, saveAuditDocument } from '../src/audit/store.js';
import { contrastRatio, relativeLuminance } from '../src/audit/pixels.js';
import { submitAudit, reviewAudit, checkAudit, validateAuditProposalRecords } from '../src/audit/review.js';

// Browserless evidence-contract fixtures, not a browser run or semantic gold labels.
// The left two columns are grey, the right two white: background (3,0) is
// outside target rect (0,0,2,2), and both actual samples have uniform neighbors.
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const name = Buffer.from(type), length = Buffer.alloc(4), crc = Buffer.alloc(4);
  length.writeUInt32BE(data.length); crc.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, crc]);
}
function fixturePng(foreground = 170, background = 255) {
  const header = Buffer.alloc(13); header.writeUInt32BE(4); header.writeUInt32BE(4, 4); header[8] = 8; header[9] = 6;
  const scanlines = Buffer.alloc(4 * 17);
  for (let y = 0; y < 4; y++) for (let x = 0; x < 4; x++) {
    const color = x < 2 ? foreground : background, at = y * 17 + 1 + x * 4;
    scanlines.set([color, color, color, 255], at);
  }
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', deflateSync(scanlines)), chunk('IEND', Buffer.alloc(0))]);
}
const png = fixturePng();
const sample = (x, rgb) => ({
  x, y: 0, rgb, rgba: [...rgb, 255], relativeLuminance: relativeLuminance(rgb),
  neighborhood: { radius: 1, pixels: 4, uniform: true, opaque: true },
});

async function collection(t, configure = () => {}, policy = AUDIT_EVIDENCE_POLICY) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-policy-v2-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'index.html'), '<!doctype html><title>Contract fixture</title><p id="result">Ready</p>');
  const runId = randomUUID(), directory = await createAuditDirectory(root, runId);
  const manifest = parseAuditManifest({ standard: { version: '2.1', targetLevel: 'AA' }, projectRoot: root, url: 'http://localhost:8123/', viewport: { width: 4, height: 4 } });
  const source = await fingerprint(root), documentId = `doc-${randomUUID()}`;
  const html = { nodeId: `${documentId}:html`, documentId, tag: 'html', parentNodeId: null, attributes: {}, attributesTruncated: [] };
  const body = { nodeId: `${documentId}:body`, documentId, tag: 'body', parentNodeId: html.nodeId, attributes: {}, attributesTruncated: [] };
  const node = {
    nodeId: `${documentId}:result`, documentId, parentNodeId: body.nodeId, selector: '#result', tag: 'p',
    attributes: { id: 'result' }, attributesTruncated: [], text: 'Ready', textTruncated: false,
    labelText: '', rect: { x: 0, y: 0, width: 2, height: 2 }, computed: { fontSize: '16px', fontWeight: '400' }, focused: false,
    ancestorSemantics: { complete: true, ancestors: [body, html] },
  };
  const active = { nodeId: `${documentId}:trigger`, documentId, selector: '#trigger', tag: 'button' };
  const state = (name, extra = {}) => ({
    stateId: digest({ name, documentId }), documentId, url: manifest.url, viewport: manifest.viewport, scroll: { x: 0, y: 0 },
    active, controls: [], spacing: { enabled: false }, keyboardOnly: false, inputPath: 'mouse-assisted', ...extra,
  });
  const initial = state('initial'), records = [];
  function add(action, { before = initial, after = before, result = {}, args = {}, image = false, success = true } = {}) {
    const record = { evidenceId: `ev-${String(records.length + 1).padStart(4, '0')}`, action, arguments: args, success, before, after, result };
    if (image) record._image = true;
    records.push(record); return record;
  }
  function dom(observed = initial, observedNode = node) { return add('inspect', { before: observed, args: { selector: observedNode.selector }, result: { element: structuredClone(observedNode) } }); }
  function contrast(observed = initial, observedNode = node) {
    return add('contrast', {
      before: observed, image: true, args: { foreground: { x: 0, y: 0 }, background: { x: 3, y: 0 } },
      result: {
        nodes: [structuredClone(observedNode)], capture: { stable: true, beforeStateId: observed.stateId, afterStateId: observed.stateId },
        contrast: {
          foreground: sample(0, [170, 170, 170]), background: sample(3, [255, 255, 255]), ratio: contrastRatio([170, 170, 170], [255, 255, 255]),
          formula: 'WCAG-relative-luminance-sRGB', srgbThreshold: 0.04045, coefficients: [0.2126, 0.7152, 0.0722], ratioOffset: 0.05,
          alphaPolicy: 'opaque-samples-only', screenshotSha256: 'fixture-png',
        },
      },
    });
  }
  const base = dom(), c = { root, directory, manifest, source, runId, node, initial, state, records, add, dom, contrast, base };
  configure(c);
  for (const record of records) {
    if (record._image) {
      delete record._image;
      const image = record._png ?? png; delete record._png;
      record.png = { ...await writeAuditArtifact(directory, `${record.evidenceId}.png`, image), width: 4, height: 4 };
      if (record.result.contrast?.screenshotSha256 === 'fixture-png') record.result.contrast.screenshotSha256 = record.png.sha256;
    }
    record.json = await writeAuditArtifact(directory, `${record.evidenceId}.json`, `${JSON.stringify(record)}\n`);
  }
  const audit = await saveAuditDocument(directory, 'audit', {
    schemaVersion: AUDIT_SCHEMA_VERSION, runId, manifest, manifestDigest: digest(manifest), standard: AUDIT_STANDARD,
    ...(policy === 'legacy' ? {} : { evidencePolicy: policy }),
    applicationBinding: 'caller-declared', codeFingerprint: source, codeFingerprintAfterRun: source,
    sourceStability: { status: 'stable_observed', eventCount: 0, changedPaths: [], errors: [] }, records, candidates: [],
    coverage: AUDIT_CATALOG.criteria.map(criterion => ({ ...criterion, status: 'not_tested', evidenceIds: [], scope: 'partial' })), errors: [], status: 'collected',
  });
  return { ...c, audit };
}
function finding(c, extra = {}) {
  return {
    id: 'F01', title: 'Recorded local claim', criterionId: '1.3.1', target: { evidenceId: c.base.evidenceId, nodeId: c.node.nodeId },
    evidenceIds: c.records.map(record => record.evidenceId), observation: 'The original local observation.', reason: 'A reviewer must assess the criterion mapping.',
    applicability: 'The claim is limited to this recorded target.', exceptions: 'Relevant exceptions require independent review.', scope: 'This node and observed state only.', ...extra,
  };
}
const proposal = findings => ({ auditor: { name: 'Auditor' }, findings });
const decision = (findingId = 'F01', prerequisiteNotes, extra = {}) => ({
  findingId, verdict: 'supported', checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' },
  reason: 'The independent reviewer assessed these original observations.', ...(prerequisiteNotes ? { prerequisiteNotes } : {}), ...extra,
});
const adjudication = decisions => ({ reviewer: { name: 'Reviewer', independentOfAuditor: true }, decisions });
const bound = record => ({ evidenceId: record.evidenceId, documentId: record.after.documentId, stateId: record.after.stateId, jsonSha256: record.json.sha256 });
const nonTextNotes = record => ({
  contrast: 'The reviewer checked the actual samples and their use in this graphic.',
  v2: { nonTextContrast: { contrastEvidenceId: record.evidenceId, requiredRatio: 3, use: 'The boundary is necessary to identify the enabled control.', adjacentColors: 'Grey foreground next to white surrounding pixels.', exceptions: 'The control is enabled; no inactive or essential-presentation exception applies.' } },
});
const textNotes = alternative => ({
  contrast: 'The text is ordinary 16px non-bold text; the reviewer checked its samples, use and applicable exceptions.',
  v2: { textContrast: { textKind: 'normal', requiredRatio: 4.5, applicability: 'This is readable body text, with no text contrast exception.', alternativePresentation: alternative } },
});
async function reviewed(c, findings, decisions) {
  const submitted = await submitAudit(c.audit.reportPath, proposal(findings));
  return reviewAudit(submitted.reportPath, adjudication(decisions));
}

for (const variant of ['direct-inspect', 'no-direct', 'bulk-only', 'other-state']) test(`native button bulk target needs same-state direct inspect evidence: ${variant}`, async t => {
  let inspected;
  const c = await collection(t, c => {
    Object.assign(c.node, { tag: 'button', text: '', textTruncated: false, labelText: '', labelTextTruncated: false,
      attributes: { id: 'result', type: 'button' }, attributesTruncated: [] });
    c.base.action = 'inspect_many';
    c.base.result = { nodes: [structuredClone(c.node)], elements: [{ nodeId: c.node.nodeId, documentId: c.node.documentId,
      ax: { available: true, role: 'button', name: '' }, flags: ['noAccessibleName'] }] };
    inspected = c.dom(variant === 'other-state' ? c.state('other') : c.initial);
    inspected.result.ariaSnapshot = '- button';
  });
  const directEvidence = { evidenceId: variant === 'bulk-only' ? c.base.evidenceId : inspected.evidenceId,
    nodeIds: [c.node.nodeId], criterionClause: 'WCAG 4.1.2 requires a programmatically determinable name for this button.',
    explanation: 'The reviewer checks the retained native button and the cited name observation.' };
  const result = await reviewed(c, [finding(c, { criterionId: '4.1.2' })],
    [decision('F01', undefined, variant === 'no-direct' ? {} : { directEvidence })]);
  assert.equal(result.confirmedFindings.length, variant === 'direct-inspect' ? 1 : 0);
  if (variant !== 'direct-inspect') assert.equal(result.verificationQueue[0].evidenceGate.status, 'insufficient');
});

test('policy receipt is exact and cannot be selected through a manifest', () => {
  assert.equal(validateAuditEvidencePolicy(undefined), undefined);
  assert.equal(validateAuditEvidencePolicy(AUDIT_EVIDENCE_POLICY), 'audit-evidence-2');
  for (const invalid of ['audit-evidence-1', 'audit-evidence-3', '', null, {}, ['audit-evidence-2']]) {
    assert.throws(() => validateAuditEvidencePolicy(invalid), { code: 'INVALID_AUDIT_EVIDENCE_POLICY' });
  }
  assert.throws(() => parseAuditManifest({ projectRoot: '/tmp/demo', url: 'http://localhost/', evidencePolicy: 'audit-evidence-1' }), { code: 'INVALID_AUDIT_MANIFEST' });
});

test('historical v1 report recomputation retains its exact gate shape and behavior', async t => {
  const c = await collection(t, () => {}, 'legacy');
  // Construct an old report directly: the old 4.1.3 gate had no special branch.
  const f = finding(c, { criterionId: '4.1.3' }), p = proposal([f]), d = decision();
  const gate = { status: 'supported', missingEvidence: [] };
  const sourceAudit = { reportPath: c.audit.reportPath, reportDigest: c.audit.reportDigest, runId: c.audit.runId, manifestDigest: c.audit.manifestDigest };
  const common = {
    schemaVersion: AUDIT_SCHEMA_VERSION, runId: c.audit.runId, manifest: c.manifest, manifestDigest: c.audit.manifestDigest,
    standard: c.audit.standard, codeFingerprint: c.source, sourceStability: c.audit.sourceStability,
    sourceAudit, collection: { reportPath: c.audit.reportPath, reportDigest: c.audit.reportDigest }, candidates: [],
  };
  const coverage = c.audit.coverage.map(row => ({ ...row, status: row.id === f.criterionId ? 'needs_review' : row.status, wholeCriterion: 'not_assessed', findingIds: row.id === f.criterionId ? [f.id] : [], confirmedFindingIds: [] }));
  const targetObservation = { ...f.target, selector: c.node.selector };
  const oldProposal = await saveAuditDocument(c.directory, 'audit-proposal', {
    ...common, ...p, status: 'needs_review', semanticValidation: 'not_reviewed', confirmedFindings: [], rejectedObservations: [],
    verificationQueue: [{ ...f, targetObservation, evidenceGate: gate, missingEvidence: ['Independent per-finding semantic review is required.'] }],
    counts: { originalFindings: 1, confirmedFindings: 0, verificationQueue: 1, rejectedObservations: 0, collectedCandidates: 0 }, coverage,
  });
  const oldReview = await saveAuditDocument(c.directory, 'audit-review', {
    ...common, ...p, ...adjudication([d]), sourceProposal: { reportPath: oldProposal.reportPath, reportDigest: oldProposal.reportDigest },
    status: 'reviewed', semanticValidation: 'reviewer-declared', independence: { basis: 'reviewer-declaration', osVerified: false },
    confirmedFindings: [{ ...f, targetObservation, decision: d, evidenceGate: gate }], verificationQueue: [], rejectedObservations: [],
    counts: { originalFindings: 1, confirmedFindings: 1, verificationQueue: 0, rejectedObservations: 0, collectedCandidates: 0 },
    coverage: coverage.map(row => ({ ...row, confirmedFindingIds: row.id === f.criterionId ? [f.id] : [] })),
  });
  for (const report of [oldProposal, oldReview]) {
    const checked = await checkAudit(report.reportPath);
    assert.equal(checked.status, report.kind === 'audit-review' ? 'needs_review' : 'current', JSON.stringify(checked.errors));
    if (report.kind === 'audit-review') {
      assert.equal(checked.reviewPolicy, 'legacy-declared');
      assert.equal(checked.requiresReReview, true);
      assert.equal(checked.report.confirmedFindings.length, 1, 'Original historical data remains intact, with re-review explicitly required.');
    }
    assert.equal(Object.hasOwn(checked.report, 'evidencePolicy'), false);
  }
  assert.deepEqual(oldReview.confirmedFindings[0].evidenceGate, { status: 'supported', missingEvidence: [] });
});

test('v2 proposals and reviews bind their exact source policy and refuse downgrade substitution', async t => {
  const c = await collection(t), f = finding(c);
  const submitted = await submitAudit(c.audit.reportPath, proposal([f]));
  const result = await reviewAudit(submitted.reportPath, adjudication([decision()]));
  assert.equal(submitted.evidencePolicy, AUDIT_EVIDENCE_POLICY); assert.equal(result.evidencePolicy, AUDIT_EVIDENCE_POLICY);
  assert.equal((await checkAudit(result.reportPath)).status, 'current');
  for (const source of [submitted, result]) {
    for (const value of [undefined, 'audit-evidence-1', { version: AUDIT_EVIDENCE_POLICY }]) {
      const forged = await saveAuditDocument(c.directory, source.kind, { ...source, evidencePolicy: value });
      assert.equal((await checkAudit(forged.reportPath)).status, 'error');
    }
  }
  const legacy = await collection(t, () => {}, 'legacy');
  const historical = await submitAudit(legacy.audit.reportPath, proposal([finding(legacy)]));
  const substituted = await saveAuditDocument(legacy.directory, 'audit-proposal', { ...historical, evidencePolicy: AUDIT_EVIDENCE_POLICY });
  assert.equal((await checkAudit(substituted.reportPath)).status, 'error');
  for (const value of ['audit-evidence-1', null, { version: AUDIT_EVIDENCE_POLICY }]) {
    const malformed = await saveAuditDocument(c.directory, 'audit', { ...c.audit, evidencePolicy: value });
    assert.equal((await checkAudit(malformed.reportPath)).status, 'error');
    await assert.rejects(submitAudit(malformed.reportPath, proposal([f])));
  }
});

test('draft validation checks successful original node references without review', async t => {
  const c = await collection(t), p = proposal([finding(c)]);
  assert.deepEqual(validateAuditProposalRecords(p, c.records), p);
  for (const mutation of [
    { evidenceIds: ['ev-9999'] }, { target: { evidenceId: c.base.evidenceId, nodeId: 'doc-other:node' } }, { method: 'screen_reader' },
  ]) assert.throws(() => validateAuditProposalRecords(proposal([finding(c, mutation)]), c.records));
  assert.throws(() => validateAuditProposalRecords(p, [{ ...c.base, success: false }]), { code: 'INVALID_AUDIT_EVIDENCE_REFERENCE' });
});

test('explicit checkpoint submission persists provenance and revalidates it through review and check', async t => {
  const { saveAuditCheckpoint } = await import('../src/audit/checkpoint.js');
  const c = await collection(t), p = proposal([finding(c)]);
  const checkpoint = await saveAuditCheckpoint({ runId: c.runId, directory: c.directory, records: c.records, proposal: p, context: { evidencePolicy: AUDIT_EVIDENCE_POLICY } });
  const sourceCheckpoint = { checkpointPath: checkpoint.checkpointPath, checkpointDigest: checkpoint.checkpointDigest };
  const submitted = await submitAudit(c.audit.reportPath, p, { sourceCheckpoint });
  assert.deepEqual(JSON.parse(await fs.readFile(submitted.reportPath, 'utf8')).sourceCheckpoint, sourceCheckpoint);
  assert.equal(submitted.status, 'needs_review'); assert.equal(submitted.confirmedFindings.length, 0);
  const result = await reviewAudit(submitted.reportPath, adjudication([decision()]));
  assert.deepEqual(result.sourceCheckpoint, sourceCheckpoint);
  assert.equal((await checkAudit(submitted.reportPath)).status, 'current'); assert.equal((await checkAudit(result.reportPath)).status, 'current');
  await assert.rejects(submitAudit(c.audit.reportPath, p, { sourceCheckpoint: { ...sourceCheckpoint, checkpointDigest: `sha256:${'0'.repeat(64)}` } }), { code: 'AUDIT_CHECKPOINT_BINDING_MISMATCH' });
  await assert.rejects(submitAudit(c.audit.reportPath, proposal([finding(c, { title: 'A different draft' })]), { sourceCheckpoint }), { code: 'AUDIT_CHECKPOINT_BINDING_MISMATCH' });
  await assert.rejects(submitAudit(c.audit.reportPath, p, { sourceCheckpoint, extra: true }), { code: 'INVALID_AUDIT_SUBMIT_OPTIONS' });
  const other = await collection(t), otherProposal = proposal([finding(other)]);
  const otherCheckpoint = await saveAuditCheckpoint({ runId: other.runId, directory: other.directory, records: other.records, proposal: otherProposal, context: { evidencePolicy: AUDIT_EVIDENCE_POLICY } });
  await assert.rejects(submitAudit(c.audit.reportPath, p, { sourceCheckpoint: { checkpointPath: otherCheckpoint.checkpointPath, checkpointDigest: otherCheckpoint.checkpointDigest } }), { code: 'AUDIT_CHECKPOINT_CONTEXT_MISMATCH' });
  for (const changed of [
    { ...result, sourceCheckpoint: undefined },
    { ...result, sourceCheckpoint: { ...sourceCheckpoint, checkpointDigest: `sha256:${'0'.repeat(64)}` } },
  ]) {
    const forged = await saveAuditDocument(c.directory, 'audit-review', changed);
    assert.equal((await checkAudit(forged.reportPath)).status, 'error');
  }
  const forgedProposal = await saveAuditDocument(c.directory, 'audit-proposal', { ...submitted, sourceCheckpoint: { ...sourceCheckpoint, checkpointDigest: `sha256:${'0'.repeat(64)}` } });
  assert.equal((await checkAudit(forgedProposal.reportPath)).status, 'error');
  await fs.appendFile(checkpoint.checkpointPath, ' '); // byte changes are tested by original checkpoint semantic digest below.
  const raw = JSON.parse(await fs.readFile(checkpoint.checkpointPath, 'utf8')); raw.proposal.findings[0].title = 'Changed checkpoint';
  await fs.writeFile(checkpoint.checkpointPath, JSON.stringify(raw));
  assert.equal((await checkAudit(submitted.reportPath)).status, 'error'); assert.equal((await checkAudit(result.reportPath)).status, 'error');
});

test('v2 non-text contrast refuses screenshot-only and malformed prerequisites', async t => {
  for (const variant of ['screenshot-only', 'wrong-state', 'wrong-png', 'forged-pixels', 'outside-foreground', 'passing-ratio', 'missing-review']) {
    const c = await collection(t, c => {
      const state = variant === 'wrong-state' ? c.state('other') : c.initial;
      c.measurement = c.contrast(state);
      if (variant === 'screenshot-only') { c.measurement.action = 'screenshot'; delete c.measurement.result.contrast; }
      if (variant === 'wrong-png') c.measurement.result.contrast.screenshotSha256 = 'wrong';
      if (variant === 'forged-pixels') {
        c.measurement.result.contrast.foreground = sample(0, [255, 255, 255]); c.measurement.result.contrast.ratio = 1;
      }
      if (variant === 'outside-foreground') {
        c.measurement.arguments.foreground.x = 3; c.measurement.result.contrast.foreground = sample(3, [255, 255, 255]); c.measurement.result.contrast.ratio = 1;
      }
      if (variant === 'passing-ratio') {
        c.measurement._png = fixturePng(170, 0);
        c.measurement.result.contrast.background = sample(3, [0, 0, 0]);
        c.measurement.result.contrast.ratio = contrastRatio([170, 170, 170], [0, 0, 0]);
      }
    });
    const result = await reviewed(c, [finding(c, { criterionId: '1.4.11' })], [decision('F01', variant === 'missing-review' ? undefined : nonTextNotes(c.measurement))]);
    assert.equal(result.confirmedFindings.length, 0, variant); assert.equal(result.verificationQueue.length, 1, variant);
  }
});

test('v2 non-text contrast supports original low-contrast pixels with background outside the component', async t => {
  const c = await collection(t, c => { c.measurement = c.contrast(); });
  const result = await reviewed(c, [finding(c, { criterionId: '1.4.11' })], [decision('F01', nonTextNotes(c.measurement))]);
  assert.equal(c.measurement.result.contrast.background.x > c.node.rect.x + c.node.rect.width, true);
  assert.equal(result.confirmedFindings.length, 1);
  assert.equal(result.confirmedFindings[0].evidenceGate.semanticAssessment, 'reviewer-dependent');
  assert.equal((await checkAudit(result.reportPath)).status, 'current');
});

test('v2 non-text contrast refuses foreign targets, unstable captures and fabricated ratios', async t => {
  for (const variant of ['wrong-document', 'wrong-node', 'unstable-capture', 'fabricated-ratio']) {
    const c = await collection(t, c => {
      const state = variant === 'wrong-document' ? c.state('foreign', { documentId: 'doc-other' }) : c.initial;
      const node = { ...c.node, documentId: state.documentId, ...(variant === 'wrong-node' ? { nodeId: `${c.node.nodeId}-other` } : {}) };
      c.measurement = c.contrast(state, node);
      if (variant === 'unstable-capture') c.measurement.result.capture.stable = false;
      if (variant === 'fabricated-ratio') c.measurement.result.contrast.ratio += 0.1;
    });
    const result = await reviewed(c, [finding(c, { criterionId: '1.4.11' })], [decision('F01', nonTextNotes(c.measurement))]);
    assert.equal(result.confirmedFindings.length, 0, variant);
    assert.equal(result.verificationQueue.length, 1, variant);
    assert.equal(result.verificationQueue[0].evidenceGate.status, 'insufficient', variant);
    assert.match(result.verificationQueue[0].missingEvidence.join(' '), /same-state target-bound original PNG/, variant);
  }
});

test('v2 non-text contrast uses the 3:1 threshold with original pixels on either side', async t => {
  for (const foreground of [149, 148]) {
    const rgb = [foreground, foreground, foreground], ratio = contrastRatio(rgb, [255, 255, 255]);
    const c = await collection(t, c => {
      c.measurement = c.contrast(); c.measurement._png = fixturePng(foreground);
      c.measurement.result.contrast.foreground = sample(0, rgb);
      c.measurement.result.contrast.ratio = ratio;
    });
    const result = await reviewed(c, [finding(c, { criterionId: '1.4.11' })], [decision('F01', nonTextNotes(c.measurement))]);
    assert.equal(ratio < 3, foreground === 149);
    assert.equal(result.confirmedFindings.length, foreground === 149 ? 1 : 0);
    assert.equal(result.verificationQueue.length, foreground === 149 ? 0 : 1);
    if (foreground === 148) assert.match(result.verificationQueue[0].missingEvidence.join(' '), /3:1 non-text threshold/);
  }
});

test('v2 non-text contrast requires intact original PNG and JSON bytes', async t => {
  for (const artifact of ['png', 'json']) {
    const c = await collection(t, c => { c.measurement = c.contrast(); });
    const findings = [finding(c, { criterionId: '1.4.11' })];
    const result = await reviewed(c, findings, [decision('F01', nonTextNotes(c.measurement))]);
    assert.equal(result.confirmedFindings.length, 1, artifact);
    assert.equal((await checkAudit(result.reportPath)).status, 'current', artifact);
    await fs.appendFile(c.measurement[artifact].path, '\n');
    const checked = await checkAudit(result.reportPath);
    assert.equal(checked.status, 'error', artifact);
    assert.equal(checked.errors[0].code, 'AUDIT_ARTIFACT_INTEGRITY_MISMATCH', artifact);
    await assert.rejects(submitAudit(c.audit.reportPath, proposal(findings)), { code: 'INVALID_AUDIT_EVIDENCE' });
  }
});

function statusScenario(c, variant) {
  const changed = !['no-change', 'same-text'].includes(variant), afterState = variant === 'no-change' ? c.initial : c.state('result-updated');
  const afterNode = structuredClone(c.node); afterNode.text = changed ? '2 results found' : 'Ready';
  if (variant === 'focused') { afterNode.focused = true; afterState.active = afterNode; }
  if (variant === 'missing-ancestry') delete afterNode.ancestorSemantics;
  if (variant === 'truncated-ancestor') afterNode.ancestorSemantics.ancestors[0].attributesTruncated = ['aria-live'];
  if (variant === 'ancestor-live') afterNode.ancestorSemantics.ancestors[0].attributes['aria-live'] = 'polite';
  if (variant === 'native-output') afterNode.tag = 'output';
  if (variant === 'native-progress') afterNode.tag = 'progress';
  if (variant === 'status-role') afterNode.attributes.role = 'status';
  if (variant === 'cross-document') {
    afterState.documentId = 'doc-other'; afterNode.documentId = 'doc-other';
    afterNode.ancestorSemantics.ancestors.forEach(node => { node.documentId = 'doc-other'; });
  }
  c.operation = c.add('click', { before: c.initial, after: afterState, args: { selector: '#trigger' }, result: { clicked: true } });
  if (variant === 'wrong-operation-state') c.operation.before = c.state('unrelated');
  c.after = c.dom(afterState, afterNode);
}
function statusNotes(c, variant) {
  return { v2: { statusMessage: {
    beforeEvidenceId: c.base.evidenceId, operationEvidenceId: variant === 'missing-operation' ? c.base.evidenceId : c.operation.evidenceId,
    afterEvidenceId: c.after.evidenceId, applicability: 'The action updates a count without moving focus.',
    resultKind: variant === 'substantive-result' ? 'substantive-result' : 'status-summary',
    semanticReview: 'The reviewer treats the count as a status summary and reviewed the recorded target and all ancestor ARIA attributes; this is not screen-reader output.',
  } } };
}
test('v2 status messages require changed original content, actual operation, focus, ancestry and semantic applicability', async t => {
  for (const variant of ['no-change', 'same-text', 'missing-operation', 'wrong-operation-state', 'cross-document', 'focused', 'missing-ancestry', 'truncated-ancestor', 'ancestor-live', 'native-output', 'native-progress', 'status-role', 'substantive-result', 'missing-review', 'complete']) {
    const c = await collection(t, c => statusScenario(c, variant));
    const result = await reviewed(c, [finding(c, { criterionId: '4.1.3', target: { evidenceId: c.after.evidenceId, nodeId: c.node.nodeId } })], [decision('F01', variant === 'missing-review' ? undefined : statusNotes(c, variant))]);
    assert.equal(result.confirmedFindings.length, variant === 'complete' ? 1 : 0, variant);
    if (variant === 'complete') {
      assert.notEqual(c.base.after.stateId, c.after.after.stateId);
      assert.equal(result.confirmedFindings[0].evidenceGate.semanticAssessment, 'reviewer-dependent');
      assert.equal((await checkAudit(result.reportPath)).status, 'current');
    }
    if (variant === 'no-change') assert.match(result.verificationQueue[0].missingEvidence.join(' '), /changed, untruncated result text/);
  }
});

test('v2 status messages support retained click, global press and redacted fill operations', async t => {
  for (const action of ['click', 'press', 'fill']) {
    const c = await collection(t, c => {
      statusScenario(c, 'complete');
      c.operation.action = action;
      if (action === 'press') {
        c.operation.arguments = { key: 'Enter' };
        c.operation.result = { key: 'Enter', keyboardOnly: false, inputPath: 'mouse-assisted', keyboardPath: [{ key: 'Enter', documentId: c.initial.documentId, activeBefore: c.initial.active.nodeId }] };
      } else {
        if (action === 'fill') c.initial.active.tag = 'input';
        c.operation.arguments = { selector: '#trigger', ...(action === 'fill' ? { value: '[omitted]' } : {}) };
        c.operation.result = { target: { ...structuredClone(c.node), ...c.initial.active, attributes: { id: 'trigger' }, text: action === 'fill' ? '' : 'Search', focused: true }, [action === 'fill' ? 'filled' : 'clicked']: true, keyboardOnly: false, inputPath: 'mouse-assisted' };
      }
    });
    const result = await reviewed(c, [finding(c, { criterionId: '4.1.3', target: { evidenceId: c.after.evidenceId, nodeId: c.node.nodeId } })], [decision('F01', statusNotes(c))]);
    assert.equal(result.confirmedFindings.length, 1, action);
    assert.equal(result.verificationQueue.length, 0, action);
    assert.notEqual(c.base.after.stateId, c.after.after.stateId, action);
    assert.equal(result.confirmedFindings[0].evidenceGate.semanticAssessment, 'reviewer-dependent', action);
    assert.equal((await checkAudit(result.reportPath)).status, 'current', action);
    if (action === 'fill') {
      const retained = JSON.parse(await fs.readFile(c.operation.json.path, 'utf8'));
      assert.deepEqual(retained.arguments, { selector: '#trigger', value: '[omitted]' });
    }
  }
});

test('v2 status messages refuse invalid observation boundaries, operations, text and focus', async t => {
  for (const variant of ['wrong-before-node', 'unstable-before', 'unstable-after', 'wrong-operation-after-state', 'wrong-order', 'wait-only', 'failed-operation', 'uncited-operation', 'changed-text-same-state', 'truncated-before-text', 'truncated-after-text', 'missing-focus', 'active-target', 'wrong-after-reference']) {
    const c = await collection(t, c => {
      statusScenario(c, 'complete');
      if (variant === 'wrong-before-node') c.base.result.element.nodeId += '-other';
      if (variant === 'unstable-before') c.base.before = c.state('before-raced');
      if (variant === 'unstable-after') c.after.before = c.state('after-raced');
      if (variant === 'wrong-operation-after-state') c.operation.after = c.state('unrelated-after');
      if (variant === 'wrong-order') {
        c.records.push(...c.records.splice(1, 1));
        c.records.forEach((record, index) => { record.evidenceId = `ev-${String(index + 1).padStart(4, '0')}`; });
      }
      if (variant === 'wait-only') { c.operation.action = 'wait'; c.operation.arguments = { ms: 0 }; c.operation.result = { waitedMs: 0 }; }
      if (variant === 'failed-operation') c.operation.success = false;
      if (variant === 'changed-text-same-state') c.operation.after = c.after.before = c.after.after = c.initial;
      if (variant === 'truncated-before-text') c.base.result.element.textTruncated = true;
      if (variant === 'truncated-after-text') c.after.result.element.textTruncated = true;
      if (variant === 'missing-focus') c.after.after.active = null;
      if (variant === 'active-target') c.after.after.active = structuredClone(c.after.result.element);
    });
    const f = finding(c, { criterionId: '4.1.3', target: { evidenceId: c.after.evidenceId, nodeId: c.node.nodeId } });
    if (variant === 'failed-operation') {
      await assert.rejects(submitAudit(c.audit.reportPath, proposal([f])), { code: 'INVALID_AUDIT_EVIDENCE_REFERENCE' });
      continue;
    }
    if (variant === 'uncited-operation') f.evidenceIds = f.evidenceIds.filter(id => id !== c.operation.evidenceId);
    const notes = statusNotes(c);
    if (variant === 'wrong-after-reference') notes.v2.statusMessage.afterEvidenceId = c.base.evidenceId;
    const result = await reviewed(c, [f], [decision('F01', notes)]);
    assert.equal(result.confirmedFindings.length, 0, variant);
    assert.equal(result.verificationQueue.length, 1, variant);
    assert.equal(result.verificationQueue[0].evidenceGate.status, 'insufficient', variant);
    assert.ok(result.verificationQueue[0].missingEvidence.length, variant);
  }
});

test('v2 status messages require complete lineage and review existing target or ancestor semantics', async t => {
  for (const variant of ['broken-parent', 'missing-html', 'incomplete-chain', 'duplicate-ancestor', 'cross-document-ancestor', 'truncated-target', 'missing-before-chain', 'live-before', 'target-live', 'ancestor-role', 'native-meter']) {
    const c = await collection(t, c => {
      statusScenario(c, 'complete');
      const before = c.base.result.element, after = c.after.result.element, chain = after.ancestorSemantics;
      if (variant === 'broken-parent') after.parentNodeId += '-unobserved';
      if (variant === 'missing-html') chain.ancestors.pop();
      if (variant === 'incomplete-chain') chain.complete = false;
      if (variant === 'duplicate-ancestor') chain.ancestors.unshift(structuredClone(chain.ancestors[0]));
      if (variant === 'cross-document-ancestor') chain.ancestors[0].documentId = 'doc-other';
      if (variant === 'truncated-target') after.attributesTruncated = ['role'];
      if (variant === 'missing-before-chain') delete before.ancestorSemantics;
      if (variant === 'live-before') before.attributes['aria-live'] = 'assertive';
      if (variant === 'target-live') after.attributes['aria-live'] = 'polite';
      if (variant === 'ancestor-role') chain.ancestors[0].attributes.role = 'alert';
      if (variant === 'native-meter') after.tag = 'meter';
    });
    const result = await reviewed(c, [finding(c, { criterionId: '4.1.3', target: { evidenceId: c.after.evidenceId, nodeId: c.node.nodeId } })], [decision('F01', statusNotes(c))]);
    assert.equal(result.confirmedFindings.length, 0, variant);
    assert.equal(result.verificationQueue.length, 1, variant);
    const semanticsPresent = ['live-before', 'target-live', 'ancestor-role', 'native-meter'].includes(variant);
    assert.match(result.verificationQueue[0].missingEvidence.join(' '), semanticsPresent ? /live-region semantics require further review/ : /complete original target-to-html ancestor semantics/, variant);
  }
});

test('v2 non-text contrast and status messages require explicit structured semantic notes', async t => {
  for (const criterionId of ['1.4.11', '4.1.3']) {
    const c = await collection(t, c => { c.measurement = c.contrast(); statusScenario(c, 'complete'); });
    const f = finding(c, { criterionId, ...(criterionId === '4.1.3' ? { target: { evidenceId: c.after.evidenceId, nodeId: c.node.nodeId } } : {}) });
    const notes = criterionId === '1.4.11' ? nonTextNotes(c.measurement) : statusNotes(c);
    const section = criterionId === '1.4.11' ? 'nonTextContrast' : 'statusMessage';
    const fields = criterionId === '1.4.11' ? ['use', 'adjacentColors', 'exceptions'] : ['applicability', 'semanticReview'];
    const submitted = await submitAudit(c.audit.reportPath, proposal([f]));
    const supported = await reviewAudit(submitted.reportPath, adjudication([decision('F01', notes)]));
    assert.equal(supported.confirmedFindings.length, 1, criterionId);
    for (const field of fields) for (const missing of [true, false]) {
      const incomplete = structuredClone(notes);
      if (missing) delete incomplete.v2[section][field];
      else incomplete.v2[section][field] = '   ';
      await assert.rejects(reviewAudit(submitted.reportPath, adjudication([decision('F01', incomplete)])), { code: 'INVALID_AUDIT_ADJUDICATION' });
    }
    assert.equal(submitted.status, 'needs_review'); assert.equal(submitted.confirmedFindings.length, 0);
    assert.equal((await checkAudit(submitted.reportPath)).status, 'current');
  }
});

test('v2 status messages reject present notes with missing before, after or operation evidence references', async t => {
  const c = await collection(t, c => statusScenario(c, 'complete'));
  const f = finding(c, { criterionId: '4.1.3', target: { evidenceId: c.after.evidenceId, nodeId: c.node.nodeId } });
  const notes = statusNotes(c);
  const submitted = await submitAudit(c.audit.reportPath, proposal([f]));
  assert.equal(submitted.status, 'needs_review');
  const supported = await reviewAudit(submitted.reportPath, adjudication([decision('F01', notes)]));
  assert.equal(supported.confirmedFindings.length, 1);

  const fields = ['beforeEvidenceId', 'afterEvidenceId', 'operationEvidenceId'];
  for (const dropped of [fields, ...fields.map(field => [field])]) {
    const incomplete = structuredClone(notes);
    // Keep statusMessage, applicability and semanticReview; only references are absent.
    for (const field of dropped) delete incomplete.v2.statusMessage[field];
    await assert.rejects(
      reviewAudit(submitted.reportPath, adjudication([decision('F01', incomplete)])),
      { code: 'INVALID_AUDIT_ADJUDICATION' },
      `Present statusMessage notes missing ${dropped.join(', ')}`,
    );
    assert.equal(submitted.status, 'needs_review');
    assert.equal(submitted.confirmedFindings.length, 0);
  }
  const checked = await checkAudit(submitted.reportPath);
  assert.equal(checked.status, 'current');
  assert.equal(checked.report.status, 'needs_review');
  assert.equal(checked.report.confirmedFindings.length, 0);
});

function alternateScenario(c, reverse = false) {
  c.defaultContrast = c.contrast(); c.alternate = c.state('alternate');
  c.activate = c.add('click', { before: c.initial, after: c.alternate, args: { selector: '#theme' }, result: { clicked: true } });
  c.alternateDom = c.dom(c.alternate); c.alternateContrast = c.contrast(c.alternate);
  if (reverse) {
    c.deactivate = c.add('click', { before: c.alternate, after: c.initial, args: { selector: '#theme' }, result: { clicked: true } });
    c.returnDom = c.dom(c.initial);
  }
}
function evaluatedAlternative(c, dependencies, extra = {}) {
  return {
    kind: 'evaluated', explanation: 'The recorded control activates a distinct presentation of the same information and functions.', alternateState: bound(c.alternateDom),
    control: { status: 'supported', explanation: 'The recorded control is usable and its relevant conditions were reviewed.', evidenceIds: [c.activate.evidenceId, c.alternateDom.evidenceId] },
    equivalence: { status: 'supported', explanation: 'The reviewer compared equivalent information and functionality.', evidenceIds: [c.alternateDom.evidenceId] },
    targetLevel: { status: 'counterexample', explanation: 'A supported failure was measured in this same alternate state.', dependencies }, ...extra,
  };
}
const dependencyReference = (findingId, observed, evidence) => ({ ...bound(observed), findingId, evidenceIds: [observed.evidenceId, evidence.evidenceId] });

test('v2 text contrast requires explicit alternatives and never treats an incomplete audit as a failure', async t => {
  const c = await collection(t, alternateScenario);
  for (const alternative of [
    { kind: 'unverified', explanation: 'The available alternative has not been fully audited.' },
    evaluatedAlternative(c, [], { targetLevel: { status: 'not-fully-audited', explanation: 'Other criteria remain untested.', dependencies: [] } }),
    evaluatedAlternative(c, [], { targetLevel: { status: 'supported', explanation: 'The reviewer supports the target-level alternative.', dependencies: [] } }),
  ]) {
    const result = await reviewed(c, [finding(c, { criterionId: '1.4.3' })], [decision('F01', textNotes(alternative))]);
    assert.equal(result.confirmedFindings.length, 0); assert.equal(result.rejectedObservations.length, 0); assert.equal(result.verificationQueue.length, 1);
    assert.match(result.verificationQueue[0].missingEvidence.join(' '), /not.*failure|not disproved/);
  }
  const missing = await reviewed(c, [finding(c, { criterionId: '1.4.3' })], [decision('F01', { contrast: 'Text and exceptions reviewed.' })]);
  assert.equal(missing.confirmedFindings.length, 0);
  const none = await reviewed(c, [finding(c, { criterionId: '1.4.3' })], [decision('F01', textNotes({ kind: 'none-observed', explanation: 'The reviewer inspected the recorded available controls and found no alternative.', evidenceIds: [c.base.evidenceId] }))]);
  assert.equal(none.confirmedFindings.length, 1);
});

test('v2 text contrast cannot label recorded large text as normal to claim a stricter threshold', async t => {
  for (const [fontSize, fontWeight] of [['24px', '400'], ['20px', '700']]) {
    const c = await collection(t, c => {
      c.node.computed = { fontSize, fontWeight };
      c.base.result.element.computed = { fontSize, fontWeight };
      const pixels = c.contrast(); pixels._png = fixturePng(140);
      pixels.result.contrast.foreground = sample(0, [140, 140, 140]);
      pixels.result.contrast.ratio = contrastRatio([140, 140, 140], [255, 255, 255]);
    });
    const notes = textNotes({ kind: 'none-observed', explanation: 'No alternative was observed in this fixture.', evidenceIds: [c.base.evidenceId] });
    const result = await reviewed(c, [finding(c, { criterionId: '1.4.3' })], [decision('F01', notes)]);
    assert.equal(result.confirmedFindings.length, 0);
    assert.equal(result.verificationQueue.length, 1);
    assert.match(result.verificationQueue[0].missingEvidence.join(' '), /text.*threshold|actual text size/i);
    assert.equal((await checkAudit(result.reportPath)).status, 'current');
    notes.v2.textContrast.textKind = 'large'; notes.v2.textContrast.requiredRatio = 3;
    const declaredLarge = await reviewed(c, [finding(c, { criterionId: '1.4.3' })], [decision('F01', notes)]);
    assert.equal(declaredLarge.confirmedFindings.length, 0);
  }
});

test('same-alternate-state supported counterexample dependencies can support the text-contrast assessment', async t => {
  const c = await collection(t, alternateScenario), dep = dependencyReference('F02', c.alternateDom, c.alternateContrast);
  const findings = [finding(c, { criterionId: '1.4.3' }), finding(c, { id: 'F02', criterionId: '1.4.11', target: { evidenceId: c.alternateDom.evidenceId, nodeId: c.node.nodeId }, evidenceIds: dep.evidenceIds })];
  const result = await reviewed(c, findings, [decision('F01', textNotes(evaluatedAlternative(c, [dep]))), decision('F02', nonTextNotes(c.alternateContrast))]);
  assert.equal(result.confirmedFindings.length, 2);
  assert.equal((await checkAudit(result.reportPath)).status, 'current');
});

test('missing, default-state, wrong-digest and invalidated alternate dependencies are refused', async t => {
  for (const variant of ['missing', 'empty', 'wrong-digest', 'default-state', 'invalidated', 'invalidated-gate', 'default-masquerade']) {
    const c = await collection(t, alternateScenario);
    const originalState = variant === 'default-state', observed = originalState ? c.base : c.alternateDom, contrast = originalState ? c.defaultContrast : c.alternateContrast;
    const dep = dependencyReference(variant === 'missing' ? 'unknown' : 'F02', observed, contrast);
    if (variant === 'wrong-digest') dep.jsonSha256 = '0'.repeat(64);
    const alternative = evaluatedAlternative(c, variant === 'empty' ? [] : [dep]);
    if (variant === 'default-masquerade') alternative.alternateState = bound(c.base);
    const findings = [finding(c, { criterionId: '1.4.3' }), finding(c, { id: 'F02', criterionId: '1.4.11', target: { evidenceId: observed.evidenceId, nodeId: c.node.nodeId }, evidenceIds: [observed.evidenceId, contrast.evidenceId] })];
    const result = await reviewed(c, findings, [decision('F01', textNotes(alternative)), decision('F02', variant === 'invalidated-gate' ? undefined : nonTextNotes(contrast), variant === 'invalidated' ? { verdict: 'rejected' } : {})]);
    assert.equal(result.confirmedFindings.some(f => f.id === 'F01'), false, variant);
    assert.match(result.verificationQueue.find(f => f.id === 'F01').missingEvidence.join(' '), /dependencies|default-state/, variant);
  }
});

test('circular same-state alternative dependencies cannot confirm either finding', async t => {
  const c = await collection(t, c => alternateScenario(c, true));
  const depB = dependencyReference('F02', c.alternateDom, c.alternateContrast), depA = dependencyReference('F01', c.base, c.defaultContrast);
  const altA = evaluatedAlternative(c, [depB]);
  const altB = evaluatedAlternative(c, [depA], {
    alternateState: bound(c.returnDom),
    control: { status: 'supported', explanation: 'The reverse control returns to the original presentation.', evidenceIds: [c.deactivate.evidenceId, c.returnDom.evidenceId] },
  });
  const findings = [finding(c, { criterionId: '1.4.3' }), finding(c, { id: 'F02', criterionId: '1.4.3', target: { evidenceId: c.alternateDom.evidenceId, nodeId: c.node.nodeId } })];
  const result = await reviewed(c, findings, [decision('F01', textNotes(altA)), decision('F02', textNotes(altB))]);
  assert.equal(result.confirmedFindings.length, 0); assert.equal(result.verificationQueue.length, 2);
  assert.ok(result.verificationQueue.every(f => f.missingEvidence.some(message => message.includes('acyclic'))));
});
