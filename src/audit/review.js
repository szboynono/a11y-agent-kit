import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { digest, errorRecord, ToolError } from '../evidence.js';
import { AUDIT_CATALOG, AUDIT_SCHEMA_VERSION, resolveAuditStandard, parseAuditManifest } from './schema.js';
import { checkAuditCollection, readAuditDocument, saveAuditDocument, saveExternalAuditReview } from './store.js';
import { contrastRatio, decodePng, pixelAt } from './pixels.js';
import { AUDIT_EVIDENCE_POLICY, VISUAL_CRITERIA, validateAuditEvidencePolicy } from './policy.js';
import { expandAxeAdoption, deriveAxeCandidates } from './axe-candidates.js';
import { zodIssueDetails } from './error-details.js';
import { stableSelectorIndex } from './stable-selector.js';
import { CURRENT_REVIEW_POLICY, reviewPolicyOf, requiresReReview } from './review-policy.js';
import { summarizeGaps } from './gaps.js';

const criterionIds = new Set([...AUDIT_CATALOG.criteria, ...resolveAuditStandard({ version: '2.2', targetLevel: 'AA' }).criteria].map(criterion => criterion.id));
const text = z.string().trim().min(1).max(20000).refine(value => !value.includes('\0'));
const id = text.max(300);
/** Bounds for the optional maker notes on a finding: list length and characters per string. */
export const FINDING_NOTE_LIMITS = Object.freeze({ counterevidenceItems: 10, counterevidenceItem: 1000, confidenceRationale: 2000 });
const identity = z.object({ name: text.max(200), model: text.max(300).optional() }).strict();
const findingSchema = z.object({
  id,
  title: text.max(1000),
  criterionId: id.refine(value => criterionIds.has(value), 'criterionId must belong to the supported WCAG catalogs.'),
  target: z.object({ evidenceId: id, nodeId: id }).strict(),
  evidenceIds: z.array(id).min(1).max(500),
  observation: text,
  reason: text,
  applicability: text,
  exceptions: text,
  scope: text,
  method: z.enum(['dom', 'visual', 'keyboard', 'combined', 'screen_reader']).optional(),
  // Both or neither; validateProposal verifies the pair against the retained axe violation.
  source: z.literal('axe').optional(),
  axeCandidateId: id.optional(),
  // Optional maker notes, additive and never required: observations that were tried but did not support the claim,
  // and why the maker considers the claim established. No evidence gate, review outcome or count reads them.
  counterevidence: z.array(text.max(FINDING_NOTE_LIMITS.counterevidenceItem)).min(1).max(FINDING_NOTE_LIMITS.counterevidenceItems).optional(),
  confidenceRationale: text.max(FINDING_NOTE_LIMITS.confidenceRationale).optional(),
}).strict();
const proposalSchema = z.object({ auditor: identity, findings: z.array(findingSchema).max(1000) }).strict();
const checkValue = z.enum(['supported', 'insufficient', 'contradicted']);
const evidenceIds = z.array(id).min(1).max(500).refine(values => new Set(values).size === values.length, 'Evidence identifiers must be unique.');
const stateReference = z.object({ evidenceId: id, documentId: id, stateId: id, jsonSha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
const alternateCheck = z.object({ status: checkValue, explanation: text, evidenceIds }).strict();
const dependency = stateReference.extend({ findingId: id, evidenceIds }).strict();
const alternativePresentation = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('none-observed'), explanation: text, evidenceIds }).strict(),
  z.object({ kind: z.literal('unverified'), explanation: text }).strict(),
  z.object({
    kind: z.literal('evaluated'), explanation: text, alternateState: stateReference,
    control: alternateCheck, equivalence: alternateCheck,
    targetLevel: z.object({
      status: z.enum(['supported', 'not-fully-audited', 'counterexample']), explanation: text,
      dependencies: z.array(dependency).max(100),
    }).strict(),
  }).strict(),
]);
const prerequisiteNotesV2 = z.object({
  nonTextContrast: z.object({ contrastEvidenceId: id, requiredRatio: z.literal(3), use: text, adjacentColors: text, exceptions: text }).strict().optional(),
  statusMessage: z.object({
    beforeEvidenceId: id, operationEvidenceId: id, afterEvidenceId: id, settledEvidenceId: id.optional(),
    applicability: text, resultKind: z.enum(['status-summary', 'substantive-result', 'uncertain']), semanticReview: text,
  }).strict().optional(),
  textContrast: z.object({
    textKind: z.enum(['normal', 'large']), requiredRatio: z.union([z.literal(3), z.literal(4.5)]),
    applicability: text, alternativePresentation,
  }).strict().optional(),
}).strict();
const decisionSchema = z.object({
  findingId: id,
  verdict: z.enum(['supported', 'insufficient', 'rejected']),
  checks: z.object({
    evidenceSupport: checkValue,
    criterionMapping: checkValue,
    scope: checkValue,
    prerequisites: checkValue,
  }).strict(),
  reason: text,
  missingEvidence: z.array(text).max(100).optional(),
  directEvidence: z.object({ evidenceId: id, nodeIds: z.array(id).min(1).max(100), criterionClause: text, explanation: text }).strict().optional(),
  prerequisiteNotes: z.object({ alternativePresentation: text.optional(), exceptions: text.optional(), contrast: text.optional(), v2: prerequisiteNotesV2.optional() }).strict().optional(),
}).strict();
const adjudicationSchema = z.object({
  reviewer: identity.extend({ independentOfAuditor: z.literal(true) }).strict(),
  decisions: z.array(decisionSchema).max(1000),
}).strict();
const sourceCheckpointSchema = z.object({ checkpointPath: text, checkpointDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/) }).strict();
const submitOptionsSchema = z.object({ sourceCheckpoint: sourceCheckpointSchema.optional() }).strict();

function parse(schema, input, code) {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new ToolError(code, 'Audit input validation failed.', zodIssueDetails(result.error.issues));
  }
  return result.data;
}

function fail(code, message) { throw new ToolError(code, message); }
function same(a, b) { return a === undefined || b === undefined ? a === b : digest(a) === digest(b); }
function sameState(a, b) {
  return Boolean(a?.stateId && a?.documentId && a.stateId === b?.stateId && a.documentId === b?.documentId);
}
function nodes(record) {
  return [...(Array.isArray(record.result?.nodes) ? record.result.nodes : []),
    ...(record.result?.element ? [record.result.element] : [])];
}
function nodeIn(record, target) {
  return nodes(record).find(node => node.nodeId === target.nodeId && node.documentId === record.after?.documentId);
}

function validateCollection(audit) {
  if (audit?.kind !== 'audit' || audit.schemaVersion !== AUDIT_SCHEMA_VERSION) fail('INVALID_AUDIT', 'An audit-1 collection is required.');
  validateAuditEvidencePolicy(audit.evidencePolicy);
  const manifest = parseAuditManifest(audit.manifest);
  if (!same(manifest, audit.manifest) || audit.manifestDigest !== digest(manifest)) fail('AUDIT_CONTRACT_MISMATCH', 'The recorded manifest is not the normalized collection contract.');
  const standard = resolveAuditStandard(manifest.standard);
  const criterionIds = new Set(standard.criteria.map(row => row.id));
  if (!same(audit.standard, standard)) fail('AUDIT_STANDARD_MISMATCH', 'The collection must use the supported WCAG catalogs.');
  const coverageIds = audit.coverage?.map(item => item.id);
  if (!Array.isArray(coverageIds) || coverageIds.length !== criterionIds.size || new Set(coverageIds).size !== criterionIds.size || coverageIds.some(value => !criterionIds.has(value))) {
    fail('AUDIT_COVERAGE_MISMATCH', 'All selected catalog criteria must remain in the collection coverage.');
  }
  if (!Array.isArray(audit.records) || !Array.isArray(audit.candidates)) fail('INVALID_AUDIT', 'Audit records and candidates are required.');
  const ids = new Set();
  for (const record of audit.records) {
    if (!record?.evidenceId || ids.has(record.evidenceId)) fail('INVALID_AUDIT_EVIDENCE', 'Collection evidence identifiers must be present and unique.');
    ids.add(record.evidenceId);
  }
  return audit;
}

async function currentCollection(reportPath) {
  const checked = await checkAuditCollection(reportPath);
  if (checked.status !== 'current' || !checked.report) {
    throw new ToolError(checked.status === 'expired' ? 'AUDIT_EXPIRED' : 'INVALID_AUDIT_EVIDENCE',
      'The source audit must have intact attachments and current source bindings.', checked.errors);
  }
  const audit = validateCollection(checked.report);
  if (audit.evidencePolicy === AUDIT_EVIDENCE_POLICY) await verifyOriginalContrastPixels(audit);
  return audit;
}

function validateProposal(input, audit) {
  const standard = resolveAuditStandard(audit.manifest?.standard);
  const proposal = parse(proposalSchema, expandAxeAdoption(input, audit.records, standard).proposal, 'INVALID_AUDIT_PROPOSAL');
  const records = new Map(audit.records.map(record => [record.evidenceId, record]));
  const ids = new Set(), axeByRecord = new Map();
  const selectedIds = new Set(standard.criteria.map(row => row.id));
  for (const finding of proposal.findings) {
    if (!selectedIds.has(finding.criterionId)) fail('INVALID_AUDIT_PROPOSAL', 'Finding is outside the selected WCAG catalog.');
    if (ids.has(finding.id)) fail('DUPLICATE_AUDIT_FINDING', 'Finding identifiers must be unique.');
    ids.add(finding.id);
    if (finding.method === 'screen_reader') fail('UNSUPPORTED_SCREEN_READER_METHOD', 'Real screen reader collection is not implemented; browser ARIA and keyboard records cannot support a screen reader claim.');
    if (new Set(finding.evidenceIds).size !== finding.evidenceIds.length || !finding.evidenceIds.includes(finding.target.evidenceId)) {
      fail('INVALID_AUDIT_EVIDENCE_REFERENCE', 'Each finding must include its target observation once in its unique evidenceIds.');
    }
    for (const evidenceId of finding.evidenceIds) {
      const record = records.get(evidenceId);
      if (!record || record.success !== true) fail('INVALID_AUDIT_EVIDENCE_REFERENCE', 'Only successful observations from this audit run may be referenced.');
    }
    const observed = records.get(finding.target.evidenceId);
    const target = nodeIn(observed, finding.target);
    if (!target || !target.selector || !observed.after?.stateId || !target.documentId) {
      fail('INVALID_AUDIT_TARGET', 'The target must be a real node in the referenced successful DOM observation, including its original document and state.');
    }
    if ((finding.source === 'axe') !== (finding.axeCandidateId !== undefined)) fail('INVALID_AXE_SOURCE', 'source "axe" and axeCandidateId must be supplied together.');
    if (finding.source === 'axe') {
      if (!axeByRecord.has(observed.evidenceId)) axeByRecord.set(observed.evidenceId, deriveAxeCandidates(observed, standard));
      const candidate = axeByRecord.get(observed.evidenceId).find(row => row.candidateId === finding.axeCandidateId);
      if (!candidate?.adoptable || candidate.nodeId !== finding.target.nodeId || !candidate.criterionIds.includes(finding.criterionId)) {
        fail('INVALID_AXE_SOURCE', 'An axe-sourced finding must match a retained axe violation on its bound target node and one of that rule\'s mapped criteria.');
      }
    }
  }
  return proposal;
}

/** Strict draft validation only: this neither reviews nor confirms a finding. */
export function validateAuditProposalRecords(proposalInput, records, standard) {
  if (!Array.isArray(records)) fail('INVALID_AUDIT_EVIDENCE_REFERENCE', 'Original audit records are required.');
  return validateProposal(proposalInput, { records, manifest: { standard } });
}

function validateAdjudication(input, proposal) {
  const adjudication = parse(adjudicationSchema, input, 'INVALID_AUDIT_ADJUDICATION');
  if (adjudication.reviewer.name.toLocaleLowerCase('en-US') === proposal.auditor.name.toLocaleLowerCase('en-US')) {
    fail('AUDIT_REVIEW_NOT_INDEPENDENT', 'The reviewer must declare independence and use a different identity from the auditor.');
  }
  const ids = new Set(proposal.findings.map(finding => finding.id));
  const seen = new Set();
  for (const decision of adjudication.decisions) {
    if (!ids.has(decision.findingId) || seen.has(decision.findingId)) fail('AUDIT_REVIEW_DENOMINATOR_MISMATCH', 'Each original finding must receive exactly one decision; unknown or duplicate identifiers are forbidden.');
    seen.add(decision.findingId);
  }
  return adjudication;
}

const spacingRequest = { lineHeight: 1.5, letterSpacingEm: 0.12, wordSpacingEm: 0.16, paragraphMarginBlockEndEm: 2 };

function completeSpacing(result) {
  if (result?.enabled !== true || result.applied !== true || !same(result.requested, spacingRequest) ||
      typeof result.css !== 'string' || (Array.isArray(result.failures) && result.failures.length)) return false;
  const cssDigest = createHash('sha256').update(result.css).digest('hex');
  if (result.cssSha256 !== cssDigest && result.cssSha256 !== `sha256:${cssDigest}`) return false;
  const css = result.css.replace(/\/\*[\s\S]*?\*\//g, '');
  if (!/line-height\s*:\s*1\.5(?:\s|;|!|})/i.test(css) ||
      !/letter-spacing\s*:\s*(?:0?\.12)em(?:\s|;|!|})/i.test(css) ||
      !/word-spacing\s*:\s*(?:0?\.16)em(?:\s|;|!|})/i.test(css) ||
      !/margin-(?:block-end|bottom)\s*:\s*2em(?:\s|;|!|})/i.test(css)) return false;
  const paragraph = result.representativeParagraph;
  const fontSize = Number.parseFloat(paragraph?.fontSize);
  const margin = Number.parseFloat(paragraph?.marginBlockEnd);
  return Number.isFinite(fontSize) && fontSize > 0 && Number.isFinite(margin) && margin >= fontSize * 2 - 0.1;
}

function measuredContrast(record) {
  const result = record.result?.contrast;
  if (!result || result.screenshotSha256 !== record.png?.sha256 || result.formula !== 'WCAG-relative-luminance-sRGB' ||
      result.srgbThreshold !== 0.04045 || !same(result.coefficients, [0.2126, 0.7152, 0.0722]) ||
      result.ratioOffset !== 0.05 || result.alphaPolicy !== 'opaque-samples-only') return false;
  for (const name of ['foreground', 'background']) {
    const sample = result[name];
    if (!sample || sample.x !== record.arguments?.[name]?.x || sample.y !== record.arguments?.[name]?.y ||
        !Number.isInteger(sample.x) || !Number.isInteger(sample.y) || sample.x < 0 || sample.y < 0 ||
        sample.x >= record.png.width || sample.y >= record.png.height ||
        !Array.isArray(sample.rgb) || sample.rgb.length !== 3 || sample.rgb.some(value => !Number.isInteger(value) || value < 0 || value > 255) ||
        !same(sample.rgba, [...sample.rgb, 255]) || sample.neighborhood?.radius !== 1 ||
        typeof sample.neighborhood.uniform !== 'boolean' || sample.neighborhood.opaque !== true ||
        !Number.isInteger(sample.neighborhood.pixels) || sample.neighborhood.pixels < 1 || sample.neighborhood.pixels > 9) return false;
    const luminance = sample.rgb.map(value => {
      const channel = value / 255;
      return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
    }).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
    if (!Number.isFinite(sample.relativeLuminance) || Math.abs(luminance - sample.relativeLuminance) > 1e-12) return false;
  }
  return Number.isFinite(result.ratio) && Math.abs(contrastRatio(result.foreground.rgb, result.background.rgb) - result.ratio) < 1e-12;
}

const originalContrastPixels = new WeakSet();

async function verifyOriginalContrastPixels(audit) {
  await Promise.all(audit.records.filter(record => record.success === true && record.action === 'contrast' && record.png).map(async record => {
    try {
      const bytes = await readFile(record.png.path);
      if (bytes.length !== record.png.bytes || createHash('sha256').update(bytes).digest('hex') !== record.png.sha256) return;
      const image = decodePng(bytes);
      for (const name of ['foreground', 'background']) {
        const sample = record.result?.contrast?.[name];
        if (!sample || !same(pixelAt(image, sample.x, sample.y), sample.rgba)) return;
        const neighbors = [];
        for (let y = Math.max(0, sample.y - 1); y <= Math.min(image.height - 1, sample.y + 1); y++) {
          for (let x = Math.max(0, sample.x - 1); x <= Math.min(image.width - 1, sample.x + 1); x++) neighbors.push(pixelAt(image, x, y));
        }
        if (sample.neighborhood?.pixels !== neighbors.length ||
            sample.neighborhood?.opaque !== neighbors.every(color => color[3] === 255) ||
            sample.neighborhood?.uniform !== neighbors.every(color => same(color, sample.rgba))) return;
      }
      originalContrastPixels.add(record);
    } catch { /* Unsupported or inconsistent original pixels leave this prerequisite insufficient. */ }
  }));
}

function referencedRecord(audit, finding, evidenceId) {
  return finding.evidenceIds.includes(evidenceId) ? audit.records.find(record => record.evidenceId === evidenceId && record.success === true) : undefined;
}

function boundStateReference(reference, audit, finding) {
  const record = referencedRecord(audit, finding, reference.evidenceId);
  return record && record.json?.sha256 === reference.jsonSha256 && record.after?.documentId === reference.documentId && record.after?.stateId === reference.stateId ? record : undefined;
}

function foregroundInTarget(record, target) {
  const rect = target?.rect, sample = record.result?.contrast?.foreground, viewport = record.after?.viewport;
  // Contrast captures are viewport PNGs in the collector's CSS-pixel context.
  if (!rect || !sample || !same(nodeIn(record, target)?.rect, rect) || record.png?.width !== viewport?.width || record.png?.height !== viewport?.height ||
      ![rect.x, rect.y, rect.width, rect.height].every(Number.isFinite) || rect.width <= 0 || rect.height <= 0) return false;
  return sample.x + 0.5 >= rect.x && sample.x + 0.5 < rect.x + rect.width &&
    sample.y + 0.5 >= rect.y && sample.y + 0.5 < rect.y + rect.height;
}

function completeAncestorSemantics(node) {
  const chain = node?.ancestorSemantics;
  if (chain?.complete !== true || !Array.isArray(chain.ancestors) || !chain.ancestors.length) return undefined;
  const lineage = [node, ...chain.ancestors], seen = new Set();
  for (let index = 0; index < lineage.length; index++) {
    const entry = lineage[index];
    if (!entry?.nodeId || seen.has(entry.nodeId) || entry.documentId !== node.documentId ||
        !entry.attributes || Array.isArray(entry.attributes) || typeof entry.attributes !== 'object' ||
        !Array.isArray(entry.attributesTruncated) || entry.attributesTruncated.length ||
        entry.parentNodeId !== (lineage[index + 1]?.nodeId ?? null)) return undefined;
    seen.add(entry.nodeId);
  }
  return lineage.at(-1).tag === 'html' ? lineage : undefined;
}

function actualOperation(record) {
  return record && (record.action === 'press' && record.arguments?.key && !Object.hasOwn(record.arguments, 'selector') ||
    record.action === 'click' && record.arguments?.selector && record.result?.clicked === true ||
    record.action === 'fill' && record.arguments?.selector && typeof record.arguments?.value === 'string' && record.result?.filled === true);
}

// An optional readiness bridge preserves the real trigger while allowing asynchronous
// state advancement. Restrict selector identity to original, unique simple IDs.
function settledStatusEvidence(finding, audit, notes, operation, after, beforeNode, afterNode) {
  const readiness = referencedRecord(audit, finding, notes.settledEvidenceId);
  const start = audit.records.indexOf(operation), end = audit.records.indexOf(after);
  const readyIndex = audit.records.indexOf(readiness);
  const selector = beforeNode?.selector, documentId = beforeNode?.documentId;
  if (!operation || !after || !/^#[A-Za-z_][A-Za-z0-9_-]*$/.test(selector ?? '') ||
      selector !== afterNode?.selector || selector !== `#${beforeNode?.attributes?.id}` ||
      selector !== `#${afterNode?.attributes?.id}` || !(start < readyIndex && readyIndex < end) ||
      !sameState(readiness?.after, after.after) || afterNode?.textTruncated !== false) return false;
  const literalReadiness = record => record.action === 'wait_for' &&
    record.arguments?.condition === 'text' && record.arguments.selector === selector &&
    record.arguments.expected === afterNode.text && record.result?.condition === 'text' &&
    record.result.selector === selector && record.result.matched === true && record.result.count === 1 &&
    record.result.actual === afterNode.text && record.result.actualTruncated === false && record.result.actualOmitted === false;
  // This branch reviews the observed summary, not business completion or continuity.
  const before = referencedRecord(audit, finding, notes.beforeEvidenceId);
  const busyReadiness = readiness?.action === 'wait_for' &&
    readiness.arguments?.condition === 'attribute' && readiness.arguments.selector === selector &&
    readiness.arguments.name === 'aria-busy' && readiness.arguments.value === 'false' &&
    readiness.result?.condition === 'attribute' && readiness.result.selector === selector &&
    readiness.result.matched === true && readiness.result.count === 1 && readiness.result.actual === 'false' &&
    readiness.result.actualOmitted === false && readiness.result.actualTruncated === false &&
    afterNode.attributes?.['aria-busy'] === 'false' &&
    before?.action === 'inspect' && before.arguments?.selector === selector &&
    after.action === 'inspect' && after.arguments?.selector === selector &&
    operation.action === 'click' && operation.result?.clicked === true &&
    audit.records.indexOf(before) + 1 === start && readyIndex === start + 1 && end === readyIndex + 1;
  if (!literalReadiness(readiness) && !busyReadiness) return false;
  return audit.records.slice(start, end + 1).every((record, index) =>
    record.success === true && finding.evidenceIds.includes(record.evidenceId) &&
    record.before?.documentId === documentId && record.after?.documentId === documentId &&
    (index === 0 || (busyReadiness && record === readiness) || (['snapshot', 'inspect', 'screenshot', 'contrast'].includes(record.action) || literalReadiness(record))));
}

function statusMessageGate(finding, audit, notes, missing) {
  if (!notes) {
    missing.push('Status messages require structured before/operation/after references and applicability review in prerequisiteNotes.v2.statusMessage.');
    return;
  }
  const before = referencedRecord(audit, finding, notes.beforeEvidenceId);
  const operation = referencedRecord(audit, finding, notes.operationEvidenceId);
  const after = referencedRecord(audit, finding, notes.afterEvidenceId);
  const beforeNode = before && nodeIn(before, finding.target), afterNode = after && nodeIn(after, finding.target);
  const order = [before, operation, after].map(record => audit.records.indexOf(record));
  const domObservations = [before, after].every(record => record && ['snapshot', 'inspect'].includes(record.action) && sameState(record.before, record.after));
  const realOperation = actualOperation(operation);
  if (!domObservations || !realOperation || !(order[0] < order[1] && order[1] < order[2]) ||
      notes.afterEvidenceId !== finding.target.evidenceId || !beforeNode || !afterNode ||
      !sameState(before.after, operation.before) ||
      !(notes.settledEvidenceId === undefined ? sameState(operation.after, after.after) :
        settledStatusEvidence(finding, audit, notes, operation, after, beforeNode, afterNode)) ||
      before.after.documentId !== after.after.documentId || beforeNode.nodeId !== afterNode.nodeId) {
    missing.push('Status messages require original stable DOM observations of the same document/node, bracketing one successful actual operation with matching recorded states.');
    return;
  }
  const originalText = node => typeof node.text === 'string' && node.textTruncated === false;
  if (!originalText(beforeNode) || !originalText(afterNode) || beforeNode.text === afterNode.text || sameState(before.after, after.after)) {
    missing.push('Status messages require a changed, untruncated result text and its distinct before/after stateIds; no-change observations do not establish a status update.');
  }
  if (![before, after].every((record, index) => {
    const node = index ? afterNode : beforeNode;
    return node.focused === false && record.after.active?.documentId === node.documentId &&
      record.after.active?.nodeId && record.after.active.nodeId !== node.nodeId;
  })) missing.push('Status messages require recorded before/after focus showing that the result target did not receive focus.');
  const lineages = [beforeNode, afterNode].map(completeAncestorSemantics);
  if (lineages.some(lineage => !lineage)) {
    missing.push('Status messages require complete original target-to-html ancestor semantics, parent identities and untruncated attributes for both observations.');
  } else if (lineages.some(lineage => lineage.some(node =>
    ['output', 'progress', 'meter'].includes(node.tag) ||
    /(?:^|\s)(?:status|alert|log|timer|marquee|progressbar|meter)(?:\s|$)/i.test(String(node.attributes.role ?? '')) ||
    ['polite', 'assertive'].includes(String(node.attributes['aria-live'] ?? '').toLowerCase())))) {
    missing.push('Recorded target or ancestor live-region semantics require further review; absence of programmatic status semantics is not established.');
  }
  if (notes.resultKind !== 'status-summary') missing.push('The reviewer must identify this change as an applicable status summary rather than substantive result content or an uncertain case.');
}

function alternativePresentationGate(finding, audit, alternative, context, missing) {
  if (alternative.kind === 'unverified') {
    missing.push('Alternative presentation remains unverified; missing complete auditing is not a counterexample or a failure.');
    return;
  }
  if (alternative.kind === 'none-observed') {
    if (!alternative.evidenceIds.every(evidenceId => referencedRecord(audit, finding, evidenceId))) {
      missing.push('The reviewer must cite original successful evidence for the alternative-presentation assessment.');
    }
    return;
  }
  const alternate = boundStateReference(alternative.alternateState, audit, finding);
  if (!alternate || !['snapshot', 'inspect'].includes(alternate.action)) {
    missing.push('The alternative presentation must bind an original DOM observation, its actual document/state and JSON SHA-256.');
    return;
  }
  const checks = [alternative.control, alternative.equivalence];
  if (!checks.every(check => check.evidenceIds.every(evidenceId => referencedRecord(audit, finding, evidenceId)))) {
    missing.push('Alternative control and information/function equivalence judgments must cite original successful evidence.');
    return;
  }
  const original = referencedRecord(audit, finding, finding.target.evidenceId);
  const activation = alternative.control.evidenceIds.map(evidenceId => referencedRecord(audit, finding, evidenceId)).some(record =>
    record && (actualOperation(record) || record.action === 'navigate' && record.result?.url) &&
    audit.records.indexOf(original) < audit.records.indexOf(record) && audit.records.indexOf(record) < audit.records.indexOf(alternate) &&
    sameState(record.before, original.after) && sameState(record.after, alternate.after));
  if (sameState(original.after, alternate.after) || !activation) {
    missing.push('An alternative presentation requires a recorded activation from the finding state to the distinct alternate state; default-state evidence cannot stand in for it.');
    return;
  }
  const targetLevel = alternative.targetLevel;
  if (targetLevel.status !== 'counterexample' && targetLevel.dependencies.length) {
    missing.push('Only an explicit alternate-state counterexample may declare finding dependencies.');
    return;
  }
  if (targetLevel.status === 'counterexample') {
    let valid = targetLevel.dependencies.length > 0;
    const ids = new Set();
    for (const dependency of targetLevel.dependencies) {
      const record = boundStateReference(dependency, audit, finding), dependent = context?.findings.get(dependency.findingId);
      const decision = context?.decisions.get(dependency.findingId);
      if (ids.has(dependency.findingId)) valid = false;
      ids.add(dependency.findingId);
      if (!record || !sameState(record.after, alternate.after) || !dependent ||
          dependent.target.evidenceId !== dependency.evidenceId || !dependency.evidenceIds.includes(dependency.evidenceId) ||
          !dependency.evidenceIds.every(evidenceId => {
            const counterexample = referencedRecord(audit, finding, evidenceId);
            return counterexample && dependent.evidenceIds.includes(evidenceId) && sameState(counterexample.after, alternate.after);
          }) || decision?.verdict !== 'supported' || !Object.values(decision.checks).every(value => value === 'supported')) {
        valid = false;
      } else if (context.gate(dependent).status !== 'supported') valid = false;
    }
    if (!valid) {
      missing.push('Alternative counterexample dependencies must be acyclic, independently supported findings with intact original digests and counterexample evidence from that exact alternate state.');
      return;
    }
  }
  // A recorded failed control/equivalence condition can independently disqualify
  // this alternative. An unaudited target level cannot do so by itself.
  if (checks.some(check => check.status === 'contradicted')) return;
  if (checks.some(check => check.status !== 'supported') || targetLevel.status !== 'counterexample') {
    missing.push('The available alternative is not disproved: the G174 control, equivalent information/function and target-level conditions need explicit evidence; not-fully-audited does not mean failure.');
  }
}

function v2EvidenceGate(finding, audit, decision, sameStatePictures, target, context, missing) {
  const notes = decision?.prerequisiteNotes?.v2;
  if (finding.criterionId === '1.4.11') {
    const contrast = notes?.nonTextContrast;
    const record = contrast && sameStatePictures.find(record => record.evidenceId === contrast.contrastEvidenceId && record.action === 'contrast');
    if (!record || !measuredContrast(record) || !originalContrastPixels.has(record) || !foregroundInTarget(record, target)) {
      missing.push('Non-text contrast requires a same-state target-bound original PNG, reproducible actual pixel samples and a foreground sample spatially inside the recorded target; adjacent background may be outside it.');
    } else if (record.result.contrast.ratio >= contrast.requiredRatio) {
      missing.push('The recorded contrast does not fall below the applicable 3:1 non-text threshold.');
    }
    if (!contrast || !decision?.prerequisiteNotes?.contrast) {
      missing.push('The reviewer must explain the necessary graphic/component use, adjacent colors, 3:1 threshold and applicable exceptions in prerequisiteNotes.contrast and prerequisiteNotes.v2.nonTextContrast.');
    }
  }
  if (finding.criterionId === '4.1.3') statusMessageGate(finding, audit, notes?.statusMessage, missing);
  if (finding.criterionId === '1.4.3') {
    const contrast = notes?.textContrast;
    const fontSize = Number.parseFloat(target.computed?.fontSize), fontWeight = Number.parseFloat(target.computed?.fontWeight);
    const largeText = fontSize >= 24 || fontSize >= 18.666666666666668 && fontWeight >= 700;
    const threshold = largeText ? 3 : 4.5;
    if (!contrast || contrast.requiredRatio !== threshold || !Number.isFinite(fontSize) || fontSize <= 0 ||
        contrast.textKind !== (largeText ? 'large' : 'normal')) {
      missing.push('Text contrast requires structured applicability, recorded actual text size/type and its appropriate 4.5:1 or large-text 3:1 threshold in prerequisiteNotes.v2.textContrast.');
    }
    if (!sameStatePictures.some(record => record.action === 'contrast' && measuredContrast(record) && originalContrastPixels.has(record) &&
      foregroundInTarget(record, target) && record.result.contrast.ratio < threshold)) {
      missing.push('Text contrast requires actual original PNG pixels bound to the target and below the applicable text threshold.');
    }
    if (contrast) alternativePresentationGate(finding, audit, contrast.alternativePresentation, context, missing);
  }
}

function missingNamePredicate(record, target, retained, missing) {
  const attributes = target.attributes;
  const complete = Array.isArray(target.attributesTruncated) && !target.attributesTruncated.length &&
    target.labelTextTruncated === false && target.textTruncated === false && typeof target.labelText === 'string';
  if (!complete) {
    missing.push('Missing-name evidence requires complete retained attributes, labelText and text receipts; truncated or absent fields cannot establish an empty name.');
    return;
  }
  if (target.labelText.trim() || ['aria-label', 'aria-labelledby', 'title', 'alt', 'placeholder'].some(key => String(attributes[key] ?? '').trim())) {
    missing.push('Retained naming attributes, associated label text or a placeholder may name this component; a missing-name predicate is not established.');
    return;
  }
  const targetId = attributes.id;
  if (targetId && retained.some(node => node.tag === 'label' && node.attributes?.for === targetId)) {
    missing.push('A retained label is associated with this nonempty target id; its naming effect requires further review.');
    return;
  }
  const byId = new Map(retained.map(node => [node.nodeId, node]));
  const excluded = node => String(node.attributes?.['aria-hidden'] ?? '').trim().toLowerCase() === 'true' || Object.hasOwn(node.attributes ?? {}, 'inert');
  if ([target, ...(target.ancestorSemantics?.ancestors ?? [])].some(excluded)) {
    missing.push('The target or a retained ancestor is aria-hidden or inert; missing-name exposure is not established.');
    return;
  }
  const visited = new Set();
  for (let parent = byId.get(target.parentNodeId); parent && !visited.has(parent.nodeId); parent = byId.get(parent.parentNodeId)) {
    if (excluded(parent)) {
      missing.push('The target or a retained ancestor is aria-hidden or inert; missing-name exposure is not established.');
      return;
    }
    if (parent.tag === 'label') {
      missing.push('A retained wrapping label requires further name computation review.');
      return;
    }
    visited.add(parent.nodeId);
  }
  if (Object.hasOwn(attributes, 'hidden') || target.computed?.display === 'none' ||
      ['hidden', 'collapse'].includes(target.computed?.visibility) || !(target.rect?.width > 0 && target.rect?.height > 0)) {
    missing.push('The missing-name predicate requires a retained rendered component; hidden or unestablished exposure remains unverified.');
    return;
  }
  const nativeInput = target.tag === 'input' && !attributes.role &&
    ['text', 'search', 'email', 'url', 'tel', 'password', 'number'].includes(attributes.type?.toLowerCase() ?? 'text');
  const slider = attributes.role === 'slider' && Number(attributes.tabindex) >= 0 && Object.hasOwn(attributes, 'tabindex');
  // Only an inspect ARIA snapshot is bound to this single button; body snapshots cannot identify a node by position or a matching name.
  const unnamedButton = target.tag === 'button' && !attributes.role && record.action === 'inspect' &&
    record.result.element?.nodeId === target.nodeId && /^- button(?: \[[^\]\r\n]*\])*\s*$/.test(record.result.ariaSnapshot?.trim() ?? '');
  if (!nativeInput && !slider && !unnamedButton) {
    missing.push('No missing-name predicate is implemented for this component. Supported cases are native text/number inputs, focusable sliders, and native buttons with a target-scoped empty-name ARIA inspect snapshot.');
  }
}

function evidenceGate(finding, audit, decision, context) {
  const referenced = audit.records.filter(record => finding.evidenceIds.includes(record.evidenceId));
  const observed = referenced.find(record => record.evidenceId === finding.target.evidenceId);
  const target = nodeIn(observed, finding.target);
  const screenshots = referenced.filter(record => record.success === true && ['screenshot', 'contrast'].includes(record.action) && record.png &&
    record.result?.capture?.stable === true && record.result.capture.beforeStateId === record.after?.stateId &&
    record.result.capture.afterStateId === record.after?.stateId && sameState(record.before, record.after) && nodeIn(record, finding.target));
  const sameStatePictures = screenshots.filter(record => sameState(record.after, observed.after));
  const missing = [];
  if (context?.requireDirectEvidence && !VISUAL_CRITERIA.has(finding.criterionId) && !(finding.criterionId === '4.1.3' && audit.evidencePolicy === AUDIT_EVIDENCE_POLICY)) {
    const citation = decision?.directEvidence;
    const record = referenced.find(row => row.evidenceId === citation?.evidenceId && row.success && sameState(row.after, observed.after));
    const retained = record ? nodes(record) : [];
    const citedTarget = retained.find(node => node.nodeId === target.nodeId && node.documentId === target.documentId);
    if (!citation || !citedTarget?.tag || !citedTarget.attributes || !citation.nodeIds.includes(target.nodeId) ||
        citation.nodeIds.some(nodeId => !retained.some(node => node.nodeId === nodeId && node.documentId === target.documentId))) {
      missing.push('Ordinary observations require directEvidence citing retained same-state target DOM, nodeIds, criterionClause and an explanation; axe results and reviewer declarations alone do not establish semantics.');
    } else if (context.requirePredicates
      ? !new RegExp(`(^|[^0-9A-Za-z_.])${finding.criterionId.replaceAll('.', '\\.')}($|[^0-9A-Za-z_.])`).test(citation.criterionClause)
      : !citation.criterionClause.includes(finding.criterionId)) {
      missing.push('directEvidence.criterionClause must identify the exact finding criterion token.');
    } else if (context.requirePredicates && finding.criterionId === '4.1.2') {
      missingNamePredicate(record, citedTarget, retained, missing);
    } else if (finding.criterionId === '1.3.1') {
      const seen = new Set([citedTarget.nodeId]);
      let current = citedTarget;
      if (!current.parentNodeId) missing.push('Info and relationships requires a retained parent/ancestor chain in directEvidence.');
      while (current.parentNodeId) {
        const parent = retained.find(node => node.nodeId === current.parentNodeId && node.documentId === target.documentId);
        if (!parent || !citation.nodeIds.includes(parent.nodeId) || seen.has(parent.nodeId)) {
          missing.push(context.requirePredicates && !parent
            ? 'An ancestor lies outside the retained snapshot (truncated or unobserved ancestry); relationship ownership cannot be established.'
            : 'Info and relationships requires every retained ownership ancestor; a missing or circular chain cannot establish ownership.');
          break;
        }
        seen.add(parent.nodeId); current = parent;
      }
    }
    if (context.requirePredicates && finding.criterionId !== '4.1.2') missing.push(`No machine-checked semantic predicate is implemented for ordinary criterion ${finding.criterionId}; citations and a reviewer declaration cannot confirm it.`);
  }
  if (VISUAL_CRITERIA.has(finding.criterionId) || ['visual', 'combined'].includes(finding.method)) {
    if (!sameStatePictures.length) missing.push('A PNG and the target DOM must be captured in the same actual stateId and documentId.');
  }
  if (finding.method === 'keyboard') {
    if (!referenced.some(record => record.success === true && record.action === 'press' && record.arguments?.key)) missing.push('A real global keyboard press must be recorded.');
  }
  if (finding.criterionId === '1.4.3') {
    if (!sameStatePictures.some(record => record.action === 'contrast' && measuredContrast(record))) {
      missing.push('Text contrast requires same-state original PNG pixel samples, opaque colors, coordinates and a reproducible WCAG contrast calculation.');
    }
    if (!decision?.prerequisiteNotes?.contrast) missing.push('The reviewer must explain text use, actual text size/type and applicable contrast exceptions in prerequisiteNotes.contrast.');
  }
  if (finding.criterionId === '2.4.7') {
    const keyboard = referenced.filter(record => record.action === 'press' && record.success === true &&
      record.arguments?.key && !Object.hasOwn(record.arguments, 'selector') && record.result?.keyboardOnly === true &&
      record.result?.inputPath === 'keyboard-only' && record.after?.keyboardOnly === true && record.after.inputPath === 'keyboard-only' &&
      record.before?.active?.nodeId !== target.nodeId && record.after.active?.nodeId === target.nodeId &&
      record.after.active?.documentId === target.documentId && sameState(record.after, observed.after));
    if (!keyboard.length || !sameStatePictures.some(record => record.after.keyboardOnly === true &&
      record.after.active?.nodeId === target.nodeId && record.after.active?.documentId === target.documentId)) {
      missing.push('Focus visible requires an actual global keyboard path to this focused node and a keyboardOnly PNG of that same state.');
    }
  }
  if (finding.criterionId === '1.4.12') {
    const spacing = referenced.filter(record => record.action === 'spacing' && record.success === true && completeSpacing(record.result) &&
      sameState(record.after, observed.after) && record.before?.documentId === record.after?.documentId);
    if (!spacing.some(record => screenshots.some(picture => sameState(picture.after, record.before)) &&
      screenshots.some(picture => sameState(picture.after, record.after)))) {
      missing.push('Text spacing requires the complete four-property CSS receipt, actual paragraph end spacing, the target, and before/after PNGs of the recorded states.');
    }
  }
  if (finding.criterionId === '1.4.10') {
    if (observed.after.viewport?.width !== 320 || !sameStatePictures.some(record => record.after.viewport?.width === 320)) {
      missing.push('Reflow requires the actual target and a PNG recorded at a 320 CSS pixel viewport.');
    }
    if (!decision?.prerequisiteNotes?.alternativePresentation || !decision?.prerequisiteNotes?.exceptions) {
      missing.push('The reviewer must explain alternative presentation and applicable exceptions in prerequisiteNotes.');
    }
  }
  const v2 = audit.evidencePolicy === AUDIT_EVIDENCE_POLICY;
  if (v2) v2EvidenceGate(finding, audit, decision, sameStatePictures, target, context, missing);
  return { status: missing.length ? 'insufficient' : 'supported', missingEvidence: missing,
    ...(v2 ? { evidencePolicy: AUDIT_EVIDENCE_POLICY, semanticAssessment: 'reviewer-dependent' } : {}),
  };
}

function coverage(audit, findings, confirmed = []) {
  return audit.coverage.map(criterion => ({
    ...criterion,
    status: findings.some(finding => finding.criterionId === criterion.id) ? 'needs_review' : criterion.status,
    wholeCriterion: 'not_assessed',
    findingIds: findings.filter(finding => finding.criterionId === criterion.id).map(finding => finding.id),
    confirmedFindingIds: confirmed.filter(finding => finding.criterionId === criterion.id).map(finding => finding.id),
  }));
}

function common(audit) {
  const sourceAudit = { reportPath: audit.reportPath, reportDigest: audit.reportDigest, runId: audit.runId, manifestDigest: audit.manifestDigest };
  return {
    schemaVersion: AUDIT_SCHEMA_VERSION,
    runId: audit.runId,
    manifest: audit.manifest,
    manifestDigest: audit.manifestDigest,
    ...(audit.contractDigest ? { contractDigest: audit.contractDigest } : {}),
    ...(Object.hasOwn(audit, 'evidencePolicy') ? { evidencePolicy: audit.evidencePolicy } : {}),
    standard: audit.standard,
    codeFingerprint: audit.codeFingerprint,
    sourceStability: audit.sourceStability,
    ...(audit.navigation ? { navigation: audit.navigation } : {}),
    sourceAudit,
    collection: { reportPath: audit.reportPath, reportDigest: audit.reportDigest },
    candidates: audit.candidates,
    assessment: { status: 'incomplete', wholeCriteriaAssessed: 0, wholePage: 'not_assessed', complete: false },
    screenReader: { implemented: false, status: 'not_tested' },
    zeroFalsePositiveGuarantee: false,
    collectionStatus: audit.status,
    errors: audit.errors,
  };
}

// The recorded selector stays as captured; stableSelector fields are additive and derived only from retained records.
function targetObservation(audit, finding, stable) {
  return { ...finding.target, selector: nodeIn(audit.records.find(record => record.evidenceId === finding.target.evidenceId), finding.target).selector, ...stable.fieldsFor(finding.target) };
}

function proposalResult(audit, proposal) {
  const stable = stableSelectorIndex(audit.records);
  return {
    ...proposal,
    status: 'needs_review',
    semanticValidation: 'not_reviewed',
    confirmedFindings: [],
    verificationQueue: proposal.findings.map(finding => ({
      ...finding,
      targetObservation: targetObservation(audit, finding, stable),
      evidenceGate: evidenceGate(finding, audit),
      missingEvidence: ['Independent per-finding semantic review is required.', ...evidenceGate(finding, audit).missingEvidence],
    })),
    rejectedObservations: [],
    counts: { originalFindings: proposal.findings.length, confirmedFindings: 0, verificationQueue: proposal.findings.length, rejectedObservations: 0, collectedCandidates: audit.candidates.length },
    coverage: coverage(audit, proposal.findings),
  };
}

function reviewResult(audit, proposal, adjudication, reviewPolicy = CURRENT_REVIEW_POLICY) {
  const confirmedFindings = [];
  const verificationQueue = [];
  const rejectedObservations = [];
  const decisions = new Map(adjudication.decisions.map(decision => [decision.findingId, decision]));
  const stable = stableSelectorIndex(audit.records);
  const requireDirectEvidence = reviewPolicy !== 'legacy-declared';
  const context = { findings: new Map(proposal.findings.map(finding => [finding.id, finding])), decisions, requireDirectEvidence, requirePredicates: reviewPolicy === CURRENT_REVIEW_POLICY };
  const gates = new Map(), active = new Set();
  context.gate = finding => {
    if (gates.has(finding.id)) return gates.get(finding.id);
    if (active.has(finding.id)) return { status: 'insufficient', missingEvidence: ['Circular alternative-presentation dependencies cannot support a finding.'] };
    active.add(finding.id);
    const result = evidenceGate(finding, audit, decisions.get(finding.id), context);
    active.delete(finding.id);
    gates.set(finding.id, result);
    return result;
  };
  for (const finding of proposal.findings) {
    const decision = decisions.get(finding.id) ?? { findingId: finding.id, verdict: 'insufficient', checks: { evidenceSupport: 'insufficient', criterionMapping: 'insufficient', scope: 'insufficient', prerequisites: 'insufficient' }, reason: 'UNASSESSED: no decision submitted for this finding.', missingEvidence: ['Independent review has not been submitted.'] };
    const gate = audit.evidencePolicy === AUDIT_EVIDENCE_POLICY ? context.gate(finding) : evidenceGate(finding, audit, decision, context);
    const result = {
      ...finding,
      targetObservation: targetObservation(audit, finding, stable),
      decision,
      evidenceGate: gate,
    };
    if (decision.verdict === 'rejected') rejectedObservations.push({ ...result, interpretation: 'reviewer-rejected-observation; not an automatically established false positive' });
    else if (decision.verdict === 'supported' && Object.values(decision.checks).every(value => value === 'supported') && gate.status === 'supported') confirmedFindings.push(result);
    else verificationQueue.push({
      ...result,
      missingEvidence: [...new Set([...(decision.missingEvidence ?? []), ...gate.missingEvidence,
        ...Object.entries(decision.checks).filter(([, value]) => value !== 'supported').map(([key, value]) => `Reviewer check ${key}: ${value}.`),
        ...(decision.verdict !== 'supported' ? [`Reviewer verdict: ${decision.verdict}.`] : []),
      ])],
    });
  }
  return {
    auditor: proposal.auditor,
    findings: proposal.findings,
    ...adjudication,
    status: verificationQueue.length ? 'partial' : 'reviewed',
    semanticValidation: 'reviewer-declared',
    independence: { basis: 'reviewer-declaration', osVerified: false },
    confirmedFindings,
    verificationQueue,
    rejectedObservations,
    ...(requireDirectEvidence ? { directEvidencePolicy: reviewPolicy } : {}),
    reviewProgress: { submittedDecisions: adjudication.decisions.length, unassessedFindings: proposal.findings.length - adjudication.decisions.length },
    counts: { originalFindings: proposal.findings.length, confirmedFindings: confirmedFindings.length, verificationQueue: verificationQueue.length, rejectedObservations: rejectedObservations.length, collectedCandidates: audit.candidates.length },
    coverage: coverage(audit, proposal.findings, confirmedFindings),
  };
}

function assertBinding(document, audit) {
  const reference = { reportPath: audit.reportPath, reportDigest: audit.reportDigest };
  const sourceAudit = { ...reference, runId: audit.runId, manifestDigest: audit.manifestDigest };
  if (document.schemaVersion !== AUDIT_SCHEMA_VERSION || document.runId !== audit.runId ||
      document.manifestDigest !== audit.manifestDigest || !same(document.manifest, audit.manifest) ||
      !same(document.standard, audit.standard) || !same(document.codeFingerprint, audit.codeFingerprint) ||
      !same(document.sourceStability, audit.sourceStability) || !same(document.candidates, audit.candidates) ||
      !same(document.evidencePolicy, audit.evidencePolicy) || Object.hasOwn(document, 'evidencePolicy') !== Object.hasOwn(audit, 'evidencePolicy') ||
      document.contractDigest !== audit.contractDigest || !same(document.collection, reference) || !same(document.sourceAudit, sourceAudit)) {
    fail('AUDIT_SOURCE_BINDING_MISMATCH', 'Derived audit evidence must retain the exact source run, contract, catalog, fingerprint, report path, and report digest.');
  }
}

const STABLE_FIELDS = ['stableSelector', 'stableSelectorConfidence', 'stableSelectorCheck'];
// Documents written before stableSelector fields existed are compared without them (the fields are additive only).
function withoutStableFields(value) {
  const strip = rows => Array.isArray(rows) ? rows.map(row => row?.targetObservation
    ? { ...row, targetObservation: Object.fromEntries(Object.entries(row.targetObservation).filter(([key]) => !STABLE_FIELDS.includes(key))) } : row) : rows;
  return { ...value, ...['verificationQueue', 'confirmedFindings', 'rejectedObservations'].reduce((out, key) => Object.hasOwn(value, key) ? { ...out, [key]: strip(value[key]) } : out, {}) };
}
const hasStableFields = document => ['verificationQueue', 'confirmedFindings', 'rejectedObservations']
  .some(key => Array.isArray(document[key]) && document[key].some(row => row?.targetObservation && STABLE_FIELDS.some(field => Object.hasOwn(row.targetObservation, field))));

function assertResult(document, computed) {
  const expected = hasStableFields(document) ? computed : withoutStableFields(computed);
  if (!Object.hasOwn(document, 'reviewProgress')) delete expected.reviewProgress;
  for (const [key, value] of Object.entries(expected)) {
    if (!same(document[key], value)) fail('AUDIT_REVIEW_RESULT_MISMATCH', `Stored ${key} does not match the original proposal and review evidence gates.`);
  }
}

async function loadProposal(proposalPath) {
  const document = await readAuditDocument(proposalPath);
  if (document.kind !== 'audit-proposal') fail('INVALID_AUDIT_PROPOSAL', 'An audit-proposal document is required.');
  const audit = await currentCollection(document.collection?.reportPath);
  assertBinding(document, audit);
  const proposal = validateProposal({ auditor: document.auditor, findings: document.findings }, audit);
  if (Object.hasOwn(document, 'sourceCheckpoint')) await validateSourceCheckpoint(document.sourceCheckpoint, audit, proposal);
  assertResult(document, proposalResult(audit, proposal));
  return { document, audit, proposal };
}

async function validateSourceCheckpoint(input, audit, proposal) {
  const source = parse(sourceCheckpointSchema, input, 'INVALID_AUDIT_CHECKPOINT_REFERENCE');
  if (!same(source, input) || audit.evidencePolicy !== AUDIT_EVIDENCE_POLICY) {
    fail('AUDIT_CHECKPOINT_CONTEXT_MISMATCH', 'Recovery provenance requires an exact checkpoint reference and a current evidence-policy collection.');
  }
  // Checkpoint validation itself imports draft validation from this module.
  const { readAuditCheckpoint } = await import('./checkpoint.js');
  const checkpoint = await readAuditCheckpoint(source.checkpointPath, {
    runId: audit.runId, directory: path.dirname(audit.reportPath), evidencePolicy: audit.evidencePolicy,
  });
  if (!same(resolveAuditStandard(checkpoint.context?.standard), resolveAuditStandard(audit.manifest.standard))) fail('AUDIT_CHECKPOINT_CONTEXT_MISMATCH', 'Checkpoint WCAG selection differs from collection.');
  if (checkpoint.checkpointDigest !== source.checkpointDigest || !same(checkpoint.proposal, proposal)) {
    fail('AUDIT_CHECKPOINT_BINDING_MISMATCH', 'The submitted proposal must exactly match its acknowledged original checkpoint and digest.');
  }
  return source;
}

export async function submitAudit(auditPath, proposalInput, options = {}) {
  const parsedOptions = parse(submitOptionsSchema, options, 'INVALID_AUDIT_SUBMIT_OPTIONS');
  const audit = await currentCollection(auditPath);
  const proposal = validateProposal(proposalInput, audit);
  const sourceCheckpoint = parsedOptions.sourceCheckpoint && await validateSourceCheckpoint(parsedOptions.sourceCheckpoint, audit, proposal);
  return saveAuditDocument(path.dirname(audit.reportPath), 'audit-proposal', {
    ...common(audit), ...proposalResult(audit, proposal), createdAt: new Date().toISOString(),
    ...(sourceCheckpoint ? { sourceCheckpoint } : {}),
  });
}

export async function reviewAudit(proposalPath, adjudicationInput, options = {}) {
  const parsedOptions = parse(z.object({ out: text.optional() }).strict(), options, 'INVALID_AUDIT_REVIEW_OPTIONS');
  const { document, audit, proposal } = await loadProposal(proposalPath);
  const adjudication = validateAdjudication(adjudicationInput, proposal);
  const payload = {
    ...common(audit), ...reviewResult(audit, proposal, adjudication), createdAt: new Date().toISOString(),
    sourceProposal: { reportPath: document.reportPath, reportDigest: document.reportDigest },
    ...(document.sourceCheckpoint ? { sourceCheckpoint: document.sourceCheckpoint } : {}),
  };
  return parsedOptions.out ? saveExternalAuditReview(parsedOptions.out, payload) : saveAuditDocument(path.dirname(audit.reportPath), 'audit-review', payload);
}

export async function checkAudit(reportPath) {
  try {
    const report = await readAuditDocument(reportPath);
    if (report.kind === 'audit') {
      const result = await checkAuditCollection(reportPath);
      if (result.status === 'current') validateCollection(result.report);
      return { kind: 'audit-check', checkedKind: report.kind, ...result };
    }
    if (report.kind === 'audit-proposal') {
      await loadProposal(reportPath);
    } else if (report.kind === 'audit-review') {
      const { document, audit, proposal } = await loadProposal(report.sourceProposal?.reportPath);
      assertBinding(report, audit);
      if (!same(report.sourceProposal, { reportPath: document.reportPath, reportDigest: document.reportDigest })) fail('AUDIT_PROPOSAL_BINDING_MISMATCH', 'The review must retain its exact original proposal report and digest.');
      if (!same(report.sourceCheckpoint, document.sourceCheckpoint) || Object.hasOwn(report, 'sourceCheckpoint') !== Object.hasOwn(document, 'sourceCheckpoint')) {
        fail('AUDIT_CHECKPOINT_BINDING_MISMATCH', 'The review must retain its original proposal checkpoint provenance.');
      }
      const adjudication = validateAdjudication({ reviewer: report.reviewer, decisions: report.decisions }, proposal);
      if (![undefined, 'dom-citations-v1', CURRENT_REVIEW_POLICY].includes(report.directEvidencePolicy)) fail('INVALID_AUDIT_REVIEW_POLICY', 'Unknown direct evidence policy.');
      assertResult(report, reviewResult(audit, proposal, adjudication, reviewPolicyOf(report)));
    } else fail('INVALID_AUDIT_DOCUMENT', 'Unsupported audit document kind.');
    return { kind: 'audit-check', checkedKind: report.kind, status: requiresReReview(report) ? 'needs_review' : 'current',
      ...(report.kind === 'audit-review' ? { reviewPolicy: reviewPolicyOf(report), requiresReReview: requiresReReview(report) } : {}), report, errors: [] };
  } catch (error) {
    return { kind: 'audit-check', status: error.code === 'AUDIT_EXPIRED' ? 'expired' : 'error', errors: [errorRecord(error, 'audit-check')] };
  }
}

/** A compact local view; the durable report keeps every original observation. */
export function summarizeAudit(result) {
  if (result.kind === 'audit-check') return { ...result, ...(result.report ? { report: summarizeAudit(result.report) } : {}) };
  if (!['audit', 'audit-proposal', 'audit-review'].includes(result.kind)) return result;
  const { records, candidates, manifest, ...metadata } = result;
  return {
    ...metadata,
    ...(result.kind === 'audit-review' ? { reviewPolicy: reviewPolicyOf(result), requiresReReview: requiresReReview(result) } : {}),
    // Additive: the same gap predicate and wording as the HTML report, without reading evidence files.
    ...(result.kind === 'audit' ? {} : { evidenceGaps: summarizeGaps(result) }),
    outputFormat: 'summary',
    scope: { projectRoot: manifest.projectRoot, url: manifest.url, viewport: manifest.viewport, maxActions: manifest.maxActions, wallSeconds: manifest.wallSeconds },
    ...(records ? { records: records.map(record => ({ evidenceId: record.evidenceId, action: record.action, success: record.success, stateId: record.after?.stateId, documentId: record.after?.documentId, json: record.json, ...(record.png ? { png: record.png } : {}) })) } : {}),
    candidates: candidates ?? [],
  };
}
