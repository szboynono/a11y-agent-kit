import path from 'node:path';
import { reviewPolicyOf, requiresReReview } from './review-policy.js';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { digest, ToolError } from '../evidence.js';
import { readAuditDocument, readAuditCompanion, writeAuditArtifact } from './store.js';
import { checkAudit } from './review.js';
import { AUDIT_TEXT_LIMIT, boundAuditResponse } from './projection.js';
import { axeBindingIndex, resolveAxeBinding } from './axe-candidates.js';

const fail = message => { throw new ToolError('INVALID_AUDIT_INVENTORY', message); };
const hash = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const reference = z.object({ reportPath: z.string().min(1), reportDigest: hash }).strict();
export const inventoryOptionsSchema = z.object({ cursor: z.string().min(1).max(4000).optional(), limit: z.number().int().min(1).max(200).optional() }).strict();
const dispositionSchema = z.object({ kind: z.literal('audit-inventory-dispositions'), version: z.literal(1),
  revision: z.number().int().positive(), runId: z.string().min(1).max(256), collection: reference,
  proposal: reference.nullable(), maker: z.object({ name: z.string().trim().min(1).max(300) }).strict(),
  dispositions: z.array(z.discriminatedUnion('status', [
    z.object({ observationId: hash, status: z.literal('linked'), findingIds: z.array(z.string().min(1).max(300)).min(1).max(1000) }).strict(),
    z.object({ observationId: hash, status: z.literal('ignored'), reason: z.string().trim().min(1).max(4000) }).strict(),
    z.object({ observationId: hash, status: z.literal('unresolved') }).strict(),
  ])), }).strict();
const ref = report => ({ reportPath: report.reportPath, reportDigest: report.reportDigest });
const size = value => Buffer.byteLength(JSON.stringify(value));
// Large original fields stay available through record reads; listing never copies HTML/check payloads.
function compact(value, handle) {
  return size(value) <= 2048 ? value : { truncated: true, bytes: size(value), digest: digest(value), originalFieldRead: handle };
}

/** Pure shared derivation. Callers validate retained source bytes before invoking. */
export function deriveAuditInventory({ collection, report = collection, proposal = null, dispositions = null }, options = {}, textLimit = AUDIT_TEXT_LIMIT) {
  const parsed = inventoryOptionsSchema.safeParse(options);
  if (!parsed.success) fail('Unknown or invalid inventory pagination options.');
  const { limit = 100, cursor } = parsed.data;
  const catalog = new Set(collection.standard.criteria.map(row => row.id));
  const source = { runId: collection.runId, collection: ref(collection), proposal: proposal ? ref(proposal) : null,
    report: ref(report), catalogDigest: digest(collection.standard), version: 1,
    ...(report.kind === 'audit-review' ? { reviewPolicy: reviewPolicyOf(report), requiresReReview: requiresReReview(report) } : {}),
    observationsDigest: digest(collection.records), dispositionsDigest: digest(dispositions) };
  const rows = [], limitations = [];
  let scans = 0, omittedBindings = 0;
  for (const record of collection.records) {
    if (record.action !== 'axe') continue;
    const read = field => ({ tool: 'read', evidenceId: record.evidenceId, options: { runId: collection.runId, view: 'field', field } });
    if (!record.success || !record.result?.axe) {
      limitations.push({ evidenceId: record.evidenceId, reason: 'failed_or_missing_axe_result', originalFieldRead: read('/error') }); continue;
    }
    scans++;
    const bindings = record.result.axeNodeBindings, bindingIndex = axeBindingIndex(record);
    omittedBindings += bindings?.omittedTargets ?? 0;
    if (!bindings || bindings.omittedTargets || !bindings.stable) limitations.push({ evidenceId: record.evidenceId,
      reason: !bindings ? 'bindings_not_retained' : !bindings.stable ? 'bindings_not_stable' : 'binding_rows_omitted', originalFieldRead: read('/result/axeNodeBindings') });
    for (const bucket of ['violations', 'incomplete']) {
      if (!Array.isArray(record.result.axe[bucket])) fail('Successful scans must retain both original axe buckets.');
      record.result.axe[bucket].forEach((rule, ruleIndex) => {
        if (typeof rule.id !== 'string' || !Array.isArray(rule.nodes)) fail('Invalid retained axe rule.');
        const criterionIds = [...new Set((rule.tags ?? []).filter(tag => /^wcag\d{3,4}$/.test(tag)).map(tag => {
          const digits = tag.slice(4); return `${digits[0]}.${digits[1]}.${Number(digits.slice(2))}`;
        }).filter(id => catalog.has(id)))];
        rule.nodes.forEach((node, ruleNodeIndex) => {
          const observationId = digest([collection.runId, record.evidenceId, bucket, rule.id, ruleNodeIndex]);
          const resolved = resolveAxeBinding(record, bindingIndex, bucket, rule, node, ruleNodeIndex);
          const binding = resolved.status === 'bound' ? { ...resolved,
            nodeRead: { tool: 'read', evidenceId: record.evidenceId, options: { runId: collection.runId, view: 'nodes', nodeIds: [resolved.nodeId] } } } : resolved;
          const row = { observationId, runId: collection.runId, evidenceId: record.evidenceId, bucket, ruleId: rule.id, ruleNodeIndex,
            rawPointer: `/result/axe/${bucket}/${ruleIndex}/nodes/${ruleNodeIndex}`, criterionIds,
            target: node.target ?? null, binding, documentId: record.after?.documentId ?? null, stateId: record.after?.stateId ?? null,
            url: record.after?.url ?? null, viewport: record.after?.viewport ?? null, json: record.json ?? null, png: record.png ?? null,
            originalFieldRead: read('/result/axe'), authorDisposition: { status: 'unresolved' }, semanticStatus: 'not_established' };
          for (const key of Object.keys(row)) row[key] = compact(row[key], read(key === 'target' || key === 'ruleId' ? '/result/axe' : key === 'binding' ? '/result/axeNodeBindings' : '/after'));
          rows.push(row);
        });
      });
    }
  }
  if (!scans) limitations.push({ reason: 'no_successful_axe_scan' });
  if (new Set(rows.map(row => row.observationId)).size !== rows.length) fail('Duplicate original observation identities.');
  if (dispositions !== null) {
    const input = dispositionSchema.safeParse(dispositions);
    if (!input.success) fail('Invalid versioned maker dispositions.');
    const d = input.data;
    if (d.runId !== collection.runId || digest(d.collection) !== digest(ref(collection)) || digest(d.proposal) !== digest(proposal ? ref(proposal) : null)) fail('Disposition source binding differs from this collection/proposal.');
    const seen = new Set(), byId = new Map(rows.map(row => [row.observationId, row]));
    for (const entry of d.dispositions) {
      const row = byId.get(entry.observationId);
      if (!row || seen.has(entry.observationId)) fail('Unknown or duplicate observation ID.');
      seen.add(entry.observationId);
      if (entry.status === 'linked') {
        if (!proposal || proposal.auditor?.name !== d.maker.name || new Set(entry.findingIds).size !== entry.findingIds.length) fail('Links require the original proposal maker and unique finding IDs.');
        row.linkedReview = entry.findingIds.map(id => {
          const finding = proposal.findings.find(f => f.id === id);
          if (!finding || finding.target.evidenceId !== row.evidenceId || !finding.evidenceIds.includes(row.evidenceId)) fail('Linked findings must reference this original evidence ID.');
          if (row.binding.status !== 'bound' || finding.target.nodeId !== row.binding.nodeId) fail('Linked findings require the same stable original node binding.');
          const group = ['confirmedFindings', 'rejectedObservations', 'verificationQueue'].find(key => report[key]?.some(f => f.id === id));
          const reviewed = report[group]?.find(f => f.id === id);
          return { findingId: id, status: group === 'confirmedFindings' && requiresReReview(report) ? 'verificationQueue' : group ?? 'not_reviewed', verdict: reviewed?.decision?.verdict ?? null, evidenceGate: reviewed?.evidenceGate?.status ?? null };
        });
      }
      row.authorDisposition = { ...entry, maker: d.maker }; delete row.authorDisposition.observationId;
      for (const key of ['authorDisposition', 'linkedReview']) if (row[key] && size(row[key]) > 4096) {
        row[key] = { status: entry.status, truncated: true, digest: digest(row[key]), bytes: size(row[key]),
          originalDisposition: { revision: d.revision, observationId: row.observationId } };
      }
    }
  }
  const counts = { observations: rows.length, unresolved: 0, linked: 0, ignored: 0 };
  for (const row of rows) counts[row.authorDisposition.status]++;
  const binding = digest(source);
  let offset = 0;
  if (cursor) {
    try {
      const decoded = JSON.parse(Buffer.from(cursor, 'base64url').toString());
      if (Object.keys(decoded).sort().join() !== 'binding,cursor,version' || decoded.version !== 1 || decoded.binding !== binding || !Number.isSafeInteger(decoded.cursor) || decoded.cursor < 0 || decoded.cursor >= rows.length) fail('Stale or invalid inventory cursor.');
      offset = decoded.cursor;
    } catch { fail('Stale or invalid inventory cursor.'); }
  }
  const response = { kind: 'audit-pending-inventory', version: 1, success: true, source, counts,
    limitations: { successfulScans: scans, omittedBindings, count: limitations.length, entries: limitations.slice(0, 8), entriesTruncated: limitations.length > 8 },
    candidates: 'Original candidates remain retained and untouched in collection/proposal/review reports.',
    rows: [], pagination: {}, conformanceStatus: 'not_assessed' };
  const setNext = end => {
    const next = end < rows.length ? { limit, cursor: Buffer.from(JSON.stringify({ version: 1, binding, cursor: end })).toString('base64url') } : null;
    response.pagination = { complete: !next, next, returned: response.rows.length };
  };
  for (let end = offset; end < Math.min(rows.length, offset + limit); end++) {
    response.rows.push(rows[end]); setNext(end + 1);
    if (size(response) > textLimit - 4096) {
      response.rows.pop(); setNext(end);
      if (!response.rows.length) fail('Inventory metadata cannot fit one observation; no observation was delivered.');
      break;
    }
  }
  if (!rows.length) setNext(0);
  return boundAuditResponse(response, textLimit);
}

export async function auditInventory(reportPath, dispositionsPath, options = {}) {
  const report = await readAuditDocument(reportPath);
  const checked = await checkAudit(reportPath);
  // Historical collections remain readable when only current source freshness expired.
  if (checked.status === 'error' || (report.kind !== 'audit' && checked.status !== 'current' && !(checked.status === 'needs_review' && checked.requiresReReview))) fail('Source audit validation failed.');
  const collection = report.kind === 'audit' ? report : await readAuditDocument(report.collection.reportPath);
  const proposal = report.kind === 'audit-proposal' ? report : report.kind === 'audit-review' ? await readAuditDocument(report.sourceProposal.reportPath) : null;
  const dispositions = dispositionsPath ? await readAuditCompanion(dispositionsPath, path.dirname(collection.reportPath)) : null;
  return deriveAuditInventory({ collection, report, proposal, dispositions }, options);
}

/** Explicit write mode: new exclusive artifact per invocation, never an old report rewrite. */
export async function writeInventoryPage(reportPath, dispositionsPath, options = {}) {
  const page = await auditInventory(reportPath, dispositionsPath, options);
  const artifact = await writeAuditArtifact(path.dirname(page.source.collection.reportPath), `inventory-v1-${randomUUID()}.json`, `${JSON.stringify(page, null, 2)}\n`);
  return boundAuditResponse({ ...page, companion: artifact });
}
