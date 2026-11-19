import { digest, ToolError } from '../evidence.js';
import { VISUAL_CRITERIA } from './policy.js';
import { stableSelectorIndex } from './stable-selector.js';

const fail = (code, message) => { throw new ToolError(code, message); };
const bytes = value => Buffer.byteLength(JSON.stringify(value));
const clip = (value, limit) => typeof value === 'string' && value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
export const AXE_PAGE_LIMIT = 20;

/** axe tag wcag143 -> 1.4.3, wcag1410 -> 1.4.10; only criteria in the selected catalog survive. */
export function axeCriterionIds(tags, standard) {
  const catalog = new Set(standard.criteria.map(row => row.id));
  return [...new Set((tags ?? []).filter(tag => /^wcag\d{3,4}$/.test(tag)).map(tag => {
    const digits = tag.slice(4);
    return `${digits[0]}.${digits[1]}.${Number(digits.slice(2))}`;
  }).filter(id => catalog.has(id)))];
}

/** Index a retained axe record's node bindings once; lookups below are then O(1). */
export function axeBindingIndex(record) {
  const rows = new Map();
  for (const row of record.result?.axeNodeBindings?.rows ?? []) {
    const key = `${row.disposition}|${row.ruleId}|${row.ruleNodeIndex}`;
    rows.set(key, [...(rows.get(key) ?? []), row]);
  }
  const nodes = new Map((record.result?.nodes ?? []).map(node => [`${node.documentId}|${node.nodeId}`, node]));
  return { bindings: record.result?.axeNodeBindings, rows, nodes };
}

/** A binding is usable only when the whole scan was captured in one stable state and still matches the original node. */
export function resolveAxeBinding(record, index, bucket, rule, node, ruleNodeIndex) {
  const { bindings } = index;
  const matches = index.rows.get(`${bucket}|${rule.id}|${ruleNodeIndex}`) ?? [];
  const bound = matches.length === 1 ? matches[0] : null;
  const original = bound ? index.nodes.get(`${bound.documentId}|${bound.nodeId}`) : undefined;
  const valid = bound?.status === 'bound' && bindings.stable === true && bindings.capturedStateId === record.after?.stateId &&
    bindings.capturedDocumentId === record.after?.documentId && bindings.capturedStateId === record.before?.stateId &&
    bindings.capturedDocumentId === record.before?.documentId && bound.documentId === record.after?.documentId &&
    typeof bound.nodeId === 'string' && bound.nodeId.length <= 512 && original &&
    digest(bound.target) === digest(node.target) && bound.selector === original.selector;
  return valid ? { status: 'bound', nodeId: bound.nodeId, documentId: bound.documentId, stableSelector: bound.stableSelector }
    : { status: 'unbound', reason: bound?.status === 'unbound' ? bound.reason : 'no_valid_stable_binding' };
}

// Subjects for rules whose violation is exactly "no accessible name" (axe's own rule semantics, nothing page-specific).
const NAME_SUBJECT = { 'button-name': 'button', 'link-name': 'link', 'input-button-name': 'input button', 'select-name': 'select', 'input-image-alt': 'image input',
  'image-alt': 'image', 'role-img-alt': 'role="img" element', 'svg-img-alt': 'svg image', 'aria-input-field-name': 'ARIA input field', 'aria-command-name': 'ARIA command',
  'aria-toggle-field-name': 'ARIA toggle', 'aria-dialog-name': 'dialog', 'aria-meter-name': 'meter', 'aria-progressbar-name': 'progressbar', 'aria-tooltip-name': 'tooltip',
  'aria-treeitem-name': 'tree item', 'summary-name': 'summary', 'area-alt': 'image map area', 'object-alt': 'object' };
const SEVERITY = { critical: 0, serious: 1, moderate: 2, minor: 3 };
const text = (value, limit) => typeof value === 'string' || typeof value === 'number' ? clip(String(value).replace(/\s+/g, ' ').trim(), limit) : '';

/** `tag[role="..."][type="..."]` of the node captured with the axe scan; only these three attributes, never markup. */
function nodeSummary(original) {
  if (!original?.tag) return '';
  const attributes = ['role', 'type', 'name'].filter(name => typeof original.attributes?.[name] === 'string' && original.attributes[name])
    .map(name => `[${name}="${text(original.attributes[name], 40).replace(/["<>]/g, '')}"]`).join('');
  return `${original.tag}${attributes}`;
}

/** A claim built only from what axe returned for this node (rule, impact, check data and messages), plus the captured node's tag and role/type/name. */
function axeClaim(rule, node, impact, original) {
  const checks = ['any', 'all', 'none'].flatMap(group => Array.isArray(node[group]) ? node[group] : []);
  const contrast = checks.find(check => check?.id === 'color-contrast' && check.data && typeof check.data === 'object' && check.data.fgColor && check.data.bgColor && check.data.contrastRatio !== undefined);
  const summary = nodeSummary(original), tail = `(axe ${rule.id}${impact ? `, ${impact}` : ''})`;
  const on = summary ? ` [${summary}]` : '';
  if (contrast) {
    const { fgColor, bgColor, contrastRatio, expectedContrastRatio, fontSize, fontWeight } = contrast.data;
    const ratio = value => text(value, 12).includes(':') ? text(value, 12) : `${text(value, 12)}:1`;
    const font = [text(fontSize, 30), text(fontWeight, 12)].filter(Boolean).join(' ');
    return clip(`text ${text(fgColor, 20)} on ${text(bgColor, 20)}, ${ratio(contrastRatio)}${expectedContrastRatio !== undefined ? `, needs ${ratio(expectedContrastRatio)}` : ''}${font ? ` (${font})` : ''}${on} ${tail}`, 300);
  }
  // Only when every alternative failed to give a name; any `all`/`none` failure (e.g. alt-space-value) is a different defect, stated by axe's message.
  if (NAME_SUBJECT[rule.id] && !node.all?.length && !node.none?.length) return clip(`${NAME_SUBJECT[rule.id]} has no accessible name${summary.includes('[') ? on : ''} ${tail}`, 300);
  // axe's own check message is the specific statement; the rule help (already the title) only stands in when there is none.
  const message = checks.map(check => text(check?.message, 140)).find(Boolean);
  return clip(`${message || text(rule.help, 120) || rule.id}${on} ${tail}`, 300);
}

/**
 * Compact, redacted candidates for the axe VIOLATIONS of one retained axe record.
 * `incomplete` and `passes` are never candidates. Raw HTML was already omitted at collection;
 * failure summaries are deliberately not copied here, only the check data a claim states.
 */
export function deriveAxeCandidates(record, standard, { records } = {}) {
  const axe = record?.action === 'axe' && record.success === true ? record.result?.axe : undefined;
  if (!Array.isArray(axe?.violations) || !record.result.axeNodeBindings) return [];
  const index = axeBindingIndex(record), rows = [];
  // Run records (when given) let a same-state DOM capture supply a reload-stable selector; otherwise only this record's own binding is used.
  let stableIndex;
  const stableFields = nodeId => {
    stableIndex ??= stableSelectorIndex(Array.isArray(records) && records.some(row => row?.evidenceId === record.evidenceId) ? records : [record]);
    const { stableSelector, stableSelectorConfidence } = stableIndex.fieldsFor({ evidenceId: record.evidenceId, nodeId });
    return stableSelector ? { stableSelector, stableSelectorConfidence } : {};
  };
  axe.violations.forEach((rule, ruleIndex) => {
    const criterionIds = axeCriterionIds(rule.tags, standard);
    (rule.nodes ?? []).forEach((node, ruleNodeIndex) => {
      const binding = resolveAxeBinding(record, index, 'violations', rule, node, ruleNodeIndex);
      const reason = binding.status !== 'bound' ? `unbound:${binding.reason}` : criterionIds.length ? null : 'no_criterion_in_selected_catalog';
      const visual = criterionIds.filter(id => VISUAL_CRITERIA.has(id));
      const target = (Array.isArray(node.target) ? node.target : []).slice(0, 4).map(part => clip(typeof part === 'string' ? part : JSON.stringify(part), 300));
      const impact = node.impact ?? rule.impact ?? null, help = clip(rule.help, 300) ?? null;
      // A stable selector was checked unique in the captured DOM; anything else keeps the axe target at low confidence.
      const axeTarget = clip(target.join(' >> '), 400), stable = binding.stableSelector;
      const checked = binding.status === 'bound' && typeof stable?.selector === 'string' && stable.selector.length <= 400;
      const selector = checked ? stable.selector : axeTarget;
      const original = binding.status === 'bound' ? index.nodes.get(`${binding.documentId}|${binding.nodeId}`) : undefined;
      // Copy-ready for a host's own findings tool only; it is not the checkpoint/submit proposal finding shape (use adoptAxe there). The claim is axe's observation, not a verdict.
      const draftFinding = criterionIds.length ? { pageUrl: clip(record.after?.url, 300) ?? null, selector, selectorConfidence: checked ? stable.confidence : 'low',
        axeTarget, ...(binding.status === 'bound' ? stableFields(binding.nodeId) : {}), criterionId: criterionIds[0], title: clip(help ?? rule.id, 120),
        claim: axeClaim(rule, node, impact, original),
        evidenceIds: [record.evidenceId], ...(binding.status === 'bound' ? { nodeId: binding.nodeId } : {}) } : null;
      rows.push({ candidateId: `${record.evidenceId}:${rule.id}:${ruleNodeIndex}`, ruleId: rule.id, impact,
        help, helpUrl: clip(rule.helpUrl, 300) ?? null, criterionIds, target,
        evidenceId: record.evidenceId, stateId: record.after?.stateId ?? null, documentId: record.after?.documentId ?? null,
        nodeId: binding.status === 'bound' ? binding.nodeId : null, adoptable: reason === null,
        ...(reason ? { notAdoptableReason: reason } : {}),
        ...(visual.length ? { visualEvidenceRequired: visual } : {}),
        ...(draftFinding ? { draftFinding } : {}),
        rawPointer: `/result/axe/violations/${ruleIndex}/nodes/${ruleNodeIndex}` });
    });
  });
  return rows;
}

const RULE_SUMMARY_LIMIT = 40;

/** Rule-first order: one representative per violated rule (worst impact first, an adoptable node when there is one), then every remaining node in axe order. */
export function orderRuleFirst(rows) {
  const rules = new Map();
  for (const row of rows) {
    const rule = rules.get(row.ruleId) ?? { ruleId: row.ruleId, impact: row.impact, criterionIds: row.criterionIds, help: row.help, nodes: 0, adoptable: 0, rows: [] };
    rule.nodes++; if (row.adoptable) rule.adoptable++; rule.rows.push(row); rules.set(row.ruleId, rule);
  }
  const list = [...rules.values()].sort((a, b) => (SEVERITY[a.impact] ?? 4) - (SEVERITY[b.impact] ?? 4));
  for (const rule of list) rule.representative = rule.rows.find(row => row.adoptable) ?? rule.rows[0];
  const representatives = new Set(list.map(rule => rule.representative));
  return { ordered: [...list.map(rule => rule.representative), ...rows.filter(row => !representatives.has(row))],
    summary: list.slice(0, RULE_SUMMARY_LIMIT).map(rule => ({ ruleId: rule.ruleId, impact: rule.impact, criterionIds: rule.criterionIds, nodes: rule.nodes, adoptable: rule.adoptable,
      help: clip(rule.help, 90), firstCandidateId: rule.representative.candidateId })), ruleCount: list.length };
}

const encodeCursor = (record, recordDigest, position) => Buffer.from(JSON.stringify({ v: 1, r: record.evidenceId, d: recordDigest, p: position })).toString('base64url');

function decodeCursor(record, recordDigest, cursor, total) {
  let decoded;
  try { decoded = JSON.parse(Buffer.from(cursor, 'base64url').toString()); } catch { /* reported below */ }
  if (!decoded || decoded.v !== 1 || decoded.r !== record.evidenceId || decoded.d !== recordDigest ||
      !Number.isSafeInteger(decoded.p) || decoded.p < 0 || decoded.p > total || encodeCursor(record, recordDigest, decoded.p) !== cursor) {
    fail('INVALID_AUDIT_CURSOR', `The axe candidate cursor is invalid for this original record. Omit cursor to restart at page 1, or send the pagination.nextRequest of the previous ${record.evidenceId} axe response.`);
  }
  return decoded.p;
}

/**
 * One bounded page. Candidates are rule-first: page 1 opens with `rules` (every violated rule, compact), then one representative
 * node per rule, then the remaining nodes. `maxBytes` bounds the serialized page even if it holds fewer than `limit` rows.
 */
export function pageAxeCandidates(record, standard, { limit = AXE_PAGE_LIMIT, cursor, maxBytes = 40_000, runId, records } = {}) {
  if (record?.action !== 'axe' || record.success !== true || !Array.isArray(record.result?.axe?.violations)) {
    fail('NOT_AN_AXE_RECORD', 'View "axe" requires a successful axe record.');
  }
  const { ordered: all, summary, ruleCount } = orderRuleFirst(deriveAxeCandidates(record, standard, { records })), recordDigest = digest(record);
  const offset = cursor ? decodeCursor(record, recordDigest, cursor, all.length) : 0;
  const adoptable = all.filter(row => row.adoptable).length;
  const page = (end, rows) => {
    const next = end < all.length ? { view: 'axe', limit, cursor: encodeCursor(record, recordDigest, end), ...(runId ? { runId } : {}) } : null;
    const { runId: _runId, ...options } = next ?? {};
    return { evidenceId: record.evidenceId,
      counts: { candidates: all.length, adoptable, notAdoptable: all.length - adoptable, rules: ruleCount },
      // Page 1 only: the rule list, the ordering and the boilerplate that never changes between pages.
      ...(offset === 0 ? { source: 'axe-core violations only; incomplete and passes are never candidates', rules: summary,
        ...(ruleCount > summary.length ? { rulesOmitted: ruleCount - summary.length } : {}),
        order: 'rule-first: one representative node per rule (firstCandidateId), then the remaining nodes',
        adopt: 'In checkpoint/submit put proposal.adoptAxe = "all" | [candidateId, ...]; only adoptable candidates with a stable node binding can be adopted. draftFinding (pageUrl, selector, claim) is only for a host\'s own findings tool: it is not a proposal finding, which needs target:{evidenceId,nodeId}, observation, reason, applicability, exceptions and scope.' } : {}),
      candidates: rows,
      pagination: { offset, returned: rows.length, total: all.length, complete: end >= all.length,
        ...(next ? { more: `more available: ${all.length - end} of ${all.length} candidates; send pagination.nextRequest (cursor only, no offset)` } : {}),
        next, nextRequest: next ? { tool: 'read', evidenceId: record.evidenceId, options } : null } };
  };
  const rows = [];
  let used = bytes(page(offset, rows)) + 256;
  for (let end = offset; end < all.length && rows.length < limit; end++) {
    used += bytes(all[end]) + 1;
    if (used > maxBytes) break;
    rows.push(all[end]);
  }
  const result = page(offset + rows.length, rows);
  if ((!rows.length && offset < all.length) || bytes(result) > maxBytes) {
    fail('AUDIT_AXE_PAGE_TOO_LARGE', 'The axe candidate row or envelope cannot fit in this page. Increase maxBytes, or read {view:"field",field:"/result/axe"} on this evidenceId.');
  }
  return result;
}

/**
 * Expand `adoptAxe` into ordinary findings (one per candidate and mapped criterion). The result is
 * a plain proposal that goes through the unchanged proposal schema and evidence gates.
 */
export function expandAxeAdoption(input, records, standard) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || !Object.hasOwn(input, 'adoptAxe')) return { proposal: input, adoption: null };
  const { adoptAxe, ...rest } = input;
  if (adoptAxe !== 'all' && !(Array.isArray(adoptAxe) && adoptAxe.length > 0 && adoptAxe.length <= 1000 &&
      adoptAxe.every(value => typeof value === 'string' && value.length <= 300) && new Set(adoptAxe).size === adoptAxe.length)) {
    fail('INVALID_AXE_ADOPTION', 'adoptAxe must be "all" or a nonempty array of distinct candidate IDs.');
  }
  if (rest.findings !== undefined && !Array.isArray(rest.findings)) return { proposal: rest, adoption: null };
  const candidates = new Map();
  for (const record of Array.isArray(records) ? records : []) {
    for (const row of deriveAxeCandidates(record, standard)) candidates.set(row.candidateId, row);
  }
  let chosen;
  if (adoptAxe === 'all') chosen = [...candidates.values()].filter(row => row.adoptable);
  else chosen = adoptAxe.map(candidateId => {
    const row = candidates.get(candidateId);
    if (!row) fail('INVALID_AXE_ADOPTION', `Unknown axe violation candidate ID: ${clip(candidateId, 120)}.`);
    if (!row.adoptable) fail('INVALID_AXE_ADOPTION', `Candidate ${candidateId} cannot be adopted: ${row.notAdoptableReason}.`);
    return row;
  });
  const findings = chosen.flatMap(row => row.criterionIds.map(criterionId => ({
    id: `axe:${row.candidateId}:${criterionId}`,
    title: clip(`${row.help ?? row.ruleId} (axe ${row.ruleId})`, 1000),
    criterionId, target: { evidenceId: row.evidenceId, nodeId: row.nodeId }, evidenceIds: [row.evidenceId],
    observation: `axe-core reported rule "${row.ruleId}" (impact: ${row.impact ?? 'unspecified'}) as a violation on ${JSON.stringify(row.target)}. Original result: ${row.evidenceId} ${row.rawPointer}.`,
    reason: `axe-core's tags map rule "${row.ruleId}" to WCAG ${criterionId}${row.helpUrl ? ` (${row.helpUrl})` : ''}. This is an automated observation that needs independent review, not a whole-criterion verdict.`,
    applicability: 'Applicability is whatever axe-core decided for this node in the recorded document and state; not independently verified.',
    exceptions: 'None assessed beyond axe-core rule logic; the reviewer must consider exceptions.',
    scope: 'Only this node in the recorded document and state.',
    method: 'dom', source: 'axe', axeCandidateId: row.candidateId,
  })));
  const skipped = adoptAxe === 'all' ? [...candidates.values()].filter(row => !row.adoptable) : [];
  return { proposal: { ...rest, findings: [...(rest.findings ?? []), ...findings] },
    adoption: { requested: adoptAxe === 'all' ? 'all' : adoptAxe.length, candidatesAdopted: chosen.length, findingsAdded: findings.length,
      notAdoptable: skipped.length, notAdoptableSample: skipped.slice(0, 10).map(row => ({ candidateId: row.candidateId, reason: row.notAdoptableReason })),
      note: 'Adopted findings are source:"axe" drafts. Findings on visual criteria still need their usual same-state PNG evidence at review.' } };
}
