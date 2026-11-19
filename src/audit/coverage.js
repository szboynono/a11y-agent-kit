/**
 * Deterministic, non-blocking coverage progress for an agent session.
 *
 * Computed only from the session's own records, budget counters and latest draft. It never blocks,
 * refuses or changes a finding; it shows the host what the recorded evidence has not yet touched.
 * An item the records cannot support is listed in `abstained` instead of being guessed.
 */
import { isInteractiveNode } from './precheck.js';

export const COVERAGE_VERSION = 'coverage-1';
// Suggestions stop once either half of the wall time or calls is used; the budget line needs both under a quarter.
export const SUGGEST_BELOW = 0.5;
export const ADVISE_BELOW = 0.25;
const MAX_SUGGESTIONS = 3;
const MAX_LISTED_VIEWPORTS = 8;
const TAB = /^(?:Shift\+)?Tab$/i;
const PNG_ACTIONS = new Set(['screenshot', 'contrast', 'measure_nontext']);

const ratio = (used, total) => total > 0 ? Math.min(1, Math.round((used / total) * 100) / 100) : 1;
export const viewportLabel = viewport => Number.isInteger(viewport?.width) && Number.isInteger(viewport?.height) ? `${viewport.width}x${viewport.height}` : null;
const key = (documentId, nodeId) => documentId && nodeId ? `${documentId}|${nodeId}` : null;

/** Facts one immutable record contributes; cached by evidenceId so repeated envelopes stay cheap. */
function recordFacts(record, cache) {
  if (cache?.has(record.evidenceId)) return cache.get(record.evidenceId);
  const facts = { interactive: [], examined: [], nodeBearing: false };
  if (record.success === true) {
    const result = record.result ?? {}, documentId = record.after?.documentId;
    const nodes = Array.isArray(result.nodes) ? result.nodes : [];
    if (nodes.length || Array.isArray(result.elements)) facts.nodeBearing = true;
    for (const node of nodes) if (isInteractiveNode(node)) facts.interactive.push(key(node.documentId ?? documentId, node.nodeId));
    // inspect_many rows were selected as interactive (preset) or named by the host (selectors).
    for (const row of Array.isArray(result.elements) ? result.elements : []) facts.interactive.push(key(row.documentId ?? documentId, row.nodeId));
    // Individually examined: one inspect, one click/fill target, one measured element, or the element a global key press focused.
    const single = result.element ?? result.target;
    if (['inspect', 'click', 'fill', 'measure_nontext'].includes(record.action) && single) {
      const singleKey = key(single.documentId ?? documentId, single.nodeId);
      facts.examined.push(singleKey);
      if (isInteractiveNode(single)) { facts.interactive.push(singleKey); facts.nodeBearing = true; }
    }
    if (record.action === 'press' && record.after?.active) facts.examined.push(key(record.after.active.documentId ?? documentId, record.after.active.nodeId));
    facts.interactive = facts.interactive.filter(Boolean); facts.examined = facts.examined.filter(Boolean);
  }
  cache?.set(record.evidenceId, facts);
  return facts;
}

/** Axe candidates that can be adopted, one per document/node/rule, and whether the draft adopts or cites each. */
function axeProgress(records, candidatesFor, findings) {
  const scanned = records.filter(record => record.action === 'axe' && record.success === true);
  if (!scanned.length || typeof candidatesFor !== 'function') return null;
  const documentOf = new Map(records.map(record => [record.evidenceId, record.after?.documentId]));
  const adoptedIds = new Set(), cited = new Set();
  for (const finding of findings) {
    if (typeof finding?.axeCandidateId === 'string') adoptedIds.add(finding.axeCandidateId);
    const nodeKey = key(documentOf.get(finding?.target?.evidenceId), finding?.target?.nodeId);
    if (nodeKey && typeof finding.criterionId === 'string') cited.add(`${nodeKey}|${finding.criterionId}`);
  }
  const groups = new Map();
  for (const record of scanned) {
    for (const row of candidatesFor(record) ?? []) {
      if (!row?.adoptable) continue;
      const nodeKey = key(record.after?.documentId, row.nodeId), group = `${nodeKey ?? row.candidateId}|${row.ruleId}`;
      const addressed = adoptedIds.has(row.candidateId) || (nodeKey !== null && (row.criterionIds ?? []).some(id => cited.has(`${nodeKey}|${id}`)));
      groups.set(group, groups.get(group) === true || addressed);
    }
  }
  return { adoptable: groups.size, unaddressed: [...groups.values()].filter(addressed => !addressed).length };
}

/**
 * input: { records, elapsedMs, wallMs, toolCalls, maxToolCalls, inScopeViewports, viewed:Set<evidenceId>,
 *          findings (latest draft or submitted proposal, or null when none), catalogSize, candidatesFor(record), cache }
 * Returns { coverage, gaps } where gaps are ordered by expected yield; each gap has `next` and `short` text.
 */
export function deriveCoverage(input) {
  const records = Array.isArray(input.records) ? input.records : [];
  const coverage = { version: COVERAGE_VERSION, advisory: true,
    used: { time: ratio(input.elapsedMs, input.wallMs), calls: ratio(input.toolCalls, input.maxToolCalls) } };
  const abstained = [], gaps = [];
  const ok = records.filter(record => record.success === true);

  const tabPresses = ok.filter(record => record.action === 'press' && TAB.test(String(record.result?.key ?? record.arguments?.key ?? ''))).length;
  coverage.keyboard = { tabPresses, traversal: tabPresses >= 2 };
  if (!coverage.keyboard.traversal) gaps.push({ next: `Tab through the page: step with several {action:'press',key:'Tab'}, then inspect focus (${tabPresses ? 'only 1 Tab press' : 'no keyboard traversal'} recorded)`, short: 'keyboard Tab traversal' });

  const inScope = [...new Set((input.inScopeViewports ?? []).map(viewportLabel).filter(Boolean))];
  const captured = [...new Set(ok.filter(record => record.png && PNG_ACTIONS.has(record.action)).map(record => viewportLabel(record.after?.viewport)).filter(Boolean))];
  coverage.viewports = { inScope: inScope.slice(0, MAX_LISTED_VIEWPORTS), captured: captured.slice(0, MAX_LISTED_VIEWPORTS) };
  for (const label of inScope.filter(label => !captured.includes(label))) {
    gaps.push({ next: `Capture ${label} (in scope, not captured): step [{action:'viewport',width:${label.split('x')[0]},height:${label.split('x')[1]}},{action:'screenshot'}], then view it`, short: `${label} screenshot` });
  }

  const pngIds = ok.filter(record => record.png).map(record => record.evidenceId);
  const viewed = pngIds.filter(id => input.viewed?.has(id)).length;
  coverage.screenshots = { captured: pngIds.length, viewed };
  if (pngIds.length > viewed) gaps.push({ next: `View ${pngIds.length - viewed} captured screenshot(s) not yet viewed ({tool:'view',evidenceId})`, short: `${pngIds.length - viewed} unviewed screenshot(s)` });

  const seen = new Set(), examined = new Set();
  let nodeBearing = false;
  for (const record of records) {
    const facts = recordFacts(record, input.cache);
    nodeBearing ||= facts.nodeBearing;
    for (const id of facts.interactive) seen.add(id);
    for (const id of facts.examined) examined.add(id);
  }
  if (!nodeBearing) abstained.push('interactive');
  else {
    const hit = [...examined].filter(id => seen.has(id)).length;
    coverage.interactive = { seen: seen.size, examined: hit };
    if (seen.size && hit < seen.size / 2) gaps.push({ next: `${seen.size} interactive elements seen, ${hit} examined individually: click/fill/inspect the untested ones (menus, editors, dialogs)`, short: `${seen.size - hit} of ${seen.size} interactive elements not examined` });
  }

  const findings = Array.isArray(input.findings) ? input.findings : null;
  const axe = axeProgress(records, input.candidatesFor, findings ?? []);
  if (!axe) abstained.push('axe');
  else {
    coverage.axe = axe;
    if (axe.unaddressed) gaps.push({ next: `${axe.unaddressed} adoptable axe candidate(s) not adopted or cited: checkpoint with adoptAxe:'all' or cite them`, short: `${axe.unaddressed} axe candidate(s) unaddressed` });
  }

  if (!findings) abstained.push('criteria');
  else coverage.criteria = { cited: new Set(findings.filter(finding => typeof finding?.criterionId === 'string' &&
    ((Array.isArray(finding.evidenceIds) && finding.evidenceIds.length) || finding.target?.evidenceId)).map(finding => finding.criterionId)).size,
    catalog: Number.isInteger(input.catalogSize) ? input.catalogSize : null };

  const states = new Set(ok.map(record => record.after?.stateId).filter(Boolean)), urls = new Set(ok.map(record => record.after?.url).filter(Boolean));
  if (!states.size) abstained.push('states');
  else {
    coverage.states = states.size; coverage.urls = urls.size;
    if (urls.size <= 1 && states.size <= 2) gaps.push({ next: `Only ${states.size} page state(s) observed: open menus/dialogs, run an editing workflow, or navigate`, short: 'other page states' });
  }

  if (abstained.length) coverage.abstained = abstained;
  return { coverage, gaps };
}

/** At most three next actions while less than half of wall time and calls are used; never while closed. */
export function suggestNext(coverage, gaps, { open = true } = {}) {
  if (!open || Math.max(coverage.used.time, coverage.used.calls) >= SUGGEST_BELOW || !gaps.length) return null;
  return gaps.slice(0, MAX_SUGGESTIONS).map(gap => gap.next);
}

/** One advisory line for checkpoint/submit ACKs when under a quarter of the budget is used; null otherwise. */
export function budgetAdvisory(coverage, gaps) {
  const used = Math.max(coverage.used.time, coverage.used.calls);
  if (used >= ADVISE_BELOW || !gaps.length) return null;
  return `Advisory only (findings unchanged): ${Math.round((1 - used) * 100)}% of the wall time and call budget remains, and these checks were not done: ${gaps.map(gap => gap.short).join('; ')}.`;
}
