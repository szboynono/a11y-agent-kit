import { requiresReReview } from './review-policy.js';

/**
 * Honest evidence gaps: one predicate and one set of wording, shared by the HTML report and the JSON audit summary,
 * so both say the same thing about the same finding. Three states are kept apart:
 *   missing     - nothing was recorded for the item;
 *   unavailable - the report refers to a record, but it could not be read, so it cannot be used as evidence;
 *   unverified  - the item is recorded, but the finding has not passed independent review and the evidence gate.
 * Only the items listed in GAP_ITEMS are classified. Anything else is not claimed either way.
 */
export const GAP_VERSION = 'evidence-gaps-1';
export const GAP_STATES = Object.freeze({
  missing: Object.freeze({ label: 'Missing', meaning: 'Nothing was recorded for this item. A missing record is not evidence for or against the finding.' }),
  unavailable: Object.freeze({ label: 'Unavailable', meaning: 'The report refers to this record, but it could not be read. It cannot be used as evidence about the finding.' }),
  unverified: Object.freeze({ label: 'Unverified', meaning: 'This item is recorded, but the finding has not passed independent review and the evidence gate.' }),
});
export const GAP_ITEMS = Object.freeze({
  review: Object.freeze({
    label: 'Review',
    missing: 'No reviewer decision was recorded for this finding.',
    unverified: 'Not confirmed by independent review and the evidence gate.',
  }),
  targetSelector: Object.freeze({
    label: 'Target selector',
    missing: 'No target selector was recorded for this finding.',
    unavailable: 'The target evidence record could not be read, so its selector cannot be shown.',
  }),
});
/** Said wherever gaps are listed without reading evidence files (the JSON summary). */
export const GAP_LOOKUP_NOTE = 'This view reads only the report document, not evidence files, so it reports no Unavailable items; views that read evidence files (the HTML report) can.';

const array = value => Array.isArray(value) ? value : [];
const modeOf = kind => ({ 'audit-review': 'reviewed', 'audit-proposal': 'proposal', 'audit-checkpoint-1': 'checkpoint' })[kind];

/**
 * Review placement of each original finding: where its row sits (confirmed, queue, rejected), its displayed status and
 * whether a reviewer decision was recorded. Confirmations under a legacy review policy are shown as needing review.
 */
export function reviewPlacement(report) {
  const mode = modeOf(report?.kind);
  const reReview = requiresReReview(report);
  const decisions = new Map(array(report?.decisions).map(decision => [decision?.findingId, decision]));
  const byId = (rows, status) => array(rows).map(row => [row?.id, { row, status }]);
  const placed = new Map([...byId(report?.verificationQueue, 'queue'), ...byId(report?.rejectedObservations, 'rejected'), ...byId(report?.confirmedFindings, 'confirmed')]);
  const statusOf = id => {
    const hit = placed.get(id);
    if (hit?.status === 'confirmed' && !reReview) return 'confirmed';
    return hit?.status === 'rejected' ? 'rejected' : 'needs_review';
  };
  return { mode, reReview, decisions, placed, statusOf, decisionRecorded: id => mode === 'reviewed' && decisions.has(id) };
}

const gap = (item, state) => ({ item, state, label: GAP_STATES[state].label, text: GAP_ITEMS[item][state] });

/**
 * Gaps of one finding, in a fixed item order. `selectorRecorded` says whether a target selector is known.
 * `lookup` is null when no evidence file was read (then the target selector is not classified), or
 * `{ targetRecord: 'read' | 'unavailable' }` after the target evidence record was looked up.
 */
export function findingGaps({ mode, status, decisionRecorded, evidenceId, selectorRecorded }, lookup = null) {
  const gaps = [];
  if (status === 'needs_review') gaps.push(gap('review', mode === 'reviewed' && !decisionRecorded ? 'missing' : 'unverified'));
  if (!selectorRecorded && lookup) {
    gaps.push(gap('targetSelector', typeof evidenceId === 'string' && evidenceId && lookup.targetRecord === 'unavailable' ? 'unavailable' : 'missing'));
  }
  return gaps;
}

/** The additive JSON summary block for a proposal or review: shared wording plus finding IDs per item and state. */
export function summarizeGaps(report) {
  const placement = reviewPlacement(report);
  if (!placement.mode || placement.mode === 'checkpoint') return null;
  const groups = new Map();
  for (const finding of array(report.findings)) {
    const row = placement.placed.get(finding?.id)?.row;
    const selector = row?.targetObservation?.selector;
    for (const entry of findingGaps({ mode: placement.mode, status: placement.statusOf(finding?.id), decisionRecorded: placement.decisionRecorded(finding?.id),
      evidenceId: finding?.target?.evidenceId, selectorRecorded: typeof selector === 'string' && selector.length > 0 })) {
      const key = `${entry.item}|${entry.state}`;
      if (!groups.has(key)) groups.set(key, { ...entry, findingIds: [] });
      groups.get(key).findingIds.push(finding.id);
    }
  }
  return { version: GAP_VERSION, states: GAP_STATES, fileLookups: 'not-performed', note: GAP_LOOKUP_NOTE, items: [...groups.values()] };
}
