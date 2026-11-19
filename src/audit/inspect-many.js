import { digest, ToolError } from '../evidence.js';
import { inPageStableFields } from './stable-selector.js';

/** Hard bounds. Selector lists are capped by the action schema; the preset is capped here and reports what it omitted. */
export const INSPECT_MANY_MAX_SELECTORS = 50;
export const INSPECT_MANY_PRESET_LIMIT = 150;
export const INSPECT_MANY_PAGE_LIMIT = 40;

/** Exact candidate rule of query:"interactive" (document order, rendered elements of the main document body only). */
export const INTERACTIVE_RULE = Object.freeze({
  native: 'a[href], area[href], button, input (not type=hidden), select, textarea, summary, audio[controls], video[controls], [contenteditable] (not "false")',
  attributes: '[tabindex], [onclick], [role]',
  ariaState: '[aria-expanded], [aria-pressed], [aria-selected], [aria-checked], [aria-haspopup], [aria-autocomplete], [aria-activedescendant], [aria-valuenow], [aria-controls]',
  cursorPointer: 'computed cursor is pointer and the parent element\'s computed cursor is not (the boundary of an inherited pointer cursor)',
  limit: INSPECT_MANY_PRESET_LIMIT,
});

/** Roles whose accessible name the author supplies; the noAccessibleName flag applies only to these. */
const NAMED_ROLES = new Set(['button', 'link', 'checkbox', 'radio', 'switch', 'tab', 'menuitem', 'menuitemcheckbox', 'menuitemradio',
  'option', 'treeitem', 'textbox', 'searchbox', 'combobox', 'slider', 'spinbutton']);
/** Roles whose value reflects user input; matching the existing ARIA snapshot policy, their AX value is never retained. */
const INPUT_VALUE_ROLES = new Set(['textbox', 'searchbox', 'spinbutton', 'combobox']);
const GENERIC_ROLES = new Set(['generic', 'none', 'GenericContainer']);
const RELATION_TYPES = new Set(['idref', 'idrefList', 'nodeList', 'node', 'computedString']);

export const INSPECT_MANY_FLAG_RULES = Object.freeze({
  noAccessibleName: `Chrome's accessibility tree has a non-ignored node whose role is one of [${[...NAMED_ROLES].join(', ')}] and whose computed name is the empty string. Purely an observation of the computed name; placeholder/title fallbacks Chrome applies are already included.`,
  interactiveWithoutRole: 'The element has no role attribute, is not natively interactive, its non-ignored AX role is generic/none, and the author declared interaction with an inline onclick attribute or a tabindex >= 0. Handlers added by addEventListener are not visible to the DOM; cursor:pointer alone never sets this flag.',
  notFlagged: 'Missing aria-expanded/selected/valuenow are not flagged: Chrome supplies defaults (for example slider value 50, checkbox checked:false), so absence in the AX tree is ambiguous. Read the raw `aria` attributes.',
});

const clip = (value, limit) => typeof value === 'string' && value.length > limit ? { text: value.slice(0, limit), truncated: true } : { text: value ?? '', truncated: false };

/** Reduce one Accessibility.getPartialAXTree node to the retained fields. Input values are dropped, never summarized. */
export function compactAxNode(axNode) {
  if (!axNode || typeof axNode !== 'object') return { available: false, reason: 'no_ax_node' };
  const role = axNode.role?.value ?? null, ignored = axNode.ignored === true;
  const states = {};
  for (const property of Array.isArray(axNode.properties) ? axNode.properties : []) {
    const type = property?.value?.type, value = property?.value?.value;
    if (typeof property?.name !== 'string' || RELATION_TYPES.has(type) || value === undefined || typeof value === 'object') continue;
    states[property.name] = value;
  }
  const hideValue = INPUT_VALUE_ROLES.has(role);
  if (hideValue) { delete states.valuenow; delete states.valuetext; }
  const name = clip(typeof axNode.name?.value === 'string' ? axNode.name.value : '', 300);
  const rawValue = axNode.value?.value;
  const value = !hideValue && rawValue !== undefined && rawValue !== null ? clip(String(rawValue), 200) : null;
  return { available: true, ignored, ...(ignored ? { ignoredReasons: (axNode.ignoredReasons ?? []).map(reason => reason?.name).filter(Boolean).slice(0, 6) } : {}),
    role, name: name.text, ...(name.truncated ? { nameTruncated: true } : {}),
    ...(value ? { value: value.text, ...(value.truncated ? { valueTruncated: true } : {}) } : {}),
    ...(hideValue ? { valueOmitted: true } : {}), states };
}

/** Neutral observations from AX + DOM facts; each rule is documented in INSPECT_MANY_FLAG_RULES. */
export function observationFlags(ax, facts) {
  const flags = [];
  if (!ax?.available || ax.ignored) return flags;
  if (NAMED_ROLES.has(ax.role) && ax.name === '') flags.push('noAccessibleName');
  if (facts.explicitRole === null && !facts.nativeInteractive && GENERIC_ROLES.has(ax.role) &&
      (facts.onclickAttr || (facts.tabindexAttr !== null && facts.tabIndex >= 0))) flags.push('interactiveWithoutRole');
  return flags;
}

const round = value => Math.round(value * 10) / 10;

/** Join in-page DOM facts with their AX nodes into the compact retained rows. */
export function buildElementRows(rows, axNodes) {
  return rows.map((fact, index) => {
    const ax = compactAxNode(axNodes[index]);
    const tabStop = ax.available ? ax.states.focusable === true && fact.tabIndex >= 0 : null;
    return { nodeId: fact.nodeId, documentId: fact.documentId, tag: fact.tag, selector: fact.stable.selector,
      selectorBasis: fact.stable.basis, selectorConfidence: fact.stable.confidence, ...inPageStableFields(fact.stable),
      ...(fact.matchedBy ? { matchedBy: fact.matchedBy } : {}),
      visible: fact.visible, box: fact.box.map(round),
      ax, explicitRole: fact.explicitRole, nativeRole: fact.explicitRole === null && ax.available ? ax.role : null,
      aria: fact.aria, focus: { tabIndex: fact.tabIndex, tabindexAttr: fact.tabindexAttr, axFocusable: ax.available ? ax.states.focusable === true : null, tabStop },
      flags: observationFlags(ax, fact) };
  });
}

const encodeCursor = (record, recordDigest, position) => Buffer.from(JSON.stringify({ v: 1, r: record.evidenceId, d: recordDigest, p: position })).toString('base64url');

function decodeCursor(record, recordDigest, cursor, total) {
  let decoded;
  try { decoded = JSON.parse(Buffer.from(cursor, 'base64url').toString()); } catch { /* reported below */ }
  if (!decoded || decoded.v !== 1 || decoded.r !== record.evidenceId || decoded.d !== recordDigest ||
      !Number.isSafeInteger(decoded.p) || decoded.p < 0 || decoded.p > total || encodeCursor(record, recordDigest, decoded.p) !== cursor) {
    throw new ToolError('INVALID_AUDIT_CURSOR', `The inspect_many cursor is invalid for this original record. Omit cursor to restart at page 1, or send the pagination.nextRequest of the previous ${record.evidenceId} elements response.`);
  }
  return decoded.p;
}

const bytes = value => Buffer.byteLength(JSON.stringify(value), 'utf8');

/**
 * One bounded page of the compact element rows of a successful inspect_many record. `maxBytes` bounds the serialized
 * page even if it holds fewer than `limit` rows; pagination.nextRequest is the exact read call for the next page.
 */
export function pageInspectElements(record, { limit = INSPECT_MANY_PAGE_LIMIT, cursor, maxBytes = 16_000 } = {}) {
  if (record?.action !== 'inspect_many' || record.success !== true || !Array.isArray(record.result?.elements)) {
    throw new ToolError('NOT_AN_INSPECT_MANY_RECORD', 'View "elements" requires a successful inspect_many record.');
  }
  const all = record.result.elements, recordDigest = digest(record);
  const offset = cursor ? decodeCursor(record, recordDigest, cursor, all.length) : 0;
  const page = (end, rows) => {
    const next = end < all.length ? { view: 'elements', limit, cursor: encodeCursor(record, recordDigest, end) } : null;
    return { evidenceId: record.evidenceId, stateId: record.after?.stateId ?? null, documentId: record.after?.documentId ?? null,
      counts: record.result.counts,
      ...(offset === 0 ? { source: record.result.observationSource, query: record.result.query,
        ...(record.result.selectorStatus?.some(row => row.status !== 'ok') ? { selectorStatus: record.result.selectorStatus.filter(row => row.status !== 'ok').slice(0, 20) } : {}),
        flagRules: INSPECT_MANY_FLAG_RULES, use: 'Observations only. To cite one in a finding, use target {evidenceId, nodeId} from a row; the row\'s selector re-targets it for inspect/click.' } : {}),
      elements: rows,
      pagination: { offset, returned: rows.length, total: all.length, complete: end >= all.length,
        ...(next ? { more: `more available: ${all.length - end} of ${all.length} elements; send pagination.nextRequest (cursor only, no offset)` } : {}),
        next, nextRequest: next ? { tool: 'read', evidenceId: record.evidenceId, options: next } : null } };
  };
  const rows = [];
  let used = bytes(page(offset, rows)) + 512;
  for (let end = offset; end < all.length && rows.length < limit; end++) {
    used += bytes(all[end]) + 1;
    if (used > maxBytes) break;
    rows.push(all[end]);
  }
  if (!rows.length && offset < all.length) throw new ToolError('AUDIT_ELEMENT_PAGE_TOO_LARGE', 'One element row cannot fit in a bounded page; read /result/elements with view:"field".');
  return page(offset + rows.length, rows);
}
