// Reload-stable selectors for recorded target nodes. Pure: reads retained records only, never a page.
//
// Order of preference: a unique non-generated id; a test attribute (data-testid, data-test-id, data-test, data-qa, ...);
// a unique name / aria-label / label[for]; another stable data-* attribute; non-generated classes; then a short path
// from the nearest such anchor. Positional chains are a last resort and are labelled as such. Uniqueness is checked
// against the DOM the run captured; selectors that the page itself checked against its full DOM are preferred on ties.
// The generated-token rules mirror createStableSelector in browser.js, which must stay self-contained for page.evaluate.

export const STABLE_SELECTOR_CONFIDENCE = Object.freeze(['unique-anchor', 'anchored-path', 'positional-fallback']);
const RANK = { 'unique-anchor': 2, 'anchored-path': 1, 'positional-fallback': 0 };
const MAX_SELECTOR = 400, MAX_DEPTH = 6, MAX_PATH_DEPTH = 16;

export const generatedValue = value => value.length > 80 || /[\u0000-\u001f]/.test(value) || /[-_:]\d+(?:[-_:]|$)/.test(value) || /^:[\w:-]*:$/.test(value) ||
  /^(?:radix|headlessui|react-aria|ember|ext-gen|yui|mui|rc|uid|auto)[-_:]?[\w:-]*\d/i.test(value) || /[0-9a-f]{8}-[0-9a-f]{4}/i.test(value) ||
  /(?=[0-9a-f]*\d)[0-9a-f]{8,}/i.test(value) || /\d{5,}/.test(value) || /(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{12,}/.test(value);
export const generatedClass = value => generatedValue(value) || /^(?:css|sc|jsx|svelte|emotion|styled|ng|chakra)-/.test(value) || /__[\w-]{5,}$/.test(value) ||
  /^_[\w-]{5,}$/.test(value) || /^(?:active|open|opened|closed|hover|focus|focused|selected|disabled|checked|hidden|show|shown|visible|expanded|collapsed|loading|current|on|off|in|out)$/.test(value);
const TEST_ATTRIBUTES = ['data-testid', 'data-test-id', 'data-test', 'data-qa', 'data-cy', 'data-automation-id'];
// Framework bookkeeping and tooltip libraries that rewrite their attribute at runtime (bootstrap's data-original-title).
const SKIPPED_DATA = /^data-(?:v-|react|radix|state$|orientation$|headlessui|emotion|styled|ng|ember|index$|key$|rbd|rr-|astro|svelte|sentry|original-title$|bs-original-title$|id$)/;
const IDENT = /^-?[A-Za-z_][A-Za-z0-9_-]*$/;
// in-page basis -> confidence; positional, path and raw axe-target results are never promoted.
const IN_PAGE_BASIS = { id: 'unique-anchor', 'data-attribute': 'unique-anchor', name: 'unique-anchor', 'aria-attribute': 'unique-anchor',
  attribute: 'unique-anchor', attributes: 'unique-anchor', class: 'unique-anchor', ancestor: 'anchored-path' };

const quote = value => `"${value.replace(/["\\]/g, '\\$&')}"`;
const usable = value => typeof value === 'string' && value.length > 0 && !generatedValue(value);
const classesOf = node => typeof node.attributes?.class === 'string' ? node.attributes.class.split(/\s+/).filter(Boolean) : [];
const positional = css => /:nth-(?:of-type|child)\(/.test(css);

/** A selector leaning on a generated #id or .class token is not reload-stable. */
export function usesGeneratedToken(css) {
  return (css.match(/#(?:\\.|[\w-])+/g) ?? []).some(token => generatedValue(token.slice(1).replace(/\\/g, ''))) ||
    (css.match(/\.(?:\\.|[\w-])+/g) ?? []).some(token => generatedClass(token.slice(1).replace(/\\/g, '')));
}

function css(step) {
  const id = step.id === undefined ? '' : IDENT.test(step.id) ? `#${step.id}` : `[id=${quote(step.id)}]`;
  return `${step.tag ?? ''}${id}${(step.attrs ?? []).map(([name, value]) => `[${name}=${quote(value)}]`).join('')}${(step.classes ?? []).map(name => `.${name}`).join('')}`;
}

/** Keys the in-page snapshot index uses (browser.js anchorIndex): any key absent there matches no uncaptured element. */
function impliedKeys(step) {
  const tag = step.tag ?? '*';
  return [...(step.tag ? [step.tag] : []), ...(step.id !== undefined ? [`${tag} id=${step.id}`] : []),
    ...(step.attrs ?? []).map(([name, value]) => `${tag} ${name}=${value}`), ...(step.tag ? (step.classes ?? []).map(name => `${step.tag} .${name}`) : [])];
}

/**
 * One captured DOM (one document state): node lookup plus attribute/class/tag postings for fast uniqueness counts.
 * With the snapshot's uncaptured-anchor index, a step also has to match no uncaptured element, which makes the check
 * cover the whole document; without it (older records, screenshots) only the captured nodes are known.
 */
function captureIndex(nodes, uncaptured) {
  const keys = uncaptured?.version === 1 && uncaptured.keys && typeof uncaptured.keys === 'object' ? uncaptured.keys : null;
  const absentElsewhere = step => impliedKeys(step).some(key => !Object.hasOwn(keys, key));
  const byId = new Map(), postings = new Map();
  const post = (key, node) => { const list = postings.get(key); if (list) list.push(node); else postings.set(key, [node]); };
  for (const node of nodes) {
    if (!node || typeof node.nodeId !== 'string' || byId.has(node.nodeId)) continue;
    byId.set(node.nodeId, node);
    post(`t\u0000${node.tag}`, node);
    for (const [name, value] of Object.entries(node.attributes ?? {})) if (typeof value === 'string' && value.length <= 200) post(`a\u0000${name}\u0000${value}`, node);
    for (const name of classesOf(node)) post(`c\u0000${name}`, node);
  }
  const matches = (step, node) => (!step.tag || node.tag === step.tag) && (step.id === undefined || node.attributes?.id === step.id) &&
    (step.attrs ?? []).every(([name, value]) => node.attributes?.[name] === value) && (step.classes ?? []).every(name => classesOf(node).includes(name));
  const candidates = step => {
    const keys = [...(step.id !== undefined ? [`a\u0000id\u0000${step.id}`] : []), ...(step.attrs ?? []).map(([name, value]) => `a\u0000${name}\u0000${value}`),
      ...(step.classes ?? []).map(name => `c\u0000${name}`), ...(step.tag ? [`t\u0000${step.tag}`] : [])];
    let best = null;
    for (const key of keys) { const list = postings.get(key) ?? []; if (!best || list.length < best.length) best = list; }
    return (best ?? []).filter(node => matches(step, node));
  };
  const hasAncestor = (node, step) => {
    for (let parent = byId.get(node.parentNodeId), depth = 0; parent && depth < 128; parent = byId.get(parent.parentNodeId), depth++) if (matches(step, parent)) return true;
    return false;
  };
  /** True when [anchor] target (descendant combinator) matches exactly `node` in this capture (and nothing uncaptured, when known). */
  const unique = (steps, node) => {
    if (keys && !steps.every(absentElsewhere)) return false;
    const found = candidates(steps.at(-1)).filter(candidate => steps.length === 1 || hasAncestor(candidate, steps[0]));
    return found.length === 1 && found[0] === node;
  };
  const anchors = new Map();
  const anchorFor = node => {
    if (!anchors.has(node.nodeId)) anchors.set(node.nodeId, ownSteps(node).find(({ step }) => unique([step], node)) ?? null);
    return anchors.get(node.nodeId);
  };
  return { byId, unique, anchorFor, check: keys ? 'full-dom-at-capture' : 'captured-dom' };
}

function ownSteps(node) {
  const tag = node.tag, attributes = node.attributes ?? {}, steps = [];
  if (usable(attributes.id)) steps.push({ step: { id: attributes.id }, basis: 'id' });
  for (const name of TEST_ATTRIBUTES) if (usable(attributes[name])) steps.push({ step: { attrs: [[name, attributes[name]]] }, basis: 'test-attribute' }, { step: { tag, attrs: [[name, attributes[name]]] }, basis: 'test-attribute' });
  for (const name of ['name', 'aria-label']) if (usable(attributes[name])) steps.push({ step: { tag, attrs: [[name, attributes[name]]] }, basis: name });
  if (tag === 'label' && usable(attributes.for)) steps.push({ step: { tag, attrs: [['for', attributes.for]] }, basis: 'for' });
  for (const [name, value] of Object.entries(attributes)) {
    if (name.startsWith('data-') && !TEST_ATTRIBUTES.includes(name) && !SKIPPED_DATA.test(name) && usable(value)) steps.push({ step: { tag, attrs: [[name, value]] }, basis: 'data-attribute' });
  }
  const classes = classesOf(node).filter(name => IDENT.test(name) && !generatedClass(name)).slice(0, 4);
  for (const name of classes) steps.push({ step: { tag, classes: [name] }, basis: 'class' });
  for (let i = 0; i < classes.length; i++) for (let j = i + 1; j < classes.length; j++) steps.push({ step: { tag, classes: [classes[i], classes[j]] }, basis: 'class' });
  return steps;
}

/** Descendant forms of the target under an anchor, most specific-but-stable last. */
function descendantSteps(node) {
  const tag = node.tag, attributes = node.attributes ?? {}, steps = [{ tag }];
  for (const name of ['role', 'type', 'name', 'aria-label']) if (usable(attributes[name])) steps.push({ tag, attrs: [[name, attributes[name]]] });
  for (const [name, value] of Object.entries(attributes)) if (name.startsWith('data-') && !SKIPPED_DATA.test(name) && usable(value)) steps.push({ tag, attrs: [[name, value]] });
  for (const name of classesOf(node).filter(name => IDENT.test(name) && !generatedClass(name)).slice(0, 3)) steps.push({ tag, classes: [name] });
  return steps;
}

/** Computed from one captured DOM. `node.selector` (the original positional path) is only reused, never rewritten. */
function fromCapture(node, capture, complete) {
  const own = capture.byId.get(node.nodeId) ?? null;
  const subject = own ?? node;
  if (own && complete) {
    const anchor = capture.anchorFor(own);
    if (anchor) return { selector: css(anchor.step), confidence: 'unique-anchor', check: capture.check };
  }
  const segments = typeof subject.selector === 'string' && subject.selector.startsWith('html') ? subject.selector.split(' > ') : null;
  let path = null;
  if (own && complete) {
    for (let ancestor = capture.byId.get(own.parentNodeId), depth = 1; ancestor && ancestor.tag !== 'body' && depth <= MAX_PATH_DEPTH; ancestor = capture.byId.get(ancestor.parentNodeId), depth++) {
      if (depth > MAX_DEPTH && path) break;
      const anchor = capture.anchorFor(ancestor);
      if (!anchor) continue;
      const found = depth <= MAX_DEPTH && descendantSteps(own).find(step => capture.unique([anchor.step, step], own));
      if (found) return { selector: `${css(anchor.step)} ${css(found)}`, confidence: 'anchored-path', check: capture.check };
      // An anchored child chain reuses the original positional steps below the anchor (they were indexed in the full DOM).
      if (!path && segments && segments.length > depth) path = { selector: `${css(anchor.step)} > ${segments.slice(-depth).join(' > ')}`, confidence: 'positional-fallback', check: capture.check };
    }
  }
  if (path) return path;
  if (typeof subject.selector === 'string' && subject.selector && !usesGeneratedToken(subject.selector)) {
    return { selector: subject.selector, confidence: positional(subject.selector) ? 'positional-fallback' : 'unique-anchor', check: 'full-dom-at-capture' };
  }
  return null;
}

/** Map a selector the page checked unique against its full DOM ({selector, basis}) into this vocabulary; null when it is positional or generated. */
export function classifyInPageStable(stable) {
  const confidence = IN_PAGE_BASIS[stable?.basis];
  if (!confidence || typeof stable.selector !== 'string' || !stable.selector || stable.selector.length > MAX_SELECTOR ||
      positional(stable.selector) || usesGeneratedToken(stable.selector)) return null;
  return { selector: stable.selector, confidence, check: 'full-dom-at-capture' };
}

/** Fields for one row the page checked itself (inspect_many, inspect): a positional result stays labelled positional; generated tokens abstain. */
export function inPageStableFields(stable) {
  const classified = classifyInPageStable(stable);
  if (classified) return { stableSelector: classified.selector, stableSelectorConfidence: classified.confidence };
  const selector = stable?.selector;
  return typeof selector === 'string' && selector && selector.length <= MAX_SELECTOR && !usesGeneratedToken(selector)
    ? { stableSelector: selector, stableSelectorConfidence: 'positional-fallback' } : {};
}

const fullCapture = record => record?.success === true && Array.isArray(record.result?.nodes) && record.result.truncation && typeof record.result.truncation === 'object';
const complete = record => record.result.truncation.omittedVisibleElements === 0;

/** Selectors the page itself checked against its full DOM, per node, from records of one document state. */
function inPageIndex(records, documentId, stateId) {
  const found = new Map();
  const add = (nodeId, stable) => { const value = classifyInPageStable(stable); if (value) found.set(nodeId, [...(found.get(nodeId) ?? []), value]); };
  for (const record of records) {
    if (record?.success !== true || record.after?.documentId !== documentId || record.after?.stateId !== stateId) continue;
    for (const row of Array.isArray(record.result?.elements) ? record.result.elements : []) {
      if (row?.documentId === documentId) add(row.nodeId, { selector: row.selector, basis: row.selectorBasis });
    }
    const bindings = record.result?.axeNodeBindings;
    if (bindings?.stable === true) for (const row of Array.isArray(bindings.rows) ? bindings.rows : []) {
      if (row?.status === 'bound' && row.documentId === documentId && row.stableSelector) add(row.nodeId, row.stableSelector);
    }
    const element = record.result?.element;
    if (element?.documentId === documentId && element.stableSelector) add(element.nodeId, element.stableSelector);
  }
  return found;
}

/**
 * Index over one run's retained records. `fieldsFor(target)` returns the additive target fields
 * {stableSelector, stableSelectorConfidence, stableSelectorCheck}, or {} when no selector can be stated.
 */
export function stableSelectorIndex(records) {
  const list = Array.isArray(records) ? records : [], byEvidence = new Map(list.map(record => [record?.evidenceId, record]));
  const position = new Map(list.map((record, index) => [record, index]));
  const memo = new Map(), captures = new Map(), inPage = new Map();
  const captureOf = record => {
    if (!captures.has(record)) captures.set(record, captureIndex(record.result.nodes, record.result.uncapturedAnchors));
    return captures.get(record);
  };
  const empty = captureIndex([], null);
  const pick = target => {
    const record = byEvidence.get(target?.evidenceId);
    const documentId = record?.after?.documentId, stateId = record?.after?.stateId;
    if (!record || typeof documentId !== 'string' || typeof stateId !== 'string') return null;
    const nodes = [...(Array.isArray(record.result?.nodes) ? record.result.nodes : []), ...(record.result?.element ? [record.result.element] : [])];
    const node = nodes.find(row => row?.nodeId === target.nodeId && row.documentId === documentId);
    if (!node) return null;
    // The target record when it captured the whole document, otherwise the nearest full capture of the same state.
    const index = position.get(record);
    // Prefer a capture with the uncaptured-anchor index (snapshots), then the nearest one.
    const indexed = row => row.result.uncapturedAnchors?.keys ? 0 : 1;
    const sameState = list.filter(row => fullCapture(row) && row.after?.documentId === documentId && row.after?.stateId === stateId)
      .sort((a, b) => indexed(a) - indexed(b) || Math.abs(position.get(a) - index) - Math.abs(position.get(b) - index));
    const capture = sameState.find(row => captureOf(row).byId.has(node.nodeId)) ?? sameState[0];
    const computed = capture ? fromCapture(node, captureOf(capture), complete(capture)) : fromCapture(node, empty, false);
    const stateKey = `${documentId}|${stateId}`;
    if (!inPage.has(stateKey)) inPage.set(stateKey, inPageIndex(list, documentId, stateId));
    const options = [...(inPage.get(stateKey).get(node.nodeId) ?? []), ...(computed ? [computed] : [])];
    // Highest confidence wins; on a tie the page's own full-DOM check wins over the captured-DOM check.
    options.sort((a, b) => RANK[b.confidence] - RANK[a.confidence] || (b.check === 'full-dom-at-capture') - (a.check === 'full-dom-at-capture'));
    const best = options.find(option => option.selector.length <= MAX_SELECTOR);
    if (!best) return null;
    return { stableSelector: best.selector, stableSelectorConfidence: best.confidence, stableSelectorCheck: best.check };
  };
  return {
    fieldsFor(target) {
      const key = `${target?.evidenceId}|${target?.nodeId}`;
      if (!memo.has(key)) { let value = null; try { value = pick(target); } catch { value = null; } memo.set(key, value); }
      return memo.get(key) ? { ...memo.get(key) } : {};
    },
  };
}

export function stableSelectorFor(records, target) {
  return stableSelectorIndex(records).fieldsFor(target);
}

export const STABLE_SELECTOR_NOTE = 'stableSelector re-finds the target after a reload: unique-anchor = own id/test/name/aria-label/data attribute or class; anchored-path = short path from such an anchor; positional-fallback = position-dependent. stableSelectorCheck says where uniqueness was checked (full-dom-at-capture = the whole page DOM at capture; captured-dom = only the rendered nodes this run captured). Keep selector as recorded.';
