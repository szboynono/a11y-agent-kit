/**
 * Deterministic, non-blocking applicability notes for draft findings.
 *
 * Notes are computed only from evidence already recorded in the session (DOM node records,
 * attributes, ancestor chains and optional inspect_many AX rows). They never block, drop,
 * confirm or rewrite a finding; they name a WCAG applicability question the host should
 * re-check. When a needed fact was not recorded, the rule abstains instead of guessing.
 */

import { stableSelectorIndex } from './stable-selector.js';

export const PRECHECK_VERSION = 'precheck-1';
export const PRECHECK_INSTRUCTION = 'Advisory only: notes never block, change, drop or confirm a finding. For each noted finding, add evidence that answers the note, revise the claim, or withdraw it before submit.';
const MAX_LISTED_NOTES = 20;
const MAX_LISTED_BYTES = 8000;

const WIDGET_ROLES = new Set(['button', 'checkbox', 'combobox', 'gridcell', 'link', 'listbox', 'menu', 'menubar', 'menuitem', 'menuitemcheckbox',
  'menuitemradio', 'option', 'radio', 'radiogroup', 'scrollbar', 'searchbox', 'slider', 'spinbutton', 'switch', 'tab', 'tablist', 'textbox',
  'tree', 'treegrid', 'treeitem', 'grid', 'PopUpButton', 'ToggleButton']);
// Elements that exist only inside SVG; SVG_SHARED names also exist in HTML and count only under an <svg> ancestor.
const SVG_ONLY = new Set(['path', 'g', 'circle', 'ellipse', 'line', 'polyline', 'polygon', 'use', 'tspan', 'textpath', 'defs', 'symbol', 'lineargradient',
  'radialgradient', 'stop', 'clippath', 'mask', 'pattern', 'marker', 'desc', 'foreignobject', 'fegaussianblur', 'filter']);
const SVG_SHARED = new Set(['rect', 'text', 'title', 'image', 'style']);
// Descendants that render perceivable content or are themselves controls.
const CONTENT_TAGS = new Set(['img', 'svg', 'canvas', 'picture', 'video', 'audio', 'object', 'embed', 'iframe', 'input', 'button', 'select', 'textarea', 'a', 'math']);
const NAME_ATTRIBUTES = ['aria-label', 'aria-labelledby', 'title', 'alt', 'placeholder'];
// Author-supplied purpose text kept by tooltip libraries (for example data-original-title, data-bs-original-title, data-tooltip).
const PURPOSE_ATTRIBUTE = /title|tooltip|tippy|hint|label/i;
// Chromium/Firefox default link colours (unvisited, visited); author pages almost always restyle them.
const UA_LINK_COLORS = new Set(['rgb(0, 0, 238)', 'rgb(85, 26, 139)']);
const UA_FONT = /^\s*["']?(?:times new roman|times|serif)["']?\s*(?:,|$)/i;
const SHORTCUT_ATTRIBUTE = /^(?:title|aria-label|aria-description|aria-keyshortcuts|accesskey)$|tooltip|title|hint|shortcut|hotkey/i;
const SHORTCUT_PATTERNS = [
  /(?:^|[^A-Za-z])\(\s*(?:[A-Z]|F(?:[1-9]|1[0-2])|Enter|Return|Esc(?:ape)?|Tab|Space|Del(?:ete)?|Backspace|Home|End|Page ?(?:Up|Down)|(?:Arrow ?)?(?:Up|Down|Left|Right)|[↑↓←→])\s*\)/,
  /\b(?:Ctrl|Control|Shift|Alt|Option|Opt|Cmd|Command|Meta)\s*(?:\+\s*(?!(?:click|tap|drag|scroll|wheel)\b)\S|-(?:[A-Za-z0-9]|F\d{1,2})\b)/i,
  /[⌘⌥⇧⌃]/,
  /\b(?:keyboard shortcut|shortcut|hotkey|access ?key)s?\b/i,
];

export const PRECHECK_RULES = Object.freeze({
  'not-a-ui-component': 'SC 4.1.2, 2.1.1 and 2.5.x: the target has no recorded interactive signal (interactive tag, widget role, tabindex >= 0, contenteditable, inline handler, pointer cursor or tab stop in inspect_many) and is an SVG sub-element, or an element with no text, no name source and no content-bearing descendants.',
  'documented-shortcut': 'SC 2.1.1: the target or its two nearest ancestors expose accesskey, aria-keyshortcuts, or a title/label/tooltip/text with a shortcut hint such as "(P)", "Ctrl+", "Shift+" or "⌘".',
  'target-size-exception': 'SC 2.5.8: the target link is rendered with user-agent default link colour and font and no class/style on it or any ancestor up to <html> (user-agent control exception), or it is an inline link whose parent has other text (inline exception).',
  'list-semantics-exposed': 'SC 1.3.1: the target is a native or role="list" list whose list role is exposed, so markup validity alone (for example non-<li> children) is not a 1.3.1 failure.',
  'no-keyboard-evidence': 'SC 2.1.1: the session records no successful global Tab, Shift+Tab, Enter, Space, Escape or arrow press whose focus before or after is the target, inside it, or a close non-<body> ancestor of it (also matched by recorded path or unique #id selector after a reload of the same URL). Abstains when a press record lacks focus data.',
  'operation-not-tested': 'SC 2.1.1 functional-operation claims on a contacted target: no same-document Enter/Space press with before/after observations on that target. Tab contact is traversal only; activation observations still require host interpretation.',
  'name-present-now': 'SC 4.1.2, 2.4.4 and 1.1.1 missing-name claims: the latest observation of the target recorded after the cited target evidence shows a name source (aria-label, aria-labelledby text, alt, label, text content of a name-from-content element, title, AX name, or a tooltip attribute when no recorded AX row says the name is empty).',
});

const lower = value => typeof value === 'string' ? value.toLowerCase() : '';
const squash = value => typeof value === 'string' ? value.replace(/[\s\u200b]+/g, ' ').trim() : '';
const clip = (value, limit = 80) => { const text = squash(value).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim(); return text.length > limit ? `${text.slice(0, limit - 1)}…` : text; };
const attributesOf = node => node?.attributes && typeof node.attributes === 'object' ? node.attributes : {};
const has = (attributes, name) => Object.hasOwn(attributes, name);

function isInteractive(context) {
  const { node, ax } = context;
  if (!node) return null;
  const attributes = attributesOf(node), tag = lower(node.tag);
  if (['button', 'select', 'textarea', 'summary', 'option'].includes(tag)) return 'interactive tag';
  if (tag === 'input' && lower(attributes.type) !== 'hidden') return 'interactive tag';
  if ((tag === 'a' || tag === 'area') && has(attributes, 'href')) return 'link with href';
  if ((tag === 'audio' || tag === 'video') && has(attributes, 'controls')) return 'media controls';
  const role = lower(attributes.role).split(/\s+/)[0];
  if (role && WIDGET_ROLES.has(role)) return `role="${role}"`;
  const tabindex = Number.parseInt(attributes.tabindex, 10);
  if (Number.isInteger(tabindex) && tabindex >= 0) return 'tabindex >= 0';
  if (has(attributes, 'contenteditable') && lower(attributes.contenteditable) !== 'false') return 'contenteditable';
  if (Object.keys(attributes).some(name => /^on[a-z]+$/i.test(name))) return 'inline event handler';
  if (Number.isInteger(node.tabIndex) && node.tabIndex >= 0) return 'focusable (tabIndex >= 0)';
  if (ax) {
    if (ax.role && WIDGET_ROLES.has(ax.role)) return `AX role ${ax.role}`;
    if (ax.tabStop === true || ax.focusable === true) return 'AX focusable';
    if (Array.isArray(ax.matchedBy) && ax.matchedBy.some(reason => ['native', 'onclick', 'cursor-pointer', 'aria-state'].includes(reason))) return `inspect_many ${ax.matchedBy.join('+')}`;
  }
  return null;
}

/** True when a recorded node carries any interactive signal (shared with coverage progress). */
export const isInteractiveNode = node => Boolean(node && typeof node.tag === 'string' && isInteractive({ node }));

function svgPart(context) {
  const tag = lower(context.node.tag);
  if (!tag || tag === 'svg') return false;
  if (SVG_ONLY.has(tag)) return true;
  return SVG_SHARED.has(tag) && Array.isArray(context.ancestors) && context.ancestors.some(ancestor => lower(ancestor.tag) === 'svg');
}

/** True, false, or null when the recorded data cannot tell. */
function emptyWithoutName(context) {
  const { node, ax } = context, attributes = attributesOf(node);
  if (typeof node.text !== 'string') return null;
  if (squash(node.text)) return false;
  if (NAME_ATTRIBUTES.some(name => squash(attributes[name]))) return false;
  if (Object.entries(attributes).some(([name, value]) => PURPOSE_ATTRIBUTE.test(name) && squash(value))) return false;
  if (squash(node.labelText)) return false;
  if (ax && squash(ax.name)) return false;
  if (!Array.isArray(context.descendantTags)) return null;
  return !context.descendantTags.some(tag => CONTENT_TAGS.has(lower(tag)));
}

function shortcutHint(context) {
  const sources = [{ where: 'target', node: context.node, text: true }];
  for (const ancestor of (context.ancestors ?? []).slice(0, 2)) sources.push({ where: `ancestor <${lower(ancestor.tag)}>`, node: ancestor, text: false });
  for (const { where, node, text } of sources) {
    const attributes = attributesOf(node);
    for (const name of ['accesskey', 'aria-keyshortcuts']) if (squash(attributes[name])) return { where, source: name, hint: clip(attributes[name]) };
    for (const [name, value] of Object.entries(attributes)) {
      if (!SHORTCUT_ATTRIBUTE.test(name) || typeof value !== 'string') continue;
      if (SHORTCUT_PATTERNS.some(pattern => pattern.test(value))) return { where, source: name, hint: clip(value) };
    }
    if (text) for (const [source, value] of [['text', node.text], ['labelText', node.labelText], ['AX name', context.ax?.name]]) {
      if (typeof value === 'string' && SHORTCUT_PATTERNS.some(pattern => pattern.test(value))) return { where, source, hint: clip(value) };
    }
  }
  return null;
}

function isLink(node) {
  const attributes = attributesOf(node), tag = lower(node.tag);
  return (tag === 'a' && has(attributes, 'href')) || lower(attributes.role) === 'link';
}

function userAgentStyled(context) {
  const { node } = context, computed = node.computed ?? {};
  if (!isLink(node) || typeof computed.color !== 'string' || !UA_LINK_COLORS.has(computed.color.replace(/\s+/g, ' ').trim())) return null;
  if (typeof computed.fontFamily === 'string' && !UA_FONT.test(computed.fontFamily)) return null;
  if (!Array.isArray(context.ancestors) || context.ancestorsComplete !== true) return null;
  const styled = [node, ...context.ancestors.filter(ancestor => lower(ancestor.tag) !== 'html')]
    .some(element => has(attributesOf(element), 'class') || has(attributesOf(element), 'style'));
  return styled ? null : { color: computed.color, ...(computed.fontFamily ? { fontFamily: computed.fontFamily } : {}) };
}

function inlineInText(context) {
  const { node, parent } = context;
  if (!isLink(node) || !parent || typeof parent.text !== 'string' || typeof node.text !== 'string') return null;
  if (node.computed?.display && node.computed.display !== 'inline') return null;
  const own = squash(node.text), around = squash(parent.text);
  if (!own || !around.includes(own)) return null;
  const rest = around.replace(own, ' ');
  return (rest.match(/[\p{L}\p{N}]/gu) ?? []).length >= 3 ? { parentTag: lower(parent.tag), surroundingText: clip(rest, 60) } : null;
}

function exposedList(context) {
  const { node, ax } = context, attributes = attributesOf(node), tag = lower(node.tag), role = lower(attributes.role);
  const list = role ? role === 'list' : ['ul', 'ol'].includes(tag);
  if (!list) return null;
  if (ax?.role && ax.role !== 'list') return null;
  return { tag, ...(role ? { role } : {}), ...(ax?.role ? { axRole: ax.role } : {}) };
}

const isTargetCriterion = id => id === '4.1.2' || id === '2.1.1' || /^2\.5\.\d+$/.test(id);

/** Notes for one finding target; `context` is a recorded node plus whatever related facts exist (missing facts mean abstain). */
export function precheckNode(criterionId, context) {
  const notes = [];
  if (!context?.node || typeof context.node.tag !== 'string') return notes;
  const tag = lower(context.node.tag);
  if (isTargetCriterion(criterionId) && !isInteractive(context)) {
    const operable = (context.ancestors ?? []).find(ancestor => isInteractive({ node: ancestor }));
    const nearest = operable ? { operableAncestor: lower(operable.tag) } : {};
    const retarget = operable ? ` (nearest operable ancestor: <${lower(operable.tag)}>)` : '';
    if (svgPart(context)) {
      notes.push({ rule: 'not-a-ui-component', basis: { tag, kind: 'svg-sub-element', ...nearest },
        message: `Target is an SVG <${tag}> fragment, not a user interface component, so ${criterionId} does not apply to it. Retarget to the operable element${retarget} with evidence, or withdraw.` });
    } else if (emptyWithoutName(context) === true) {
      notes.push({ rule: 'not-a-ui-component', basis: { tag, kind: 'empty-without-name', ...nearest },
        message: `Target <${tag}> has no text, name source, content or recorded interactive signal${retarget}. Keep ${criterionId} only with evidence it is an operable custom control (click result, inspect_many pointer/focus); otherwise withdraw.` });
    }
  }
  if (criterionId === '2.1.1') {
    const hint = shortcutHint(context);
    if (hint) notes.push({ rule: 'documented-shortcut', basis: hint,
      message: `Shortcut hint on ${hint.where} ${hint.source}: "${hint.hint}". 2.1.1 is about functionality: a documented shortcut for the same function can satisfy it. Press it and record the result before claiming a failure; otherwise revise or withdraw.` });
  }
  if (criterionId === '2.5.8') {
    const agent = userAgentStyled(context);
    if (agent) notes.push({ rule: 'target-size-exception', basis: { exception: 'user-agent-control', ...agent },
      message: 'Link uses user-agent default colour/font with no class or style on it or any ancestor, so the 2.5.8 user-agent exception (size set by the user agent, not the author) likely applies. Show author styling that sets its size, or withdraw.' });
    const inline = inlineInText(context);
    if (inline) notes.push({ rule: 'target-size-exception', basis: { exception: 'inline', ...inline },
      message: `Inline link inside text of its parent <${inline.parentTag}>: the 2.5.8 inline exception (target in a sentence or constrained by its line-height) may apply. Show it does not, or withdraw.` });
  }
  if (criterionId === '1.3.1') {
    const list = exposedList(context);
    if (list) notes.push({ rule: 'list-semantics-exposed', basis: list,
      message: 'Target list exposes its list role; invalid list children alone are a markup-validity issue, not a 1.3.1 failure. Name the visually conveyed relationship that is not programmatically determined, with evidence, or revise/withdraw.' });
  }
  return notes;
}

function nodesOf(record) {
  return [...(Array.isArray(record?.result?.nodes) ? record.result.nodes : []), ...(record?.result?.element ? [record.result.element] : [])];
}

function descendantTagsFromHtml(html) {
  if (typeof html !== 'string') return null;
  const tags = [...html.matchAll(/<([a-zA-Z][\w:-]*)/g)].map(match => match[1].toLowerCase());
  return tags.slice(1);
}

/** Build the precheck context for one finding target from the session's recorded evidence only. */
export function precheckContextFromRecords(records, target) {
  const byId = new Map(records.map(record => [record.evidenceId, record]));
  const observed = byId.get(target?.evidenceId);
  const documentId = observed?.after?.documentId;
  const node = nodesOf(observed).find(row => row.nodeId === target.nodeId && row.documentId === documentId);
  if (!node) return null;
  const index = new Map();
  let ax = null;
  for (const record of records) {
    if (record?.success !== true || record.after?.documentId !== documentId) continue;
    for (const row of nodesOf(record)) if (row.documentId === documentId && !index.has(row.nodeId)) index.set(row.nodeId, row);
    if (record.action === 'inspect_many' && Array.isArray(record.result?.elements)) {
      const element = record.result.elements.find(row => row.nodeId === node.nodeId);
      if (element) ax = { role: element.ax?.available ? element.ax.role : null, name: element.ax?.available ? element.ax.name : null,
        tabStop: element.focus?.tabStop === true, focusable: element.ax?.states?.focusable === true, matchedBy: element.matchedBy ?? [] };
    }
  }
  let ancestors = null, ancestorsComplete = false;
  if (Array.isArray(node.ancestorSemantics?.ancestors)) {
    ancestors = node.ancestorSemantics.ancestors; ancestorsComplete = node.ancestorSemantics.complete === true;
  } else {
    ancestors = [];
    let parentId = node.parentNodeId;
    for (; parentId && ancestors.length < 128; ) {
      const parent = index.get(parentId);
      if (!parent) break;
      ancestors.push(parent); parentId = parent.parentNodeId;
    }
    // Captures list <body> and its descendants only; reaching <body> leaves just the root <html> above it.
    ancestorsComplete = parentId === null || parentId === undefined || lower(ancestors.at(-1)?.tag) === 'body' || lower(node.tag) === 'body';
  }
  // Visible descendants are known from the outer HTML of an inspect, or from an untruncated capture that contains the node.
  let descendantTags = descendantTagsFromHtml(node.outerHTML && !node.outerHTMLTruncated ? node.outerHTML : null);
  const capture = [observed, ...records].find(record => record?.success === true && record.after?.documentId === documentId &&
    record.after?.stateId === observed.after?.stateId && record.result?.truncation?.omittedVisibleElements === 0 &&
    Array.isArray(record.result?.nodes) && record.result.nodes.some(row => row.nodeId === node.nodeId));
  if (!descendantTags && capture) {
    const captured = capture.result.nodes, children = new Map();
    for (const row of captured) { if (!children.has(row.parentNodeId)) children.set(row.parentNodeId, []); children.get(row.parentNodeId).push(row); }
    descendantTags = [];
    const stack = [...(children.get(node.nodeId) ?? [])];
    while (stack.length && descendantTags.length < 2000) { const row = stack.pop(); descendantTags.push(row.tag); stack.push(...(children.get(row.nodeId) ?? [])); }
  }
  const parent = node.parentNodeId ? index.get(node.parentNodeId) ?? null : null;
  return { node, ancestors, ancestorsComplete, descendantTags, parent, ax };
}

// ---- Session rules: facts from the whole record sequence, not only the target node. ----

const KEYBOARD_CRITERIA = new Set(['2.1.1']);
const NAVIGATION_KEY = /^(?:Shift\+)?Tab$|^(?:Enter|Return|Space|Spacebar| |Escape|Esc|Arrow(?:Up|Down|Left|Right))$/i;
const NAME_CRITERIA = new Set(['4.1.2', '2.4.4', '1.1.1']);
const MISSING_NAME_CLAIM = /\b(?:no|missing|empty|without|lacks?|lacking|absent|blank)\b[^.;:]{0,40}?\b(?:names?|labels?|alt(?:ernative)?(?: text)?)\b|\bun(?:named|labell?ed)\b|\bnames? (?:is|are) (?:the )?(?:empty|blank|missing)\b/i;
// axe rules whose violation means "this element has no accessible name or text alternative".
const AXE_NAME_RULE = /^(?:button-name|link-name|input-button-name|input-image-alt|image-alt|role-img-alt|svg-img-alt|area-alt|object-alt|select-name|label|summary-name|frame-title|aria-[a-z-]+-name)$/;
const NAME_FROM_CONTENT_TAGS = new Set(['button', 'summary', 'option', 'legend', 'caption', 'th', 'td', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
const NAME_FROM_CONTENT_ROLES = new Set(['button', 'link', 'menuitem', 'menuitemcheckbox', 'menuitemradio', 'tab', 'option', 'checkbox', 'radio', 'switch',
  'treeitem', 'cell', 'gridcell', 'columnheader', 'rowheader', 'heading', 'tooltip', 'row']);
// Text made only of private-use icon-font glyphs (or markup and punctuation) is not a usable name.
const meaningful = value => typeof value === 'string' && /[\p{L}\p{N}]/u.test(clip(value, 1000).replace(/[\uE000-\uF8FF]|[\u{F0000}-\u{10FFFF}]/gu, ''));

/** Every recorded observation of a node, in record order: node rows plus inspect_many AX rows. */
function sessionIndex(records) {
  const rows = new Map(), parents = new Map();
  const add = (index, record, row) => {
    if (!row || typeof row.nodeId !== 'string') return;
    if (row.parentNodeId && !parents.has(row.nodeId)) parents.set(row.nodeId, row.parentNodeId);
    if (!rows.has(row.nodeId)) rows.set(row.nodeId, []);
    rows.get(row.nodeId).push({ index, evidenceId: record.evidenceId, row });
  };
  records.forEach((record, index) => {
    if (record?.success !== true) return;
    const result = record.result ?? {};
    for (const row of [...nodesOf(record), result.target, result.focusedElement, record.after?.active]) add(index, record, row);
    for (const element of Array.isArray(result.elements) ? result.elements : []) {
      if (typeof element?.nodeId !== 'string' || !element.ax?.available) continue;
      if (!rows.has(element.nodeId)) rows.set(element.nodeId, []);
      rows.get(element.nodeId).push({ index, evidenceId: record.evidenceId, ax: { role: element.ax.role ?? null, name: element.ax.name ?? '' } });
    }
  });
  return { rows, parents };
}

function isAncestor(parents, ancestorId, nodeId, maxDepth = 256) {
  let cursor = parents.get(nodeId);
  for (let depth = 0; cursor && depth < maxDepth; depth++, cursor = parents.get(cursor)) if (cursor === ancestorId) return true;
  return false;
}

// A recorded positional path (html:nth-of-type(1) > body... ) or unique #id selector (the recorder emits #id only when unique)
// identifies the same element after a reload of the same URL; ids match by equality only.
const PATH = /^html(?::nth-of-type\(1\))? > /;
// One CSS.escape'd id and nothing else (hex escapes may end in one space); never a compound or descendant selector.
const ID_SELECTOR = /^#(?:\\[0-9a-fA-F]{1,6} ?|\\[^0-9a-fA-F\s]|[^\s\\>+~,.[:#])+$/;
const reloadSelector = selector => typeof selector === 'string' && (PATH.test(selector) || ID_SELECTOR.test(selector)) ? selector : null;
const pathDepth = selector => selector.split(' > ').length;

/** no-keyboard-evidence: null (abstain), or the number of qualifying presses when none involved the target. */
function keyboardContact(records, target, parents) {
  const targetId = target.nodeId, targetPath = reloadSelector(target.selector);
  let presses = 0;
  for (const record of records) {
    if (record?.success !== true || record.action !== 'press' || Object.hasOwn(record.arguments ?? {}, 'selector')) continue;
    if (!NAVIGATION_KEY.test(String(record.arguments?.key ?? record.result?.key ?? ''))) continue;
    if (!Object.hasOwn(record.before ?? {}, 'active') || !Object.hasOwn(record.after ?? {}, 'active')) return null;
    presses++;
    for (const [part, active] of [['before', record.before.active], ['after', record.after.active]]) {
      const id = active?.nodeId;
      if (typeof id !== 'string') continue;
      // Document-level focus on <body>/<html> is no focus at all.
      const documentFocus = ['body', 'html'].includes(lower(active.tag));
      if (active.parentNodeId && !parents.has(id)) parents.set(id, active.parentNodeId);
      // Focus on the target, inside it, or on a close ancestor (for example an icon inside a focused button).
      if (id === targetId || isAncestor(parents, targetId, id) || (!documentFocus && isAncestor(parents, id, targetId, 3))) return null;
      const path = reloadSelector(active.selector);
      if (!targetPath || !path || record[part]?.url !== target.url) continue;
      if (path === targetPath || path.startsWith(`${targetPath} > `)) return null;
      if (!documentFocus && targetPath.startsWith(`${path} > `) && pathDepth(targetPath) - pathDepth(path) <= 3) return null;
    }
  }
  return { presses };
}

function missingNameClaim(finding) {
  if (!NAME_CRITERIA.has(finding?.criterionId)) return false;
  const axeRule = typeof finding.axeCandidateId === 'string' ? finding.axeCandidateId.split(':')[1]
    : typeof finding.id === 'string' && finding.id.startsWith('axe:') ? finding.id.split(':')[2] : null;
  if (axeRule && AXE_NAME_RULE.test(axeRule)) return true;
  return MISSING_NAME_CLAIM.test(`${finding.title ?? ''}. ${finding.observation ?? ''}`);
}

function labelledbyText(attributes, rows, upTo) {
  const ids = squash(attributes['aria-labelledby']).split(' ').filter(Boolean);
  if (!ids.length) return null;
  const texts = ids.map(id => {
    for (const observations of rows.values()) {
      const hit = observations.filter(entry => entry.row && entry.index <= upTo && attributesOf(entry.row).id === id).at(-1);
      if (hit) return hit.row.text;
    }
    return null;
  });
  return texts.every(text => typeof text === 'string') && meaningful(texts.join(' ')) ? texts.join(' ') : null;
}

/** name-present-now: the first name source on the latest node row recorded after the target evidence, or null. */
function namePresentNow(records, target, index) {
  const at = records.findIndex(record => record?.evidenceId === target.evidenceId);
  const observations = index.rows.get(target.nodeId) ?? [];
  const later = observations.filter(entry => entry.row && entry.index > at);
  if (at < 0 || !later.length) return null;
  const latest = later.at(-1), node = latest.row, attributes = attributesOf(node), tag = lower(node.tag), role = lower(attributes.role).split(/\s+/)[0];
  const ax = observations.filter(entry => entry.ax).at(-1)?.ax ?? null;
  const sources = [['aria-label', attributes['aria-label']], ['aria-labelledby', labelledbyText(attributes, index.rows, latest.index)]];
  if (['img', 'area'].includes(tag) || (tag === 'input' && lower(attributes.type) === 'image')) sources.push(['alt', attributes.alt]);
  sources.push(['label', node.labelText]);
  if (NAME_FROM_CONTENT_TAGS.has(tag) || (tag === 'a' && has(attributes, 'href')) || NAME_FROM_CONTENT_ROLES.has(role)) sources.push(['text content', node.text]);
  sources.push(['title', attributes.title]);
  const axLater = observations.filter(entry => entry.ax && entry.index > at).at(-1)?.ax;
  if (axLater) sources.push(['AX name', axLater.name]);
  // Tooltip-library attributes are not name sources by themselves; a recorded empty AX name shows they were not exposed.
  if (!ax || meaningful(ax.name)) for (const [name, value] of Object.entries(attributes)) if (name !== 'title' && name !== 'aria-label' && PURPOSE_ATTRIBUTE.test(name)) sources.push([name, value]);
  const found = sources.find(([, value]) => meaningful(value));
  return found ? { evidenceId: latest.evidenceId, source: found[0], value: clip(found[1], 60) } : null;
}

/** Notes from session-wide facts for one finding whose target node was found in the records. */
export function precheckSession(finding, records, index = sessionIndex(records)) {
  const notes = [], target = finding?.target;
  if (typeof target?.nodeId !== 'string') return notes;
  if (KEYBOARD_CRITERIA.has(finding.criterionId)) {
    const row = (index.rows.get(target.nodeId) ?? []).find(entry => entry.row && entry.evidenceId === target.evidenceId);
    const url = records.find(record => record?.evidenceId === target.evidenceId)?.after?.url;
    const contact = keyboardContact(records, { nodeId: target.nodeId, selector: row?.row.selector, url }, new Map(index.parents));
    if (contact) notes.push({ rule: 'no-keyboard-evidence', basis: { navigationPresses: contact.presses },
      message: `No keyboard interaction with this target was recorded (${contact.presses} Tab/Enter/Space/Escape/arrow press${contact.presses === 1 ? '' : 'es'}, none focused it or a node inside it). Test reachability and record the keyboard path; if reachable, test the appropriate operation and observe its result. An unreachable target does not require activation evidence. Recheck the claim against these observations.` });
  }
  // Narrow advisory: only explicit functional claims with demonstrated same-document contact.
  // Unreachable targets retain the traversal advisory; activation is not a prerequisite for reporting them.
  if (finding.criterionId === '2.1.1' && /operab|activat|enter|space|does(?:n't| not) (?:work|respond)/i.test(`${finding.title ?? ''} ${finding.observation ?? ''}`)) {
    const cited = records.find(record => record.evidenceId === target.evidenceId);
    const documentId = cited?.after?.documentId;
    const touches = active => active?.nodeId === target.nodeId || isAncestor(index.parents, target.nodeId, active?.nodeId);
    const local = records.filter(record => record.success && record.action === 'press' && !Object.hasOwn(record.arguments ?? {}, 'selector') &&
      documentId && record.before?.documentId === documentId && record.after?.documentId === documentId);
    const contacted = local.some(record => touches(record.before?.active) || touches(record.after?.active));
    const operation = local.some(record => /^(Enter|Space| )$/.test(record.arguments?.key ?? record.result?.key ?? '') &&
      touches(record.before?.active) && record.before?.stateId && record.after?.stateId);
    if (contacted && !operation) notes.push({ rule: 'operation-not-tested', basis: { documentId },
      message: 'Tab/focus contact records traversal only. No same-document Enter/Space operation and resulting state were recorded on this target. If reachable, test the appropriate operation and inspect its result; interpret the outcome before retaining this functional 2.1.1 claim. Do not activate an unreachable target just to satisfy this advisory.' });
    // Same-ID reloads may explain traversal contact, but never transfer operation evidence.
    const selector = reloadSelector((index.rows.get(target.nodeId) ?? []).find(e => e.row)?.row.selector);
    const reloadedContact = selector && records.some(record => record.success && record.action === 'press' && !Object.hasOwn(record.arguments ?? {}, 'selector') &&
      ['before', 'after'].some(part => record[part]?.documentId !== documentId && record[part]?.url === cited?.after?.url && record[part]?.active?.selector === selector));
    if (!contacted && reloadedContact)
      notes.push({ rule: 'operation-not-tested', basis: { documentId }, message: 'Contact from another document does not test this target operation. Recheck the current control and result; selector equality after reload does not transfer functional evidence.' });
  }
  if (missingNameClaim(finding)) {
    const name = namePresentNow(records, target, index);
    if (name) notes.push({ rule: 'name-present-now', basis: name,
      message: `The latest observation of the target (${name.evidenceId}) shows a name source: ${name.source} "${name.value}". Check the computed name (inspect_many AX row) before claiming it is missing; if it is named, revise or withdraw.` });
  }
  return notes;
}

// ---- Suspected duplicates: advisory grouping across findings; never merges, drops or blocks. ----

export const DUPLICATE_RULE = 'suspected-duplicate';
export const DUPLICATE_INSTRUCTION = 'Advisory only: each group lists findings with the same criterionId, the same recorded stateId and the same target (the same nodeId or the same stableSelector). They may describe one issue. Nothing was merged, dropped or blocked, and review outcomes and counts are unchanged. Keep distinct claims, or merge or withdraw repeats yourself before submit.';
const MAX_DUPLICATE_GROUPS = 10, MAX_DUPLICATE_BYTES = 2000, MAX_GROUP_IDS = 10;

/**
 * Groups of two or more rows `{ findingId, criterionId, stateId, nodeId, stableSelector? }` that share criterionId and
 * stateId and are joined by a shared nodeId or stableSelector. Rows without a stateId, or with neither target key, are
 * skipped. Groups and their IDs keep input order.
 */
export function suspectedDuplicateGroups(rows) {
  const buckets = new Map();
  (Array.isArray(rows) ? rows : []).forEach((row, index) => {
    if (typeof row?.findingId !== 'string' || typeof row.criterionId !== 'string' || typeof row.stateId !== 'string' || !row.stateId) return;
    const keys = [typeof row.nodeId === 'string' && row.nodeId ? `nodeId|${row.nodeId}` : null,
      typeof row.stableSelector === 'string' && row.stableSelector ? `stableSelector|${row.stableSelector}` : null].filter(Boolean);
    if (!keys.length) return;
    const bucket = JSON.stringify([row.criterionId, row.stateId]);
    if (!buckets.has(bucket)) buckets.set(bucket, []);
    buckets.get(bucket).push({ row, index, keys });
  });
  const groups = [];
  for (const members of buckets.values()) {
    if (members.length < 2) continue;
    const parent = members.map((_, i) => i), first = new Map(), shared = members.map(() => new Set());
    const find = i => { while (parent[i] !== i) i = parent[i] = parent[parent[i]]; return i; };
    members.forEach((member, i) => {
      for (const key of member.keys) {
        if (!first.has(key)) { first.set(key, i); continue; }
        const j = first.get(key);
        shared[i].add(key); shared[j].add(key);
        const [a, b] = [find(i), find(j)];
        if (a !== b) parent[Math.max(a, b)] = Math.min(a, b);
      }
    });
    const clusters = new Map();
    members.forEach((member, i) => { const root = find(i); if (!clusters.has(root)) clusters.set(root, []); clusters.get(root).push(i); });
    for (const cluster of clusters.values()) {
      if (cluster.length < 2) continue;
      const keys = new Set(cluster.flatMap(i => [...shared[i]]));
      const selectors = [...new Set(cluster.map(i => members[i].row.stableSelector).filter(value => typeof value === 'string' && value))];
      const { criterionId, stateId } = members[cluster[0]].row;
      groups.push({ index: members[cluster[0]].index, criterionId, stateId,
        matchedBy: ['nodeId', 'stableSelector'].filter(kind => [...keys].some(key => key.startsWith(`${kind}|`))),
        ...(selectors.length === 1 && cluster.every(i => members[i].row.stableSelector === selectors[0]) ? { stableSelector: selectors[0] } : {}),
        nodeIds: [...new Set(cluster.map(i => members[i].row.nodeId).filter(value => typeof value === 'string' && value))],
        findingIds: cluster.map(i => members[i].row.findingId) });
    }
  }
  return groups.sort((a, b) => a.index - b.index).map(({ index: _index, ...group }) => group);
}

/** Target rows for duplicate grouping, from the finding target and the session's own records only. */
function duplicateRows(findings, records) {
  const byId = new Map(records.map(record => [record?.evidenceId, record])), stable = stableSelectorIndex(records);
  return findings.map(finding => {
    const record = byId.get(finding?.target?.evidenceId);
    const selector = record ? stable.fieldsFor(finding.target).stableSelector : undefined;
    return { findingId: finding?.id, criterionId: finding?.criterionId, stateId: record?.after?.stateId, nodeId: finding?.target?.nodeId,
      ...(typeof selector === 'string' ? { stableSelector: selector } : {}) };
  });
}

/** Bounded ACK section, or null when no group was found. A failure here is reported without touching the other notes. */
function duplicateSection(findings, records) {
  let groups;
  try { groups = suspectedDuplicateGroups(duplicateRows(findings, records)); }
  catch { return { rule: DUPLICATE_RULE, advisory: true, unavailable: true, instruction: DUPLICATE_INSTRUCTION }; }
  if (!groups.length) return null;
  const listed = [];
  let bytes = 0;
  for (const group of groups) {
    const row = group.findingIds.length > MAX_GROUP_IDS ? { ...group, findingIds: group.findingIds.slice(0, MAX_GROUP_IDS), findingCount: group.findingIds.length } : group;
    const size = Buffer.byteLength(JSON.stringify(row));
    if (listed.length >= MAX_DUPLICATE_GROUPS || bytes + size > MAX_DUPLICATE_BYTES) break;
    listed.push(row); bytes += size;
  }
  return { rule: DUPLICATE_RULE, advisory: true, groupsFound: groups.length, groups: listed,
    ...(groups.length > listed.length ? { omittedGroups: groups.length - listed.length } : {}), instruction: DUPLICATE_INSTRUCTION };
}

/** Precheck a validated proposal against the session records; returns a bounded, advisory ACK section. */
export function precheckProposal(proposal, records) {
  const findings = Array.isArray(proposal?.findings) ? proposal.findings : [];
  const notes = [];
  let abstained = 0, index = null;
  for (const finding of findings) {
    const context = precheckContextFromRecords(records, finding.target);
    if (!context) { abstained++; continue; }
    for (const note of precheckNode(finding.criterionId, context)) notes.push({ findingId: finding.id, criterionId: finding.criterionId, ...note });
    index ??= sessionIndex(records);
    for (const note of precheckSession(finding, records, index)) notes.push({ findingId: finding.id, criterionId: finding.criterionId, ...note });
  }
  // Listed notes share the response text limit with the ACK; the rest are counted, never silently dropped.
  const listed = [];
  let bytes = 0;
  for (const note of notes) {
    const size = Buffer.byteLength(JSON.stringify(note));
    if (listed.length >= MAX_LISTED_NOTES || bytes + size > MAX_LISTED_BYTES) break;
    listed.push(note); bytes += size;
  }
  const duplicates = duplicateSection(findings, Array.isArray(records) ? records : []);
  return { version: PRECHECK_VERSION, advisory: true, checkedFindings: findings.length, findingsWithNotes: new Set(notes.map(note => note.findingId)).size,
    ...(abstained ? { targetsUnavailable: abstained } : {}), notes: listed,
    ...(notes.length > listed.length ? { omittedNotes: notes.length - listed.length } : {}),
    ...(duplicates ? { suspectedDuplicates: duplicates } : {}), instruction: PRECHECK_INSTRUCTION };
}
