import { openStatusRecorder } from './status-observer.js';
import { openBlobCapture, blobDeadline } from './blob.js';
import { randomUUID, createHash } from 'node:crypto';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import { digest, errorRecord, ToolError } from '../evidence.js';
import { decodePng, pixelAt, relativeLuminance, contrastRatio, pngDimensions } from './pixels.js';
import { auditAxeTags } from './schema.js';
import { loadNetworkReplay } from './network-replay.js';
import { clipUrl, decideNavigation, navigationBlockDetails, navigationPolicy, redactUrl, withNavigation } from './navigation.js';
import { buildElementRows, compactAxNode, INTERACTIVE_RULE, INSPECT_MANY_PRESET_LIMIT } from './inspect-many.js';
import { collectNonTextFacts, analyzeNonText, NONTEXT_SCOPE } from './nontext.js';

// Main-document CSS only, matching observeDocument's selector trust boundary.
function readinessObservation(action) {
  const found = document.querySelectorAll(action.selector), count = found.length;
  if (count > 1) return { matched: false, count, ambiguous: true };
  if (!count) return { matched: ['detached', 'hidden'].includes(action.condition), count };
  const element = found[0];
  if (action.condition === 'attached') return { matched: true, count };
  if (action.condition === 'detached') return { matched: false, count };
  if (['visible', 'hidden'].includes(action.condition)) {
    // Geometry/CSS predicate only: no viewport, occlusion, opacity or AT claim.
    const style = getComputedStyle(element), rect = element.getBoundingClientRect();
    const visible = !['hidden', 'collapse'].includes(style.visibility) && rect.width > 0 && rect.height > 0;
    return { matched: action.condition === 'visible' ? visible : !visible, count, visible };
  }
  const actual = action.condition === 'text' ? element.textContent : element.getAttribute(action.name);
  // Never read input.value; also preserve the existing password/hidden attribute omission.
  const omitted = action.condition === 'text'
    ? element.localName === 'script' || Boolean(element.querySelector('script'))
    : action.name.toLowerCase() === 'value' && element.tagName === 'INPUT' && ['password', 'hidden'].includes(element.type);
  return { matched: actual === (action.condition === 'text' ? action.expected : action.value), count,
    actual: omitted ? '[omitted]' : actual === null ? null : actual.slice(0, 1200),
    actualOmitted: omitted, actualTruncated: !omitted && actual !== null && actual.length > 1200 };
}

export const AXE_AUDIT_TAGS = Object.freeze(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']);
export const SPACING_REQUEST = Object.freeze({ lineHeight: 1.5, letterSpacingEm: 0.12, wordSpacingEm: 0.16, paragraphMarginBlockEndEm: 2 });
export const SPACING_CSS = 'html,body,body *{line-height:1.5!important;letter-spacing:0.12em!important;word-spacing:0.16em!important;}body p{margin-block-end:2em!important;}';
const textLimit = 1200;
/**
 * Read-only observations whose before/after states differ are re-captured after a bounded settle, inside the same
 * action. Mutating actions are never repeated. The window covers every settle and re-capture start after the first
 * attempt and never extends past the action's own deadline.
 */
export const CAPTURE_RETRY_POLICY = Object.freeze({ actions: Object.freeze(['snapshot', 'inspect', 'inspect_many']),
  reason: 'DOM_STATE_CHANGED', maxExtraAttempts: 2, windowMs: 3000, quietMs: 200, minAttemptMs: 250 });
const axeBindingRowLimit = 5000;

// Executed in the document. Node identity lives in a WeakMap; no reference
// attributes or focus changes are written to the application DOM.
function observeDocument(options) {
  let store = globalThis[options.storeKey];
  if (!store || store.document !== document) {
    store = globalThis[options.storeKey] = { document, documentId: options.documentCandidate, ids: new WeakMap(), next: 1, spacingStyle: null };
  }
  const normalize = value => String(value || '').replace(/\s+/g, ' ').trim();
  const box = r => ({ x: r.x, y: r.y, width: r.width, height: r.height, top: r.top, right: r.right, bottom: r.bottom, left: r.left });
  const identifier = element => {
    if (!store.ids.has(element)) store.ids.set(element, `${store.documentId}:n${String(store.next++).padStart(6, '0')}`);
    return store.ids.get(element);
  };
  const sensitiveField = element => element.tagName === 'INPUT' && ['password', 'hidden'].includes(element.type);
  const attributes = element => Object.fromEntries([...element.attributes].map(attribute => [attribute.name,
    attribute.name === 'value' && sensitiveField(element) ? '[omitted]' : attribute.value.slice(0, 8192)]));
  const selector = element => {
    if (element.id && document.querySelectorAll(`#${CSS.escape(element.id)}`).length === 1) return `#${CSS.escape(element.id)}`;
    const parts = [];
    for (let current = element; current; current = current.parentElement) {
      const tag = current.tagName.toLowerCase();
      const index = current.parentElement ? [...current.parentElement.children].filter(sibling => sibling.tagName === current.tagName).indexOf(current) + 1 : 1;
      parts.unshift(`${tag}:nth-of-type(${index})`);
      if (current === document.documentElement) break;
    }
    return parts.join(' > ');
  };
  const control = element => ({
    checked: 'checked' in element ? element.checked : null,
    value: sensitiveField(element) ? '[omitted]' : 'value' in element ? String(element.value) : null,
    sensitiveValueOmitted: sensitiveField(element),
    selectedIndex: 'selectedIndex' in element ? element.selectedIndex : null,
    selected: 'selected' in element ? element.selected : null,
    expanded: element.getAttribute('aria-expanded'),
    ariaChecked: element.getAttribute('aria-checked'),
    ariaPressed: element.getAttribute('aria-pressed'),
    open: 'open' in element ? element.open : null,
    disabled: 'disabled' in element ? element.disabled : null,
  });
  const properties = ['display', 'visibility', 'opacity', 'color', 'backgroundColor', 'colorScheme', 'fontFamily', 'fontSize', 'fontWeight', 'lineHeight', 'letterSpacing', 'wordSpacing', 'marginBlockEnd', 'width', 'height', 'minWidth', 'maxWidth', 'maxHeight', 'whiteSpace', 'overflowX', 'overflowY', 'clipPath', 'outlineStyle', 'outlineWidth', 'outlineColor', 'outlineOffset', 'boxShadow', 'textDecorationLine'];
  const visible = element => {
    const style = getComputedStyle(element);
    if (element.checkVisibility && !element.checkVisibility({ checkVisibilityCSS: true, contentVisibilityAuto: true })) return false;
    for (let details = element.parentElement?.closest('details:not([open])'); details; details = details.parentElement?.closest('details:not([open])')) {
      const summary = [...details.children].find(child => child.tagName === 'SUMMARY');
      if (!summary?.contains(element)) return false;
    }
    return style.display !== 'none' && !['hidden', 'collapse'].includes(style.visibility) && element.getClientRects().length > 0;
  };
  const scriptlessText = (element, rendered = false) => {
    if (!element || element.localName === 'script') return '';
    const scripts = [...element.querySelectorAll('script')];
    if (rendered && typeof element.innerText === 'string' && visible(element) && !scripts.some(visible)) return element.innerText;
    const clone = element.cloneNode(true);
    const originals = [element, ...element.querySelectorAll('*')], copies = [clone, ...clone.querySelectorAll('*')];
    const pruneHidden = rendered && visible(element);
    for (let index = originals.length - 1; index >= 0; index--) {
      if (originals[index].localName === 'script' || (pruneHidden && !visible(originals[index]))) copies[index].remove();
    }
    return clone.textContent || '';
  };
  const describe = (element, inspect = false) => {
    const style = getComputedStyle(element), text = normalize(scriptlessText(element, true));
    const labels = [...(element.labels || [])].map(label => normalize(scriptlessText(label))).join(' ');
    const labelledBy = (element.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean).map(id => normalize(scriptlessText(document.getElementById(id)))).join(' ');
    const labelText = element.getAttribute('aria-label') || labelledBy || labels || element.getAttribute('alt') || '';
    const href = element.getAttribute('href');
    let url = null;
    if (href !== null) try { url = new URL(href, location.href).href; } catch { /* Preserve invalid href. */ }
    const result = {
      nodeId: identifier(element), documentId: store.documentId, parentNodeId: element.parentElement ? identifier(element.parentElement) : null,
      selector: selector(element), tag: element.tagName.toLowerCase(),
      attributes: attributes(element), attributesTruncated: [...element.attributes].filter(attribute => attribute.value.length > 8192).map(attribute => attribute.name),
      text: text.slice(0, options.textLimit), textLength: text.length, textTruncated: text.length > options.textLimit,
      labelText: labelText.slice(0, options.textLimit), labelTextTruncated: labelText.length > options.textLimit,
      rect: box(element.getBoundingClientRect()), computed: Object.fromEntries(properties.map(property => [property, style[property]])),
      ...control(element), role: element.getAttribute('role'), href, url, tabIndex: element.tabIndex,
      focused: element === document.activeElement, focusVisible: element.matches(':focus-visible'),
    };
    if (inspect) {
      const range = document.createRange(); range.selectNodeContents(element);
      const rects = [...range.getClientRects()];
      const clone = element.cloneNode(true);
      for (const input of [clone, ...clone.querySelectorAll('input')]) {
        if (sensitiveField(input) && input.hasAttribute('value')) input.setAttribute('value', '[omitted]');
      }
      for (const script of [clone, ...clone.querySelectorAll('script')]) {
        if (script.tagName === 'SCRIPT') script.textContent = '[inline script omitted]';
      }
      const html = clone.outerHTML;
      result.outerHTML = html.slice(0, 16000); result.outerHTMLTruncated = html.length > 16000;
      result.client = { width: element.clientWidth, height: element.clientHeight };
      result.scroll = { width: element.scrollWidth, height: element.scrollHeight, left: element.scrollLeft, top: element.scrollTop };
      result.textRangeRects = rects.slice(0, 2000).map(box); result.textRangeRectsTruncated = Math.max(0, rects.length - 2000);
    }
    return result;
  };
  if (!document.body) throw new Error('The document has no body to observe.');
  const all = [document.body, ...document.body.querySelectorAll('*')];
  const eligible = all.filter(visible);
  const nodes = eligible.slice(0, options.maxElements).map(element => describe(element));
  const allControls = [...document.querySelectorAll('input,select,textarea,button,details,dialog,option,[aria-expanded],[aria-checked],[aria-pressed],[role="switch"],[contenteditable]')];
  const controls = allControls.slice(0, options.maxElements).map(element => ({ nodeId: identifier(element), documentId: store.documentId, tag: element.tagName.toLowerCase(), attributes: attributes(element), ...control(element) }));
  const style = store.spacingStyle;
  const css = style?.isConnected ? style.textContent : '';
  let sheetActive = false;
  try { sheetActive = Boolean(style?.isConnected && style.sheet && !style.sheet.disabled && style.sheet.cssRules.length); } catch { /* CSP or stylesheet rejection is observable. */ }
  const visibleText = scriptlessText(document.body, true);
  const paragraphs = [...document.querySelectorAll('p')].filter(visible);
  const paragraph = paragraphs[0];
  const computedParagraph = paragraph ? getComputedStyle(paragraph) : null;
  const spacingFailures = [];
  let checkedElements = 0;
  if (options.spacingRequested) {
    if (!sheetActive || css !== options.spacingCss) spacingFailures.push({ reason: 'stylesheet_missing_or_changed' });
    for (const element of eligible.slice(0, options.maxElements)) {
      const computed = getComputedStyle(element), fontSize = Number.parseFloat(computed.fontSize);
      const expected = { lineHeight: fontSize * 1.5, letterSpacing: fontSize * 0.12, wordSpacing: fontSize * 0.16 };
      if (element.matches('p')) expected.marginBlockEnd = fontSize * 2;
      checkedElements++;
      for (const [property, target] of Object.entries(expected)) {
        const actual = Number.parseFloat(computed[property]);
        if (!Number.isFinite(actual) || Math.abs(actual - target) > 0.15) {
          if (spacingFailures.length < 100) spacingFailures.push({ nodeId: identifier(element), property, expectedPx: target, actual: computed[property] });
        }
      }
    }
  }
  const result = {
    documentId: store.documentId, url: location.href, title: document.title, language: document.documentElement.lang,
    viewport: { width: innerWidth, height: innerHeight }, scroll: { x: scrollX, y: scrollY },
    active: document.activeElement ? describe(document.activeElement) : null,
    controls, controlsTotal: allControls.length, controlsTruncated: Math.max(0, allControls.length - controls.length),
    document: { clientWidth: document.documentElement.clientWidth, clientHeight: document.documentElement.clientHeight, scrollWidth: document.documentElement.scrollWidth, scrollHeight: document.documentElement.scrollHeight, rootAttributes: attributes(document.documentElement), bodyAttributes: attributes(document.body) },
    spacing: { requested: options.spacingRequested, enabled: Boolean(style?.isConnected), css, sheetActive, applied: options.spacingRequested && sheetActive && !spacingFailures.length && eligible.length <= options.maxElements, checkedElements, uncheckedElements: Math.max(0, eligible.length - options.maxElements), failures: spacingFailures, representativeParagraph: paragraph ? { nodeId: identifier(paragraph), documentId: store.documentId, selector: selector(paragraph), fontSize: computedParagraph.fontSize, marginBlockEnd: computedParagraph.marginBlockEnd, lineHeight: computedParagraph.lineHeight, letterSpacing: computedParagraph.letterSpacing, wordSpacing: computedParagraph.wordSpacing } : null },
    nodes, visibleText: visibleText.slice(0, 250000), visibleTextLength: visibleText.length, visibleTextTruncated: visibleText.length > 250000,
    truncation: { totalElements: all.length, visibleElements: eligible.length, capturedElements: nodes.length, omittedVisibleElements: Math.max(0, eligible.length - nodes.length), unobservedScope: ['child-frame DOM', 'shadow-root DOM', 'pixels outside supplied screenshots'], note: 'Truncated or unobserved content is not covered.' },
  };
  if (options.statusSnapshot) {
    result.statusNodes = all.filter(el => el.localName !== 'script').slice(0, options.maxElements).map(el => {
      const node = describe(el), ancestors = [];
      let ancestor = el.parentElement;
      for (; ancestor && ancestors.length < 128; ancestor = ancestor.parentElement) ancestors.push({
        nodeId: identifier(ancestor), documentId: store.documentId,
        parentNodeId: ancestor.parentElement ? identifier(ancestor.parentElement) : null,
        tag: ancestor.localName, attributes: attributes(ancestor),
        attributesTruncated: [...ancestor.attributes].filter(a => a.value.length > 8192).map(a => a.name),
      });
      return { ...node, ancestorSemantics: { complete: ancestor === null, ancestors } };
    });
    const captured = new Set(result.statusNodes.map(node => node.nodeId));
    result.statusTruncation = { ...result.truncation,
      capturedElements: result.statusNodes.length,
      omittedVisibleElements: eligible.filter(el => !captured.has(identifier(el))).length,
      omittedElements: all.filter(el => el.localName !== 'script').length - result.statusNodes.length,
    };
  }
  if (options.selector) {
    const found = document.querySelectorAll(options.selector);
    if (found.length !== 1) throw new Error(`A selector must identify exactly one element; found ${found.length}.`);
    result.element = describe(found[0], true);
    // Inspect is the explicit, bounded way to obtain the original semantic
    // ancestor chain. Do not duplicate every chain in full-page snapshots.
    const ancestors = [];
    let ancestor = found[0].parentElement;
    for (; ancestor && ancestors.length < 128; ancestor = ancestor.parentElement) {
      ancestors.push({
        nodeId: identifier(ancestor), documentId: store.documentId,
        parentNodeId: ancestor.parentElement ? identifier(ancestor.parentElement) : null,
        tag: ancestor.tagName.toLowerCase(), attributes: attributes(ancestor),
        attributesTruncated: [...ancestor.attributes].filter(attribute => attribute.value.length > 8192).map(attribute => attribute.name),
      });
    }
    result.element.ancestorSemantics = { complete: ancestor === null, ancestors };
  }
  // Checked-unique selector from stable attributes (not generated ids/classes), computed in this same synchronous observation.
  // Work is time-boxed; a node past the box keeps only its axe target.
  const createStableSelector = () => {
    const quote = value => `"${value.replace(/["\\]/g, '\\$&')}"`;
    const generatedValue = value => value.length > 80 || /[\u0000-\u001f]/.test(value) || /[-_:]\d+(?:[-_:]|$)/.test(value) || /^:[\w:-]*:$/.test(value) ||
      /^(?:radix|headlessui|react-aria|ember|ext-gen|yui|mui|rc|uid|auto)[-_:]?[\w:-]*\d/i.test(value) || /[0-9a-f]{8}-[0-9a-f]{4}/i.test(value) ||
      /(?=[0-9a-f]*\d)[0-9a-f]{8,}/i.test(value) || /\d{5,}/.test(value) || /(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{12,}/.test(value);
    const generatedClass = value => generatedValue(value) || /^(?:css|sc|jsx|svelte|emotion|styled|ng|chakra)-/.test(value) || /__[\w-]{5,}$/.test(value) ||
      /^_[\w-]{5,}$/.test(value) || /^(?:active|open|opened|closed|hover|focus|focused|selected|disabled|checked|hidden|show|shown|visible|expanded|collapsed|loading|current|on|off|in|out)$/.test(value);
    const testAttributes = ['data-testid', 'data-test', 'data-test-id', 'data-cy', 'data-qa', 'data-automation-id', 'data-id'];
    const skippedData = /^data-(?:v-|react|radix|state$|orientation$|headlessui|emotion|styled|ng|ember|index$|key$|rbd|rr-|astro|svelte|sentry)/;
    const unique = (css, element) => { try { const found = document.querySelectorAll(css); return found.length === 1 && found[0] === element; } catch { return false; } };
    const until = performance.now() + 1500;
    const ownSelector = element => {
      const tag = element.localName, id = element.id;
      if (id && !generatedValue(id) && unique(`#${CSS.escape(id)}`, element)) return { selector: `#${CSS.escape(id)}`, confidence: 'high', basis: 'id' };
      const usable = name => { const value = element.getAttribute(name); return value && !generatedValue(value) ? value : null; };
      const picked = [];
      for (const name of testAttributes) if (usable(name)) picked.push({ name, basis: 'data-attribute', confidence: 'high' });
      for (const { name } of element.attributes) if (name.startsWith('data-') && !testAttributes.includes(name) && !skippedData.test(name) && usable(name)) picked.push({ name, basis: 'data-attribute', confidence: 'high' });
      for (const name of ['name', 'aria-label', 'aria-labelledby']) if (usable(name)) picked.push({ name, basis: name === 'name' ? 'name' : 'aria-attribute', confidence: 'high' });
      for (const name of ['placeholder', 'title', 'alt', 'for', 'href']) if (usable(name)) picked.push({ name, basis: 'attribute', confidence: 'medium' });
      const part = ({ name }) => `[${name}=${quote(element.getAttribute(name))}]`;
      const extras = ['type', 'role'].filter(usable).map(name => ({ name }));
      for (const attribute of picked) if (unique(`${tag}${part(attribute)}`, element)) return { selector: `${tag}${part(attribute)}`, confidence: attribute.confidence, basis: attribute.basis };
      const combos = [...extras.flatMap(extra => picked.map(attribute => [attribute, extra])), ...picked.flatMap((first, index) => picked.slice(index + 1).map(second => [first, second]))];
      for (const pair of combos.slice(0, 24)) {
        if (performance.now() > until) return null;
        const css = `${tag}${pair.map(part).join('')}`;
        if (unique(css, element)) return { selector: css, confidence: 'medium', basis: 'attributes' };
      }
      const classes = [...element.classList].filter(name => !generatedClass(name)).slice(0, 4);
      const classCombos = [...classes.map(name => [name]), ...classes.flatMap((first, index) => classes.slice(index + 1).map(second => [first, second]))];
      for (const names of classCombos) {
        const css = `${tag}${names.map(name => `.${CSS.escape(name)}`).join('')}`;
        if (unique(css, element)) return { selector: css, confidence: 'medium', basis: 'class' };
      }
      return null;
    };
    const stableSelector = (element, css) => {
      const clean = !(css.match(/#(?:\\.|[\w-])+/g) ?? []).some(token => generatedValue(token.slice(1))) &&
        !(css.match(/\.(?:\\.|[\w-])+/g) ?? []).some(token => generatedClass(token.slice(1)));
      const own = performance.now() > until ? null : ownSelector(element);
      if (own) return own;
      let ancestor = element.parentElement, depth = 0;
      for (; ancestor && ancestor !== document.body && depth < 6 && performance.now() <= until; ancestor = ancestor.parentElement, depth++) {
        const anchor = ownSelector(ancestor);
        if (!anchor) continue;
        const tag = element.localName, confidence = anchor.confidence === 'high' ? 'medium' : 'low';
        const attributes = [...element.attributes].filter(({ name, value }) => /^(?:type|role|name|aria-label|href|title|alt)$/.test(name) && value && !generatedValue(value)).slice(0, 4);
        const tries = [`${anchor.selector} ${tag}`, ...attributes.map(({ name, value }) => `${anchor.selector} ${tag}[${name}=${quote(value)}]`),
          ...[...element.classList].filter(name => !generatedClass(name)).slice(0, 3).map(name => `${anchor.selector} ${tag}.${CSS.escape(name)}`)];
        const found = tries.find(candidate => unique(candidate, element));
        if (found) return { selector: found, confidence, basis: 'ancestor' };
        // axe's own target already reads well unless it leans on generated ids/classes; only then is a positional path from a stable anchor better.
        if (clean) continue;
        const steps = [];
        for (let node = element; node && node !== ancestor; node = node.parentElement) {
          steps.unshift(`${node.localName}:nth-of-type(${[...node.parentElement.children].filter(sibling => sibling.localName === node.localName).indexOf(node) + 1})`);
        }
        const path = `${anchor.selector} > ${steps.join(' > ')}`;
        if (unique(path, element)) return { selector: path, confidence: 'low', basis: 'path' };
      }
      return { selector: css, confidence: 'low', basis: 'axe-target' };
    };
    return stableSelector;
  };
  if (options.anchorIndex) {
    // Snapshot only: anchor keys of every element the node list did not capture (hidden or past maxElements), so a selector
    // checked unique among captured nodes can also be shown to match no uncaptured element. Keys: "tag name=value",
    // "* name=value" (id and test attributes), "tag .class", "tag". Body subtree only; only anchor attribute names (never value,
    // content, href or src) and values of at most 200 characters are kept.
    const captured = new Set(options.statusSnapshot ? all.filter(el => el.localName !== 'script').slice(0, options.maxElements) : eligible.slice(0, options.maxElements));
    const keys = new Map(), add = key => keys.set(key, (keys.get(key) ?? 0) + 1), tagless = new Set(['id', 'data-testid', 'data-test', 'data-test-id', 'data-cy', 'data-qa', 'data-automation-id']);
    let uncaptured = 0;
    for (const element of document.body.querySelectorAll('*')) {
      if (captured.has(element)) continue;
      uncaptured++;
      const tag = element.localName;
      add(tag);
      for (const { name, value } of element.attributes) {
        if (!/^(?:id|name|aria-label|for|role|type|data-[\w.:-]+)$/.test(name) || value.length > 200) continue;
        add(`${tag} ${name}=${value}`);
        if (tagless.has(name)) add(`* ${name}=${value}`);
      }
      for (const name of element.classList) add(`${tag} .${name}`);
      if (keys.size > 4000) break;
    }
    result.uncapturedAnchors = keys.size > 4000 ? { version: 1, overflow: true } : { version: 1, elements: uncaptured, keys: Object.fromEntries(keys) };
  }
  if (options.selector && options.elementStable && result.element) {
    // inspect only: the same full-DOM uniqueness check as inspect_many rows; a positional result keeps that label.
    const stable = createStableSelector()(document.querySelector(options.selector), result.element.selector);
    result.element.stableSelector = stable.basis === 'axe-target' ? { ...stable, basis: 'positional' } : stable;
  }
  if (Array.isArray(options.axeTargets)) {
    // Resolve every requested target in this same synchronous observation. A
    // query cannot enlarge the bounded original-node observation or traverse a
    // frame/shadow path. Reuse descriptions already used in the state digest.
    const observed = new Map(eligible.slice(0, options.maxElements).map((element, index) => [element, nodes[index]]));
    const visibleElements = new Set(eligible), resolved = new Map(), elements = new Map();
    const stableSelector = createStableSelector();
    const stableByCss = new Map();
    const resolve = target => {
      if (!Array.isArray(target) || !target.length) return { status: 'unbound', reason: 'not_a_single_css_target' };
      if (target.some(part => typeof part !== 'string')) return { status: 'unbound', reason: 'shadow_or_nested_target_path' };
      if (target.length !== 1) return { status: 'unbound', reason: 'frame_or_multiple_selector_target' };
      const css = target[0];
      if (!css.trim()) return { status: 'unbound', reason: 'invalid_css_selector' };
      if (resolved.has(css)) return resolved.get(css);
      let found, binding;
      try { found = document.querySelectorAll(css); }
      catch { binding = { status: 'unbound', reason: 'invalid_css_selector' }; }
      if (found?.length === 0) binding = { status: 'unbound', reason: 'not_found_in_main_document' };
      else if (found?.length > 1) binding = { status: 'unbound', reason: 'ambiguous_main_document_target' };
      else if (found?.length === 1) {
        const element = found[0], node = observed.get(element);
        elements.set(css, element);
        if (node) binding = { status: 'bound', nodeId: node.nodeId, documentId: node.documentId, selector: node.selector };
        else if (visibleElements.has(element)) binding = { status: 'unbound', reason: 'outside_max_elements' };
        else if (!document.body.contains(element)) binding = { status: 'unbound', reason: 'outside_observed_main_body' };
        else binding = { status: 'unbound', reason: 'not_visible' };
      }
      resolved.set(css, binding);
      return binding;
    };
    result.axeNodeBindings = options.axeTargets.map(row => {
      const binding = { ...row, ...resolve(row.target) };
      if (binding.status !== 'bound' || row.disposition !== 'violations') return binding;
      const css = row.target[0];
      if (!stableByCss.has(css)) stableByCss.set(css, stableSelector(elements.get(css), css));
      return { ...binding, stableSelector: stableByCss.get(css) };
    });
  }
  if (options.inspectMany) {
    // Read-only: elements are resolved and identified in this one synchronous observation, then left on the page-global store
    // (not the DOM) so the accessibility tree can be queried for exactly these nodes. No attribute, focus or style is written.
    const request = options.inspectMany;
    const stableSelector = createStableSelector();
    const nativeInteractive = 'a[href],area[href],button,input:not([type="hidden"]),select,textarea,summary,audio[controls],video[controls],[contenteditable]:not([contenteditable="false"])';
    const ariaState = '[aria-expanded],[aria-pressed],[aria-selected],[aria-checked],[aria-haspopup],[aria-autocomplete],[aria-activedescendant],[aria-valuenow],[aria-controls]';
    const cursorPointer = element => getComputedStyle(element).cursor === 'pointer' && (!element.parentElement || getComputedStyle(element.parentElement).cursor !== 'pointer');
    const matchedBy = element => [element.matches(nativeInteractive) && 'native', element.hasAttribute('tabindex') && 'tabindex', element.hasAttribute('onclick') && 'onclick',
      element.hasAttribute('role') && 'role', element.matches(ariaState) && 'aria-state', cursorPointer(element) && 'cursor-pointer'].filter(Boolean);
    let chosen = [], total = 0, hiddenExcluded = 0;
    const selectorStatus = [];
    if (request.query === 'interactive') {
      const matched = [];
      for (const element of document.body.querySelectorAll('*')) {
        const reasons = matchedBy(element);
        if (!reasons.length) continue;
        if (!visible(element)) { hiddenExcluded++; continue; }
        total++;
        if (matched.length < request.limit) matched.push([element, reasons]);
      }
      chosen = matched;
    } else {
      const seen = new Set();
      for (const css of request.selectors) {
        let found;
        try { found = document.querySelectorAll(css); } catch { selectorStatus.push({ selector: css, status: 'invalid_selector' }); continue; }
        if (found.length === 0) { selectorStatus.push({ selector: css, status: 'not_found' }); continue; }
        if (found.length > 1) { selectorStatus.push({ selector: css, status: 'ambiguous', count: found.length }); continue; }
        const element = found[0];
        selectorStatus.push({ selector: css, status: 'ok', nodeId: identifier(element), ...(seen.has(element) ? { duplicateOf: true } : {}) });
        if (!seen.has(element)) { seen.add(element); chosen.push([element, null]); }
      }
      total = chosen.length;
    }
    const resolvedNodes = [], rows = [];
    for (const [element, reasons] of chosen) {
      const node = describe(element), rect = element.getBoundingClientRect();
      const stable = stableSelector(element, node.selector);
      resolvedNodes.push(node);
      rows.push({ nodeId: node.nodeId, documentId: store.documentId, tag: node.tag, ...(reasons ? { matchedBy: reasons } : {}),
        stable: stable.basis === 'axe-target' ? { ...stable, basis: 'positional' } : stable,
        visible: visible(element), box: [rect.x, rect.y, rect.width, rect.height],
        explicitRole: element.getAttribute('role'), nativeInteractive: element.matches(nativeInteractive),
        onclickAttr: element.hasAttribute('onclick'), tabindexAttr: element.getAttribute('tabindex'), tabIndex: element.tabIndex,
        aria: Object.fromEntries([...element.attributes].filter(attribute => attribute.name.startsWith('aria-')).slice(0, 24).map(attribute => [attribute.name, attribute.value.slice(0, 200)])) });
    }
    store.many = chosen.map(([element]) => element);
    result.inspectMany = { nodes: resolvedNodes, rows, selectorStatus, total, hiddenExcluded };
  }
  return result;
}

function axeTargets(axe) {
  const rows = [];
  let totalTargets = 0;
  for (const disposition of ['violations', 'incomplete']) {
    for (const rule of axe[disposition] || []) {
      for (const [ruleNodeIndex, node] of (rule.nodes || []).entries()) {
        totalTargets++;
        if (rows.length < axeBindingRowLimit) rows.push({ disposition, ruleId: rule.id, ruleNodeIndex, target: node.target });
      }
    }
  }
  return { rows, totalTargets, omittedTargets: Math.max(0, totalTargets - rows.length), rowLimit: axeBindingRowLimit };
}

const CHAIN_HISTORY = 64;
// Insertion-ordered maps: drop the oldest entries so a long session stays bounded without breaking a live chain.
const remember = (map, key, value, limit = CHAIN_HISTORY * 4) => {
  map.set(key, value);
  while (map.size > limit) map.delete(map.keys().next().value);
};
const hopView = hop => ({ url: clipUrl(hop.url), status: hop.status ?? null, ...(hop.blocked ? { blocked: true } : {}) });
const httpUrl = raw => { try { const url = new URL(raw); return ['http:', 'https:'].includes(url.protocol) ? url : null; } catch { return null; } };

function contrastSample(image, point) {
  const rgba = pixelAt(image, point.x, point.y);
  if (rgba[3] !== 255) throw new ToolError('TRANSPARENT_CONTRAST_SAMPLE', 'The selected screenshot pixel must be opaque; alpha compositing must be established separately.');
  let count = 0, uniform = true, opaque = true;
  const samples = [], colors = new Map();
  for (let y = Math.max(0, point.y - 1); y <= Math.min(image.height - 1, point.y + 1); y++) {
    for (let x = Math.max(0, point.x - 1); x <= Math.min(image.width - 1, point.x + 1); x++) {
      const sample = pixelAt(image, x, y); count++;
      samples.push({ x, y, rgba: sample });
      const key = sample.join(',');
      if (colors.has(key)) colors.get(key).count++;
      else colors.set(key, { rgba: sample, count: 1 });
      if (sample[3] !== 255) opaque = false;
      if (sample.some((value, index) => value !== rgba[index])) uniform = false;
    }
  }
  return { ...point, rgb: rgba.slice(0, 3), rgba, relativeLuminance: relativeLuminance(rgba), neighborhood: { radius: 1, pixels: count, uniform, opaque, samples, colors: [...colors.values()] }, quality: uniform ? 'uniform-neighborhood' : 'nonuniform-neighborhood-requires-review' };
}

function ariaWithoutInputValues(snapshot) {
  let valueIndent = null;
  return snapshot.split('\n').flatMap(line => {
    const indent = line.match(/^\s*/)[0].length;
    if (valueIndent !== null && indent > valueIndent) return [];
    valueIndent = null;
    if (!/^\s*-\s*(textbox|searchbox|spinbutton|combobox)\b/.test(line)) return [line];
    let quoted = false, escaped = false;
    for (let index = 0; index < line.length; index++) {
      if (escaped) { escaped = false; continue; }
      if (line[index] === '\\' && quoted) { escaped = true; continue; }
      if (line[index] === '"') quoted = !quoted;
      if (line[index] === ':' && !quoted) { valueIndent = indent; return [`${line.slice(0, index)}: [value omitted]`]; }
    }
    return [line];
  }).join('\n');
}

function axeWithoutHtml(value) {
  if (Array.isArray(value)) return value.map(axeWithoutHtml);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key,
    key === 'html' ? '[HTML omitted; use the corresponding DOM observation]' : axeWithoutHtml(item)]));
}

/** Keydown events one Playwright key spec produces: one per `+`-joined token (`Shift++` is Shift and +). */
function keydownCount(key) {
  const tokens = key.split('+');
  if (tokens.length > 1 && tokens.at(-1) === '') { tokens.pop(); tokens[tokens.length - 1] = '+'; }
  return tokens.length;
}

/**
 * One-press, capture-phase keydown listener on the main window. `read(expected)` removes it and returns the last keydown's
 * `defaultPrevented`, or null when that cannot be established: install/read failed (navigation, closed page), or the window
 * saw a different number of trusted keydowns than the key spec implies (focus inside a frame, an earlier handler stopped the event).
 */
async function openKeydownProbe(page) {
  let handle;
  try {
    handle = await page.evaluateHandle(() => {
      const probe = { count: 0, last: null };
      const listener = event => { if (event.isTrusted) { probe.count++; probe.last = event; } };
      probe.stop = () => window.removeEventListener('keydown', listener, true);
      window.addEventListener('keydown', listener, true);
      return probe;
    });
  } catch { return { read: async () => null }; }
  return {
    async read(expected) {
      try { return await handle.evaluate((probe, count) => { probe.stop(); return probe.last && probe.count === count ? probe.last.defaultPrevented : null; }, expected); }
      catch { return null; }
      finally { handle.dispose().catch(() => {}); }
    },
  };
}

export class AuditBrowser {
  /** `launchArgs` is an in-process option for tests (e.g. host resolver rules); manifests cannot set it. */
  constructor(manifest, { handleSignals = true, launchArgs } = {}) {
    this.manifest = manifest;
    this.axeTags = Object.freeze(auditAxeTags(manifest.standard));
    this.handleSignals = handleSignals;
    this.launchArgs = launchArgs;
    this.origin = new URL(manifest.url).origin;
    // Main-document navigation state. Without allowedOrigins/followRedirects this is the original single-origin rule.
    this.navigationPolicy = navigationPolicy(manifest);
    this.sessionOrigins = new Set([this.origin, ...this.navigationPolicy.allowedOrigins]);
    this.baseUrl = manifest.url; this.pinnedToLanding = false; this.startUrl = null;
    // Blocks are counted, not kept in a capped list, so the newest block is always reachable however long the session.
    this.navigationStage = 'audit-browser-start'; this.navigationBlockCount = 0; this.lastNavigationBlock = null;
    // Structured payload per legacy `blocked` event; the event objects keep their 0.1.1 shape {reason, url}.
    this.blockedNavigation = new WeakMap();
    this.chainByInterception = new Map(); this.pendingRedirectStatus = new Map(); this.navigationChains = []; this.chainSeq = 0;
    this.initialChain = null; this.initialBlock = null;
    this.storeKey = `__a11yAudit_${randomUUID().replaceAll('-', '')}`;
    this.keyboardOnly = true; this.inputPath = 'keyboard-only'; this.keyboardPath = [];
    this.spacingEnabled = false; this.blocked = []; this.pageErrors = []; this.browser = null; this.context = null; this.page = null;
    this.navigationResponses = [];
    this.networkReplay = null; this.networkReplayCursor = 0;
  }

  async start() {
    if (this.manifest.networkReplay) this.networkReplay = await loadNetworkReplay({ projectRoot: this.manifest.projectRoot, origin: this.origin, descriptor: this.manifest.networkReplay, onMainNavigationBlocked: event => this.blocked.push(event) });
    this.browser = await chromium.launch({ headless: true, handleSIGINT: this.handleSignals, handleSIGTERM: this.handleSignals, ...(this.launchArgs ? { args: [...this.launchArgs] } : {}) });
    if (this.closed) { await this.browser.close(); throw new ToolError('AUDIT_BROWSER_CLOSED', 'The browser session was cancelled while launching.'); }
    this.context = await this.browser.newContext({ viewport: this.manifest.viewport, serviceWorkers: 'block', acceptDownloads: false });
    if (this.closed) { await this.context.close(); await this.browser.close(); throw new ToolError('AUDIT_BROWSER_CLOSED', 'The browser session was cancelled while creating a context.'); }
    this.page = await this.context.newPage();
    this.page.setDefaultTimeout(3000); this.page.setDefaultNavigationTimeout(15000);
    this.page.on('pageerror', error => this.pageErrors.push(errorRecord(error, 'audit-page-script')));
    this.page.on('response', response => {
      if (response.request().isNavigationRequest() && response.frame() === this.page.mainFrame()) {
        this.navigationResponses.push({ url: response.url(), status: response.status(), ok: response.ok() });
      }
    });
    this.context.on('page', page => { if (page !== this.page && !this.allowAxePages) { this.blocked.push({ reason: 'unsupported_popup', url: page.url() }); void page.close().catch(() => {}); } });
    this.page.on('download', download => { this.blocked.push({ reason: 'unsupported_download', url: download.url() }); void download.cancel().catch(() => {}); });
    if (this.networkReplay) await this.networkReplay.attach(this.context);
    else {
      // Chromium's Playwright routes omit redirect hops. Intercept Document
      // requests through CDP so every main-frame hop is checked before sending.
      const navigation = await this.context.newCDPSession(this.page);
      const { frameTree } = await navigation.send('Page.getFrameTree');
      const mainFrame = frameTree.frame.id;
      // Network events only annotate the recorded hop chain with HTTP statuses; Fetch decides every hop.
      navigation.on('Network.requestWillBeSent', event => { if (event.frameId === mainFrame) this.recordRedirectResponse(event); });
      navigation.on('Network.responseReceived', event => { if (event.frameId === mainFrame) this.recordFinalResponse(event); });
      navigation.on('Fetch.requestPaused', event => {
        const decision = event.frameId === mainFrame ? this.decideMainFrameRequest(event) : { allowed: true };
        void navigation.send(decision.allowed ? 'Fetch.continueRequest' : 'Fetch.failRequest', decision.allowed
          ? { requestId: event.requestId }
          : { requestId: event.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
      });
      // Events only: this session never reads bodies, so it retains none.
      await navigation.send('Network.enable', { maxTotalBufferSize: 0, maxResourceBufferSize: 0 });
      await navigation.send('Fetch.enable', { patterns: [{ resourceType: 'Document', requestStage: 'Request' }] });
    }
    try { await this.goto(this.manifest.url, 15000); }
    finally { this.navigationStage = 'between-actions'; }
    // Landing: when the start URL was redirected to another (allowed) origin, later navigate/reset
    // resolve against the landed URL, so they never re-enter the old origin's redirect. Only an http(s)
    // page on the origin of the last followed start hop is pinned; anything else (a script moving to
    // about:blank, a replayed start) keeps the 0.1.1 behavior of resolving against manifest.url.
    this.startUrl = this.page.url();
    const landed = httpUrl(this.startUrl), lastHop = this.initialChain?.hops.at(-1);
    const followed = lastHop && !lastHop.blocked ? httpUrl(lastHop.url) : null;
    if (landed && followed && landed.origin === followed.origin && landed.origin !== this.origin) {
      this.sessionOrigins.add(landed.origin); this.baseUrl = this.startUrl; this.pinnedToLanding = true;
    }
    await this.settle();
    this.networkReplay?.setPhase('between_actions');
    return { browser: this.browser.version() };
  }

  /** Instances built without the constructor (test doubles) fall back to the manifest-only state. */
  ensureNavigationState() {
    this.navigationPolicy ??= navigationPolicy(this.manifest);
    this.sessionOrigins ??= new Set([this.navigationPolicy.manifestOrigin, ...this.navigationPolicy.allowedOrigins]);
    this.baseUrl ??= this.manifest.url;
    this.navigationBlockCount ??= 0;
    this.blockedNavigation ??= new WeakMap();
  }

  /** The chain whose network request id matches, newest first. */
  chainForNetworkId(networkId) {
    return (this.navigationChains ?? []).findLast(item => item.networkId === networkId);
  }

  /**
   * `Network.requestWillBeSent` with a redirectResponse carries the status of the hop that redirected. CDP
   * does not order it against `Fetch.requestPaused` for the next hop, so the k-th redirect response of a
   * request is applied to hop k-1 whenever it arrives; a status that arrives before its chain exists waits.
   */
  recordRedirectResponse(event) {
    if (event.type !== 'Document' || !event.redirectResponse) return;
    const chain = this.chainForNetworkId(event.requestId);
    if (!chain) {
      const pending = this.pendingRedirectStatus.get(event.requestId) ?? [];
      remember(this.pendingRedirectStatus, event.requestId, [...pending, event.redirectResponse.status]);
      return;
    }
    this.applyRedirectStatus(chain, chain.redirectResponses = (chain.redirectResponses ?? 0) + 1, event.redirectResponse.status);
  }

  applyRedirectStatus(chain, index, status) {
    const hop = chain.hops[index - 1];
    if (hop) { if (hop.status === null) hop.status = status; }
    else (chain.pendingStatuses ??= new Map()).set(index - 1, status);
  }

  recordFinalResponse(event) {
    if (event.type !== 'Document') return;
    const last = this.chainForNetworkId(event.requestId)?.hops.at(-1);
    if (last && !last.blocked && last.url === event.response.url) last.status = event.response.status;
  }

  /** Policy decision for one paused main-frame Document request; records the hop chain and any block. */
  decideMainFrameRequest(event) {
    const url = event.request.url;
    const parent = event.redirectedRequestId ? this.chainByInterception.get(event.redirectedRequestId) : undefined;
    const chain = parent ?? { seq: ++this.chainSeq, networkId: event.networkId, stage: this.navigationStage, hops: [] };
    if (!parent) {
      this.navigationChains.push(chain);
      if (this.navigationChains.length > CHAIN_HISTORY) this.navigationChains.shift();
      if (this.navigationStage === 'audit-browser-start' && !this.initialChain) this.initialChain = chain;
      const pending = this.pendingRedirectStatus.get(event.networkId);
      if (pending) { this.pendingRedirectStatus.delete(event.networkId); chain.redirectResponses = pending.length; pending.forEach((status, index) => (chain.pendingStatuses ??= new Map()).set(index, status)); }
    }
    remember(this.chainByInterception, event.requestId, chain);
    const previous = chain.hops.at(-1) ?? null;
    const decision = decideNavigation({ url, previousUrl: previous?.url ?? null, redirects: chain.hops.length, policy: this.navigationPolicy, sessionOrigins: this.sessionOrigins });
    const hop = { url, status: chain.pendingStatuses?.get(chain.hops.length) ?? null };
    chain.pendingStatuses?.delete(chain.hops.length);
    chain.hops.push(hop);
    if (!decision.allowed) {
      hop.blocked = true; chain.blocked = true;
      let current = null;
      try { current = this.page.url(); } catch { /* The page may be closing. */ }
      const details = navigationBlockDetails({ ...decision, fromUrl: previous?.url ?? current, blockedUrl: url, chain: chain.hops.map(hopView),
        policy: this.navigationPolicy, sessionOrigins: this.sessionOrigins, stage: chain.stage, initial: chain.stage === 'audit-browser-start' });
      this.navigationBlockCount++; this.lastNavigationBlock = details;
      if (chain.stage === 'audit-browser-start' && !this.initialBlock) this.initialBlock = details;
      // The 0.1.1 event shape {reason, url} is kept; the structured payload rides alongside as `navigation`.
      const legacy = { reason: 'navigation_outside_origin', url: redactUrl(url) };
      this.blockedNavigation.set(legacy, details);
      this.blocked.push(legacy);
    }
    return decision;
  }

  async goto(url, timeout) {
    const previous = new URL(this.page.url());
    const target = new URL(url);
    const blocksBefore = this.navigationBlockCount ?? 0;
    let response;
    try { response = await this.page.goto(target.href, { waitUntil: 'domcontentloaded', timeout }); }
    catch (error) {
      // The 0.1.1 error (code, message) is rethrown unchanged; a policy block adds `navigation`.
      if ((this.navigationBlockCount ?? 0) > blocksBefore) withNavigation(error, this.lastNavigationBlock);
      throw error;
    }
    previous.hash = ''; target.hash = '';
    if (response ? !response.ok() : previous.href !== target.href) {
      throw new ToolError('HTTP_ERROR', `Audit navigation returned HTTP ${response?.status() ?? 'no response'}.`);
    }
    return response;
  }

  async settle(allowNavigationTurn = true) {
    try {
      await this.page.waitForLoadState('domcontentloaded');
      await this.page.evaluate(async () => {
        await Promise.race([document.fonts.ready, new Promise(resolve => setTimeout(resolve, 1500))]);
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        const finite = document.getAnimations().filter(animation => animation.playState === 'running' &&
          Number.isFinite(animation.effect?.getComputedTiming().endTime));
        if (finite.length) await Promise.race([
          Promise.allSettled(finite.map(animation => animation.finished)),
          new Promise(resolve => setTimeout(resolve, 1500)),
        ]);
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      });
    } catch (error) {
      // A key can commit a navigation while the old document is settling.
      // Settle the new document once; never repeat the user's action.
      if (allowNavigationTurn && /Execution context was destroyed|Cannot find context with specified id/.test(String(error.message))) return this.settle(false);
      throw error;
    }
  }

  async observe(selector, { axeTargets: targets, inspectMany, elementStable, anchorIndex } = {}) {
    const raw = await this.page.evaluate(observeDocument, { storeKey: this.storeKey, documentCandidate: `doc-${randomUUID()}`, maxElements: this.manifest.maxElements, textLimit, spacingRequested: this.spacingEnabled, spacingCss: SPACING_CSS, statusSnapshot: this.statusSnapshot, selector, axeTargets: targets, inspectMany, ...(elementStable ? { elementStable: true } : {}), ...(anchorIndex ? { anchorIndex: true } : {}) });
    raw.spacing.cssSha256 = createHash('sha256').update(raw.spacing.css).digest('hex');
    const state = {
      documentId: raw.documentId, url: raw.url, viewport: raw.viewport, scroll: raw.scroll, active: raw.active,
      controls: raw.controls, controlsTotal: raw.controlsTotal, controlsTruncated: raw.controlsTruncated,
      document: raw.document, spacing: raw.spacing,
      renderedDigest: digest({ nodes: raw.nodes, visibleText: raw.visibleText, visibleTextLength: raw.visibleTextLength }),
      truncation: raw.truncation,
      keyboardOnly: this.keyboardOnly, inputPath: this.inputPath,
    };
    state.stateId = digest(state);
    this.lastObservation = { state, raw };
    return this.lastObservation;
  }

  /** AX node for each element left on the page store by the last inspect_many observation; null where the browser has none. */
  async accessibilityNodes(count) {
    const group = 'a11y-inspect-many';
    let cdp;
    try {
      cdp = await this.context.newCDPSession(this.page);
      const list = await cdp.send('Runtime.evaluate', { expression: `globalThis[${JSON.stringify(this.storeKey)}]?.many`, objectGroup: group });
      if (!list.result?.objectId) throw new ToolError('AUDIT_INSPECT_MANY_CHANGED', 'The document changed before the accessibility tree could be read.');
      const props = (await cdp.send('Runtime.getProperties', { objectId: list.result.objectId, ownProperties: true })).result
        .filter(property => /^\d+$/.test(property.name) && property.value?.objectId);
      if (props.length !== count) throw new ToolError('AUDIT_INSPECT_MANY_CHANGED', 'The document changed before the accessibility tree could be read.');
      const nodes = new Array(count).fill(null);
      for (let start = 0; start < count; start += 16) {
        await Promise.all(props.slice(start, start + 16).map(async (property, offset) => {
          try {
            const { node } = await cdp.send('DOM.describeNode', { objectId: property.value.objectId });
            const tree = await cdp.send('Accessibility.getPartialAXTree', { backendNodeId: node.backendNodeId, fetchRelatives: false });
            nodes[start + offset] = tree.nodes?.[0] ?? null;
          } catch { /* A node the browser cannot describe stays null and is counted as axUnavailable. */ }
        }));
      }
      return nodes;
    } finally {
      // The page-global reference list is cleared whether or not a CDP session could be opened.
      await this.page.evaluate(key => { delete globalThis[key]?.many; }, this.storeKey).catch(() => {});
      await cdp?.send('Runtime.releaseObjectGroup', { objectGroup: group }).catch(() => {});
      await cdp?.detach().catch(() => {});
    }
  }

  async applySpacing(enabled) {
    this.spacingEnabled = enabled;
    await this.observe();
    await this.page.evaluate(({ storeKey, enabled, css }) => {
      const store = globalThis[storeKey];
      store.spacingStyle?.remove(); store.spacingStyle = null;
      if (enabled) {
        const style = document.createElement('style'); style.textContent = css;
        (document.head || document.documentElement).append(style); store.spacingStyle = style;
      }
    }, { storeKey: this.storeKey, enabled, css: SPACING_CSS });
    await this.settle();
  }

  /**
   * Read-only: how many elements each selector matches in the current main document. No navigation, focus, style or
   * attribute change; the page store is only read, to say whether this is still the observed document.
   */
  async probeSelectors(selectors) {
    if (this.closed || !this.page || this.page.isClosed()) return null;
    return this.page.evaluate(({ list, storeKey }) => {
      const store = globalThis[storeKey];
      return { documentId: store && store.document === document ? store.documentId : null,
        counts: list.map(css => { try { return document.querySelectorAll(css).length; } catch { return -1; } }) };
    }, { list: selectors, storeKey: this.storeKey });
  }

  async uniqueSelector(selector, options = {}) {
    const observed = await this.observe(selector, options);
    return { locator: this.page.locator(`css=${selector}`), element: observed.raw.element };
  }

  /** Wait, bounded, until the main document has had no DOM mutation for quietMs. Read-only. */
  async waitForDomQuiet(quietMs, maxMs) {
    if (maxMs <= 0) return { quiet: false, waitedMs: 0 };
    return this.page.evaluate(({ quietMs, maxMs }) => new Promise(resolve => {
      const started = performance.now();
      let quietTimer, endTimer;
      const done = quiet => { observer.disconnect(); clearTimeout(quietTimer); clearTimeout(endTimer); resolve({ quiet, waitedMs: Math.round(performance.now() - started) }); };
      const arm = () => { clearTimeout(quietTimer); quietTimer = setTimeout(() => done(true), quietMs); };
      const observer = new MutationObserver(arm);
      observer.observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
      endTimer = setTimeout(() => done(false), maxMs);
      arm();
    }), { quietMs, maxMs });
  }

  /** Product settle plus a DOM-quiet wait, both bounded by `ms`; never throws (the re-capture reports any failure). */
  async settleForRecapture(ms) {
    const started = performance.now();
    let timer;
    const bound = new Promise(resolve => { timer = setTimeout(resolve, Math.max(0, ms)); });
    try {
      let quiet = false;
      await Promise.race([(async () => {
        await this.settle();
        quiet = (await this.waitForDomQuiet(CAPTURE_RETRY_POLICY.quietMs, Math.floor(ms - (performance.now() - started)))).quiet;
      })().catch(() => {}), bound]);
      return { settleMs: Math.round(performance.now() - started), domQuiet: quiet };
    } finally { clearTimeout(timer); }
  }

  async execute(action, timeoutMs = 15000, statusOptions = {}) {
    const policy = CAPTURE_RETRY_POLICY;
    // observe_status snapshots are timed against their trigger; settling them would move that timing.
    const retryable = policy.actions.includes(action.action) && statusOptions.snapshot !== true && !statusOptions.windowMs;
    if (!retryable) return this.executeOnce(action, timeoutMs, statusOptions);
    const executeDeadline = performance.now() + timeoutMs, replayCursor = this.networkReplayCursor;
    let observation = await this.executeOnce(action, timeoutMs, statusOptions);
    const retryEnd = Math.min(executeDeadline, performance.now() + policy.windowMs), retries = [];
    const changedInPlace = item => !item.success && item.error?.code === policy.reason && item.before && item.after &&
      item.before.documentId === item.after.documentId && !item.result?.navigationResponses;
    while (changedInPlace(observation) && retries.length < policy.maxExtraAttempts) {
      const remaining = retryEnd - performance.now();
      if (remaining < policy.minAttemptMs) break;
      const retry = { attempt: retries.length + 1, reason: policy.reason,
        beforeStateId: observation.before.stateId, afterStateId: observation.after.stateId, documentId: observation.before.documentId };
      this.networkReplay?.setPhase('action');
      // Leave room for the re-capture itself inside the window: split the settle budget over the remaining retries.
      Object.assign(retry, await this.settleForRecapture(Math.max(0, remaining - policy.minAttemptMs) / (policy.maxExtraAttempts - retries.length)));
      retries.push(retry);
      observation = await this.executeOnce(action, Math.max(1, executeDeadline - performance.now()), statusOptions);
    }
    observation.captureAttempts = retries.length + 1;
    if (retries.length) {
      observation.captureRetries = retries;
      // One action, one replay delta: cover every attempt's network observations.
      if (this.networkReplay) {
        const value = this.networkReplay.snapshot({ since: replayCursor });
        this.networkReplayCursor = value.nextCursor; observation.networkReplay = value;
      }
    }
    return observation;
  }

  async executeOnce(action, timeoutMs, statusOptions) {
    const executeDeadline = performance.now() + timeoutMs;
    const blobEnd = Math.min(executeDeadline, performance.now() + (action.timeoutMs ?? 3000));
    let blobCapture, statusCapture;
    this.statusSnapshot = statusOptions.snapshot === true;
    const observeBounded = (...args) => action.action === 'blob_digest'
      ? blobDeadline(() => this.observe(...args), blobEnd) : this.observe(...args);
    this.networkReplay?.setPhase('action');
    let before = null, after = null, result = {}, png, bindingTargets;
    if (action.action === 'blob_digest') result = { complete: false, selector: action.selector, attribute: action.attribute };
    if (action.action === 'wait_for') result = { condition: action.condition, selector: action.selector,
      timeoutMs: action.timeoutMs ?? 3000, effectiveTimeoutMs: 0, matched: false };
    const blockedBefore = this.blocked.length;
    const navigationBefore = this.navigationResponses.length, chainBefore = this.chainSeq ?? 0;
    this.navigationStage = action.action;
    const captureNavigation = () => {
      const responses = this.navigationResponses.slice(navigationBefore);
      if (responses.length) result = { ...result, navigationResponses: responses };
      // Only redirected or blocked main-document navigations add a chain; plain loads keep the original record shape.
      const chains = (this.navigationChains ?? []).filter(chain => chain.seq > chainBefore && (chain.hops.length > 1 || chain.blocked));
      if (chains.length) result = { ...result, redirectChains: chains.map(chain => ({ hops: chain.hops.map(hopView), ...(chain.blocked ? { blocked: true } : {}) })) };
      return responses;
    };
    const replayDelta = () => {
      if (!this.networkReplay) return {};
      const value = this.networkReplay.snapshot({ since: this.networkReplayCursor });
      this.networkReplayCursor = value.nextCursor;
      if (!this.closed) this.networkReplay.setPhase('between_actions');
      return { networkReplay: value };
    };
    try {
      if (action.action === 'blob_digest') blobCapture = await openBlobCapture(this, action, blobEnd, executeDeadline);
      const initial = await observeBounded(undefined, action.action === 'snapshot' ? { anchorIndex: true } : {}); before = initial.state;
      if (statusOptions.windowMs) {
        if (statusOptions.focusSelector) {
          const { element } = await this.uniqueSelector(statusOptions.focusSelector);
          if (!element.focused) throw new ToolError('STATUS_TRIGGER_FOCUS', 'press selector must already have focus.');
        }
        statusCapture = await openStatusRecorder(this);
      }
      switch (action.action) {
        case 'blob_digest': {
          result = { complete: false, selector: action.selector, attribute: action.attribute };
          await blobCapture.read(initial);
          break;
        }
        case 'snapshot': {
          result = { nodes: initial.raw.statusNodes ?? initial.raw.nodes, visibleText: initial.raw.visibleText, visibleTextLength: initial.raw.visibleTextLength, visibleTextTruncated: initial.raw.visibleTextTruncated, document: initial.raw.document, truncation: initial.raw.statusTruncation ?? initial.raw.truncation, ...(initial.raw.uncapturedAnchors ? { uncapturedAnchors: initial.raw.uncapturedAnchors } : {}), ariaSnapshot: ariaWithoutInputValues(await this.page.locator('body').ariaSnapshot({ timeout: Math.min(timeoutMs, 3000) })), ariaInputValuesOmitted: true, observationSource: 'Rendered DOM and native browser ARIA snapshot via Playwright with input values omitted; body.innerText is not OCR, pixel visibility proof, or screen-reader output.' };
          break;
        }
        case 'inspect': {
          const observed = await this.uniqueSelector(action.selector, { elementStable: true });
          result = { element: observed.element, ariaSnapshot: ariaWithoutInputValues(await observed.locator.ariaSnapshot({ timeout: Math.min(timeoutMs, 3000) })), ariaInputValuesOmitted: true, observationSource: 'Rendered DOM and native browser ARIA snapshot with input values omitted; not screen-reader output.' };
          break;
        }
        case 'inspect_many': {
          const request = action.query ? { query: action.query, limit: INSPECT_MANY_PRESET_LIMIT } : { selectors: action.selectors };
          const many = (await this.observe(undefined, { inspectMany: request })).raw.inspectMany;
          const axNodes = await this.accessibilityNodes(many.rows.length);
          result = { query: action.query ? { preset: action.query, rule: INTERACTIVE_RULE } : { selectors: action.selectors },
            nodes: many.nodes, elements: buildElementRows(many.rows, axNodes),
            ...(many.selectorStatus.length ? { selectorStatus: many.selectorStatus } : {}),
            counts: { matched: many.total, returned: many.rows.length, omitted: Math.max(0, many.total - many.rows.length),
              ...(action.query ? { hiddenExcluded: many.hiddenExcluded } : {}), axUnavailable: axNodes.filter(node => !node).length },
            observationSource: "Rendered DOM plus Chrome's accessibility tree (CDP Accessibility.getPartialAXTree) for each listed node; input values are omitted. Not screen-reader output. Main document only: child frames and shadow roots are not covered. Flags are neutral observations (flagRules), not findings." };
          break;
        }
        case 'axe':
          // The public axe Playwright integration creates a temporary blank page
          // while assembling results. It must not be mistaken for a site popup.
          this.allowAxePages = true;
          try {
            const axe = axeWithoutHtml(await new AxeBuilder({ page: this.page }).withTags([...this.axeTags]).analyze());
            bindingTargets = axeTargets(axe);
            result = { axe, axeHtmlOmitted: true, tags: [...this.axeTags], nodes: [],
              axeNodeBindings: { profile: 'main-dom-axe-targets-v1', capturedStateId: null, capturedDocumentId: null, stable: false,
                ...bindingTargets, rows: bindingTargets.rows.map(row => ({ ...row, status: 'unbound', reason: 'capture_not_completed' })) },
              assessment: 'All default configured rule results and targets remain; HTML snippets are omitted in favor of the separately captured DOM. Only stable, bounded, unique main-document CSS targets have original-node bindings. Automated observations require review and are not whole-criterion verdicts.' };
          }
          finally { this.allowAxePages = false; }
          break;
        case 'screenshot':
        case 'contrast': {
          const captured = await this.observe(); before = captured.state;
          // Playwright's default caret hiding leaves empty style attributes on
          // form fields in this browser. Preserve the real caret and DOM state.
          png = await this.page.screenshot({ fullPage: action.action === 'screenshot' && action.fullPage === true, animations: 'disabled', caret: 'initial', timeout: timeoutMs });
          const observed = await this.observe(); after = observed.state;
          result = { ...pngDimensions(png), nodes: captured.raw.nodes, focusedElement: captured.state.active, truncation: captured.raw.truncation, capture: { beforeStateId: before.stateId, afterStateId: after.stateId, stable: before.stateId === after.stateId, method: 'DOM observation immediately before and after one screenshot; changing states are rejected.' } };
          if (!result.capture.stable) throw new ToolError('SCREENSHOT_STATE_CHANGED', 'The rendered state changed while capturing this screenshot; bind new evidence after it settles.');
          if (action.action === 'contrast') {
            const image = decodePng(png), foreground = contrastSample(image, action.foreground), background = contrastSample(image, action.background);
            result.contrast = { foreground, background, ratio: contrastRatio(foreground.rgba, background.rgba), formula: 'WCAG-relative-luminance-sRGB', srgbThreshold: 0.04045, coefficients: [0.2126, 0.7152, 0.0722], ratioOffset: 0.05, alphaPolicy: 'opaque-samples-only', screenshotSha256: createHash('sha256').update(png).digest('hex'), qualityWarnings: [foreground, background].filter(sample => !sample.neighborhood.uniform).map(sample => ({ x: sample.x, y: sample.y, code: 'NONUNIFORM_SAMPLE_NEIGHBORHOOD', message: 'The neighboring pixels include edges or other colors. Establish separately that the selected pixel represents the intended foreground/background.' })), scope: 'Caller-selected screenshot samples; whether pixels represent text colors, text size/type and WCAG applicability require review.' };
          }
          break;
        }
        case 'measure_nontext': {
          // Read-only: one stable viewport PNG (the same capture `contrast` makes, so pair coordinates are valid contrast arguments) bound to this node and state.
          const captured = await this.observe(action.selector); before = captured.state;
          const target = captured.raw.element;
          const facts = await this.page.evaluate(collectNonTextFacts, { storeKey: this.storeKey, selector: action.selector, nodeId: target.nodeId });
          if (facts.changed) throw new ToolError('NONTEXT_TARGET_CHANGED', 'The selector no longer identifies the observed element; measure again.');
          const ax = compactAxNode((await this.accessibilityNodes(1))[0]);
          const { rect, viewport } = facts;
          if (!(rect.width > 0 && rect.height > 0) || rect.x + rect.width <= 0 || rect.y + rect.height <= 0 || rect.x >= viewport.width || rect.y >= viewport.height) {
            throw new ToolError('NONTEXT_TARGET_NOT_IN_VIEWPORT', 'The element has no box inside the current viewport; use scroll to bring it into view, then measure again.');
          }
          png = await this.page.screenshot({ animations: 'allow', caret: 'initial', timeout: timeoutMs });
          const observed = await this.observe(action.selector); after = observed.state;
          result = { ...pngDimensions(png), element: target, target: { nodeId: target.nodeId, documentId: target.documentId, selector: target.selector },
            capture: { beforeStateId: before.stateId, afterStateId: after.stateId, stable: before.stateId === after.stateId, method: 'DOM observation immediately before and after one screenshot; changing states are rejected.' } };
          if (!result.capture.stable) throw new ToolError('SCREENSHOT_STATE_CHANGED', 'The rendered state changed while capturing this screenshot; bind new evidence after it settles.');
          const analysis = analyzeNonText({ image: decodePng(png), facts, part: action.part, ax });
          result.nonText = { ...analysis, requestedPart: action.part ?? null, screenshotSha256: createHash('sha256').update(png).digest('hex'),
            facts, ax: { role: ax.role ?? null, name: ax.name ?? null, ignored: ax.ignored ?? null, states: ax.states ?? null }, scope: NONTEXT_SCOPE };
          break;
        }
        case 'viewport':
          await this.page.setViewportSize({ width: action.width, height: action.height });
          await this.settle(); result = { viewport: this.page.viewportSize() }; break;
        case 'spacing':
          await this.applySpacing(action.enabled);
          break;
        case 'press': {
          // A capture-phase listener on window sees the keydown even when the app stops propagation; it is removed on every path.
          const probe = await openKeydownProbe(this.page);
          let defaultPrevented = null;
          try { await this.page.keyboard.press(action.key, { timeout: timeoutMs }); }
          finally { defaultPrevented = await probe.read(keydownCount(action.key)); }
          this.keyboardPath.push({ key: action.key, documentId: before.documentId, activeBefore: before.active?.nodeId || null });
          await this.settle(); result = { key: action.key, defaultPrevented, keyboardOnly: this.keyboardOnly, inputPath: this.inputPath, keyboardPath: [...this.keyboardPath], method: 'page.keyboard.press from the document’s actual current focus; no selector focus was applied.' }; break;
        }
        case 'hover': {
          const { locator, element } = await this.uniqueSelector(action.selector);
          result = { target: element, hovered: false, keyboardOnly: false, inputPath: 'mouse-assisted' };
          this.keyboardOnly = false; this.inputPath = 'mouse-assisted';
          if (!await locator.isVisible()) throw new ToolError('AUDIT_HOVER_TARGET_NOT_VISIBLE', 'The hover target is not visible.');
          try { await locator.hover({ timeout: Math.min(timeoutMs, 3000) }); }
          catch { throw new ToolError('AUDIT_HOVER_FAILED', 'The target could not be hovered within the action timeout.'); }
          await this.settle(); result.hovered = true; break;
        }
        case 'focus': {
          const { locator, element } = await this.uniqueSelector(action.selector);
          this.keyboardOnly = false; this.inputPath = 'programmatic';
          result = { target: element, focused: false, keyboardOnly: false, inputPath: this.inputPath };
          try {
            await locator.focus({ timeout: Math.min(timeoutMs, 3000) });
            await this.settle();
            const acquired = await locator.evaluate(el => document.activeElement === el, undefined, { timeout: Math.min(timeoutMs, 3000) });
            after = (await this.observe()).state;
            if (!acquired || after.active?.nodeId !== element.nodeId || after.active?.documentId !== element.documentId) {
              throw new Error('Focus did not remain on the observed target.');
            }
          } catch { throw new ToolError('AUDIT_FOCUS_NOT_ACQUIRED', 'The observed target did not acquire and retain document focus.'); }
          result.focused = true; break;
        }
        case 'click': {
          const { locator, element } = await this.uniqueSelector(action.selector);
          this.keyboardOnly = false; this.inputPath = 'mouse-assisted';
          await locator.click({ timeout: Math.min(timeoutMs, 3000) }); await this.settle();
          result = { target: element, clicked: true, keyboardOnly: false, inputPath: this.inputPath }; break;
        }
        case 'fill': {
          const { locator, element } = await this.uniqueSelector(action.selector);
          this.keyboardOnly = false; this.inputPath = 'mouse-assisted';
          await locator.fill(action.value, { timeout: Math.min(timeoutMs, 3000) }); await this.settle();
          result = { target: element, filled: true, keyboardOnly: false, inputPath: this.inputPath }; break;
        }
        case 'navigate': {
          // Relative paths resolve against the landed start URL when the start redirected to another origin.
          this.ensureNavigationState();
          const target = new URL(action.path, this.baseUrl);
          const decision = decideNavigation({ url: target.href, policy: this.navigationPolicy, sessionOrigins: this.sessionOrigins });
          if (!decision.allowed) {
            throw withNavigation(new ToolError('UNSAFE_AUDIT_NAVIGATION', 'Navigation must remain on the manifest HTTP(S) origin without credentials.'), navigationBlockDetails({ ...decision, fromUrl: this.page.url(),
              blockedUrl: target.href, chain: [{ url: target.href, status: null, blocked: true }], policy: this.navigationPolicy, sessionOrigins: this.sessionOrigins, stage: 'navigate' }));
          }
          await this.goto(target.href, Math.min(timeoutMs, 15000));
          await this.settle(); result = { url: this.page.url() }; break;
        }
        case 'scroll':
          await this.page.evaluate(({ x, y }) => window.scrollTo({ left: x, top: y, behavior: 'instant' }), action);
          await this.settle(); result = { scroll: await this.page.evaluate(() => ({ x: scrollX, y: scrollY })) }; break;
        case 'wait_for': {
          const effective = Math.max(0, Math.min(result.timeoutMs, executeDeadline - performance.now()));
          result.effectiveTimeoutMs = effective;
          const deadline = performance.now() + effective;
          const metadata = { ...result };
          // Poll only this predicate; each request remains one action, with no host retry.
          while (performance.now() < deadline) {
            let timer;
            try {
              const observation = await Promise.race([
                this.page.evaluate(readinessObservation, action),
                new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new ToolError('AUDIT_READINESS_TIMEOUT', 'Readiness predicate did not match within its effective timeout.')), Math.max(1, deadline - performance.now())); }),
              ]);
              result = { ...metadata, ...observation, matched: false };
              if (observation.ambiguous) throw new ToolError('AUDIT_READINESS_AMBIGUOUS', 'Readiness selector must match at most one main-document element.');
              if (observation.matched && performance.now() <= deadline) { result.matched = true; break; }
            } finally { clearTimeout(timer); }
            await new Promise(resolve => setTimeout(resolve, Math.min(25, Math.max(0, deadline - performance.now()))));
          }
          if (!result.matched) throw new ToolError('AUDIT_READINESS_TIMEOUT', 'Readiness predicate did not match within its effective timeout.');
          break;
        }
        case 'wait':
          await this.page.waitForTimeout(action.ms); await this.settle(); result = { waitedMs: action.ms }; break;
        case 'reset':
          this.spacingEnabled = false;
          this.keyboardOnly = true; this.inputPath = 'keyboard-only'; this.keyboardPath = [];
          await this.page.setViewportSize(this.manifest.viewport);
          // A fragment-only goto can retain the document, styles and focus.
          await this.page.goto('about:blank', { waitUntil: 'domcontentloaded', timeout: Math.min(timeoutMs, 15000) });
          this.ensureNavigationState();
          await this.goto(this.baseUrl, Math.min(timeoutMs, 15000));
          await this.settle(); result = { reset: true, keyboardOnly: true, inputPath: this.inputPath, focusOrigin: 'new-document-initial-focus' }; break;
        default: throw new ToolError('UNSUPPORTED_AUDIT_ACTION', `Unsupported audit action: ${action.action}`);
      }
      if (!after) {
        if (statusCapture) {
          await new Promise(resolve => setTimeout(resolve, Math.min(statusOptions.windowMs, Math.max(0, executeDeadline - performance.now()))));
          result.statusObservation = await statusCapture.finish();
          result.statusObservation.expectedText = statusOptions.expectedText ?? null;
        }
        const observationOptions = bindingTargets ? { axeTargets: bindingTargets.rows } : {};
        let observed = await observeBounded(undefined, observationOptions);
        if (action.action !== 'blob_digest' && this.spacingEnabled && observed.state.documentId !== before.documentId) { await this.applySpacing(true); observed = await this.observe(undefined, observationOptions); }
        after = observed.state;
      }
      if (bindingTargets) {
        const observed = this.lastObservation.raw, rows = observed.axeNodeBindings;
        const boundIds = new Set(rows.filter(row => row.status === 'bound').map(row => row.nodeId));
        const boundNodes = observed.nodes.filter(node => boundIds.has(node.nodeId));
        const originalNodes = new Map(initial.raw.nodes.map(node => [node.nodeId, node]));
        const stable = before.stateId === after.stateId && before.documentId === after.documentId &&
          boundNodes.every(node => originalNodes.has(node.nodeId) && digest(originalNodes.get(node.nodeId)) === digest(node));
        result.nodes = stable ? boundNodes : [];
        result.axeNodeBindings = { profile: 'main-dom-axe-targets-v1', capturedStateId: stable ? after.stateId : null,
          capturedDocumentId: stable ? after.documentId : null, stable, beforeStateId: before.stateId, afterStateId: after.stateId,
          ...bindingTargets, rows: rows.map(row => {
            if (stable || row.status !== 'bound') return row;
            const { nodeId, documentId, selector, stableSelector, ...unbound } = row;
            return { ...unbound, status: 'unbound', reason: 'axe_capture_state_changed' };
          }) };
      }
      if (action.action === 'spacing') result = { ...after.spacing, stylePresent: after.spacing.enabled, enabled: action.enabled, requestedCss: SPACING_CSS, requested: { ...SPACING_REQUEST }, nodes: this.lastObservation.raw.nodes };
      if (['snapshot', 'inspect', 'inspect_many'].includes(action.action) && before.stateId !== after.stateId) throw new ToolError('DOM_STATE_CHANGED', 'The rendered state changed while capturing the DOM and native ARIA snapshot; collect again after it settles.');
      if (this.blocked.length > blockedBefore) {
        const events = this.blocked.slice(blockedBefore), block = events.map(event => this.blockedNavigation?.get(event)).findLast(Boolean);
        throw withNavigation(new ToolError('AUDIT_BROWSER_ACTION_BLOCKED', 'The action attempted an unsupported popup, download or navigation outside the allowed origin.', events), block);
      }
      const failedNavigation = captureNavigation().filter(response => response.status >= 400);
      if (failedNavigation.length) throw new ToolError('HTTP_ERROR', 'An action navigated the main document to an HTTP error response.', failedNavigation);
      if (blobCapture) {
        await blobCapture.verify();
        if (before.documentId !== after.documentId) throw new ToolError('AUDIT_BLOB_CHANGED', 'Document changed during capture.');
        result = { ...blobCapture.metadata, capture: { beforeStateId: before.stateId, afterStateId: after.stateId, stable: before.stateId === after.stateId } };
      }
      return { success: true, before, after, result, ...replayDelta(), ...(png ? { pngBytes: png } : {}) };
    } catch (error) {
      if (action.action === 'blob_digest') result = { complete: false, selector: action.selector, attribute: action.attribute };
      if (!after) try { after = (await observeBounded()).state; } catch { /* Closed/unreachable documents have no claimed after-state. */ }
      captureNavigation();
      // Playwright's failed-fill call log can include the runtime input value.
      const detail = action.action === 'fill'
        ? { code: error.code || 'AUDIT_FILL_ERROR', stage: 'fill', message: 'The fill action failed; the supplied input value is omitted.' }
        : errorRecord(error, action.action);
      return { success: false, before, after, result, error: detail, ...replayDelta(), ...(png ? { pngBytes: png } : {}) };
    } finally { this.statusSnapshot = false; this.navigationStage = 'between-actions'; if (statusCapture) await statusCapture.close(); if (blobCapture) await blobCapture.close(); }
  }

  async close() {
    this.closed = true;
    if (this.closing) return this.closing;
    this.closing = this.closeResources();
    return this.closing;
  }

  async closeResources() {
    this.networkReplay?.setPhase('cleanup');
    const errors = [...this.pageErrors, ...this.blocked.map(event => {
      const navigation = this.blockedNavigation?.get(event);
      return { code: 'AUDIT_UNSUPPORTED_EVENT', message: `The site attempted an unsupported browser event: ${event.reason}.`, details: event, ...(navigation ? { navigation } : {}) };
    })];
    if (this.context) await this.context.close().catch(error => errors.push(errorRecord(error, 'audit-context-close')));
    if (this.browser) await this.browser.close().catch(error => errors.push(errorRecord(error, 'audit-browser-close')));
    if (this.networkReplay) { await this.networkReplay.drain(); this.networkReplay.setPhase('closed'); }
    errors.push(...this.navigationResponses.filter(response => response.status >= 400).map(response => ({ code: 'HTTP_ERROR', stage: 'audit-main-document-navigation', message: `A main-document navigation returned HTTP ${response.status}.`, details: response })));
    return errors;
  }

  /** Additive report field: declared URL, recorded start chain, landed URL and the policy in force. */
  navigationReport() {
    const hops = this.initialChain?.hops.map(hopView) ?? [];
    const last = hops.at(-1);
    // The landed URL comes from page.url(); it is redacted and clipped like every other recorded URL.
    const landed = this.startUrl ?? (last && !last.blocked ? this.initialChain.hops.at(-1).url : null);
    const finalUrl = landed == null ? null : clipUrl(landed);
    return {
      version: this.navigationPolicy.version, manifestUrl: this.manifest.url, finalUrl,
      redirectChain: hops, redirects: Math.max(0, hops.length - 1),
      landingOrigin: finalUrl ? clipUrl(new URL(landed).origin) : null, pinnedToLanding: this.pinnedToLanding,
      sessionOrigins: [...this.sessionOrigins],
      policy: { followRedirects: this.navigationPolicy.followRedirects, allowedOrigins: [...this.navigationPolicy.allowedOrigins], maxRedirects: this.navigationPolicy.maxRedirects },
      ...(this.initialBlock ? { blocked: this.initialBlock } : {}),
      ...(this.networkReplay || this.manifest.networkReplay ? { chainSource: 'not-recorded-under-network-replay' } : {}),
    };
  }

  networkReplayReport() {
    if (!this.manifest.networkReplay) return undefined;
    return this.networkReplay?.report() ?? { mode: 'exact-local-response-replay-v1', status: 'not_loaded', descriptor: this.manifest.networkReplay, note: 'Local replay validation did not complete; no fallback network profile was used.' };
  }
}
