import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { precheckNode, precheckContextFromRecords, precheckProposal, precheckSession, PRECHECK_RULES } from '../src/audit/precheck.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { fixture } from './helpers.js';

const rules = notes => notes.map(note => note.rule);
const ctx = (node, extra = {}) => ({ node: { attributes: {}, text: '', ...node }, ancestors: [], ancestorsComplete: false, descendantTags: [], parent: null, ax: null, ...extra });
const body = { tag: 'body', attributes: {} };

test('rule catalogue is documented for every emitted rule', () => {
  assert.deepEqual(Object.keys(PRECHECK_RULES).sort(), ['documented-shortcut', 'list-semantics-exposed', 'name-present-now', 'no-keyboard-evidence', 'not-a-ui-component', 'operation-not-tested', 'target-size-exception']);
});

test('not-a-ui-component: SVG fragments and empty unnamed elements are noted for 4.1.2, 2.1.1 and 2.5.x', () => {
  const path_ = ctx({ tag: 'path', attributes: { 'aria-label': 'n7m', fill: 'currentColor' } }, { ancestors: [{ tag: 'svg', attributes: {} }, { tag: 'a', attributes: { href: '/x' } }] });
  const svg = precheckNode('4.1.2', path_);
  assert.deepEqual(rules(svg), ['not-a-ui-component']);
  assert.equal(svg[0].basis.kind, 'svg-sub-element'); assert.equal(svg[0].basis.operableAncestor, 'a');
  const rail = ctx({ tag: 'div', attributes: { class: 'scrollbar-rail', 'data-scrollbar-rail': 'true' } });
  for (const sc of ['4.1.2', '2.1.1', '2.5.8']) assert.deepEqual(rules(precheckNode(sc, rail)), ['not-a-ui-component'], sc);
  assert.equal(precheckNode('4.1.2', rail)[0].basis.kind, 'empty-without-name');
  // Only targeted criteria: 1.4.3 or 1.1.1 on the same node get no note.
  assert.deepEqual(precheckNode('1.4.3', rail), []); assert.deepEqual(precheckNode('1.1.1', path_), []);
  // `rect` is SVG only with an <svg> ancestor.
  assert.equal(precheckNode('4.1.2', ctx({ tag: 'rect' }, { descendantTags: null })).length, 0);
  assert.deepEqual(rules(precheckNode('4.1.2', ctx({ tag: 'rect' }, { ancestors: [{ tag: 'svg', attributes: {} }] }))), ['not-a-ui-component']);
});

test('not-a-ui-component abstains on any interactive signal, content, name source or unknown descendants', () => {
  const signals = [
    { tag: 'button' }, { tag: 'input', attributes: { type: 'text' } }, { tag: 'a', attributes: { href: '#' } }, { tag: 'select' },
    { tag: 'div', attributes: { role: 'switch' } }, { tag: 'div', attributes: { tabindex: '0' } }, { tag: 'div', attributes: { contenteditable: '' } },
    { tag: 'div', attributes: { onclick: 'go()' } }, { tag: 'div', tabIndex: 0 },
  ];
  for (const node of signals) assert.deepEqual(precheckNode('4.1.2', ctx(node)), [], JSON.stringify(node));
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'div' }, { ax: { role: 'none', name: '', matchedBy: ['cursor-pointer'] } })), []);
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'div' }, { ax: { role: 'generic', name: '', tabStop: true } })), []);
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'path' }, { ax: { role: 'button', name: 'x' } })), []);
  // Content or a name source means it may be a custom control: abstain.
  assert.deepEqual(precheckNode('2.1.1', ctx({ tag: 'div', text: 'Crypto' })), []);
  assert.deepEqual(precheckNode('2.1.1', ctx({ tag: 'div', attributes: { title: 'Resize' } })), []);
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'li', attributes: { 'data-original-title': 'Eraser tool' } })), []);
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'div' }, { ax: { role: 'generic', name: 'Close' } })), []);
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'div' }, { descendantTags: ['span', 'img'] })), []);
  // Unknown text or descendants: abstain rather than guess.
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'div', text: undefined })), []);
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'div' }, { descendantTags: null })), []);
  assert.deepEqual(precheckNode('4.1.2', null), []);
});

test('documented-shortcut: 2.1.1 targets or near ancestors with shortcut hints are noted', () => {
  const eraser = ctx({ tag: 'li', attributes: { title: "<div>Eraser tool <span class='tooltip-shortcut'>(E)</span></div>" } });
  const note = precheckNode('2.1.1', eraser);
  assert.deepEqual(rules(note), ['documented-shortcut']); assert.equal(note[0].basis.source, 'title'); assert.match(note[0].message, /Eraser tool \(E\)/);
  const cases = [
    ctx({ tag: 'div', attributes: { title: 'Swap colors (X)' } }),
    ctx({ tag: 'div', text: 'Undo Ctrl+Z' }), ctx({ tag: 'div', text: 'Redo Ctrl-Y' }),
    ctx({ tag: 'div', attributes: { 'aria-label': 'Save ⌘S' } }),
    ctx({ tag: 'div', attributes: { accesskey: 's' } }),
    ctx({ tag: 'div', attributes: { 'aria-keyshortcuts': 'Shift+N' } }),
    ctx({ tag: 'div', attributes: { 'data-tooltip': 'Next result (Enter)' } }),
    ctx({ tag: 'span' }, { ancestors: [{ tag: 'div', attributes: { title: 'Pen tool (P)' } }] }),
  ];
  for (const value of cases) assert.ok(rules(precheckNode('2.1.1', value)).includes('documented-shortcut'), JSON.stringify(value.node));
  // Only 2.1.1, and no false hints from counters, plural "(s)" or distant ancestors.
  assert.deepEqual(precheckNode('4.1.2', ctx({ tag: 'button', attributes: { title: 'Expand (Ctrl+E)' } })), []);
  for (const value of [
    ctx({ tag: 'div', text: 'Add new frame' }), ctx({ tag: 'div', text: 'Notifications (3)' }), ctx({ tag: 'div', text: 'Select file(s)' }),
    ctx({ tag: 'div', attributes: { title: 'Edit alt-text' } }), ctx({ tag: 'div', attributes: { title: 'Shift+Click to select a range' } }),
    ctx({ tag: 'div', text: 'Add' }, { ancestors: [{ tag: 'div', attributes: {} }, { tag: 'div', attributes: {} }, { tag: 'div', attributes: { title: 'Pen tool (P)' } }] }),
    ctx({ tag: 'div', text: 'Add' }, { ancestors: [{ tag: 'div', attributes: { class: 'shortcut-free (P)' } }] }),
  ]) assert.deepEqual(precheckNode('2.1.1', value), [], JSON.stringify(value));
});

test('target-size-exception: user-agent styled links and inline links are noted for 2.5.8 only', () => {
  const listing = ctx({ tag: 'a', attributes: { href: '01_basic_usage.html' }, text: '01_basic_usage.html', computed: { color: 'rgb(0, 0, 238)', fontFamily: 'Times', display: 'inline' } },
    { ancestors: [{ tag: 'li', attributes: {} }, { tag: 'ul', attributes: {} }, body, { tag: 'html', attributes: { lang: 'en', class: 'x' } }], ancestorsComplete: true,
      parent: { tag: 'li', text: '01_basic_usage.html' } });
  const notes = precheckNode('2.5.8', listing);
  assert.deepEqual(rules(notes), ['target-size-exception']); assert.equal(notes[0].basis.exception, 'user-agent-control');
  assert.deepEqual(precheckNode('2.4.4', listing), []);
  // Abstain: author class/style anywhere below <html>, non-default colour/font, incomplete or unknown ancestry, unknown colour.
  const variants = [
    { ancestors: [{ tag: 'li', attributes: { class: 'item' } }, body], ancestorsComplete: true },
    { node: { ...listing.node, attributes: { href: 'x', style: 'padding:0' } } },
    { node: { ...listing.node, computed: { color: 'rgb(26, 115, 232)', fontFamily: 'Times' } } },
    { node: { ...listing.node, computed: { color: 'rgb(0, 0, 238)', fontFamily: 'Inter, sans-serif' } } },
    { node: { ...listing.node, computed: {} } },
    { ancestorsComplete: false },
    { ancestors: null },
  ];
  for (const change of variants) assert.deepEqual(precheckNode('2.5.8', { ...listing, ...change }), [], JSON.stringify(change));
  // Missing fontFamily is tolerated (colour plus unstyled ancestry still apply).
  assert.equal(precheckNode('2.5.8', { ...listing, node: { ...listing.node, computed: { color: 'rgb(85, 26, 139)' } } }).length, 1);
  const inline = ctx({ tag: 'a', attributes: { href: '/terms', class: 'link' }, text: 'terms', computed: { color: 'rgb(10, 10, 10)', display: 'inline' } },
    { parent: { tag: 'p', text: 'By continuing you accept the terms and the privacy policy.' } });
  const inlineNotes = precheckNode('2.5.8', inline);
  assert.deepEqual(rules(inlineNotes), ['target-size-exception']); assert.equal(inlineNotes[0].basis.exception, 'inline');
  for (const change of [{ parent: null }, { parent: { tag: 'li', text: 'terms' } }, { node: { ...inline.node, computed: { display: 'inline-block' } } }, { node: { ...inline.node, tag: 'button', attributes: {} } }]) {
    assert.deepEqual(precheckNode('2.5.8', { ...inline, ...change }), [], JSON.stringify(change));
  }
});

test('list-semantics-exposed: 1.3.1 claims on exposed lists are noted; overridden roles abstain', () => {
  const list = ctx({ tag: 'ul', attributes: { id: 'preview-list' }, text: '1 Add new frame' }, { descendantTags: ['li', 'div'] });
  assert.deepEqual(rules(precheckNode('1.3.1', list)), ['list-semantics-exposed']);
  assert.deepEqual(rules(precheckNode('1.3.1', ctx({ tag: 'div', attributes: { role: 'list' } }))), ['list-semantics-exposed']);
  assert.deepEqual(precheckNode('1.3.1', { ...list, ax: { role: 'list', name: '' } }).length, 1);
  assert.deepEqual(precheckNode('1.3.1', { ...list, ax: { role: 'generic', name: '' } }), []);
  assert.deepEqual(precheckNode('1.3.1', ctx({ tag: 'ul', attributes: { role: 'presentation' } })), []);
  assert.deepEqual(precheckNode('1.3.1', ctx({ tag: 'h3', text: 'All the tools' })), []);
  assert.deepEqual(precheckNode('4.1.2', list), []);
});

test('context from records: snapshot ancestry, same-state descendants, inspect chain and inspect_many AX', () => {
  const doc = 'doc-1', state = { documentId: doc, stateId: 's1', url: 'http://x/' };
  const n = (id, parent, tag, extra = {}) => ({ nodeId: `${doc}:${id}`, documentId: doc, parentNodeId: parent ? `${doc}:${parent}` : `${doc}:html`, selector: id, tag, attributes: {}, text: '', ...extra });
  const nodes = [n('b', null, 'body'), n('ul', 'b', 'ul'), n('li', 'ul', 'li', { text: 'a.html' }),
    n('a', 'li', 'a', { attributes: { href: 'a.html' }, text: 'a.html', computed: { color: 'rgb(0, 0, 238)', fontFamily: 'Times', display: 'inline' } }),
    n('rail', 'b', 'div', { attributes: { class: 'rail' } }), n('icon', 'b', 'div', { attributes: { class: 'icon' } }), n('img', 'icon', 'img')];
  const snapshot = { evidenceId: 'ev-0001', action: 'snapshot', success: true, after: state, result: { nodes, truncation: { omittedVisibleElements: 0 } } };
  const axe = { evidenceId: 'ev-0002', action: 'axe', success: true, after: state, result: { nodes: [nodes[3], nodes[4]] } };
  const many = { evidenceId: 'ev-0003', action: 'inspect_many', success: true, after: state, result: { nodes: [nodes[5]],
    elements: [{ nodeId: `${doc}:icon`, ax: { available: true, role: 'generic', name: '' }, focus: { tabStop: false }, matchedBy: ['cursor-pointer'] }] } };
  const records = [snapshot, axe, many];
  const link = precheckContextFromRecords(records, { evidenceId: 'ev-0002', nodeId: `${doc}:a` });
  assert.deepEqual(link.ancestors.map(a => a.tag), ['li', 'ul', 'body']); assert.equal(link.ancestorsComplete, true);
  assert.equal(link.parent.tag, 'li'); assert.deepEqual(rules(precheckNode('2.5.8', link)), ['target-size-exception']);
  // An axe-bound target borrows descendants from the untruncated capture of the same state.
  const rail = precheckContextFromRecords(records, { evidenceId: 'ev-0002', nodeId: `${doc}:rail` });
  assert.deepEqual(rail.descendantTags, []); assert.deepEqual(rules(precheckNode('4.1.2', rail)), ['not-a-ui-component']);
  const icon = precheckContextFromRecords(records, { evidenceId: 'ev-0001', nodeId: `${doc}:icon` });
  assert.deepEqual(icon.descendantTags, ['img']); assert.deepEqual(icon.ax.matchedBy, ['cursor-pointer']); assert.deepEqual(precheckNode('4.1.2', icon), []);
  // A different state has no complete capture: descendants unknown, so the empty rule abstains.
  const later = { ...axe, evidenceId: 'ev-0004', after: { ...state, stateId: 's2' } };
  const unknown = precheckContextFromRecords([snapshot, later], { evidenceId: 'ev-0004', nodeId: `${doc}:rail` });
  assert.equal(unknown.descendantTags, null); assert.deepEqual(precheckNode('4.1.2', unknown), []);
  // A truncated capture never proves emptiness.
  const truncated = { ...snapshot, result: { ...snapshot.result, truncation: { omittedVisibleElements: 3 } } };
  assert.equal(precheckContextFromRecords([truncated], { evidenceId: 'ev-0001', nodeId: `${doc}:rail` }).descendantTags, null);
  // Inspect records carry their own outer HTML and complete ancestor chain.
  const inspect = { evidenceId: 'ev-0005', action: 'inspect', success: true, after: state, result: { element: { ...n('wrap', 'b', 'div'),
    outerHTML: '<div id="wrap"><div id="inner">  </div></div>', outerHTMLTruncated: false, ancestorSemantics: { complete: true, ancestors: [body, { tag: 'html', attributes: {} }] } } } };
  const wrap = precheckContextFromRecords([inspect], { evidenceId: 'ev-0005', nodeId: `${doc}:wrap` });
  assert.deepEqual(wrap.descendantTags, ['div']); assert.equal(wrap.ancestorsComplete, true);
  assert.equal(precheckContextFromRecords(records, { evidenceId: 'ev-0009', nodeId: 'x' }), null);
  // Proposal level: unknown targets are counted, notes are bounded and advisory.
  const finding = (id, sc, nodeId, evidenceId = 'ev-0001') => ({ id, criterionId: sc, target: { evidenceId, nodeId: `${doc}:${nodeId}` } });
  const result = precheckProposal({ findings: [finding('F1', '4.1.2', 'rail'), finding('F2', '2.5.8', 'a'), finding('F3', '4.1.2', 'icon'), finding('F4', '4.1.2', 'gone', 'ev-0009')] }, records);
  assert.equal(result.advisory, true); assert.equal(result.checkedFindings, 4); assert.equal(result.findingsWithNotes, 2); assert.equal(result.targetsUnavailable, 1);
  assert.deepEqual(result.notes.map(note => [note.findingId, note.rule]), [['F1', 'not-a-ui-component'], ['F2', 'target-size-exception']]);
  const many_ = precheckProposal({ findings: Array.from({ length: 60 }, (_, i) => finding(`R${i}`, '4.1.2', 'rail')) }, records);
  assert.ok(many_.notes.length <= 20 && Buffer.byteLength(JSON.stringify(many_.notes)) <= 8000); assert.equal(many_.notes.length + many_.omittedNotes, 60);
});

// Session-rule fixtures: one document, positional selectors, records in order.
const DOC = 'doc-k', URL_ = 'http://x/';
const at = (id, parent, tag, extra = {}) => ({ nodeId: `${DOC}:${id}`, documentId: DOC, parentNodeId: parent ? `${DOC}:${parent}` : null, tag, attributes: {}, text: '',
  selector: `html:nth-of-type(1) > body:nth-of-type(1) > ${id}`, ...extra });
const bodyNode = { ...at('body', null, 'body'), selector: 'html:nth-of-type(1) > body:nth-of-type(1)' };
const state = (active, extra = {}) => ({ documentId: DOC, stateId: 's1', url: URL_, active, ...extra });
const snap = (evidenceId, nodes, extra = {}) => ({ evidenceId, action: 'snapshot', success: true, before: state(bodyNode), after: state(bodyNode), result: { nodes }, ...extra });
const press = (evidenceId, key, before, after) => ({ evidenceId, action: 'press', arguments: { key }, success: true, before: state(before), after: state(after), result: { key } });
const sessionRules = (finding, records) => rules(precheckSession(finding, records));

test('no-keyboard-evidence: 2.1.1 targets that no recorded navigation press focused are noted', () => {
  const tool = at('tool', 'body', 'div', { attributes: { class: 'tool', title: 'Flip' } }), button = at('save', 'body', 'button', { text: 'Save' });
  const finding = { id: 'K1', criterionId: '2.1.1', target: { evidenceId: 'ev-0001', nodeId: tool.nodeId } };
  const records = [snap('ev-0001', [bodyNode, tool, button]), press('ev-0002', 'Tab', bodyNode, button), press('ev-0003', 'Tab', button, bodyNode), press('ev-0004', 'p', bodyNode, bodyNode)];
  const notes = precheckSession(finding, records);
  assert.deepEqual(rules(notes), ['no-keyboard-evidence']); assert.equal(notes[0].basis.navigationPresses, 2);
  assert.match(notes[0].message, /No keyboard interaction with this target was recorded/); assert.match(notes[0].message, /Enter\/Space/);
  // No presses at all is also no keyboard evidence; other criteria are not keyboard claims.
  assert.equal(precheckSession(finding, records.slice(0, 1))[0].basis.navigationPresses, 0);
  for (const sc of ['4.1.2', '2.4.7', '2.4.3', '1.4.3']) assert.deepEqual(sessionRules({ ...finding, criterionId: sc }, records), [], sc);
  // Shift+Tab, Enter, Space, Escape and arrows count; a shortcut letter does not.
  for (const key of ['Shift+Tab', 'Enter', 'Space', ' ', 'Escape', 'ArrowDown']) assert.equal(precheckSession(finding, [records[0], press('ev-0002', key, bodyNode, bodyNode)])[0].basis.navigationPresses, 1, key);
});

test('no-keyboard-evidence abstains when focus reached the target, a node inside it, a close ancestor, or press focus data is missing', () => {
  const toolbar = at('bar', 'body', 'ul'), item = at('bar > li', 'bar', 'li', { attributes: { tabindex: '0' } }), icon = at('bar > li > svg', 'bar > li', 'svg');
  const base = snap('ev-0001', [bodyNode, toolbar, item, icon]);
  const finding = nodeId => ({ id: 'K', criterionId: '2.1.1', target: { evidenceId: 'ev-0001', nodeId } });
  // Target focused (after, or before an Enter press), focus inside the target, or target inside a focused element.
  assert.deepEqual(sessionRules(finding(item.nodeId), [base, press('ev-0002', 'Tab', bodyNode, item)]), []);
  assert.deepEqual(sessionRules(finding(item.nodeId), [base, press('ev-0002', 'Enter', item, item)]), []);
  assert.deepEqual(sessionRules(finding(toolbar.nodeId), [base, press('ev-0002', 'Tab', bodyNode, item)]), []);
  assert.deepEqual(sessionRules(finding(icon.nodeId), [base, press('ev-0002', 'Tab', bodyNode, item)]), []);
  // <body> focus is not focus on its descendants.
  assert.deepEqual(sessionRules(finding(icon.nodeId), [base, press('ev-0002', 'Tab', item, bodyNode)]), []);
  assert.deepEqual(sessionRules(finding(icon.nodeId), [base, press('ev-0002', 'Escape', bodyNode, bodyNode)]), ['no-keyboard-evidence']);
  // The same element after a reload of the same URL (new document, same recorded path) counts; another URL does not.
  const reloaded = { ...item, nodeId: 'doc-r:bar > li', documentId: 'doc-r', parentNodeId: 'doc-r:bar' };
  const reload = (url) => ({ ...press('ev-0002', 'Tab', bodyNode, reloaded), after: { ...state(reloaded), documentId: 'doc-r', url } });
  assert.deepEqual(sessionRules(finding(item.nodeId), [base, reload(URL_)]), []);
  assert.deepEqual(sessionRules(finding(item.nodeId), [base, reload('http://x/other')]), ['no-keyboard-evidence']);
  // A navigation press without recorded focus: abstain rather than guess.
  const blind = press('ev-0002', 'Tab', bodyNode, bodyNode); delete blind.after.active;
  assert.deepEqual(sessionRules(finding(icon.nodeId), [base, blind]), []);
  // Failed presses are ignored.
  assert.deepEqual(sessionRules(finding(icon.nodeId), [base, { ...press('ev-0002', 'Tab', bodyNode, icon), success: false }]), ['no-keyboard-evidence']);
});

test('name-present-now: missing-name claims whose target later shows a name source are noted', () => {
  const button = at('add', 'body', 'button', { attributes: { class: 'icon-plus' } });
  const named = { ...button, attributes: { class: 'icon-plus', title: '<div>Create a layer</div>' } };
  const claim = { id: 'N1', criterionId: '4.1.2', title: 'Layer buttons have no accessible name', observation: 'Icon-only buttons.', target: { evidenceId: 'ev-0001', nodeId: button.nodeId } };
  const notes = precheckSession(claim, [snap('ev-0001', [bodyNode, button]), snap('ev-0002', [bodyNode, named])]);
  assert.deepEqual(rules(notes), ['name-present-now']);
  assert.deepEqual(notes[0].basis, { evidenceId: 'ev-0002', source: 'title', value: 'Create a layer' }); assert.match(notes[0].message, /title "Create a layer"/);
  // axe name rules are missing-name claims from the finding's own fields; 2.4.4 and 1.1.1 count too.
  const axe = { id: 'axe:ev-0001:button-name:0:4.1.2', criterionId: '4.1.2', title: 'Buttons must have discernible text', axeCandidateId: 'ev-0001:button-name:0', target: claim.target };
  const later = (attributes, extra = {}) => [snap('ev-0001', [bodyNode, button]), snap('ev-0002', [bodyNode, { ...button, attributes, ...extra }])];
  assert.deepEqual(sessionRules(axe, later({ 'aria-label': 'Add layer' })), ['name-present-now']);
  assert.deepEqual(sessionRules({ ...claim, criterionId: '2.4.4', title: 'Link is unnamed' }, later({ 'aria-label': 'Docs' })), ['name-present-now']);
  assert.deepEqual(sessionRules({ ...claim, criterionId: '1.1.1', title: 'Image has no alt text' }, [snap('ev-0001', [bodyNode, { ...button, tag: 'img' }]), snap('ev-0002', [bodyNode, { ...button, tag: 'img', attributes: { alt: 'Chart' } }])]), ['name-present-now']);
  // Text content names a button; labelled-by text resolves; an AX row name counts.
  assert.equal(precheckSession(claim, later({}, { text: 'Add' }))[0].basis.source, 'text content');
  const label = at('lbl', 'body', 'span', { attributes: { id: 'lbl' }, text: 'Add layer' });
  assert.equal(precheckSession(claim, [snap('ev-0001', [bodyNode, button, label]), snap('ev-0002', [bodyNode, { ...button, attributes: { 'aria-labelledby': 'lbl' } }, label])])[0].basis.source, 'aria-labelledby');
  const many = { evidenceId: 'ev-0002', action: 'inspect_many', success: true, after: state(bodyNode), result: { nodes: [button], elements: [{ nodeId: button.nodeId, ax: { available: true, role: 'button', name: 'Add layer' } }] } };
  assert.deepEqual(precheckSession(claim, [snap('ev-0001', [bodyNode, button]), many])[0].basis, { evidenceId: 'ev-0002', source: 'AX name', value: 'Add layer' });
});

test('name-present-now abstains without a later observation, on non-name claims, and on sources that are not exposed', () => {
  const button = at('add', 'body', 'button');
  const titled = { ...button, attributes: { title: 'Create a layer' } };
  const claim = { id: 'N', criterionId: '4.1.2', title: 'Button has an empty accessible name', target: { evidenceId: 'ev-0002', nodeId: button.nodeId } };
  // The latest observation is the cited target itself (or earlier): nothing recorded later.
  assert.deepEqual(sessionRules(claim, [snap('ev-0001', [bodyNode, titled]), snap('ev-0002', [bodyNode, titled])]), []);
  const records = [snap('ev-0001', [bodyNode]), snap('ev-0002', [bodyNode, button]), snap('ev-0003', [bodyNode, titled])];
  assert.deepEqual(sessionRules(claim, records), ['name-present-now']);
  // Claims about role or state, other criteria, and unknown targets get no note.
  assert.deepEqual(sessionRules({ ...claim, title: 'Button exposes the wrong role', observation: 'role is generic' }, records), []);
  assert.deepEqual(sessionRules({ ...claim, criterionId: '1.4.3' }, records), []);
  assert.deepEqual(sessionRules({ ...claim, target: { evidenceId: 'ev-0009', nodeId: button.nodeId } }, records), []);
  // Only the latest observation counts: a title removed later is not a name now.
  assert.deepEqual(sessionRules(claim, [...records, snap('ev-0004', [bodyNode, { ...button, attributes: { 'data-original-title': 'Create a layer' } }]),
    { evidenceId: 'ev-0005', action: 'inspect_many', success: true, after: state(bodyNode), result: { elements: [{ nodeId: button.nodeId, ax: { available: true, role: 'button', name: '' } }] } }]), []);
  // Tooltip attributes count only while no AX row records an empty name; icon-font glyph names are empty.
  const tooltip = [snap('ev-0001', [bodyNode]), snap('ev-0002', [bodyNode, button]), snap('ev-0003', [bodyNode, { ...button, attributes: { 'data-original-title': 'Create a layer' } }])];
  assert.equal(precheckSession(claim, tooltip)[0].basis.source, 'data-original-title');
  const glyph = { evidenceId: 'ev-0004', action: 'inspect_many', success: true, after: state(bodyNode), result: { elements: [{ nodeId: button.nodeId, ax: { available: true, role: 'button', name: '' } }] } };
  assert.deepEqual(sessionRules(claim, [...tooltip, glyph]), []);
  // Generic elements do not take their name from text content.
  assert.deepEqual(sessionRules(claim, [snap('ev-0001', []), snap('ev-0002', [bodyNode, { ...button, tag: 'div' }]), snap('ev-0003', [bodyNode, { ...button, tag: 'div', text: 'Close' }])]), []);
});

test('precheckProposal adds session notes next to node notes, within the same bounds', () => {
  const tool = at('tool', 'body', 'div', { attributes: { title: 'Flip' } }), button = at('add', 'body', 'button');
  const records = [snap('ev-0001', [bodyNode, tool, button]), press('ev-0002', 'Tab', bodyNode, bodyNode), snap('ev-0003', [bodyNode, tool, { ...button, attributes: { title: 'Add' } }])];
  const result = precheckProposal({ findings: [
    { id: 'K', criterionId: '2.1.1', target: { evidenceId: 'ev-0001', nodeId: tool.nodeId } },
    { id: 'N', criterionId: '4.1.2', title: 'Add button is unnamed', target: { evidenceId: 'ev-0001', nodeId: button.nodeId } },
    { id: 'G', criterionId: '2.1.1', target: { evidenceId: 'ev-0009', nodeId: 'gone' } },
  ] }, records);
  assert.deepEqual(result.notes.map(note => [note.findingId, note.criterionId, note.rule]), [['K', '2.1.1', 'no-keyboard-evidence'], ['N', '4.1.2', 'name-present-now']]);
  assert.equal(result.findingsWithNotes, 2); assert.equal(result.targetsUnavailable, 1);
});

test('agent checkpoint and submit ACKs return advisory precheck notes without changing the findings', async t => {
  const page = '<!doctype html><html lang="en"><head><title>Precheck</title></head><body><main><div id="rail" class="rail"></div><button id="named">Save</button></main></body></html>';
  const site = await fixture(t, page), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  assert.equal((await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] })).success, true);
  const snapshot = JSON.parse(await fs.readFile(path.join(agent.directory, 'ev-0001.json')));
  const node = id => snapshot.result.nodes.find(row => row.attributes?.id === id).nodeId;
  const finding = (id, nodeId) => ({ id, title: `Claim ${id}`, criterionId: '4.1.2', target: { evidenceId: 'ev-0001', nodeId }, evidenceIds: ['ev-0001'],
    observation: 'Observed node.', reason: 'Draft reason.', applicability: 'Draft applicability.', exceptions: 'None recorded.', scope: 'This node.' });
  const proposal = { auditor: { name: 'Precheck test' }, findings: [finding('F-rail', node('rail')), finding('F-button', node('named'))] };
  const draft = await agent.request({ tool: 'checkpoint', proposal });
  assert.equal(draft.success, true, JSON.stringify(draft)); assert.equal(draft.checkpoint.findings, 2);
  assert.equal(draft.precheck.advisory, true); assert.equal(draft.precheck.checkedFindings, 2);
  assert.deepEqual(draft.precheck.notes.map(note => [note.findingId, note.rule]), [['F-rail', 'not-a-ui-component']]);
  const submitted = await agent.request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  assert.deepEqual(submitted.precheck.notes.map(note => note.findingId), ['F-rail']);
  const stored = JSON.parse(await fs.readFile(submitted.proposalReportPath));
  assert.deepEqual(stored.findings.map(row => row.id), ['F-rail', 'F-button']);
  assert.equal((await agent.close()).status, 'submitted');
});

test('agent checkpoint ACK carries no-keyboard-evidence and name-present-now notes from the real session records', async t => {
  const page = '<!doctype html><html lang="en"><head><title>Session rules</title></head><body><main><div id="tool" class="tool" style="cursor:pointer">Flip</div>' +
    '<button id="add" class="icon" title="Create a layer"></button></main></body></html>';
  const site = await fixture(t, page), agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  t.after(() => agent.close());
  const step = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'press', key: 'Tab' }, { action: 'snapshot' }] });
  assert.equal(step.success, true, JSON.stringify(step));
  const snapshot = JSON.parse(await fs.readFile(path.join(agent.directory, 'ev-0001.json')));
  const node = id => snapshot.result.nodes.find(row => row.attributes?.id === id).nodeId;
  const finding = (id, criterionId, nodeId, title) => ({ id, title, criterionId, target: { evidenceId: 'ev-0001', nodeId }, evidenceIds: ['ev-0001'],
    observation: 'Observed node.', reason: 'Draft reason.', applicability: 'Draft applicability.', exceptions: 'None recorded.', scope: 'This node.' });
  const proposal = { auditor: { name: 'Precheck test' }, findings: [finding('F-tool', '2.1.1', node('tool'), 'Flip tool is not keyboard operable'),
    finding('F-add', '4.1.2', node('add'), 'Add button has no accessible name')] };
  const draft = await agent.request({ tool: 'checkpoint', proposal });
  assert.equal(draft.success, true, JSON.stringify(draft));
  assert.deepEqual(draft.precheck.notes.map(note => [note.findingId, note.rule]), [['F-tool', 'no-keyboard-evidence'], ['F-add', 'name-present-now']]);
  assert.equal(draft.precheck.notes[1].basis.source, 'title'); assert.equal(draft.precheck.notes[1].basis.evidenceId, 'ev-0003');
  assert.equal(draft.checkpoint.findings, 2);
  await agent.close();
});
