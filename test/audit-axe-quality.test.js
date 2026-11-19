import test from 'node:test';
import assert from 'node:assert/strict';
import { openAuditAgent } from '../src/audit/agent.js';
import { AuditBrowser } from '../src/audit/browser.js';
import { deriveAxeCandidates } from '../src/audit/axe-candidates.js';
import { parseAuditManifest, resolveAuditStandard } from '../src/audit/schema.js';
import { MCP_TEXT_LIMIT } from '../src/audit/projection.js';
import { fixture } from './helpers.js';

const page = body => `<!doctype html><html lang="en"><head><title>Axe quality</title></head><body><main><h1>Axe quality</h1>${body}</main></body></html>`;
const size = value => Buffer.byteLength(JSON.stringify(value));

async function start(t, html, options = {}) {
  let agent;
  t.after(() => agent?.close());
  const site = await fixture(t, html);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, options);
  return { agent, site };
}

async function capture(t, html) {
  const site = await fixture(t, html);
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: site.projectRoot, url: site.url }), { handleSignals: false });
  t.after(() => browser.close());
  await browser.start();
  const record = await browser.execute({ action: 'axe' });
  assert.equal(record.success, true, JSON.stringify(record.error));
  return { browser, site, record, candidates: deriveAxeCandidates({ ...record, action: 'axe', evidenceId: 'ev-0001' }, resolveAuditStandard()) };
}

// 120 unnamed buttons dominate; four other rule types follow them in axe's alphabetical order.
const dominant = page(`${Array.from({ length: 120 }, (_, i) => `<button class="tool" data-i="${i}"></button>`).join('')}
<img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" id="photo">
<a href="/somewhere" id="empty-link"></a>
<select id="color"><option>Red</option></select>
<p id="faint" style="color:#aaa;background:#fff">Faint text</p>`);

test('rule-first paging: page 1 lists every violated rule and one representative each, even when one rule has 120 nodes', async t => {
  const { agent } = await start(t, dominant, { textLimit: MCP_TEXT_LIMIT });
  const step = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'axe' }] });
  assert.equal(step.success, true, JSON.stringify(step));
  assert.ok(size(step) <= MCP_TEXT_LIMIT, 'the 20,000-character cap holds');
  const [first] = step.axe;
  const ids = first.rules.map(rule => rule.ruleId);
  for (const id of ['button-name', 'image-alt', 'link-name', 'select-name', 'color-contrast']) assert.ok(ids.includes(id), `${id} missing from ${ids}`);
  const dominantRule = first.rules.find(rule => rule.ruleId === 'button-name');
  assert.equal(dominantRule.nodes, 120);
  for (const rule of first.rules) {
    assert.ok(rule.impact && rule.criterionIds.length && rule.help && rule.firstCandidateId, JSON.stringify(rule));
    assert.ok(first.candidates.some(row => row.candidateId === rule.firstCandidateId), `representative of ${rule.ruleId} is not on page 1`);
  }
  // Order: the representatives (one per rule) come before any second node of any rule.
  const head = first.candidates.slice(0, first.rules.length).map(row => row.ruleId);
  assert.equal(new Set(head).size, first.rules.length, `representatives first, got ${head}`);
  assert.equal(first.candidates.filter(row => row.ruleId === 'button-name').length > 1, true, 'remaining nodes follow the representatives');
  assert.ok(first.counts.candidates > first.candidates.length);
  // Paging is cursor-only; every page carries a copy-pasteable next request, and the union is exactly the candidate set.
  const seen = [...first.candidates];
  for (let page = first; page.pagination.nextRequest;) {
    assert.deepEqual(page.pagination.nextRequest.options.cursor, page.pagination.next.cursor);
    assert.equal(page.pagination.nextRequest.tool, 'read');
    const read = await agent.request(page.pagination.nextRequest);
    assert.equal(read.success, true, JSON.stringify(read));
    assert.equal(read.rules, undefined, 'the rule list is page-1 only');
    seen.push(...read.candidates); page = read;
  }
  assert.equal(seen.length, first.counts.candidates);
  assert.equal(new Set(seen.map(row => row.candidateId)).size, seen.length);
});

test('an unsupported paging option names the exact cursor call to use, bounded, without echoing input or skipping candidates', async t => {
  const { agent } = await start(t, dominant, { textLimit: MCP_TEXT_LIMIT });
  const step = await agent.request({ tool: 'step', actions: [{ action: 'axe' }] });
  const [first] = step.axe;
  assert.ok(first.pagination.nextRequest && first.candidates.length < first.counts.candidates);
  // `offset` is not a thing: the error names the page-1 read, whose response carries the next cursor call.
  const offset = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe', offset: first.candidates.length } });
  assert.equal(offset.success, false);
  assert.equal(offset.error.code, 'INVALID_AUDIT_READ_OPTIONS');
  assert.match(offset.error.message, /pages by cursor only/);
  assert.match(offset.error.message, /does not support offset/);
  const named = { tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe' } };
  assert.ok(offset.error.message.includes(JSON.stringify(named)), offset.error.message);
  assert.ok(offset.error.message.length < 1000);
  // Following the guidance and then each nextRequest reaches every candidate the step did not deliver.
  const seen = new Set(first.candidates.map(row => row.candidateId));
  for (let page = await agent.request(named); ; page = await agent.request(page.pagination.nextRequest)) {
    assert.equal(page.success, true, JSON.stringify(page));
    for (const row of page.candidates) seen.add(row.candidateId);
    if (!page.pagination.nextRequest) break;
  }
  assert.equal(seen.size, first.counts.candidates);
  // With a valid cursor the named call reads the page at that cursor, not the one after it.
  const second = await agent.request(first.pagination.nextRequest);
  const again = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe', cursor: first.pagination.next.cursor, nodeIds: ['n1'] } });
  assert.ok(again.error.message.includes(JSON.stringify({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe', cursor: first.pagination.next.cursor } })), again.error.message);
  assert.equal(second.success, true);
  // An invalid cursor is never echoed, with or without an unsupported option.
  const bad = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe', cursor: 'HOSTILE_CURSOR_SENTINEL' } });
  assert.equal(bad.error.code, 'INVALID_AUDIT_CURSOR');
  assert.match(bad.error.message, /pagination\.nextRequest/);
  assert.equal(bad.error.message.includes('HOSTILE_CURSOR_SENTINEL'), false);
  const badOffset = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe', cursor: 'HOSTILE_CURSOR_SENTINEL', offset: 3 } });
  assert.equal(badOffset.error.code, 'INVALID_AUDIT_READ_OPTIONS');
  assert.equal(badOffset.error.message.includes('HOSTILE_CURSOR_SENTINEL'), false);
  assert.ok(badOffset.error.message.includes(JSON.stringify(named)));
  // base64url decoding ignores trailing junk: a non-canonical cursor is invalid and is not echoed either.
  const padded = first.pagination.next.cursor + '!'.repeat(8000);
  assert.equal((await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe', cursor: padded } })).error.code, 'INVALID_AUDIT_CURSOR');
  const paddedOffset = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe', cursor: padded, offset: 1 } });
  assert.equal(paddedOffset.error.code, 'INVALID_AUDIT_READ_OPTIONS');
  assert.equal(paddedOffset.error.message.includes('!!!'), false);
  assert.ok(paddedOffset.error.message.includes(JSON.stringify(named)));
  // Unknown keys are rejected by the strict request schema without being echoed.
  const hostile = await agent.request({ tool: 'read', evidenceId: 'ev-0001', options: { view: 'axe', HOSTILE_KEY_SENTINEL: 1 } });
  assert.equal(hostile.success, false);
  assert.equal(JSON.stringify(hostile).includes('HOSTILE_KEY_SENTINEL'), false);
});

const selectors = page(`<button id="save_922" data-testid="save-order"></button>
<select id="gender_922" name="gender"><option>x</option></select>
<div id="toolbar"><button id="ui-id-1"></button><button id="ui-id-2"></button></div>
<img class="css-1x2y3z sc-abc123 hero" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" id="hero_77">
<a id="a_1" href="/same"></a><a id="a_2" href="/same"></a>
<ul class="todo-list"><li><input type="checkbox" class="toggle"></li><li><input type="checkbox" class="toggle"></li></ul>`);

test('draft selectors are checked unique, avoid generated ids/classes, and keep the axe target as fallback', async t => {
  const { browser, candidates } = await capture(t, selectors);
  const byTarget = target => candidates.find(row => row.target[0] === target)?.draftFinding;
  const uniqueCount = css => browser.page.evaluate(selector => document.querySelectorAll(selector).length, css);
  for (const row of candidates.filter(row => row.adoptable)) {
    assert.equal(await uniqueCount(row.draftFinding.selector), 1, `${row.draftFinding.selector} must match exactly one element`);
    assert.ok(['high', 'medium', 'low'].includes(row.draftFinding.selectorConfidence));
    assert.equal(row.draftFinding.axeTarget, row.target.join(' >> '));
  }
  // A data-* attribute beats a generated id (`_\d+$`).
  assert.deepEqual([byTarget('#save_922').selector, byTarget('#save_922').selectorConfidence], ['button[data-testid="save-order"]', 'high']);
  // Use the unique name attribute for the selector while retaining the original axe target.
  assert.deepEqual([byTarget('#gender_922').selector, byTarget('#gender_922').selectorConfidence], ['select[name="gender"]', 'high']);
  assert.equal(byTarget('#gender_922').axeTarget, '#gender_922');
  // Generated classes (css-*, sc-*) are not used; the semantic class is, at medium confidence.
  assert.deepEqual([byTarget('#hero_77').selector, byTarget('#hero_77').selectorConfidence], ['img.hero', 'medium']);
  // Two identical unnamed buttons with generated ids: a path from the stable ancestor, flagged low.
  const toolbar = ['#ui-id-1', '#ui-id-2'].map(target => byTarget(target));
  assert.deepEqual(toolbar.map(draft => draft.selector), ['#toolbar > button:nth-of-type(1)', '#toolbar > button:nth-of-type(2)']);
  assert.deepEqual(toolbar.map(draft => draft.selectorConfidence), ['low', 'low']);
  // Repeated items whose axe target is already clean (classes, nth-child): keep it rather than swap in a worse positional path.
  const toggles = candidates.filter(row => row.ruleId === 'label').map(row => row.draftFinding);
  assert.equal(toggles.length, 2);
  for (const draft of toggles) assert.deepEqual([draft.selector, draft.selectorConfidence], [draft.axeTarget, 'low']);
  // Nothing stable at all: the axe target stays, flagged low (it was unique when bound).
  const bare = byTarget('#a_1');
  assert.deepEqual([bare.selector, bare.selectorConfidence, bare.axeTarget], ['#a_1', 'low', '#a_1']);
  for (const { draftFinding: draft } of candidates.filter(row => row.draftFinding.selectorConfidence !== 'low')) assert.equal(/_\d+|ui-id-\d|css-|sc-abc/.test(draft.selector), false, draft.selector);
});

test('draft claims state axe\'s own check data and the page URL, and nothing else', async t => {
  const { site, record, candidates } = await capture(t, page(`<p id="faint" style="color:#aaa;background:#fff;font-size:14px">Faint text</p><button id="plain" type="submit"></button><img id="spaced" alt=" " aria-label="Portrait" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">`));
  const contrast = candidates.find(row => row.ruleId === 'color-contrast');
  const rule = record.result.axe.violations.find(rule => rule.id === 'color-contrast');
  const data = rule.nodes[0].any.find(check => check.id === 'color-contrast').data;
  const { draftFinding } = contrast;
  assert.equal(draftFinding.pageUrl, site.url);
  assert.equal(draftFinding.pageUrl, record.after.url);
  assert.ok(draftFinding.claim.startsWith(`text ${data.fgColor} on ${data.bgColor}, ${data.contrastRatio}:1, needs ${data.expectedContrastRatio}`), draftFinding.claim);
  assert.ok(draftFinding.claim.includes(data.fontSize) && draftFinding.claim.includes(data.fontWeight), draftFinding.claim);
  assert.match(draftFinding.claim, /^text #aaaaaa on #ffffff, 2\.\d+:1, needs 4\.5:1 \(.*14px.*normal\)/);
  assert.match(draftFinding.claim, /\(axe color-contrast, serious\)$/);
  const named = candidates.find(row => row.ruleId === 'button-name').draftFinding;
  assert.equal(named.claim, 'button has no accessible name [button[type="submit"]] (axe button-name, critical)');
  assert.equal(named.pageUrl, site.url);
  assert.equal(named.selector, '#plain');
  // A name rule that failed for another reason (alt=" " with an aria-label) must not claim the name is missing.
  const spaced = candidates.find(row => row.target[0] === '#spaced')?.draftFinding;
  assert.ok(spaced, 'alt-space image violation expected');
  assert.equal(/no accessible name/.test(spaced.claim), false, spaced.claim);
  for (const row of candidates) assert.equal(/<|>|HTML omitted|Faint text/.test(row.draftFinding.claim), false, row.draftFinding.claim);
});

test('axe pages either advance or give actionable overflow, including first-row envelope', async () => {
  const { pageAxeCandidates } = await import('../src/audit/axe-candidates.js');
  const record = { evidenceId: 'ev-0001', action: 'axe', success: true, result: { axeNodeBindings: { rows: [] }, axe: { violations: [{ id: 'button-name', tags: ['wcag412'], impact: 'critical', help: 'Buttons must have names', nodes: Array.from({ length: 8 }, (_, i) => ({ target: ['#button' + i], failureSummary: 'Name missing' })) }] } } };
  assert.throws(() => pageAxeCandidates(record, resolveAuditStandard(), { maxBytes: 2048 }), error => error.code === 'AUDIT_AXE_PAGE_TOO_LARGE' && /field/.test(error.message));
  const seen = []; let cursor;
  do {
    const page = pageAxeCandidates(record, resolveAuditStandard(), { maxBytes: 5000, limit: 2, cursor });
    assert.ok(page.candidates.length); seen.push(...page.candidates.map(row => row.candidateId)); cursor = page.pagination.next?.cursor;
  } while (cursor);
  assert.equal(seen.length, 8); assert.equal(new Set(seen).size, 8);
});

test('optional axe preview overflow keeps successful step and readable original', async t => {
  const originalExecute = AuditBrowser.prototype.execute;
  t.mock.method(AuditBrowser.prototype, 'execute', async function (...args) {
    const result = await originalExecute.apply(this, args);
    if (args[0].action === 'axe') for (const rule of result.result.axe.violations) {
      rule.help = 'Long help '.repeat(40); rule.helpUrl = 'https://example.invalid/' + 'a'.repeat(300);
      for (const node of rule.nodes) node.target = ['#' + 'b'.repeat(300)];
    }
    return result;
  });
  const { agent } = await start(t, page('<button></button>'), { textLimit: 10000 });
  const step = await agent.request({ tool: 'step', actions: [{ action: 'axe' }] });
  assert.equal(step.success, true, JSON.stringify(step));
  assert.equal(step.records[0].success, true); assert.equal(step.axe, undefined);
  const read = await agent.request({ tool: 'read', evidenceId: step.records[0].evidenceId, options: { view: 'field', field: '/result/axe' } });
  assert.equal(read.success, true);
  await agent.close();
});
