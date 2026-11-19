import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveCoverage, suggestNext, budgetAdvisory, SUGGEST_BELOW, ADVISE_BELOW } from '../src/audit/coverage.js';

const doc = 'doc-1';
let sequence = 0;
const state = (extra = {}) => ({ documentId: doc, url: 'http://site.test/', stateId: 's-a', viewport: { width: 1280, height: 800 }, ...extra });
const rec = (action, fields = {}) => ({ evidenceId: `ev-${String(++sequence).padStart(4, '0')}`, action, success: true, arguments: {}, after: state(), result: {}, ...fields });
const node = (nodeId, tag, attributes = {}, extra = {}) => ({ nodeId, documentId: doc, tag, attributes, tabIndex: -1, ...extra });
const base = { elapsedMs: 30_000, wallMs: 600_000, toolCalls: 5, maxToolCalls: 60, inScopeViewports: [{ width: 1280, height: 800 }], viewed: new Set(), findings: null, catalogSize: 55 };
const derive = (records, extra = {}) => deriveCoverage({ ...base, records, ...extra });
const snapshot = (count, after) => rec('snapshot', { ...(after ? { after } : {}), result: { nodes: [node('n-0', 'body'),
  ...Array.from({ length: count }, (_, index) => node(`n-${index + 1}`, 'button', {}, { tabIndex: 0 }))] } });

test('used fractions come from wall time and attempted calls, capped at 1', () => {
  const { coverage } = derive([], { elapsedMs: 150_000, toolCalls: 6 });
  assert.deepEqual(coverage.used, { time: 0.25, calls: 0.1 });
  assert.deepEqual(derive([], { elapsedMs: 700_000, toolCalls: 70 }).coverage.used, { time: 1, calls: 1 });
  assert.equal(coverage.advisory, true);
});

test('keyboard traversal needs two successful global Tab presses', () => {
  assert.deepEqual(derive([]).coverage.keyboard, { tabPresses: 0, traversal: false });
  const one = [rec('press', { arguments: { key: 'Tab' }, result: { key: 'Tab' } }), rec('press', { success: false, arguments: { key: 'Tab' } }), rec('press', { arguments: { key: 'Enter' }, result: { key: 'Enter' } })];
  const result = derive(one);
  assert.deepEqual(result.coverage.keyboard, { tabPresses: 1, traversal: false });
  assert.match(result.gaps[0].next, /only 1 Tab press/);
  const two = derive([...one, rec('press', { arguments: { key: 'Shift+Tab' }, result: { key: 'Shift+Tab' } })]);
  assert.deepEqual(two.coverage.keyboard, { tabPresses: 2, traversal: true });
  assert.ok(!two.gaps.some(gap => /Tab through/.test(gap.next)));
});

test('viewports compare successful screenshot captures with in-scope sizes; undeclared sizes are never suggested', () => {
  const shot = rec('screenshot', { png: { path: '/x.png' } });
  const failed = rec('screenshot', { success: false, png: { path: '/y.png' }, after: state({ viewport: { width: 390, height: 844 } }) });
  const declared = derive([shot, failed], { inScopeViewports: [{ width: 1280, height: 800 }, { width: 390, height: 844 }] });
  assert.deepEqual(declared.coverage.viewports, { inScope: ['1280x800', '390x844'], captured: ['1280x800'] });
  assert.match(declared.gaps.find(gap => gap.short === '390x844 screenshot').next, /^Capture 390x844 \(in scope, not captured\)/);
  const undeclared = derive([shot]);
  assert.deepEqual(undeclared.coverage.viewports, { inScope: ['1280x800'], captured: ['1280x800'] });
  assert.ok(!undeclared.gaps.some(gap => /screenshot$/.test(gap.short) && !/unviewed/.test(gap.short)));
  // A viewport change without a PNG is not a capture.
  const resized = derive([rec('viewport', { after: state({ viewport: { width: 390, height: 844 } }) })], { inScopeViewports: [{ width: 390, height: 844 }] });
  assert.deepEqual(resized.coverage.viewports.captured, []);
});

test('screenshots count successful PNG records and view requests', () => {
  const shots = [rec('screenshot', { png: {} }), rec('contrast', { png: {} })];
  const result = derive(shots, { viewed: new Set([shots[0].evidenceId]) });
  assert.deepEqual(result.coverage.screenshots, { captured: 2, viewed: 1 });
  assert.match(result.gaps.find(gap => /unviewed/.test(gap.short)).next, /View 1 captured screenshot/);
  assert.ok(!derive(shots, { viewed: new Set(shots.map(row => row.evidenceId)) }).gaps.some(gap => /unviewed/.test(gap.short)));
});

test('interactive elements seen vs examined individually; abstains without node-bearing records', () => {
  const none = derive([rec('press', { arguments: { key: 'Escape' }, result: { key: 'Escape' } })]);
  assert.equal(none.coverage.interactive, undefined);
  assert.ok(none.coverage.abstained.includes('interactive'));
  const snap = snapshot(12);
  const inspectOne = rec('inspect', { result: { element: node('n-1', 'button', {}, { tabIndex: 0 }) } });
  const clickTwo = rec('click', { result: { target: node('n-2', 'button', {}, { tabIndex: 0 }) } });
  const result = derive([snap, inspectOne, clickTwo]);
  assert.deepEqual(result.coverage.interactive, { seen: 12, examined: 2 });
  assert.match(result.gaps.find(gap => /interactive/.test(gap.short)).next, /^12 interactive elements seen, 2 examined individually/);
  // Keyboard focus counts as examining the focused element; inspect_many rows count as seen, not examined.
  const many = rec('inspect_many', { result: { nodes: [], elements: [{ nodeId: 'n-20', documentId: doc }, { nodeId: 'n-21', documentId: doc }] } });
  const focus = rec('press', { arguments: { key: 'Tab' }, result: { key: 'Tab' }, after: state({ active: { nodeId: 'n-20', documentId: doc } }) });
  assert.deepEqual(derive([many, focus]).coverage.interactive, { seen: 2, examined: 1 });
  // Half or more examined: no interactive suggestion.
  const half = derive([snapshot(2), inspectOne]);
  assert.ok(!half.gaps.some(gap => /interactive/.test(gap.short)));
  // Non-interactive nodes are not counted.
  assert.deepEqual(derive([rec('snapshot', { result: { nodes: [node('n-1', 'div'), node('n-2', 'p')] } })]).coverage.interactive, { seen: 0, examined: 0 });
});

test('axe candidates count adoptable rows once per node/rule, minus those adopted or cited; abstains without axe', () => {
  assert.ok(derive([snapshot(1)]).coverage.abstained.includes('axe'));
  const failedAxe = rec('axe', { success: false });
  assert.ok(derive([failedAxe], { candidatesFor: () => [] }).coverage.abstained.includes('axe'));
  const first = rec('axe'), second = rec('axe');
  const rows = record => [
    { candidateId: `${record.evidenceId}:image-alt:0`, ruleId: 'image-alt', nodeId: 'n-5', criterionIds: ['1.1.1'], adoptable: true },
    { candidateId: `${record.evidenceId}:label:0`, ruleId: 'label', nodeId: 'n-6', criterionIds: ['1.3.1', '4.1.2'], adoptable: true },
    { candidateId: `${record.evidenceId}:region:0`, ruleId: 'region', nodeId: null, criterionIds: [], adoptable: false },
  ];
  const fresh = derive([first, second], { candidatesFor: rows });
  assert.deepEqual(fresh.coverage.axe, { adoptable: 2, unaddressed: 2 });
  assert.match(fresh.gaps.find(gap => /axe/.test(gap.short)).next, /^2 adoptable axe candidate/);
  const adopted = [{ id: 'axe:1', criterionId: '1.1.1', axeCandidateId: `${second.evidenceId}:image-alt:0`, target: { evidenceId: second.evidenceId, nodeId: 'n-5' }, evidenceIds: [second.evidenceId] }];
  assert.deepEqual(derive([first, second], { candidatesFor: rows, findings: adopted }).coverage.axe, { adoptable: 2, unaddressed: 1 });
  const inspect = rec('inspect', { result: { element: node('n-6', 'input') } });
  const cited = [{ id: 'F1', criterionId: '4.1.2', target: { evidenceId: inspect.evidenceId, nodeId: 'n-6' }, evidenceIds: [inspect.evidenceId] }];
  assert.deepEqual(derive([first, second, inspect], { candidatesFor: rows, findings: [...adopted, ...cited] }).coverage.axe, { adoptable: 2, unaddressed: 0 });
});

test('criteria cited come from the latest draft; abstains when there is no draft', () => {
  assert.ok(derive([]).coverage.abstained.includes('criteria'));
  const findings = [{ criterionId: '1.1.1', evidenceIds: ['ev-0001'] }, { criterionId: '1.1.1', evidenceIds: ['ev-0002'] }, { criterionId: '2.4.7', target: { evidenceId: 'ev-0003' } }, { criterionId: '1.4.3', evidenceIds: [] }];
  assert.deepEqual(derive([], { findings }).coverage.criteria, { cited: 2, catalog: 55 });
  assert.deepEqual(derive([], { findings: [] }).coverage.criteria, { cited: 0, catalog: 55 });
});

test('states and URLs count successful after-states; abstains with none', () => {
  assert.ok(derive([rec('snapshot', { success: false, after: null })]).coverage.abstained.includes('states'));
  const single = derive([rec('snapshot')]);
  assert.equal(single.coverage.states, 1); assert.equal(single.coverage.urls, 1);
  assert.ok(single.gaps.some(gap => gap.short === 'other page states'));
  const many = derive([rec('snapshot'), rec('click', { after: state({ stateId: 's-b' }) }), rec('navigate', { after: state({ stateId: 's-c', url: 'http://site.test/two' }) })]);
  assert.equal(many.coverage.states, 3); assert.equal(many.coverage.urls, 2);
  assert.ok(!many.gaps.some(gap => gap.short === 'other page states'));
});

test('suggestedNext lists at most three actions only while both fractions are under half and the session is open', () => {
  const records = [snapshot(12), rec('screenshot', { png: {} })];
  const inScopeViewports = [{ width: 1280, height: 800 }, { width: 390, height: 844 }];
  const early = derive(records, { inScopeViewports });
  assert.ok(early.gaps.length > 3);
  const next = suggestNext(early.coverage, early.gaps);
  assert.equal(next.length, 3);
  assert.match(next[0], /^Tab through the page/); assert.match(next[1], /^Capture 390x844/);
  assert.equal(SUGGEST_BELOW, 0.5);
  const atHalfTime = derive(records, { inScopeViewports, elapsedMs: 300_000 });
  assert.equal(suggestNext(atHalfTime.coverage, atHalfTime.gaps), null);
  const atHalfCalls = derive(records, { inScopeViewports, toolCalls: 30 });
  assert.equal(suggestNext(atHalfCalls.coverage, atHalfCalls.gaps), null);
  const justUnder = derive(records, { inScopeViewports, elapsedMs: 294_000, toolCalls: 29 });
  assert.equal(suggestNext(justUnder.coverage, justUnder.gaps).length, 3);
  assert.equal(suggestNext(early.coverage, early.gaps, { open: false }), null);
  assert.equal(suggestNext(early.coverage, []), null);
});

test('budget advisory appears only under a quarter used and only when checks are missing', () => {
  const records = [snapshot(12)];
  const early = derive(records, { inScopeViewports: [{ width: 1280, height: 800 }, { width: 390, height: 844 }], elapsedMs: 60_000, toolCalls: 6 });
  const line = budgetAdvisory(early.coverage, early.gaps);
  assert.match(line, /^Advisory only \(findings unchanged\): 90% of the wall time and call budget remains, and these checks were not done: keyboard Tab traversal; 1280x800 screenshot; 390x844 screenshot; 12 of 12 interactive elements not examined; other page states\.$/);
  assert.equal(ADVISE_BELOW, 0.25);
  const quarter = derive(records, { elapsedMs: 150_000 });
  assert.equal(budgetAdvisory(quarter.coverage, quarter.gaps), null);
  const quarterCalls = derive(records, { toolCalls: 15 });
  assert.equal(budgetAdvisory(quarterCalls.coverage, quarterCalls.gaps), null);
  assert.equal(budgetAdvisory(early.coverage, []), null);
});

test('the coverage block stays small and is deterministic', () => {
  const records = [snapshot(40), rec('screenshot', { png: {} }), rec('axe')];
  const input = { inScopeViewports: [{ width: 1280, height: 800 }, { width: 390, height: 844 }], findings: [], candidatesFor: () => [] };
  const one = derive(records, input), two = derive(records, { ...input, cache: new Map() });
  assert.deepEqual(one.coverage, two.coverage);
  assert.ok(Buffer.byteLength(JSON.stringify(one.coverage)) < 400, JSON.stringify(one.coverage));
  assert.ok(Buffer.byteLength(JSON.stringify(suggestNext(one.coverage, one.gaps))) < 600);
});

test('agent responses carry coverage, suggestedNext and an early checkpoint advisory without changing outcomes', async t => {
  const { openAuditAgent } = await import('../src/audit/agent.js');
  const { fixture } = await import('./helpers.js');
  const site = await fixture(t, '<!doctype html><html lang="en"><head><title>Coverage</title></head><body><main><button id="a">One</button><button id="b">Two</button><a href="#x">Three</a></main></body></html>');
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, viewport: { width: 1280, height: 800 }, viewports: [{ width: 390, height: 844 }] });
  t.after(() => agent.close());
  const step = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'screenshot' }] });
  assert.equal(step.success, true, JSON.stringify(step));
  assert.deepEqual(step.coverage.viewports, { inScope: ['1280x800', '390x844'], captured: ['1280x800'] });
  assert.deepEqual(step.coverage.keyboard, { tabPresses: 0, traversal: false });
  assert.deepEqual(step.coverage.interactive, { seen: 3, examined: 0 });
  assert.deepEqual(step.coverage.screenshots, { captured: 1, viewed: 0 });
  assert.deepEqual(step.coverage.abstained, ['axe', 'criteria']);
  assert.ok(step.suggestedNext.length <= 3);
  assert.match(step.suggestedNext[0], /^Tab through the page/); assert.match(step.suggestedNext[1], /^Capture 390x844/);
  assert.equal((await agent.request({ tool: 'view', evidenceId: 'ev-0002' })).coverage.screenshots.viewed, 1);
  const tabs = await agent.request({ tool: 'step', actions: [{ action: 'press', key: 'Tab' }, { action: 'press', key: 'Tab' }] });
  assert.deepEqual(tabs.coverage.keyboard, { tabPresses: 2, traversal: true });
  assert.equal(tabs.coverage.interactive.examined, 2);
  const draft = await agent.request({ tool: 'checkpoint', proposal: { auditor: { name: 'Coverage test' }, findings: [] } });
  assert.equal(draft.success, true, JSON.stringify(draft));
  assert.deepEqual(draft.coverage.criteria, { cited: 0, catalog: draft.coverage.criteria.catalog });
  assert.ok(draft.coverage.criteria.catalog > 0);
  assert.match(draft.budgetAdvisory, /^Advisory only \(findings unchanged\): \d+% of the wall time and call budget remains, and these checks were not done: 390x844 screenshot/);
  assert.ok(draft.precheck && !('budgetAdvisory' in draft.precheck));
  assert.equal(draft.checkpoint.findings, 0);
  const failed = await agent.request({ tool: 'checkpoint', proposal: { bogus: true } });
  assert.equal(failed.success, false); assert.equal(failed.budgetAdvisory, undefined);
  const submitted = await agent.request({ tool: 'submit', checkpointDigest: draft.checkpoint.checkpointDigest });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  assert.equal(submitted.sealed, true);
  assert.equal(submitted.checkpointDigest, draft.checkpoint.checkpointDigest);
  assert.match(submitted.reportDigest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(submitted.delivery, { checkpoint: 'saved', submission: 'submitted' });
  assert.equal(submitted.next, undefined);
  assert.equal(submitted.suggestedNext, undefined);
  assert.deepEqual(submitted.coverage.viewports, draft.coverage.viewports);
  assert.match(submitted.budgetAdvisory, /% of the wall time and call budget remains/);
  const closed = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  assert.equal(closed.error?.code, 'AUDIT_AGENT_CLOSED');
  await agent.close();
});

test('viewports is agent-only configuration: it is validated and never reaches strict collection parsing', async t => {
  const { openAuditAgent } = await import('../src/audit/agent.js');
  const { fixture } = await import('./helpers.js');
  const site = await fixture(t, '<!doctype html><title>x</title><p>x</p>');
  await assert.rejects(openAuditAgent({ projectRoot: site.projectRoot, url: site.url, viewports: [{ width: 0, height: 10 }] }), /validation failed/);
  let seen;
  const { openAuditSession } = await import('../src/audit/live.js');
  const agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, viewports: [{ width: 390, height: 844 }] }, { openAuditSession: manifest => { seen = manifest; return openAuditSession(manifest); } });
  t.after(() => agent.close());
  assert.equal(Object.hasOwn(seen, 'viewports'), false);
  await agent.close();
});
