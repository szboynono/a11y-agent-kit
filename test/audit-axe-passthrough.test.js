import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { openAuditAgent } from '../src/audit/agent.js';
import { deriveAxeCandidates, expandAxeAdoption, pageAxeCandidates } from '../src/audit/axe-candidates.js';
import { resolveAuditStandard } from '../src/audit/schema.js';
import { checkAudit, reviewAudit, validateAuditProposalRecords } from '../src/audit/review.js';
import { AUDIT_TEXT_LIMIT } from '../src/audit/projection.js';
import { fixture } from './helpers.js';

const page = body => `<!doctype html><html lang="en"><head><title>Axe passthrough</title></head><body><main><h1>Axe passthrough</h1>${body}</main></body></html>`;
const size = value => Buffer.byteLength(JSON.stringify(value));
const SENTINEL = 'PASSWORD_VALUE_SENTINEL_7731';
// One bound violation set, a visual-criterion violation, an `incomplete` result and an unbound (framed) violation.
const mixed = page(`<button id="one"></button><button id="two"></button>
<p id="faint" style="color:#aaa;background:#fff">Faint text on a white background</p>
<div id="over-image" style="background-image:linear-gradient(#fff,#000);color:#888">Text over a gradient</div>
<input id="secret" type="password" value="${SENTINEL}" aria-label="Secret">
<iframe srcdoc="&lt;!doctype html&gt;&lt;html lang=en&gt;&lt;title&gt;f&lt;/title&gt;&lt;button id=framed&gt;&lt;/button&gt;"></iframe>`);

async function start(t, html) {
  let agent;
  t.after(() => agent?.close()); // registered before the fixture so it runs before the project directory is removed
  const site = await fixture(t, html);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url });
  return agent;
}
async function scan(agent) {
  const step = await agent.request({ tool: 'step', actions: [{ action: 'axe' }] });
  assert.equal(step.success, true, JSON.stringify(step));
  return step;
}
const original = (agent, id) => fs.readFile(path.join(agent.directory, `${id}.json`), 'utf8').then(JSON.parse);
const author = { name: 'Axe passthrough maker' };
const decision = findingId => ({ findingId, verdict: 'supported', reason: 'Axe observation reviewed against the retained node.',
  checks: { evidenceSupport: 'supported', criterionMapping: 'supported', scope: 'supported', prerequisites: 'supported' } });

test('an axe step returns bounded redacted violation candidates bound to the recorded node', async t => {
  const agent = await start(t, mixed), step = await scan(agent);
  assert.ok(size(step) <= AUDIT_TEXT_LIMIT);
  const [block] = step.axe, raw = await original(agent, 'ev-0001');
  assert.equal(block.evidenceId, 'ev-0001');
  const violations = raw.result.axe.violations.flatMap(rule => rule.nodes.map(() => rule.id));
  assert.equal(block.counts.candidates, violations.length);
  assert.ok(raw.result.axe.incomplete.length > 0, 'fixture must produce an incomplete result');
  const button = block.candidates.find(row => row.ruleId === 'button-name' && row.target[0] === '#one');
  assert.match(button.candidateId, /^ev-0001:button-name:\d+$/);
  assert.deepEqual(button.criterionIds, ['4.1.2']);
  assert.equal(button.impact, 'critical'); assert.match(button.helpUrl, /^https:\/\/dequeuniversity\.com\//);
  assert.ok(button.help); assert.equal(button.adoptable, true);
  const bound = raw.result.axeNodeBindings.rows.find(row => row.ruleId === 'button-name' && row.target[0] === '#one');
  assert.equal(button.nodeId, bound.nodeId); assert.equal(button.documentId, raw.after.documentId); assert.equal(button.stateId, raw.after.stateId);
  assert.ok(raw.result.nodes.some(node => node.nodeId === button.nodeId));
  assert.ok(block.candidates.every(row => row.rawPointer.startsWith('/result/axe/violations/')));
  // Incomplete rules are never candidates.
  const incompleteIds = new Set(raw.result.axe.incomplete.map(rule => rule.id));
  for (const id of incompleteIds) if (!raw.result.axe.violations.some(rule => rule.id === id)) assert.equal(block.candidates.some(row => row.ruleId === id), false);
  // Unbound (framed) targets are listed but cannot be adopted.
  const framed = block.candidates.find(row => row.target.length > 1);
  assert.equal(framed?.adoptable, false); assert.match(framed.notAdoptableReason, /^unbound:/); assert.equal(framed.nodeId, null);
  // The visual criterion is flagged, not hidden.
  assert.deepEqual(block.candidates.find(row => row.ruleId === 'color-contrast')?.visualEvidenceRequired, ['1.4.3']);
  // Redaction: no input value, raw HTML or axe check payloads in the candidates.
  const text = JSON.stringify(step.axe);
  for (const forbidden of [SENTINEL, '<button', 'failureSummary', 'HTML omitted']) assert.equal(text.includes(forbidden), false, forbidden);
});

// See docs/test-coverage.md for the omitted upstream-fixture cases.
test('axe pagination stays within the byte budget for many candidates', async t => {
  const many = await start(t, page(Array.from({ length: 400 }, (_, i) => `<button id="b${i}"></button>`).join('')));
  const big = await scan(many), [overflow] = big.axe;
  assert.ok(size(big) <= AUDIT_TEXT_LIMIT, 'step response must stay inside the text limit');
  const total = overflow.counts.candidates;
  assert.ok(total >= 400); assert.ok(overflow.candidates.length < total);
  assert.equal(overflow.pagination.complete, false); assert.ok(overflow.pagination.next.cursor);
  // The byte budget also bounds a page that is under its row limit.
  const squeezed = pageAxeCandidates(await original(many, 'ev-0001'), resolveAuditStandard(), { limit: 200, maxBytes: 4000 });
  assert.ok(squeezed.candidates.length > 0 && squeezed.candidates.length < 200); assert.ok(size(squeezed) <= 4000);
  assert.equal(squeezed.pagination.next.cursor.length > 0, true);
  const seen = [...overflow.candidates];
  for (let next = overflow.pagination.next; next;) {
    const read = await many.request({ tool: 'read', evidenceId: 'ev-0001', options: { ...next, limit: 200 } });
    assert.equal(read.success, true); assert.ok(size(read) <= AUDIT_TEXT_LIMIT);
    seen.push(...read.candidates); next = read.pagination.next;
  }
  assert.equal(seen.length, total); assert.equal(new Set(seen.map(row => row.candidateId)).size, total);
});

test('adopting all or some candidates saves a valid axe-sourced draft that submits and reviews', async t => {
  const agent = await start(t, mixed), step = await scan(agent), [block] = step.axe;
  const raw = await original(agent, 'ev-0001');
  const adoptable = block.candidates.filter(row => row.adoptable);
  const buttons = adoptable.filter(row => row.ruleId === 'button-name');
  assert.ok(buttons.length >= 2);

  const some = await agent.request({ tool: 'checkpoint', proposal: { auditor: author, adoptAxe: [buttons[0].candidateId] } });
  assert.equal(some.success, true, JSON.stringify(some));
  assert.equal(some.adoption.candidatesAdopted, 1); assert.equal(some.checkpoint.findings, 1);

  const all = await agent.request({ tool: 'checkpoint', proposal: { auditor: author, adoptAxe: 'all' } });
  assert.equal(all.success, true, JSON.stringify(all));
  const expected = adoptable.reduce((sum, row) => sum + row.criterionIds.length, 0);
  assert.equal(all.checkpoint.findings, expected); assert.equal(all.adoption.findingsAdded, expected);
  assert.equal(all.adoption.notAdoptable, block.counts.notAdoptable); assert.ok(all.adoption.notAdoptable > 0);
  assert.ok(size(all) <= AUDIT_TEXT_LIMIT);

  const enriched = JSON.parse(await fs.readFile(all.checkpoint.checkpointPath, 'utf8')).proposal;
  const button = enriched.findings.find(row => row.axeCandidateId === buttons[0].candidateId);
  const inspected = await agent.request({ tool: 'step', actions: [{ action: 'inspect', selector: raw.result.nodes.find(node => node.nodeId === button.target.nodeId).selector }] });
  assert.equal(inspected.success, true, JSON.stringify(inspected));
  const inspectId = inspected.records[0].evidenceId;
  button.evidenceIds.push(inspectId);
  const saved = await agent.request({ tool: 'checkpoint', proposal: enriched });
  assert.equal(saved.success, true, JSON.stringify(saved));
  const submitted = await agent.request({ tool: 'submit', checkpointDigest: saved.checkpoint.checkpointDigest });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  const proposal = JSON.parse(await fs.readFile(submitted.proposalReportPath, 'utf8'));
  assert.equal((await checkAudit(proposal.reportPath)).status, 'current');
  assert.equal(proposal.findings.length, expected);
  const finding = proposal.findings.find(row => row.axeCandidateId === buttons[0].candidateId);
  assert.equal(finding.source, 'axe'); assert.equal(finding.method, 'dom'); assert.equal(finding.criterionId, '4.1.2');
  assert.deepEqual(finding.target, { evidenceId: 'ev-0001', nodeId: buttons[0].nodeId }); assert.deepEqual(finding.evidenceIds, ['ev-0001', inspectId]);
  assert.equal(Object.hasOwn(proposal, 'adoptAxe'), false);
  assert.ok(proposal.findings.every(row => row.source === 'axe' && raw.result.nodes.some(node => node.nodeId === row.target.nodeId)));

  // A cited original button can pass; the visual 1.4.3 finding still needs PNG evidence.
  const reviewed = await reviewAudit(proposal.reportPath, { reviewer: { name: 'Independent axe reviewer', independentOfAuditor: true },
    decisions: proposal.findings.map(row => ({ ...decision(row.id), ...(row.id === finding.id ? {
      directEvidence: { evidenceId: inspectId, nodeIds: [row.target.nodeId],
        criterionClause: '4.1.2 requires a programmatically determinable name for a user interface component.',
        explanation: 'The retained native button has no content or explicit naming attributes; this fixture cites the original node.' },
    } : {}) })) });
  const byId = new Map([...reviewed.confirmedFindings, ...reviewed.verificationQueue].map(row => [row.id, row]));
  assert.equal(reviewed.confirmedFindings.find(row => row.id === finding.id)?.evidenceGate.status, 'supported');
  const contrast = proposal.findings.find(row => row.criterionId === '1.4.3');
  assert.ok(contrast, 'contrast violation is adoptable');
  assert.equal(reviewed.confirmedFindings.some(row => row.id === contrast.id), false);
  assert.equal(byId.get(contrast.id).evidenceGate.status, 'insufficient');
  assert.ok(byId.get(contrast.id).missingEvidence.some(message => /PNG/.test(message)));
});

test('incomplete, unknown, unbound and forged axe adoption is refused', async t => {
  const agent = await start(t, mixed), step = await scan(agent), [block] = step.axe, raw = await original(agent, 'ev-0001');
  const framed = block.candidates.find(row => !row.adoptable), good = block.candidates.find(row => row.adoptable);
  const incomplete = raw.result.axe.incomplete[0];
  for (const adoptAxe of [[`ev-0001:${incomplete.id}:0`], ['ev-0001:nope:0'], [framed.candidateId], [], 'some', [good.candidateId, good.candidateId]]) {
    const refused = await agent.request({ tool: 'checkpoint', proposal: { auditor: author, adoptAxe } });
    assert.equal(refused.success, false); assert.equal(refused.error.code, 'INVALID_AXE_ADOPTION', JSON.stringify(refused.error));
  }
  assert.equal((await agent.request({ tool: 'checkpoint', proposal: { auditor: author, adoptAxe: [] } })).delivery.checkpoint, 'none');
  // "all" never reaches incomplete candidates.
  const all = await agent.request({ tool: 'checkpoint', proposal: { auditor: author, adoptAxe: 'all' } });
  assert.equal(all.success, true);
  assert.equal(all.adoption.candidatesAdopted, block.counts.adoptable);
  // A hand-written source:"axe" finding must match a retained violation on that node and criterion.
  const forge = patch => ({ auditor: author, findings: [{ ...expandAxeAdoption({ auditor: author, adoptAxe: [good.candidateId] }, [raw], resolveAuditStandard()).proposal.findings[0], ...patch }] });
  for (const patch of [{ criterionId: '1.1.1' }, { axeCandidateId: 'ev-0001:image-alt:0' }, { source: undefined }, { axeCandidateId: undefined }, { target: { evidenceId: 'ev-0001', nodeId: 'other' } }]) {
    const result = await agent.request({ tool: 'checkpoint', proposal: forge(patch) });
    assert.equal(result.success, false, JSON.stringify(patch));
  }
  assert.equal((await agent.request({ tool: 'checkpoint', proposal: forge({}) })).success, true);
});

test('criteria follow the selected WCAG catalog and the proposal schema stays strict', () => {
  const rule = (id, tags) => ({ id, tags, impact: 'serious', help: id, helpUrl: `https://example.test/${id}`, nodes: [{ target: ['#a'], impact: 'serious', html: 'x' }] });
  const record = { evidenceId: 'ev-0001', action: 'axe', success: true, before: { stateId: 's', documentId: 'd' }, after: { stateId: 's', documentId: 'd' },
    result: { axe: { violations: [rule('size', ['wcag2aa', 'wcag258', 'wcag22aa']), rule('contrast', ['wcag2aa', 'wcag143']), rule('reflow', ['wcag1410'])], incomplete: [rule('maybe', ['wcag412'])] },
      nodes: [{ nodeId: 'n', documentId: 'd', selector: '#a' }],
      axeNodeBindings: { stable: true, capturedStateId: 's', capturedDocumentId: 'd', rows: ['size', 'contrast', 'reflow'].map(id => ({ disposition: 'violations', ruleId: id, ruleNodeIndex: 0, target: ['#a'], status: 'bound', nodeId: 'n', documentId: 'd', selector: '#a' })) } } };
  const ids = standard => deriveAxeCandidates(record, resolveAuditStandard(standard)).map(row => `${row.ruleId}=${row.criterionIds.join('+')}`);
  assert.deepEqual(ids({ version: '2.2', targetLevel: 'AA' }), ['size=2.5.8', 'contrast=1.4.3', 'reflow=1.4.10']);
  assert.deepEqual(ids({ version: '2.1', targetLevel: 'AA' }), ['size=', 'contrast=1.4.3', 'reflow=1.4.10']);
  assert.deepEqual(ids({ version: '2.1', targetLevel: 'A' }), ['size=', 'contrast=', 'reflow=']);
  const nested = structuredClone(record); nested.result.axe.violations[0].nodes[0].target = [['iframe', 'x'.repeat(45000)]];
  assert.ok(size(deriveAxeCandidates(nested, resolveAuditStandard())[0]) < 2000, 'nested shadow/frame targets are clipped');
  assert.equal(deriveAxeCandidates({ ...record, success: false }, resolveAuditStandard()).length, 0);
  assert.throws(() => validateAuditProposalRecords({ auditor: author, findings: [], extra: true }, [record]), /validation failed/);
});

test('every open-session response carries a next hint through axe, adoption, exploration and finalization', async t => {
  const agent = await start(t, mixed);
  const snapshot = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  assert.match(snapshot.next, /axe/);
  const scanned = await scan(agent);
  assert.match(scanned.next, /checkpoint .*adoptAxe:'all'/);
  const adopted = await agent.request({ tool: 'checkpoint', proposal: { auditor: author, adoptAxe: 'all' } });
  assert.equal(adopted.success, true, JSON.stringify(adopted));
  assert.match(adopted.next, /Budget: \d+ calls, \d+ actions, \d+ seconds total, \d+ seconds exploration remaining; plenty left/);
  assert.match(adopted.next, /keyboard\/focus.*names in context.*non-text contrast/);
  const explored = await agent.request({ tool: 'step', actions: [{ action: 'press', key: 'Tab' }, { action: 'inspect', selector: '#one' }, { action: 'screenshot' }] });
  assert.equal(explored.success, true, JSON.stringify(explored));
  assert.match(explored.next, /has not been axe-scanned/);
  await scan(agent);
  assert.ok(size(explored) <= AUDIT_TEXT_LIMIT);
  const replaced = await agent.request({ tool: 'checkpoint', proposal: { auditor: author, findings: [] } });
  assert.match(replaced.next, /Next: checkpoint new axe candidates as findings/);
  assert.match(replaced.next, /retain the complete saved proposal and adopt only new candidate IDs/);
  assert.match(replaced.next, /\d+ candidate\(s\) may need banking/);
  const submitted = await agent.request({ tool: 'submit', proposal: { auditor: author, adoptAxe: 'all' } });
  assert.equal(submitted.success, true, JSON.stringify(submitted));
  assert.equal(Object.hasOwn(submitted, 'next'), false);
});

test('the next hint skips adoption when axe has nothing adoptable and nudges adoption of newly found candidates', async t => {
  const agent = await start(t, page('<p>All good here.</p>'));
  const clean = await scan(agent);
  assert.equal(clean.axe[0].counts.adoptable, 0);
  assert.match(clean.next, /axe has nothing to adopt here/); assert.doesNotMatch(clean.next, /Next: checkpoint/);
  const fresh = await start(t, mixed);
  await scan(fresh);
  assert.match((await fresh.request({ tool: 'checkpoint', proposal: { auditor: author, adoptAxe: 'all' } })).next, /plenty left/);
  const again = await fresh.request({ tool: 'step', actions: [{ action: 'axe' }] });
  assert.match(again.next, /Next: checkpoint new axe candidates as findings/);
  assert.match(again.next, /retain the complete saved proposal and adopt only new candidate IDs/);
  assert.match(again.next, /\d+ candidate\(s\) may need banking/);
});

test('the next hint switches to finalization when few calls remain', async t => {
  let agent;
  t.after(() => agent?.close());
  const site = await fixture(t, mixed);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, maxToolCalls: 5 });
  assert.match((await agent.request({ tool: 'step', actions: [{ action: 'axe' }] })).next, /checkpoint/);
  const last = await agent.request({ tool: 'checkpoint', proposal: { auditor: author, adoptAxe: 'all' } });
  assert.match(last.next, /Budget: 3 calls.*finalize now/);
  assert.equal(last.budget.remainingToolCalls, 3);
});

test('the next hint finalizes when the action allowance is spent', async t => {
  let agent;
  t.after(() => agent?.close());
  const site = await fixture(t, mixed);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url, maxActions: 1 });
  assert.match((await agent.request({ tool: 'step', actions: [{ action: 'axe' }] })).next, /finalize now/);
});
