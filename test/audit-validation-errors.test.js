import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { auditAgentRequestSchema } from '../src/audit/agent.js';
import { MCP_TEXT_LIMIT } from '../src/audit/projection.js';
import { boundErrorIssues, errorPayload, zodIssueDetails, proposalFindingHint, DRAFT_FINDING_FIELDS, EXPECTED_FINDING, ERROR_ISSUE_LIMIT } from '../src/audit/error-details.js';
import { fixture, unwrapEnvelopedText } from './helpers.js';

async function host(t) {
  const site = await fixture(t, '<!doctype html><html lang="en"><title>Audit</title><main><button id="unnamed"></button><button id="other"></button></main></html>');
  const transport = mcpTransport({ command: process.execPath, args: ['src/cli.js', 'serve'], stderr: 'pipe' });
  const client = new Client({ name: 'audit-validation-test', version: '1' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(transport, { mode: 'auto' });
  const call = async (name, args) => {
    const response = await client.callTool({ name, arguments: args });
    assert.ok(Buffer.byteLength(response.content[0].text) <= MCP_TEXT_LIMIT);
    assert.deepEqual(unwrapEnvelopedText(response), response.structuredContent);
    return response.structuredContent;
  };
  const start = await call('a11y_audit_start', { manifest: { projectRoot: site.projectRoot, url: site.url } });
  assert.equal(start.success, true, JSON.stringify(start));
  return { client, start, request: request => call('a11y_audit_request', { runId: start.runId, request }) };
}

test('a checkpoint with draftFinding-shaped findings returns field-level issues and an expectedFinding over MCP', async t => {
  const h = await host(t);
  const candidates = h.start.startup.axe[0].candidates.filter(row => row.adoptable && row.ruleId === 'button-name');
  assert.ok(candidates.length >= 2, JSON.stringify(h.start.startup.axe[0].counts));
  // The shape a real host sent (evidence cell-12-attempt2): draftFinding fields, no id/target/observation/... .
  const [first, second] = candidates.map(row => row.draftFinding);
  assert.deepEqual(Object.keys(first).filter(key => !['criterionId', 'title', 'evidenceIds'].includes(key)).sort(), [...DRAFT_FINDING_FIELDS].sort());
  const bad = { auditor: { name: 'host' }, adoptAxe: 'all', findings: [
    { ...first, title: 'Icon-only button has no accessible name' },
    { source: 'manual', method: 'dom', ...second, target: { evidenceId: second.evidenceIds[0], nodeId: second.nodeId }, hostPrivateNote: 'x' },
  ] };
  for (let attempt = 0; attempt < 2; attempt++) {
    const failed = await h.request({ tool: 'checkpoint', proposal: bad });
    assert.equal(failed.success, false);
    assert.equal(failed.error.code, 'INVALID_AUDIT_PROPOSAL');
    assert.equal(failed.delivery.checkpoint, 'none');
    const { issues } = failed.error;
    assert.equal(issues.length, ERROR_ISSUE_LIMIT);
    assert.ok(failed.error.issuesOmitted > 0, JSON.stringify(failed.error));
    for (const issue of issues) { assert.ok(issue.path.length <= 120 && issue.message.length <= 200, JSON.stringify(issue)); }
    const at = path => issues.find(issue => issue.path === path);
    for (const field of ['id', 'observation', 'reason', 'applicability', 'exceptions', 'scope']) assert.ok(at(`findings.0.${field}`), field);
    assert.match(at('findings.0.target').message, /expected object/);
    assert.match(at('findings.0').message, /^Unsupported field\(s\): pageUrl, selector, selectorConfidence, axeTarget, stableSelector, stableSelectorConfidence, claim, nodeId\.$/);
    assert.deepEqual(failed.error.expectedFinding, EXPECTED_FINDING);
    assert.match(failed.error.findingShapeNote, /^pageUrl, selector, selectorConfidence, axeTarget, stableSelector, stableSelectorConfidence, claim, nodeId are draftFinding fields \(only for a host's own findings tool\)/);
    assert.match(failed.error.findingShapeNote, /1 other unsupported field\(s\) were sent/);
    assert.match(failed.error.findingShapeNote, /target:\{evidenceId,nodeId\}, evidenceIds, observation, reason, applicability, exceptions, scope/);
    // Unknown keys outside the fixed vocabulary are counted, never echoed.
    assert.equal(JSON.stringify(failed).includes('hostPrivateNote'), false);
    assert.match(failed.next, /draftFinding entries \(pageUrl\/selector\/claim\) are only for a host's own findings\/submit tool/);
  }

  // The example validates once its placeholders are replaced with real IDs from this session; no other field changes.
  const filled = { ...EXPECTED_FINDING, target: { evidenceId: first.evidenceIds[0], nodeId: first.nodeId }, evidenceIds: [first.evidenceIds[0]] };
  const saved = await h.request({ tool: 'checkpoint', proposal: { auditor: { name: 'host' }, adoptAxe: 'all', findings: [filled] } });
  assert.equal(saved.success, true, JSON.stringify(saved));
  assert.equal(saved.checkpoint.findings, 1 + saved.adoption.findingsAdded);
});

test('protocol-level request errors carry bounded field issues', async t => {
  const h = await host(t);
  const badRead = await h.request({ tool: 'read', evidenceId: 'not-an-id' });
  assert.equal(badRead.error.code, 'INVALID_AGENT_REQUEST');
  assert.ok(badRead.error.issues.some(issue => issue.path === 'evidenceId'), JSON.stringify(badRead.error));
  assert.equal(badRead.error.expectedFinding, undefined);
  const extra = await h.request({ tool: 'checkpoint', proposal: {}, somethingElse: 1 });
  assert.equal(extra.error.code, 'INVALID_AGENT_REQUEST');
  assert.deepEqual(extra.error.issues, [{ path: 'input', message: 'Unsupported field(s): 1 other field(s).' }]);
  assert.equal(JSON.stringify(extra).includes('somethingElse'), false);
  // A non-finding proposal error still gets its issues, without the finding example.
  const auditorless = await h.request({ tool: 'checkpoint', proposal: { findings: [] } });
  assert.equal(auditorless.error.code, 'INVALID_AUDIT_PROPOSAL');
  assert.deepEqual(auditorless.error.issues.map(issue => issue.path), ['auditor']);
  assert.equal(auditorless.error.expectedFinding, undefined);
});

test('the checkpoint and submit schema descriptions name the proposal finding shape and scope draftFinding to host tools', () => {
  const descriptions = auditAgentRequestSchema.options.filter(option => ['checkpoint', 'submit'].includes(option.shape.tool.value)).map(option => option.shape.proposal.description);
  assert.equal(descriptions.length, 2);
  for (const description of descriptions) {
    assert.match(description, /proposal\.findings:\[\{id,title,criterionId,target:\{evidenceId,nodeId\},evidenceIds,observation,reason,applicability,exceptions,scope,method\?\}\]/);
    assert.match(description, /axe draftFinding\(pageUrl,selector,claim\): host's findings tool only; use adoptAxe here\./);
    assert.match(description, /Optional adoptAxe:"all"\|\[candidateId,\.\.\.\] adds axe violation candidates as source:"axe" findings\./);
    assert.match(description, /Evidence contract: read options view:'guide'\./);
  }
});

test('error issue bounding caps count and length and keeps code and message', () => {
  const details = Array.from({ length: 40 }, (_, index) => ({ path: `findings.${index}.${'x'.repeat(200)}`, message: 'm'.repeat(500) }));
  const bounded = boundErrorIssues(details);
  assert.equal(bounded.issues.length, ERROR_ISSUE_LIMIT); assert.equal(bounded.issuesOmitted, 40 - ERROR_ISSUE_LIMIT);
  for (const issue of bounded.issues) { assert.ok(issue.path.length <= 120 && issue.message.length <= 200); assert.match(issue.path, /^findings\.\d+\.\?$/); }
  assert.equal(boundErrorIssues(undefined), null); assert.equal(boundErrorIssues('text'), null); assert.equal(boundErrorIssues([{ nope: 1 }]), null);
  // Non-zod details such as error records keep their code and message.
  assert.deepEqual(boundErrorIssues([{ code: 'AUDIT_BLOB_CHANGED', message: 'Attachment differs.', stage: 'check' }]), { issues: [{ code: 'AUDIT_BLOB_CHANGED', message: 'Attachment differs.' }] });
  const plain = errorPayload(Object.assign(new Error('boom'), { code: 'X' }));
  assert.deepEqual(plain, { code: 'X', message: 'boom' });
  assert.equal(JSON.stringify(errorPayload({ code: 'INVALID_AUDIT_PROPOSAL', message: 'm', details })).length < 6000, true);
});

test('zod issue details name only known unknown keys and the hint does not invent finding text', () => {
  const details = zodIssueDetails([{ code: 'unrecognized_keys', keys: ['claim', 'pageUrl', '<script>', 'other'], path: ['findings', 0], message: 'Unrecognized keys: "claim", "pageUrl", "<script>", "other"' }]);
  assert.deepEqual(details, [{ path: 'findings.0', message: 'Unsupported field(s): claim, pageUrl, 2 other field(s).', unknownKeys: ['claim', 'pageUrl'], otherUnknownKeys: 2 }]);
  const hint = proposalFindingHint(details);
  assert.match(hint.findingShapeNote, /^pageUrl, claim are draftFinding fields/);
  assert.equal(proposalFindingHint([{ path: 'auditor', message: 'x' }]), null);
  // Placeholders only: every free-text field is an obvious <...> placeholder for the host to replace.
  for (const field of ['title', 'observation', 'reason', 'applicability', 'exceptions', 'scope']) assert.match(EXPECTED_FINDING[field], /^<.+>$/);
});
