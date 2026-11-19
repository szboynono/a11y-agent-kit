import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { digest } from '../src/evidence.js';
import { openAuditAgent, AUDIT_PLAYBOOK_TEXT, auditAgentRequestSchema } from '../src/audit/agent.js';
import { auditActionSchema } from '../src/audit/schema.js';
import { createAuditDirectory, writeAuditArtifact, readAuditDocument } from '../src/audit/store.js';
import { saveAuditCheckpoint, readAuditCheckpoint, recoverAuditCheckpoint } from '../src/audit/checkpoint.js';

// Browserless storage contract fixtures, not collected findings or semantic labels.
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aN1kAAAAASUVORK5CYII=', 'base64');
const context = { evidencePolicy: 'audit-evidence-2' };

async function fixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-checkpoint-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'index.html'), '<!doctype html><title>Checkpoint fixture</title>');
  const runId = randomUUID(), directory = await createAuditDirectory(root, runId), documentId = `doc-${randomUUID()}`;
  const node = { nodeId: `${documentId}:n000001`, documentId, selector: '#target', tag: 'button', text: '', rect: { x: 0, y: 0, width: 1, height: 1 } };
  const state = { documentId, stateId: digest({ documentId, state: 'initial' }), active: node };
  const records = [];
  async function add({ success = true, image = false } = {}) {
    const evidenceId = `ev-${String(records.length + 1).padStart(4, '0')}`;
    const record = { evidenceId, action: image ? 'screenshot' : 'snapshot', arguments: {}, success, before: state, after: state, result: { nodes: [node], longObservation: 'fixture-only-detail'.repeat(100) } };
    if (image) record.png = { ...await writeAuditArtifact(directory, `${evidenceId}.png`, png), width: 1, height: 1 };
    record.json = await writeAuditArtifact(directory, `${evidenceId}.json`, `${JSON.stringify(record)}\n`);
    records.push(record);
    return record;
  }
  const base = await add(), picture = await add({ image: true });
  const proposal = { auditor: { name: 'Fixture auditor' }, findings: [{
    id: 'F-01', title: 'A caller-authored observation', criterionId: '4.1.2',
    target: { evidenceId: base.evidenceId, nodeId: node.nodeId }, evidenceIds: [base.evidenceId, picture.evidenceId],
    observation: 'The recorded button has no name.', reason: 'The criterion mapping requires review.',
    applicability: 'This is a recorded button.', exceptions: 'No exception has been established.', scope: 'Only this recorded target.',
  }] };
  return { root, runId, directory, node, base, picture, records, proposal, context, add };
}

const save = (fixture, proposal = fixture.proposal) => saveAuditCheckpoint({ ...fixture, proposal });

async function rewrite(checkpoint, change, rehash = true) {
  const copy = structuredClone(checkpoint);
  change(copy);
  if (rehash) { delete copy.checkpointDigest; copy.checkpointDigest = digest(copy); }
  await fs.writeFile(checkpoint.checkpointPath, `${JSON.stringify(copy)}\n`);
}

test('checkpoints retain only a frozen caller draft and original identities, without sealing or changing evidence bytes', async t => {
  const f = await fixture(t), original = new Map();
  for (const record of f.records) for (const attachment of [record.json, record.png].filter(Boolean)) original.set(attachment.path, await fs.readFile(attachment.path));
  assert.equal(await recoverAuditCheckpoint(f.directory), null);
  const first = await save(f), firstBytes = await fs.readFile(first.checkpointPath);
  const secondProposal = structuredClone(f.proposal); secondProposal.findings[0].observation = 'The caller revised the observation.';
  const second = await save(f, secondProposal);
  assert.deepEqual([first.version, second.version], [1, 2]);
  assert.notEqual(first.checkpointPath, second.checkpointPath);
  assert.deepEqual(await fs.readFile(first.checkpointPath), firstBytes);
  assert.equal(second.kind, 'audit-checkpoint-1');
  assert.equal(second.status, 'draft'); assert.equal(second.reviewStatus, 'needs_review');
  assert.equal(second.sealed, false); assert.equal(second.scoreable, false);
  assert.equal(second.records, undefined); assert.equal(second.confirmedFindings, undefined);
  assert.equal(JSON.stringify(second).includes('fixture-only-detail'), false, 'large raw action results are not copied into the draft');
  assert.deepEqual(second.targets, [{ findingId: 'F-01', evidenceId: f.base.evidenceId, nodeId: f.node.nodeId, documentId: f.node.documentId, stateId: f.base.after.stateId }]);
  assert.deepEqual(await readAuditCheckpoint(first.checkpointPath), first);
  assert.deepEqual(await recoverAuditCheckpoint(f.directory, { runId: f.runId, evidencePolicy: context.evidencePolicy }), second);
  assert.throws(() => { second.proposal.findings[0].title = 'changed'; }, TypeError);
  assert.throws(() => { second.evidence[0].json.sha256 = 'changed'; }, TypeError);
  await assert.rejects(readAuditDocument(second.checkpointPath), { code: 'INVALID_AUDIT_DOCUMENT' });
  assert.equal((await fs.readdir(f.directory)).some(name => /^audit(?:-proposal|-review)?-[a-f\d-]{36}\.json$/.test(name)), false);
  for (const [file, bytes] of original) assert.deepEqual(await fs.readFile(file), bytes);
  const later = await f.add();
  assert.equal(later.evidenceId, 'ev-0003', 'saving a draft permits subsequent original observations');
  assert.equal((await save(f)).version, 3);
});

test('unknown, failed, forged and cross-run references are rejected using the strict proposal rules and actual original JSON', async t => {
  const f = await fixture(t), failed = await f.add({ success: false }), other = await fixture(t);
  const changed = change => { const value = structuredClone(f.proposal); change(value.findings[0], value); return value; };
  for (const proposal of [
    changed(finding => { finding.evidenceIds.push('ev-9999'); }),
    changed(finding => { finding.evidenceIds.push(failed.evidenceId); }),
    changed(finding => { finding.target.nodeId = other.node.nodeId; }),
    changed(finding => { finding.target.selector = '#forged'; }),
    changed(finding => { finding.method = 'screen_reader'; }),
    changed((_finding, value) => { value.findings.push(structuredClone(value.findings[0])); }),
  ]) await assert.rejects(save(f, proposal));
  await assert.rejects(saveAuditCheckpoint({ ...f, runId: other.runId }), { code: 'AUDIT_CHECKPOINT_CONTEXT_MISMATCH' });
  await assert.rejects(saveAuditCheckpoint({ ...f, records: other.records, proposal: other.proposal }), { code: 'INVALID_AUDIT_CHECKPOINT_REFERENCE' });
  const claimed = structuredClone(f.records); claimed[0].result.nodes[0].text = 'invented';
  await assert.rejects(saveAuditCheckpoint({ ...f, records: claimed }), { code: 'AUDIT_RECORD_INTEGRITY_MISMATCH' });
  const inventedHash = structuredClone(f.records); inventedHash[0].json.sha256 = '0'.repeat(64);
  await assert.rejects(saveAuditCheckpoint({ ...f, records: inventedHash }), { code: 'AUDIT_ARTIFACT_INTEGRITY_MISMATCH' });
  assert.equal(await recoverAuditCheckpoint(f.directory), null, 'failed validation publishes no draft');
});

test('original JSON or PNG changes invalidate read and recovery rather than returning a stale draft', async t => {
  for (const name of ['json', 'png']) {
    const f = await fixture(t), checkpoint = await save(f);
    const attachment = name === 'json' ? f.base.json : f.picture.png;
    await fs.appendFile(attachment.path, ' ');
    await assert.rejects(readAuditCheckpoint(checkpoint.checkpointPath), { code: 'AUDIT_ARTIFACT_INTEGRITY_MISMATCH' });
    await assert.rejects(recoverAuditCheckpoint(f.directory), { code: 'AUDIT_ARTIFACT_INTEGRITY_MISMATCH' });
  }
});

test('committed digest, target identity, fixed draft status and expected context are checked on read', async t => {
  const mutations = [
    [value => { value.proposal.findings[0].title = 'edited'; }, false, 'AUDIT_CHECKPOINT_INTEGRITY_MISMATCH'],
    [value => { value.targets[0].documentId = 'doc-other'; }, true, 'AUDIT_CHECKPOINT_REFERENCE_MISMATCH'],
    [value => { value.evidence[0].after.stateId = 'invented'; }, true, 'AUDIT_CHECKPOINT_REFERENCE_MISMATCH'],
    [value => { value.status = 'confirmed'; }, true, 'INVALID_AUDIT_CHECKPOINT'],
    [value => { value.scoreable = true; }, true, 'INVALID_AUDIT_CHECKPOINT'],
    [value => { value.sealed = true; }, true, 'INVALID_AUDIT_CHECKPOINT'],
  ];
  for (const [mutation, rehash, code] of mutations) {
    const f = await fixture(t), checkpoint = await save(f);
    await rewrite(checkpoint, mutation, rehash);
    await assert.rejects(readAuditCheckpoint(checkpoint.checkpointPath), { code });
  }
  const f = await fixture(t), checkpoint = await save(f);
  await assert.rejects(readAuditCheckpoint(checkpoint.checkpointPath, { runId: randomUUID() }), { code: 'AUDIT_CHECKPOINT_CONTEXT_MISMATCH' });
  await assert.rejects(readAuditCheckpoint(checkpoint.checkpointPath, { directory: f.root }), { code: 'AUDIT_CHECKPOINT_CONTEXT_MISMATCH' });
  await assert.rejects(saveAuditCheckpoint({ ...f, context: { evidencePolicy: context.evidencePolicy, arbitraryPath: f.root } }), { code: 'INVALID_AUDIT_CHECKPOINT_CONTEXT' });
  const old = await fixture(t); delete old.context;
  const legacy = await save(old);
  await assert.rejects(readAuditCheckpoint(legacy.checkpointPath, { evidencePolicy: context.evidencePolicy }), { code: 'AUDIT_CHECKPOINT_CONTEXT_MISMATCH' });
});

test('host attachment paths, symlinks and noncanonical directories cannot read outside original action attachments', async t => {
  const f = await fixture(t);
  for (const file of [path.join(f.root, 'index.html'), path.join(f.directory, 'unrelated.json'), path.join(f.directory, '..', 'ev-0001.json')]) {
    const records = structuredClone(f.records); records[0].json.path = file;
    await assert.rejects(saveAuditCheckpoint({ ...f, records }), { code: 'INVALID_AUDIT_CHECKPOINT_REFERENCE' });
  }
  const outside = path.join(f.root, 'outside.json');
  await fs.copyFile(f.base.json.path, outside);
  await fs.unlink(f.base.json.path); await fs.symlink(outside, f.base.json.path);
  await assert.rejects(save(f), { code: 'UNSAFE_AUDIT_PATH' });
  const link = path.join(f.root, 'run-link'); await fs.symlink(f.directory, link);
  await assert.rejects(recoverAuditCheckpoint(link), { code: 'UNSAFE_AUDIT_PATH' });
  await assert.rejects(recoverAuditCheckpoint(`${f.directory}/../${path.basename(f.directory)}`), { code: 'UNSAFE_AUDIT_PATH' });
});

test('recovery ignores unfinished temporary data but exposes invalid newest committed data', async t => {
  const f = await fixture(t);
  await save(f); const latest = await save(f);
  await fs.writeFile(path.join(f.directory, '.audit-checkpoint-interrupted.tmp'), '{"partial":');
  assert.deepEqual(await recoverAuditCheckpoint(f.directory), latest);
  await fs.writeFile(path.join(f.directory, 'audit-checkpoint-00000003.json'), '{"partial":');
  await assert.rejects(recoverAuditCheckpoint(f.directory), { code: 'INVALID_AUDIT_CHECKPOINT' });
  await assert.rejects(save(f), { code: 'INVALID_AUDIT_CHECKPOINT' });
});

test('concurrent checkpoint saves publish distinct immutable committed versions and clean their own temporary files', async t => {
  const f = await fixture(t), alternate = structuredClone(f.proposal); alternate.findings[0].title = 'Concurrent revision';
  const drafts = await Promise.all([save(f), save(f, alternate)]);
  assert.deepEqual(drafts.map(draft => draft.version).sort(), [1, 2]);
  for (const draft of drafts) assert.deepEqual(await readAuditCheckpoint(draft.checkpointPath), draft);
  assert.equal((await recoverAuditCheckpoint(f.directory)).version, 2);
  assert.equal((await fs.readdir(f.directory)).some(name => name.startsWith('.audit-checkpoint-')), false);
});

test('two acknowledged child-process writes recover the latest complete draft after SIGTERM', { timeout: 10000 }, async t => {
  const f = await fixture(t), originalJson = await fs.readFile(f.base.json.path), originalPng = await fs.readFile(f.picture.png.path);
  const payloadPath = path.join(f.root, 'child-input.json');
  await fs.writeFile(payloadPath, JSON.stringify({ runId: f.runId, directory: f.directory, records: f.records, proposal: f.proposal, context }));
  const moduleUrl = new URL('../src/audit/checkpoint.js', import.meta.url).href;
  const script = `
    import * as fs from 'node:fs/promises';
    import path from 'node:path';
    import { saveAuditCheckpoint } from ${JSON.stringify(moduleUrl)};
    const input = JSON.parse(await fs.readFile(process.argv[1], 'utf8'));
    const first = await saveAuditCheckpoint(input);
    process.stdout.write(JSON.stringify({ version: first.version, digest: first.checkpointDigest }) + '\\n');
    input.proposal.findings[0].observation = 'Second caller-authored draft before interruption.';
    const second = await saveAuditCheckpoint(input);
    await fs.writeFile(path.join(input.directory, '.audit-checkpoint-stopped.tmp'), '{"partial":');
    process.stdout.write(JSON.stringify({ version: second.version, digest: second.checkpointDigest }) + '\\n');
    setInterval(() => {}, 1000);
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, payloadPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  const acknowledgements = []; let buffer = '', stderr = '';
  child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4000); });
  child.stdout.on('data', chunk => {
    buffer += chunk;
    for (;;) {
      const newline = buffer.indexOf('\n'); if (newline < 0) break;
      acknowledgements.push(JSON.parse(buffer.slice(0, newline))); buffer = buffer.slice(newline + 1);
      if (acknowledgements.length === 2) child.kill('SIGTERM');
    }
  });
  let timer;
  const result = await Promise.race([
    new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); }),
    new Promise((_resolve, reject) => { timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`Checkpoint child did not exit: ${stderr}`)); }, 6000); }),
  ]).finally(() => clearTimeout(timer));
  assert.deepEqual(result, { code: null, signal: 'SIGTERM' }, stderr);
  assert.deepEqual(acknowledgements.map(item => item.version), [1, 2]);
  const recovered = await recoverAuditCheckpoint(f.directory);
  assert.equal(recovered.checkpointDigest, acknowledgements[1].digest);
  assert.equal(recovered.proposal.findings[0].observation, 'Second caller-authored draft before interruption.');
  assert.equal(recovered.status, 'draft'); assert.equal(recovered.scoreable, false);
  assert.deepEqual(await fs.readFile(f.base.json.path), originalJson);
  assert.deepEqual(await fs.readFile(f.picture.png.path), originalPng);
});


async function guideAgent(t, f) {
  const session = { runId: f.runId, directory: f.directory, records: f.records,
    status: 'open', finished: new Promise(() => {}),
    finish: async () => { session.status = 'sealed'; return { evidencePolicy: context.evidencePolicy }; },
    perform: async () => { throw new Error('This protocol fixture must not execute browser actions.'); } };
  const agent = await openAuditAgent({ projectRoot: f.root, url: 'http://localhost/' }, {
    openAuditSession: async () => session,
  });
  return agent;
}

test('browserless guide delivers legal readiness and contrast steps on demand with evidence and seal limits', async t => {
  let agent;
  t.after(() => agent?.close());
  const f = await fixture(t); agent = await guideAgent(t, f);
  assert.ok(AUDIT_PLAYBOOK_TEXT.split(/\s+/).length < 220);
  assert.doesNotMatch(AUDIT_PLAYBOOK_TEXT, /repeat adoptAxe|text-interior|SCREENSHOT_STATE_CHANGED/);
  assert.match(AUDIT_PLAYBOOK_TEXT, /keep all findings; enrich existing ones without adoptAxe/);
  const reply = await agent.request({ tool: 'read', options: { view: 'guide' } });
  assert.equal(reply.success, true, JSON.stringify(reply));
  assert.equal(reply.budget.requestedActions, 0);
  const { changing_page: changing, text_contrast: contrast, sealed, checkpoint } = reply.guide;
  // Parse actual examples delivered to the caller through the real request path.
  const examples = changing.match(/\{action:"wait_for"[^}]+\}/g);
  assert.equal(examples.length, 2);
  const parseExample = text => JSON.parse(text.replace(/([a-zA-Z]+):/g, '"$1":'));
  for (const example of examples) assert.equal(auditActionSchema.safeParse(parseExample(example)).success, true);
  assert.match(changing, /timeoutMs is 1–5000 \(default 3000\)/);
  assert.match(changing, /new snapshot and screenshot; check success and matching documentId\/stateId/);
  assert.match(changing, /retain the failure.*at most once within remaining budget/);
  assert.match(changing, /leave visual evidence unresolved/);
  assert.match(changing, /not automatic runtime retry/);
  assert.match(changing, /infer continuous stability/);
  const action = parseExample(contrast.match(/\{action:"contrast".*?background:\{x:20,y:10\}\}/)[0]);
  assert.equal(auditActionSchema.safeParse(action).success, true);
  assert.match(contrast, /DOM identity\/rectangle and actual text size\/weight/);
  assert.match(contrast, /same-state original PNG/);
  assert.match(contrast, /opaque text-interior and background pixel coordinates/);
  assert.match(contrast, /NEW PNG: read its result and view that resulting original PNG/);
  assert.match(contrast, /documentId\/stateId and target binding/);
  assert.match(contrast, /target DOM and successful contrast evidence IDs.*evidenceIds/);
  assert.match(checkpoint, /ALL existing findings, including unresolved candidates/);
  assert.match(sealed, /does not reopen an ended session/);
  assert.match(sealed, /New samples require a new run/);
  assert.match(sealed, /preserve the old unresolved result/);
  // Detailed instructions remain behind guide, even after checkpoint ACK.
  const ack = await agent.request({ tool: 'checkpoint', proposal: f.proposal });
  assert.equal(ack.success, true, JSON.stringify(ack));
  assert.equal(JSON.stringify(ack).includes('text-interior'), false);
  assert.equal(auditAgentRequestSchema.safeParse({ tool: 'read', options: { view: 'guide' } }).success, true);
});

test('browserless checkpoint ACK guides complete proposal enrichment without repeat adoption or losing unresolved findings', async t => {
  let agent;
  t.after(() => agent?.close());
  const f = await fixture(t); agent = await guideAgent(t, f);
  const record = { evidenceId: 'ev-0003', action: 'axe', arguments: {}, success: true,
    before: f.base.before, after: f.base.after,
    result: { nodes: [f.node], axe: { violations: [{ id: 'button-name', tags: ['wcag412'], help: 'Button name',
      nodes: [{ target: ['#target'] }] }] }, axeNodeBindings: {
      stable: true, capturedStateId: f.base.after.stateId, capturedDocumentId: f.node.documentId,
      rows: [{ disposition: 'violations', ruleId: 'button-name', ruleNodeIndex: 0, status: 'bound',
        documentId: f.node.documentId, nodeId: f.node.nodeId, selector: '#target', target: ['#target'] }] } } };
  record.json = await writeAuditArtifact(f.directory, 'ev-0003.json', JSON.stringify(record));
  f.records.push(record);
  const first = await agent.request({ tool: 'checkpoint', proposal: { auditor: f.proposal.auditor, findings: f.proposal.findings, adoptAxe: 'all' } });
  assert.equal(first.success, true, JSON.stringify(first));
  assert.equal(first.checkpoint.findings, 2);
  assert.doesNotMatch(first.next, /repeat adoptAxe/);
  assert.match(first.next, /preserve all findings, enrich existing ones without adoptAxe/);
  assert.match(first.next, /read view:'guide'/);
  const guide = await agent.request({ tool: 'read', options: { view: 'guide' } });
  assert.match(guide.guide.checkpoint, /checkpoint.checkpointPath/);
  assert.match(guide.guide.checkpoint, /only candidates not already adopted/);
  const saved = await readAuditCheckpoint(first.checkpoint.checkpointPath);
  const enriched = structuredClone(saved.proposal);
  enriched.findings[1].evidenceIds.push(f.picture.evidenceId);
  const duplicate = await agent.request({ tool: 'checkpoint', proposal: { ...enriched, adoptAxe: 'all' } });
  assert.equal(duplicate.success, false);
  assert.equal(duplicate.error.code, 'DUPLICATE_AUDIT_FINDING');
  const second = await agent.request({ tool: 'checkpoint', proposal: enriched });
  assert.equal(second.success, true, JSON.stringify(second));
  assert.equal(second.checkpoint.version, 2, 'rejected duplicate did not publish a draft');
  const actual = await readAuditCheckpoint(second.checkpoint.checkpointPath);
  assert.deepEqual(actual.proposal.findings.map(f => f.id), saved.proposal.findings.map(f => f.id));
  assert.deepEqual(actual.proposal.findings[0], saved.proposal.findings[0], 'other unresolved finding retained');
  assert.deepEqual(actual.proposal.findings[1].evidenceIds, [record.evidenceId, f.picture.evidenceId]);
  assert.equal(actual.reviewStatus, 'needs_review');
  const later = structuredClone(record); delete later.json;
  later.evidenceId = 'ev-0004';
  later.json = await writeAuditArtifact(f.directory, 'ev-0004.json', JSON.stringify(later));
  f.records.push(later);
  const page = await agent.request({ tool: 'read', evidenceId: later.evidenceId, options: { view: 'axe' } });
  assert.equal(page.success, true, JSON.stringify(page));
  const third = await agent.request({ tool: 'checkpoint', proposal: { ...actual.proposal, adoptAxe: [page.candidates[0].candidateId] } });
  assert.equal(third.success, true, JSON.stringify(third));
  const added = await readAuditCheckpoint(third.checkpoint.checkpointPath);
  assert.equal(added.proposal.findings.length, 3);
  assert.deepEqual(added.proposal.findings.slice(0, 2), actual.proposal.findings, 'new-only adoption retains both previous findings and enrichment');
});
