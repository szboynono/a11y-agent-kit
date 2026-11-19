import path from 'node:path';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { digest, ToolError } from '../evidence.js';
import { validateAuditProposalRecords } from './review.js';
import { auditStandardSelectionSchema } from './schema.js';
import { pngDimensions } from './pixels.js';

const format = 'audit-checkpoint-1';
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const evidenceIdPattern = /^ev-\d{4,}$/;
const committedName = /^audit-checkpoint-(\d{8,16})\.json$/;
const maxBytes = 256 * 1024 * 1024;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const nameFor = version => `audit-checkpoint-${String(version).padStart(8, '0')}.json`;
const fail = (code, message) => { throw new ToolError(code, message); };

function immutable(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) immutable(child);
    Object.freeze(value);
  }
  return value;
}

function keys(value, required, optional = []) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    required.every(key => Object.hasOwn(value, key)) &&
    Object.keys(value).every(key => required.includes(key) || optional.includes(key));
}

async function realDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.resolve(directory) !== directory || directory.includes('\0')) {
    fail('UNSAFE_AUDIT_PATH', 'An absolute canonical directory is required.');
  }
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || await fs.realpath(directory) !== directory) {
    fail('UNSAFE_AUDIT_PATH', 'Checkpoint paths must use real directories without symlinks.');
  }
}

async function auditDirectory(directory) {
  await realDirectory(directory);
  const runId = path.basename(directory).slice(6), evidence = path.dirname(directory), projectRoot = path.dirname(evidence);
  if (path.basename(directory) !== `audit-${runId}` || !uuid.test(runId) || path.basename(evidence) !== 'evidence') {
    fail('UNSAFE_AUDIT_PATH', 'Checkpoints must be directly inside projectRoot/evidence/audit-<UUID>.');
  }
  await realDirectory(evidence);
  await realDirectory(projectRoot);
  return { runId, projectRoot };
}

function validateContext(context) {
  if (context !== undefined && (!keys(context, ['evidencePolicy'], ['standard']) || context.evidencePolicy !== 'audit-evidence-2')) {
    fail('INVALID_AUDIT_CHECKPOINT_CONTEXT', 'Checkpoint context requires the supported evidencePolicy and optional WCAG selection.');
  }
  if (context?.standard !== undefined && !auditStandardSelectionSchema.safeParse(context.standard).success) fail('INVALID_AUDIT_CHECKPOINT_CONTEXT', 'Invalid WCAG selection.');
}

function validateExpected(expected, binding) {
  if (!keys(expected, [], ['runId', 'directory', 'evidencePolicy']) ||
      (expected.evidencePolicy !== undefined && expected.evidencePolicy !== 'audit-evidence-2')) {
    fail('INVALID_AUDIT_CHECKPOINT_CONTEXT', 'Expected checkpoint context contains unsupported fields.');
  }
  if ((expected.runId !== undefined && expected.runId !== binding.runId) ||
      (expected.directory !== undefined && expected.directory !== binding.directory) ||
      (expected.evidencePolicy !== undefined && expected.evidencePolicy !== binding.context?.evidencePolicy)) {
    fail('AUDIT_CHECKPOINT_CONTEXT_MISMATCH', 'The checkpoint does not match the expected run, directory or evidence policy.');
  }
}

async function readBytes(filePath, directory, durable = false) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || path.resolve(filePath) !== filePath || path.dirname(filePath) !== directory) {
    fail('AUDIT_ARTIFACT_OUTSIDE_RUN', 'Checkpoint evidence must remain directly in its original audit directory.');
  }
  await auditDirectory(directory);
  if (await fs.realpath(filePath) !== filePath) fail('UNSAFE_AUDIT_PATH', 'Checkpoint files and evidence must not be symlinks.');
  const handle = await fs.open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > maxBytes) fail('INVALID_AUDIT_ARTIFACT', 'Checkpoint files and evidence must be regular files no larger than 256 MiB.');
    const bytes = await handle.readFile();
    if (durable) await handle.sync();
    return bytes;
  } finally { await handle.close(); }
}

function artifact(value, directory, evidenceId, extension) {
  const image = extension === 'png';
  if (!keys(value, ['path', 'sha256', 'bytes', ...(image ? ['width', 'height'] : [])]) ||
      value.path !== path.join(directory, `${evidenceId}.${extension}`) ||
      !/^[a-f0-9]{64}$/.test(value.sha256) || !Number.isSafeInteger(value.bytes) || value.bytes < 0 || value.bytes > maxBytes ||
      (image && (!Number.isSafeInteger(value.width) || value.width < 1 || !Number.isSafeInteger(value.height) || value.height < 1))) {
    fail('INVALID_AUDIT_CHECKPOINT_REFERENCE', 'A checkpoint requires exact original action attachment names, hashes and dimensions.');
  }
  return { ...value };
}

async function verifyArtifact(value, directory, durable) {
  const bytes = await readBytes(value.path, directory, durable);
  if (bytes.length !== value.bytes || sha256(bytes) !== value.sha256) {
    fail('AUDIT_ARTIFACT_INTEGRITY_MISMATCH', 'Original checkpoint evidence changed after collection.');
  }
  return bytes;
}

function stateBinding(state) {
  if (state == null) return null;
  if (typeof state.documentId !== 'string' || !state.documentId || typeof state.stateId !== 'string' || !state.stateId) {
    fail('INVALID_AUDIT_CHECKPOINT_REFERENCE', 'Referenced observations require their original document and state identities.');
  }
  return { documentId: state.documentId, stateId: state.stateId };
}

async function originalRecord(reference, directory, runId, supplied, durable = false) {
  if (!evidenceIdPattern.test(reference?.evidenceId)) fail('INVALID_AUDIT_CHECKPOINT_REFERENCE', 'An original action evidence ID is required.');
  const json = artifact(reference.json, directory, reference.evidenceId, 'json');
  const bytes = await verifyArtifact(json, directory, durable);
  let original;
  try { original = JSON.parse(bytes.toString('utf8')); }
  catch { fail('INVALID_AUDIT_ARTIFACT', 'Original action evidence is not valid JSON.'); }
  if (!original || typeof original !== 'object' || Array.isArray(original) || Object.hasOwn(original, 'json') ||
      original.evidenceId !== reference.evidenceId || original.success !== true || typeof original.action !== 'string' || !original.action ||
      (original.runId !== undefined && original.runId !== runId)) {
    fail('INVALID_AUDIT_CHECKPOINT_REFERENCE', 'A checkpoint can reference only successful original actions from the current run.');
  }
  if (supplied) {
    const { json: _json, ...body } = supplied;
    if (digest(original) !== digest(body)) fail('AUDIT_RECORD_INTEGRITY_MISMATCH', 'The supplied observation differs from its original action JSON.');
  }
  const png = original.png ? artifact(original.png, directory, reference.evidenceId, 'png') : undefined;
  if (png) {
    const dimensions = pngDimensions(await verifyArtifact(png, directory, durable));
    if (dimensions.width !== png.width || dimensions.height !== png.height) fail('AUDIT_PNG_DIMENSIONS_MISMATCH', 'Original screenshot dimensions do not match.');
  }
  const binding = { evidenceId: original.evidenceId, action: original.action, before: stateBinding(original.before), after: stateBinding(original.after), json, ...(png ? { png } : {}) };
  if (!binding.after) fail('INVALID_AUDIT_CHECKPOINT_REFERENCE', 'Successful checkpoint evidence requires its original observed document and state.');
  if (!supplied && digest(binding) !== digest(reference)) fail('AUDIT_CHECKPOINT_REFERENCE_MISMATCH', 'The checkpoint reference differs from its original action.');
  return { record: { ...original, json }, binding };
}

function targetBindings(proposal, records) {
  const byId = new Map(records.map(record => [record.evidenceId, record]));
  return proposal.findings.map(finding => {
    const record = byId.get(finding.target.evidenceId);
    const nodes = [...(Array.isArray(record.result?.nodes) ? record.result.nodes : []), ...(record.result?.element ? [record.result.element] : [])];
    const node = nodes.find(value => value.nodeId === finding.target.nodeId && value.documentId === record.after.documentId);
    return { findingId: finding.id, evidenceId: record.evidenceId, nodeId: node.nodeId, documentId: node.documentId, stateId: record.after.stateId };
  });
}

function referencedIds(proposal) {
  return [...new Set(proposal.findings.flatMap(finding => finding.evidenceIds))].sort();
}

async function committedVersions(directory) {
  const versions = [];
  for (const name of await fs.readdir(directory)) {
    if (!name.startsWith('audit-checkpoint-') || !name.endsWith('.json')) continue;
    const match = committedName.exec(name), version = Number(match?.[1]);
    if (!match || !Number.isSafeInteger(version) || version < 1 || nameFor(version) !== name) {
      fail('INVALID_AUDIT_CHECKPOINT', 'A committed checkpoint has an invalid version filename.');
    }
    versions.push(version);
  }
  return versions.sort((a, b) => a - b);
}

/** Read a draft only; this never seals, submits, reviews or scores it. */
export async function readAuditCheckpoint(checkpointPath, expected = {}) {
  if (typeof checkpointPath !== 'string' || !path.isAbsolute(checkpointPath) || path.resolve(checkpointPath) !== checkpointPath || !committedName.test(path.basename(checkpointPath))) {
    fail('INVALID_AUDIT_CHECKPOINT_PATH', 'An original committed checkpoint path is required.');
  }
  const directory = path.dirname(checkpointPath), { runId, projectRoot } = await auditDirectory(directory);
  let checkpoint;
  try { checkpoint = JSON.parse((await readBytes(checkpointPath, directory)).toString('utf8')); }
  catch (error) { if (error instanceof SyntaxError) fail('INVALID_AUDIT_CHECKPOINT', 'Committed checkpoint is not valid JSON.'); throw error; }
  if (!keys(checkpoint, ['kind', 'schemaVersion', 'runId', 'projectRoot', 'directory', 'version', 'createdAt', 'status', 'reviewStatus', 'sealed', 'scoreable', 'proposal', 'evidence', 'targets', 'checkpointPath', 'checkpointDigest'], ['context']) ||
      checkpoint.kind !== format || checkpoint.schemaVersion !== format || checkpoint.runId !== runId || checkpoint.projectRoot !== projectRoot || checkpoint.directory !== directory ||
      !Number.isSafeInteger(checkpoint.version) || checkpoint.version < 1 || nameFor(checkpoint.version) !== path.basename(checkpointPath) || checkpoint.checkpointPath !== checkpointPath ||
      typeof checkpoint.createdAt !== 'string' || !Number.isFinite(Date.parse(checkpoint.createdAt)) || new Date(checkpoint.createdAt).toISOString() !== checkpoint.createdAt ||
      checkpoint.status !== 'draft' || checkpoint.reviewStatus !== 'needs_review' || checkpoint.sealed !== false || checkpoint.scoreable !== false ||
      !Array.isArray(checkpoint.evidence) || checkpoint.evidence.length > 500 || !Array.isArray(checkpoint.targets)) {
    fail('INVALID_AUDIT_CHECKPOINT', 'The committed checkpoint must retain its draft status, version and original run binding.');
  }
  validateContext(checkpoint.context);
  validateExpected(expected, checkpoint);
  const { checkpointDigest, ...body } = checkpoint;
  if (digest(body) !== checkpointDigest) fail('AUDIT_CHECKPOINT_INTEGRITY_MISMATCH', 'The committed checkpoint content changed.');
  const records = [], ids = new Set();
  for (const reference of checkpoint.evidence) {
    if (ids.has(reference?.evidenceId)) fail('INVALID_AUDIT_CHECKPOINT_REFERENCE', 'Checkpoint evidence references must be unique.');
    ids.add(reference?.evidenceId);
    records.push((await originalRecord(reference, directory, runId)).record);
  }
  const proposal = validateAuditProposalRecords(checkpoint.proposal, records, checkpoint.context?.standard);
  if (digest(proposal) !== digest(checkpoint.proposal) || digest(referencedIds(proposal)) !== digest(checkpoint.evidence.map(reference => reference.evidenceId)) ||
      digest(targetBindings(proposal, records)) !== digest(checkpoint.targets)) {
    fail('AUDIT_CHECKPOINT_REFERENCE_MISMATCH', 'The draft proposal or target identities do not match its original evidence.');
  }
  return immutable(checkpoint);
}

/** Corrupt newest committed data is an error, never a fallback to an older draft. */
export async function recoverAuditCheckpoint(directory, expected = {}) {
  const { runId } = await auditDirectory(directory);
  validateExpected(expected, { runId, directory, ...(expected.evidencePolicy ? { context: { evidencePolicy: expected.evidencePolicy } } : {}) });
  const versions = await committedVersions(directory);
  return versions.length ? readAuditCheckpoint(path.join(directory, nameFor(versions.at(-1))), expected) : null;
}

async function publish(directory, checkpoint) {
  const temporaryPath = path.join(directory, `.audit-checkpoint-${randomUUID()}.tmp`);
  const bytes = Buffer.from(`${JSON.stringify(checkpoint, null, 2)}\n`);
  if (bytes.length > maxBytes) fail('INVALID_AUDIT_CHECKPOINT', 'A checkpoint must be no larger than 256 MiB.');
  let handle;
  try {
    handle = await fs.open(temporaryPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close(); handle = undefined;
    await auditDirectory(directory);
    try { await fs.link(temporaryPath, checkpoint.checkpointPath); }
    catch (error) { if (error.code === 'EEXIST') return false; throw error; }
    await fs.unlink(temporaryPath);
    const directoryHandle = await fs.open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
    return true;
  } finally {
    if (handle) await handle.close();
    await fs.unlink(temporaryPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}

/** Persist caller-authored findings without changing the live session or original evidence. */
export async function saveAuditCheckpoint({ runId, directory, records, proposal: input, context }) {
  const binding = await auditDirectory(directory);
  if (runId !== binding.runId) fail('AUDIT_CHECKPOINT_CONTEXT_MISMATCH', 'Checkpoint runId must match its original audit directory.');
  validateContext(context);
  context = context ? { ...context } : undefined;
  if (!Array.isArray(records) || records.length > 500 || new Set(records.map(record => record?.evidenceId)).size !== records.length) {
    fail('INVALID_AUDIT_CHECKPOINT_REFERENCE', 'Checkpoint records require unique original evidence IDs within the run action limit.');
  }
  const proposal = validateAuditProposalRecords(input, records, context?.standard), byId = new Map(records.map(record => [record.evidenceId, record]));
  const originals = [], evidence = [];
  for (const evidenceId of referencedIds(proposal)) {
    const supplied = byId.get(evidenceId);
    const verified = await originalRecord(supplied, directory, runId, supplied, true);
    originals.push(verified.record); evidence.push(verified.binding);
  }
  validateAuditProposalRecords(proposal, originals, context?.standard);
  const targets = targetBindings(proposal, originals);
  // The link operation arbitrates concurrent writers without replacing any version.
  for (let attempt = 0; attempt < 64; attempt++) {
    const latest = await recoverAuditCheckpoint(directory, { runId });
    const version = (latest?.version ?? 0) + 1;
    if (!Number.isSafeInteger(version)) fail('AUDIT_CHECKPOINT_VERSION_EXHAUSTED', 'Checkpoint version limit was reached.');
    const checkpoint = JSON.parse(JSON.stringify({
      kind: format, schemaVersion: format, runId, projectRoot: binding.projectRoot, directory, version, createdAt: new Date().toISOString(),
      status: 'draft', reviewStatus: 'needs_review', sealed: false, scoreable: false, proposal, evidence, targets,
      ...(context ? { context } : {}), checkpointPath: path.join(directory, nameFor(version)),
    }));
    checkpoint.checkpointDigest = digest(checkpoint);
    if (await publish(directory, checkpoint)) return immutable(checkpoint);
  }
  fail('AUDIT_CHECKPOINT_BUSY', 'Concurrent checkpoint writers prevented a committed version.');
}
