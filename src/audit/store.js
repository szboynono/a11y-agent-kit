import path from 'node:path';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { digest, fingerprint, IGNORED_DIRECTORIES, ToolError, errorRecord } from '../evidence.js';
import { AUDIT_SCHEMA_VERSION, resolveAuditStandard, parseAuditManifest } from './schema.js';
import { pngDimensions } from './pixels.js';
import { validateAuditEvidencePolicy } from './policy.js';

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const kinds = new Set(['audit', 'audit-proposal', 'audit-review']);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

async function realDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.resolve(directory) !== directory) {
    throw new ToolError('UNSAFE_AUDIT_PATH', 'An absolute canonical directory is required.');
  }
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || await fs.realpath(directory) !== directory) {
    throw new ToolError('UNSAFE_AUDIT_PATH', 'Audit paths must use real directories without symlinks.');
  }
  return directory;
}

async function auditDirectory(directory) {
  await realDirectory(directory);
  if (!path.basename(directory).startsWith('audit-') || !uuid.test(path.basename(directory).slice(6)) || path.basename(path.dirname(directory)) !== 'evidence') {
    throw new ToolError('UNSAFE_AUDIT_PATH', 'Audit files must be directly inside projectRoot/evidence/audit-<UUID>.');
  }
  const root = path.dirname(path.dirname(directory));
  await realDirectory(root);
  await realDirectory(path.join(root, 'evidence'));
  return { root, runId: path.basename(directory).slice(6) };
}

export async function createAuditDirectory(projectRoot, runId) {
  await realDirectory(projectRoot);
  if (!uuid.test(runId)) throw new ToolError('INVALID_AUDIT_RUN_ID', 'An audit run requires a UUID.');
  const evidence = path.join(projectRoot, 'evidence');
  await fs.mkdir(evidence, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
  await realDirectory(evidence);
  const directory = path.join(evidence, `audit-${runId}`);
  await fs.mkdir(directory, { mode: 0o700 });
  await auditDirectory(directory);
  return directory;
}

export async function writeAuditArtifact(directory, name, bytes) {
  await auditDirectory(directory);
  if (typeof name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,180}$/.test(name) || name === '.' || name === '..') {
    throw new ToolError('UNSAFE_AUDIT_PATH', 'An artifact name must be a single safe filename.');
  }
  if (!(typeof bytes === 'string' || bytes instanceof Uint8Array)) throw new ToolError('INVALID_AUDIT_ARTIFACT', 'Artifact content must be bytes or text.');
  const content = Buffer.from(bytes), artifactPath = path.join(directory, name);
  const handle = await fs.open(artifactPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(content); }
  finally { await handle.close(); }
  await auditDirectory(directory);
  return { path: artifactPath, sha256: sha256(content), bytes: content.length };
}

export async function saveAuditDocument(directory, kind, payload) {
  const { root, runId } = await auditDirectory(directory);
  if (!kinds.has(kind) || payload?.schemaVersion !== AUDIT_SCHEMA_VERSION || payload?.manifest?.projectRoot !== root || payload?.runId !== runId) {
    throw new ToolError('INVALID_AUDIT_DOCUMENT', 'Audit documents require the supported schema, kind, root and collection runId.');
  }
  const reportPath = path.join(directory, `${kind}-${randomUUID()}.json`);
  const { reportDigest: _oldDigest, reportPath: _oldPath, kind: _oldKind, ...body } = payload;
  const report = JSON.parse(JSON.stringify({ ...body, kind, reportPath }));
  report.reportDigest = digest(report);
  await writeAuditArtifact(directory, path.basename(reportPath), `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

async function readBytes(filePath, directory) {
  await auditDirectory(directory);
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || path.resolve(filePath) !== filePath || path.dirname(filePath) !== directory) {
    throw new ToolError('AUDIT_ARTIFACT_OUTSIDE_RUN', 'Evidence attachments must remain directly within their original audit directory.');
  }
  if (await fs.realpath(filePath) !== filePath) throw new ToolError('UNSAFE_AUDIT_PATH', 'Audit files must not be symlinks.');
  const handle = await fs.open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 256 * 1024 * 1024) throw new ToolError('INVALID_AUDIT_ARTIFACT', 'Evidence must be a regular file no larger than 256 MiB.');
    return await handle.readFile();
  } finally { await handle.close(); }
}

async function readExternalBytes(filePath) {
  const handle = await fs.open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW).catch(error => {
    if (error.code === 'ELOOP') throw new ToolError('UNSAFE_AUDIT_PATH', 'External review files must not be symlinks.');
    throw error;
  });
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 32 * 1024 * 1024) throw new ToolError('UNSAFE_AUDIT_PATH', 'An external review must be a regular JSON file no larger than 32 MiB.');
    return await handle.readFile();
  } finally { await handle.close(); }
}

async function verifyArtifact(artifact, directory) {
  if (!artifact || !/^[a-f0-9]{64}$/.test(artifact.sha256) || !Number.isInteger(artifact.bytes) || artifact.bytes < 0) {
    throw new ToolError('INVALID_AUDIT_ARTIFACT', 'An evidence attachment requires its path, SHA-256 and byte length.');
  }
  const bytes = await readBytes(artifact.path, directory);
  if (bytes.length !== artifact.bytes || sha256(bytes) !== artifact.sha256) {
    throw new ToolError('AUDIT_ARTIFACT_INTEGRITY_MISMATCH', 'An evidence attachment changed after collection.');
  }
  return bytes;
}

function validateCollection(report) {
  const standard = resolveAuditStandard(report.manifest.standard);
  if (report.manifestDigest !== digest(report.manifest) || digest(report.standard) !== digest(standard)) {
    throw new ToolError('AUDIT_CONTRACT_MISMATCH', 'The audit manifest or selected WCAG catalog does not match.');
  }
  const expected = standard.criteria.map(criterion => criterion.id).sort();
  if (!Array.isArray(report.coverage) || report.coverage.length !== expected.length || digest(report.coverage.map(row => row.id).sort()) !== digest(expected) || report.coverage.some(row => !['not_tested', 'needs_review'].includes(row.status))) {
    throw new ToolError('INVALID_AUDIT_COVERAGE', 'A collection must retain all selected criteria without whole-criterion pass/fail claims.');
  }
  if (report.coverage.some(row => !standard.criteria.some(c => c.id === row.id && c.level === row.level && c.url === row.url)) ||
      report.candidates?.some(candidate => (candidate.criterionIds === undefined ? !expected.includes(candidate.criterionId) : !Array.isArray(candidate.criterionIds) || candidate.criterionIds.some(id => !expected.includes(id))))) {
    throw new ToolError('INVALID_AUDIT_COVERAGE', 'Coverage and candidate claims must belong to the selected catalog.');
  }
  const source = report.codeFingerprint;
  if (report.applicationBinding !== 'caller-declared' || source?.algorithm !== 'sha256-tree-v1' || !/^sha256:[a-f0-9]{64}$/.test(source?.digest) ||
      digest(source.ignoredDirectories) !== digest(IGNORED_DIRECTORIES) || digest(source.ignoredFiles) !== digest(['.DS_Store', '*.log']) || source.symlinkPolicy !== 'reject-source-symlinks') {
    throw new ToolError('INVALID_AUDIT_SOURCE', 'The audit requires the fixed source fingerprint scope and declared URL binding.');
  }
  if (!Array.isArray(report.records) || !Array.isArray(report.errors) || !Array.isArray(report.candidates) || !['collected', 'partial', 'error'].includes(report.status)) {
    throw new ToolError('INVALID_AUDIT_DOCUMENT', 'Collection records, candidates, errors or status are invalid.');
  }
  const ids = new Set();
  for (const record of report.records) {
    if (!/^ev-\d{4,}$/.test(record?.evidenceId) || ids.has(record.evidenceId) || typeof record.action !== 'string' || typeof record.success !== 'boolean' || !record.json) {
      throw new ToolError('INVALID_AUDIT_RECORD', 'Audit records require unique evidence IDs, action, success and JSON attachment.');
    }
    ids.add(record.evidenceId);
  }
}

async function readDocument(inputPath, seen) {
  if (typeof inputPath !== 'string' || !inputPath.trim() || inputPath.includes('\0')) throw new ToolError('INVALID_AUDIT_PATH', 'An audit report path is required.');
  const reportPath = path.resolve(inputPath), directory = path.dirname(reportPath);
  if (seen.has(reportPath)) throw new ToolError('AUDIT_REFERENCE_CYCLE', 'Audit document references must not form a cycle.');
  seen.add(reportPath);
  let location, externalBytes;
  try { location = await auditDirectory(directory); }
  catch (error) {
    if (error.code !== 'UNSAFE_AUDIT_PATH') throw error;
    await realDirectory(directory);
    externalBytes = await readExternalBytes(reportPath);
    let candidate;
    try { candidate = JSON.parse(externalBytes.toString('utf8')); }
    catch { throw new ToolError('UNSAFE_AUDIT_PATH', 'A noncanonical file must be a valid external audit-review JSON document.'); }
    if (candidate.kind === 'audit-review' && candidate.reportPath === reportPath) {
      location = { root: candidate.manifest?.projectRoot, runId: candidate.runId, externalReview: true };
    } else {
      throw new ToolError('UNSAFE_AUDIT_PATH', 'This is a noncanonical audit copy. Use its original reportPath after checking the original; no automatic redirect is performed.', { canonicalPath: typeof candidate.reportPath === 'string' ? candidate.reportPath : null });
    }
  }
  const { root, runId, externalReview } = location;
  let report;
  try { report = JSON.parse((externalReview ? externalBytes : await readBytes(reportPath, directory)).toString('utf8')); }
  catch (error) { if (error instanceof SyntaxError) throw new ToolError('INVALID_AUDIT_DOCUMENT', 'Audit report is not valid JSON.'); throw error; }
  if (!report || report.schemaVersion !== AUDIT_SCHEMA_VERSION || !kinds.has(report.kind) || (externalReview && report.kind !== 'audit-review') || report.reportPath !== reportPath || report.runId !== runId) {
    throw new ToolError('INVALID_AUDIT_DOCUMENT', 'Audit report schema, kind, runId or original path does not match; copied reports must use their original reportPath.', { canonicalPath: typeof report?.reportPath === 'string' ? report.reportPath : null });
  }
  const { reportDigest, ...payload } = report;
  if (digest(payload) !== reportDigest) throw new ToolError('AUDIT_REPORT_INTEGRITY_MISMATCH', 'Audit report content changed after it was created.');
  const manifest = parseAuditManifest(report.manifest);
  validateAuditEvidencePolicy(report.evidencePolicy);
  if (manifest.projectRoot !== root || digest(manifest) !== digest(report.manifest)) throw new ToolError('AUDIT_REPORT_OUTSIDE_PROJECT', 'Audit report does not belong to its declared canonical projectRoot.');
  if (report.kind === 'audit') {
    validateCollection(report);
    const attachments = new Set();
    for (const record of report.records) {
      for (const artifact of [record.json, record.png].filter(Boolean)) {
        if (attachments.has(artifact.path)) throw new ToolError('AUDIT_ARTIFACT_REUSED', 'Each action requires distinct evidence attachment files.');
        attachments.add(artifact.path);
      }
      const jsonBytes = await verifyArtifact(record.json, directory);
      const { json: _json, ...body } = record;
      let attached;
      try { attached = JSON.parse(jsonBytes.toString('utf8')); }
      catch { throw new ToolError('INVALID_AUDIT_ARTIFACT', 'Action attachment is not valid JSON.'); }
      if (digest(attached) !== digest(body)) throw new ToolError('AUDIT_RECORD_INTEGRITY_MISMATCH', 'Action JSON is not the same observation as the report record.');
      if (record.png) {
        const image = await verifyArtifact(record.png, directory), size = pngDimensions(image);
        if (size.width !== record.png.width || size.height !== record.png.height) throw new ToolError('AUDIT_PNG_DIMENSIONS_MISMATCH', 'Screenshot dimensions do not match its original PNG.');
      }
    }
  } else {
    if (!report.collection || typeof report.collection.reportPath !== 'string' || typeof report.collection.reportDigest !== 'string') {
      throw new ToolError('INVALID_AUDIT_REFERENCE', 'Derived audit documents require their original collection reference.');
    }
    if (!externalReview && path.dirname(report.collection.reportPath) !== directory) throw new ToolError('AUDIT_REFERENCE_OUTSIDE_RUN', 'Derived audit documents must refer to the collection in the same run.');
    const collection = await readDocument(report.collection.reportPath, seen);
    if (collection.kind !== 'audit' || collection.reportDigest !== report.collection.reportDigest || digest(collection.manifest) !== digest(report.manifest) || report.evidencePolicy !== collection.evidencePolicy) {
      throw new ToolError('AUDIT_REFERENCE_MISMATCH', 'Derived audit collection identity does not match its original evidence.');
    }
  }
  return report;
}

export async function readAuditDocument(reportPath) {
  return readDocument(reportPath, new Set());
}

export async function checkAuditCollection(reportPath) {
  let report;
  try {
    report = await readAuditDocument(reportPath);
    if (report.kind !== 'audit') throw new ToolError('INVALID_AUDIT_KIND', 'A collection check requires an original audit collection.');
    const current = await fingerprint(report.manifest.projectRoot);
    const errors = [];
    if (report.sourceStability?.status !== 'stable_observed' || report.sourceStability?.eventCount !== 0 || report.sourceStability?.errors?.length || report.codeFingerprintAfterRun?.digest !== report.codeFingerprint.digest) {
      errors.push({ code: 'AUDIT_SOURCE_UNSTABLE', message: 'Source stability was not established throughout the collection.' });
    }
    if (current.digest !== report.codeFingerprint.digest) errors.push({ code: 'AUDIT_SOURCE_CHANGED', message: 'Current source differs from the source observed by this collection.' });
    return { status: errors.length ? 'expired' : 'current', report, errors };
  } catch (error) {
    return { status: 'error', ...(report ? { report } : {}), errors: [errorRecord(error, 'audit-check')] };
  }
}

/** Read-only companion input under the same original-run containment policy. */
export async function readAuditCompanion(filePath, directory) {
  return JSON.parse((await readBytes(path.resolve(filePath), directory)).toString('utf8'));
}

export async function saveExternalAuditReview(outputPath, payload) {
  const reportPath = path.resolve(outputPath);
  await realDirectory(path.dirname(reportPath));
  const ownDirectory = path.dirname(payload.collection.reportPath);
  const relative = path.relative(payload.manifest.projectRoot, reportPath);
  const insideSource = relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
  const parts = path.dirname(reportPath).split(path.sep);
  const foreignRun = parts.some((part, index) => parts[index - 1] === 'evidence' && part.startsWith('audit-') && uuid.test(part.slice(6))) && path.dirname(reportPath) !== ownDirectory;
  if ((insideSource && path.dirname(reportPath) !== ownDirectory) || foreignRun) {
    throw new ToolError('UNSAFE_AUDIT_REVIEW_OUTPUT', 'Choose a new file directly in this collection\'s canonical run directory or outside the audited project and other audit runs. Writing into source would expire its fingerprint.', { canonicalRunDirectory: ownDirectory });
  }
  const { reportDigest: _digest, reportPath: _path, kind: _kind, ...body } = payload;
  const report = JSON.parse(JSON.stringify({ ...body, kind: 'audit-review', reportPath }));
  report.reportDigest = digest(report);
  const handle = await fs.open(reportPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(`${JSON.stringify(report, null, 2)}\n`); }
  finally { await handle.close(); }
  return report;
}
