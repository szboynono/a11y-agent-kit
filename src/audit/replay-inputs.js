/** Opt-in input preparation only. No browser imports, capture, scoring or retries. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { auditActionSchema, parseAuditManifest } from './schema.js';
import { fingerprint, digest } from '../evidence.js';

const VERSION = 'replay-inputs-v1';
const hash = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const sha = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const id = z.string().regex(/^ev-\d{4,}$/);
const privateSchema = z.object({ version: z.literal(VERSION), reportSha256: sha,
  bindings: z.record(id, z.string().max(100000).refine(v => !v.includes('\0') && v !== '[omitted]')) }).strict();
const receiptSchema = z.object({ version: z.literal(VERSION), recipeSha256: sha, reportSha256: sha,
  bindingSha256: sha.nullable() }).strict();
const fail = () => { throw new Error('REPLAY_INPUTS_REFUSED: invalid, unsafe, missing or changed input.'); };
// Never forward native IO, JSON, validation or executor diagnostics: these can contain secrets.
async function guardedAsync(fn) { try { return await fn(); } catch { return fail(); } }

/** JSON.parse silently accepts duplicate keys. Scan every object, including escaped keys. */
function json(bytes) {
  const s = bytes.toString('utf8'); let i = 0;
  const ws = () => { while (/\s/.test(s[i] || '') && i < s.length) i++; };
  const string = () => { const start = i++; while (i < s.length) { if (s[i] === '\\') { i += 2; continue; } if (s[i++] === '"') return JSON.parse(s.slice(start, i)); } fail(); };
  function value(depth = 0) {
    if (depth > 100) fail(); ws();
    if (s[i] === '"') { string(); return; }
    if (s[i] === '{') { i++; ws(); const keys = new Set(); if (s[i] === '}') { i++; return; }
      while (true) { ws(); if (s[i] !== '"') fail(); const k = string(); if (keys.has(k)) fail(); keys.add(k); ws(); if (s[i++] !== ':') fail(); value(depth + 1); ws(); const c = s[i++]; if (c === '}') return; if (c !== ',') fail(); }
    }
    if (s[i] === '[') { i++; ws(); if (s[i] === ']') { i++; return; } while (true) { value(depth + 1); ws(); const c = s[i++]; if (c === ']') return; if (c !== ',') fail(); } }
    const m = s.slice(i).match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/); if (!m) fail(); i += m[0].length;
  }
  value(); ws(); if (i !== s.length) fail(); return JSON.parse(s);
}
function canonical(p) {
  if (typeof p !== 'string' || !path.isAbsolute(p) || p.includes('\0') || path.normalize(p) !== p) fail();
  // Reject all symlink components, including parents; caller supplies canonical paths.
  let current = path.parse(p).root;
  for (const part of p.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part); if (fs.lstatSync(current).isSymbolicLink()) fail();
  }
  if (fs.realpathSync(p) !== p) fail(); return p;
}
function read(p, privateFile = false) {
  canonical(p);
  const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const a = fs.fstatSync(fd, { bigint: true });
    if (!a.isFile() || a.size > 32n * 1024n * 1024n || (privateFile && ((a.mode & 0o777n) !== 0o600n || a.uid !== BigInt(process.getuid())))) fail();
    const bytes = fs.readFileSync(fd), b = fs.fstatSync(fd, { bigint: true });
    canonical(p); const c = fs.lstatSync(p, { bigint: true });
    if (['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode'].some(k => a[k] !== b[k] || a[k] !== c[k])) fail();
    // Re-read the same handle to hash-check a stable snapshot.
    const again = Buffer.alloc(bytes.length); fs.readSync(fd, again, 0, again.length, 0);
    const d = fs.fstatSync(fd, { bigint: true });
    if (!bytes.equals(again) || ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode'].some(k => a[k] !== d[k])) fail();
    return { bytes, sha256: hash(bytes), data: json(bytes) };
  } finally { fs.closeSync(fd); }
}
const inside = (p, root) => p === root || p.startsWith(root + path.sep);
function layout(outputDirectory, reportPath, sourceRoot, bindingsPath) {
  canonical(sourceRoot); canonical(path.dirname(outputDirectory));
  if (!fs.statSync(sourceRoot).isDirectory()) fail();
  if (path.normalize(outputDirectory) !== outputDirectory || !path.isAbsolute(outputDirectory) || outputDirectory.includes('\0') ||
      inside(outputDirectory, sourceRoot) || inside(sourceRoot, outputDirectory) ||
      inside(outputDirectory, path.dirname(reportPath)) || inside(reportPath, outputDirectory) ||
      (bindingsPath && inside(bindingsPath, outputDirectory))) fail();
}
async function inputs(reportPath, bindingsPath) {
  const original = read(reportPath), report = original.data;
  if (report.schemaVersion !== 'audit-1' || report.kind !== 'audit' || !Array.isArray(report.records) || report.records.length > 500) fail();
  const manifest = parseAuditManifest(report.manifest);
  canonical(manifest.projectRoot);
  if (bindingsPath && (inside(bindingsPath, manifest.projectRoot) || inside(bindingsPath, path.dirname(reportPath)))) fail();
  if (report.reportDigest !== undefined) { const { reportDigest, ...body } = report; if (digest(body) !== reportDigest) fail(); }
  if (report.manifestDigest !== undefined && report.manifestDigest !== digest(report.manifest)) fail();
  if (!sha.safeParse(report.codeFingerprint?.digest).success) fail();
  if ((await fingerprint(manifest.projectRoot)).digest !== report.codeFingerprint.digest) fail();
  const seen = new Set();
  const actions = report.records.map(r => {
    if (!id.safeParse(r.evidenceId).success || seen.has(r.evidenceId) || typeof r.success !== 'boolean' || !r.arguments || typeof r.arguments !== 'object' || Array.isArray(r.arguments) || 'action' in r.arguments) fail();
    seen.add(r.evidenceId);
    const a = { ...r.arguments, action: r.action }; if (!auditActionSchema.safeParse(a).success) fail();
    if (r.result?.status !== undefined && !['ok', 'success', 'error', 'not_run', 'completed'].includes(r.result.status)) fail();
    return a;
  });
  // Do not silently lose planned but unrecorded actions.
  if (report.plan && (report.plan.length !== report.records.length || report.plan.some((p, n) => {
    const { evidenceId, ...a } = p; return evidenceId !== report.records[n].evidenceId || digest(a) !== digest(actions[n]);
  }))) fail();
  const parameters = bindingsPath ? read(bindingsPath, true) : null;
  const binding = parameters ? privateSchema.parse(parameters.data) : null;
  if (binding && binding.reportSha256 !== original.sha256) fail();
  const slots = report.records.filter(r => r.action === 'fill' && r.arguments.value === '[omitted]').map(r => r.evidenceId);
  if (slots.some(k => !binding || !Object.hasOwn(binding.bindings, k)) || (binding && Object.keys(binding.bindings).some(k => !slots.includes(k)))) fail();
  // Resolve only in memory; never serialize these actions.
  const resolved = actions.map((a, n) => a.action === 'fill' && a.value === '[omitted]' ? { ...a, value: binding.bindings[report.records[n].evidenceId] } : a);
  const recipe = { version: VERSION, original: { path: reportPath, sha256: original.sha256 },
    source: { path: manifest.projectRoot, sha256: report.codeFingerprint.digest, binding: 'caller-declared' },
    parameters: { path: bindingsPath ?? null, slots },
    actions: report.records.map(r => ({ evidenceId: r.evidenceId, action: r.action, originalSuccess: r.success, originalStatus: r.result?.status ?? null })) };
  return { recipe, resolved, report, original, parameters };
}
const encode = data => Buffer.from(JSON.stringify(data, null, 2) + '\n');
function write(dir, name, data) { fs.writeFileSync(path.join(dir, name), encode(data), { flag: 'wx', mode: 0o600 }); }

export async function prepareReplayInputs({ reportPath, bindingsPath = null, outputDirectory }) {
  return guardedAsync(async () => {
    const state = await inputs(reportPath, bindingsPath);
    layout(outputDirectory, reportPath, state.recipe.source.path, bindingsPath);
    const receipt = { version: VERSION, recipeSha256: hash(encode(state.recipe)), reportSha256: state.original.sha256, bindingSha256: state.parameters?.sha256 ?? null };
    // Recheck after async fingerprinting and before writing anything.
    if (read(reportPath).sha256 !== receipt.reportSha256 || (bindingsPath && read(bindingsPath, true).sha256 !== receipt.bindingSha256)) fail();
    fs.mkdirSync(outputDirectory, { mode: 0o700 }); canonical(outputDirectory);
    if ((fs.statSync(outputDirectory).mode & 0o777) !== 0o700) fail();
    write(outputDirectory, 'recipe.json', state.recipe);
    write(outputDirectory, 'private-manifest.json', receipt);
    return { recipePath: path.join(outputDirectory, 'recipe.json') };
  });
}

async function load(directory) {
  canonical(directory);
  const directoryStat = fs.statSync(directory);
  if (!directoryStat.isDirectory() || (directoryStat.mode & 0o777) !== 0o700 || directoryStat.uid !== process.getuid()) fail();
  const publicFile = read(path.join(directory, 'recipe.json'));
  const receipt = receiptSchema.parse(read(path.join(directory, 'private-manifest.json'), true).data);
  if (publicFile.sha256 !== receipt.recipeSha256) fail();
  const p = publicFile.data;
  const state = await inputs(p.original?.path, p.parameters?.path);
  layout(directory, p.original.path, state.recipe.source.path, p.parameters.path);
  if (JSON.stringify(p) !== JSON.stringify(state.recipe) || state.original.sha256 !== receipt.reportSha256 || (state.parameters?.sha256 ?? null) !== receipt.bindingSha256) fail();
  if (read(p.original.path).sha256 !== receipt.reportSha256 || (p.parameters.path && read(p.parameters.path, true).sha256 !== receipt.bindingSha256)) fail();
  return state;
}
/** Loading returns only public metadata; private values never escape through this API. */
export async function loadReplayInputs(directory) { return guardedAsync(async () => (await load(directory)).recipe); }
export async function verifyReplayInputs(directory) { await loadReplayInputs(directory); return { version: VERSION, verified: true }; }

/** Factory is invoked only after verification. Executor output/errors are discarded. */
export async function executeReplayInputs(directory, createExecutor) {
  return guardedAsync(async () => {
    const state = await load(directory);
    const executor = await createExecutor(); const records = [];
    try {
      for (const [n, action] of state.resolved.entries()) {
        let success = false;
        try { const result = await executor.execute(action); success = result?.success === true; } catch { /* fixed safe status only */ }
        const original = state.report.records[n];
        records.push({ ...state.recipe.actions[n], arguments: original.action === 'fill' ? { ...original.arguments, value: '[omitted]' } : original.arguments,
          freshSuccess: success, freshStatus: success ? 'completed' : 'error' });
      }
    } finally { await executor.close?.(); }
    return { version: VERSION, originalSha256: state.original.sha256, records };
  });
}
