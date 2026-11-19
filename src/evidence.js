import { createHash, randomUUID } from 'node:crypto';
import { constants, lstatSync, watch } from 'node:fs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { manifestSchema } from './schema.js';
import { standardMetadata, coverageMetadata } from './wcag.js';

export const SCHEMA_VERSION = '1.0.0';
export const EXECUTION_POLICY = Object.freeze({
  actionTimeoutMs: 3000,
  navigationTimeoutMs: 15000,
  assertionTimeoutMs: 3000,
  waitUntil: 'domcontentloaded',
  selectorEngine: 'standard-css',
  textComparison: 'exact-textContent',
  serviceWorkers: 'block',
  sourceWatchWarmupMs: 100,
  sourceWatchSettleMs: 100,
});

// Fixed policy: callers cannot shrink the fingerprint scope through a manifest.
export const IGNORED_DIRECTORIES = Object.freeze([
  '.git', 'node_modules', 'evidence', '.project-memory', '.cache', '.next', '.nuxt',
  '.output', '.svelte-kit', '.turbo', '.vite', '.parcel-cache', '.astro',
  'coverage', 'dist', 'build', 'out', 'playwright-report', 'test-results',
]);
const ignored = new Set(IGNORED_DIRECTORIES);

// A watch notification can arrive long after its write, so fixed delays cannot
// separate pre-run history from in-run edits. Notifications arrive in write order:
// a marker written now and then delivered bounds everything before it.
const SOURCE_MARKER_CONFIRM_MS = 10000;

export function monitorSource(projectRoot) {
  const paths = new Set();
  const errors = [];
  const markers = new Map();
  let eventCount = 0;
  let armed = false;
  let watcher;
  try {
    watcher = watch(projectRoot, { recursive: true, persistent: false }, (_event, filename) => {
      const relative = filename == null ? null : path.relative(projectRoot, path.resolve(projectRoot, String(filename))).split(path.sep).join('/');
      const marker = markers.get(relative);
      if (marker) {
        markers.delete(relative);
        marker();
        return;
      }
      if (!armed) return;
      if (relative === null) {
        errors.push({ code: 'SOURCE_MONITOR_UNKNOWN_PATH', message: 'A source notification had no path; source stability is unknown.' });
        return;
      }
      if (!relative || relative.startsWith('../') || path.isAbsolute(relative)) {
        errors.push({ code: 'SOURCE_MONITOR_UNKNOWN_PATH', message: 'A source notification could not be scoped to projectRoot.' });
        return;
      }
      const parts = relative.split('/');
      if (parts.slice(0, -1).some(part => ignored.has(part)) || parts.at(-1) === '.DS_Store' || parts.at(-1).endsWith('.log')) return;
      if (ignored.has(parts.at(-1))) {
        try {
          const stat = lstatSync(path.resolve(projectRoot, relative));
          if (stat.isDirectory() || stat.isSymbolicLink()) return;
        } catch { /* A vanished path is conservatively treated as a change. */ }
      }
      eventCount++;
      if (paths.size < 50) paths.add(relative);
    });
    watcher.on('error', error => errors.push({ code: 'SOURCE_MONITOR_ERROR', message: String(error.message).slice(0, 1000) }));
  } catch {
    throw new ToolError('SOURCE_MONITOR_UNAVAILABLE', 'Recursive source monitoring is unavailable; stable-run verification cannot proceed.');
  }
  // Markers live in the ignored evidence directory, so they never enter the
  // fingerprint or count as source changes, even when delivered twice.
  async function mark(stage, onDelivered = () => {}) {
    let relative, timer;
    try {
      const absolute = path.join(await evidenceDirectory(projectRoot, true), `.source-watch-${randomUUID()}`);
      relative = path.relative(projectRoot, absolute).split(path.sep).join('/');
      const delivered = new Promise(resolve => markers.set(relative, () => { onDelivered(); resolve(true); }));
      await fs.writeFile(absolute, '', { flag: 'wx', mode: 0o600 });
      await fs.rm(absolute, { force: true });
      if (!await Promise.race([delivered, new Promise(resolve => { timer = setTimeout(resolve, SOURCE_MARKER_CONFIRM_MS, false); })])) {
        errors.push({ code: 'SOURCE_MONITOR_UNCONFIRMED', message: `The source monitor did not report its ${stage} marker; source stability is unknown.` });
      }
    } catch (error) {
      errors.push({ code: 'SOURCE_MONITOR_UNCONFIRMED', message: `The source monitor ${stage} marker failed: ${String(error.message).slice(0, 1000)}` });
    } finally {
      clearTimeout(timer);
      markers.delete(relative);
    }
  }
  return {
    // Notifications delivered before the start marker predate the run window.
    // Arming in the delivery callback leaves no gap before later notifications.
    async arm() {
      await mark('start', () => { armed = true; });
      armed = true;
    },
    // Every notification for a write before the end marker has been delivered.
    async settle() { await mark('end'); },
    close() { watcher.close(); markers.clear(); },
    snapshot() {
      return {
        method: 'recursive-notifications-ordered-by-markers-and-before-after-sha256',
        status: errors.length ? 'unknown' : eventCount ? 'changed' : 'stable_observed',
        eventCount, changedPaths: [...paths].sort(), errors: [...errors],
      };
    },
  };
}

export class ToolError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'ToolError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

export function errorRecord(error, stage) {
  const record = {
    code: error.code || 'RUNTIME_ERROR',
    message: String(error.message || error).slice(0, 4000),
  };
  if (stage) record.stage = stage;
  if (error.details !== undefined) record.details = error.details;
  return record;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().filter(key => value[key] !== undefined)
      .map(key => [key, canonicalize(value[key])]));
  }
  return value;
}

export function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex')}`;
}

export function contractDigest(manifest, executionPolicy = EXECUTION_POLICY) {
  return digest({ manifest, executionPolicy });
}

export function parseManifest(input) {
  const result = manifestSchema.safeParse(input);
  if (!result.success) {
    throw new ToolError('INVALID_MANIFEST', 'Manifest validation failed.', result.error.issues.map(issue => ({
      path: issue.path.join('.'), message: issue.message,
    })));
  }
  return result.data;
}

export async function canonicalRoot(projectRoot) {
  const resolved = await fs.realpath(projectRoot);
  if (!(await fs.stat(resolved)).isDirectory()) {
    throw new ToolError('INVALID_PROJECT_ROOT', 'projectRoot must be a directory.');
  }
  return resolved;
}

export async function fingerprint(projectRoot) {
  const root = await canonicalRoot(projectRoot);
  const files = [];
  async function walk(directory) {
    const dirStat = await fs.lstat(directory);
    if (dirStat.isSymbolicLink() || await fs.realpath(directory) !== directory) {
      throw new ToolError('UNSUPPORTED_SYMLINK', 'Source symlinks are unsupported; no paths outside projectRoot are followed.');
    }
    const entries = (await fs.readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const entry of entries) {
      if (ignored.has(entry.name) && (entry.isDirectory() || entry.isSymbolicLink())) continue;
      if (entry.name === '.DS_Store' || entry.name.endsWith('.log')) continue;
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      if (relative.startsWith('../') || path.isAbsolute(relative)) {
        throw new ToolError('PATH_OUTSIDE_PROJECT', 'Source path escapes projectRoot.');
      }
      const stat = await fs.lstat(absolute);
      if (stat.isSymbolicLink()) {
        throw new ToolError('UNSUPPORTED_SYMLINK', `Source symlinks are unsupported: ${relative}`);
      }
      if (stat.isDirectory()) {
        await walk(absolute);
      } else if (stat.isFile()) {
        const handle = await fs.open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          const openedStat = await handle.stat();
          files.push({
            path: relative,
            digest: createHash('sha256').update(await handle.readFile()).digest('hex'),
            executable: Boolean(openedStat.mode & 0o111),
          });
        } finally {
          await handle.close();
        }
      } else {
        throw new ToolError('UNSUPPORTED_SOURCE_FILE', `Non-regular source file is unsupported: ${relative}`);
      }
    }
  }
  await walk(root);
  return {
    algorithm: 'sha256-tree-v1',
    digest: digest(files),
    fileCount: files.length,
    ignoredDirectories: [...IGNORED_DIRECTORIES],
    ignoredFiles: ['.DS_Store', '*.log'],
    symlinkPolicy: 'reject-source-symlinks',
  };
}

async function evidenceDirectory(root, create = false) {
  const directory = path.join(root, 'evidence');
  if (create) await fs.mkdir(directory, { mode: 0o700 }).catch(error => {
    if (error.code !== 'EEXIST') throw error;
  });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || await fs.realpath(directory) !== directory) {
    throw new ToolError('UNSAFE_EVIDENCE_PATH', 'evidence must be a real directory directly under projectRoot.');
  }
  return directory;
}

export async function saveReport(report) {
  const directory = await evidenceDirectory(report.manifest.projectRoot, true);
  const reportPath = path.join(directory, `${report.kind}-${report.runId}.json`);
  const payload = JSON.parse(JSON.stringify({ ...report, reportPath }));
  payload.reportDigest = digest(payload);
  await fs.writeFile(reportPath, `${JSON.stringify(payload, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return payload;
}

export function newRunId() {
  return randomUUID();
}

export async function readReport(inputPath) {
  if (typeof inputPath !== 'string' || !inputPath.trim() || inputPath.includes('\0')) {
    throw new ToolError('INVALID_REPORT_PATH', 'A nonempty report path is required.');
  }
  const reportPath = path.resolve(inputPath);
  const handle = await fs.open(reportPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let report;
  try {
    if (!(await handle.stat()).isFile()) throw new ToolError('INVALID_REPORT', 'Report must be a regular JSON file.');
    report = JSON.parse(await handle.readFile('utf8'));
  } catch (error) {
    if (error instanceof SyntaxError) throw new ToolError('INVALID_REPORT', 'Report is not valid JSON.');
    throw error;
  } finally {
    await handle.close();
  }
  if (!report || report.schemaVersion !== SCHEMA_VERSION || !['analyze', 'verify'].includes(report.kind)) {
    throw new ToolError('INVALID_REPORT', 'Unsupported report schema or kind.');
  }
  const { reportDigest, ...payload } = report;
  if (typeof reportDigest !== 'string' || digest(payload) !== reportDigest) {
    throw new ToolError('REPORT_INTEGRITY_MISMATCH', 'Report content changed after it was created.');
  }
  const manifest = parseManifest(report.manifest);
  const root = await canonicalRoot(manifest.projectRoot);
  if (root !== manifest.projectRoot || path.dirname(await fs.realpath(reportPath)) !== await evidenceDirectory(root)) {
    throw new ToolError('REPORT_OUTSIDE_PROJECT', 'Report must remain in its projectRoot/evidence directory.');
  }
  if (digest(report.executionPolicy) !== digest(EXECUTION_POLICY) ||
      report.contractDigest !== contractDigest(manifest, report.executionPolicy)) {
    throw new ToolError('CONTRACT_MISMATCH', 'The frozen manifest or execution policy was changed.');
  }
  if (Object.hasOwn(report, 'standard')) {
    if (!report.standard || !report.coverage ||
        digest(report.standard) !== digest(standardMetadata()) ||
        digest(report.coverage) !== digest(coverageMetadata(manifest.rules))) {
      throw new ToolError('STANDARD_MISMATCH', 'The recorded WCAG target, rubric, or partial-evidence policy does not match this tool.');
    }
  } else if (Object.hasOwn(report, 'coverage')) {
    throw new ToolError('STANDARD_MISMATCH', 'Coverage metadata requires its recorded WCAG target and rubric.');
  }
  if (report.applicationBinding !== 'caller-declared' ||
      report.codeFingerprint?.algorithm !== 'sha256-tree-v1' ||
      typeof report.codeFingerprint.digest !== 'string') {
    throw new ToolError('INVALID_REPORT', 'Report is missing its source binding or fingerprint.');
  }
  return { report, reportPath };
}
