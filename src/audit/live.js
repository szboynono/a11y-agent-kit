import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { digest, errorRecord, EXECUTION_POLICY, fingerprint, monitorSource, ToolError } from '../evidence.js';
import { AUDIT_SCHEMA_VERSION, resolveAuditStandard, DEFAULT_AUDIT_SELECTION, parseAuditManifest } from './schema.js';
import { AuditBrowser } from './browser.js';
import { createAuditDirectory, writeAuditArtifact, saveAuditDocument } from './store.js';
import { pngDimensions } from './pixels.js';
import { AUDIT_EVIDENCE_POLICY } from './policy.js';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const retainedAction = action => action.action === 'fill' ? { ...action, value: '[omitted]' } : { ...action };
const terminalCodes = {
  wall_budget_exhausted: 'AUDIT_WALL_BUDGET_EXCEEDED',
  action_budget_exhausted: 'AUDIT_ACTION_BUDGET_EXCEEDED',
  interrupted: 'AUDIT_SESSION_INTERRUPTED',
  input_error: 'AUDIT_SESSION_INPUT_ERROR',
  startup_error: 'AUDIT_SESSION_START_FAILED',
  internal_error: 'AUDIT_SESSION_RUNTIME_ERROR',
};

/** Shared preflight: preserve the live finish reason/signal contract before admission changes. */
export function validateAuditFinishOptions(options = {}) {
  const reason = options.reason ?? 'requested';
  if (!['requested', 'eof', ...Object.keys(terminalCodes)].includes(reason) ||
      (options.signal !== undefined && !['SIGINT', 'SIGTERM'].includes(options.signal))) {
    throw new ToolError('INVALID_AUDIT_SESSION_FINISH', 'Unsupported live session finish reason or signal.');
  }
}

function immutable(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) immutable(child);
    Object.freeze(value);
  }
  return value;
}

function candidatesFor(records, catalog) {
  const candidates = [];
  for (const record of records) {
    if (!record.success || record.action !== 'axe') continue;
    for (const disposition of ['violations', 'incomplete']) for (const rule of record.result.axe[disposition]) {
      const criterionIds = rule.tags.filter(tag => /^wcag\d{3,4}$/.test(tag)).map(tag => {
        const digits = tag.slice(4); return `${digits[0]}.${digits[1]}.${Number(digits.slice(2))}`;
      }).filter(id => catalog.criteria.some(criterion => criterion.id === id));
      candidates.push({ candidateId: `candidate-${String(candidates.length + 1).padStart(4, '0')}`, source: 'axe', disposition, ruleId: rule.id, criterionIds: [...new Set(criterionIds)], evidenceIds: [record.evidenceId], stateId: record.after?.stateId, documentId: record.after?.documentId, targets: rule.nodes.map(node => ({ selector: node.target, failureSummary: node.failureSummary || null })), status: 'needs_review', note: 'An automated observation is a candidate for independent review, not an established WCAG violation.' });
    }
  }
  return candidates;
}

function coverageFor(candidates, catalog) {
  return catalog.criteria.map(criterion => {
    const relevant = candidates.filter(candidate => candidate.criterionIds.includes(criterion.id));
    return { id: criterion.id, level: criterion.level, url: criterion.url, status: relevant.length ? 'needs_review' : 'not_tested', evidenceIds: [...new Set(relevant.flatMap(candidate => candidate.evidenceIds))], scope: 'partial', note: 'The whole criterion remains unassessed. Collected observations and automated candidates require independent review.' };
  });
}

/** One bounded, local browser context. Actions execute once in request order. */
export async function openAuditSession(input, lifecycle = {}) {
  const manifest = parseAuditManifest({ ...input, standard: input?.standard === undefined ? DEFAULT_AUDIT_SELECTION : input.standard });
  const standard = resolveAuditStandard(manifest.standard);
  if (manifest.actions?.length) throw new ToolError('AUDIT_LIVE_INCREMENTAL_ACTIONS_REQUIRED', 'Live sessions accept actions through perform(); omit manifest.actions or supply an empty array.');
  const root = await fs.realpath(manifest.projectRoot);
  if (root !== manifest.projectRoot || !(await fs.stat(root)).isDirectory()) throw new ToolError('UNSAFE_AUDIT_PATH', 'projectRoot must be a real canonical directory without symlinks.');
  const runId = randomUUID(), directory = await createAuditDirectory(root, runId);
  const now = lifecycle.now ?? Date.now;
  const started = now(), startedAt = new Date(started).toISOString(), deadline = Math.min(started + manifest.wallSeconds * 1000, lifecycle.deadline ?? Infinity);
  if (!Number.isFinite(deadline)) throw new ToolError('INVALID_RUNTIME_PROFILE', 'Invalid live deadline.');
  const browser = lifecycle.createBrowser ? lifecycle.createBrowser(manifest) : new AuditBrowser(manifest, { handleSignals: false }), monitor = monitorSource(root);
  const goto = browser.goto?.bind(browser);
  if (goto) browser.goto = (...args) => {
    if (terminal || now() >= deadline || lifecycle.signal?.aborted) throw new ToolError('AUDIT_WALL_BUDGET_EXCEEDED', 'Navigation stopped before dispatch.');
    return goto(...args);
  };
  const records = [], plan = [], errors = [], versions = { node: process.versions.node };
  const retainedManifest = immutable({ ...manifest, actions: [] });
  let sourceBefore, sourceAfter, sourceStability, executedActions = 0, invalidRequests = 0;
  let phase = 'opening', terminal = null, ending = { reason: 'requested' }, queue = Promise.resolve(), sealPromise, wallTimer;
  let rejectOpening;
  const openingStopped = new Promise((_resolve, reject) => { rejectOpening = reject; });
  void openingStopped.catch(() => {});
  const onAbort = () => {
    stop('interrupted');
    rejectOpening(new ToolError('AUDIT_SESSION_INTERRUPTED', 'The live session was cancelled while opening.'));
    if (phase === 'open') void finish({ reason: 'interrupted' }).catch(() => {});
  };
  let resolveFinished, rejectFinished;
  const finished = new Promise((resolve, reject) => { resolveFinished = resolve; rejectFinished = reject; });
  // A caller can use finish() without subscribing to the automatic deadline.
  void finished.catch(() => {});

  function stop(reason, signal) {
    if (phase === 'sealed') return;
    if (!terminal) {
      terminal = { reason, ...(signal ? { signal } : {}) };
      errors.push({ code: terminalCodes[reason], message: `The live audit stopped: ${reason}. The collection is incomplete.`, ...(signal ? { signal } : {}), stage: 'audit-live-session' });
    }
    void browser.close().catch(() => {});
  }

  function finish(options = {}) {
    if (phase === 'sealed') return sealPromise;
    try { validateAuditFinishOptions(options); } catch (error) { return Promise.reject(error); }
    const reason = options.reason ?? 'requested';
    if (Object.hasOwn(terminalCodes, reason)) stop(reason, options.signal);
    if (sealPromise) return sealPromise;
    ending = { reason, ...(options.signal ? { signal: options.signal } : {}) };
    phase = 'closing';
    sealPromise = seal();
    sealPromise.then(resolveFinished, rejectFinished);
    return sealPromise;
  }

  async function seal() {
    try {
      await queue;
      clearTimeout(wallTimer); lifecycle.signal?.removeEventListener('abort', onAbort);
      errors.push(...await browser.close());
      try { sourceAfter = await fingerprint(root); }
      catch (error) { errors.push(errorRecord(error, 'audit-source-fingerprint-after-run')); }
      await delay(EXECUTION_POLICY.sourceWatchSettleMs);
      await monitor.settle(); monitor.close(); sourceStability = monitor.snapshot();
      errors.push(...sourceStability.errors);
      if (sourceBefore?.digest !== sourceAfter?.digest || sourceStability.status !== 'stable_observed') {
        errors.push({ code: 'AUDIT_SOURCE_CHANGED_DURING_RUN', message: 'Source changed, a write was observed, or stable source could not be established throughout this live session.' });
      }
      const candidates = candidatesFor(records, standard), finalManifest = { ...manifest, actions: plan.map(({ evidenceId: _id, ...action }) => action) };
      const report = await saveAuditDocument(directory, 'audit', {
        schemaVersion: AUDIT_SCHEMA_VERSION, evidencePolicy: AUDIT_EVIDENCE_POLICY, runId, manifest: finalManifest, manifestDigest: digest(finalManifest), standard,
        startedAt, completedAt: new Date().toISOString(), status: errors.length ? (records.some(record => record.success) ? 'partial' : 'error') : 'collected',
        applicationBinding: 'caller-declared', applicationBindingNote: 'The caller declares that this URL serves projectRoot. Source-to-build or deployment provenance is not attested.',
        codeFingerprint: sourceBefore, codeFingerprintAfterRun: sourceAfter, sourceStability,
        ...(manifest.networkReplay ? { networkReplay: browser.networkReplayReport() } : {}),
        executionPolicy: { mode: 'persistent-local-context', locatorTimeoutMs: 3000, navigationTimeoutMs: 15000, waitUntil: 'domcontentloaded', serviceWorkers: 'block', navigationOrigin: new URL(manifest.url).origin, axeTags: [...browser.axeTags], screenshotStateBinding: 'matching before/after observed state IDs', screenshotAnimations: 'disabled', screenshotCaret: 'initial', finiteAnimationSettleMs: 1500, keyboardMethod: 'global-page-keyboard-without-selector-focus', wallBudgetIncludesIdle: true },
        liveSession: { protocol: 'audit-live-1', sealed: true, complete: false, termination: terminal ?? ending, deadlineAt: new Date(deadline).toISOString(), contextCount: versions.browser ? 1 : 0, replays: 0, invalidRequests },
        assessment: { status: 'incomplete', wholeCriteriaAssessed: 0, wholePage: 'not_assessed', complete: false },
        plan, records, candidates, coverage: coverageFor(candidates, standard), errors, versions,
        summary: { plannedActions: plan.length, executedActions, successfulActions: records.filter(record => record.success).length, failedActions: records.filter(record => !record.success && record.result?.status !== 'not_run').length, notRunActions: records.filter(record => record.result?.status === 'not_run').length, invalidRequests, candidates: candidates.length, wholeCriteriaAssessed: 0, conformanceStatus: 'not_assessed', durationMs: now() - started },
        limitations: [
          'Sealing records the end of a bounded observation session; it does not complete an audit or establish whole-site or WCAG conformance.',
          'Actions execute once in one context. The wall-clock budget includes opening, action execution and host idle time. Budget stops and interrupts remain incomplete.',
          'Original per-action JSON and PNG bytes are retained without rewriting them when later observations are added.',
          'Native browser ARIA is not screen-reader output. Main-document DOM omits child frames/shadow roots and explicitly records truncation.',
          'Screenshots bind the observed before/after state; dynamic rendering and unobserved content limit that stability observation.',
          'Contrast records caller-selected screenshot samples. Text identity, size, exceptions and criterion applicability require independent review.',
          'Fill arguments, ARIA input values, password/hidden values, inline script text and axe HTML snippets follow the existing browser omission policy. Other visible content can still be sensitive; this is not a secret scanner.',
          'Local digests are not signatures or protection against a local owner rewriting all evidence.',
          ...(manifest.networkReplay ? ['Exact local HTTP(S)/WebSocket routing is an explicit replay environment. Unfrozen external features are unavailable; environment-induced failures are not automatic WCAG violations. This is not an OS airgap or a WebRTC/DNS/speculation firewall.'] : []),
        ],
      });
      phase = 'sealed';
      return immutable(report);
    } catch (error) {
      clearTimeout(wallTimer); lifecycle.signal?.removeEventListener('abort', onAbort);
      await browser.close().catch(() => {});
      monitor.close(); phase = 'sealed';
      throw error;
    }
  }

  async function runAction(action, retained, evidenceId, statusOptions) {
    let observation;
    if (now() >= deadline && !terminal) stop('wall_budget_exhausted');
    if (terminal) {
      observation = { success: false, before: null, after: null, result: { executed: false, status: 'not_run', reason: terminalCodes[terminal.reason] }, error: { code: terminalCodes[terminal.reason], message: 'This requested action was not run because the live session stopped.', stage: action.action } };
    } else {
      executedActions++;
      let timer, cleanupTimer;
      try {
        observation = await Promise.race([
          browser.execute(action, Math.max(1, Math.min(15000, statusOptions?.executionTimeoutMs ?? 15000, deadline - now())), statusOptions),
          ...(statusOptions?.cleanupTimeoutMs ? [new Promise((_resolve, reject) => { cleanupTimer = setTimeout(() => reject(new ToolError('AUDIT_CLEANUP_TIMEOUT', 'Bounded cleanup expired; the browser is stopped and restoration remains incomplete.')), Math.max(1, statusOptions.cleanupTimeoutMs)); })] : []),
          new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new ToolError('AUDIT_WALL_BUDGET_EXCEEDED', 'The live audit wall-clock budget was exhausted.')), Math.max(1, deadline - now())); }),
        ]);
      } catch (error) {
        stop(error.code === 'AUDIT_WALL_BUDGET_EXCEEDED' ? 'wall_budget_exhausted' : 'internal_error');
        observation = { success: false, before: browser.lastObservation?.state ?? null, after: null, result: { executed: true, status: 'error' }, error: errorRecord(error, action.action) };
      } finally { clearTimeout(timer); clearTimeout(cleanupTimer); }
    }
    if (action.action === 'fill' && observation.error) {
      // Playwright call logs can interpolate fill arguments on failure.
      observation.error = { code: observation.error.code, stage: 'fill', message: 'The fill action failed; the supplied input value is omitted.' };
    }
    const { pngBytes, ...body } = observation, { action: name, ...args } = retained;
    const record = { evidenceId, action: name, arguments: args, ...body };
    if (pngBytes) record.png = { ...await writeAuditArtifact(directory, `${evidenceId}.png`, pngBytes), ...pngDimensions(pngBytes) };
    record.json = await writeAuditArtifact(directory, `${evidenceId}.json`, `${JSON.stringify(record, null, 2)}\n`);
    records.push(immutable(record));
    if (record.error) errors.push({ ...record.error, evidenceId });
    if (executedActions >= manifest.maxActions && !terminal) {
      stop('action_budget_exhausted');
      void finish({ reason: 'action_budget_exhausted' }).catch(() => {});
    }
    return record;
  }

  function perform(inputAction, statusOptions) {
    if (phase !== 'open') return Promise.reject(new ToolError('AUDIT_SESSION_CLOSED', 'The live session is closing or sealed; no new actions are accepted.'));
    let action;
    try { action = parseAuditManifest({ ...manifest, actions: [inputAction] }).actions[0]; }
    catch (error) { invalidRequests++; errors.push(errorRecord(error, 'audit-live-action-validation')); return Promise.reject(error); }
    if (plan.length >= 500) {
      stop('action_budget_exhausted'); void finish({ reason: 'action_budget_exhausted' }).catch(() => {});
      return Promise.reject(new ToolError('AUDIT_ACTION_BUDGET_EXCEEDED', 'The live session cannot accept more than 500 requested actions.'));
    }
    const retained = retainedAction(action), evidenceId = `ev-${String(plan.length + 1).padStart(4, '0')}`;
    plan.push(immutable({ evidenceId, ...retained }));
    const task = queue.then(() => runAction(action, retained, evidenceId, statusOptions));
    queue = task.then(() => undefined, error => {
      errors.push(errorRecord(error, 'audit-live-artifact'));
      stop('internal_error'); void finish({ reason: 'internal_error' }).catch(() => {});
    });
    return task;
  }

  async function observeStatus(action) {
    const { selector, ...globalPress } = action.trigger;
    const trigger = action.trigger.action === 'press' ? globalPress : action.trigger;
    const tasks = [perform({ action: 'snapshot' }, { snapshot: true }),
      perform(trigger, { windowMs: action.windowMs, expectedText: action.expectedText,
        focusSelector: action.trigger.action === 'press' ? selector : undefined }),
      perform({ action: 'snapshot' }, { snapshot: true })];
    return Promise.all(tasks);
  }

  /** Read-only selector match counts in the live page (advisory; never recorded as evidence). null when no page is open. */
  function probeSelectors(selectors) {
    if (phase !== 'open' || terminal || !Array.isArray(selectors) || !selectors.length) return Promise.resolve(null);
    const task = queue.then(() => {
      if (terminal || now() >= deadline) return null;
      let timer;
      const timeout = new Promise(resolve => { timer = setTimeout(() => resolve(null), 2000); });
      return Promise.race([browser.probeSelectors(selectors.slice(0, 200)), timeout]).finally(() => clearTimeout(timer));
    }).catch(() => null);
    queue = task.then(() => undefined);
    return task;
  }

  const session = Object.freeze({ observeStatus, probeSelectors, runId, directory, manifest: retainedManifest, startedAt, deadlineAt: new Date(deadline).toISOString(), perform, finish, finished,
    get status() { return phase; }, get records() { return Object.freeze([...records]); } });
  lifecycle.signal?.addEventListener('abort', onAbort, { once: true });
  if (lifecycle.signal?.aborted) onAbort();
  wallTimer = setTimeout(() => {
    stop('wall_budget_exhausted');
    rejectOpening(new ToolError('AUDIT_WALL_BUDGET_EXCEEDED', 'The live audit wall-clock budget was exhausted.'));
    if (phase !== 'opening') void finish({ reason: 'wall_budget_exhausted' }).catch(() => {});
  }, Math.max(1, deadline - now()));
  try {
    await Promise.race([delay(EXECUTION_POLICY.sourceWatchWarmupMs), openingStopped]); await monitor.arm();
    sourceBefore = await fingerprint(root);
    if (now() >= deadline) throw new ToolError('AUDIT_WALL_BUDGET_EXCEEDED', 'The live audit wall-clock budget expired while opening.');
    if (terminal) throw new ToolError(terminalCodes[terminal.reason], 'Opening stopped.');
    const starting = browser.start();
    // AuditBrowser.start observes close() during launch/context creation. Also
    // close late completions from an injected adapter; never expose a late session.
    void starting.then(() => terminal ? browser.close() : undefined, () => {}).catch(() => {});
    const startup = Promise.race([starting, openingStopped]);
    queue = startup.then(() => undefined, () => undefined);
    Object.assign(versions, await startup);
    if (terminal || now() >= deadline) throw new ToolError('AUDIT_WALL_BUDGET_EXCEEDED', 'Opening stopped.');
    if (phase === 'opening') phase = 'open';
    return session;
  } catch (error) {
    errors.push(errorRecord(error, 'audit-live-open'));
    if (!sourceBefore) {
      clearTimeout(wallTimer); lifecycle.signal?.removeEventListener('abort', onAbort); monitor.close(); await browser.close();
      throw error;
    }
    const report = await finish({ reason: error.code === 'AUDIT_WALL_BUDGET_EXCEEDED' ? 'wall_budget_exhausted' : 'startup_error' });
    throw new ToolError('AUDIT_SESSION_START_FAILED', 'The live session could not open; its incomplete report was retained.', { reportPath: report.reportPath });
  }
}
