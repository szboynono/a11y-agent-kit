import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { digest, errorRecord, EXECUTION_POLICY, fingerprint, monitorSource, ToolError } from '../evidence.js';
import { AUDIT_SCHEMA_VERSION, resolveAuditStandard, DEFAULT_AUDIT_SELECTION, parseAuditManifest } from './schema.js';
import { AuditBrowser } from './browser.js';
import { createAuditDirectory, writeAuditArtifact, saveAuditDocument } from './store.js';
import { pngDimensions } from './pixels.js';
import { AUDIT_EVIDENCE_POLICY } from './policy.js';

const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

export function defaultAuditActions(viewport = { width: 1280, height: 900 }) {
  const actions = [
    { action: 'snapshot' }, { action: 'axe' }, { action: 'screenshot' },
    { action: 'viewport', width: 320, height: viewport.height }, { action: 'snapshot' }, { action: 'screenshot' },
    { action: 'viewport', ...viewport }, { action: 'spacing', enabled: true }, { action: 'snapshot' }, { action: 'screenshot' },
    { action: 'reset' }, { action: 'snapshot' }, { action: 'screenshot' },
  ];
  // A bounded sample of the actual document's Tab order, starting after a fresh
  // navigation. Each key has its own screenshot; this does not claim exhaustive
  // keyboard operability or a screen-reader test.
  for (let index = 0; index < 8; index++) actions.push({ action: 'press', key: 'Tab' }, { action: 'screenshot' });
  return actions;
}

async function withinBudget(operation, remaining) {
  if (remaining <= 0) throw new ToolError('AUDIT_WALL_BUDGET_EXCEEDED', 'The audit wall-clock budget was exhausted.');
  let timer;
  try {
    return await Promise.race([operation(), new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(new ToolError('AUDIT_WALL_BUDGET_EXCEEDED', 'The audit wall-clock budget was exhausted; the browser session was stopped.')), remaining);
    })]);
  } finally { clearTimeout(timer); }
}

function unexecuted(action, reason, message) {
  return { success: false, before: null, after: null, result: { executed: false, status: 'not_run', reason }, error: { code: reason, message, stage: action.action } };
}

function candidatesFor(records, catalog) {
  const candidates = [];
  for (const record of records) {
    if (!record.success || record.action !== 'axe') continue;
    for (const disposition of ['violations', 'incomplete']) {
      for (const rule of record.result.axe[disposition]) {
        const criterionIds = rule.tags.filter(tag => /^wcag\d{3,4}$/.test(tag)).map(tag => {
          const digits = tag.slice(4); return `${digits[0]}.${digits[1]}.${Number(digits.slice(2))}`;
        }).filter(id => catalog.criteria.some(criterion => criterion.id === id));
        candidates.push({ candidateId: `candidate-${String(candidates.length + 1).padStart(4, '0')}`, source: 'axe', disposition, ruleId: rule.id, criterionIds: [...new Set(criterionIds)], evidenceIds: [record.evidenceId], stateId: record.after?.stateId, documentId: record.after?.documentId, targets: rule.nodes.map(node => ({ selector: node.target, failureSummary: node.failureSummary || null })), status: 'needs_review', note: 'An automated observation is a candidate for independent review, not an established WCAG violation.' });
      }
    }
  }
  return candidates;
}

function coverageFor(candidates, catalog) {
  return catalog.criteria.map(criterion => {
    const relevant = candidates.filter(candidate => candidate.criterionIds.includes(criterion.id));
    return { id: criterion.id, level: criterion.level, url: criterion.url, status: relevant.length ? 'needs_review' : 'not_tested', evidenceIds: [...new Set(relevant.flatMap(candidate => candidate.evidenceIds))], scope: 'partial', note: relevant.length ? 'Partial automated candidates require evidence and criterion review; the whole criterion is unassessed.' : 'No whole-criterion assessment was performed. Observations elsewhere do not establish a pass.' };
  });
}

/** Collect local, reviewable browser observations without a model or upload. */
export async function collectAudit(input) {
  const manifest = parseAuditManifest({ ...input, standard: input?.standard === undefined ? DEFAULT_AUDIT_SELECTION : input.standard });
  const standard = resolveAuditStandard(manifest.standard);
  const retainedAction = action => action.action === 'fill' ? { ...action, value: '[omitted]' } : action;
  const retainedManifest = { ...manifest, ...(manifest.actions ? { actions: manifest.actions.map(retainedAction) } : {}) };
  const root = await fs.realpath(manifest.projectRoot);
  if (root !== manifest.projectRoot || !(await fs.stat(root)).isDirectory()) throw new ToolError('UNSAFE_AUDIT_PATH', 'projectRoot must be a real canonical directory without symlinks.');
  const runId = randomUUID(), directory = await createAuditDirectory(root, runId);
  const startedAt = new Date().toISOString(), started = Date.now(), deadline = started + manifest.wallSeconds * 1000;
  const plan = manifest.actions ?? defaultAuditActions(manifest.viewport);
  const monitor = monitorSource(root);
  const records = [], errors = [], versions = { node: process.versions.node };
  let sourceBefore, sourceAfter, sourceStability, fatal = null, executedActions = 0;
  const browser = new AuditBrowser(manifest);
  try {
    await delay(EXECUTION_POLICY.sourceWatchWarmupMs);
    await monitor.arm();
    sourceBefore = await fingerprint(root);
    if (plan.length) {
      try { Object.assign(versions, await withinBudget(() => browser.start(), deadline - Date.now())); }
      catch (error) { fatal = errorRecord(error, 'audit-browser-start'); errors.push(fatal); await browser.close(); }
    }
    for (const [index, action] of plan.entries()) {
      let observation;
      if (index >= manifest.maxActions) {
        observation = unexecuted(action, 'AUDIT_ACTION_BUDGET_EXCEEDED', 'This planned action was not executed because the action budget was exhausted.');
      } else if (Date.now() >= deadline) {
        observation = unexecuted(action, 'AUDIT_WALL_BUDGET_EXCEEDED', 'This planned action was not executed because the wall-clock budget was exhausted.');
      } else if (fatal) {
        observation = unexecuted(action, 'AUDIT_BROWSER_UNAVAILABLE', 'This planned action was not executed because the browser session was unavailable.');
      } else {
        executedActions++;
        try { observation = await withinBudget(() => browser.execute(action, Math.max(1, Math.min(15000, deadline - Date.now()))), deadline - Date.now()); }
        catch (error) {
          fatal = errorRecord(error, action.action);
          observation = { success: false, before: browser.lastObservation?.state || null, after: null, result: { executed: true, status: 'error' }, error: fatal };
          await browser.close();
        }
      }
      const { pngBytes, ...body } = observation;
      const { action: name, ...arguments_ } = retainedAction(action);
      const record = { evidenceId: `ev-${String(index + 1).padStart(4, '0')}`, action: name, arguments: arguments_, ...body };
      if (pngBytes) record.png = { ...await writeAuditArtifact(directory, `${record.evidenceId}.png`, pngBytes), ...pngDimensions(pngBytes) };
      record.json = await writeAuditArtifact(directory, `${record.evidenceId}.json`, `${JSON.stringify(record, null, 2)}\n`);
      records.push(record);
      if (record.error) errors.push({ ...record.error, evidenceId: record.evidenceId });
    }
  } finally {
    errors.push(...await browser.close());
    if (sourceBefore) {
      try { sourceAfter = await fingerprint(root); }
      catch (error) { errors.push(errorRecord(error, 'audit-source-fingerprint-after-run')); }
    }
    await delay(EXECUTION_POLICY.sourceWatchSettleMs);
    await monitor.settle();
    monitor.close();
    sourceStability = monitor.snapshot();
  }
  const unchanged = sourceBefore?.digest === sourceAfter?.digest && sourceStability.status === 'stable_observed';
  errors.push(...sourceStability.errors);
  if (!unchanged) errors.push({ code: 'AUDIT_SOURCE_CHANGED_DURING_RUN', message: 'Source changed, a write was observed, or stable source could not be established throughout this collection.' });
  const candidates = candidatesFor(records, standard);
  return saveAuditDocument(directory, 'audit', {
    schemaVersion: AUDIT_SCHEMA_VERSION, evidencePolicy: AUDIT_EVIDENCE_POLICY, runId, manifest: retainedManifest, manifestDigest: digest(retainedManifest), standard,
    startedAt, completedAt: new Date().toISOString(), status: errors.length ? (records.some(record => record.success) ? 'partial' : 'error') : 'collected',
    applicationBinding: 'caller-declared', applicationBindingNote: 'The caller declares that this URL serves projectRoot. Source-to-build or deployment provenance is not attested.',
    codeFingerprint: sourceBefore, codeFingerprintAfterRun: sourceAfter, sourceStability,
    ...(manifest.networkReplay ? { networkReplay: browser.networkReplayReport() } : {}),
    executionPolicy: { actionTimeoutMs: 3000, navigationTimeoutMs: 15000, waitUntil: 'domcontentloaded', serviceWorkers: 'block', navigationOrigin: new URL(manifest.url).origin, axeTags: [...browser.axeTags], screenshotStateBinding: 'matching before/after observed state IDs', screenshotAnimations: 'disabled', screenshotCaret: 'initial', finiteAnimationSettleMs: 1500, keyboardMethod: 'global-page-keyboard-without-selector-focus' },
    plan: plan.map((action, index) => ({ evidenceId: `ev-${String(index + 1).padStart(4, '0')}`, ...retainedAction(action) })),
    summary: { plannedActions: plan.length, executedActions, successfulActions: records.filter(record => record.success).length, failedActions: records.filter(record => !record.success && record.result?.status !== 'not_run').length, notRunActions: records.filter(record => record.result?.status === 'not_run').length, candidates: candidates.length, wholeCriteriaAssessed: 0, conformanceStatus: 'not_assessed', durationMs: Date.now() - started },
    records, candidates, coverage: coverageFor(candidates, standard), errors, versions,
    limitations: [
      'This is a bounded collection of observations, not a whole-site audit or WCAG conformance verdict. All selected success criteria remain unassessed as whole criteria.',
      'Axe violations and incomplete results are retained as candidates; an independent evidence review is required before publishing a finding.',
      'Native browser ARIA snapshots are not VoiceOver/JAWS output. No real screen reader was operated.',
      'Main-document DOM observations omit child-frame DOM and shadow-root DOM, and report truncation explicitly. Rendered text is not proof of unclipped pixels.',
      'Screenshots are bracketed by DOM observations; changing observed states fail capture. Browser timing and unobserved content limit that stability observation.',
      'Finite CSS transitions are allowed to settle for up to 1500 ms. Screenshots disable animations and retain the caret; they do not establish timing behavior or persistent focus visibility over time.',
      'The default eight Tab presses sample keyboard navigation. Click/fill mark the path mouse-assisted; a reset returns to a new document’s initial focus.',
      'Contrast samples measure supplied opaque screenshot pixels and retain their neighborhood colors and quality flags; intended foreground/background, text identity, size, exceptions and criterion applicability require independent review.',
      'Local digests detect changed bytes; they are not signatures or protection against a local owner rewriting all evidence.',
      'Fill arguments, ARIA input values and password/hidden input values are omitted from retained reports; original input values are not replay credentials. Inline script text and axe HTML snippets are omitted in favor of separately captured DOM. Other page content can still be sensitive; this is not a general secret scanner.',
      ...(manifest.networkReplay ? ['Exact local HTTP(S)/WebSocket routing is an explicit replay environment. Unfrozen external features are unavailable; policy blocks and resource errors induced by this environment are not natural-site WCAG findings. This is not an OS airgap or a WebRTC/DNS/speculation firewall.'] : []),
    ],
  });
}
