/**
 * Deterministic, opt-in startup interaction sweep run by the product itself after the startup snapshot + axe.
 *
 * 1. Keyboard traversal: global Tab presses from the page start, recorded as ordinary `press` records, stopping on a
 *    focus cycle or when focus leaves the document; then one `reset` (the product's existing restore: reload the entry URL).
 * 2. Narrow viewport: when the manifest declares one, one screenshot + snapshot at it, then the original viewport again.
 *
 * The sweep sends no Enter/Space, clicks or form input. Focus/blur handlers can issue requests, navigate or persist state; reset does not undo those effects. Every action goes through the caller's
 * `perform`, which counts it in the session budget; a failure is reported in `error`, never thrown.
 */
import { stableSelectorIndex } from './stable-selector.js';
import { viewportLabel } from './coverage.js';

export const SWEEP_VERSION = 'startup-sweep-1';
export const SWEEP_LIMITS = Object.freeze({ tabPresses: 25, maxMs: 45_000, cleanupMs: 30_000, nameChars: 40, selectorChars: 120 });
/** Response bytes the startup step leaves free for `startup.sweep` (the axe page shrinks by this much; the rest pages via read). */
export const SWEEP_RESERVE_BYTES = 5_000;
const NARROW_ACTIONS = 4;
const RESTORE_ACTIONS = 1;
const OMITTED_NOTE = 'Names or rows omitted for size; every press is an ordinary record: read its evidenceId (after.active) for the focused element.';

const documentFocus = active => !active || ['body', 'html'].includes(String(active.tag ?? '').toLowerCase());
const clip = (value, max) => typeof value === 'string' && value.trim() ? value.replace(/\s+/g, ' ').trim().slice(0, max) : null;

/** The recorded DOM name hint of a focused element: label text (aria-label, labelledby, label, alt) or text content. Not a computed AX name. */
function nameOf(active) {
  const label = clip(active.labelText, SWEEP_LIMITS.nameChars);
  if (label) return { name: label, nameSource: 'label' };
  const text = clip(active.text, SWEEP_LIMITS.nameChars);
  return text ? { name: text, nameSource: 'text' } : {};
}

/** The narrowest declared in-scope viewport narrower than the manifest viewport, or null. */
export function narrowViewportFor(viewports, base) {
  const narrower = (viewports ?? []).filter(v => Number.isInteger(v?.width) && Number.isInteger(v?.height) && v.width < base.width);
  return narrower.sort((a, b) => a.width - b.width || a.height - b.height)[0] ?? null;
}

/**
 * input: { perform(action) -> record (counts budget; may throw), records() -> retained records, remainingActions,
 *          now(), deadline (soft exploration cutoff; cleanup has its own bounded reserve), viewport (manifest), viewports (declared, in scope),
 *          tabLimit? }
 * Returns the bounded `startup.sweep` summary plus the evidence IDs it created.
 */
export async function runStartupSweep(input) {
  const { perform, records, now } = input;
  const limit = Math.min(input.tabLimit ?? SWEEP_LIMITS.tabPresses, SWEEP_LIMITS.tabPresses);
  const deadline = Math.min(input.deadline, now() + SWEEP_LIMITS.maxMs);
  const out = { version: SWEEP_VERSION, ran: [], tabPresses: 0, distinctFocused: 0, stopped: null, focusOrder: [], focusLost: [], abstentions: [] };
  const evidenceIds = [];
  let cleanupRemainingMs = SWEEP_LIMITS.cleanupMs, cleanupActions = 2;
  const run = async (action, cleanup = false) => {
    const timeoutMs = cleanup ? cleanupRemainingMs : deadline - now();
    if (timeoutMs <= 0 || (cleanup && cleanupActions-- <= 0)) throw Object.assign(new Error('Sweep work or cleanup allowance exhausted.'), { code: 'AUDIT_SWEEP_TIME' });
    const at = now();
    try {
      const record = await perform(action, { cleanup, timeoutMs });
      evidenceIds.push(record.evidenceId);
      return record;
    } finally { if (cleanup) cleanupRemainingMs -= Math.max(0, now() - at); }
  };
  // The sweep spends at most half the actions left after startup, so the host keeps the larger share.
  let allowance = Math.floor(Math.max(0, input.remainingActions) / 2);
  const narrow = narrowViewportFor(input.viewports, input.viewport);
  const declared = (input.viewports ?? []).map(viewportLabel).filter(Boolean);
  let narrowPlanned = Boolean(narrow);
  let tabs = Math.min(limit, allowance - RESTORE_ACTIONS - (narrowPlanned ? NARROW_ACTIONS : 0));
  if (tabs < 2 && narrowPlanned) { narrowPlanned = false; tabs = Math.min(limit, allowance - RESTORE_ACTIONS); out.abstentions.push(`narrow viewport ${viewportLabel(narrow)}: not enough actions left for both checks; keyboard traversal ran first`); }
  if (!narrow) out.abstentions.push(declared.length ? `narrow viewport: none of the declared viewports (${declared.join(', ')}) is narrower than the manifest viewport` : 'narrow viewport: none declared in manifest viewports');
  for (const label of declared.filter(label => narrow && label !== viewportLabel(narrow) && label !== viewportLabel(input.viewport))) out.abstentions.push(`viewport ${label}: declared but not captured by the sweep (one narrow viewport only)`);

  const failure = error => ({ code: String(error?.code ?? 'AUDIT_SWEEP_ERROR').slice(0, 80), message: String(error?.message ?? error).slice(0, 300) });
  try {
    if (tabs >= 2) {
      out.ran.push('tab traversal');
      const start = [...records()].reverse().find(record => record.success && record.after?.documentId);
      const documentId = start?.after?.documentId ?? null, url = start?.after?.url ?? null;
      const seen = new Set();
      if (start && !documentFocus(start.after.active)) { seen.add(start.after.active.nodeId); out.initialFocus = { nodeId: start.after.active.nodeId, tag: start.after.active.tag }; }
      let previous = start && !documentFocus(start.after.active) ? start.after.active : null, pendingLoss = null, onDocument = 0;
      out.stopped = 'limit';
      let pressAttempted = false;
      try { for (let step = 1; step <= tabs; step++) {
        if (now() >= deadline) { out.stopped = 'time'; break; }
        pressAttempted = true;
        const record = await run({ action: 'press', key: 'Tab' });
        if (!record.success) { out.stopped = 'press_failed'; out.pressError = record.error?.code ?? 'AUDIT_ACTION_ERROR'; break; }
        out.tabPresses++;
        if (documentId && record.after?.documentId !== documentId) { out.stopped = 'document_changed'; break; }
        const active = record.after?.active;
        if (documentFocus(active)) {
          // Focus on <body>/<html>: either the end of the tab order (the next Tab wraps to a seen element) or a mid-sequence loss.
          if (++onDocument >= 2) { out.stopped = 'left_document'; pendingLoss = null; break; }
          pendingLoss = { step, evidenceId: record.evidenceId, focusedTag: active?.tag ?? null, ...(previous ? { fromNodeId: previous.nodeId, fromSelector: clip(previous.selector, SWEEP_LIMITS.selectorChars) } : {}) };
          continue;
        }
        onDocument = 0;
        if (seen.has(active.nodeId)) { out.stopped = pendingLoss ? 'cycle_after_document' : 'cycle'; pendingLoss = null; break; }
        if (pendingLoss) { out.focusLost.push(pendingLoss); pendingLoss = null; }
        seen.add(active.nodeId); previous = active;
        out.focusOrder.push({ step, evidenceId: record.evidenceId, nodeId: active.nodeId, tag: active.tag ?? null, selector: clip(active.selector, SWEEP_LIMITS.selectorChars), ...nameOf(active) });
      } } catch (error) { out.error = failure(error); out.stopped = 'error'; pendingLoss = null; }
      finally {
        if (pressAttempted) {
          try {
            const restore = await run({ action: 'reset' }, true);
            out.restore = { method: 'reset', evidenceId: restore.evidenceId, success: restore.success, url,
              note: 'Reload is a new unscanned document. Site side effects are not rolled back.' };
            if (!restore.success) out.error ??= failure(restore.error ?? new Error('Reset failed.'));
          } catch (error) { out.restore = { method: 'reset', success: false, unperformed: true, errorCode: error.code }; out.error ??= failure(error); }
        }
      }
      if (pendingLoss) out.abstentions.push(`focus on <${pendingLoss.focusedTag ?? 'body'}> after the last press (${pendingLoss.evidenceId}): end of tab order or focus loss not distinguished`);
      out.distinctFocused = out.focusOrder.length;
      // Reload-stable selectors from the entry snapshot of the same document state, where one exists.
      try {
        const snapshot = [...records()].reverse().find(record => record.success && record.action === 'snapshot' && record.after?.documentId === documentId);
        if (snapshot) {
          const index = stableSelectorIndex(records());
          for (const row of out.focusOrder) {
            const { stableSelector, stableSelectorConfidence } = index.fieldsFor({ evidenceId: snapshot.evidenceId, nodeId: row.nodeId });
            if (!stableSelector) continue;
            Object.assign(row, { stableSelector: clip(stableSelector, SWEEP_LIMITS.selectorChars), stableSelectorConfidence });
            if (row.stableSelector === row.selector) delete row.selector;
          }
          out.targetEvidenceId = snapshot.evidenceId;
        }
      } catch { /* Advisory selectors only. */ }
    } else out.abstentions.push('tab traversal: not enough actions left');

    if (narrowPlanned && (out.error || out.restore?.success === false)) out.abstentions.push(`narrow viewport ${viewportLabel(narrow)}: skipped after a sweep error`);
    else if (narrowPlanned && now() < deadline) {
      out.ran.push('narrow viewport');
      const label = viewportLabel(narrow), row = { viewport: label };
      out.narrow = row;
      try {
        const set = await run({ action: 'viewport', width: narrow.width, height: narrow.height });
        if (set.success) {
          const shot = await run({ action: 'screenshot' });
          if (shot.success && shot.png) row.screenshotEvidenceId = shot.evidenceId; else row.screenshotError = shot.error?.code ?? 'NO_SCREENSHOT';
          const snap = await run({ action: 'snapshot' });
          if (snap.success) row.snapshotEvidenceId = snap.evidenceId; else row.snapshotError = snap.error?.code ?? 'AUDIT_ACTION_ERROR';
        } else row.viewportError = set.error?.code ?? 'AUDIT_ACTION_ERROR';
      } finally {
        row.restored = false;
        try {
          const back = await run({ action: 'viewport', width: input.viewport.width, height: input.viewport.height }, true);
          row.restoredViewport = viewportLabel(input.viewport); row.restoreEvidenceId = back.evidenceId; row.restored = back.success;
          if (!back.success) out.error ??= failure(back.error ?? new Error('Viewport restoration failed.'));
        } catch (error) { row.restoreError = failure(error); out.error ??= failure(error); }
      }
    } else if (narrowPlanned) out.abstentions.push(`narrow viewport ${viewportLabel(narrow)}: sweep time cap reached`);
  } catch (error) {
    out.error ??= failure(error);
    out.distinctFocused = out.focusOrder.length;
  }
  out.complete = !out.error;
  return { sweep: out, evidenceIds };
}

/** Fits the summary into `room` bytes: drops names, then trailing focus-order rows (counted), then focusLost rows. */
export function fitSweep(sweep, room) {
  const size = value => Buffer.byteLength(JSON.stringify(value));
  if (size(sweep) <= room) return sweep;
  const order = Array.isArray(sweep.focusOrder) ? sweep.focusOrder : [], lost = Array.isArray(sweep.focusLost) ? sweep.focusLost : [];
  // Anything dropped from here on is named by the note, which is counted in the size from the start.
  let value = { ...sweep, focusLost: lost, focusOrder: order.map(({ name: _n, nameSource: _s, selector, stableSelector, ...row }) => ({ ...row, ...(stableSelector ? { stableSelector } : { selector }) })), omittedNote: OMITTED_NOTE };
  const total = value.focusOrder.length;
  while (value.focusOrder.length && size(value) > room) value = { ...value, focusOrder: value.focusOrder.slice(0, -1), focusOrderOmitted: total - value.focusOrder.length + 1 };
  while (value.focusLost.length && size(value) > room) value = { ...value, focusLost: value.focusLost.slice(0, -1), focusLostOmitted: (value.focusLostOmitted ?? 0) + 1 };
  if (size(value) <= room) return value;
  // Counts and evidence handles only; every detail stays in the retained records.
  const { version, counted, evidence, tabPresses, distinctFocused, stopped, restore, narrow, error } = sweep;
  value = { version, counted, evidence, tabPresses, distinctFocused, stopped, focusOrderOmitted: total, focusLostOmitted: lost.length,
    ...(restore ? { restore: { evidenceId: restore.evidenceId, success: restore.success } } : {}),
    ...(narrow?.screenshotEvidenceId ? { narrow: { viewport: narrow.viewport, screenshotEvidenceId: narrow.screenshotEvidenceId } } : {}),
    ...(error ? { error: { code: error.code } } : {}), omittedNote: OMITTED_NOTE };
  return size(value) <= room ? value : { version, evidence, omittedNote: OMITTED_NOTE };
}
