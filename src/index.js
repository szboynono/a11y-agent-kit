import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import { standardMetadata, coverageMetadata } from './wcag.js';
import {
  SCHEMA_VERSION, EXECUTION_POLICY, ToolError, errorRecord, parseManifest, canonicalRoot,
  fingerprint, monitorSource, contractDigest, newRunId, saveReport, readReport,
} from './evidence.js';

export { manifestSchema, assertionSchema, stepSchema, SUPPORTED_RULES } from './schema.js';

// The audit workflow is independent of the frozen repair/check contract.
export async function openAuditSession(input) {
  return (await import('./audit/live.js')).openAuditSession(input);
}
export async function openAuditAgent(input) {
  return (await import('./audit/agent.js')).openAuditAgent(input);
}
export async function readAuditCheckpoint(checkpointPath) {
  return (await import('./audit/checkpoint.js')).readAuditCheckpoint(checkpointPath);
}
export async function recoverAuditCheckpoint(directory) {
  return (await import('./audit/checkpoint.js')).recoverAuditCheckpoint(directory);
}
export async function submitAuditCheckpoint(auditPath, checkpointPath) {
  return (await import('./audit/agent.js')).submitAuditCheckpoint(auditPath, checkpointPath);
}
export async function collectAudit(input) {
  return (await import('./audit/collect.js')).collectAudit(input);
}
export async function submitAudit(reportPath, input) {
  return (await import('./audit/review.js')).submitAudit(reportPath, input);
}
export async function reviewAudit(proposalPath, input, options) {
  return (await import('./audit/review.js')).reviewAudit(proposalPath, input, options);
}
export async function checkAudit(reportPath) {
  return (await import('./audit/review.js')).checkAudit(reportPath);
}

const require = createRequire(import.meta.url);
const versions = {
  node: process.versions.node,
  axeCore: require('axe-core/package.json').version,
  axePlaywright: JSON.parse(readFileSync(path.resolve(path.dirname(require.resolve('@axe-core/playwright')), '../package.json'), 'utf8')).version,
  playwright: require('playwright/package.json').version,
  browser: null,
};

function blankState(state) {
  return {
    id: state.id,
    reached: false,
    status: 'error',
    steps: state.steps.map(step => ({ ...step, status: 'not_run' })),
    assertions: state.assertions.map(assertion => ({ ...assertion, status: 'not_run' })),
    axe: null,
    errors: [],
  };
}

async function assertCondition(page, assertion) {
  const locator = page.locator(`css=${assertion.selector}`);
  const deadline = Date.now() + EXECUTION_POLICY.assertionTimeoutMs;
  let actual;
  do {
    const count = await locator.count();
    if (assertion.type === 'count') {
      actual = count;
    } else if (count !== 1) {
      actual = { count, message: 'This assertion requires exactly one matching element.' };
    } else if (assertion.type === 'visible') {
      actual = await locator.isVisible();
    } else if (assertion.type === 'enabled') {
      actual = await locator.isEnabled();
    } else if (assertion.type === 'focused') {
      actual = await locator.evaluate(element => element.matches(':focus'));
    } else {
      actual = await locator.textContent();
    }
    const expected = 'value' in assertion ? assertion.value : true;
    if (actual === expected) return { ...assertion, status: 'passed', expected, actual };
    if (Date.now() < deadline) await delay(50);
  } while (Date.now() < deadline);
  return { ...assertion, status: 'failed', expected: 'value' in assertion ? assertion.value : true, actual };
}

async function scanState(browser, manifest, state) {
  const result = blankState(state);
  let context;
  let stage = 'context';
  try {
    context = await browser.newContext({ viewport: manifest.viewport, serviceWorkers: EXECUTION_POLICY.serviceWorkers });
    context.setDefaultTimeout(EXECUTION_POLICY.actionTimeoutMs);
    context.setDefaultNavigationTimeout(EXECUTION_POLICY.navigationTimeoutMs);
    const page = await context.newPage();
    page.on('pageerror', error => result.errors.push(errorRecord(error, 'page-script')));
    page.on('response', response => {
      const request = response.request();
      if (request.isNavigationRequest() && request.frame() === page.mainFrame()) {
        result.url = response.url();
        result.httpStatus = response.status();
        if (response.status() >= 400) {
          result.errors.push({ code: 'HTTP_ERROR', message: `A page navigation returned HTTP ${response.status()}.`, stage: 'navigation' });
        }
      }
    });
    stage = 'navigation';
    const response = await page.goto(manifest.url, { waitUntil: EXECUTION_POLICY.waitUntil });
    result.url = page.url();
    result.httpStatus = response?.status() ?? null;
    if (!response || !response.ok()) {
      throw new ToolError('HTTP_ERROR', `Navigation returned HTTP ${response?.status() ?? 'no response'}.`);
    }
    stage = 'selectors';
    await page.evaluate(selectors => {
      for (const selector of selectors) document.querySelectorAll(selector);
    }, [...state.steps, ...state.assertions].map(item => item.selector));
    for (let index = 0; index < state.steps.length; index++) {
      const step = state.steps[index];
      stage = `step:${index}`;
      const locator = page.locator(`css=${step.selector}`);
      try {
        if (step.action === 'click') await locator.click();
        else if (step.action === 'press') await locator.press(step.key);
        else await locator.waitFor({ state: 'visible' });
        result.steps[index] = { ...step, status: 'passed' };
      } catch (error) {
        result.steps[index] = { ...step, status: 'error', error: errorRecord(error, stage) };
        throw error;
      }
    }
    result.reached = true;
    for (let index = 0; index < state.assertions.length; index++) {
      stage = `assertion:${index}`;
      try {
        result.assertions[index] = await assertCondition(page, state.assertions[index]);
      } catch (error) {
        const detail = errorRecord(error, stage);
        result.assertions[index] = { ...state.assertions[index], status: 'error', error: detail };
        result.errors.push(detail);
      }
    }
    stage = 'axe';
    result.axe = await new AxeBuilder({ page }).withRules(manifest.rules).analyze();
  } catch (error) {
    result.errors.push(errorRecord(error, stage));
  } finally {
    if (context) await context.close().catch(error => result.errors.push(errorRecord(error, 'context-close')));
  }
  if (result.errors.length || !result.reached || !result.axe) result.status = 'error';
  else if (result.assertions.some(assertion => assertion.status !== 'passed') || result.axe.violations.length) result.status = 'failed';
  else if (!result.assertions.length || result.axe.incomplete.length) result.status = 'needs_review';
  else result.status = 'passed';
  return result;
}

async function run(manifest, kind, baseline, baselineStandard) {
  const runId = newRunId();
  const startedAt = new Date().toISOString();
  const monitor = monitorSource(manifest.projectRoot);
  // macOS can deliver queued creation notifications when a new watch starts.
  // Arm on a delivered marker before the initial snapshot; setup history is
  // outside the scan window however late its notifications arrive.
  await delay(EXECUTION_POLICY.sourceWatchWarmupMs);
  await monitor.arm();
  let codeFingerprint;
  try {
    codeFingerprint = await fingerprint(manifest.projectRoot);
  } catch (error) {
    monitor.close();
    throw error;
  }
  const errors = [];
  const states = [];
  const runVersions = { ...versions };
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    runVersions.browser = browser.version();
    for (const state of manifest.states) states.push(await scanState(browser, manifest, state));
  } catch (error) {
    errors.push(errorRecord(error, 'browser'));
    for (const state of manifest.states.slice(states.length)) states.push(blankState(state));
  } finally {
    if (browser) await browser.close().catch(error => errors.push(errorRecord(error, 'browser-close')));
  }
  let currentFingerprint;
  try {
    currentFingerprint = await fingerprint(manifest.projectRoot);
  } catch (error) {
    errors.push(errorRecord(error, 'source-fingerprint-after-run'));
  }
  await delay(EXECUTION_POLICY.sourceWatchSettleMs);
  await monitor.settle();
  monitor.close();
  const sourceStability = monitor.snapshot();
  const unchanged = currentFingerprint?.digest === codeFingerprint.digest && sourceStability.status === 'stable_observed';
  errors.push(...sourceStability.errors);
  if (!unchanged) errors.push({ code: 'SOURCE_CHANGED_DURING_RUN', message: 'Source changed, a write was observed, or stability could not be established during this run; re-run on stable source.' });
  const summary = {
    states: states.length,
    reachedStates: states.filter(state => state.reached).length,
    assertions: states.reduce((total, state) => total + state.assertions.length, 0),
    failedAssertions: states.reduce((total, state) => total + state.assertions.filter(assertion => assertion.status === 'failed').length, 0),
    erroredAssertions: states.reduce((total, state) => total + state.assertions.filter(assertion => assertion.status === 'error').length, 0),
    notRunAssertions: states.reduce((total, state) => total + state.assertions.filter(assertion => assertion.status === 'not_run').length, 0),
    nonPassingAssertions: states.reduce((total, state) => total + state.assertions.filter(assertion => assertion.status !== 'passed').length, 0),
    violations: states.reduce((total, state) => total + (state.axe?.violations.length ?? 0), 0),
    incomplete: states.reduce((total, state) => total + (state.axe?.incomplete.length ?? 0), 0),
    statesWithoutAssertions: manifest.states.filter(state => !state.assertions.length).map(state => state.id),
  };
  let status;
  if (errors.length || states.some(state => state.status === 'error')) status = 'error';
  else if (states.some(state => state.status === 'failed')) status = 'failed';
  else if (states.some(state => state.status === 'needs_review')) status = 'needs_review';
  else status = 'passed';
  const reviewReasons = [];
  if (summary.statesWithoutAssertions.length) reviewReasons.push({ code: 'MISSING_FUNCTIONAL_ASSERTIONS', states: summary.statesWithoutAssertions });
  if (summary.incomplete) reviewReasons.push({ code: 'AXE_INCOMPLETE', count: summary.incomplete });
  return saveReport({
    schemaVersion: SCHEMA_VERSION,
    kind, runId, startedAt, completedAt: new Date().toISOString(), status,
    validity: unchanged ? 'current' : 'expired',
    standard: standardMetadata(),
    coverage: coverageMetadata(manifest.rules),
    applicationBinding: 'caller-declared',
    applicationBindingNote: 'The caller declares that this URL serves this project. Source-to-build/deployment provenance is not verified.',
    manifest,
    executionPolicy: { ...EXECUTION_POLICY },
    contractDigest: contractDigest(manifest),
    codeFingerprint,
    sourceStability,
    ...(currentFingerprint && !unchanged ? { codeFingerprintAfterRun: currentFingerprint } : {}),
    versions: runVersions,
    baseline: baseline ?? null,
    baselineStandard: baselineStandard ?? null,
    summary, reviewReasons, errors, states,
    limitations: [
      'The target is WCAG 2.1 Level AA (A and AA); partial selected-check evidence does not establish success-criterion satisfaction or WCAG conformance.',
      'Only the declared states, assertions, and supported axe rules are checked; this is not whole-site compliance.',
      'Functional removal or hiding is detected only when the frozen assertions cover it.',
      'Generated directories listed in codeFingerprint are excluded; source symlinks are unsupported.',
      'Report digests detect edits but are not signatures or proof against an owner deliberately forging evidence.',
      'Source monitoring uses filesystem notifications and content snapshots; it is an observation, not source-to-build attestation or proof that every possible transient write was observed.',
    ],
  });
}

export async function analyze(input) {
  const manifest = parseManifest(input);
  manifest.projectRoot = await canonicalRoot(manifest.projectRoot);
  return run(manifest, 'analyze');
}

export async function verify(baselinePath) {
  if (arguments.length !== 1) throw new ToolError('INVALID_ARGUMENTS', 'verify accepts only baselinePath; scope overrides are not supported.');
  const { report: baseline, reportPath } = await readReport(baselinePath);
  if (baseline.kind !== 'analyze') throw new ToolError('INVALID_BASELINE', 'verify requires an analyze report as the frozen baseline.');
  return run(baseline.manifest, 'verify', {
    reportPath, runId: baseline.runId, reportDigest: baseline.reportDigest,
  }, baseline.standard ? {
    metadataStatus: 'recorded',
    rubricId: baseline.standard.rubric.id,
    rubricDigest: baseline.standard.rubric.digest,
    conformanceStatus: baseline.standard.conformanceStatus,
  } : { metadataStatus: 'legacy_unspecified' });
}

export async function checkEvidence(reportPath) {
  try {
    const { report, reportPath: absolutePath } = await readReport(reportPath);
    const currentFingerprint = await fingerprint(report.manifest.projectRoot);
    const current = report.validity === 'current' && currentFingerprint.digest === report.codeFingerprint.digest;
    return {
      schemaVersion: SCHEMA_VERSION,
      status: current ? 'current' : 'expired',
      reportPath: absolutePath,
      reportStatus: report.status,
      statusMeaning: 'evidence-freshness-only',
      standardMetadataStatus: report.standard ? 'recorded' : 'legacy_unspecified',
      standard: report.standard ?? null,
      runId: report.runId,
      contractDigest: report.contractDigest,
      applicationBinding: 'caller-declared',
      recordedFingerprint: report.codeFingerprint,
      currentFingerprint,
      reasons: current ? [] : [report.validity === 'expired' ? 'SOURCE_CHANGED_DURING_RUN' : 'SOURCE_CHANGED'],
    };
  } catch (error) {
    return { schemaVersion: SCHEMA_VERSION, status: 'error', errors: [errorRecord(error, 'check-evidence')] };
  }
}
