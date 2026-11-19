import * as fs from 'node:fs/promises';
import path from 'node:path';
import { reviewPolicyOf, requiresReReview } from './review-policy.js';
import { createHash, randomUUID } from 'node:crypto';
import { deriveAuditInventory } from './inventory.js';
import { ToolError } from '../evidence.js';
import { stableSelectorIndex, STABLE_SELECTOR_CONFIDENCE } from './stable-selector.js';

// Pure rendering: reads only local report/evidence files, never the network or a model. Output is built from a
// fixed whitelist of report fields, so retained-record fields (node values, attributes, axe HTML) cannot leak in.
export const REPORT_LIMITS = Object.freeze({
  text: 2000, selector: 500, findings: 2000, missing: 20,
  imageBytes: 1024 * 1024, imagesTotalBytes: 6 * 1024 * 1024, images: 24, evidenceFileBytes: 32 * 1024 * 1024,
});
const KINDS = { 'audit-review': 'reviewed', 'audit-proposal': 'proposal', 'audit-checkpoint-1': 'checkpoint' };
const EVIDENCE_ID = /^ev-\d{4,12}$/;
const PNG_SIGNATURE = Buffer.from('89504e470d0a1a0a', 'hex');
const STATUS_LABEL = { confirmed: 'Confirmed', needs_review: 'Needs review', rejected: 'Rejected by reviewer' };

const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
const clipDefault = (value, limit = REPORT_LIMITS.text) => {
  const text = typeof value === 'string' ? value : value === undefined || value === null ? '' : JSON.stringify(value);
  const chars = [...text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '�')];
  return chars.length > limit ? `${chars.slice(0, limit).join('')}… [truncated]` : chars.join('');
};
const clip = clipDefault;
// Bounded delivery preserves all whitelisted text; only unsafe control characters are replaced.
const fullText = value => (typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value)).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '�');
const array = value => Array.isArray(value) ? value : [];
const criterionKey = id => String(id ?? '').split('.').map(part => part.padStart(3, '0')).join('.');
const safeW3cUrl = url => typeof url === 'string' && /^https:\/\/www\.w3\.org\/[\w\-./#?=%]*$/.test(url) ? url : null;

function fail(message) { throw new ToolError('INVALID_AUDIT_REPORT', message); }

/** Normalize a checkpoint, needs-review proposal or reviewed report into one finding list. */
export function normalizeAuditReport(report) {
  const mode = report && typeof report === 'object' ? KINDS[report.kind] : undefined;
  if (!mode) fail('Expected an audit-review, audit-proposal or audit-checkpoint-1 JSON file.');
  const source = mode === 'checkpoint' ? report.proposal : report;
  const reReview = requiresReReview(report);
  if (!source || !Array.isArray(source.findings)) fail('The report has no findings array.');
  const decisions = new Map(array(report.decisions).map(decision => [decision?.findingId, decision]));
  const byId = (rows, status) => new Map(array(rows).map(row => [row?.id, { row, status }]));
  const placed = new Map([
    ...byId(report.verificationQueue, 'queue'), ...byId(report.rejectedObservations, 'rejected'), ...byId(report.confirmedFindings, 'confirmed'),
  ]);
  const findings = source.findings.map(finding => {
    const hit = placed.get(finding?.id), row = hit?.row ?? finding;
    let status = 'needs_review';
    if (hit?.status === 'confirmed' && !reReview) status = 'confirmed';
    else if (hit?.status === 'rejected') status = 'rejected';
    const decision = row.decision ?? decisions.get(finding.id);
    return {
      id: finding.id, title: finding.title, criterionId: finding.criterionId,
      source: finding.source === 'axe' ? 'axe' : 'agent', status,
      method: finding.method, target: finding.target ?? {}, selector: row.targetObservation?.selector,
      ...(typeof row.targetObservation?.stableSelector === 'string' && STABLE_SELECTOR_CONFIDENCE.includes(row.targetObservation.stableSelectorConfidence)
        ? { stableSelector: row.targetObservation.stableSelector, stableSelectorConfidence: row.targetObservation.stableSelectorConfidence, stableSelectorCheck: row.targetObservation.stableSelectorCheck } : {}),
      observation: finding.observation, reason: finding.reason, scope: finding.scope,
      evidenceIds: array(finding.evidenceIds), reviewerReason: decision?.reason, reviewerVerdict: decision?.verdict,
      missing: status === 'confirmed' ? [] : [...array(row.missingEvidence).filter(item => typeof item === 'string'),
        ...(hit?.status === 'confirmed' && reReview ? ['Legacy or citation-only confirmation requires re-review under the current semantic predicates.'] : [])],
    };
  });
  const coverage = array(report.coverage).map(row => ({ id: row.id, level: row.level, status: row.status, url: row.url }));
  return {
    mode, kind: report.kind, findings, coverage, standard: report.standard ?? report.context?.standard ?? null,
    ...(mode === 'reviewed' ? { reviewPolicy: reviewPolicyOf(report), requiresReReview: reReview } : {}),
    auditor: source.auditor?.name, reviewer: report.reviewer?.name, createdAt: report.createdAt, runId: report.runId,
    reportDigest: report.reportDigest ?? report.checkpointDigest,
    errors: array(report.errors),
    url: report.manifest?.url,
  };
}

function untestedScope(model) {
  const items = [];
  const total = model.standard?.criteriaTotal ?? (model.coverage.length || undefined);
  const withFindings = new Set(model.findings.map(finding => finding.criterionId));
  items.push(`No success criterion was assessed as a whole${total ? ` (${total} in the selected catalog; ${withFindings.size} have findings)` : ''}. A criterion with no finding here is not a pass.`);
  items.push('Only the pages, states and viewport the agent actually visited were examined; other pages, user flows and states were not.');
  items.push('Screen readers (VoiceOver, JAWS, NVDA) were not used. Browser ARIA observations are not screen-reader output.');
  items.push('Time-based media, captions, audio description, and any criterion needing human judgment were not tested unless a finding says otherwise.');
  if (model.mode === 'checkpoint') items.push('This is a draft checkpoint: nothing here has been submitted or independently reviewed.');
  else if (model.mode === 'proposal') items.push('This proposal has not been independently reviewed: every finding is a claim awaiting review.');
  else items.push('Review is a declaration by the named reviewer; the tool does not verify that they are independent.');
  if (model.requiresReReview) items.push(`Review policy ${model.reviewPolicy} is legacy or citation-only. Its previous confirmations need re-review and are displayed as needs review.`);
  return items;
}

const badge = (kind, label) => `<span class="badge ${esc(kind)}">${esc(label)}</span>`;

const CHECK_LABEL = { 'captured-dom': 'unique in the DOM this run captured', 'full-dom-at-capture': "unique in the page's whole DOM when captured" };

/** Plain reproduction steps: where to start, which recorded state, and the selector that should survive a reload. */
function reproduce(finding, pageUrl, clipText = clip) {
  const clip = clipText;
  const url = pageUrl, evidence = finding.target.evidenceId ? clip(finding.target.evidenceId, 40) : null;
  const steps = [`Open <code>${esc(clip(url ?? 'the audited page', REPORT_LIMITS.selector))}</code>${evidence ? ` and bring it to the state recorded in evidence <code>${esc(evidence)}</code>` : ''}.`];
  if (finding.stableSelector) {
    const check = CHECK_LABEL[finding.stableSelectorCheck];
    steps.push(`Find the element with <code>${esc(clip(finding.stableSelector, REPORT_LIMITS.selector))}</code> (${esc(finding.stableSelectorConfidence)}${check ? `; ${esc(check)}` : ''}).`);
  } else steps.push('No reload-stable selector could be stated; use the recorded target selector, which may depend on element position.');
  return `<ol>${steps.map(step => `<li>${step}</li>`).join('')}</ol>`;
}

function renderFinding(finding, images, shown, pageUrl, clipText = clip, exactId = false) {
  const clip = clipText;
  const target = [finding.selector !== undefined ? clip(Array.isArray(finding.selector) ? finding.selector.join(' ') : finding.selector, REPORT_LIMITS.selector) : '', finding.target.evidenceId ? `evidence ${clip(finding.target.evidenceId, 40)}` : '', finding.target.nodeId ? `node ${clip(finding.target.nodeId, 120)}` : ''].filter(Boolean);
  // Each PNG is embedded once, under the first finding that cites it, so shared evidence cannot bypass the size caps.
  const cited = [...new Set(finding.evidenceIds)].map(id => images.get(id)).filter(Boolean);
  const shots = cited.filter(shot => !shown.has(shot.evidenceId));
  for (const shot of shots) shown.add(shot.evidenceId);
  const repeated = cited.filter(shot => !shots.includes(shot));
  const rows = [
    ['Target', target.map(part => `<code>${esc(part)}</code>`).join(' · ') || 'unknown'],
    ['Observation', esc(clip(finding.observation))],
    ['Why it fails the criterion', esc(clip(finding.reason))],
    ['Scope', esc(clip(finding.scope))],
    ['Method', esc(clip(finding.method ?? 'unspecified', 40))],
    ['Evidence IDs', finding.evidenceIds.map(id => `<code>${esc(clip(id, 40))}</code>`).join(' ') || 'none'],
  ];
  rows.splice(1, 0, ['Reproduce', reproduce(finding, pageUrl, clip)]);
  if (finding.reviewerVerdict) rows.push(['Review verdict', esc(clip(finding.reviewerVerdict))]);
  if (finding.reviewerReason) rows.push(['Reviewer', esc(clip(finding.reviewerReason))]);
  if (finding.missing.length) rows.push(['Missing', `<ul>${(exactId ? finding.missing : finding.missing.slice(0, REPORT_LIMITS.missing)).map(item => `<li>${esc(clip(item))}</li>`).join('')}</ul>`]);
  return `<article class="finding" id="f-${esc(exactId ? finding.id : clip(finding.id, 120).replace(/[^\w.:-]/g, '_'))}">
<h4>${esc(clip(finding.title, 300) || clip(finding.id, 120))}</h4>
<p>${badge(`s-${finding.status}`, STATUS_LABEL[finding.status])} ${badge(`src-${finding.source}`, finding.source === 'axe' ? 'Source: axe-adopted' : 'Source: agent-found')}</p>
<dl>${rows.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${value}</dd>`).join('')}</dl>
${shots.map(shot => `<figure><img alt="Page screenshot from evidence ${esc(shot.evidenceId)}; contents not described" width="${esc(Number(shot.width) || '')}" height="${esc(Number(shot.height) || '')}" src="data:image/png;base64,${shot.base64}"><figcaption>Screenshot, evidence <code>${esc(shot.evidenceId)}</code></figcaption></figure>`).join('')}
${repeated.map(shot => `<p><small>Screenshot <code>${esc(shot.evidenceId)}</code> is shown under an earlier finding.</small></p>`).join('')}
</article>`;
}

/**
 * Render one self-contained HTML document (inline CSS only, no script, no external requests).
 * `images` maps evidence IDs to `{ evidenceId, base64, width, height }` already size-checked by the loader.
 */
function renderReportDocument(report, { images = new Map(), imageNotes = [], selectors = new Map(), targets = new Map(), inventory = [], references = [], projection } = {}) {
  const clip = projection ? fullText : clipDefault;
  const model = normalizeAuditReport(report);
  for (const finding of model.findings) {
    const key = `${finding.target.evidenceId}|${finding.target.nodeId}`;
    finding.selector ??= selectors.get(key);
    const local = targets.get(key);
    if (!finding.stableSelector && local?.stableSelector) Object.assign(finding, { stableSelector: local.stableSelector, stableSelectorConfidence: local.stableSelectorConfidence, stableSelectorCheck: local.stableSelectorCheck });
  }
  const shown = projection ? model.findings : model.findings.slice(0, REPORT_LIMITS.findings);
  const count = status => model.findings.filter(finding => finding.status === status).length;
  const bySource = source => model.findings.filter(finding => finding.source === source).length;
  const groups = new Map(), embedded = new Set();
  for (const finding of shown) groups.set(finding.criterionId, [...(groups.get(finding.criterionId) ?? []), finding]);
  const catalog = new Map(model.coverage.map(row => [row.id, row]));
  const title = model.mode === 'reviewed' ? 'Accessibility audit report (independently reviewed)' : model.mode === 'proposal' ? 'Accessibility audit report (awaiting review)' : 'Accessibility audit report (draft checkpoint)';
  const std = model.standard ? `WCAG ${esc(clip(model.standard.version, 10))} level ${esc(clip(model.standard.targetLevel, 10))}` : 'WCAG (catalog not recorded)';
  const sections = projection ? [projection.body] : [...groups.entries()].sort(([a], [b]) => criterionKey(a).localeCompare(criterionKey(b))).map(([id, list]) => {
    const url = safeW3cUrl(catalog.get(id)?.url), level = catalog.get(id)?.level;
    const heading = `SC ${esc(clip(id, 20))}${level ? ` (level ${esc(clip(level, 4))})` : ''}`;
    return `<section aria-labelledby="sc-${esc(clip(id, 20).replace(/[^\w.-]/g, '_'))}"><h3 id="sc-${esc(clip(id, 20).replace(/[^\w.-]/g, '_'))}">${url ? `<a href="${esc(url)}" rel="noreferrer noopener">${heading}</a>` : heading} <small>${list.length} finding${list.length === 1 ? '' : 's'}</small></h3>${list.map(finding => renderFinding(finding, images, embedded, model.url)).join('\n')}</section>`;
  });
  const meta = [
    ['Standard', std], ['Page', model.url ? esc(clip(model.url, 500)) : 'not recorded'],
    ['Auditor', esc(clip(model.auditor ?? 'not recorded', 200))], ...(model.reviewer ? [['Reviewer', esc(clip(model.reviewer, 200))]] : []),
    ['Created', esc(clip(model.createdAt ?? 'not recorded', 40))], ['Run', `<code>${esc(clip(model.runId ?? 'unknown', 80))}</code>`],
    ['Source file kind', `<code>${esc(model.kind)}</code>`], ['Digest', `<code>${esc(clip(model.reportDigest ?? 'none', 100))}</code>`],
    ...(model.reviewPolicy ? [['Review policy', esc(model.reviewPolicy)]] : []),
  ];
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<title>${esc(title)}</title>
<style>
:root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fff;--mut:#595959;--line:#c8c8c8;--warn:#fff4d6;--warnfg:#4d3800}
@media (prefers-color-scheme:dark){:root{--fg:#ececec;--bg:#161616;--mut:#b0b0b0;--line:#444;--warn:#3a3000;--warnfg:#ffe9a8}}
body{font:16px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg);max-width:60rem;margin:0 auto;padding:1rem}
a{color:inherit}code{font:0.9em ui-monospace,monospace;overflow-wrap:anywhere}
.notice{background:var(--warn);color:var(--warnfg);border:2px solid var(--warnfg);padding:.75rem 1rem;border-radius:6px}
.summary{display:flex;flex-wrap:wrap;gap:.75rem;list-style:none;padding:0}.summary li{border:1px solid var(--line);border-radius:6px;padding:.5rem .9rem}
.summary b{display:block;font-size:1.6rem}.badge{border:1px solid currentColor;border-radius:4px;padding:0 .4rem;font-size:.85rem;margin-right:.25rem}
.inventory-row h3 { overflow-wrap: anywhere; }
.finding{border:1px solid var(--line);border-radius:6px;padding:.25rem 1rem;margin:1rem 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem}dt{font-weight:600;color:var(--mut)}dd{margin:0;overflow-wrap:anywhere}
@media (max-width:600px){dl{grid-template-columns:minmax(0,1fr)}dd{margin-bottom:.75rem}}
figure{margin:1rem 0}img{max-width:100%;height:auto;border:1px solid var(--line)}small{color:var(--mut);font-weight:400}
</style></head><body>
<header><h1>${esc(title)}</h1>
<p class="notice" role="note"><strong>Not a conformance certification.</strong> This report lists findings from one agent-driven session. It does not state that the page conforms, or fails to conform, to ${std}.</p>
<dl>${meta.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${value}</dd>`).join('')}</dl></header>
<main>
<section aria-labelledby="summary"><h2 id="summary">Summary</h2>
<ul class="summary"><li><b>${model.findings.length}</b>findings</li><li><b>${count('confirmed')}</b>confirmed</li><li><b>${count('needs_review')}</b>needs review</li><li><b>${count('rejected')}</b>rejected</li><li><b>${bySource('axe')}</b>axe-adopted</li><li><b>${bySource('agent')}</b>agent-found</li><li><b>${groups.size}</b>success criteria affected</li></ul>
${model.findings.length > shown.length ? `<p>Showing the first ${shown.length} of ${model.findings.length} findings.</p>` : ''}
${model.errors.length ? `<p>The collection recorded ${model.errors.length} error${model.errors.length === 1 ? '' : 's'}; treat coverage as incomplete.</p>` : ''}</section>
<section aria-labelledby="findings"><h2 id="findings">${projection ? 'Original finding records' : 'Findings by WCAG success criterion'}</h2>
${projection?.navigation ? projection.navigation + '\n' : ''}${sections.join('\n') || '<p>No findings were recorded. That does not mean the page is accessible.</p>'}</section>
${renderInventory(report, inventory, clip)}
${renderReferences(references, clip)}
<section aria-labelledby="scope"><h2 id="scope">Untested scope and limits</h2><ul>${untestedScope(model).map(item => `<li>${esc(item)}</li>`).join('')}</ul>
${imageNotes.length ? `<p>${imageNotes.map(esc).join(' ')}</p>` : ''}</section>
</main>
<footer><p><small>Rendered locally from ${esc(model.kind)} data by a11y-agent-kit. Digests are shown, not re-verified: run <code>audit-check</code> on the source report to verify it. Retained redactions are preserved; screenshots, when embedded, are original page pixels and can show sensitive content.</small></p></footer>
</body></html>
`;
}

/** Existing single-file projection, including its established text and finding caps. */
export function renderAuditReportHtml(report, context = {}) {
  return renderReportDocument(report, context);
}

// Inventory observations and adopted findings overlap. Explicit maker links are a separate declaration.
function renderInventory(report, inventory, clip) {
  if (!inventory.length) return '';
  const findings = (report.kind === 'audit-checkpoint-1' ? report.proposal : report)?.findings ?? [];
  const rows = inventory.map(row => {
    const adopted = findings.filter(f => row.bucket === 'violations' && f.source === 'axe' && f.axeCandidateId === `${row.evidenceId}:${row.ruleId}:${row.ruleNodeIndex}`);
    const disposition = row.authorDisposition ?? { status: 'unresolved' };
    const fields = [
      ['Evidence', row.evidenceId], ['Rule / bucket', `${row.ruleId} / ${row.bucket}`], ['Target', row.target],
      ['DOM binding', row.binding?.status ?? 'not recorded'], ['Author disposition', disposition.status],
      ...(disposition.reason ? [['Disposition reason', disposition.reason]] : []),
      ['Association', disposition.status === 'linked' ? `Explicitly linked: ${array(disposition.findingIds).join(', ')}` : 'Not explicitly linked'],
      ['Adoption', adopted.length ? `Adopted as ${adopted.map(f => f.id).join(', ')} (from axeCandidateId)` : 'No matching adoption recorded'],
    ];
    return `<article class="inventory-row"><h3>${esc(clip(row.observationId))}</h3><dl>${fields.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(clip(value))}</dd>`).join('')}</dl></article>`;
  });
  return `<section aria-labelledby="inventory"><h2 id="inventory">Original observation inventory (${inventory.length})</h2><p>Inventory observations can overlap adopted finding records; they are not additional defects. Author disposition and explicit association are separate from adoption, DOM binding and review status. Unresolved is an author disposition; it does not mean the observation was never adopted.</p>${rows.join('\n')}</section>`;
}

function renderReferences(references, clip) {
  return `<section aria-labelledby="originals"><h2 id="originals">Original evidence sources</h2><p>Paths are local references, relative to this HTML directory when available. They come from recorded attachment metadata; existence and digests are not verified here.</p>${references.length ? references.map(row => `<article><h3>${esc(clip(row.evidenceId))}</h3><p>Source: ${esc(clip(row.source))}</p><dl><dt>JSON</dt><dd>${row.json ? `<code>${esc(clip(row.json))}</code>` : 'Original JSON path not recorded'}</dd><dt>PNG</dt><dd>${row.png ? `<code>${esc(clip(row.png))}</code>` : 'Original PNG path not recorded'}</dd></dl></article>`).join('\n') : '<p>Original JSON path not recorded. Original PNG path not recorded.</p>'}</section>`;
}

async function readJson(file, limit, { sidecar = false } = {}) {
  const stat = await (sidecar ? fs.lstat : fs.stat)(file); // sidecars next to the report must not be links to elsewhere
  if (!stat.isFile() || stat.size > limit) fail('The file is not a regular file within the size limit.');
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

/**
 * Best-effort local lookups next to the report: selectors (recorded and reload-stable) for target nodes and, when requested, size-capped
 * original PNGs that match their recorded SHA-256. A referenced collection also supplies inventory and attachment metadata.
 */
export async function loadReportContext(reportPath, report, { screenshots = false, outputDirectory } = {}) {
  const dir = path.dirname(path.resolve(reportPath)), selectors = new Map(), targets = new Map(), images = new Map(), notes = [];
  const model = normalizeAuditReport(report);
  const ids = [...new Set(model.findings.flatMap(finding => [finding.target.evidenceId, ...finding.evidenceIds]))].filter(id => EVIDENCE_ID.test(id ?? ''));
  const references = [], inventory = [];
  const reference = report.collection?.reportPath ?? report.sourceAudit?.reportPath;
  let collection;
  if (typeof reference === 'string') {
    const file = path.resolve(dir, reference);
    collection = await readJson(file, 64 * 1024 * 1024).catch(() => null);
    if (collection?.kind !== 'audit' || collection.runId !== report.runId) collection = null;
    if (!collection) notes.push('Referenced collection unavailable or inconsistent; original inventory and attachment paths could not be loaded.');
    else {
      try {
        let options = { limit: 200 };
        do {
          const page = deriveAuditInventory({ collection, report }, options);
          inventory.push(...page.rows);
          options = page.pagination.next;
        } while (options);
      } catch { inventory.length = 0; notes.push('Original inventory could not be derived from the referenced collection.'); }
    }
  }
  const sourceRows = collection?.records ?? report.evidence ?? report.records ?? [];
  const sourceDir = collection ? path.dirname(path.resolve(dir, reference)) : dir;
  for (const row of array(sourceRows)) {
    const attachment = key => typeof row[key]?.path === 'string' && row[key].path ? path.relative(outputDirectory ?? dir, path.resolve(sourceDir, row[key].path)) : null;
    references.push({ evidenceId: row.evidenceId, json: attachment('json'), png: attachment('png'), source: collection ? 'collection.records' : 'input report attachment metadata' });
  }
  const records = new Map();
  const record = async id => {
    if (!records.has(id)) records.set(id, await readJson(path.join(dir, `${id}.json`), REPORT_LIMITS.evidenceFileBytes, { sidecar: true }).catch(() => null));
    return records.get(id);
  };
  for (const finding of model.findings) {
    if (!EVIDENCE_ID.test(finding.target.evidenceId ?? '')) continue;
    const original = await record(finding.target.evidenceId);
    const key = `${finding.target.evidenceId}|${finding.target.nodeId}`;
    // Drafts carry no targetObservation: derive a stable selector from this one record (its own nodes and in-page checks) only.
    const stable = finding.stableSelector || !original ? {} : stableSelectorIndex([original]).fieldsFor(finding.target);
    if (stable.stableSelector) targets.set(key, stable);
    if (finding.selector !== undefined) continue;
    const nodes = [...array(original?.result?.nodes), ...(original?.result?.element ? [original.result.element] : [])];
    const node = nodes.find(row => row?.nodeId === finding.target.nodeId);
    if (typeof node?.selector === 'string') selectors.set(`${finding.target.evidenceId}|${finding.target.nodeId}`, node.selector);
  }
  if (screenshots) {
    let total = 0, skipped = 0;
    for (const id of ids) {
      const png = (await record(id))?.png;
      if (!png || typeof png.sha256 !== 'string') continue;
      if (images.size >= REPORT_LIMITS.images) { skipped++; continue; }
      const file = path.join(dir, `${id}.png`);
      const bytes = (await fs.lstat(file).catch(() => null))?.isFile() ? await fs.readFile(file).catch(() => null) : null;
      if (!bytes || bytes.length > REPORT_LIMITS.imageBytes || total + bytes.length > REPORT_LIMITS.imagesTotalBytes) { if (bytes) skipped++; continue; }
      if (!bytes.subarray(0, 8).equals(PNG_SIGNATURE) || createHash('sha256').update(bytes).digest('hex') !== png.sha256) { skipped++; continue; }
      total += bytes.length;
      images.set(id, { evidenceId: id, base64: bytes.toString('base64'), width: png.width, height: png.height });
    }
    if (skipped) notes.push(`${skipped} screenshot${skipped === 1 ? ' was' : 's were'} not embedded (over the ${REPORT_LIMITS.imageBytes / 1024} KiB per-image, ${REPORT_LIMITS.imagesTotalBytes / 1024 / 1024} MiB total or ${REPORT_LIMITS.images}-image cap, or failed the SHA-256 check).`);
  } else notes.push('Screenshots were not embedded (use --screenshots).');
  return { selectors, targets, images, imageNotes: notes, inventory, references };
}

// Delivery protects originals without requiring audit-check or changing projection semantics.
async function protectReportOutput(input, report, out) {
  const parent = path.dirname(out);
  // Check existing ancestors before mkdir, including aliases to a different directory.
  let ancestor = parent;
  while (!(await fs.lstat(ancestor).catch(error => { if (error.code === 'ENOENT') return null; throw error; }))) ancestor = path.dirname(ancestor);
  for (let current = ancestor; current !== path.dirname(current); current = path.dirname(current)) {
    // Preserve standard macOS filesystem root aliases used by os.tmpdir(); reject application-created aliases.
    const platformAlias = process.platform === 'darwin' && ['/var', '/tmp', '/etc'].includes(current);
    if ((await fs.lstat(current)).isSymbolicLink() && !platformAlias) fail('--out parent must be canonical, without symlink aliases.');
  }
  const destination = await fs.lstat(out).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  if (destination?.isSymbolicLink()) fail('--out must not be a symlink.');
  const visited = new Set(), scanned = new Set();
  async function protect(file, document, json = false) {
    const absolute = path.resolve(file);
    // An untyped path may be encountered before a JSON reference to the same file.
    if (visited.has(absolute) && (!json || scanned.has(absolute))) return;
    visited.add(absolute);
    const canonical = await fs.realpath(absolute).catch(() => absolute);
    const stat = await fs.stat(absolute).catch(error => {
      if (error.code === 'ENOENT') return null; // optional sidecar absent
      fail(`Cannot scan referenced ${json ? 'JSON' : 'file'}: ${absolute} (${error.code}).`);
    });
    if (out === absolute || out === canonical || (destination && stat && destination.dev === stat.dev && destination.ino === stat.ino)) {
      fail('--out must not replace an original report or referenced evidence.');
    }
    if (document === undefined && json) {
      if (!stat) return;
      try { document = await readJson(absolute, 64 * 1024 * 1024); }
      catch { fail(`Cannot scan referenced JSON: ${absolute}; expected readable, valid JSON within 64 MiB. No output was written.`); }
    }
    if (document !== undefined) scanned.add(absolute);
    async function walk(value, jsonAttachment = false) {
      if (!value || typeof value !== 'object') return;
      if (typeof value.evidenceId === 'string' && /^ev-\d+$/.test(value.evidenceId)) {
        for (const ext of ['json', 'png']) await protect(path.join(path.dirname(absolute), `${value.evidenceId}.${ext}`), undefined, ext === 'json');
      }
      if (Array.isArray(value.evidenceIds)) for (const id of value.evidenceIds) {
        if (typeof id === 'string' && /^ev-\d+$/.test(id)) for (const ext of ['json', 'png']) await protect(path.join(path.dirname(absolute), `${id}.${ext}`), undefined, ext === 'json');
      }
      for (const [key, child] of Object.entries(value)) {
        if (['path', 'reportPath', 'checkpointPath'].includes(key) && typeof child === 'string') await protect(path.resolve(path.dirname(absolute), child), undefined, key !== 'path' || jsonAttachment);
        else if (child && typeof child === 'object') await walk(child, key === 'json');
      }
    }
    await walk(document);
  }
  await protect(input, report);
}

async function replaceHtml(out, html) {
  const temporary = path.join(path.dirname(out), `.${path.basename(out)}.tmp-${randomUUID()}`);
  let owned = false;
  try {
    const handle = await fs.open(temporary, 'wx', 0o600); owned = true;
    try { await handle.writeFile(html); } finally { await handle.close(); }
    await fs.rename(temporary, out);
  } finally { if (owned) await fs.unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
}

export async function writeAuditReport(inputPath, outPath, { screenshots = false, bounded = false } = {}) {
  const input = path.resolve(inputPath), out = path.resolve(outPath);
  if (input === out) fail('--out must differ from the input report.');
  const report = await readJson(input, 64 * 1024 * 1024).catch(error => {
    throw error instanceof ToolError ? error : new ToolError('INVALID_AUDIT_REPORT', 'The input must be a readable JSON report file.');
  });
  const context = await loadReportContext(input, report, { screenshots, outputDirectory: bounded ? out : path.dirname(out) });
  if (bounded) {
    // Render and validate everything before creating any output. Never reuse an existing directory.
    const artifacts = renderBoundedAuditReportHtml(report, context);
    await protectReportOutput(input, report, out);
    await fs.mkdir(path.dirname(out), { recursive: true });
    await fs.mkdir(out, { mode: 0o700 });
    for (const artifact of artifacts) await fs.writeFile(path.join(out, artifact.name), artifact.html, { flag: 'wx', mode: 0o600 });
    return { status: 'ok', kind: 'audit-report-html-bounded', source: KINDS[report.kind], outPath: path.join(out, 'index.html'),
      artifacts: artifacts.map(({ name, html, findings }) => ({ path: path.join(out, name), bytes: Buffer.byteLength(html, 'utf8'), findings })),
      findings: normalizeAuditReport(report).findings.length, screenshotsEmbedded: context.images.size };
  }
  const html = renderAuditReportHtml(report, context);
  await protectReportOutput(input, report, out);
  await fs.mkdir(path.dirname(out), { recursive: true });
  await replaceHtml(out, html);
  const model = normalizeAuditReport(report);
  return { status: 'ok', kind: 'audit-report-html', source: KINDS[report.kind], outPath: out, bytes: Buffer.byteLength(html), findings: model.findings.length, screenshotsEmbedded: context.images.size };
}

export const BOUNDED_REPORT_LIMITS = Object.freeze({ findings: 50, bytes: 500000 });

/** Complete local delivery in original record order; bounds include escaped content, images and chrome. */
export function renderBoundedAuditReportHtml(report, context = {}) {
  const model = normalizeAuditReport(report), embedded = new Set();
  const cards = model.findings.map(finding => {
    const key = `${finding.target.evidenceId}|${finding.target.nodeId}`;
    finding.selector ??= context.selectors?.get(key);
    const local = context.targets?.get(key);
    if (!finding.stableSelector && local?.stableSelector) Object.assign(finding, { stableSelector: local.stableSelector, stableSelectorConfidence: local.stableSelectorConfidence, stableSelectorCheck: local.stableSelectorCheck });
    return `<section><h3>SC ${esc(fullText(finding.criterionId))}</h3>${renderFinding(finding, context.images ?? new Map(), embedded, model.url, fullText, true)}</section>`;
  });
  const document = (body, navigation = '') => renderReportDocument(report, { ...context, projection: { body, navigation } });
  const fits = html => Buffer.byteLength(html, 'utf8') < BOUNDED_REPORT_LIMITS.bytes;
  const artifacts = [];
  let start = 0;
  while (start < cards.length) {
    const name = `findings-${String(artifacts.length + 1).padStart(4, '0')}.html`;
    let end = start, html;
    while (end < cards.length && end - start < BOUNDED_REPORT_LIMITS.findings) {
      const trial = document(cards.slice(start, end + 1).join('\n'),
        `<nav aria-label="Report pages"><a href="index.html">Back to index</a><p>Original finding records ${start + 1}–${end + 1} of ${cards.length}; these are not unique issue counts.</p></nav>`);
      if (!fits(trial)) break;
      html = trial; end++;
    }
    if (end === start) fail(`Original finding record ${start + 1} cannot fit in a bounded HTML artifact (<500000 UTF-8 bytes including chrome and screenshots). No output was written.`);
    artifacts.push({ name, html, findings: end - start, start: start + 1, end });
    start = end;
  }
  const index = document(`<p>${cards.length} original finding records in ${artifacts.length} detail pages. These are observations, not unique issue counts. All pages preserve original record order.</p><ol>${artifacts.map(page => `<li><a href="${page.name}">Original finding records ${page.start}–${page.end}</a></li>`).join('')}</ol>${cards.length ? '' : '<p>No findings were recorded. That does not mean the page is accessible.</p>'}`);
  if (!fits(index)) fail('The bounded HTML index cannot fit below 500000 UTF-8 bytes. No output was written.');
  return [{ name: 'index.html', html: index, findings: 0 }, ...artifacts];
}
