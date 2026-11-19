import path from 'node:path';
import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { digest, ToolError } from '../evidence.js';
import { zodIssueDetails } from './error-details.js';
import { networkReplayDescriptorSchema } from './network-replay.js';
import { NONTEXT_PARTS } from './nontext.js';

export const AUDIT_SCHEMA_VERSION = 'audit-1';

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export const AUDIT_CATALOG = freeze(JSON.parse(readFileSync(new URL('../wcag21-aa.json', import.meta.url), 'utf8')));
export const AUDIT_CATALOG_DIGEST = digest(AUDIT_CATALOG);
export const AUDIT_STANDARD = freeze({
  ...AUDIT_CATALOG,
  catalogDigest: AUDIT_CATALOG_DIGEST,
});

// Legacy exports above are deliberately pinned for historical scorer imports.
export const auditStandardSelectionSchema = z.object({
  version: z.enum(['2.1', '2.2']), targetLevel: z.enum(['A', 'AA']),
}).strict();
export const DEFAULT_AUDIT_SELECTION = freeze({ version: '2.2', targetLevel: 'AA' });
const catalog22 = freeze(JSON.parse(readFileSync(new URL('../wcag22-aa.json', import.meta.url), 'utf8')));

/** Missing retained selection always means the original 2.1 AA contract. */
export function resolveAuditStandard(selection) {
  if (selection === undefined) return AUDIT_STANDARD;
  const parsed = auditStandardSelectionSchema.safeParse(selection);
  if (!parsed.success) throw new ToolError('INVALID_AUDIT_STANDARD', 'Supported WCAG versions are 2.1/2.2 and levels A/AA.');
  const { version, targetLevel } = parsed.data;
  const base = version === '2.1' ? AUDIT_CATALOG : catalog22;
  if (targetLevel === 'AA') return version === '2.1' ? AUDIT_STANDARD : freeze({ ...base, catalogDigest: digest(base) });
  const criteria = base.criteria.filter(row => row.level === 'A');
  const catalog = { ...base, id: base.id.replace('-aa-', '-a-'), targetLevel, criteria,
    criteriaTotal: criteria.length, levelCounts: { A: criteria.length, AA: 0 } };
  return freeze({ ...catalog, catalogDigest: digest(catalog) });
}

export function auditAxeTags(selection) {
  const { version, targetLevel } = resolveAuditStandard(selection);
  return ['wcag2a', ...(targetLevel === 'AA' ? ['wcag2aa'] : []), 'wcag21a',
    ...(targetLevel === 'AA' ? ['wcag21aa'] : []),
    ...(version === '2.2' ? [targetLevel === 'AA' ? 'wcag22aa' : 'wcag22a'] : [])];
}

const text = z.string().trim().min(1).max(4096).refine(value => !value.includes('\0'));
const selector = text;
const viewport = z.object({
  width: z.number().int().min(1).max(4096),
  height: z.number().int().min(1).max(4096),
}).strict();
const pixelPoint = z.object({ x: z.number().int().min(0).max(4095), y: z.number().int().min(0).max(4095) }).strict();

// Literal DOM comparisons: no trimming, executable expressions or regular expressions.
const readinessLiteral = z.string().max(4096).refine(value => !value.includes('\0'));
const readinessBase = { action: z.literal('wait_for'), selector,
  timeoutMs: z.number().int().min(1).max(5000).default(3000) };
const readinessVariants = [
  z.object({ ...readinessBase, condition: z.enum(['attached', 'detached', 'visible', 'hidden']) }).strict(),
  z.object({ ...readinessBase, condition: z.literal('text'), expected: readinessLiteral }).strict(),
  z.object({ ...readinessBase, condition: z.literal('attribute'),
    name: z.string().min(1).max(128).regex(/^[A-Za-z_][A-Za-z0-9_.:-]*$/),
    value: readinessLiteral.nullable() }).strict(),
];

export const observeStatusSchema = z.object({
  action: z.literal('observe_status'),
  trigger: z.union([
    z.object({ action: z.literal('click'), selector }).strict(),
    z.object({ action: z.literal('fill'), selector, value: z.string().max(100000).refine(value => !value.includes('\0')) }).strict(),
    // Global keyboard path: selector asserts current focus; never focuses implicitly.
    z.object({ action: z.literal('press'), selector, key: z.string().trim().min(1).max(100).refine(value => !/[\0\r\n]/.test(value)) }).strict(),
  ]),
  windowMs: z.number().int().min(1).max(5000).default(1000),
  expectedText: readinessLiteral.optional(),
}).strict();

export const auditActionSchema = z.union([z.discriminatedUnion('condition', readinessVariants), z.discriminatedUnion('action', [
  z.object({ action: z.literal('snapshot') }).strict(),
  z.object({ action: z.literal('axe') }).strict(),
  z.object({ action: z.literal('inspect'), selector }).strict(),
  // Exactly one of selectors (each must match one element) or the "interactive" preset; both are read-only.
  z.object({ action: z.literal('inspect_many'), selectors: z.array(selector).min(1).max(50).optional(), query: z.literal('interactive').optional() }).strict()
    .refine(value => (value.selectors === undefined) !== (value.query === undefined), 'Provide exactly one of selectors (1-50) or query:"interactive".'),
  z.object({ action: z.literal('blob_digest'), selector, attribute: z.enum(['href', 'src']),
    maxBytes: z.number().int().positive().max(8388608).default(1048576),
    timeoutMs: z.number().int().min(1).max(5000).default(3000) }).strict(),
  z.object({ action: z.literal('screenshot'), fullPage: z.boolean().optional() }).strict(),
  z.object({ action: z.literal('contrast'), foreground: pixelPoint, background: pixelPoint }).strict(),
  // Read-only observations of candidate colour pairs on one element; never a verdict.
  z.object({ action: z.literal('measure_nontext'), selector, part: z.enum(NONTEXT_PARTS).optional() }).strict(),
  z.object({ action: z.literal('viewport'), ...viewport.shape }).strict(),
  z.object({ action: z.literal('spacing'), enabled: z.boolean() }).strict(),
  z.object({
    action: z.literal('press'),
    key: z.string().trim().min(1).max(100).refine(value => !/[\0\r\n]/.test(value)),
  }).strict(),
  z.object({ action: z.literal('hover'), selector }).strict(),
  z.object({ action: z.literal('focus'), selector }).strict(),
  z.object({ action: z.literal('click'), selector }).strict(),
  z.object({ action: z.literal('fill'), selector, value: z.string().max(100000).refine(value => !value.includes('\0')) }).strict(),
  z.object({ action: z.literal('navigate'), path: text }).strict(),
  z.object({ action: z.literal('scroll'), x: z.number().int().min(0).max(1000000), y: z.number().int().min(0).max(1000000) }).strict(),
  z.object({ action: z.literal('wait'), ms: z.number().int().min(0).max(5000) }).strict(),
  z.object({ action: z.literal('reset') }).strict(),
])]);

function safeHttpUrl(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
  } catch { return false; }
}

export const auditManifestSchema = z.object({
  standard: auditStandardSelectionSchema.optional(),
  projectRoot: text.refine(value => path.isAbsolute(value), 'projectRoot must be an absolute filesystem path.'),
  url: text.refine(safeHttpUrl, 'url must use HTTP(S) without username/password credentials.'),
  viewport: viewport.default({ width: 1280, height: 900 }),
  actions: z.array(auditActionSchema).max(500).optional(),
  maxActions: z.number().int().min(1).max(500).default(120),
  wallSeconds: z.number().int().min(1).max(600).default(120),
  maxElements: z.number().int().min(1).max(20000).default(3000),
  networkReplay: networkReplayDescriptorSchema.optional(),
}).strict().superRefine((manifest, ctx) => {
  if (!safeHttpUrl(manifest.url)) return;
  const base = new URL(manifest.url);
  for (const [index, action] of (manifest.actions ?? []).entries()) {
    if (action.action !== 'navigate') continue;
    try {
      const target = new URL(action.path, base);
      if (!safeHttpUrl(target.href) || target.origin !== base.origin) throw new Error();
    } catch {
      ctx.addIssue({ code: 'custom', path: ['actions', index, 'path'], message: 'Navigation must remain on the manifest HTTP(S) origin without credentials.' });
    }
  }
});

export function parseAuditManifest(input) {
  const result = auditManifestSchema.safeParse(input);
  if (!result.success) {
    throw new ToolError('INVALID_AUDIT_MANIFEST', 'Audit manifest validation failed.', zodIssueDetails(result.error.issues));
  }
  return result.data;
}
