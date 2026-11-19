import path from 'node:path';
import { z } from 'zod';

export const SUPPORTED_RULES = Object.freeze(['button-name', 'label', 'aria-valid-attr']);

const selector = z.string().trim().min(1).describe('A nonempty standard CSS selector.');
const nonempty = z.string().trim().min(1);

export const stepSchema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('click'), selector }).strict(),
  z.object({ action: z.literal('press'), selector, key: nonempty }).strict(),
  z.object({ action: z.literal('waitFor'), selector }).strict(),
]);

export const assertionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('visible'), selector }).strict(),
  z.object({ type: z.literal('enabled'), selector }).strict(),
  z.object({ type: z.literal('focused'), selector }).strict(),
  z.object({ type: z.literal('count'), selector, value: z.number().int().nonnegative() }).strict(),
  z.object({ type: z.literal('text'), selector, value: z.string() }).strict(),
]);

export const manifestSchema = z.object({
  projectRoot: nonempty.refine(value => path.isAbsolute(value) && !value.includes('\0'), {
    message: 'projectRoot must be an absolute filesystem path.',
  }),
  url: z.string().url().refine(value => {
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
    } catch {
      return false;
    }
  }, { message: 'url must use HTTP(S) and must not contain username/password credentials.' }),
  rules: z.array(z.enum(SUPPORTED_RULES)).min(1).default([...SUPPORTED_RULES]),
  viewport: z.object({
    width: z.number().int().min(1).max(16384),
    height: z.number().int().min(1).max(16384),
  }).strict(),
  states: z.array(z.object({
    id: nonempty.max(200),
    steps: z.array(stepSchema).default([]),
    assertions: z.array(assertionSchema).default([]),
  }).strict()).min(1),
}).strict().superRefine((manifest, ctx) => {
  if (new Set(manifest.rules).size !== manifest.rules.length) {
    ctx.addIssue({ code: 'custom', path: ['rules'], message: 'rules must be unique.' });
  }
  const ids = new Set();
  manifest.states.forEach((state, index) => {
    if (ids.has(state.id)) {
      ctx.addIssue({ code: 'custom', path: ['states', index, 'id'], message: 'State IDs must be unique.' });
    }
    ids.add(state.id);
  });
});

export const baselineInputSchema = z.object({ baselinePath: nonempty }).strict();
export const evidenceInputSchema = z.object({ reportPath: nonempty }).strict();
