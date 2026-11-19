import { ToolError } from '../evidence.js';

// Collection code supplies this receipt. It is deliberately not a manifest option.
export const AUDIT_EVIDENCE_POLICY = 'audit-evidence-2';

/** An absent receipt is historical v1; no other spelling or shape is accepted. */
export function validateAuditEvidencePolicy(value) {
  if (value !== undefined && value !== AUDIT_EVIDENCE_POLICY) {
    throw new ToolError('INVALID_AUDIT_EVIDENCE_POLICY', 'Evidence policy must be the exact audit-evidence-2 receipt or absent on a historical collection.');
  }
  return value;
}

// Criteria whose evidence gate always requires a same-state original PNG, whatever the claimed method.
export const VISUAL_CRITERIA = new Set(['1.3.4', '1.4.1', '1.4.3', '1.4.4', '1.4.5', '1.4.10', '1.4.11', '1.4.12', '1.4.13', '2.4.7']);
