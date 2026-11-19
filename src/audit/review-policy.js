export const CURRENT_REVIEW_POLICY = 'dom-predicates-v1';
export const reviewPolicyOf = report => report.directEvidencePolicy ?? 'legacy-declared';
export const requiresReReview = report => report.kind === 'audit-review' && reviewPolicyOf(report) !== CURRENT_REVIEW_POLICY;
