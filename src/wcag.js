import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const catalogBytes = readFileSync(new URL('./wcag21-aa.json', import.meta.url));
const catalog = JSON.parse(catalogBytes);
const sha256 = value => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const catalogDigest = sha256(catalogBytes);

// The installed axe-core 4.14.0 tags all three supported rules wcag2a/wcag412.
// These checks examine parts of 4.1.2; neither a rule pass nor a functional
// assertion establishes satisfaction of that criterion or an AA criterion.
const assessmentPolicy = {
  version: 'partial-selected-checks-v1',
  engine: { name: 'axe-core', version: '4.14.0' },
  scope: 'declared-states-and-selected-checks',
  ruleEvidence: 'partial',
  criterionAssessment: 'not_assessed',
  functionalAssertions: 'preservation-only',
  conformanceStatus: 'not_assessed',
  ruleCriteria: {
    'button-name': ['4.1.2'],
    label: ['4.1.2'],
    'aria-valid-attr': ['4.1.2'],
  },
};
// Freeze the assessment policy and mapping together with the catalog. A policy
// change cannot silently reuse a baseline's rubric digest.
const rubricDigest = sha256(JSON.stringify({ catalogDigest, assessmentPolicy }));

/** Fixed target metadata, independent of the selected subset of checks. */
export function standardMetadata() {
  return {
    name: 'WCAG',
    version: '2.1',
    targetLevel: 'AA',
    includedLevels: ['A', 'AA'],
    normativeSource: catalog.normativeSource,
    normativeSourceSha256: catalog.sourceSha256,
    conformanceSource: catalog.conformanceSource,
    rubric: {
      id: catalog.id,
      catalog: 'src/wcag21-aa.json',
      catalogDigest,
      policyVersion: assessmentPolicy.version,
      digest: rubricDigest,
      criteriaTotal: catalog.criteriaTotal,
      levelCounts: { ...catalog.levelCounts },
    },
    conformanceStatus: 'not_assessed',
  };
}

/** Mapping is potential partial evidence, never success-criterion coverage. */
export function coverageMetadata(rules) {
  const mapped = new Set(rules.flatMap(rule => assessmentPolicy.ruleCriteria[rule]));
  return {
    scope: assessmentPolicy.scope,
    assessment: 'partial-evidence-only',
    ruleMappings: rules.map(ruleId => ({
      ruleId,
      criterionIds: [...assessmentPolicy.ruleCriteria[ruleId]],
      evidence: 'partial',
    })),
    mappedCriteriaByLevel: Object.fromEntries(['A', 'AA'].map(level => [level,
      catalog.criteria.filter(criterion => criterion.level === level && mapped.has(criterion.id)).map(criterion => criterion.id),
    ])),
    aaSpecificAutomatedCriteria: catalog.criteria.filter(criterion => criterion.level === 'AA' && mapped.has(criterion.id)).length,
    fullyAssessedCriteria: [],
    // Even 4.1.2 remains unassessed as a whole when its partial checks pass.
    unassessedCriteria: catalog.criteria.map(criterion => criterion.id),
    note: 'Rule results are partial evidence only. Functional assertions check declared behavior; no success criterion or WCAG conformance requirement is assessed as a whole.',
  };
}
