// Bounded, field-level validation detail for agent and MCP error responses.
// Paths come from our own schemas; only issue messages from our schemas or zod are kept,
// and unknown keys a caller sent are named only when they belong to a fixed vocabulary.

export const ERROR_ISSUE_LIMIT = 12;
const PATH_LIMIT = 120, MESSAGE_LIMIT = 200;
const clip = (value, limit) => value.length > limit ? `${value.slice(0, limit - 1)}…` : value;

/** Fields of an axe candidate's draftFinding; they are not proposal finding fields. Kept in sync with deriveAxeCandidates. */
export const DRAFT_FINDING_FIELDS = Object.freeze(['pageUrl', 'selector', 'selectorConfidence', 'axeTarget', 'stableSelector', 'stableSelectorConfidence', 'claim', 'nodeId']);
/** Required fields of a host-authored proposal finding, in schema order. */
export const PROPOSAL_FINDING_FIELDS = Object.freeze(['id', 'title', 'criterionId', 'target', 'evidenceIds', 'observation', 'reason', 'applicability', 'exceptions', 'scope']);

/**
 * A minimal valid host-authored finding: replace target/evidenceIds with real IDs from this session and every
 * <...> text with your own words. criterionId is a real example value; use the criterion your evidence supports.
 */
export const EXPECTED_FINDING = Object.freeze({
  id: 'f1',
  title: '<short title>',
  criterionId: '4.1.2',
  target: Object.freeze({ evidenceId: '<ev-NNNN record that contains the node>', nodeId: '<nodeId from that record>' }),
  evidenceIds: Object.freeze(['<same ev-NNNN as target.evidenceId, plus any others you cite>']),
  observation: '<what the recorded evidence shows>',
  reason: '<why that fails the criterion>',
  applicability: '<why the criterion applies to this element>',
  exceptions: '<exceptions considered, or none>',
  scope: '<what this finding covers>',
  method: 'dom',
});

// Names the response may repeat back: our own schema field names and draftFinding names.
const KNOWN_NAMES = new Set([...DRAFT_FINDING_FIELDS, ...PROPOSAL_FINDING_FIELDS, 'method', 'source', 'axeCandidateId', 'auditor', 'findings', 'adoptAxe', 'name', 'model', 'evidenceId']);

const safePath = path => (Array.isArray(path) ? path : String(path ?? '').split('.').filter(Boolean))
  .map(part => typeof part === 'number' || /^\w{1,40}$/.test(String(part)) ? String(part) : '?').join('.');

function unknownKeys(keys) {
  const list = Array.isArray(keys) ? keys.filter(key => typeof key === 'string') : [];
  const known = list.filter(key => KNOWN_NAMES.has(key)), others = list.length - known.length;
  return { known, others };
}

/** zod issues -> plain {path, message[, unknownKeys, otherUnknownKeys]} details for a ToolError. */
export function zodIssueDetails(issues) {
  return (issues ?? []).map(issue => {
    if (issue.code !== 'unrecognized_keys') return { path: safePath(issue.path), message: String(issue.message) };
    const { known, others } = unknownKeys(issue.keys);
    const names = [...known, ...(others ? [`${others} other field(s)`] : [])].join(', ');
    return { path: safePath(issue.path), message: `Unsupported field(s): ${names}.`, unknownKeys: known, ...(others ? { otherUnknownKeys: others } : {}) };
  });
}

/** Bounded copy of ToolError details for a response: at most ERROR_ISSUE_LIMIT short {path?, code?, message} rows. */
export function boundErrorIssues(details) {
  if (!Array.isArray(details)) return null;
  const rows = details.filter(row => row && typeof row === 'object' && typeof row.message === 'string').map(row => ({
    ...(row.path !== undefined ? { path: clip(safePath(row.path) || 'input', PATH_LIMIT) } : {}),
    ...(typeof row.code === 'string' ? { code: clip(row.code, 80) } : {}),
    message: clip(row.message, MESSAGE_LIMIT),
  }));
  if (!rows.length) return null;
  return { issues: rows.slice(0, ERROR_ISSUE_LIMIT), ...(rows.length > ERROR_ISSUE_LIMIT ? { issuesOmitted: rows.length - ERROR_ISSUE_LIMIT } : {}) };
}

/** For INVALID_AUDIT_PROPOSAL on a finding: the expected shape and which received fields belong to draftFinding. */
export function proposalFindingHint(details) {
  if (!Array.isArray(details) || !details.some(row => /^findings\.\d+/.test(String(row?.path ?? '')))) return null;
  const received = new Set(details.flatMap(row => Array.isArray(row?.unknownKeys) ? row.unknownKeys : []));
  const draft = DRAFT_FINDING_FIELDS.filter(key => received.has(key));
  const others = details.reduce((sum, row) => sum + (Number.isInteger(row?.otherUnknownKeys) ? row.otherUnknownKeys : 0), 0);
  const unknown = draft.length
    ? `${draft.join(', ')} ${draft.length === 1 ? 'is a draftFinding field' : 'are draftFinding fields'} (only for a host's own findings tool), not proposal finding fields.`
    : '';
  return {
    expectedFinding: EXPECTED_FINDING,
    findingShapeNote: `${unknown}${unknown ? ' ' : ''}${others ? `${others} other unsupported field(s) were sent. ` : ''}Proposal findings need ${PROPOSAL_FINDING_FIELDS.map(key => key === 'target' ? 'target:{evidenceId,nodeId}' : key).join(', ')}; method is optional. Write your own observation/reason/applicability/exceptions/scope, or bank axe candidates with adoptAxe instead.`,
  };
}

/** The `error` object of an agent/MCP response: code, message, then bounded issues and, for finding shape errors, the expected shape. */
export function errorPayload(error, { messageLimit = 1500 } = {}) {
  const code = String(error?.code ?? 'AUDIT_AGENT_ERROR').slice(0, 80);
  const payload = { code, message: String(error?.message ?? error).slice(0, messageLimit) };
  const bounded = boundErrorIssues(error?.details);
  if (!bounded) return payload;
  const hint = code === 'INVALID_AUDIT_PROPOSAL' ? proposalFindingHint(error.details) : null;
  return { ...payload, ...bounded, ...(hint ?? {}) };
}
