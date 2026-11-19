function checkSummary(check) {
  // Check data and related-node HTML can contain page content. Keep the
  // diagnostic and selectors; the complete local report retains the raw data.
  const { id, impact, message, relatedNodes } = check;
  return {
    id, impact, message,
    ...(relatedNodes ? { relatedNodes: relatedNodes.map(node => ({ target: node.target })) } : {}),
  };
}

function ruleSummary(rule) {
  const { id, impact, description, help, helpUrl, tags, nodes } = rule;
  return {
    id, impact, description, help, helpUrl, tags,
    nodes: nodes.map(node => ({
      impact: node.impact,
      target: node.target,
      failureSummary: node.failureSummary,
      any: node.any.map(checkSummary),
      all: node.all.map(checkSummary),
      none: node.none.map(checkSummary),
    })),
  };
}

function stateSummary(state) {
  return {
    id: state.id,
    reached: state.reached,
    status: state.status,
    url: state.url,
    httpStatus: state.httpStatus,
    stepCount: state.steps.length,
    assertionCount: state.assertions.length,
    steps: state.steps.flatMap((step, index) => step.status === 'passed' ? [] : [{ index, ...step }]),
    assertions: state.assertions.flatMap((assertion, index) => assertion.status === 'passed' ? [] : [{ index, ...assertion }]),
    axe: state.axe ? {
      violations: state.axe.violations.map(ruleSummary),
      incomplete: state.axe.incomplete.map(ruleSummary),
    } : null,
    errors: state.errors,
  };
}

/** A CLI view only: reportDigest still identifies the complete durable report. */
export function summarizeResult(result) {
  // Evidence checks and errors have no raw scan payload to compact.
  if (!['analyze', 'verify'].includes(result.kind)) return result;
  // Preserve recorded standard/coverage metadata verbatim, including
  // not_assessed. Do not synthesize an AA assessment for legacy reports.
  const { manifest, states, ...metadata } = result;
  return {
    ...metadata,
    outputFormat: 'summary',
    scope: {
      projectRoot: manifest.projectRoot,
      url: manifest.url,
      viewport: manifest.viewport,
      rules: manifest.rules,
      stateIds: manifest.states.map(state => state.id),
    },
    states: states.map(stateSummary),
  };
}
