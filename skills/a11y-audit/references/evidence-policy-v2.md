# Evidence policy v2

New collectors internally stamp `evidencePolicy: "audit-evidence-2"`. Neither the auditor nor the reviewer selects this through a manifest. Derived proposals/reviews must bind the same receipt. Historical unversioned reports retain their original gate behavior.

Keep the ordinary independent reviewer identity, one decision per finding, all four checks, verdict and substantive reason. The examples below describe extra prerequisite notes only; replace every example ID with the actual evidence from this run. Missing prerequisites leave the finding in verification, even if a reviewer writes `supported`.

## Non-text contrast, 1.4.11

```json
{
  "contrast": "Explain the functional symbol, opaque interior samples, threshold, adjacent colors and exceptions.",
  "v2": {
    "nonTextContrast": {
      "contrastEvidenceId": "ev-0004",
      "requiredRatio": 3,
      "use": "Explain why this actual graphical information identifies a component or conveys required information.",
      "adjacentColors": "Identify the actual neighboring color in the original PNG.",
      "exceptions": "Address inactive, user-agent-default, logo and essential-presentation exceptions."
    }
  }
}
```

The contrast record and target must share the real document/state and stable original PNG. Its declared RGB values must decode from that PNG and reproduce the formula; the foreground must be inside the actual target rectangle. An adjacent background may be outside the component. Merely attaching a screenshot or typing a ratio is insufficient. Pixel geometry and arithmetic do not establish graphical meaning by themselves.

## Status messages, 4.1.3

Use `inspect` for the result before and after a real click/key/fill operation. It records `ancestorSemantics` through `html`; a plain old snapshot without that chain may be insufficient. The result keeps its node/document identity but normally changes `stateId` when the text changes.

```json
{
  "v2": {
    "statusMessage": {
      "beforeEvidenceId": "ev-0001",
      "operationEvidenceId": "ev-0002",
      "afterEvidenceId": "ev-0003",
      "applicability": "Explain why this is an action-result status summary without a change of context.",
      "resultKind": "status-summary",
      "semanticReview": "Distinguish the summary from substantive results, inspect equivalent status presentations and explain the original target/ancestor semantics and focus evidence."
    }
  }
}
```

The after observation must be the finding's target observation. The successful original operation must bridge the stable before/after states; changed untruncated text, original focus away from the result and complete parent/ancestor attributes are required. Existing live/status or relevant native semantics leave the absence claim for further review, rather than proving a pass or failure. The semantic interpretation remains reviewer-dependent, and this is not an actual screen-reader announcement test.

For a synchronous operation, the stable before observation's `after` state must equal the operation's `before`, and the operation's `after` must equal the final observation's stable state. Finish focus/navigation setup before the immediately preceding inspect; an older inspect from before focus movement is insufficient.

For an asynchronous operation whose recorded `after` is still pending, the existing optional `settledEvidenceId` bridges to the observed status summary. A later independent reviewer (not the maker) adds it inside `prerequisiteNotes.v2.statusMessage` alongside the synchronous semantic/identity fields shown above. It identifies an original successful `wait_for` with `condition:"text"`, literal `expected`, one matching node and complete untruncated actual text. It is not the operation: retain the successful actual click/global press/fill as `operationEvidenceId`.

The wait selector must be the same observed unique simple-ID selector for the result. Derive both selector and expected literal from actual observations; an observation establishing the settled text may precede the wait. Retain every record from trigger through final inspect in finding `evidenceIds`: all must be successful, same-document observations or matching literal waits permitted by the gate. No intervening click, fill, press, navigation, scroll, viewport or spacing mutation is allowed. Other readiness conditions do not satisfy the literal-text branch; the sole attribute exception is described below. Preserve the same result node/document throughout, changed untruncated before/after text, complete original target-to-html ancestor semantics/attributes at both ends, focus away from the result and exact stable before/trigger binding. The final inspect must be stable with `wait.after == final.after`; it is the finding's target observation. Missing or uncited prerequisites remain unresolved even with a supported verdict.

Collect these originals before a delivery checkpoint; draft/submit success is not sufficiency. Method must describe actual evidence: DOM plus keyboard does not automatically require combined. Visual/combined still requires a stable original target PNG in the target DOM's exact document/state, and visual judgments require authorized viewing. Visual criteria require their PNG evidence even when method is DOM or omitted. Do not evade by relabeling; unavailable access remains unresolved. No ARIA chain proves a screen-reader announcement. Mechanical completeness remains reviewer-dependent and never automatically promotes a claim.

### Unknown-text status summary

The existing reviewer-only `settledEvidenceId` also admits exactly consecutive
original `inspect -> click -> wait_for(condition:"attribute", name:"aria-busy", value:"false") -> inspect`
records on the same observed unique simple-ID status node. There may be no
intervening observation, wait or mutation. Keep the actual successful click as
operation; press/fill, arbitrary predicates and broader selectors are unsupported.
Cite all four successful ordered records. Wait arguments and result must agree
exactly on condition and selector, with `matched:true`, `count:1`, `actual:"false"`,
`actualOmitted:false`, `actualTruncated:false`; final target busy must be literal
`"false"`. Preserve all existing stable endpoint, before.after=operation.before,
wait.after=final.after, original node/document, changed untruncated text, focus,
complete untruncated attributes/ancestor lineage and live-semantics checks.
The final inspect remains the finding target. Independent applicability review
must select `status-summary`; substantive/uncertain judgments remain queued.

This supports review of the observed summary, never business terminality,
continuity or causal exclusivity. Stale false with changed Pending text and early
false with an intermediate status can structurally pass; unchanged text refuses.
No poll history or sample target ID exists, so sample-and-restore remains a
limitation as with literal text; do not infer a true transition. Waiting, progress
and errors can be status messages under [WCAG 4.1.3](https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html).
No screen-reader or autonomous completion claim follows. Completion-dependent
collection requires an independently established application contract.

## Text contrast and alternatives, 1.4.3

Also supply the existing outer `contrast` explanation. For ordinary small text:

```json
{
  "contrast": "Identify actual readable text, recorded size, full-color samples, threshold and exceptions.",
  "v2": {
    "textContrast": {
      "textKind": "normal",
      "requiredRatio": 4.5,
      "applicability": "Explain why this actual text is neither incidental nor exempt.",
      "alternativePresentation": {
        "kind": "none-observed",
        "explanation": "Describe the checks of available relevant presentation mechanisms in this declared scope.",
        "evidenceIds": ["ev-0001"]
      }
    }
  }
}
```

Use `kind: "unverified"` and an explanation when a relevant alternative remains unresolved. That does not confirm a failure. `textKind: "large"` with `requiredRatio: 3` needs the recorded font size and, when relying on bold-size eligibility, font weight.

For an actually activated alternative, use `kind: "evaluated"`, an explanation, and:

- `alternateState: {evidenceId, documentId, stateId, jsonSha256}` identifying its original DOM observation.
- `control` and `equivalence`, each `{status, explanation, evidenceIds}`. Status is `supported`, `insufficient` or `contradicted`. The control evidence includes the actual successful activation from the original to the distinct alternate state. Review the control's relevant conditions and equivalent information/function; do not infer them from one ratio.
- `targetLevel: {status, explanation, dependencies}`. Status is `supported`, `not-fully-audited` or `counterexample`. An incomplete audit alone cannot disqualify the alternative.

Each counterexample dependency has `{findingId, evidenceId, documentId, stateId, jsonSha256, evidenceIds}`. It must refer to another independently supported finding with its valid gate, actual target and supporting evidence in that same alternate state. Keep those records in both relevant original evidence lists. Cyclic, missing, wrong-digest, default-state-only or invalidated dependencies are insufficient. If the alternative is not disproved, the ordinary text's local shortfall stays unresolved under this route.

All checks establish prerequisites for a reviewer's local judgment. They do not prove complete alternative-version conformance, whole-page AA conformance or universal zero false positives.
