# Collect an unknown asynchronous result

Use the existing public `openAuditAgent` protocol when the application supplies a
trustworthy completion contract. The API matches a predicate's current state;
it does not discover terminality or know the future answer.

For this recipe, the app contract must guarantee all of the following:

- Activation sets `#status[aria-busy="true"]` synchronously.
- Busy stays true through every intermediate stage, including long pauses.
- The terminal result or terminal error is rendered before busy becomes false.
- Requests do not overlap, and the original document/container remains stable.

These are contract assumptions, established independently of this capture.
An observed false attribute, or even one observed true-to-false transition,
does not prove that contract. Without a trustworthy signal, completion is
unsupported: record that limitation and stop the dependent workflow.

First inspect the control/container to establish unique selectors, identity and
attributes; complete any focus setup before the pre-activation inspection.
With an open agent, submit this consecutive sequence:

```js
const response = await agent.request({ tool: 'step', actions: [
  { action: 'click', selector: '#go' },
  { action: 'wait_for', selector: '#status', condition: 'attribute',
    name: 'aria-busy', value: 'false', timeoutMs: 3000 },
  { action: 'inspect', selector: '#status' },
] });
```

There is no result-text discovery inspection between click and wait, and no
future result literal in the wait arguments. Check each returned record's
`success` (the step envelope alone means actions were returned). Use `read`
with each returned `evidenceId` to retrieve original fields, for example:

```js
const final = await agent.request({ tool: 'read',
  evidenceId: response.records[2].evidenceId,
  options: { view: 'field', field: '/result' } });
// Concatenate data from all pagination.next pages before JSON.parse.
```

Read the wait's `/result` and original `/before` and `/after` fields too.
Require `matched: true`, one match, final busy=false, unchanged document and
original container identity, stable final before/after state, and final state
matching wait.after. Read the actual unknown result from the final inspect;
distinguish a terminal error from successful business output before continuing.
Then inspect result controls and perform post-state audits within the budget.
These checks are observations, not proof of unseen history or persistence.
The wait and after capture are separate; a race or replacement can invalidate
the recipe even when the predicate matched.

Other signals work only under an equally trustworthy operation contract:

- `attribute`, name `disabled`, value `null`: removal of a synchronously applied
  attribute on an existing control. Attribute absence is not computed enabledness
  (consider inherited fieldset disablement or custom controls); `disabled="false"`
  still has the attribute.
- `hidden` on a spinner synchronously shown at activation and kept visible until
  terminal rendering. Absence also immediately matches hidden; delayed insertion
  or hiding between stages defeats this recipe.
- `attached` on a fresh terminal-only result node. An already attached stale or
  loading node immediately matches and supplies no completion knowledge.

Selectors use main-document CSS with at most one match; duplicates fail.
Waits stop at the first matching sample, with a 1–5000 ms timeout (default 3000),
also bounded by remaining action budget. A stale/early false signal may succeed;
the API cannot diagnose a dishonest app contract. Missing signals and timeouts
are unresolved outcomes. An intermediate pause is not completion. Do not infer
an answer from private JavaScript, gold values, arbitrary sleeps or network-idle.

Retain all ordered original actions, including failed actions, and all evidence.
The optional status-message review bridge now admits exactly consecutive original
`inspect -> click -> wait_for(attribute, name="aria-busy", value="false") -> inspect`
records on the same observed unique simple-ID status node. No intervening
observation, wait or mutation is admitted in this branch. The actual successful
click remains the operation. A later independent reviewer supplies
`prerequisiteNotes.v2.statusMessage.settledEvidenceId`, not the maker.

Cite all four successful ordered originals. Require exact wait argument/result
selector and condition agreement, `matched:true`, `count:1`, `actual:"false"`,
`actualOmitted:false`, `actualTruncated:false`, and final literal `aria-busy="false"`.
Keep stable endpoint inspections, `before.after == operation.before`,
`wait.after == final.after`, the same original document/node, changed untruncated
text, focus exclusion and complete untruncated target/ancestor lineage and
live-semantics checks. The final inspect is the finding target. Independent
review must identify an applicable `status-summary`; substantive or uncertain
content stays queued. The synchronous and literal-text branches are unchanged.
Other predicates, selectors and press/fill are not admitted by this new branch.

This bridge reviews the observed summary; it does not establish terminality,
continuity, causal exclusivity or an honest application completion contract.
[WCAG status messages](https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html)
include waiting, progress and errors as well as results, without a context change.
A stale false with changed Pending text or an early false with an intermediate
summary can pass structural checks. Unchanged text is refused. The original wait
has no poll history or per-sample target identity: sample-and-restore remains a
limitation, as for the literal-text bridge. Do not infer an unseen true transition.
Completion-dependent collection still requires the independent contract above.
Synthetic supported decisions exercise public submit/review/check, not expert
semantic judgment, screen-reader behavior or autonomous completion detection.

The browser unit test `test/audit-readiness-workflow.test.js` controls first-party
producer barriers, generates terminal text after activation, and exercises single
and multiple stages, terminal errors and contract failures through public agent
step/read calls. Its test controls are fixture machinery, not part of this recipe.
