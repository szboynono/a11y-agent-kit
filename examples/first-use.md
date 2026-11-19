# First local trial with your own agent

Use the extracted source directory, Node 22.12+, the locked dependencies and matching Playwright Chromium described in the README. The commands below run from the tool checkout; replace all absolute placeholders with your own canonical paths. Keep the application running. Nothing here selects or calls a model, edits application source, or changes global agent configuration.

Create `/absolute/application/evidence/audit-manifest.json` (create `evidence/` first):

```json
{
  "projectRoot": "/absolute/application",
  "url": "http://127.0.0.1:3000/",
  "standard": { "version": "2.2", "targetLevel": "AA" },
  "wallSeconds": 600,
  "maxActions": 180,
  "maxElements": 3000
}
```

In your existing GPT/Codex or other coding-agent session, give this instruction:

> Read `/absolute/tool/skills/a11y-audit/SKILL.md`. Use `node /absolute/tool/src/cli.js audit-agent /absolute/application/evidence/audit-manifest.json` as a persistent JSONL child process. Audit this running application, adopt bound axe observations, explore the requested business states, read original evidence and view original PNGs before visual claims. Save candidates early, explicitly submit the acknowledged checkpoint digest before the budget ends, and return the proposal, collection and checkpoint paths. Keep unresolved observations and untested scope visible. Do not edit application source. Then render an HTML report from the returned proposal path.

`audit-agent` runs no `snapshot` or `axe` on its own (only MCP `a11y_audit_start` does); the agent's first request should be `{"tool":"step","actions":[{"action":"snapshot"},{"action":"axe"}]}`.

An agent that cannot keep stdin open can start with this fixed collection instead:

```sh
node /absolute/tool/src/cli.js audit /absolute/application/evidence/audit-manifest.json --summary
```

Keep the returned `reportPath`; a collection is evidence, not reviewed findings. Read its local JSON records and attachment paths. For adaptive CLI operation envelopes and the submit/review schema, follow [BYOA workflow](byoa-audit.md). MCP hosts may instead configure the local stdio command `node /absolute/tool/src/cli.js serve` in their project/session configuration and call `a11y_audit_start`, `a11y_audit_request`, `a11y_audit_close`. Reuse the same manifest; keep the returned `runId` and use actual evidence IDs. No host-specific model integration is implied by generic transport tests.

Retrieve a report after explicit submission (or from a saved checkpoint):

```sh
node /absolute/tool/src/cli.js audit-report RETURNED_PROPOSAL_OR_CHECKPOINT.json --out /absolute/application/evidence/a11y-report.html
node /absolute/tool/src/cli.js audit-check RETURNED_PROPOSAL.json --summary
node /absolute/tool/src/cli.js audit-inventory RETURNED_PROPOSAL.json --limit 100
```

Open the HTML locally. Its JSON source, original records and hashed PNGs stay under the application's `evidence/`. The HTML needs no server or model. Screenshots are omitted by default; `--screenshots` opts into embedding original page pixels. Follow inventory continuations to retain all unresolved axe observations. In an open agent session, `read` pages original records and `view` returns the original PNG path/hash; MCP also supports explicit [inline PNG delivery](../docs/mcp-images.md) for hosts with image support.

A submitted proposal remains `needs_review`. Use a different reviewer to inspect original evidence, applicability, exceptions and scope, then supply its decisions to `audit-review`; only supported claims enter `confirmedFindings`. Do not fabricate reviewer independence. Read command JSON on nonzero exits: needs-review, incomplete, expired and error are meaningful results. `audit-check:current` proves artifact integrity/source freshness within its contract, not semantic approval, URL-to-build attestation or conformance. No whole-site compliance or real screen-reader testing is established.

Evidence paths are absolute and source-bound. Keep the original project/evidence tree in place; copying reports to another checkout or machine is not a supported replay/relocation flow. See the [source and test scope](https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/docs/publication-boundary.md).

With the installation prerequisites available, run `node scripts/quickstart.mjs` against its bundled loopback example. The fixture and review decision are synthetic and invoke no model.


For a large local HTML report, use `audit-report REPORT.json --bounded --out NEW_DIRECTORY` instead of the single-file export. Start at `NEW_DIRECTORY/index.html` and retain all numbered detail pages alongside it. The receipt enumerates paths and byte/card counts. Pages preserve original observations in order, with at most 50 cards and strictly fewer than 500,000 UTF-8 bytes per file. The new directory must not exist. Oversized individual cards fail before output creation; screenshots remain separately opt-in and subject to existing caps and the page byte limit. This changes delivery only; findings are not deduplicated or independently confirmed.
