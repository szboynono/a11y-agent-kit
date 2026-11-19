# Connect your coding agent to the local evidence audit

The evidence audit supports local CLI and stdio MCP transports. Any host that can run local commands and read local files can use batch collection. Adaptive exploration additionally needs a persistent child process with writable stdin and readable stdout. Visual judgments need the host's local image viewer. No particular model, provider, account or global agent configuration is required by this tool.

The `serve` transport registers `a11y_audit_start`, `a11y_audit_request` and `a11y_audit_close`, alongside the legacy analyze, verify and evidence-check tools. Use the audit tools for this workflow. Transport smoke uses the SDK client. Real-model host behavior remains untested by that smoke.

Start with the [first-use instructions](first-use.md) for installation and report retrieval.

## MCP connection

Install matching Chromium as described in [first use](first-use.md). For a stdio host that accepts `mcpServers`, add this entry to its configuration.

```json
{"mcpServers":{"a11y-agent-kit":{"command":"npx","args":["-y","a11y-agent-kit@0.1.1","serve"]}}}
```

If you installed Chromium with a custom `PLAYWRIGHT_BROWSERS_PATH`, set the same value in the server environment through your host configuration.

Call `a11y_audit_start` with `{"manifest":{...}}`, using the manifest below. Retain the returned exact `runId`. Call `a11y_audit_request` with `{"runId":"RETURNED_ID","request":{...}}`; `request` is one of the six JSONL requests documented below (`step`, `read`, `inventory`, `view`, `checkpoint` or `submit`). Each connection admits one session, serializes lifecycle operations and never restarts or submits automatically. MCP text results and errors are bounded to 20,000 UTF-8 bytes; CLI responses retain the 65,536-byte cap. Inspect `success` and `error`, including for needs-review submission results.

Use step → read/view → checkpoint, retain the ACK digest, then explicitly submit that digest. Close with `a11y_audit_close({runId})`; disconnect/EOF/signals retain drafts without promotion. A closed session cannot be reused. The existing 60-attempt, action and time budgets apply. Wrong IDs and changed original evidence are rejected.

By default `view` returns the verified original local PNG path/hash. MCP hosts can opt into [inline PNG delivery](../docs/mcp-images.md) with top-level `imageOutput:"inline"`. Visual claims require inspecting the image, either in a local viewer or as an inline PNG. If the host cannot show images, use text evidence and disclose the missing visual scope. Do not treat the legacy analyze/verify tools as this audit or as permission to repair.

## Prepare the local target

Main-document navigation stays on the manifest origin, including every HTTP redirect hop. Same-origin redirects are allowed; a redirect to another origin is blocked before contacting it. Ordinary cross-origin subresources remain outside this navigation guard; frozen network replay has its own stricter resource policy.

The source tree (not npm 0.1.1) adds optional `allowedOrigins` (extra exact origins) and `followRedirects` (follow redirects to those origins and same-host `http` to `https` upgrades, at most 5 hops). A blocked navigation keeps its npm 0.1.1 error code and `details`, and adds a `navigation` field (`code: "AUDIT_NAVIGATION_BLOCKED"`) with `fromUrl`, `blockedUrl`, `redirectChain`, `reason` and an advisory `suggestedAction` in CLI JSON, JSONL and MCP. Credentials in URLs and HTTPS-to-HTTP redirects are always blocked. A cloud metadata address is blocked in every session. A public site is blocked from reaching any other address that one shared table classifies as not public (see the remote-site guide for the ranges). This applies whether the address is written as an IP literal or `localhost` name or reached through a DNS name that resolves to it. A start host that resolves to a private address, such as a local development or staging name, is not refused; it makes the session private. Only an answer that proves such an address blocks. A failed or timed-out lookup does not: the session's `dnsCheck` is reported as `degraded`, and a private target may then go undetected. A slow resolver costs at most one 2-second wait per navigation; a failed host is remembered for the session (up to 64 hosts) and not looked up again, unless it timed out only because its navigation had less than 2 seconds left. `198.18.0.0/15` is treated as public on purpose because fake-IP proxies use it. Addresses are checked, not pinned, so DNS rebinding is not stopped. See the [remote-site guide](remote-site.md#4-same-origin-declared-origins-and-blocked-navigation).

Use Node.js 22.12+ and npm. Run `npx -y playwright@1.64.1 install chromium` and keep your application running. Create its `evidence/` directory and save this as `evidence/audit-manifest.json`. Set `projectRoot` to the application's canonical absolute path and `url` to its running address. Generated manifests, proposals, reviews and host logs belong under that application's `evidence/`, outside its source fingerprint.

For a deployed or third-party site you are authorized to test, set `projectRoot` to a dedicated, empty workspace directory and `url` to the site's resolved canonical start URL (see the [remote-site guide](remote-site.md) and [audit-manifest-remote.json](audit-manifest-remote.json)). Keep everything under that workspace's `evidence/`. The kit does not crawl, sign in or bypass bot protection; avoid side-effecting actions on production sites.

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

Start with the [prompt for your agent](../README.md#copy-this-to-your-agent). Use the [audit skill](../skills/a11y-audit/SKILL.md). The copy inside the npm 0.1.1 package still describes the earlier source-tree setup, so use the npx commands in these guides for setup.

New audit manifests accept optional `standard: {version: "2.1" | "2.2", targetLevel: "A" | "AA"}`. New collections default to **2.2 AA / 55 criteria** (31 A, 24 AA); 2.1 AA has 50, 2.1 A has 30, and 2.2 A has 31. Other versions and AAA are rejected. The same manifest works in CLI, MCP and audit-agent. Reports retain the normalized selection and catalog digest; historical reports without a selection remain original 2.1 AA, without upgrading their target or rewriting their bytes. Legacy v0 analyze/verify/check remains 2.1 AA. Ordinary website requests can reach external resources. Local artifact storage and absence of a product model API do not imply an offline browser or prevent your host from sending content to its configured model.

## Adaptive JSONL session

Start a child process and keep its stdin open:

```sh
npx -y a11y-agent-kit@0.1.1 audit-agent /absolute/application/evidence/audit-manifest.json
```

Read the initial `audit-agent-session` greeting before sending requests. Send one JSON object per line, wait for its response, and inspect `success`/`error`. Do not start a new process for each operation. The manifest has no predeclared `actions` for this mode.

Pair responses with requests in order. `read` returns a projection object directly (for example `success`, `nodes`, `pagination`), without the `tool:"read"` envelope used by other operations. A closing response may also arrive on deadline; handle it as terminal rather than another read result.

For changing pages, first follow the [readiness and screenshot procedure](../skills/a11y-audit/SKILL.md#collect-and-explore): `wait_for` an observed explicit condition, then acquire a new snapshot before screenshot. Preserve failures; retry that sequence at most once within budget. Continued changes leave visual evidence unresolved; fixed delays and old state cannot establish stability.

```jsonl
{"tool":"step","actions":[{"action":"snapshot"},{"action":"screenshot"}]}
```

Use the actual successful evidence IDs returned by `step`. If these are `ev-0001` (snapshot) and `ev-0002` (screenshot), the next requests can be:

```jsonl
{"tool":"read","evidenceId":"ev-0001"}
{"tool":"read","evidenceId":"ev-0001","options":{"view":"nodes","fields":["tag","attributes","text","rect"],"limit":25}}
{"tool":"view","evidenceId":"ev-0002"}
```

For node paging, pass `pagination.next` unchanged as the next request's `options`. Deferred field handles use `view:"field"`; concatenate their `data` chunks and JSON-parse the result. Step rows for `press` already show `focus` and `defaultPrevented` (`true` = the page cancelled that keydown, not proof that controls are unreachable; `null` = unknown). The full element is in the record: read `{"view":"field","field":"/after/active"}` on the press record (`/before/active` is the element focused before it); `/result/focusedElement` is not set there, and an `AUDIT_FIELD_ABSENT` error lists the nearest existing paths. Retain original truncation flags: complete paging cannot recover content never captured. `view` returns the verified original PNG path/hash; open it with your host image viewer. Text responses are capped at 65,536 UTF-8 bytes; PNG bytes remain outside JSON text.

`press` takes Playwright key names (case-sensitive): `Tab`, `Shift+Tab`, `Enter`, `Escape`, `ArrowDown`, `Space`, joined with `+` for modifiers (`Control+/`, `ControlOrMeta+/`). `Ctrl`, `Cmd`, `Esc` and lower-case `tab` are unknown names and fail the press with an error row. A printed symbol is pressed as itself: `?` reaches the page as `key:"?"`, `Shift+/` as `key:"/"` with `shiftKey:true`, and `Control+/` as `key:"/"` with `ctrlKey:true`.

Use `inventory` to list retained axe observations and check the unresolved count. Each page uses a request attempt and performs no browser action. If `inventory.pagination.next` is present, pass it unchanged as the next `inventory` request's `options`.

```jsonl
{"tool":"inventory","options":{"limit":100}}
```

Continue using observed selectors and actions documented in the [audit skill](../skills/a11y-audit/SKILL.md). Save a checkpoint after meaningful candidate/evidence changes:

```jsonl
{"tool":"checkpoint","proposal":{"auditor":{"name":"Your auditor"},"findings":[]}}
```

The empty list above demonstrates the envelope only. Actual findings require the skill's full schema, original evidence/node IDs, applicability, exceptions and scope. Check the ACK's `checkpointPath`, `checkpointDigest` and version. Checkpoints remain `draft/needs_review/scoreable:false` and allow further exploration. Do not replace unresolved candidates with an empty list to appear complete.

When ready, submit the acknowledged version explicitly:

```jsonl
{"tool":"submit","checkpointDigest":"sha256:REPLACE_WITH_ACKNOWLEDGED_DIGEST"}
```

This seals collection and creates a **needs-review proposal**, not confirmed findings. Alternatively send `{"command":"finish"}` or EOF to close without submitting; save the closing `sourceAudit` and checkpoint paths. Defaults allow 600 seconds, exploration through 480 seconds, 180 actions and 60 attempted operations. Reads, views, checkpoints, errors and host idle time consume the relevant budgets. Leave room for submission; timeout is incomplete.

For a transport smoke only, redirect [audit-agent-smoke.jsonl](audit-agent-smoke.jsonl) into the command and capture stdout under the application's `evidence/`. It assumes the first two actions succeed; it does not adapt to failures, inspect the returned image or perform an audit. Expected final status is `incomplete`, exit **1**, a retained empty draft, and no automatic proposal.

## Batch fallback and review

A host without persistent process support can collect a fixed plan:

```sh
npx -y a11y-agent-kit@0.1.1 audit /absolute/application/evidence/audit-manifest.json --summary
```

Without `actions`, this collects a bounded initial DOM/axe/visual/spacing/keyboard sample. Read returned local artifacts and use the skill's proposal schema. Each batch starts a fresh browser; keep all evidence for one claim in one collection. Batch mode has no live checkpoint/read/view operations.

Use actual returned paths for submission, independent review and integrity/source freshness:

```sh
npx -y a11y-agent-kit@0.1.1 audit-submit AUDIT_REPORT.json FINDINGS.json --summary
npx -y a11y-agent-kit@0.1.1 audit-review PROPOSAL_REPORT.json REVIEW.json --summary
npx -y a11y-agent-kit@0.1.1 audit-check REVIEWED_REPORT.json --summary
```

To recover a saved draft after closure:

```sh
npx -y a11y-agent-kit@0.1.1 audit-checkpoint-read CHECKPOINT.json
npx -y a11y-agent-kit@0.1.1 audit-submit-checkpoint AUDIT_REPORT.json CHECKPOINT.json
```

Parse JSON even on a nonzero exit. Draft reads, recovered proposals, and submissions awaiting review return exit 1 by design. `audit-agent` exits 0 only after explicit successful submission; inspect the proposal's `needs_review` status anyway. Errors/incomplete/expired states are not an accessible-site result. `audit-check:current` means intact evidence and matching source, not semantic approval. Only independently supported claims satisfying the evidence contracts enter `confirmedFindings`. Whole-page conformance remains `not_assessed`; no real screen-reader evidence is supplied here.

`audit-review` returns exit **2** when it saves a report with `status:"partial"`, with a message naming the saved file. Exit0 means a saved review with no queued findings; errors still return exit1. Capture stdout JSON and the exit code (handle the command explicitly under `set -e`), inspect `status`/errors, and use the returned `reportPath` for subsequent commands. Keep these as separate steps, not an `&&` success chain. A reviewer's `verdict:"insufficient"` remains in `verificationQueue` as `needs_review`. An error receipt or absent `reportPath` is not a partial report. Saved means written and closed, not a crash-safe storage guarantee.

You may submit any subset of decisions, including an empty list. Unknown or duplicate finding IDs are rejected. Omitted findings remain in the original denominator as unassessed, with `reviewProgress` reporting submitted and unassessed counts. An empty list assesses nothing. To choose a new exclusive output filename, use `audit-review PROPOSAL_REPORT.json REVIEW.json --out /absolute/external/review.json --summary`. Its parent directory must already exist without symlinks. The destination must be directly in the collection's own canonical run directory or outside the audited project and every other audit run; source paths and foreign run paths are rejected before writing. Existing files are never replaced. A copied proposal must still be opened at its original `reportPath`; there is no automatic redirect.

New reviews declare `directEvidencePolicy:"dom-predicates-v1"`. An ordinary nonvisual decision cites `directEvidence:{evidenceId,nodeIds,criterionClause,explanation}` using a successful referenced same-state DOM record and the exact criterion token. Citations alone cannot confirm a finding. The implemented ordinary predicate is missing programmatic name under4.1.2: it checks complete retained naming fields/attributes, label relations, rendered component evidence and a supported component kind. Native text/number inputs and focusable sliders use their naming receipts; native buttons additionally need an `inspect` record whose target-scoped browser ARIA snapshot has an empty button name. Naming attributes, label text, truncated receipts or unsupported component types keep the claim queued. Other ordinary criteria, including1.3.1, have no implemented semantic predicate and remain queued; truncated ancestry cannot establish relationships. Reviewer applicability, scope and exception checks still apply.

Visual, keyboard and status claims use their own evidence requirements. The reviewer still evaluates each claim after the tool checks its prerequisites. Historical declaration-only and `dom-citations-v1` reviews preserve their original bytes but `audit-check` returns `needs_review`, with `reviewPolicy` and `requiresReReview:true`. Summaries label them; HTML and inventory display their earlier confirmations as needing re-review. They are not current-policy confirmations.

## Read and print the HTML report

The report header shows the report state (draft checkpoint, awaiting review, or independently reviewed), the audited page, and the notice that the report is not a conformance certification. The summary counts findings by review status and by source and lists the success criteria that have findings. A criterion with no finding is not a pass. Findings are grouped by success criterion. Each card shows status, source, target, scope, observation, and any review verdict. Reproduction steps, the author's rationale, evidence IDs, and missing evidence are collapsed under each card. Screenshots embedded with `--screenshots` are inside the collapsed Evidence section. The observation inventory is collapsed below its counts. When every recorded evidence path is in one directory, the table caption names that directory and each row shows only the file name. Otherwise rows show full paths.

The page contains no script and follows the system light or dark setting. Printing uses the light colors. Browsers that support the `::details-content` selector (Chrome 131, Safari 18.4, Firefox 143, or later) print every collapsed section expanded. Older browsers print collapsed sections closed, so their printouts omit that content. In those browsers, open each section before printing, or use the JSON report as the complete record.

## Export a large HTML report

Pass a checkpoint, proposal, or reviewed report. Choose a new output directory.

```sh
npx -y a11y-agent-kit@0.1.1 audit-report REPORT.json --bounded --out evidence/a11y-report-pages
```

Open `index.html`. Keep it and the numbered detail pages together. The JSON receipt lists every generated path, UTF-8 byte size, and card count. Each file is smaller than 500,000 UTF-8 bytes. Each detail page contains at most 50 finding cards in their original order. Counts refer to the saved observations. Review status and limitations apply to the whole report.

Screenshots are opt-in with `--screenshots`. Embedded pixels count against the page size and remain subject to the image count, size, and hash checks. The renderer embeds each screenshot under its first citing finding across the report. If a card or the index cannot fit, the command fails before creating output. An I/O failure can leave an incomplete directory. Check for `status: "ok"` in the receipt.

## Exercise the source harness

Run this from the source checkout after `npm ci` and matching Chromium installation. The npm package omits this script.

```sh
node scripts/quickstart.mjs
```

The script serves an owned synthetic fixture on loopback and writes fresh local
results under `evidence/byoa-quickstart/`. It uses returned artifact paths and
checkpoint digests. The review decision is synthetic. The MCP smoke sends five
request types (`step`, `read`, `view`, `checkpoint` and `submit`).
`inventory` is outside this smoke. For `view`, the script checks that the
returned local PNG file is nonempty. See
[source verification and test scope](https://github.com/szboynono/a11y-agent-kit/blob/main/docs/publication-boundary.md) for the static verifier
and the limits of this exercise.
