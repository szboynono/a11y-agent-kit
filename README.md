# a11y-agent-kit

Install from the extracted source directory. See [source verification and test scope](docs/publication-boundary.md).

Bring your own agent. Run accessibility audits locally with your existing model and provider. Give your agent a running website and project folder: it explores with Playwright, runs axe, retains browser evidence, and produces an HTML report with findings and unfinished checks. The default workflow audits without editing application source.

We operate no model service and receive or host no audit data. There is no product account or cloud report upload. Reports, JSON and screenshots are saved on your local disk. Your agent's settings and provider policy determine what context reaches its model; the browser connects to the target site and its network resources. Captured text, URLs and pixels may be sensitive: apply your own storage policy.

New audits support WCAG 2.1 or 2.2, levels A or AA; the default is 2.2 AA.

## Why use this?

Use it when you want your agent to investigate menus, dialogs, validation, keyboard operation, focus and reflow, then hand over findings with inspectable evidence. The [audit skill](skills/a11y-audit/SKILL.md) guides exploration; the CLI saves original records, hashed PNGs and checkpoints, and supports submission for separate review. Optional local stdio MCP exposes the same operations to compatible hosts.

### How does it compare with axe?

axe-core is the automated testing foundation, run through `@axe-core/playwright`. Deque's [API documentation](https://github.com/dequelabs/axe-core/blob/develop/doc/API.md) explains that hidden menus and dialogs need activation before scanning, and `incomplete` results need further testing.

| Workflow | When to choose it |
| --- | --- |
| [axe-core with Playwright](https://github.com/dequelabs/axe-core-npm/blob/develop/packages/playwright/README.md), tests or your own agent | Automated checks on known rendered states are enough, or you already handle exploration, evidence and review. |
| a11y-agent-kit + your agent + axe-core | You want a local [exploration, evidence and review workflow](examples/byoa-audit.md) with checkpoints and HTML delivery. Budget for agent execution and separate review. |
| [Deque Axe MCP Server](https://docs.deque.com/devtools-server/4.0.0/en/axe-mcp-server/) | You want Deque's agent integration, real-browser scans, optional screenshots, automated Intelligent Guided Tests for keyboard, interactive elements and dialogs, and remediation guidance. |

An agent with axe can also explore a site. This kit supplies the surrounding workflow; it has no demonstrated detection advantage or exclusive interactive-testing claim.

## Install

Use a local copy of this source tree with Node.js 22.12 or later, npm and matching Playwright Chromium. The preferred executable is `a11y-agent-kit`; `a11y-fix-loop` remains a compatibility alias.

### Copy this to your agent

Paste into your coding-agent session for setup and an audit. No global agent configuration is required.

```text
Set up and use the local a11y-agent-kit source tree to audit my application.

1. Use my local copy of a11y-agent-kit in a separate tool folder outside
   application source. Read its README.md, package.json,
   skills/a11y-audit/SKILL.md, examples/first-use.md and examples/byoa-audit.md
   (the JSONL audit-agent request protocol) before auditing.

2. Detect OS/architecture and automatically install missing dependencies within
   host permissions. Use Node >=22.12.0 and npm via an existing version manager
   or supported user-local installation; keep PATH changes session-local and
   leave unrelated global configuration unchanged.
   Run npm ci in the tool checkout. Reuse matching Playwright Chromium or run
   node node_modules/playwright/cli.js install chromium there. On Linux, missing browser system libraries use
   node node_modules/playwright/cli.js install-deps chromium with permitted
   elevation; do not blindly sudo. Continue authorized setup without repeated
   approval questions. Report exact credential, permission, network or platform
   blockers and the command/action needed.

3. Infer the application's canonical absolute project root and running HTTP(S)
   URL; ask only if missing or ambiguous. Keep it running. Follow first-use.md
   to create evidence/audit-manifest.json: projectRoot, url,
   standard: {"version":"2.2","targetLevel":"AA"}, wallSeconds: 600,
   maxActions: 180, maxElements: 3000, no actions array.

4. Follow the audit skill using one persistent JSONL process with stdin open:
   node <absolute-tool-checkout>/src/cli.js audit-agent <absolute-manifest>
   Start with snapshot/axe, adopt bound candidates, then explore relevant
   states. Read original records and view original PNGs before visual claims;
   use real evidence/node IDs. Checkpoint early, retaining prior findings and
   axe adoption. Explicitly submit the last acknowledged checkpointDigest
   before the budget ends and check the ACK. If persistent processes are
   unavailable, follow examples/byoa-audit.md's batch workflow and explicitly
   submit its proposal. Retain unresolved axe observations and untested scope.

5. Render the returned proposal (last saved checkpoint if submission fails):
   node <absolute-tool-checkout>/src/cli.js audit-report <json-path>
   --out <projectRoot>/evidence/a11y-report.html
   Omit --screenshots unless I authorize embedding page pixels. Return HTML,
   original JSON, collection/checkpoint paths, counts by status and limitations.
   Submission is needs_review; audit-review requires actual separate reviewer
   decisions. Never fabricate approval or independence. Do not repair source
   or claim WCAG conformance.
```

### Dependencies

| Dependency | Setup / purpose |
| --- | --- |
| Source tree | Use the extracted source directory. |
| Node.js 22.12+ and npm | Run the CLI and install packages. |
| `playwright` | Browser automation. |
| `axe-core`, `@axe-core/playwright` | Automated accessibility checks. |
| `@modelcontextprotocol/server` | Optional local MCP transport. |
| `zod` | Manifest and request validation. |
| Matching Playwright Chromium | Separate browser download; regular Chrome is not a substitute. |
| Browser system libraries | Some Linux environments require additional libraries installed with approved elevation. |

`npm ci` installs the libraries together, plus development dependency `@modelcontextprotocol/client` for protocol checks. [package.json](package.json) declares dependencies; [package-lock.json](package-lock.json) pins versions and transitive dependencies in this source tree.

### Manual install for humans

With Node 22.12+ and npm available, open the extracted tool directory and install the locked dependencies:

```sh
npm ci
```

From the source directory, install matching Chromium if missing:

```sh
node node_modules/playwright/cli.js install chromium
```

If Chromium reports missing Linux system libraries, use your approved elevation flow:

```sh
node node_modules/playwright/cli.js install-deps chromium
```

## Run an audit

Follow [first use](examples/first-use.md) for the full procedure, JSONL requests, batch fallback and recovery. Keep the application running and create `evidence/audit-manifest.json` with its canonical root and actual URL:

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

Your agent follows the local audit skill through a persistent JSONL process:

```sh
node /absolute/tool/src/cli.js audit-agent /absolute/application/evidence/audit-manifest.json
```

MCP hosts can instead configure this local stdio command in project/session settings:

```sh
node /absolute/tool/src/cli.js serve
```

MCP hosts may not forward environment variables to the server process (the MCP SDK's stdio client passes only `HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM` and `USER` unless the host's server config sets `env`), so set a custom `PLAYWRIGHT_BROWSERS_PATH` in the host's server `env` config.

See [MCP connection](examples/byoa-audit.md#mcp-connection) and [image delivery](docs/mcp-images.md). Adaptive CLI needs persistent processes; visual judgment needs an image-capable host.

## Skills

A skill is your agent's playbook; the CLI executes actions, and MCP is an optional transport. Local skills need no plugin.

| Skill | Use |
| --- | --- |
| [a11y-audit](skills/a11y-audit/SKILL.md) | Recommended for new audits: collect evidence, checkpoint, submit for separate review and deliver reports. No source repair. |
| [a11y-fix-loop](skills/a11y-fix-loop/SKILL.md) | Historical, limited repair: agent-led `analyze`, source edits, `verify`, `check` against frozen states/assertions. Covers only `button-name`, `label`, `aria-valid-attr` (partial SC 4.1.2 evidence), not general automatic remediation. |

If the Claude plugin is already loaded, [its audit command](commands/a11y-audit.md) is `/a11y-agent-kit:a11y-audit <url>` and uses the audit skill/MCP. The plugin entry is included for local use from the source tree.

## What you get

Render a saved checkpoint, submitted proposal or reviewed report using its returned JSON path:

```sh
node /absolute/tool/src/cli.js audit-report /absolute/application/evidence/RETURNED_REPORT.json --out /absolute/application/evidence/a11y-report.html
```

The HTML opens locally without a server or model. It groups findings by WCAG criterion with source labels, status, targets, observations, reasoning, evidence IDs and reproduction guidance, plus standard, scope and errors. JSON and hashed PNGs remain in `evidence/`. Screenshots are omitted by default; `--screenshots` embeds bounded original pixels with your authorization. Use `audit-inventory` and follow all [inventory continuations](skills/a11y-audit/SKILL.md#account-for-retained-axe-observations) for unresolved axe observations.

For a large report, opt into bounded local delivery (the default above stays a single file):

```sh
node /absolute/tool/src/cli.js audit-report /absolute/application/evidence/RETURNED_REPORT.json --bounded --out /absolute/application/evidence/a11y-report-pages
```

`--bounded` requires an explicit, new output directory. Open its `index.html`; it lists every numbered `findings-0001.html`, `findings-0002.html`, … detail page, and each detail page links back. Keep the directory together when copying it. The CLI receipt lists every generated absolute path, UTF-8 byte size and card count. Each artifact, including the index and page chrome, is strictly below 500,000 UTF-8 bytes; each detail page has at most 50 original finding cards. Records retain their original order and full whitelisted text, IDs and evidence pointers. These counts describe original observations, not unique defects. Summary counts and review limitations apply to the whole report.

Screenshots remain opt-in via `--screenshots`, with the existing per-image, total-byte, image-count and hash checks. Embedded base64 counts toward the page bound; a screenshot is embedded only under its first citing finding across all pages. If one card (including any embedded screenshots) or the index cannot fit, the command fails before creating output; it never truncates cards or silently omits records to fit. Existing output directories are refused. Rendering and bound validation precede writes; an I/O failure may leave a new incomplete directory, whose files are only complete when the command returns `status: "ok"`. No network assets, server or model are needed. Bounded delivery does not establish host snapshot performance or browser usability.


Submission stays `needs_review`. A different reviewer inspects original evidence, criterion mapping, applicability, exceptions and scope, then supplies `audit-review` decisions; only supported claims meeting evidence requirements enter `confirmedFindings`; others stay queued or rejected. Independence is declared, not identity-verified. Rendering performs no review or integrity recheck; `audit-check` checks integrity/source freshness. Read JSON even on nonzero exits. Neither this workflow nor an axe scan establishes whole-site WCAG conformance.

## Practical limits

Coverage depends on explored pages, states, viewports and budget; catalog tracking or no findings does not mean a pass. DOM/ARIA evidence does not replace VoiceOver, JAWS or NVDA testing. DOM capture excludes iframe interiors and Shadow DOM; complex authentication and exhaustive business flows are not established.

PNGs do not establish timing or persistent focus visibility. Ordinary screenshot/contrast actions disable animations; non-text measurements allow them. Use a suitable test environment: interactions can trigger side effects. Keep the original project/evidence tree because absolute, source-bound paths do not support relocation to another checkout or machine. The caller declares which URL matches the source.

## Documentation

- [Agent index](llms.txt)
- [First local trial](examples/first-use.md)
- [CLI/MCP workflow, submission and review](examples/byoa-audit.md)
- [Audit workflow](examples/audit-workflow.md)
- [Evidence requirements](skills/a11y-audit/references/evidence-policy-v2.md)
- [MCP image delivery](docs/mcp-images.md)

See [lifecycle and state machines](docs/state-machines.md) and [reproduction and scope](docs/publication-boundary.md) for source-checkout details.

## License

Original code: [MIT](LICENSE). Dependencies and upstream material retain their licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
