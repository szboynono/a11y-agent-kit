# Run a first local audit with your own agent

Use Node.js 22.12+ and npm. Keep your application running and install the Chromium build that matches the package. To audit a deployed or third-party site instead, see [Audit a deployed or third-party site](#audit-a-deployed-or-third-party-site) below.

```sh
npx -y playwright@1.64.1 install chromium
```

If Chromium reports missing Linux system libraries, use your permitted elevation flow to run `npx -y playwright@1.64.1 install-deps chromium`.

## Collect an initial sample

From your application's directory, create `evidence/` and save this as `evidence/audit-manifest.json`. Use the canonical absolute project path (`pwd -P` in a POSIX shell) and your running application's URL.

```json
{
  "projectRoot": "/absolute/application",
  "url": "http://127.0.0.1:3000/"
}
```

```sh
npx -y a11y-agent-kit@0.1.1 audit evidence/audit-manifest.json --summary
```

Open the JSON file at the returned `reportPath`. The default plan takes a bounded sample with DOM snapshots, axe, screenshots, text spacing, and keyboard input. Use the record and attachment paths to inspect the evidence. Findings require submission and separate review.

## Let your agent explore more states

Paste the [README prompt](../README.md#copy-this-to-your-agent) into your coding-agent session. The agent can read the [audit skill](../skills/a11y-audit/SKILL.md). The copy inside the npm 0.1.1 package still describes the earlier source-tree setup, so use the npx commands in this guide for setup. Only a new npm version can update that copy. Start a new adaptive session with the same manifest and keep stdin open.

```sh
npx -y a11y-agent-kit@0.1.1 audit-agent evidence/audit-manifest.json
```

Read the greeting and send `{"tool":"step","actions":[{"action":"snapshot"},{"action":"axe"}]}` as the first request. MCP `a11y_audit_start` runs that step by default. The [BYOA workflow](byoa-audit.md) covers the JSONL requests, budget, batch fallback, and [stdio MCP configuration](byoa-audit.md#mcp-connection).

Read the original records and view the original PNGs before making visual claims. In an open session, `read` pages original records and `view` returns the original PNG path and hash. MCP also supports explicit [inline PNG delivery](../docs/mcp-images.md) for hosts with image support. Save checkpoints early and explicitly submit the last acknowledged digest. Keep unresolved axe observations and untested scope visible.

## Open the report and prepare review

Substitute the paths returned by the toolkit. Use a checkpoint JSON or the proposal JSON for HTML. Use the proposal JSON for integrity checks and inventory. Run the commands separately.

```sh
npx -y a11y-agent-kit@0.1.1 audit-report RETURNED_PROPOSAL_OR_CHECKPOINT.json --out evidence/a11y-report.html
npx -y a11y-agent-kit@0.1.1 audit-check RETURNED_PROPOSAL.json --summary
npx -y a11y-agent-kit@0.1.1 audit-inventory RETURNED_PROPOSAL.json --limit 100
```

Open the HTML locally. Use `--screenshots` only if you want to embed original page pixels. Follow the [inventory continuations](../skills/a11y-audit/SKILL.md#account-for-retained-axe-observations) for all unresolved axe observations. For a large report, add `--bounded` and pass a new directory to `--out`. Open its `index.html` and keep the numbered detail pages alongside it. The [BYOA workflow](byoa-audit.md#export-a-large-html-report) describes the output limits.

A submitted proposal stays `needs_review`. Use a separate reviewer to inspect the original evidence, applicability, exceptions, and scope. Supply that reviewer's decisions to `audit-review`. Only supported claims enter `confirmedFindings`. Read JSON even on a nonzero exit. `audit-check:current` verifies artifact integrity and source freshness within its contract. It leaves semantic approval and WCAG conformance unassessed.

## Audit a deployed or third-party site

The same commands work for any HTTP(S) site you own or are authorized to test. Three things change:

- Use a dedicated, empty workspace directory as `projectRoot` and keep the manifest under its `evidence/`. Do not point `projectRoot` at an unrelated repository.
- Resolve the canonical start URL first, for example with `curl -sSIL --max-redirs 5 -o /dev/null -w '%{url_effective}\n' https://example.com/`, and use the printed URL as `url`. Main-document navigation stays on that origin; a redirect to another origin is blocked.
- Avoid actions with side effects on production sites. The kit does not crawl, sign in or bypass bot protection.

See the [remote-site guide](remote-site.md) for declared origins, blocked-navigation details, WAF and headless behavior, and how to read the report. An audit of a third-party site is not evidence that this kit has been validated on real sites.

## Keep the evidence

Keep the original project and evidence tree in place. The evidence uses absolute paths and binds to the source. Review captured text, URLs, and images before letting your agent send them or sharing the report. See [source verification and test scope](https://github.com/szboynono/a11y-agent-kit/blob/main/docs/publication-boundary.md).
