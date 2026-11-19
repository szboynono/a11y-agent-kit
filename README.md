# a11y-agent-kit

Audit your running app with the coding agent you already use. The **Bring Your Own Agent (BYOA)** MVP is available on npm as `a11y-agent-kit@0.1.1`.

Your agent can open a menu or dialog with Playwright, scan the rendered state with axe, and save browser records and screenshots. It can save a checkpoint before exploring another state. Share an HTML report that marks findings awaiting review and points to the original JSON records and PNGs.

## Run your first audit from npm

Use Node.js 22.12+ and npm. Start your own app, then run the block below from its project directory in a POSIX shell. Replace the example project path with the output of `pwd -P` and the URL with your app's address.

```sh
npx -y playwright@1.64.1 install chromium
mkdir -p evidence
cat > evidence/audit-manifest.json <<'JSON'
{
  "projectRoot": "/absolute/application",
  "url": "http://127.0.0.1:3000/"
}
JSON
npx -y a11y-agent-kit@0.1.1 audit evidence/audit-manifest.json --summary
```

Open the `reportPath` from the command's JSON output for the local collection. A successful run saves DOM and axe records, screenshots, and a keyboard sample under `evidence/`. Leave the app running for the next step. See the [first-use guide](examples/first-use.md).

## Copy this to your agent

Paste this into the coding agent you already use, with the same project and manifest.

```text
Audit my running localhost app using evidence/audit-manifest.json in this project.
Read the evidence rules at
https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/skills/a11y-audit/SKILL.md
Start one persistent JSONL process with
npx -y a11y-agent-kit@0.1.1 audit-agent evidence/audit-manifest.json
Start with snapshot and axe, then adopt bound axe candidates. Open a relevant
menu or dialog and inspect that state if the app has one. Read original records
and view PNGs before making visual claims. Save checkpoints and submit the last
acknowledged digest for review. Render the returned proposal JSON with
npx -y a11y-agent-kit@0.1.1 audit-report REPORT.json --out evidence/a11y-report.html
Give me the HTML, the original evidence paths, and any gaps in coverage. Audit only.
```

For request examples, batch collection, and submission, see the [BYOA workflow](examples/byoa-audit.md). If your agent uses a local stdio MCP host, use `npx -y a11y-agent-kit@0.1.1 serve` as the server command. See the [MCP configuration](examples/byoa-audit.md#mcp-connection).

## Review and share the evidence

Open the HTML locally. A submitted proposal is `needs_review`. Use a separate reviewer to inspect the originals and submit decisions with `audit-review`. Keep the project and evidence directory in place for verification. The HTML leaves out embedded screenshots by default. See [the audit skill](skills/a11y-audit/SKILL.md) and [evidence requirements](skills/a11y-audit/references/evidence-policy-v2.md).

The default workflow collects evidence for the states you explore. WCAG conformance remains unassessed, and browser ARIA data cannot tell you what a screen reader actually says.

The kit writes reports, records, and PNGs to local disk and has no model service, account, or report upload. Use your agent's settings to control what it shares with its provider. The browser connects to the target and its resources. Check captured text, URLs, and screenshots before sharing them.

<a name="install"></a>

## Source verification and contributor setup

From a source checkout, run `node scripts/verify-source.mjs` to check the files listed in the source manifest. For development, run `npm ci` and install the matching Chromium with the command above. The source-only `node scripts/quickstart.mjs` exercises the CLI and stdio MCP on a synthetic loopback fixture. See [source verification and earlier archive test scope](https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/docs/publication-boundary.md).

The source tree also includes a [local plugin command](https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/commands/a11y-audit.md). See the [lifecycle and state machines](https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/docs/state-machines.md) and the [agent documentation index](llms.txt).

## License

The original code is [MIT-licensed](LICENSE). Dependencies and upstream material retain their licenses. See the [third-party notices](THIRD_PARTY_NOTICES.md).
