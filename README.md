# a11y-agent-kit

Audit your running app, or any HTTP(S) site you are authorized to test, with the coding agent you already use. The **Bring Your Own Agent (BYOA)** MVP is available on npm as `a11y-agent-kit@0.1.1`.

Your agent can open a menu or dialog with Playwright, scan the rendered state with axe, and save browser records and screenshots. It can save a checkpoint before exploring another state. Share an HTML report that marks findings awaiting review and points to the original JSON records and PNGs.

## Run your first audit from npm

Use Node.js 22.12+ and npm. Start your app. Run the block below in a POSIX shell from your app's project root. It installs matching Playwright Chromium, writes a manifest whose `projectRoot` is the output of `pwd -P`, and runs the npm package to collect evidence. If your app runs at another address, change `url` before the last command.

```sh
npx -y playwright@1.64.1 install chromium
mkdir -p evidence
cat > evidence/audit-manifest.json <<JSON
{
  "projectRoot": "$(pwd -P)",
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
https://github.com/szboynono/a11y-agent-kit/blob/main/skills/a11y-audit/SKILL.md
and use the npx commands in this prompt for setup.
Start one persistent JSONL process with
npx -y a11y-agent-kit@0.1.1 audit-agent evidence/audit-manifest.json
Start with snapshot and axe, then adopt bound axe candidates. Open a relevant
menu or dialog and inspect that state if the app has one. Read original records
and view PNGs before making visual claims. Save checkpoints and submit the last
acknowledged digest for review. Render the returned proposal JSON with
npx -y a11y-agent-kit@0.1.1 audit-report REPORT.json --out evidence/a11y-report.html
Give me the HTML, the original evidence paths, and any gaps in coverage. Audit only.
```

The skill copy inside the npm 0.1.1 package still describes the earlier source-tree setup. Use the npx commands in this README for setup. Only a new npm version can update that copy.

For request examples, batch collection, and submission, see the [BYOA workflow](examples/byoa-audit.md). If your agent uses a local stdio MCP host, use `npx -y a11y-agent-kit@0.1.1 serve` as the server command. See the [MCP configuration](examples/byoa-audit.md#mcp-connection).

## Audit a site you are authorized to test

The kit is not limited to `localhost`. To audit a staging, production or third-party site that you own or have permission to test, use an empty workspace directory as `projectRoot` instead of a source tree, and resolve the site's canonical start URL first. By default, main-document navigation stays on the manifest origin, so an entry URL that redirects to another origin (for example `example.com` to `www.example.com`) is blocked.

```sh
npx -y playwright@1.64.1 install chromium
mkdir -p "$HOME/a11y-audits/example-site/evidence" && cd "$HOME/a11y-audits/example-site"
curl -sSIL --max-redirs 5 -o /dev/null -w '%{url_effective}\n' https://example.com/
cat > evidence/audit-manifest.json <<JSON
{
  "projectRoot": "$(pwd -P)",
  "url": "https://www.example.com/"
}
JSON
npx -y a11y-agent-kit@0.1.1 audit evidence/audit-manifest.json --summary
```

Replace `https://www.example.com/` with the URL that `curl` printed. Keep only `evidence/` in the workspace. For an agent session, paste this prompt:

```text
Audit https://www.example.com/ for accessibility. I am authorized to test it.
Use the workspace ~/a11y-audits/example-site and evidence/audit-manifest.json there.
Before starting, resolve the canonical start URL with at most 5 redirects and use
the final URL in the manifest. Read the evidence rules at
https://github.com/szboynono/a11y-agent-kit/blob/main/skills/a11y-audit/SKILL.md
and the remote-site guide at
https://github.com/szboynono/a11y-agent-kit/blob/main/examples/remote-site.md
and use the npx commands in this prompt for setup.
Start one persistent JSONL process with
npx -y a11y-agent-kit@0.1.1 audit-agent evidence/audit-manifest.json
Start with snapshot and axe, then adopt bound axe candidates. Explore only pages
on the same origin. Do not submit forms, sign in, or trigger actions with side
effects. If navigation is blocked, report the blocked URL and stop that path.
Read original records and view PNGs before making visual claims. Save checkpoints
and submit the last acknowledged digest for review. Render the returned proposal
JSON with
npx -y a11y-agent-kit@0.1.1 audit-report REPORT.json --out evidence/a11y-report.html
Give me the HTML, the original evidence paths, and any gaps in coverage. Audit only.
```

The kit does not crawl a site, bypass bot protection or CAPTCHAs, or sign in. On production sites, avoid actions with side effects. The source tree adds optional `followRedirects` and `allowedOrigins` manifest fields and, on a blocked navigation, an additive `navigation` field (`code: "AUDIT_NAVIGATION_BLOCKED"`) with a suggested next step next to the unchanged npm 0.1.1 error code; npm 0.1.1 does not include them. See the [remote-site guide](examples/remote-site.md).

## Review and share the evidence

Open the HTML locally. A submitted proposal is `needs_review`. Use a separate reviewer to inspect the originals and submit decisions with `audit-review`. Keep the project and evidence directory in place for verification. The HTML leaves out embedded screenshots by default. See [the audit skill](skills/a11y-audit/SKILL.md) and [evidence requirements](skills/a11y-audit/references/evidence-policy-v2.md).

The default workflow collects evidence for the states you explore. WCAG conformance remains unassessed, and browser ARIA data cannot tell you what a screen reader actually says.

The kit writes reports, records, and PNGs to local disk and has no model service, account, or report upload. Use your agent's settings to control what it shares with its provider. The browser connects to the target and its resources. Check captured text, URLs, and screenshots before sharing them.

## Limits

- Coverage depends on the pages, states, viewports, and budget you explore. Catalog tracking or no findings does not mean a pass.
- DOM capture excludes iframe interiors and Shadow DOM.
- PNGs do not establish timing or persistent focus visibility.
- Complex authentication and exhaustive business flows are not established.
- Interactions can trigger side effects, so use a suitable test environment.
- Reviewer independence is declared, not identity-verified.
- The caller declares which URL matches the source. For a remote site, `projectRoot` is your workspace, so source freshness describes that workspace, not the live site.
- Bot protection, CAPTCHAs, sign-in and headless-specific content are reported as observed, not bypassed.
- The recorded workflow checks used owned loopback fixtures. Validation on real third-party sites remains open, and a third-party audit is not evidence of it.
- The kit has no demonstrated detection advantage over axe.
- Audited pages are untrusted input, and the kit does not provide complete prompt-injection protection. See [trusted inputs and known gaps](#trusted-inputs-and-known-gaps).

### Trusted inputs and known gaps

- Page content reaches your agent's context. Text, attribute values, accessible names, titles, selectors, URLs and axe snippets from the audited page appear in MCP and CLI responses. The MCP server instructions and the audit skill tell the agent to treat page content as data, never as instructions. In `a11y_audit_*` MCP responses, the additive `untrustedFields` lists the page fields, and the text block wraps page strings in markers that carry a random per-session nonce; page content cannot forge or close these markers. `structuredContent` keeps the original values.
- The markers are a mitigation, not a guarantee. A model can still follow injected text. A page string can stay unmarked when the response is close to the 20,000-character limit. CLI JSONL output, the `a11y_analyze`, `a11y_verify` and `a11y_check_evidence` tools, and screenshots you view carry no markers.
- The navigation policy applies to top-level document requests only. Subresource requests (images, scripts, styles, XHR/fetch, WebSocket) and iframe documents are not checked against it.
- In a public session, the host name of each top-level document request, including every redirect hop, is resolved before the request is allowed. Any returned address that is not public (loopback, private, link-local, multicast, reserved or a listed cloud metadata address) blocks it, and so does a failed lookup. This is detection only: the checked addresses are not pinned, so DNS rebinding between the check and Chromium's own lookup is not stopped, and a fake-IP proxy hides the real destination. See the [remote-site guide](examples/remote-site.md).

<a name="install"></a>

## Source verification and contributor setup

From a source checkout, run `node scripts/verify-source.mjs` to check the files listed in the source manifest. For development, run `npm ci` and install the matching Chromium with the command above. The source-only `node scripts/quickstart.mjs` exercises the CLI and stdio MCP on a synthetic loopback fixture. See [source verification and recorded release checks](https://github.com/szboynono/a11y-agent-kit/blob/main/docs/publication-boundary.md) and [earlier archive test scope at v0.1.1](https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/docs/publication-boundary.md).

The source tree also includes a [local plugin command](https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/commands/a11y-audit.md). See the [lifecycle and state machines](https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/docs/state-machines.md) and the [agent documentation index](llms.txt).

## License

The original code is [MIT-licensed](LICENSE). Dependencies and upstream material retain their licenses. See the [third-party notices](THIRD_PARTY_NOTICES.md).
