---
description: Audit a web page you are authorized to test for WCAG issues with local browser evidence, then render a single-file HTML report
argument-hint: <url>
---

Audit `$ARGUMENTS` with the `a11y-audit` skill of this plugin, driving the `a11y-agent-kit` MCP server. Audit only: do not edit source files.

1. `$ARGUMENTS` must be a reachable `http(s)` URL. If it is empty or not a URL, ask for one and stop. If it is the current project's own app on a loopback address (`localhost`, `127.0.0.1`, `[::1]`), use the current project's absolute path as `projectRoot`. For any other URL, confirm the user is authorized to test it, then create a dedicated, empty workspace directory with an `evidence/` subdirectory and use its canonical absolute path as `projectRoot`; do not use the open repository. Resolve the canonical start URL first with at most 5 redirects and use the final URL.
   If a start or action error has a `navigation` field (`navigation.code` is `AUDIT_NAVIGATION_BLOCKED`), read `navigation.reason` and `navigation.suggestedAction`; the error's own code is the npm 0.1.1 code. Apply `use_url` or a `declare_origin` `manifestPatch` only for a URL or origin the user is authorized to audit; when `overridable` is `false`, stop and report it. Do not crawl, sign in, bypass bot protection, or trigger side effects on production sites.
2. Follow the skill's audit-agent playbook: `a11y_audit_start` (no `actions`), run axe first and adopt its violations, then spend the remaining budget on what axe cannot find, saving a checkpoint as soon as a concrete finding has evidence. Keep every finding tied to real evidence IDs; never turn an axe alert or suspicion into an established failure.
3. If start fails because Chromium is missing, run `node ${CLAUDE_PLUGIN_ROOT}/node_modules/playwright/cli.js install chromium` once and start again.
4. Submit the last acknowledged checkpoint digest before the budget ends. Submission yields a proposal for independent review, not confirmed findings.
5. Finish by rendering the report from the submit response's proposal report path (or, if you could not submit, the last checkpoint path):

   `node ${CLAUDE_PLUGIN_ROOT}/src/cli.js audit-report <that json path> --out <projectRoot>/evidence/a11y-report.html`

   Add `--screenshots` only if the user allows embedding page pixels. Tell the user the HTML path, the counts of findings by status, and that the report is not a conformance certification.
