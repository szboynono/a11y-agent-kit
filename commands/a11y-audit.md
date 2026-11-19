---
description: Audit a running web page for WCAG issues with local browser evidence, then render a single-file HTML report
argument-hint: <url>
---

Audit `$ARGUMENTS` with the `a11y-audit` skill of this plugin, driving the `a11y-agent-kit` MCP server. Audit only: do not edit source files.

1. `$ARGUMENTS` must be an `http(s)` URL that is already running. If it is empty or not a URL, ask for one and stop. Use the current project's absolute path as `projectRoot`.
2. Follow the skill's audit-agent playbook: `a11y_audit_start` (no `actions`), run axe first and adopt its violations, then spend the remaining budget on what axe cannot find, saving a checkpoint as soon as a concrete finding has evidence. Keep every finding tied to real evidence IDs; never turn an axe alert or suspicion into an established failure.
3. If start fails because Chromium is missing, run `node ${CLAUDE_PLUGIN_ROOT}/node_modules/playwright/cli.js install chromium` once and start again.
4. Submit the last acknowledged checkpoint digest before the budget ends. Submission yields a proposal for independent review, not confirmed findings.
5. Finish by rendering the report from the submit response's proposal report path (or, if you could not submit, the last checkpoint path):

   `node ${CLAUDE_PLUGIN_ROOT}/src/cli.js audit-report <that json path> --out <projectRoot>/evidence/a11y-report.html`

   Add `--screenshots` only if the user allows embedding page pixels. Tell the user the HTML path, the counts of findings by status, and that the report is not a conformance certification.
