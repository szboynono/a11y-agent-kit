---
name: a11y-fix-loop
description: Legacy limited repair workflow in a11y-agent-kit: fix source accessibility issues with the local CLI, frozen functional assertions, and version-bound verification evidence. Use when a coding agent should repair an existing application and substantiate the result.
---

**Legacy skill:** `a11y-fix-loop` retains its historical identity and limited repair contract. New audits should use `a11y-audit`. The preferred executable is `a11y-agent-kit`; the commands below use its retained `a11y-fix-loop` compatibility alias.

Use the user's own coding agent and editing tools. The CLI runs Playwright and axe locally; it calls no model or model API. The host agent controls any content sent to its model. Local reports can contain DOM content, URLs, selectors, assertion text, and paths: follow the user's storage policy. Uploading reports or installing global agent configuration is not required.

The rubric target is **WCAG 2.1 Level AA**. The current three rules supply only partial evidence for SC 4.1.2; they implement no AA-specific criterion assessment. A tool `passed` result concerns the declared check contract, with WCAG conformance separately unassessed. Keep untested or human-review criteria explicit. A focused element alone does not prove a visible focus indicator under AA 2.4.7, and a mouse-assisted keyboard step does not establish keyboard-only operability. Do not mix WCAG 2.2 or AAA requirements into this target.

Use Node.js 22.12+ and install matching Chromium with `npx -y playwright@1.64.1 install chromium`. For the compatibility alias used below, run `npm install -g a11y-agent-kit@0.1.2`. You can also use `npx -y a11y-agent-kit@0.1.2` with the same subcommands. Run from the target project's working directory using absolute manifest and report paths.

Before editing source, declare the application's running HTTP(S) URL, absolute `projectRoot`, viewport, supported rules, states, interaction steps, and functional assertions in a local manifest. Supported rules are `button-name`, `label`, and `aria-valid-attr`; selectors use standard CSS. Assertions support `visible`, `enabled`, `focused`, exact `text`, and `count`. Cover the functionality that the fix must preserve. For example:

```json
{
  "projectRoot": "/absolute/target-project",
  "url": "http://127.0.0.1:3000/",
  "viewport": { "width": 1024, "height": 768 },
  "rules": ["button-name", "label", "aria-valid-attr"],
  "states": [{
    "id": "saved",
    "steps": [{ "action": "click", "selector": "#save" }],
    "assertions": [
      { "type": "visible", "selector": "#save" },
      { "type": "enabled", "selector": "#save" },
      { "type": "count", "selector": "#save", "value": 1 },
      { "type": "text", "selector": "#status", "value": "Saved" }
    ]
  }]
}
```

1. Run `a11y-fix-loop analyze /absolute/manifest.json --summary`. Keep its `reportPath` as the original frozen baseline. A nonzero exit still returns JSON; inspect `status`, errors, review reasons, failed assertions, and rule/node/check diagnostics.
2. Edit the target source with the host's tools. Address the reported selectors and causes while preserving the frozen functionality. Rebuild or restart the application as its project requires, and ensure the declared URL serves the edited source.
3. Run `a11y-fix-loop verify /absolute/original-analyze-report.json --summary`. Verification replays the baseline's original manifest; do not replace the baseline or narrow its scope to obtain a pass. If further fixes are needed, continue against that baseline within the user's task and budget.
4. Run `a11y-fix-loop check /absolute/verify-report.json --summary` after the final source edit. Treat repair as supported only when verification is `passed`, its validity is `current`, and the check is `current`. An evidence check reports freshness; it does not turn a failed report into a pass. `needs_review`, `error`, and `expired` remain unresolved outcomes.
5. Present the source diff, verification report path, result and remaining limits. These checks cover only declared states/assertions/rules. The URL-to-source relationship is caller-declared, with no build/deployment attestation; the result is not whole-site compliance.

`--summary` retains failure details and evidence metadata while omitting successful assertion details, axe passes/inapplicable results, raw node HTML, and raw check data. It is a smaller diagnostic view, with no fixed byte limit or truncation. The complete durable report at `reportPath` is authoritative; `reportDigest` identifies that file, not the summary JSON. Read the needed local report details when the summary is insufficient. Omitting `--summary` returns the full report. Keep reports local according to the user's policy; the CLI writes them under the target project's `evidence/` directory.
