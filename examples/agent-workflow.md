# Calling from a coding agent

The host agent owns the repair loop. The primary interface is a local CLI plus the portable [legacy a11y-fix-loop skill](../skills/a11y-fix-loop/SKILL.md). The tools provide browser observations and verification records; they do not call an LLM or edit application source. Full evidence stays under the target project's `evidence/`; the host controls any data it sends to its own model. See [local data handling](../README.md).

## Prepare the contract

Run the application locally. Adapt `manifest.json` to its absolute source root, URL, page states and selectors. Freeze the rules and relevant functional assertions before editing. Have a person or an independent checker review the assertions; a repair agent's own judgment is not the acceptance oracle.

v0 supports `button-name`, `label`, and `aria-valid-attr`. State steps use `action`; assertions use `type`. CSS selectors can express state, for example a `count` assertion on `input:checked` or `html[data-user-theme="dark"]`.

## Use the tools

- `analyze`: run the manifest and retain the returned report path. Read violations, uncertain results, failed assertions and state errors before proposing changes.
- Edit the responsible application source using the host agent's existing code tools. Rebuild the application when necessary.
- `verify`: pass the baseline report path. The tool reuses the frozen contract rather than accepting a smaller set of checks.
- `check`: check whether the source fingerprint for a report still matches the current files before presenting it as current evidence.

Use compact JSON first:

```sh
node /absolute/path/to/a11y-agent-kit/src/cli.js analyze /absolute/path/to/manifest.json --summary
node /absolute/path/to/a11y-agent-kit/src/cli.js verify /absolute/path/to/baseline-report.json --summary
node /absolute/path/to/a11y-agent-kit/src/cli.js check /absolute/path/to/verification-report.json --summary
```

`--summary` omits raw node HTML, raw check data and successful node/assertion details. It preserves status, report identity and actionable failures. The complete local report is authoritative; read details only as needed. Nonzero exits still return JSON; a finding is not a transport failure.

The optional MCP entrypoint is `node /absolute/path/to/a11y-agent-kit/src/cli.js serve`, exposing `a11y_analyze`, `a11y_verify` and `a11y_check_evidence` from a local child process. Configure it only if the host needs stdio MCP. Published input schemas are the authoritative argument shapes.

Check the MCP result's `isError` before consuming it. Tool execution returns JSON text plus `structuredContent`; the SDK's input-schema rejection uses the standard MCP error envelope with explanatory text and may omit `structuredContent`. Do not assume every text content block is JSON.

## Deliver the result

Present the application diff and the verification report together. Report the exact rules and page states, source fingerprint, failed or incomplete checks, and human decisions. A removed control, unreachable state, missing assertion, or stale result does not demonstrate a successful repair.

The relationship between the URL's running build and `projectRoot` is caller-declared in v0. Record how the application was built and served. Passing this bounded verification does not establish whole-site conformance or undocumented behavior.

Source stability uses before/after content hashes and recursive filesystem notifications. An observed write invalidates the run even when original bytes are restored. Notification failures invalidate the run; notification support is required. This is an observation boundary, not attested capture of every transient modification. Summary counts distinguish failed, errored, and not-run assertions.
