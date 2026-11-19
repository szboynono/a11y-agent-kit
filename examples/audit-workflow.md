# Local browser audit with your own agent

For the current bounded `audit-agent` transport, durable checkpoints and generic host setup, start with the [BYOA workflow](byoa-audit.md). The `audit-live` route below is the older action-per-line interface.

Set up Node.js and matching Chromium as described in [first use](first-use.md). Load the [audit skill](https://github.com/szboynono/a11y-agent-kit/blob/v0.1.1/skills/a11y-audit/SKILL.md) in your agent, or read it from the installed package. Keep the site running and use the target project's canonical absolute path in the [manifest](audit-manifest.json). Save input files below the target's `evidence/` directory.

```sh
npx -y a11y-agent-kit@0.1.1 audit /absolute/site/evidence/audit-manifest.json --summary
```

The result points to a durable local collection. Without `actions`, the collector performs a bounded initial browser inspection, all axe rules configured for the selected WCAG version and level, desktop/narrow screenshots, text spacing and a keyboard sample. It does not identify every violation or turn an automatic alert into a confirmed finding.

The agent reads the observed elements and chooses additional browser actions. For example, a plan can take a baseline screenshot, enable spacing, inspect a paragraph and take another screenshot. Use selectors actually observed in that site; do not copy fixture selectors. Each batch `audit` collection starts from a new browser context, so replay the required steps. A finding must cite one collection's original node identity and evidence records.

For an adaptive audit, use `audit-live` with a manifest containing no `actions`. Keep this local process open and send an action JSON object per line. Read its response, inspect the original PNG or JSON at the returned path, then choose the next action. The browser and document identities persist between steps. Send `{"command":"finish"}` to close and seal; EOF also seals. Only the finished report can be submitted. Intermediate records have `sealed:false`, and time spent waiting for the host counts against the wall budget.

```sh
npx -y a11y-agent-kit@0.1.1 audit-live /absolute/site/evidence/live-manifest.json --summary
```

The [JSONL example](audit-live.jsonl) can be redirected into that process for a fixed demonstration. Actual agent exploration can append, for example, a contrast measurement immediately after viewing its screenshot, without replaying prior navigation. An interrupted or budget-exhausted session remains incomplete, rather than silently becoming a completed audit.

```sh
npx -y a11y-agent-kit@0.1.1 audit-submit /absolute/site/evidence/audit-UUID/audit-UUID.json /absolute/site/evidence/findings.json --summary
npx -y a11y-agent-kit@0.1.1 audit-review /absolute/site/evidence/audit-UUID/audit-proposal-UUID.json /absolute/site/evidence/review.json --summary
npx -y a11y-agent-kit@0.1.1 audit-check /absolute/site/evidence/audit-UUID/audit-review-UUID.json --summary
```

Use the actual returned paths; filenames in the example are placeholders. The submission and decision schemas are documented in the skill. `audit-submit` always requires review. The reviewer must check every claim, including applicability, alternative presentations and exceptions. Only supported claims with their required evidence go into `confirmedFindings`; unresolved and rejected claims remain recorded. `audit-check` verifies intact bytes and source freshness.

This workflow calls no model API and uploads no reports. Page text, DOM, URLs, screenshots and paths stay in local artifacts; the user's agent controls its own model traffic. Native browser ARIA and keyboard actions are not real VoiceOver/JAWS evidence. Whole-page WCAG conformance is always unassessed.
