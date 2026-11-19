# Codex local trial

For a first audit with your existing GPT/Codex agent, follow [first use](first-use.md). Use the pinned npm CLI and the [audit skill](../skills/a11y-audit/SKILL.md) in your existing session.

## Source transport check

For the current provider-neutral evidence-audit workflow, use the
[BYOA workflow](byoa-audit.md). Its local CLI commands and generic MCP adapter
can be checked without calling any model:

```sh
node scripts/quickstart.mjs
```

Run this source harness from the checkout after `npm ci` and matching Chromium installation.
The smoke exercises the documented product commands with first-party fixtures;
it does not configure or invoke Codex, select a provider, change permissions or
repair source.
