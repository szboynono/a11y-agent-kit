# Codex local trial

For a first audit with your existing GPT/Codex agent, follow [first use](first-use.md). Use the local skill and CLI paths in the existing session; no global configuration or model-invoking wrapper is required.

## Local transport check

For the current provider-neutral evidence-audit workflow, use the
[BYOA quickstart](byoa-audit.md). Its local CLI commands and generic MCP adapter
can be checked without calling any model:

```sh
node scripts/quickstart.mjs
```

Run this from the source checkout after `npm ci` and Chromium installation.
The smoke exercises the documented product commands with first-party fixtures;
it does not configure or invoke Codex, select a provider, change permissions or
repair source. A user's agent can load `skills/a11y-audit/SKILL.md` and call those
local commands under its existing configuration.
