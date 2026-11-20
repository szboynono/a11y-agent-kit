# Local MCP transport and host boundary

The current stdio server registers the three evidence-audit lifecycle tools
alongside the historical analyze/verify/check tools. Use the
[generic MCP configuration and workflow](byoa-audit.md#mcp-connection), with
`npx -y a11y-agent-kit@0.1.2 serve` as the local child process.

To exercise the stdio protocol on a local fixture, run the source harness
from a checkout after `npm ci` and matching Chromium installation.

```sh
node scripts/quickstart.mjs
```

The official SDK client initializes stdio, starts a fixture audit, steps, reads,
views a local PNG path, checkpoints, explicitly submits its ACK and closes.
Visual judgments require actual inspection through the host image viewer or explicit [inline image delivery](../docs/mcp-images.md). This transport
smoke does not validate any particular Codex model/provider configuration.
