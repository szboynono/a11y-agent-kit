# Local MCP transport and host boundary

The current stdio server registers the three evidence-audit lifecycle tools
alongside the historical analyze/verify/check tools. Use the
[generic MCP configuration and workflow](byoa-audit.md#mcp-connection), with
`node /absolute/tool/src/cli.js serve` as the local child process.

To exercise that exact server command and its audit operations without a model,
run this in a source checkout after dependency/browser setup:

```sh
node scripts/quickstart.mjs
```

The official SDK client initializes stdio, starts a fixture audit, steps, reads,
views a local PNG path, checkpoints, explicitly submits its ACK and closes.
Visual judgments require actual inspection through the host image viewer or explicit [inline image delivery](../docs/mcp-images.md). This transport
smoke does not validate any particular Codex model/provider configuration.
