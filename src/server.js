import { registerAuditTools } from './audit/mcp.js';
import { AUDIT_SERVER_INSTRUCTIONS } from './audit/agent.js';
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { analyze, verify, checkEvidence } from './index.js';
import { manifestSchema, baselineInputSchema, evidenceInputSchema } from './schema.js';
import { errorRecord } from './evidence.js';

async function toolResult(action) {
  try {
    const result = await action();
    return {
      content: [{ type: 'text', text: JSON.stringify(result) }],
      structuredContent: result,
      isError: ['error', 'failed', 'needs_review', 'expired'].includes(result.status),
    };
  } catch (error) {
    const result = { status: 'error', errors: [errorRecord(error)] };
    return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: true };
  }
}

export function createServer() {
  const server = new McpServer({ name: 'a11y-agent-kit', version: '0.1.2' }, { instructions: AUDIT_SERVER_INSTRUCTIONS });
  server.registerTool('a11y_analyze', {
    description: 'Replay declared states and CSS assertions, scan three supported axe rules, and save a frozen baseline under projectRoot/evidence. URL/source binding is caller-declared.',
    inputSchema: manifestSchema,
  }, manifest => toolResult(() => analyze(manifest)));
  server.registerTool('a11y_verify', {
    description: 'Re-run the complete frozen analyze baseline. Accepts only its path; no rule, state, assertion, or URL overrides. Errors, incomplete checks, and missing assertions cannot pass.',
    inputSchema: baselineInputSchema,
  }, ({ baselinePath }) => toolResult(() => verify(baselinePath)));
  server.registerTool('a11y_check_evidence', {
    description: 'Check report integrity and compare current source contents, including uncommitted and untracked files, with the report fingerprint.',
    inputSchema: evidenceInputSchema,
  }, ({ reportPath }) => toolResult(() => checkEvidence(reportPath)));
  registerAuditTools(server);
  return server;
}

export function serve() {
  const servers = new Set();
  const handle = serveStdio(() => { const server = createServer(); servers.add(server); return server; }, { onerror: error => process.stderr.write(`${JSON.stringify(errorRecord(error, 'mcp'))}\n`) });
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => {
    await Promise.allSettled([...servers].map(server => server.closeAudit({ reason: 'interrupted', signal })));
    await Promise.allSettled([...servers].map(server => server.close()));
    await handle.close();
    process.exitCode = signal === 'SIGTERM' ? 143 : 130;
    process.stdin.pause();
  });
  return handle;
}
