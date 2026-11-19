import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { openAuditAgent } from './agent.js';
import { AUDIT_TEXT_LIMIT, AUDIT_NODE_FIELDS, AUDIT_RECORD_FIELDS, boundAuditResponse } from './projection.js';
import { ToolError } from '../evidence.js';
import { errorPayload } from './error-details.js';

/** Persistent local JSONL. Every line is bounded text; PNGs remain files. */
export async function runAuditAgentCli({ manifest, input = process.stdin, output = process.stdout, signals = true } = {}) {
  let agent, reader, pendingSignal, writes = Promise.resolve();
  const emit = value => {
    const line = `${JSON.stringify(boundAuditResponse(value))}\n`;
    writes = writes.then(() => new Promise((resolve, reject) => output.write(line, error => error ? reject(error) : resolve())));
    return writes;
  };
  const stop = () => { reader?.close(); input.pause?.(); };
  const onSignal = signal => {
    pendingSignal = signal;
    if (agent) { void agent.close({ reason: 'interrupted', signal }).catch(() => {}); stop(); }
  };
  const handlers = new Map(['SIGINT', 'SIGTERM'].map(signal => [signal, () => onSignal(signal)]));
  if (signals) for (const [signal, fn] of handlers) process.on(signal, fn);
  try {
    agent = await openAuditAgent(manifest);
    const dnsCheck = agent.dnsCheck?.() ?? null;
    await emit({ kind: 'audit-agent-session', protocol: 'audit-agent-1', runId: agent.runId, directory: agent.directory,
      evidencePolicy: agent.evidencePolicy, budget: agent.budget(), ...(dnsCheck ? { dnsCheck } : {}), operations: ['step', 'read', 'view', 'checkpoint', 'submit', 'inventory'],
      read: { views: ['summary', 'nodes', 'field'], nodeFields: AUDIT_NODE_FIELDS, recordFields: AUDIT_RECORD_FIELDS },
      note: 'Send one operation per JSON line. Save drafts before the deadline; drafts are not final findings. Send {"command":"finish"} or EOF to close without automatic submission.' });
    reader = createInterface({ input, crlfDelay: Infinity, terminal: false });
    void agent.finished.then(stop, stop);
    if (pendingSignal) { void agent.close({ reason: 'interrupted', signal: pendingSignal }).catch(() => {}); stop(); }
    let reason = 'eof';
    if (agent.status === 'open') for await (const line of reader) {
      if (!line.trim()) continue;
      if (Buffer.byteLength(line) > AUDIT_TEXT_LIMIT) { await emit(await agent.request(null)); continue; }
      let value;
      try { value = JSON.parse(line); } catch { await emit(await agent.request(null)); continue; }
      if (value?.command !== undefined) {
        if (value.command === 'finish' && Object.keys(value).length === 1) { reason = 'requested'; break; }
        await emit(await agent.request(null)); continue;
      }
      await emit(await agent.request(value));
      if (agent.status !== 'open') break;
    }
    const result = await agent.close({ reason: pendingSignal ? 'interrupted' : reason, ...(pendingSignal ? { signal: pendingSignal } : {}) });
    await emit(result); await writes;
    return result;
  } finally {
    stop();
    if (signals) for (const [signal, fn] of handlers) process.removeListener(signal, fn);
    if (agent) await agent.close().catch(() => {});
  }
}

async function main(args) {
  if (args.length !== 1 || !args[0].trim() || args[0].startsWith('-')) throw new ToolError('USAGE', 'Usage: node src/audit/agent-cli.js manifest.json');
  const result = await runAuditAgentCli({ manifest: JSON.parse(await fs.readFile(args[0], 'utf8')) });
  if (result.termination?.signal) process.exitCode = result.termination.signal === 'SIGINT' ? 130 : 143;
  else if (result.status !== 'submitted') process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    process.stdout.write(`${JSON.stringify(boundAuditResponse({ kind: 'audit-agent-error', success: false, error: errorPayload(error, { messageLimit: 1000 }) }))}\n`);
    process.exitCode = 1;
  });
}
