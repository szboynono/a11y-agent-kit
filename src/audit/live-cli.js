import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { errorRecord, ToolError } from '../evidence.js';
import { summarizeAudit } from './review.js';
import { openAuditSession } from './live.js';

function summarizedRecord(record) {
  return { evidenceId: record.evidenceId, action: record.action, arguments: record.arguments, success: record.success,
    stateId: record.after?.stateId ?? null, documentId: record.after?.documentId ?? null, json: record.json,
    ...(record.png ? { png: record.png } : {}), ...(record.error ? { error: record.error } : {}) };
}

/** Local JSONL transport. Returns the complete sealed report. */
/** `lifecycle` is an in-process option for tests (for example an injected browser); the CLI never sets it. */
export async function runAuditSessionCli({ manifest, input = process.stdin, output = process.stdout, signals = true, summary = false, lifecycle } = {}) {
  let session, reader, pendingSignal, outputQueue = Promise.resolve();
  const emit = value => {
    outputQueue = outputQueue.then(() => new Promise((resolve, reject) => {
      output.write(`${JSON.stringify(value)}\n`, error => error ? reject(error) : resolve());
    }));
    return outputQueue;
  };
  const stopReading = () => { reader?.close(); input.pause?.(); };
  const onSignal = signal => {
    pendingSignal = signal;
    if (session) { void session.finish({ reason: 'interrupted', signal }).catch(() => {}); stopReading(); }
  };
  const handlers = new Map(['SIGINT', 'SIGTERM'].map(signal => [signal, () => onSignal(signal)]));
  if (signals) for (const [signal, handler] of handlers) process.on(signal, handler);
  try {
    session = await openAuditSession(manifest, lifecycle);
    const dnsCheck = session.dnsCheck;
    await emit({ type: 'session', status: session.status, sealed: false, session: { runId: session.runId, directory: session.directory, manifest: session.manifest, startedAt: session.startedAt, deadlineAt: session.deadlineAt }, ...(dnsCheck ? { dnsCheck } : {}) });
    reader = createInterface({ input, crlfDelay: Infinity, terminal: false });
    void session.finished.then(stopReading, stopReading);
    if (pendingSignal) { void session.finish({ reason: 'interrupted', signal: pendingSignal }).catch(() => {}); stopReading(); }
    let finishReason = 'eof';
    if (session.status === 'open') for await (const line of reader) {
      if (!line.trim()) continue;
      let value;
      try { value = JSON.parse(line); }
      catch {
        await emit({ type: 'error', sealed: false, error: { code: 'INVALID_AUDIT_LIVE_LINE', message: 'Each input line must be a JSON action or the finish command.' } });
        finishReason = 'input_error'; break;
      }
      if (value?.command !== undefined) {
        if (value.command !== 'finish' || Object.keys(value).length !== 1) {
          await emit({ type: 'error', sealed: false, error: { code: 'INVALID_AUDIT_LIVE_COMMAND', message: 'The only supported command is {"command":"finish"}.' } });
          finishReason = 'input_error';
        } else finishReason = 'requested';
        break;
      }
      try {
        const record = await session.perform(value), dns = session.dnsCheck;
        // A degraded DNS check is repeated on each record line, so a reader of any line sees that detection was reduced.
        await emit({ type: 'record', sealed: false, record: summary ? summarizedRecord(record) : record, ...(dns?.status === 'degraded' ? { dnsCheck: dns } : {}) });
      } catch (error) {
        await emit({ type: 'error', sealed: false, error: errorRecord(error, 'audit-live-command') });
      }
      if (session.status !== 'open') break;
    }
    const report = await session.finish(pendingSignal ? { reason: 'interrupted', signal: pendingSignal } : { reason: finishReason });
    await emit({ type: 'finished', sealed: true, status: report.status, report: summary ? summarizeAudit(report) : report });
    return report;
  } catch (error) {
    if (session) await session.finish({ reason: 'internal_error' }).catch(() => {});
    throw error;
  } finally {
    stopReading();
    if (signals) for (const [signal, handler] of handlers) process.off(signal, handler);
  }
}

async function main(args) {
  const summary = args.at(-1) === '--summary', paths = summary ? args.slice(0, -1) : args;
  if (paths.length !== 1 || paths[0].startsWith('-')) throw new ToolError('USAGE', 'Usage: node src/audit/live-cli.js manifest.json [--summary]');
  let manifest;
  try { manifest = JSON.parse(await fs.readFile(paths[0], 'utf8')); }
  catch { throw new ToolError('INVALID_AUDIT_MANIFEST', 'A valid local JSON manifest file is required.'); }
  const report = await runAuditSessionCli({ manifest, summary });
  const termination = report.liveSession.termination;
  if (termination.reason === 'interrupted') process.exitCode = termination.signal === 'SIGINT' ? 130 : 143;
  else if (['partial', 'error'].includes(report.status)) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    process.stdout.write(`${JSON.stringify({ type: 'error', status: 'error', error: errorRecord(error) })}\n`);
    process.exitCode = 1;
  });
}
