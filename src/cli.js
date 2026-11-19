#!/usr/bin/env node
import * as fs from 'node:fs/promises';
import { analyze, verify, checkEvidence } from './index.js';
import { serve } from './server.js';
import { ToolError, errorRecord } from './evidence.js';
import { summarizeResult } from './summary.js';

const [command, ...args] = process.argv.slice(2);
try {
  if (command === 'serve') {
    if (args.length) throw new ToolError('USAGE', 'Usage: a11y-agent-kit serve');
    serve();
  } else if (command === 'audit-inventory') {
    const paths = [], options = {}; let persist = false;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--write') { if (persist) throw new ToolError('USAGE', 'Duplicate --write.'); persist = true; }
      else if (['--cursor', '--limit'].includes(args[i])) {
        const key = args[i].slice(2), value = args[++i];
        if (!value || options[key] !== undefined) throw new ToolError('USAGE', 'Missing or duplicate pagination option.');
        options[key] = key === 'limit' ? Number(value) : value;
      } else if (args[i].startsWith('-')) throw new ToolError('USAGE', 'Unknown inventory option.');
      else paths.push(args[i]);
    }
    if (![1, 2].includes(paths.length)) throw new ToolError('USAGE', 'Usage: audit-inventory REPORT_PATH [DISPOSITIONS_PATH] [--limit 1..200] [--cursor TOKEN] [--write]');
    const { auditInventory, writeInventoryPage } = await import('./audit/inventory.js');
    const result = await (persist ? writeInventoryPage : auditInventory)(paths[0], paths[1], options);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else if (command === 'audit-report') {
    const usage = 'Usage: a11y-agent-kit audit-report REPORT.json [--out report.html] [--screenshots] [--bounded --out NEW_DIRECTORY]';
    const paths = []; let out, screenshots = false, bounded = false;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--screenshots') { if (screenshots) throw new ToolError('USAGE', usage); screenshots = true; }
      else if (args[i] === '--bounded') { if (bounded) throw new ToolError('USAGE', usage); bounded = true; }
      else if (args[i] === '--out') { out = args[++i]; if (!out?.trim() || out.startsWith('-') || args.indexOf('--out') !== i - 1) throw new ToolError('USAGE', usage); }
      else if (args[i].startsWith('-') || !args[i].trim()) throw new ToolError('USAGE', usage);
      else paths.push(args[i]);
    }
    if (paths.length !== 1 || (bounded && !out)) throw new ToolError('USAGE', usage);
    const { writeAuditReport } = await import('./audit/report-html.js');
    const result = await writeAuditReport(paths[0], out ?? paths[0].replace(/\.json$/i, '') + '.html', { screenshots, bounded });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else if (command === 'audit-agent') {
    if (args.length !== 1 || !args[0].trim() || args[0].startsWith('-')) throw new ToolError('USAGE', 'Usage: a11y-agent-kit audit-agent manifest.json');
    const { runAuditAgentCli } = await import('./audit/agent-cli.js');
    const result = await runAuditAgentCli({ manifest: JSON.parse(await fs.readFile(args[0], 'utf8')) });
    if (result.termination?.signal) process.exitCode = result.termination.signal === 'SIGINT' ? 130 : 143;
    else if (result.status !== 'submitted') process.exitCode = 1;
  } else if (command === 'audit-checkpoint-read' || command === 'audit-submit-checkpoint') {
    const expected = command === 'audit-checkpoint-read' ? 1 : 2;
    if (args.length !== expected || args.some(value => !value.trim() || value.startsWith('-'))) throw new ToolError('USAGE', 'Usage: a11y-agent-kit audit-checkpoint-read checkpoint.json | audit-submit-checkpoint audit.json checkpoint.json');
    const { boundAuditResponse } = await import('./audit/projection.js');
    if (command === 'audit-checkpoint-read') {
      const { readAuditCheckpoint } = await import('./audit/checkpoint.js');
      const draft = await readAuditCheckpoint(args[0]);
      process.stdout.write(`${JSON.stringify(boundAuditResponse({ kind: draft.kind, runId: draft.runId, checkpointPath: draft.checkpointPath, checkpointDigest: draft.checkpointDigest, version: draft.version, status: 'draft', reviewStatus: 'needs_review', scoreable: false, findings: draft.proposal.findings.length }))}\n`);
      process.exitCode = 1;
    } else {
      const { submitAuditCheckpoint } = await import('./audit/agent.js');
      const proposal = await submitAuditCheckpoint(args[0], args[1]);
      process.stdout.write(`${JSON.stringify(boundAuditResponse({ kind: proposal.kind, reportPath: proposal.reportPath, reportDigest: proposal.reportDigest, sourceCheckpoint: proposal.sourceCheckpoint, status: proposal.status, counts: proposal.counts }))}\n`);
      process.exitCode = 1;
    }
  } else if (command === 'audit-live') {
    const summary = args.at(-1) === '--summary';
    const paths = summary ? args.slice(0, -1) : args;
    if (paths.length !== 1 || !paths[0].trim() || paths[0].startsWith('-')) {
      throw new ToolError('USAGE', 'Usage: a11y-agent-kit audit-live manifest.json [--summary]');
    }
    const { runAuditSessionCli } = await import('./audit/live-cli.js');
    const result = await runAuditSessionCli({ manifest: JSON.parse(await fs.readFile(paths[0], 'utf8')), input: process.stdin, output: process.stdout, signals: true, summary });
    const signal = result.liveSession?.termination?.signal;
    if (signal === 'SIGINT' || signal === 'SIGTERM') process.exitCode = signal === 'SIGINT' ? 130 : 143;
    else if (['partial', 'error'].includes(result.status)) process.exitCode = 1;
  } else if (['audit', 'audit-submit', 'audit-review', 'audit-check'].includes(command)) {
    let summary = false, out;
    const paths = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--summary' && !summary) summary = true;
      else if (args[i] === '--out' && command === 'audit-review' && out === undefined) {
        out = args[++i];
        if (!out?.trim() || out.startsWith('-')) throw new ToolError('USAGE', 'audit-review --out requires one new output filename.');
      } else paths.push(args[i]);
    }
    const expected = ['audit-submit', 'audit-review'].includes(command) ? 2 : 1;
    if (paths.length !== expected || paths.some(value => !value.trim() || value.startsWith('-'))) {
      throw new ToolError('USAGE', 'Usage: a11y-agent-kit audit manifest.json [--summary] | audit-submit audit.json findings.json [--summary] | audit-review proposal.json adjudication.json [--out NEW_REVIEW.json] [--summary] | audit-check report.json [--summary]');
    }
    let result;
    if (command === 'audit') {
      const { collectAudit } = await import('./audit/collect.js');
      result = await collectAudit(JSON.parse(await fs.readFile(paths[0], 'utf8')));
    } else {
      const { submitAudit, reviewAudit, checkAudit } = await import('./audit/review.js');
      if (command === 'audit-check') result = await checkAudit(paths[0]);
      else {
        const input = JSON.parse(await fs.readFile(paths[1], 'utf8'));
        result = command === 'audit-submit' ? await submitAudit(paths[0], input) : await reviewAudit(paths[0], input, out ? { out } : {});
      }
    }
    const { summarizeAudit } = await import('./audit/review.js');
    process.stdout.write(`${JSON.stringify(summary ? summarizeAudit(result) : result)}\n`);
    if (command === 'audit-review' && result.status === 'partial') {
      process.stderr.write(`Partial review saved: ${result.reportPath}. ${result.counts.verificationQueue} findings remain in needs_review.\n`);
      process.exitCode = 2;
    } else if (['needs_review', 'partial', 'error', 'expired'].includes(result.status)) process.exitCode = 1;
  } else {
    if (!['analyze', 'verify', 'check'].includes(command) ||
        ![1, 2].includes(args.length) || !args[0].trim() || args[0].startsWith('-') ||
        (args.length === 2 && args[1] !== '--summary')) {
      throw new ToolError('USAGE', 'Usage: a11y-agent-kit analyze manifest.json [--summary] | verify baseline.json [--summary] | check report.json [--summary] | serve');
    }
    let result;
    if (command === 'analyze') result = await analyze(JSON.parse(await fs.readFile(args[0], 'utf8')));
    else if (command === 'verify') result = await verify(args[0]);
    else result = await checkEvidence(args[0]);
    process.stdout.write(`${JSON.stringify(args[1] === '--summary' ? summarizeResult(result) : result)}\n`);
    if (['failed', 'needs_review', 'error', 'expired'].includes(result.status)) process.exitCode = 1;
  }
} catch (error) {
  let result = { status: 'error', errors: [errorRecord(error)] };
  if (['audit-inventory', 'audit-agent', 'audit-checkpoint-read', 'audit-submit-checkpoint'].includes(command)) {
    const { boundAuditResponse } = await import('./audit/projection.js');
    result = boundAuditResponse(result);
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = 1;
}
