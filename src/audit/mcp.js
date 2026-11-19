import { z } from 'zod';
import { readInlineOriginal, INLINE_IMAGE_LIMITS } from './mcp-image.js';
import { AUDIT_PLAYBOOK, AUDIT_PLAYBOOK_TEXT, openAuditAgent, auditAgentRequestSchema, auditAgentManifestSchemaFor, validateAuditRuntimeProfile } from './agent.js';
import { boundAuditResponse, MCP_TEXT_LIMIT } from './projection.js';
import { errorPayload } from './error-details.js';
import { SWEEP_RESERVE_BYTES, SWEEP_VERSION, fitSweep } from './sweep.js';
import { createUntrustedEnvelope, UNTRUSTED_ENVELOPE_RESERVE } from './untrusted.js';
import { dnsCheckBrief } from './navigation.js';

const inlineReply = Symbol('inlineReply');
const imageOutput = z.enum(['path', 'inline']).optional();

/** Connection-local lifecycle only; all evidence and budget decisions belong to the agent. */
export function registerAuditTools(server, { runtimeProfile, openAgent = openAuditAgent } = {}) {
  const profile = validateAuditRuntimeProfile(runtimeProfile);
  const profileGuide = profile ? ' v2: selector-only hover/focus each cost one shared action, including failed/reserved unexecuted actions; reserve the full batch. hover is mouse-assisted; focus is programmatic, never natural Tab or keyboard focus-visible evidence; success is not delivery/confirmation. inspect_many requires explicit selectors and costs N actions; interactive query is forbidden. Shared ledger budget is authoritative; native counters are diagnostic. Every attempt, native/common submit and receipt query costs a call; reserve two calls for native + common submit (three with checkpoint).' : '';
  const requestSchema = profile ? z.discriminatedUnion('tool', auditAgentRequestSchema.options.map(option => option.shape.tool.value === 'step'
    ? option.safeExtend({ actions: option.shape.actions.describe(profileGuide.trim()) }) : option)) : auditAgentRequestSchema;
  const manifestSchema = auditAgentManifestSchemaFor(runtimeProfile);
  const startupController = new AbortController();
  // One random nonce per connection, which holds one audit session; it never reaches records, reports or evidence.
  const untrusted = createUntrustedEnvelope();
  let agent, started = false, disconnected = false, queue = Promise.resolve();
  const serial = action => {
    const task = queue.then(action);
    queue = task.catch(() => {});
    return task;
  };
  const fail = (code, message = 'Audit session or input is invalid for this operation.') => ({ success: false, error: { code, message } });
  // The runId is a connection-local UUID minted by this server, so it is safe to return to the same connection.
  const mismatch = () => fail('AUDIT_RUN_MISMATCH', agent
    ? `runId does not match this connection's audit session. Use runId "${agent.runId}", the runId field of the a11y_audit_start response.`
    : 'No audit session is open on this connection. Call a11y_audit_start first, then pass the runId field of its response.');
  const alreadyStarted = () => fail('AUDIT_SESSION_ALREADY_STARTED', !agent
    ? 'This connection can no longer start an audit session; reconnect to start a new one.'
    : agent.status === 'open'
      ? `A session is already open on this connection. Do not start again; use runId "${agent.runId}" with a11y_audit_request.`
      : `This connection's session (runId "${agent.runId}") has ended (${agent.status}) and one connection holds one session; reconnect to start a new one.`);
  // Names fixed by our schemas and validator messages only; never echo received values or unknown keys.
  const inputShape = {
    a11y_audit_start: `Expected {manifest:{projectRoot:<absolute path>, url:<http(s) URL>, optional ${Object.keys(manifestSchema.shape).filter(key => !['projectRoot', 'url', 'actions'].includes(key)).join(', ')}}}. Do not send actions: start without them, then send actions via a11y_audit_request {tool:'step'}. A rejected start leaves no session, so fix the input and call a11y_audit_start again.`,
    a11y_audit_request: "Expected {runId:<runId from a11y_audit_start>, request:{tool:'step'|'read'|'inventory'|'view'|'checkpoint'|'submit', ...}, optional imageOutput:'path'|'inline'} and no other top-level fields.",
    a11y_audit_close: 'Expected {runId:<runId from a11y_audit_start>} and no other fields.',
  };
  const invalidInput = (name, error) => {
    const issues = error.issues.filter(issue => issue.code !== 'unrecognized_keys').slice(0, 5).map(issue => {
      const where = issue.path.every(part => typeof part === 'number' || /^\w{1,40}$/.test(part)) ? issue.path.join('.') : '';
      return `${where || 'input'}: ${issue.message}`.slice(0, 200);
    });
    const extra = error.issues.some(issue => issue.code === 'unrecognized_keys') ? 'Remove unsupported fields. ' : '';
    return `Invalid ${name} input. ${extra}${issues.length ? `Problems: ${issues.join('; ')}. ` : ''}${inputShape[name]}`.slice(0, 1500);
  };
  const result = async action => {
    let value, image;
    try { value = await action(); if (value?.[inlineReply]) { image = value.block; value = value.metadata; } }
    catch (error) { value = { success: false, error: errorPayload({ code: error.code ?? 'AUDIT_MCP_ERROR', message: error.message ?? String(error), details: error.details, navigation: error.navigation }), ...(profile ? { budget: profile.budget(), complete: false } : {}) }; }
    if (profile) value = { ...value, ...(value?.budget && value.budget.authority !== 'shared-ledger' ? { nativeBudgetDiagnostic: value.budget } : {}), budget: profile.budget() };
    value = boundAuditResponse(value, MCP_TEXT_LIMIT);
    // Additive envelope fields plus page-string markers; the text stays within MCP_TEXT_LIMIT.
    const { structured, text } = untrusted.wrap(value, MCP_TEXT_LIMIT);
    return { content: [{ type: 'text', text }, ...(image && structured.success === true ? [image] : [])], structuredContent: structured, isError: structured.success === false };
  };
  // Catch schema errors inside the bounded handler, rather than letting SDK validation echo untrusted input.
  const input = schema => ({ '~standard': { version: 1, vendor: 'a11y-bounded-input', validate: value => ({ value }), jsonSchema: { input: options => z.toJSONSchema(schema, { target: options.target }), output: options => z.toJSONSchema(schema, { target: options.target }) } } });
  const register = (name, description, schema, action) => server.registerTool(name, { description, inputSchema: input(schema) }, raw => result(() => { const execute = () => serial(async () => {
    const parsed = (name === 'a11y_audit_request' ? z.object({ runId: z.string().max(256), request: z.unknown(), imageOutput }).strict() : schema).safeParse(raw);
    if (!parsed.success) return fail('INVALID_AUDIT_MCP_INPUT', invalidInput(name, parsed.error));
    return action(parsed.data);
  }); return profile ? profile.runCall(name, raw, execute) : execute(); }));
  register('a11y_audit_start', 'Start the one audit session per connection (snapshot, axe; sweeps need startupSweep:true). ' + AUDIT_PLAYBOOK_TEXT + profileGuide, z.object({ manifest: manifestSchema }).strict(), async ({ manifest }) => {
    if (started || disconnected) return alreadyStarted();
    const { startupAxe, startupSweep, ...collection } = manifest;
    // Mark started only after open succeeds, so a rejected manifest can be corrected and retried.
    if (profile) await profile.reserveActions(1);
    agent = await openAgent(collection, { textLimit: MCP_TEXT_LIMIT, runtimeProfile, signal: startupController.signal });
    started = true;
    // One ordinary step, counted once like any other: 1 tool call and 2 actions, which the agent would otherwise have spent on firstRequest.
    const sweeping = Boolean(startupAxe && startupSweep);
    // The start response carries the full DNS check, so the axe page leaves room for it as well as for startup.sweep.
    const dnsBytes = json => json ? Buffer.byteLength(JSON.stringify({ dnsCheck: json })) : 0;
    const startDns = agent.dnsCheck?.() ?? null, dnsRoom = dnsBytes(startDns);
    // The axe page leaves room for startup.sweep; candidates past it page via read view:'axe' as usual.
    const first = startupAxe ? await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'axe' }] }, { reserveBytes: (sweeping ? SWEEP_RESERVE_BYTES : 0) + dnsRoom }) : null;
    // A failed sweep never blocks the start: its error is reported in startup.sweep.error and the session stays open.
    let swept = null;
    if (sweeping) {
      try { swept = await agent.startupSweep(); }
      catch (error) { swept = { success: false, sweep: { version: SWEEP_VERSION, error: errorPayload(error) } }; }
    }
    const progress = swept?.coverage ? swept : first;
    // A check that grew past the room left for it (the startup sweep navigated) is given in brief; the sealed report keeps it in full.
    const latestDns = agent.dnsCheck?.() ?? null;
    const dnsCheck = latestDns && dnsBytes(latestDns) > dnsRoom ? dnsCheckBrief(latestDns) : latestDns;
    const response = sweep => ({ success: true, runId: agent.runId, directory: agent.directory, evidencePolicy: agent.evidencePolicy, budget: agent.budget(),
      ...(dnsCheck ? { dnsCheck } : {}),
      playbook: AUDIT_PLAYBOOK,
      ...(first ? { startup: { ran: 'snapshot + axe', counted: '1 tool call and 2 actions', success: first.success, records: first.records, ...(first.axe ? { axe: first.axe } : {}),
          ...(first.errors?.length ? { errors: first.errors } : {}), ...(first.error ? { error: first.error } : {}),
          ...(sweep ? { sweep } : {}),
          ...(progress?.coverage ? { coverage: progress.coverage } : {}), ...(progress?.suggestedNext ? { suggestedNext: progress.suggestedNext } : {}) } }
        : { firstRequest: { runId: agent.runId, request: { tool: 'step', actions: [{ action: 'snapshot' }, { action: 'axe' }] } } }),
      next: (swept?.next ?? first?.next) ? `${swept?.sweep?.ran?.length ? `startup.sweep already ran ${swept.sweep.ran.join(' and ')} as ordinary records: cite them as evidence and extend them with Enter/Space on specific targets. ` : ''}${swept?.next ?? first.next}`
        : 'Send firstRequest to a11y_audit_request, then follow the playbook; budget is returned with every response.',
      visualAudit: 'requires_reading_original_image', imageOutput: { default: 'path', supported: ['path', 'inline'], inlineTool: 'view', ...INLINE_IMAGE_LIMITS } });
    if (!swept?.sweep) return response(null);
    const room = MCP_TEXT_LIMIT - 512 - UNTRUSTED_ENVELOPE_RESERVE - Buffer.byteLength(JSON.stringify(response({})));
    return response(fitSweep(swept.sweep, room));
  });
  const match = runId => agent && agent.runId === runId;
  register('a11y_audit_request', 'Run step/read/view/checkpoint/submit/inventory. ' + AUDIT_PLAYBOOK_TEXT + profileGuide + ' Responses are capped at 20,000 characters and paged by cursor.', z.object({ runId: z.string().max(256), request: requestSchema, imageOutput }).strict(), async ({ runId, request, imageOutput }) => {
    if (!match(runId)) return mismatch();
    if (imageOutput === 'inline' && request?.tool !== 'view') return fail('INVALID_AUDIT_IMAGE_OUTPUT');
    const value = await agent.request(request);
    if (imageOutput !== 'inline') return value;
    const delivery = { mode: 'inline', delivered: false, ...INLINE_IMAGE_LIMITS };
    if (!value.success) return { ...value, imageOutput: delivery };
    try {
      const { block, dimensions } = await readInlineOriginal(value.image, agent.directory);
      return { [inlineReply]: true, block, metadata: { ...value,
        imageOutput: { ...delivery, delivered: true, ...dimensions },
        note: 'Original PNG delivered in the MCP image block. Read it before visual claims; delivery is not inspection or review.' } };
    } catch (error) {
      return { ...value, success: false, imageOutput: delivery,
        note: 'No inline image delivered or inspected. Path mode remains available with a local viewer.',
        error: errorPayload(error) };
    }
  });
  register('a11y_audit_close', 'Close collection retaining drafts without automatic submission.', z.object({ runId: z.string().max(256) }).strict(), ({ runId }) => match(runId) ? agent.close() : mismatch());
  const dispose = options => {
    disconnected = true;
    // Opening must be cancelled immediately; an open session drains on normal EOF.
    if (!agent || options?.reason === 'interrupted') startupController.abort();
    if (options?.reason === 'interrupted' && agent) return agent.close(options);
    return serial(() => agent?.close(options));
  };
  const close = server.close.bind(server);
  server.close = async () => { await dispose({ reason: 'eof' }); await close(); };
  const previous = server.server.onclose;
  server.server.onclose = () => { void dispose({ reason: 'eof' }).catch(error => { console.error('Audit MCP cleanup failed:', String(error.code ?? 'AUDIT_MCP_CLEANUP_ERROR')); }); previous?.(); };
  server.closeAudit = dispose;
  return { dispose };
}
