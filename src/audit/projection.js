import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const AUDIT_TEXT_LIMIT = 65_536;
/** MCP text cap. Claude Code truncates MCP output above MAX_MCP_OUTPUT_TOKENS (default 25,000 tokens, warning at 10,000); 20,000 characters stay under the warning even for dense JSON at 2 characters per token. */
export const MCP_TEXT_LIMIT = 20_000;
export const AUDIT_READ_VIEWS = Object.freeze(['summary', 'nodes', 'field']);
export const AUDIT_NODE_FIELDS = Object.freeze([
  'nodeId', 'documentId', 'parentNodeId', 'ancestorSemantics', 'selector', 'tag',
  'attributes', 'attributesTruncated', 'text', 'textLength', 'textTruncated',
  'labelText', 'labelTextTruncated', 'rect', 'computed', 'checked', 'value',
  'sensitiveValueOmitted', 'selectedIndex', 'selected', 'expanded', 'ariaChecked',
  'ariaPressed', 'open', 'disabled', 'role', 'href', 'url', 'tabIndex', 'focused',
  'focusVisible', 'outerHTML', 'outerHTMLTruncated', 'client', 'scroll',
  'textRangeRects', 'textRangeRectsTruncated', 'fontSize', 'marginBlockEnd',
  'lineHeight', 'letterSpacing', 'wordSpacing',
]);
export const AUDIT_NODE_READ_HINT = `For view:'nodes', fields selects distinct names from: ${AUDIT_NODE_FIELDS.join(', ')}. $node is not valid in fields. For whole retained node occurrences, follow row.read as read options with the same evidenceId and runId: view:'field', nodeId, field:'$node'. Follow pagination.next; concatenate data chunks, then JSON.parse.`;
const stateFields = ['documentId', 'url', 'viewport', 'scroll', 'active', 'controls',
  'controlsTotal', 'controlsTruncated', 'document', 'spacing', 'renderedDigest',
  'truncation', 'keyboardOnly', 'inputPath', 'stateId'];
const resultFields = ['defaultPrevented', 'statusObservation', 'nodes', 'element', 'target', 'focusedElement', 'document',
  'visibleText', 'visibleTextLength', 'visibleTextTruncated', 'truncation',
  'ariaSnapshot', 'ariaInputValuesOmitted', 'observationSource', 'axe',
  'axeHtmlOmitted', 'tags', 'axeNodeBindings', 'assessment', 'width', 'height',
  'capture', 'contrast', 'viewport', 'key', 'keyboardOnly', 'inputPath',
  'keyboardPath', 'method', 'clicked', 'hovered', 'focused', 'filled', 'url', 'scroll', 'waitedMs',
  'reset', 'focusOrigin', 'requested', 'enabled', 'css', 'cssSha256',
  'sheetActive', 'applied', 'checkedElements', 'uncheckedElements', 'failures',
  'representativeParagraph', 'stylePresent', 'requestedCss', 'navigationResponses',
  'executed', 'status', 'reason', 'elements', 'counts', 'selectorStatus', 'query', 'nonText'];
export const AUDIT_RECORD_FIELDS = Object.freeze([
  '/arguments', '/error', '/before', '/after', '/result', '/networkReplay', '/captureAttempts', '/captureRetries',
  ...['before', 'after'].flatMap(part => stateFields.map(field => `/${part}/${field}`)),
  ...resultFields.map(field => `/result/${field}`),
]);

// Reserve room for the caller's audit ID, budget, and tool envelope. The caller
// must still run boundAuditResponse after adding its final text metadata.
const inlineLimit = 1024;
// The additive navigation payload of a blocked navigation is projected beside the error, under its own bound,
// so the 0.1.1 error keys keep their inline/deferred decision. Typical payloads are under 1.5 KiB.
const navigationInlineLimit = 4096;
const cursorKey = randomBytes(32);
const optionsKeys = new Set(['runId', 'view', 'nodeIds', 'fields', 'cursor', 'limit', 'field', 'nodeId', 'offset']);
const nodeFields = new Set(AUDIT_NODE_FIELDS);
const recordFields = new Set(AUDIT_RECORD_FIELDS);
const own = (value, key) => Object.hasOwn(value ?? {}, key);
const bytes = value => Buffer.byteLength(JSON.stringify(value), 'utf8');
const sha = value => createHash('sha256').update(value).digest('hex');
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const smallString = (value, maximum = 512) => typeof value === 'string' && value.length > 0 && value.length <= maximum;

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details !== undefined) error.details = details;
  throw error;
}

function errorResponse(code, message, details) {
  const text = typeof message === 'string' ? message : 'The audit read failed.';
  return freeze({ success: false, complete: false, error: {
    code: typeof code === 'string' ? code.slice(0, 80) : 'INVALID_AUDIT_RESPONSE',
    message: text.slice(0, 2000), ...(text.length > 2000 ? { messageTruncated: true } : {}),
    ...(isObject(details) && bytes(details) <= 2048 ? { details } : {}),
  } });
}

function hasImageBytes(value) {
  if (!value || typeof value !== 'object') return false;
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return true;
  return Object.entries(value).some(([key, item]) => ['imageBase64', 'pngBytes'].includes(key) || hasImageBytes(item));
}

/** Bound the final TEXT response after separating any unchanged MCP image block.
 * Oversize metadata is an explicit error, never a clipped successful response.
 */
export function boundAuditResponse(value, limit = AUDIT_TEXT_LIMIT) {
  try {
    if (hasImageBytes(value)) return errorResponse('IMAGE_BYTES_IN_TEXT', 'Return PNG bytes as a separate image content block.');
    const text = JSON.stringify(value);
    if (typeof text !== 'string') return errorResponse('INVALID_AUDIT_RESPONSE', 'A JSON text response is required.');
    const length = Buffer.byteLength(text, 'utf8');
    if (length > limit) return freeze({ success: false, complete: false,
      error: { code: 'AUDIT_RESPONSE_TOO_LARGE', message: `The response exceeds ${limit.toLocaleString('en-US')} UTF-8 bytes. Use the bounded record read handles; this response has not delivered the original content.` },
      originalResponse: { bytes: length, sha256: sha(text), success: typeof value?.success === 'boolean' ? value.success : null } });
    return freeze(JSON.parse(text));
  } catch {
    return errorResponse('INVALID_AUDIT_RESPONSE', 'The response must be finite JSON without cycles or binary image bytes.');
  }
}

function normalizeOptions(value) {
  if (!isObject(value) || Object.keys(value).some(key => !optionsKeys.has(key))) fail('INVALID_AUDIT_READ_OPTIONS', 'Read options contain an unknown key or are not an object.');
  const view = value.view ?? 'summary';
  if (!AUDIT_READ_VIEWS.includes(view)) fail('INVALID_AUDIT_READ_VIEW', 'Choose summary, nodes, or field.');
  if (own(value, 'runId') && !smallString(value.runId, 256)) fail('INVALID_AUDIT_RUN_ID', 'runId must be a nonempty string of at most 256 code units.');
  if (own(value, 'cursor') && (!smallString(value.cursor, 2048) || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value.cursor))) fail('INVALID_AUDIT_CURSOR', 'The cursor is invalid.');
  if (own(value, 'offset') && (!Number.isSafeInteger(value.offset) || value.offset < 0)) fail('INVALID_AUDIT_OFFSET', 'offset must be a nonnegative safe integer.');
  if (own(value, 'cursor') && own(value, 'offset')) fail('INVALID_AUDIT_READ_OPTIONS', 'Use a cursor or an explicit field offset, not both.');
  const allowed = view === 'summary' ? ['runId', 'view'] : view === 'nodes'
    ? ['runId', 'view', 'nodeIds', 'fields', 'cursor', 'limit']
    : ['runId', 'view', 'nodeId', 'field', 'cursor', 'offset'];
  if (Object.keys(value).some(key => !allowed.includes(key))) fail('INVALID_AUDIT_READ_OPTIONS', 'These options do not apply to the selected view.');
  if (view === 'nodes') {
    if (own(value, 'limit') && (!Number.isInteger(value.limit) || value.limit < 1 || value.limit > 200)) fail('INVALID_AUDIT_PAGE_LIMIT', 'limit must be an integer from 1 to 200.');
    if (own(value, 'nodeIds') && (!Array.isArray(value.nodeIds) || !value.nodeIds.length || value.nodeIds.length > 200 || value.nodeIds.some(id => !smallString(id)) || new Set(value.nodeIds).size !== value.nodeIds.length)) fail('INVALID_AUDIT_NODE_IDS', 'nodeIds must contain 1 to 200 distinct original node IDs.');
    if (own(value, 'fields') && (!Array.isArray(value.fields) || value.fields.some(field => !nodeFields.has(field)) || new Set(value.fields).size !== value.fields.length)) fail('INVALID_AUDIT_NODE_FIELDS', 'fields must contain distinct allowlisted node field names.');
    return { view, runId: value.runId ?? null, nodeIds: value.nodeIds ? [...value.nodeIds] : null,
      fields: value.fields ? [...value.fields] : ['selector', 'tag', 'text', 'labelText', 'rect', 'parentNodeId'], limit: value.limit ?? 25,
      ...(value.cursor ? { cursor: value.cursor } : {}) };
  }
  if (view === 'field') {
    if (own(value, 'nodeId') && !smallString(value.nodeId)) fail('INVALID_AUDIT_NODE_ID', 'nodeId must be an original node ID.');
    if (value.nodeId ? !nodeFields.has(value.field) && !['$node', '$occurrences'].includes(value.field) : !recordFields.has(value.field)) fail('INVALID_AUDIT_FIELD', 'Choose an allowlisted record JSON pointer or node field.');
    return { view, runId: value.runId ?? null, field: value.field, nodeId: value.nodeId ?? null,
      ...(value.cursor ? { cursor: value.cursor } : {}), ...(own(value, 'offset') ? { offset: value.offset } : {}) };
  }
  return { view, runId: value.runId ?? null };
}

function queryFor(options) {
  const { cursor: _cursor, offset: _offset, textLimit: _textLimit, ...query } = options;
  return query;
}

function cursorFor(recordDigest, query, position) {
  const payload = Buffer.from(JSON.stringify({ v: 1, recordDigest, queryDigest: sha(JSON.stringify(query)), position })).toString('base64url');
  return `${payload}.${createHmac('sha256', cursorKey).update(payload).digest('base64url')}`;
}

function cursorPosition(cursor, recordDigest, query) {
  const [payload, signature] = cursor.split('.');
  const expected = createHmac('sha256', cursorKey).update(payload).digest();
  const actual = Buffer.from(signature, 'base64url');
  if (actual.toString('base64url') !== signature || actual.length !== expected.length || !timingSafeEqual(actual, expected)) fail('INVALID_AUDIT_CURSOR', 'The cursor is invalid or belongs to another process.');
  let decoded;
  try { decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); }
  catch { fail('INVALID_AUDIT_CURSOR', 'The cursor is invalid.'); }
  if (decoded.v !== 1 || decoded.recordDigest !== recordDigest || decoded.queryDigest !== sha(JSON.stringify(query)) || !Number.isSafeInteger(decoded.position) || decoded.position < 0) fail('AUDIT_CURSOR_QUERY_MISMATCH', 'The cursor does not match this original record and query.');
  return decoded.position;
}

function artifact(value, evidenceId, kind) {
  if (!isObject(value)) return null;
  if (!/^[a-f0-9]{64}$/i.test(value.sha256 ?? '') || !Number.isSafeInteger(value.bytes) || value.bytes < 0) fail('INVALID_AUDIT_ARTIFACT', 'An artifact requires its retained SHA-256 and byte count.');
  return { handle: { evidenceId, kind }, sha256: value.sha256, bytes: value.bytes,
    ...Object.fromEntries(['width', 'height'].filter(key => Number.isSafeInteger(value[key]) && value[key] > 0).map(key => [key, value[key]])) };
}

function publicNode(node) {
  return Object.fromEntries(AUDIT_NODE_FIELDS.filter(field => own(node, field)).map(field => [field, node[field]]));
}

function indexNodes(record) {
  const nodes = new Map(), sources = {};
  function add(node, source, observation, group) {
    if (!isObject(node) || !own(node, 'nodeId')) return;
    if (!smallString(node.nodeId) || own(node, 'documentId') && node.documentId !== null && !smallString(node.documentId, 256)) fail('INVALID_AUDIT_NODE_IDENTITY', 'Stored node identities must be bounded original strings.');
    const existing = nodes.get(node.nodeId);
    if (existing?.documentId && node.documentId && existing.documentId !== node.documentId) fail('AUDIT_NODE_DOCUMENT_MISMATCH', 'One stored node ID refers to different documents.');
    const entry = existing ?? { nodeId: node.nodeId, documentId: node.documentId ?? null, occurrences: [] };
    if (!entry.documentId && node.documentId) entry.documentId = node.documentId;
    entry.occurrences.push({ source, stateId: observation?.stateId ?? null, documentId: node.documentId ?? null, node });
    nodes.set(node.nodeId, entry); sources[group] = (sources[group] ?? 0) + 1;
    if (Array.isArray(node.ancestorSemantics?.ancestors)) node.ancestorSemantics.ancestors.forEach((ancestor, index) => add(ancestor, `${source}/ancestorSemantics/ancestors/${index}`, observation, 'stored.ancestors'));
  }
  for (const part of ['before', 'after']) {
    const observation = record[part];
    add(observation?.active, `/${part}/active`, observation, `${part}.active`);
    if (Array.isArray(observation?.controls)) observation.controls.forEach((node, index) => add(node, `/${part}/controls/${index}`, observation, `${part}.controls`));
    add(observation?.spacing?.representativeParagraph, `/${part}/spacing/representativeParagraph`, observation, `${part}.spacing.representativeParagraph`);
  }
  const observation = record.after ?? record.before;
  if (Array.isArray(record.result?.nodes)) record.result.nodes.forEach((node, index) => add(node, `/result/nodes/${index}`, observation, 'result.nodes'));
  for (const field of ['element', 'target', 'focusedElement', 'representativeParagraph']) add(record.result?.[field], `/result/${field}`, observation, `result.${field}`);
  return { nodes, sources };
}

function handle(options, extra) {
  return { ...(options.runId ? { runId: options.runId } : {}), ...extra };
}

function inlineOrHandle(value, read, maximum = inlineLimit) {
  if (value === undefined) return null;
  const length = bytes(value);
  return length <= maximum ? value : { deferred: true, serializedBytes: length, read };
}

function baseResponse(record, options, recordDigest, index) {
  const state = part => record[part] ? { documentId: record[part].documentId ?? null, stateId: record[part].stateId ?? null } : null;
  const truncation = part => inlineOrHandle(record[part]?.truncation,
    handle(options, { view: 'field', field: `/${part}/truncation` }));
  return { success: true, projectionVersion: 1, view: options.view,
    identity: { runId: options.runId ?? record.runId ?? null, evidenceId: record.evidenceId, action: record.action,
      recordSuccess: record.success, recordDigest, before: state('before'), after: state('after') },
    artifacts: { json: artifact(record.json, record.evidenceId, 'json'), png: artifact(record.png, record.evidenceId, 'png') },
    source: { scope: 'Retained original observations only; no whole-DOM or WCAG conformance claim.',
      originalTruncation: { before: truncation('before'), after: truncation('after'), result: truncation('result'),
        beforeControls: record.before?.controlsTruncated ?? null, afterControls: record.after?.controlsTruncated ?? null,
        visibleText: record.result?.visibleTextTruncated ?? null },
      nodeTruncation: AUDIT_NODE_READ_HINT,
      relationships: 'Stored parentNodeId and ancestorSemantics only; no inferred ancestors.' },
    nodeCount: index.nodes.size };
}

// A small stateFields subset, with fixed scalar leaves only. Hashes come first
// so the capture guard's two identities survive the 1 KiB diagnostic budget.
const captureStatePaths = ['renderedDigest', 'stateId', 'documentId',
  'viewport/width', 'viewport/height', 'scroll/x', 'scroll/y',
  'controlsTotal', 'controlsTruncated', 'keyboardOnly'];
const captureDiffEntryLimit = 10;
const captureDiffByteLimit = 1024;

function captureStateDifference(record) {
  const entries = [];
  const result = { scope: 'Fixed scalar paths in retained before/after only; no cause or continuous stability claim.',
    entryLimit: captureDiffEntryLimit, byteLimit: captureDiffByteLimit,
    entries, omittedEntries: captureStatePaths.length, truncated: true };
  for (const path of captureStatePaths) {
    const get = part => path.split('/').reduce((value, key) => own(value, key) ? value[key] : undefined, record[part]);
    const before = get('before'), after = get('after');
    const supported = value => ['renderedDigest', 'stateId'].includes(path)
      ? typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value)
      : path === 'documentId' ? smallString(value, 256)
        : path === 'keyboardOnly' ? typeof value === 'boolean'
          : typeof value === 'number' && Number.isFinite(value);
    const known = supported(before) && supported(after);
    const row = { beforePath: `/before/${path}`, afterPath: `/after/${path}`,
      status: known ? before === after ? 'equal' : 'different' : 'unknown' };
    // Only retained SHA-256 identifiers are echoed; other values are compared
    // without adding URL, DOM, form, or arbitrary string content to summary.
    if (known && ['renderedDigest', 'stateId'].includes(path)) Object.assign(row, { before, after });
    if (entries.length === captureDiffEntryLimit) break;
    entries.push(row);
    result.omittedEntries = captureStatePaths.length - entries.length;
    result.truncated = result.omittedEntries > 0;
    if (bytes(result) > captureDiffByteLimit) {
      entries.pop();
      result.omittedEntries = captureStatePaths.length - entries.length;
      result.truncated = true;
      break;
    }
  }
  return result;
}

function summary(record, options, base, index) {
  const read = field => handle(options, { view: 'field', field });
  // A record error's navigation key is additive: the remaining keys are inlined (or deferred) exactly as before,
  // and errorNavigation carries the payload in the same response. The /error field read still returns both.
  const { navigation: errorNavigation, ...legacyError } = isObject(record.error) ? record.error : {};
  const hasNavigation = errorNavigation !== undefined;
  const observation = part => record[part] ? {
    viewport: record[part].viewport ?? null, scroll: record[part].scroll ?? null,
    active: record[part].active?.nodeId ? { nodeId: record[part].active.nodeId, read: handle(options, { view: 'nodes', nodeIds: [record[part].active.nodeId] }) } : null,
    keyboardOnly: record[part].keyboardOnly ?? null, inputPath: record[part].inputPath ?? null,
    spacing: inlineOrHandle(record[part].spacing, read(`/${part}/spacing`)),
  } : null;
  return { ...base, pagination: { complete: false, viewPartial: true, detailsDeferred: true, nextCursor: null },
    arguments: inlineOrHandle(record.arguments, read('/arguments')),
    before: observation('before'), after: observation('after'),
    result: { fields: Object.keys(record.result ?? {}).filter(field => recordFields.has(`/result/${field}`)),
      capture: record.success === false && record.error?.code === 'SCREENSHOT_STATE_CHANGED' && isObject(record.result?.capture)
        ? { ...inlineOrHandle(record.result.capture, read('/result/capture')), stateDifference: captureStateDifference(record) }
        : inlineOrHandle(record.result?.capture, read('/result/capture')),
      contrast: inlineOrHandle(record.result?.contrast, read('/result/contrast')) },
    error: inlineOrHandle(hasNavigation ? legacyError : record.error, read('/error')),
    // Above 4 KiB the handle's serializedBytes counts navigation alone; the /error read it points to also returns
    // the 0.1.1 keys, so it is larger. /error is the only record field that holds navigation.
    ...(hasNavigation ? { errorNavigation: inlineOrHandle(errorNavigation, read('/error'), navigationInlineLimit) } : {}),
    nodeSources: index.sources,
    retrieval: { nodes: handle(options, { view: 'nodes' }),
      recordFields: AUDIT_RECORD_FIELDS.filter(field => field.split('/').slice(1).reduce((value, key) => own(value, key) ? value[key] : undefined, record) !== undefined)
        .map(field => ({ field, read: read(field) })),
      nodeFields: AUDIT_NODE_FIELDS, nodeSpecialFields: ['$node', '$occurrences'],
      fieldEncoding: 'Concatenate field data in order, then JSON.parse; offsets count UTF-16 code units in serialized JSON.' } };
}

function nodeRow(entry, options) {
  const read = field => handle(options, { view: 'field', nodeId: entry.nodeId, field });
  const row = { nodeId: entry.nodeId, documentId: entry.documentId, occurrenceCount: entry.occurrences.length, read: read('$node'),
    occurrences: entry.occurrences.map(occurrence => ({ source: occurrence.source, stateId: occurrence.stateId, documentId: occurrence.documentId,
      fields: Object.fromEntries(options.fields.filter(field => own(occurrence.node, field)).map(field => [field,
        inlineOrHandle(occurrence.node[field], read(field))])) })) };
  // A heavily repeated node is still enumerable in one bounded row. Its entire
  // set of occurrences and every selected field can be recovered via chunks.
  if (bytes(row) > 12_000) return { nodeId: entry.nodeId, documentId: entry.documentId, occurrenceCount: entry.occurrences.length, read: read('$node'),
    occurrences: { deferred: true, read: read('$occurrences') },
    fields: Object.fromEntries(options.fields.map(field => [field, { deferred: true, read: read(field) }])) };
  return row;
}

function nodesPage(record, options, base, index, recordDigest) {
  const pageLimit = options.textLimit - 4096;
  const selected = options.nodeIds ? options.nodeIds.map(id => {
    if (!index.nodes.has(id)) fail('UNKNOWN_AUDIT_NODE_ID', 'A requested node ID is absent from this original record.');
    return index.nodes.get(id);
  }) : [...index.nodes.values()];
  const query = queryFor(options);
  const offset = options.cursor ? cursorPosition(options.cursor, recordDigest, query) : 0;
  if (offset > selected.length) fail('INVALID_AUDIT_CURSOR', 'The node cursor is outside this record.');
  const rows = [];
  const response = nextOffset => ({ ...base, selectedFields: options.fields, nodes: rows,
    pagination: { offset, returned: rows.length, total: selected.length, complete: nextOffset === selected.length,
      viewPartial: true, nextCursor: nextOffset < selected.length ? cursorFor(recordDigest, query, nextOffset) : null,
      next: nextOffset < selected.length ? { ...query, runId: query.runId ?? undefined, nodeIds: query.nodeIds ?? undefined, cursor: cursorFor(recordDigest, query, nextOffset) } : null } });
  let position = offset;
  while (position < selected.length && rows.length < options.limit) {
    rows.push(nodeRow(selected[position], options));
    if (bytes(response(position + 1)) > pageLimit) { rows.pop(); break; }
    position++;
  }
  if (!rows.length && position < selected.length) fail('AUDIT_NODE_PAGE_TOO_LARGE', 'This node cannot fit in a bounded enumeration page; read it with the $node field.');
  return response(position);
}

const FOCUS_NAME = /focus|active/i;

/** Bounded, actionable help for a field path that is not in a record: what exists nearest to it, and where focus lives for key presses. */
function absentFieldDetails(record, field) {
  const keysOf = value => isObject(value) ? Object.keys(value).slice(0, 24) : [];
  const segments = field.split('/').slice(1);
  let present = '', node = record;
  for (const key of segments) { if (!own(node, key)) break; node = node[key]; present += `/${key}`; }
  const last = segments.at(-1) ?? '', sameName = [];
  const walk = (value, path, depth) => {
    if (!isObject(value) || depth > 4 || sameName.length >= 5) return;
    for (const [key, child] of Object.entries(value)) {
      const here = `${path}/${key}`;
      if (key === last && sameName.length < 5) sameName.push(here);
      if (key !== 'nodes') walk(child, here, depth + 1);
    }
  };
  walk(record, '', 0);
  const focusHolders = ['/before/active', '/after/active'].filter(path => path.split('/').slice(1).reduce((value, key) => own(value, key) ? value[key] : undefined, record) !== undefined);
  const keyboard = record.action === 'press' || own(record.result ?? {}, 'keyboardPath');
  const focusHint = focusHolders.length && (keyboard || FOCUS_NAME.test(last))
    ? ` The focused element after ${keyboard ? 'this key press' : 'this action'} is at ${focusHolders.includes('/after/active') ? '/after/active' : focusHolders[0]}${focusHolders.length > 1 ? ' (before it: /before/active)' : ''}; read it with {view:"field",field:"/after/active"}.` : '';
  const nearest = present || '/';
  const hint = `Nearest existing path: ${nearest}${isObject(node) ? ` (keys: ${keysOf(node).join(', ') || 'none'})` : ''}.${sameName.length ? ` A field named "${last}" exists at: ${sameName.join(', ')}.` : ''}${focusHint}`.slice(0, 900);
  return { requestedField: field.slice(0, 200), nearestExistingPath: nearest, keysAtNearestPath: keysOf(node), recordTopLevelKeys: keysOf(record),
    ...(sameName.length ? { sameNamedPaths: sameName } : {}), ...(focusHint ? { focusedElement: focusHolders } : {}), hint };
}

function fieldValue(record, options, index) {
  if (!options.nodeId) {
    const value = options.field.split('/').slice(1).reduce((current, key) => own(current, key) ? current[key] : undefined, record);
    if (value === undefined) {
      if (options.field === '/result/defaultPrevented') fail('INVALID_AUDIT_FIELD', 'This original record has no defaultPrevented field.');
      const details = absentFieldDetails(record, options.field);
      const { hint, ...structured } = details;
      fail('AUDIT_FIELD_ABSENT', `This original record does not contain the requested field. ${hint}`, structured);
    }
    return value;
  }
  const entry = index.nodes.get(options.nodeId);
  if (!entry) fail('UNKNOWN_AUDIT_NODE_ID', 'The requested node ID is absent from this original record.');
  return entry.occurrences.map(({ source, stateId, documentId, node }) => ({ source, stateId, documentId,
    ...(options.field === '$occurrences' ? {} : options.field === '$node' ? { value: publicNode(node) }
      : { present: own(node, options.field), ...(own(node, options.field) ? { value: node[options.field] } : {}) }) }));
}

const splitSurrogate = (text, offset) => offset > 0 && offset < text.length && /[\uD800-\uDBFF]/.test(text[offset - 1]) && /[\uDC00-\uDFFF]/.test(text[offset]);

function fieldPage(record, options, base, index, recordDigest) {
  const pageLimit = options.textLimit - 4096;
  const text = JSON.stringify(fieldValue(record, options, index));
  const fieldSha256 = sha(text), fieldBytes = Buffer.byteLength(text, 'utf8');
  const query = queryFor(options);
  const offset = options.cursor ? cursorPosition(options.cursor, recordDigest, query) : options.offset ?? 0;
  if (offset > text.length || splitSurrogate(text, offset)) fail('INVALID_AUDIT_OFFSET', 'The offset is outside the serialized field or splits a Unicode surrogate pair.');
  const response = end => ({ ...base, field: options.field, nodeId: options.nodeId, encoding: 'json', offset,
    nextOffset: end, totalCodeUnits: text.length, fieldSha256, fieldBytes,
    data: text.slice(offset, end),
    pagination: { complete: end === text.length, viewPartial: true,
      nextCursor: end < text.length ? cursorFor(recordDigest, query, end) : null,
      next: end < text.length ? { ...query, runId: query.runId ?? undefined, nodeId: query.nodeId ?? undefined, cursor: cursorFor(recordDigest, query, end) } : null } });
  let low = offset, high = Math.min(text.length, offset + pageLimit);
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (bytes(response(middle)) <= pageLimit) low = middle;
    else high = middle - 1;
  }
  if (splitSurrogate(text, low)) low--;
  if (low === offset && offset < text.length) fail('AUDIT_FIELD_PAGE_TOO_LARGE', 'The field page envelope cannot fit within the text limit.');
  return response(low);
}

/** Immutable bounded view of a retained record; this never reads a path or
 * rewrites original JSON/PNG. All complete flags describe only the selected
 * page query, while viewPartial always preserves the original scope boundary.
 * Cursors are process-local, authenticated and bound to record + run + query.
 *
 * Options: { runId?, view?: 'summary'|'nodes'|'field' }. Nodes additionally
 * accepts { nodeIds?: string[1..200], fields?: AUDIT_NODE_FIELDS[], limit?:
 * integer[1..200], cursor? }. Field accepts { field: AUDIT_RECORD_FIELDS member,
 * cursor? | offset?: nonnegative integer }, or { nodeId, field: node field name
 * | '$node' | '$occurrences', cursor? | offset? }. An empty nodes fields array
 * enumerates identities only. With a cursor, repeat the original query exactly
 * (or use pagination.next); explicit field offsets are UTF-16 code units in the
 * serialized JSON. Join data across field pages and JSON.parse it once.
 */
export function projectAuditRecord(record, options = {}, { textLimit = AUDIT_TEXT_LIMIT } = {}) {
  try {
    const normalized = { ...normalizeOptions(options), textLimit };
    if (!isObject(record) || !smallString(record.evidenceId, 256) || !smallString(record.action, 256) || typeof record.success !== 'boolean') fail('INVALID_AUDIT_RECORD', 'A retained record requires bounded evidence/action IDs and its original success state.');
    for (const part of ['before', 'after']) for (const field of ['documentId', 'stateId']) {
      if (record[part]?.[field] !== undefined && record[part][field] !== null && !smallString(record[part][field], 256)) fail('INVALID_AUDIT_RECORD_IDENTITY', 'Observation identities must be bounded original strings.');
    }
    if (own(record, 'runId') && !smallString(record.runId, 256)) fail('INVALID_AUDIT_RUN_ID', 'The stored run ID is invalid.');
    if (normalized.runId && record.runId && normalized.runId !== record.runId) fail('AUDIT_RUN_ID_MISMATCH', 'The requested and stored run IDs differ.');
    const serialized = JSON.stringify(record), recordDigest = sha(serialized);
    const source = JSON.parse(serialized);
    if (hasImageBytes(source)) fail('IMAGE_BYTES_IN_TEXT', 'PNG bytes must be separate from textual record observations.');
    const index = indexNodes(source), base = baseResponse(source, normalized, recordDigest, index);
    const projected = normalized.view === 'nodes' ? nodesPage(source, normalized, base, index, recordDigest)
      : normalized.view === 'field' ? fieldPage(source, normalized, base, index, recordDigest)
        : summary(source, normalized, base, index);
    return boundAuditResponse(projected, textLimit);
  } catch (error) {
    const known = smallString(error?.code, 80) && error.code.startsWith('AUDIT_') || smallString(error?.code, 80) && ['INVALID_AUDIT', 'UNKNOWN_AUDIT', 'IMAGE_BYTES'].some(prefix => error.code.startsWith(prefix));
    return errorResponse(known ? error.code : 'INVALID_AUDIT_RECORD', known ? error.message : 'The retained record must be finite JSON with valid bounded identities.', known ? error.details : undefined);
  }
}
