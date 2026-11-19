import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { AUDIT_TEXT_LIMIT, AUDIT_NODE_FIELDS, AUDIT_RECORD_FIELDS, projectAuditRecord, boundAuditResponse } from '../src/audit/projection.js';

const sha = value => createHash('sha256').update(value).digest('hex');
const size = value => Buffer.byteLength(JSON.stringify(value), 'utf8');
const nodeId = number => `doc-original:n${String(number).padStart(6, '0')}`;

function fixture(count = 4) {
  const nodes = Array.from({ length: count }, (_, index) => ({
    nodeId: nodeId(index), documentId: 'doc-original', selector: `body > div:nth-of-type(${index + 1})`, tag: 'div',
    attributes: { id: `node-${index}`, role: 'status', 'aria-live': 'polite' }, attributesTruncated: [],
    text: `Original text ${index}`, textLength: 15, textTruncated: false,
    labelText: '', labelTextTruncated: false,
    rect: { x: index, y: index, width: 20, height: 20 },
    computed: { color: 'rgb(0, 0, 0)', backgroundColor: 'rgb(255, 255, 255)' },
    focused: index === 0, focusVisible: index === 0,
  }));
  const spacing = { requested: true, applied: true, requestedCss: 'p{margin-block-end:2em}', cssSha256: sha('css'),
    checkedElements: count, uncheckedElements: 0, lineHeight: 1.5, letterSpacing: 0.12, wordSpacing: 0.16, marginBlockEnd: 2 };
  const state = { documentId: 'doc-original', stateId: 'original-before', active: nodes[0], controls: [], controlsTotal: 0, controlsTruncated: 0,
    viewport: { width: 320, height: 900 }, scroll: { x: 0, y: 0 }, spacing,
    truncation: { capturedElements: count, omittedVisibleElements: 2, unobservedScope: ['child-frame DOM'] } };
  return { runId: 'original-run', evidenceId: 'ev-0001', action: 'contrast', arguments: { foreground: { x: 1, y: 1 }, background: { x: 2, y: 2 } }, success: true,
    before: structuredClone(state), after: { ...structuredClone(state), stateId: 'original-after' },
    result: { nodes, focusedElement: structuredClone(nodes[0]), truncation: state.truncation,
      capture: { beforeStateId: 'original-before', afterStateId: 'original-after', stable: false },
      contrast: { ratio: 21, foreground: { x: 1, y: 1, rgb: [0, 0, 0] }, background: { x: 2, y: 2, rgb: [255, 255, 255] }, screenshotSha256: sha('png') } },
    json: { path: '/private/original.json', sha256: sha('original-json-bytes'), bytes: 500 },
    png: { path: '/private/original.png', sha256: sha('png'), bytes: 30, width: 320, height: 900 } };
}

function checked(value) {
  assert.ok(size(value) <= AUDIT_TEXT_LIMIT, `response was ${size(value)} UTF-8 bytes`);
  return value;
}

function readField(record, options) {
  let cursor, text = '', previousOffset = options.offset ?? 0, count = 0, digest;
  do {
    const page = checked(projectAuditRecord(record, { ...options, ...(cursor ? { cursor } : {}) }));
    assert.equal(page.success, true, JSON.stringify(page));
    assert.equal(page.encoding, 'json');
    assert.equal(page.offset, previousOffset);
    assert.equal(page.pagination.viewPartial, true);
    if (digest) assert.equal(page.fieldSha256, digest);
    digest = page.fieldSha256;
    text += page.data;
    previousOffset = page.nextOffset;
    cursor = page.pagination.nextCursor;
    count++;
    assert.ok(count < 500, 'field chunks must make progress');
  } while (cursor);
  assert.equal(sha(text), digest);
  return { value: JSON.parse(text), count };
}

test('summary preserves original identities, failure and artifact hashes without paths or completeness claims', () => {
  const record = fixture(); record.success = false; record.error = { code: 'STATE_CHANGED', message: 'The original failure remains.' };
  const original = JSON.stringify(record), summary = checked(projectAuditRecord(record));
  assert.equal(summary.success, true);
  assert.equal(summary.identity.recordSuccess, false);
  assert.equal(summary.identity.runId, 'original-run');
  assert.equal(summary.identity.before.stateId, 'original-before');
  assert.equal(summary.identity.after.stateId, 'original-after');
  assert.equal(summary.artifacts.json.sha256, record.json.sha256);
  assert.equal(summary.artifacts.png.sha256, record.png.sha256);
  assert.deepEqual(summary.artifacts.png.handle, { evidenceId: record.evidenceId, kind: 'png' });
  assert.equal(summary.source.originalTruncation.result.omittedVisibleElements, 2);
  assert.equal(summary.pagination.complete, false);
  assert.equal(summary.pagination.viewPartial, true);
  assert.equal(summary.error.code, 'STATE_CHANGED');
  assert.ok(summary.retrieval.recordFields.some(item => item.field === '/result/nodes'));
  assert.ok(size(summary) < 16_384);
  assert.equal(JSON.stringify(summary).includes('/private/'), false);
  assert.ok(Object.isFrozen(summary.identity));
  assert.throws(() => { summary.artifacts.png.sha256 = 'mutated'; }, TypeError);
  assert.equal(JSON.stringify(record), original);
});

test('all original IDs page without omission or duplication and retain selectable original fields', () => {
  const record = fixture(1200), original = JSON.stringify(record), seen = [];
  let cursor, pages = 0;
  do {
    const response = checked(projectAuditRecord(record, { view: 'nodes', fields: ['attributes', 'computed', 'rect'], limit: 200, ...(cursor ? { cursor } : {}) }));
    assert.equal(response.success, true, JSON.stringify(response));
    assert.equal(response.pagination.total, record.result.nodes.length);
    assert.equal(response.pagination.offset, seen.length);
    for (const node of response.nodes) {
      seen.push(node.nodeId);
      assert.equal(node.documentId, 'doc-original');
      const result = node.occurrences.find(occurrence => occurrence.source.startsWith('/result/nodes/'));
      assert.ok(result);
      assert.equal(result.fields.attributes.role, 'status');
      assert.equal(result.fields.computed.color, 'rgb(0, 0, 0)');
      assert.equal(own(result.fields, 'text'), false);
    }
    cursor = response.pagination.nextCursor; pages++;
    assert.equal(response.pagination.complete, !cursor);
  } while (cursor);
  assert.ok(pages > 1);
  assert.deepEqual(seen, record.result.nodes.map(node => node.nodeId));
  assert.equal(new Set(seen).size, record.result.nodes.length);
  const selected = checked(projectAuditRecord(record, { view: 'nodes', nodeIds: [nodeId(100), nodeId(2)], fields: ['text'] }));
  assert.deepEqual(selected.nodes.map(node => node.nodeId), [nodeId(100), nodeId(2)]);
  assert.equal(selected.nodes[0].occurrences[0].fields.text, 'Original text 100');
  assert.equal(JSON.stringify(record), original);
});
const own = (value, key) => Object.hasOwn(value, key);

test('oversized Unicode and escaped fields are recoverable exactly, including deep attributes', () => {
  const record = fixture(2), huge = '😀€₹\\\"\n\u0000'.repeat(30_000);
  record.result.nodes[1].text = huge;
  record.result.nodes[1].textLength = huge.length;
  record.result.nodes[1].textTruncated = true;
  record.result.nodes[1].attributes['data-huge'] = huge;
  record.result.nodes[1].attributesTruncated = ['data-originally-shortened'];
  const original = JSON.stringify(record);
  const node = checked(projectAuditRecord(record, { view: 'nodes', nodeIds: [nodeId(1)], fields: ['text', 'attributes', 'textTruncated', 'attributesTruncated'] })).nodes[0];
  const whole = readField(record, node.read);
  assert.ok(whole.count > 1);
  assert.deepEqual(whole.value[0].value, record.result.nodes[1]);
  const occurrence = node.occurrences[0];
  assert.equal(occurrence.fields.text.deferred, true);
  assert.equal(occurrence.fields.attributes.deferred, true);
  assert.equal(occurrence.fields.textTruncated, true);
  const texts = readField(record, occurrence.fields.text.read);
  assert.ok(texts.count > 1);
  assert.equal(texts.value[0].value, huge);
  const attributes = readField(record, occurrence.fields.attributes.read);
  assert.ok(attributes.count > 1);
  assert.equal(attributes.value[0].value['data-huge'], huge);
  const allNodes = readField(record, { view: 'field', field: '/result/nodes' });
  assert.deepEqual(allNodes.value, record.result.nodes);
  assert.equal(JSON.stringify(record), original);
});

test('before/after focus, spacing, capture and contrast facts remain retrievable', () => {
  const record = fixture(); record.before.active.text = 'before'; record.after.active.text = 'after';
  const original = JSON.stringify(record);
  const focused = readField(record, { view: 'field', nodeId: nodeId(0), field: '$node' }).value;
  assert.equal(focused.find(value => value.source === '/before/active').value.text, 'before');
  assert.equal(focused.find(value => value.source === '/after/active').value.text, 'after');
  assert.deepEqual(readField(record, { view: 'field', field: '/after/spacing' }).value, record.after.spacing);
  assert.deepEqual(readField(record, { view: 'field', field: '/result/capture' }).value, record.result.capture);
  assert.deepEqual(readField(record, { view: 'field', field: '/result/contrast' }).value, record.result.contrast);
  assert.equal(JSON.stringify(record), original);
});

test('ancestor enumeration uses actual stored descriptors and never invents selector ancestors', () => {
  const record = fixture(1), target = record.result.nodes[0];
  target.parentNodeId = 'doc-original:parent';
  target.ancestorSemantics = { complete: true, ancestors: [
    { nodeId: 'doc-original:parent', documentId: 'doc-original', tag: 'main', parentNodeId: 'doc-original:html', attributes: { role: 'main' } },
    { nodeId: 'doc-original:html', documentId: 'doc-original', tag: 'html', parentNodeId: null, attributes: { lang: 'en' } },
  ] };
  const response = checked(projectAuditRecord(record, { view: 'nodes', fields: ['tag', 'parentNodeId', 'attributes', 'ancestorSemantics'] }));
  assert.equal(response.success, true);
  assert.deepEqual(response.nodes.map(node => node.nodeId), [nodeId(0), 'doc-original:parent', 'doc-original:html']);
  const html = response.nodes.find(node => node.nodeId === 'doc-original:html');
  assert.ok(html.occurrences[0].source.endsWith('/ancestorSemantics/ancestors/1'));
  assert.equal(html.occurrences[0].fields.attributes.lang, 'en');
  const noAncestors = fixture(1);
  assert.deepEqual(projectAuditRecord(noAncestors, { view: 'nodes' }).nodes.map(node => node.nodeId), [nodeId(0)]);
});

test('cursors bind record, run, selection and fields; malformed and out of range requests fail bounded', () => {
  const record = fixture(3), query = { view: 'nodes', limit: 1, fields: ['rect'] };
  const cursor = projectAuditRecord(record, query).pagination.nextCursor;
  const changed = structuredClone(record); changed.after.stateId = 'different';
  const cases = [
    [record, { ...query, cursor, fields: ['text'] }],
    [record, { ...query, cursor, nodeIds: [nodeId(0)] }],
    [record, { ...query, cursor, runId: 'foreign-run' }],
    [changed, { ...query, cursor }],
    [record, { ...query, cursor: `${cursor.slice(0, -2)}xx` }],
    [record, { ...query, cursor: 'x'.repeat(1_000_000) }],
    [record, { view: 'nodes', nodeIds: ['foreign-document:n00001'] }],
    [record, { view: 'nodes', nodeIds: [nodeId(0), nodeId(0)] }],
    [record, { view: 'nodes', fields: ['__proto__'] }],
    [record, { view: 'nodes', limit: 0 }],
    [record, { view: 'nodes', offset: 1 }],
    [record, { view: 'field', field: '/png/path' }],
    [record, { view: 'field', field: '/result/not-a-field' }],
    [record, { view: 'field', field: '/result/contrast', offset: 999_999 }],
    [record, { view: 'field', field: '/result/contrast', offset: -1 }],
    [record, { view: 'field', field: '/result/contrast', offset: 0, cursor }],
    [record, { view: 'field', field: 'rect', nodeId: 'foreign' }],
    [record, { view: 'summary', unexpected: 'x'.repeat(1_000_000) }],
  ];
  for (const [source, options] of cases) {
    const response = checked(projectAuditRecord(source, options));
    assert.equal(response.success, false, JSON.stringify(options).slice(0, 100));
    assert.equal(response.complete, false);
    assert.ok(response.error.code);
  }
  assert.ok(AUDIT_NODE_FIELDS.includes('ancestorSemantics'));
  assert.ok(AUDIT_RECORD_FIELDS.includes('/result/contrast'));
});

test('field offsets reject Unicode pair splitting and cursor continuation returns original JSON', () => {
  const record = fixture(1); record.result.visibleText = '😀 next';
  const bad = checked(projectAuditRecord(record, { view: 'field', field: '/result/visibleText', offset: 2 }));
  assert.equal(bad.success, false);
  assert.equal(bad.error.code, 'INVALID_AUDIT_OFFSET');
  assert.equal(readField(record, { view: 'field', field: '/result/visibleText' }).value, '😀 next');
});

test('ordinary metadata and every error stay byte bounded without silently successful clipping', () => {
  const small = { success: false, error: { code: 'ORIGINAL', message: 'kept' }, budget: { toolCalls: 3 } };
  assert.deepEqual(boundAuditResponse(small), small);
  assert.notEqual(boundAuditResponse(small), small);
  for (const value of [{ success: true, result: '€😀\\\"'.repeat(100_000) }, { success: false, error: { message: 'x'.repeat(1_000_000) } }]) {
    const response = checked(boundAuditResponse(value));
    assert.equal(response.success, false);
    assert.equal(response.complete, false);
    assert.equal(response.error.code, 'AUDIT_RESPONSE_TOO_LARGE');
    assert.ok(response.originalResponse.bytes > AUDIT_TEXT_LIMIT);
    assert.equal(response.originalResponse.sha256, sha(JSON.stringify(value)));
  }
  assert.equal(checked(boundAuditResponse({ success: true, imageBase64: 'xxxx' })).error.code, 'IMAGE_BYTES_IN_TEXT');
  assert.equal(checked(boundAuditResponse({ pngBytes: Buffer.from([1, 2]) })).error.code, 'IMAGE_BYTES_IN_TEXT');
  const cyclic = {}; cyclic.self = cyclic;
  assert.equal(checked(boundAuditResponse(cyclic)).success, false);
  assert.equal(checked(projectAuditRecord(cyclic)).success, false);
  const hostile = { get evidenceId() { const error = new Error('😀'.repeat(100_000)); error.code = 'AUDIT_HOSTILE_GETTER'; throw error; } };
  const hostileResponse = checked(projectAuditRecord(hostile));
  assert.equal(hostileResponse.success, false);
  assert.equal(hostileResponse.error.messageTruncated, true);
});

// See docs/test-coverage.md for the omitted retained-record cases.
test('whole-node handles survive compact deferred rows and oversized original nodes', () => {
  const record = fixture(1);
  record.result.nodes[0].text = '€😀'.repeat(1000);
  record.after.controls = Array.from({ length: 100 }, () => structuredClone(record.result.nodes[0]));
  const page = checked(projectAuditRecord(record, { runId: record.runId, view: 'nodes' }));
  const row = page.nodes[0];
  assert.equal(row.occurrences.deferred, true);
  assert.deepEqual(row.read, { runId: record.runId, view: 'field', nodeId: row.nodeId, field: '$node' });
  const recovered = readField(record, row.read);
  assert.ok(recovered.count > 1);
  assert.equal(recovered.value.length, 104);
  for (const occurrence of recovered.value) {
    const original = occurrence.source.split('/').slice(1).reduce((v, k) => v[k], record);
    assert.deepEqual(occurrence.value, original);
  }
});

test('an absent field names the nearest existing path, same-named paths and, for key presses, where focus is recorded', () => {
  const base = fixture(2);
  const press = { ...base, evidenceId: 'ev-0012', action: 'press', arguments: { key: 'Tab' },
    result: { key: 'Tab', keyboardOnly: true, inputPath: 'keyboard', keyboardPath: [{ key: 'Tab', documentId: 'doc-original', activeBefore: null }], method: 'page.keyboard.press' } };
  const absent = projectAuditRecord(press, { view: 'field', field: '/result/focusedElement' });
  assert.equal(absent.success, false); assert.equal(absent.error.code, 'AUDIT_FIELD_ABSENT');
  assert.match(absent.error.message, /\/after\/active/);
  const details = absent.error.details;
  assert.equal(details.nearestExistingPath, '/result'); assert.ok(details.keysAtNearestPath.includes('keyboardPath'));
  assert.deepEqual(details.focusedElement, ['/before/active', '/after/active']);
  assert.ok(details.recordTopLevelKeys.includes('after')); assert.ok(size(absent.error) < 3000);
  // The pointed-to field really holds the focused element, and reading it works.
  const focused = readField(press, { view: 'field', field: '/after/active' });
  assert.equal(focused.value.nodeId, nodeId(0));
  // Another absent field gets its nearest real parent and the paths where the same name does exist; no focus hint without a focus-like name or key press.
  const other = projectAuditRecord(base, { view: 'field', field: '/result/viewport' });
  assert.equal(other.error.code, 'AUDIT_FIELD_ABSENT');
  assert.equal(other.error.details.nearestExistingPath, '/result'); assert.ok(other.error.details.keysAtNearestPath.includes('contrast'));
  assert.deepEqual(other.error.details.sameNamedPaths, ['/before/viewport', '/after/viewport']);
  assert.equal(other.error.details.focusedElement, undefined); assert.ok(size(other) < 4000);
});

test('defaultPrevented field preserves true false null and rejects absence', () => {
  for (const value of [true, false, null]) {
    const record = fixture(); record.result.defaultPrevented = value;
    assert.equal(readField(record, { view: 'field', field: '/result/defaultPrevented' }).value, value);
  }
  assert.equal(projectAuditRecord(fixture(), { view: 'field', field: '/result/defaultPrevented' }).error.code, 'INVALID_AUDIT_FIELD');
});

function changedScreenshot() {
  const record = fixture(1);
  record.action = 'screenshot'; record.success = false;
  record.error = { code: 'SCREENSHOT_STATE_CHANGED', message: 'Retained failure', stage: 'screenshot' };
  for (const part of ['before', 'after']) {
    record[part].renderedDigest = `sha256:${sha(`rendered-${part}`)}`;
    record[part].stateId = `sha256:${sha(`state-${part}`)}`;
  }
  return record;
}

test('changed screenshot capture summarizes retained scalar paths and hashes without mutating facts', () => {
  const record = changedScreenshot(), original = JSON.stringify(record);
  const summary = checked(projectAuditRecord(record));
  const diff = summary.result.capture.stateDifference;
  for (const path of ['renderedDigest', 'stateId']) {
    const row = diff.entries.find(row => row.beforePath === `/before/${path}`);
    assert.equal(row.afterPath, `/after/${path}`);
    assert.equal(row.status, 'different');
    assert.equal(row.before, record.before[path]); assert.equal(row.after, record.after[path]);
  }
  assert.equal(diff.entries.find(row => row.beforePath === '/before/documentId').status, 'equal');
  assert.equal(summary.identity.recordSuccess, false);
  assert.deepEqual(summary.error, record.error);
  assert.deepEqual(readField(record, { view: 'field', field: '/result/capture' }).value, record.result.capture);
  assert.equal(JSON.stringify(record), original);
});

test('missing and unsupported state scalars are unknown even when both sides lack a value', () => {
  for (const value of [undefined, null, {}, [], 'not-a-retained-hash']) {
    const record = changedScreenshot();
    delete record.before.stateId; delete record.after.stateId;
    record.before.renderedDigest = value; record.after.renderedDigest = value;
    const diff = checked(projectAuditRecord(record)).result.capture.stateDifference;
    for (const path of ['renderedDigest', 'stateId']) {
      const row = diff.entries.find(row => row.beforePath === `/before/${path}`);
      assert.equal(row.status, 'unknown');
      assert.equal(own(row, 'before'), false); assert.equal(own(row, 'after'), false);
    }
  }
  const record = changedScreenshot(); delete record.after.renderedDigest;
  assert.equal(projectAuditRecord(record).result.capture.stateDifference.entries[0].status, 'unknown');
});

test('capture differences explicitly truncate at the entry or UTF-8 budget and add no free content', () => {
  const record = changedScreenshot();
  const secret = 'PRIVATE-€😀-password?token=credential';
  for (const part of ['before', 'after']) {
    record[part].url = `https://example.test/?${secret}`;
    record[part].active.text = secret; record[part].active.value = secret;
    record[part].document = { bodyAttributes: { title: secret } };
    record[part].inputPath = secret;
    record[part].viewport = { width: 390, height: 844, text: secret };
  }
  const diff = checked(projectAuditRecord(record)).result.capture.stateDifference;
  assert.equal(diff.entryLimit, 10); assert.equal(diff.byteLimit, 1024);
  assert.ok(diff.entries.length <= diff.entryLimit); assert.ok(size(diff) <= diff.byteLimit);
  assert.equal(diff.truncated, true); assert.ok(diff.omittedEntries > 0);
  assert.equal(diff.entries.length + diff.omittedEntries, 10);
  assert.equal(JSON.stringify(diff).includes(secret), false);
  assert.ok(diff.entries.every(row => !/url|text|value|attributes|inputPath/.test(row.beforePath)));
  record.before.renderedDigest = secret.repeat(1000);
  assert.equal(projectAuditRecord(record).result.capture.stateDifference.entries[0].status, 'unknown');
});

test('successful screenshots, other failures, and detailed views keep their existing capture projection', () => {
  for (const change of [r => { r.success = true; }, r => { r.error.code = 'OTHER'; }]) {
    const record = changedScreenshot(); change(record);
    assert.deepEqual(checked(projectAuditRecord(record)).result.capture, record.result.capture);
  }
  const record = changedScreenshot();
  assert.equal(own(checked(projectAuditRecord(record, { view: 'nodes' })), 'result'), false);
  delete record.result.capture;
  assert.equal(projectAuditRecord(record).result.capture, null);
  const large = changedScreenshot(); large.result.capture.method = 'x'.repeat(2000);
  const capture = checked(projectAuditRecord(large)).result.capture;
  assert.equal(capture.deferred, true); assert.equal(capture.read.field, '/result/capture');
  assert.ok(capture.stateDifference.entries.length > 0);
});
