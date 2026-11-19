import { createHash, randomUUID } from 'node:crypto';
import { ToolError } from '../evidence.js';

export async function blobDeadline(operation, deadline) {
  let timer;
  try {
    if (performance.now() >= deadline) throw new ToolError('AUDIT_BLOB_TIMEOUT', 'Blob capture exceeded its effective deadline.');
    const promise = operation();
    const result = await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new ToolError('AUDIT_BLOB_TIMEOUT', 'Blob capture exceeded its effective deadline.')), Math.max(0, deadline - performance.now()));
    })]);
    if (performance.now() >= deadline) throw new ToolError('AUDIT_BLOB_TIMEOUT', 'Blob capture exceeded its effective deadline.');
    return result;
  } finally { clearTimeout(timer); }
}

// Fixed code only. All selector/attribute/limit input travels as CDP values.
function prepare(action) {
  const found = document.querySelectorAll(action.selector);
  if (found.length !== 1) throw new Error('AUDIT_BLOB_TARGET: expected one main-document element');
  const node = found[0], url = node.getAttribute(action.attribute);
  if (url === null) throw new Error('AUDIT_BLOB_URL: missing literal attribute');
  const parsed = new URL(url);
  const inner = parsed.protocol === 'blob:' ? new URL(url.slice(5)) : null;
  if (!inner || !['http:', 'https:'].includes(inner.protocol) || inner.origin !== location.origin || location.origin === 'null') {
    throw new Error('AUDIT_BLOB_URL: expected a same-origin HTTP(S) blob URL');
  }
  const state = { node, url, document, changed: false, controller: new AbortController(), reader: null };
  const changed = records => {
    for (const record of records) {
      if (record.type === 'attributes' && record.target === node && record.attributeName === action.attribute) state.changed = true;
      if (record.type === 'childList' && [...record.removedNodes].some(removed => removed === node || removed.contains(node))) state.changed = true;
    }
  };
  state.observer = new MutationObserver(changed);
  state.observer.observe(document, { subtree: true, attributes: true, childList: true });
  state.verify = () => {
    changed(state.observer.takeRecords());
    const matches = document.querySelectorAll(action.selector);
    if (state.changed || state.document !== document || !node.isConnected || matches.length !== 1 || matches[0] !== node || node.getAttribute(action.attribute) !== url) {
      throw new Error('AUDIT_BLOB_CHANGED: original target or source changed');
    }
  };
  return state;
}

async function readBody(maxBytes, timeoutMs) {
  const timer = setTimeout(() => this.controller.abort(), timeoutMs);
  try {
    this.verify();
    const response = await fetch(this.url, { signal: this.controller.signal });
    if (!response.ok) throw new Error('AUDIT_BLOB_READ: unsuccessful blob response');
    const mimeType = response.headers.get('content-type') ?? '';
    const declared = response.headers.get('content-length');
    if (declared !== null && Number(declared) > maxBytes) throw new Error('AUDIT_BLOB_OVERSIZE: body exceeds maxBytes');
    this.reader = response.body.getReader();
    let size = 0;
    const chunks = [];
    while (true) {
      const { done, value } = await this.reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error('AUDIT_BLOB_OVERSIZE: body exceeds maxBytes');
      chunks.push(value);
    }
    this.verify();
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return { bytes: Array.from(bytes), size, mimeType, originalBlobURL: this.url };
  } finally {
    clearTimeout(timer);
    this.controller.abort();
    if (this.reader) { await this.reader.cancel().catch(() => {}); this.reader.releaseLock(); this.reader = null; }
  }
}

/** Transient bytes cross CDP into Node only; the caller receives metadata. */
export async function openBlobCapture(browser, action, deadline, cleanupDeadline = deadline) {
  let session, attaching;
  try {
    session = await blobDeadline(() => (attaching = browser.context.newCDPSession(browser.page)), deadline);
  } catch (error) {
    if (attaching) void attaching.then(late => late.detach()).catch(() => {});
    throw error;
  }
  let objectId, isolatedContext;
  const captureKey = `audit-blob-state-${randomUUID()}`;
  let closing;
  const close = () => closing ??= (async () => {
    // Dispatch all cleanup independently: a stalled renderer must not postpone
    // the detach attempt. Late completions remain handled after our bounded wait.
    const operations = [];
    if (isolatedContext) operations.push(() => session.send('Runtime.evaluate', { contextId: isolatedContext,
      expression: `((key) => { const state=globalThis[key]; if(state){state.controller.abort(); state.observer.disconnect(); if(state.reader) void state.reader.cancel().catch(()=>{});} delete globalThis[key]; })(${JSON.stringify(captureKey)})`,
      returnByValue: true }));
    operations.push(() => session.send('Runtime.releaseObjectGroup', { objectGroup: captureKey }), () => session.detach());
    const pending = Promise.all(operations.map(operation => Promise.resolve().then(operation).catch(() => {})));
    const remaining = Math.max(0, Math.min(100, cleanupDeadline - performance.now()));
    if (!remaining) return;
    let timer;
    try { await Promise.race([pending, new Promise(resolve => { timer = setTimeout(resolve, remaining); })]); }
    finally { clearTimeout(timer); }
  })();
  const send = (method, args) => blobDeadline(() => session.send(method, args), deadline);
  const value = response => {
    if (response.exceptionDetails) {
      // Never serialize arbitrary browser exception text, which can include payloads.
      const description = response.exceptionDetails.exception?.description ?? '';
      const code = description.match(/AUDIT_BLOB_[A-Z]+/)?.[0] ?? 'AUDIT_BLOB_READ';
      throw new ToolError(code, 'Isolated blob capture failed; no complete digest retained.');
    }
    return response.result;
  };
  try {
    const { frameTree } = await send('Page.getFrameTree', {});
    let mainContext;
    session.on('Runtime.executionContextCreated', ({ context }) => {
      if (context.auxData?.isDefault && context.auxData.frameId === frameTree.frame.id) mainContext = context.id;
    });
    await send('Runtime.enable', {});
    const { executionContextId } = await send('Page.createIsolatedWorld', { frameId: frameTree.frame.id, worldName: `audit-blob-${randomUUID()}`, grantUniveralAccess: false });
    isolatedContext = executionContextId;
    objectId = value(await send('Runtime.evaluate', { contextId: executionContextId, objectGroup: captureKey,
      expression: `globalThis[${JSON.stringify(captureKey)}] = (${prepare.toString()})(${JSON.stringify(action)})`, returnByValue: false })).objectId;
    if (!objectId || !mainContext) throw new ToolError('AUDIT_BLOB_UNAVAILABLE', 'Chromium isolated blob context or main-document binding unavailable.');
    // The target reference and observer now precede the initial DOM observation.
    // Resolving its original observation ID happens afterwards, never by reselecting.
    const capture = { close,
      verify: async () => { value(await send('Runtime.callFunctionOn', { objectId, functionDeclaration: 'function(){this.verify();}', returnByValue: true })); },
      read: async initial => {
        await capture.verify();
        const nodeId = value(await send('Runtime.callFunctionOn', { objectId, objectGroup: captureKey, functionDeclaration: 'function(){return this.node;}' })).objectId;
        const { node } = await send('DOM.describeNode', { objectId: nodeId });
        const { object } = await send('DOM.resolveNode', { backendNodeId: node.backendNodeId, executionContextId: mainContext, objectGroup: captureKey });
        const binding = value(await send('Runtime.callFunctionOn', { objectId: object.objectId,
          functionDeclaration: 'function(key){const s=globalThis[key]; return {nodeId:s?.ids.get(this), documentId:s?.documentId};}',
          arguments: [{ value: browser.storeKey }], returnByValue: true })).value;
        const original = initial.raw.nodes.find(n => n.nodeId === binding?.nodeId && n.documentId === binding?.documentId);
        if (!original) throw new ToolError('AUDIT_BLOB_UNBOUND', 'Target is outside the original bounded visible DOM observation.');
        const captured = value(await send('Runtime.callFunctionOn', { objectId, functionDeclaration: readBody.toString(),
          arguments: [{ value: action.maxBytes ?? 1048576 }, { value: Math.max(1, deadline - performance.now()) }], awaitPromise: true, returnByValue: true })).value;
        if (captured.originalBlobURL !== original.attributes[action.attribute]) throw new ToolError('AUDIT_BLOB_CHANGED', 'Source differs from original DOM observation.');
        const sha256 = createHash('sha256').update(Buffer.from(captured.bytes)).digest('hex');
        capture.metadata = { algorithm: 'sha256', sha256, size: captured.size, mimeType: captured.mimeType,
          originalBlobURL: captured.originalBlobURL, selector: action.selector, attribute: action.attribute, complete: true,
          nodeId: original.nodeId, documentId: original.documentId, stateId: initial.state.stateId };
      } };
    return capture;
  } catch (error) { await close(); throw error; }
}
