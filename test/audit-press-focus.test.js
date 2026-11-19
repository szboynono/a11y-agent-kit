import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { openAuditAgent } from '../src/audit/agent.js';
import { MCP_TEXT_LIMIT } from '../src/audit/projection.js';
import { fixture } from './helpers.js';

// Owned fixtures only. Counts live keydown listeners on window so a leaked probe is visible from the page.
const COUNT_LISTENERS = `<script>
  const live = new Set(), add = EventTarget.prototype.addEventListener, remove = EventTarget.prototype.removeEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, opts) { if (this === window && type === 'keydown') live.add(fn); return add.call(this, type, fn, opts); };
  EventTarget.prototype.removeEventListener = function (type, fn, opts) { if (this === window && type === 'keydown') live.delete(fn); return remove.call(this, type, fn, opts); };
  window.liveKeydownListeners = () => live.size;
</script>`;
const shell = (body, head = '') => `<!doctype html><html lang="en"><head><title>Press focus</title>${head}</head><body>${body}</body></html>`;
const container = (extra = '') => shell(`<main id="app" tabindex="-1" aria-label="Canvas app"><button id="one">One</button><button id="two">Two</button></main>
  <script>const app = document.getElementById('app'); app.addEventListener('keydown', e => { if (e.key === 'Tab') { e.preventDefault(); ${extra} } }); app.focus();</script>`, COUNT_LISTENERS);

async function open(t, html, textLimit) {
  let agent;
  t.after(() => agent?.close()); // registered before the fixture's cleanup so the agent closes while its directory still exists
  const site = await fixture(t, html);
  agent = await openAuditAgent({ projectRoot: site.projectRoot, url: site.url }, textLimit ? { textLimit } : {});
  const step = actions => agent.request({ tool: 'step', actions });
  return { site, agent, step, press: async (...keys) => (await step(keys.map(key => ({ action: 'press', key })))).records };
}
const record = async (agent, id) => JSON.parse(await fs.readFile(path.join(agent.directory, `${id}.json`)));

test('Tab cancelled on a focused container reports defaultPrevented true, unchanged focus, in the step row', async t => {
  const { agent, step } = await open(t, container());
  const res = await step([{ action: 'press', key: 'Tab' }]);
  const [row] = res.records;
  assert.equal(row.success, true); assert.equal(row.defaultPrevented, true);
  assert.deepEqual({ on: row.focus.on, tag: row.focus.tag, name: row.focus.name }, { on: 'element', tag: 'main', name: 'Canvas app' });
  assert.deepEqual(res.focus, row.focus);
  const saved = await record(agent, row.evidenceId);
  assert.equal(saved.result.defaultPrevented, true);
  assert.equal(saved.before.active.nodeId, saved.after.active.nodeId, 'focus did not move');
});

test('stopPropagation in the app does not hide the cancelled key', async t => {
  const { press } = await open(t, container('e.stopPropagation();'));
  const [row] = await press('Tab');
  assert.equal(row.defaultPrevented, true);
});

test('stopImmediatePropagation from an earlier window capture handler leaves it unknown (null), never false', async t => {
  const { press } = await open(t, shell('<button id="a">A</button><script>addEventListener("keydown", e => e.stopImmediatePropagation(), true);</script>'));
  const [row] = await press('Tab');
  assert.equal(row.success, true); assert.equal(row.defaultPrevented, null);
});

test('a synthetic replacement cannot establish whether a hidden trusted keydown was cancelled', async t => {
  const { agent, press } = await open(t, shell(`<button id="a">A</button><script>
    document.getElementById('a').focus();
    addEventListener('keydown', e => {
      if (!e.isTrusted) return;
      e.preventDefault(); e.stopImmediatePropagation();
      window.dispatchEvent(new KeyboardEvent('keydown', { key: e.key, bubbles: true, cancelable: true }));
    }, true);
  </script>`));
  for (const row of await press('Tab', 'Control+/')) {
    assert.equal(row.success, true);
    assert.equal(row.defaultPrevented, null, 'an untrusted substitute cannot establish the real keydown outcome');
    const saved = await record(agent, row.evidenceId);
    assert.equal(saved.result.defaultPrevented, null);
    assert.equal(saved.before.active.nodeId, saved.after.active.nodeId);
  }
});

test('an ordinary Tab reports defaultPrevented false and the new focus in the row', async t => {
  const { press } = await open(t, shell('<button id="a">Alpha</button><button id="b" aria-label="Beta label">Beta</button>'));
  const rows = await press('Tab', 'Tab');
  assert.deepEqual(rows.map(row => row.defaultPrevented), [false, false]);
  assert.deepEqual(rows.map(row => [row.focus.on, row.focus.tag, row.focus.name]), [['element', 'button', 'Alpha'], ['element', 'button', 'Beta label']]);
  assert.ok(rows.every(row => typeof row.focus.nodeId === 'string'));
});

test('focus on the body is distinguishable from a focused element and the step carries the final focus', async t => {
  const { step } = await open(t, shell('<button>Alpha</button>'));
  const res = await step([{ action: 'press', key: 'Shift' }, { action: 'press', key: 'Tab' }, { action: 'snapshot' }]);
  const [first, second] = res.records;
  assert.equal(first.focus.on, 'body'); assert.equal(first.focus.tag, 'body'); assert.equal(first.focus.name, undefined);
  assert.equal(second.focus.on, 'element'); assert.equal(second.focus.name, 'Alpha');
  assert.deepEqual(res.focus, second.focus, 'step focus is the focus after the last action');
});

test('long accessible names are truncated to about 80 characters', async t => {
  const { press } = await open(t, shell(`<button aria-label="${'long '.repeat(60)}">x</button>`));
  const [row] = await press('Tab');
  assert.ok(row.focus.name.length <= 80 && row.focus.name.endsWith('…'));
});

test('a press that moves focus inside an iframe reports unknown (null), not false', async t => {
  const { press } = await open(t, shell(`<iframe id="f" title="inner" srcdoc="<input id='inner' aria-label='Inner'>"></iframe>
    <script>document.getElementById('f').addEventListener('load', () => document.getElementById('f').contentDocument.getElementById('inner').focus());</script>`));
  await new Promise(resolve => setTimeout(resolve, 300));
  const [row] = await press('a');
  assert.equal(row.success, true); assert.equal(row.focus.tag, 'iframe'); assert.equal(row.defaultPrevented, null);
});

test('a press that navigates the page still succeeds and reports unknown (null)', async t => {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-press-nav-')));
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'cache-control': 'no-store' });
    res.end(req.url === '/' ? shell('<a id="go" href="/next">Next</a><script>document.getElementById("go").focus(); addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); location.href = "/next"; } });</script>') : shell('<p>Arrived</p>'));
  });
  let agent;
  t.after(() => agent?.close());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await fs.rm(dir, { recursive: true, force: true }); });
  agent = await openAuditAgent({ projectRoot: dir, url: `http://127.0.0.1:${server.address().port}/` });
  const res = await agent.request({ tool: 'step', actions: [{ action: 'press', key: 'Enter' }] });
  const [row] = res.records;
  assert.equal(row.success, true);
  assert.equal(row.defaultPrevented, null, 'the document was replaced mid-press; the answer cannot be established');
  assert.notEqual(row.stateId, null);
});

test('the probe leaves no listener behind after a press, a failed press or a bad key name', async t => {
  // The page reports its live window keydown listeners 400 ms after each keydown, long after the probe was removed.
  const { agent, step, press } = await open(t, shell(`<button>A</button><output id="n">unset</output>${COUNT_LISTENERS}
    <script>addEventListener('keydown', () => setTimeout(() => { document.getElementById('n').textContent = String(liveKeydownListeners()); }, 400));</script>`));
  await press('Tab', 'Shift+Tab', 'Control+/');
  const bad = await step([{ action: 'press', key: 'NoSuchKey' }]);
  assert.equal(bad.records[0].success, false); assert.ok(bad.records[0].errorCode);
  await press('Tab');
  await step([{ action: 'wait', ms: 700 }]);
  const inspected = await step([{ action: 'inspect', selector: '#n' }]);
  assert.equal((await record(agent, inspected.records[0].evidenceId)).result.element.text, '1', 'only the page’s own listener remains');
});

test('modifier combinations are judged on the last keydown', async t => {
  const { press } = await open(t, shell('<button>A</button><script>addEventListener("keydown", e => { if (e.key === "/" && e.ctrlKey) e.preventDefault(); });</script>'));
  const [cancelled, free] = await press('Control+/', 'Shift+/');
  assert.equal(cancelled.defaultPrevented, true); assert.equal(free.defaultPrevented, false);
});

test('observe_status with a press trigger records defaultPrevented like a plain press', async t => {
  const { agent } = await open(t, container());
  const res = await agent.request({ tool: 'step', actions: [{ action: 'observe_status', trigger: { action: 'press', selector: '#app', key: 'Tab' }, windowMs: 200 }] });
  const press = res.records.find(row => row.action === 'press');
  assert.equal(press.defaultPrevented, true);
});

test('other actions keep their row shape', async t => {
  const { step } = await open(t, shell('<button id="b">B</button>'));
  const res = await step([{ action: 'snapshot' }, { action: 'inspect', selector: '#b' }, { action: 'scroll', x: 0, y: 0 }]);
  for (const row of res.records) { assert.equal(row.focus, undefined); assert.equal(row.defaultPrevented, undefined); }
  assert.deepEqual(Object.keys(res.records[0]), ['evidenceId', 'action', 'success', 'stateId', 'documentId']);
});

test('25 Tab presses keep focus on every row within the MCP cap; a huge batch falls back to the record', async t => {
  const buttons = Array.from({ length: 30 }, (_, i) => `<button>Control number ${i} with a reasonably descriptive label</button>`).join('');
  const { step } = await open(t, shell(buttons), MCP_TEXT_LIMIT);
  const res = await step(Array.from({ length: 25 }, () => ({ action: 'press', key: 'Tab' })));
  assert.equal(res.records.length, 25); assert.ok(res.records.every(row => row.focus?.on === 'element' && row.defaultPrevented === false));
  assert.ok(Buffer.byteLength(JSON.stringify(res)) <= MCP_TEXT_LIMIT);
  const big = await step(Array.from({ length: 150 }, () => ({ action: 'press', key: 'Tab' })));
  assert.ok(Buffer.byteLength(JSON.stringify(big)) <= MCP_TEXT_LIMIT);
  assert.equal(big.records[0].focus, undefined);
  assert.match(big.focusNote, /\/after\/active/);
  assert.equal(big.focus.on, 'element');
});
