import * as fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

export function html({ broken = false, hidden = false, removed = false } = {}) {
  return `<!doctype html><html lang="en"><head><title>Local accessibility fixture</title></head><body>
  ${removed ? '' : `<button id="save" type="button" ${hidden ? 'hidden' : ''} ${broken ? 'aria-labl="Save"' : 'aria-label="Save"'}><span aria-hidden="true">+</span></button>`}
  ${broken ? '' : '<label for="email">Email</label>'}<input id="email" type="email">
  <output id="status">0</output>
  <script>
    let count = Number(localStorage.getItem('count') || 0);
    document.querySelector('#status').textContent = String(count);
    document.querySelector('#save')?.addEventListener('click', () => {
      localStorage.setItem('count', String(++count));
      document.querySelector('#status').textContent = String(count);
    });
  </script></body></html>`;
}

// Desktop hosts can probe every new loopback listener with a bare `GET /`
// (T3 Code's dev-server port detection does, with a non-browser user agent).
// Chromium and Playwright's route.fetch() always identify as HeadlessChrome, so
// such a probe is never product traffic and must not trigger fixture hooks or
// count as a request from the browser under test.
export function externalProbe(request) {
  return request.method === 'GET' && request.url === '/' && !/\bHeadlessChrome\//.test(request.headers['user-agent'] ?? '');
}

export async function fixture(t, initial = html()) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-fix-loop-'));
  const projectRoot = await fs.realpath(directory);
  await fs.writeFile(path.join(projectRoot, 'index.html'), initial);
  let beforeResponse;
  const server = http.createServer(async (request, response) => {
    try {
      if (request.url !== '/') {
        response.writeHead(404, { 'content-type': 'text/plain' }).end('Not found');
        return;
      }
      if (beforeResponse && !externalProbe(request)) await beforeResponse();
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      response.end(await fs.readFile(path.join(projectRoot, 'index.html')));
    } catch {
      response.writeHead(500).end('Fixture error');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await fs.rm(projectRoot, { recursive: true, force: true });
  });
  const url = `http://127.0.0.1:${server.address().port}/`;
  return {
    projectRoot, url,
    manifest: {
      projectRoot, url,
      viewport: { width: 1024, height: 768 },
      states: [{ id: 'initial', assertions: [
        { type: 'visible', selector: '#save' },
        { type: 'enabled', selector: '#save' },
        { type: 'count', selector: '#save', value: 1 },
        { type: 'count', selector: '#email', value: 1 },
      ] }],
    },
    write: value => fs.writeFile(path.join(projectRoot, 'index.html'), value),
    beforeResponse: callback => { beforeResponse = callback; },
  };
}

/**
 * MCP audit text carries the untrusted page-content envelope: page strings sit between the session's open and close
 * markers. Strip complete marker pairs; for fixtures without marker look-alikes the result equals structuredContent.
 */
export function unwrapEnvelopedText(response) {
  const { open, close } = response.structuredContent.untrustedContent;
  const strip = value => {
    if (typeof value === 'string') return value.startsWith(open) && value.endsWith(close) ? value.slice(open.length, -close.length) : value;
    if (Array.isArray(value)) return value.map(strip);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, key === 'untrustedContent' ? item : strip(item)]));
    return value;
  };
  return strip(JSON.parse(response.content[0].text));
}
