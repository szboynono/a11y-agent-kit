import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { chromium } from 'playwright';
import { externalProbe } from './helpers.js';

test('every Chromium and route.fetch() request counts as browser traffic, not an external probe', async t => {
  const browserRows = [];
  const server = http.createServer((req, res) => {
    // A concurrent host probe may also arrive; it is classified, never counted.
    if (!externalProbe(req)) browserRows.push(req.url);
    res.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html><title>Probe classifier</title>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true }); t.after(() => browser.close());
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await context.route(`${origin}/routed`, async route => route.fulfill({ response: await route.fetch({ url: `${origin}/` }) }));
  const page = await context.newPage();
  await page.goto(`${origin}/`);
  await page.evaluate(() => fetch('/').then(response => response.text()));
  await page.evaluate(() => fetch('/routed').then(response => response.text()));
  await context.close();
  assert.deepEqual(browserRows, ['/', '/', '/'], 'navigation, page fetch and route.fetch() must all remain countable');
});

test('only a bare non-browser GET / is classified as an external probe', () => {
  const request = (method, url, userAgent) => ({ method, url, headers: userAgent === undefined ? {} : { 'user-agent': userAgent } });
  assert.equal(externalProbe(request('GET', '/', 'node')), true);
  assert.equal(externalProbe(request('GET', '/')), true);
  assert.equal(externalProbe(request('GET', '/data', 'node')), false);
  assert.equal(externalProbe(request('HEAD', '/', 'node')), false);
  assert.equal(externalProbe(request('GET', '/', 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36')), false);
});
