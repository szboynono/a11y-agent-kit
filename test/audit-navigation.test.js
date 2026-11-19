import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { AuditBrowser } from '../src/audit/browser.js';
import { parseAuditManifest } from '../src/audit/schema.js';
import { collectAudit } from '../src/audit/collect.js';
import { submitAudit } from '../src/audit/review.js';
import { renderAuditReportHtml, writeAuditReport } from '../src/audit/report-html.js';
import { errorPayload } from '../src/audit/error-details.js';
import { errorRecord } from '../src/evidence.js';
import { canonicalOrigin, decideNavigation, isPrivateHost, MAX_REDIRECTS, navigationBlockDetails, navigationPolicy, redactUrl } from '../src/audit/navigation.js';
import { mcpTransport } from './mcp-transport.js';
import { externalProbe } from './helpers.js';

// Loopback fixtures only. `*.localhost` names resolve to loopback inside Chromium, so one local server can play
// an apex host, its www host and an unrelated third-party host. No real site is contacted.
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const page = title => `<!doctype html><html lang="en"><head><title>${title}</title></head><body><main><h1>${title}</h1></main></body></html>`;

async function workspace(t) {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-any-site-')));
  await fs.mkdir(path.join(directory, 'evidence'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

/** One loopback server; `route(host, url, port)` returns { location, status } or { body, status }. Hits are counted per host. */
async function site(t, route) {
  const hits = [];
  const server = http.createServer((request, response) => {
    if (externalProbe(request)) { response.end(); return; }
    const host = String(request.headers.host ?? '').replace(/:\d+$/, '');
    hits.push({ host, url: request.url });
    const answer = route(host, request.url, server.address().port) ?? {};
    if (answer.location) response.writeHead(answer.status ?? 302, { location: answer.location }).end();
    else response.writeHead(answer.status ?? 200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(answer.body ?? page(`${host}${request.url}`));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const port = server.address().port;
  return { port, hits, origin: host => `http://${host}:${port}`, count: host => hits.filter(hit => hit.host === host).length };
}

/** apex.localhost redirects every path to the same path on www.apex.localhost; www serves pages and links. */
async function apexWwwSite(t, { wwwStatus = 200 } = {}) {
  return site(t, (host, url, port) => {
    if (host === 'apex.localhost') return { status: 301, location: `http://www.apex.localhost:${port}${url === '/' ? '/en.html' : url}` };
    if (host === 'www.apex.localhost') {
      if (url === '/away') return { location: `http://third.localhost:${port}/` };
      return { status: wwwStatus, body: page(`www ${url}`).replace('</main>', `<a id="abs" href="http://www.apex.localhost:${port}/about">About</a><a id="third" href="http://third.localhost:${port}/">Third</a></main>`) };
    }
    return {};
  });
}

// Public sessions resolve DNS names before each main-frame request. These fixtures map public-site.example to
// loopback inside Chromium, so the DNS check is given a fixed public answer instead of the system resolver.
const publicAnswer = { name: 'test-public', lookup: async () => [{ address: '8.8.8.8', family: 4 }] };

async function startBlocked(manifest, options) {
  const browser = new AuditBrowser(parseAuditManifest(manifest), options);
  try { await browser.start(); } catch (error) { return { browser, error }; } finally { await browser.close(); }
  assert.fail('The start navigation should have been blocked.');
}

/** What a client agent does with the structured block: no prose parsing, only the additive `navigation` fields. */
function applySuggestion(manifest, details, preferred = 'use_url') {
  assert.equal(details.code, 'AUDIT_NAVIGATION_BLOCKED');
  assert.equal(details.overridable, true, `floor reasons say stop: ${details.reason}`);
  const actions = [details.suggestedAction, details.alternativeAction].filter(Boolean);
  const action = actions.find(item => item.kind === preferred) ?? actions[0];
  if (action.kind === 'use_url') return { ...manifest, url: action.url };
  if (action.kind === 'declare_origin') return { ...manifest, ...action.manifestPatch };
  assert.fail(`unexpected suggestion ${action.kind}`);
}

// ---------- Decision function and schema (T3, T6, T7, T8, T9, T14, malformed URLs) ----------

test('decision floors are not overridable by allowedOrigins or followRedirects', () => {
  const policy = navigationPolicy({ url: 'https://example.com/', followRedirects: true, allowedOrigins: ['http://example.com', 'https://www.example.com', 'http://127.0.0.1:3000'] });
  const origins = new Set(['https://example.com', ...policy.allowedOrigins]);
  const decide = (url, previousUrl = null, redirects = previousUrl ? 1 : 0) => decideNavigation({ url, previousUrl, redirects, policy, sessionOrigins: origins });
  assert.deepEqual(decide('https://user:pass@www.example.com/'), { allowed: false, reason: 'credentials_in_url', overridable: false });
  assert.deepEqual(decide('https://user@www.example.com/', 'https://example.com/'), { allowed: false, reason: 'credentials_in_url', overridable: false });
  assert.deepEqual(decide('http://example.com/', 'https://example.com/'), { allowed: false, reason: 'scheme_downgrade', overridable: false }, 'T7 even when declared');
  assert.deepEqual(decide('http://127.0.0.1:3000/'), { allowed: false, reason: 'private_network_target', overridable: false }, 'T9 even when declared');
  assert.deepEqual(decide('https://10.0.0.1/', 'https://example.com/'), { allowed: false, reason: 'private_network_target', overridable: false }, 'T9 redirect hop');
  for (const host of ['10.1.2.3', '192.168.0.1', '172.16.0.1', '169.254.1.1', '[::1]', '[fd00::1]', '[fe80::1]', 'localhost', 'app.localhost', '0.0.0.0', '[::ffff:127.0.0.1]']) {
    assert.equal(decide(`http://${host}/`).reason, 'private_network_target', host);
  }
  assert.equal(decide('https://www.example.com/', 'https://example.com/', MAX_REDIRECTS).allowed, true);
  assert.deepEqual(decide('https://www.example.com/', 'https://example.com/', MAX_REDIRECTS + 1), { allowed: false, reason: 'redirect_limit', overridable: false }, 'T8');
  assert.deepEqual(decide('ftp://example.com/'), { allowed: false, reason: 'non_http_scheme', overridable: false });
  assert.deepEqual(decide('http://exa mple.com:99999/'), { allowed: false, reason: 'invalid_url', overridable: false }, 'malformed URL');
  assert.equal(isPrivateHost('example.com'), false); assert.equal(isPrivateHost('8.8.8.8'), false); assert.equal(isPrivateHost('[2606:4700::1]'), false);
});

test('T3: http to https on the same host is blocked by default and followed only when opted in', () => {
  const base = { url: 'http://example.com/' };
  const decide = manifest => {
    const policy = navigationPolicy(manifest);
    return decideNavigation({ url: 'https://example.com/', previousUrl: 'http://example.com/', redirects: 1, policy, sessionOrigins: new Set(['http://example.com', ...policy.allowedOrigins]) });
  };
  assert.deepEqual(decide(base), { allowed: false, reason: 'cross_origin_redirect', overridable: true });
  assert.deepEqual(decide({ ...base, allowedOrigins: ['https://example.com'] }), { allowed: false, reason: 'cross_origin_redirect', overridable: true }, 'declared but not following redirects');
  assert.deepEqual(decide({ ...base, followRedirects: true }), { allowed: true }, 'same-host upgrade');
  assert.deepEqual(decide({ ...base, followRedirects: true, allowedOrigins: ['https://example.com'] }), { allowed: true });
  const policy = navigationPolicy({ ...base, followRedirects: true });
  assert.equal(decideNavigation({ url: 'https://www.example.com/', previousUrl: 'http://example.com/', redirects: 1, policy, sessionOrigins: new Set(['http://example.com']) }).reason,
    'cross_origin_redirect', 'upgrade does not include a host change');
  assert.equal(decideNavigation({ url: 'https://example.com:8443/', previousUrl: 'http://example.com/', redirects: 1, policy, sessionOrigins: new Set(['http://example.com']) }).reason,
    'cross_origin_redirect', 'upgrade does not include a port change');
});

test('T14: new manifest fields validate strictly and old manifests parse unchanged', () => {
  const old = parseAuditManifest({ projectRoot: '/tmp/demo', url: 'http://127.0.0.1:3000/' });
  assert.equal(Object.hasOwn(old, 'followRedirects'), false); assert.equal(Object.hasOwn(old, 'allowedOrigins'), false);
  const parsed = parseAuditManifest({ projectRoot: '/tmp/demo', url: 'https://example.com/', followRedirects: true, allowedOrigins: ['https://www.example.com', 'http://example.com:8080'],
    actions: [{ action: 'navigate', path: 'https://www.example.com/about' }, { action: 'navigate', path: '/x' }] });
  assert.deepEqual(parsed.allowedOrigins, ['https://www.example.com', 'http://example.com:8080']);
  for (const bad of ['https://www.example.com/', 'https://www.example.com/path', 'https://u:p@www.example.com', 'ftp://example.com', 'www.example.com', 'https://www.example.com?x=1']) {
    assert.throws(() => parseAuditManifest({ projectRoot: '/tmp/demo', url: 'https://example.com/', allowedOrigins: [bad] }), error => error.code === 'INVALID_AUDIT_MANIFEST', bad);
  }
  assert.throws(() => parseAuditManifest({ projectRoot: '/tmp/demo', url: 'https://example.com/', followRedirects: 'yes' }), error => error.code === 'INVALID_AUDIT_MANIFEST');
  assert.throws(() => parseAuditManifest({ projectRoot: '/tmp/demo', url: 'https://example.com/', maxRedirects: 10 }), error => error.code === 'INVALID_AUDIT_MANIFEST', 'the hop cap is not a manifest field');
  assert.throws(() => parseAuditManifest({ projectRoot: '/tmp/demo', url: 'https://example.com/', actions: [{ action: 'navigate', path: 'https://other.example/' }] }),
    error => error.code === 'INVALID_AUDIT_MANIFEST' && error.details.some(issue => issue.path === 'actions.0.path'));
  assert.throws(() => parseAuditManifest({ projectRoot: '/tmp/demo', url: 'https://user:pw@example.com/' }), error => error.code === 'INVALID_AUDIT_MANIFEST');
  assert.throws(() => parseAuditManifest({ projectRoot: '/tmp/demo', url: 'not a url' }), error => error.code === 'INVALID_AUDIT_MANIFEST', 'malformed manifest URL');
});

test('T15: networkReplay stays single-origin; a valid descriptor is rejected only with followRedirects:true or non-empty allowedOrigins', () => {
  const base = { projectRoot: '/tmp/demo', url: 'http://127.0.0.1:3000/', networkReplay: { manifestPath: '/tmp/demo/replay/manifest.json', sha256: 'a'.repeat(64) } };
  assert.deepEqual(parseAuditManifest(base).networkReplay, base.networkReplay, 'the descriptor itself is valid');
  for (const extra of [{ followRedirects: true }, { allowedOrigins: ['http://127.0.0.1:3001'] }, { followRedirects: true, allowedOrigins: ['http://127.0.0.1:3001'] }]) {
    assert.throws(() => parseAuditManifest({ ...base, ...extra }), error => error.code === 'INVALID_AUDIT_MANIFEST' &&
      error.details.length === 1 && error.details[0].path === 'networkReplay' && /cannot be combined/.test(error.details[0].message), JSON.stringify(extra));
  }
  for (const extra of [{ followRedirects: false }, { allowedOrigins: [] }, { followRedirects: false, allowedOrigins: [] }]) {
    assert.equal(parseAuditManifest({ ...base, ...extra }).networkReplay.sha256, 'a'.repeat(64), JSON.stringify(extra));
  }
});

test('n3: allowedOrigins normalizes case, default ports and IDN hostnames, and names the canonical form when it rejects', () => {
  const parsed = parseAuditManifest({ projectRoot: '/tmp/demo', url: 'https://example.com/', followRedirects: true,
    allowedOrigins: ['HTTPS://WWW.Example.com:443', 'http://b\u00fccher.example:80', 'https://www.example.com'], actions: [{ action: 'navigate', path: 'https://www.example.com/about' }] });
  assert.deepEqual(navigationPolicy(parsed).allowedOrigins, ['https://www.example.com', 'http://xn--bcher-kva.example']);
  assert.equal(canonicalOrigin('https://www.example.com/'), null, 'a trailing slash is a path and is rejected, not dropped');
  assert.throws(() => parseAuditManifest({ projectRoot: '/tmp/demo', url: 'https://example.com/', allowedOrigins: ['https://www.example.com/'] }),
    error => /scheme:\/\/host\[:port\]/.test(error.details[0].message) && /canonical origin/.test(error.details[0].message));
  const details = navigationBlockDetails({ reason: 'cross_origin_navigation', overridable: true, fromUrl: 'https://example.com/', blockedUrl: 'https://WWW.Example.com:443/x',
    chain: [], policy: navigationPolicy(parsed), sessionOrigins: new Set(['https://example.com']), stage: 'click' });
  assert.deepEqual(details.suggestedAction.manifestPatch.allowedOrigins, ['https://www.example.com', 'http://xn--bcher-kva.example'], 'the suggestion uses the canonical form');
});

test('n5: navigate schema accepts the https upgrade of a declared http origin only with followRedirects; runtime allows it only after landing there', () => {
  const manifest = { projectRoot: '/tmp/demo', url: 'http://example.com/', actions: [{ action: 'navigate', path: 'https://example.com/x' }] };
  assert.throws(() => parseAuditManifest(manifest), error => error.details.some(issue => issue.path === 'actions.0.path'), 'no followRedirects: the upgrade origin is not reachable');
  const parsed = parseAuditManifest({ ...manifest, followRedirects: true });
  assert.throws(() => parseAuditManifest({ ...manifest, followRedirects: true, actions: [{ action: 'navigate', path: 'https://www.example.com/x' }] }),
    error => error.details.some(issue => issue.path === 'actions.0.path'), 'an upgrade never changes the host');
  const policy = navigationPolicy(parsed), unpinned = new Set(['http://example.com']);
  assert.equal(decideNavigation({ url: 'https://example.com/x', policy, sessionOrigins: unpinned }).reason, 'cross_origin_navigation', 'not landed on https: runtime blocks it');
  assert.equal(decideNavigation({ url: 'https://example.com/x', policy, sessionOrigins: new Set([...unpinned, 'https://example.com']) }).allowed, true, 'landed on https: runtime allows it');
});

test('block details carry a usable suggestion and never echo URL credentials', () => {
  const policy = navigationPolicy({ url: 'https://example.com/' });
  const sessionOrigins = new Set(['https://example.com']);
  const start = navigationBlockDetails({ reason: 'cross_origin_redirect', overridable: true, fromUrl: 'https://example.com/', blockedUrl: 'https://www.example.com/en.html',
    chain: [{ url: 'https://example.com/', status: 301 }, { url: 'https://www.example.com/en.html', status: null, blocked: true }], policy, sessionOrigins, stage: 'audit-browser-start', initial: true });
  assert.deepEqual(start.suggestedAction.kind, 'use_url'); assert.equal(start.suggestedAction.url, 'https://www.example.com/en.html');
  assert.deepEqual(start.alternativeAction.manifestPatch, { followRedirects: true, allowedOrigins: ['https://www.example.com'] });
  const click = navigationBlockDetails({ reason: 'cross_origin_navigation', overridable: true, fromUrl: 'https://example.com/', blockedUrl: 'https://other.example/', chain: [], policy, sessionOrigins, stage: 'click' });
  assert.deepEqual(click.suggestedAction.manifestPatch, { allowedOrigins: ['https://other.example'] }); assert.equal(click.alternativeAction, undefined);
  const floor = navigationBlockDetails({ reason: 'credentials_in_url', overridable: false, fromUrl: 'https://example.com/', blockedUrl: 'https://user:secret@example.com/',
    chain: [{ url: 'https://user:secret@example.com/', blocked: true }], policy, sessionOrigins, stage: 'click' });
  assert.equal(floor.suggestedAction.kind, 'stop'); assert.doesNotMatch(JSON.stringify(floor), /secret/);
  assert.equal(redactUrl('https://user:secret@example.com/a'), 'https://redacted@example.com/a');
  assert.equal(start.code, 'AUDIT_NAVIGATION_BLOCKED');
  const payload = errorPayload({ code: 'AUDIT_SESSION_START_FAILED', message: 'blocked', details: { reportPath: '/x' }, navigation: { ...start, ignored: 'x' } });
  assert.deepEqual(Object.keys(payload), ['code', 'message', 'navigation'], 'object details stay out of the payload as in 0.1.1; navigation is additive');
  assert.equal(payload.code, 'AUDIT_SESSION_START_FAILED');
  assert.equal(payload.navigation.ignored, undefined); assert.equal(payload.navigation.code, 'AUDIT_NAVIGATION_BLOCKED'); assert.equal(payload.navigation.suggestedAction.url, start.suggestedAction.url);
  const record = errorRecord(Object.assign(new Error('net::ERR_BLOCKED_BY_CLIENT'), { navigation: start }), 'audit-browser-start');
  assert.deepEqual(Object.keys(record), ['code', 'message', 'stage', 'navigation']); assert.equal(record.code, 'RUNTIME_ERROR');
});

// ---------- Browser behavior on loopback fixtures ----------

test('T1 and T13: an undeclared apex-to-www redirect is blocked before www is contacted, with a structured payload', async t => {
  const fixture = await apexWwwSite(t), apex = fixture.origin('apex.localhost'), www = fixture.origin('www.apex.localhost');
  const { browser, error } = await startBlocked({ projectRoot: '/tmp', url: `${apex}/` });
  assert.equal(errorRecord(error).code, 'RUNTIME_ERROR', 'the 0.1.1 start error is unchanged'); assert.equal(error.details, undefined);
  assert.equal(fixture.count('www.apex.localhost'), 0, 'No hop may contact the undeclared origin.');
  const details = error.navigation;
  assert.equal(details.code, 'AUDIT_NAVIGATION_BLOCKED');
  assert.equal(details.reason, 'cross_origin_redirect'); assert.equal(details.overridable, true); assert.equal(details.stage, 'audit-browser-start');
  assert.equal(details.fromUrl, `${apex}/`); assert.equal(details.blockedUrl, `${www}/en.html`);
  assert.deepEqual(details.redirectChain, [{ url: `${apex}/`, status: 301 }, { url: `${www}/en.html`, status: null, blocked: true }]);
  assert.deepEqual(details.suggestedAction, { kind: 'use_url', url: `${www}/en.html`, origin: www, note: details.suggestedAction.note });
  assert.deepEqual(details.alternativeAction.manifestPatch, { followRedirects: true, allowedOrigins: [www] });
  assert.deepEqual(details.policy, { followRedirects: false, allowedOrigins: [], maxRedirects: null, sessionOrigins: [apex] });
  const report = browser.navigationReport();
  assert.equal(report.finalUrl, null); assert.equal(report.blocked.reason, 'cross_origin_redirect');
  assert.deepEqual(browser.blocked, [{ reason: 'navigation_outside_origin', url: `${www}/en.html` }], 'the legacy event keeps its 0.1.1 shape');
});

test('T2, T11: a declared apex-to-www redirect is followed, recorded, and pins navigate/reset to the landed origin', async t => {
  const fixture = await apexWwwSite(t), apex = fixture.origin('apex.localhost'), www = fixture.origin('www.apex.localhost');
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${apex}/`, followRedirects: true, allowedOrigins: [www] }));
  t.after(() => browser.close());
  await browser.start();
  const report = browser.navigationReport();
  assert.equal(report.manifestUrl, `${apex}/`); assert.equal(report.finalUrl, `${www}/en.html`); assert.equal(report.redirects, 1);
  assert.deepEqual(report.redirectChain, [{ url: `${apex}/`, status: 301 }, { url: `${www}/en.html`, status: 200 }]);
  assert.equal(report.pinnedToLanding, true); assert.deepEqual(report.sessionOrigins, [apex, www]);
  assert.deepEqual(report.policy, { followRedirects: true, allowedOrigins: [www], maxRedirects: MAX_REDIRECTS });
  const apexHits = fixture.count('apex.localhost');
  const navigated = await browser.execute({ action: 'navigate', path: '/about' });
  assert.equal(navigated.success, true); assert.equal(navigated.result.url, `${www}/about`, 'relative navigate resolves against the landed URL');
  const clicked = await browser.execute({ action: 'click', selector: '#abs' });
  assert.equal(clicked.success, true, 'T11: an absolute link on the landed origin is allowed');
  const reset = await browser.execute({ action: 'reset' });
  assert.equal(reset.success, true); assert.equal(browser.page.url(), `${www}/en.html`);
  assert.equal(fixture.count('apex.localhost'), apexHits, 'navigate/reset never re-enter the old origin');
});

test('T4: a same-origin trailing-slash redirect is followed under the default policy and recorded', async t => {
  const fixture = await site(t, (host, url) => url === '/docs' ? { status: 301, location: '/docs/' } : {});
  const origin = fixture.origin('127.0.0.1');
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${origin}/docs` }));
  t.after(() => browser.close());
  await browser.start();
  const report = browser.navigationReport();
  assert.equal(report.finalUrl, `${origin}/docs/`); assert.equal(report.pinnedToLanding, false);
  assert.deepEqual(report.redirectChain, [{ url: `${origin}/docs`, status: 301 }, { url: `${origin}/docs/`, status: 200 }]);
  const reset = await browser.execute({ action: 'reset' });
  assert.equal(reset.success, true);
  assert.deepEqual(reset.result.redirectChains, [{ hops: [{ url: `${origin}/docs`, status: 301 }, { url: `${origin}/docs/`, status: 200 }] }], 'unpinned reset re-follows the declared URL as before');
});

test('T5: undeclared third-party navigation mid-session is blocked with declare_origin, zero hits', async t => {
  const fixture = await apexWwwSite(t), www = fixture.origin('www.apex.localhost'), third = fixture.origin('third.localhost');
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${www}/en.html` }));
  t.after(() => browser.close());
  await browser.start();
  const clicked = await browser.execute({ action: 'click', selector: '#third' });
  assert.equal(clicked.success, false); assert.equal(clicked.error.code, 'AUDIT_BROWSER_ACTION_BLOCKED', '0.1.1 code');
  assert.deepEqual(clicked.error.details, [{ reason: 'navigation_outside_origin', url: `${third}/` }], '0.1.1 details: an array of events');
  assert.equal(clicked.error.navigation.reason, 'cross_origin_navigation'); assert.equal(clicked.error.navigation.stage, 'click');
  assert.deepEqual(clicked.error.navigation.suggestedAction.manifestPatch, { allowedOrigins: [third] });
  await browser.execute({ action: 'reset' });
  const redirected = await browser.execute({ action: 'navigate', path: '/away' });
  assert.equal(redirected.error.code, 'RUNTIME_ERROR', '0.1.1: the failed goto'); assert.equal(redirected.error.details, undefined);
  assert.equal(redirected.error.navigation.reason, 'cross_origin_redirect');
  assert.deepEqual(redirected.error.navigation.suggestedAction.manifestPatch, { followRedirects: true, allowedOrigins: [third] });
  assert.equal(redirected.error.navigation.alternativeAction, undefined, 'use_url is only suggested for the start URL');
  const precheck = await browser.execute({ action: 'navigate', path: `${third}/` });
  assert.equal(precheck.error.code, 'UNSAFE_AUDIT_NAVIGATION', '0.1.1 preflight code'); assert.equal(precheck.error.navigation.reason, 'cross_origin_navigation');
  assert.equal(fixture.count('third.localhost'), 0);
  const closed = await browser.close();
  const unsupported = closed.filter(error => error.code === 'AUDIT_UNSUPPORTED_EVENT');
  assert.deepEqual(unsupported.map(error => error.details), [{ reason: 'navigation_outside_origin', url: `${third}/` }, { reason: 'navigation_outside_origin', url: `${third}/` }]);
  assert.deepEqual(unsupported.map(error => error.navigation.reason), ['cross_origin_navigation', 'cross_origin_redirect']);
});

test('T6: a redirect hop with URL credentials is blocked even when its origin is declared; credentials are redacted', async t => {
  const fixture = await site(t, (host, url, port) => host === 'apex.localhost' ? { location: `http://user:secret@www.apex.localhost:${port}/x` } : {});
  const www = fixture.origin('www.apex.localhost');
  const { browser, error } = await startBlocked({ projectRoot: '/tmp', url: `${fixture.origin('apex.localhost')}/`, followRedirects: true, allowedOrigins: [www] });
  assert.equal(error.navigation.reason, 'credentials_in_url'); assert.equal(error.navigation.overridable, false); assert.equal(error.navigation.suggestedAction.kind, 'stop');
  assert.equal(fixture.count('www.apex.localhost'), 0);
  assert.doesNotMatch(JSON.stringify([error.navigation, browser.navigationReport(), browser.blocked]), /secret/);
});

test('T8: a chain longer than the cap is blocked at cap+1 when following; the default policy is unchanged', async t => {
  const fixture = await site(t, (host, url) => {
    const step = Number(url.slice(1) || 0);
    return step < 7 ? { location: `/${step + 1}` } : {};
  });
  const origin = fixture.origin('127.0.0.1');
  const { error } = await startBlocked({ projectRoot: '/tmp', url: `${origin}/0`, followRedirects: true });
  assert.equal(error.navigation.reason, 'redirect_limit'); assert.equal(error.navigation.overridable, false);
  assert.equal(error.navigation.redirectChain.length, MAX_REDIRECTS + 2);
  assert.deepEqual(error.navigation.redirectChain.at(-1), { url: `${origin}/6`, status: null, blocked: true });
  assert.ok(error.navigation.redirectChain.slice(0, -1).every(hop => hop.status === 302));
  assert.equal(fixture.hits.some(hit => hit.url === '/6'), false, 'the hop past the cap is never sent');
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${origin}/0` }));
  t.after(() => browser.close());
  await browser.start();
  assert.equal(browser.navigationReport().finalUrl, `${origin}/7`, 'old manifests keep following same-origin chains');
});

test('T9: a public-looking site cannot redirect into loopback even when declared; loopback to loopback stays allowed', async t => {
  const target = await site(t, () => ({}));
  const loopback = target.origin('127.0.0.1');
  const fixture = await site(t, () => ({ location: `${loopback}/` }));
  const publicUrl = `http://public-site.example:${fixture.port}/`;
  const { error } = await startBlocked({ projectRoot: '/tmp', url: publicUrl, followRedirects: true, allowedOrigins: [loopback] },
    { launchArgs: ['--host-resolver-rules=MAP public-site.example 127.0.0.1'], hostResolver: publicAnswer });
  assert.equal(fixture.hits.length, 1, 'the public-looking host was reached through the resolver rule');
  assert.equal(error.navigation.reason, 'private_network_target'); assert.equal(error.navigation.overridable, false);
  assert.equal(target.hits.length, 0, 'the loopback target was never contacted');
  const local = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${fixture.origin('apex.localhost')}/`, followRedirects: true, allowedOrigins: [loopback] }));
  t.after(() => local.close());
  await local.start();
  assert.equal(local.navigationReport().finalUrl, `${loopback}/`);
});

test('T10: a followed redirect to an error page reports HTTP_ERROR and keeps the chain', async t => {
  const fixture = await apexWwwSite(t, { wwwStatus: 503 }), www = fixture.origin('www.apex.localhost');
  const { browser, error } = await startBlocked({ projectRoot: '/tmp', url: `${fixture.origin('apex.localhost')}/`, followRedirects: true, allowedOrigins: [www] });
  assert.equal(error.code, 'HTTP_ERROR');
  const report = browser.navigationReport();
  assert.equal(report.finalUrl, `${www}/en.html`);
  assert.deepEqual(report.redirectChain.map(hop => hop.status), [301, 503]);
});

test('m6: a declared origin is still blocked on a redirect hop unless followRedirects is true', async t => {
  const fixture = await apexWwwSite(t), apex = fixture.origin('apex.localhost'), www = fixture.origin('www.apex.localhost');
  const { error } = await startBlocked({ projectRoot: '/tmp', url: `${apex}/`, allowedOrigins: [www] });
  assert.equal(errorRecord(error).code, 'RUNTIME_ERROR');
  assert.equal(error.navigation.reason, 'cross_origin_redirect'); assert.equal(error.navigation.overridable, true);
  assert.deepEqual(error.navigation.policy, { followRedirects: false, allowedOrigins: [www], maxRedirects: null, sessionOrigins: [apex, www] });
  assert.deepEqual(error.navigation.alternativeAction.manifestPatch, { followRedirects: true, allowedOrigins: [www] });
  assert.equal(fixture.count('www.apex.localhost'), 0, 'declaring the origin alone does not follow the redirect');
});

test('m6: mid-session click and navigate from a public-looking site to a private literal are blocked even when declared', async t => {
  const target = await site(t, () => ({}));
  const loopback = target.origin('127.0.0.1');
  const fixture = await site(t, (host, url) => url === '/hop' ? { location: `${loopback}/` }
    : { body: page('public').replace('</main>', `<a id="private" href="${loopback}/">Private</a></main>`) });
  const publicOrigin = `http://public-site.example:${fixture.port}`;
  for (const extra of [{}, { followRedirects: true, allowedOrigins: [loopback] }]) {
    const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${publicOrigin}/`, ...extra }), { launchArgs: ['--host-resolver-rules=MAP public-site.example 127.0.0.1'], hostResolver: publicAnswer });
    t.after(() => browser.close());
    await browser.start();
    const clicked = await browser.execute({ action: 'click', selector: '#private' });
    assert.equal(clicked.error.code, 'AUDIT_BROWSER_ACTION_BLOCKED'); assert.deepEqual(clicked.error.details, [{ reason: 'navigation_outside_origin', url: `${loopback}/` }]);
    assert.equal(clicked.error.navigation.reason, 'private_network_target'); assert.equal(clicked.error.navigation.overridable, false);
    assert.equal(clicked.error.navigation.suggestedAction.kind, 'stop');
    await browser.execute({ action: 'reset' });
    const navigated = await browser.execute({ action: 'navigate', path: `${loopback}/` });
    assert.equal(navigated.error.code, 'UNSAFE_AUDIT_NAVIGATION'); assert.equal(navigated.error.navigation.reason, 'private_network_target');
    const redirected = await browser.execute({ action: 'navigate', path: '/hop' });
    assert.equal(redirected.error.code, 'RUNTIME_ERROR'); assert.equal(redirected.error.navigation.reason, 'private_network_target');
    await browser.close();
  }
  assert.equal(target.hits.length, 0, 'the private literal was never contacted');
});

test('m1: a start page that leaves for about:blank is not pinned; navigate and reset keep resolving against manifest.url', async t => {
  const fixture = await site(t, (host, url) => url === '/' ? { body: '<!doctype html><html lang="en"><head><title>x</title><script>location.href = "about:blank";</script></head><body></body></html>' } : {});
  const origin = fixture.origin('127.0.0.1');
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${origin}/` }));
  t.after(() => browser.close());
  await browser.start();
  const report = browser.navigationReport();
  assert.equal(report.pinnedToLanding, false); assert.deepEqual(report.sessionOrigins, [origin]);
  const navigated = await browser.execute({ action: 'navigate', path: '/ok' });
  assert.equal(navigated.success, true, JSON.stringify(navigated.error)); assert.equal(navigated.result.url, `${origin}/ok`);
  const reset = await browser.execute({ action: 'reset' });
  assert.equal(reset.error?.code, undefined, 'reset reaches manifest.url again');
});

/** Drive the CDP handlers directly to pin both event orders deterministically. */
function cdpDouble(manifest) {
  const browser = new AuditBrowser(parseAuditManifest(manifest));
  browser.page = { url: () => manifest.url };
  const paused = (url, requestId, redirectedRequestId) => browser.decideMainFrameRequest({ frameId: 'main', request: { url }, requestId, networkId: 'net-1', ...(redirectedRequestId ? { redirectedRequestId } : {}) });
  const redirect = (url, status) => browser.recordRedirectResponse({ frameId: 'main', type: 'Document', requestId: 'net-1', request: { url }, redirectResponse: { url: 'ignored', status } });
  const final = (url, status) => browser.recordFinalResponse({ frameId: 'main', type: 'Document', requestId: 'net-1', response: { url, status } });
  return { browser, paused, redirect, final };
}

test('m5: redirect statuses are recorded whichever CDP event arrives first', () => {
  const a = 'http://127.0.0.1:9/a', b = 'http://127.0.0.1:9/b', c = 'http://127.0.0.1:9/c';
  const early = cdpDouble({ projectRoot: '/tmp', url: a });
  early.paused(a, 'i1'); early.redirect(b, 301); early.paused(b, 'i2', 'i1'); early.redirect(c, 302); early.paused(c, 'i3', 'i2'); early.final(c, 200);
  const late = cdpDouble({ projectRoot: '/tmp', url: a });
  late.paused(a, 'i1'); late.paused(b, 'i2', 'i1'); late.redirect(b, 301); late.paused(c, 'i3', 'i2'); late.redirect(c, 302); late.final(c, 200);
  for (const { browser } of [early, late]) {
    assert.deepEqual(browser.navigationChains[0].hops, [{ url: a, status: 301 }, { url: b, status: 302 }, { url: c, status: 200 }]);
  }
  // Same URL on both hops, final response before the redirect event: statuses are matched by hop index, not URL.
  const repeated = cdpDouble({ projectRoot: '/tmp', url: a });
  repeated.paused(a, 'i1'); repeated.paused(a, 'i2', 'i1'); repeated.final(a, 200); repeated.redirect(a, 307);
  assert.deepEqual(repeated.browser.navigationChains[0].hops.map(hop => hop.status), [307, 200], 'a repeated URL never receives the wrong status');
  const before = cdpDouble({ projectRoot: '/tmp', url: a });
  before.redirect(b, 301); before.paused(a, 'i1'); before.paused(b, 'i2', 'i1');
  assert.deepEqual(before.browser.navigationChains[0].hops.map(hop => hop.status), [301, null], 'a status that precedes its chain is applied when the hop is recorded');
});

test('R-n3: a redirect status never overwrites a status the hop already has', () => {
  const a = 'http://127.0.0.1:9/a', b = 'http://127.0.0.1:9/b';
  const known = cdpDouble({ projectRoot: '/tmp', url: a });
  known.paused(a, 'i1'); known.final(a, 200); known.paused(b, 'i2', 'i1'); known.redirect(b, 301);
  assert.deepEqual(known.browser.navigationChains[0].hops.map(hop => hop.status), [200, null], 'the first status recorded for hop 0 is kept');
});

test('n2: the 65th and later blocked navigations in one session still carry the structured payload', async () => {
  const origin = 'http://127.0.0.1:9';
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${origin}/` }));
  let n = 0;
  browser.page = { url: () => `${origin}/`, goto: async () => {
    n++; browser.decideMainFrameRequest({ frameId: 'main', request: { url: `http://third.example/${n}` }, requestId: `i${n}`, networkId: `net-${n}` });
    throw new Error('net::ERR_BLOCKED_BY_CLIENT');
  } };
  browser.navigationStage = 'navigate';
  for (let index = 1; index <= 70; index++) {
    const error = await browser.goto(`${origin}/x`, 1000).then(() => null, value => value);
    assert.equal(error.code, undefined); assert.equal(error.navigation?.blockedUrl, `http://third.example/${index}`, `block ${index}`);
  }
});

test('n4: report hop URLs are clipped to 2048 characters like block details', () => {
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: 'http://127.0.0.1:9/' }));
  const long = `http://127.0.0.1:9/${'a'.repeat(3000)}`;
  browser.initialChain = { hops: [{ url: long, status: 301 }, { url: `http://u:secret@127.0.0.1:9/${'b'.repeat(3000)}`, status: null, blocked: true }] };
  const { redirectChain } = browser.navigationReport();
  assert.deepEqual(redirectChain.map(hop => hop.url.length), [2048, 2048]); assert.doesNotMatch(JSON.stringify(redirectChain), /secret/);
});

test('R-n1: an old manifest keeps the 0.1.1 navigate issue code, path and message word for word', () => {
  const issue = manifest => { try { parseAuditManifest(manifest); } catch (error) { return { code: error.code, details: error.details }; } assert.fail('expected a validation error'); };
  const old = issue({ projectRoot: '/tmp/demo', url: 'https://example.com/', actions: [{ action: 'navigate', path: 'https://other.example/' }] });
  assert.equal(old.code, 'INVALID_AUDIT_MANIFEST');
  assert.deepEqual(old.details.map(({ path: where, message }) => ({ path: where, message })),
    [{ path: 'actions.0.path', message: 'Navigation must remain on the manifest HTTP(S) origin without credentials.' }]);
  const opted = issue({ projectRoot: '/tmp/demo', url: 'https://example.com/', allowedOrigins: ['https://www.example.com'], actions: [{ action: 'navigate', path: 'https://other.example/' }] });
  assert.equal(opted.details[0].path, 'actions.0.path'); assert.match(opted.details[0].message, /allowedOrigins entry/);
});

test('R-n2: navigationReport clips and redacts finalUrl and landingOrigin like every recorded URL', () => {
  const origin = 'http://127.0.0.1:9';
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${origin}/` }));
  browser.startUrl = `${origin}/${'a'.repeat(3000)}`;
  const long = browser.navigationReport();
  assert.equal(long.finalUrl.length, 2048); assert.equal(long.finalUrl, `${browser.startUrl.slice(0, 2047)}\u2026`); assert.equal(long.landingOrigin, origin);
  browser.startUrl = `http://u:secret@127.0.0.1:9/${'b'.repeat(3000)}`;
  const credentialed = browser.navigationReport();
  assert.equal(credentialed.finalUrl.length, 2048); assert.doesNotMatch(JSON.stringify(credentialed), /secret/);
  browser.startUrl = `${origin}/en/products/widgets?id=42`;
  assert.deepEqual([browser.navigationReport().finalUrl, browser.navigationReport().landingOrigin], [`${origin}/en/products/widgets?id=42`, origin], 'normal URLs are unchanged');
  browser.startUrl = null; browser.initialChain = { hops: [{ url: `${origin}/${'c'.repeat(3000)}`, status: 200 }] };
  assert.equal(browser.navigationReport().finalUrl.length, 2048);
});

// ---------- Reports ----------

test('collection, proposal and HTML record the declared URL, every hop and the final URL', async t => {
  const fixture = await apexWwwSite(t), apex = fixture.origin('apex.localhost'), www = fixture.origin('www.apex.localhost');
  const projectRoot = await workspace(t);
  const audit = await collectAudit({ projectRoot, url: `${apex}/`, followRedirects: true, allowedOrigins: [www], actions: [{ action: 'snapshot' }], wallSeconds: 60 });
  assert.equal(audit.status, 'collected', JSON.stringify(audit.errors));
  assert.equal(audit.navigation.manifestUrl, `${apex}/`); assert.equal(audit.navigation.finalUrl, `${www}/en.html`);
  assert.deepEqual(audit.navigation.redirectChain, [{ url: `${apex}/`, status: 301 }, { url: `${www}/en.html`, status: 200 }]);
  assert.equal(audit.applicationBinding, 'caller-declared');
  const proposal = await submitAudit(audit.reportPath, { auditor: { name: 'Agent' }, findings: [] });
  assert.deepEqual(proposal.navigation, audit.navigation);
  const out = path.join(projectRoot, 'evidence', 'report.html');
  await writeAuditReport(proposal.reportPath, out);
  const html = await fs.readFile(out, 'utf8');
  assert.match(html, new RegExp(`<dt>Page</dt><dd>${www}/en\\.html</dd>`));
  assert.match(html, new RegExp(`<dt>Declared URL</dt><dd>${apex}/ \\(redirected 1 hop to the page above\\)</dd>`));
  assert.match(html, /<dt>URL binding<\/dt><dd>Caller-declared: /);
});

test('HTML Page row keeps old reports unchanged and omits Declared URL when no redirect happened', () => {
  const base = { kind: 'audit-proposal', runId: 'r', findings: [], coverage: [], standard: { version: '2.2', targetLevel: 'AA' }, auditor: { name: 'A' }, manifest: { url: 'http://127.0.0.1:1/' } };
  const old = renderAuditReportHtml(base);
  assert.match(old, /<dt>Page<\/dt><dd>http:\/\/127\.0\.0\.1:1\/<\/dd>/); assert.doesNotMatch(old, /Declared URL|URL binding/);
  const same = renderAuditReportHtml({ ...base, manifest: { url: 'http://127.0.0.1:1' }, navigation: { finalUrl: 'http://127.0.0.1:1/', redirects: 0 } });
  assert.doesNotMatch(same, /Declared URL/); assert.match(same, /URL binding/);
  const blocked = renderAuditReportHtml({ ...base, navigation: { finalUrl: null, redirects: 1 } });
  assert.match(blocked, /<dt>Page<\/dt><dd>http:\/\/127\.0\.0\.1:1\/ \(declared URL; no final URL was recorded\)<\/dd>/);
});

// ---------- T12: an agent recovers from the structured block in all three transports ----------

function run(args, { input = '' } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, lines: stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) }));
    child.stdin.end(input);
  });
}

test('T12 CLI JSON: the agent reads reason/suggestedAction, rewrites the manifest URL and collects on the second run', async t => {
  const fixture = await apexWwwSite(t), apex = fixture.origin('apex.localhost'), www = fixture.origin('www.apex.localhost');
  const projectRoot = await workspace(t), file = path.join(projectRoot, 'evidence', 'audit-manifest.json');
  let manifest = { projectRoot, url: `${apex}/`, actions: [{ action: 'snapshot' }], wallSeconds: 60 };
  await fs.writeFile(file, JSON.stringify(manifest));
  const first = await run(['audit', file, '--summary']);
  assert.equal(first.code, 1);
  const block = first.lines[0].errors.find(error => error.stage === 'audit-browser-start');
  assert.equal(block.code, 'RUNTIME_ERROR', '0.1.1 code'); assert.equal(block.details, undefined, '0.1.1: no details');
  const unsupported = first.lines[0].errors.find(error => error.code === 'AUDIT_UNSUPPORTED_EVENT');
  assert.deepEqual(unsupported.details, { reason: 'navigation_outside_origin', url: `${www}/en.html` }, '0.1.1 event details');
  assert.deepEqual(unsupported.navigation, block.navigation);
  assert.equal(first.lines[0].navigation.blocked.reason, block.navigation.reason);
  manifest = applySuggestion(manifest, block.navigation, 'use_url');
  assert.equal(manifest.url, `${www}/en.html`);
  await fs.writeFile(file, JSON.stringify(manifest));
  const second = await run(['audit', file, '--summary']);
  assert.equal(second.lines[0].status, 'collected', JSON.stringify(second.lines[0].errors));
  assert.equal(second.code, 0); assert.equal(second.lines[0].navigation.finalUrl, `${www}/en.html`);
});

test('T12 JSONL: audit-agent returns the structured block, and a declared-origin retry opens the session', async t => {
  const fixture = await apexWwwSite(t), apex = fixture.origin('apex.localhost'), www = fixture.origin('www.apex.localhost');
  const projectRoot = await workspace(t), file = path.join(projectRoot, 'evidence', 'agent-manifest.json');
  let manifest = { projectRoot, url: `${apex}/`, wallSeconds: 60 };
  await fs.writeFile(file, JSON.stringify(manifest));
  const first = await run(['audit-agent', file], { input: '{"command":"finish"}\n' });
  assert.equal(first.code, 1);
  const [error] = first.lines[0].errors;
  assert.equal(error.code, 'AUDIT_SESSION_START_FAILED', '0.1.1 code');
  assert.deepEqual(Object.keys(error.details), ['reportPath'], '0.1.1 details'); assert.equal(error.navigation.reportPath, error.details.reportPath);
  manifest = applySuggestion(manifest, error.navigation, 'declare_origin');
  assert.deepEqual({ followRedirects: manifest.followRedirects, allowedOrigins: manifest.allowedOrigins }, { followRedirects: true, allowedOrigins: [www] });
  await fs.writeFile(file, JSON.stringify(manifest));
  const second = await run(['audit-agent', file], { input: '{"command":"finish"}\n' });
  assert.equal(second.lines[0].kind, 'audit-agent-session', JSON.stringify(second.lines[0]));
  const files = (await fs.readdir(second.lines[0].directory)).filter(name => /^audit-[\w-]+\.json$/.test(name));
  assert.equal(files.length, 1);
  const collection = JSON.parse(await fs.readFile(path.join(second.lines[0].directory, files[0]), 'utf8'));
  assert.equal(collection.navigation.finalUrl, `${www}/en.html`);
});

test('T12 MCP: a rejected start returns the structured block and the corrected start succeeds on the same connection', async t => {
  const fixture = await apexWwwSite(t), apex = fixture.origin('apex.localhost'), www = fixture.origin('www.apex.localhost');
  const projectRoot = await workspace(t);
  const client = new Client({ name: 'any-site-test', version: '1' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(mcpTransport({ command: process.execPath, args: [cli, 'serve'], stderr: 'pipe' }), { mode: 'auto' });
  const start = async manifest => (await client.callTool({ name: 'a11y_audit_start', arguments: { manifest } })).structuredContent;
  let manifest = { projectRoot, url: `${apex}/`, startupAxe: false, wallSeconds: 60 };
  const first = await start(manifest);
  assert.equal(first.success, false); assert.equal(first.error.code, 'AUDIT_SESSION_START_FAILED', '0.1.1 code');
  assert.equal(first.error.details, undefined, '0.1.1: object details are not echoed over MCP');
  assert.equal(first.error.navigation.reason, 'cross_origin_redirect'); assert.equal(first.error.navigation.suggestedAction.kind, 'use_url');
  assert.equal(typeof first.error.navigation.reportPath, 'string');
  manifest = applySuggestion(manifest, first.error.navigation, 'use_url');
  const second = await start(manifest);
  assert.equal(second.success, true, JSON.stringify(second));
  assert.ok(fixture.count('www.apex.localhost') > 0);
  await client.callTool({ name: 'a11y_audit_close', arguments: { runId: second.runId } });
});

// ---------- R-M1: the read summary keeps the 0.1.1 error inline and adds errorNavigation ----------

const BLOCKED_ACTION_MESSAGE = 'The action attempted an unsupported popup, download or navigation outside the allowed origin.';
/** Two URL tiers: short names (about 960 bytes of error with navigation) and a typical product URL (over 1080 bytes). */
const readTiers = [
  { name: 'short', host: 'a.localhost', start: '/', outHost: 'b.localhost', outPath: '/' },
  { name: 'typical', host: 'www.apex.localhost', start: '/en/products/widgets?id=42', outHost: 'checkout.partner-example.localhost', outPath: '/cart' },
];

async function tierSite(t) {
  return site(t, (host, url, port) => {
    const tier = readTiers.find(item => item.host === host);
    if (!tier) return {};
    const out = `http://${tier.outHost}:${port}${tier.outPath}`;
    if (url === '/away') return { location: out };
    return { body: page(`${host}${url}`).replace('</main>', `<a id="out" href="${out}">Out</a></main>`) };
  });
}

/** Checks one read summary against the field read of /error for the same record. */
function assertLegacyRead(summary, full, expected, label) {
  assert.equal(summary.success, true, label);
  assert.equal(full.navigation?.code, 'AUDIT_NAVIGATION_BLOCKED', label);
  const { navigation, ...legacy } = full;
  assert.deepEqual(summary.error, legacy, `${label}: the summary error is the 0.1.1 error, inline`);
  assert.deepEqual(Object.keys(summary.error), expected.keys, label);
  assert.equal(summary.error.code, expected.code, label); assert.equal(summary.error.stage, expected.stage, label);
  if (expected.details) assert.deepEqual(summary.error.details, expected.details, `${label}: 0.1.1 details are an array of events`);
  if (expected.message) assert.equal(summary.error.message, expected.message, label);
  assert.equal(Object.hasOwn(summary.error, 'deferred'), false, label);
  assert.doesNotMatch(JSON.stringify(summary.error), /AUDIT_NAVIGATION_BLOCKED|suggestedAction/, `${label}: navigation never leaks into the old keys`);
  assert.deepEqual(summary.errorNavigation, navigation, `${label}: navigation is in the same response`);
  assert.equal(summary.errorNavigation.code, 'AUDIT_NAVIGATION_BLOCKED', label);
  return Buffer.byteLength(JSON.stringify(full));
}

/** Click a link to an undeclared origin and navigate through a blocked redirect; read each record as summary and as /error. */
async function blockedReads(request, fixture, tier) {
  const origin = fixture.origin(tier.host), out = `${fixture.origin(tier.outHost)}${tier.outPath}`, sizes = {};
  for (const [kind, action, expected] of [
    ['click', { action: 'click', selector: '#out' }, { keys: ['code', 'message', 'stage', 'details'], code: 'AUDIT_BROWSER_ACTION_BLOCKED', stage: 'click', message: BLOCKED_ACTION_MESSAGE, details: [{ reason: 'navigation_outside_origin', url: out }] }],
    ['navigate', { action: 'navigate', path: '/away' }, { keys: ['code', 'message', 'stage'], code: 'RUNTIME_ERROR', stage: 'navigate' }],
  ]) {
    const step = await request({ tool: 'step', actions: [action] });
    const [record] = step.records;
    assert.equal(record.errorCode, expected.code, `${tier.name} ${kind}`);
    const summary = await request({ tool: 'read', evidenceId: record.evidenceId });
    const field = await request({ tool: 'read', evidenceId: record.evidenceId, options: { view: 'field', field: '/error' } });
    assert.equal(field.pagination.complete, true);
    const full = JSON.parse(field.data);
    if (kind === 'navigate') assert.ok(full.message.startsWith(`page.goto: net::ERR_BLOCKED_BY_CLIENT at ${origin}/away`), full.message);
    sizes[kind] = assertLegacyRead(summary, full, expected, `${tier.name} ${kind}`);
    await request({ tool: 'step', actions: [{ action: 'reset' }] });
  }
  assert.equal(fixture.count(tier.outHost), 0);
  return sizes;
}

function interactiveAgent(file) {
  const child = spawn(process.execPath, [cli, 'audit-agent', file], { stdio: ['pipe', 'pipe', 'pipe'] });
  const lines = createInterface({ input: child.stdout }), queue = [], waiting = [];
  lines.on('line', line => { const value = JSON.parse(line); const resolve = waiting.shift(); if (resolve) resolve(value); else queue.push(value); });
  const next = () => queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve => waiting.push(resolve));
  const closed = new Promise(resolve => child.on('close', resolve));
  return { next, request: value => { child.stdin.write(`${JSON.stringify(value)}\n`); return next(); },
    finish: async () => { child.stdin.end('{"command":"finish"}\n'); await closed; } };
}

test('R-M1 JSONL: read keeps a blocked action error inline in its 0.1.1 shape and adds errorNavigation, for short and typical URLs', async t => {
  const fixture = await tierSite(t), projectRoot = await workspace(t), sizes = {};
  for (const tier of readTiers) {
    const file = path.join(projectRoot, 'evidence', `read-${tier.name}.json`);
    await fs.writeFile(file, JSON.stringify({ projectRoot, url: `${fixture.origin(tier.host)}${tier.start}`, wallSeconds: 120 }));
    const agent = interactiveAgent(file);
    t.after(() => agent.finish());
    const opened = await agent.next();
    assert.equal(opened.kind, 'audit-agent-session', JSON.stringify(opened));
    sizes[tier.name] = await blockedReads(agent.request, fixture, tier);
    await agent.finish();
  }
  assert.ok(sizes.typical.click > 1080 && sizes.typical.navigate > 1080, `the typical tier exceeds the 1 KiB inline bound with navigation: ${JSON.stringify(sizes)}`);
  assert.ok(sizes.short.click >= 940 && sizes.short.click < sizes.typical.click, JSON.stringify(sizes));
});

test('R-M1 MCP: read keeps a blocked action error inline in its 0.1.1 shape and adds errorNavigation, for short and typical URLs', async t => {
  const fixture = await tierSite(t), projectRoot = await workspace(t), sizes = {};
  for (const tier of readTiers) {
    // One MCP connection holds one session, so each tier uses its own connection.
    const client = new Client({ name: 'any-site-read-test', version: '1' }, { capabilities: {} });
    t.after(() => client.close());
    await client.connect(mcpTransport({ command: process.execPath, args: [cli, 'serve'], stderr: 'pipe' }), { mode: 'auto' });
    const call = async (name, args) => (await client.callTool({ name, arguments: args })).structuredContent;
    const start = await call('a11y_audit_start', { manifest: { projectRoot, url: `${fixture.origin(tier.host)}${tier.start}`, startupAxe: false, wallSeconds: 120 } });
    assert.equal(start.success, true, JSON.stringify(start));
    sizes[tier.name] = await blockedReads(request => call('a11y_audit_request', { runId: start.runId, request }), fixture, tier);
    await call('a11y_audit_close', { runId: start.runId });
    await client.close();
  }
  assert.ok(sizes.typical.click > 1080 && sizes.typical.navigate > 1080, JSON.stringify(sizes));
});

// ---------- R2-n1: no errorNavigation key without navigation; a deferred handle only above 4 KiB ----------

/** Long (about 700-character URLs, navigation about 2.8 KB) and xlong (about 1900-character URLs, navigation over 4 KiB). */
const sizeTiers = [
  { name: 'long', host: 'long.localhost', start: `/en/${'p'.repeat(680)}`, outHost: 'out-long.localhost', outPath: `/${'q'.repeat(680)}` },
  { name: 'xlong', host: 'xlong.localhost', start: `/en/${'p'.repeat(1880)}`, outHost: 'out-xlong.localhost', outPath: `/${'q'.repeat(1880)}` },
];

test('R2-n1 JSONL: a record without navigation has no errorNavigation key; navigation above 4 KiB is a deferred handle to /error', async t => {
  const fixture = await site(t, (host, url, port) => {
    const tier = sizeTiers.find(item => item.host === host);
    return tier ? { body: page(host).replace('</main>', `<a id="out" href="http://${tier.outHost}:${port}${tier.outPath}">Out</a></main>`) } : {};
  });
  const projectRoot = await workspace(t), size = value => Buffer.byteLength(JSON.stringify(value));
  for (const tier of sizeTiers) {
    // An old manifest: no followRedirects, no allowedOrigins.
    const file = path.join(projectRoot, 'evidence', `size-${tier.name}.json`);
    await fs.writeFile(file, JSON.stringify({ projectRoot, url: `${fixture.origin(tier.host)}${tier.start}`, wallSeconds: 120 }));
    const agent = interactiveAgent(file);
    t.after(() => agent.finish());
    assert.equal((await agent.next()).kind, 'audit-agent-session');
    const read = async (evidenceId, options) => agent.request({ tool: 'read', evidenceId, ...(options ? { options } : {}) });

    const [missing] = (await agent.request({ tool: 'step', actions: [{ action: 'click', selector: '#nope' }] })).records;
    const [snapshot] = (await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] })).records;
    const missingSummary = await read(missing.evidenceId), snapshotSummary = await read(snapshot.evidenceId);
    assert.equal(missingSummary.success, true); assert.notEqual(missingSummary.error, null, `${tier.name}: the failed click keeps its error`);
    assert.equal(Object.hasOwn(missingSummary, 'errorNavigation'), false, `${tier.name}: an error without navigation adds no key`);
    assert.equal(snapshotSummary.error, null); assert.equal(Object.hasOwn(snapshotSummary, 'errorNavigation'), false, `${tier.name}: a record without an error adds no key`);

    const [blocked] = (await agent.request({ tool: 'step', actions: [{ action: 'click', selector: '#out' }] })).records;
    assert.equal(blocked.errorCode, 'AUDIT_BROWSER_ACTION_BLOCKED');
    const summary = await read(blocked.evidenceId);
    const field = await read(blocked.evidenceId, { view: 'field', field: '/error' });
    assert.equal(field.pagination.complete, true);
    const full = JSON.parse(field.data), navigationBytes = size(full.navigation);
    assert.equal(full.navigation.code, 'AUDIT_NAVIGATION_BLOCKED');
    t.diagnostic(`${tier.name}: navigation ${navigationBytes} B, /error ${size(full)} B`);
    if (tier.name === 'long') {
      assert.ok(navigationBytes > 2048 && navigationBytes <= 4096, `long navigation is ${navigationBytes} B`);
      assert.deepEqual(summary.errorNavigation, full.navigation, 'long: navigation stays inline under the 4 KiB bound');
    } else {
      assert.ok(navigationBytes > 4096, `xlong navigation is ${navigationBytes} B`);
      assert.equal(summary.errorNavigation.deferred, true, 'xlong: navigation becomes a deferred handle in the same read');
      assert.equal(summary.errorNavigation.read.field, '/error'); assert.equal(summary.errorNavigation.read.view, 'field');
      // serializedBytes counts navigation alone; the /error read it points to is larger.
      assert.equal(summary.errorNavigation.serializedBytes, navigationBytes);
      assert.ok(size(full) > navigationBytes, `/error is ${size(full)} B`);
    }
    assert.equal(fixture.count(tier.outHost), 0);
    await agent.finish();
  }
});

// ---------- R2-n2: only a landing on the origin of the last followed start hop is pinned ----------

test('R2-n2: a start page whose script moves to another declared origin is not pinned; navigate keeps resolving against manifest.url', async t => {
  // One loopback server for a.localhost and b.localhost. a.localhost/ sends its head with the script first and ends
  // only once the scripted request to b.localhost arrives, so the start reliably lands on b without any timer.
  let release = null;
  const server = http.createServer((request, response) => {
    if (externalProbe(request)) { response.end(); return; }
    const host = String(request.headers.host ?? '').replace(/:\d+$/, '');
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    if (host === 'a.localhost' && request.url === '/') {
      response.write(`<!doctype html><html lang="en"><head><title>a</title><script>location.replace(${JSON.stringify(`http://b.localhost:${server.address().port}/landed`)});</script>`);
      release = () => response.end('</head><body></body></html>');
      return;
    }
    if (host === 'b.localhost') release?.();
    response.end(page(`${host}${request.url}`));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const a = `http://a.localhost:${server.address().port}`, b = `http://b.localhost:${server.address().port}`;
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${a}/`, allowedOrigins: [b] }));
  t.after(() => browser.close());
  await browser.start();
  const report = browser.navigationReport();
  // Precondition: the browser really landed on the other declared origin, by script and not by a redirect.
  assert.equal(report.finalUrl, `${b}/landed`); assert.equal(report.landingOrigin, b);
  assert.deepEqual(report.redirectChain.map(hop => hop.url), [`${a}/`], 'the start chain has no redirect to b');
  assert.equal(report.pinnedToLanding, false, 'b is not the origin of the last followed start hop');
  assert.deepEqual(report.sessionOrigins, [a, b], 'the session origins are the declared ones only');
  const navigated = await browser.execute({ action: 'navigate', path: '/ok' });
  assert.equal(navigated.success, true, JSON.stringify(navigated.error)); assert.equal(navigated.result.url, `${a}/ok`);
});
