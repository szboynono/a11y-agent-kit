import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { openAuditAgent } from '../src/audit/agent.js';
import { registerAuditTools } from '../src/audit/mcp.js';
import { runAuditSessionCli } from '../src/audit/live-cli.js';
import { AUDIT_TEXT_LIMIT, MCP_TEXT_LIMIT } from '../src/audit/projection.js';
import { submitAudit } from '../src/audit/review.js';
import { renderAuditReportHtml, writeAuditReport } from '../src/audit/report-html.js';
import { AuditBrowser } from '../src/audit/browser.js';
import { parseAuditManifest } from '../src/audit/schema.js';
import { errorPayload } from '../src/audit/error-details.js';
import { errorRecord } from '../src/evidence.js';
import {
  boundNavigationDetails, classifyAddress, CLOUD_METADATA_ADDRESSES, decideNavigation, DNS_FAILED_HOST_LIMIT, DNS_LOOKUP_TIMEOUT_MS, DNS_NAVIGATION_WAIT_MS, dnsCheckSummary,
  DNS_BRIEF_MAX_BYTES, dnsCheckBrief,
  FLOOR_REASONS, isCloudMetadataHost, isPrivateHost, navigationBlockDetails, navigationPolicy, resolutionHost, resolveNavigationTarget, startSession, systemHostResolver,
} from '../src/audit/navigation.js';
import { externalProbe } from './helpers.js';

// Loopback fixtures only, and no real DNS: Chromium maps the *.example names below to 127.0.0.1 with
// --host-resolver-rules, while the DNS check runs against an injected resolver that answers from a table.
const page = title => `<!doctype html><html lang="en"><head><title>${title}</title></head><body><main><h1>${title}</h1></main></body></html>`;
const MAPPED = ['public-site.example', 'internal.example', 'rebind.example', 'meta.example', 'nxdomain.example', 'staging.example', 'slow.example',
  'hop.example', 'hop2.example', 'nav.example', 'nav2.example', 'mixed.example'];
const launchArgs = [`--host-resolver-rules=${MAPPED.map(host => `MAP ${host} 127.0.0.1`).join(', ')}`];

/** An injected resolver: `table[host]` is an address list, or an Error to throw. Every call is recorded. */
function tableResolver(table) {
  const calls = [];
  return {
    calls,
    resolver: {
      name: 'test-table',
      lookup: async host => {
        calls.push(host);
        const answer = table[host];
        if (answer instanceof Error) throw answer;
        if (!answer) throw Object.assign(new Error(`no fixture answer for ${host}`), { code: 'ENOTFOUND' });
        return answer.map(address => ({ address, family: address.includes(':') ? 6 : 4 }));
      },
    },
  };
}
const dnsError = code => Object.assign(new Error(`lookup failed: ${code}`), { code });

/** One loopback server answering for every mapped name; hits are counted per Host header. */
async function site(t, route = () => ({})) {
  const hits = [];
  const server = http.createServer((request, response) => {
    if (externalProbe(request)) { response.end(); return; }
    const host = String(request.headers.host ?? '').replace(/:\d+$/, '');
    hits.push({ host, url: request.url });
    const answer = route(host, request.url, server.address().port) ?? {};
    if (answer.location) response.writeHead(answer.status ?? 302, { location: answer.location }).end();
    else response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(answer.body ?? page(`${host}${request.url}`));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const port = server.address().port;
  return { port, hits, origin: host => `http://${host}:${port}`, count: host => hits.filter(hit => hit.host === host).length };
}

async function startBlocked(manifest, options) {
  const browser = new AuditBrowser(parseAuditManifest(manifest), { launchArgs, ...options });
  try { await browser.start(); } catch (error) { return { browser, error }; } finally { await browser.close(); }
  assert.fail('The start navigation should have been blocked.');
}

const publicPolicy = navigationPolicy({ url: 'https://public-site.example/' });
const privatePolicy = navigationPolicy({ url: 'http://127.0.0.1:3000/' });

// ---------- Classification ----------

test('DNS guard: every resolved address is classified, and only public, non-metadata addresses pass', () => {
  const table = [
    ['8.8.8.8', 'public', false], ['172.32.0.1', 'public', false], ['2606:4700::1', 'public', false], ['198.18.0.1', 'public', false],
    ['10.1.2.3', 'private', true], ['172.16.0.1', 'private', true], ['172.31.255.255', 'private', true], ['192.168.1.1', 'private', true],
    ['127.0.0.1', 'loopback', true], ['127.255.0.9', 'loopback', true], ['::1', 'loopback', true],
    ['169.254.1.1', 'link_local', true], ['fe80::1', 'link_local', true], ['fe80::1%en0', 'link_local', true],
    ['0.0.0.0', 'unspecified', true], ['0.1.2.3', 'unspecified', true], ['::', 'unspecified', true],
    ['100.64.0.1', 'shared_address_space', true], ['fc00::1', 'unique_local', true], ['fd12:3456::1', 'unique_local', true], ['fec0::1', 'site_local', true],
    ['224.0.0.1', 'multicast', true], ['239.255.255.250', 'multicast', true], ['ff02::1', 'multicast', true],
    ['240.0.0.1', 'reserved', true], ['255.255.255.255', 'reserved', true], ['192.0.2.1', 'reserved', true], ['2001:db8::1', 'reserved', true],
    ['::ffff:10.0.0.1', 'private', true], ['::ffff:7f00:1', 'loopback', true], ['::ffff:8.8.8.8', 'public', false], ['64:ff9b::10.0.0.1', 'private', true],
    ['not-an-address', 'invalid', true], ['', 'invalid', true], [null, 'invalid', true],
  ];
  for (const [address, category, blocked] of table) {
    const result = classifyAddress(address);
    assert.equal(result.category, category, String(address)); assert.equal(result.blocked, blocked, String(address));
  }
  assert.equal(classifyAddress('::ffff:10.0.0.1').embeddedIpv4, '10.0.0.1');
  assert.equal(classifyAddress('[FE80::1]').address, 'fe80::1', 'brackets, case and zone ids are normalized');
  assert.equal(classifyAddress('fe80::1%en0').address, 'fe80::1', 'the interface name is not recorded');
});

test('DNS guard: the cloud metadata list is checked by exact address, including IPv4-mapped forms', () => {
  // A known list, not an exhaustive one (see CLOUD_METADATA_ADDRESSES).
  assert.deepEqual([...CLOUD_METADATA_ADDRESSES], ['169.254.169.254', '169.254.170.2', '169.254.170.23', 'fd00:ec2::254', 'fd00:ec2::23',
    'fd20:ce::254', '168.63.129.16', '192.0.0.192', '100.100.100.200', '169.254.0.23', 'fe80::a9fe:a9fe']);
  for (const address of [...CLOUD_METADATA_ADDRESSES, 'FD00:EC2:0:0::254', '::ffff:169.254.169.254', '::ffff:a9fe:a9fe', '::a9fe:a9fe', '::ffff:168.63.129.16', 'fe80::a9fe:a9fe%eth0']) {
    const result = classifyAddress(address);
    assert.equal(result.cloudMetadata, true, address); assert.equal(result.blocked, true, address);
  }
  assert.equal(classifyAddress('169.254.169.253').cloudMetadata, undefined, 'neighbors are link-local, not metadata');
  assert.equal(classifyAddress('100.100.100.200').category, 'shared_address_space');
});

// ---------- Resolution decision ----------

test('DNS guard: a name is denied when any resolved address is not public, not only the first', async () => {
  const resolve = async (addresses, url = 'https://public-site.example/') => resolveNavigationTarget({ url, policy: publicPolicy, resolver: { name: 'fixed', lookup: async () => addresses } });
  const allowed = await resolve([{ address: '8.8.8.8', family: 4 }, { address: '2606:4700::1', family: 6 }]);
  assert.equal(allowed.allowed, true); assert.deepEqual(allowed.resolution.addresses.map(item => item.category), ['public', 'public']);
  const mixed = await resolve([{ address: '8.8.8.8', family: 4 }, { address: '2606:4700::1', family: 6 }, { address: '10.0.0.7', family: 4 }]);
  assert.deepEqual({ allowed: mixed.allowed, reason: mixed.reason, overridable: mixed.overridable }, { allowed: false, reason: 'private_network_target', overridable: false });
  assert.deepEqual(mixed.resolution.addresses.map(item => item.blocked), [false, false, true]);
  assert.equal(mixed.resolution.host, 'public-site.example'); assert.equal(mixed.resolution.resolver, 'fixed');
  const metadata = await resolve(['8.8.8.8', '169.254.169.254']);
  assert.equal(metadata.reason, 'private_network_target'); assert.equal(metadata.resolution.cloudMetadata, true, 'string answers are accepted');
  const mapped = await resolve([{ address: '::ffff:127.0.0.1', family: 6 }]);
  assert.equal(mapped.reason, 'private_network_target'); assert.equal(mapped.resolution.addresses[0].embeddedIpv4, '127.0.0.1');
  assert.equal((await resolve(['not-an-ip'])).reason, 'private_network_target', 'an unparseable answer is never treated as public');
});

test('DNS guard: lookup failure, timeout and empty answers degrade with a structured error instead of blocking', async () => {
  const outcome = (lookup, policy = publicPolicy) => resolveNavigationTarget({ url: 'https://public-site.example/a', policy, resolver: { name: 'fixed', lookup } });
  for (const code of ['ENOTFOUND', 'EAI_AGAIN', 'ETIMEOUT', 'ESERVFAIL']) {
    const result = await outcome(async () => { throw dnsError(code); });
    assert.deepEqual(result, { allowed: true, degraded: true, resolution: { host: 'public-site.example', resolver: 'fixed', addresses: [], error: code } }, code);
  }
  assert.equal((await outcome(() => { throw new Error('synchronous failure'); })).resolution.error, 'LOOKUP_FAILED', 'a synchronous throw without a code');
  assert.equal((await outcome(async () => [])).resolution.error, 'NO_ADDRESSES');
  assert.equal((await outcome(async () => null)).resolution.error, 'NO_ADDRESSES');
  assert.equal((await outcome(async () => { throw dnsError('ENOTFOUND'); }, privatePolicy)).degraded, true, 'a private session degrades the same way');
  assert.ok(!FLOOR_REASONS.includes('target_resolution_failed'), 'a failed lookup is no longer a blocking reason');
  // A lookup that never answers is cut off at the bound, and its timer does not keep the process alive.
  const started = performance.now();
  const hung = await resolveNavigationTarget({ url: 'https://public-site.example/a', policy: publicPolicy, resolver: { name: 'hung', lookup: () => new Promise(() => {}) }, timeoutMs: 50 });
  assert.deepEqual(hung, { allowed: true, degraded: true, resolution: { host: 'public-site.example', resolver: 'hung', addresses: [], error: 'LOOKUP_TIMEOUT' } });
  assert.ok(performance.now() - started < 1000, 'bounded by timeoutMs');
  assert.ok(DNS_LOOKUP_TIMEOUT_MS >= 1000 && DNS_LOOKUP_TIMEOUT_MS <= 3000, 'the default bound is between 1 and 3 seconds');
  // A late answer after the bound is ignored rather than changing the decision.
  let release;
  const late = resolveNavigationTarget({ url: 'https://public-site.example/a', policy: publicPolicy, resolver: { name: 'late', lookup: () => new Promise(resolve => { release = resolve; }) }, timeoutMs: 20 });
  assert.equal((await late).resolution.error, 'LOOKUP_TIMEOUT'); release(['10.0.0.1']);
});

test('DNS guard: literals, localhost names and non-http URLs are not resolved; a private session resolves names only for the metadata floor', async () => {
  for (const url of ['http://10.0.0.1/', 'http://8.8.8.8/', 'http://[::1]/', 'http://[2606:4700::1]/', 'http://localhost/', 'http://app.localhost/', 'http://localhost./', 'ftp://public-site.example/', 'not a url']) {
    assert.equal(resolutionHost(url, publicPolicy), null, url);
  }
  assert.equal(resolutionHost('https://www.public-site.example/', publicPolicy), 'www.public-site.example');
  assert.equal(resolutionHost('https://public-site.example/', privatePolicy), 'public-site.example', 'a private session also resolves DNS names');
  let calls = 0;
  const answering = addresses => ({ name: 'count', lookup: async () => { calls++; return addresses; } });
  assert.deepEqual(await resolveNavigationTarget({ url: 'http://8.8.8.8/', policy: publicPolicy, resolver: answering(['10.0.0.1']) }), { allowed: true });
  assert.equal(calls, 0, 'literals are never resolved');
  const privateToPrivate = await resolveNavigationTarget({ url: 'http://internal.example/', policy: privatePolicy, resolver: answering(['10.0.0.1']) });
  assert.equal(privateToPrivate.allowed, true, 'private to private is allowed'); assert.equal(privateToPrivate.resolution.addresses[0].category, 'private');
  const privateToMetadata = await resolveNavigationTarget({ url: 'http://internal.example/', policy: privatePolicy, resolver: answering(['10.0.0.1', '169.254.169.254']) });
  assert.deepEqual([privateToMetadata.allowed, privateToMetadata.reason, privateToMetadata.overridable, privateToMetadata.resolution.cloudMetadata], [false, 'private_network_target', false, true], 'metadata is blocked in a private session');
  assert.equal(calls, 2);
  // isPrivateHost and the synchronous decision see only literals and localhost names; metadata literals are a floor in every session.
  assert.equal(isPrivateHost('internal.example'), false);
  const origins = new Set(['https://public-site.example', 'https://internal.example', 'http://169.254.169.254', 'http://10.0.0.1']);
  assert.deepEqual(decideNavigation({ url: 'https://internal.example/', policy: { ...publicPolicy, allowedOrigins: ['https://internal.example'] }, sessionOrigins: origins }), { allowed: true });
  assert.equal(decideNavigation({ url: 'http://169.254.169.254/', policy: publicPolicy, sessionOrigins: origins }).reason, 'private_network_target');
  assert.deepEqual(decideNavigation({ url: 'http://169.254.169.254/', policy: privatePolicy, sessionOrigins: origins }), { allowed: false, reason: 'private_network_target', overridable: false }, 'declared metadata literal in a private session');
  assert.deepEqual(decideNavigation({ url: 'http://10.0.0.1/', policy: privatePolicy, sessionOrigins: origins }), { allowed: true }, 'declared private literal in a private session');
  assert.equal(systemHostResolver.name, 'system'); assert.equal(typeof systemHostResolver.lookup, 'function');
  assert.equal(new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: 'https://public-site.example/' })).hostResolver, systemHostResolver, 'the default resolver');
});

test('DNS guard: the resolution record is bounded in block details and in agent/MCP payloads', () => {
  const addresses = Array.from({ length: 40 }, (_, index) => ({ ...classifyAddress(`10.0.0.${index + 1}`), extra: 'dropped' }));
  const details = navigationBlockDetails({ reason: 'private_network_target', overridable: false, fromUrl: null, blockedUrl: 'https://public-site.example/',
    chain: [{ url: 'https://public-site.example/', status: null, blocked: true }], policy: publicPolicy, sessionOrigins: new Set([publicPolicy.manifestOrigin]), stage: 'navigate',
    resolution: { host: `${'a'.repeat(300)}.example`, resolver: 'r', addresses, cloudMetadata: true, error: 'E'.repeat(100), ignored: 'x' } });
  assert.equal(details.resolution.addresses.length, 16); assert.equal(details.resolution.addressesOmitted, 24);
  assert.equal(details.resolution.host.length, 255); assert.equal(details.resolution.error.length, 64);
  assert.deepEqual(Object.keys(details.resolution.addresses[0]), ['address', 'family', 'category', 'blocked']);
  assert.equal(details.resolution.ignored, undefined); assert.equal(details.suggestedAction.kind, 'stop');
  assert.deepEqual(boundNavigationDetails(details).resolution, details.resolution, 'bounding twice keeps the omission count');
  const raw = boundNavigationDetails({ ...details, resolution: { host: 'h', resolver: 'r', addresses: [...addresses, ...addresses] } });
  assert.equal(raw.resolution.addresses.length, 16); assert.equal(raw.resolution.addressesOmitted, 64);
  assert.equal(boundNavigationDetails({ ...details, resolution: undefined }).resolution, undefined, 'blocks without a lookup carry no resolution');
  const payload = errorPayload({ code: 'AUDIT_SESSION_START_FAILED', message: 'blocked', details: { reportPath: '/x' }, navigation: details });
  assert.deepEqual(Object.keys(payload), ['code', 'message', 'navigation'], 'the 0.1.1 payload shape; navigation stays additive');
  assert.deepEqual(payload.navigation.resolution, details.resolution);
});

// ---------- Browser integration (loopback fixture, injected resolver) ----------

test('DNS guard start: a public start URL whose name resolves to a cloud metadata address is never contacted', async t => {
  // Renamed from "...resolves to a private address...": since B1 a start name that resolves to any other non-public
  // address opens a private session instead (see the B1 tests below); a cloud metadata answer is still refused.
  const fixture = await site(t);
  const { resolver, calls } = tableResolver({ 'public-site.example': ['8.8.8.8', '169.254.169.254'] });
  const { browser, error } = await startBlocked({ projectRoot: '/tmp', url: `${fixture.origin('public-site.example')}/` }, { hostResolver: resolver });
  assert.equal(fixture.hits.length, 0, 'the request was failed before it was sent');
  assert.deepEqual(calls, ['public-site.example']);
  assert.equal(errorRecord(error).code, 'RUNTIME_ERROR', '0.1.1 code for a blocked start');
  assert.equal(error.navigation.reason, 'private_network_target'); assert.equal(error.navigation.overridable, false);
  assert.equal(error.navigation.suggestedAction.kind, 'stop'); assert.equal(error.navigation.stage, 'audit-browser-start');
  assert.doesNotMatch(error.navigation.suggestedAction.note, /redirect/, 'the note does not describe a redirect that did not happen');
  assert.deepEqual(error.navigation.resolution, { host: 'public-site.example', resolver: 'test-table', addresses: [
    { address: '8.8.8.8', family: 4, category: 'public', blocked: false }, { address: '169.254.169.254', family: 4, category: 'link_local', cloudMetadata: true, blocked: true }], cloudMetadata: true });
  assert.deepEqual(browser.blocked, [{ reason: 'navigation_outside_origin', url: `${fixture.origin('public-site.example')}/` }], '0.1.1 event shape');
});

test('DNS guard start: a lookup failure degrades the start instead of blocking it; a public answer opens it', async t => {
  const fixture = await site(t);
  for (const failure of [dnsError('ENOTFOUND'), dnsError('ETIMEOUT')]) {
    const { resolver } = tableResolver({ 'nxdomain.example': failure });
    const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${fixture.origin('nxdomain.example')}/` }), { launchArgs, hostResolver: resolver });
    t.after(() => browser.close());
    await browser.start();
    const { dnsCheck } = browser.navigationReport();
    assert.equal(dnsCheck.status, 'degraded'); assert.deepEqual(dnsCheck.session, { type: 'public', basis: 'literal_fallback',
      resolution: { host: 'nxdomain.example', resolver: 'test-table', addresses: [], error: failure.code } });
    assert.deepEqual(dnsCheck.failures, [{ stage: 'audit-browser-start', host: 'nxdomain.example', error: failure.code }]);
    assert.equal(browser.navigationPolicy.publicSession, true, 'the literal classification stands');
    await browser.close();
  }
  assert.equal(fixture.count('nxdomain.example'), 2, 'each degraded start was sent');
  const { resolver, calls } = tableResolver({ 'public-site.example': ['8.8.8.8', '2606:4700::1'] });
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${fixture.origin('public-site.example')}/` }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  assert.equal(fixture.count('public-site.example'), 1); assert.deepEqual(calls, ['public-site.example']);
  assert.equal(browser.navigationReport().finalUrl, `${fixture.origin('public-site.example')}/`);
  assert.deepEqual([browser.navigationReport().dnsCheck.status, browser.navigationReport().dnsCheck.session.type, browser.navigationReport().dnsCheck.session.basis], ['checked', 'public', 'resolution']);
});

test('DNS guard redirects: every hop is resolved, and a hop into a private address is blocked before it is sent', async t => {
  const fixture = await site(t, (host, url, port) => {
    if (url === '/a') return { location: '/b' };
    if (url === '/away') return { location: `http://rebind.example:${port}/` };
    return {};
  });
  const pub = fixture.origin('public-site.example'), rebind = fixture.origin('rebind.example');
  const { resolver, calls } = tableResolver({ 'public-site.example': ['8.8.8.8'], 'rebind.example': ['::ffff:127.0.0.1'] });
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${pub}/a` }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  assert.deepEqual(calls, ['public-site.example', 'public-site.example'], 'the start and its same-origin redirect hop were each resolved');
  assert.deepEqual(browser.navigationReport().redirectChain, [{ url: `${pub}/a`, status: 302 }, { url: `${pub}/b`, status: 200 }]);
  await browser.close();
  const { error } = await startBlocked({ projectRoot: '/tmp', url: `${pub}/away`, followRedirects: true, allowedOrigins: [rebind] }, { hostResolver: resolver });
  assert.equal(error.navigation.reason, 'private_network_target'); assert.equal(error.navigation.overridable, false);
  assert.deepEqual(error.navigation.redirectChain, [{ url: `${pub}/away`, status: 302 }, { url: `${rebind}/`, status: null, blocked: true }]);
  assert.equal(error.navigation.resolution.host, 'rebind.example'); assert.equal(error.navigation.resolution.addresses[0].embeddedIpv4, '127.0.0.1');
  assert.equal(fixture.count('rebind.example'), 0, 'the declared origin was never contacted');
});

test('DNS guard mid-session: navigate, a redirecting navigate and a click keep their 0.1.1 codes and add the resolution', async t => {
  const fixture = await site(t, (host, url, port) => {
    if (url === '/hop') return { location: `http://internal.example:${port}/` };
    if (host === 'public-site.example') return { body: page('public').replace('</main>', `<a id="meta" href="http://meta.example:${port}/">Meta</a><a id="internal" href="http://internal.example:${port}/">Internal</a></main>`) };
    return {};
  });
  const pub = fixture.origin('public-site.example'), internal = fixture.origin('internal.example'), meta = fixture.origin('meta.example');
  const { resolver, calls } = tableResolver({ 'public-site.example': ['8.8.8.8'], 'internal.example': ['2606:4700::1', 'fd00::5'], 'meta.example': ['169.254.169.254'] });
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${pub}/`, followRedirects: true, allowedOrigins: [internal, meta] }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();

  const navigated = await browser.execute({ action: 'navigate', path: `${meta}/` });
  assert.equal(navigated.success, false); assert.equal(navigated.error.code, 'UNSAFE_AUDIT_NAVIGATION', 'the run-time check code');
  assert.equal(navigated.error.navigation.reason, 'private_network_target'); assert.equal(navigated.error.navigation.stage, 'navigate');
  assert.equal(navigated.error.navigation.resolution.cloudMetadata, true);
  assert.deepEqual(navigated.error.navigation.resolution.addresses, [{ address: '169.254.169.254', family: 4, category: 'link_local', cloudMetadata: true, blocked: true }]);

  const redirected = await browser.execute({ action: 'navigate', path: '/hop' });
  assert.equal(redirected.error.code, 'RUNTIME_ERROR'); assert.equal(redirected.error.navigation.reason, 'private_network_target');
  assert.equal(redirected.error.navigation.resolution.host, 'internal.example');
  assert.deepEqual(redirected.error.navigation.resolution.addresses.map(item => item.category), ['public', 'unique_local']);

  await browser.execute({ action: 'reset' });
  const clicked = await browser.execute({ action: 'click', selector: '#internal' });
  assert.equal(clicked.error.code, 'AUDIT_BROWSER_ACTION_BLOCKED');
  assert.deepEqual(clicked.error.details, [{ reason: 'navigation_outside_origin', url: `${internal}/` }], '0.1.1 details');
  assert.equal(clicked.error.navigation.reason, 'private_network_target'); assert.equal(clicked.error.navigation.suggestedAction.kind, 'stop');
  assert.equal(clicked.error.navigation.resolution.host, 'internal.example');

  assert.equal(fixture.count('internal.example') + fixture.count('meta.example'), 0, 'no private-resolving name was contacted');
  assert.ok(calls.includes('meta.example') && calls.includes('internal.example'));
});

test('DNS guard: a loopback session never consults the resolver, even for mapped names', async t => {
  const fixture = await site(t, () => ({ body: page('local').replace('</main>', '<a id="next" href="/next">Next</a></main>') }));
  const { resolver, calls } = tableResolver({});
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${fixture.origin('127.0.0.1')}/` }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  assert.equal((await browser.execute({ action: 'navigate', path: '/other' })).success, true);
  assert.equal((await browser.execute({ action: 'click', selector: '#next' })).error?.code, undefined);
  assert.deepEqual(calls, []);
});

test('DNS guard: a script navigation during an action is checked, and a slow answer still blocks it', async t => {
  // A scroll listener navigates. The answer arrives several macrotasks later; the request stays paused until then.
  const fixture = await site(t, (host, url, port) => host === 'public-site.example'
    ? { body: page('public').replace('</main>', `<div style="height:4000px"></div><script>addEventListener('scroll', () => { location.href = 'http://internal.example:${port}/'; }, { once: true });</script></main>`) } : {});
  const pub = fixture.origin('public-site.example'), internal = fixture.origin('internal.example');
  const calls = [];
  const resolver = { name: 'slow', lookup: async host => {
    calls.push(host);
    if (host !== 'internal.example') return [{ address: '8.8.8.8', family: 4 }];
    for (let turn = 0; turn < 20; turn++) await new Promise(resolve => setImmediate(resolve));
    return [{ address: '2606:4700::1', family: 6 }, { address: '192.168.4.4', family: 4 }];
  } };
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${pub}/`, allowedOrigins: [internal] }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  const scrolled = await browser.execute({ action: 'scroll', x: 0, y: 2000 });
  assert.deepEqual(calls, ['public-site.example', 'internal.example']);
  // As with a literal or cross-origin block in this path, the action fails and the session keeps the 0.1.1 event.
  assert.equal(scrolled.success, false, JSON.stringify(scrolled.result));
  const event = browser.blocked.at(-1), details = browser.blockedNavigation.get(event);
  assert.deepEqual(event, { reason: 'navigation_outside_origin', url: `${internal}/` });
  assert.equal(details.reason, 'private_network_target'); assert.equal(details.stage, 'scroll'); assert.equal(details.overridable, false);
  assert.deepEqual(details.resolution.addresses.map(item => item.blocked), [false, true]);
  assert.equal(fixture.count('internal.example'), 0);
});

// ---------- Shared classification for IP literals and DNS answers ----------

test('DNS guard: IP literals and DNS answers share one classification, including embedded IPv4 forms', async () => {
  // [address, not public, cloud metadata, category]
  const table = [
    ['8.8.8.8', false, false, 'public'], ['2606:4700::1', false, false, 'public'],
    ['198.18.0.1', false, false, 'public'], ['198.19.255.254', false, false, 'public'],
    ['64:ff9b::a9fe:a9fe', true, true, 'link_local'], ['64:ff9b::10.0.0.1', true, false, 'private'], ['64:ff9b::', true, false, 'unspecified'],
    ['64:ff9b::808:808', false, false, 'public'], ['64:ff9b:1::a00:1', true, false, 'private'],
    ['fec0::1', true, false, 'site_local'], ['224.0.0.1', true, false, 'multicast'], ['239.255.255.250', true, false, 'multicast'], ['ff02::1', true, false, 'multicast'],
    ['255.255.255.255', true, false, 'reserved'],
    ['2002:7f00:1::1', true, false, 'loopback'], ['2002:a9fe:a9fe::1', true, true, 'link_local'], ['2002:808:808::1', false, false, 'public'],
    ['2001:0:4136:e378::f7f7:f7f7', false, false, 'public'], ['2001:0:4136:e378::80ff:fffe', true, false, 'loopback'], ['2001:0:a9fe:a9fe::f7f7:f7f7', true, true, 'link_local'],
    ['::ffff:127.0.0.1', true, false, 'loopback'], ['::ffff:0:7f00:1', true, false, 'loopback'], ['::ffff:169.254.169.254', true, true, 'link_local'],
    ['fd00:ec2::254', true, true, 'unique_local'], ['169.254.170.2', true, true, 'link_local'], ['100.100.100.200', true, true, 'shared_address_space'],
    ['10.0.0.1', true, false, 'private'], ['127.0.0.1', true, false, 'loopback'],
  ];
  for (const [address, nonPublic, metadata, category] of table) {
    const literal = address.includes(':') ? `[${address}]` : address, url = `http://${literal}/`;
    const classified = classifyAddress(address);
    assert.deepEqual([classified.category, classified.blocked, classified.cloudMetadata === true], [category, nonPublic, metadata], address);
    assert.equal(isPrivateHost(literal), nonPublic, `literal ${address}`); assert.equal(isCloudMetadataHost(literal), metadata, `literal ${address}`);
    // Declared origins do not change the floor: a non-public literal is never a cross-origin (overridable) block.
    const origins = new Set([publicPolicy.manifestOrigin, new URL(url).origin]);
    assert.deepEqual(decideNavigation({ url, policy: publicPolicy, sessionOrigins: origins }), nonPublic ? { allowed: false, reason: 'private_network_target', overridable: false } : { allowed: true }, `public session literal ${address}`);
    assert.deepEqual(decideNavigation({ url, policy: privatePolicy, sessionOrigins: origins }), metadata ? { allowed: false, reason: 'private_network_target', overridable: false } : { allowed: true }, `private session literal ${address}`);
    const answer = { name: 'fixed', lookup: async () => [address] };
    const viaPublic = await resolveNavigationTarget({ url: 'https://public-site.example/', policy: publicPolicy, resolver: answer });
    const viaPrivate = await resolveNavigationTarget({ url: 'https://public-site.example/', policy: privatePolicy, resolver: answer });
    assert.equal(viaPublic.allowed, !nonPublic, `public session answer ${address}`); assert.equal(viaPrivate.allowed, !metadata, `private session answer ${address}`);
    if (!viaPublic.allowed) assert.deepEqual([viaPublic.reason, viaPublic.overridable], ['private_network_target', false]);
  }
});

// ---------- B1: the start URL's own answer decides the session type ----------

test('DNS guard B1: startSession turns a non-public start answer into a private session and keeps refusing metadata', () => {
  const resolution = addresses => ({ host: 'staging.example', resolver: 'r', addresses: addresses.map(classifyAddress) });
  const privateAnswer = startSession({ allowed: false, reason: 'private_network_target', overridable: false, resolution: resolution(['10.20.0.5']) }, publicPolicy);
  assert.deepEqual(privateAnswer.decision, { allowed: true, resolution: resolution(['10.20.0.5']) });
  assert.deepEqual([privateAnswer.session.type, privateAnswer.session.basis], ['private', 'resolution']);
  const publicAnswer = startSession({ allowed: true, resolution: resolution(['8.8.8.8']) }, publicPolicy);
  assert.deepEqual([publicAnswer.decision.allowed, publicAnswer.session.type, publicAnswer.session.basis], [true, 'public', 'resolution']);
  const metadata = { allowed: false, reason: 'private_network_target', overridable: false, resolution: { ...resolution(['10.0.0.1', '169.254.169.254']), cloudMetadata: true } };
  assert.equal(startSession(metadata, publicPolicy).decision, metadata, 'a metadata answer stays refused');
  const failed = { allowed: true, degraded: true, resolution: { host: 'staging.example', resolver: 'r', addresses: [], error: 'ENOTFOUND' } };
  assert.deepEqual(startSession(failed, publicPolicy).session, { type: 'public', basis: 'literal_fallback', resolution: failed.resolution });
  assert.deepEqual(startSession({ allowed: true }, privatePolicy).session, { type: 'private', basis: 'literal' });
});

test('DNS guard B1: a start name resolving to a private address opens a private session; private targets are allowed and metadata stays blocked', async t => {
  const fixture = await site(t, (host, url, port) => host === 'staging.example' && url === '/'
    ? { body: page('staging').replace('</main>', `<a id="meta" href="http://meta.example:${port}/">Meta</a></main>`) } : {});
  const staging = fixture.origin('staging.example'), internal = fixture.origin('internal.example'), meta = fixture.origin('meta.example'), loopback = fixture.origin('127.0.0.1');
  const { resolver, calls } = tableResolver({ 'staging.example': ['10.20.0.5'], 'internal.example': ['192.168.1.9'], 'meta.example': ['10.0.0.9', '169.254.169.254'] });
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${staging}/`, allowedOrigins: [internal, loopback, meta, 'http://169.254.169.254'] }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  assert.equal(fixture.count('staging.example'), 1, 'the start was not refused');
  const { dnsCheck } = browser.navigationReport();
  assert.deepEqual(dnsCheck.session, { type: 'private', basis: 'resolution', resolution: { host: 'staging.example', resolver: 'test-table',
    addresses: [{ address: '10.20.0.5', family: 4, category: 'private', blocked: true }] } });
  assert.equal(browser.navigationPolicy.publicSession, false);

  assert.equal((await browser.execute({ action: 'navigate', path: `${internal}/` })).success, true, 'private name to private name');
  assert.equal((await browser.execute({ action: 'navigate', path: `${loopback}/` })).success, true, 'private name to a private literal');
  assert.equal(fixture.count('internal.example'), 1);

  const metaName = await browser.execute({ action: 'navigate', path: `${meta}/` });
  assert.equal(metaName.error.code, 'UNSAFE_AUDIT_NAVIGATION'); assert.equal(metaName.error.navigation.reason, 'private_network_target');
  assert.equal(metaName.error.navigation.overridable, false); assert.equal(metaName.error.navigation.resolution.cloudMetadata, true);
  const metaLiteral = await browser.execute({ action: 'navigate', path: 'http://169.254.169.254/' });
  assert.equal(metaLiteral.error.code, 'UNSAFE_AUDIT_NAVIGATION'); assert.equal(metaLiteral.error.navigation.reason, 'private_network_target');
  assert.equal(metaLiteral.error.navigation.resolution, undefined, 'a literal needs no lookup');

  await browser.execute({ action: 'navigate', path: `${staging}/` });
  const clicked = await browser.execute({ action: 'click', selector: '#meta' });
  assert.equal(clicked.error.code, 'AUDIT_BROWSER_ACTION_BLOCKED'); assert.equal(clicked.error.navigation.reason, 'private_network_target');
  assert.equal(fixture.count('meta.example'), 0, 'the metadata-resolving name was never contacted');
  assert.equal(browser.navigationReport().dnsCheck.status, 'checked');
  assert.ok(calls.filter(host => host === 'meta.example').length >= 2);
});

test('DNS guard B1: a public start keeps the public-to-private floor for names and literals', async t => {
  const fixture = await site(t);
  const pub = fixture.origin('public-site.example'), staging = fixture.origin('staging.example'), loopback = fixture.origin('127.0.0.1');
  const { resolver } = tableResolver({ 'public-site.example': ['8.8.8.8'], 'staging.example': ['10.20.0.5'] });
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${pub}/`, allowedOrigins: [staging, loopback] }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  assert.deepEqual([browser.navigationReport().dnsCheck.session.type, browser.navigationReport().dnsCheck.session.basis], ['public', 'resolution']);
  for (const target of [staging, loopback]) {
    const navigated = await browser.execute({ action: 'navigate', path: `${target}/` });
    assert.equal(navigated.error.code, 'UNSAFE_AUDIT_NAVIGATION', target); assert.equal(navigated.error.navigation.reason, 'private_network_target', target);
  }
  assert.equal(fixture.count('staging.example') + fixture.count('127.0.0.1'), 0);
});

// ---------- M1: a failed or slow lookup degrades instead of blocking, within a bound ----------

test('DNS guard M1: a lookup that never answers degrades start, navigate and click within a bounded time', async t => {
  const fixture = await site(t, (host, url, port) => host === 'slow.example'
    ? { body: page(`slow${url}`).replace('</main>', `<a id="next" href="http://slow.example:${port}/next">Next</a></main>`) } : {});
  const slow = fixture.origin('slow.example'), loopback = fixture.origin('127.0.0.1');
  const calls = [];
  const resolver = { name: 'hung', lookup: host => { calls.push({ host, at: performance.now() }); return new Promise(() => {}); } };
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${slow}/`, allowedOrigins: [loopback] }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  const bound = DNS_LOOKUP_TIMEOUT_MS + 3000;
  assert.ok(performance.now() - calls[0].at < bound, 'the start continued after the lookup bound');
  assert.equal(fixture.count('slow.example'), 1);

  let started = performance.now();
  const navigated = await browser.execute({ action: 'navigate', path: '/other' }, 4000);
  assert.equal(navigated.success, true, JSON.stringify(navigated.error)); assert.ok(performance.now() - started < bound, 'navigate is bounded');
  assert.equal(calls.length, 1, 'the host already failed at the start, so navigate does not look it up again');
  started = performance.now();
  const clicked = await browser.execute({ action: 'click', selector: '#next' }, 4000);
  assert.equal(clicked.success, true, JSON.stringify(clicked.error)); assert.ok(performance.now() - started < bound, 'click is bounded');
  assert.equal(fixture.count('slow.example'), 3);

  // The session stays public by its literal, so the public-to-private floor still applies to a declared private literal.
  const floor = await browser.execute({ action: 'navigate', path: `${loopback}/` });
  assert.equal(floor.error.navigation.reason, 'private_network_target');
  const { dnsCheck } = browser.navigationReport();
  // One lookup timed out; the navigate check and the click hop reused that failure instead of waiting again.
  assert.equal(dnsCheck.status, 'degraded'); assert.equal(dnsCheck.failedLookups, 1); assert.equal(dnsCheck.lookups, 1); assert.equal(dnsCheck.skippedLookups, 2);
  assert.deepEqual(dnsCheck.failures.map(item => [item.stage, item.error]), [['audit-browser-start', 'LOOKUP_TIMEOUT']]);
  assert.deepEqual([dnsCheck.session.type, dnsCheck.session.basis, dnsCheck.session.resolution.error], ['public', 'literal_fallback', 'LOOKUP_TIMEOUT']);
  assert.match(dnsCheck.note, /may not have been detected/);
});

async function workspace(t) {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-dns-guard-')));
  await fs.mkdir(path.join(directory, 'evidence'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}
const failingResolver = { name: 'test-offline', lookup: async () => { throw dnsError('ENOTFOUND'); } };
const injectedBrowser = (hostResolver = failingResolver) => manifest => new AuditBrowser(manifest, { handleSignals: false, launchArgs, hostResolver });

test('DNS guard M1 JSONL and HTML: a degraded check is on the session line, each record line, the sealed report and the HTML limits', async t => {
  const fixture = await site(t), projectRoot = await workspace(t);
  const input = new PassThrough(), output = new PassThrough(), lines = [];
  output.on('data', chunk => lines.push(...String(chunk).split('\n').filter(Boolean).map(line => JSON.parse(line))));
  input.end('{"action":"snapshot"}\n{"command":"finish"}\n');
  const report = await runAuditSessionCli({ manifest: { projectRoot, url: `${fixture.origin('nxdomain.example')}/`, wallSeconds: 60 }, input, output, signals: false,
    lifecycle: { createBrowser: injectedBrowser() } });
  const [session, record, finished] = lines;
  assert.equal(session.type, 'session'); assert.equal(session.dnsCheck.status, 'degraded');
  assert.deepEqual(session.dnsCheck.session.resolution, { host: 'nxdomain.example', resolver: 'test-offline', addresses: [], error: 'ENOTFOUND' });
  assert.match(session.dnsCheck.note, /may not have been detected/);
  assert.equal(record.type, 'record'); assert.equal(record.record.success, true); assert.equal(record.dnsCheck.status, 'degraded');
  assert.equal(finished.type, 'finished'); assert.equal(finished.report.navigation.dnsCheck.status, 'degraded');
  assert.deepEqual(report.navigation.dnsCheck.failures, [{ stage: 'audit-browser-start', host: 'nxdomain.example', error: 'ENOTFOUND' }]);
  const proposal = await submitAudit(report.reportPath, { auditor: { name: 'Agent' }, findings: [] });
  assert.deepEqual(proposal.navigation.dnsCheck, report.navigation.dnsCheck);
  const out = path.join(projectRoot, 'evidence', 'report.html');
  await writeAuditReport(proposal.reportPath, out);
  const html = await fs.readFile(out, 'utf8'), scope = html.slice(html.indexOf('id="scope"'));
  assert.match(scope, /DNS check degraded: 1 of 1 main-document DNS lookup failed or timed out\. Those navigations were checked against IP literals and localhost names only/);
});

test('DNS guard HTML: the limits list names a degraded check and a private session decided by DNS, and nothing otherwise', () => {
  const base = { kind: 'audit-proposal', runId: 'r', findings: [], coverage: [], standard: { version: '2.2', targetLevel: 'AA' }, auditor: { name: 'A' }, manifest: { url: 'http://staging.example/' } };
  const render = dnsCheck => { const html = renderAuditReportHtml({ ...base, navigation: { finalUrl: 'http://staging.example/', redirects: 0, dnsCheck } }); return html.slice(html.indexOf('id="scope"')); };
  const checked = render({ status: 'checked', session: { type: 'public', basis: 'resolution' }, lookups: 2, failedLookups: 0 });
  assert.doesNotMatch(checked, /DNS check degraded|treated as private/);
  assert.match(render({ status: 'degraded', session: { type: 'public', basis: 'literal_fallback' }, lookups: 3, failedLookups: 2 }), /DNS check degraded: 2 of 3 main-document DNS lookups failed or timed out/);
  assert.match(render({ status: 'checked', session: { type: 'private', basis: 'resolution' }, lookups: 1, failedLookups: 0 }), /resolved to a non-public address, so the session was treated as private/);
  assert.doesNotMatch(renderAuditReportHtml(base), /DNS check/, 'old reports are unchanged');
});

test('DNS guard M1 MCP: a degraded check is in the start response and in later responses', async t => {
  const fixture = await site(t), projectRoot = await workspace(t);
  const handlers = new Map(), server = { registerTool: (name, _spec, handler) => handlers.set(name, handler), close: async () => {}, server: {} };
  registerAuditTools(server, { openAgent: (input, options) => openAuditAgent(input, { ...options, liveOptions: { createBrowser: injectedBrowser() } }) });
  const started = (await handlers.get('a11y_audit_start')({ manifest: { projectRoot, url: `${fixture.origin('nxdomain.example')}/`, startupAxe: false, wallSeconds: 60 } })).structuredContent;
  t.after(() => handlers.get('a11y_audit_close')({ runId: started.runId }));
  assert.equal(started.success, true, JSON.stringify(started.error));
  assert.equal(started.dnsCheck.status, 'degraded'); assert.equal(started.dnsCheck.session.resolution.error, 'ENOTFOUND');
  const stepped = (await handlers.get('a11y_audit_request')({ runId: started.runId, request: { tool: 'step', actions: [{ action: 'snapshot' }] } })).structuredContent;
  assert.equal(stepped.success, true); assert.equal(stepped.dnsCheck.status, 'degraded'); assert.match(stepped.dnsCheck.note, /may not have been detected/);
});

// ---------- MJ-1: slow DNS is paid at most once per host and once per navigation ----------

test('DNS guard MJ-1: a failed host is remembered for the session, and a used-up DNS wait skips the lookup', async () => {
  const failedHosts = new Map();
  let calls = 0;
  const hung = { name: 'hung', lookup: () => { calls++; return new Promise(() => {}); } };
  const first = await resolveNavigationTarget({ url: 'https://slow.example/a', policy: publicPolicy, resolver: hung, timeoutMs: 30, failedHosts });
  assert.deepEqual(first, { allowed: true, degraded: true, resolution: { host: 'slow.example', resolver: 'hung', addresses: [], error: 'LOOKUP_TIMEOUT' } });
  assert.deepEqual([...failedHosts], [['slow.example', 'LOOKUP_TIMEOUT']]);
  const started = performance.now();
  const again = await resolveNavigationTarget({ url: 'https://slow.example/b', policy: publicPolicy, resolver: hung, failedHosts });
  assert.ok(performance.now() - started < 50, 'no second wait');
  assert.deepEqual(again, { allowed: true, degraded: true, skipped: 'host_failed_before', resolution: { host: 'slow.example', resolver: 'hung', addresses: [], error: 'LOOKUP_TIMEOUT' } });
  assert.equal(calls, 1, 'the resolver is not called again for that host');
  // A fast failure is remembered the same way; a success is not.
  const answering = { name: 'table', lookup: async host => { calls++; if (host === 'nxdomain.example') throw dnsError('ENOTFOUND'); return ['8.8.8.8']; } };
  await resolveNavigationTarget({ url: 'https://nxdomain.example/', policy: publicPolicy, resolver: answering, failedHosts });
  await resolveNavigationTarget({ url: 'https://public-site.example/', policy: publicPolicy, resolver: answering, failedHosts });
  assert.equal(failedHosts.get('nxdomain.example'), 'ENOTFOUND'); assert.equal(failedHosts.has('public-site.example'), false);
  // A navigation that has used its DNS wait does not look up again, and that untried host is not remembered.
  const exhausted = await resolveNavigationTarget({ url: 'https://hop2.example/', policy: publicPolicy, resolver: answering, timeoutMs: 0, failedHosts });
  assert.deepEqual(exhausted, { allowed: true, degraded: true, skipped: 'budget_exhausted', resolution: { host: 'hop2.example', resolver: 'table', addresses: [], error: 'LOOKUP_BUDGET_EXHAUSTED' } });
  assert.equal(failedHosts.has('hop2.example'), false); assert.equal(calls, 3);
  // The remembered set is bounded; the oldest host is dropped first.
  const failing = { name: 'f', lookup: async () => { throw dnsError('ENOTFOUND'); } };
  for (let index = 0; index < DNS_FAILED_HOST_LIMIT + 5; index++) await resolveNavigationTarget({ url: `https://h${index}.example/`, policy: publicPolicy, resolver: failing, failedHosts });
  assert.equal(failedHosts.size, DNS_FAILED_HOST_LIMIT); assert.equal(failedHosts.has('slow.example'), false); assert.equal(failedHosts.has(`h${DNS_FAILED_HOST_LIMIT + 4}.example`), true);
  assert.equal(DNS_NAVIGATION_WAIT_MS <= DNS_LOOKUP_TIMEOUT_MS, true, 'one navigation never waits longer than one lookup bound');
});

/** A resolver that never answers, recording each host it was asked for. */
function hungResolver() {
  const calls = [];
  return { calls, resolver: { name: 'hung', lookup: host => { calls.push(host); return new Promise(() => {}); } } };
}
const timed = async run => { const started = performance.now(); const value = await run(); return { value, ms: Math.round(performance.now() - started) }; };
// One DNS wait per navigation plus loopback page loads; the per-hop behavior this replaces took 2 s per hop.
const ONE_WAIT_BOUND = DNS_NAVIGATION_WAIT_MS + 1500;

test('DNS guard MJ-1: with a hanging resolver, a 7-hop same-host start and a click through same-host redirects succeed after one wait', async t => {
  const fixture = await site(t, (host, url) => {
    const hop = /^\/r(\d+)$/.exec(url);
    if (hop && Number(hop[1]) > 0) return { location: `/r${Number(hop[1]) - 1}` };
    return { body: page(`${host}${url}`).replace('</main>', '<a id="same" href="/r2">Same</a></main>') };
  });
  const slow = fixture.origin('slow.example');
  const { resolver, calls } = hungResolver();
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${slow}/r7` }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  const start = await timed(() => browser.start());
  t.diagnostic(`start through 7 same-host redirects: ${start.ms} ms`);
  assert.ok(start.ms < ONE_WAIT_BOUND, `start took ${start.ms} ms`);
  assert.equal(browser.navigationReport().redirectChain.length, 8); assert.equal(browser.navigationReport().finalUrl, `${slow}/r0`);
  assert.deepEqual(calls, ['slow.example'], 'one lookup for the host, not one per hop');

  const click = await timed(() => browser.execute({ action: 'click', selector: '#same' }));
  t.diagnostic(`click through 2 same-host redirects: ${click.ms} ms`);
  assert.equal(click.value.success, true, JSON.stringify(click.value.error)); assert.ok(click.ms < ONE_WAIT_BOUND, `click took ${click.ms} ms`);
  assert.equal(fixture.count('slow.example'), 8 + 3);
  const { dnsCheck } = browser.navigationReport();
  assert.deepEqual([dnsCheck.status, dnsCheck.lookups, dnsCheck.failedLookups, dnsCheck.skippedLookups], ['degraded', 1, 1, 7 + 3]);
  assert.deepEqual(dnsCheck.failures, [{ stage: 'audit-browser-start', host: 'slow.example', error: 'LOOKUP_TIMEOUT' }]);
  assert.deepEqual([dnsCheck.session.basis, dnsCheck.session.resolution.error], ['literal_fallback', 'LOOKUP_TIMEOUT']);
});

test('DNS guard MJ-1: with a hanging resolver, a click and a navigate through cross-host redirects share one DNS wait per navigation', async t => {
  const fixture = await site(t, (host, url, port) => {
    const hop = /^\/r(\d+)$/.exec(url);
    if (hop && Number(hop[1]) > 0) return { location: `/r${Number(hop[1]) - 1}` };
    if (host === 'hop.example' && url === '/x') return { location: `http://hop2.example:${port}/y` };
    if (host === 'nav.example' && url === '/n') return { location: `http://nav2.example:${port}/z` };
    return { body: page(`${host}${url}`).replace('</main>', `<a id="cross" href="http://hop.example:${port}/x">Cross</a></main>`) };
  });
  const [slow, hop, hop2, nav, nav2] = ['slow.example', 'hop.example', 'hop2.example', 'nav.example', 'nav2.example'].map(fixture.origin);
  const { resolver, calls } = hungResolver();
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${slow}/`, followRedirects: true, allowedOrigins: [hop, hop2, nav, nav2] }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();

  // Click default timeout is 3 s; two fresh hosts at 2 s each used to exceed it.
  const click = await timed(() => browser.execute({ action: 'click', selector: '#cross' }));
  t.diagnostic(`click through a cross-host redirect (2 fresh hosts): ${click.ms} ms`);
  assert.equal(click.value.success, true, JSON.stringify(click.value.error)); assert.ok(click.ms < ONE_WAIT_BOUND, `click took ${click.ms} ms`);
  assert.equal(fixture.count('hop2.example'), 1);

  // A 4 s navigate: its check before leaving and its redirect hops share one wait.
  const navigate = await timed(() => browser.execute({ action: 'navigate', path: `${nav}/n` }, 4000));
  t.diagnostic(`navigate (4 s budget) through a cross-host redirect (2 fresh hosts): ${navigate.ms} ms`);
  assert.equal(navigate.value.success, true, JSON.stringify(navigate.value.error)); assert.ok(navigate.ms < ONE_WAIT_BOUND, `navigate took ${navigate.ms} ms`);
  assert.equal(fixture.count('nav2.example'), 1);

  // A host that already failed costs nothing, however many redirects follow.
  const again = await timed(() => browser.execute({ action: 'navigate', path: `${slow}/r3` }, 4000));
  t.diagnostic(`navigate through 3 same-host redirects to a failed host: ${again.ms} ms`);
  assert.equal(again.value.success, true, JSON.stringify(again.value.error)); assert.ok(again.ms < 1500, `navigate took ${again.ms} ms`);

  assert.deepEqual(calls, ['slow.example', 'hop.example', 'nav.example'], 'each fresh host is looked up once; hosts past a used-up wait are not');
  const { dnsCheck } = browser.navigationReport();
  assert.deepEqual([dnsCheck.status, dnsCheck.lookups, dnsCheck.failedLookups, dnsCheck.skippedLookups], ['degraded', 3, 3, 2 + 1 + 3]);
  assert.deepEqual(dnsCheck.failures.map(item => [item.stage, item.host, item.error]), [
    ['audit-browser-start', 'slow.example', 'LOOKUP_TIMEOUT'], ['click', 'hop.example', 'LOOKUP_TIMEOUT'], ['click', 'hop2.example', 'LOOKUP_BUDGET_EXHAUSTED'],
    ['navigate', 'nav.example', 'LOOKUP_TIMEOUT'], ['navigate', 'nav2.example', 'LOOKUP_BUDGET_EXHAUSTED']]);
  assert.match(dnsCheck.note, /not looked up again/);
});

// ---------- m-1: a start answer with both public and private addresses ----------

test('DNS guard m-1: a start answer with both public and private addresses opens a private session and records both', async t => {
  const answer = ['8.8.8.8', '10.0.0.5'];
  const mixed = startSession({ allowed: false, reason: 'private_network_target', overridable: false,
    resolution: { host: 'mixed.example', resolver: 'r', addresses: answer.map(classifyAddress) } }, publicPolicy);
  assert.deepEqual([mixed.decision.allowed, mixed.session.type, mixed.session.basis], [true, 'private', 'resolution']);

  const fixture = await site(t);
  const start = fixture.origin('mixed.example'), loopback = fixture.origin('127.0.0.1');
  const { resolver, calls } = tableResolver({ 'mixed.example': answer });
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${start}/`, allowedOrigins: [loopback] }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  const { dnsCheck } = browser.navigationReport();
  assert.deepEqual(dnsCheck.session, { type: 'private', basis: 'resolution', resolution: { host: 'mixed.example', resolver: 'test-table', addresses: [
    { address: '8.8.8.8', family: 4, category: 'public', blocked: false }, { address: '10.0.0.5', family: 4, category: 'private', blocked: true }] } });
  assert.equal(browser.navigationPolicy.publicSession, false);
  // Being private, the session may reach a declared private literal.
  assert.equal((await browser.execute({ action: 'navigate', path: `${loopback}/` })).success, true, 'declared loopback literal in a private session');
  // A navigate resolves its target once: the request reuses the check made before leaving.
  assert.equal((await browser.execute({ action: 'navigate', path: `${start}/two` })).success, true);
  assert.deepEqual(calls, ['mixed.example', 'mixed.example']);
  assert.equal(fixture.count('mixed.example'), 2);
});

// ---------- Size of the dnsCheck repeated in later responses ----------

test('DNS guard MJ-2: only a brief dnsCheck of at most DNS_BRIEF_MAX_BYTES is repeated after the start, whatever the full record holds', t => {
  // The full record is clipped (8 failures, 16 addresses) but still several KB, and more once JSON escapes a host; it
  // stays in the start response and the sealed report. Later responses repeat the brief form, which has a fixed bound.
  const longHost = `${'"'.repeat(300)}.example`;
  const addresses = Array.from({ length: 40 }, (_, index) => classifyAddress(`::ffff:10.0.${index}.1`));
  const largest = dnsCheckSummary({ session: { type: 'public', basis: 'literal_fallback', resolution: { host: longHost, resolver: 'r'.repeat(100), addresses, error: 'E'.repeat(100) } },
    lookups: Number.MAX_SAFE_INTEGER, failures: Array.from({ length: 50 }, () => ({ stage: 's'.repeat(100), host: longHost, error: 'E'.repeat(100) })),
    failureCount: Number.MAX_SAFE_INTEGER, skipped: Number.MAX_SAFE_INTEGER, entryCount: Number.MAX_SAFE_INTEGER });
  assert.equal(largest.failures.length, 8); assert.equal(largest.session.resolution.addresses.length, 16);
  const fullBytes = Buffer.byteLength(JSON.stringify(largest)), brief = dnsCheckBrief(largest), briefBytes = Buffer.byteLength(JSON.stringify({ dnsCheck: brief }));
  t.diagnostic(`full dnsCheck ${fullBytes} bytes, brief ${briefBytes} bytes`);
  assert.ok(fullBytes > 4 * DNS_BRIEF_MAX_BYTES, 'the full record is too large to repeat in every response');
  assert.ok(briefBytes <= DNS_BRIEF_MAX_BYTES, `brief dnsCheck is ${briefBytes} bytes`);
  assert.deepEqual({ ...brief, note: undefined }, { status: 'degraded', session: { type: 'public', basis: 'literal_fallback' }, lookups: Number.MAX_SAFE_INTEGER,
    failedLookups: Number.MAX_SAFE_INTEGER, skippedLookups: Number.MAX_SAFE_INTEGER, failureEntries: Number.MAX_SAFE_INTEGER, detail: 'brief', note: undefined });
  assert.match(brief.note, /may not have been detected/); assert.doesNotMatch(JSON.stringify(brief), /example/, 'no host is repeated');
  // Values that are not counts or known names never widen it.
  const hostile = dnsCheckBrief({ status: 'x'.repeat(5000), session: { type: 'y'.repeat(5000), basis: 'z'.repeat(5000) }, lookups: '9'.repeat(5000), failedLookups: 1e300, skippedLookups: -1, failures: 'f'.repeat(5000), failuresOmitted: {} });
  assert.ok(Buffer.byteLength(JSON.stringify({ dnsCheck: hostile })) <= DNS_BRIEF_MAX_BYTES);
  assert.deepEqual([hostile.status, hostile.session.type, hostile.session.basis, hostile.lookups, hostile.failedLookups, hostile.skippedLookups], ['degraded', 'public', 'literal', 0, 0, undefined]);
  assert.equal(dnsCheckBrief({ status: 'checked', lookups: 2, failedLookups: 0 }).note, undefined, 'a check that is not degraded has no degraded note');
});

test('DNS guard HTML: the limits list counts requests that were not looked up after a failure', () => {
  const base = { kind: 'audit-proposal', runId: 'r', findings: [], coverage: [], standard: { version: '2.2', targetLevel: 'AA' }, auditor: { name: 'A' }, manifest: { url: 'http://slow.example/' } };
  const render = dnsCheck => { const html = renderAuditReportHtml({ ...base, navigation: { finalUrl: 'http://slow.example/', redirects: 0, dnsCheck } }); return html.slice(html.indexOf('id="scope"')); };
  assert.match(render({ status: 'degraded', session: { type: 'public', basis: 'literal_fallback' }, lookups: 1, failedLookups: 1, skippedLookups: 7 }),
    /1 of 1 main-document DNS lookup failed or timed out\. 7 later main-document requests were not looked up, because the host had already failed or the navigation had used its DNS wait\./);
  assert.doesNotMatch(render({ status: 'degraded', session: { type: 'public', basis: 'literal_fallback' }, lookups: 1, failedLookups: 1 }), /not looked up/);
});

// ---------- MJ-2: a large degraded check does not crowd out full read pages ----------

// A start host with the largest session record and 8 declared hosts whose lookups fail:
// the proxy or split-DNS case, where the full dnsCheck grows past 2 KB. Every *.example name maps to the loopback server.
const wideLaunchArgs = ['--host-resolver-rules=MAP *.example 127.0.0.1'];
const cdnHost = index => `static-assets-${index}.eu-west-1.cdn.example-company.example`;
// The largest start record: a 253-character host and 16 NAT64 addresses, each naming its embedded public IPv4 address.
const startHost = `s${'q'.repeat(62)}.${'r'.repeat(63)}.${'s'.repeat(63)}.${'t'.repeat(53)}.example`;
const wideAnswer = Array.from({ length: 16 }, (_, i) => `64:ff9b::6810:${(0x100 + i).toString(16)}`);
const splitResolver = () => tableResolver({ [startHost]: wideAnswer });
const bigPage = paragraphs => `<!doctype html><html lang="en"><head><title>Big</title></head><body><main><h1>Big</h1>${
  Array.from({ length: paragraphs }, (_, i) => `<p id="p${i}">Paragraph ${i} ${'lorem ipsum '.repeat(12)}</p><img src="data:," width="1" height="1">`).join('')}</main></body></html>`;
const FULL_PAGE_READS = [{ view: 'field', field: '/result/visibleText' }, { view: 'field', field: '/result/nodes' }, { view: 'field', field: '/result' }, { view: 'nodes', limit: 200 }];

test('DNS guard MJ-2 MCP: with 8 failed hosts and the largest start answer, the start and every full-page read stay within 20,000 characters', async t => {
  const fixture = await site(t, () => ({ body: bigPage(400) })), projectRoot = await workspace(t);
  const hosts = Array.from({ length: 8 }, (_, index) => cdnHost(index));
  const handlers = new Map(), server = { registerTool: (name, _spec, handler) => handlers.set(name, handler), close: async () => {}, server: {} };
  const { resolver } = splitResolver();
  registerAuditTools(server, { openAgent: (input, options) => openAuditAgent(input, { ...options,
    liveOptions: { createBrowser: manifest => new AuditBrowser(manifest, { handleSignals: false, launchArgs: wideLaunchArgs, hostResolver: resolver }) } }) });
  const call = async (name, input) => {
    const reply = await handlers.get(name)(input), text = reply.content[0].text;
    assert.ok(text.length <= MCP_TEXT_LIMIT, `${name} text is ${text.length} characters`);
    return { value: reply.structuredContent, chars: text.length };
  };
  const start = await call('a11y_audit_start', { manifest: { projectRoot, url: `${fixture.origin(startHost)}/`, startupAxe: true, wallSeconds: 120,
    allowedOrigins: hosts.map(fixture.origin) } });
  const started = start.value;
  t.after(() => handlers.get('a11y_audit_close')({ runId: started.runId }));
  assert.equal(started.success, true, JSON.stringify(started.error));
  assert.equal(started.dnsCheck.session.resolution.addresses.length, 16, 'the start response keeps the full record');
  assert.equal(started.dnsCheck.session.resolution.addresses[0].embeddedIpv4, '104.16.1.0');
  const request = async body => (await call('a11y_audit_request', { runId: started.runId, request: body })).value;
  const snapshot = started.startup.records.find(row => row.action === 'snapshot').evidenceId;
  const readAll = async () => { const replies = []; for (const options of FULL_PAGE_READS) replies.push(await call('a11y_audit_request', { runId: started.runId, request: { tool: 'read', evidenceId: snapshot, options } })); return replies; };
  const before = await readAll();
  for (const read of before) { assert.equal(read.value.success, true); assert.equal(read.value.dnsCheck, undefined); }
  // The startup axe preview leaves room for the full dnsCheck: the same snapshot + axe step, sent later, previews more.
  const again = await request({ tool: 'step', actions: [{ action: 'snapshot' }, { action: 'axe' }] });
  const axeBytes = value => Buffer.byteLength(JSON.stringify(value.axe)), startDnsBytes = Buffer.byteLength(JSON.stringify({ dnsCheck: started.dnsCheck }));
  t.diagnostic(`axe preview: start ${axeBytes(started.startup)} bytes, later step ${axeBytes(again)} bytes`);
  assert.ok(axeBytes(again) - axeBytes(started.startup) >= startDnsBytes / 2, `the start preview gave up ${axeBytes(again) - axeBytes(started.startup)} bytes for a ${startDnsBytes}-byte dnsCheck`);

  for (const host of hosts) assert.equal((await request({ tool: 'step', actions: [{ action: 'navigate', path: `${fixture.origin(host)}/` }] })).success, true);
  const stepped = await request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  const evidenceId = stepped.records.at(-1).evidenceId;
  const sizes = [];
  for (const options of FULL_PAGE_READS) {
    const read = await call('a11y_audit_request', { runId: started.runId, request: { tool: 'read', evidenceId, options } });
    assert.equal(read.value.success, true, `${JSON.stringify(options)}: ${JSON.stringify(read.value.error)}`);
    assert.equal(read.value.dnsCheck.status, 'degraded', 'the degraded status is still in every response');
    assert.equal(read.value.dnsCheck.failedLookups, 8);
    const dnsBytes = Buffer.byteLength(JSON.stringify({ dnsCheck: read.value.dnsCheck }));
    assert.ok(dnsBytes <= DNS_BRIEF_MAX_BYTES, `dnsCheck is ${dnsBytes} bytes`);
    sizes.push(`${options.field ?? options.view} ${read.chars}`);
  }
  t.diagnostic(`start ${start.chars} characters (full dnsCheck ${Buffer.byteLength(JSON.stringify(started.dnsCheck))} bytes); full-page reads: ${sizes.join(', ')} characters`);
  // Field pages shrink by what the repeated check takes: the same page of the same record carries that much less data.
  const after = await readAll(), dataBytes = read => Buffer.byteLength(JSON.stringify(read.value.data));
  after.forEach((read, index) => {
    assert.equal(read.value.success, true, JSON.stringify(read.value.error)); assert.equal(read.value.dnsCheck.status, 'degraded');
    if (FULL_PAGE_READS[index].view !== 'field') return;
    const room = Buffer.byteLength(JSON.stringify({ dnsCheck: read.value.dnsCheck })), shrunk = dataBytes(before[index]) - dataBytes(read);
    assert.ok(shrunk >= room - 64 && shrunk <= room + 64, `${FULL_PAGE_READS[index].field}: data shrank by ${shrunk} bytes for a ${room}-byte dnsCheck`);
  });
  // A paged read continues from its cursor after the check degraded.
  assert.equal(after[0].value.pagination.complete, false);
  const next = await request({ tool: 'read', evidenceId: snapshot, options: after[0].value.pagination.next });
  assert.equal(next.success, true, JSON.stringify(next.error));
});

test('DNS guard MJ-2 JSONL agent: with 8 failed hosts, full-page reads succeed and every response line stays within 65,536 bytes', async t => {
  // The JSONL agent writes each agent response as one line, JSON.stringify(boundAuditResponse(response)) (agent-cli.js);
  // the agent is opened directly here so that the resolver can be injected.
  const fixture = await site(t, () => ({ body: bigPage(1200) })), projectRoot = await workspace(t);
  const hosts = Array.from({ length: 8 }, (_, index) => cdnHost(index));
  const { resolver } = splitResolver();
  const agent = await openAuditAgent({ projectRoot, url: `${fixture.origin(startHost)}/`, wallSeconds: 120, allowedOrigins: hosts.map(fixture.origin) },
    { liveOptions: { createBrowser: manifest => new AuditBrowser(manifest, { handleSignals: false, launchArgs: wideLaunchArgs, hostResolver: resolver }) } });
  t.after(() => agent.close({ reason: 'requested' }).catch(() => {}));
  const line = value => { const bytes = Buffer.byteLength(JSON.stringify(value)); assert.ok(bytes <= AUDIT_TEXT_LIMIT, `line is ${bytes} bytes`); return bytes; };
  for (const host of hosts) { const reply = await agent.request({ tool: 'step', actions: [{ action: 'navigate', path: `${fixture.origin(host)}/` }] }); line(reply); assert.equal(reply.success, true); }
  const stepped = await agent.request({ tool: 'step', actions: [{ action: 'snapshot' }] });
  line(stepped);
  const full = agent.dnsCheck();
  assert.equal(full.failures.length, 8); assert.ok(Buffer.byteLength(JSON.stringify(full)) > 2048, 'the full record is past the old 2 KB margin');
  const sizes = [];
  for (const options of FULL_PAGE_READS) {
    const read = await agent.request({ tool: 'read', evidenceId: stepped.records.at(-1).evidenceId, options });
    sizes.push(line(read));
    assert.equal(read.success, true, `${JSON.stringify(options)}: ${JSON.stringify(read.error)}`);
    assert.equal(read.dnsCheck.status, 'degraded'); assert.ok(Buffer.byteLength(JSON.stringify({ dnsCheck: read.dnsCheck })) <= DNS_BRIEF_MAX_BYTES);
  }
  t.diagnostic(`JSONL full-page reads: ${sizes.join(', ')} bytes; full dnsCheck ${Buffer.byteLength(JSON.stringify(full))} bytes`);
});

// ---------- n-A: a timeout cut short by the navigation's wait is not remembered ----------

test('DNS guard n-A: a lookup that times out only because its navigation had little wait left is looked up again later', async t => {
  const fixture = await site(t, (host, url, port) => host === 'hop.example' && url === '/x' ? { location: `http://hop2.example:${port}/y` } : {});
  const [hop, hop2] = ['hop.example', 'hop2.example'].map(fixture.origin);
  const failedHosts = new Map();
  const hung = { name: 'hung', lookup: () => new Promise(() => {}) };
  const shortened = await resolveNavigationTarget({ url: 'https://slow.example/', policy: publicPolicy, resolver: hung, waitMs: 30, failedHosts });
  assert.deepEqual(shortened, { allowed: true, degraded: true, resolution: { host: 'slow.example', resolver: 'hung', addresses: [], error: 'LOOKUP_TIMEOUT' } });
  assert.equal(failedHosts.size, 0, 'a shortened timeout is not a verdict on the host');
  await resolveNavigationTarget({ url: 'https://slow.example/', policy: publicPolicy, resolver: hung, timeoutMs: 30, waitMs: 1000, failedHosts });
  assert.deepEqual([...failedHosts], [['slow.example', 'LOOKUP_TIMEOUT']], 'a timeout after the full lookup bound is remembered');
  const refused = { name: 'nx', lookup: async () => { throw dnsError('ENOTFOUND'); } };
  await resolveNavigationTarget({ url: 'https://nxdomain.example/', policy: publicPolicy, resolver: refused, waitMs: 30, failedHosts });
  assert.equal(failedHosts.get('nxdomain.example'), 'ENOTFOUND', 'an answer that the name does not exist is remembered whatever the wait');

  // In a browser: a -> b redirect where each lookup takes 1.2 s. b gets the 0.8 s left and times out; a later navigate looks b up again.

  const calls = [];
  // Necessary timer: it stands in for a slow resolver; the late answer is ignored once its lookup has timed out.
  const slowResolver = { name: 'slow', lookup: host => { calls.push(host); return new Promise(resolve => setTimeout(() => resolve([{ address: '8.8.8.8', family: 4 }]), 1200)); } };
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${fixture.origin('127.0.0.1')}/`, followRedirects: true, allowedOrigins: [hop, hop2] }), { launchArgs, hostResolver: slowResolver });
  t.after(() => browser.close());
  await browser.start();
  assert.equal((await browser.execute({ action: 'navigate', path: `${hop}/x` }, 6000)).success, true);
  assert.deepEqual(calls, ['hop.example', 'hop2.example']);
  const again = await browser.execute({ action: 'navigate', path: `${hop2}/y` }, 6000);
  assert.equal(again.success, true, JSON.stringify(again.error));
  assert.deepEqual(calls, ['hop.example', 'hop2.example', 'hop2.example'], 'hop2 is looked up again instead of being skipped as failed');
  const { dnsCheck } = browser.navigationReport();
  assert.deepEqual([dnsCheck.status, dnsCheck.lookups, dnsCheck.failedLookups, dnsCheck.skippedLookups], ['degraded', 3, 1, undefined]);
  assert.deepEqual(dnsCheck.failures, [{ stage: 'navigate', host: 'hop2.example', error: 'LOOKUP_TIMEOUT' }]);
});
