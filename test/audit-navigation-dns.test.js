import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AuditBrowser } from '../src/audit/browser.js';
import { parseAuditManifest } from '../src/audit/schema.js';
import { errorPayload } from '../src/audit/error-details.js';
import { errorRecord } from '../src/evidence.js';
import {
  boundNavigationDetails, classifyAddress, CLOUD_METADATA_ADDRESSES, decideNavigation, FLOOR_REASONS, isPrivateHost,
  navigationBlockDetails, navigationPolicy, resolutionHost, resolveNavigationTarget, systemHostResolver,
} from '../src/audit/navigation.js';
import { externalProbe } from './helpers.js';

// Loopback fixtures only, and no real DNS: Chromium maps the *.example names below to 127.0.0.1 with
// --host-resolver-rules, while the DNS check runs against an injected resolver that answers from a table.
const page = title => `<!doctype html><html lang="en"><head><title>${title}</title></head><body><main><h1>${title}</h1></main></body></html>`;
const MAPPED = ['public-site.example', 'internal.example', 'rebind.example', 'meta.example', 'nxdomain.example'];
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
  assert.deepEqual([...CLOUD_METADATA_ADDRESSES], ['169.254.169.254', '169.254.170.2', 'fd00:ec2::254', '100.100.100.200']);
  for (const address of [...CLOUD_METADATA_ADDRESSES, 'FD00:EC2:0:0::254', '::ffff:169.254.169.254', '::ffff:a9fe:a9fe']) {
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

test('DNS guard: lookup failure, timeout and empty answers fail closed with a structured, non-overridable reason', async () => {
  const outcome = lookup => resolveNavigationTarget({ url: 'https://public-site.example/a', policy: publicPolicy, resolver: { name: 'fixed', lookup } });
  for (const code of ['ENOTFOUND', 'EAI_AGAIN', 'ETIMEOUT', 'ESERVFAIL']) {
    const result = await outcome(async () => { throw dnsError(code); });
    assert.deepEqual(result, { allowed: false, reason: 'target_resolution_failed', overridable: false, resolution: { host: 'public-site.example', resolver: 'fixed', addresses: [], error: code } }, code);
  }
  assert.equal((await outcome(() => { throw new Error('synchronous failure'); })).resolution.error, 'LOOKUP_FAILED', 'a synchronous throw without a code');
  assert.equal((await outcome(async () => [])).resolution.error, 'NO_ADDRESSES');
  assert.equal((await outcome(async () => null)).resolution.error, 'NO_ADDRESSES');
  assert.ok(FLOOR_REASONS.includes('target_resolution_failed'));
  const details = navigationBlockDetails({ ...(await outcome(async () => { throw dnsError('ETIMEOUT'); })), fromUrl: null, blockedUrl: 'https://public-site.example/a',
    chain: [{ url: 'https://public-site.example/a', status: null, blocked: true }], policy: publicPolicy, sessionOrigins: new Set([publicPolicy.manifestOrigin]), stage: 'audit-browser-start', initial: true });
  assert.equal(details.suggestedAction.kind, 'stop'); assert.match(details.suggestedAction.note, /could not be resolved/);
});

test('DNS guard: literals, localhost names, private sessions and non-http URLs are not resolved; literal decisions are unchanged', async () => {
  for (const url of ['http://10.0.0.1/', 'http://8.8.8.8/', 'http://[::1]/', 'http://[2606:4700::1]/', 'http://localhost/', 'http://app.localhost/', 'http://localhost./', 'ftp://public-site.example/', 'not a url']) {
    assert.equal(resolutionHost(url, publicPolicy), null, url);
  }
  assert.equal(resolutionHost('https://www.public-site.example/', publicPolicy), 'www.public-site.example');
  assert.equal(resolutionHost('https://public-site.example/', privatePolicy), null, 'a loopback session never resolves');
  let calls = 0;
  const counting = { name: 'count', lookup: async () => { calls++; return ['10.0.0.1']; } };
  assert.deepEqual(await resolveNavigationTarget({ url: 'http://8.8.8.8/', policy: publicPolicy, resolver: counting }), { allowed: true });
  assert.deepEqual(await resolveNavigationTarget({ url: 'http://internal.example/', policy: privatePolicy, resolver: counting }), { allowed: true });
  assert.equal(calls, 0);
  // isPrivateHost and the synchronous decision still see only literals and localhost names.
  assert.equal(isPrivateHost('internal.example'), false);
  const origins = new Set(['https://public-site.example', 'https://internal.example']);
  assert.deepEqual(decideNavigation({ url: 'https://internal.example/', policy: { ...publicPolicy, allowedOrigins: ['https://internal.example'] }, sessionOrigins: origins }), { allowed: true });
  assert.equal(decideNavigation({ url: 'http://169.254.169.254/', policy: publicPolicy, sessionOrigins: origins }).reason, 'private_network_target');
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

test('DNS guard start: a public start URL whose name resolves to a private address is never contacted', async t => {
  const fixture = await site(t);
  const { resolver, calls } = tableResolver({ 'public-site.example': ['8.8.8.8', '10.0.0.5'] });
  const { browser, error } = await startBlocked({ projectRoot: '/tmp', url: `${fixture.origin('public-site.example')}/` }, { hostResolver: resolver });
  assert.equal(fixture.hits.length, 0, 'the request was failed before it was sent');
  assert.deepEqual(calls, ['public-site.example']);
  assert.equal(errorRecord(error).code, 'RUNTIME_ERROR', '0.1.1 code for a blocked start');
  assert.equal(error.navigation.reason, 'private_network_target'); assert.equal(error.navigation.overridable, false);
  assert.equal(error.navigation.suggestedAction.kind, 'stop'); assert.equal(error.navigation.stage, 'audit-browser-start');
  assert.deepEqual(error.navigation.resolution, { host: 'public-site.example', resolver: 'test-table', addresses: [
    { address: '8.8.8.8', family: 4, category: 'public', blocked: false }, { address: '10.0.0.5', family: 4, category: 'private', blocked: true }] });
  assert.deepEqual(browser.blocked, [{ reason: 'navigation_outside_origin', url: `${fixture.origin('public-site.example')}/` }], '0.1.1 event shape');
});

test('DNS guard start: a lookup failure blocks the start with target_resolution_failed; a public answer opens it', async t => {
  const fixture = await site(t);
  for (const failure of [dnsError('ENOTFOUND'), dnsError('ETIMEOUT')]) {
    const { resolver } = tableResolver({ 'nxdomain.example': failure });
    const { error } = await startBlocked({ projectRoot: '/tmp', url: `${fixture.origin('nxdomain.example')}/` }, { hostResolver: resolver });
    assert.equal(error.navigation.reason, 'target_resolution_failed'); assert.equal(error.navigation.overridable, false);
    assert.equal(error.navigation.resolution.error, failure.code); assert.deepEqual(error.navigation.resolution.addresses, []);
  }
  assert.equal(fixture.count('nxdomain.example'), 0);
  const { resolver, calls } = tableResolver({ 'public-site.example': ['8.8.8.8', '2606:4700::1'] });
  const browser = new AuditBrowser(parseAuditManifest({ projectRoot: '/tmp', url: `${fixture.origin('public-site.example')}/` }), { launchArgs, hostResolver: resolver });
  t.after(() => browser.close());
  await browser.start();
  assert.equal(fixture.count('public-site.example'), 1); assert.deepEqual(calls, ['public-site.example']);
  assert.equal(browser.navigationReport().finalUrl, `${fixture.origin('public-site.example')}/`);
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
