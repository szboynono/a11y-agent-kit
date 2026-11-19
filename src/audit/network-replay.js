import path from 'node:path';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { IGNORED_DIRECTORIES, ToolError } from '../evidence.js';

export const NETWORK_REPLAY_LIMITS = Object.freeze({ maxEntries: 512, maxManifestBytes: 1024 * 1024, maxBodyBytes: 8 * 1024 * 1024, maxTotalBodyBytes: 32 * 1024 * 1024, maxObservations: 1000, maxUrlCharacters: 8192 });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const absolutePath = z.string().min(1).max(4096).refine(value => !value.includes('\0') && path.isAbsolute(value) && path.resolve(value) === value);
export const networkReplayDescriptorSchema = z.object({ manifestPath: absolutePath, sha256 }).strict();
const relativeFile = z.string().min(1).max(4096).refine(value => !/[\0\\]/.test(value) && !path.isAbsolute(value) && value.split('/').every(part => part && part !== '.' && part !== '..'));
const exactHttpUrl = z.string().min(1).max(NETWORK_REPLAY_LIMITS.maxUrlCharacters).refine(value => {
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && !value.includes('#') && url.href === value; }
  catch { return false; }
});
const replayManifestSchema = z.object({ schemaVersion: z.literal(1), entries: z.array(z.object({
  url: exactHttpUrl, file: relativeFile, sha256, bytes: z.number().int().min(0).max(NETWORK_REPLAY_LIMITS.maxBodyBytes),
  status: z.number().int().min(200).max(599), contentType: z.string().min(1).max(300).refine(value => !/[\0\r\n]/.test(value)),
}).strict()).max(NETWORK_REPLAY_LIMITS.maxEntries) }).strict();

function fail(code, message, details) { throw new ToolError(code, message, details); }
function parse(schema, value) {
  const result = schema.safeParse(value);
  if (!result.success) fail('INVALID_NETWORK_REPLAY', 'Local response replay validation failed.', result.error.issues.map(issue => ({ path: issue.path.join('.'), message: issue.message })));
  return result.data;
}
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
const copy = value => JSON.parse(JSON.stringify(value));

async function readSourceFile(root, absolute, maximumBytes) {
  if (!path.isAbsolute(absolute) || path.resolve(absolute) !== absolute) fail('UNSAFE_NETWORK_REPLAY_PATH', 'Replay files must use canonical absolute paths.');
  const relative = path.relative(root, absolute), parts = relative.split(path.sep);
  if (!relative || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) || relative === '..') fail('NETWORK_REPLAY_OUTSIDE_PROJECT', 'Replay files must remain within projectRoot.');
  if (parts.slice(0, -1).some(part => IGNORED_DIRECTORIES.includes(part)) || parts.some(part => part === '.DS_Store' || part.endsWith('.log'))) {
    fail('NETWORK_REPLAY_EXCLUDED_SOURCE', 'Replay inputs must participate in the fixed source fingerprint, outside ignored paths.');
  }
  if (await fs.realpath(absolute) !== absolute) fail('UNSAFE_NETWORK_REPLAY_PATH', 'Replay files and their parent directories must not be symlinks.');
  if (!(await fs.lstat(absolute)).isFile()) fail('INVALID_NETWORK_REPLAY_FILE', 'Replay input must be a regular file.');
  const handle = await fs.open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) fail('INVALID_NETWORK_REPLAY_FILE', 'Replay input must be a regular file.');
    if (stat.size > maximumBytes) fail('NETWORK_REPLAY_LIMIT_EXCEEDED', 'A local replay input exceeds its byte limit.');
    // Read at most the initial bounded size plus one sentinel byte. A source
    // growing concurrently cannot turn readFile() into an unbounded allocation.
    const bytes = Buffer.alloc(stat.size + 1); let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, null);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset !== stat.size) fail('NETWORK_REPLAY_INPUT_CHANGED', 'A replay input changed size while it was being read.');
    return bytes.subarray(0, offset);
  } finally { await handle.close(); }
}

/** Verify local inputs once; returned routing uses only these in-memory bytes. */
export async function loadNetworkReplay({ projectRoot, origin, descriptor, onMainNavigationBlocked } = {}) {
  const configured = parse(networkReplayDescriptorSchema, descriptor);
  if (!path.isAbsolute(projectRoot) || path.resolve(projectRoot) !== projectRoot || await fs.realpath(projectRoot) !== projectRoot || !(await fs.stat(projectRoot)).isDirectory()) {
    fail('UNSAFE_NETWORK_REPLAY_PATH', 'Replay projectRoot must be a canonical real directory.');
  }
  const base = new URL(origin);
  if (!['http:', 'https:'].includes(base.protocol) || base.origin !== origin || base.username || base.password) fail('INVALID_NETWORK_REPLAY_ORIGIN', 'Replay requires the exact HTTP(S) site origin.');
  const manifestBytes = await readSourceFile(projectRoot, configured.manifestPath, NETWORK_REPLAY_LIMITS.maxManifestBytes);
  if (hash(manifestBytes) !== configured.sha256) fail('NETWORK_REPLAY_HASH_MISMATCH', 'Replay manifest bytes do not match their declared SHA-256.');
  let raw;
  try { raw = JSON.parse(manifestBytes.toString('utf8')); } catch { fail('INVALID_NETWORK_REPLAY', 'The local response manifest is not valid JSON.'); }
  const manifest = parse(replayManifestSchema, raw), bodies = new Map(), entries = [];
  let totalBytes = 0;
  for (const entry of manifest.entries) {
    if (bodies.has(entry.url)) fail('NETWORK_REPLAY_DUPLICATE_URL', 'Replay URLs must be unique exact strings.');
    if ([204, 205, 304].includes(entry.status) && entry.bytes !== 0) fail('INVALID_NETWORK_REPLAY_STATUS', 'Bodyless HTTP statuses require an empty frozen body.');
    totalBytes += entry.bytes;
    if (totalBytes > NETWORK_REPLAY_LIMITS.maxTotalBodyBytes) fail('NETWORK_REPLAY_LIMIT_EXCEEDED', 'The response set exceeds its total body byte limit.');
    const bodyPath = path.resolve(path.dirname(configured.manifestPath), entry.file);
    const bytes = await readSourceFile(projectRoot, bodyPath, NETWORK_REPLAY_LIMITS.maxBodyBytes);
    if (bytes.length !== entry.bytes) fail('NETWORK_REPLAY_LENGTH_MISMATCH', 'A frozen response body differs from its declared byte length.', { file: entry.file });
    if (hash(bytes) !== entry.sha256) fail('NETWORK_REPLAY_HASH_MISMATCH', 'A frozen response body differs from its declared SHA-256.', { file: entry.file });
    bodies.set(entry.url, { ...entry, body: bytes });
    entries.push({ ...entry, bodyPath });
  }
  const inputs = freeze({ descriptor: configured, manifest: { path: configured.manifestPath, sha256: hash(manifestBytes), bytes: manifestBytes.length, schemaVersion: 1 }, entries, totalBodyBytes: totalBytes });
  const observations = [], pending = new Set();
  const counts = { continuedSameOrigin: 0, fulfilledSameOrigin: 0, fulfilledLocal: 0, blockedOffOrigin: 0, blockedNavigation: 0, blockedRedirect: 0, allowedNativeScheme: 0, errors: 0 };
  let totalObserved = 0, phase = 'initialization';

  function begin(url, method, resourceType) {
    const row = { sequence: ++totalObserved, observedAt: new Date().toISOString(), phase, method: String(method).slice(0, 30), url: url.slice(0, NETWORK_REPLAY_LIMITS.maxUrlCharacters), resourceType: String(resourceType).slice(0, 80), outcome: 'pending' };
    if (row.url !== url) { row.urlTruncated = true; row.urlSha256 = hash(url); }
    if (observations.length < NETWORK_REPLAY_LIMITS.maxObservations) observations.push(row);
    return row;
  }
  function complete(row, outcome, reason, category, extra = {}) {
    Object.assign(row, { outcome, reason, completedAt: new Date().toISOString(), ...extra }); counts[category]++;
  }
  function tracked(operation) {
    const promise = operation(); pending.add(promise);
    promise.then(() => pending.delete(promise), () => pending.delete(promise));
    return promise;
  }
  function route(routeObject) {
    return tracked(async () => {
      const request = routeObject.request(), url = request.url(), method = request.method();
      const row = begin(url, method, request.resourceType());
      try {
        const parsed = new URL(url);
        // Preserve native same-document/blob/data use. This does not authorize
        // any HTTP(S) URL embedded in their contents.
        if (['data:', 'blob:', 'about:'].includes(parsed.protocol)) {
          await routeObject.continue(); complete(row, 'continued', 'native_non_network_scheme', 'allowedNativeScheme'); return;
        }
        const sameOrigin = ['http:', 'https:'].includes(parsed.protocol) && parsed.origin === origin && !parsed.username && !parsed.password;
        if (request.isNavigationRequest() && !request.frame().parentFrame() && !sameOrigin) {
          onMainNavigationBlocked?.({ reason: 'navigation_outside_origin', url });
          await routeObject.abort('blockedbyclient'); complete(row, 'blocked', 'main_navigation_outside_origin', 'blockedNavigation'); return;
        }
        if (sameOrigin) {
          // Chromium does not call Playwright routes for subsequent redirect
          // hops. Never continue a response that could bypass this policy.
          const response = await routeObject.fetch({ maxRedirects: 0, timeout: 15000 });
          try {
            const status = response.status(), location = response.headers().location;
            if ([301, 302, 303, 307, 308].includes(status) && location) {
              if (request.isNavigationRequest() && !request.frame().parentFrame()) onMainNavigationBlocked?.({ reason: 'redirect_unavailable_in_replay', url });
              await routeObject.abort('blockedbyclient');
              complete(row, 'blocked', 'redirect_unavailable_in_replay', 'blockedRedirect', { status, redirectLocation: location.slice(0, NETWORK_REPLAY_LIMITS.maxUrlCharacters) });
              return;
            }
            await routeObject.fulfill({ response });
            complete(row, 'fulfilled', 'same_origin_response_without_redirect', 'fulfilledSameOrigin', { status });
          } finally { await response.dispose().catch(() => {}); }
          return;
        }
        const entry = bodies.get(url);
        if (!['GET', 'HEAD'].includes(method) || !entry) {
          await routeObject.abort('blockedbyclient'); complete(row, 'blocked', !['GET', 'HEAD'].includes(method) ? 'method_not_replayed' : 'exact_url_not_frozen', 'blockedOffOrigin'); return;
        }
        await routeObject.fulfill({ status: entry.status, headers: { 'content-type': entry.contentType, 'content-length': String(entry.bytes), 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, HEAD', 'access-control-expose-headers': 'content-type, content-length', 'cache-control': 'no-store' }, body: method === 'HEAD' ? Buffer.alloc(0) : entry.body });
        complete(row, 'fulfilled', 'verified_local_bytes', 'fulfilledLocal', { status: entry.status, contentType: entry.contentType, bodySha256: entry.sha256, bodyBytes: entry.bytes, responseBodyBytes: method === 'HEAD' ? 0 : entry.bytes });
      } catch (error) {
        complete(row, 'error', 'route_or_transport_closed', 'errors', { message: String(error.message).slice(0, 1000) });
        await routeObject.abort('blockedbyclient').catch(() => {});
      }
    });
  }
  function routeWebSocket(socket) {
    return tracked(async () => {
      const url = socket.url(), row = begin(url, 'WEBSOCKET', 'websocket');
      try {
        const parsed = new URL(url); parsed.protocol = parsed.protocol === 'wss:' ? 'https:' : parsed.protocol === 'ws:' ? 'http:' : parsed.protocol;
        if (parsed.origin === origin && !parsed.username && !parsed.password) {
          socket.connectToServer(); complete(row, 'continued', 'same_origin_websocket', 'continuedSameOrigin');
        } else {
          await socket.close({ code: 1008, reason: 'External WebSockets are unavailable in local audit replay.' });
          complete(row, 'blocked', 'external_websocket_not_replayed', 'blockedOffOrigin');
        }
      } catch (error) { complete(row, 'error', 'websocket_route_closed', 'errors', { message: String(error.message).slice(0, 1000) }); }
    });
  }
  function snapshot({ since = 0 } = {}) {
    if (!Number.isInteger(since) || since < 0 || since > totalObserved) fail('INVALID_NETWORK_REPLAY_CURSOR', 'Replay observation cursor must identify an earlier observed sequence.');
    const retained = observations.filter(row => row.sequence > since);
    return { since, nextCursor: totalObserved, totalObserved, counts: { ...counts, pending: totalObserved - Object.values(counts).reduce((sum, value) => sum + value, 0) }, omittedCount: Math.max(0, totalObserved - observations.length), deltaObserved: totalObserved - since, deltaOmittedCount: totalObserved - since - retained.length, observations: copy(retained) };
  }
  const controller = {
    inputs, limits: NETWORK_REPLAY_LIMITS, route, routeWebSocket, snapshot,
    setPhase(value) { if (!['initialization', 'between_actions', 'action', 'cleanup', 'closed'].includes(value)) fail('INVALID_NETWORK_REPLAY_PHASE', 'Unsupported replay lifecycle phase.'); phase = value; },
    async drain() { while (pending.size) await Promise.allSettled([...pending]); },
    async attach(context) {
      if (typeof context.routeWebSocket !== 'function') fail('NETWORK_REPLAY_WEBSOCKET_GUARD_UNAVAILABLE', 'This browser cannot enforce the configured external-network boundary.');
      // A fulfilled loopback document has no network response address. Chromium
      // otherwise blocks its own loopback WebSocket before our route connects.
      if (['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)) await context.grantPermissions(['local-network-access'], { origin });
      await context.route('**/*', route);
      await context.routeWebSocket('**/*', routeWebSocket);
      return controller;
    },
    report() { return { mode: 'exact-local-response-replay-v1', origin, projectRoot, inputs, limits: NETWORK_REPLAY_LIMITS, observationLog: snapshot(), policy: {
      http: 'Same-origin HTTP responses are fetched without following redirects and fulfilled locally. All redirect responses are unavailable in this bounded replay mode. Only exact off-origin GET/HEAD entries are fulfilled from preverified memory; other off-origin requests are blocked without fetching.',
      navigation: 'Main-document navigation remains same-origin even when a frozen entry exists.', websocket: 'Same-origin sockets connect normally; external WebSockets are unavailable.',
      responseHeaders: 'Frozen off-origin responses use public CORS without credential, authentication or cookie headers; their production headers are not reproduced. Ordinary same-origin response headers are retained.',
      loopbackPermission: 'For loopback origins only, the isolated browser context grants local-network-access to this exact origin so fulfilled local documents retain same-origin networking. Off-origin HTTP/WebSocket guards still apply; no OS permission or global browser preference is changed.',
      unavailableFeatures: 'Unfrozen external search, analytics, authentication and other resources are unavailable. Policy blocks and environment-induced errors are not automatic WCAG violations.',
      scope: 'HTTP(S)/WebSocket routing only; not an OS airgap or a WebRTC, DNS or speculative-network firewall.',
      requirement: 'Configure the browser context with serviceWorkers:block. Install this policy before page requests, with no overriding route handlers.',
    } }; },
  };
  return Object.freeze(controller);
}

/** Shared by product and trusted baseline browsers; never calls an HTTP client. */
export async function configureNetworkReplay(context, options) {
  return (await loadNetworkReplay(options)).attach(context);
}
