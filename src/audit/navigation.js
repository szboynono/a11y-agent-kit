import { BlockList, isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

// Main-document navigation policy. Defaults keep the original rule: every main-frame request,
// including each redirect hop, stays on the manifest origin. Callers opt in to more with
// `allowedOrigins` (exact origins) and `followRedirects` (cross-origin redirect hops).
// The floors below apply whatever the manifest says and are never overridable.

/** Redirect hops one main-frame navigation may follow when `followRedirects` is true. Not a manifest option. */
export const MAX_REDIRECTS = 5;
/** Code inside the additive `navigation` payload. The surrounding error keeps its 0.1.1 code and details. */
export const NAVIGATION_BLOCK_CODE = 'AUDIT_NAVIGATION_BLOCKED';
export const NAVIGATION_POLICY_VERSION = 'main-document-navigation-1';
export const FLOOR_REASONS = Object.freeze(['invalid_url', 'non_http_scheme', 'credentials_in_url', 'scheme_downgrade', 'private_network_target', 'redirect_limit']);
const URL_LIMIT = 2048, CHAIN_LIMIT = MAX_REDIRECTS + 2, ADDRESS_LIMIT = 16, HOST_LIMIT = 255, ERROR_CODE_LIMIT = 64;

/** Recorded URLs never retain userinfo: a username/password is replaced before it reaches evidence or a response. */
export function redactUrl(value) {
  if (typeof value !== 'string') return value ?? null;
  const url = parse(value);
  if (!url || (!url.username && !url.password)) return value;
  url.username = 'redacted'; url.password = '';
  return url.href;
}
/** Redacted and clipped to the same 2048-character bound as block details. */
export const clipUrl = raw => { const value = redactUrl(raw); return typeof value === 'string' && value.length > URL_LIMIT ? `${value.slice(0, URL_LIMIT - 1)}…` : value; };

function parse(value) {
  try { return new URL(value); } catch { return null; }
}

/**
 * The canonical origin for an `allowedOrigins` entry, or null. Scheme and host case, a default port and a
 * Unicode (IDN) hostname are normalized, so `HTTPS://WWW.Example.com:443` becomes `https://www.example.com`.
 * A path (even a trailing slash), query, fragment, credentials or a non-http(s) scheme is rejected, not dropped.
 */
export function canonicalOrigin(value) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9+.-]*:\/\/[^/?#@\\]+$/i.test(value)) return null;
  const url = parse(value);
  return url && ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.origin : null;
}

/** A bare http(s) origin as `allowedOrigins` accepts it (see canonicalOrigin). */
export function isBareOrigin(value) {
  return canonicalOrigin(value) !== null;
}

/** http origins with a default port and their same-host https upgrade origin. */
export function httpsUpgradeOrigin(origin) {
  const url = parse(origin);
  return url && url.protocol === 'http:' && defaultPort(url) ? `https://${url.host.replace(/:80$/, '')}` : null;
}

const isLocalhostName = host => host === 'localhost' || host.endsWith('.localhost');
const bareHost = hostname => String(hostname ?? '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

/**
 * True for a `localhost` name or an IP literal that is not public under `classifyAddress` (loopback, private,
 * link-local, unspecified, multicast, broadcast, reserved, IPv6 unique-local or site-local, a cloud metadata
 * address, or an IPv6 form that embeds such an IPv4 address). Any other DNS name is not recognized here; the
 * DNS check (`resolveNavigationTarget`) resolves such names before each main-frame request.
 */
export function isPrivateHost(hostname) {
  const host = bareHost(hostname);
  if (isLocalhostName(host)) return true;
  return isIP(host) ? classifyAddress(host).blocked : false;
}

/** True when `hostname` is an IP literal for a cloud metadata endpoint, in any form `classifyAddress` recognizes. */
export function isCloudMetadataHost(hostname) {
  const host = bareHost(hostname);
  return isIP(host) ? classifyAddress(host).cloudMetadata === true : false;
}

// ---------- Address classification, shared by IP literals and DNS answers ----------
// The DNS check is detection only: the name is resolved before the decision, but Chromium resolves it again when it
// connects. Addresses are not pinned, so a DNS answer that changes between the two lookups (DNS rebinding) is not stopped.

/**
 * Cloud instance metadata endpoints, blocked by exact address in every session, whether or not they fall in a
 * private range: 169.254.169.254 (AWS, Google Cloud, Azure, Oracle Cloud, OpenStack and others), 169.254.170.2
 * (AWS ECS task metadata and credentials), fd00:ec2::254 (AWS IPv6 instance metadata) and 100.100.100.200 (Alibaba Cloud).
 */
export const CLOUD_METADATA_ADDRESSES = Object.freeze(['169.254.169.254', '169.254.170.2', 'fd00:ec2::254', '100.100.100.200']);

/** Upper bound for one DNS lookup. A lookup that has not answered by then counts as failed (`LOOKUP_TIMEOUT`). */
export const DNS_LOOKUP_TIMEOUT_MS = 2000;

// Special-purpose ranges, checked in order. 198.18.0.0/15 (benchmarking) is deliberately absent: fake-IP proxies
// answer every name from it, and blocking it would block every site for their users. Such proxies hide the real
// destination, so this check cannot see where they connect. 255.255.255.255 (broadcast) falls in 240.0.0.0/4.
const ADDRESS_RANGES = [
  ['unspecified', [['0.0.0.0', 8, 'ipv4'], ['::', 128, 'ipv6']]],
  ['loopback', [['127.0.0.0', 8, 'ipv4'], ['::1', 128, 'ipv6']]],
  ['private', [['10.0.0.0', 8, 'ipv4'], ['172.16.0.0', 12, 'ipv4'], ['192.168.0.0', 16, 'ipv4']]],
  ['shared_address_space', [['100.64.0.0', 10, 'ipv4']]],
  ['link_local', [['169.254.0.0', 16, 'ipv4'], ['fe80::', 10, 'ipv6']]],
  ['unique_local', [['fc00::', 7, 'ipv6']]],
  ['site_local', [['fec0::', 10, 'ipv6']]],
  ['multicast', [['224.0.0.0', 4, 'ipv4'], ['ff00::', 8, 'ipv6']]],
  ['reserved', [['240.0.0.0', 4, 'ipv4'], ['192.0.0.0', 24, 'ipv4'], ['192.0.2.0', 24, 'ipv4'], ['198.51.100.0', 24, 'ipv4'],
    ['203.0.113.0', 24, 'ipv4'], ['::', 96, 'ipv6'], ['100::', 64, 'ipv6'], ['2001:db8::', 32, 'ipv6']]],
].map(([category, subnets]) => {
  const list = new BlockList();
  for (const [network, prefix, type] of subnets) list.addSubnet(network, prefix, type);
  return { category, list };
});
const metadataSet = new Set(CLOUD_METADATA_ADDRESSES);
const rangeOf = (address, type) => ADDRESS_RANGES.find(range => range.list.check(address, type))?.category ?? 'public';

/** The 16 bytes of a canonical (URL-serialized, hex-only) IPv6 address. */
function ipv6Bytes(canonical) {
  const [head, tail] = canonical.includes('::') ? canonical.split('::') : [canonical, null];
  const left = head ? head.split(':') : [], right = tail ? tail.split(':') : [];
  const groups = tail === null ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  return groups.flatMap(group => { const value = parseInt(group, 16); return [value >> 8, value & 255]; });
}
const quad = (bytes, at) => bytes.slice(at, at + 4).join('.');
const zero = (bytes, from, to) => bytes.slice(from, to).every(byte => byte === 0);

/**
 * IPv4 addresses embedded in an IPv6 address, in the forms a connection can reach: IPv4-mapped (::ffff:0:0/96),
 * IPv4-translated (::ffff:0:0:0/96), NAT64 well-known (64:ff9b::/96) and local-use (64:ff9b:1::/48, read from
 * the last 32 bits as in a /96 deployment), 6to4 (2002::/16) and Teredo (2001::/32: server and de-obfuscated client).
 */
function embeddedIpv4(canonical) {
  const b = ipv6Bytes(canonical);
  if (zero(b, 0, 10) && b[10] === 255 && b[11] === 255) return [quad(b, 12)];
  if (zero(b, 0, 8) && b[8] === 255 && b[9] === 255 && zero(b, 10, 12)) return [quad(b, 12)];
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && (zero(b, 4, 12) || (b[4] === 0 && b[5] === 1))) return [quad(b, 12)];
  if (b[0] === 0x20 && b[1] === 0x02) return [quad(b, 2)];
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0 && b[3] === 0) return [quad(b, 4), b.slice(12, 16).map(byte => byte ^ 255).join('.')];
  return [];
}

/**
 * Classify one address, from an IP literal or a DNS answer. `category` is `public` or the special-purpose range it
 * falls in; an IPv6 address that embeds IPv4 (`embeddedIpv4`) takes the category of a non-public embedded address.
 * `blocked` means "not public": every non-public category, a cloud metadata address and a value that is not an IP
 * address. Whether that blocks a request depends on the session (see `resolveNavigationTarget`).
 */
export function classifyAddress(value) {
  const raw = typeof value === 'string' ? value.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '') : '';
  const family = isIP(raw);
  if (!family) return { address: String(value ?? '').slice(0, 64), family: null, category: 'invalid', blocked: true };
  const address = family === 6 ? new URL(`http://[${raw}]/`).hostname.slice(1, -1) : raw;
  let category = rangeOf(address, family === 4 ? 'ipv4' : 'ipv6'), embedded = null;
  if (family === 6) {
    const inner = embeddedIpv4(address).map(item => ({ item, category: rangeOf(item, 'ipv4') }));
    const chosen = inner.find(entry => entry.category !== 'public' || metadataSet.has(entry.item)) ?? inner[0];
    if (chosen) { embedded = chosen.item; if (category === 'public') category = chosen.category; }
  }
  const cloudMetadata = metadataSet.has(address) || (embedded !== null && metadataSet.has(embedded));
  return { address, family, category, ...(embedded ? { embeddedIpv4: embedded } : {}), ...(cloudMetadata ? { cloudMetadata: true } : {}),
    blocked: category !== 'public' || cloudMetadata };
}

/** The default resolver: the operating system's resolver through `dns.lookup`, every address in the order returned. */
export const systemHostResolver = Object.freeze({ name: 'system', lookup: hostname => lookup(hostname, { all: true, order: 'verbatim' }) });

/**
 * The hostname a main-frame request to `url` resolves before it is allowed, or null. IP literals and `localhost` names
 * are classified as literals in `decideNavigation`; non-http(s) URLs are not resolved. Every live session resolves:
 * a public session to apply the private-network floor, a private one to apply the cloud metadata floor.
 */
export function resolutionHost(url) {
  const target = parse(url);
  if (!target || !['http:', 'https:'].includes(target.protocol)) return null;
  const host = bareHost(target.hostname);
  return isIP(host) || isLocalhostName(host) ? null : target.hostname;
}

/** `resolver.lookup(host)` bounded by `timeoutMs`; a late answer is ignored. */
async function boundedLookup(resolver, host, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => resolver.lookup(host)),
      // Necessary timer: a real upper bound on a lookup the resolver cannot cancel. Cleared in `finally`.
      new Promise((_resolve, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('DNS lookup timed out.'), { code: 'LOOKUP_TIMEOUT' })), Math.max(1, timeoutMs)); }),
    ]);
  } finally { clearTimeout(timer); }
}

/**
 * Resolve the target of an otherwise allowed main-frame request. A cloud metadata address in the answer denies it in
 * every session; in a public session any other non-public address denies it too (`private_network_target`, not
 * overridable). A lookup that fails, times out (`DNS_LOOKUP_TIMEOUT_MS`) or returns nothing does not deny: the request
 * continues on the literal-only check and the result is marked `degraded` with `resolution.error`. Every result that
 * performed a lookup carries the structured `resolution` record. `resolver` is `{ name, lookup(hostname) }` returning
 * `[{ address, family }]` (or address strings).
 */
export async function resolveNavigationTarget({ url, policy, resolver = systemHostResolver, timeoutMs = DNS_LOOKUP_TIMEOUT_MS }) {
  const host = resolutionHost(url);
  if (!host) return { allowed: true };
  const base = { host, resolver: typeof resolver?.name === 'string' && resolver.name ? resolver.name : 'injected' };
  const degraded = error => ({ allowed: true, degraded: true, resolution: { ...base, addresses: [], error } });
  let answers;
  try { answers = await boundedLookup(resolver, host, timeoutMs); }
  catch (error) { return degraded(typeof error?.code === 'string' && error.code ? error.code : 'LOOKUP_FAILED'); }
  if (!Array.isArray(answers) || answers.length === 0) return degraded('NO_ADDRESSES');
  const addresses = answers.map(answer => classifyAddress(typeof answer === 'string' ? answer : answer?.address));
  const cloudMetadata = addresses.some(item => item.cloudMetadata);
  const resolution = { ...base, addresses, ...(cloudMetadata ? { cloudMetadata: true } : {}) };
  if (cloudMetadata || (policy?.publicSession && addresses.some(item => item.blocked))) return { allowed: false, reason: 'private_network_target', overridable: false, resolution };
  return { allowed: true, resolution };
}

/**
 * The session type decided from the start URL's own DNS answer, and the decision for that start hop. The start URL is
 * the caller's chosen target, so a name that resolves to a non-public address makes the session private (an internal
 * or staging host) instead of being refused; a cloud metadata answer still refuses it. When the lookup degrades, the
 * literal-only classification stands (a DNS name is public), so the public-to-private floor stays in force.
 */
export function startSession(screened, policy) {
  const literal = policy.publicSession ? 'public' : 'private';
  if (!screened?.resolution) return { decision: screened, session: { type: literal, basis: 'literal' } };
  const { resolution } = screened;
  if (screened.degraded) return { decision: screened, session: { type: literal, basis: 'literal_fallback', resolution } };
  if (resolution.cloudMetadata) return { decision: screened, session: { type: literal, basis: 'resolution', resolution } };
  const nonPublic = resolution.addresses.some(item => item.blocked);
  return { decision: { allowed: true, resolution }, session: { type: nonPublic ? 'private' : 'public', basis: 'resolution', resolution } };
}

/** The bounded `resolution` record carried in block details: at most 16 addresses, clipped strings, known keys only. */
function boundResolution(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const text = (item, limit) => typeof item === 'string' ? item.slice(0, limit) : undefined;
  const addresses = Array.isArray(value.addresses) ? value.addresses : [];
  // A record that was already bounded keeps its earlier omission count.
  const omitted = Math.max(0, addresses.length - ADDRESS_LIMIT) + (Number.isSafeInteger(value.addressesOmitted) && value.addressesOmitted > 0 ? value.addressesOmitted : 0);
  const entry = item => Object.fromEntries(Object.entries({ address: text(item?.address, 64), family: [4, 6].includes(item?.family) ? item.family : null,
    category: text(item?.category, 32), embeddedIpv4: text(item?.embeddedIpv4, 15), cloudMetadata: item?.cloudMetadata === true ? true : undefined,
    blocked: typeof item?.blocked === 'boolean' ? item.blocked : undefined }).filter(([, field]) => field !== undefined));
  return Object.fromEntries(Object.entries({
    host: text(value.host, HOST_LIMIT), resolver: text(value.resolver, 64),
    addresses: addresses.slice(0, ADDRESS_LIMIT).map(entry),
    addressesOmitted: omitted > 0 ? omitted : undefined,
    cloudMetadata: value.cloudMetadata === true ? true : undefined,
    error: text(value.error, ERROR_CODE_LIMIT),
  }).filter(([, field]) => field !== undefined));
}

const FAILURE_LIMIT = 8;
export const DNS_DEGRADED_NOTE = 'At least one DNS lookup failed or timed out, so those requests were allowed on the IP-literal and localhost-name check only. A DNS name that reaches a private address may not have been detected. This is common behind a proxy that resolves names itself, or offline.';
const SESSION_TYPES = ['public', 'private'], SESSION_BASES = ['literal', 'resolution', 'literal_fallback'];

/**
 * The bounded, additive DNS check summary for one session, used in the navigation report, JSONL and MCP. `status` is
 * `checked` (every lookup answered), `degraded` (at least one lookup failed or timed out; see `failures`), `not_used`
 * (no DNS name was looked up) or `not_applicable` (network replay sends no requests). `session` records how the
 * session type was decided: from the start URL literal, from its DNS answer, or from the literal after that lookup failed.
 */
export function dnsCheckSummary({ replay = false, session, lookups = 0, failures = [], failureCount = failures.length } = {}) {
  const status = replay ? 'not_applicable' : failureCount > 0 ? 'degraded' : lookups > 0 ? 'checked' : 'not_used';
  const text = (value, limit) => typeof value === 'string' ? value.slice(0, limit) : null;
  const kept = failures.slice(0, FAILURE_LIMIT).map(item => ({ stage: text(item?.stage, 64), host: text(item?.host, HOST_LIMIT), error: text(item?.error, ERROR_CODE_LIMIT) }));
  return {
    status,
    session: { type: SESSION_TYPES.includes(session?.type) ? session.type : 'public', basis: SESSION_BASES.includes(session?.basis) ? session.basis : 'literal',
      ...(session?.resolution ? { resolution: boundResolution(session.resolution) } : {}) },
    lookups, failedLookups: failureCount,
    ...(failureCount > 0 ? { failures: kept, ...(failureCount > kept.length ? { failuresOmitted: failureCount - kept.length } : {}), note: DNS_DEGRADED_NOTE } : {}),
  };
}

const defaultPort = url => url.port === '' || (url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443');

/** http://host[:80] -> https://host[:443] on the identical hostname. */
export function isHttpsUpgrade(from, to) {
  return from.protocol === 'http:' && to.protocol === 'https:' && from.hostname === to.hostname && defaultPort(from) && defaultPort(to);
}

/** Normalized policy for one browser session. */
export function navigationPolicy(manifest) {
  const manifestUrl = new URL(manifest.url);
  const allowedOrigins = [...new Set((manifest.allowedOrigins ?? []).map(origin => canonicalOrigin(origin) ?? origin))];
  return Object.freeze({
    version: NAVIGATION_POLICY_VERSION,
    followRedirects: manifest.followRedirects === true,
    allowedOrigins: Object.freeze(allowedOrigins),
    maxRedirects: manifest.followRedirects === true ? MAX_REDIRECTS : null,
    manifestOrigin: manifestUrl.origin,
    publicSession: !isPrivateHost(manifestUrl.hostname),
  });
}

/**
 * Decide one main-frame request. `previousUrl` is set only for a redirect hop; `redirects` counts the
 * redirects in this navigation including this hop. `sessionOrigins` is the current allowed origin set.
 */
export function decideNavigation({ url, previousUrl = null, redirects = 0, policy, sessionOrigins }) {
  const target = parse(url);
  const deny = (reason, overridable = false) => ({ allowed: false, reason, overridable });
  if (!target) return deny('invalid_url');
  if (!['http:', 'https:'].includes(target.protocol)) return deny('non_http_scheme');
  if (target.username || target.password) return deny('credentials_in_url');
  const previous = previousUrl === null ? null : parse(previousUrl);
  if (previous?.protocol === 'https:' && target.protocol === 'http:') return deny('scheme_downgrade');
  if (isCloudMetadataHost(target.hostname) || (policy.publicSession && isPrivateHost(target.hostname))) return deny('private_network_target');
  if (previous && policy.followRedirects && redirects > MAX_REDIRECTS) return deny('redirect_limit');
  if (!previous) return sessionOrigins.has(target.origin) ? { allowed: true } : deny('cross_origin_navigation', true);
  if (previous.origin === target.origin) return { allowed: true };
  if (!policy.followRedirects) return deny('cross_origin_redirect', true);
  if (sessionOrigins.has(target.origin) || isHttpsUpgrade(previous, target)) return { allowed: true };
  return deny('cross_origin_redirect', true);
}

const NOTES = {
  invalid_url: 'The navigation URL could not be parsed. This is a safety floor; no manifest field changes it.',
  non_http_scheme: 'Only http: and https: main-document navigation is supported. This is a safety floor.',
  credentials_in_url: 'URLs with a username or password are never followed. This is a safety floor; do not add credentials to the manifest.',
  scheme_downgrade: 'An HTTPS-to-HTTP redirect is never followed. This is a safety floor.',
  private_network_target: 'The browser never loads a cloud metadata address, and a public session never loads a loopback, private, link-local or other non-public address, whether written as an IP literal or reached through a DNS name. This is a safety floor.',
  redirect_limit: `Redirect chains longer than ${MAX_REDIRECTS} hops are not followed. This is a safety floor; start from a URL closer to the final page.`,
};

/** Advisory next step. The calling agent decides; floor reasons always say stop. */
function suggestion({ reason, overridable, blockedUrl, initial, policy }) {
  if (!overridable) return { primary: { kind: 'stop', note: NOTES[reason] } };
  const origin = parse(blockedUrl)?.origin ?? null;
  const allowedOrigins = [...new Set([...policy.allowedOrigins, ...(origin ? [origin] : [])])];
  const declare = { kind: 'declare_origin', origin,
    manifestPatch: reason === 'cross_origin_redirect' ? { followRedirects: true, allowedOrigins } : { allowedOrigins },
    note: 'Merge manifestPatch into the manifest and start again, but only if you are authorized to audit this origin. The patch widens where the browser may navigate, and the report records it.' };
  if (reason === 'cross_origin_redirect' && initial) {
    return { primary: { kind: 'use_url', url: clipUrl(blockedUrl), origin,
      note: 'Set manifest url to this URL and start again, if you are authorized to audit it. The new URL may redirect again; repeat at most a few times.' }, alternative: declare };
  }
  return { primary: declare };
}

/**
 * The structured AUDIT_NAVIGATION_BLOCKED details: from/blocked URL, the hop chain, the reason, the
 * policy in force and an advisory suggestedAction an agent can apply without parsing prose.
 */
export function navigationBlockDetails({ reason, overridable, fromUrl, blockedUrl, chain, policy, sessionOrigins, stage, initial = false, resolution }) {
  const { primary, alternative } = suggestion({ reason, overridable, blockedUrl, initial, policy });
  const hops = (chain ?? []).slice(-CHAIN_LIMIT).map(hop => ({ url: clipUrl(hop.url), status: hop.status ?? null, ...(hop.blocked ? { blocked: true } : {}) }));
  return {
    code: NAVIGATION_BLOCK_CODE, stage, fromUrl: clipUrl(fromUrl), blockedUrl: clipUrl(blockedUrl), redirectChain: hops,
    ...((chain?.length ?? 0) > CHAIN_LIMIT ? { redirectChainOmitted: chain.length - CHAIN_LIMIT } : {}),
    reason, overridable,
    ...(resolution ? { resolution: boundResolution(resolution) } : {}),
    policy: { followRedirects: policy.followRedirects, allowedOrigins: [...policy.allowedOrigins], maxRedirects: policy.maxRedirects, sessionOrigins: [...sessionOrigins] },
    suggestedAction: primary,
    ...(alternative ? { alternativeAction: alternative } : {}),
  };
}

/**
 * Attach the structured payload to an error without changing its code, message or details, so callers that
 * branch on 0.1.1 codes keep working. `errorRecord` (CLI JSON) and `errorPayload` (JSONL/MCP) copy it as
 * `navigation`.
 */
export function withNavigation(error, navigation) {
  if (error && typeof error === 'object' && navigation) error.navigation = navigation;
  return error;
}

/** Bounded copy of a `navigation` payload for agent/MCP responses (drops unknown keys). */
export function boundNavigationDetails(details) {
  if (!details || typeof details !== 'object' || Array.isArray(details) || typeof details.reason !== 'string') return null;
  const pick = (value, keys) => value && typeof value === 'object' ? Object.fromEntries(keys.filter(key => value[key] !== undefined).map(key => [key, value[key]])) : undefined;
  const action = value => pick(value, ['kind', 'url', 'origin', 'manifestPatch', 'note']);
  return {
    ...pick(details, ['code', 'stage', 'fromUrl', 'blockedUrl', 'reason', 'overridable', 'redirectChainOmitted', 'reportPath']),
    redirectChain: Array.isArray(details.redirectChain) ? details.redirectChain.slice(-CHAIN_LIMIT).map(hop => pick(hop, ['url', 'status', 'blocked'])) : [],
    ...(details.resolution ? { resolution: boundResolution(details.resolution) } : {}),
    ...(details.policy ? { policy: pick(details.policy, ['followRedirects', 'allowedOrigins', 'maxRedirects', 'sessionOrigins']) } : {}),
    ...(details.suggestedAction ? { suggestedAction: action(details.suggestedAction) } : {}),
    ...(details.alternativeAction ? { alternativeAction: action(details.alternativeAction) } : {}),
  };
}
