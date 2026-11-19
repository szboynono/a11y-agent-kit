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
export const FLOOR_REASONS = Object.freeze(['invalid_url', 'non_http_scheme', 'credentials_in_url', 'scheme_downgrade', 'private_network_target', 'target_resolution_failed', 'redirect_limit']);
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

function ipv4Private(address) {
  const [a, b] = address.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * Loopback, private, link-local or unspecified address, or a `localhost` name. Only literals and `localhost`
 * names are recognized here; any other DNS name is treated as public. A public session additionally resolves
 * such names before each main-frame request (`resolveNavigationTarget`).
 */
export function isPrivateHost(hostname) {
  const host = String(hostname ?? '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  const family = isIP(host);
  if (family === 4) return ipv4Private(host);
  if (family === 6) {
    if (host === '::' || host === '::1') return true;
    const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return ipv4Private(mapped[1]);
    if (/^::ffff:[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(host)) {
      const [hi, lo] = host.slice(7).split(':').map(part => parseInt(part, 16));
      return ipv4Private([hi >> 8, hi & 255, lo >> 8, lo & 255].join('.'));
    }
    return /^f[cd]/.test(host) || /^fe[89ab]/.test(host);
  }
  return false;
}

// ---------- DNS check for main-frame targets in a public session ----------
// Detection only: the name is resolved before the decision, but Chromium resolves it again when it connects.
// Addresses are not pinned, so a DNS answer that changes between the two lookups (DNS rebinding) is not stopped.

/**
 * Cloud instance metadata endpoints, blocked by exact address whether or not they fall in a private range:
 * 169.254.169.254 (AWS, Google Cloud, Azure, Oracle Cloud, OpenStack and others), 169.254.170.2 (AWS ECS task
 * metadata and credentials), fd00:ec2::254 (AWS IPv6 instance metadata) and 100.100.100.200 (Alibaba Cloud).
 */
export const CLOUD_METADATA_ADDRESSES = Object.freeze(['169.254.169.254', '169.254.170.2', 'fd00:ec2::254', '100.100.100.200']);

// Ranges a public site's DNS name may not resolve into, checked in order. 198.18.0.0/15 (benchmarking) is
// deliberately absent: fake-IP proxies answer every name from it, and blocking it would block every site for
// their users. Such proxies hide the real destination, so this check cannot see where they connect.
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

/** IPv4 embedded in an IPv4-mapped (::ffff:0:0/96) or NAT64 well-known-prefix (64:ff9b::/96) IPv6 address. */
function embeddedIpv4(canonical) {
  const match = canonical.match(/^(?:::ffff|64:ff9b:):(?:([0-9a-f]{1,4}):)?([0-9a-f]{1,4})$/);
  if (!match) return null;
  const hi = parseInt(match[1] ?? '0', 16), lo = parseInt(match[2], 16);
  return [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');
}

/**
 * Classify one resolved address. `category` is `public` or the special-purpose range it falls in; an
 * IPv4-mapped or NAT64 IPv6 address is classified by its embedded IPv4 address (`embeddedIpv4`). Every
 * non-public category, a cloud metadata address and a value that is not an IP address are `blocked`.
 */
export function classifyAddress(value) {
  const raw = typeof value === 'string' ? value.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '') : '';
  const family = isIP(raw);
  if (!family) return { address: String(value ?? '').slice(0, 64), family: null, category: 'invalid', blocked: true };
  const address = family === 6 ? new URL(`http://[${raw}]/`).hostname.slice(1, -1) : raw;
  const embedded = family === 6 ? embeddedIpv4(address) : null;
  const [checked, type] = embedded ? [embedded, 'ipv4'] : [address, family === 4 ? 'ipv4' : 'ipv6'];
  const category = ADDRESS_RANGES.find(range => range.list.check(checked, type))?.category ?? 'public';
  const cloudMetadata = metadataSet.has(address) || metadataSet.has(checked);
  return { address, family, category, ...(embedded ? { embeddedIpv4: embedded } : {}), ...(cloudMetadata ? { cloudMetadata: true } : {}),
    blocked: category !== 'public' || cloudMetadata };
}

/** The default resolver: the operating system's resolver through `dns.lookup`, every address in the order returned. */
export const systemHostResolver = Object.freeze({ name: 'system', lookup: hostname => lookup(hostname, { all: true, order: 'verbatim' }) });

/**
 * The hostname a public session must resolve before `url` is allowed, or null. IP literals and `localhost` names
 * keep the literal-only check in `decideNavigation`; private sessions and non-http(s) URLs are not resolved.
 */
export function resolutionHost(url, policy) {
  const target = parse(url);
  if (!policy?.publicSession || !target || !['http:', 'https:'].includes(target.protocol)) return null;
  const host = target.hostname.replace(/^\[|\]$/g, '');
  return isIP(host) || isPrivateHost(host) ? null : target.hostname;
}

/**
 * Resolve the target of an otherwise allowed main-frame request in a public session. Any resolved address that
 * is not public denies the request with the `private_network_target` floor; a failed lookup or an empty answer
 * denies it with `target_resolution_failed` (fail-closed). Both carry the structured `resolution` record.
 * `resolver` is `{ name, lookup(hostname) }` returning `[{ address, family }]` (or address strings).
 */
export async function resolveNavigationTarget({ url, policy, resolver = systemHostResolver }) {
  const host = resolutionHost(url, policy);
  if (!host) return { allowed: true };
  const base = { host, resolver: typeof resolver?.name === 'string' && resolver.name ? resolver.name : 'injected' };
  const failed = error => ({ allowed: false, reason: 'target_resolution_failed', overridable: false, resolution: { ...base, addresses: [], error } });
  let answers;
  try { answers = await resolver.lookup(host); }
  catch (error) { return failed(typeof error?.code === 'string' && error.code ? error.code : 'LOOKUP_FAILED'); }
  if (!Array.isArray(answers) || answers.length === 0) return failed('NO_ADDRESSES');
  const addresses = answers.map(answer => classifyAddress(typeof answer === 'string' ? answer : answer?.address));
  const resolution = { ...base, addresses, ...(addresses.some(item => item.cloudMetadata) ? { cloudMetadata: true } : {}) };
  return addresses.some(item => item.blocked) ? { allowed: false, reason: 'private_network_target', overridable: false, resolution } : { allowed: true, resolution };
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
  if (policy.publicSession && isPrivateHost(target.hostname)) return deny('private_network_target');
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
  private_network_target: 'A public site may not redirect or navigate the browser to a loopback, private, link-local or cloud metadata address, written as a literal or reached through a DNS name. This is a safety floor.',
  target_resolution_failed: 'The target host name could not be resolved, so its addresses could not be checked. A public session does not navigate to a name it cannot check. This is a safety floor.',
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
