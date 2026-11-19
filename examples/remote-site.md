# Audit a site you are authorized to test

The kit audits any HTTP(S) site that you own or have permission to test, not only an app on `localhost`. This guide covers a deployed or third-party site: a staging URL, a production site, or a public page your organization has approved for testing.

Audit only sites you own or are authorized to test. Check the site's terms of service and your organization's policy before you run an automated browser against it.

## 1. Use an empty workspace as `projectRoot`

A remote site has no source tree on your machine. Create a dedicated, empty workspace directory and use its canonical path as `projectRoot`. Do not use the repository you happen to have open: the kit fingerprints the files under `projectRoot` (it skips `evidence/`, `.git`, `node_modules` and common build output directories), so an unrelated repository makes collection slow and makes `audit-check` report `expired` after any edit.

```sh
npx -y playwright@1.64.1 install chromium
mkdir -p "$HOME/a11y-audits/example-site/evidence"
cd "$HOME/a11y-audits/example-site"
```

Keep the manifest, findings and reports under `evidence/`. Do not add other files to the workspace root, or `audit-check` turns `expired` and `audit-review` refuses the audit.

## 2. Resolve the canonical start URL first

Many public sites redirect their entry URL, for example from `http://` to `https://`, or from `example.com` to `www.example.com`. By default the browser keeps main-document navigation on the manifest origin and blocks a redirect to another origin. Resolve the final URL before writing the manifest, with a bounded number of redirects:

```sh
curl -sSIL --max-redirs 5 -o /dev/null -w '%{url_effective}\n' https://example.com/
```

If the server refuses `HEAD` requests, drop `-I`. Use the printed URL as `url`. Your shell client and headless Chromium can be redirected differently (user agent, cookies, location), so the kit still records its own redirect chain, and a resolved URL can still be blocked. Section 4 explains how to read that.

## 3. Write the manifest

```json
{
  "projectRoot": "/absolute/path/to/a11y-audits/example-site",
  "url": "https://www.example.com/"
}
```

Save it as `evidence/audit-manifest.json` (see [audit-manifest-remote.json](audit-manifest-remote.json)). Run a bounded sample, or start an agent session as in the [README](../README.md#audit-a-site-you-are-authorized-to-test):

```sh
npx -y a11y-agent-kit@0.1.1 audit evidence/audit-manifest.json --summary
```

## 4. Same origin, declared origins and blocked navigation

Main-document navigation, including every redirect hop, stays on the manifest origin. Subresources such as CDNs, fonts and analytics load normally; only the main document is guarded. The kit does not crawl a site. It audits the pages and states your agent visits within the session budget.

The source tree (not npm 0.1.1) adds two optional manifest fields. npm 0.1.1 rejects unknown manifest fields, so with 0.1.1 use the resolved URL from step 2 instead.

- `allowedOrigins`: extra exact origins, such as `["https://www.example.com"]`, that the main document may navigate to. List only origins you are authorized to audit. Write each entry as `scheme://host[:port]` with no path (not even a trailing slash), query, fragment or credentials. Letter case, a default port (`:443`, `:80`) and a Unicode hostname are normalized to the canonical origin; the report and `suggestedAction` always use the canonical form.
- `followRedirects`: `true` follows a main-document redirect to the manifest origin or an `allowedOrigins` entry, and a same-host `http` to `https` upgrade, for at most 5 hops. Omitted or `false` keeps the original rule: redirects must stay on the same origin.

```json
{
  "projectRoot": "/absolute/path/to/a11y-audits/example-site",
  "url": "https://example.com/",
  "followRedirects": true,
  "allowedOrigins": ["https://www.example.com"]
}
```

When the start URL redirects to another origin, later `navigate` actions resolve against the landed URL and `reset` returns to the landed URL. They do not go back through the original redirect. This applies only when the start lands on an `http(s)` page on the origin of the last followed redirect hop; if a page script leaves for `about:blank` or similar, `navigate` and `reset` keep using the declared `url`.

A `navigate` action in a manifest may use an absolute URL on the manifest origin or an `allowedOrigins` entry. With `followRedirects`, the schema also accepts the same-host `https` origin of a declared `http` origin (the only other origin a start can land on); at run time such a `navigate` is allowed only if the start actually landed there.

These are always blocked, and no manifest field changes them: URLs with a username or password, HTTPS-to-HTTP redirects, redirect chains longer than 5 hops when `followRedirects` is on, and redirects or navigation from a public site to a loopback, private, link-local or cloud metadata address. Whether the session counts as public is decided from the manifest host: it is public unless that host is an IP literal in a private range or a `localhost` name.

In a public session, the host name of every main-frame request (the start URL, each `navigate`, a navigation started by a click or other action, and every redirect hop) is resolved with the operating system resolver before the request is allowed. The request is blocked with `private_network_target` if any returned address, not only the first, is unspecified, loopback, private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), shared address space (`100.64.0.0/10`), link-local, IPv6 unique-local or site-local, multicast or reserved, including the IPv4-mapped and NAT64 forms of those IPv4 addresses. Cloud metadata endpoints are listed separately and blocked by exact address: `169.254.169.254`, `169.254.170.2`, `fd00:ec2::254` and `100.100.100.200`. If the lookup fails or returns no address, the request is blocked with `target_resolution_failed`; it is not allowed through unchecked. Both reasons are not overridable. This includes the start URL: a host name such as `staging.internal` that resolves to a private address cannot be audited as a public site. To audit it, use its IP literal or a `localhost` name in `url`, which makes the session private.

The check is detection only. Chromium resolves the name again when it connects, and the checked addresses are not pinned, so a DNS answer that changes between the two lookups (DNS rebinding) is not stopped. A local proxy or resolver that returns synthetic addresses for every name, such as a fake-IP proxy, hides the real destination from the check. IP literals and `localhost` names are checked as before, without a lookup. Private sessions and network-replay sessions resolve nothing. Subresource requests and iframe documents are still outside the navigation policy.

In the source tree, a blocked navigation keeps the error code and `details` that npm 0.1.1 returns, and adds a structured `navigation` field next to them. This is additive: no code is renamed and no existing field moves. `navigation` is present in CLI JSON (`errors[]`), JSONL and MCP. In the JSONL and MCP `read` summary of an action record, `error` keeps only its 0.1.1 keys, inlined or deferred by the same 1 KiB rule as in 0.1.1, and the payload is a separate `errorNavigation` field in the same response (a deferred handle only above 4 KiB); a `read` of the field `/error` returns the error together with `navigation`. The handle's `serializedBytes` counts `navigation` alone; the `/error` read it points to also returns the 0.1.1 keys, so it is larger. `navigation` has:

- `code`: always `AUDIT_NAVIGATION_BLOCKED`;
- `stage`, `fromUrl`, `blockedUrl` and `redirectChain`, with each hop's URL and HTTP status;
- `reason`, such as `cross_origin_redirect`, `cross_origin_navigation`, `scheme_downgrade`, `credentials_in_url`, `private_network_target`, `target_resolution_failed` or `redirect_limit`;
- `overridable` and `policy`;
- `resolution`, only when a DNS lookup decided the block: `host`, `resolver` (`system` for the operating system resolver), up to 16 `addresses` (each with `address`, `family`, `category`, `blocked`, and `cloudMetadata` or `embeddedIpv4` when they apply), `addressesOmitted` beyond 16, `cloudMetadata: true` when a metadata address was returned, and `error` (a lookup error code such as `ENOTFOUND`, or `NO_ADDRESSES`) when the lookup failed;
- `suggestedAction` (and sometimes `alternativeAction`), with `kind` set to `use_url` (with `url`), `declare_origin` (with a `manifestPatch` to merge into the manifest) or `stop`;
- `reportPath` when a live or agent session failed to start.

| Where the block happens | Code and `details` (as npm 0.1.1 returns them, where 0.1.1 can reach the case) | Added in the source tree |
|---|---|---|
| CLI `audit`, start URL | `errors[]` entry `RUNTIME_ERROR` with `stage: "audit-browser-start"` and no `details`, plus `AUDIT_UNSUPPORTED_EVENT` with `details: {reason: "navigation_outside_origin", url}` | `navigation` on both entries |
| `audit-agent`, `audit-live` or MCP `a11y_audit_start`, start URL | `AUDIT_SESSION_START_FAILED` with `details: {reportPath}` (MCP returns only `code` and `message`, as in 0.1.1) | `navigation`, including `reportPath` |
| A click or other action during a session | action error `AUDIT_BROWSER_ACTION_BLOCKED` with `details` as an array of `{reason, url}` events | `navigation` on the action error |
| A `navigate` action whose redirect is blocked | action error `RUNTIME_ERROR` | `navigation` on the action error |
| A `navigate` action to an origin the manifest does not allow | rejected while the manifest or step is validated: `INVALID_AUDIT_MANIFEST` (in CLI `details`, the issue path is `actions.N.path`); a JSONL or MCP `step` returns it with no record | nothing: no record and no `navigation`; to allow the origin, add it to `allowedOrigins` |
| A `navigate` action that validation accepts but the run-time check rejects: with `followRedirects`, the `https` upgrade of a declared `http` origin when the start did not land there; from a public site, a declared origin written as a private IP literal or `localhost` name, or whose host name resolves to a non-public address or cannot be resolved | action error `UNSAFE_AUDIT_NAVIGATION`, the code 0.1.1 uses for its run-time check (except for a manifest-origin name whose DNS answer changes during the session, these targets need the new manifest fields, so a 0.1.1 manifest does not reach this row) | `navigation` on the action error |

Read only `navigation` to decide the next step; the 0.1.1 code and `details` remain for callers that already branch on them. URLs recorded in `details` have any username or password replaced with `redacted`.

A suggestion is advisory. Apply it only if you are authorized to audit the new URL or origin. When `overridable` is `false`, stop that path and report it. npm 0.1.1 returns the codes in the table without `navigation`.

## 5. Bot protection, sign-in and headless browsers

The kit does not bypass bot protection, CAPTCHAs or sign-in, and has no credential, cookie or user-agent input. A 403, a challenge page or a sign-in redirect is reported as-is: as `HTTP_ERROR`, as a blocked navigation, or as a normal-looking page that is really an interstitial. Check the first screenshot and snapshot before treating the results as the site's content. Headless Chromium may be served different content than a regular browser.

## 6. Production sites

On production sites, avoid actions with side effects: submitting forms, adding to carts, sending messages or changing account settings. Keyboard and focus handlers can also trigger requests, so leave `startupSweep` off unless that is acceptable. A `reset` reloads the page but cannot undo server-side effects.

## 7. Reading the report

The HTML header's **Page** row shows the URL the browser landed on. When it differs from the declared `url`, a **Declared URL** row shows the declared URL and the number of redirect hops. The report JSON's `navigation` field records the declared URL, every main-document hop and the final URL.

The **URL binding** row and `applicationBinding: "caller-declared"` say that the caller declares the URL serves `projectRoot`. For a remote site, `projectRoot` is your workspace, not the site's source. The source fingerprint and `audit-check: current` say that the workspace and evidence are unchanged, not that the live site is unchanged.

Results describe the states that were observed. They are not a conformance verdict for the page or site. An audit of a third-party site is not evidence that this kit has been validated on real sites; that validation remains open (see the [publication boundary](../docs/publication-boundary.md)).
