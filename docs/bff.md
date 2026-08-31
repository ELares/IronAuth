# Browser-based apps: which architecture, and why

The OAuth 2.0 for Browser-Based Apps BCP (draft-ietf-oauth-browser-based-apps) ranks three
architectures. IronAuth ships the first one and documents the other two honestly, because a
ranking without the tradeoffs is a slogan.

## The ranking

### 1. Backend-for-frontend (BFF) — what to build

A server-side component in the same origin as the frontend holds every token. The browser holds
one `__Host-` prefixed, `HttpOnly`, `Secure`, `SameSite` cookie carrying an opaque session id.
API calls go through the BFF, which attaches the access token and refreshes it server-side.

**What you get:** no token is ever reachable from JavaScript, so an XSS that runs in your page
cannot exfiltrate a credential that outlives the page. Refresh tokens never touch the browser.
Revocation is immediate, because the session is a database row.

**What it costs:** you run a server. Every API call is a hop through it, which is latency and a
scaling component you now own. A purely static frontend cannot use this pattern.

`@ironauth/bff` implements it: five handler groups (login, callback, logout, userinfo, proxy),
framework-agnostic, with adapters for `Request -> Response` runtimes and for the `(req, res)`
shape Express and `node:http` share.

### 2. Token-mediating backend — acceptable

A backend holds the refresh token and hands the browser short-lived access tokens.

**What you get:** the refresh token, which is the long-lived credential, stays off the browser.
Fewer hops than a BFF, because API calls go direct.

**What it costs:** the access token IS in the browser, so an XSS can take it and use it until it
expires. You are trading a bounded exposure for the latency. That is a real trade and it can be
the right one; it is second rather than first because the exposure is not zero.

### 3. Browser-held tokens — last, and only with mitigations

The browser holds both tokens.

**What you get:** no server component at all.

**What it costs:** an XSS takes everything, including the refresh token, and keeps it after the
user closes the tab. If you must, then **both** of these, not one:

- **DPoP** (RFC 9449), so a stolen token is useless without the private key; and
- **refresh token rotation** with reuse detection, so a stolen refresh token is detectable and
  the family is killed on replay.

IronAuth's DPoP support is tracked separately; refresh rotation with reuse detection is already
how its refresh families work.

## Token storage in the browser

**There is no supported way to store a token in `localStorage`.** It is readable by any script on
the origin, it survives the tab, and it is the single most common way a browser app's credentials
end up in an attacker's hands.

This is not a recommendation against it. It is the absence of a recommendation for it: no
IronAuth document describes how to do it, and `scripts/bff-docs.sh` fails the build if one starts
to. Where a token must live in a browser at all, it lives in memory for the lifetime of the page
and is re-obtained after a reload.

## What the BFF cookie is, exactly

One cookie. `__Host-ironauth_bff`, holding an opaque 256-bit id and nothing else.

| Attribute | Value | Why |
|---|---|---|
| `__Host-` prefix | required | RFC 6265bis: pins `Path=/`, requires `Secure`, and forbids `Domain` -- so a sibling subdomain cannot set your session cookie |
| `HttpOnly` | set | script cannot read it, which is the whole point |
| `Secure` | set | and implied by the prefix |
| `SameSite` | `Lax` | `Strict` withholds the cookie on the top-level redirect back from the authorization server, so a `Strict` session cookie makes the login loop forever. `Lax` still withholds it from cross-site POSTs |
| `Domain` | never set | see the prefix |

**The attributes are not configurable.** A knob that turns one off turns the architecture into
the one ranked last while the package still calls itself a BFF.

### The cookie budget

Total auth cookie bytes stay under **4096**, and a regression test fails the build if they do not.
The number is a ceiling on a *design*, not a tuning knob: an opaque id is a few dozen bytes, so
the only way to approach it is to start putting claims or tokens in cookies -- the chunked
multi-kilobyte encrypted cookie design the BCP warns about.

The test asserts the cookie **count** as well as the size, because that design shows up as a
second cookie named `...1` before it shows up as bytes.

## CSRF

State-changing BFF endpoints require a custom header (`X-IronAuth-BFF`). Any value; the presence
is what matters.

A cross-site form post or image load **cannot** set a custom header -- doing so makes the request
non-simple and forces a CORS preflight the attacker's origin will not pass. `SameSite=Lax` is the
first line; this is the second, because Lax still admits top-level GET navigations and browsers
have differed on what counts.

## Failure handling

Every handler returns a typed result rather than throwing or returning a bare status:

| Result | Means | Typical mapping |
|---|---|---|
| `redirect` | go here, and set this cookie | 302 |
| `json` | a body for the frontend | 200 |
| `proxied` | the upstream's own response | pass through |
| `unauthenticated` | `no_session`, `session_expired`, or `refresh_failed` | 401 for an XHR, a redirect to login for a page |
| `refused` | `csrf`, `bad_state`, `missing_code`, `unknown_login` | 403 |
| `upstream_error` | the IdP or the API answered something unusable | 502 |

A **failed refresh destroys the session** rather than leaving it to fail on every later request:
a session whose refresh token is dead cannot recover, and keeping it is keeping a cookie that
says "signed in" while nothing works. The proxy never forwards a request without a token, because
that turns an authentication problem into whatever the API says about an anonymous call.
