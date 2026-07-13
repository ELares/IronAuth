# ADR 0003: The SSRF-hardened outbound fetcher

Status: accepted (M1, SSRF-fetcher issue #10)

## Context

An OpenID Provider fetches attacker-influenced URLs by design: a client's
`jwks_uri` and `sector_identifier_uri`, a consent page's `logo_uri`, client
metadata documents, and webhook targets are URLs a tenant or a registering
client controls. Each is a server-side request forgery (SSRF) primitive against
cloud metadata services (the `169.254.169.254` link-local address) and internal
networks. Handled per feature, the class recurs: every new fetching feature
re-implements, or forgets, the checks. Casdoor shipped a webhook SSRF CVE for
lack of exactly this layer; node-oidc-provider isolated a single hardened
dispatcher for all its outbound fetches; the CIMD draft's hardening list and RFC
8725 section 3.10 (jku/x5u handling) both assume these controls.

Shipping the dispatcher in M1, before any feature fetches anything, means DCR,
CIMD, pairwise sector validation, and webhooks all consume a pre-hardened path
and the SSRF class is closed structurally rather than per code review.

## Decision

Add one crate, `crates/ironauth-fetch`, that is the ONLY way IronAuth code
performs a server-side HTTP request. Its design is dictated by the anti-rebinding
requirement.

### A custom connector, not a high-level client

The fetcher uses hyper's low-level client connection API
(`hyper::client::conn::http1`) with a connector it builds by hand. It does NOT
use any high-level client (reqwest, or hyper-util's pooling `Client`) that would
re-resolve the host at connect time or bring ambient behavior (a cookie jar,
proxy-env trust, redirect following). The connector and all socket construction
live in a private module; the crate exposes exactly one outbound method,
`Fetcher::fetch`.

### Resolve, validate, then pin (close the DNS-rebinding window)

The exchange is one straight line whose ORDER is the security property:

1. Resolve the host to addresses exactly once (an IP-literal host is taken
   directly, still validated).
2. Validate EVERY resolved address against the deny policy. A single denied
   address in the answer blocks the whole fetch, so an attacker cannot slip a
   private address into a multi-record set.
3. Pin: hand ONE validated `SocketAddr` (by value) to the dialer. The dialer
   never sees the hostname, so nothing re-resolves between the check and the
   connect. A DNS record that flips to an internal address after our lookup
   cannot move the connection, because there is no second lookup to poison.

The resolver and dialer are injectable seams (a `test-harness` feature exposes
them), which is what lets the tests prove the pin: a resolver that would return a
public address first and a private one on a second lookup is consulted exactly
once, and the recording dialer shows the connection pinned to the validated
public address, never the private one.

### Deny by resolved address, for every address form

The policy denies (it does not allowlist hosts): loopback, private (RFC 1918 and
IPv6 unique-local `fc00::/7`), link-local (`169.254.0.0/16` and `fe80::/10`,
which is where cloud metadata lives), shared CGN (`100.64.0.0/10`), multicast,
unspecified, documentation, benchmarking, and other special-use ranges, for IPv4
AND IPv6. The IPv4-in-IPv6 forms (IPv4-mapped `::ffff:a.b.c.d`, IPv4-compatible
`::a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) are peeled apart: the
embedded IPv4 is extracted and classified, and the wrapping form is refused even
for a public embedded address, because a normal DNS answer never produces one.
The ranges are enumerated explicitly with a comment per range, and the deny set
is intentionally NOT configurable: loosening it reopens the SSRF class. Because
validation is on the RESOLVED ADDRESS, textual bypasses (decimal, octal, or hex
IP spellings that the OS resolver expands) are caught at the same gate.

### The other controls

- **Scheme allowlist.** https by default; plaintext http only when the request
  explicitly opts in (the seam exists now; non-production guardrails come later).
- **Never follow redirects.** A 3xx with a `Location` is returned as an error,
  never followed. The fetcher issues a single request; there is no redirect loop.
- **Response caps.** A maximum body size and a total deadline, enforced WHILE
  streaming: the body is read frame by frame and aborted the instant it would
  cross the size cap, and the whole exchange runs under one deadline (tokio's
  timer, per ADR 0001). Both caps have safe defaults (1 MiB, 10 s) and are
  configurable per the tunability principle; the deny policy and redirect rule
  are not.
- **No ambient authority.** No cookie jar, no default credentials, no
  `HTTP_PROXY`/`NO_PROXY` trust; userinfo in a URL is rejected. A request carries
  only what the caller set, plus a `Host` header for the true destination.
- **Caller identity and purpose in the API.** `fetch` takes a `FetchPurpose`
  (jwks_uri, sector-identifier, client-metadata, webhook-delivery, logo) so
  blocked and completed attempts are observable per purpose in metrics and logs
  (a bounded-cardinality label, like the server's method bucketing). A blocked
  destination returns the single uniform `FetchError::Blocked` (no oracle for
  internal topology), while the structured reason goes to metrics and a scrubbed
  log field, never to the caller.

### TLS

Client TLS is rustls with the ring provider and the OS trust store
(`rustls-native-certs`), matching ironauth-store: no aws-lc, no
native-tls/openssl, no webpki-roots (CDLA-Permissive, off the allowlist). The
handshake verifies the certificate against the ORIGINAL hostname (SNI and name
verification), while the bytes flow over the pinned socket. This keeps the tree
permissive and the musl static lane holding.

## Consequences

- Later features (DCR jwks_uri fetches, CIMD, webhooks, logo and sector URI
  handling) CONSUME `Fetcher::fetch`; they do not extend the connector.
- Single-dispatcher discipline is enforced two ways: module visibility (the
  connector is private; the seams are behind a test-only feature) and
  `scripts/http-audit.sh`, which fails the build if any other crate declares a
  direct HTTP-client dependency or constructs an HTTP/TLS client in source. The
  assembler wires that lint into CI.
- The connector speaks HTTP/1.1 only. HTTP/2 for outbound fetches, if ever
  needed, is a separate opt-in decision recorded in a new ADR.
- The deny policy is deliberately rigid. An environment that genuinely needs to
  reach an internal address does so through deployment-level egress policy, not
  by loosening this crate.
