# ironauth-fetch changelog

All notable changes to the `ironauth-fetch` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Add three federation `FetchPurpose` variants (issue #75, PR A): `FederationDiscovery`,
  `FederationJwks`, and `FederationUserinfo`, for the inbound-federation connector's outbound
  fetches (a connector's issuer / `jwks_uri` / `userinfo_endpoint` are all tenant-controlled,
  attacker-influenced URLs). They are declared NOW but unused, so the federation upstream slice
  touches no fetch-crate code; each rides the same SSRF-hardened path, so a discovery, JWKS, or
  `UserInfo` URL that resolves to an internal or loopback address is refused exactly like any
  other blocked destination. Each carries a stable metric label.
- Raise the MDS3 response cap so the feature works (issue #66 PR B, adversarial review):
  the real FIDO MDS3 BLOB is several megabytes, past the 1 MiB default cap, so a sync would
  fail closed with `ResponseTooLarge` and leave `direct` attestation inert. A new per-purpose
  `FetchPurpose::response_cap` floors the `Mds3Sync` body cap at `MDS3_SYNC_MIN_RESPONSE_BYTES`
  (32 MiB, still bounded) while every other purpose keeps the configured cap; the total-time
  bound and SSRF hardening are unchanged. A behavior test proves a 2 MiB body is refused under
  an ordinary purpose but fetched under `Mds3Sync`.
- Add the `FetchPurpose::Mds3Sync` label (issue #66 PR B): the outbound FIDO MDS3 BLOB
  fetch declares its own purpose so it rides the SSRF-hardened path with a distinct,
  bounded metric label.
- Add the `FetchPurpose::BreachScreening` label (issue #63): the online HIBP
  k-anonymity breached-password screening query is an outbound call, so it rides the same
  SSRF-hardened dispatcher as every other fetch. ONLY the 5-character SHA-1 prefix is ever
  placed on the wire (never the password or its full hash); a range URL that resolves to a
  loopback or otherwise internal address is refused exactly like any other blocked
  destination. The new purpose only adds a bounded metric label (`breach_screening`).
- Add the `FetchPurpose::LazyMigration` label (issue #56): the inbound
  lazy-migration hook verifies a first login against a legacy credential store,
  which is an outbound call, so it rides the same SSRF-hardened dispatcher as every
  other fetch. A verification endpoint that resolves to a loopback or otherwise
  internal address is refused, and a plaintext `http` target is refused, exactly like
  any other blocked destination; the new purpose only adds a bounded metric label,
  never a policy exception.
- Add the `FetchPurpose::KmsRequest` label (issue #49): an external
  customer-managed KMS/HSM call for BYOK key wrap/unwrap is outbound, so it rides
  the same SSRF-hardened dispatcher as every other fetch. A KMS endpoint that
  resolves to a loopback or otherwise internal address is refused exactly like
  any other blocked destination; the new purpose only adds a bounded metric
  label, never a policy exception.
- Added the `FetchPurpose::AcmeDirectory` label (issue #47): the outbound purpose
  for talking to an ACME certificate authority (RFC 8555) when issuing a custom
  domain's certificate. The CA URL and the validated domain are untrusted, so the
  ACME exchange rides the same SSRF-hardened path as every other outbound fetch.
- Initial SSRF-hardened outbound fetcher (issue #10): the single, hardened
  dispatcher for every server-side HTTP request IronAuth makes, so the SSRF
  class is closed structurally rather than per feature. See
  docs/adr/0003-outbound-fetch.md.
  - **Single dispatcher.** `Fetcher::fetch` is the only outbound path; the
    connector and all socket construction are module-private. No other workspace
    crate may depend on an HTTP-client crate, enforced by `scripts/http-audit.sh`
    (module visibility plus the lint).
  - **Resolve, validate, then pin (no DNS rebinding).** The host is resolved
    once, EVERY resolved address is validated against the deny policy, and the
    connection is pinned to one validated address by value; the socket layer
    never re-resolves the hostname, so a record that flips between the check and
    the connect cannot move the connection to an internal address. The resolver
    and dialer are injectable seams (`test-harness` feature) so the rebinding
    defense is proven in tests.
  - **Deny by resolved address.** Loopback, private, link-local (including the
    `169.254.169.254` cloud-metadata address), unique-local, shared-CGN,
    multicast, unspecified, documentation (`2001:db8::/32` and RFC 9637
    `3fff::/20`), benchmarking, and other special-use ranges are refused for
    IPv4, IPv6, and the IPv4-in-IPv6 forms (IPv4-mapped, IPv4-compatible, NAT64
    `64:ff9b::/96` and the RFC 8215 local-use `64:ff9b:1::/48`, 6to4). ISATAP and
    SRv6 embeddings are a documented known limitation. The deny set is fixed, not
    configurable. Out-of-range, non-numeric, and zero ports are rejected as
    malformed rather than silently defaulted.
  - **https by default**, plaintext http only on explicit per-request opt-in.
  - **Never follows redirects**: a 3xx with a `Location` is returned as an error.
  - **The dispatcher owns request framing**: caller-supplied `Content-Length`,
    `Transfer-Encoding`, `Connection`, and `Proxy-*` headers are stripped so
    hyper derives the framing from the actual body (no request-smuggling desync).
  - **Response caps** enforced while streaming (size cap aborts mid-body, total
    deadline aborts mid-flight), with safe defaults (1 MiB, 10 s), configurable
    per the tunability principle.
  - **No ambient authority**: no cookie jar, no default credentials, no
    `HTTP_PROXY`/`NO_PROXY` trust, userinfo in URLs rejected.
  - **Per-purpose observability**: `FetchPurpose` labels bounded-cardinality
    metrics (`ironauth_outbound_fetch_requests_total`,
    `ironauth_outbound_fetch_blocked_total`) and a scrubbed structured log for
    every block; callers get the uniform `FetchError::Blocked` with no topology
    oracle.
  - TLS is rustls + ring with the OS trust store (`rustls-native-certs`); no
    aws-lc, no native-tls/openssl, no webpki-roots, so the tree stays permissive
    and the musl static and MSRV-1.85 lanes hold. The connector is hyper's
    low-level connection API with a custom connector (no high-level re-resolving
    client).
  - Adversarial coverage: cloud-metadata, private, loopback, link-local,
    unique-local, IPv6 and IPv4-mapped targets (as literal-IP URLs and as
    hostnames that resolve to them); the DNS-rebinding crux; redirect-not-
    followed; size and time bombs; no-cookie/credential/proxy assertions; a
    stable adversarial URL/address table; and a nightly-only cargo-fuzz target
    over URL parsing and destination validation (`fuzz/`, not a workspace
    member, no CI fuzz lane).
