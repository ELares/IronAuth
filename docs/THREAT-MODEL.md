# IronAuth Threat Model

Per-surface STRIDE analysis. This document is a merge-gated artifact: no new
surface merges without its section landing in the same pull request, and CI
enforces the rule via the PR checklist for changes labeled as new surfaces.
The method follows the FAPI 2.0 attacker-model discipline: name the attacker
capabilities first, then show the structural control that defeats each threat,
or the tracked issue that will land it.

## Surfaces shipped today

As of milestone M1, the shipped surfaces are the repository and release
infrastructure and the HTTP server skeleton (dual-plane listener, observability,
log scrubbing, and the trusted-proxy policy). The skeleton is network-facing but
carries no protocol endpoint yet: those arrive in M2. The remaining sections are
forward-looking: they model the surfaces the later M1 and M2 issues are about to
ship, so that every implementation PR lands into an existing threat frame rather
than inventing one after the fact. Each mitigation cell cites the issue that owns
it; a cell without a citation is shipped.

## Attacker model

We assume: a network attacker who can read and inject traffic on untrusted
segments (defeated by TLS everywhere); a web attacker who can run script on
origins other than ours and lure users (the OAuth/OIDC attacker); a malicious
or compromised relying party; a malicious tenant attacking the platform or a
sibling tenant; and a curious-but-honest operator who must be auditable. We
do not assume a compromised host OS or hypervisor.

## Surface: repository and release infrastructure (shipped)

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | Impersonated release artifacts | Cosign keyless signing plus GitHub build provenance attestations on binary and image |
| Tampering | Dependency or action supply-chain injection | Committed lockfile, cargo-deny (sources restricted to crates.io), dependabot, OpenSSF Scorecard |
| Repudiation | Untraceable changes to main | Branch protection: PR-only, review required, linear history |
| Information disclosure | Secrets in repo or logs | GitHub secret scanning plus push protection enabled; no secrets in CI beyond GITHUB_TOKEN |
| Denial of service | CI-lane rot blocking releases | Job timeouts; per-artifact release lanes are independent |
| Elevation | Workflow permission escalation | Least-privilege per-job permissions; default contents: read |

## Surface: HTTP server skeleton (shipped)

The properties below are structural: they exist before any protocol endpoint,
so every later surface inherits them. Cells without a citation are shipped by
the skeleton; later issues extend, never weaken, them.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | Forged `Forwarded`/`X-Forwarded-*`/`Host` to move the issuer, scheme, or client IP (the Zitadel forwarded-header account-takeover class) | Scheme, host, and issuer derive from `server.public_url` config, never from headers; forwarding is honored only under an exact trusted-hop topology (`proxy.trusted_hops`/`trust_forwarded`, default trust-nothing) and fails closed on any ambiguity |
| Tampering | Spoofed hop count or conflicting forwarding headers to smuggle a false client IP | Exactly `trusted_hops` entries are required; extra, missing, malformed, or conflicting (`Forwarded` and `X-Forwarded-For` together) entries fail closed to the transport peer and increment `ironauth_proxy_forwarding_rejected_total` |
| Repudiation | Unattributable request handling | Structured JSON request logs (method, route template, config-derived scheme, effective client IP, status) with an async writer; per-surface audit rows land with the persistence substrate (#7) |
| Information disclosure | Secrets, tokens, or PII in logs (the Okta 2023 HAR class) | Request logging carries route TEMPLATES and safe fields only, never query strings, `Authorization`, `Cookie`, other headers, or bodies; sensitive runtime values are typed `Redacted<T>`; a scrubbing corpus test asserts zero leaks; management plane (health/readiness/metrics) is bound separately and absent from the public data plane |
| Denial of service | Metric-label cardinality blow-up via crafted paths; unclean shutdown dropping in-flight work | Metric labels are route templates, never raw paths (unmatched requests collapse to one series); `SIGTERM`/`SIGINT` drains in-flight requests within `server.shutdown_grace_secs`; per-tenant rate limiting lands later (#50, M15) |
| Elevation | Public probing of privileged management endpoints | Health, readiness, and metrics live only on the management plane (`server.management_bind`, loopback by default) and 404 on the public plane |

## Surface: persistence and tenant isolation substrate (shipped)

The store layer parses untrusted resource identifiers and mediates every access
to tenant-scoped tables. It ships no network endpoint of its own, but every
later data surface inherits its isolation, so its controls are structural. See
docs/design/TENANCY.md. Cells without a citation are shipped by the substrate;
the same-transaction audit log is owned by #7.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | Reaching another tenant's resource with a forged, guessed, or recycled identifier (the IDOR and recycled-identifier classes) | Typed scoped identifiers embed tenant and environment, are 128-bit non-guessable and random (never serial, never recycled), and parse cross-scope as a uniform not-found; a handler holding a scoped identifier cannot express a cross-tenant query |
| Tampering | Writing or updating a row that claims another tenant or environment | Scope-only repositories apply the `(tenant, environment)` filter to every write; Postgres row-level security `WITH CHECK` rejects a mis-scoped write beneath the application |
| Repudiation | Unattributable data changes | Same-transaction audit rows land with the relational primary store (#7) |
| Information disclosure | Cross-tenant reads (IDOR) and existence or error-shape oracles | Deny-by-default `(tenant, environment)` scope on every query; row-level security ENABLED and FORCED on every scoped table, verified by a low-privilege-role test; malformed, absent, and cross-scope lookups all return the identical not-found, so there is no oracle; the reusable IDOR harness probes every scoped operation in CI |
| Denial of service | Query and pagination abuse | Cursor pagination and per-tenant rate limits land with the surfaces that expose these repositories (#11, #50, M15) |
| Elevation | A raw unscoped query bypassing the repository to read across tenants | The pool and scoped tables are crate-private (no cross-crate raw access); repositories are constructible only from a scope (compile-fail tested); `scripts/query-audit.sh` fails CI on any scoped-table SQL outside the repository module |

## Surface: authorization endpoint (planned; lands with issue #12)

| STRIDE | Threat | Control (owning issue) |
|---|---|---|
| Spoofing | Client impersonation via forged redirect | Exact-string redirect_uri matching, no wildcards (#13); RFC 9207 iss parameter against mix-up (#13) |
| Tampering | Authorization code interception or injection | PKCE S256 required everywhere, single-use codes bound to client, redirect, nonce, and verifier, family revocation on reuse (#12, #13) |
| Repudiation | Untraceable grants | Same-transaction audit rows on every issuance (#7) |
| Information disclosure | Token leakage via URL, referrer, or history | No token-bearing response types; form_post mode; Referrer-Policy on code-bearing pages (#17, #38) |
| Denial of service | Unauthenticated request floods and state exhaustion | Pre-auth artifact TTL plus quotas; per-tenant fairness (#50 quota substrate, M15 full limiter) |
| Elevation | Cross-tenant issuance | Tenant and environment isolation enforced at the persistence layer with typed scoped IDs and forced row-level security (shipped; see the persistence and tenant isolation substrate above) |

## Surface: token endpoint (planned; lands with issues #12, #21, #22, #23)

| STRIDE | Threat | Control (owning issue) |
|---|---|---|
| Spoofing | Client authentication bypass or confusion | Full client-auth suite with hygiene: reject multiple methods, jti replay cache, aud policy (#25) |
| Tampering | Algorithm confusion, forged tokens | One hardened JOSE verify path, per-client alg allowlists, never trusting in-token key material (#8); EdDSA-default signing core (#9) |
| Repudiation | Unattributed token issuance | Audit rows in the issuing transaction (#7) |
| Information disclosure | Token theft and replay | Refresh rotation with reuse detection and family revocation (#21); sender-constraining lands with DPoP (#124) and mTLS (M16) |
| Denial of service | Hashing or signing resource exhaustion | Bounded pools with admission control (#62 for password hashing); rate limits per client and tenant (#50, M15) |
| Elevation | Grant-type confusion, ambient trust on exchange | Pluggable grant seams with per-grant revalidation; the no-ambient-trust rule (#9 seams; M13 token exchange) |

## Surface: management API (planned; lands with issue #11)

| STRIDE | Threat | Control (owning issue) |
|---|---|---|
| Spoofing | Stolen or replayed admin credentials | Environment-scoped credentials; control-plane and data-plane keys separated (#11, #42) |
| Tampering | Unaudited mutation | Audit events on every mutation, written in the same transaction (#7, #11) |
| Repudiation | Untraceable admin actions | Admin-action audit stream separated from authn events (M11) |
| Information disclosure | Cross-tenant reads (IDOR) | Deny-by-default repository scoping, typed scoped IDs, forced row-level security, and the dedicated IDOR harness (all shipped; see the persistence and tenant isolation substrate above); the management API registers each of its endpoints with that harness |
| Denial of service | Pagination and query abuse | Cursor pagination everywhere; structured rate limits with headers (#11) |
| Elevation | Overbroad admin roles | Scoped admin roles and delegated administration (M10); every admin capability is a documented public API, so there are no hidden privileged paths (#11) |

## Surface: hosted pages (planned; bootstrap with issue #20, full in M9)

| STRIDE | Threat | Control (owning issue) |
|---|---|---|
| Spoofing | Phishing lookalikes of auth pages | Per-environment custom domains with automated TLS (M5); passkey origin binding defeats credential replay (M7) |
| Tampering | XSS on the auth origin | Strict nonce-based CSP, frame-ancestors none, no customer HTML or script on the auth origin ever, sanitized branding tokens only (#20 baseline, M9 full) |
| Repudiation | Disputed logins | Authentication event stream with device and geo context (M8, M11) |
| Information disclosure | Reflected parameters, account enumeration | HTML-escape every reflected parameter including error_description (M9); uniform responses and timing across login, registration, and recovery (M7) |
| Denial of service | Bot-driven form floods | Proof-of-work challenges with pluggable adapters, never a hard third-party dependency (M8) |
| Elevation | Session fixation or cookie theft | __Host- prefixed, Secure, HttpOnly, SameSite cookies; session ID rotation on privilege transitions (#32 session model) |

## Process rule

Every PR that ships a new surface (a network-facing endpoint family, a new
parser over untrusted input, or a new privileged plane) must extend this
document in the same PR. Reviewers block merges that add a surface without
its STRIDE section. This rule is stated in CONTRIBUTING.md and enforced by
the PR template checklist.
