# ironauth-oidc changelog

All notable changes to the `ironauth-oidc` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Dynamic Client Registration abuse controls (issue #31), wrapping the #30 create.
  - **Exposure switch.** A per-environment `closed` / `token_gated` / `open` mode
    (default `token_gated`) governs who may register: `closed` refuses every public
    registration, `token_gated` requires a valid initial access token, and `open`
    allows anonymous registration but starts the client quarantined. An unauthorized
    request is a uniform 403 `access_denied` (no oracle for an unknown vs expired vs
    exhausted token).
  - **Initial access tokens with reusable policy chains.** A presented token is
    consumed atomically (its usage limit cannot be raced past), and the policy chain
    it carries (force / restrict / reject / default primitives, a pure engine in
    `dcr_policy`) is applied to the submitted metadata BEFORE validation. The chain
    snapshot is persisted on the client, so an RFC 7592 update re-applies the SAME
    chain for the client's lifetime, even if the source policy is later edited or
    deleted.
  - **Opaque-but-diagnosable rejections.** A policy rejection is the generic
    `invalid_client_metadata` on the wire (it never names the property or the
    operator's policy), while the actionable diagnostic is recorded out of band as a
    `dcr.policy_rejected` audit event plus a structured log line.
  - **Quota and rate limit.** The per-environment registered-client quota is enforced
    atomically inside the create transaction; over it, the request is a typed 403 plus
    a `dcr.quota_hit` audit event. The endpoint's fixed-window rate limit (keyed by
    source and by presented token) yields a 429 `temporarily_unavailable` plus a
    `dcr.rate_limited` audit event.
  - **Unverified-client quarantine.** A quarantined client NEVER gets the first-party
    consent carve-out (consent is always shown, ignoring `skip_consent` / implicit
    mode) AND its recorded-consent fast path is disabled: a quarantined client
    re-prompts consent on EVERY authorization even with a PRE-RECORDED consent, until an
    admin verifies it. Its effective redirect set is restricted to its https targets (a
    native/loopback redirect is refused with a page error, never an open redirect).
    Verification lifts all of these. Exports the `dcr_policy` engine (`PolicyPrimitive`,
    `apply_chain`, `parse_chain`, `serialize_chain`) for reuse by the management API.
  - **Abuse-control hardening.** The endpoint rate-limit source key is now the
    non-forgeable transport peer address (from the server's `ConnectInfo`), never a
    caller-controlled `X-Forwarded-For` hop, so a direct caller can no longer rotate a
    header to mint a fresh bucket per request or poison a victim's bucket; the endpoint
    limit is documented as best-effort/advisory (the per-environment quota is the real
    hard cap; the robust trusted-proxy-aware limiter is deferred to M15). The exposure
    switch is now evaluated BEFORE the request body is parsed, so an unauthorized
    request is the uniform 403 regardless of body validity (no 400-vs-403 oracle). A
    stored policy-chain snapshot that fails to parse now fails CLOSED (a `server_error`
    at registration and at RFC 7592 update), never proceeding with an unconstrained
    chain. A `dcr.policy_rejected` audit event now carries the offending property as an
    operator-safe detail dimension (the wire stays opaque). The `Restrict` primitive's
    omission footgun (an omitted property is unconstrained, then takes the spec default)
    is documented on the primitive and in the management API policy-create schema.
- Token revocation (RFC 7009) and introspection (RFC 7662) endpoints (issue #22).
  - **`POST /revoke`.** An authenticated client revokes one of its OWN tokens, in any
    format IronAuth issues (a refresh token, an opaque access token, or an at+jwt), told
    apart by the token's own self-describing shape rather than the advisory
    `token_type_hint` (so a wrong hint still revokes). The token declares its own
    `(tenant, environment)` scope, exactly as the opaque `UserInfo` path does, and the
    endpoint fixes the scope from the AUTHENTICATED client's id, so a cross-tenant token
    can never be revoked. Once the client is authenticated, EVERY token outcome (unknown,
    malformed, expired, already-revoked, or belonging to a different client) returns a
    uniform `200` empty body, so there is no existence oracle (RFC 7009 section 2.2). A
    public `none` client authenticates by presenting its `client_id`; a confidential
    client must present its secret. `revocation_endpoint` is now advertised in discovery.
  - **`POST /introspect`.** An authorized caller reads a token's active state and standard
    metadata (`scope`, `client_id`, `sub`, `exp`, `iat`, `aud`, `token_type`). A
    CONFIDENTIAL client is REQUIRED: introspection accepts only a real
    `client_secret_basic`/`client_secret_post`/`private_key_jwt` credential and REJECTS
    the public `none` method, because a `client_id` is not secret (it appears in
    front-channel authorize URLs), so a public client presenting only its id has proven
    nothing (RFC 7662 section 2.1). A public `none` client (or a caller presenting only a
    `client_id`), an unauthenticated call, and a badly-authenticated call all return the
    SAME uniform `401` that leaks nothing about any token (RFC 7662 section 4, the
    token-scanning-oracle defense). The resource-server model is otherwise intact: any
    authenticated confidential client may introspect any token in its own scope. Every
    not-active cause (unknown, expired, revoked, cross-tenant, wrong format, and a
    transient store fault, which fails closed) returns the same `200 {"active":false}`.
    An at+jwt's metadata comes from the VERIFIED token, so a tampered payload reads as
    not-active; a revoked grant flips `active` to `false` even while the signature still
    verifies. The at+jwt resolve accepts an `aud` that is EITHER a single string OR a
    JSON array (RFC 7519), verifying the token against any member, so a multi-audience
    token (forthcoming with issue #28 resource indicators, RFC 8707) introspects
    correctly rather than reading as not-active. `introspection_endpoint` is now
    advertised in discovery. (`/revoke` continues to accept a public `none` client, which
    RFC 7009 explicitly permits: it is owner-scoped and returns no data.)
  - **Revocation cascades through the grant.** The append-only issued/opaque token rows
    derive their active state only from `grants.revoked_at`, so revoking a token revokes
    its grant chain. Revoking a REFRESH token additionally revokes its whole family (the
    #21 spine) AND the grant, so every access token derived from it introspects as
    `active:false` immediately (RFC 7009 section 2.1). Because the token tables are
    append-only, revoking any access token from a grant revokes the whole grant chain (a
    deliberate consequence of the digest-only, no-per-token-mutation storage model; RFC
    7009 permits revoking the associated tokens).
  - **Pluggable introspection serializer.** Response construction goes through the
    `IntrospectionSerializer` seam so the RFC 9701 signed-JWT introspection response (M16)
    slots in as a new serializer without touching the endpoint; only the RFC 7662
    plain-JSON serializer ships now. Wire a custom one with
    `OidcState::with_introspection_serializer`.
  - **Internal revocation-event seam.** Every successful revocation publishes a typed,
    shape-locked `RevocationEvent` on the internal `RevocationEventSink`, so an in-process
    cache or resource-server bridge can react; only the no-op sink ships (the EXTERNAL
    fan-out is M4, wired later through `OidcState::with_revocation_sink`). The durable
    record is the store audit row (`token.revoke` / `refresh_family.revoke`) written in
    the same transaction as the state change.
  - **Discovery.** `revocation_endpoint`, `introspection_endpoint`, and their
    `*_auth_methods_supported` (and RFC 8414 section 2 `*_auth_signing_alg_values_supported`)
    arrays are emitted by the single live-config generator on every well-known form,
    sourced from the shared client-auth suite so they cannot drift from what the endpoints
    accept. The two advertised method sets DIFFER by exactly `none`:
    `revocation_endpoint_auth_methods_supported` (and `token_endpoint_auth_methods_supported`)
    advertise the full `ClientAuthMethod::ALL` including `none`, while
    `introspection_endpoint_auth_methods_supported` advertises only the CONFIDENTIAL
    methods (`ALL` minus `none`), matching the endpoint's confidential-client requirement.
  - The revocation and introspection endpoints REUSE the token-endpoint client-auth suite
    through a new `authenticate_client_self_scoped` seam (it recovers the scope from the
    presented `client_id`, since these endpoints are global like `/token`). The
    authenticated client now also carries its registered `auth_method`, so `/introspect`
    can require a confidential one.
  - **Test coverage** added for the introspection hardening: a public `none` client (and
    a caller presenting only a `client_id`) is rejected at `/introspect` with a uniform
    `401` while a confidential client still introspects; advancing-clock expiry for both
    an at+jwt access token (past its TTL) and a refresh token (past its idle lifetime);
    the access-token-revoke to refresh cascade (the whole grant chain); a foreign and a
    double revoke publish no second event and write no second audit row (exactly-once on
    a real state flip); the full active-refresh introspection body shape; a synthetic
    multi-audience at+jwt introspecting active; a swapped `IntrospectionSerializer` being
    honored by the endpoint; and the discovery unit test now asserts the revocation,
    introspection, and PAR endpoints and their (differing) auth-method arrays.
- The `client_credentials` grant with service-account principals (issue #23, RFC
  6749 4.4, RFC 9068).
  - **The grant.** The token endpoint services `grant_type=client_credentials`: an
    authenticated CONFIDENTIAL client obtains a machine-to-machine access token for
    its own service-account principal. Client authentication is REQUIRED and delegates
    to the shared `authenticate_client` seam, so a public client (auth method `none`,
    which proves nothing) is refused as `invalid_client`. The `(tenant, environment)`
    scope is recovered from the presented `cli_` client id, then the secret is proven
    within it. `client_credentials` is now an advertised `grant_type`.
  - **Stable service-account `sub`.** Every M2M-capable client maps to a first-class
    service-account principal (a `sva_` id), minted lazily on first issuance and read
    back thereafter. The issued token's `sub` is that principal id (RFC 9068:
    DISTINCT from `client_id`, consistent across issuances); `client_id` is the OAuth
    client. RBAC (M10) will attach to the principal.
  - **Custom claims.** Per-client STATIC claims (the `clients.custom_token_claims`
    JSON object) are embedded in the token. A custom claim can NEVER set a RESERVED
    claim name: the guard is a comprehensive denylist enforced in the mint, so it
    holds even for a value written straight into the store. The reserved set covers
    the protocol claims (`iss`/`sub`/`aud`/`exp`/`iat`/`nbf`/`jti`/`client_id`/`scope`
    plus `typ`/`token_type`), the authentication-context claims
    (`acr`/`amr`/`auth_time`/`nonce`/`azp`), the binding claim `cnf`, and the
    hash/session claims (`at_hash`/`c_hash`/`sid`): a static business claim can never
    forge an authentication context a machine token must not carry, nor a
    self-asserted confirmation key that would undermine sender-constrained (DPoP /
    mTLS) token binding. Custom claims are an at+jwt feature ONLY: an opaque access
    token carries no embedded claims by design, so when the resolved format is opaque
    the configured custom claims are dropped and the mint WARNS (without the claim
    values), their metadata surfacing instead through #22 introspection.
  - **No auth context, no refresh token.** A machine token carries NO `acr` and NO
    `auth_time` (there is no user authentication event), via a dedicated M2M claim
    builder that reuses the same signing core and opaque mint as every other access
    token. NO refresh token is returned (RFC 6749 4.4.3) and no ID token (no user);
    this is asserted at the DATABASE too (a client-credentials issuance opens no
    `refresh_families` row and mints no `refresh_tokens` row), not only in the
    response body.
  - **Revocable/introspectable by construction.** The token is minted in the same #29
    formats (at+jwt with `jti`, opaque `ira_at_`) and recorded against a fresh grant
    in one transaction, so the #22 revoke/introspect endpoints consume it through the
    SAME grant chain the code/refresh tokens use.
  - **Audience.** The token is audience-restricted; the default audience when no
    resource server is targeted is configurable
    (`oidc.client_credentials_default_audience`: `client_id` or `issuer`), and the
    existing `resolve_access_token_target(scope, resource, ...)` seam (#29) is consumed
    so issue #28's `resource` parameter feeds it without reshaping the mint.
  - **Errors.** `invalid_client` (401, with `WWW-Authenticate: Basic` on a Basic
    attempt) for a failed authentication; `invalid_scope` for an out-of-policy scope
    request (`openid`/`offline_access` are not valid for a machine principal; the full
    per-client scope allowlist is M10 RBAC).
  - **Covenant.** NO metering, counting-for-billing, or quota hook exists on the M2M
    issuance path; `scripts/no-m2m-metering.sh` asserts it in CI over the WHOLE
    issuance path (the request handler in full, plus the CC-specific mint helpers
    `mint_client_credentials_access_token` /
    `build_client_credentials_access_token_claims` and the persistence helper
    `issue_client_credentials`, scoped to those function regions), and SDK-facing
    token-caching guidance is published at `docs/design/M2M-TOKEN-CACHING.md`.
- Refresh-token rotation, families, `offline_access`, and consent modes (issue #21).
  - **The `refresh_token` grant.** The token endpoint exchanges a rotating refresh
    token for a fresh access token. The refresh token is an opaque reference mirroring
    the #29 access token, `ira_rt_<jti>~<secret>` (a scope-declaring `rft_` handle
    plus 256 bits from the entropy seam), stored only as a SHA-256 digest; the
    presented token declares its own `(tenant, environment)` scope, so the global
    endpoint recovers the scope and runs the RLS-scoped resolve. `refresh_token` is
    now an advertised `grant_type`.
  - **Graduated rotation policy.** A public (sender-unbound) client rotates on every
    refresh; a confidential client rotates only once past the configured fraction of
    idle TTL (default 70%), with an optional per-client `always`/`threshold` override.
    A family hard cap bounds the total rotated lifetime.
  - **Reuse detection.** A superseded token presented outside the grace window is
    `invalid_grant`, revokes the entire family, and emits the typed reuse event
    exactly once per incident; benign concurrent refreshes within the grace window all
    succeed without revoking. A revoked-family refresh is `invalid_grant`. An event
    shape-lock test pins the SIEM-facing `refresh_token.reuse` audit row so it cannot
    drift silently.
  - **Concurrent within-grace refreshes converge on one live leaf.** A within-grace
    refresh that is NOT the atomic-rotate winner (a concurrent loser, a multi-tab
    retry, or a lost rotation response) now returns ONLY a fresh access token and
    OMITS the `refresh_token` (optional per RFC 6749 5.1): it mints no new refresh
    leaf, so N concurrent refreshes CONVERGE on the winner's single live leaf instead
    of forking the family into independent, never-detected chains. Accepted,
    documented limitation: a client that ENTIRELY loses the winner's rotation response
    never receives the new refresh token and must re-authenticate; no plaintext token
    is cached and replayed (that would forfeit the no-replayable-material-at-rest
    guarantee). Regression is guarded by an HTTP-layer test that fires 8 true-parallel
    refreshes and asserts exactly one live leaf and zero reuse events.
  - **`offline_access` advertised in discovery.** `scopes_supported` now lists
    `offline_access` (OIDC Core 11), so an RP can learn the provider issues refresh
    tokens.
  - **`offline_access` (OIDC Core 11).** Ignored on a flow that returns no
    authorization code; a web client must consent to it, with a trusted first-party
    carve-out (`implicit` mode or `skip_consent`). An `offline_access` family survives
    RP logout (Back-Channel Logout 2.7) with its own finite idle and max lifetimes,
    while a session-bound family is invalidated with the session.
  - **Consent modes per client.** `explicit` (always prompt unless a covering consent
    exists), `implicit` (first-party auto-grant), and `remembered` (honor the recorded
    consent until its TTL, then re-prompt), plus `skip_consent` and a
    `store_skipped_consent` no-store knob.
- Pushed authorization requests (PAR, RFC 9126, issue #27).
  - **`POST /par`.** A new back-channel endpoint that authenticates the client
    with the SAME suite as the token endpoint (the shared `authenticate_client`
    seam: public `none`, secret, or `private_key_jwt`) and validates the COMPLETE
    authorization request at push time, then returns a single-use
    `urn:ietf:params:oauth:request_uri:<par_id>` reference and its `expires_in`. A
    bad `redirect_uri`, missing PKCE, a disabled response type, or a malformed
    `claims`/`prompt`/`max_age` is rejected HERE on the back channel, not later at
    `/authorize`. A `request_uri` in the pushed request is refused (RFC 9126
    section 2.1).
  - **One shared request validator.** The authorization-request validation is
    factored into a single `validate_request` function that BOTH `/authorize` and
    `/par` run, so the two paths cannot diverge; `/authorize` renders a page or a
    redirect and `/par` renders JSON from the same neutral error.
  - **`request_uri` at `/authorize`.** A `request_uri` is accepted ONLY as a PAR
    reference. It is PEEKED (read, not consumed) at every authorization hop, so it
    survives the login and consent interaction round-trip, and the single-use
    consume happens ATOMICALLY at the moment of code issuance: exactly one code per
    `request_uri`, and a concurrent or prior issuance, a reuse, or an expiry is
    rejected (single use holds end to end across stateless nodes). The reference is
    bound to the pushing client (a reference presented by a different `client_id`
    resolves to nothing, and is never revealed or burned), the pushed values are
    authoritative and any conflicting inline query parameters are ignored (RFC 9126
    section 4), and no code path ever dereferences an external `request_uri` over
    the network (there is no outbound fetch on this path, test-enforced).
  - **Require-PAR enforcement.** When the environment switch
    (`oidc.require_pushed_authorization_requests`) OR the per-client registration
    flag is set, a plain (non-PAR) authorization request is rejected with
    `invalid_request`. A request that arrived through PAR satisfies the requirement
    at the first hop AND at every login/consent resume hop: the gate keys off the
    unforgeable `request_uri`, which is re-presented on the minimal resume link (not
    the expanded parameters), so a fresh-login user of a require-PAR client resumes
    through the interaction to a real code rather than a 400.
  - **Discovery.** `pushed_authorization_request_endpoint` and
    `require_pushed_authorization_requests` are advertised from live config on both
    well-known forms.
- Dynamic Client Registration and configuration management (issue #30).
  - **RFC 7591 registration.** New `client_registration` module serving
    `POST {issuer}/connect/register` (a distinct concept and path from the human
    `/register` account surface). The metadata property set is validated with
    per-spec defaults applied when omitted (`client_secret_basic`
    `token_endpoint_auth_method`, `["code"]` `response_types`; an omitted
    `id_token_signed_response_alg` records the environment's actual default signing
    algorithm) and UNRECOGNIZED properties ignored per RFC 7591.
    `token_endpoint_auth_method` and every algorithm are validated against the
    implemented client-auth suite (issue #25), so the inert `client_secret_jwt`
    and unknown methods are refused with `invalid_client_metadata`. `redirect_uris`
    are RFC 8252 aware (web: https only; native: https, http loopback IP literals,
    and reverse-domain private-use schemes; dangerous schemes rejected with
    `invalid_redirect_uri`). `jwks` and `jwks_uri` are mutually exclusive, and a
    `jwks_uri` is fetched THROUGH the SSRF-hardened fetcher (the issue #25
    `ClientKeyResolver` path), so a private-address destination is rejected.
  - **RP Metadata Choices 1.0 (recorded == signed).** `id_token_signed_response_alg`
    may be an array of acceptable values (or the plural
    `id_token_signed_response_alg_values`). The OP negotiates ONLY against the
    algorithms the environment can ACTUALLY sign an ID token with (each permitted by
    the environment policy AND backed by a loaded, active signing key), never the
    advertised `id_token_signing_alg_values` (which carries the RS256 discovery floor
    even where no RS256 key exists). Of the offered signable algorithms it prefers
    `EdDSA`, else `RS256`, else the first mutual value; an offered set with nothing
    the environment can sign is REJECTED with `invalid_client_metadata` (never
    silently downgraded). The token endpoint then signs THAT client's ID token under
    the recorded algorithm (an additive per-client override on the ID-token mint
    path; the access token keeps the environment default), so the algorithm DCR
    records and echoes is exactly the algorithm the ID token is signed under.
  - **RFC 7592 management.** `GET`/`PUT`/`DELETE
    {issuer}/connect/register/{client_id}` authenticated by the registration
    access token (constant-time hash compare). Every successful update ROTATES the
    token, so the superseded one is rejected on the next call. Credentials
    (`client_secret`, `registration_access_token`) are stored SHA-256-hashed and
    returned once.
  - **Discovery + config.** Discovery advertises the per-environment
    `registration_endpoint` (`{issuer}/connect/register`) only when enabled. The
    endpoint ships behind a plain default-off `oidc.registration_enabled` flag; the
    real abuse gating (quotas, quarantine, initial-access-token policy) is owned by
    issue #31, with the enable gate and the single `register` funnel left as its
    seam.

- Complete the client authentication suite with JWT assertions and uniform
  failure hygiene (issue #25).
  - **`private_key_jwt` (RFC 7523).** A client authenticates the token endpoint
    with a JWS assertion signed by a key it registered (`jwks` inline or a
    `jwks_uri` fetched through the SSRF-hardened `ironauth-fetch`, cached with a
    TTL). Every asymmetric algorithm the verify core represents is accepted
    (`EdDSA`, `RS256/384/512`, `ES256/384`, `PS256/384/512`); an `ES512`
    assertion is rejected, matching the M1 exclusion. The assertion is validated
    through the one hardened `verify` path: `iss` and `sub` must equal the client
    id, `exp` is enforced with the configured skew through the `Clock` seam, and
    `aud` must be an accepted audience per the `oidc.client_assertion_audience`
    policy (the token-endpoint URL or the issuer by default, issuer-only in the
    strict mode). A non-empty `jti` is required (an empty or whitespace-only `jti`
    is treated as absent and rejected) and spent through the cross-node single-use
    store, so a replayed assertion is refused on every node. The single-use row is
    retained until `exp + skew + 1s`: acceptance floors `now` to whole seconds and
    accepts while `now_secs <= exp+skew`, so the assertion stays acceptable for the
    whole wall-clock second `[exp+skew, exp+skew+1)`; the +1s margin makes retention
    strictly outlast acceptance so a replay is caught across that entire second (a
    bare `exp+skew` retention pruned at microsecond precision would re-admit it).
  - **`private_key_jwt` key-source and algorithm pin.** A `private_key_jwt` client
    must register EXACTLY ONE key source; a per-client `token_endpoint_auth_signing_alg`
    is a strict allowlist (a client pinned to `EdDSA` rejects an otherwise-valid
    `RS256` assertion). Discovery advertises the asymmetric assertion matrix in
    `token_endpoint_auth_signing_alg_values_supported` (REQUIRED by OIDC Discovery 1.0
    section 3 whenever `private_key_jwt` is advertised; `none` and `ES512` excluded).
  - **`client_secret_jwt` fails closed, by decision.** The method is inert: HMAC
    verification would require the raw client secret at verify time, and IronAuth
    stores only a one-way hash of client secrets; implementing it would have weakened
    the `basic`/`post` hashed-secret posture or pulled in retrievable-secret key
    management, both out of scope for #25. It is therefore NOT advertised in
    discovery's `token_endpoint_auth_methods_supported`, and registering a client for
    it is refused LOUD at registration (a `Conflict`), so no such client can reach the
    token endpoint; the runtime fail-closed arm (an opaque `invalid_client` with a
    recorded diagnostic) remains as defense in depth. The tradeoff is documented at
    the top of `client_auth.rs`.
  - **Uniform failure hygiene.** Presenting more than one authentication method
    is an `invalid_request`; every other authentication failure is an opaque
    `invalid_client` (HTTP 401 with the correct `WWW-Authenticate` challenge only
    when the client used HTTP Basic, per RFC 6749 5.2), with no oracle
    distinguishing an unknown client from a bad signature from a replayed `jti`.
    The rich reason is written out of band to `client_auth_diagnostics`, never to
    the wire. Exactly one registered method is honored per client.
  - **Reusable `authenticate_client` seam.** The token endpoint's client
    authentication is now the crate-public `client_auth::authenticate_client`
    (over `ClientAuthInputs`), so #22 introspection/revocation and #26's JWT
    bearer grant inherit the same parsing, routing, verification, single-use, and
    diagnostics without reimplementing them. `ClientKeyResolver` centralizes
    `jwks`/`jwks_uri` key resolution and caching.
  - **`client_secret_basic` decode hardening.** `form_urldecode` now decodes `%XX`
    escapes from the raw BYTES (rejecting a non-hex pair), so a `%` followed by a
    multi-byte UTF-8 character in an `Authorization: Basic` credential can no longer
    string-slice at a non-char-boundary and panic (previously a 500 via the
    catch-panic layer, reachable unauthenticated).
- JWT (RFC 9068) and opaque access tokens with per-resource-server format
  selection (issue #29).
  - **RFC 9068 `at+jwt` conformance.** The access token now carries the RFC 9068
    section 2.2 claims (`iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`,
    `scope` when granted) plus `acr` (the achieved authentication context, derived
    from the recorded authentication event, never a request parameter) and, when the
    authentication instant was frozen onto the code as due, `auth_time` -- threaded
    from the authenticated session exactly as the ID token's `auth_time` is. The
    header `typ` stays `at+jwt`. Claims hygiene: no PII beyond these protocol claims.
  - **`aud` preserves `UserInfo`.** When no resource server is targeted the access
    token's `aud` is the client id (so `userinfo::verify_access_token`'s `aud ==
    client` check keeps working); when a registered resource server is targeted it is
    that resource server's audience. `client_id` is always the OAuth client.
  - **Opaque access tokens (Hydra digest-only pattern).** A new opaque format mints
    a SCOPE-DECLARING `ira_at_` token and stores ONLY its SHA-256 digest plus metadata
    (`opaque_access_tokens`), never the token. The token is
    `ira_at_<jti>~<256-bit secret>`: the `jti` is a `tok_` scoped id that embeds the
    token's `(tenant, environment)` as a NON-secret routing handle (so a global
    consumer can recover the scope and run the scope-bound store resolve, exactly as
    an `at+jwt`'s `jti` does), and the 256-bit suffix from the ironauth-env entropy
    seam is the secret; only the digest of the WHOLE token is stored. There is no
    offline validation; the internal `AuthorizationRepo::resolve_opaque_access_token`
    is the only verification path. The `ira_at_` prefix scheme and its scanner regex,
    plus the reserved `ira_rt_` refresh prefix (issue #21), are documented in
    `docs/design/TOKEN-FORMATS.md`.
  - **`UserInfo` consumes BOTH access-token formats.** The `UserInfo` endpoint now
    validates an opaque `ira_at_` token, not just an `at+jwt`: it recovers the scope
    from the token's routing handle and runs the scope-bound, row-level-security
    `resolve_opaque_access_token`, then enforces the SAME checks it enforces for an
    `at+jwt` -- `aud == client` (the confused-deputy gate, so a resource-server token
    is refused), the `openid` scope, and the PUBLIC `sub` through the one shared
    subject derivation from the resolved LOCAL subject. Every failure (absent,
    expired, revoked-grant, cross-scope, wrong audience) is the uniform RFC 6750
    `invalid_token` `401`, with no oracle distinguishing an opaque-but-unknown token
    from a malformed one. Without this an environment defaulted to `opaque` minted
    access tokens `UserInfo` rejected, so the opaque format was inert until issue #22.
  - **Per-resource-server format selection.** `OidcState::resolve_access_token_target`
    resolves the access-token format, audience, and lifetime: a targeted resource
    server (matched by audience) supplies its `token_format` and
    `access_token_ttl_secs`, otherwise the environment default
    (`oidc.default_access_token_format`) and the environment access-token lifetime
    apply. The pure `tokens::mint` now takes the resolved `AccessTokenTarget`, so the
    crypto stays pure while the resource-server lookup awaits in the handler. The RFC
    8707 `resource` request-parameter wiring is issue #28; the token endpoint passes
    `resource = None` today, so the default (at+jwt) behavior is unchanged. The
    selection function takes the resolved audience, so #28 can feed the `resource`
    parameter without reshaping the mint.
  - **Recording.** An at+jwt keeps recording its `jti` in `issued_tokens`; an opaque
    token records its digest-only row in `opaque_access_tokens`, in the SAME redeem
    transaction as the code consume, so it is as unbypassable and as
    revocation-reachable as an at+jwt.

- Consent-hardening prerequisites for enabling OIDC (issue #196, blocking
  issue #13). Two hard security gaps in the issue #20 bootstrap are closed; the
  provider stays gated off by default (`oidc.enabled` unchanged).
  - **Scope-aware consent.** `resolve_gate` (the authorize login/consent gate) now
    treats a recorded consent as covering a request only when the request's scope is
    a SUBSET of the scope the consent was granted against (new
    `consent_covers_scope`, splitting on ASCII whitespace like the mint's own
    `parse_scope_set`). A consent for a narrow scope (for example `openid`) no longer
    silently auto-grants a later broader request (`openid profile email`): the
    broader request re-prompts through the consent screen, and under `prompt=none`
    returns `consent_required`, exactly as an absent consent does. A same-or-narrower
    request still issues directly. Re-consent persists the broadened scope (the store
    `grant` upsert), so it does not loop. Reads the granted scope through the store's
    new `GrantedConsent`.
  - **CSRF defense-in-depth on the login, consent, and registration POSTs.**
    `login_post`, `consent_post`, and `register_post` now evaluate an Origin +
    `Sec-Fetch-Site` allowlist (`interaction::same_origin_ok`) BEFORE any state change
    (before verifying the password / recording consent / creating the account). A
    conclusively cross-site POST (`Sec-Fetch-Site: cross-site`, or an `Origin` that
    does not match the deployment's own origin, derived from `issuer_base` via
    `OidcState::self_origin`) is refused with a generic `403` that creates no session,
    records no consent, and creates no account. When neither header is conclusive the
    existing `SameSite=Lax` cookie remains the backstop, so header-stripped and
    non-browser clients are unaffected. This closes the Chromium "Lax+POST"
    transitional window and the non-enforcing-legacy-client residual with no schema,
    cookie, or token plumbing. `login_post` and `register_post` now take `HeaderMap`.
    - **`register_post` was the load-bearing gap.** Unlike login and consent, the
      registration POST needs NO pre-existing cookie and MINTS a session on success
      (auto-login), so the `SameSite=Lax` backstop does not cover it at all: a
      cross-site auto-submit with attacker-chosen credentials would sign the victim
      into an attacker-known account (login-CSRF / session fixation). The check runs
      before `hash_password` and before any account creation.
    - **The Origin comparison is now normalized on both sides** so it never falsely
      rejects a legitimate same-origin POST: `origin_of` lowercases the scheme and
      host and drops the default port (`:443` for https, `:80` for http), matching the
      `Origin` a browser normalizes and sends. A `public_url` configured with an
      uppercase host or an explicit default port therefore still matches. This is
      never a false ALLOW: a different scheme, host, or non-default port still differs.
  - **Regression coverage.** A `prompt=none` request whose scope is NOT a subset of a
    RECORDED consent now has an explicit test that it returns `consent_required`
    through the negotiated response mode (an error redirect, never a consent page and
    never a code), alongside the existing absent-consent and covered-consent cases.
- Compose per-environment issuers, JWKS serving, and signing into the LIVE data
  plane (issue #194). The #19 primitives (per-environment `IssuerRegistry`, JWKS
  serving, algorithm policy, rotation `KeySet`) were inert; they now back the live
  mint and the mounted JWKS surface. The provider stays gated off by default
  (`oidc.enabled` unchanged).
  - **One lazy, store-backed, RLS-scoped registry is the single source of truth.**
    The `IssuerRegistry` is now interior-mutable and keyed by the FULL
    `(tenant, environment)` scope. On the first request for an issuer it loads that
    scope's keys through `Store::scoped` (row-level-security FORCED), builds the
    `KeySet` and the algorithm policy from exactly those keys, and caches the entry.
    `OidcState` no longer holds a separate `EnvironmentKeyStore`: BOTH the mint (via
    `OidcState`) and the JWKS/discovery serving (via `IssuerState`) read the SAME
    `Arc<IssuerRegistry>` and the SAME cached entry, so a signed `kid` is in the
    published JWKS by construction (they cannot drift).
  - **Env-to-tenant binding falls out of the RLS-scoped load.** A request to
    `/t/{tenantA}/e/{envOfTenantB}/...` loads under scope `(tenantA, envOfTenantB)`;
    RLS finds no rows, so the key set is empty and JWKS/discovery return 404 and the
    mint fails closed. Keying the cache by the full scope (not the environment id
    alone) means a cross-tenant probe gets its own empty slot and can never collide
    with a legitimately cached entry: a self-consistent bogus issuer cannot resolve.
  - **The mint enforces the environment's algorithm policy.** Both tokens are now
    signed through `sign_jws_with_policy`, so an ES256-only environment (its loaded
    keys are all ES256, hence policy `{ES256}`) can emit nothing but ES256: a
    non-ES256 key is neither present nor policy-permitted. `verify_access_token`
    likewise builds its trusted keys and allowlist from the SAME loaded key set.
  - **Discovery is registry-backed, closing the last divergent source of truth.**
    The well-known discovery routes (`DiscoveryState`) now hold the SAME
    `Arc<IssuerRegistry>` the mint and the JWKS surface read and resolve each
    environment's signing policy from its loaded keys, so the advertised
    `id_token_signing_alg_values_supported` is derived from exactly the keys that
    environment signs with (plus the OIDC-mandated RS256 floor). An ES256-only
    environment therefore advertises `ES256`, never the EdDSA default, matching its
    JWKS and its minted tokens. An unprovisioned or cross-tenant scope resolves to no
    entry and returns a uniform `404`, exactly like the JWKS surface, rather than a
    self-consistent bogus 200. The config-only policy default (and the dead
    `IssuerRegistry::discovery_json`) are gone.
  - **The mounted surface** now serves the protocol router, discovery (both
    well-known forms), AND the per-environment JWKS, all over the one registry. The
    JWKS/discovery `Cache-Control` max-age is derived from
    `oidc.jwks_cache_max_age_secs`. An environment with no provisioned key resolves
    to an empty key set: its token endpoint fails closed and its JWKS AND discovery
    return 404. Pairwise salt persistence, per-environment policy persistence, and
    rotation timers remain later milestones (a documented placeholder salt is used;
    nothing live reads it).
- `prompt`, `max_age`, interaction-hint plumbing, `prompt=create`, and the
  `unmet_authentication_requirements` error (issue #16). Extends the #12/#13/#17
  authorization endpoint and the #20 interaction surfaces; the provider stays gated
  off (`oidc.enabled` unchanged).
  - **`prompt` is a space-separated SET** (`PromptSet`, parsed order-insensitively
    like `ResponseType`). `none` renders NO UI: a missing session, missing consent,
    or a `max_age`-stale session returns `login_required` / `consent_required`
    through the NEGOTIATED response mode (never a page), exactly as other authorize
    errors to a validated `redirect_uri`. `login` forces fresh authentication despite
    a valid session; `consent` re-prompts consent even when recorded;
    `select_account` degrades to a forced re-login under the single-session
    bootstrap; `create` still deep-links to registration. `none` combined with any
    other value, or an unrecognized value, is `invalid_request`.
  - **`max_age`** forces re-authentication when the session's `auth_time` is older
    than the requested window, and `max_age=0` behaves exactly as `prompt=login`
    (and forces `auth_time` in the ID token). The PRESENCE of `max_age` (including
    `max_age=0`) is checked EXPLICITLY, never by truthiness, so `max_age=0` is
    distinguished from an absent `max_age` (the classic integer-falsy conformance
    trap); a non-integer value is `invalid_request`.
  - **A forced interaction is CONSUMED on the resume**, so the flow completes after
    one round-trip instead of looping forever. The `/authorize` URL an interaction
    redirects back to drops the `prompt` token it just satisfied (`login` and
    `select_account` for a login, `consent` for a consent) and removes a consumed
    `max_age` (the fresh authentication satisfies any `max_age`, including
    `max_age=0`), while a marker preserves the `auth_time` emission that `max_age`
    required. Because a resume can only ever DROP a trigger, never inject a bypass,
    this cannot be used to skip a demanded re-authentication or consent.
  - **Interaction-hint seam** (`InteractionHints`): `login_hint` prefills the login
    form (reflected through the HTML escaper); `ui_locales`, `claims_locales`, and
    `display` (`page`/`popup`/`touch`/`wap`) reach a typed page-rendering context
    (the page `lang` attribute and a `data-display` layout hint); `logout_hint` is
    accepted and carried for a later logout surface (no logout endpoint is added).
    The typed struct is produced once at `/authorize` and carried across the
    interaction round-trip, the seam upstream-IdP forwarding (M8) plugs into (no
    upstream forwarding is done here).
  - **`unmet_authentication_requirements`** (and the new registered
    `login_required` / `consent_required` / `interaction_required` /
    `account_selection_required` error codes) refines the issue #15 essential-`acr`
    fail-closed: an essential `acr` whose pinned values NO available method can
    achieve (checked against `acr_values_supported`) is
    `unmet_authentication_requirements`; a value achievable in principle but not by
    this session stays `access_denied` (the residual step-up, M7). A VOLUNTARY
    `acr_values` preference remains best-effort and never errors (the achieved `acr`
    is reported honestly).
  - **Discovery** advertises `prompt_values_supported`
    (`none login consent select_account create`), `display_values_supported`
    (`page`), and `ui_locales_supported` / `claims_locales_supported` (English, the
    languages the bootstrap pages render), each sourced from the owning registry or
    const so discovery never advertises a capability the server does not honor.
- Legacy response types (`id_token`, `code id_token`, `none`), `form_post`, and
  per-mode response negotiation, DISABLED by default (issue #17). Extends the
  #12/#13 authorization endpoint; the provider stays gated off.
  - **Token-bearing response types are unrepresentable, not merely disabled.** The
    `ResponseType` registry is a closed set of exactly `code`, `code id_token`,
    `id_token`, `none`, with NO access-token component anywhere in the type, and
    `parse` maps every `token`-bearing spelling (in any order) to a rejected value.
    A structural test locks the set, so a token-bearing variant fails the build.
    The authorization endpoint therefore can never issue an access token, in any
    spelling (the permanent OAuth 2.1 / RFC 9700 2.1.2 non-goal).
  - **Front-channel ID tokens** for the implicit (`id_token`) and hybrid
    (`code id_token`) flows are minted through the token endpoint's EXACT claim and
    signing path (never a second signer, never an access token). `nonce` is
    REQUIRED for both. The hybrid ID token carries `c_hash` of the issued code; the
    pure implicit ID token carries neither `c_hash` nor `at_hash`. Per OIDC Core
    5.4, the pure `id_token` flow (which issues NO access token, so `UserInfo` is
    unreachable) emits the granted scope's claims AND the `claims` parameter's
    `id_token` member INTO the ID token, through the same shared `assemble_claims`;
    the hybrid flow stays lean (its code yields an access token, so `UserInfo`
    serves the authoritative claims).
  - **Response-mode negotiation** (OAuth 2.0 Multiple Response Type Encoding
    Practices): default `query` for `code`/`none`, `fragment` for the front-channel
    types; `query` is REFUSED for a front-channel type (it would leak an ID token
    into the logged, `Referer`-exposed query string); an illegal or disabled mode
    is `invalid_request`. `form_post` (Form Post Response Mode 1.0) returns an
    auto-submitting form with the response parameters as HTML-escaped hidden fields,
    a hash-pinned `script-src` CSP (no `unsafe-inline`), `form-action` scoped to the
    validated redirect origin, and `Cache-Control: no-store` / `Referrer-Policy:
    no-referrer`, so the code never lands in a URL, `Location`, or `Referer`.
  - **RFC 9207 `iss`** rides EVERY mode: query, fragment, and `form_post` all
    serialize the SAME mode-independent parameter list. Discovery advertises exactly
    the per-environment enabled set (`response_types_supported`,
    `response_modes_supported`), with `code`/`query` always on.
- UserInfo endpoint, scope-to-claims mapping, and the `claims` request parameter
  (issue #15). Builds on the #12/#13 authorization and token endpoints; the
  provider stays gated off (`oidc.enabled` unchanged).
  - **UserInfo endpoint** (`GET`/`POST`/`OPTIONS /userinfo`) that authenticates a
    Bearer access token from the `Authorization` header ONLY (a query-string token
    is `invalid_request`; a POST body token is unsupported by design). The token is
    resolved by an UNTRUSTED `jti` peek, then a scope-bound store lookup (the
    IDOR/revocation gate), then the one hardened JWS verify (signature BEFORE
    claims, `aud` bound to the resolved grant's client, `exp`/`iss`/revocation
    enforced): no claim is released before a valid signature. A missing token or an
    unsupported/empty `Authorization` scheme gets the bare `401 Bearer` challenge
    with no error code (RFC 6750 3); invalid/expired/revoked collapse to a uniform
    `401 invalid_token`; a token lacking `openid` is `403 insufficient_scope`.
  - **Scope-to-claims** (OIDC Core 5.4): the `profile`, `email`, `address`, and
    `phone` scopes map to their standard claim sets, served from UserInfo. `sub` is
    always derived through the ONE shared subject function (so the ID token and
    UserInfo agree) and can never be shadowed by stored claim data.
  - **The `claims` request parameter** (OIDC Core 5.5): voluntary and essential
    members, `value`/`values`, and both the `userinfo` and `id_token` targets. It
    is parsed and canonicalized at `/authorize` and FROZEN onto the grant and the
    code, so a client cannot widen its release at call time. Unsatisfiable
    voluntary/essential claims are omitted rather than erroring; an essential `acr`
    fails CLOSED at `/authorize`. Discovery advertises
    `claims_parameter_supported = true` via `DiscoveryCapabilities::from_config`.
  - **`oidc.conform_id_token_claims`** (default `false`, spec-conform) keeps the ID
    token lean with scope claims at UserInfo; `true` additionally copies them into
    the ID token for legacy relying parties (the node-oidc-provider
    `conformIdTokenClaims = false` behavior), documented as NON-conform.
    **`oidc.userinfo_cors_origins`** lists SPA web origins allowed to call UserInfo
    cross-origin: each is matched EXACTLY and echoed back (never a wildcard, no
    credentials), and CORS is offered on UserInfo ONLY. Both are promotable
    per-environment settings.
- PKCE enforcement, exact redirect matching, native-app redirect rules, and the
  RFC 9207 `iss` (issue #13). Hardens the #12 authorization and token endpoints;
  the provider stays gated off (`oidc.enabled` unchanged).
  - **PKCE is S256-only and mandatory.** `plain` is structurally absent (no
    registry variant, no config), so any method but `S256` (and a challenge with a
    defaulted method) is `invalid_request`. A PUBLIC client
    (`token_endpoint_auth_method` = none) MUST use PKCE (RFC 9700 2.1.1); a
    CONFIDENTIAL client follows the per-environment policy
    `oidc.require_pkce_for_confidential_clients` (default required). Downgrade
    prevention holds BOTH ways: a challenge-bound code needs the matching verifier,
    and a no-challenge code is never redeemable WITH one.
  - **redirect_uri is matched by EXACT string** against the client's registered set
    (via `ironauth_store`), with only the RFC 8252 loopback port exception; native
    private-use-scheme and claimed-`https` redirects are accepted, and a malformed
    scheme is rejected at authorization time as it is at registration. An
    unregistered or malformed redirect NEVER receives a redirect (an error page),
    so it cannot become an open redirector, and this holds on error paths too.
  - **RFC 9207 `iss`** is emitted on EVERY authorization response, success and
    error, assembled mode-independently (`src/response.rs`) so it covers the
    fragment and `form_post` modes issue #17 enables; discovery now advertises
    `authorization_response_iss_parameter_supported = true` via
    `DiscoveryCapabilities::from_config`.
  - **PKCE format is validated, not just the transform** (RFC 7636 4.1/4.2). The
    `code_challenge` must be a 43-character unpadded base64url SHA-256 digest at
    `/authorize` (a truncated or low-entropy binding is rejected up front as
    `invalid_request`, not deferred to a guaranteed token failure), and the
    `code_verifier` must be 43 to 128 unreserved characters at redemption, so a
    client cannot slip below the RFC's entropy floor even with a self-consistent
    challenge. The exact-string redirect comparator's loopback port exception now
    range-checks the port (`1..=65535`), and a registered `https` redirect carrying
    userinfo (`https://good@evil/cb`, a host-confusion vector) is refused at
    registration.
- Initial OIDC core provider: the authorization endpoint and the
  `authorization_code` grant (issue #12), mounted on the PUBLIC listener.
  - **Authorization endpoint** (`GET`/`POST /authorize`) and the token endpoint's
    `authorization_code` grant (`POST /token`), against a per-environment issuer.
  - **Single-use codes bound at issuance and re-checked BEFORE the code is
    burned.** Each `ac_` code binds its `client_id`, `redirect_uri`, `nonce`, and
    PKCE `code_challenge`. The token endpoint reads the code without consuming it,
    re-checks every binding INCLUDING the `client_id` (the 2026 Zitadel advisory
    class, RFC 6749 4.1.3), and pre-signs the tokens; only then does the atomic
    redeem consume the code. A wrong-binding presentation or a signing failure
    therefore never burns the one-time code, and any mismatch is a uniform
    `invalid_grant` that never says which binding failed.
  - **Single use across N stateless nodes** via one atomic DB statement under READ
    COMMITTED (`UPDATE ... WHERE consumed_at IS NULL RETURNING ...`), which also
    records the issued tokens and the redeem audit in the SAME transaction as the
    consume; zero rows affected is a miss that is then classified. No in-memory
    marker; a seam is left for a future cache accelerator.
  - **Reuse revokes the grant chain; a benign retry does not.** A second
    presentation within a configurable grace window (`oidc.reuse_grace_secs`,
    default 10s) is a benign double-submit or client retry: it is `invalid_grant`
    but does NOT revoke. Beyond the window it is a genuine reuse: the grant is
    revoked (flipping the observable active state of every token issued from the
    code, per an introspection/active-state check; it does not cryptographically
    invalidate an already-minted JWT) and the reuse is audited (RFC 9700).
  - **Grant record** links code, session, consent, and issued tokens: the spine
    for revocation and the M3 refresh families.
  - **Error handling.** `redirect_uri` and `client_id` are validated BEFORE any
    redirect; an invalid one renders an error page and never redirects. All other
    errors are spec-exact codes with `error_description` via the redirect (or the
    OAuth token-error JSON at the token endpoint).
  - **Forbidden flows are structurally absent.** There is no ROPC handler, no
    access-token issuance from the authorization endpoint, and no plain PKCE code
    path: the grant-type, response-type, and PKCE-method registries cannot express
    them, proved by a structural test.
  - Tokens (ID token and access token) are minted through the #9 signing core
    (`ironauth-jose`). ID-token claim contents are minimal here; the conditional
    claim rules are #14. PKCE plumbing is the minimal correct bind-and-verify; the
    S256-only enforcement hardening is #13.
  - **Hardening.** `redirect_uri` validation rejects any non-printable-ASCII byte
    (control characters, raw whitespace, non-ASCII), closing header-splitting and
    look-alike-authority smuggling before the `Location` header is written. The
    authorization-code and issued-token identifiers redact their payload in
    `Debug` so a struct dump or a `tracing` field cannot leak a live bearer
    secret. Issue and redeem audit rows are attributed to the client the flow is
    for, not a throwaway identity. Emits `ironauth_oidc_code_reuse_total` and
    `ironauth_oidc_redeem_error_total` counters.
- New persistence (issue #12, in `ironauth-store`): migration `0004`, the
  tenant-scoped `grants`, `authorization_codes`, and `issued_tokens` tables (RLS
  enabled and forced, nonempty-scope CHECK, and isolation-preserving COMPOSITE
  `(grant_id, tenant_id, environment_id)` foreign keys so a code or token can only
  reference a grant in its own scope), the scoped `authorization` repository, and
  the `authorization_codes.redeem` / `issued_tokens.token_status` IDOR probes.
