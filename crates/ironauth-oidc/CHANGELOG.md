# ironauth-oidc changelog

All notable changes to the `ironauth-oidc` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
