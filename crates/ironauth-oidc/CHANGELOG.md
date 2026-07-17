# ironauth-oidc changelog

All notable changes to the `ironauth-oidc` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Declarative claim-mapped provisioning for federated login (issue #75, PR C): the callback now
  provisions a federated user's identity TRAITS from the connector's declarative claim mapping,
  completing the "login works with zero code changes" acceptance criterion (PR B half-met it).
  - **The evaluator seam.** After the upstream ID token is validated, the callback evaluates the
    connector's `claim_mapping` (via `ironauth_connector::evaluate`) against the VERIFIED
    id-token claims, type-checked against the scope's active `TraitSchema` (adapted to the
    connector crate's store-free `TraitSchemaView`). The evaluator NFKC-normalizes the resolved
    `email` trait value itself (before its type check), so the mapped email is canonicalized
    regardless of the claim path it resolves from (a top-level `email` or a nested path like
    `emails.0`) and the type-checked and stored values are the same canonical form; the callback
    no longer pre-normalizes only the top-level `email` claim.
  - **Fail-closed (the acceptance-critical crux).** On ANY mapping failure (a missing required
    claim, a wrong type, an undeclared trait, or no active schema for mapped traits) the login
    aborts BEFORE any user row is written or mutated: NO partial identity is ever provisioned. A
    mapping-definition fault is a `Config` error and an upstream claim fault is an
    `UpstreamProtocol` error (distinguished so an operator can tell "my mapping is wrong" from
    "the IdP is misbehaving").
  - **Provisioning.** The local identity still keys on the VERIFIED, issuer-namespaced
    `(issuer, sub)` composite (unchanged from PR B), never the mapped subject. A first login
    creates the user with the mapped traits (or a minimal identity when the mapping maps none); a
    returning login refreshes the mapped traits in place (a documented policy) on the one identity.
  - `VerifiedUpstreamIdentity` now retains the full verified id-token claims (so the mapping can
    resolve trait fields from them); `ConnectorRuntimeConfig` reads back the connector's
    `claim_mapping` and `quirks`.
- Generic OIDC UPSTREAM for inbound federation (issue #75, PR B): the wire that turns a
  declarative connector (PR A) into a full federated login with ZERO per-provider code.
  - **The federated login legs** (string-literal routes on `oidc_router`):
    `GET /t/{tenant}/e/{env}/federation/{connector_slug}/authorize` loads the DATA-ONLY
    connector by slug, generates an unguessable `state`/`nonce` (and a PKCE `S256` challenge
    when the upstream advertises it) from the entropy seam, persists the single-use
    correlation row (migration 0058, the PKCE verifier SEALED), and 302s to the upstream;
    `.../callback` consumes the correlation row by `state` SINGLE-USE (the CSRF defence),
    exchanges the code with the PRODUCTION-unsealed client secret and the bound verifier,
    VALIDATES the upstream ID token through the JOSE core, and only then provisions and
    resumes. Both mapped in `docs/conformance/rfc9700-checklist.md`. WIRED by the server boot
    path (`build_oidc_router`) when `oidc.federation.enabled` is set (OFF by default), which
    constructs the `FederationRuntime` (its own SSRF-hardened fetcher plus the configured
    discovery / JWKS TTLs) and installs it via `OidcState::with_federation`; with federation
    disabled the `/federation` routes stay a uniform not-found.
  - **Cross-connector takeover fix** (issue #75, HIGH-1). The local federated identity is keyed
    on the upstream ISSUER + `sub`, not the bare `sub`: an OIDC `sub` is unique only within one
    issuer (OIDC Core section 2), so keying on the bare `sub` let two connectors to DIFFERENT
    IdPs that emit the same `sub` resolve to the SAME local user (an account takeover by anyone
    running a second connector's IdP). The external-id is now a length-prefixed
    `(issuer, sub)` composite (`federated_external_id`): same issuer + same `sub` still shares
    one user; different issuers with the same `sub` are distinct users. A downstream RS MUST key
    trust on `acr` (`urn:ironauth:acr:federated`), NOT on the passed-through `amr`, which merely
    reflects the UPSTREAM's own assertion.
  - **Upstream key rotation without waiting out the TTL** (issue #75, LOW-1). When an upstream ID
    token names a `kid` the cached JWKS does not answer to, the resolver triggers ONE bounded
    refetch (`resolve_for_kid`, the `kid` a REFETCH HINT via `ironauth_jose::compact_jws_kid`,
    never a key source) before failing closed, so a rotated-in upstream key is picked up on the
    next login. Explicit-endpoint connectors are rejected CLEANLY at the authorize leg (LOW-3),
    and `enabled` is RE-CHECKED at the callback (INFO-2) so a connector disabled mid-flow fails
    closed.
  - **Minimal provisioning + honest LOCAL token.** From the VERIFIED upstream `sub` it
    find-or-creates a local user by external id (no local password) and establishes a local
    session, then resumes the pending local `/authorize` so the LOCAL token flow issues the
    token. The session's `auth_methods` carries the federated method PLUS the upstream `amr`
    passthrough (base64url-encoded in one reserved token that survives the persistence
    channel), so the MINTED local token's `amr` is the upstream's asserted `amr` VERBATIM and
    its `acr` is the federated context, never a fabricated local factor (proven end to end by
    the `federation` suite and the `tokens` mint test). The federated context is deliberately
    UNRANKED (excluded from `acr_values_supported` and the step-up ladder): IronAuth cannot
    vouch for another operator's assurance level.
  - **Upstream ID-token validation through the ONE JOSE entry point** (`federation` module, the
    security crux). Building a `VerificationPolicy` that pins the algorithm allowlist (the
    upstream-advertised or connector algorithms INTERSECTED with the JOSE core's allowlist, so
    `none`/HMAC are inexpressible), the cached upstream trusted keys (never a token-embedded key),
    the expected issuer (the configured connector issuer), and the expected audience (the
    connector client id), then verifying the bound `nonce`. It writes NO crypto: `alg: none`,
    algorithm confusion, an unknown `kid`, a forged issuer, a wrong audience, an expired token, a
    forged signature, and a `nonce` mismatch ALL die in `ironauth_jose::verify` and yield
    `ConnectorError::UpstreamProtocol` with NO identity produced.
  - **Per-connector upstream JWKS cache through the hardened fetcher** (`federation_jwks` module),
    copied from the `private_key_jwt` client-key resolver and keyed per `(connector_id, jwks_uri)`,
    SEPARATE from the local signing keys. A private-range `jwks_uri` is `FetchError::Blocked` on the
    wire (resolve-once, no rebind), so resolution yields no keys and validation fails closed as
    `UpstreamUnavailable`. A non-empty resolution is cached for a bounded, clock-seam TTL.
  - **Discovery + code exchange over the hardened fetcher.** `fetch_discovery` resolves an
    issuer-form connector through `FetchPurpose::FederationDiscovery` (parsing and mix-up-checking
    via `ironauth-connector`), and `exchange_code` posts the code through `FetchPurpose::FederationToken`.
    Every federation outbound rides `ironauth-fetch`; a private-range issuer is likewise Blocked.
  - **Honest `AuthMethod::Federated`** (the covenant). A new registry row achieving the DISTINCT
    `urn:ironauth:acr:federated` context, deliberately unranked against the local ladder (IronAuth
    cannot vouch for another operator's assurance level). It contributes NO local `amr` factor: the
    upstream's OWN asserted `amr` tokens are carried as passthrough DATA on a new
    `AuthenticationEvent::federated` constructor (never re-asserted as a local factor), and if the
    upstream asserted no `amr`, IronAuth asserts none. `auth_time` is the upstream `auth_time` when
    present, else the callback instant. `authn.rs` stays the single honest source for `acr`/`amr`.
  - **Error taxonomy mapping.** `FetchError` -> `UpstreamUnavailable`, a JOSE verify failure ->
    `UpstreamProtocol`, a policy/config fault -> `Config`, consuming the `ironauth-connector`
    `ConnectorError` contract issue #76 builds on.
- Registration abuse defenses (issue #80), all OFF by default. An invisible, SELF-CONTAINED
  proof-of-work challenge (a Rauthy-spow-style hashcash) issued on the registration,
  password-reset, and OTP-send surfaces: the server issues a random challenge and a
  difficulty via the env entropy/clock seam, the client finds a nonce such that
  `SHA-256(challenge || nonce)` has N leading zero bits, and the server verifies it FULLY
  server-side with ZERO third-party calls (so it works self-hosted and air-gapped and can
  never fail open/closed on an outage). Challenges are SINGLE-USE (an atomic spent-latch
  consume in the new `pow_challenges` store table), EXPIRING (`env.clock()`), and
  CONTEXT-BOUND to the endpoint plus a request context (a solution for one endpoint/context
  cannot be replayed or outsourced to another). Issuance is CONDITIONED on the #79 risk
  level (`pow.challenge_at` reuses the `off`/`low`/`med`/`high` threshold vocabulary via a
  new subject-less `anonymous_challenge_level`), and a new `POST /pow/challenge` endpoint
  mints a challenge for the built-in path. A pluggable `ChallengeProvider` trait (`pow`
  module) has the built-in `BuiltinPowProvider` as the DEFAULT and ships Turnstile and
  reCAPTCHA as `SiteverifyProvider` adapters behind a `RemoteChallengeVerifier` seam (the
  real verify goes through `ironauth-fetch`; a mock satisfies the contract test); an adapter
  outage degrades per a configurable fail-open/fail-closed policy, and the built-in PoW is
  installed via `OidcState::with_challenge_provider`.
- Disposable / low-reputation email defense (issue #80): evaluated at signup on the
  NFKC-normalized email domain, per-environment `off` / `flag` (feed the risk engine a MED
  signal) / `block`. A BLOCK is an ANTI-ENUMERATION uniform failure (an ordinary validation
  re-render that never leaks whether the account exists), reusing the #64/#68 discipline.
  The deny list and an allow override are updateable per-environment config data (the #79 IP
  allow/deny-list precedent) that promotes with the config snapshot.
- Waitlist gate (issue #80): a per-environment toggle that lands a self-service signup in a
  PENDING `waitlisted` lifecycle state that CANNOT authenticate (fenced at login, holds no
  session/token capability) until an admin approves it (transition to active) or rejects it
  (transition to disabled) through the existing user-lifecycle management API.
- Registration-abuse hardening follow-ups (issue #80):
  - The account-lifecycle fence is now CENTRALIZED in `interaction::establish_session`, the
    single choke point EVERY session-minting path funnels through, so no factor can mint a
    session for a non-authenticatable account. Previously only the password, token/refresh,
    and device paths consulted `UserState::can_authenticate()`; the passwordless paths
    (email-OTP verify, magic-link consume, SMS-OTP verify, WebAuthn assertion) omitted it, so
    a waitlisted, blocked, disabled, or pending-verification account could obtain a full
    session through them. `establish_session` now resolves the subject's state and REFUSES
    with a `NotAuthenticatable` outcome that each caller renders as its OWN uniform
    auth-failure shape (the same wrong-code / failed-ceremony response a normal failure
    returns), so it is never an existence/state oracle; Active and ScheduledOffboarding are
    unaffected and the already-gating paths are unchanged. This closes a systemic
    pre-existing hole that the #80 waitlist surfaced.
  - `magic/send` is now proof-of-work gated at parity with `otp/send` (via a new
    `magic_send` challenge endpoint label with its own context binding), so every
    OTP-send-class endpoint (register, recover, otp/send, magic/send) is consistently
    protected when PoW is enabled.
  - `POST /pow/challenge` is now per-IP mint-rate throttled through the #64 abuse layer and
    eagerly reclaims a bounded batch of the scope's already-expired challenge rows on each
    mint, so an unauthenticated caller cannot grow `pow_challenges` without bound.
  - KNOWN LIMITATIONS / future work: waitlist approval is today a plain `waitlisted ->
    active` flip, which satisfies "approval triggers the normal verification flow" only
    vacuously because open registration has no email-verification step yet; when the
    email-verification milestone lands, approved-waitlist accounts MUST be routed through it.
    Disposable-domain normalization folds fullwidth / compatibility forms via NFKC (closing
    the classic dodges) but does NOT yet defend against genuine punycode / IDN homographs, a
    deeper homograph-normalization follow-up.
- Account recovery as a first-class subsystem (issue #81): a distinct recovery state
  machine, NOT a branch of password reset, governed by three pillars. DELAY as a security
  feature: a recovery that would REDUCE account security is HELD for the configured
  `oidc.recovery_delay_secs` window before it can complete, cancellable throughout.
  NOTIFICATION everywhere: initiating recovery notifies EVERY registered channel (all
  verified emails and phone numbers) through the #68 verification seam, with a
  cancellation path; completion and factor changes notify again. THE DOWNGRADE INVARIANT:
  recovery can NEVER silently remove or bypass a factor STRONGER than the one used to
  recover; removing such a factor requires EITHER a fresh equal-or-stronger re-verification
  OR the elapsed delay window. "Stronger" REUSES the issue #66 credential-ladder / `acr`
  strength order via `step_up::acr_satisfies` and `AuthMethod::acr` (no parallel ordering):
  an email-OTP recovery restores access but leaves a passkey or TOTP intact and its removal
  BLOCKED until the rule is satisfied. Adds the `recovery` domain module
  (`initiate_recovery`, `cancel_from_token`, `evaluate_factor_change`,
  `factor_change_decision`, the `RecoveryFactor` projection onto `AuthMethod`), the
  `RiskEvaluator` SEAM (a null/allow default, installed with `OidcState::with_risk_evaluator`)
  so issue #79's risk engine can force the delay path or block a recovery without a hard
  dependency, and a `POST /recover/cancel` scanner-safe cancellation surface (a GET renders
  a confirm page but never cancels; a same-origin POST with the high-entropy token revokes
  the pending recovery). The `POST /recover` surface now, for a KNOWN account, creates the
  (possibly delay-held) flow and notifies every channel side-effect-only, so it stays
  byte-identical to an unknown identifier (anti-enumeration). The per-account cooldown
  (`oidc.recovery_cooldown_secs`) rate-limits repeated initiations. All timers run through
  the env clock seam (no wall-clock sleeps) and the cancellation token through the entropy
  seam.
- Review fix (issue #81): the downgrade invariant is now ENFORCED on the LIVE
  factor-removal surface, not just in `evaluate_factor_change`. The three removal handlers
  (`POST /webauthn/credentials/remove`, `POST /account/credentials/remove`,
  `POST /account/mfa/totp/remove`) and the password-removal path
  (`POST /account/password/remove`) consult a subject's pending recovery flow before
  removing a factor: if a recovery is pending, removing a factor STRONGER than the one the
  recovery was performed with is refused with a non-enumerating `409`
  (`recovery_downgrade_blocked`) while the flow is held (`hold_until` in the future) and no
  fresh equal-or-stronger re-verification is proven, and the `recovery.factor_change`
  transition is audited live either way. The webauthn removal projects the credential's TRUE
  passkey rung (attested > device-bound `phrh` > synced `phr`); a fresh session within the
  step-up window unblocks a downgrade at its achieved strength (`AllowedByReverify`), and a
  removal past `hold_until` proceeds (`AllowedByDelay`), so a stale delay-elapsed flow never
  perpetually locks removals. The gate keys off the PRESENCE of a pending recovery flow
  (recovery access is an ordinary email-OTP session, not a special session type). The
  `POST /recover` unknown-identifier branch now runs an anti-timing DECOY performing the
  SAME risk-seam call and store round-trips as a known initiation before the identical
  acknowledgment, so a registered identifier is not distinguishable by latency (the #68/#70
  discipline). The recovery hold decision now fails CLOSED (a strongest-factor read fault is
  treated as the ladder's top rung, routing to the HELD delay path) and projects the TRUE
  strongest enrolled passkey rung, so a device-bound / attested passkey holder is never
  under-held.
- Known limitation (issue #81, M11): the recovery cancellation link is minted but not yet
  DELIVERED. `recover_post` discards the cancellation token and the notify transport is the
  M11 stub, so the "cancellable from a notification link" path is structurally correct
  (token minted, digest stored, `GET/POST /recover/cancel` wired) but not reachable end to
  end until M11 wires the token into the delivered message.
- Minimal risk engine (issue #79), off by default behind `oidc.risk.enabled`. The design
  bet is LEGIBILITY over ML: a small set of explainable signals feed a LOW/MED/HIGH score
  through a documented, deterministic combination rule (the base is the max signal
  contribution; two or more MED-or-higher signals escalate a MED base to HIGH) and a
  three-verb action vocabulary (block / challenge / notify). Signals, each independently
  toggleable per environment: NEW-DEVICE (reuses the #71 trusted-device state, read-only),
  IMPOSSIBLE-TRAVEL (geo-velocity via a PLUGGABLE `GeoIpProvider` seam, null default, no
  bundled dependency), IP-REPUTATION (per-environment allow/deny lists plus a pluggable
  `IpReputationProvider` seam, null default), and VELOCITY (per-account/IP/ASN rates on the
  #64 `CounterStore` layer). Every decision is persisted and audited (`risk.decision`),
  enumerating each contributing signal so a sampled decision is reconstructable from the
  audit trail. The score feeds the #72 step-up seam: at `oidc.risk.require_mfa_at=med` a
  MED-or-stronger score raises the effective requirement so `evaluate_step_up` challenges a
  second factor, while a LOW score does not. A `block` returns the SAME uniform failure as
  an ordinary wrong password (only an explicit IP deny-list hit blocks; a velocity flood
  raises the score but never blocks, so a shared NAT cannot lock a victim out). A new-device
  login sends a notification (through the #68 `VerificationSender` seam, extended with
  `deliver_new_device_notice`; the default sender performs no delivery) carrying the device,
  User-Agent, and geo context plus a single-use "this wasn't me" link. The global
  `/risk/disavow` endpoint (GET a scanner-safe confirmation page, POST to execute) consumes
  the single-use token, revokes the flagged sessions (all of the subject's, signing out
  everywhere) and every trusted device, and marks the credentials for review, all audited
  and uniform. The engine runs COMPLETE with zero IronCache and zero third-party services
  (the null-provider default path). Providers install via `OidcState::with_geoip_provider`
  / `with_ip_reputation_provider`.
- Adversarial-review hardening (issue #79): the `GET /risk/disavow` confirmation page now
  HTML-escapes the reflected `token` query parameter before interpolating it into the
  hidden-field attribute (closing a reflected XSS: a `token` of `"><script>...` is
  neutralized), and both the disavow GET and the POST result page now serve through the
  shared `pages::secure_html` seam, so they carry the SAME strict hosted-page hardening
  headers as every other page (CSP `default-src 'none'`/`form-action 'self'`/`frame-ancestors
  'none'`, X-Frame-Options DENY, nosniff, no-store, same-origin referrer). A blocked
  (deny-listed) login now records its risk decision OFF the synchronous response path (a
  detached spawn, like the on-login breach screen), so a block is timing-uniform with an
  ordinary wrong-password failure and leaks neither the block nor password validity to the
  deny-listed client (the decision/audit row is still written). New-device notifications are
  now deduped per (subject, device/User-Agent fingerprint) over `oidc.risk.notify_cooldown_secs`
  (reusing the #64 counter layer), bounding a repeated-new-device notification flood to at
  most one notice (and one minted disavowal token) per new device per window. The audit
  `risk.decision` detail now also carries a compact PII-free enumerated signal summary
  (signal kinds + levels), so a decision is reconstructable from the audit trail alone even
  if the `risk_decisions` row is pruned.
- Trusted devices (remember-device 2FA) and the conditional-credential skip (issue #71),
  off by default behind `oidc.trusted_devices_enabled`. After a COMPLETED multi-factor
  login the `POST /login/mfa` path may plant a `__Host-ironauth_trusted_device` cookie
  (`<tdv_ id>.<secret>`, HttpOnly, Secure, SameSite=Lax); only the secret's SHA-256 DIGEST
  is stored server-side, so the cookie is not a self-contained skip token. On a subsequent
  login the authorize gate (`evaluate_step_up`) validates the cookie server-side
  (subject-bound, not revoked, within the per-tenant max-age and idle windows) and, when
  the ONLY unmet requirement is the tenant baseline MFA credential-class floor, SKIPS the
  second factor while primary authentication still runs. The honesty crux: a new
  `AuthMethod::TrustedDevice` (amr contributes NOTHING) yields a DISTINCT, weaker
  `urn:ironauth:acr:mfa_remembered` acr ranked BELOW `mfa`, so the token records
  `[<primary>, trusted_device]` (acr `mfa_remembered`, and an amr that NEVER fabricates
  `mfa`/`otp` from the cookie). Precedence: an explicit RFC 9470 / issue #72 step-up acr
  floor and a passkey/attested credential-class floor are NEVER satisfied by a remembered
  device; the conditional-credential skip keys on `performed_second_factor` (a genuine
  TOTP/recovery code or a USER-VERIFIED passkey carries `mfa`), so a UV passkey satisfies
  the MFA requirement with no extra prompt while a non-UV passkey does NOT. Trusted devices
  appear in the M6 device list and are revocable one or all
  (`GET/POST .../account/trusted-devices[/revoke|/revoke-all]`); revocation is server-side
  IMMEDIATE (a replayed cookie then fails), and a password change invalidates trust per
  the `oidc.trusted_device_revoke_on_password_change` policy. The token endpoint mirrors
  the composition, honoring a frozen `trusted_device` contribution.
- Review fix (issue #71): removing an MFA/login factor now invalidates the subject's
  remembered devices (reason `FactorChange`) from the TOTP-remove, passkey/webauthn-remove,
  and account credential-remove surfaces, so a replayed device cookie re-prompts after a
  factor change. Setting a FIRST password (the passkey-only conversion) now invalidates
  trusted devices through the same seam a password change uses, for consistency. Documented
  the revocation scope: a device revoke is IMMEDIATE for the MFA-skip but does NOT
  retroactively kill sessions or refresh-token families already issued from the device
  (those are the issue #61 session-revocation domain).
- WebAuthn Level 3 Signal API and conditional-create, EXPLORATORY and off by default
  (issue #73). Behind the new per-environment `oidc.webauthn_signal_api_enabled` flag, the
  hosted passkey-management page (`GET .../webauthn/manage`) emits ONE nonce-guarded,
  feature-detected script that reads a new authenticated signal-data endpoint
  (`GET .../webauthn/signal`) and calls `signalAllAcceptedCredentials` (dropping
  server-deleted ghost credentials) and `signalCurrentUserDetails`; the login ceremony
  script additionally calls `signalUnknownCredential` on a failed assertion the server
  reports as a ghost. Behind the additional `oidc.webauthn_conditional_create_enabled`
  policy (with a per-tenant frequency cap), a passkey-less user is offered a
  `mediation: 'conditional'` silent upgrade recorded through the STANDARD #65 registration
  ceremony, wrapped so a failure never interrupts anything. Every call is feature-detected;
  an unsupported browser and a flag-off deployment see no behavior change and no errors
  (the endpoint is a uniform 404 and the page emits no script). The literal Chrome-132
  browser behavior (the authenticator drop/update) is deferred to the browser-conformance
  wave, matching the #20/#17 precedent; the server endpoints, the flag-gated page emission,
  the accepted-credential id list, and the conditional-create policy gating are tested
  rust-natively. Reuses the freshness seam via a new `step_up::privilege_is_fresh`.
- Direct-mode attestation end-to-end coverage (issue #66 PR B, adversarial review): a new
- Passkey-only accounts, bidirectional conversion, and password-strength scoring (issue
  #66 PR C, CLOSES #66). A first-class passwordless account state: the new scope-routed
  `webauthn/signup/options` + `webauthn/signup/verify` endpoints create an account with
  the unusable password sentinel and `passwordless = true` (no session required, no
  password screen/hash/policy reachable), run a UV-REQUIRED passkey registration, and
  establish the HONEST passkey session (`phr`/`phrh`/`attested_passkey`, never a
  fabricated `pwd`) that resumes the authorization request. The account is created only
  when the passkey is verified, so an abandoned ceremony leaves no orphan;
  `webauthn/signup/verify` now re-checks `registration_closed()` too, so a registration
  toggled closed MID-ceremony cannot still complete (adversarial review INFO). A password
  attempt against a passwordless account fails uniformly (the sentinel never verifies), so
  a passwordless account is never offered the password form; that password-login attempt
  now spends the SAME dummy Argon2 hash an absent account pays (adversarial review LOW-2),
  closing a login-timing enumeration oracle where the sentinel's fast PHC-parse failure
  distinguished an existing passwordless account by its quick response. Bidirectional
  conversion: `POST /account/password/remove` removes the password (password ->
  passkey-only), gated by a FRESH passkey re-authentication and the cross-source
  last-credential guard (a documented residual: that guard counts any passkey and does not
  require the surviving one to be UV-capable, a future policy option); the change-password
  endpoint gains a passwordless branch (passkey-only -> password) that skips the
  current-password check, demands a FRESH passkey re-auth, and runs the full set-path
  policy. Coarse password-strength scoring (`min_password_strength_score`, default 0 = off)
  is wired into the register, account change-password, and invitation-accept set/change
  hooks, scored after the length/composition policy and before the breach screen; it is a
  length/charset/pattern floor BLIND to dictionary words and l33t substitution, so the
  breach screen remains the primary defense (see the `ironauth-screening` changelog).
  `webauthn_attestation` integration test (real database, software authenticator) exercises
  the registration GLUE the unit tests could not: attestation mode `direct`, the AAGUID-rule
  disposition lookup, the `mds3_blob_cache` read/parse, the packed-format dispatch, and the
  row stamping. It proves a valid packed attestation over an allow-listed AAGUID stamps
  `attestation_verified` + `attestation_type`/`fmt` and that a subsequent login reaches the
  `attested_passkey` acr, plus the fail-closed negative: a non-allow-listed AAGUID under
  `direct` is rejected and stamps nothing.
- Passkey attestation activation (issue #66 PR B): the dormant `attested_passkey`
  credential-class rung is now ACTIVE. Registration under a tenant's `direct` attestation
  mode evaluates the presented AAGUID against the allow/deny rules and validates the
  packed attestation against the scope's verified FIDO MDS3 cache, stamping a
  reg-time-immutable `attestation_verified` verdict onto the credential; a passkey login
  reads that stored verdict to record the attested method through ONE recording path, so
  an attested login earns the `attested_passkey` acr end to end while a plain passkey
  never can. The disjoint attested representation is reconciled: `satisfied_class` now
  includes the attested variants and agrees with the achieved acr, and a login-path
  covenant self-check (`satisfied_class` + `CredentialFacts` fed from the stored row)
  makes those helpers load-bearing. `ACR_ATTESTED` is ranked at the top of the default
  step-up order so strictest-wins composition is exact. Adds the `mds3_sync`
  verify-and-cache job (fetch through the SSRF-hardened client, verify against the pinned
  FIDO root, cache the verified entries).
- Guarded SMS OTP adversarial-review hardening (issue #70): the no-silent-downgrade
  invariant now holds for EVERY purpose, not only `login` / `recovery`. Previously every
  successful verify (any purpose) fell through to a full PRIMARY session, so `mfa`,
  `verify_address`, and `register` each minted an authenticated `sms` session on a
  passkey / TOTP-protected account while SKIPPING the strong-factor check (a SIM-swap
  factor-downgrade to account takeover). Now only `login`, `recovery`, and self-service
  `register` are session-establishing and each passes the `has_stronger_factor` gate
  (blocked for a protected account unless the tenant opted into the documented downgrade
  path); `register` is a no-op gate for a genuinely new account but blocks an EXISTING
  protected one. `mfa` and `verify_address` are now NON-session-establishing possession
  proofs (`{"verified":true,"purpose":...}`, no `__Host-ironauth_session` cookie, never
  `authenticated:true` or an `amr`): SMS-as-a-second-factor session elevation is the
  step-up flow (issue #72), and minting a primary session from an `mfa` OTP alone would
  claim a first factor that was never proven. The downgrade BLOCK no longer short-circuits
  faster than a real attempt (it runs the same resolve + Argon2 + single durable write, so
  a blocked strong-factor account is timing-uniform with a wrong guess and not a
  factor-possession oracle). The SEND path now falls through to the UNIFORM ack on a
  hashing-pool rejection instead of surfacing a distinct 429/503, closing a
  present-vs-absent enumeration oracle under pool back-pressure. The pumping alarm compares
  the RAW conversion ratio against the threshold rather than a rounded integer percent, so
  the effective threshold is exact (a 29.5 percent route no longer rounds up to a healthy
  30). The route bucket is per-COUNTRY (a documented known limitation; carrier-bucket
  granularity is a follow-up).
- Guarded SMS OTP with pumping defense (issue #70): new `otp/sms/send` and `otp/sms/verify`
  handlers reuse the #68 email-OTP core (rejection-sampled numeric code, #62-pool Argon2
  hashing, single-active-per-(subject, purpose), single-use consume, per-code attempt death,
  reissue invalidation, #64 abuse throttle on verify) and add the SMS-specific guard layer.
  SMS is OFF by default at two layers: a deployment kill switch (`sms_otp_enabled`, default
  false, fails closed with a 404) and a per-tenant enablement that stays unusable until the
  tenant explicitly turns it on AND populates a country ALLOWLIST (never a blocklist; an
  empty allowlist means unusable, not open). A destination outside the allowlist, an
  unparseable number, or a number that fails pre-send phone SCORING (a documented,
  self-contained number-type table blocking toll-free / premium / virtual / malformed
  ranges) is refused with a UNIFORM acknowledgment and an EQUAL dummy Argon2 spend, so no
  branch is an existence / allowlist / scoring oracle. Velocity caps (per-number,
  per-tenant, per-route send caps plus a per-number cooldown) layer on the #64 in-process
  counters. The differentiating pumping defense tracks send-to-verify CONVERSION per route
  (country bucket): a route whose conversion drops below a configurable threshold over a
  sufficient sample AUTO-THROTTLES without operator intervention while HEALTHY routes keep
  sending, emitting both an audit (`sms_route.throttled` + `sms_route.conversion_alarm`) and
  an ops metric. A no-silent-downgrade invariant blocks SMS from completing a login/recovery
  for an account protected by a passkey or active TOTP unless the tenant configured the
  explicit downgrade path. New `AuthMethod::Sms` reports `amr` `sms` HONESTLY (RFC 8176),
  distinct from the email/app `otp`. Phone-scoring heuristics and conversion-rate arithmetic
  are pure and unit-tested; the full lifecycle, allowlist enforcement, velocity caps, the
  pumping simulation, and the downgrade block are integration-tested against a stub provider.
- Credential-class ladder + honest acr feed + strictest-wins enforcement (issue #66, PR A):
  the covenant-critical spine of the passkey policy engine. A new `CredentialClass` ladder
  (`Any < Mfa < Passkey < AttestedPasskey`, `Ord`-derived so `max()` is strictest-wins)
  lives co-located with the acr registry in `authn`, the ONE honesty choke point. A pure
  `satisfied_class(event, facts)` folds the SATISFIED class ONLY from stored/proven facts
  (the frozen registration-time backup-eligibility, the actually-asserted user-verification
  bit, and the dormant stored attestation fact), never a client-supplied wire value;
  `required_class(policies)` composes applicable policy minimums with strictest-wins; and
  `acr_for_class` is the single canonical class -> acr mapping the step-up gate and the class
  enforcer both compare against. The four `attested_passkey` `AuthMethod` rows and the
  `urn:ironauth:acr:attested_passkey` ACR ship DORMANT (`is_active() == false`), so the rung
  is unreachable and requiring it fails closed until PR B lands the attestation writer;
  `AuthenticationEvent::attested_passkey` records it ahead of activation. Enforcement folds
  the tenant's required class into the existing step-up requirement as an acr floor (so the
  one gate steers an under-class session to the passkey ceremony / enrollment and never mints
  a token above the SATISFIED class), with `required_credential_class` exposing the class a
  subject must reach for the enrollment-plan surface. NO attestation/MDS3 (PR B), NO
  passkey-only signup or password-strength scoring (PR C).
- Email OTP + magic-link adversarial-review hardening (issue #68): the `otp/send` and
  `magic/send` handlers now EQUALIZE their present-vs-absent response WORK, closing a
  timing enumeration oracle. The present path spends one #62-pool Argon2 hash (on the code /
  short code); an unknown or suppressed recipient now burns the SAME single dummy Argon2
  hash through the same pool (mirroring the verify path's `verify_absent`), so a probe can no
  longer distinguish a real from an unknown recipient by send latency. The cross-device
  magic-link SHORT CODE (a low-entropy 6-8 digit secret) is now per-link ATTEMPT-LIMITED:
  a wrong short-code guess increments a per-link counter and the link is invalidated at the
  budget (reusing `email_otp_max_attempts`), closing a binding-cookie-plus-IP-rotation
  brute force that the per-IP throttle alone did not stop; the high-entropy same-device token
  path is unchanged. The send acknowledgment page now renders a minimal `short_code` entry
  form posting to the consume endpoint, so the cross-device flow is completable through the
  UI rather than only a raw POST. The `HashingPool` gains a test-only `argon2_ops` counter
  (a deterministic seam for the send-timing-equalization regression test).
- Email OTP and scanner-safe magic links (issue #68): two passwordless / recovery /
  address-verification factors on the #64 abuse-defense layer. Email OTP mints a numeric
  6-8 digit code (per-tenant width and 5-10 minute TTL), single-active per (user, purpose)
  so reissue invalidates the predecessor, hashed through the #62 pool (constant-time verify),
  with a per-code attempt counter that kills a code after N wrong guesses; send/verify are
  throttled per recipient and per tenant, and a send to an unknown recipient is suppressed
  with an identical acknowledgment (the anti-enumeration contract). Magic links are the
  differentiator: a GET on the link renders a CONFIRMATION PAGE ONLY (a prefetching email
  scanner can never consume the single-use link), consumption is a POST from that page, the
  token can ride the URL FRAGMENT (kept out of server logs and scanner request paths via a
  nonce-guarded page script), and a same-device binding cookie binds consumption to the
  requesting browser with a cross-device fallback to a short code printed in the same email.
  Tokens are CSPRNG `ira_mlk_<id>~<secret>` stored digest-only (issue #29), the short code is
  Argon2id-hashed, consumption is a guarded single-use UPDATE, and a successful sign-in
  establishes a session with an honest `otp` amr (new `AuthMethod::EmailOtp`). New routes
  `otp/send`, `otp/verify`, `magic/send`, `magic/confirm`, `magic/consume` (mapped in the
  RFC 9700 checklist); the `VerificationSender` seam gains `deliver_email_otp` /
  `deliver_magic_link` with a `LoggingVerificationSender` dev transport (the real email
  provider is an M11 seam). New `oidc.email_otp_*` / `oidc.magic_link_*` config.
- Breached-password screening adversarial-review fixes (issue #63). Closed a MEDIUM: the
  invitation-accept password path (`accept_invitation`) now runs the SAME
  evaluate-policy-then-screen-BEFORE-hash sequence as register and account change-password,
  so an invitee who chooses their own password can no longer set a breached or
  sub-15-code-point password on a real credential-set path (a breached or policy-violating
  password is refused with a non-enumerating error and the pending user is not activated; a
  passkey invitation is unaffected). Made on-login screening NON-BLOCKING: when
  `screen_on_login` is enabled the (potentially outbound HIBP) screen is now spawned DETACHED
  instead of awaited inline, so a slow or hung provider can no longer add latency to (or
  stall) the login hot path; the detached task still emits the breached-at-login audit event
  and metric and never changes the login outcome, and it clones only what it needs (never
  logging the plaintext). Documented residuals: the `FactorContext::MfaFactor` 8-code-point
  floor is inert until the MFA-enrollment context drives it; no password reset/recovery
  surface exists yet (a future one must wire the same evaluate+screen-before-hash); screening
  digests the NFKC-normalized (canonical stored) form while HIBP is raw-byte SHA-1; and the
  `fail_open` default is availability-biased (use `fail_closed` or the offline corpus for
  hard enforcement).
- Breached-password screening and the NIST SP 800-63B-4 policy on set/change/login (issue
  #63). The register (set) and account change-password paths now, BEFORE any hash is
  computed, evaluate the 800-63B-4 policy (length in code points, sole-factor 15 by default;
  no composition unless a legacy tenant enabled it) and screen the password against the
  installed `ironauth-screening` provider (online HIBP k-anonymity or offline corpus). A
  breached password is refused with a non-enumerating message; a provider outage follows the
  configured fail-open (allow + audit) or fail-closed (refuse) policy. NFKC normalization is
  applied ONCE at the hashing seam (`OidcState::{hash_password,verify_password,verify_absent}`),
  so a Unicode password round-trips (set and verify agree; identity on ASCII). On-login
  breached detection is gated by `screen_on_login`: a successful login whose password is now
  breached emits an audit event (metric + structured log) without blocking the sign-in. New
  builders `OidcState::with_password_policy` / `with_breach_provider`; new metrics
  `ironauth_password_screen_total` and `ironauth_password_breached_at_login_total` with
  `describe_screening_metrics`. Only the 5-char SHA-1 prefix ever leaves the process.
- Step-up adversarial-review fixes (RFC 9470, issue #72): the step-up second-factor
  challenge (`/login/mfa`) is now THROTTLED through the #64 abuse regulation on a new
  INDEPENDENT `AuthPath::SecondFactor` path, so an online TOTP/recovery-code guess storm
  is escalated to a uniform 429 (and can auto-place a ban) before any code is compared,
  while never locking the owner out of the password or passkey path; the #69 self-service
  TOTP verify / recovery-code redeem surface routes through the SAME path, closing the seam
  that left them unthrottled. A phishing-resistant (`phr`/`phrh`) floor no longer routes to
  a generic re-login (which looped forever on a password re-login) or a TOTP-enrollment
  dead-end: a passkey holder is routed to a passkey-only ceremony page
  (`/login?...&passkey=1`, no password form, new `passkey_signin_page`) that terminates on a
  verified passkey, and a subject with no passkey fails closed with
  `unmet_authentication_requirements` (new `Remediation::PasskeyReauth`). The per-scope
  policy read at token issuance/refresh now FAILS CLOSED on a store fault (never silently
  issues an under-evaluated token); authorization stays the primary gate. `oidc.acr_order`
  is documented as a DEPLOYMENT-level order (not per-tenant). New `canonical_step_up_acr`
  helper canonicalizes a short acr alias for the CLI. The sample RS and the runnable example
  now emit and evaluate `max_age` (not only `acr`).
- Step-up authentication end to end (RFC 9470, issue #72): a new `step_up` module models
  the declarative authentication requirement (an acr floor plus a max auth age) and its
  evaluation against a recorded authentication, comparing acr by the tenant's configured
  order (`oidc.acr_order`, defaulting to the credential ladder pwd < mfa < phr < phrh).
  The requirement is assembled from three sources (the request `acr_values`/`max_age`, the
  per-client floor `clients.step_up_acr`/`step_up_max_age_secs`, and the per-scope
  `scope_step_up_policies` table) and evaluated at THREE points: at authorization, at token
  issuance, and on refresh. When the current session does not satisfy the requirement the
  authorize endpoint RUNS the required authentication (the hosted `/login/mfa` second-factor
  challenge for a multi-factor floor with an enrolled TOTP, or a full re-login), then issues
  tokens with a FRESH `acr` + `auth_time` reflecting what actually happened (never a stale or
  asserted value); a user with no qualifying factor is routed to an enrollment prompt where
  tenant policy allows, or fails with `unmet_authentication_requirements`. The token endpoint
  re-evaluates the policy against the frozen authentication (code) or the refresh family, and
  a refresh whose auth-age window has LAPSED fails with the new
  `TokenError::InsufficientUserAuthentication` (RFC 9470 `insufficient_user_authentication`
  carrying `acr_values`/`max_age`) rather than silently minting an under-qualified token. A
  request `acr_values` stays VOLUNTARY (an unachievable value is best-effort, never an error)
  while an ESSENTIAL `acr` from the `claims` parameter and the tenant policy are binding.
  `/login/mfa` reuses the credential-bearing interaction seam (same-origin CSRF gate, 303,
  page hardening) and upgrades the session on a verified TOTP or recovery code. The challenge
  contract for resource servers is documented in `docs/design/step-up-authentication.md`, with
  a minimal sample resource server (`examples/step_up_resource_server.rs`) and an integration
  suite that drives the full round trip (challenge, re-authorization, real step-up, acceptance).
- WebAuthn Related Origin Requests (issue #67, WebAuthn Level 3): a new
  `GET /.well-known/webauthn` endpoint serving the `{"origins": [...]}` document, and
  related-origin acceptance in the passkey ceremony. The document is generated from
  live per-environment config at request time (never a baked static asset), served as
  `application/json` with the shared well-known cache discipline (an explicit
  `Cache-Control` plus a strong `ETag` and `304` on a matching `If-None-Match`), and a
  uniform `404` when the feature is unconfigured (WebAuthn disabled or no related
  origins). `OidcState::webauthn_relying_party` now returns the serving origin plus the
  configured related origins as the accepted origin set, and a new
  `webauthn_related_origins_document` renders the well-known body. This BROADENS ONLY
  the accepted origin set: the RP-ID-hash, the assertion signature, and the single-use
  challenge checks are unchanged, so an assertion from a listed related origin verifies
  end to end while an unlisted origin still fails with the uniform non-enumerating
  ceremony error. A related-origin ceremony is a legitimately cross-site POST, so the
  four ceremony endpoints now guard with the new `interaction::related_origin_ok`
  (accept a request whose browser-set, script-unforgeable `Origin` is in the operator
  allowlist) instead of the strict same-origin check; the passkey management endpoints
  stay strictly same-origin. Without a usable `Origin`, `related_origin_ok` now FAILS
  CLOSED: it admits a request only on a positive, unforgeable `Sec-Fetch-Site:
  same-origin` signal, so a fully header-less ceremony request is refused (issue #67
  review, acceptance criterion 2); the legitimate related-origin flow (which always
  carries a real `Origin`) and the `#196` bootstrap `same_origin_ok` path are
  unchanged. RP ID continuity is documented in
  `docs/design/PASSKEY-RP-ID-MIGRATION.md` and proven end to end by a ceremony-layer
  domain-cutover test (acceptance criterion 5): a passkey registered while the server
  is host A still verifies after the serving host cuts over to host B under the same
  stable RP ID, since the authData RP-ID-hash is `sha256(rp_id)`, independent of the
  serving host.
- Credential-abuse defenses (issue #64): a new `abuse` module with the counter INTERFACE
  (`CounterStore` trait + in-process L1 `MemoryCounterStore`, shaped so an optional
  IronCache L2 slots in behind the same trait later), the risk-based escalation
  (`escalating_delay`, `RegulationSettings`), and the documented fail-open/closed matrix
  (per-IP fails OPEN / availability-biased; per-identifier, per-account, and the ban check
  fail CLOSED / security-biased). `login_post`, `register_post`, and a NEW anti-enumeration
  recovery surface (`GET`/`POST /recover`) key regulation on the CANONICAL identifier (the
  #54 seam) and the non-forgeable resolved peer IP (the #31 lesson), per authentication
  PATH, so failed-password spray throttles ONLY the password path and never the passkey or
  recovery path (the account-DoS safeguard, Keycloak CVE-2024-1722). Anti-enumeration is
  uniform across login, registration, and recovery (byte-identical present vs absent), and
  a new `VerificationSender` seam suppresses a send to an unknown recipient under closed
  registration while returning the identical acknowledgment (the Logto pattern). Throttled
  responses carry the standard rate-limit headers (reusing the quota crate's contract).
- Credential-abuse regulation, review hardening (issue #64): the escalation now actually
  ESCALATES. `regulate_before` RECORDS every regulated attempt (throttled OR allowed) as
  part of the decision and computes the delay from the incremented count, so the
  per-identifier / per-IP `Retry-After` doubles per failure up to `max_delay` and the
  per-account counter climbs until the opt-in `hard_lockout` threshold is REACHABLE
  (previously the counter froze at the soft threshold because a throttled attempt was never
  recorded, pinning `Retry-After` flat at the base delay and making `hard_lockout`
  unreachable). The passkey ceremony (`authenticate/verify`) is now GOVERNED on its own
  `AuthPath::Passkey` path: a passkey or `all` ban is enforced and passkey abuse is
  throttled on its own per-IP counters, while a password-path ban or spray never touches
  it (path independence preserved). A successful login (and passkey sign-in) RESETS its
  path's identifier/account/IP failure counters so a legitimate user is not punished after
  a correct credential. Under `hard_lockout`, the banned-account response now carries the
  SAME snapshot shape (status, body, `Retry-After`) as an escalation throttle at the cap,
  so a banned present account is not distinguishable from a throttled identifier by the
  RESPONSE (only the inherent onset differs; see the `hard_lockout` config note).
- TOTP review hardening (issue #69, review):
  - Recovery-code regeneration is now behind FRESH AUTHENTICATION (MEDIUM). The
    `recovery-codes` POST requires a current credential proof (the password verified
    through the #62 pool, a current TOTP code, or an unconsumed recovery code) and
    verifies it BEFORE regenerating; a request with no proof is `403 reauth_required`
    and a wrong proof is `403 invalid_proof`, so a stolen/shared already-signed-in
    cookie can no longer silently rotate a victim's codes (a recovery denial of
    service). Replaces the inert `step_up.enforced=false` declaration.
  - Recovery redemption now resolves the ONE candidate by the store's keyed blind
    index, so a redemption verifies a single Argon2 hash instead of scanning up to 16
    (LOW; a CPU-amplification lever while #64's throttle is a no-op).
  - Honesty: `mfa_required` drives the enrollment PROMPT and the `/account/mfa/plan`
    surface only; HARD login-flow enforcement (challenging the second factor before a
    full session) lands with step-up (#72). The two login-orchestration acceptance
    lines are scoped to #72, not claimed here.
- TOTP second-factor and recovery-code endpoints (issue #69), a new self-service
  `totp` module mounted under `/t/{tenant}/e/{environment}/account/mfa/...`.
  `totp/enroll` mints a seed from the entropy seam, seals it (issue #48), and returns
  the `otpauth://` provisioning URI plus the grouped Base32 secret;
  `totp/verify-enrollment` activates the factor ONLY after a valid current code and
  mints the one-time recovery codes shown once; `totp/verify` checks a second-factor
  code with a bounded drift window, a constant-time compare, and the hard store-level
  single-use invariant (a replay is the uniform invalid-code response);
  `recovery-codes/redeem` spends a code (hashed through the #62 pool) in place of the
  second factor, audited distinctly; `recovery-codes` (POST) regenerates the set; and
  `mfa/plan` reports the per-tenant factor-orchestration order. A clearly-marked
  `throttle_seam` is the integration point for the #64 abuse-defense counters (not
  blocked on #64). The `authn` factor model gains `AuthMethod::Totp` (amr `otp`) and
  `AuthMethod::RecoveryCode` (amr `kba`, distinct from a live authenticator), a new
  multi-factor ACR, and `AuthenticationEvent::password_and_totp` /
  `password_and_recovery_code`. The generic `account_credentials` enroll now rejects
  `totp` / `recovery_code` (they have dedicated code-verified flows), and the account
  credential list folds in the TOTP factors and the recovery-code remaining count.

- Argon2id hashing pool with per-tenant fair-share admission (issue #62): password
  hashing, the hottest and most denial-of-service-prone operation, now runs in a
  dedicated worker pool (`HashingPool`) of fixed OS threads kept OFF the async request
  threads, so an Argon2 hash never blocks protocol I/O (a runtime check,
  `thread_diagnostics`, proves the job runs with no tokio runtime present). In front of
  the pool sits per-tenant fair-share admission that REUSES the issue #50 quota engine
  (a new `PasswordHashing` dimension and its 429 block-signal contract), so one tenant's
  credential-stuffing storm drains only that tenant's hashing bucket and is shed with a
  retryable 429, never starving another tenant or the instance. A bounded queue depth
  load-sheds with a retryable 503; pool exhaustion and worker faults are TYPED
  `HashRejection` errors, and verification never falls back to an unbounded inline hash.
  New passwords hash with Argon2id at the configured `[password_hashing]` parameters
  (OWASP defaults `m=19456, t=2, p=1`, tunable per environment in spirit); a parameter
  change applies to NEW hashes and an existing hash upgrades transparently on the user's
  next successful login, because the PHC string stores parameters per hash
  (`hash_password_with`, `Argon2Params`): a native login whose stored hash drifted from
  the current parameters (`needs_rehash`) is rehashed to them through the store's
  `rehash_native_password` (best-effort, race-safe), alongside the existing #55
  foreign-to-native rehash. The login,
  registration, and change-password surfaces route every hash and verification through
  the pool. A measured tuning probe (`run_probe`, exposed as the `ironauth hash-probe`
  CLI for headless installs and reusable by the in-admin tuning helper) times real
  Argon2id hashes on the host, recommends the strongest memory cost that meets the
  configured latency target, and projects logins/s per core. Metrics: pool queue depth,
  active workers, worker capacity, admission rejections by reason, and a hash-latency
  histogram; per-tenant admission counts remain observable through the quota engine's
  per-scope samples.
- Argon2id hashing pool hardening (issue #62, adversarial-review follow-up):
  - Two public endpoints that ran Argon2 INLINE on protocol-I/O threads (bypassing the
    pool and admission) now route through the pool: the RFC 8628 device-flow sign-in
    (`POST .../device`) verifies through `OidcState::verify_password`/`verify_absent`,
    and invitation accept (`POST .../invitations/accept`) hashes through
    `OidcState::hash_password`. A new structural lint (`scripts/hashing-pool-boundary.sh`,
    wired into CI and the gate) fails the build if a raw `password::hash_password`,
    `verify_password`, or `verify_absent` is called anywhere outside the pool-boundary
    modules, so this cross-tenant DoS lever cannot regress.
  - The pool queue is now PER-TENANT fair-queued instead of one global FIFO: each
    `(tenant, environment)` gets its own sub-queue and the workers dequeue round-robin
    across tenants with waiting work, so one tenant's admitted backlog can no longer
    head-of-line-block another tenant's already-admitted hash. Load-shedding is
    per-tenant (a tenant exceeding its bounded depth is shed, never an innocent
    tenant), with a generous global memory backstop charged only to the submitting
    tenant. `[password_hashing].max_queue_depth` is the PER-`(tenant, environment)`
    sub-queue bound (see the re-review follow-up below for the per-tenant AGGREGATE cap
    that makes the cross-tenant isolation hold across a tenant's own environments).
  - The no-pool `spawn_blocking` fallback (the self-hoster and test posture) is now
    bounded by a semaphore capped at the host core count, so a flood cannot pin the
    tokio blocking pool (~512 threads). The installed pool remains the production path.
  - `needs_rehash` no longer upgrades on a DOWNWARD parameter drift: a rehash happens
    only when the configured parameters are at least as strong as the stored hash on
    every axis (and stronger on one), so lowering `[password_hashing]` never downgrades
    an existing stronger hash.
  - The admission-rejection metric exposes the machine-readable rejection REASON today
    (`over_share`, `per_tenant_queue_full`, `per_environment_queue_full`,
    `global_backstop_full`, `shutting_down`); a per-tenant breakdown deliberately rides
    the same bounded-cardinality scrape-hook follow-up as issue #50 rather than an
    unbounded per-tenant label (cardinality-safe).
- Argon2id hashing pool re-review residuals (issue #62, second adversarial review):
  - The queue-layer load-shed is now genuinely PER-TENANT, closing a per-tenant
    isolation hole. The prior bound was per-`(tenant, environment)`, so one tenant using
    16 or more of its OWN environments could fill 16 sub-queues up to the global memory
    backstop and shed an INNOCENT different tenant with `PoolExhausted`. Each tenant now
    also carries an AGGREGATE queued-depth cap summed across ALL of its environments,
    set strictly below the global backstop (`max_queue_depth * 8` versus the backstop's
    `* 16`), so a tenant spanning any number of its environments sheds on its OWN total
    (`per_tenant_queue_full`) and can never exhaust the backstop to shed another tenant.
    The per-`(tenant, environment)` round-robin fairness and the finer per-environment
    sub-queue bound (`per_environment_queue_full`) are unchanged; only a BROAD
    multi-tenant flood now reaches the global valve.
  - The device-flow sign-in step now surfaces a pool rejection UNIFORMLY on all three
    identifier branches (present, fenced, absent), closing an anti-enumeration oracle
    under overload: the fenced and absent branches previously swallowed the rejection
    and returned the generic failure page (200) while a present-and-loginable identifier
    surfaced the retryable 429/503, so an attacker-inducible hashing overload
    distinguished user presence and status. All three branches now return the identical
    retryable rejection, matching the hardened `/login` path.
  - The pool-boundary lint (`scripts/hashing-pool-boundary.sh`) now scans EVERY crate's
    production source (not just `ironauth-oidc/src`) and catches the crate-root
    re-export call form (`ironauth_oidc::{hash_password,verify_password,verify_absent}`),
    so a cross-crate inline hash cannot slip past the boundary. The existing
    disabled-by-default, token-authenticated, single-scope `ironauth-admin` migration
    verify (#58) carries an explicit `pool-boundary-allow` marker with its written
    justification (the admin crate hosts no pool), matching how the repo's other audit
    lints allow justified exceptions.
- Passwordless self-lockout guard on passkey removal (issue #65 review hardening):
  `webauthn/credentials/remove` no longer unconditionally deletes a passkey. A
  passwordless account (activated by a passkey invitation, with no password ever
  provisioned) can have a passkey as its ONLY login factor, so removing the caller's
  LAST usable login factor is now BLOCKED with a `409 last_credential` unless
  `acknowledgeRecovery` is set, mirroring the sibling #61 `account_credentials` guard.
  The remaining factors are counted in the removal transaction across all sources: a
  provisioned native password, any `account_credentials` usable for login, and the
  caller's other passkeys.
- Passkey acr/amr truthfulness and credential management (issue #65 review hardening):
  a sign-in's assurance is now derived from the credential's STORED, registration-time
  backup-eligible flag, never the mutable BE bit of the presented assertion, so a
  synced passkey can no longer claim the device-bound `phrh`. A BE flip between the
  assertion and the stored value is treated as a spec violation (WebAuthn L3 7.2) and a
  clone/spoof signal: the sign-in is refused with the non-enumerating ceremony error
  and a `webauthn.backup_eligibility.mismatch` security event is written, with no
  partial state advanced. The amr is now honest about user verification: `phr`/`phrh`
  assert phishing resistance (not user verification), `user` (presence) is kept for
  every passkey login, and `mfa` is added only when the assertion actually verified the
  user, so a user-presence-only login never implies a verification factor. A defensive
  userHandle check rejects an assertion whose userHandle does not match the credential's
  stored subject. New authenticated, IDOR-safe passkey management endpoints
  (`GET webauthn/credentials`, `webauthn/credentials/rename`, `webauthn/credentials/remove`)
  let a user list their own passkeys with live BE/BS, rename, and remove them (subject
  bound, same-origin/CSRF guarded, audited on mutation); the list is also folded into
  `GET account/credentials` so every credential appears in one place.
- WebAuthn passkeys, first-class (issue #65): four scope-routed ceremony endpoints
  (`webauthn/register/options`, `register/verify`, `authenticate/options`,
  `authenticate/verify`) implement WebAuthn Level 3 registration and authentication.
  Registration is authenticated by the caller's session and populates
  `excludeCredentials` so an authenticator cannot enrol twice; authentication uses
  discoverable credentials (conditional UI), resolves the user through the
  credential's stored subject, and on success establishes the same server-side
  session the password login does. Each ceremony draws a single-use challenge from
  the store, verifies the response in the pure `ironauth-webauthn` core (challenge,
  origin, RP ID hash, flags, and for an assertion the signature via the ring-backed
  jose core), persists only after a successful verification (no partial row on
  failure), and returns one non-enumerating error for every failure. A UV passkey
  authentication records an honest `AuthenticationEvent`: the acr/amr registry's
  dormant passkey rows are now ACTIVE, so a UV synced passkey issues tokens whose
  `acr` is `phr` (amr `swk`+`user`) and a device-bound one `phrh` (amr `hwk`+`user`),
  chosen by the backup-eligible flag, flowing through the whole session -> code ->
  token chain; `parse_methods` gained an achievability guard that drops any recorded
  method not currently active, so a stale/dormant elevated method can never
  over-claim. The sign-count clone-detection policy (warn or block) is applied on
  every assertion, with zero-counter synced passkeys never tripping it. The hosted
  login page wires conditional UI: the identifier field carries the `webauthn`
  autocomplete token, a passkey button path also exists, and one nonce-guarded
  ceremony script is served under a login CSP that opens exactly `script-src
  'nonce-...'` and `connect-src 'self'`. The RP ID and origin are resolved
  per-environment from the serving origin (or the configured override, validated at
  startup). Mounted only when `oidc.webauthn_enabled` (default on). Attestation
  trust (MDS3, AAGUID allowlists) is out of scope (issue #66); ceremonies request
  `attestation: "none"`.

- Inbound lazy-migration hook (issue #56): when the `[oidc.lazy_migration]` config arms
  it, a login whose canonicalized identifier is UNKNOWN locally verifies the submitted
  credential against a legacy store through a pluggable `CredentialVerifier` (the only
  shipped implementation, `WebhookVerifier`, delivers the check over the M1 SSRF-hardened
  fetcher, HTTPS ONLY, with a configured bearer secret). On a positive verdict the user is
  created locally with a native Argon2id hash and NO foreign hash (migrated by
  construction), an optional profile's traits are validated against the active identity
  schema (#53) before anything is persisted (an invalid profile is refused), the user is
  audited (`user.create`), a session is established, and the request resumes; the SECOND
  login is a normal local login that never calls the hook. Every non-success outcome
  (rejected, timeout, error, blocked, or an open breaker) falls through to the SAME uniform
  failure a local wrong password produces, spending the same `verify_absent` Argon2id work,
  so the hook is not a user-enumeration oracle. Resilience: a per-call timeout (the
  fetcher's deadline), NO retry in the login path, and an in-memory per-node
  `CircuitBreaker` that opens on an error/timeout rate (a verdict never trips it) and
  fails unmigrated logins fast while local users are unaffected; its window and cooldown
  read the env clock seam. Observability: the migrated count, per-outcome hook counter,
  latency histogram, breaker-state gauge, and breaker-transition counter are exported as
  metrics (`describe_lazy_migration_metrics`). The contract is implementation-agnostic so
  the M11 WASM hooks engine can slot a WASM verifier in behind the same trait. A standard
  #55 bulk import closes the tail of stragglers, after which the hook is disabled per
  environment (a pure config change).
- Lazy-migration hook hardening (issue #56, adversarial review):
  - The migration profile no longer carries a verbatim `claims` channel. A hostile or
    compromised legacy store could previously return an attacker-controlled
    `email`/`email_verified` or `groups`/`roles` claim that was persisted verbatim and
    released to RPs (identity spoof / privilege amplification). Issue #56 authorizes only
    the schema-validated TRAITS channel; the created user's claims now come from the normal
    path exactly like any other user. `HookProfile`/`WebhookProfile` drop the `claims`
    field (a webhook that sends one has it ignored), and the login path never writes it.
  - The circuit breaker admits exactly ONE half-open trial at a time. Previously, after the
    cooldown a burst of concurrent logins all saw the half-open state and fired outbound at
    a possibly-still-dead backend; a trial-in-progress flag now fast-fails the others until
    the single probe resolves. The trial slot is released even when the trial is ABANDONED:
    an RAII guard in `attempt` re-opens the breaker (a fresh cooldown) if the future is
    dropped mid-await (client disconnect, request timeout, shutdown cancellation) or the
    verifier panics, and `allow` self-heals an outstanding trial that has been in flight
    past the cooldown, so a wedged trial-in-progress flag can never disable lazy migration
    on a node until restart (an availability regression the first version of the flag
    introduced).
  - `LazyMigrationHook::attempt` now wraps the verifier in the configured timeout, so a
    verifier that does not self-bound (a future non-webhook impl) cannot stall the login
    path; an elapsed timeout counts as a failure toward the breaker. The shipped
    `WebhookVerifier` already self-bounds via the fetcher, so production behavior is
    unchanged. `LazyMigrationHook::new` takes the per-call timeout.
  - Documented the ACCEPTED timing residual: while the hook is armed, an unknown-local
    identifier takes an outbound-call path that an already-local login does not, so timing
    reveals migration STATUS (never credentials, never legacy existence). It is bounded to
    the migration window and matches Auth0/Cognito lazy migration; we deliberately do not
    pad response time. Failure responses remain uniform in status and body shape.
- Exported `verify_absent` (issue #58, review): the login path's dummy-Argon2id
  primitive is now public so the management outbound verify-credential endpoint can
  reuse the exact same anti-user-enumeration work, keeping absent and wrong-password
  timing indistinguishable through one shared primitive.
- Public invitation-accept endpoint (issue #60):
  `POST /t/{tenant}/e/{environment}/invitations/accept` on the public data plane
  (never the management port), scope-routed so the redeem runs under the right RLS
  scope. Authenticated by the single-use token alone (no session, no admin
  credential): the token is hashed and resolved by digest, then consumed atomically
  while the invited user is activated (`pending_verification -> active`) in the same
  transaction, so a concurrent double-accept redeems at most once. A `password`
  invitation enrolls an Argon2id verifier through the #20 path; a `passkey`
  invitation provisions none. Forged, expired, redeemed, revoked, and cross-scope
  tokens all collapse to one uniform not-found, so the endpoint is never a
  token-guessing oracle. No CSRF gate: it carries no ambient authority, so there is
  no cookie for a cross-site submit to ride.
- Foreign-hash login with verify-then-rehash (issue #55): the interactive login now
  verifies an imported FOREIGN password hash (bcrypt, scrypt, PBKDF2, the Argon2
  family, or Firebase modified scrypt) when the native Argon2id verifier is the
  unusable import sentinel, dispatching through the `ironauth-import` scheme layer.
  On the FIRST successful foreign login the password is transparently rehashed to
  the native Argon2id verifier and the foreign hash is retired
  (`ActingUserRepo::upgrade_foreign_password`), so the second login verifies
  natively; the upgrade is best-effort, so a transient failure or a lost race leaves
  the foreign hash for the next login rather than failing the sign-in. A present but
  wrong password stays a generic failure whether the stored verifier is native or
  foreign (no wrong-password oracle).

- User lifecycle authentication fence (issue #52): the interactive login and the
  device-verification login paths now consult the resolved user's lifecycle `state`
  and REFUSE a user that cannot authenticate (blocked, disabled, or
  pending-verification). The password is still verified (so a fenced account is
  timing-indistinguishable from a wrong password) and the SAME generic failure is
  returned, so there is no blocked-vs-wrong-password oracle. A soft-deleted user
  resolves as absent.
- Refresh-grant lifecycle re-check (issue #52, fence completeness): the
  `refresh_token` grant now re-checks the token subject's user lifecycle state before
  minting and FAILS CLOSED (`invalid_grant`) when the user cannot authenticate
  (blocked, disabled, pending-verification) or is absent/deleted, treating a store
  fault as fail-closed too. An `offline_access` family deliberately survives the
  block/disable session cascade (issue #21), so without this re-check a user fenced
  AFTER the family was opened could keep minting access tokens through that surviving
  token. The invariant is now complete: after block/disable/delete a user obtains no
  new tokens by ANY path (authorize, refresh, or an existing offline token). A normal
  active user's refresh is unaffected. See `docs/design/USER-LIFECYCLE.md`.
- Self-service end-user account API (issue #61). An API-first surface an
  AUTHENTICATED user manages their OWN account with, mounted on the public data plane
  and scope-routed under `/t/{tenant}/e/{environment}/account/...`, authenticated by
  the user's OWN session cookie (never the management API's admin credentials). The
  hosted account pages (M9) consume this API without any private endpoint.
  - **Sessions.** `GET .../account/sessions` lists the caller's OWN active sessions
    with device metadata (user agent, a coarse network-locality hint derived from the
    IP observed at authentication with the host portion zeroed), created / last-seen
    timestamps, and a current-session marking; `POST .../account/sessions/revoke`
    revokes ONE own session; `POST .../account/sessions/revoke-others` signs out
    everywhere else. Every read and write binds to the authenticated subject: a session
    the caller does not own is the uniform not-found and is never actionable, and a
    revoke flows through the unified session-ended fan-out exactly as an admin revoke.
  - **Credentials.** `GET`/`POST .../account/credentials` list and enroll the caller's
    OWN credentials; `POST .../account/credentials/remove` removes one, subject-bound
    (a cross-user id is refused) and behind the last-usable-credential guardrail (a 409
    unless the request carries the documented `acknowledge_recovery`). The endpoints and
    authorization contract ship now; the concrete factor ceremonies land with M7.
  - **Password change.** `POST .../account/password` verifies the CURRENT password via
    the Argon2id path, sets a new verifier at the same OWASP parameters through the
    entropy seam (never returning or logging the hash), and revokes the caller's OTHER
    sessions (session-fixation defense).
  - **Guardrails.** Every state-changing POST carries the same-origin CSRF check
    (issue #196) BEFORE any mutation; the sensitive operations DECLARE a configurable
    recent-re-authentication (step-up) requirement recorded in the audit trail and
    reported to the caller, with the enforcement seam ready to activate once M7's
    step-up issue lands; an unauthenticated request, and a session cookie presented at
    the wrong scope, are `401`.
- ACME certificate-authority DIRECTORY client for custom domains (issue #47,
  EXPLORATORY): `AcmeDirectoryClient` fetches and parses a CA's directory (RFC 8555
  7.1.1) ONLY through the SSRF-hardened `ironauth_fetch::Fetcher`, so a directory or
  validation URL that is (or resolves to) a loopback, private, or cloud-metadata
  address is refused with the uniform `AcmeError::Blocked` and never dialed. This
  ships the entry point of the ACME flow and its SSRF confinement; the full order
  lifecycle (account registration, order, challenge fulfilment, finalize, download)
  is deferred and gated on a provisioned CA account and a reachable domain, and MUST
  reuse this client's fetcher when built. New `AcmeDirectory`/`AcmeDirectoryClient`/
  `AcmeError` public types.
- Tenant lifecycle data-plane fence (issue #46). The store-backed issuer registry
  now consults each scope's data-plane serving state on EVERY resolution (in
  `IssuerRegistry::entry_for`, ahead of the cache), not only on a cold load, and
  fails closed (no issuer entry, so JWKS/discovery and signing all 404) for a
  suspended or offboarded tenant. A suspend or delete therefore stops serving on the
  very next request with no process restart, and a resume serves again with no data
  loss. A store error reading the fence fails closed (denies serving).
- Tenant/environment quota enforcement on the data plane (issue #50). The provider
  now constructs one `ironauth_quota::QuotaEnforcer` from the `[quota]` config
  (seeded with the same env clock) and spends it on the request path, turning the
  previously inert quota engine live.
  - **Enforcement point (`quota.rs`, `authorize.rs`).** `/authorize` charges the
    request-rate quota for the `(tenant, environment)` the `client_id` declares,
    only AFTER the client store lookup confirms the client exists in that scope, so a
    spend is only ever drawn on a VERIFIED, real scope. A well-formed but
    unregistered `client_id` (whose declared scope is attacker-chosen and
    unauthenticated: any random bytes decode to a valid-looking scope) is rejected by
    the not-found path and NEVER reaches a spend. This restores the engine's "an
    unknown scope is rejected before it reaches a spend" invariant and closes an
    unauthenticated unbounded-bucket-allocation memory-exhaustion vector and a
    spoofed-victim-tenant throttling vector (the fix for the pre-verification spend
    the re-review flagged). An over-quota spend short-circuits with an RFC 6585 `429`
    carrying the structured `RateLimit`/`RateLimit-Policy` headers, the legacy
    `X-RateLimit-*` triplet, `Retry-After`, the `x-ratelimit-block` signal header,
    and the `__Host-ira-rl-block` cookie for a cookie-gating WAF. A scope under quota
    passes through untouched.
  - **Fairness.** The spend draws from the environment bucket and, by nesting, its
    tenant bucket, and the buckets are per-scope: one tenant flooding its own quota
    never throttles another tenant. Proven end to end over the live router in
    `tests/quota.rs` (at-quota 429 with headers, under-quota passes, noisy-vs-quiet
    fairness, the configured tier governing the limit, and a concurrency storm that
    never oversells the burst) over REGISTERED clients on the verified-scope path.
    Three further tests prove the enforcement point is safe: a flood of unregistered
    `client_id`s allocates zero buckets, a spoofed victim-tenant scope cannot drain
    the victim's shared bucket, and an idle bucket is reaped after the configured
    window.
  - **State wiring (`state.rs`).** `OidcState::with_quota_enforcer` installs the
    enforcer; with none installed the data plane admits every request (the default,
    and the self-hoster's unlimited posture), so the existing DB-only tests are
    unaffected.
  - Still deferred (precisely): live charging of the token-issuance and hook-seconds
    dimensions on their request paths (the engine enforces them independently; the
    same `OidcState` hook applies at the `/token` mint and the hook-execution
    accounting point), the usage-threshold webhook delivery (no platform eventing
    surface exists yet to route the produced events to), and the audited
    management-API surface for adjusting a tenant's quota at runtime. See notes.
- Session Management 1.0 and Front-Channel Logout 1.0, behind default-off flags for
  certification completeness (issue #39). Both iframe mechanisms are degraded under
  third-party-cookie partitioning (Session Management 1.0 section 5.1), so they ship
  opt-in and honestly documented; see `docs/design/IFRAME-LOGOUT-CAVEAT.md`.
  - **`session_state` (`session_mgmt.rs`).** A one-way keyed digest of the client id,
    the RP origin, and the OP browser state, where the OP browser state is itself a
    one-way digest of the session id: `session_state` NEVER carries the session id. It
    is stable per (client, origin, session, salt) and changes when the session changes.
    Emitted on authorization responses (a new `session_state` slot in
    `response::success_params`) ONLY when `oidc.session_management_enabled` is set.
  - **`check_session_iframe`.** Served at `/connect/check_session`, mounted and
    advertised in discovery ONLY when session management is enabled. It is the ONE page
    served with a framing carve-out (no `X-Frame-Options`, no `frame-ancestors 'none'`)
    so an RP can embed it cross-origin; its inline script is SHA-256 hash-pinned by CSP
    and replies ONLY to the sender's exact `postMessage` origin (never `*`), folding
    that origin into the recomputed value.
  - **Front-Channel Logout.** When `oidc.frontchannel_logout_enabled` is set, the
    `end_session` flow renders a page embedding one hidden iframe per participating RP
    (`pages::frontchannel_logout_response`), each carrying `iss` and the RP's OWN `sid`
    when it registered `frontchannel_logout_session_required`. The page keeps its
    anti-clickjacking posture and scopes `frame-src` to exactly the participating RP
    origins. A post-logout redirect still takes precedence; front-channel delivery is
    best-effort and never blocks or reorders back-channel logout.
  - **Discovery.** `check_session_iframe`, `frontchannel_logout_supported`, and
    `frontchannel_logout_session_supported` are advertised only when their feature is
    enabled, and truthfully; with the flags off the document is unchanged.
- Back-Channel Logout: the Logout Token and the delivery worker (OIDC Back-Channel Logout
  1.0, issue #34). `backchannel.rs`.
  - **The Logout Token (`build_logout_token_claims`).** A signed JWT per section 2.4:
    `iss`, `aud` (the RP client id), `iat`, `exp`, `jti`, the `events` member naming the
    back-channel-logout event, and `sid` (this session-based OP always sends the
    per-(client, session) value from #32, never the raw session id). It carries NO `nonce`
    and no `sub` (sid alone identifies the session, avoiding the ambiguous sub-only token),
    and is minted through the SAME ironauth-jose signing core and per-environment key as an
    ID token, with the header `typ = logout+jwt`.
  - **The delivery worker (`BackChannelLogoutWorker`).** Generic over a `LogoutSender`
    seam so the network is injectable. `run_once(scope)` drains the durable session-ended
    outbox (#35), EXPLODES each ended session into one per-RP delivery (resolving the
    participating clients and each one's own `sid`), then attempts every due delivery:
    marking delivered on a 2xx, or scheduling a bounded exponential-backoff retry (its
    schedule and jitter drawn from the `ironauth-env` clock and entropy seams, so it is
    deterministic under a manual clock) and dead-lettering the delivery once the attempts
    cap is reached. A slow or failing RP never blocks the others or wedges the worker.
  - **The SSRF-hardened sender (`FetchLogoutSender`).** The production `LogoutSender` POSTs
    the form-encoded `logout_token` through `ironauth-fetch` (the only sanctioned outbound
    path), so an RP-controlled `backchannel_logout_uri` that resolves to a loopback,
    private, or metadata address is refused, no redirect is followed, and a per-delivery
    timeout caps a slow RP. `SendFailure` gives bounded, non-secret failure labels.
  - **Discovery** now advertises `backchannel_logout_supported = true` (alongside the
    `backchannel_logout_session_supported` already advertised since #32).
- RP-Initiated Logout: the `end_session` endpoint (OIDC RP-Initiated Logout 1.0, issue
  #33). A top-level browser navigation that ends the OP session and, only when it is
  cryptographically attributable, redirects back to the relying party.
  - **The endpoint (`logout.rs`), GET and POST at `/end_session`.** Accepts ONLY the
    spec parameters (`id_token_hint`, `client_id`, `logout_hint`, `state`, `ui_locales`,
    `post_logout_redirect_uri`); nothing proprietary (no Cognito-style `logout_uri`).
    Advertised in discovery as `end_session_endpoint`.
  - **Hint verification through the JOSE core.** The `id_token_hint` is verified by the
    new `OidcState::verify_logout_hint` against the environment's own published keys
    (rotated-out verification keys retained), accepting a PAST `exp` (the new
    `VerificationPolicy::allow_expired`, mandated by the spec for a stale hint) while
    still enforcing the signature, algorithm allowlist, exact issuer, exact audience,
    `nbf`, and `iat`. The scope is recovered from the client the `aud` names; a foreign
    or unverifiable hint does NOT attribute the request.
  - **Synchronous termination (the hydra#4070 race).** An attributed logout ends the SSO
    session via `ActingSessionRepo::revoke` (cause `LoggedOut`, `hard_kill = false`)
    BEFORE the response, so the immediate-revocation read guard refuses it on the very
    next request; `offline_access` families survive. The terminal `SessionLifecycleEvent`
    fires on the revocation sink for the #35/#34 fan-out. The session cookie is cleared
    (`Max-Age=0`).
  - **Exact-match redirect, or none.** `post_logout_redirect_uri` is honored only on an
    EXACT string match against the client's registered set AND with a verifiable hint
    (RFC 9700 section 2.1: no wildcards, normalization, or case folding); `state`
    round-trips only then. A near miss, an unregistered value, or an unattributable
    request renders a neutral logged-out page, never an open redirect.
  - **CSRF: confirm an unattributable logout.** Without a verifiable hint a GET renders a
    confirmation prompt and changes nothing; the confirm POST ends the session behind the
    `same_origin_ok` check (issue #196). New `pages::logout_confirm_page` /
    `pages::logged_out_page`; `LogoutParams` is exported.
- The Global Token Revocation receiver, EXPERIMENTAL (issue #36): `POST
  /global-token-revocation`, the Okta Universal Logout shape of the individual
  Internet-Draft `draft-parecki-oauth-global-token-revocation` (NOT WG-adopted, so the
  wire shape may change between releases; the endpoint ships behind the config maturity
  ladder's experimental ack gate and is unmounted by default).
  - **What it does.** A single subject-scoped call ends ALL of one subject's sessions and
    revokes ALL of its refresh-token families in one environment (the account-takeover
    panic button), reusing `ActingSessionRepo::revoke_all_for_user`. It then publishes a
    TERMINAL `SessionLifecycleEvent` (cause `user_revoked_all`, no successor) per revoked
    session on the `RevocationEventSink` seam, so the #35 logout fan-out terminates every
    relying party's view of the subject. The request is the draft JSON shape, an RFC 9493
    Subject Identifier under `sub_id`; the `opaque` format maps to the local `usr_`
    subject (other formats return a clean 400, never a false 204). `204 No Content` on
    success, idempotent (a repeat flips nothing and publishes no spurious signal).
  - **Authorized strongly, fails closed.** The caller authenticates as a CONFIDENTIAL
    client through the `Authorization` header (the same client-auth suite the token
    endpoint uses); a public `none` client and an unauthenticated caller both get a
    uniform 401 (a `client_id` is not a secret), mirroring the RFC 7662 introspection
    restriction. Authentication fixes the `(tenant, environment)` scope from the client's
    own id and the subject is parsed WITHIN it, so a global revoke can NEVER reach a
    subject in another tenant (a foreign-scope id is a uniform 400, no cross-tenant
    oracle). A store fault is a 500, never a false 204.
  - **Offline handling per flag.** By default `offline_access` families survive a global
    revoke (issue #21/#32 semantic); `oidc.global_token_revocation_hard_kill` revokes
    those too for an account-takeover posture. `OidcState::with_global_token_revocation_enabled`
    is the ONLY way to arm the endpoint, set by the boot path from the feature ladder so
    the experimental ack can never be bypassed from `[oidc]`.
  - **Not yet built** (honest scope): the TRANSMITTER side (emitting Global Token
    Revocation calls to downstream receivers) needs the #35 delivery-worker fan-out, which
    is not merged; only the RECEIVER ships here. The terminal session-ended signals are
    produced on the shared `RevocationEventSink` seam, but the DEFAULT sink is a no-op, so
    the durable relying-party logout landing arrives only once #35 wires a real sink via
    `OidcState::with_revocation_sink`. Subject-identifier formats beyond `opaque`
    (`email`, `iss_sub`, ...) are recognized but not yet mapped to a local subject. The
    external-interop acceptance criterion (a recorded run against an outside receiver such
    as Okta or Auth0) is infra-gated and NOT done; nothing here claims verified
    conformance against another implementation, only the pinned draft revision.
- The session model on the OIDC surface (issue #32).
  - **`sid` in EVERY flow's ID token (not just the code flow).** The token endpoint
    resolves the per-(client, session) `sid` from the code's authenticating SSO session
    and emits it as a legitimate issuer claim; `claims_supported` advertises it. The
    front-channel implicit/hybrid mints (`authorize.rs`) and the device-flow mint
    (`device.rs`) now thread the SAME `sid` through, resolved from the authenticating SSO
    session exactly as the code flow does, so `backchannel_logout_session_supported = true`
    is truthful for EVERY enabled flow, not only the code flow (previously those mints
    passed `sid: None`, making the advertisement a lie whenever a legacy response type or
    the device flow was enabled).
  - **The token endpoint checks SSO-session liveness.** A code redeemed AFTER its session
    was revoked is now a uniform `invalid_grant` and mints nothing: the code-exchange path
    resolves `session_ref` through the authoritative read guard before minting, so a code
    minted before a revoke can no longer produce a fresh live refresh family and `sid`
    bound to a dead session. `sid` resolution now fails CLOSED (a store error fails the
    exchange rather than silently emitting a session-less ID token).
  - **Session-fixation defense.** `interaction::establish_session` now takes the request
    headers and ROTATES the session id at every privilege transition (login,
    registration, device-verification login): a fresh entropy-seam id, with the prior
    one invalidated in the SAME transaction, so no call site can forget to rotate.
  - **Immediate revocation on the read path.** `interaction::resolve_session` takes the
    headers too and refuses a revoked or rotated session at once (the store's read guard
    is authoritative), so a logout can never silently no-op.
  - **Hardened cookies.** The session cookie keeps `__Host-` + `Secure` + `HttpOnly` +
    `SameSite=Lax` and carries a SMALL OPAQUE id (a size-bounding test keeps the
    multi-KB-cookie 431 class structurally impossible). New: an off-by-default CHIPS
    toggle that emits the REAL CHIPS shape `Secure; SameSite=None; Partitioned` (the
    `__Host-` prefix stays valid), so the cookie actually rides the cross-site embedded
    subrequests CHIPS exists to serve; a `Lax` cookie with `Partitioned` merely appended
    would have been withheld from exactly those subrequests. `clear_set_cookie` mirrors
    the same shape so a logout targets the same jar.
  - **Idle timeout slides on the read path.** `resolve_session` passes the configured idle
    window to the store read, which slides `idle_expires_at` on an active session (past
    roughly half the window), so a continuously active session is no longer killed at the
    idle TTL as if it were a second absolute cap.
  - **Off-by-default binding knobs.** Peer-IP and device/user-agent session binding, each
    inert unless an operator enables it (the tunability principle) and each failing
    CLOSED when enabled. The peer IP is the POLICY-RESOLVED client IP the server stamps
    on `PEER_IP_HEADER`, never a client-supplied header.
  - **Session lifecycle signal.** `SessionLifecycleEvent` and `SessionSignalCause` on the
    existing `RevocationEventSink` seam (a default no-op method, so existing sinks keep
    compiling), for the #35 fan-out to consume. A ROTATION carries a successor and is
    explicitly NON-terminal (`is_terminal()`), so a naive consumer cannot mistake it for
    a logout. When a login TERMINALLY replaces a different user's session on the same
    browser, the signal is the new NON-rotation `ReplacedByOtherSubject` cause with NO
    successor, so a consumer never reads the outgoing user's session as living on as the
    incoming user's.
  - **Rolling-restart acceptance test.** An integration test rebuilds all process-level
    state from scratch against the same Postgres and re-drives authorize with the same
    cookie, asserting the session still authenticates and the `sid` is unchanged: the
    "authoritative in Postgres, no in-memory-only state" claim is now proven.

- RFC 9700 (OAuth 2.0 Security BCP) checklist encoded as CI conformance invariants
  (issue #38).
  - **Conformance suite.** A new registered test target `tests/rfc9700.rs` drives the
    live authorization, token, discovery, and interaction endpoints and asserts each
    applicable RFC 9700 item: exact `redirect_uri` matching with the scoped RFC 8252
    loopback exception, no open redirector, S256-only PKCE with downgrade prevention in
    both directions, no front-channel access token, RFC 9207 `iss` on every
    authorization response, refresh rotation with reuse family revocation,
    audience-restricted tokens never delivered in a URL, single-use client- and
    `redirect_uri`-bound codes, sender-uniform token errors, and no ROPC. Each
    header/shape item reduces to a shared predicate scored against the live response;
    an in-binary mutation harness feeds each predicate the regression shape a flipped
    guard would produce and asserts it is rejected, so no test can pass vacuously. The
    harness lives only in the test binary and is absent from the release and musl
    builds. Traceability: `docs/conformance/rfc9700-checklist.md`; rationale:
    `docs/design/rfc9700-conformance.md`.
  - **303 for credential-bearing redirects (behavior change).** The authorization and
    interaction redirects now emit `303 See Other` instead of `302 Found`, so the user
    agent re-issues the follow-up as a body-less `GET` (a submitted login/consent POST
    body is never replayed to the redirect target) and a code-carrying redirect is
    never method-ambiguous; `307`/`308` are forbidden. Emitted from the three existing
    redirect builders (`error.rs::redirect_response`, `interaction.rs::redirect` and
    `redirect_setting_cookie`).
  - **Referrer-Policy on code-carrying redirects.** `Referrer-Policy: no-referrer` now
    rides the `query`-mode authorization redirect (which carries the code in the
    `Location` query) from the same single seam, closing the gap where it previously
    set only `Cache-Control: no-store`; the `form_post` interstitial already had it.
  - **FIX (security, user-facing): every bootstrap form POST failed in a real browser.**
    The login, registration, consent, and device-approval pages were served with
    `Referrer-Policy: no-referrer`. Per the Fetch standard ("append a request `Origin`
    header"), a non-`GET`/`HEAD`, non-CORS request (exactly a same-origin HTML form
    POST) from a `no-referrer` document has its serialized origin set to `null`, so a
    real user agent submitted every one of those forms with `Origin: null`, which the
    same-origin CSRF allowlist (issue #196) read as a cross-origin mismatch and refused
    with a `403`. The test suites never saw it because a harness request carries no
    `Origin` at all and the absent-header path deliberately falls through to allow.
    Fixed in both layers: the PAGES now carry `Referrer-Policy: same-origin`
    (`pages::PAGE_REFERRER_POLICY`), which still sends no `Referer` to any cross-origin
    destination but leaves a real, checkable `Origin` on the same-origin POST, while the
    code-carrying responses keep `no-referrer`; and `interaction::same_origin_ok` now
    resolves an opaque `Origin: null` by fetch metadata, accepting it only alongside a
    user-agent-authored `Sec-Fetch-Site: same-origin` (a forbidden header name that page
    script cannot forge) and rejecting it when the metadata is absent or says `same-site`
    or `cross-site`. A genuine foreign `Origin` is still rejected whatever the fetch
    metadata claims. Pinned by browser-shaped regression tests in the `interactive` and
    `rfc9700` suites.
  - **Conformance coverage completed.** The checklist now also asserts CSRF on the
    credential-bearing interaction POSTs (R16), clickjacking refusal on every
    interaction page (R17), refusal of a non-registrable or insecure `redirect_uri` at
    registration (R18), and a server-minted `client_id` a client cannot choose (R19).
    Codes additionally assert their short lifetime and grant-chain revocation on reuse
    (R13), and "never in a URL" now asserts both directions: no token is placed in any
    URL-valued header or echoed into any response header, and a valid access token
    presented in a query string is refused (R9).
  - **Freshness lint.** `scripts/rfc9700-scan.sh` (wired into `scripts/gate.sh` and the
    `invariants` CI job) generates the OAuth endpoint inventory from EVERY router in the
    crate, diffs it, and binds every mounted endpoint to a covering test, so a future
    BCP-relevant endpoint cannot ship uncovered while the checklist reads complete. It
    previously sliced `lib.rs` at `pub fn oidc_router`, which made the discovery and
    issuer/JWKS routes invisible to it; those four endpoints are now in the inventory
    and mapped in the checklist.
- Add `tests/conformance_seed.rs` (issue #37). The OIDF harness's `seed.sh` used
  to compute the cert user's Argon2id hash at run time by pulling a MUTABLE
  `alpine:3.20` tag and installing a package FROM THE NETWORK inside the gate
  lane. The hash is committed instead (`deploy/conformance/cert-user-password.phc`),
  so seeding pulls no image and reaches no network. This test re-derives the
  claim rather than taking it on trust: it verifies the committed PHC string
  against the committed cert password through the product's own
  `verify_password` (the code path a real login takes), checks it rejects a wrong
  password, and asserts the harness scripts have not drifted from the password
  the hash was made for. A wrong hash would otherwise surface as every
  conformance plan failing at its login step, far from the cause. Database-free;
  no library change.
- RFC 8628 device authorization grant with cross-device BCP mitigations (issue #24).
  - **Device-authorization endpoint.** `POST /device_authorization` authenticates the
    client (self-scoped, exactly like the token endpoint), gates on the per-client
    grant allowlist (the device grant is opt-in), and returns `device_code`,
    `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, and
    `interval`. The device code is the scope-declaring opaque credential
    `ira_dc_<scoped-handle>~<256-bit-secret>` (only its whole-token digest is stored),
    so the GLOBAL token endpoint recovers its `(tenant, environment)` scope. The
    `user_code` is drawn by unbiased rejection sampling from the RFC 8628 restricted,
    transcription-friendly alphabet (`BCDFGHJKLMNPQRSTVWXZ`) and stored only as a hash.
  - **Token-endpoint poll.** A new `grant_type=urn:ietf:params:oauth:grant-type:device_code`
    arm returns the RFC 8628 section 3.5 set: `authorization_pending`, an ENFORCED
    `slow_down` (a poll faster than the per-device_code interval increases that interval
    in place), `access_denied`, and `expired_token`. Tokens are pre-signed then the flow
    is atomically redeemed, so a signing failure never burns it and the device code is
    single use.
  - **Verification page** at `/t/{tenant}/e/{environment}/device`, built on the M2
    login/consent bootstrap: it shows the client name, its registered logo (rendered as
    a browser-fetched `<img>` under a narrowed CSP, never fetched server-side), and a
    coarse initiation-location hint, and requires an EXPLICIT approval before any consent
    is recorded or any token is issued. `verification_uri_complete` prefills the code for
    a QR scan. An unknown, expired, or exhausted code shows one NON-oracular error;
    user-code entry is rate limited per source and a flow dies after a bounded number of
    failed matches. The device code and user code are never logged in plaintext
    (redacted from every `Debug`; a test captures a full flow's trace output and asserts
    their absence). Discovery advertises the endpoint and the grant on both well-known
    forms.
  - **Verification GET is prefill-only (user-code enumeration oracle closed).** Opening
    `GET /t/{tenant}/e/{environment}/device?user_code=<code>` (a QR scan of
    `verification_uri_complete`) now renders the code into the entry field WITHOUT
    resolving it, so the GET returns byte-identical output whether or not the code names
    a live flow: it can never be a user-code existence oracle and needs no rate limit of
    its own (RFC 8628 sections 3.3 and 5.1). A code is resolved ONLY through the
    rate-limited POST, which remains the sole path to sign-in, confirmation, and
    approval, so a prefilled code still requires the explicit user action the
    cross-device BCP demands. Previously the GET resolved the code and returned a
    distinguishable page (the sign-in/confirm view for a live code, the non-oracular
    error otherwise) with no per-source rate limit, making a live code enumerable at
    HTTP speed over the primary (QR) entry path. Tests assert the GET renders identically
    for a valid and an invalid code, that opening the prefilled link approves nothing
    (the device still polls `authorization_pending`), and that a device_code is bound to
    its issuing client (a different client polling an approved code is `invalid_grant`
    and does not burn the flow). The device grant issues a refresh token whenever the
    environment issues them, independent of `offline_access` (a deliberate divergence
    from the authorization-code grant, documented in `issue_device_refresh`): a
    constrained device that completed a one-time cross-device approval expects a durable
    session; `offline_access` still governs the refresh lifetime.
- JWT bearer assertion grant (issue #26, RFC 7521 4.1 / RFC 7523 2.1, 3):
  `urn:ietf:params:oauth:grant-type:jwt-bearer` at the token endpoint.
  - **Trust configuration.** Per-tenant, per-environment REGISTERED external
    assertion issuers, each with a key source (an inline pinned `jwks`, OR a
    `jwks_uri` fetched through the SAME SSRF-hardened resolver a `private_key_jwt`
    client's keys use), an optional per-issuer signing-alg allowlist, and an enable
    switch. Assertions from an unregistered or disabled issuer are rejected.
  - **Assertion validation (RFC 7523 3).** The signature is verified against the
    trusted issuer's keys THROUGH the same allowlist JOSE `verify` path #8/#25 use
    (EdDSA + ES256/384 + RS256/384/512 + PS256/384/512; ES512 unrepresentable), so
    the assertion's own `alg` header is never trusted. `iss`/`sub`/`aud`/`exp` are
    required, clock-skew bounds run via `env.clock()`, and an OPTIONAL single-use
    `jti` is spent in a DISTINCT `external_assertion_jtis` cache keyed by the
    external ISSUER, so an external jti can never collide with a #25
    client-assertion jti.
  - **Shared audience policy.** The set of audiences an assertion may be addressed
    to REUSES the one `OidcState::client_assertion_audiences` knob #25 introduced
    (issuer-or-token-endpoint by default, issuer-only under the strict switch), so a
    FAPI-shaped deployment flips ONE config switch for both client assertions and
    this grant; the clock-skew bound is the same `client_assertion_skew`.
  - **Subject mapping, reject by default.** A REGISTERED, explicit rule maps a
    verified (external issuer + `sub`, plus an optional claim gate) to an IronAuth
    principal; the token is issued under that mapped identity as its `sub`. An
    unmapped subject is REJECTED, never auto-provisioned.
  - **Normal token lifecycle, no refresh.** The issued access token is short-lived,
    audienced to the presenting client via the #29 `resolve_access_token_target`
    seam (`resource = None`), minted through the same signing core, and recorded
    against a fresh grant (audited `jwt_bearer_assertion.issue`), so it is revocable
    and introspectable by construction. NO refresh token and NO ID token are issued
    (RFC 7521 4.1: re-present the assertion).
  - **Errors and diagnostics.** Every assertion-validation or mapping failure is the
    uniform, opaque `invalid_grant` on the wire, with the specific reason recorded
    OUT OF BAND in the SAME `client_auth_diagnostics` sink client authentication
    uses; the presenting client's authentication fails INDEPENDENTLY as
    `invalid_client`. `urn:ietf:params:oauth:grant-type:jwt-bearer` joins
    `grant_types_supported` in generated discovery (from live config).
  - **Machine-grant scope policy (shared with client-credentials).** The requested
    `scope` is validated through the SAME `validate_m2m_scope` helper the #23
    client-credentials grant uses, so a mapped-identity assertion-grant token can
    never carry `openid` (an OIDC/user concept) or `offline_access` (a refresh token,
    which this grant never issues): either is `invalid_scope`, rejected BEFORE the
    assertion's single-use jti is spent.
  - **Revocable trust config.** A registered issuer OR mapping can be DISABLED through
    the data plane, after which the grant rejects its assertions exactly as an
    unregistered/unmapped one (uniform `invalid_grant`, existing diagnostic reason).
    The issuer resolve already required `enabled`; the mapping resolve now filters on
    `enabled = true` too, so a mis-authored mapping is revocable now (the HTTP
    management surface is M13).
- RFC 8707 Resource Indicators (issue #28) at the authorization, PAR, and token
  endpoints.
  - **The `resource` parameter, possibly repeated.** The authorization request, the
    PAR request, and the token request (on both the `authorization_code` and the
    `refresh_token` grant) accept one or more `resource` values. Each must be an
    absolute URI with no fragment (RFC 8707 section 2); a malformed, unregistered, or
    disallowed value is rejected with the `invalid_target` error (rendered on the
    token error body and on the authorization redirect). The `/par` endpoint validates
    the pushed `resource` indicators at PUSH time (RFC 9126 section 2.3), through the
    SAME per-client allowlist, URI-shape, and registered-resource-server check the
    authorization endpoint applies, so a bad `resource` surfaces `invalid_target` on
    the back channel rather than being deferred to `/authorize`; the two paths reuse
    one helper and cannot diverge.
  - **Audience-restricted access tokens (RFC 9068, RFC 9700).** An at+jwt carries
    ONLY the requested, allowlisted audiences: a single resource yields a string
    `aud` (byte-identical to the pre-#28 wire form), multiple resources yield a JSON
    array `aud`. An opaque token records its audiences so introspection reports them
    (a string for one, an array for many). There is no default-everything audience;
    a token minted for resource A fails audience validation at resource B.
    Introspection (RFC 7662 section 2.2) reports the FULL audience set for BOTH token
    formats: an at+jwt now reports EVERY signed `aud` member (not just the first),
    matching the opaque path, so a resource server that relies on introspection sees
    the token's true intended audience and never wrongly rejects a valid
    multi-resource token (a single-audience token still reports a bare string).
  - **Per-client policy.** An optional allowlist restricts which registered resources
    a client may target; a per-client knob decides the no-resource case (fall back to
    the client-id audience, the additive default, or refuse the request). Resources
    resolve against the environment `resource_servers` registry for their audience,
    token format, and lifetime; all targeted resource servers must agree on a format
    (else `invalid_target`) and the token takes the shortest of their lifetimes.
  - **Downscope, never expand.** The resources approved at authorization are frozen on
    the code and the grant. A code exchange or a refresh may name a SUBSET of them
    (narrowing the token), but naming a resource outside the approved set is
    `invalid_target`, so a refresh can never broaden a grant.
  - `OidcState::resolve_access_token_target` now takes a `&[String]` of resources and
    returns a `Result<AccessTokenTarget, ResourceTargetError>` carrying an audience
    vector; the no-resource path is unchanged, so the device (#24), jwt-bearer (#26),
    and client-credentials grants keep their single client-id audience.

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
