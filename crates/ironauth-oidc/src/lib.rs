// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth OIDC core provider: the authorization endpoint and the
//! `authorization_code` grant (issue #12).
//!
//! This crate is the first public-facing protocol surface. It mounts on the
//! PUBLIC data plane (never the management port) and ships the two endpoints the
//! authorization-code flow needs, built to the OAuth 2.1 posture and RFC 9700:
//!
//! - `GET`/`POST /authorize`: issues a single-use authorization code bound to the
//!   request's `client_id`, `redirect_uri`, `nonce`, and PKCE `code_challenge`.
//! - `POST /token`: redeems a code under the `authorization_code` grant, atomically
//!   and exactly once, re-checking every binding (including `client_id`), and
//!   issues an ID token and an access token through the #9 signing core.
//!
//! # What makes this safe by construction
//!
//! - **Single use across N stateless nodes.** The code is consumed by ONE atomic
//!   database statement (`UPDATE ... WHERE consumed_at IS NULL RETURNING ...`)
//!   under READ COMMITTED; zero rows affected is a miss that is then classified.
//!   There is no in-memory marker, so the property holds no matter how many nodes
//!   serve the token endpoint. A seam is left for a future cache-based accelerator
//!   (never mandatory, per the covenants).
//! - **Every binding re-checked, uniformly, BEFORE the code is burned.** The token
//!   endpoint reads the code (without consuming it), re-checks the `client_id`,
//!   `redirect_uri`, and PKCE `code_challenge`, and pre-signs the tokens; only
//!   then does the atomic redeem consume the code. A wrong-binding presentation or
//!   a signing failure therefore never burns the one-time code. Any mismatch is a
//!   uniform `invalid_grant` that never says which one failed.
//! - **Reuse revokes the chain; a benign retry does not.** Presenting a
//!   still-consumed code within a small configurable grace window
//!   (`oidc.reuse_grace_secs`, default 10s) is treated as a benign double-submit
//!   or client retry: it fails with `invalid_grant` but does NOT revoke. Beyond
//!   the window it is a genuine reuse: the grant is revoked, which flips the
//!   observable active state of every token issued from it (an introspection or
//!   active-state check then rejects them; it does not cryptographically
//!   invalidate an already-minted JWT), and the reuse is audited.
//! - **Forbidden flows are structurally absent** (see [`registry`]): no ROPC
//!   handler, no access-token issuance from the authorization endpoint, no plain
//!   PKCE. The grant-type, response-type, and PKCE-method registries cannot
//!   express them.
//! - **No redirect before validation.** `client_id` and `redirect_uri` are
//!   validated before anything is redirected; an invalid one renders an error page.
//!
//! # Scope of this issue
//!
//! The conditional ID-token claim rules (OIDC Core errata set 2: honest `acr`,
//! `amr`, `auth_time`, the 255-ASCII `sub` cap, `nonce`, and the staged
//! `at_hash`/`c_hash`) are #14 and land here (see [`tokens`] and [`authn`]).
//! Out of scope, with clean seams left for them: PKCE S256-only ENFORCEMENT and
//! exact redirect matching and RFC 9207 `iss` (#13); refresh rotation and
//! families (M3); the legacy response types and `form_post` and the front-channel
//! emission of `at_hash`/`c_hash` (#17); and the IronCache-backed replay
//! accelerator.
//!
//! Because the strict registered-redirect match and mandatory-S256 enforcement
//! are #13, this provider MUST NOT be enabled in production before #13 lands:
//! `oidc.enabled` is `false` by default, and even when enabled it fails closed
//! without per-environment signing keys.
//!
//! # Mounting
//!
//! Build the router with [`oidc_router`] over an [`OidcState`] and mount it on the
//! server's PUBLIC plane (`ironauth_server::Server::mount_public`). In production
//! the state's store authenticates as the data-plane `ironauth_app` role and the
//! signing keys are provisioned per environment; the integration tests build the
//! router directly with a populated key store, exactly as the management-API tests
//! build their router.

mod abuse;
mod account;
/// The pure trust decision for guarded account linking (issue #78), unit-tested in
/// isolation and correct-but-unwired in PR 1 (PR 2 wires it into the callback).
pub mod account_linking;
mod acme;
pub mod advanced_recovery;
mod authn;
mod authorize;
mod backchannel;
pub mod branding;
mod broker_overlay;
mod claims_request;
mod client_auth;
mod client_credentials;
mod client_keys;
mod client_registration;
mod consent;
mod dcr_policy;
mod device;
mod device_verify;
mod discovery;
mod disposable;
mod email_otp;
mod error;
mod fedcm;
mod federation;
mod federation_client_secret;
mod federation_health;
mod federation_jwks;
mod federation_oauth2;
mod federation_relay;
pub mod flow;
mod global_revocation;
mod hashing_pool;
mod hints;
mod interaction;
mod introspection;
mod invitations;
mod issuer;
mod jwks;
mod jwt_bearer;
mod login;
mod logout;
mod magic_link;
pub mod mds3_sync;
mod migration;
mod pages;
mod par;
mod password;
mod phone;
mod pkce;
mod policy_trace;
pub mod pow;
mod pow_gate;
mod probe;
mod quota;
mod recover;
pub mod recovery;
mod register;
mod registry;
mod resource;
mod response;
mod revocation;
mod risk;
mod risk_signals;
pub mod routing;
mod scope_claims;
mod sector;
mod session;
mod session_mgmt;
mod sms_conversion;
mod sms_otp;
mod state;
mod step_up;
mod subject;
mod token;
mod token_credential;
mod token_hash;
mod tokens;
mod totp;
mod trusted_device;
mod upstream_token;
mod userinfo;
mod util;
mod verification;
mod webauthn;
mod webauthn_wellknown;
mod wellknown;

use axum::Router;
use axum::routing::{get, post};

pub use abuse::{
    AttemptContext, CounterError, CounterStore, MemoryCounterStore, RegulationOutcome,
    RegulationSettings, canonical_login_identifier, layer_fails_open,
};
pub use acme::{AcmeDirectory, AcmeDirectoryClient, AcmeError};
pub use authn::{
    AuthMethod, AuthenticationEvent, CredentialClass, CredentialFacts, achieved_acr, acr_federated,
    acr_for_class, acr_for_mfa, acr_values_supported, amr_values, federated_amr_from_auth_methods,
    methods_token, parse_methods, required_class, satisfied_class,
};
pub use backchannel::{
    BACKCHANNEL_LOGOUT_EVENT, BackChannelLogoutWorker, DrainStats, FetchLogoutSender,
    LOGOUT_TOKEN_TYP, LogoutSender, SendFailure, WorkerSettings, build_logout_token_claims,
};
pub use client_auth::{
    AuthenticatedClient, ClientAuthError, ClientAuthInputs, ClientAuthMethod, ClientAuthParseError,
    JWT_BEARER_ASSERTION_TYPE, PresentedClientAuth, authenticate_client,
    authenticate_client_self_scoped, generate_secret, hash_secret, parse_presented,
};
pub use client_keys::ClientKeyResolver;
pub use dcr_policy::{
    PolicyPrimitive, PolicyRejectReason, PolicyRejection, apply_chain, parse_chain, serialize_chain,
};
pub use device::normalize_user_code;
pub use discovery::{
    ADVERTISED_ENDPOINTS, CLAIMS_LOCALES_SUPPORTED, DiscoveryCapabilities, DiscoveryEndpoint,
    DiscoveryState, ID_TOKEN_CLAIMS_SUPPORTED, SCOPES_SUPPORTED, UI_LOCALES_SUPPORTED,
    claims_supported, discovery_document, discovery_router, id_token_signing_alg_values,
};
pub use error::{AuthorizeError, AuthzErrorCode, TokenError};
pub use federation::{
    FederationRuntime, TokenExchange, UpstreamTokenPolicy, VerifiedUpstreamIdentity, exchange_code,
    federated_external_id, fetch_discovery, resolve_alg_allowlist, validate_upstream_id_token,
};
pub use federation_health::{
    Admission, CONNECTOR_HEALTHY, CONNECTOR_UPSTREAM_ERROR_TOTAL, CONNECTOR_UPSTREAM_SUCCESS_TOTAL,
    ConnectorHealthRegistry, ConnectorHealthSnapshot, DenyReason, HealthState,
    describe_connector_health_metrics,
};
pub use federation_jwks::FederationKeyResolver;
pub use federation_oauth2::resolve_primary_verified_email;
pub use federation_relay::{EMAIL_RELAY_TRAIT, is_relay_email, routable_email};
pub use global_revocation::GLOBAL_TOKEN_REVOCATION_PATH;
pub use hashing_pool::{
    ADMISSION_REJECTED_TOTAL, HASH_DURATION_SECONDS, HashRejection, HashingPool,
    POOL_ACTIVE_WORKERS, POOL_QUEUE_DEPTH, POOL_THREADS, ThreadDiagnostics, default_pool_threads,
    describe_hashing_pool_metrics, on_hash_worker_thread,
};
pub use hints::{Display, InteractionHints};
pub use introspection::{
    IntrospectionClaims, IntrospectionSerializer, JsonIntrospectionSerializer,
    SerializedIntrospection,
};
pub use issuer::{
    IssuerEntry, IssuerError, IssuerRegistry, JwksCacheError, JwksCacheWindow, load_signing_key,
};
pub use jwks::{IssuerState, issuer_router};
pub use logout::LogoutParams;
pub use migration::{
    BreakerState, CircuitBreaker, CredentialVerifier, HookError, HookOutcome, HookProfile,
    HookVerdict, LAZY_MIGRATION_BREAKER_STATE, LAZY_MIGRATION_BREAKER_TRANSITIONS_TOTAL,
    LAZY_MIGRATION_HOOK_LATENCY_SECONDS, LAZY_MIGRATION_HOOK_TOTAL, LAZY_MIGRATION_MIGRATED_TOTAL,
    LazyMigrationHook, WebhookVerifier, build_from_config as build_lazy_migration_hook,
    describe_metrics as describe_lazy_migration_metrics,
};
pub use password::{
    Argon2Params, PasswordError, hash_password, hash_password_with, needs_rehash, verify_absent,
    verify_password,
};
pub use probe::{
    ProbeReport, available_memory_kib, default_memory_budget_kib, run_probe, total_memory_kib,
};
pub use recovery::{
    FactorChangeDecision, NullRiskEvaluator, RecoveryFactor, RecoverySettings, RiskDirective,
    RiskEvaluator, RiskEvent, factor_change_decision,
};
pub use registry::{
    GrantType, PkceMethod, PromptSet, PromptSetError, PromptValue, ResponseMode, ResponseType,
};
pub use revocation::{
    NoopRevocationSink, RevocationEvent, RevocationEventSink, RevokedTokenType,
    SessionLifecycleEvent, SessionSignalCause,
};
pub use risk::{
    GeoIpProvider, GeoLocation, IpReputation, IpReputationProvider, NullGeoIpProvider,
    NullIpReputationProvider, RiskAction, RiskDecision, RiskLevel, SignalOutcome,
};
pub use routing::{RouteCandidates, normalize_email_domain, resolve_route};
pub use sector::{
    SectorError, check_sector_document, sector_uri_required, validate_sector_identifier,
};
pub use session::{PEER_IP_HEADER, SESSION_COOKIE, clear_set_cookie};
pub use state::{
    OidcState, PASSWORD_BREACHED_AT_LOGIN_TOTAL, PASSWORD_SCREEN_TOTAL, ResourceTargetError,
    describe_screening_metrics,
};
pub use step_up::{canonical_step_up_acr, privilege_is_fresh, required_credential_class};
pub use subject::{
    MAX_SUBJECT_LEN, PairwiseSalt, SubjectCache, SubjectConfig, SubjectType, resolve_subject,
    subject_within_cap,
};
pub use token_hash::{HashKind, at_hash, c_hash, left_half_hash};
pub use tokens::{
    AccessTokenTarget, ClientCredentialsMintRequest, MintedAccessToken, OPAQUE_ACCESS_TOKEN_PREFIX,
    OPAQUE_REFRESH_TOKEN_PREFIX,
};
pub use verification::{
    EmailOtpMessage, LoggingSmsSender, LoggingVerificationSender, MagicLinkMessage,
    NewDeviceNotice, NullSmsSender, NullVerificationSender, SmsOtpMessage, SmsSender,
    VerificationPurpose, VerificationSender,
};

/// Build the OIDC provider router.
///
/// Mount the returned router on the PUBLIC data plane (for example by passing it
/// to `ironauth_server::Server::mount_public`). It serves `GET`/`POST /authorize`
/// and `POST /token`; the `state` carries the data-plane store, the environment
/// seam, the per-environment signing keys, the issuer base, and the configured
/// code and access-token lifetimes.
// A flat inventory of `.route()` mounts; splitting the endpoint list across helpers
// would scatter the single mounted surface the RFC 9700 lint reads.
#[allow(clippy::too_many_lines)]
pub fn oidc_router(state: OidcState) -> Router {
    let mut router = Router::new()
        .route(
            "/authorize",
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route("/token", post(token::token))
        // Pushed authorization requests (PAR, RFC 9126, issue #27): an authenticated
        // back-channel POST that validates a complete authorization request and
        // returns a one-time request_uri. Advertised in discovery as
        // pushed_authorization_request_endpoint at this exact path.
        .route("/par", post(par::par))
        // Token revocation (RFC 7009, issue #22): an authenticated client revokes one
        // of its own tokens (refresh, opaque access, or at+jwt). Advertised in
        // discovery as revocation_endpoint at this exact path.
        .route("/revoke", post(revocation::revoke))
        // Token introspection (RFC 7662, issue #22): an authenticated caller reads a
        // token's active state and metadata. Advertised in discovery as
        // introspection_endpoint at this exact path.
        .route("/introspect", post(introspection::introspect))
        // RP-Initiated Logout (OIDC RP-Initiated Logout 1.0, issue #33): a top-level
        // browser navigation that ends the SSO session and, only on an exact registered
        // post_logout_redirect_uri match with a verifiable id_token_hint, redirects back
        // to the client. Advertised in discovery as end_session_endpoint at this exact
        // path. GET is the RP-initiated navigation; POST is the confirmation submit for
        // an unattributable request (behind the same-origin CSRF check).
        .route(
            "/end_session",
            get(logout::end_session_get).post(logout::end_session_post),
        )
        // UserInfo (OIDC Core 5.3): GET and POST with header Bearer auth, plus the
        // OPTIONS preflight for the CORS SPA origins (issue #15). CORS is applied on
        // this endpoint ONLY; the authorization endpoint above never gets it.
        .route(
            "/userinfo",
            get(userinfo::userinfo_get)
                .post(userinfo::userinfo_post)
                .options(userinfo::userinfo_preflight),
        )
        // The bootstrap login, registration, and consent interaction surfaces
        // (issue #20). GET renders the minimal hardened page; POST records the
        // decision and resumes the authorization request. This `/register` is
        // HUMAN account registration; the DCR CLIENT registration below is a
        // distinct concept mounted at a distinct `/connect/register` path.
        .route("/login", get(login::login_get).post(login::login_post))
        // The generic OIDC UPSTREAM federated login legs (issue #75, PR B): begin a
        // federated login by redirecting to a declarative connector's upstream provider,
        // and receive the callback, where the correlation row is consumed SINGLE-USE (the
        // CSRF defence), the upstream ID token is validated through the JOSE core, and a
        // minimal local identity is provisioned. Adding a provider is a stored connector
        // definition, never a route. Inert (a uniform not-found) until a federation runtime
        // is installed on the state.
        .route(
            "/t/{tenant_id}/e/{environment_id}/federation/{connector_slug}/authorize",
            get(federation::federation_authorize),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/federation/{connector_slug}/callback",
            get(federation::federation_callback),
        )
        // The upstream token vault retrieval endpoint (issue #77, PR 3): an authorized
        // client POSTs here to retrieve its own session's captured upstream tokens, behind
        // session-ownership and client-capability checks. Inert (a uniform not-found) until
        // a federation runtime is installed on the state.
        .route(
            "/t/{tenant_id}/e/{environment_id}/federation/upstream-token",
            post(upstream_token::retrieve_upstream_token),
        )
        // The "this wasn't me" disavowal endpoint (issue #79): a new-device notification
        // links here with a single-use token. GET renders a scanner-safe confirmation
        // page; POST consumes the token, revokes the flagged sessions and trusted devices,
        // and marks the credentials for review. The handler recovers the scope from the
        // token, so the route is global (mounted once, not per environment).
        .route(
            risk::DISAVOWAL_PATH,
            get(risk::disavow_get).post(risk::disavow_post),
        )
        // The RFC 9470 step-up second-factor challenge (issue #72): shown when an
        // authorization request needs an authentication context the current session
        // has not achieved. Verifies a TOTP or recovery code and upgrades the session
        // with a fresh acr and auth_time.
        .route(
            "/login/mfa",
            get(login::mfa_challenge_get).post(login::mfa_challenge_post),
        )
        .route(
            "/register",
            get(register::register_get).post(register::register_post),
        )
        // HUMAN account recovery (issue #64): the anti-enumeration-uniform recovery
        // request surface, governed on the INDEPENDENT recovery path.
        .route(
            "/recover",
            get(recover::recover_get).post(recover::recover_post),
        )
        // The recovery cancellation-from-notification-link surface (issue #81): the
        // "this was not me" path that revokes a pending recovery in its delay window.
        .route(
            "/recover/cancel",
            get(recover::recover_cancel_get).post(recover::recover_cancel_post),
        )
        .route(
            "/consent",
            get(consent::consent_get).post(consent::consent_post),
        )
        // The RFC 8628 device authorization grant (issue #24). The back-channel
        // device-authorization endpoint (advertised in the discovery document, whose
        // metadata key is defined only in discovery.rs) at this deployment-root path
        // mints a device_code and user_code; the scope-routed verification page under
        // the per-environment issuer path is where a human enters the user code, signs
        // in, and EXPLICITLY approves before the device is issued any token.
        .route("/device_authorization", post(device::device_authorization))
        .route(
            "/t/{tenant_id}/e/{environment_id}/device",
            get(device_verify::device_get).post(device_verify::device_post),
        )
        // The self-service end-user account API (issue #61): an AUTHENTICATED user
        // manages their OWN account. Scope-routed under the per-environment path so
        // every read/write runs under the right row-level-security scope, and
        // authenticated by the user's OWN session cookie (never the management API's
        // admin credentials). Every endpoint acts ONLY on the authenticated subject's
        // resources; the state-changing POSTs carry the #196 same-origin CSRF check.
        // The hosted account pages (M9) consume this API without any private endpoint.
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/sessions",
            get(account::list_sessions),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/sessions/revoke",
            post(account::revoke_session),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/sessions/revoke-others",
            post(account::revoke_other_sessions),
        )
        // The remembered-device (trusted-device) surface (issue #71): list the caller's
        // OWN remembered devices with their metadata, and revoke one or all. Revocation
        // takes effect server-side IMMEDIATELY (a replayed device cookie fails). Every
        // endpoint acts ONLY on the authenticated subject; the POSTs carry the #196
        // same-origin CSRF check.
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/trusted-devices",
            get(account::list_trusted_devices),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/trusted-devices/revoke",
            post(account::revoke_trusted_device),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/trusted-devices/revoke-all",
            post(account::revoke_all_trusted_devices),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/credentials",
            get(account::list_credentials).post(account::enroll_credential),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/credentials/remove",
            post(account::remove_credential),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/password",
            post(account::change_password),
        )
        // Passkey-only conversion (issue #66): remove the password, converting a password
        // account to passkey-only. Gated by a fresh passkey re-authentication and the
        // cross-source last-credential guard (the reverse direction, setting a first
        // password on a passkey-only account, is the passwordless branch of the change
        // endpoint above).
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/password/remove",
            post(account::remove_password),
        )
        // Guarded account linking (issue #78): the self-service linked-identities API. List
        // the caller's OWN linked federated identities, START a manual link (gated by a
        // FRESH re-authentication of the target account, never merely an active session),
        // and REMOVE one (the write-skew-safe last-usable-method guard refuses unlinking the
        // account's sole surviving method). Every link and unlink emits an audit event and a
        // coarse notification to every verified channel.
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/linked-identities",
            get(account::list_linked_identities),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/linked-identities/start",
            post(account::start_link),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/linked-identities/remove",
            post(account::remove_linked_identity),
        )
        // WebAuthn Related Origin Requests document (issue #67, WebAuthn Level 3):
        // GET /.well-known/webauthn serves the {"origins": [...]} list a browser
        // fetches from the RP ID's own origin to accept a ceremony from a related
        // origin. Deployment-root (NOT scope-routed): a browser fetches it from the
        // bare host, and the RP ID + related origins are process-level config. It
        // 404s when the feature is unconfigured, so a domain not using it discloses
        // nothing.
        .route(
            "/.well-known/webauthn",
            get(webauthn_wellknown::related_origins),
        )
        // IdP-side FedCM READ surface (issue #83, EXPLORATORY, W3C Federated Credential
        // Management). The origin-level /.well-known/web-identity is deployment-root
        // (a browser fetches it from the bare host and it points at the single
        // designated env's scoped config); the config and accounts endpoints are
        // scope-routed, as is the credential-issuing /assertion endpoint (PR 2). The
        // handlers fail closed with a 404 when the `fedcm` experimental feature is off,
        // so the route literals stay UNCONDITIONAL for the RFC 9700 endpoint inventory.
        // Redirect flows are unaffected; with the flag off nothing here answers.
        .route("/.well-known/web-identity", get(fedcm::well_known))
        .route(
            "/t/{tenant_id}/e/{environment_id}/fedcm/config.json",
            get(fedcm::config),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/fedcm/accounts",
            get(fedcm::accounts),
        )
        // The credential-issuing FedCM ID assertion endpoint (issue #83, PR 2): a form
        // POST from the browser's FedCM machinery that mints an ID token DIRECTLY to a
        // relying party, under the SAME client/origin/consent/nonce discipline as the
        // redirect flow (no bypass). Fails closed with a 404 when the feature is off, so
        // the literal stays UNCONDITIONAL for the RFC 9700 endpoint inventory.
        .route(
            "/t/{tenant_id}/e/{environment_id}/fedcm/assertion",
            post(fedcm::assertion),
        )
        // The third-party risk-signal ingestion endpoint (issue #82, PR 1, EXPLORATORY): a
        // signed Security Event Token (SET, a compact JWS) pushed by an external fraud/risk
        // source, authenticated by its SIGNATURE against the source's registered public key
        // (never a shared secret) and ingested as one weighted policy input for the #79
        // engine (never a verdict). The handler fails closed with a 404 when the
        // `risk-signals` experimental feature is off, so the route literal stays
        // UNCONDITIONAL for the RFC 9700 endpoint inventory.
        .route(
            "/t/{tenant_id}/e/{environment_id}/risk/signals",
            post(risk_signals::ingest),
        )
        // Advanced recovery modes (issue #82, PR 3, EXPLORATORY): the trusted-contact
        // confirmation surface (a designated contact confirms a recovery out of band with a
        // single-use link) and the IDV-gated recovery callback (consume a provider's signed,
        // single-use, case-bound JOSE-verified callback). Both handlers fail closed with a
        // 404 when the `advanced-recovery` experimental feature is off (or the mode's config
        // sub-toggle is disabled), so the route literals stay UNCONDITIONAL for the RFC 9700
        // endpoint inventory. Standard recovery is unchanged.
        .route(
            "/t/{tenant_id}/e/{environment_id}/recover/trusted-contact/confirm",
            post(advanced_recovery::trusted_contact_confirm),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/recover/idv/callback",
            post(advanced_recovery::idv_callback),
        )
        // WebAuthn passkey ceremonies (issue #65), scope-routed so the RP ID/origin
        // and the credential reads/writes run under the right per-environment scope.
        // The register endpoints require the caller's session; the authenticate
        // endpoints ARE the sign-in (discoverable credentials, conditional UI). The
        // handlers fail closed with a 404 when `oidc.webauthn_enabled` is off, so the
        // route literals stay unconditional for the RFC 9700 endpoint inventory.
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/register/options",
            post(webauthn::register_options),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/register/verify",
            post(webauthn::register_verify),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/authenticate/options",
            post(webauthn::authenticate_options),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/authenticate/verify",
            post(webauthn::authenticate_verify),
        )
        // Passwordless (passkey-only) SIGNUP ceremony (issue #66): no session required
        // (the account does not exist yet). `options` mints a subject and a UV-required
        // registration challenge; `verify` creates the passkey-only account (no password
        // code path), persists the passkey, and establishes the HONEST passkey session
        // that resumes the authorization request. Fail closed with a 404 when WebAuthn is
        // off, so the route literals stay unconditional for the RFC 9700 inventory.
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/signup/options",
            post(webauthn::register_passkey_signup_options),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/signup/verify",
            post(webauthn::register_passkey_signup_verify),
        )
        // The authenticated passkey management surface (issue #65): the caller lists,
        // renames, and removes their OWN passkeys (subject-bound, IDOR-safe, audited
        // on mutation). The list also appears folded into GET /account/credentials so
        // a user sees every credential in one place; these give the passkey-specific
        // detail (live BE/BS) and the nickname/remove mutations.
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/credentials",
            get(webauthn::list_credentials),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/credentials/rename",
            post(webauthn::rename_credential),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/credentials/remove",
            post(webauthn::remove_credential),
        )
        // The exploratory WebAuthn L3 Signal API surface (issue #73): the
        // authenticated signal-data endpoint and the hosted passkey-management page
        // that emits the feature-detected signal JavaScript. Both fail closed with a
        // 404 when `oidc.webauthn_signal_api_enabled` (or the base webauthn flag) is
        // off, so the routes stay unconditional for the RFC 9700 endpoint inventory
        // while the feature is fully inert.
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/signal",
            get(webauthn::signal_data),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/webauthn/manage",
            get(webauthn::signal_manage_page),
        )
        // The TOTP second-factor and recovery-code endpoints (issue #69), self-service
        // and session-authenticated. Each handler fails closed with a 404 when
        // `oidc.totp_enabled` is off, so a disabled deployment exposes no surface.
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/mfa/totp/enroll",
            post(totp::enroll_begin),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/mfa/totp/verify-enrollment",
            post(totp::enroll_verify),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/mfa/totp/verify",
            post(totp::verify),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/mfa/totp/remove",
            post(totp::remove),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/mfa/recovery-codes",
            post(totp::recovery_regenerate),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/mfa/recovery-codes/redeem",
            post(totp::recovery_redeem),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/account/mfa/plan",
            get(totp::plan),
        )
        // The public invitation-accept endpoint (issue #60): the invitee side of the
        // admin-initiated invitation flow. Scope-routed under the per-environment path
        // so the redeem runs under the right row-level-security scope, and
        // authenticated by the single-use TOKEN in the body (never a session cookie,
        // never an admin credential). Accepting atomically consumes the invitation and
        // activates the pending_verification user (pending_verification -> active),
        // enrolling the credential; every non-resolving token is the uniform not-found.
        .route(
            "/t/{tenant_id}/e/{environment_id}/invitations/accept",
            post(invitations::accept_invitation),
        )
        // Email OTP + scanner-safe magic links (issue #68), scope-routed under the
        // per-environment path so the send/verify/consume run under the right
        // row-level-security scope. Each handler fails closed with a 404 when its
        // factor is disabled. `otp/send` and `magic/send` are JSON send surfaces
        // (abuse-throttled, anti-enumeration uniform); `otp/verify` is the JSON code
        // verify that establishes a session; `magic/confirm` is the SCANNER-SAFE GET
        // that renders a confirmation page only (never consumes); `magic/consume` is the
        // POST from that page that consumes the single-use link and establishes a session.
        .route(
            "/t/{tenant_id}/e/{environment_id}/otp/send",
            post(email_otp::send),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/otp/verify",
            post(email_otp::verify),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/magic/send",
            post(magic_link::send),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/magic/confirm",
            get(magic_link::confirm_get),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/magic/consume",
            post(magic_link::consume_post),
        )
        // The registration-abuse proof-of-work challenge issuance (issue #80), scope-routed
        // so the challenge is minted under the right row-level-security scope. Issues a
        // self-contained hashcash challenge for the registration / reset / OTP-send
        // surfaces with ZERO third-party calls; a uniform 404 when the PoW defense is off or
        // an external adapter is configured (which issues its own client-side widget).
        .route(
            "/t/{tenant_id}/e/{environment_id}/pow/challenge",
            post(pow_gate::pow_challenge_issue),
        )
        // Guarded SMS OTP (issue #70), scope-routed under the per-environment path so the
        // send/verify run under the right row-level-security scope. Both handlers fail
        // closed with a uniform 404 when the deployment kill switch is off, and every
        // guard refusal (a non-allowlisted country, a scored-out number, an
        // auto-throttled route) returns a UNIFORM acknowledgment, so no branch is an
        // enumeration oracle. SMS stays unusable in a tenant until that tenant explicitly
        // enables it AND configures a country allowlist.
        .route(
            "/t/{tenant_id}/e/{environment_id}/otp/sms/send",
            post(sms_otp::send),
        )
        .route(
            "/t/{tenant_id}/e/{environment_id}/otp/sms/verify",
            post(sms_otp::verify),
        )
        // The headless flow API (issue #84), scope-routed under the per-environment issuer
        // path so a flow runs under the right row-level-security scope. ONE machine-readable
        // flow object served to the browser transport (form POST + same-origin CSRF +
        // cookie/303) and the native JSON transport (a per-flow submit token + a 200
        // envelope), sharing ONE state machine, node renderer, message-id registry, error
        // shaping, and anti-enumeration recipe. The handlers fail closed with a uniform 404
        // when `flows.enabled` is off (FORK D), so the route literals stay UNCONDITIONAL for
        // the RFC 9700 endpoint inventory while the bootstrap `/login`, `/consent`, and
        // `/register` pages are untouched (their cutover onto this engine is issue #85).
        .route(
            flow::FLOW_BROWSER_PATH,
            get(flow::flow_browser_get).post(flow::flow_browser_post),
        )
        .route(flow::FLOW_CREATE_API_PATH, post(flow::flow_api_create))
        .route(flow::FLOW_API_SUBMIT_PATH, post(flow::flow_api_submit))
        // The hosted flow render app stylesheet (issue #85, FORK C): the ONE embedded, same
        // origin `.../pages.css` the server rendered flow pages link, served under the
        // `style-src 'self'` CSP. Gated behind `flows.enabled` (a uniform 404 when off), so
        // the render app adds no live surface while the flag is off (no cutover in this PR).
        .route(flow::FLOW_STYLESHEET_PATH, get(flow::flow_stylesheet))
        // The served brand assets (issue #86, PR 3): the same origin `.../brand/{slug}/{kind}`
        // GET that streams a brand's stored logo / favicon raster with server-fixed headers, the
        // source the flow page's `<img>` and favicon `<link>` point at under `img-src 'self'`.
        // Gated behind `flows.enabled` (a uniform 404 when off), so it adds no live surface while
        // the flag is off.
        .route(flow::FLOW_BRAND_ASSET_PATH, get(flow::flow_brand_asset));

    // Dynamic Client Registration (issue #30, RFC 7591 + RFC 7592), mounted ONLY
    // when enabled (default off; issue #31 owns the real abuse gating). The routes
    // live under the per-environment issuer path (`{issuer}/connect/register`), so
    // a registration lands in the (tenant, environment) the client will operate in,
    // and never shadow the human `/register` route above.
    if state.registration_enabled() {
        router = router
            .route(
                "/t/{tenant_id}/e/{environment_id}/connect/register",
                post(client_registration::register),
            )
            .route(
                "/t/{tenant_id}/e/{environment_id}/connect/register/{client_id}",
                get(client_registration::read)
                    .put(client_registration::update)
                    .delete(client_registration::delete),
            );
    }

    // OIDC Session Management 1.0 check_session_iframe (issue #39), mounted ONLY when
    // session management is enabled for this deployment (default off). It is the ONE
    // page deliberately framable cross-origin (an RP embeds it), so it is served with a
    // framing carve-out; with the flag off it is never mounted and discovery omits
    // check_session_iframe. The route literal is unconditional here so the RFC 9700
    // endpoint-inventory lint sees it.
    if state.session_management_enabled() {
        router = router.route("/connect/check_session", get(session_mgmt::check_session));
    }

    // Global Token Revocation receiver (issue #36), mounted ONLY when the experimental
    // `global-token-revocation` feature is enabled and acknowledged (the boot path
    // resolves the gate from the strict config feature ladder). A strongly-authenticated
    // confidential client revokes EVERYTHING one subject holds in its own scope. The
    // draft is not WG-adopted, so the endpoint is unmounted by default.
    if state.global_token_revocation_enabled() {
        router = router.route(
            global_revocation::GLOBAL_TOKEN_REVOCATION_PATH,
            post(global_revocation::global_token_revocation),
        );
    }

    router.with_state(state)
}
