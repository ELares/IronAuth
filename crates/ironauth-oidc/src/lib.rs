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

mod authn;
mod authorize;
mod claims_request;
mod client_auth;
mod client_credentials;
mod client_keys;
mod client_registration;
mod consent;
mod discovery;
mod error;
mod hints;
mod interaction;
mod issuer;
mod jwks;
mod login;
mod pages;
mod par;
mod password;
mod pkce;
mod register;
mod registry;
mod response;
mod scope_claims;
mod sector;
mod session;
mod state;
mod subject;
mod token;
mod token_hash;
mod tokens;
mod userinfo;
mod util;
mod wellknown;

use axum::Router;
use axum::routing::{get, post};

pub use authn::{
    AuthMethod, AuthenticationEvent, achieved_acr, acr_values_supported, amr_values, methods_token,
    parse_methods,
};
pub use client_auth::{
    AuthenticatedClient, ClientAuthError, ClientAuthInputs, ClientAuthMethod, ClientAuthParseError,
    JWT_BEARER_ASSERTION_TYPE, PresentedClientAuth, authenticate_client, generate_secret,
    hash_secret, parse_presented,
};
pub use client_keys::ClientKeyResolver;
pub use discovery::{
    ADVERTISED_ENDPOINTS, CLAIMS_LOCALES_SUPPORTED, DiscoveryCapabilities, DiscoveryEndpoint,
    DiscoveryState, ID_TOKEN_CLAIMS_SUPPORTED, SCOPES_SUPPORTED, UI_LOCALES_SUPPORTED,
    claims_supported, discovery_document, discovery_router, id_token_signing_alg_values,
};
pub use error::{AuthorizeError, AuthzErrorCode, TokenError};
pub use hints::{Display, InteractionHints};
pub use issuer::{
    IssuerEntry, IssuerError, IssuerRegistry, JwksCacheError, JwksCacheWindow, load_signing_key,
};
pub use jwks::{IssuerState, issuer_router};
pub use password::{PasswordError, hash_password, verify_password};
pub use registry::{
    GrantType, PkceMethod, PromptSet, PromptSetError, PromptValue, ResponseMode, ResponseType,
};
pub use sector::{
    SectorError, check_sector_document, sector_uri_required, validate_sector_identifier,
};
pub use session::SESSION_COOKIE;
pub use state::OidcState;
pub use subject::{
    MAX_SUBJECT_LEN, PairwiseSalt, SubjectCache, SubjectConfig, SubjectType, resolve_subject,
    subject_within_cap,
};
pub use token_hash::{HashKind, at_hash, c_hash, left_half_hash};
pub use tokens::{
    AccessTokenTarget, ClientCredentialsMintRequest, MintedAccessToken, OPAQUE_ACCESS_TOKEN_PREFIX,
    OPAQUE_REFRESH_TOKEN_PREFIX,
};

/// Build the OIDC provider router.
///
/// Mount the returned router on the PUBLIC data plane (for example by passing it
/// to `ironauth_server::Server::mount_public`). It serves `GET`/`POST /authorize`
/// and `POST /token`; the `state` carries the data-plane store, the environment
/// seam, the per-environment signing keys, the issuer base, and the configured
/// code and access-token lifetimes.
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
        .route(
            "/register",
            get(register::register_get).post(register::register_post),
        )
        .route(
            "/consent",
            get(consent::consent_get).post(consent::consent_post),
        );

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

    router.with_state(state)
}
