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
//!   database statement (`UPDATE ... WHERE consumed_at IS NULL RETURNING ...`);
//!   zero rows affected is a replay. There is no in-memory marker, so the property
//!   holds no matter how many nodes serve the token endpoint. A seam is left for a
//!   future cache-based accelerator (never mandatory, per the covenants).
//! - **Every binding re-checked, uniformly.** At redemption the `client_id`,
//!   `redirect_uri`, and PKCE `code_challenge` are all re-checked; any mismatch is
//!   a uniform `invalid_grant` that never says which one failed.
//! - **Reuse revokes the chain.** Redeeming a consumed code revokes its grant, so
//!   every token issued from it becomes inactive, and the reuse is audited.
//! - **Forbidden flows are structurally absent** (see [`registry`]): no ROPC
//!   handler, no access-token issuance from the authorization endpoint, no plain
//!   PKCE. The grant-type, response-type, and PKCE-method registries cannot
//!   express them.
//! - **No redirect before validation.** `client_id` and `redirect_uri` are
//!   validated before anything is redirected; an invalid one renders an error page.
//!
//! # Scope of this issue
//!
//! Out of scope, with clean seams left for them: PKCE S256-only ENFORCEMENT and
//! exact redirect matching and RFC 9207 `iss` (#13); the conditional ID-token
//! claim rules (#14); refresh rotation and families (M3); the legacy response
//! types and `form_post` (#17); and the IronCache-backed replay accelerator.
//!
//! # Mounting
//!
//! Build the router with [`oidc_router`] over an [`OidcState`] and mount it on the
//! server's PUBLIC plane (`ironauth_server::Server::mount_public`). In production
//! the state's store authenticates as the data-plane `ironauth_app` role and the
//! signing keys are provisioned per environment; the integration tests build the
//! router directly with a populated key store, exactly as the management-API tests
//! build their router.

mod authorize;
mod error;
mod pkce;
mod registry;
mod state;
mod token;
mod tokens;
mod util;

use axum::Router;
use axum::routing::{get, post};

pub use error::{AuthorizeError, AuthzErrorCode, TokenError};
pub use registry::{GrantType, PkceMethod, ResponseType};
pub use state::OidcState;

/// Build the OIDC provider router.
///
/// Mount the returned router on the PUBLIC data plane (for example by passing it
/// to `ironauth_server::Server::mount_public`). It serves `GET`/`POST /authorize`
/// and `POST /token`; the `state` carries the data-plane store, the environment
/// seam, the per-environment signing keys, the issuer base, and the configured
/// code and access-token lifetimes.
pub fn oidc_router(state: OidcState) -> Router {
    Router::new()
        .route(
            "/authorize",
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route("/token", post(token::token))
        .with_state(state)
}
