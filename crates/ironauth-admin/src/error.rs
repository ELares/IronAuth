// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed management-API errors and their structured JSON rendering.
//!
//! Two error shapes are load-bearing for the isolation contract:
//!
//! - [`ApiError::NotFound`] is the UNIFORM not-found: a malformed identifier, an
//!   absent resource, and a resource in another scope all render identically, so
//!   the API is never an existence oracle (the anti-oracle rule).
//! - [`ApiError::WrongScope`] is the LOUD wrong-scope error: a credential
//!   presented against the wrong environment or the wrong plane fails with a
//!   structured error that names the expected and actual scope, so a
//!   misconfigured client gets a clear signal rather than a silent denial.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{GuardrailViolation, StoreError};
use serde::Serialize;
use utoipa::ToSchema;

/// The structured error body every management error renders to. Stable shape, so
/// generated SDKs can type it from the first endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorBody {
    /// A stable, machine-readable error type (for example `not_found`,
    /// `wrong_scope`, `idempotency_key_conflict`).
    #[schema(example = "not_found")]
    pub error: String,
    /// A human-readable message. Never carries a secret; for a wrong-scope error
    /// it names only the scope identifiers the caller already presented.
    #[schema(example = "resource not found")]
    pub message: String,
    /// Present only on a wrong-scope error: the scope the credential is
    /// authorized for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_scope: Option<String>,
    /// Present only on a wrong-scope error: the scope the request targeted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_scope: Option<String>,
    /// Present only on a guardrail-violation error (issue #42): the stable code of
    /// every guardrail the request failed, so the caller learns each failure at
    /// once (for example `["custom_domain_required", "https_only_redirect_uris"]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_guardrails: Option<Vec<String>>,
    /// Present only on a sudo-mode re-authentication challenge (issue #73): the maximum
    /// authentication age, in seconds, the mutation requires. Mirrors the RFC 9470
    /// `max_age` challenge parameter (also carried in the `WWW-Authenticate` header), so
    /// the admin SPA learns how fresh a re-authentication it must obtain before
    /// retrying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
}

/// A management API error.
#[derive(Debug)]
pub enum ApiError {
    /// The request was malformed (missing required header, invalid cursor, or an
    /// unparseable body). Renders 400.
    BadRequest(String),
    /// No valid credential was presented. Renders 401 with `WWW-Authenticate`.
    Unauthorized(String),
    /// A credential was presented against the wrong environment or the wrong
    /// plane. Renders 403, naming the expected and actual scope. The LOUD half of
    /// the two wrong-scope behaviors.
    WrongScope {
        /// The scope the credential is authorized for.
        expected: String,
        /// The scope the request targeted.
        actual: String,
        /// A human-readable summary.
        message: String,
    },
    /// The resource is not visible in the current scope: absent, deactivated,
    /// malformed identifier, or belonging to another scope, all identical. The
    /// uniform anti-oracle half. Renders 404.
    NotFound,
    /// A named resource already exists (for example a DCR policy name reused within
    /// an environment, issue #31). Distinct from the anti-oracle not-found because a
    /// name collision is a legitimate signal the operator asked to create by name.
    /// Renders 409.
    Conflict(String),
    /// An Idempotency-Key was replayed with a DIFFERENT request. Renders 422.
    IdempotencyKeyConflict,
    /// A well-formed request whose value is semantically rejected by a policy the
    /// request itself cannot satisfy (issue #93): the compatibility wizard rejecting an
    /// algorithm the environment cannot actually sign with, so the column is left
    /// unchanged. Distinct from a plain bad request (a malformed or out-of-set value is
    /// a 400): the value parses and is in the wizard set, but the target environment
    /// cannot honor it. Renders 422.
    Unprocessable(String),
    /// A config write failed one or more typed environment guardrails (issue #42):
    /// for example creating a production environment with no custom domain. Renders
    /// 422 with the stable code of every failed guardrail. Distinct from a plain
    /// bad request because the request is well-formed but violates the environment's
    /// enforced guardrail class.
    GuardrailViolation(Vec<GuardrailViolation>),
    /// Admin sudo mode is on and this mutation needs a RECENT re-authentication that
    /// the acting credential does not have (issue #73): the recorded elevation is
    /// absent or its freshness window has lapsed. Renders a 401 RFC 9470
    /// `insufficient_user_authentication` challenge, carrying the required `max_age`
    /// both in the JSON body and in the `WWW-Authenticate` header, and executes NOTHING.
    /// The elevation derives from a server-recorded re-auth event, never from a
    /// client-supplied header, so a stolen credential alone cannot clear this challenge.
    ReauthRequired {
        /// The maximum authentication age, in seconds, the mutation requires.
        max_age: u64,
    },
    /// An unexpected internal failure. Renders 500; never leaks detail.
    Internal,
}

impl ApiError {
    /// The HTTP status this error renders to.
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            // A missing credential and the RFC 9470 step-up challenge are both 401 (the
            // challenge carries its requirement in the WWW-Authenticate header and body).
            ApiError::Unauthorized(_) | ApiError::ReauthRequired { .. } => StatusCode::UNAUTHORIZED,
            ApiError::WrongScope { .. } => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::IdempotencyKeyConflict
            | ApiError::GuardrailViolation(_)
            | ApiError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The structured body this error renders to.
    fn body(&self) -> ErrorBody {
        match self {
            ApiError::BadRequest(message) => ErrorBody {
                error: "bad_request".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::Unauthorized(message) => ErrorBody {
                error: "unauthorized".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::WrongScope {
                expected,
                actual,
                message,
            } => ErrorBody {
                error: "wrong_scope".to_owned(),
                message: message.clone(),
                expected_scope: Some(expected.clone()),
                actual_scope: Some(actual.clone()),
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::NotFound => ErrorBody {
                error: "not_found".to_owned(),
                message: "resource not found".to_owned(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::Conflict(message) => ErrorBody {
                error: "conflict".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::IdempotencyKeyConflict => ErrorBody {
                error: "idempotency_key_conflict".to_owned(),
                message: "the Idempotency-Key was reused with a different request".to_owned(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::GuardrailViolation(violations) => ErrorBody {
                error: "guardrail_violation".to_owned(),
                message: guardrail_message(violations),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: Some(violations.iter().map(|v| v.code().to_owned()).collect()),
                max_age: None,
            },
            ApiError::Unprocessable(message) => ErrorBody {
                error: "unprocessable_entity".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::ReauthRequired { max_age } => ErrorBody {
                error: "insufficient_user_authentication".to_owned(),
                message: "a fresh re-authentication is required for this operation".to_owned(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: Some(*max_age),
            },
            ApiError::Internal => ErrorBody {
                error: "internal".to_owned(),
                message: "internal server error".to_owned(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
        }
    }
}

/// A single-line summary of the failed guardrails, listing each one's message so
/// an operator reading only the message learns every failure.
fn guardrail_message(violations: &[GuardrailViolation]) -> String {
    if violations.is_empty() {
        return "the environment guardrails were violated".to_owned();
    }
    let joined = violations
        .iter()
        .map(GuardrailViolation::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    format!("the environment guardrails were violated: {joined}")
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = serde_json::to_string(&self.body()).unwrap_or_else(|_| {
            "{\"error\":\"internal\",\"message\":\"internal server error\"}".to_owned()
        });
        let mut response = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        if matches!(self, ApiError::Unauthorized(_)) {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        // RFC 9470: a sudo-mode challenge carries the structured requirement in the
        // WWW-Authenticate header (the `insufficient_user_authentication` error and the
        // `max_age` the mutation requires), mirroring the step-up (issue #72) contract.
        if let ApiError::ReauthRequired { max_age } = self {
            let challenge = format!(
                "Bearer error=\"insufficient_user_authentication\", \
                 error_description=\"a fresh re-authentication is required for this operation\", \
                 max_age={max_age}"
            );
            if let Ok(value) = header::HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
        }
        response
    }
}

impl From<crate::provision::ProvisionError> for ApiError {
    fn from(error: crate::provision::ProvisionError) -> Self {
        // Day-one signing-key generation failing is an internal fault (a healthy RNG
        // never fails ES256/RS256 keygen); the detail is logged, never returned.
        tracing::error!(error = %error, "day-one signing key generation failed");
        ApiError::Internal
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            // The uniform not-found is preserved across the boundary.
            StoreError::NotFound => ApiError::NotFound,
            // An invalid invitation org-context (issue #94) is a caller-facing bad
            // request (the admin layer validates it richly up front; this is the
            // store's defense-in-depth guard surfacing).
            StoreError::InvalidOrgContext => {
                ApiError::BadRequest("org_context is not a valid organization id".to_owned())
            }
            // A group create or reparent the organization's hierarchy cannot honor
            // (issue #97). 422 rather than 400 (the value is well formed and names
            // a group the caller can see) and rather than 409 (this is a
            // structural refusal, not a uniqueness collision), matching the
            // config-promotion unresolved-reference precedent.
            //
            // These arms are here, in the ONE central conversion, and not only at
            // the handler call sites: the wildcard below turns any unmapped
            // variant into an opaque 500, so a handler that forgets its explicit
            // arm degrades to the correct 422 instead of a server error on every
            // route. Neither message names a group id, so neither can report
            // anything the caller did not already send.
            StoreError::OrgGroupCycle => ApiError::Unprocessable(
                "the requested parent would create a cycle in the group hierarchy".to_owned(),
            ),
            // "AT LEAST" is exact, not hedging. Both recursive walks stop one level
            // past the bound, so the depth they report SATURATES: against an
            // already-over-deep hierarchy the number here is a FLOOR on the depth the
            // write would have produced, never necessarily the depth itself. Wording
            // it as an exact value would have an operator resolve a request that is
            // "3 levels" over by raising the bound by 3 and watch it be refused
            // again.
            StoreError::OrgGroupDepthExceeded { max, attempted } => {
                ApiError::Unprocessable(format!(
                    "the requested parent would nest groups at least {attempted} levels deep, \
                     exceeding the configured maximum of {max}"
                ))
            }
            // A per-organization authentication policy document the store refused
            // (issue #95). 422 for the same reason as the group refusals above: the
            // values are well formed and in set, and this is a structural refusal of
            // a document rather than a uniqueness collision.
            //
            // This arm lands AHEAD of issue #95's admin routes, exactly as the two
            // group arms above landed ahead of theirs. It adds no type, no route, and
            // no schema, so the served management spec cannot drift; and omitting it
            // would NOT be neutral, because the wildcard below would turn this
            // variant into an opaque 500 on every route that can produce it, with
            // nothing failing to say so.
            //
            // Every carried refusal is value free by construction (each names a
            // DIMENSION, never the offending value), so rendering them all is safe
            // and is what makes the response actionable in one round trip. The list
            // is already sorted and deduplicated by the store's validator, so the
            // message is a deterministic function of the submitted document.
            StoreError::OrgAuthPolicyInvalid(ref errors) => {
                let dimensions: Vec<&str> = errors.iter().map(|failure| failure.as_str()).collect();
                ApiError::Unprocessable(format!(
                    "the organization authentication policy is invalid: {}",
                    dimensions.join("; ")
                ))
            }
            // Anything else (a database fault, or an idempotency conflict that
            // did not funnel through the re-read path) is an opaque internal
            // error; the detail is logged, never returned. `StoreError` is
            // non-exhaustive, so a wildcard keeps this total.
            other => {
                tracing::error!(error = %other, "management store error");
                ApiError::Internal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiError, StatusCode};
    use crate::state::AdminState;
    use ironauth_store::{AuthPolicyError, StoreError};

    #[test]
    fn the_group_hierarchy_refusals_render_as_unprocessable_and_never_as_internal() {
        // `impl From<StoreError> for ApiError` wildcards every unmapped variant to an
        // opaque 500 with a tracing error. A new typed refusal that is added to the
        // store but not mapped here is therefore a SILENT 500 on every route that can
        // produce it, with nothing failing to say so. These two assertions are what
        // make the issue #97 refusals a caller-facing 422 rather than that.
        let cycle: ApiError = StoreError::OrgGroupCycle.into();
        assert_eq!(cycle.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            matches!(&cycle, ApiError::Unprocessable(message) if message.contains("cycle")),
            "the cycle refusal must render a caller-facing message: {cycle:?}"
        );

        let depth: ApiError = StoreError::OrgGroupDepthExceeded {
            max: 8,
            attempted: 11,
        }
        .into();
        assert_eq!(depth.status(), StatusCode::UNPROCESSABLE_ENTITY);
        // The configured bound and the attempted depth ride the message, so an
        // operator learns both the limit and how far past it the request went with no
        // new field on the stable error body.
        assert!(
            matches!(
                &depth,
                ApiError::Unprocessable(message)
                    if message.contains("11") && message.contains('8')
            ),
            "the depth refusal must report both the attempted depth and the bound: {depth:?}"
        );
    }

    #[test]
    fn the_org_auth_policy_refusal_renders_as_unprocessable_and_names_every_dimension() {
        // The same guard as the group refusals above, for issue #95: an unmapped
        // variant is a SILENT 500 on every route that can produce it. This arm and
        // this test are what make the policy refusal a caller-facing 422 instead.
        let refusal: ApiError = StoreError::OrgAuthPolicyInvalid(vec![
            AuthPolicyError::UnknownFactor,
            AuthPolicyError::MfaRequiredWithNoSecondFactor,
        ])
        .into();
        assert_eq!(refusal.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let ApiError::Unprocessable(ref message) = refusal else {
            panic!("the policy refusal must render as unprocessable: {refusal:?}");
        };
        // EVERY carried failure reaches the caller, so an operator fixes all of them
        // in one round trip rather than discovering them one write at a time.
        assert!(
            message.contains("allowed_factors") && message.contains("mfa_required"),
            "the refusal must name every failed dimension: {message}"
        );
        // And nothing that was not sent: each variant is value free, so no submitted
        // factor token or email domain can appear in the response.
        assert!(
            !message.contains("email_otp") && !message.contains('@'),
            "a refusal must never echo a submitted value: {message}"
        );

        // An empty list is not reachable from the validator (it returns Ok when
        // nothing failed), but the arm must stay total and must never become a 500.
        let empty: ApiError = StoreError::OrgAuthPolicyInvalid(Vec::new()).into();
        assert_eq!(empty.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn the_config_and_store_session_ttl_ceilings_agree() {
        // The store clamps a submitted policy lifetime against its OWN mirror of the
        // ceiling, because `ironauth-store` deliberately has no dependency on the
        // config crate. If the two drifted, an operator could state a policy lifetime
        // the deployment itself refuses to load, or the store could reject one the
        // deployment would have accepted. This crate is the only one that can see
        // both, so the agreement is pinned here, exactly as the group depth ceiling
        // is below.
        assert_eq!(
            u64::from(ironauth_store::ORG_POLICY_MAX_SESSION_TTL_SECS),
            ironauth_config::OIDC_MAX_SESSION_TTL_SECS
        );
        // And the shipped defaults land within it, so a deployment that never touches
        // the setting can state any policy lifetime the store will accept.
        let shipped = ironauth_config::Config::from_toml_str("", "<inline>")
            .expect("the shipped defaults must load")
            .config;
        assert!(
            shipped.oidc.session_ttl_secs <= ironauth_config::OIDC_MAX_SESSION_TTL_SECS,
            "the shipped default session lifetime must be within the ceiling"
        );
    }

    #[test]
    fn the_config_and_store_group_depth_ceilings_agree() {
        // The store clamps its `max_group_depth` parameter to its OWN mirror of the
        // ceiling, because `ironauth-store` deliberately has no dependency on the
        // config crate. If the two drifted apart, config load would accept a depth the
        // store then silently clamped, and the operator-visible setting would stop
        // meaning what it says. This crate is the only one that can see both, so the
        // agreement is pinned here (the same arrangement as the list hard cap, which
        // is pinned in the pagination module that consumes it).
        assert_eq!(
            ironauth_config::ORGANIZATIONS_MAX_GROUP_DEPTH_CEILING,
            ironauth_store::ORG_GROUP_MAX_DEPTH_CEILING
        );
        // And an EMPTY config file (the shipped defaults) both loads and lands within
        // the ceiling, so a deployment that never touches the setting boots and its
        // effective bound is the one the store will honor unclamped.
        let shipped = ironauth_config::Config::from_toml_str("", "<inline>")
            .expect("the shipped defaults must load")
            .config;
        assert_eq!(
            shipped.organizations.max_group_depth,
            ironauth_config::ORGANIZATIONS_DEFAULT_MAX_GROUP_DEPTH
        );
        assert!(
            shipped.organizations.max_group_depth <= ironauth_store::ORG_GROUP_MAX_DEPTH_CEILING,
            "the shipped default must not be clamped by the store"
        );
    }

    #[test]
    fn the_id_token_bloat_signal_and_the_access_token_budget_warn_at_the_same_number() {
        // The access-token budget's shipped approach threshold (issue #98) is
        // deliberately the SAME number as the shipped ID-token growth signal, so an
        // operator meets ONE number across both token kinds rather than two that mean
        // "this token is getting big" and can silently disagree. That parity is
        // asserted in four places in prose (the two constants' doc comments, the
        // config CHANGELOG, and the design) and, before this assertion, was enforced
        // by nothing: moving either number alone left both crates green.
        //
        // `ironauth-config` cannot hold this, because it depends on no other IronAuth
        // crate and so cannot name the OIDC constant at all. `ironauth-oidc` could
        // (it does depend on `ironauth-config`), but it lands here instead so that
        // every cross-crate constant agreement sits in ONE place: this module already
        // holds the session TTL and group depth ceiling agreements above, and a
        // reviewer auditing them finds this one without knowing to look elsewhere.
        assert_eq!(
            u32::try_from(ironauth_oidc::ID_TOKEN_BLOAT_THRESHOLD_BYTES)
                .expect("the ID-token growth signal threshold fits a u32"),
            ironauth_config::TOKEN_CLAIMS_DEFAULT_ACCESS_TOKEN_WARN_BYTES,
            "the ID-token growth signal and the access-token budget's approach \
             threshold must stay EQUAL: they are one operator-facing number, and \
             moving one alone gives the same idea two values that disagree"
        );
        // And the shared number really is the one a default deployment runs, rather
        // than a constant the shipped section overrides: an EMPTY config file loads
        // and its threshold is that same number.
        let shipped = ironauth_config::Config::from_toml_str("", "<inline>")
            .expect("the shipped defaults must load")
            .config;
        assert_eq!(
            usize::try_from(shipped.token_claims.access_token_warn_bytes)
                .expect("a byte threshold fits a usize"),
            ironauth_oidc::ID_TOKEN_BLOAT_THRESHOLD_BYTES,
            "a default deployment must warn on both token kinds at the same size"
        );
    }

    /// A store over a LAZY pool: parses the URL but never connects, so the two token
    /// claim budget tests below stay database-free (neither touches the store).
    fn lazy_store() -> ironauth_store::Store {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://ironauth@localhost/ironauth")
            .expect("lazy pool parses the URL");
        ironauth_store::Store::from_pool(pool)
    }

    /// A database-free [`OidcState`] carrying nothing but its defaults, so a builder
    /// installed on it is the only thing under test.
    fn oidc_state() -> ironauth_oidc::OidcState {
        let registry = std::sync::Arc::new(ironauth_oidc::IssuerRegistry::new(
            "https://auth.example.test",
            ironauth_oidc::JwksCacheWindow::clamped(300),
        ));
        ironauth_oidc::OidcState::new(
            lazy_store(),
            ironauth_env::Env::system(),
            registry,
            &ironauth_config::OidcConfig::default(),
            "https://auth.example.test",
        )
    }

    #[tokio::test]
    async fn the_token_claims_budget_is_clamped_to_the_same_ceilings_on_both_planes() {
        // The token claim budget (issue #98) lives in ONE top-level `[token_claims]`
        // section and is installed on BOTH planes: the mint enforces it and the
        // management API reports the approach warning against it. If the two planes
        // disagreed about what the budget is, one operator-visible number would mean
        // two things. This crate is the only one that can see both state builders, so
        // the agreement is pinned here, exactly as the group depth ceiling is above.
        //
        // The section fed in is one config load would have REFUSED outright, because
        // that is precisely the case the builders' re-clamp exists for: a state can
        // also be built directly from a hand-constructed section (every test harness
        // does that), and a budget that quietly exceeded its ceiling there would be a
        // bound that is not a bound.
        let over_ceiling = ironauth_config::TokenClaimsConfig {
            access_token_max_bytes: ironauth_config::TOKEN_CLAIMS_ACCESS_TOKEN_MAX_BYTES_CEILING
                + 10_000,
            access_token_warn_bytes: u32::MAX,
            permission_claim_max_count:
                ironauth_config::TOKEN_CLAIMS_PERMISSION_CLAIM_MAX_COUNT_CEILING + 10_000,
            permission_claim_warn_count: u32::MAX,
            permission_claim_overflow: ironauth_config::PermissionOverflow::PdpRequired,
        };
        // The section really is outside the bounds, so the assertions below are about a
        // clamp that fired rather than a value that was already inside.
        assert!(
            over_ceiling.access_token_max_bytes
                > ironauth_config::TOKEN_CLAIMS_ACCESS_TOKEN_MAX_BYTES_CEILING
                && over_ceiling.permission_claim_max_count
                    > ironauth_config::TOKEN_CLAIMS_PERMISSION_CLAIM_MAX_COUNT_CEILING,
            "the fixture must be over both ceilings or the clamp is untested"
        );

        let data_plane = oidc_state().with_token_claims(&over_ceiling);
        let management_plane = AdminState::new(
            lazy_store(),
            ironauth_env::Env::system(),
            &ironauth_config::AdminConfig::default(),
        )
        .expect("an AdminState with no bootstrap token builds")
        .with_token_claims(&over_ceiling);

        for (plane, budget) in [
            ("data", data_plane.token_claims()),
            ("management", management_plane.token_claims()),
        ] {
            assert_eq!(
                budget.access_token_max_bytes,
                ironauth_config::TOKEN_CLAIMS_ACCESS_TOKEN_MAX_BYTES_CEILING,
                "the {plane} plane must clamp the token budget to the ceiling"
            );
            assert_eq!(
                budget.permission_claim_max_count,
                ironauth_config::TOKEN_CLAIMS_PERMISSION_CLAIM_MAX_COUNT_CEILING,
                "the {plane} plane must clamp the claim element budget to the ceiling"
            );
            // Each approach threshold lands on the CLAMPED maximum, never above it, so
            // no plane is left with a threshold that could not fire.
            assert_eq!(
                budget.access_token_warn_bytes,
                ironauth_config::TOKEN_CLAIMS_ACCESS_TOKEN_MAX_BYTES_CEILING,
                "the {plane} plane must clamp the byte threshold to the clamped maximum"
            );
            assert_eq!(
                budget.permission_claim_warn_count,
                ironauth_config::TOKEN_CLAIMS_PERMISSION_CLAIM_MAX_COUNT_CEILING,
                "the {plane} plane must clamp the count threshold to the clamped maximum"
            );
            // The overflow mode has no ceiling and is carried through untouched.
            assert_eq!(
                budget.permission_claim_overflow,
                ironauth_config::PermissionOverflow::PdpRequired,
                "the {plane} plane must carry the configured overflow mode"
            );
        }
        // And the two planes agree value for value, which is the property the single
        // top-level section exists to guarantee.
        assert_eq!(
            data_plane.token_claims().access_token_max_bytes,
            management_plane.token_claims().access_token_max_bytes
        );
        assert_eq!(
            data_plane.token_claims().access_token_warn_bytes,
            management_plane.token_claims().access_token_warn_bytes
        );
        assert_eq!(
            data_plane.token_claims().permission_claim_max_count,
            management_plane.token_claims().permission_claim_max_count
        );
        assert_eq!(
            data_plane.token_claims().permission_claim_warn_count,
            management_plane.token_claims().permission_claim_warn_count
        );
        assert_eq!(
            data_plane.token_claims().permission_claim_overflow,
            management_plane.token_claims().permission_claim_overflow
        );
    }

    #[tokio::test]
    async fn a_state_built_with_no_token_claims_budget_matches_a_default_deployment() {
        // A directly-built state must behave like a default deployment rather than
        // pinning every bound to zero, on BOTH planes: a zero budget would mean no
        // access token could ever carry a permission claim, which is the opposite of
        // the shipped posture and would make every harness silently untypical.
        let shipped = ironauth_config::Config::from_toml_str("", "<inline>")
            .expect("the shipped defaults must load")
            .config
            .token_claims;
        assert_eq!(
            shipped.access_token_max_bytes,
            ironauth_config::TOKEN_CLAIMS_DEFAULT_ACCESS_TOKEN_MAX_BYTES
        );
        assert_eq!(
            shipped.permission_claim_max_count,
            ironauth_config::TOKEN_CLAIMS_DEFAULT_PERMISSION_CLAIM_MAX_COUNT
        );
        // The shipped defaults land inside both ceilings, so a deployment that never
        // touches the section gets the bounds it reads rather than clamped ones.
        assert!(
            shipped.access_token_max_bytes
                <= ironauth_config::TOKEN_CLAIMS_ACCESS_TOKEN_MAX_BYTES_CEILING
                && shipped.permission_claim_max_count
                    <= ironauth_config::TOKEN_CLAIMS_PERMISSION_CLAIM_MAX_COUNT_CEILING,
            "the shipped defaults must not be clamped by either builder"
        );

        let data_plane = oidc_state();
        let management_plane = AdminState::new(
            lazy_store(),
            ironauth_env::Env::system(),
            &ironauth_config::AdminConfig::default(),
        )
        .expect("an AdminState with no bootstrap token builds");
        for (plane, budget) in [
            ("data", data_plane.token_claims()),
            ("management", management_plane.token_claims()),
        ] {
            assert_eq!(
                budget.access_token_max_bytes, shipped.access_token_max_bytes,
                "an uninstalled {plane} plane must carry the shipped token budget"
            );
            assert_eq!(
                budget.access_token_warn_bytes, shipped.access_token_warn_bytes,
                "an uninstalled {plane} plane must carry the shipped byte threshold"
            );
            assert_eq!(
                budget.permission_claim_max_count, shipped.permission_claim_max_count,
                "an uninstalled {plane} plane must carry the shipped element budget"
            );
            assert_eq!(
                budget.permission_claim_warn_count, shipped.permission_claim_warn_count,
                "an uninstalled {plane} plane must carry the shipped count threshold"
            );
            assert_eq!(
                budget.permission_claim_overflow,
                ironauth_config::PermissionOverflow::RolesOnly,
                "an uninstalled {plane} plane must default to the roles-only overflow"
            );
        }
    }
}
