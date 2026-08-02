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
use ironauth_store::{GuardrailViolation, StoreError, StoreErrorWire};
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
    /// Present only on an identity-traits validation refusal (issue #53): one entry per
    /// FAILING FIELD, each carrying an RFC 6901 JSON Pointer to the exact location in
    /// the submitted document and a stable reason.
    ///
    /// It is a LIST and not a flattened string on purpose. A trait document fails field
    /// by field, and a form that renders the failures has to attach each one to its own
    /// input; a joined sentence forces every consumer to re-parse what the validator
    /// already knew. The `message` field still carries the joined summary, so a client
    /// that reads only that is not left with nothing.
    ///
    /// No entry ever echoes the offending VALUE (the validator's reasons name a
    /// dimension, never data), so a refusal carries no trait PII.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trait_errors: Option<Vec<TraitErrorView>>,
}

impl ErrorBody {
    /// The body every error shape starts from: the stable `error` code, the human message,
    /// and NO optional field set. Each variant that carries an extra sets exactly that one
    /// with functional-update syntax.
    ///
    /// This exists so that adding an optional field to [`ErrorBody`] touches ONE place
    /// rather than every arm of the render. It used to be every arm, and the arms
    /// re-spelled `expected_scope: None, actual_scope: None, failed_guardrails: None,
    /// max_age: None` ten times over: a shape where the ONLY thing keeping a new field
    /// off an unrelated error was ten identical hand edits.
    fn plain(error: &str, message: String) -> Self {
        Self {
            error: error.to_owned(),
            message,
            expected_scope: None,
            actual_scope: None,
            failed_guardrails: None,
            max_age: None,
            trait_errors: None,
        }
    }
}

/// One per-field identity-traits validation failure on the wire (issue #53).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TraitErrorView {
    /// An RFC 6901 JSON Pointer to the failing location in the submitted document (the
    /// empty string points at the document root).
    #[schema(example = "/address/zip")]
    pub pointer: String,
    /// A stable, operator-safe reason. Never echoes the offending value.
    #[schema(example = "expected type string")]
    pub message: String,
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
    /// A submitted identity-traits document failed the environment's ACTIVE trait
    /// schema (issue #53). Renders 422 with one `trait_errors` entry PER FAILING FIELD,
    /// each carrying an RFC 6901 JSON Pointer, and NOTHING is written.
    ///
    /// It is its own variant rather than an `Unprocessable(String)` because the central
    /// [`StoreError`] conversion renders through `Display`, which JOINS the failures
    /// into one sentence. That join is exactly the information a form needs and cannot
    /// reconstruct: which INPUT failed. Collapsing it would have made the structured
    /// per-field contract unreachable from the one place every route converts through.
    TraitsInvalid(Vec<ironauth_store::ValidationFailure>),
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
            | ApiError::TraitsInvalid(_)
            | ApiError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The structured body this error renders to.
    fn body(&self) -> ErrorBody {
        match self {
            ApiError::BadRequest(message) => ErrorBody::plain("bad_request", message.clone()),
            ApiError::Unauthorized(message) => ErrorBody::plain("unauthorized", message.clone()),
            ApiError::WrongScope {
                expected,
                actual,
                message,
            } => ErrorBody {
                expected_scope: Some(expected.clone()),
                actual_scope: Some(actual.clone()),
                ..ErrorBody::plain("wrong_scope", message.clone())
            },
            ApiError::NotFound => ErrorBody::plain("not_found", "resource not found".to_owned()),
            ApiError::Conflict(message) => ErrorBody::plain("conflict", message.clone()),
            ApiError::IdempotencyKeyConflict => ErrorBody::plain(
                "idempotency_key_conflict",
                "the Idempotency-Key was reused with a different request".to_owned(),
            ),
            ApiError::GuardrailViolation(violations) => ErrorBody {
                failed_guardrails: Some(violations.iter().map(|v| v.code().to_owned()).collect()),
                ..ErrorBody::plain("guardrail_violation", guardrail_message(violations))
            },
            ApiError::Unprocessable(message) => {
                ErrorBody::plain("unprocessable_entity", message.clone())
            }
            ApiError::TraitsInvalid(failures) => ErrorBody {
                trait_errors: Some(
                    failures
                        .iter()
                        .map(|failure| TraitErrorView {
                            pointer: failure.pointer.clone(),
                            message: failure.message.clone(),
                        })
                        .collect(),
                ),
                ..ErrorBody::plain("traits_invalid", traits_invalid_message(failures))
            },
            ApiError::ReauthRequired { max_age } => ErrorBody {
                max_age: Some(*max_age),
                ..ErrorBody::plain(
                    "insufficient_user_authentication",
                    "a fresh re-authentication is required for this operation".to_owned(),
                )
            },
            ApiError::Internal => ErrorBody::plain("internal", "internal server error".to_owned()),
        }
    }
}

/// A single-line summary of the per-field trait failures, so a caller reading only
/// `message` still learns every failure and its location. The structured
/// `trait_errors` list is what a form attaches to its inputs.
fn traits_invalid_message(failures: &[ironauth_store::ValidationFailure]) -> String {
    if failures.is_empty() {
        return "the traits document failed the active trait schema".to_owned();
    }
    let joined = failures
        .iter()
        .map(|failure| format!("{}: {}", failure.pointer, failure.message))
        .collect::<Vec<_>>()
        .join("; ");
    format!("the traits document failed the active trait schema: {joined}")
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
        // # There is no wildcard here, and that is the point
        //
        // This conversion used to map five variants explicitly and collapse the other
        // seventeen into `ApiError::Internal` with a `_ =>` arm. That arm was not a
        // safety net, it was a silencer: a typed refusal the store already knew how to
        // describe became an opaque 500 on every route that could produce it, and
        // nothing failed to say so. Three separate issues were filed for three
        // symptoms of it (#442, #449, #279) before the shape itself was addressed.
        //
        // FOURTEEN of those seventeen changed answer. The other three are `Database`,
        // `Migration`, and `Encryption`, which are genuine faults and still render 500
        // through the one arm that may.
        //
        // Exhaustiveness now runs in TWO links and neither can be skipped. `StoreError`
        // is `#[non_exhaustive]`, so this crate cannot match it exhaustively at all;
        // `StoreError::into_wire` can, because it lives in the crate that defines the
        // type, and IT carries no wildcard, so a new variant fails the build there
        // until its wire shape is decided. `StoreErrorWire` is not `#[non_exhaustive]`,
        // so the match below is exhaustive too, and a new CLASS fails the build HERE
        // until its status and body are decided.
        //
        // The old arm's stated defense was that "a handler that forgets its explicit
        // arm degrades to the correct 422 instead of a server error". That reasoning
        // is preserved and generalized rather than discarded: every caller-facing
        // class still has a central answer, so a handler that adds no arm of its own
        // still gets the right shape. What is gone is the SILENCE, which is the half
        // that was doing the damage.
        //
        // The message comes from the store's `Display`, which is exhaustive in that
        // crate and value free by construction on every caller-facing variant (each
        // arm names a DIMENSION or a structural fact, never an offending value or a
        // resource id), so nothing here can report anything the caller did not already
        // send. Reading it from there rather than restating it means the log line and
        // the caller's message cannot drift apart.
        // The ONE interception ahead of the wire conversion, and it exists for exactly
        // the reason the note above gives about silencers. `into_wire` maps this variant
        // to `Unprocessable`, whose body is the `Display` string: correct status, right
        // message, and the per-field list GONE. That is not a silenced error, it is a
        // silenced STRUCTURE, and the acceptance criterion is about the structure ("per
        // field JSON Pointer errors"). Lifting the failures out here keeps every route
        // that converts through this impl on the structured contract without any of them
        // having to carry an arm of its own.
        //
        // Nothing else may join it without the same argument: a variant whose typed
        // payload the wire class DISCARDS, and a caller that needs the payload.
        if let StoreError::TraitsInvalid(failures) = error {
            return ApiError::TraitsInvalid(failures);
        }
        let message = error.to_string();
        match error.into_wire() {
            // The uniform not-found is preserved across the boundary.
            StoreErrorWire::NotFound => ApiError::NotFound,
            // A collision inside a scope the caller has already proven it can address.
            // Every live route that can produce one carries its OWN arm with a
            // resource-specific message; this is the backstop for the ones that do
            // not, and answering it 409 rather than 500 is what stops a legitimate
            // name collision from reading as a server fault.
            StoreErrorWire::Conflict => ApiError::Conflict(message),
            // A concurrent request under the SAME Idempotency-Key won the insert race.
            // Reaching here means a create path skipped its replay, so it is logged at
            // WARN: the condition is genuinely retryable and the caller is told so,
            // but the missing replay stays visible rather than being absorbed.
            //
            // Deliberately NOT `IdempotencyKeyConflict`, which is a 422 meaning
            // something else entirely (the key was replayed with a DIFFERENT request).
            // Answering that here would tell the caller their request was malformed
            // when it was not.
            StoreErrorWire::IdempotencyRace => {
                tracing::warn!(
                    error = %message,
                    "a management create reached the central conversion with an \
                     Idempotency-Key race; its replay path did not run"
                );
                ApiError::Conflict(
                    "a concurrent request is already storing a result under this \
                     Idempotency-Key; retry"
                        .to_owned(),
                )
            }
            // A malformed submitted value. Decided from the submitted bytes alone,
            // without reading a row, so it can never be an existence probe.
            StoreErrorWire::BadRequest => ApiError::BadRequest(message),
            // A well-formed value a policy, schema, or structure refuses. 422 rather
            // than 400 (the value parses and is in set) and rather than 409 (nothing
            // collided; this is a structural refusal), matching the config-promotion
            // unresolved-reference precedent.
            StoreErrorWire::Unprocessable => ApiError::Unprocessable(message),
            // A typed environment-guardrail refusal, rendered with the stable code of
            // the failed guardrail so the caller learns which one. The management
            // plane already emits this shape from its own pre-check; routing the
            // store's refusal to the SAME shape means the two cannot answer the same
            // failure two different ways.
            StoreErrorWire::Guardrail(violation) => ApiError::GuardrailViolation(vec![violation]),
            // A genuine server fault; the detail is logged, never returned.
            StoreErrorWire::Internal => {
                tracing::error!(error = %message, "management store error");
                ApiError::Internal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiError, GuardrailViolation, StatusCode};
    use crate::state::AdminState;
    use ironauth_store::{AuthPolicyError, Guardrail, GuardrailClass, StoreError, StoreErrorWire};

    /// Every wire class, with the status it must render and a representative
    /// [`StoreError`] that carries it.
    ///
    /// The list is a hand-written one and could in principle shrink, but a class that
    /// went unlisted would not be a silent hole: adding a class to `StoreErrorWire`
    /// fails the BUILD of the conversion above, because that match is exhaustive and
    /// carries no wildcard. This is the belt to that brace, pinning the STATUS each
    /// class renders rather than merely that it renders something.
    /// A representative guardrail violation: the production `https` rule, which is the
    /// one an operator meets first.
    fn https_only_violation() -> GuardrailViolation {
        GuardrailViolation::new(
            Guardrail::HttpsOnlyRedirectUris,
            GuardrailClass::Production,
            "a production redirect uri must be https".to_owned(),
        )
    }

    fn class_expectations() -> Vec<(StoreErrorWire, StatusCode, StoreError)> {
        vec![
            (
                StoreErrorWire::NotFound,
                StatusCode::NOT_FOUND,
                StoreError::NotFound,
            ),
            (
                StoreErrorWire::Conflict,
                StatusCode::CONFLICT,
                StoreError::Conflict,
            ),
            (
                StoreErrorWire::IdempotencyRace,
                StatusCode::CONFLICT,
                StoreError::IdempotencyConflict,
            ),
            (
                StoreErrorWire::BadRequest,
                StatusCode::BAD_REQUEST,
                StoreError::InvalidOrgContext,
            ),
            (
                StoreErrorWire::Unprocessable,
                StatusCode::UNPROCESSABLE_ENTITY,
                StoreError::OrgGroupCycle,
            ),
            (
                StoreErrorWire::Guardrail(https_only_violation()),
                StatusCode::UNPROCESSABLE_ENTITY,
                StoreError::GuardrailViolation(https_only_violation()),
            ),
            (
                StoreErrorWire::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                StoreError::Encryption,
            ),
        ]
    }

    #[test]
    fn every_wire_class_renders_its_own_status_and_only_the_fault_class_renders_a_500() {
        // THE PROPERTY THE WILDCARD DESTROYED. The conversion used to map five variants
        // and collapse the other seventeen into an opaque 500, so a typed refusal the
        // store already knew how to describe reached the caller as a server fault.
        // Fourteen of the seventeen now answer typed; the three that stay 500 are the
        // faults, and the last clause below is what holds that line.
        //
        // What makes this assertion worth having, rather than a restatement of the
        // match, is the LAST clause: exactly one class may render a 500. A future edit
        // that quietly routes a caller-facing class back to `Internal` to make some
        // handler simpler fails here.
        for (class, expected_status, error) in class_expectations() {
            let rendered = ApiError::from(error);
            assert_eq!(
                rendered.status(),
                expected_status,
                "the {class:?} class must render {expected_status}: {rendered:?}"
            );
            assert_eq!(
                matches!(rendered, ApiError::Internal),
                class == StoreErrorWire::Internal,
                "only the fault class may render as an opaque internal error, and it \
                 must: {class:?} rendered {rendered:?}"
            );
        }
    }

    #[test]
    fn the_classification_agrees_with_what_the_conversion_is_handed() {
        // The two halves of the chain are in DIFFERENT crates, so nothing but this
        // checks that the representative error each expectation above carries really
        // does classify as the class it is filed under. Without it a mislabelled row
        // would silently assert the wrong thing while still passing.
        for (class, _status, error) in class_expectations() {
            let actual = error.into_wire();
            assert_eq!(
                actual, class,
                "the representative error for {class:?} must actually classify as it"
            );
        }
    }

    #[test]
    fn a_caller_facing_refusal_carries_the_store_s_own_message_and_no_submitted_value() {
        // The conversion reads its message from the store's `Display` rather than
        // restating it, so the log line and the caller's message cannot drift. That is
        // only safe because every caller-facing arm of that `Display` is value free by
        // construction, and this is where "value free" stops being a claim in a doc
        // comment.
        let rendered = ApiError::from(StoreError::OrgGroupDepthExceeded {
            max: 8,
            attempted: 11,
        });
        let ApiError::Unprocessable(ref message) = rendered else {
            panic!("the depth refusal must render as unprocessable: {rendered:?}");
        };
        assert!(
            message.contains("11") && message.contains('8'),
            "the refusal must report both the attempted depth and the bound: {message}"
        );

        let rendered = ApiError::from(StoreError::InvalidOrgContext);
        let ApiError::BadRequest(ref message) = rendered else {
            panic!("an invalid org context must render as a bad request: {rendered:?}");
        };
        assert_eq!(
            message, "org_context is not a valid organization id",
            "the wire message must be the one the management surface has always sent, \
             which is why the store's Display arm carries exactly this text"
        );
    }

    #[test]
    fn the_idempotency_race_is_a_retryable_conflict_and_not_the_unprocessable_replay_error() {
        // These two are easy to confuse and mean opposite things. `IdempotencyRace` is a
        // CONCURRENT request under the same key, which is retryable and is not the
        // caller's fault; `ApiError::IdempotencyKeyConflict` is a 422 meaning the key was
        // replayed with a DIFFERENT request, which IS. Answering the 422 for the race
        // would tell a caller their request was malformed when it was not.
        let rendered = ApiError::from(StoreError::IdempotencyConflict);
        assert_eq!(rendered.status(), StatusCode::CONFLICT);
        assert!(
            !matches!(rendered, ApiError::IdempotencyKeyConflict),
            "the race must not borrow the replay error's shape: {rendered:?}"
        );
        assert!(
            matches!(&rendered, ApiError::Conflict(message) if message.contains("retry")),
            "and it must tell the caller the condition is retryable: {rendered:?}"
        );
    }

    #[test]
    fn a_guardrail_refusal_from_the_store_renders_the_failed_guardrail_code() {
        // The management plane already emits `ApiError::GuardrailViolation` from its OWN
        // pre-check. Before this arm existed the store's refusal of the same condition
        // reached the wildcard instead, so one failure had two answers depending on
        // which layer caught it. The stable CODE is the part an integrator keys on, so
        // it is what is asserted.
        let rendered = ApiError::from(StoreError::GuardrailViolation(https_only_violation()));
        assert_eq!(rendered.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = rendered.body();
        assert_eq!(body.error, "guardrail_violation");
        assert_eq!(
            body.failed_guardrails,
            Some(vec!["https_only_redirect_uris".to_owned()]),
            "the refusal must name the failed guardrail by its stable code"
        );
    }

    #[test]
    fn the_group_hierarchy_refusals_render_as_unprocessable_and_never_as_internal() {
        // These two assertions predate the exhaustive conversion and are kept as they
        // were: they pin the WIRE SHAPE of the issue #97 refusals, which is a narrower
        // and more durable claim than how the conversion happens to reach it.
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
