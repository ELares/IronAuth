// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minting the self-service admin portal's entry link (issue #140).
//!
//! # What a vendor gets, and why it is the only authority in the product
//!
//! A vendor's backend calls this once and hands the result to their customer's IT admin. The
//! admin follows it, configures SSO or SCIM or a domain for exactly one organization, and the
//! vendor does nothing further -- which is the whole point of the feature and the reason this
//! link is the only credential anybody outside the deployment ever holds. Every boundary the
//! portal has is therefore a property of the row this mints: the organization, the intent, the
//! expiry, and the fact that it works once.
//!
//! # The token is returned here and nowhere else, ever again
//!
//! The store keeps only a SHA-256 digest, so this response is the sole moment the bearer value
//! exists outside the caller's process. There is no "show me the link again" endpoint and there
//! cannot be one; a vendor that loses it mints another. That is the same posture the rest of this
//! crate takes with client secrets and API keys, and for the same reason.
//!
//! # The path is not served yet
//!
//! This slice mints the link and nothing redeems it: the portal session, the GET that renders a
//! confirmation and the POST that consumes the row all land in the next slice of #140. A vendor
//! calling this today gets a real, single-use, expiring row and a path that answers 404. That is
//! recorded in the published contract and on the field itself rather than left to be found,
//! because the failure lands on somebody else's IT admin rather than on the caller.
//!
//! # Why the response carries a PATH and not an absolute URL
//!
//! The management API does not reliably know the origin an end user reaches this deployment on.
//! A deployment may sit behind a vendor's own domain, or several; the issuer registry knows an
//! issuer base for the DATA plane, which is not necessarily where a human's browser goes. So
//! this returns the path and the vendor joins it to the origin they publish. Inventing an origin
//! here would produce a link that looks right and lands nowhere, and it would do so in the one
//! artifact the customer sees first.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{CorrelationId, NewPortalLink, PortalLinkId, StoreError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::resolve_scope;
use crate::response::json;
use crate::state::AdminState;

/// The intents a link may carry.
///
/// THE SAME CLOSED SET THE COLUMN'S CHECK PINS, restated here so a typo is a 400 naming the
/// field rather than a 500 from a constraint violation. The database remains the authority --
/// this list existing does not make it safe to widen one side alone.
const INTENTS: [&str; 4] = ["sso", "scim", "domain-verification", "log-streams"];

/// The default life of a link, in seconds.
///
/// FIVE MINUTES, which is what #140 asks for. It is short because the link is handed over out of
/// band -- pasted into a ticket, an email, a chat -- and every one of those places keeps a copy;
/// a link that has expired by the time anybody reads the copy is the point.
const DEFAULT_TTL_SECS: i64 = 300;

/// The longest life a caller may ask for, in seconds.
///
/// AN HOUR. A vendor sending an invitation their customer opens tomorrow wants something longer
/// than five minutes, and refusing them entirely would push them to mint links on a schedule
/// nobody watches. An hour is long enough for a human to act on a message and short enough that
/// a leaked ticket is not an open door for a working day.
const MAX_TTL_SECS: i64 = 3600;

/// The default TTL must be a value the handler would accept.
///
/// A COMPILE-TIME ASSERTION rather than a test, which is both stronger and the reason clippy
/// objected to the test it replaced: the operands are constants, so the check has an answer
/// before anything runs and a test that asserts it can only ever be decoration. A default
/// outside the accepted range would refuse every request that OMITTED `ttl_seconds`, which is
/// the common case and precisely the one an integration test that always sends the field
/// would never reach. Here it fails the build instead.
const _: () = assert!(
    DEFAULT_TTL_SECS > 0 && DEFAULT_TTL_SECS <= MAX_TTL_SECS,
    "the default portal-link TTL is outside the range the handler accepts, so every request \
     that omits ttl_seconds would be refused"
);

/// A portal link to mint.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePortalLinkRequest {
    /// The `org_` organization the resulting portal session may configure. The session can see
    /// no other organization's state.
    pub organization_id: String,
    /// What the session may configure: `sso`, `scim`, `domain-verification`, or `log-streams`.
    /// A session cannot navigate outside the intent it was opened with.
    pub intent: String,
    /// How long the link stays redeemable, in seconds. Defaults to five minutes; an hour is the
    /// maximum.
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

/// A freshly minted portal link.
#[derive(Debug, Serialize, ToSchema)]
pub struct PortalLinkView {
    /// The `plk_` handle. Not secret: it appears in audit rows and logs, and holding it grants
    /// nothing without the token.
    pub id: String,
    /// The path to hand the IT admin, token included, joined to whatever origin the vendor
    /// publishes for this deployment.
    ///
    /// NOT YET SERVED. The redeeming route lands in the next slice of #140; until it does,
    /// following this path reaches a 404. It is stated here rather than left to be discovered
    /// because the alternative is a vendor emailing a customer's IT admin a link that looks
    /// correct and goes nowhere, which is the one artifact that customer sees first.
    ///
    /// RETURNED ONCE. The store keeps only a digest, so this response is the only place the
    /// token ever exists outside the caller.
    pub url_path: String,
    /// The organization the session will be bound to.
    pub organization_id: String,
    /// The intent the session will be bound to.
    pub intent: String,
    /// When the link stops being redeemable, in milliseconds since the epoch.
    pub expires_at_unix_ms: i64,
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/portal-links",
    operation_id = "createPortalLink",
    tag = "connectors",
    request_body = CreatePortalLinkRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The minted link; the token appears here and nowhere else. The returned url_path is not served until the portal session slice of issue #140 lands", body = PortalLinkView),
        (status = 400, description = "An unknown intent or an out-of-range TTL", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment or the organization is not a live row of this scope, or the organization id is malformed or unreadable in this scope", body = ErrorBody)
    )
)]
/// `POST /v1/tenants/{tenant_id}/environments/{environment_id}/portal-links`: mint a link.
///
/// # Errors
///
/// [`ApiError::BadRequest`] for an unknown intent or an out-of-range TTL;
/// [`ApiError::NotFound`] when the environment or the organization is not a live row of this
/// scope, which is also the answer for an organization id this scope cannot parse -- the
/// uniform not-found is what stops a caller enumerating which organizations exist here;
/// [`ApiError::Internal`] on a persistence fault.
pub async fn create_portal_link(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`. Minting a
    // link hands CONFIGURATION authority for one organization to somebody outside this
    // deployment, so it is a grant rather than a lookup.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // THE ENVIRONMENT IS ANSWERED BEFORE THE BODY IS READ, and this order is the whole point
    // rather than a tidiness preference. `resolve_live_org` below checks environment liveness
    // too -- but it cannot run until the body has been parsed, because the organization it
    // fences is a body field. So without this line the first refusal a decommissioned
    // environment could produce was a 400 about the body, and the crate's invariant "a
    // soft-deleted environment refuses every write" was true only of well formed requests.
    //
    // That is not a hypothetical: `live_surface.rs` drives a malformed body at a soft-deleted
    // environment against every environment-scoped write for exactly this reason, and it is
    // what caught this one.
    crate::org_context::require_live_environment(&state, &scope).await?;
    let request: CreatePortalLinkRequest = parse_json(&body)?;

    if !INTENTS.contains(&request.intent.as_str()) {
        return Err(ApiError::BadRequest(
            "intent must be one of sso, scim, domain-verification, log-streams".to_owned(),
        ));
    }
    let ttl = request.ttl_seconds.unwrap_or(DEFAULT_TTL_SECS);
    if ttl <= 0 || ttl > MAX_TTL_SECS {
        return Err(ApiError::BadRequest(
            "ttl_seconds must be between 1 and 3600".to_owned(),
        ));
    }
    // `resolve_live_org` RATHER THAN A BARE PARSE, and the first version of this line was the
    // bare parse. It looked sufficient because the id embeds its scope, so a foreign
    // organization's id fails to parse here -- but scope is (tenant, environment) and says
    // nothing about WHICH organization inside that environment a credential may act for. This
    // is the crate's ONE fence for that question, and it answers three at once:
    //
    //   * DELEGATED CONFINEMENT. `require_organization` is what stops a management credential
    //     confined to organization A minting a link that hands configuration authority over
    //     organization B to a third party. Without it a confined key escalated across the
    //     organizations it was confined away from, and the audit row recorded the grant as its
    //     own. Every other organization-addressed route reaches this; carrying the organization
    //     in the BODY rather than the path is what routed around it.
    //   * A LIVE ENVIRONMENT. A write must not land rows inside something an operator believes
    //     is decommissioned.
    //   * A LIVE ORGANIZATION. A link for a soft-deleted organization would mint an authority
    //     over something already gone.
    //
    // All three answer the uniform not-found, so a caller cannot tell "absent" from "not
    // yours" -- which is the property that stops this endpoint confirming which organization
    // ids are live in an environment a confined credential can otherwise reach.
    let organization_id = crate::org_context::resolve_live_org(
        &state,
        &principal,
        scope,
        &request.organization_id,
        crate::org_context::EnvironmentAccess::Write,
    )
    .await?;

    // THE TOKEN IS MINTED FROM THE ENTROPY SEAM, like every other unguessable value in this
    // workspace, and base64url so it survives a URL without escaping.
    let mut token_bytes = [0_u8; 32];
    state.env().entropy().fill_bytes(&mut token_bytes);
    let token = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
    };
    let digest = {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(token.as_bytes()).to_vec()
    };

    let id = PortalLinkId::generate(state.env(), &scope);
    let created_at_micros = state.now_unix_micros();
    let expires_at_micros = created_at_micros + ttl * 1_000_000;

    // THE EVENT IS BUILT BEFORE THE WRITE and handed to it, so the announcement and the row
    // land in one transaction. A link that exists and was never announced is the state no
    // integrator can detect: the authority is live, somebody outside the deployment holds it,
    // and the redemption happens in a browser the management API never sees.
    let event = created_event(
        &state,
        scope,
        &id,
        &organization_id,
        &request.intent,
        expires_at_micros,
    );
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // ATTRIBUTED TO THE ORGANIZATION, which is a different column from the audit detail
        // this write already carries. `audit_log.organization_id` is what a per-organization
        // log stream selects on, and this is the write that hands somebody outside the
        // deployment configuration authority over that organization -- the single row its
        // own operator most needs to see on their own stream.
        .in_organization(organization_id)
        .portal_links()
        .mint_with_event(
            state.env(),
            NewPortalLink {
                id: &id,
                organization_id: &organization_id,
                intent: &request.intent,
                token_digest: &digest,
            },
            created_at_micros,
            expires_at_micros,
            event
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;
    match result {
        Ok(()) => {}
        // THE ORGANIZATION DID NOT EXIST HERE. Checked in the insert statement rather than by a
        // read beforehand, so a concurrent delete cannot slip between the two.
        Err(StoreError::NotFound) => {
            // THE UNIFORM NOT-FOUND, which is what this crate answers for a malformed id, an
            // absent row and a foreign scope alike -- so a caller cannot enumerate which
            // organizations exist in an environment they can otherwise reach.
            return Err(ApiError::NotFound);
        }
        Err(_) => return Err(ApiError::Internal),
    }

    let view = PortalLinkView {
        id: id.to_string(),
        url_path: format!(
            "/t/{}/e/{}/portal/{id}?t={token}",
            scope.tenant(),
            scope.environment()
        ),
        organization_id: organization_id.to_string(),
        intent: request.intent,
        expires_at_unix_ms: expires_at_micros / 1000,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::CREATED, body))
}

/// The `portal_link.created` envelope.
///
/// RETURNS `None` WHEN THE ENVELOPE CANNOT BE BUILT, and it is worth being exact about when
/// that is, because the first version of this comment was not. `event_catalog::envelope` never
/// looks at the payload: it answers `None` only when the event TYPE is unregistered. A payload
/// that does not match the registered schema is built happily here, committed with the row,
/// and refused later by the fan-out -- so a schema mismatch is not a dropped event, it is an
/// event permanently stuck in the outbox.
///
/// That is why `the_minted_envelope_satisfies_its_registered_schema` exists beside this: the
/// only place the payload and the schema are ever compared is a test, so it has to be one.
fn created_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &PortalLinkId,
    organization_id: &ironauth_store::OrganizationId,
    intent: &str,
    expires_at_micros: i64,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "portal_link.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &created_payload(
            &subject,
            &organization_id.to_string(),
            intent,
            expires_at_micros,
        ),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}

/// The `portal_link.created` payload.
///
/// SEPARATED FROM THE BUILDER SO A TEST CAN REACH IT. Nothing in the running system compares
/// this object to its registered schema: `envelope` does not look at a payload, and the
/// fan-out that does look sees it only after the row is committed. A mismatch is therefore not
/// a dropped event but a stuck one, discovered by an integrator rather than by us, and the
/// only place the two can be compared before that is a test. A payload built inline inside a
/// function that needs an `AdminState` is not reachable from one.
fn created_payload(
    portal_link_id: &str,
    organization_id: &str,
    intent: &str,
    expires_at_micros: i64,
) -> serde_json::Value {
    serde_json::json!({
        "portal_link_id": portal_link_id,
        "organization_id": organization_id,
        "intent": intent,
        // MILLISECONDS, matching the field this endpoint returns to the caller. A receiver
        // correlating the event with the response body compares two numbers, not two units.
        "expires_at_unix_ms": expires_at_micros / 1000,
    })
}

#[cfg(test)]
mod tests {
    use super::{INTENTS, created_payload};

    /// The envelope this producer mints satisfies the schema the fan-out enforces.
    ///
    /// THE ONLY PLACE THE TWO ARE EVER COMPARED. `event_catalog::envelope` answers `None` for
    /// an unregistered TYPE and nothing else -- it never reads the payload -- so a payload that
    /// does not match its registered schema is built, committed in the same transaction as the
    /// portal link, and then refused by the fan-out forever. The link is live, the vendor holds
    /// the token, and the event that announces it sits in the outbox. Nothing in the running
    /// system can detect that, which is why it has to be detected here.
    ///
    /// It drives every intent, and the honest reason is weaker than the one first written
    /// here: the registered schema constrains `intent` only to a non-empty string, so the loop
    /// cannot pass for one intent and fail for another and would be satisfied by a value the
    /// column's own CHECK refuses. What the loop buys is that a future schema which DOES
    /// constrain the intent -- an enum, a pattern -- is measured against every value this
    /// handler can actually send, rather than against whichever one a single-case test froze.
    /// It is not a pin on the intent set; `an_unknown_intent_can_never_be_written` in the
    /// store suite is that.
    #[test]
    fn the_minted_envelope_satisfies_its_registered_schema() {
        for intent in INTENTS {
            let payload = created_payload("plk_x", "org_x", intent, 1_700_000_000_000_000);
            let envelope = ironauth_store::event_catalog::envelope(
                "evt_x",
                "portal_link.created",
                "ten_x",
                "env_x",
                1_700_000_000_000,
                &payload,
            )
            .expect("portal_link.created is registered, so an envelope is built");
            ironauth_store::event_catalog::validate_event(&envelope).unwrap_or_else(|error| {
                panic!(
                    "the envelope this producer mints for intent {intent:?} is refused by the \
                     same validation the fan-out applies, so every link minted with it would \
                     be announced to nobody: {error:?}"
                )
            });
        }
    }
}
