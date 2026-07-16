// SPDX-License-Identifier: MIT OR Apache-2.0

//! The account-recovery request surface (`GET`/`POST /recover`, issue #64).
//!
//! Recovery is governed INDEPENDENTLY of the password path: it has its own
//! [`AuthPath::Recovery`](ironauth_store::AuthPath) counters and bans, so failed-password
//! spray against a victim can NEVER throttle or lock the owner's recovery path (the
//! account-DoS safeguard, Keycloak CVE-2024-1722). The POST is ANTI-ENUMERATION uniform:
//! whether the identifier resolves to an account or not, the response body, status code,
//! and work performed are identical. The only difference is invisible: a send to a KNOWN
//! recipient goes through the verification seam, a send to an UNKNOWN one is suppressed
//! (the Logto pattern), neither visible in the response.

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;

use crate::interaction::{self, parse_resume};
use crate::login::ResumeQuery;
use crate::pages;
use crate::state::OidcState;
use crate::verification::VerificationPurpose;

/// The posted recovery form.
#[derive(Deserialize)]
pub struct RecoverForm {
    /// The identifier to recover.
    pub identifier: Option<String>,
    /// The authorization URL to resume at after recovery (carries the scope).
    pub return_to: Option<String>,
}

/// `GET /recover`: render the recovery request form for a valid resume target.
pub async fn recover_get(
    State(state): State<OidcState>,
    Query(query): Query<ResumeQuery>,
) -> Response {
    match parse_resume(query.return_to.as_deref()) {
        Some(resume) => {
            let banner = state.environment_banner(&resume.scope).await;
            pages::secure_html(
                StatusCode::OK,
                pages::recover_page(
                    resume.hints.login_hint().unwrap_or_default(),
                    &resume.return_to,
                    None,
                    &resume.hints,
                    banner,
                ),
            )
        }
        None => interaction::invalid_link_page(),
    }
}

/// `POST /recover`: request account recovery. ALWAYS returns the SAME uniform
/// acknowledgment; a send to a known recipient goes out, a send to an unknown one is
/// suppressed, neither observable (issue #64).
pub async fn recover_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(form): Form<RecoverForm>,
) -> Response {
    let Some(resume) = parse_resume(form.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };

    // CSRF defense-in-depth (issue #196): a conclusively cross-site POST is a generic 403,
    // before any lookup or send.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }

    let identifier = form
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let banner = state.environment_banner(&resume.scope).await;

    // Regulation for the RECOVERY path (issue #64), keyed on the canonical identifier and
    // the resolved peer IP, INDEPENDENTLY of the password path. Every processed attempt is
    // counted, so recovery-request spam is throttled without a hard lockout.
    let ctx = crate::abuse::AttemptContext {
        path: ironauth_store::AuthPath::Recovery,
        scope: resume.scope,
        ip: crate::abuse::resolved_client_ip(&headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id: None,
        client_id: Some(resume.client_id.to_string()),
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        let mut response = recovery_ack_page(banner);
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return response;
    }
    // `regulate_before` already RECORDED this attempt on the recovery-path counters (every
    // processed attempt is counted, throttled or allowed), so recovery-request spam climbs
    // the per-identifier and per-IP throttle without a hard lockout (issue #64).

    // Look the identifier up ONLY to decide whether the recovery send is permitted; the
    // lookup runs for both present and absent identifiers, so the work is uniform. A send
    // to an unknown recipient is SUPPRESSED, but the acknowledgment is identical.
    let recipient_known = matches!(
        state
            .store()
            .scoped(resume.scope)
            .users()
            .by_identifier(identifier)
            .await,
        Ok(Some(_))
    );
    state.dispatch_verification(
        resume.scope,
        VerificationPurpose::Recovery,
        identifier,
        recipient_known,
    );
    recovery_ack_page(banner)
}

/// The UNIFORM recovery acknowledgment (issue #64): the SAME body and status for a known
/// and an unknown identifier.
fn recovery_ack_page(environment_banner: Option<&str>) -> Response {
    let _ = environment_banner;
    pages::secure_html(
        StatusCode::OK,
        pages::notice_page(
            "Check your email",
            "If an account exists for that identifier, we have sent recovery instructions.",
        ),
    )
}
