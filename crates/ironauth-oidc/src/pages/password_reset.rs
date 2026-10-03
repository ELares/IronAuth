// SPDX-License-Identifier: MIT OR Apache-2.0

//! Password-reset presentation. Handlers must resolve stored authorization context,
//! enforce browser/CSRF proof and password policy, and map actual store outcomes.
//! Rendering these pages neither mounts a route nor creates authentication authority.

use super::{document, error_banner, escape_html, interaction_href};
use crate::hints::InteractionHints;
use std::fmt::Write as _;

use axum::http::StatusCode;
use axum::response::Response;

/// Render the same code-entry form for eligible, unknown and ineligible accounts.
/// `return_to` must be the validated server-owned continuation. Password/code values
/// are deliberately not accepted as arguments and cannot be reflected after errors.
/// Policy guidance and expiry label come from the handler's actual configuration
/// and persisted challenge. The sole authority field posted is the CSRF proof;
/// subject, client and challenge are resolved from the browser binding and store.
#[must_use]
pub fn code_page(
    csrf: &str,
    return_to: &str,
    error: Option<&str>,
    password_guidance: &str,
    expires_at_label: &str,
    hints: &InteractionHints,
    environment_banner: Option<&str>,
) -> String {
    let body = format!(
        r#"<h1>Reset your password</h1>
<p class="page-description">If your account is eligible for email recovery, a code will arrive at its verified email address. Check your inbox and spam folder, then enter the code in this browser.</p>
{error}
<form method="post" action="/recover/reset">
<input type="hidden" name="csrf" value="{csrf}">
<p><label for="reset-code">Recovery code</label><input id="reset-code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{8}}" minlength="8" maxlength="8" aria-describedby="reset-code-help" required></p>
<p id="reset-code-help">Enter the eight-digit code, including any leading zeros. This attempt expires at {expiry}.</p>
<p><label for="reset-password">New password</label><input id="reset-password" name="new_password" type="password" autocomplete="new-password" aria-describedby="reset-password-help" required></p>
<p id="reset-password-help">{guidance}</p>
<p><label for="reset-confirmation">Confirm new password</label><input id="reset-confirmation" name="confirm_password" type="password" autocomplete="new-password" required></p>
<p>Your other authentication factors stay in place. After resetting your password, sign in again to continue.</p>
<p><button type="submit">Reset password</button></p>
</form>
<div class="auth-links"><a href="{recover}">Request another code</a><a href="{login}">Back to sign in</a></div>
<p>If you did not request recovery, use the cancellation link in the notification email.</p>"#,
        error = error_banner(error),
        csrf = escape_html(csrf),
        expiry = escape_html(expires_at_label),
        guidance = escape_html(password_guidance),
        recover = interaction_href("/recover", return_to),
        login = interaction_href("/login", return_to),
    );
    document(
        "Reset your password",
        &body,
        hints.lang(),
        hints.display().as_str(),
        environment_banner,
    )
}

/// A browser-wide resend delay keeps the original code form reachable without
/// disclosing whether its request resolved an eligible account.
#[must_use]
pub fn recent_request_page() -> String {
    document(
        "A recovery code was recently requested",
        "<h1>A recovery code was recently requested</h1><p>Wait a minute before requesting another code. You can still use the code-entry page for your current request.</p><p><a href=\"/recover/reset\">Enter your current code</a></p>",
        "en",
        "page",
        None,
    )
}

/// Server-resolved lifecycle outcomes, not browser-selected status values.
#[derive(Clone, Copy)]
pub enum ResetNotice<'a> {
    /// The transaction committed, or its exact completion receipt was recovered.
    Completed,
    /// Correct proof cannot bypass the notified waiting period. The displayed
    /// deadline must be the current store horizon, with an explicit timezone.
    Waiting {
        /// Human-readable current store horizon, including its timezone.
        until_label: &'a str,
    },
    /// Uniform expired, exhausted, cancelled, missing or stale ceremony.
    UnavailableAttempt,
    /// Deployment-wide recovery delivery is disabled or unconfigured. Show this
    /// before account lookup rather than pretending instructions were sent.
    UnavailableService,
}

/// Explain a verified lifecycle outcome and retain the application continuation.
/// Waiting/expired notices offer an explicit request page, never automatic sends.
#[must_use]
pub fn notice_page(
    notice: ResetNotice<'_>,
    return_to: &str,
    hints: &InteractionHints,
    environment_banner: Option<&str>,
) -> String {
    let (title, message, request_again) = match notice {
        ResetNotice::Completed => (
            "Your password has been reset",
            "Sign in with your new password and your usual authentication factors to continue. Your previous IronAuth sign-in sessions have ended.".to_owned(), false,
        ),
        ResetNotice::Waiting { until_label } => (
            "Your recovery is on hold",
            format!("For your account's security, password reset must wait until {until_label}. Your password has not changed. Request a fresh code after that time. Requesting another code will not restart this waiting period. If you did not request recovery, use the cancellation link in the notification email."), true,
        ),
        ResetNotice::UnavailableAttempt => (
            "This recovery attempt is no longer available",
            "If you already submitted a new password, try signing in with it. Otherwise, request a fresh code. A code works only in the browser that requested it and before its expiry.".to_owned(), true,
        ),
        ResetNotice::UnavailableService => (
            "Password recovery is unavailable",
            "This service is not configured to deliver password recovery instructions. Contact your administrator for help accessing your account.".to_owned(), false,
        ),
    };
    let mut body = format!(
        "<h1>{}</h1><p>{}</p><div class=\"auth-links\"><a href=\"{}\">Back to sign in</a>",
        escape_html(title),
        escape_html(&message),
        interaction_href("/login", return_to)
    );
    if request_again {
        let _ = write!(
            body,
            "<a href=\"{}\">Request a fresh code</a>",
            interaction_href("/recover", return_to)
        );
    }
    body.push_str("</div>");
    document(
        title,
        &body,
        hints.lang(),
        hints.display().as_str(),
        environment_banner,
    )
}

/// Apply shared form-page hardening, including same-origin referrers so browsers
/// retain usable Origin metadata on POST. No code or password is in the URL.
#[must_use]
pub fn response(status: StatusCode, html: String) -> Response {
    super::secure_html(status, html)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn reset_form_escapes_context_and_never_posts_account_or_password_defaults() {
        let hostile = "\"><script>alert(1)</script>";
        let page = code_page(
            hostile,
            "/authorize?client_id=fixture&state=kept",
            Some(hostile),
            hostile,
            hostile,
            &InteractionHints::default(),
            None,
        );
        assert!(!page.contains("<script>"));
        assert!(page.contains("role=\"alert\""));
        for name in ["code", "new_password", "confirm_password", "csrf"] {
            assert!(page.contains(&format!("name=\"{name}\"")));
        }
        for name in [
            "subject",
            "identifier",
            "client_id",
            "return_to",
            "challenge_id",
        ] {
            assert!(!page.contains(&format!("name=\"{name}\"")));
        }
        assert!(page.contains("inputmode=\"numeric\""));
        assert!(page.contains("autocomplete=\"one-time-code\""));
        assert_eq!(page.matches("type=\"password\"").count(), 2);
        for input in page.split("<input").skip(1) {
            let input = input.split('>').next().unwrap();
            if !input.contains("type=\"hidden\"") {
                assert!(!input.contains("value="));
            }
        }
        assert!(page.contains("state%3Dkept"));
        assert!(page.contains("If your account is eligible"));
    }

    #[test]
    fn lifecycle_notices_give_honest_recovery_choices_without_automatic_mutations() {
        let hints = InteractionHints::default();
        let context = "/authorize?client_id=fixture&state=kept";
        let completed = notice_page(ResetNotice::Completed, context, &hints, None);
        assert!(completed.contains("Sign in with your new password"));
        assert!(!completed.contains("Request a fresh code"));
        let waiting = notice_page(
            ResetNotice::Waiting {
                until_label: "tomorrow UTC <script>",
            },
            context,
            &hints,
            None,
        );
        assert!(waiting.contains("Your password has not changed"));
        assert!(waiting.contains("will not restart"));
        assert!(!waiting.contains("<script>"));
        let expired = notice_page(ResetNotice::UnavailableAttempt, context, &hints, None);
        assert!(expired.contains("If you already submitted a new password"));
        let unavailable = notice_page(ResetNotice::UnavailableService, context, &hints, None);
        assert!(unavailable.contains("not configured to deliver"));
        assert!(!unavailable.contains("Request a fresh code"));
        for page in [completed, waiting, expired, unavailable] {
            assert!(!page.contains("<form"));
            assert!(!page.contains("<script"));
            assert!(page.contains("state%3Dkept"));
        }
    }

    #[test]
    fn reset_response_retains_no_store_and_same_origin_form_policy() {
        let response = response(
            StatusCode::OK,
            code_page(
                "csrf",
                "/authorize?client_id=fixture",
                None,
                "Use a unique password.",
                "12:00 UTC",
                &InteractionHints::default(),
                None,
            ),
        );
        let headers = response.headers();
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::REFERRER_POLICY], "same-origin");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert!(
            headers[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("form-action 'self'")
        );
        assert!(!headers.contains_key(header::SET_COOKIE));
    }
}
