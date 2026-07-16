// SPDX-License-Identifier: MIT OR Apache-2.0

//! The minimal hosted login page (`GET`/`POST /login`, issue #20).
//!
//! It renders an identifier and password form and, on submit, verifies the
//! password against the stored Argon2id hash. On success it establishes a
//! bootstrap session (the `__Host-` cookie) and sends the user back to the
//! authorization request they came from (`return_to`). A failed attempt re-renders
//! the form with a GENERIC error (never distinguishing a wrong password from an
//! unknown account), and an unknown account still spends a full Argon2id
//! verification so the endpoint is not a user-enumeration oracle.

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ironauth_import::ForeignHash;
use ironauth_store::{
    CorrelationId, NewAdminUser, Scope, TraitSchema, UserId, UserRecord, UserState,
};
use serde::Deserialize;

use crate::authn::AuthenticationEvent;
use crate::interaction::{self, parse_resume};
use crate::migration::{HookOutcome, HookProfile, LazyMigrationHook};
use crate::pages;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The `return_to` carried on the `GET /login` query.
#[derive(Deserialize)]
pub struct ResumeQuery {
    /// The authorization URL to resume at after a successful sign-in.
    pub return_to: Option<String>,
}

/// The posted login form.
#[derive(Deserialize)]
pub struct LoginForm {
    /// The login handle.
    pub identifier: Option<String>,
    /// The password (never logged or echoed).
    pub password: Option<String>,
    /// The authorization URL to resume at.
    pub return_to: Option<String>,
}

/// `GET /login`: render the sign-in form for a valid resume target. The
/// `login_hint` carried on the resuming authorization request prefills the
/// identifier field (escaped into the attribute by the page), and the `display` /
/// `ui_locales` hints shape the page shell (issue #16).
pub async fn login_get(
    State(state): State<OidcState>,
    Query(query): Query<ResumeQuery>,
) -> Response {
    match parse_resume(query.return_to.as_deref()) {
        Some(resume) => {
            // The environment-kind chrome (issue #42): a non-production environment
            // marks the page noindex and shows a visible banner; prod shows neither.
            let banner = state.environment_banner(&resume.scope).await;
            // Conditional-UI passkey sign-in (issue #65): when WebAuthn is enabled,
            // the page carries the autofill token, a passkey button, and the one
            // nonce-guarded ceremony script served under the login CSP. The ceremony
            // endpoints are scope-routed, so the script targets this request's scope.
            if state.webauthn_enabled() {
                let nonce = passkey_nonce(&state);
                let scope_path = format!(
                    "/t/{}/e/{}",
                    resume.scope.tenant(),
                    resume.scope.environment()
                );
                let ui = pages::PasskeyUi {
                    nonce: &nonce,
                    scope_path: &scope_path,
                };
                let body = pages::login_page(
                    resume.hints.login_hint().unwrap_or_default(),
                    &resume.return_to,
                    None,
                    &resume.hints,
                    banner,
                    Some(&ui),
                );
                pages::login_html(StatusCode::OK, body, &nonce)
            } else {
                pages::secure_html(
                    StatusCode::OK,
                    pages::login_page(
                        resume.hints.login_hint().unwrap_or_default(),
                        &resume.return_to,
                        None,
                        &resume.hints,
                        banner,
                        None,
                    ),
                )
            }
        }
        None => interaction::invalid_link_page(),
    }
}

/// A per-response CSP script nonce for the login page's conditional-UI script
/// (issue #65), drawn from the entropy seam and hex-encoded so it is a valid CSP
/// nonce token.
fn passkey_nonce(state: &OidcState) -> String {
    let mut bytes = [0_u8; 16];
    state.env().entropy().fill_bytes(&mut bytes);
    let mut nonce = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(nonce, "{byte:02x}");
    }
    nonce
}

/// `POST /login`: verify the password and, on success, establish a session and
/// resume the authorization request.
// The linear flow (parse, CSRF, lookup, regulate, verify, session, per-arm failure
// recording) reads best as one function; splitting it would scatter the anti-enumeration
// invariant across helpers, so the length lint is allowed here (issue #64).
#[allow(clippy::too_many_lines)]
pub async fn login_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(resume) = parse_resume(form.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };

    // CSRF defense-in-depth (issue #196), BEFORE verifying the password or creating
    // a session: the SameSite=Lax session cookie the login establishes blocks the
    // standard cross-site auto-submit on later POSTs, and this Origin +
    // Sec-Fetch-Site allowlist closes the two residuals it leaves (the Chromium
    // Lax+POST window and non-enforcing legacy clients) on the login POST itself. A
    // conclusively cross-site POST is refused with a generic 403; no session is
    // created and no password work is spent.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }

    let identifier = form
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let password = form.password.as_deref().unwrap_or_default();

    // The environment-kind chrome (issue #42) for a re-rendered failure page.
    let banner = state.environment_banner(&resume.scope).await;

    let lookup = state
        .store()
        .scoped(resume.scope)
        .users()
        .by_identifier(identifier)
        .await;

    // Credential-abuse regulation (issue #64), keyed on the CANONICAL identifier (the
    // #54 seam) and the non-forgeable resolved peer IP (the #31 lesson), on the PASSWORD
    // path only. The account id is threaded in when the identifier resolved, so a manual
    // per-account ban applies; the escalation decision itself uses only the
    // existence-INDEPENDENT identifier + IP dimensions, so a throttle never distinguishes
    // a present from an absent identifier. Evaluated AFTER the (uniform-cost) lookup so
    // both present and absent identifiers pay the same work before any throttle. A
    // throttled attempt spends NO password verification, uniformly for both.
    let account_id = match &lookup {
        Ok(Some(user)) => Some(user.id.to_string()),
        _ => None,
    };
    let ctx = crate::abuse::AttemptContext {
        path: ironauth_store::AuthPath::Password,
        scope: resume.scope,
        ip: crate::abuse::resolved_client_ip(&headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id,
        client_id: Some(resume.client_id.to_string()),
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        return throttled_login_page(
            &snapshot,
            identifier,
            &resume.return_to,
            &resume.hints,
            banner,
        );
    }

    match lookup {
        // A user whose lifecycle state cannot authenticate (blocked, disabled, or
        // pending verification) is FENCED (issue #52): the password is still spent
        // (so a fenced account is timing-indistinguishable from a wrong password),
        // then the SAME generic failure is returned, never a distinct signal.
        Ok(Some(user)) if !user.state.can_authenticate() => {
            // Spend the verification through the admission-controlled pool (issue
            // #62), off the async threads; an over-share tenant or a saturated pool
            // is the retryable 429/503, never an inline hash on this thread.
            match state
                .verify_password(&resume.scope, password, &user.password_hash)
                .await
            {
                Ok(_) => {}
                Err(rejection) => return rejection.to_response(),
            }
            state.record_auth_failure(&ctx).await;
            failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
        }
        Ok(Some(user)) => {
            // Verify the native Argon2id hash first; if the account was imported with
            // a FOREIGN hash (issue #55) and has not yet logged in, the native hash is
            // the unusable sentinel, so fall through to the foreign verify. The native
            // verification runs on the admission-controlled hashing pool (issue #62).
            let native_ok = match state
                .verify_password(&resume.scope, password, &user.password_hash)
                .await
            {
                Ok(ok) => ok,
                Err(rejection) => return rejection.to_response(),
            };
            let foreign_ok = !native_ok && verify_foreign(&user, password);
            if native_ok || foreign_ok {
                // Transparently upgrade the stored credential when due (best-effort;
                // the login has already succeeded): a first FOREIGN login rehashes to
                // the native Argon2id verifier (#55), and a NATIVE login whose hash was
                // written at OLDER parameters rehashes to the current ones (#62), so a
                // per-environment parameter change reaches existing users on next login.
                upgrade_credential_after_login(&state, resume.scope, &user, password, native_ok)
                    .await;
                let actor = interaction::user_actor(&user.id);
                let subject = user.id.to_string();
                // The recorded authentication event: a password login (RFC 8176
                // `pwd`) at the current clock instant. The ID token's auth_time, amr,
                // and acr all derive from it (issue #14).
                let event = AuthenticationEvent::password(epoch_micros(state.now()));
                // Session-fixation defense (issue #32): establish_session rotates away
                // any session the browser already presented (read from `headers`),
                // invalidating it in the same transaction as the fresh one.
                match interaction::establish_session(
                    &state,
                    resume.scope,
                    &subject,
                    &event,
                    actor,
                    &headers,
                )
                .await
                {
                    Ok(cookie) => interaction::redirect_setting_cookie(&resume.return_to, &cookie),
                    Err(_) => interaction::server_error_page(),
                }
            } else {
                // Present but wrong password: generic failure (no wrong-password
                // oracle), whether the stored verifier is native or foreign. The failed
                // attempt is recorded against the layered abuse counters (issue #64).
                state.record_auth_failure(&ctx).await;
                failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
            }
        }
        // Absent account: the lazy-migration hook (issue #56) gets FIRST refusal when
        // one is configured, verifying this unknown identifier against a legacy store and
        // (on success) creating the user locally with a native Argon2id hash so the NEXT
        // login is a normal local login that never calls the hook. Every non-success
        // outcome (rejected, timeout, error, breaker open, an invalid profile, a create
        // conflict) falls through to the SAME uniform failure a local wrong password
        // produces, including the comparable Argon2id time spend, so the hook's existence
        // is not observable to an attacker.
        Ok(None) => {
            if let Some(hook) = state.migration_hook() {
                if let HookOutcome::Verified(profile) = hook.attempt(identifier, password).await {
                    if let Some(response) = complete_lazy_migration(
                        &state,
                        resume.scope,
                        identifier,
                        password,
                        &resume.return_to,
                        &headers,
                        profile,
                    )
                    .await
                    {
                        return response;
                    }
                }
            }
            // No hook, a non-success verdict, or a refused/failed create: spend comparable
            // Argon2id time (through the admission-controlled pool, issue #62), then the
            // SAME generic failure (no user-enumeration oracle). Admission is charged here
            // too, so stuffing unknown identifiers cannot bypass fair-share admission.
            match state.verify_absent(&resume.scope, password).await {
                Ok(_) => {}
                Err(rejection) => return rejection.to_response(),
            }
            // Record the failed attempt against the layered abuse counters (issue #64) on
            // the SAME existence-independent dimensions (identifier + IP) an existing
            // account would, so an absent identifier is counted and throttled identically.
            state.record_auth_failure(&ctx).await;
            failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
        }
        Err(_) => interaction::server_error_page(),
    }
}

/// Transparently upgrade a user's stored credential after a successful login,
/// best-effort. When the login succeeded on the NATIVE hash (`native_ok`), rehash
/// it to the current parameters if it drifted (issue #62); otherwise the login
/// succeeded on an imported FOREIGN hash, so rehash it to the native verifier and
/// retire the foreign hash (issue #55). Any failure is swallowed: the sign-in has
/// already succeeded and the credential simply upgrades on the next login.
async fn upgrade_credential_after_login(
    state: &OidcState,
    scope: Scope,
    user: &UserRecord,
    password: &str,
    native_ok: bool,
) {
    if native_ok {
        if crate::password::needs_rehash(&user.password_hash, state.hashing_params()) {
            rehash_native_credential(state, scope, &user.id, &user.password_hash, password).await;
        }
    } else {
        rehash_foreign_credential(state, scope, &user.id, password).await;
    }
}

/// Verify `password` against a user's imported FOREIGN hash (issue #55), if it has
/// one. Returns `false` when the user carries no foreign hash or the stored value
/// cannot be parsed (fail closed). Dispatches on the hash scheme (bcrypt, scrypt,
/// PBKDF2, Argon2, Firebase modified scrypt).
fn verify_foreign(user: &UserRecord, password: &str) -> bool {
    let Some(stored) = user.foreign_password_hash.as_deref() else {
        return false;
    };
    match ForeignHash::parse(stored) {
        Ok(foreign) => foreign.verify(password.as_bytes()),
        Err(_) => false,
    }
}

/// Land the verify-then-rehash upgrade after a successful foreign login (issue #55):
/// hash `password` with the native Argon2id at current parameters and hand it to the
/// audited store upgrade, which writes it onto the user and clears the foreign hash
/// atomically. Best-effort: any failure (a hashing error, a lost race, a transient
/// persistence fault) is swallowed so the sign-in still succeeds; the foreign hash
/// simply remains to be upgraded on the next login. The plaintext never leaves this
/// function and the hash is never logged.
async fn rehash_foreign_credential(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    password: &str,
) {
    // Rehash through the admission-controlled pool (issue #62). Best-effort: the
    // login already succeeded, so an over-share/pool-exhausted/fault rejection just
    // leaves the foreign hash to upgrade on the next login rather than failing here.
    let Ok(new_hash) = state.hash_password(&scope, password).await else {
        return;
    };
    let actor = interaction::user_actor(subject);
    let _ = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .upgrade_foreign_password(state.env(), subject, &new_hash)
        .await;
}

/// Land the transparent native-parameter rehash after a successful native login
/// (issue #62): hash `password` at the CURRENT parameters through the
/// admission-controlled pool and hand it, with the verified `current_hash`, to the
/// audited store upgrade, which writes it onto the user only while the stored hash
/// still equals `current_hash` (so a concurrent change is never clobbered).
/// Best-effort: any rejection or fault (an over-share pool, a lost race, a
/// transient persistence fault) is swallowed so the sign-in still succeeds; the
/// older-parameter hash simply upgrades on the next login. The plaintext never
/// leaves this function and the hash is never logged.
async fn rehash_native_credential(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    current_hash: &str,
    password: &str,
) {
    let Ok(new_hash) = state.hash_password(&scope, password).await else {
        return;
    };
    let actor = interaction::user_actor(subject);
    let _ = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .rehash_native_password(state.env(), subject, current_hash, &new_hash)
        .await;
}

/// Land a verified lazy-migration first login (issue #56): validate the returned
/// profile, create the user locally with a NATIVE Argon2id hash (and no foreign hash,
/// so they are migrated by construction), audit the create, and establish the session,
/// returning the same redirect a local success does. Returns `None` when nothing could
/// be persisted (an invalid profile, a lost create race, or a persistence fault), in
/// which case the caller falls through to the uniform failure and NOTHING is persisted.
///
/// The plaintext password is hashed here through the shared native hash path (the
/// entropy seam) and never leaves this function; it is never logged.
async fn complete_lazy_migration(
    state: &OidcState,
    scope: Scope,
    identifier: &str,
    password: &str,
    return_to: &str,
    headers: &HeaderMap,
    profile: Option<HookProfile>,
) -> Option<Response> {
    // Hash the in-flight password to the native Argon2id verifier (the migration
    // target) through the admission-controlled pool (issue #62); an over-share or
    // saturated pool falls through to the uniform failure and persists nothing.
    let Ok(new_hash) = state.hash_password(&scope, password).await else {
        return None;
    };

    // Resolve and VALIDATE the optional profile BEFORE persisting anything. The migration
    // profile's ONLY identity channel is the traits document, validated against the
    // environment's active identity schema (issue #53); an INVALID traits document refuses
    // the whole migration (nothing is persisted). There is deliberately NO verbatim-claims
    // channel: a hostile or compromised legacy store must not be able to inject an
    // attacker-controlled email/email_verified/groups claim that an RP would trust. The
    // created user's released claims come from the normal claim path, exactly like any
    // other user; the hook never writes `claims_json`.
    let mut traits_json: Option<String> = None;
    let mut traits_schema_version: Option<i32> = None;
    if let Some(profile) = &profile {
        if let Some(traits) = &profile.traits {
            match state.store().scoped(scope).trait_schemas().active().await {
                // An active schema is the validation contract: an invalid profile is
                // refused and nothing is persisted.
                Ok(Some(active)) => {
                    let schema = TraitSchema::compile(&active.schema_json).ok()?;
                    if !schema.validate(traits).is_empty() {
                        return None;
                    }
                    traits_json = serde_json::to_string(traits).ok();
                    traits_schema_version = Some(active.version);
                }
                // No active schema to validate against: drop the traits rather than
                // persist an unvalidated document. The user still migrates.
                Ok(None) => {}
                // Fail closed on a store fault rather than persist unvalidated traits.
                Err(_) => return None,
            }
        }
    }

    // Mint the id up front so the create's audit actor is the user acting on themselves,
    // matching the interactive login's session actor.
    let id = UserId::generate(state.env(), &scope);
    let actor = interaction::user_actor(&id);
    let created_at_micros = epoch_micros(state.now());
    let spec = NewAdminUser {
        id: Some(&id),
        identifier,
        password_hash: Some(&new_hash),
        // No verbatim claims from the hook: a migrated user's claims come from the normal
        // path, so a legacy store cannot inject an RP-trusted claim (see the traits note).
        claims_json: None,
        external_id: None,
        // A migrated user is live and can authenticate immediately.
        state: UserState::Active,
        // No foreign hash: the user is migrated by construction (native hash only), so
        // the next login is a normal local login and never calls the hook.
        foreign_password_hash: None,
        foreign_password_algo: None,
        traits_json: traits_json.as_deref(),
        traits_schema_version,
    };
    let create = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .admin_create(state.env(), spec, created_at_micros, None)
        .await;
    // A conflict means a concurrent login already migrated this identifier; a fault is a
    // transient failure. Either way, fall through to the uniform failure: the user's retry
    // finds them locally and logs in natively.
    let Ok(user_id) = create else {
        return None;
    };
    LazyMigrationHook::record_migrated();

    // Establish the session exactly as a known-user success does (session-fixation
    // defense included, via establish_session).
    let event = AuthenticationEvent::password(epoch_micros(state.now()));
    let subject = user_id.to_string();
    match interaction::establish_session(
        state,
        scope,
        &subject,
        &event,
        interaction::user_actor(&user_id),
        headers,
    )
    .await
    {
        Ok(cookie) => Some(interaction::redirect_setting_cookie(return_to, &cookie)),
        Err(_) => Some(interaction::server_error_page()),
    }
}

/// The uniform throttle response when credential-abuse regulation refuses the attempt
/// (issue #64): the SAME generic login page body a wrong password renders (so it stays
/// non-oracular), but with a `429 Too Many Requests` status and the standard rate-limit
/// response headers. Identical for a present and an absent identifier, since the throttle
/// decision keys only on the existence-independent identifier + IP dimensions.
fn throttled_login_page(
    snapshot: &ironauth_quota::RateLimitSnapshot,
    identifier: &str,
    return_to: &str,
    hints: &crate::hints::InteractionHints,
    environment_banner: Option<&str>,
) -> Response {
    let mut response = failed_login_page(identifier, return_to, hints, environment_banner);
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    crate::abuse::stamp_rate_limit_headers(&mut response, snapshot);
    response
}

/// Re-render the login form with a generic failure message, prefilling the
/// SUBMITTED identifier. The message never distinguishes a wrong password from an
/// unknown account.
fn failed_login_page(
    identifier: &str,
    return_to: &str,
    hints: &crate::hints::InteractionHints,
    environment_banner: Option<&str>,
) -> Response {
    // The error re-render is the strict, script-free page: the passkey path is
    // offered on the primary GET login page (this is a failed-password re-render).
    pages::secure_html(
        StatusCode::OK,
        pages::login_page(
            identifier,
            return_to,
            Some("Incorrect identifier or password."),
            hints,
            environment_banner,
            None,
        ),
    )
}
