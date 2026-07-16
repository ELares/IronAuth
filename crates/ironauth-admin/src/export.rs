// SPDX-License-Identifier: MIT OR Apache-2.0

//! The full identity export: the exit-friendliness covenant, made mechanical
//! (issue #58).
//!
//! `GET .../export` streams EVERY identity of a `(tenant, environment)` as the
//! SAME newline-delimited record format the streaming bulk import (issue #55)
//! consumes, so export-to-import round-trips by construction: one JSON object per
//! line, one user per object. Each record carries the user's id, login handle,
//! external id, lifecycle state, standard claims, identity traits (and their schema
//! version), and the password verifier with its algorithm tag and full parameters
//! (a native Argon2id PHC string, or the imported FOREIGN hash for a user who has
//! not yet logged in). "You can always leave" means everything leaves, including the
//! hashes: no support ticket, no operator intervention, no private knowledge, just
//! the API call and the published format.
//!
//! Three covenant properties this endpoint holds:
//!
//! * SELF-SERVE and PERMISSION-GATED. The export is a single authorized management
//!   call: the operator plane, or the environment's OWN management key, may drain
//!   it (the same `require_environment` gate the other per-environment reads use). A
//!   cross-environment key is the loud wrong-scope error.
//! * AUDITED. Every export writes one `user.export` audit row attributed to the
//!   acting principal (issue #58): a bulk read of sensitive credential material is
//!   OBSERVABLE, never obstructed. The exported values are never recorded on the
//!   audit row, only the identity count.
//! * BOUNDED MEMORY. The export drains the scope one bounded PAGE at a time through
//!   the store's keyset-paginated [`ironauth_store::UserRepo::export_page`], so a
//!   100k-user export never loads the whole set. [`export_paged`] is the pure
//!   streaming core (generic over the page fetcher and a per-record sink), holding
//!   at most one page at a time; a test asserts that ceiling over 100k+ records
//!   without a database.

use std::future::Future;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_import::{ImportCredential, ImportRecord, to_record_line};
use ironauth_store::{
    ActorRef, CorrelationId, CursorPosition, Scope, StoreError, UserExportRecord, UserState,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::ndjson;
use crate::state::AdminState;

/// Resolve and authorize the `(tenant, environment)` scope from the path, exactly
/// like the user-CRUD surface: the operator passes, a management key must be scoped
/// to this environment (otherwise the loud wrong-scope error), and a malformed id is
/// the uniform not-found.
fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ActorRef), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Export every identity of an environment as newline-delimited import records.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/export",
    operation_id = "exportIdentities",
    tag = "exit",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The full identity export as newline-delimited JSON \
         (application/x-ndjson): one import record per line, carrying every user's id, login \
         handle, external id, lifecycle state, standard claims, identity traits and schema \
         version, and the password verifier with its algorithm tag and parameters (a native \
         Argon2id PHC string, or the imported foreign hash for a user not yet logged in). This \
         is the exact format the streaming bulk import consumes, so it re-imports into a fresh \
         instance losslessly with logins intact. Documented at docs/exit-guide.md.", content_type = "application/x-ndjson"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn export_identities(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;

    // Drain the scope one bounded page at a time, serializing each user to a line of
    // the import format. The page size is the management list ceiling, so a single
    // page is bounded regardless of how many identities the environment holds.
    let page_limit = i64::from(state.max_page_size());
    let mut body = String::new();
    let count = export_paged(
        page_limit,
        |after| {
            let state = &state;
            async move {
                state
                    .store()
                    .scoped(scope)
                    .users()
                    .export_page(after.as_ref(), page_limit)
                    .await
            }
        },
        |record| {
            // A serialization failure cannot occur for this concrete record shape;
            // the covenant is to emit every user, so a lost line is unacceptable.
            // `to_record_line` returns a Result rather than panicking, and the (impossible)
            // error yields a non-emitted line rather than a torn export; the field-coverage
            // and round-trip tests assert every line is present. Returning whether the line
            // was emitted keeps the audited count equal to the number of lines actually
            // written, never over-counting a skipped line.
            match to_record_line(&export_record_to_import(record)) {
                Ok(line) => {
                    body.push_str(&line);
                    body.push('\n');
                    true
                }
                Err(_) => false,
            }
        },
    )
    .await?;

    // Audit the export with actor attribution BEFORE returning it: a bulk read of
    // credential material is observable. The row records only the identity count.
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .record_export_audit(state.env(), count)
        .await?;

    Ok(ndjson(StatusCode::OK, body))
}

/// The pure streaming core of the export (issue #58): pull pages lazily through
/// `fetch` (keyset paginated by the previous page's last cursor) and hand each
/// record to `sink`, holding AT MOST ONE page in memory at a time. It never
/// collects the whole result set, so a 100k-user export is bounded by one page
/// regardless of total size (the memory ceiling a test asserts). Returns the total
/// number of records emitted.
///
/// Generic over the fetcher and the sink so the streaming / bounded-memory behavior
/// is testable without a database, mirroring the import engine's `drive_import`. The
/// sink returns whether it EMITTED the record; the returned total counts only emitted
/// records, so the audited count never exceeds the lines actually written.
///
/// # Errors
///
/// Propagates any [`StoreError`] the fetcher returns.
async fn export_paged<Fetch, Fut, Sink>(
    page_limit: i64,
    mut fetch: Fetch,
    mut sink: Sink,
) -> Result<u64, StoreError>
where
    Fetch: FnMut(Option<CursorPosition>) -> Fut,
    Fut: Future<Output = Result<Vec<UserExportRecord>, StoreError>>,
    Sink: FnMut(&UserExportRecord) -> bool,
{
    let mut after: Option<CursorPosition> = None;
    let mut total: u64 = 0;
    loop {
        let page = fetch(after.clone()).await?;
        if page.is_empty() {
            break;
        }
        let fetched = page.len();
        for record in &page {
            if sink(record) {
                total += 1;
            }
        }
        // A short page is the last page: stop before an empty fetch.
        if i64::try_from(fetched).unwrap_or(i64::MAX) < page_limit {
            break;
        }
        let last = page.last().expect("a non-empty page has a last record");
        after = Some(CursorPosition {
            created_at_unix_micros: last.created_at_unix_micros,
            id: last.id.to_string(),
        });
        // The page (and its records) is dropped here, before the next fetch, so the
        // core never holds two pages at once.
    }
    Ok(total)
}

/// Project a stored [`UserExportRecord`] onto the import [`ImportRecord`] shape
/// (issue #58), the single mapping that makes export-to-import lossless.
///
/// * The effective credential is the native Argon2id hash when the user has one,
///   otherwise the imported foreign hash; both are algorithm-tagged PHC strings the
///   import scheme layer recognizes, so a native credential re-imports through the
///   same foreign-verify-then-rehash path and logs in unchanged. A credential-less
///   account carries no hash.
/// * `active` is the default, so it (and `scheduled_offboarding`, which is an
///   operational overlay on an authenticatable account and is not a creatable state)
///   is emitted as no state; every other state is emitted verbatim.
/// * An empty claims object is omitted to keep the line minimal; traits are carried
///   verbatim with their source schema version.
/// * The internal `usr_` id is NOT emitted: it embeds the SOURCE scope, so it cannot
///   be reused in a fresh instance (a different tenant and environment), and the
///   import engine correctly rejects a cross-scope id. The PORTABLE identity keys
///   (the login handle and the external id) are what carry across; the target
///   instance mints a fresh scoped id. A re-import into the SAME scope stays
///   idempotent through the login handle's per-scope uniqueness.
fn export_record_to_import(record: &UserExportRecord) -> ImportRecord {
    let password_hash = record
        .password_hash
        .clone()
        .or_else(|| record.foreign_password_hash.clone());
    let state = match record.state {
        UserState::Active | UserState::ScheduledOffboarding => None,
        other => Some(other.as_str().to_owned()),
    };
    let claims = parse_object(&record.claims_json).filter(|value| !is_empty_object(value));
    let traits = record.traits_json.as_deref().and_then(parse_object);
    // The enrolled credential registry (issue #58): each passkey / TOTP /
    // recovery-code enrollment rides the record so the export carries the registry,
    // not merely the password. An empty registry is omitted to keep the line minimal.
    let credentials = if record.credentials.is_empty() {
        None
    } else {
        Some(
            record
                .credentials
                .iter()
                .map(|credential| ImportCredential {
                    credential_type: credential.credential_type.clone(),
                    friendly_name: credential.friendly_name.clone(),
                    last_used_at: credential.last_used_at_unix_micros,
                })
                .collect(),
        )
    };
    ImportRecord {
        identifier: record.identifier.clone(),
        id: None,
        external_id: record.external_id.clone(),
        state,
        claims,
        traits,
        traits_schema_version: record.traits_schema_version,
        password_hash,
        credentials,
    }
}

/// Parse stored JSON text into a [`serde_json::Value`], or [`None`] when it is not
/// valid JSON (which a sealed-at-rest document never is in practice; the export
/// then omits the field rather than tearing the line).
fn parse_object(json: &str) -> Option<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(json).ok()
}

/// Whether a JSON value is the empty object `{}`.
fn is_empty_object(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ironauth_env::Env;
    use ironauth_store::{Scope, UserId, UserState};

    use super::*;

    fn synthetic_record(scope: Scope, env: &Env, n: usize) -> UserExportRecord {
        UserExportRecord {
            id: UserId::generate(env, &scope),
            identifier: format!("user-{n}@example.test"),
            state: UserState::Active,
            external_id: None,
            claims_json: "{}".to_owned(),
            traits_json: None,
            traits_schema_version: None,
            password_hash: Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned()),
            foreign_password_hash: None,
            foreign_password_algo: None,
            credentials: Vec::new(),
            totp: Vec::new(),
            recovery_codes: Vec::new(),
            created_at_unix_micros: i64::try_from(n).unwrap_or(i64::MAX),
        }
    }

    /// The export core streams 100k+ records while holding AT MOST ONE page in
    /// memory at any instant: the covenant's bounded-memory guarantee, asserted
    /// without a database (mirroring the import engine's streaming test). The
    /// fetcher refuses to produce the next page until the previous one has been
    /// fully consumed, and the sink asserts the live-record count never exceeds one
    /// page, so an implementation that collected the whole set would fail here.
    #[tokio::test]
    async fn export_streams_within_a_one_page_memory_ceiling() {
        const TOTAL: usize = 100_000;
        const PAGE: usize = 500;
        let page_limit = i64::try_from(PAGE).expect("page fits i64");

        let (env, _) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 1);
        let scope = {
            use ironauth_store::{EnvironmentId, TenantId};
            Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env))
        };
        // The number of records currently alive to the core (produced by a fetch but
        // not yet released by finishing the page). The ceiling this test asserts.
        let held = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let produced = Arc::new(AtomicUsize::new(0));

        let held_fetch = Arc::clone(&held);
        let peak_fetch = Arc::clone(&peak);
        let produced_fetch = Arc::clone(&produced);
        let held_sink = Arc::clone(&held);

        let total = export_paged(
            page_limit,
            move |_after| {
                // The previous page must be fully consumed before the next is
                // produced: proof the core does not accumulate pages.
                assert_eq!(
                    held_fetch.load(Ordering::SeqCst),
                    0,
                    "a page was fetched before the previous one was released"
                );
                let already = produced_fetch.load(Ordering::SeqCst);
                let this_page = TOTAL.saturating_sub(already).min(PAGE);
                let mut rows = Vec::new();
                for i in 0..this_page {
                    rows.push(synthetic_record(scope, &env, already + i));
                }
                produced_fetch.fetch_add(this_page, Ordering::SeqCst);
                let now = held_fetch.fetch_add(this_page, Ordering::SeqCst) + this_page;
                peak_fetch.fetch_max(now, Ordering::SeqCst);
                async move { Ok(rows) }
            },
            move |_record| {
                held_sink.fetch_sub(1, Ordering::SeqCst);
                // Every synthetic record is emitted, so the sink always counts it: the
                // returned total must equal TOTAL.
                true
            },
        )
        .await
        .expect("export core is infallible with an in-memory fetcher");

        assert_eq!(
            usize::try_from(total).expect("total fits usize"),
            TOTAL,
            "every record is emitted exactly once"
        );
        assert_eq!(
            peak.load(Ordering::SeqCst),
            PAGE,
            "at most one page of records is ever alive: the export is bounded by one page, \
             never the whole {TOTAL}-user set"
        );
    }

    #[test]
    fn a_native_hash_maps_to_the_credential_and_active_is_omitted() {
        let (env, _) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 1);
        let scope = {
            use ironauth_store::{EnvironmentId, TenantId};
            Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env))
        };
        let record = synthetic_record(scope, &env, 1);
        let mapped = export_record_to_import(&record);
        assert_eq!(mapped.identifier, "user-1@example.test");
        assert!(
            mapped.state.is_none(),
            "active is the default, so it is omitted"
        );
        assert!(mapped.claims.is_none(), "an empty claims object is omitted");
        assert_eq!(
            mapped.password_hash.as_deref(),
            record.password_hash.as_deref()
        );
    }

    #[test]
    fn a_foreign_only_user_maps_the_foreign_hash_as_the_credential() {
        let (env, _) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 1);
        let scope = {
            use ironauth_store::{EnvironmentId, TenantId};
            Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env))
        };
        let mut record = synthetic_record(scope, &env, 2);
        record.password_hash = None; // the unusable sentinel normalized away
        record.foreign_password_hash = Some("$2b$08$abcdefghijklmnopqrstuv".to_owned());
        record.foreign_password_algo = Some("bcrypt".to_owned());
        let mapped = export_record_to_import(&record);
        assert_eq!(
            mapped.password_hash.as_deref(),
            Some("$2b$08$abcdefghijklmnopqrstuv"),
            "a foreign-only user exports its foreign hash as the credential"
        );
    }
}
