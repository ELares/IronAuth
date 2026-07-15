// SPDX-License-Identifier: MIT OR Apache-2.0

//! The streaming import engine (issue #55).
//!
//! [`import_stream`] consumes an iterator of import lines ONE AT A TIME (bounded
//! memory: it never collects the input, so a 100k-user dataset is processed
//! without loading it), and creates each user THROUGH the audited, isolation-scoped
//! `ActingUserRepo::admin_create` (issue #52), so an imported user gets the full
//! lifecycle, tenant isolation, and PII encryption (issue #48) for free.
//!
//! Three properties the engine guarantees:
//!
//! * PER-RECORD FAILURE ISOLATION: a malformed line, an out-of-bounds foreign hash,
//!   an invalid state, or a cross-scope id fails only THAT record (reported with its
//!   stable key and an operator-safe reason); the stream continues. Nothing is
//!   silently dropped.
//! * IDEMPOTENCE: re-running an import does not duplicate. A record whose id,
//!   external id, or login handle already exists in the scope is reported as
//!   SKIPPED (the scope's unique constraints reject the duplicate), not created
//!   twice and not failed.
//! * SCOPE CONFINEMENT: every create targets the one [`ImportContext::scope`]; a
//!   record carrying an id minted in another scope is rejected, so an import into
//!   tenant A can never touch tenant B.
//!
//! The foreign hash is BOUNDS-CHECKED at import ([`crate::scheme::ForeignHash::parse`]):
//! an attacker-supplied bcrypt cost or PBKDF2 iteration count above the documented
//! maximum is rejected with a per-record error, never stored, so a later login
//! verification can never be a denial-of-service vector.

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::{
    ActorRef, CorrelationId, NewAdminUser, Scope, Store, StoreError, UserId, UserState,
};

use crate::record::{ImportRecord, parse_record_line};
use crate::scheme::ForeignHash;

/// Everything a streaming import needs besides the input itself: the store, the
/// target scope, the determinism seam, and the acting principal every create is
/// audited to.
pub struct ImportContext<'a> {
    /// The persistence layer the users are created in.
    pub store: &'a Store,
    /// The single (tenant, environment) scope every imported user lands in. A
    /// record carrying an id from a different scope is rejected per-record.
    pub scope: Scope,
    /// The determinism seam: `created_at` is read from `env.clock()` and (on a
    /// later login) the rehash salt from `env.entropy()`.
    pub env: &'a Env,
    /// The management principal the import runs as; each `user.create` audit row is
    /// attributed to it.
    pub actor: ActorRef,
}

/// The running tally of a streaming import (issue #55). Progress-observable: the
/// counters are the processed / succeeded / skipped / failed projection the
/// management job surface reports. It holds only aggregate counts (never the record
/// set), so it stays bounded regardless of input size; a caller observes each
/// individual outcome through the `on_record` callback instead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Non-blank lines seen (a blank separator line is not counted).
    pub processed: u64,
    /// Users newly created by this run.
    pub succeeded: u64,
    /// Records skipped as already-imported duplicates (idempotent re-import).
    pub skipped: u64,
    /// Records that failed (reported through `on_record`), never silently dropped.
    pub failed: u64,
}

/// A single record's operator-safe failure (issue #55): the stable record key and a
/// reason that never echoes a secret (never a password, and never a stored hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError {
    /// The stable identity the failure is reported against: the caller-supplied id,
    /// else the external id, else the login handle (or a placeholder when the line
    /// could not be parsed at all).
    pub key: String,
    /// The operator-safe reason.
    pub reason: String,
}

/// The outcome of a single import record, delivered to the `on_record` observer as
/// the stream is processed (issue #55).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    /// The user was newly created; carries the record key and the created user id.
    Created {
        /// The stable record key.
        key: String,
        /// The created user id (a `usr_` string).
        id: String,
    },
    /// The record was an already-imported duplicate and was skipped (idempotent).
    Skipped {
        /// The stable record key.
        key: String,
    },
    /// The record failed and was reported, not dropped.
    Failed(RecordError),
}

/// Whether a create was refused as an idempotent duplicate or failed outright.
enum CreateError {
    /// The scope already has this id / external id / login handle: a benign
    /// idempotent skip, not a fault.
    Conflict,
    /// A genuine failure, with an operator-safe reason.
    Failed(String),
}

/// A validated, ready-to-create record: the outcome of parsing and bounds-checking
/// one line, with every field owned so it outlives the borrow of the source line.
#[derive(Debug)]
struct PreparedCreate {
    identifier: String,
    id: Option<UserId>,
    external_id: Option<String>,
    claims_json: Option<String>,
    traits_json: Option<String>,
    traits_schema_version: Option<i32>,
    state: UserState,
    foreign_hash: Option<String>,
    foreign_algo: Option<&'static str>,
}

/// Stream a bulk import to completion, creating each user through the audited admin
/// create path and reporting every record's outcome to `on_record` as it is
/// processed.
///
/// `lines` is consumed lazily (one owned line held at a time), so the engine's
/// memory is bounded by a single record regardless of how many the input yields.
/// A blank line is a benign separator (skipped, not counted). The return value is
/// the final aggregate tally; individual creates, skips, and failures arrive
/// through `on_record`.
pub async fn import_stream<I>(
    ctx: &ImportContext<'_>,
    lines: I,
    on_record: impl FnMut(RecordOutcome),
) -> ImportReport
where
    I: IntoIterator<Item = String>,
{
    drive_import(
        ctx.scope,
        lines,
        async |prepared: PreparedCreate| create_user(ctx, prepared).await,
        on_record,
    )
    .await
}

/// Create one prepared record through the audited admin-create path, mapping a
/// duplicate to the idempotent [`CreateError::Conflict`].
async fn create_user(
    ctx: &ImportContext<'_>,
    prepared: PreparedCreate,
) -> Result<String, CreateError> {
    let created_at = epoch_micros(ctx.env.clock().now_utc());
    let result = ctx
        .store
        .scoped(ctx.scope)
        .acting(ctx.actor, CorrelationId::generate(ctx.env))
        .users()
        .admin_create(
            ctx.env,
            NewAdminUser {
                id: prepared.id.as_ref(),
                identifier: &prepared.identifier,
                // Every imported credential lands in the foreign column and is
                // verified-then-rehashed on first login, so the native verifier is
                // left unset (the login fence and the foreign path handle it).
                password_hash: None,
                claims_json: prepared.claims_json.as_deref(),
                external_id: prepared.external_id.as_deref(),
                state: prepared.state,
                foreign_password_hash: prepared.foreign_hash.as_deref(),
                foreign_password_algo: prepared.foreign_algo,
                // Traits are restored VERBATIM (issue #58): sealed as-is without
                // re-validating against the target scope's active schema, so a full
                // export imports losslessly even into a fresh scope with no schema.
                traits_json: prepared.traits_json.as_deref(),
                traits_schema_version: prepared.traits_schema_version,
            },
            created_at,
            None,
        )
        .await;
    match result {
        Ok(id) => Ok(id.to_string()),
        // A duplicate id / external id / login handle: the scope's unique
        // constraints make a re-import idempotent (skip, never a second row).
        Err(StoreError::Conflict) => Err(CreateError::Conflict),
        Err(StoreError::NotFound) => Err(CreateError::Failed(
            "user id is not in this scope".to_owned(),
        )),
        Err(_) => Err(CreateError::Failed("persistence failure".to_owned())),
    }
}

/// The pure streaming driver: pull lines lazily, parse and validate each, and hand a
/// prepared record to `create`, tallying and reporting outcomes. Generic over the
/// create step so the parsing / validation / streaming behavior is testable without
/// a database.
async fn drive_import<I, C>(
    scope: Scope,
    lines: I,
    mut create: C,
    mut on_record: impl FnMut(RecordOutcome),
) -> ImportReport
where
    I: IntoIterator<Item = String>,
    C: AsyncFnMut(PreparedCreate) -> Result<String, CreateError>,
{
    let mut report = ImportReport::default();
    for line in lines {
        let record = match parse_record_line(&line) {
            Ok(Some(record)) => record,
            // A blank separator line: not a record, not counted.
            Ok(None) => continue,
            Err(error) => {
                report.processed += 1;
                report.failed += 1;
                on_record(RecordOutcome::Failed(RecordError {
                    key: "<unparsable record>".to_owned(),
                    reason: format!("parse error: {}", error.message()),
                }));
                continue;
            }
        };
        report.processed += 1;
        let key = record.record_key().to_owned();
        let prepared = match prepare_record(record, scope) {
            Ok(prepared) => prepared,
            Err(reason) => {
                report.failed += 1;
                on_record(RecordOutcome::Failed(RecordError { key, reason }));
                continue;
            }
        };
        match create(prepared).await {
            Ok(id) => {
                report.succeeded += 1;
                on_record(RecordOutcome::Created { key, id });
            }
            Err(CreateError::Conflict) => {
                report.skipped += 1;
                on_record(RecordOutcome::Skipped { key });
            }
            Err(CreateError::Failed(reason)) => {
                report.failed += 1;
                on_record(RecordOutcome::Failed(RecordError { key, reason }));
            }
        }
    }
    report
}

/// Parse and bounds-check one record into a [`PreparedCreate`], or return an
/// operator-safe reason it was rejected (issue #55). This is where the foreign-hash
/// denial-of-service bounds are enforced AT IMPORT.
fn prepare_record(record: ImportRecord, scope: Scope) -> Result<PreparedCreate, String> {
    let state = match record.state.as_deref() {
        None => UserState::Active,
        Some(tag) => {
            let parsed =
                UserState::from_wire(tag).ok_or_else(|| format!("unknown state: {tag}"))?;
            if !parsed.is_creatable() {
                return Err(format!("state is not a valid initial state: {tag}"));
            }
            parsed
        }
    };
    let id = match record.id.as_deref() {
        None => None,
        Some(raw) => Some(
            UserId::parse_in_scope(raw, &scope)
                .map_err(|_| "id is malformed or belongs to another scope".to_owned())?,
        ),
    };
    let (foreign_hash, foreign_algo) = match record.password_hash.as_deref() {
        None => (None, None),
        Some(raw) => {
            let parsed = ForeignHash::parse(raw)
                .map_err(|error| format!("foreign hash rejected: {error}"))?;
            (Some(parsed.stored().to_owned()), Some(parsed.tag()))
        }
    };
    let claims_json = match record.claims {
        None => None,
        Some(ref value) if value.is_object() => Some(
            serde_json::to_string(value).map_err(|_| "claims are not serializable".to_owned())?,
        ),
        Some(_) => return Err("claims must be a JSON object".to_owned()),
    };
    let traits_json = match record.traits {
        None => None,
        Some(ref value) if value.is_object() => Some(
            serde_json::to_string(value).map_err(|_| "traits are not serializable".to_owned())?,
        ),
        Some(_) => return Err("traits must be a JSON object".to_owned()),
    };
    Ok(PreparedCreate {
        identifier: record.identifier,
        id,
        external_id: record.external_id,
        claims_json,
        traits_json,
        traits_schema_version: record.traits_schema_version,
        state,
        foreign_hash,
        foreign_algo,
    })
}

/// Convert a seam-read wall-clock instant to microseconds since the Unix epoch.
/// Reads no clock of its own (the value comes from `env.clock()`), so it is
/// deterministic under a manual test clock.
fn epoch_micros(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_micros()).map_or(i64::MIN, |m| -m),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ironauth_env::Env;
    use ironauth_store::{EnvironmentId, Scope, TenantId};

    use super::*;

    /// A scope built from raw ids for the DB-free driver tests (no database needed:
    /// the driver's create step is mocked).
    fn test_scope() -> Scope {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 1);
        let tenant = TenantId::generate(&env);
        let environment = EnvironmentId::generate(&env);
        Scope::new(tenant, environment)
    }

    fn line(json: &str) -> String {
        json.to_owned()
    }

    #[tokio::test]
    #[allow(clippy::items_after_statements)] // the lazy-iterator type reads clearest inline
    async fn streaming_is_bounded_and_never_collects_the_input() {
        // A lazy iterator that yields a large number of records and tracks the
        // maximum number of lines alive at once. The driver holds one line at a
        // time, so the peak never exceeds one: proof it does not collect the input.
        const N: u64 = 200_000;
        let alive = Arc::new(AtomicU64::new(0));
        let peak = Arc::new(AtomicU64::new(0));

        struct Lazy {
            next: u64,
            alive: Arc<AtomicU64>,
            peak: Arc<AtomicU64>,
        }
        impl Iterator for Lazy {
            type Item = String;
            fn next(&mut self) -> Option<String> {
                if self.next >= N {
                    return None;
                }
                let now = self.alive.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                let s = format!(r#"{{"identifier":"user-{}"}}"#, self.next);
                self.next += 1;
                Some(s)
            }
        }

        let lazy = Lazy {
            next: 0,
            alive: Arc::clone(&alive),
            peak: Arc::clone(&peak),
        };
        // The mock create consumes the prepared record (dropping the line's memory)
        // and marks it no-longer-alive, then always succeeds.
        let alive_for_create = Arc::clone(&alive);
        let report = drive_import(
            test_scope(),
            lazy,
            async move |prepared: PreparedCreate| {
                alive_for_create.fetch_sub(1, Ordering::SeqCst);
                Ok(format!("usr_{}", prepared.identifier))
            },
            |_| {},
        )
        .await;

        assert_eq!(report.processed, N);
        assert_eq!(report.succeeded, N);
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "at most one line is ever alive: the input is streamed, never collected"
        );
    }

    #[tokio::test]
    async fn per_record_failure_isolation_does_not_abort_the_batch() {
        let lines = vec![
            line(r#"{"identifier":"ok-1"}"#),
            line("{ this is not json"),
            line(
                r#"{"identifier":"bad-cost","password_hash":"$2b$31$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            ),
            line(r#"{"identifier":"ok-2","state":"blocked"}"#),
            line(r#"{"identifier":"bad-state","state":"scheduled_offboarding"}"#),
            line(""),
            line(r#"{"identifier":"ok-3"}"#),
        ];
        let outcomes = Cell::new(Vec::new());
        let report = drive_import(
            test_scope(),
            lines,
            async |prepared: PreparedCreate| Ok(format!("usr_{}", prepared.identifier)),
            |outcome| {
                let mut v = outcomes.take();
                v.push(outcome);
                outcomes.set(v);
            },
        )
        .await;

        // Three good records created, three bad ones failed, one blank skipped;
        // crucially the batch ran to the end past every failure.
        assert_eq!(report.processed, 6, "six non-blank lines");
        assert_eq!(report.succeeded, 3, "ok-1, ok-2, ok-3");
        assert_eq!(report.failed, 3, "malformed json, bad cost, bad state");
        let failures = outcomes
            .take()
            .into_iter()
            .filter(|o| matches!(o, RecordOutcome::Failed(_)))
            .count();
        assert_eq!(failures, 3);
    }

    #[tokio::test]
    async fn idempotent_reimport_reports_skips_not_failures() {
        let lines = vec![
            line(r#"{"identifier":"dup"}"#),
            line(r#"{"identifier":"fresh"}"#),
        ];
        // The mock create rejects the record whose identifier is "dup" as a
        // conflict, exactly as a re-import hits the scope's unique constraint.
        let report = drive_import(
            test_scope(),
            lines,
            async |prepared: PreparedCreate| {
                if prepared.identifier == "dup" {
                    Err(CreateError::Conflict)
                } else {
                    Ok(format!("usr_{}", prepared.identifier))
                }
            },
            |_| {},
        )
        .await;
        assert_eq!(report.succeeded, 1);
        assert_eq!(report.skipped, 1, "the duplicate is a skip, not a failure");
        assert_eq!(report.failed, 0);
    }

    #[test]
    fn prepare_rejects_out_of_bounds_foreign_hash() {
        let record = parse_record_line(
            r#"{"identifier":"a","password_hash":"$2b$31$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .expect("parse")
        .expect("some");
        let error = prepare_record(record, test_scope()).unwrap_err();
        assert!(error.contains("foreign hash rejected"), "{error}");
    }

    #[test]
    fn prepare_tags_a_valid_foreign_hash() {
        let record = parse_record_line(
            r#"{"identifier":"a","password_hash":"$2b$08$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .expect("parse")
        .expect("some");
        let prepared = prepare_record(record, test_scope()).expect("prepared");
        assert_eq!(prepared.foreign_algo, Some("bcrypt"));
        assert!(prepared.foreign_hash.is_some());
    }
}
