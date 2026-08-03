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
//! * PER-RECORD FAILURE ISOLATION: a malformed line, a line that is not valid UTF-8, a
//!   blank login handle, an out-of-bounds foreign hash, an invalid state, or a cross-scope
//!   id fails only THAT record (reported with its stable key and an operator-safe reason);
//!   the stream continues. Nothing is silently dropped, and that is a claim about the
//!   KEY as much as about the report: a record's key is its LOGIN HANDLE, and a line that
//!   never became a record is keyed on a digest of its own bytes, so two failures are two
//!   accounted failures. Keying every parse failure on one constant string (which the
//!   first cut did) means the ledger's per-subject dedup DISCARDS all but the first, which
//!   is exactly the silent drop this sentence denies.
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

use std::fmt::Write as _;
use std::future::Future;
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::{
    ActorRef, CorrelationId, CredentialType, NewAdminUser, NewUserTraits, RestoredRecoveryCode,
    RestoredTotp, Scope, Store, StoreError, TraitSchema, TraitWriteVisibility, UserId, UserState,
};
use sha2::{Digest as _, Sha256};

use crate::record::{ImportRecord, parse_record_line};
use crate::scheme::ForeignHash;

/// A PULL source of import lines: awaited once per line, yielding [`None`] at end of
/// input.
///
/// A line is RAW BYTES rather than a `String`, and that is the difference between an
/// undecodable line being REPORTED and being silently rewritten. A transport that decodes
/// lossily turns a Latin-1 login handle into one carrying U+FFFD, which imports cleanly,
/// counts as a success, and produces an account whose owner can never log in, with no
/// error anywhere (MEASURED before this signature). Handing the engine the bytes puts the
/// UTF-8 decision in the one place that can fail a RECORD, which is where this module's
/// per-record failure isolation lives.
///
/// It is a trait rather than an `AsyncFnMut() -> Option<String>` bound, and that is not a
/// style choice. A borrowing async CLOSURE produces a future whose `Send` implementation
/// rustc cannot generalize over lifetimes, so an axum handler driving one is refused with
/// "implementation of `Send` is not general enough" at the ROUTER, naming types the
/// handler never mentions (MEASURED: nine such errors, on `&Store`, `&AdminState`,
/// `&str`, and the store's own audited-write closure). Declaring the returned future
/// `Send` HERE is what makes the bound general, so the management import job can drive
/// the engine at all.
///
/// A synchronous iterator adapts through [`IterLines`]; a transport (an HTTP body read
/// frame by frame) implements this directly.
pub trait LineSource {
    /// The next line's bytes, or [`None`] at end of input.
    fn next_line(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// A SINK for per-record outcomes: awaited once per record as the stream drains, so an
/// observer that persists outcomes can do so INCREMENTALLY rather than being handed the
/// whole run at the end.
///
/// A trait for the same reason [`LineSource`] is one: an observer that borrows what it
/// writes into is an async closure, and a borrowing async closure's future has no general
/// `Send` implementation, which puts the whole engine out of reach of an axum handler.
pub trait OutcomeSink {
    /// Record one outcome durably.
    ///
    /// # Errors
    ///
    /// Whatever the sink's persistence layer returns. An error STOPS the import: the
    /// alternative is creating identities that nothing is accounting.
    fn record(
        &mut self,
        outcome: RecordOutcome,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// A sink that DISCARDS every per-record outcome, for a caller that wants only the
/// aggregate [`ImportReport`].
///
/// The counts survive; the per-record REASONS do not, so this is not what a production
/// import wants (issue #55 requires every failure be reported with its record identity).
/// It exists for callers that genuinely have nowhere to put them.
#[derive(Debug, Default, Clone, Copy)]
pub struct DiscardOutcomes;

impl OutcomeSink for DiscardOutcomes {
    async fn record(&mut self, _outcome: RecordOutcome) -> Result<(), StoreError> {
        Ok(())
    }
}

/// A sink that KEEPS every per-record outcome in memory.
///
/// Its footprint grows with the record count, which is exactly what the streaming profile
/// forbids, so it is NOT what a bulk import uses: the shipped observer is the migration
/// run's ledger, which flushes a bounded batch and holds nothing else. This is for a
/// caller with a small, known-bounded input that wants to inspect the individual
/// outcomes, which in practice means a test.
#[derive(Debug, Default)]
pub struct CollectOutcomes(pub Vec<RecordOutcome>);

impl OutcomeSink for &mut CollectOutcomes {
    async fn record(&mut self, outcome: RecordOutcome) -> Result<(), StoreError> {
        self.0.push(outcome);
        Ok(())
    }
}

/// Adapts a synchronous [`Iterator`] of lines to a [`LineSource`].
pub struct IterLines<I>(I);

impl<I> IterLines<I>
where
    I: Iterator<Item = String> + Send,
{
    /// Wrap `lines` as a pull source.
    pub fn new(lines: I) -> Self {
        Self(lines)
    }
}

impl<I> LineSource for IterLines<I>
where
    I: Iterator<Item = String> + Send,
{
    async fn next_line(&mut self) -> Option<Vec<u8>> {
        self.0.next().map(String::into_bytes)
    }
}

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
    /// The stable identity the failure is reported against: the record's LOGIN HANDLE,
    /// or, for a line the engine could not decode or parse into a record at all, a
    /// truncated one-way digest of the line's own bytes, prefixed `unparsable-line:`.
    /// Distinct per distinct line either way, which is what keeps two bad lines two
    /// accounted failures.
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
    credentials: Vec<PreparedCredential>,
    totp: Vec<PreparedTotp>,
    recovery_codes: Vec<PreparedRecoveryCode>,
}

/// A validated MFA / login credential to restore alongside an imported user (issue
/// #58): the factor kind parsed to the closed [`CredentialType`] set, the
/// bounds-checked friendly name, and the preserved last-used instant.
#[derive(Debug)]
struct PreparedCredential {
    credential_type: CredentialType,
    friendly_name: String,
    last_used_at: Option<i64>,
}

/// A validated TOTP authenticator to restore alongside an imported user (issue
/// #58/#69): the DECODED seed (Base32 opened back to raw bytes, ready to re-seal), the
/// bounds-checked parameters and friendly name, the status, and the single-use step.
/// The seed is secret material; the redacting `Debug` keeps a dump from spilling it.
struct PreparedTotp {
    seed: Vec<u8>,
    friendly_name: String,
    algorithm: String,
    digits: i32,
    period_secs: i32,
    status: String,
    last_consumed_step: Option<i64>,
}

impl std::fmt::Debug for PreparedTotp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedTotp")
            .field("seed", &"<redacted>")
            .field("friendly_name", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period_secs", &self.period_secs)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// A validated recovery code to restore alongside an imported user (issue #58/#69):
/// the one-way Argon2id hash carried verbatim and its consumed state. The hash is
/// credential material; the redacting `Debug` renders only the consumed flag.
struct PreparedRecoveryCode {
    code_hash: String,
    consumed: bool,
}

impl std::fmt::Debug for PreparedRecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRecoveryCode")
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

/// Stream a bulk import to completion from a SYNCHRONOUS line iterator, creating each
/// user through the audited admin create path and reporting every record's outcome to
/// `on_record` as it is processed.
///
/// `lines` is consumed lazily (one owned line held at a time), so the engine's
/// memory is bounded by a single record regardless of how many the input yields.
/// A blank line is a benign separator (skipped, not counted). The return value is
/// the final aggregate tally; individual creates, skips, and failures arrive
/// through `on_record`.
///
/// This is the thin adapter over [`import_stream_lines`], which is the general form: a
/// caller whose input arrives ASYNCHRONOUSLY (an HTTP request body read frame by frame)
/// cannot express itself as an [`Iterator`] without buffering the whole body first, which
/// is exactly the bound this engine exists to hold.
///
/// # Errors
///
/// Whatever `on_record` returns. A per-RECORD failure is never an error here (it is
/// reported through `on_record` and the stream continues); an error means the OBSERVER
/// could not durably account an outcome, so the import stops rather than processing
/// records nothing is recording.
pub async fn import_stream<I, F>(
    ctx: &ImportContext<'_>,
    lines: I,
    on_record: F,
) -> Result<ImportReport, StoreError>
where
    I: IntoIterator<Item = String>,
    I::IntoIter: Send,
    F: OutcomeSink,
{
    import_stream_lines(ctx, IterLines::new(lines.into_iter()), on_record).await
}

/// Stream a bulk import to completion from an ASYNCHRONOUS pull source (issue #55).
///
/// `next_line` is awaited once per line and yields [`None`] at end of input; the engine
/// holds exactly ONE line at a time, so its memory is bounded by a single record
/// regardless of how many the source yields. `on_record` is awaited once per record, so
/// an observer that DURABLY records each outcome (the migration-run ledger) can do so
/// INCREMENTALLY rather than accumulating the whole run in memory first.
///
/// A source that stops early (a truncated upload, a killed producer) is not an error: it
/// is a partially completed import, which the run's ledger has durably accounted and a
/// later call resumes. That is the resumability contract, not a failure mode.
///
/// # Errors
///
/// Whatever `on_record` returns; see [`import_stream`].
pub async fn import_stream_lines<N, F>(
    ctx: &ImportContext<'_>,
    lines: N,
    on_record: F,
) -> Result<ImportReport, StoreError>
where
    N: LineSource,
    F: OutcomeSink,
{
    // The target scope's ACTIVE trait schema, resolved ONCE for the whole run rather than
    // per record (a scope has one active version for the duration of an import, and the
    // read is a round trip).
    //
    // A restore SEALS traits verbatim, and it must: the exit covenant is that a full export
    // re-imports losslessly even into a FRESH scope that has registered no schema at all,
    // so validation cannot be a precondition of the path. That is the whole of what the
    // covenant needs, and the first cut generalized it into skipping validation
    // UNCONDITIONALLY, which is strictly more: importing into a scope that DOES serve a
    // schema then wrote documents no live write could have written, and the next cutover
    // scan is where an operator would find out. So: no active schema, no validation (the
    // covenant); an active schema, validate and report the offenders per record through the
    // report the path already has.
    //
    // A stored schema that does not COMPILE is a persistence corruption, not a record
    // fault; it is treated as no schema rather than failing every record, so a corrupt
    // registry cannot turn a restore into a total loss.
    let schema = match ctx.store.scoped(ctx.scope).trait_schemas().active().await {
        Ok(Some(version)) => TraitSchema::compile(&version.schema_json).ok(),
        Ok(None) | Err(_) => None,
    };
    drive_import(ctx.scope, lines, StoreCreator { ctx, schema }, on_record).await
}

/// How [`drive_import`] creates one prepared record. A trait rather than an async closure
/// for the reason [`LineSource`] records.
trait RecordCreator {
    /// Create one prepared record, returning its `usr_` id.
    fn create(
        &mut self,
        prepared: PreparedCreate,
    ) -> impl Future<Output = Result<String, CreateError>> + Send;
}

/// The SHIPPED creator: the audited, isolation-scoped admin create path, with the target
/// scope's active trait schema resolved once for the whole run.
struct StoreCreator<'a> {
    ctx: &'a ImportContext<'a>,
    schema: Option<TraitSchema>,
}

impl RecordCreator for StoreCreator<'_> {
    async fn create(&mut self, prepared: PreparedCreate) -> Result<String, CreateError> {
        create_user(self.ctx, self.schema.as_ref(), prepared).await
    }
}

/// Validate an imported traits document against the target scope's active schema, or
/// report the per-field offenders as this record's operator-safe failure reason.
///
/// Value-free by construction: a [`ValidationFailure`] carries an RFC 6901 pointer and a
/// stable reason and never echoes the offending value, so a failure report from an import
/// carries no trait PII into an operator's console or log.
fn check_imported_traits(
    schema: Option<&TraitSchema>,
    traits_json: Option<&str>,
) -> Result<(), CreateError> {
    let (Some(schema), Some(traits_json)) = (schema, traits_json) else {
        return Ok(());
    };
    let value: serde_json::Value = serde_json::from_str(traits_json)
        .map_err(|_| CreateError::Failed("traits are not valid JSON".to_owned()))?;
    let failures = schema.validate(&value);
    if failures.is_empty() {
        return Ok(());
    }
    let detail = failures
        .iter()
        .map(|failure| format!("{}: {}", failure.pointer, failure.message))
        .collect::<Vec<_>>()
        .join("; ");
    Err(CreateError::Failed(format!(
        "traits fail the target scope's active schema: {detail}"
    )))
}

/// Create one prepared record through the audited admin-create path, mapping a
/// duplicate to the idempotent [`CreateError::Conflict`].
async fn create_user(
    ctx: &ImportContext<'_>,
    schema: Option<&TraitSchema>,
    prepared: PreparedCreate,
) -> Result<String, CreateError> {
    // Validate against the target scope's active schema when it HAS one (see
    // `import_stream`). A violating record is this record's failure and nothing else's:
    // the rest of the import proceeds, which is what a bulk restore needs.
    check_imported_traits(schema, prepared.traits_json.as_deref())?;
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
                // Traits are restored VERBATIM (issue #58): the document is sealed exactly
                // as the source instance held it, with no coercion, no defaulting, and no
                // re-serialization of its shape. It IS re-validated first when the target
                // scope serves an active schema (`check_imported_traits`, called at the
                // top of this function); a scope with NO active schema validates nothing,
                // which is the exit covenant's carve-out and the reason a full export
                // imports losslessly into a fresh instance. The
                // ADMIN class, because a restore is an operator action carrying the SOURCE
                // instance's own admin-only metadata: refusing the fields the operator is
                // restoring would make the round trip lossy by construction.
                traits: prepared
                    .traits_json
                    .as_deref()
                    .map(|traits_json| NewUserTraits {
                        traits_json,
                        schema_version: prepared.traits_schema_version,
                        visibility: TraitWriteVisibility::Admin,
                    }),
            },
            created_at,
            None,
        )
        .await;
    let id = match result {
        Ok(id) => id,
        // A duplicate id / external id / login handle: the scope's unique
        // constraints make a re-import idempotent (skip, never a second row). The
        // credentials are NOT re-enrolled on a skip, so a re-import cannot duplicate a
        // user's credential registry.
        Err(StoreError::Conflict) => return Err(CreateError::Conflict),
        Err(StoreError::NotFound) => {
            return Err(CreateError::Failed(
                "user id is not in this scope".to_owned(),
            ));
        }
        Err(_) => return Err(CreateError::Failed("persistence failure".to_owned())),
    };
    // Restore the user's enrolled credential registry (issue #58): each passkey /
    // TOTP / recovery-code enrollment is re-enrolled under the fresh user, sealing
    // the friendly name against the target scope's DEK and preserving the last-used
    // instant, so the exit export round-trips the full credential registry.
    restore_credentials(ctx, &id, &prepared.credentials).await?;
    // Restore the SECOND FACTOR (issue #58/#69): re-seal each TOTP seed under the
    // TARGET tenant's DEK so a re-imported factor verifies against the original
    // authenticator, and insert the recovery-code hashes so a re-imported code stays
    // redeemable. This is the exit covenant made real for MFA, not a metadata echo.
    restore_totp(ctx, &id, &prepared.totp).await?;
    restore_recovery_codes(ctx, &id, &prepared.recovery_codes).await?;
    Ok(id.to_string())
}

/// Re-enroll an imported user's credential registry (issue #58) through the audited,
/// subject-bound restore path. A credential-restore failure fails only THIS record
/// (the user is already created); the stream continues.
async fn restore_credentials(
    ctx: &ImportContext<'_>,
    subject: &UserId,
    credentials: &[PreparedCredential],
) -> Result<(), CreateError> {
    for credential in credentials {
        ctx.store
            .scoped(ctx.scope)
            .acting(ctx.actor, CorrelationId::generate(ctx.env))
            .account_credentials()
            .enroll_restored(
                ctx.env,
                subject,
                credential.credential_type,
                &credential.friendly_name,
                credential.last_used_at,
            )
            .await
            .map_err(|_| {
                CreateError::Failed("credential enrollment failed on restore".to_owned())
            })?;
    }
    Ok(())
}

/// Re-home an imported user's TOTP authenticators (issue #58/#69): re-seal each
/// exported seed under the TARGET scope's DEK and insert the row reproducing the
/// source status and single-use step, so a re-imported active factor verifies against
/// the ORIGINAL authenticator. A restore failure fails only THIS record.
async fn restore_totp(
    ctx: &ImportContext<'_>,
    subject: &UserId,
    factors: &[PreparedTotp],
) -> Result<(), CreateError> {
    for factor in factors {
        ctx.store
            .scoped(ctx.scope)
            .acting(ctx.actor, CorrelationId::generate(ctx.env))
            .totp_credentials()
            .restore(
                ctx.env,
                subject,
                &RestoredTotp {
                    seed: &factor.seed,
                    friendly_name: &factor.friendly_name,
                    algorithm: &factor.algorithm,
                    digits: factor.digits,
                    period_secs: factor.period_secs,
                    status: &factor.status,
                    last_consumed_step: factor.last_consumed_step,
                },
            )
            .await
            .map_err(|_| CreateError::Failed("totp restore failed".to_owned()))?;
    }
    Ok(())
}

/// Re-home an imported user's recovery codes (issue #58/#69): insert each carried
/// one-way hash with its consumed state, so a re-imported, still-unconsumed code stays
/// redeemable. A restore failure fails only THIS record.
async fn restore_recovery_codes(
    ctx: &ImportContext<'_>,
    subject: &UserId,
    codes: &[PreparedRecoveryCode],
) -> Result<(), CreateError> {
    if codes.is_empty() {
        return Ok(());
    }
    let restored: Vec<RestoredRecoveryCode> = codes
        .iter()
        .map(|code| RestoredRecoveryCode {
            code_hash: code.code_hash.clone(),
            consumed: code.consumed,
        })
        .collect();
    ctx.store
        .scoped(ctx.scope)
        .acting(ctx.actor, CorrelationId::generate(ctx.env))
        .recovery_codes()
        .restore_all(ctx.env, subject, &restored)
        .await
        .map_err(|_| CreateError::Failed("recovery-code restore failed".to_owned()))?;
    Ok(())
}

/// The pure streaming driver: pull lines lazily, parse and validate each, and hand a
/// prepared record to `create`, tallying and awaiting `on_record` for each outcome.
/// Generic over the line source, the create step, and the observer, so the parsing /
/// validation / streaming behavior is testable without a database.
///
/// TWO memory bounds, not one, and the second is the reason this signature is what it
/// is. The driver holds at most ONE line at a time (the input is never collected), and
/// it awaits the observer per record, so an observer that persists outcomes never has to
/// be handed the whole run at the end. The previous signature took a SYNCHRONOUS
/// observer, which forced the migration-run adapter to collect every translated outcome
/// into a `Vec` before it could ingest any of them: the engine was bounded and the
/// adapter above it was O(n).
async fn drive_import<N, C, F>(
    scope: Scope,
    mut lines: N,
    mut create: C,
    mut on_record: F,
) -> Result<ImportReport, StoreError>
where
    N: LineSource,
    C: RecordCreator,
    F: OutcomeSink,
{
    let mut report = ImportReport::default();
    while let Some(bytes) = lines.next_line().await {
        // The UTF-8 decision is the engine's, not the transport's: an undecodable line is
        // THIS record's failure, reported under a key derived from its own bytes, and the
        // stream continues.
        let line = match std::str::from_utf8(&bytes) {
            Ok(line) => line,
            Err(error) => {
                report.processed += 1;
                report.failed += 1;
                on_record
                    .record(RecordOutcome::Failed(RecordError {
                        key: undecodable_line_key(&bytes),
                        reason: format!(
                            "line is not valid UTF-8 (first invalid byte at offset {})",
                            error.valid_up_to()
                        ),
                    }))
                    .await?;
                continue;
            }
        };
        let record = match parse_record_line(line) {
            Ok(Some(record)) => record,
            // A blank separator line: not a record, not counted.
            Ok(None) => continue,
            Err(error) => {
                report.processed += 1;
                report.failed += 1;
                on_record
                    .record(RecordOutcome::Failed(RecordError {
                        key: undecodable_line_key(&bytes),
                        reason: format!("parse error: {}", error.message()),
                    }))
                    .await?;
                continue;
            }
        };
        report.processed += 1;
        let key = ledger_key(&record, &bytes);
        let prepared = match prepare_record(record, scope) {
            Ok(prepared) => prepared,
            Err(reason) => {
                report.failed += 1;
                on_record
                    .record(RecordOutcome::Failed(RecordError { key, reason }))
                    .await?;
                continue;
            }
        };
        match create.create(prepared).await {
            Ok(id) => {
                report.succeeded += 1;
                on_record.record(RecordOutcome::Created { key, id }).await?;
            }
            Err(CreateError::Conflict) => {
                report.skipped += 1;
                on_record.record(RecordOutcome::Skipped { key }).await?;
            }
            Err(CreateError::Failed(reason)) => {
                report.failed += 1;
                on_record
                    .record(RecordOutcome::Failed(RecordError { key, reason }))
                    .await?;
            }
        }
    }
    Ok(report)
}

/// The ledger subject one line is accounted under when the engine cannot get a login
/// handle out of it: a truncated SHA-256 of the line's own BYTES.
///
/// It has to be a property OF THE LINE, and the first cut made it the constant
/// `"<unparsable record>"`. Every malformed line in a run then shared one subject, and the
/// ledger's `ON CONFLICT (tenant, environment, run, subject_bidx) DO NOTHING` discarded
/// the second and every later one. MEASURED with two bad lines and one good against a
/// declared `source_total` of 3: `imported=1 failed=1 accounted=2`, one record short
/// FOREVER, so the count invariant could never be satisfied and the run could never
/// complete. It also refuted this module's own "nothing is silently dropped".
///
/// A digest of the bytes has both properties the subject needs. It is STABLE across
/// attempts, so a genuinely repeated bad line still dedups to one row on a resume; and it
/// is DISTINCT per distinct bad line, so two different bad lines are two accounted
/// failures. It is one-way, so it carries no PII out of the line it summarizes even though
/// the line itself may be full of it. Sixteen hex characters is 64 bits, whose birthday
/// collision probability across the ten million records the management route's largest
/// accepted `source_total` allows is under three in a million.
fn undecodable_line_key(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut key = String::from("unparsable-line:");
    for byte in &digest[..8] {
        write!(key, "{byte:02x}").expect("writing to a String never fails");
    }
    key
}

/// The stable ledger subject one PARSED record is accounted under: its LOGIN HANDLE,
/// trimmed exactly as the create path trims it.
///
/// The login handle is the only field of a record that is REQUIRED and therefore the only
/// one that cannot appear or disappear between two presentations of the same identity. The
/// first cut keyed on the id, else the external id, else the handle, which is stable only
/// while the SOURCE does not change. MEASURED: pass 1 delivers a record with no external
/// id; pass 2 resumes with the same identity now carrying one. The two passes account it
/// under two different subjects, `accounted` reaches 3 against a `source_total` of 2, and
/// `remainder == 0` can never hold again. The identity population stayed correct
/// throughout: only the ledger broke. Since the whole documented recovery procedure is
/// "post the source again", a key that survives only an UNCHANGED source is not a
/// resumability mechanism.
///
/// A record whose handle is blank has no usable subject and is a per-record failure
/// anyway ([`prepare_record`] refuses it, exactly as `POST .../users` does); it falls back
/// to the line digest so two blank-handle records stay two accounted failures rather than
/// one.
fn ledger_key(record: &ImportRecord, bytes: &[u8]) -> String {
    let handle = record.record_key();
    if handle.is_empty() {
        return undecodable_line_key(bytes);
    }
    handle.to_owned()
}

/// Require a field the MANAGEMENT EDGE requires: non-blank after trimming, returned
/// trimmed.
///
/// This is `ironauth_admin::input::require_non_empty` applied on the import path, and it
/// is here because the two paths were measurably disagreeing about what a login handle is.
/// MEASURED: `{"identifier":""}` is a 400 on `POST .../users` and was IMPORTED here, and
/// `" a@x.test "` was stored verbatim here and trimmed there, so the same login handle
/// written by the two writers produced two different rows. A bulk import writes the same
/// column through the same repository; it does not get its own idea of validity.
fn required_field(value: &str, field: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(trimmed.to_owned())
}

/// Parse and bounds-check one record into a [`PreparedCreate`], or return an
/// operator-safe reason it was rejected (issue #55). This is where the foreign-hash
/// denial-of-service bounds are enforced AT IMPORT, and where the management edge's own
/// input validation is applied so the two writers of a login handle agree.
fn prepare_record(record: ImportRecord, scope: Scope) -> Result<PreparedCreate, String> {
    let identifier = required_field(&record.identifier, "identifier")?;
    let external_id = match record.external_id.as_deref() {
        None => None,
        Some(raw) => Some(required_field(raw, "external_id")?),
    };
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
            let raw = required_field(raw, "password_hash")?;
            let parsed = ForeignHash::parse(&raw)
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
    let credentials = prepare_credentials(record.credentials)?;
    let totp = prepare_totp(record.totp)?;
    let recovery_codes = prepare_recovery_codes(record.recovery_codes)?;
    Ok(PreparedCreate {
        identifier,
        id,
        external_id,
        claims_json,
        traits_json,
        traits_schema_version: record.traits_schema_version,
        state,
        foreign_hash,
        foreign_algo,
        credentials,
        totp,
        recovery_codes,
    })
}

/// Validate the record's TOTP authenticators (issue #58/#69): decode each Base32 seed
/// to raw bytes, bounds-check the parameters exactly as the live enroll path and the
/// store CHECK constraints do (digits 6..=8, period 15..=60, a known RFC 6238 hash, a
/// known status, a 1 to 200 character friendly name), so a restored factor can never
/// carry a malformed seed or an out-of-range parameter. An invalid factor fails ONLY
/// its record, never the batch.
fn prepare_totp(totp: Option<Vec<crate::record::ImportTotp>>) -> Result<Vec<PreparedTotp>, String> {
    let Some(totp) = totp else {
        return Ok(Vec::new());
    };
    let mut prepared = Vec::with_capacity(totp.len());
    for factor in totp {
        let seed = ironauth_jose::base32_decode(&factor.seed_base32)
            .map_err(|_| "totp seed is not valid Base32".to_owned())?;
        if seed.is_empty() {
            return Err("totp seed must not be empty".to_owned());
        }
        if !matches!(factor.algorithm.as_str(), "SHA1" | "SHA256" | "SHA512") {
            return Err(format!("unknown totp algorithm: {}", factor.algorithm));
        }
        if !(6..=8).contains(&factor.digits) {
            return Err(format!("totp digits ({}) must be in 6..=8", factor.digits));
        }
        if !(15..=60).contains(&factor.period_secs) {
            return Err(format!(
                "totp period_secs ({}) must be in 15..=60",
                factor.period_secs
            ));
        }
        if !matches!(factor.status.as_str(), "active" | "pending") {
            return Err(format!("unknown totp status: {}", factor.status));
        }
        let name = factor.friendly_name.trim();
        if name.is_empty() || name.chars().count() > 200 {
            return Err("totp friendly_name must be 1 to 200 characters".to_owned());
        }
        prepared.push(PreparedTotp {
            seed,
            friendly_name: name.to_owned(),
            algorithm: factor.algorithm,
            digits: factor.digits,
            period_secs: factor.period_secs,
            status: factor.status,
            last_consumed_step: factor.last_consumed_step,
        });
    }
    Ok(prepared)
}

/// Validate the record's recovery codes (issue #58/#69): each carries a non-empty
/// one-way hash (never a plaintext code) and its consumed state. An invalid code fails
/// ONLY its record, never the batch.
fn prepare_recovery_codes(
    codes: Option<Vec<crate::record::ImportRecoveryCode>>,
) -> Result<Vec<PreparedRecoveryCode>, String> {
    let Some(codes) = codes else {
        return Ok(Vec::new());
    };
    let mut prepared = Vec::with_capacity(codes.len());
    for code in codes {
        if code.code_hash.trim().is_empty() {
            return Err("recovery code_hash must not be empty".to_owned());
        }
        prepared.push(PreparedRecoveryCode {
            code_hash: code.code_hash,
            consumed: code.consumed,
        });
    }
    Ok(prepared)
}

/// Validate the record's MFA / login credential enrollments (issue #58): every
/// factor kind must be in the closed [`CredentialType`] set and every friendly name
/// within 1 to 200 characters, exactly the bounds the live self-service enroll path
/// enforces, so a restored credential can never carry an unknown type or an oversized
/// name. An invalid credential fails ONLY its record, never the batch.
fn prepare_credentials(
    credentials: Option<Vec<crate::record::ImportCredential>>,
) -> Result<Vec<PreparedCredential>, String> {
    let Some(credentials) = credentials else {
        return Ok(Vec::new());
    };
    let mut prepared = Vec::with_capacity(credentials.len());
    for credential in credentials {
        let credential_type = CredentialType::parse(&credential.credential_type)
            .ok_or_else(|| format!("unknown credential type: {}", credential.credential_type))?;
        let name = credential.friendly_name.trim();
        if name.is_empty() || name.chars().count() > 200 {
            return Err("credential friendly_name must be 1 to 200 characters".to_owned());
        }
        prepared.push(PreparedCredential {
            credential_type,
            friendly_name: name.to_owned(),
            last_used_at: credential.last_used_at,
        });
    }
    Ok(prepared)
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ironauth_env::Env;
    use ironauth_store::{EnvironmentId, Scope, TenantId};

    use super::*;

    /// A creator double: runs `step` on each prepared record. The DB-free driver tests
    /// need a creator, and a trait needs a named implementor, so this is the one.
    struct MockCreator<S>(S);
    impl<S> RecordCreator for MockCreator<S>
    where
        S: FnMut(PreparedCreate) -> Result<String, CreateError> + Send,
    {
        async fn create(&mut self, prepared: PreparedCreate) -> Result<String, CreateError> {
            (self.0)(prepared)
        }
    }

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
            IterLines::new(lazy),
            MockCreator(move |prepared: PreparedCreate| {
                alive_for_create.fetch_sub(1, Ordering::SeqCst);
                Ok(format!("usr_{}", prepared.identifier))
            }),
            &mut CollectOutcomes::default(),
        )
        .await
        .expect("the observer never fails");

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
        let mut outcomes = CollectOutcomes::default();
        let report = drive_import(
            test_scope(),
            IterLines::new(lines.into_iter()),
            MockCreator(|prepared: PreparedCreate| Ok(format!("usr_{}", prepared.identifier))),
            &mut outcomes,
        )
        .await
        .expect("the observer never fails");

        // Three good records created, three bad ones failed, one blank skipped;
        // crucially the batch ran to the end past every failure.
        assert_eq!(report.processed, 6, "six non-blank lines");
        assert_eq!(report.succeeded, 3, "ok-1, ok-2, ok-3");
        assert_eq!(report.failed, 3, "malformed json, bad cost, bad state");
        let failures = outcomes
            .0
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
            IterLines::new(lines.into_iter()),
            MockCreator(|prepared: PreparedCreate| {
                if prepared.identifier == "dup" {
                    Err(CreateError::Conflict)
                } else {
                    Ok(format!("usr_{}", prepared.identifier))
                }
            }),
            &mut CollectOutcomes::default(),
        )
        .await
        .expect("the observer never fails");
        assert_eq!(report.succeeded, 1);
        assert_eq!(report.skipped, 1, "the duplicate is a skip, not a failure");
        assert_eq!(report.failed, 0);
    }

    /// A byte source, for the cases a `String` cannot express.
    struct ByteLines(std::vec::IntoIter<Vec<u8>>);
    impl LineSource for ByteLines {
        async fn next_line(&mut self) -> Option<Vec<u8>> {
            self.0.next()
        }
    }

    #[tokio::test]
    async fn every_unparseable_line_is_its_own_accounted_failure() {
        // The defect: keying every parse failure on one constant subject. The ledger
        // dedups on the subject, so the SECOND bad line and every later one was silently
        // discarded, `accounted` came up short of `source_total` forever, and the run
        // could never complete. MEASURED at `imported=1 failed=1 accounted=2` against a
        // declared 3.
        let lines = vec![
            line("{ not json at all"),
            line("{ also not json, differently"),
            line(r#"{"identifier":"ok@example.test"}"#),
        ];
        let mut outcomes = CollectOutcomes::default();
        let report = drive_import(
            test_scope(),
            IterLines::new(lines.into_iter()),
            MockCreator(|prepared: PreparedCreate| Ok(format!("usr_{}", prepared.identifier))),
            &mut outcomes,
        )
        .await
        .expect("the observer never fails");
        assert_eq!(report.processed, 3);
        assert_eq!(report.failed, 2);

        let keys: Vec<&str> = outcomes
            .0
            .iter()
            .filter_map(|outcome| match outcome {
                RecordOutcome::Failed(error) => Some(error.key.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert_ne!(
            keys[0], keys[1],
            "two DIFFERENT bad lines must be two different ledger subjects, or the second \
             is discarded by the ingest's conflict clause: {keys:?}"
        );
        for key in &keys {
            assert!(
                key.starts_with("unparsable-line:"),
                "the subject says what it is: {key}"
            );
        }
    }

    #[tokio::test]
    async fn a_repeated_bad_line_keeps_one_stable_key_across_attempts() {
        // The other half of the property: the key is a function of the LINE, so the same
        // bad line presented on a resume dedups to the one ledger row it already has.
        let bad = "{ not json at all";
        let first = undecodable_line_key(bad.as_bytes());
        let second = undecodable_line_key(bad.as_bytes());
        assert_eq!(first, second, "stable across attempts");
        assert_ne!(
            first,
            undecodable_line_key(b"{ not json at all "),
            "and sensitive to one trailing byte"
        );
    }

    #[tokio::test]
    async fn an_undecodable_line_fails_its_own_record_rather_than_being_rewritten() {
        // A Latin-1 identifier. Decoding it lossily (which the transport used to do)
        // created a user carrying U+FFFD who cannot log in, counted as imported, with no
        // error anywhere.
        let latin1 = b"{\"identifier\":\"caf\xe9@x.test\"}".to_vec();
        let good = br#"{"identifier":"ok@x.test"}"#.to_vec();
        let mut outcomes = CollectOutcomes::default();
        let report = drive_import(
            test_scope(),
            ByteLines(vec![latin1, good].into_iter()),
            MockCreator(|prepared: PreparedCreate| Ok(format!("usr_{}", prepared.identifier))),
            &mut outcomes,
        )
        .await
        .expect("the observer never fails");
        assert_eq!(report.processed, 2);
        assert_eq!(report.failed, 1, "the undecodable line fails, alone");
        assert_eq!(report.succeeded, 1, "and the stream continues");
        let Some(RecordOutcome::Failed(error)) = outcomes.0.first() else {
            panic!("the first outcome is the failure: {:?}", outcomes.0);
        };
        assert!(
            error.reason.contains("not valid UTF-8"),
            "the reason says what happened: {}",
            error.reason
        );
        // And no created record carries a replacement character.
        for outcome in &outcomes.0 {
            if let RecordOutcome::Created { id, .. } = outcome {
                assert!(!id.contains('\u{fffd}'), "{id}");
            }
        }
    }

    #[test]
    fn prepare_applies_the_management_edges_own_input_validation() {
        // `POST .../users` runs `require_non_empty` (which also TRIMS) on the identifier,
        // the external id, and the password hash. The import path ran none of it, so
        // `identifier: ""` was a 400 there and an IMPORT here, and `" a@x.test "` was
        // stored verbatim here and trimmed there: two writers of one column disagreeing
        // about what a login handle is.
        for (line, field) in [
            (r#"{"identifier":"   "}"#, "identifier"),
            (
                r#"{"identifier":"a@x.test","external_id":" "}"#,
                "external_id",
            ),
            (
                r#"{"identifier":"a@x.test","password_hash":"  "}"#,
                "password_hash",
            ),
        ] {
            let record = parse_record_line(line).expect("parse").expect("some");
            let error = prepare_record(record, test_scope())
                .expect_err("a blank required field is a per-record failure");
            assert_eq!(error, format!("{field} must not be empty"), "{line}");
        }
        // And the surviving values are TRIMMED, exactly as the live path stores them.
        let record = parse_record_line(r#"{"identifier":"  a@x.test  ","external_id":" crm-1 "}"#)
            .expect("parse")
            .expect("some");
        let prepared = prepare_record(record, test_scope()).expect("prepared");
        assert_eq!(prepared.identifier, "a@x.test");
        assert_eq!(prepared.external_id.as_deref(), Some("crm-1"));
    }

    #[tokio::test]
    async fn a_blank_handle_record_is_keyed_on_its_line_and_not_on_the_empty_string() {
        // Two records with blank handles are two failures, and they must not collapse into
        // one ledger subject any more than two unparseable lines do.
        let lines = vec![
            line(r#"{"identifier":"","external_id":"a"}"#),
            line(r#"{"identifier":"  ","external_id":"b"}"#),
        ];
        let mut outcomes = CollectOutcomes::default();
        let report = drive_import(
            test_scope(),
            IterLines::new(lines.into_iter()),
            MockCreator(|prepared: PreparedCreate| Ok(format!("usr_{}", prepared.identifier))),
            &mut outcomes,
        )
        .await
        .expect("the observer never fails");
        assert_eq!(report.failed, 2);
        let keys: Vec<&str> = outcomes
            .0
            .iter()
            .filter_map(|outcome| match outcome {
                RecordOutcome::Failed(error) => Some(error.key.as_str()),
                _ => None,
            })
            .collect();
        assert_ne!(keys[0], keys[1], "{keys:?}");
        assert!(keys.iter().all(|key| !key.is_empty()));
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
