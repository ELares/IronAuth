// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Postgres-backed [`HotState`]: the implementation that makes the accelerator optional
//! (issue #146).
//!
//! # What this is for
//!
//! The covenant is that IronAuth is complete on PostgreSQL alone. `ironauth-hot` declares one
//! classified interface for everything an accelerator could hold, and this is the implementation
//! that is ALWAYS THERE behind it. With IronCache attached, a use is faster; with IronCache
//! gone, the same call reaches here and answers correctly. That is the difference between an
//! accelerator and a dependency, and it is the reason Keycloak's Infinispan requirement is the
//! shape this project's covenant forbids.
//!
//! # It is a cache, and it is also the only copy
//!
//! Both, depending on the use, which is exactly what [`ironauth_hot::Class`] records. For
//! `JWKS` this table holds a render of keys that live elsewhere and losing it costs a read. For
//! `SINGLE_USE_MARKER` and `ROTATION_LOCK` there is nowhere else: their whole purpose is to be
//! the one place a claim is settled. That is why [`crate::repository::HotStateRepo`]'s
//! `put_if_absent` is a single guarded statement rather than a read and a write.
//!
//! # Migration 0226 says this quota does not exist, and 0226 cannot be corrected
//!
//! Three comments in `migrations/0226_hot_state.sql` are now FALSE:
//!
//! * on the `key` bound: "NOTHING OUTSIDE THE TESTS REACHES THIS TABLE YET" -- still true of the
//!   registry's uses, which have no production call sites, but no longer the whole story;
//! * on the `value` bound: "a quota on the NUMBER of rows is the other half of that defence and
//!   does not exist yet ... an anonymous flood is bounded in bytes per row and unbounded in
//!   rows". IT EXISTS. It is [`ironauth_hot::Reach::Anonymous`], enforced by
//!   [`crate::repository::HotStateRepo`] on every write, and a flood is bounded in rows per
//!   scope per use;
//! * on the `use_name` column: "The per-use sweep, per-use quota and per-use disable that #146
//!   also asks for would filter on this column, and NONE OF THEM EXIST YET". The per-use quota
//!   now exists and does filter on it, which also makes the sentence after it -- "the sweep that
//!   does exist is scope-wide and ignores it" -- half wrong: `sweep_expired` still is, but
//!   `prune_expired_for_use` is per use and is the one the quota drives.
//!
//! THE FILE CANNOT BE EDITED TO SAY SO. `migrate.rs` digests each migration's whole bytes,
//! comments included, so changing one makes every already-migrated database refuse to boot with
//! a checksum mismatch -- and `scripts/migration-immutability.sh` fails the build for exactly
//! that reason. A landed migration is a historical record of what was true when it ran, not a
//! document to be kept current.
//!
//! So the correction lives here, where the code it is about lives, and this paragraph is the
//! pointer a reader who started at the schema needs. The general lesson is worth stating once:
//! a comment in a migration should describe the SCHEMA, which cannot change under it, and not
//! the state of the code around it, which can.
//!
//! # This module is an ADAPTER and holds no SQL
//!
//! Every scoped statement in this crate lives in [`crate::repository`], which
//! `scripts/query-audit.sh` enforces by allowing exactly one module. So what is here is the part
//! that cannot live there: the foreign-trait implementation, the clock that supplies the instants
//! the repository takes as parameters, and the translation from [`crate::StoreError`] into the
//! errors the classification system acts on.

use std::sync::Arc;

use ironauth_env::{Clock, Env};
use ironauth_hot::{Answer, HotError, HotState, HotUse, Ttl};

use crate::{Scope, Store, StoreError};

/// How many rows one [`PgHotState::sweep_expired`] call may delete.
///
/// A sweep exists because a TTL makes a row UNREADABLE and not absent: a read filters expired
/// rows out, so correctness never waits on this, but disk does. Without a sweep the table grows
/// with every pre-authentication artifact any anonymous caller ever caused -- which is the Dex
/// #1292 shape, open since 2018.
///
/// BOUNDED PER CALL rather than "delete everything expired", and the reason is LOCK DURATION
/// rather than volume. An unbounded delete over a large backlog holds row locks on every row it
/// has touched until it commits, and holds one transaction open for as long as the scan takes;
/// a concurrent `put_if_absent` for one of those keys waits behind it. Batching does not reduce
/// the total work or the total WAL -- repeated transactions write somewhat MORE of both -- it
/// bounds how long any single lock is held and gives the sweep a place to stop.
///
/// A caller that wants the backlog gone calls it until it reports fewer rows than the bound.
pub const SWEEP_BATCH: i64 = 1_000;

/// The always-present [`HotState`], backed by the `hot_state` table.
///
/// # Scope
///
/// [`HotState`]'s methods take a use and a key and no tenant, because a caller holding one of
/// these already knows which tenant it is serving. So the SCOPE IS BOUND INTO THIS VALUE at
/// construction, and a key can never read across tenants no matter what a caller passes -- which
/// matters here more than in most places, because several of the registry's uses take a key an
/// unauthenticated request influenced.
///
/// # What actually isolates, measured rather than assumed
///
/// THE POLICY DOES. The three statements that FILTER rows -- the read, the delete and the
/// sweep -- also name the scope in their `WHERE` clause (the two writes bind it as the value
/// they insert instead), and an earlier version of this paragraph called those predicates the
/// filter and called RLS "the backstop". Deleting the scope predicate from the read and running the cross-tenant test
/// proved that backwards: the test still passed, because `hot_state_scope` reads the same
/// `ironauth.tenant_id` setting the scoped transaction pins, and applies whether or not the
/// statement repeats it.
///
/// `ENABLE` IS WHAT REACHES `ironauth_app`; `FORCE` IS FOR THE OWNER. The migration sets both,
/// and it is worth not confusing them: `ENABLE ROW LEVEL SECURITY` subjects every non-owner,
/// non-superuser role to the policy, which is the data-plane role this adapter runs as.
/// `FORCE` extends the same policy to the table's OWNER, who would otherwise bypass it -- the
/// backstop for migrations and for any tooling connecting as the owning role. Saying "FORCE is
/// why `ironauth_app` is filtered" would name the wrong one of the two.
///
/// The predicates are worth keeping: `sweep_expired` needs the leading scope columns to use
/// `hot_state_scope_expires_at` at all, and for the three single-row statements the primary key
/// is the access path, which also begins with the scope. But the ISOLATION claim rests on the
/// policy, so a change that touched the policy would be the one to worry about, not a tidy-up
/// of a `WHERE` clause. On the WRITE paths the bound scope is load-bearing in a different way:
/// it is the value being written, and the policy's `WITH CHECK` refuses a row that names
/// another tenant.
pub struct PgHotState {
    store: Arc<Store>,
    scope: Scope,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for PgHotState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written because neither field can be derived: `dyn Clock` is not `Debug`, and
        // `Store` has no `Debug` impl at all. The scope is the part that identifies which of
        // these a reader is looking at.
        f.debug_struct("PgHotState")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl PgHotState {
    /// Bind a store and a scope into a hot state.
    #[must_use]
    pub fn new(store: Arc<Store>, scope: Scope, env: &Env) -> Self {
        Self {
            store,
            scope,
            clock: env.clock_arc(),
        }
    }

    /// The instant every expiry comparison this module makes is measured against.
    fn now_unix_micros(&self) -> Result<i64, HotError> {
        let since_epoch = self
            .clock
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| HotError::Malformed)?;
        i64::try_from(since_epoch.as_micros()).map_err(|_| HotError::Malformed)
    }

    /// `now + ttl`, saturating rather than wrapping.
    ///
    /// A TTL long enough to overflow is a caller error, and the two ways to treat it are to
    /// refuse the write or to clamp it. CLAMPING, because the overflow point is roughly the year
    /// 294000 and an entry that expires then is one that never expires, which is what a caller
    /// asking for that TTL meant. Refusing would turn an absurd input into an error path that
    /// callers would handle by ignoring it.
    fn expires_at_unix_micros(now: i64, ttl: Ttl) -> i64 {
        let micros = i64::try_from(ttl.duration().as_micros()).unwrap_or(i64::MAX);
        now.saturating_add(micros)
    }

    /// What a store failure MEANS to a hot-state caller.
    ///
    /// # Why this is not all `Unavailable`
    ///
    /// [`HotError::Unavailable`] says "the accelerator is not answering", and a
    /// [`ironauth_hot::Class::Correctness`] use responds by going to its documented fallback --
    /// which, here, IS the database. A caller told `Unavailable` because it passed a 70 KiB
    /// value would retry the same oversized write against the same table for ever, and the
    /// operator would be reading a graph that says their database is down.
    ///
    /// [`StoreError::Conflict`] is what the repository reports for a CHECK violation. The table
    /// has four, and ALL FOUR are the caller's input rather than the deployment's state: an
    /// empty or over-long `use_name` (64 bytes), an empty or over-long `key` (512), a value
    /// past 64 KiB, and an empty scope component. The last cannot be reached through this type
    /// -- the scope is bound at construction from a [`Scope`], which cannot hold an empty id --
    /// but it is a CHECK on the same table, so a reader counting producers should find it named
    /// here rather than discover it. All of them are [`HotError::Malformed`]: no retry fixes
    /// them and no fallback answers them.
    ///
    /// # Exhaustive on purpose
    ///
    /// A `_ =>` arm here would silently absorb every variant added to [`StoreError`] later, and
    /// the default it absorbs them into is `Unavailable` -- the one that sends a correctness
    /// use to its fallback. [`StoreError::NotFound`] is the example that matters: no method on
    /// `HotStateRepo` returns it today (a missing row is `Ok(None)`, which is a hit-or-miss
    /// answer and not an error at all), and if one ever did, "not found" reaching a caller as
    /// "the store is unreachable" is precisely the confusion this function exists to prevent.
    /// Listing the variants makes that a compile error instead of a behaviour.
    // TWO ARMS WITH ONE BODY, kept apart on purpose. `Conflict`/`Invalid` are what this table
    // can actually produce; the long arm is everything that cannot reach this seam. Both answer
    // `Malformed`, and collapsing them would erase the distinction a reader needs to decide
    // whether a new variant belongs above or below -- which is the decision the exhaustive
    // match exists to force.
    #[allow(clippy::match_same_arms)]
    fn classify(error: &StoreError) -> HotError {
        match error {
            // THE CALLER'S INPUT, which is what every CHECK on this table is about. No retry
            // fixes these and no fallback answers them.
            StoreError::Conflict | StoreError::Invalid => HotError::Malformed,

            // THE CEILING, which is neither an outage nor bad input: the write was understood
            // and refused because this scope already holds as many entries for this use as
            // `Reach::Anonymous` allows (expired ones included: the ceiling bounds disk). A correctness use answers it the same way it answers an
            // outage -- by going to the fallback its declaration names -- but the two must not
            // be the same value, because an operator watching for an unreachable database would
            // otherwise be shown a tenant hitting a quota.
            StoreError::QuotaExceeded => HotError::QuotaExceeded,

            // NOT REACHABLE FROM THIS TABLE, and `Malformed` rather than `Unavailable` because
            // if one ever did surface here it would be a bug in `HotStateRepo`, not an
            // accelerator outage -- and sending a correctness use to "the store" when the store
            // is what just failed to make sense is the confusion `classify` exists to prevent.
            // `NotFound` is the one worth naming: a missing row on this seam is `Ok(None)`, a
            // miss rather than an error, so the repository never produces it.
            StoreError::NotFound
            | StoreError::IdempotencyConflict
            | StoreError::SelfApproval
            | StoreError::InvalidRedirectUri
            | StoreError::InvalidOrgContext
            | StoreError::InvitationMintCollision
            | StoreError::InvalidCustomDomain
            | StoreError::InvalidName
            | StoreError::InvalidIdentifier
            | StoreError::SchemaMalformed(_)
            | StoreError::TraitsInvalid(_)
            | StoreError::NoActiveTraitSchema
            | StoreError::JourneyInvalid(_)
            | StoreError::OrgGroupCycle
            | StoreError::OrgAuthPolicyInvalid(_)
            | StoreError::AuditUnclassified(_)
            | StoreError::OrgGroupDepthExceeded { .. }
            | StoreError::GuardrailViolation(_) => HotError::Malformed,

            // THE DEPLOYMENT'S STATE: the database is not answering, or this process cannot
            // talk to it correctly. These are the ones a class should act on.
            StoreError::Database(_)
            | StoreError::Migration(_)
            | StoreError::Encryption
            | StoreError::CutoverBlocked { .. }
            | StoreError::IllegalMigrationTransition { .. }
            | StoreError::RetentionGap => HotError::Unavailable,
        }
    }

    /// The repository this adapter drives.
    fn repo(&self) -> crate::repository::HotStateRepo<'_> {
        self.store.scoped(self.scope).hot_state()
    }

    /// The ceiling this use declares, paired with the instant "live" is judged against.
    ///
    /// READ OFF THE USE, never passed in. The whole point of the registry is that a ceiling is a
    /// property of the use rather than of the call site: a caller that could choose its own
    /// would be a caller that could choose not to have one, and the uses with a ceiling are
    /// exactly the ones an anonymous request can reach.
    fn quota_for(r#use: &'static HotUse, now_unix_micros: i64) -> crate::repository::HotStateQuota {
        crate::repository::HotStateQuota {
            per_scope_entries: r#use.per_scope_entry_quota(),
            now_unix_micros,
        }
    }

    /// Delete up to [`SWEEP_BATCH`] expired entries in this scope, reporting how many went.
    ///
    /// # Nothing calls this ONE yet, but expired rows are no longer left to accumulate
    ///
    /// There is still no scheduler, no scope enumerator, and no sweep interval, so this batched
    /// entry point has no caller. That used to mean expired rows accumulated indefinitely.
    ///
    /// IT NO LONGER DOES SO WITHOUT BOUND, which is a weaker statement than "it no longer does"
    /// and is the accurate one. A write against a use that declares
    /// [`ironauth_hot::Reach::Anonymous`] prunes that scope's dead rows for that use AT THE
    /// MOMENT THE CEILING IS REACHED, and retries. So the three uses an anonymous caller can
    /// flood collect their own garbage, driven by the pressure that would otherwise be the
    /// problem -- but only at the ceiling. BELOW IT NOTHING PRUNES, so a scope that churns and
    /// then goes quiet keeps its dead rows until it is busy again.
    ///
    /// The four uses only an authenticated caller reaches have no ceiling and so are never
    /// pruned by this path at all. Their entry counts are bounded by things that do not grow
    /// with traffic: the number of environments for `JWKS` and `TENANT_CONFIG`, the number of
    /// live tokens for `INTROSPECTION`, and the number of rotatable things for `ROTATION_LOCK`.
    ///
    /// This remains the right entry point for a scheduled sweep when one lands, because pressure
    /// is a poor scheduler for a store nobody is pushing on. And either way it is disk rather
    /// than correctness: an expired row is already invisible to a read and already claimable, by
    /// the statement rather than by any sweep having run.
    ///
    /// # Errors
    ///
    /// [`HotError::Unavailable`] if the database cannot be reached; [`HotError::Malformed`] if
    /// the clock is before the epoch.
    pub async fn sweep_expired(&self) -> Result<u64, HotError> {
        let now = self.now_unix_micros()?;
        self.repo()
            .sweep_expired(now, SWEEP_BATCH)
            .await
            .map_err(|error| Self::classify(&error))
    }
}

impl HotState for PgHotState {
    fn get<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let now = self.now_unix_micros()?;
            self.repo()
                .get(r#use.name(), key, now)
                .await
                .map_err(|error| Self::classify(&error))
        })
    }

    fn put<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> Answer<'a, ()> {
        Box::pin(async move {
            let now = self.now_unix_micros()?;
            self.repo()
                .put(
                    r#use.name(),
                    key,
                    value,
                    Self::expires_at_unix_micros(now, ttl),
                    Self::quota_for(r#use, now),
                )
                .await
                .map_err(|error| Self::classify(&error))
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> Answer<'a, bool> {
        Box::pin(async move {
            let now = self.now_unix_micros()?;
            self.repo()
                .put_if_absent(
                    r#use.name(),
                    key,
                    value,
                    Self::expires_at_unix_micros(now, ttl),
                    now,
                    Self::quota_for(r#use, now),
                )
                .await
                .map_err(|error| Self::classify(&error))
        })
    }

    fn delete<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, ()> {
        Box::pin(async move {
            self.repo()
                .delete(r#use.name(), key)
                .await
                .map_err(|error| Self::classify(&error))
        })
    }
}
