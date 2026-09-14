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
/// BOUNDED PER CALL rather than "delete everything expired". An unbounded delete over a backlog
/// takes row locks proportional to the backlog, writes one enormous WAL record, and blocks the
/// live traffic it is meant to be cleaning up for. A bounded sweep called repeatedly does the
/// same work in pieces that each finish, and a caller that wants the backlog gone calls it until
/// it reports fewer rows than the bound.
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
/// ROW-LEVEL SECURITY DOES. Every statement in the repository ALSO names the scope in its
/// `WHERE` clause, and an earlier version of this paragraph called that the filter and called
/// RLS "the backstop". Deleting the scope predicate from the read and running the cross-tenant
/// test proved that backwards: the test still passed, because `hot_state` is `FORCE ROW LEVEL
/// SECURITY` and the policy reads the same `ironauth.tenant_id` setting the scoped transaction
/// pins.
///
/// The predicates are worth keeping -- they let the planner use `hot_state_scope_expires_at`
/// directly -- but the ISOLATION claim rests on the policy, so a change that touched the policy
/// would be the one to worry about, not a tidy-up of a `WHERE` clause. On the WRITE paths the
/// bound scope is load-bearing in a different way: it is the value being written, and the
/// policy's `WITH CHECK` refuses a row that names another tenant.
pub struct PgHotState {
    store: Arc<Store>,
    scope: Scope,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for PgHotState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn Clock` is not `Debug` and the store's own is enormous; the scope is the part
        // that identifies which of these a reader is looking at.
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
    /// [`StoreError::Conflict`] is what the repository reports for a CHECK violation, which on
    /// this table means the caller's input is out of bounds: a key past 512 bytes or a value
    /// past 64 KiB, both of which it refuses on purpose because unauthenticated traffic can
    /// influence them. That is [`HotError::Malformed`], which no retry fixes and no fallback
    /// answers.
    fn classify(error: &StoreError) -> HotError {
        match error {
            StoreError::Conflict => HotError::Malformed,
            _ => HotError::Unavailable,
        }
    }

    /// The repository this adapter drives.
    fn repo(&self) -> crate::repository::HotStateRepo<'_> {
        self.store.scoped(self.scope).hot_state()
    }

    /// Delete up to [`SWEEP_BATCH`] expired entries in this scope, reporting how many went.
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
