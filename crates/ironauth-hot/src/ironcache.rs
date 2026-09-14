// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronCache-backed [`HotState`]: the accelerator (issue #146).
//!
//! # What this is, and what it is not
//!
//! It is the FAST tier of a [`crate::Tiered`], and nothing else. It is never the only copy of
//! anything: every value it holds is also in the durable tier, every claim is settled there, and
//! a deployment that never attaches one behaves identically and more slowly. If this file were
//! deleted the product would still be correct, which is the property the whole seam exists for.
//!
//! # Why a Redis client and not an IronCache one
//!
//! IronCache publishes no client crate -- its repository is server crates -- and it speaks RESP.
//! So the client here is the `redis` crate against IronCache's Redis-compatible surface, which
//! is also what makes the same code work against any RESP server an operator already runs.
//!
//! # The command mapping, measured rather than assumed
//!
//! Taken from a live `ironcache server` built from source, not from documentation:
//!
//! | Operation        | Command              | Reply on success | Reply otherwise |
//! |------------------|----------------------|------------------|-----------------|
//! | `get`            | `GET k`              | bulk string      | nil (a miss)    |
//! | `put`            | `SET k v PX <ms>`    | `+OK`            | an error        |
//! | `put_if_absent`  | `SET k v NX PX <ms>` | `+OK` (won)      | nil (lost)      |
//! | `delete`         | `DEL k`              | integer          | an error        |
//!
//! # The asymmetry with the Postgres implementation is real and is worth naming
//!
//! [`ironauth_store::hot_state::PgHotState`]'s claim is a guarded
//! `INSERT ... ON CONFLICT ... DO UPDATE ... WHERE expires_at <= now`, because in a table an
//! EXPIRED ROW IS STILL PRESENT until something deletes it, and the obvious `DO NOTHING` would
//! read a dead holder as a live one and refuse the claim for ever.
//!
//! HERE THAT TRAP DOES NOT EXIST: an expired key is absent, so `SET NX` claims it. One command
//! does what three SQL clauses do there. The two implementations are not symmetric and should
//! not be made to look it -- a reader comparing them should find the difference explained rather
//! than hidden.

use redis::AsyncCommands;
use redis::aio::ConnectionManager;

use crate::{Answer, HotError, HotState, HotUse, Ttl};

/// The namespace every key this process writes lives under.
///
/// Short, because it is paid on every key.
const NAMESPACE: &str = "ira";

/// An IronCache (or any RESP server) used as the fast tier.
///
/// # THE KEY PREFIX IS THE TENANT ISOLATION, and there is no backstop
///
/// This is the sharpest difference from the Postgres implementation and the thing to review
/// hardest. There, `hot_state` is `ENABLE ROW LEVEL SECURITY` and a policy filters every
/// statement whatever it says -- a scope predicate that was dropped by accident would be caught
/// by the database. A RESP keyspace is FLAT. Nothing here filters, nothing checks, and a key
/// built without its scope reads another tenant's value with no error anywhere.
///
/// So [`IronCacheHotState::redis_key`] is a security boundary written in string concatenation,
/// and the properties it needs are stated and tested rather than assumed:
///
/// * EVERY key carries its scope. There is one constructor for a key and no path around it.
/// * The encoding is INJECTIVE: two different (tenant, environment, use, key) tuples cannot
///   produce the same string. That holds because the first three components cannot contain the
///   separator -- tenant and environment render as `{prefix}_{url-safe base64}`, whose alphabet
///   is `A-Za-z0-9-_`, and a use name is checked to be lowercase alphanumeric and underscore by
///   `registry::tests::no_use_name_can_confuse_a_key`. The caller's key is LAST and may contain
///   anything, because everything after the fourth separator is it.
#[derive(Clone)]
pub struct IronCacheHotState {
    connection: ConnectionManager,
    tenant: String,
    environment: String,
}

impl std::fmt::Debug for IronCacheHotState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ConnectionManager` has no useful Debug and could carry a URL with credentials in it.
        f.debug_struct("IronCacheHotState")
            .field("tenant", &self.tenant)
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

impl IronCacheHotState {
    /// Bind a connection and a scope.
    ///
    /// The scope is BOUND HERE rather than passed per call for the same reason it is in the
    /// Postgres adapter: a caller holding one of these already knows which tenant it serves, and
    /// a per-call scope is a parameter a call site can get wrong.
    #[must_use]
    pub fn new(connection: ConnectionManager, tenant: &str, environment: &str) -> Self {
        Self {
            connection,
            tenant: tenant.to_owned(),
            environment: environment.to_owned(),
        }
    }

    /// The one place a key is built. See the type's doc for what this is.
    fn redis_key(&self, r#use: &'static HotUse, key: &str) -> String {
        format!(
            "{NAMESPACE}:{}:{}:{}:{key}",
            self.tenant,
            self.environment,
            r#use.name()
        )
    }

    /// Milliseconds for `PX`, floored at one.
    ///
    /// [`Ttl::of`] already clamps to at least a second, so this cannot round to zero from any
    /// TTL a caller can construct. It is written defensively anyway because a `PX 0` is rejected
    /// by the server, and an operation that failed because of an arithmetic edge would surface
    /// as [`HotError::Unavailable`] -- an accelerator outage that is not one.
    fn px(ttl: Ttl) -> u64 {
        u64::try_from(ttl.duration().as_millis())
            .unwrap_or(u64::MAX)
            .max(1)
    }

    /// Every redis error means the same thing here.
    ///
    /// AN ACCELERATOR IS EITHER ANSWERING OR IT IS NOT. A caller cannot act differently on a
    /// connection reset than on a timeout than on a server error: all three mean this tier did
    /// not answer, and [`crate::Tiered`] responds to all three by going to the durable tier.
    /// Splitting them would be a distinction with no consumer.
    fn unavailable(_error: &redis::RedisError) -> HotError {
        HotError::Unavailable
    }
}

impl HotState for IronCacheHotState {
    fn get<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let value: Option<Vec<u8>> = connection
                .get(self.redis_key(r#use, key))
                .await
                .map_err(|error| Self::unavailable(&error))?;
            Ok(value)
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
            let mut connection = self.connection.clone();
            // `SET ... PX` and never `SET` then `EXPIRE`: two commands are two round trips and a
            // window in which the key exists with NO expiry, which for a crash in between is an
            // entry that never goes away.
            let _: () = redis::cmd("SET")
                .arg(self.redis_key(r#use, key))
                .arg(value)
                .arg("PX")
                .arg(Self::px(ttl))
                .query_async(&mut connection)
                .await
                .map_err(|error| Self::unavailable(&error))?;
            Ok(())
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
            let mut connection = self.connection.clone();
            // NX AND PX IN ONE COMMAND, which is the whole reason this operation is cheap here.
            // The reply distinguishes the two outcomes without a second query: `+OK` means this
            // call set the key, and a nil bulk reply means one already existed.
            //
            // Note what is NOT needed: the expired-holder guard the Postgres implementation
            // must carry. An expired key is absent to `NX`, so a lapsed lease is claimable with
            // no special case.
            let outcome: Option<String> = redis::cmd("SET")
                .arg(self.redis_key(r#use, key))
                .arg(value)
                .arg("NX")
                .arg("PX")
                .arg(Self::px(ttl))
                .query_async(&mut connection)
                .await
                .map_err(|error| Self::unavailable(&error))?;
            Ok(outcome.is_some())
        })
    }

    fn delete<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, ()> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            // THE COUNT IS DISCARDED. `DEL` answers how many keys it removed, and zero means the
            // key was already gone -- which is the caller's goal already met, not a failure.
            let _: i64 = connection
                .del(self.redis_key(r#use, key))
                .await
                .map_err(|error| Self::unavailable(&error))?;
            Ok(())
        })
    }
}

/// Connect to `url` and return a manager that reconnects on its own.
///
/// # It returns a CONNECTION, not a [`IronCacheHotState`]
///
/// The first version of this returned a ready-made state with empty tenant and environment
/// strings for the caller to fill in later. That is a hole, not a convenience: an unfilled state
/// builds keys like `ira:::jwks:k`, identical for every tenant in the deployment, and nothing
/// downstream would notice. A type whose safety rests on a string prefix must not have a
/// constructor that produces one without it, so the only way to get a state is
/// [`IronCacheHotState::new`], which requires the scope.
///
/// # It is TIME-BOXED, because the client underneath is not
///
/// `ConnectionManager::new` performs the first connection itself and RETRIES WITH BACKOFF before
/// giving up. Measured against an address nothing listens on, that is about nine seconds. Nine
/// seconds is not a failure -- it eventually returns the right answer -- but it is nine seconds
/// of boot spent on a component this crate exists to make optional, which is the same "mandatory
/// by the back door" the paragraph below is about, arriving as latency instead of as an error.
///
/// So the wait is bounded at [`CONNECT_BOUND`] and a slower answer is
/// [`HotError::Unavailable`] -- the same value, sooner. An accelerator that could not be reached
/// in two seconds is one the deployment should start without and pick up later; the manager
/// reconnects on its own once it is handed to a caller.
///
/// # Errors
///
/// [`HotError::Unavailable`] if the URL cannot be parsed, the first connection fails, or it has
/// not succeeded within [`CONNECT_BOUND`].
///
/// # A failure here is not fatal to a deployment
///
/// The caller's correct response is to log and carry on with the durable tier alone, which is
/// what makes the accelerator optional at STARTUP and not only at runtime. A deployment that
/// refused to boot because its cache was down would have made the cache mandatory by the back
/// door.
pub async fn connect(url: &str) -> Result<ConnectionManager, HotError> {
    let client = redis::Client::open(url).map_err(|_| HotError::Unavailable)?;
    match tokio::time::timeout(CONNECT_BOUND, ConnectionManager::new(client)).await {
        Ok(Ok(connection)) => Ok(connection),
        Ok(Err(_)) | Err(_) => Err(HotError::Unavailable),
    }
}

/// How long [`connect`] waits before deciding the accelerator is not there.
///
/// Two seconds: long enough for a cache on the far side of a congested link, short enough that a
/// deployment booting with its accelerator down does not notice.
pub const CONNECT_BOUND: std::time::Duration = std::time::Duration::from_secs(2);
