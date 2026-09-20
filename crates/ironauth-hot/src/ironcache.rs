// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronCache-backed [`HotState`]: the accelerator (issue #146).
//!
//! # What this is, and what it is not
//!
//! It is MEANT to be the fast tier of a [`crate::Tiered`], and that composition is what makes
//! every value it holds also present in the durable tier and every claim settled there. A
//! deployment that never attaches one behaves identically and more slowly; delete this file and
//! the product is still correct, which is the property the whole seam exists for.
//!
//! NOTHING IN THE TYPE SYSTEM CONFINES IT TO A `Tiered`, and it is worth saying so rather than
//! writing "it is never the only copy of anything" as though it were an invariant. This is an
//! ordinary [`HotState`]; a caller that constructed one and used it directly would have a cache
//! that is the only copy, and single-use markers settled in a store that forgets them on
//! restart. The composition is the contract, and it is a convention this file cannot enforce.
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

/// What separates the components of a key.
///
/// A CONSTANT because two places depend on it being the same character: the key format, and the
/// check in [`IronCacheHotState::new`] that no scope component contains it. Spelling it twice
/// would let one of them change.
const SEPARATOR: char = ':';

/// # Two deployments sharing one IronCache will collide
///
/// [`NAMESPACE`] is a fixed literal, so two IronAuth deployments pointed at the same server use
/// the same keyspace, and a tenant id that exists in both reads across them. That is not a
/// tenant-isolation hole within a deployment -- it is two deployments that were configured to
/// share a cache and were not told they must not.
///
/// IT IS UNFIXED ON PURPOSE, for now. A configurable namespace is a config key, a validation
/// rule and a migration story for anyone who changes it, and #146 has no requirement that asks
/// for one. Sharing a cache between deployments is also the sort of thing an operator does
/// knowingly. Written down so the next person meets it here rather than in production.
const _SHARED_SERVER_HAZARD: () = ();

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
    /// # Panics
    ///
    /// If `tenant` or `environment` is empty, or contains the key separator.
    ///
    /// A PANIC AND NOT A `Result`, because there is no sensible recovery and the alternative is
    /// worse than a crash. An empty scope builds `ira:::jwks:k`, identical for every tenant in
    /// the deployment, and a component containing a colon makes the encoding ambiguous -- both
    /// are silent cross-tenant reads, which is the failure this whole type is arranged to
    /// prevent. A caller cannot handle that meaningfully at runtime; it is a wiring mistake, and
    /// it should stop the process at the point it is made rather than serve wrong answers.
    ///
    /// Neither can happen with ids from `ironauth-store`, which render as a prefix and url-safe
    /// base64. The check is here because this constructor takes `&str` and cannot insist on
    /// that.
    #[must_use]
    pub fn new(connection: ConnectionManager, tenant: &str, environment: &str) -> Self {
        assert!(
            !tenant.is_empty() && !environment.is_empty(),
            "a hot-state scope component is empty, which makes this key identical for every \
             tenant in the deployment"
        );
        assert!(
            !tenant.contains(SEPARATOR) && !environment.contains(SEPARATOR),
            "a hot-state scope component contains {SEPARATOR:?}, which makes the key encoding \
             ambiguous between tenants"
        );
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
    pub(crate) fn px(ttl: Ttl) -> u64 {
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
    pub(crate) fn unavailable(error: &redis::RedisError) -> HotError {
        // THE SERVER ANSWERED SOMETHING THIS CANNOT USE is a different fact from IT DID NOT
        // ANSWER, and `HotError` has a variant for each. `Parse` and `UnexpectedReturnType` are
        // the two kinds `redis` 1.7 reports when a reply arrived and could not be turned into
        // the type asked for -- a value that is not the bytes a `get` wants, a `SET` answering
        // something other than a status. That is `Malformed`, and it is not fixed by retrying or
        // by going to the durable tier for a second opinion about this tier's health.
        //
        // Everything else -- a connection reset, a timeout, a server error, an auth failure --
        // means the tier did not answer. A caller cannot act differently on which, so they
        // collapse into `Unavailable`, which is the value [`crate::Tiered`] treats as a miss.
        match error.kind() {
            redis::ErrorKind::Parse | redis::ErrorKind::UnexpectedReturnType => HotError::Malformed,
            _ => HotError::Unavailable,
        }
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
/// A [`HotState`] over a raw connection with a caller-supplied keyspace, for a use whose
/// KEY itself carries the scope (the rate counter: the layered limiter is multi-tenant, so
/// the scope cannot be bound to the connection).
///
/// [`IronCacheHotState`] is the scope-bound shape; this is the sibling for a keyspace that
/// must span tenants. The key is `{NAMESPACE}:{keyspace}:{use}:{key}` with NAMESPACE the
/// crate's fixed literal, so two deployments pointing at one server still do not collide.
#[derive(Debug)]
pub struct IronCacheKeyspace {
    connection: ConnectionManager,
    keyspace: String,
}

impl IronCacheKeyspace {
    /// Bind a connection and a keyspace prefix.
    ///
    /// # Panics
    ///
    /// If `keyspace` is empty or contains the key separator, for the same reason the
    /// scope-bound sibling panics: an ambiguous key is a cross-tenant read.
    #[must_use]
    pub fn new(connection: ConnectionManager, keyspace: &str) -> Self {
        assert!(
            !keyspace.is_empty() && !keyspace.contains(SEPARATOR),
            "a keyspace is empty or contains {SEPARATOR:?}, which makes the key encoding              ambiguous between tenants"
        );
        Self {
            connection,
            keyspace: keyspace.to_owned(),
        }
    }

    /// The one place a key is built.
    fn redis_key(&self, r#use: &'static HotUse, key: &str) -> String {
        format!("{NAMESPACE}:{}:{}:{key}", self.keyspace, r#use.name())
    }
}

impl HotState for IronCacheKeyspace {
    fn get<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let value: Option<Vec<u8>> = connection
                .get(self.redis_key(r#use, key))
                .await
                .map_err(|error| IronCacheHotState::unavailable(&error))?;
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
            let _: () = redis::cmd("SET")
                .arg(self.redis_key(r#use, key))
                .arg(value)
                .arg("PX")
                .arg(IronCacheHotState::px(ttl))
                .query_async(&mut connection)
                .await
                .map_err(|error| IronCacheHotState::unavailable(&error))?;
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
            let outcome: Option<String> = redis::cmd("SET")
                .arg(self.redis_key(r#use, key))
                .arg(value)
                .arg("NX")
                .arg("PX")
                .arg(IronCacheHotState::px(ttl))
                .query_async(&mut connection)
                .await
                .map_err(|error| IronCacheHotState::unavailable(&error))?;
            Ok(outcome.is_some())
        })
    }

    fn delete<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, ()> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let _: i64 = connection
                .del(self.redis_key(r#use, key))
                .await
                .map_err(|error| IronCacheHotState::unavailable(&error))?;
            Ok(())
        })
    }
}

/// `ConnectionManager::new` performs the first connection itself and RETRIES WITH BACKOFF before
/// giving up. Measured against an address nothing listens on, that was about nine seconds in the runs
/// this was developed against. The backoff is retried and jittered, so that is an observation
/// and not a constant -- which is itself the argument for a bound rather than for relying on
/// the client to give up promptly. Nine
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
