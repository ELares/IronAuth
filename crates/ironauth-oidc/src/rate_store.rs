// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronCache-backed SHARED (L2) bucket tier for the layered limiter (issue #150
//! criterion 5).
//!
//! [`ironauth_quota::layered::SharedRateStore`] is the seam; this is the production
//! implementation over the `ironauth_hot` accelerator. Two nodes whose limiters share one
//! of these charge ONE budget: the bucket state lives in the cache, and every admit is a
//! read-modify-write of it.
//!
//! # The fail-open class, and who reports it
//!
//! The rate counter's [`Class`] is fail-open by declaration (`ironauth_hot`'s
//! `RATE_COUNTER`): a cache that cannot answer must cost cross-node accuracy, never an
//! admission or a refusal. This impl maps every cache failure to the seam's
//! `Unavailable` answers, the limiter falls back to its local (L1) bucket, and the
//! outcome's `shared_fell_back` carries the alert.

use ironauth_hot::{HotState, Ttl};
use ironauth_quota::layered::{BucketState, SharedRateStore, SharedRead, SharedWrite};

/// The TTL of a shared bucket.
///
/// A bucket expires after it has been idle for a while, so a key whose traffic has stopped
/// does not accumulate in the cache forever; a spend after expiry starts the bucket full,
/// exactly as a first spend anywhere does. The window is comfortably above the longest
/// plausible refill-to-full time for the limits an operator configures; it is a leak bound,
/// not a semantics.
const BUCKET_TTL_SECS: u64 = 3_600;

/// The shared-rate store over the accelerator, attached to a limiter's buckets.
pub struct HotSharedRates {
    hot: std::sync::Arc<dyn HotState>,
}

impl std::fmt::Debug for HotSharedRates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotSharedRates").finish_non_exhaustive()
    }
}

impl HotSharedRates {
    /// Wrap an accelerator (the keyspace-bound [`ironauth_hot::ironcache::IronCacheKeyspace`],
    /// or the `Tiered` composition).
    #[must_use]
    pub fn new(hot: std::sync::Arc<dyn HotState>) -> Self {
        Self { hot }
    }
}

impl SharedRateStore for HotSharedRates {
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SharedRead> + Send + 'a>> {
        Box::pin(async move {
            match self
                .hot
                .get(&ironauth_hot::registry::RATE_COUNTER, key)
                .await
            {
                Ok(Some(bytes)) => match BucketState::decode(&bytes) {
                    // An unreadable payload is a miss: the bucket starts full, which is the
                    // safe direction, and the next spend overwrites the foreign bytes.
                    Some(state) => SharedRead::Some(state),
                    None => SharedRead::None,
                },
                Ok(None) => SharedRead::None,
                Err(_) => SharedRead::Unavailable,
            }
        })
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        state: &'a BucketState,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SharedWrite> + Send + 'a>> {
        let bytes = state.encode();
        Box::pin(async move {
            match self
                .hot
                .put(
                    &ironauth_hot::registry::RATE_COUNTER,
                    key,
                    &bytes,
                    Ttl::of(std::time::Duration::from_secs(BUCKET_TTL_SECS)),
                )
                .await
            {
                Ok(()) => SharedWrite::Ok,
                Err(_) => SharedWrite::Unavailable,
            }
        })
    }
}
