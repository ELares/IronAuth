// SPDX-License-Identifier: MIT OR Apache-2.0

//! The interface itself.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::HotUse;

/// How long a written entry stays useful.
///
/// EVERY WRITE CARRIES ONE. There is no unbounded put, because an accelerator holding an entry
/// nothing expires is a store with no schema and no migration -- and pre-auth artifacts with no
/// TTL are the shape of Dex #1292, a storage exhaustion open since 2018.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl(Duration);

impl Ttl {
    /// A time to live, clamped to at least one second.
    ///
    /// A ZERO TTL IS A WRITE THAT IS ALREADY GONE, which reads at the call site as "cache this"
    /// and behaves as "do not". Clamping rather than refusing keeps a caller's arithmetic from
    /// turning into an error path it would have to handle and would handle by ignoring.
    #[must_use]
    pub fn of(duration: Duration) -> Self {
        Self(duration.max(Duration::from_secs(1)))
    }

    /// The duration, for an implementation to apply.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// Why a hot-state operation did not answer.
///
/// # There is no "not found" here, and that is deliberate
///
/// A miss is `Ok(None)`, because a caller must treat a miss as an ordinary outcome. An `Err` is
/// the accelerator failing to answer AT ALL, which is the thing a [`crate::Class`] decides what
/// to do about -- and collapsing the two would let a caller's `?` turn a routine miss into a
/// refused request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotError {
    /// The operation outran its bound. See [`crate::Bounded`].
    Stalled,
    /// The accelerator is not reachable.
    Unavailable,
    /// The accelerator answered, and the answer was not usable.
    Malformed,
    /// This scope already holds as many live entries for this use as it is allowed.
    ///
    /// # Not a failure of the accelerator, and not the caller's input either
    ///
    /// The other three variants say the accelerator could not answer or answered nonsense. This
    /// one says it WORKED and refused, because [`crate::Reach::Anonymous`] declares a ceiling on
    /// how many live entries one scope may hold for a use an unauthenticated request can cause,
    /// and the ceiling is reached.
    ///
    /// A caller must not retry it. A caller for a [`crate::Class::Correctness`] use must go to
    /// the fallback its declaration names, exactly as for [`HotError::Unavailable`] -- the
    /// decision that use makes is still owed an answer, and the quota is about disk rather than
    /// about the decision.
    QuotaExceeded,
}

/// What every [`HotState`] method returns: a boxed future, because the trait is used behind
/// `dyn` and a bare `async fn` in a trait is not `dyn`-safe.
///
/// PUBLIC BECAUSE AN IMPLEMENTOR NEEDS TO NAME IT. It was private when this crate shipped,
/// which meant every implementation outside `ironauth-hot` -- the Postgres one, the IronCache
/// one, and every test fake -- had to spell out the whole `Pin<Box<dyn Future<Output = ...>>>`
/// four times. That was not a deliberate restriction; it was an export nobody had needed yet.
pub type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, HotError>> + Send + 'a>>;

/// Hot state an accelerator may hold and Postgres always can.
///
/// # `&HotUse` on every method, which is the whole design
///
/// It is not a convenience for metrics. A use that cannot be named cannot be classified, and a
/// call that does not name one cannot be reviewed -- so the parameter is what makes
/// `scripts/hotstate-classification.sh` able to say that every use of this interface has
/// declared what it is allowed to lose.
///
/// # Bytes rather than a serialized type
///
/// What goes in an accelerator is decided by the caller that owns the meaning. A trait that took
/// a `Serialize` would put this crate in the business of versioning everybody else's payloads,
/// and a stored value whose shape changed under a running deployment is a defect this layer
/// cannot see and cannot fix.
pub trait HotState: Send + Sync {
    /// Read, or `Ok(None)` for a miss.
    fn get<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, Option<Vec<u8>>>;

    /// Write, replacing whatever was there.
    fn put<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> Answer<'a, ()>;

    /// Write ONLY if the key is absent, answering whether this call is the one that wrote.
    ///
    /// # The only primitive a correctness use may act on
    ///
    /// `get`-then-`put` is two operations and a race between them; this is one. A one-time-use
    /// marker, a device-code redemption, a rotation lock -- each is a question of who got there
    /// first, and only an atomic answer settles it.
    ///
    /// AN IMPLEMENTATION THAT CANNOT DO THIS ATOMICALLY MUST RETURN [`HotError::Unavailable`]
    /// rather than approximating it. A best-effort answer here is worse than none: the caller
    /// would act on it, and a [`crate::Class::Correctness`] use acting on a wrong answer is the
    /// double redemption the marker exists to prevent.
    fn put_if_absent<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> Answer<'a, bool>;

    /// Remove, whether or not it was there.
    fn delete<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, ()>;
}
