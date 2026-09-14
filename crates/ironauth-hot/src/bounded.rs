// SPDX-License-Identifier: MIT OR Apache-2.0

//! The stall bounds, enforced once rather than at every call site.

use std::time::Duration;

use crate::{HotError, HotState, HotUse, Ttl};

/// How long an operation may take before it is treated as not having answered.
///
/// # The numbers are Logto's, and the asymmetry is deliberate
///
/// Reads are bounded tight because a read that has not answered is a read the caller can do
/// itself: the store has the value, and waiting longer for the accelerator is strictly worse
/// than not having asked. Writes get longer because abandoning one leaves the entry unwritten,
/// and a caller that gave up too early turns every subsequent read into a miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    read: Duration,
    write: Duration,
}

impl Bounds {
    /// The shipped defaults: one second for a read, five for a write.
    #[must_use]
    pub const fn shipped() -> Self {
        Self {
            read: Duration::from_secs(1),
            write: Duration::from_secs(5),
        }
    }

    /// Bounds an operator chose.
    ///
    /// CLAMPED BELOW at a millisecond so a zero cannot make every operation a stall, which would
    /// read in a config file as "no limit" and behave as "never use the cache".
    #[must_use]
    pub fn new(read: Duration, write: Duration) -> Self {
        Self {
            read: read.max(Duration::from_millis(1)),
            write: write.max(Duration::from_millis(1)),
        }
    }

    /// The read bound.
    #[must_use]
    pub const fn read(self) -> Duration {
        self.read
    }

    /// The write bound.
    #[must_use]
    pub const fn write(self) -> Duration {
        self.write
    }
}

impl Default for Bounds {
    fn default() -> Self {
        Self::shipped()
    }
}

/// Any [`HotState`], time-boxed.
///
/// # A stalled READ is a miss FOR THE USES THAT CAN SURVIVE ONE
///
/// An earlier version of this wrapper answered every stalled read with `Ok(None)` and justified
/// it with "to a caller those are the same thing -- it goes to the store either way". That is
/// true of an accelerator and false of everything else, and the falsehood was not academic:
/// `PRE_AUTH_QUOTA` is declared fail-CLOSED, a miss on a quota counter reads as "nothing
/// outstanding", and the wrapper therefore admitted the request. The one use whose whole
/// argument is that it must refuse when the accelerator stops answering was made to fail open by
/// the layer above it -- and precisely under the load its own doc says is when it matters.
///
/// So the bound asks the use. [`crate::HotUse::proceeds_without_cache`] is exactly the question
/// "is a silent accelerator survivable here", and a use that answers no is told
/// [`HotError::Stalled`] so its caller can do what its class says. A wrapper that decided for
/// them would be a second classification, contradicting the declared one.
///
/// THE ACCELERATOR CASE IS UNCHANGED and is still the reason the translation exists at all: an
/// accelerator's caller goes to the store on a miss, so an error would make every such caller
/// write the same `Err(Stalled) => None` arm -- the arm somebody eventually writes differently.
///
/// # A stalled WRITE is an error for every use, and the asymmetry is the point
///
/// A write that did not land means a later read will miss, which for a
/// [`crate::Class::Correctness`] use is not an ordinary outcome: `put_if_absent` answering "you
/// got there first" when nothing was written is the double redemption the marker exists to
/// prevent. There is no class for which silently losing a write is right, so this one does not
/// ask.
pub struct Bounded<S> {
    inner: S,
    bounds: Bounds,
}

impl<S> Bounded<S> {
    /// Wrap `inner` with `bounds`.
    pub const fn new(inner: S, bounds: Bounds) -> Self {
        Self { inner, bounds }
    }

    /// The bounds in force.
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }

    /// The wrapped state.
    ///
    /// A caller reaching past the bound would be undoing the point of this type, so this exists
    /// for the OTHER direction: an implementation's own tests asking what actually reached it.
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: HotState> HotState for Bounded<S> {
    fn get<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, HotError>> + Send + 'a>,
    > {
        let bound = self.bounds.read;
        Box::pin(async move {
            match tokio::time::timeout(bound, self.inner.get(r#use, key)).await {
                Ok(answer) => answer,
                // THE USE DECIDES, not this wrapper. See the type's own doc: an accelerator's
                // caller goes to the store on a miss so the translation saves it an arm, and a
                // use that cannot survive a silent accelerator must be TOLD rather than handed
                // an answer that reads as "there is nothing there".
                Err(_) if r#use.proceeds_without_cache() => Ok(None),
                Err(_) => Err(HotError::Stalled),
            }
        })
    }

    fn put<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HotError>> + Send + 'a>>
    {
        let bound = self.bounds.write;
        Box::pin(async move {
            match tokio::time::timeout(bound, self.inner.put(r#use, key, value, ttl)).await {
                Ok(answer) => answer,
                Err(_) => Err(HotError::Stalled),
            }
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, HotError>> + Send + 'a>>
    {
        let bound = self.bounds.write;
        Box::pin(async move {
            match tokio::time::timeout(bound, self.inner.put_if_absent(r#use, key, value, ttl))
                .await
            {
                Ok(answer) => answer,
                // NEVER `Ok(false)` AND NEVER `Ok(true)`. A stalled claim is a claim whose
                // outcome is unknown, and both answers are assertions this wrapper cannot make:
                // `true` would let a second caller redeem what the first may already hold, and
                // `false` would refuse a caller that may in fact have won.
                Err(_) => Err(HotError::Stalled),
            }
        })
    }

    fn delete<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HotError>> + Send + 'a>>
    {
        let bound = self.bounds.write;
        Box::pin(async move {
            match tokio::time::timeout(bound, self.inner.delete(r#use, key)).await {
                Ok(answer) => answer,
                Err(_) => Err(HotError::Stalled),
            }
        })
    }
}
