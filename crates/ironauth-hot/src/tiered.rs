// SPDX-License-Identifier: MIT OR Apache-2.0

//! An accelerator in front of the durable tier (issue #146).

use crate::{Answer, HotState, HotUse, Ttl};

/// An optional accelerator in front of the tier that is always there.
///
/// # The covenant, made mechanical
///
/// IronAuth is complete on PostgreSQL alone. This type is where that stops being a promise and
/// becomes a control-flow property: every operation has a path that reaches `durable` and
/// succeeds, and no operation's outcome depends on `fast` answering. Attach an accelerator and
/// reads get quicker; take it away, unplug it, or let it fail every call, and the same code
/// produces the same answers.
///
/// # What each operation does, and why
///
/// READ: ask the accelerator; on a hit, answer. On a miss OR ANY ERROR, ask the durable tier,
/// and populate the accelerator with what it said. An accelerator that is down is therefore
/// indistinguishable from one that is empty, which is the only treatment that keeps the covenant
/// -- a read that propagated the accelerator's error would be a read that needs it.
///
/// WRITE: the durable tier FIRST, and only then the accelerator. The order is the whole
/// correctness argument: if the durable write fails, nothing is in the accelerator claiming
/// otherwise, and the caller is told. The reverse order leaves a populated cache in front of a
/// store that never got the value, which is a lie that outlives the request.
///
/// CLAIM: the durable tier, and ONLY the durable tier. See [`Tiered::put_if_absent`].
///
/// DELETE: both, durable first. The accelerator's failure is swallowed like every other, and
/// [`Tiered::delete`] explains why that is not the obvious answer and what bounds its cost.
///
/// # This type makes no use of [`crate::Class`], deliberately
///
/// A reader expecting the classification to appear here is expecting the wrong layer. `Class`
/// says what a CALLER should do when the hot state cannot answer; this type's entire job is to
/// make sure that situation does not arise from the accelerator alone. The two compose: with a
/// `Tiered`, the only way a caller sees an error is the durable tier failing, and that is the
/// case every `Class` is written about.
///
/// [`crate::Bounded`] does consult the class, for the one thing this cannot fix: a tier that
/// never answers at all.
#[derive(Debug, Clone, Copy)]
pub struct Tiered<F, D> {
    fast: F,
    durable: D,
}

impl<F, D> Tiered<F, D> {
    /// Put `fast` in front of `durable`.
    pub const fn new(fast: F, durable: D) -> Self {
        Self { fast, durable }
    }

    /// The accelerator.
    pub const fn fast(&self) -> &F {
        &self.fast
    }

    /// The tier that is always there.
    pub const fn durable(&self) -> &D {
        &self.durable
    }
}

impl<F: HotState, D: HotState> HotState for Tiered<F, D> {
    /// Read through: the accelerator, then the durable tier, populating on the way back.
    ///
    /// A POPULATE FAILURE IS DISCARDED. The read has its answer, and failing the call because
    /// the accelerator would not accept a copy of it would make an optional component decide a
    /// request -- which is the one thing this type exists to prevent.
    fn get<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            // AN ERROR IS A MISS, on this path only. The durable tier answers next either way,
            // so distinguishing "the accelerator is down" from "the accelerator does not have
            // it" would change nothing about what this returns and would give a caller a reason
            // to branch on the health of a component it is not supposed to know about.
            if let Ok(Some(hit)) = self.fast.get(r#use, key).await {
                return Ok(Some(hit));
            }

            let answer = self.durable.get(r#use, key).await?;

            if let Some(value) = answer.as_deref() {
                // POPULATED WITH THE USE'S OWN TTL, not with what the durable tier has left on
                // its copy. This type cannot see the remaining lifetime of a durable entry, and
                // inventing one would put an entry in the accelerator that outlives the thing it
                // caches. `populate_ttl` states the rule and its cost.
                let _ = self.fast.put(r#use, key, value, populate_ttl(r#use)).await;
            }
            Ok(answer)
        })
    }

    /// Write to the durable tier, then to the accelerator.
    ///
    /// The accelerator's failure is DISCARDED: the value is durable, a later read finds it there
    /// and populates on the way back, and reporting an error for a write that succeeded would
    /// make a caller retry a thing that already happened.
    fn put<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> Answer<'a, ()> {
        Box::pin(async move {
            self.durable.put(r#use, key, value, ttl).await?;
            let _ = self.fast.put(r#use, key, value, ttl).await;
            Ok(())
        })
    }

    /// Claim on the DURABLE TIER ONLY, then mirror the winner's value.
    ///
    /// # Why the accelerator never participates in the decision
    ///
    /// "Who got there first" has exactly one correct answer, and two stores cannot both produce
    /// it. If the accelerator were asked and it won, a caller would hold a claim recorded
    /// nowhere durable -- gone the moment the accelerator restarts, after which a second caller
    /// claims the same key and both believe they may spend the artifact. That is the double
    /// redemption [`crate::registry::SINGLE_USE_MARKER`] exists to prevent, reintroduced by the
    /// layer that was supposed to be optional.
    ///
    /// So the accelerator is not consulted, not written before the answer, and not allowed to
    /// change it. It is only told, AFTER the fact, what the durable tier decided -- and only
    /// when this caller won, because a caller that lost does not know what the winner stored and
    /// must not write its own value over it.
    ///
    /// THIS IS WHY A CLAIM IS NOT FASTER WITH AN ACCELERATOR ATTACHED. That is the correct
    /// trade and it is worth stating plainly: the operation whose whole purpose is to be
    /// authoritative is the operation an accelerator cannot speed up.
    fn put_if_absent<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> Answer<'a, bool> {
        Box::pin(async move {
            let won = self.durable.put_if_absent(r#use, key, value, ttl).await?;
            if won {
                let _ = self.fast.put(r#use, key, value, ttl).await;
            }
            Ok(won)
        })
    }

    /// Delete from the durable tier, then from the accelerator, reporting only the durable
    /// tier's failure.
    ///
    /// # This was written the other way first, and the covenant decided it
    ///
    /// The argument for REPORTING an accelerator's delete failure is real: an entry that
    /// survives there keeps being served, so a revocation whose delete was lost leaves a revoked
    /// token reading as active until the entry lapses, with a receipt saying otherwise.
    ///
    /// It loses to a stronger one. "With the accelerator unreachable, every flow completes
    /// correctly and only latency degrades" is the covenant and it is criterion 2 of #146; an
    /// unreachable accelerator that makes revocation RETURN AN ERROR is a flow that does not
    /// complete. The first version of this method failed exactly that test, and the failure was
    /// the design telling me the two rules could not both hold.
    ///
    /// # Why swallowing is safe in the case that matters
    ///
    /// AN ACCELERATOR THAT CANNOT ACCEPT A DELETE USUALLY CANNOT SERVE A READ EITHER, because
    /// the ordinary cause of both is that it is gone. A stale entry in an unreachable cache is
    /// not being read by anyone: [`Tiered::get`] treats its error as a miss and the durable tier
    /// answers correctly. So in the outage case the swallowed error costs nothing at all.
    ///
    /// THE RESIDUAL CASE IS AN ACCELERATOR THAT SERVES READS WHILE REFUSING DELETES -- a
    /// read-only replica, or one that is full. There the stale entry is served, and what bounds
    /// it is the TTL. That is not a consolation invented here: it is why
    /// [`crate::registry::INTROSPECTION`] is written with a seconds-scale TTL and says so, and a
    /// use whose staleness window cannot be bounded by a TTL is a use that should not be read
    /// through a cache.
    ///
    /// THE DURABLE DELETE HAPPENS FIRST and its failure IS returned, so a caller that sees an
    /// error knows the durable tier was the thing that failed.
    fn delete<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, ()> {
        Box::pin(async move {
            self.durable.delete(r#use, key).await?;
            let _ = self.fast.delete(r#use, key).await;
            Ok(())
        })
    }
}

/// The TTL a read-through populate writes into the accelerator.
///
/// # Why this is not the durable entry's remaining lifetime
///
/// Because [`HotState::get`] does not report one. It answers with bytes, not with bytes and a
/// deadline, and widening it so this one caller could copy a TTL would put a field on every
/// implementation for the sake of a layer above them.
///
/// So the populate uses a FIXED, SHORT ceiling instead. The cost is bounded and worth naming: an
/// entry the durable tier would have expired in one second can live in the accelerator for up to
/// [`POPULATE_TTL_SECS`] seconds after that. For an accelerator use that is a stale read for a
/// few seconds, which is the ordinary cost of caching and is why those uses are classified as
/// they are. For anything where it would not be acceptable, the answer is not a cleverer TTL
/// here: it is that a read-through cache is the wrong shape, and the use should be reaching the
/// durable tier directly.
fn populate_ttl(_use: &'static HotUse) -> Ttl {
    Ttl::of(std::time::Duration::from_secs(POPULATE_TTL_SECS))
}

/// Seconds a read-through populate lives in the accelerator.
///
/// Short on purpose: it bounds how long a populate can outlive the durable entry it copied, and
/// nothing here can measure that overhang, so the only way to keep it small is to keep this
/// small. Ten seconds costs a re-read every ten seconds for a key under constant traffic, which
/// is the cheap side of the trade.
pub const POPULATE_TTL_SECS: u64 = 10;
