// SPDX-License-Identifier: MIT OR Apache-2.0

//! An accelerator in front of the durable tier (issue #146).

use crate::{Answer, HotState, HotUse, Ttl};

/// An optional accelerator in front of the tier that is always there.
///
/// # The covenant, made mechanical, and stated precisely enough to be false
///
/// IronAuth is complete on PostgreSQL alone. This type is where that stops being a promise and
/// becomes a control-flow property:
///
/// NO OUTCOME DEPENDS ON THE ACCELERATOR BEING AVAILABLE. Take it away, unplug it, or let it
/// fail every call, and the same code produces the same answers. That is the property the outage
/// tests measure by running one script against three accelerators and comparing.
///
/// AN AVAILABLE ACCELERATOR CAN SERVE A STALE VALUE, bounded by [`POPULATE_TTL_SECS`]. This is
/// the sentence the first version of this doc left out, and it said instead that no outcome
/// depends on the accelerator ANSWERING -- which is not true of any cache and was not true of
/// this one. A read served from `fast` is by definition a value the durable tier was not asked
/// about, and [`Tiered::get`] documents the three ways it can be out of date.
///
/// The two together are the honest claim: an accelerator cannot make an operation FAIL, and it
/// can make a read OLD for a bounded time. A use for which the second is unacceptable is a use
/// that should not be read through a cache, which is what its [`crate::Class`] is for.
///
/// # What each operation does, and why
///
/// READ: ask the accelerator; on a hit, answer. On a miss OR ANY ERROR, ask the durable tier,
/// and populate the accelerator with what it said IF IT SAID ANYTHING -- a miss is not cached,
/// because caching an absence would make the accelerator serve a "not found" it invented. An
/// accelerator that is down is therefore indistinguishable from one that is empty, which is the
/// only treatment that keeps the covenant: a read that propagated the accelerator's error would
/// be a read that needs it.
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
    ///
    /// # THE POPULATE CAN RESURRECT AN ENTRY A DELETE ALREADY REMOVED
    ///
    /// This method reads the durable tier and then writes the accelerator, and those are two
    /// separate await points. A `delete` that runs to completion in between -- durable row gone,
    /// accelerator entry gone because this populate has not written it yet -- is then UNDONE by
    /// the write that follows. A revocation can return `Ok` and the revoked value still be
    /// served afterwards, from an accelerator that is working perfectly.
    ///
    /// IT IS NOT FIXABLE AT THIS LAYER. Closing it needs a compare-and-set or a generation
    /// number, and [`HotState`] has neither by design: it is the interface a Postgres table and
    /// a RESP server both implement, and versioning is exactly the kind of thing they express
    /// differently. Re-reading after the populate narrows the window without closing it, at the
    /// cost of doubling the reads on every miss.
    ///
    /// SO IT IS BOUNDED INSTEAD, at [`POPULATE_TTL_SECS`] seconds by `cache_ttl`, and written
    /// down here so a reader deciding whether a use may be cached can see the actual worst case
    /// rather than an assurance. `a_populate_that_lands_after_a_delete_is_bounded_by_the_cap`
    /// drives the interleaving deterministically.
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
                // BOUNDED, because this type cannot see how long the durable copy has left.
                // `HotState::get` answers with bytes and no deadline, so any TTL chosen here is
                // a guess; making it short is what keeps the guess cheap. See `cache_ttl`.
                let _ = self
                    .fast
                    .put(r#use, key, value, Ttl::of(POPULATE_CEILING))
                    .await;
            }
            Ok(answer)
        })
    }

    /// Write to the durable tier, then to the accelerator; on a failed accelerator write,
    /// REMOVE whatever it is holding.
    ///
    /// # The removal is the whole correctness of this method
    ///
    /// An earlier version simply discarded the accelerator's failure, justified with "the value
    /// is durable, a later read finds it there and populates on the way back". That is true when
    /// the accelerator holds NOTHING for the key, and false in the case that matters. On an
    /// OVERWRITE it still holds the PREVIOUS value: the later read hits it, never reaches the
    /// durable tier, and serves the old value for as long as the earlier write's TTL had left.
    /// A signing-key rotation would keep serving the retired key set.
    ///
    /// So a failed write is followed by a delete, which converts a WRONG answer into a SLOW one:
    /// the entry is gone, the next read misses and re-reads the durable tier. If the delete
    /// fails too the stale entry survives, which is no worse than before and is bounded by
    /// [`POPULATE_TTL_SECS`] because that is the longest any accelerator entry lives.
    ///
    /// The caller is still told `Ok`: the value IS durable, and reporting an error for a write
    /// that succeeded would make it retry something that already happened.
    fn put<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> Answer<'a, ()> {
        Box::pin(async move {
            self.durable.put(r#use, key, value, ttl).await?;
            if self
                .fast
                .put(r#use, key, value, cache_ttl(ttl))
                .await
                .is_err()
            {
                let _ = self.fast.delete(r#use, key).await;
            }
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
                // THE MIRROR IS BOUNDED LIKE EVERY OTHER ACCELERATOR WRITE. It used the
                // CALLER's TTL, which for a sixty-second marker left a sixty-second window in
                // which a concurrent delete could be undone by this write landing after it. The
                // window is now the same bounded one every other path has.
                if self
                    .fast
                    .put(r#use, key, value, cache_ttl(ttl))
                    .await
                    .is_err()
                {
                    let _ = self.fast.delete(r#use, key).await;
                }
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
    /// THERE ARE RESIDUAL CASES, PLURAL, and an earlier version of this paragraph named one and
    /// called it "the" residual case. All of them are bounded by the same thing, which is why
    /// the bound is one constant:
    ///
    /// 1. An accelerator that SERVES READS WHILE REFUSING DELETES (a read-only replica, or one
    ///    that is full): the entry it holds is served until it lapses.
    /// 2. A POPULATE THAT LANDS AFTER THIS DELETE. [`Tiered::get`] reads the durable tier and
    ///    then writes the accelerator, and a delete that completes between those two steps is
    ///    undone by the write. The accelerator is perfectly healthy in this case; the race is in
    ///    the read path, and it is described there.
    /// 3. A DELETE ON ANOTHER NODE, for a shared accelerator: this process removes its durable
    ///    row and its own request's view, and another process's in-flight populate can still
    ///    resurrect the entry.
    ///
    /// What bounds all three is [`POPULATE_TTL_SECS`], because `cache_ttl` caps EVERY write into
    /// the accelerator at it. That is the argument for having one cap rather than three: the
    /// staleness story is one sentence instead of a case analysis.
    ///
    /// A use whose staleness window cannot be bounded by ten seconds is a use that should not be
    /// read through a cache at all, which is what its [`crate::Class`] is for.
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

/// What an accelerator entry's TTL is capped at: `min(what the caller asked, the ceiling)`.
///
/// # One rule for every write into the accelerator
///
/// `put` and the `put_if_absent` mirror go through this; the read-through populate writes the
/// ceiling directly, because it has no requested TTL to cap -- it is copying a value whose
/// remaining lifetime it cannot see. Either way NO write into the accelerator asks for longer
/// than the ceiling, so the type has ONE staleness bound rather than three. That bound is what every claim in this file
/// rests on, and it is worth being able to state in a sentence: NO ENTRY IN THE ACCELERATOR
/// OUTLIVES ITS WRITE BY MORE THAN [`POPULATE_TTL_SECS`] SECONDS.
///
/// The `min` matters as much as the ceiling. A caller asking for a one-second TTL must not have
/// its value cached for ten, so the cap never lengthens a lifetime -- it only shortens one.
///
/// # What it costs, and what it buys
///
/// It costs a re-read every [`POPULATE_TTL_SECS`] seconds for a key under constant traffic. It
/// buys the only bound available: [`HotState::get`] answers with bytes and no deadline, so this
/// layer cannot know how long a durable entry has left, and a long-lived accelerator copy of an
/// entry the durable tier has since changed or deleted would be stale for that whole time with
/// nothing to correct it.
fn cache_ttl(requested: Ttl) -> Ttl {
    if requested.duration() <= POPULATE_CEILING {
        requested
    } else {
        Ttl::of(POPULATE_CEILING)
    }
}

/// The ceiling [`cache_ttl`] caps at.
const POPULATE_CEILING: std::time::Duration = std::time::Duration::from_secs(POPULATE_TTL_SECS);

/// Seconds an accelerator entry may live, at most.
///
/// Short on purpose: it is the bound on every kind of staleness this type can produce, and
/// nothing here can measure the actual overhang, so the only way to keep it small is to keep
/// this small.
pub const POPULATE_TTL_SECS: u64 = 10;
