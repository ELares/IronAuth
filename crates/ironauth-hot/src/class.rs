// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a hot-state use is allowed to lose, declared at the use rather than at the call.

/// What happens to a use when the accelerator cannot answer.
///
/// # Why this is not one policy for the whole cache
///
/// Losing a JWKS entry costs a database read. Losing a one-time-use marker can mean an
/// authorization code redeemed twice. A single "fail open" or "fail closed" switch over a cache
/// holding both is a switch that is wrong for one of them whichever way it is set, and the
/// deployment only finds out which under load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Safe to lose. A miss costs latency and nothing else.
    ///
    /// The caller must already be able to answer from the store, which is what makes this class
    /// safe: the accelerator is skipping work, never holding the only copy.
    Accelerator,

    /// Losing it weakens a control, and the deployment chooses which way that fails.
    ///
    /// THE RIGHT ANSWER IS A PROPERTY OF THE DEPLOYMENT rather than of the code. A rate counter
    /// that fails open lets a burst through; one that fails closed turns a cache outage into an
    /// outage. Neither is universally correct.
    ///
    /// SO WHAT IS THIS FIELD? It is the DEFAULT the code ships, and nothing more. Issue #146
    /// asks for "fail open with alerting or fail closed, PER CONFIG", and this slice does not
    /// deliver the config half: there is no operator input anywhere in this crate, so a
    /// deployment that wants the other answer currently edits [`crate::registry`] and rebuilds.
    /// An earlier version of this comment said the choice was the operator's, which read as a
    /// description of a surface that does not exist.
    ///
    /// The override belongs with the limiter that spends the counter (issue #150), because that
    /// is where an operator already configures the limits this would qualify; when it lands,
    /// this field becomes the default it starts from.
    LossyDegradesSecurity {
        /// What this use does when the accelerator is unavailable.
        on_loss: OnLoss,
    },

    /// Correctness depends on it, so it needs an atomic operation and a store-backed fallback.
    ///
    /// A USE IN THIS CLASS MAY NOT BE SERVED BY A BEST-EFFORT CACHE AT ALL. `put_if_absent` is
    /// the only primitive whose result a correctness use may act on, and when the accelerator is
    /// unavailable the caller must fall back to the store rather than proceed -- which is why
    /// [`HotUse::fallback`](crate::HotUse::fallback) is required for this class and refused for
    /// the others.
    Correctness,
}

/// What a security-sensitive use does when the accelerator cannot answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnLoss {
    /// Proceed without the cached signal. The control is weaker until the accelerator returns.
    FailOpen,
    /// Refuse. The control holds and the request does not.
    FailClosed,
}

/// One declared use of the hot-state interface.
///
/// # It is a value, not a string, and that is what the CI gate rests on
///
/// A caller passes a `&'static HotUse` from [`crate::registry`], and cannot construct one of its
/// own: [`HotUse::declare`] is visible only inside this crate, so for every OTHER crate -- which
/// is every call site the matrix is about -- the restriction is the privacy rule rather than a
/// convention anyone has to keep.
///
/// An earlier version of this comment said a call site "cannot construct one ... because
/// `HotUse::declare` is `const`". THAT WAS FALSE: `const fn` says a call CAN be evaluated at
/// compile time, not that it must be, and a runtime call is perfectly legal -- which would also
/// have turned the compile-time assertion below into a runtime panic in a live process. The
/// visibility does what the sentence claimed.
///
/// Inside this crate the compiler cannot express "registry.rs only", so
/// `scripts/hotstate-classification.sh` covers that last file-sized gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotUse {
    name: &'static str,
    class: Class,
    fallback: Option<&'static str>,
    reach: Reach,
}

/// Who can cause an entry for a use to exist.
///
/// # This is a STORAGE question, not a permission one
///
/// Nothing here decides what a caller may read or write; [`Class`] does that, and row-level
/// security does the rest. This answers one narrower question the class system cannot: CAN AN
/// ANONYMOUS REQUEST MAKE A ROW APPEAR? Because if it can, the number of rows is
/// attacker-controlled, and a store that answers every read correctly is still a store that
/// fills up.
///
/// That is the Dex #1292 shape: a pre-authentication flow-row denial of service, filed in 2018
/// and still open. It is neither exotic nor subtle -- unauthenticated endpoints mint artifacts,
/// nothing bounds how many, and the disk is the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Only an authenticated caller can cause an entry.
    ///
    /// The count is then bounded by whatever already limits that caller, and a second ceiling
    /// here would be a number nobody could choose well.
    Authenticated,
    /// An UNAUTHENTICATED request can cause an entry, so the count needs a ceiling.
    ///
    /// PER SCOPE and not per deployment, on purpose: a global cap would let one tenant's flood
    /// deny every other tenant the same store, turning a storage problem into a fairness problem,
    /// which is strictly worse.
    Anonymous {
        /// The most live entries one tenant-and-environment may hold for this use at once.
        per_scope_entries: u32,
    },
}

impl HotUse {
    /// Declare a use. See [`crate::registry`] for where these live and why.
    ///
    /// # Panics
    ///
    /// At COMPILE TIME, through a const assertion, when the class and the fallback disagree: a
    /// [`Class::Correctness`] use without a documented store fallback, or any other class with
    /// one. The pairing is the whole content of the classification -- a correctness use with no
    /// fallback is a use that proceeds on a cache it may not trust, and an accelerator with one
    /// is a use whose class is a mislabel.
    ///
    /// # Visibility
    ///
    /// `pub(crate)` ON PURPOSE. Every declaration belongs in [`crate::registry`], and a private
    /// constructor is the only version of that rule the compiler can hold on its own.
    #[must_use]
    pub(crate) const fn declare(
        name: &'static str,
        class: Class,
        fallback: Option<&'static str>,
        reach: Reach,
    ) -> Self {
        assert!(
            !matches!(
                reach,
                Reach::Anonymous {
                    per_scope_entries: 0
                }
            ),
            "a quota of zero is a use nothing can ever write; declare Authenticated instead"
        );
        assert!(
            matches!(
                (class, fallback.is_some()),
                (Class::Correctness, true)
                    | (
                        Class::Accelerator | Class::LossyDegradesSecurity { .. },
                        false
                    )
            ),
            "a Correctness use needs a documented store fallback and no other class may have one"
        );
        Self {
            name,
            class,
            fallback,
            reach,
        }
    }

    /// Who can cause an entry for this use, and the per-scope ceiling if that is anyone.
    #[must_use]
    pub const fn reach(&self) -> Reach {
        self.reach
    }

    /// The per-scope ceiling on live entries, or [`None`] when only an authenticated caller can
    /// cause one.
    ///
    /// A caller enforcing this does NOT need to know why the number is what it is; it needs to
    /// know whether there is one. Returning an `Option` rather than a sentinel means a use with
    /// no ceiling cannot be compared against accidentally.
    #[must_use]
    pub const fn per_scope_entry_quota(&self) -> Option<u32> {
        match self.reach {
            Reach::Authenticated => None,
            Reach::Anonymous { per_scope_entries } => Some(per_scope_entries),
        }
    }

    /// The stable name this use is keyed and reported under.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// What this use is allowed to lose.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// Where a [`Class::Correctness`] use goes when the accelerator cannot answer.
    #[must_use]
    pub const fn fallback(&self) -> Option<&'static str> {
        self.fallback
    }

    /// Whether an unavailable accelerator lets this use proceed.
    ///
    /// # The three classes answer differently and the differences are the point
    ///
    /// An accelerator proceeds: the store has the answer. A security-sensitive use proceeds only
    /// if the operator said so. A correctness use NEVER proceeds on the cache's silence -- it
    /// takes its documented fallback, which is a different code path rather than a weaker
    /// version of this one.
    #[must_use]
    pub const fn proceeds_without_cache(&self) -> bool {
        match self.class {
            Class::Accelerator => true,
            Class::LossyDegradesSecurity { on_loss } => matches!(on_loss, OnLoss::FailOpen),
            Class::Correctness => false,
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn each_class_decides_for_itself_whether_a_silent_cache_is_survivable() {
        // THE TABLE IS THE CLASSIFICATION. A single policy over a cache holding all four is
        // wrong for at least one of them whichever way it is set.
        //
        // ON REAL REGISTRY ENTRIES rather than uses invented here, and not only for tidiness:
        // `scripts/hotstate-classification.sh` forbids a declaration outside the registry, so a
        // test that minted its own would either defeat the gate or force an exemption -- and an
        // exemption is how a gate stops catching the thing it is for. Using the real entries
        // also means this test measures the classification a deployment actually has.
        use crate::registry;

        assert!(registry::JWKS.proceeds_without_cache(), "an accelerator");
        assert!(registry::RATE_COUNTER.proceeds_without_cache(), "fail open");
        assert!(
            !registry::PRE_AUTH_QUOTA.proceeds_without_cache(),
            "fail closed"
        );
        // A CORRECTNESS USE NEVER PROCEEDS on silence, whatever an operator would prefer: it has
        // somewhere else to go, and that is what the fallback records.
        assert!(!registry::SINGLE_USE_MARKER.proceeds_without_cache());
        assert!(registry::SINGLE_USE_MARKER.fallback().is_some());
    }
}
