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
    /// THE CHOICE IS THE OPERATOR'S because the right answer is a property of the deployment
    /// rather than of the code. A rate counter that fails open lets a burst through; one that
    /// fails closed turns a cache outage into an outage. Neither is universally correct, and a
    /// library that picked one would be picking for every deployment.
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
/// A caller passes a `&'static HotUse` from [`crate::registry`]. It cannot construct one at a
/// call site, because [`HotUse::declare`] is `const` and the gate greps for uses declared
/// anywhere but the registry -- so "every trait use is classified" is checked by the build
/// rather than asserted in a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotUse {
    name: &'static str,
    class: Class,
    fallback: Option<&'static str>,
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
    #[must_use]
    pub const fn declare(name: &'static str, class: Class, fallback: Option<&'static str>) -> Self {
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
