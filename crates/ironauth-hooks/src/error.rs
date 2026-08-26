// SPDX-License-Identifier: MIT OR Apache-2.0
//! What can go wrong running a hook, classified by what the host should DO about it.
//!
//! Criterion 3 asks that an abort apply "the documented per-hook failure policy". A policy
//! cannot be written against a single opaque error: "the hook ran out of fuel" and "the hook
//! returned a value we could not decode" call for different responses, and one of them is a
//! reason to stop invoking that hook at all. So the classification is part of the type rather
//! than something each caller re-derives by matching on a message.
//!
//! The classification is structural wherever it can be. [`AbortKind::Unlinkable`] is decided by
//! WHERE the failure happened, not by what it said: a component that fails to instantiate asked
//! for a capability the sandbox does not offer, and no string matching is involved. Fuel and
//! deadline come from wasmtime's own [`wasmtime::Trap`] variants.

/// A hook failed to compile, load, or run.
#[derive(Debug)]
pub enum HookError {
    /// The hook did not complete.
    Aborted {
        /// What stopped it, for the failure policy to act on.
        kind: AbortKind,
        /// The underlying error, for whoever reads the log.
        source: wasmtime::Error,
    },
    /// The hook ran to completion and returned an error of its own.
    ///
    /// Deliberately NOT an abort. A hook that declines has made a decision and has a reason to
    /// report; a hook that traps never got to decide. A failure policy that treated them alike
    /// would either fail logins on a deliberate refusal or ignore a runaway hook.
    Declined(String),
}

/// Why a hook did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortKind {
    /// The component asked for a host capability the sandbox does not offer.
    ///
    /// The hook never ran: this is decided at instantiation, before guest code executes. It is
    /// a DEPLOYMENT error rather than a runtime one, and it is the same answer every time, so a
    /// failure policy that retries is retrying something that cannot change.
    Unlinkable,
    /// The hook exhausted its instruction budget.
    ///
    /// Deterministic: the same hook on the same input exhausts the same budget every time. A
    /// hook that hits this is either genuinely too expensive or is looping.
    OutOfFuel,
    /// The hook was still running when its deadline passed.
    ///
    /// NOT deterministic, unlike fuel. A hook can hit this once under load and never again, so
    /// a policy that disables a hook permanently on one deadline is reacting to the machine
    /// rather than to the hook.
    DeadlineExceeded,
    /// The hook trapped.
    ///
    /// Includes a guest whose own allocator failed against the memory cap: a failed
    /// `memory.grow` is not a trap in itself, so a guest that cannot allocate aborts through
    /// whatever its language does about allocation failure. That is why this variant is not
    /// called `MemoryLimit`; the host cannot honestly tell the two apart from the trap alone.
    Trapped,
}

impl HookError {
    /// Classify a wasmtime error from the invocation path.
    pub(crate) fn from_call(error: wasmtime::Error) -> Self {
        let kind = match error.downcast_ref::<wasmtime::Trap>() {
            Some(wasmtime::Trap::OutOfFuel) => AbortKind::OutOfFuel,
            Some(wasmtime::Trap::Interrupt) => AbortKind::DeadlineExceeded,
            _ => AbortKind::Trapped,
        };
        Self::Aborted {
            kind,
            source: error,
        }
    }

    /// Classify a wasmtime error from instantiation.
    ///
    /// Everything that fails here failed before guest code ran, which is what
    /// [`AbortKind::Unlinkable`] means. Decided by the call site rather than by inspecting the
    /// message, so a change to wasmtime's wording cannot silently reclassify it.
    pub(crate) fn from_instantiate(error: wasmtime::Error) -> Self {
        Self::Aborted {
            kind: AbortKind::Unlinkable,
            source: error,
        }
    }

    /// What stopped the hook, or [`None`] if it declined.
    #[must_use]
    pub fn abort_kind(&self) -> Option<AbortKind> {
        match self {
            Self::Aborted { kind, .. } => Some(*kind),
            Self::Declined(_) => None,
        }
    }
}

impl core::fmt::Display for HookError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Aborted { kind, source } => {
                let what = match kind {
                    AbortKind::Unlinkable => "asked for a capability it was not granted",
                    AbortKind::OutOfFuel => "exhausted its fuel",
                    AbortKind::DeadlineExceeded => "passed its deadline",
                    AbortKind::Trapped => "trapped",
                };
                write!(f, "hook {what}: {source}")
            }
            Self::Declined(reason) => write!(f, "hook declined: {reason}"),
        }
    }
}

impl std::error::Error for HookError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Aborted { source, .. } => Some(source.as_ref()),
            Self::Declined(_) => None,
        }
    }
}
