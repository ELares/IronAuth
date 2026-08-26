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
    /// The runtime itself could not be built.
    ///
    /// A deployment or platform fault, not a hook outcome: no hook was involved, and no
    /// per-hook failure policy should fire on it. Distinct from [`Self::Invalid`], which is a
    /// statement about uploaded bytes that do not exist at that point.
    EngineUnavailable,
    /// The bytes are not a hook this deployment can run.
    ///
    /// A truncated upload, something that is not WebAssembly at all, or a precompiled artifact
    /// from a different engine. Distinct from [`Self::Unlinkable`] because the two read very
    /// differently in an audit log: "asked for a capability it was not granted" describes an
    /// attempted capability escape, and reporting a mistyped upload that way would put an
    /// accusation in the record where a parse error belongs.
    Invalid,
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
    /// The call site says the failure happened before guest code ran, but it does NOT say why,
    /// and a deadline can expire during instantiation: a component that takes longer to
    /// instantiate than its epoch allows raises `Trap::Interrupt` here, not on the call path.
    /// Binning that as [`AbortKind::Unlinkable`] would tell a failure policy that a hook asked
    /// for a capability it was not granted, which is both wrong and unfixable by the operator
    /// it is reported to. So the trap is consulted first and the call site only decides what is
    /// left.
    pub(crate) fn from_instantiate(error: wasmtime::Error) -> Self {
        let kind = match error.downcast_ref::<wasmtime::Trap>() {
            Some(wasmtime::Trap::OutOfFuel) => AbortKind::OutOfFuel,
            Some(wasmtime::Trap::Interrupt) => AbortKind::DeadlineExceeded,
            _ => AbortKind::Unlinkable,
        };
        Self::Aborted {
            kind,
            source: error,
        }
    }

    /// Classify a failure to build the runtime.
    pub(crate) fn from_engine(error: wasmtime::Error) -> Self {
        Self::Aborted {
            kind: AbortKind::EngineUnavailable,
            source: error,
        }
    }

    /// Classify a wasmtime error from compiling or loading bytes.
    ///
    /// Separate from [`Self::from_instantiate`] because nothing on this path is about
    /// capabilities: the bytes either are a component this engine can run or they are not.
    pub(crate) fn from_load(error: wasmtime::Error) -> Self {
        Self::Aborted {
            kind: AbortKind::Invalid,
            source: error,
        }
    }

    /// Rebuild an abort that was already decided, from its kind and its message.
    ///
    /// For a CACHED refusal. A component that fails import resolution fails it identically
    /// every time -- same bytes, same engine, same missing capability -- so a dispatch that
    /// remembers the answer avoids recompiling something that can never run. Remembering it
    /// means storing the classification and the text, because [`wasmtime::Error`] is not
    /// `Clone`, and handing them back means this.
    ///
    /// NOT a way to invent an abort. The kind must be one this crate already returned for these
    /// bytes; a caller that guesses is asserting a classification it did not measure.
    #[must_use]
    pub fn recalled(kind: AbortKind, reason: String) -> Self {
        Self::Aborted {
            kind,
            source: wasmtime::Error::msg(reason),
        }
    }

    /// Why the hook did not complete, if it was an abort rather than a decline.
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
                    AbortKind::Invalid => "could not be loaded",
                    AbortKind::EngineUnavailable => "could not run: the runtime is unavailable",
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

#[cfg(test)]
mod tests {
    use super::{AbortKind, HookError};

    /// Each constructor bins into its own kind.
    ///
    /// Unit tests rather than through the runtime, because `HookEngine::new` cannot be made to
    /// fail on a supported platform: without these, reverting `from_engine` to `Invalid` --
    /// exactly the defect the round-2 change fixed -- turns nothing red, and a failure policy
    /// would disable a hook for "malformed bytes" when the runtime itself was unavailable.
    #[test]
    fn each_constructor_bins_into_its_own_kind() {
        let message = || wasmtime::Error::msg("something went wrong");
        assert_eq!(
            HookError::from_engine(message()).abort_kind(),
            Some(AbortKind::EngineUnavailable),
            "a runtime that could not be built is not a hook outcome"
        );
        assert_eq!(
            HookError::from_load(message()).abort_kind(),
            Some(AbortKind::Invalid),
            "bytes that are not a hook are not a capability refusal"
        );
        assert_eq!(
            HookError::from_instantiate(message()).abort_kind(),
            Some(AbortKind::Unlinkable),
            "an instantiation failure with no trap is a capability refusal"
        );
        assert_eq!(
            HookError::Declined("no".to_owned()).abort_kind(),
            None,
            "a decline is not an abort"
        );
    }

    /// The three kinds render differently, so an audit line says which happened.
    #[test]
    fn the_kinds_do_not_read_alike() {
        let message = || wasmtime::Error::msg("x");
        let engine = HookError::from_engine(message()).to_string();
        let load = HookError::from_load(message()).to_string();
        let link = HookError::from_instantiate(message()).to_string();
        assert_ne!(engine, load);
        assert_ne!(load, link);
        assert_ne!(engine, link);
        assert!(
            link.contains("capability"),
            "a capability refusal must say so: {link}"
        );
        assert!(
            !load.contains("capability"),
            "a parse failure must NOT read as an attempted capability escape: {load}"
        );
    }
}
