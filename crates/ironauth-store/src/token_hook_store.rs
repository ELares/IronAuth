// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deployed WASM token hooks (issue #114).
//!
//! The persistence shape only. What a hook DOES lives in `ironauth-hooks`, which this crate
//! cannot depend on and does not need to: from here a hook is bytes and a version number.
//!
//! # Why the component travels as bytes rather than a precompiled artifact
//!
//! `HookEngine::compile` produces machine code for the exact engine, wasmtime version, CPU
//! features and flags that produced it, and `load_precompiled` is `unsafe` because nothing
//! checks that. A precompiled artifact in a shared database is a portability hazard with a
//! memory-safety failure mode: a replica on a different CPU deserializes machine code built for
//! something else. So the durable form is the portable one, and each process compiles what it
//! loads.

/// One deployed hook: the component, and the payload version its guest was built against.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenHookRecord {
    /// The OAuth client whose tokens this hook shapes, unique per scope.
    pub client_id: String,
    /// The WASM component.
    pub component: Vec<u8>,
    /// The payload version the guest expects (issue #113 criterion 6).
    pub payload_version: i32,
}

/// Hand-written, and the component is rendered as a LENGTH.
///
/// A derived `Debug` would put megabytes of WASM into any log line that formats a record, and
/// the bytes are the one field nobody reading a log wants. What a reader needs is which client,
/// which version, and whether the component is the size they deployed.
impl std::fmt::Debug for TokenHookRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenHookRecord")
            .field("client_id", &self.client_id)
            .field("component_bytes", &self.component.len())
            .field("payload_version", &self.payload_version)
            .finish()
    }
}

/// A deployed hook's metadata, without the component (issue #114).
///
/// The management read reports a LENGTH, so it reads a length: `TokenHookRecord` carries up to
/// eight megabytes that this surface would immediately discard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHookMetadata {
    /// The OAuth client whose tokens this hook shapes.
    pub client_id: String,
    /// How many bytes the deployed component is.
    pub component_bytes: i32,
    /// The payload version the guest expects.
    pub payload_version: i32,
}
