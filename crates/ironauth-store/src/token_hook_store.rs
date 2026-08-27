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

/// A precompiled artifact and the identity of the engine that can load it.
///
/// The KEY is what makes storing machine code in a shared table safe. `compile` emits code for
/// one wasmtime version, configuration and CPU, and `load_precompiled` is `unsafe` because
/// nothing about the bytes says which. `Engine::compatibility_key` answers it: wasmtime
/// guarantees that engines reporting the same key can load each other's artifacts, so a reader
/// deserializes only on an exact match and compiles from source on any mismatch.
///
/// A replica on a different CPU, or a node one wasmtime version ahead, therefore pays a compile
/// rather than executing code built for something else.
#[derive(Clone, PartialEq, Eq)]
pub struct PrecompiledHook {
    /// The machine code, as `HookEngine::compile` produced it.
    pub artifact: Vec<u8>,
    /// `HookEngine::compatibility_key` of the engine that produced `artifact`.
    pub engine_key: Vec<u8>,
}

/// Hand-written for the same reason [`TokenHookRecord`]'s is: the artifact is machine code and
/// larger than the component, and nobody reading a log wants it inline.
impl core::fmt::Debug for PrecompiledHook {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrecompiledHook")
            .field("artifact_bytes", &self.artifact.len())
            .field("engine_key", &hex_key(&self.engine_key))
            .finish()
    }
}

/// The first four bytes of a key, which is enough to tell two engines apart in a log.
fn hex_key(key: &[u8]) -> String {
    use std::fmt::Write as _;
    key.iter()
        .take(4)
        .fold(String::new(), |mut rendered, byte| {
            let _ = write!(rendered, "{byte:02x}");
            rendered
        })
}

/// One deployed hook: the component, and the payload version its guest was built against.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenHookRecord {
    /// The OAuth client whose tokens this hook shapes, unique per scope.
    pub client_id: String,
    /// The WASM component.
    pub component: Vec<u8>,
    /// The payload version the guest expects (issue #113 criterion 6).
    pub payload_version: i32,
    /// A precompiled artifact for this component, and the key of the engine that produced it.
    ///
    /// [`None`] when the row predates the artifact columns, or when whoever wrote it had no
    /// engine to compile with. A reader that finds `None` compiles `component`, which is what
    /// every reader did before this existed.
    ///
    /// The pair is ONE field because neither half is usable alone: an artifact without its key
    /// cannot be safely deserialized, and a key without an artifact describes nothing. The
    /// table enforces the same thing with a CHECK, so this cannot represent a row the database
    /// would accept but the type could not.
    pub precompiled: Option<PrecompiledHook>,
}

/// Hand-written, and the component is rendered as a LENGTH.
///
/// A derived `Debug` would put megabytes of WASM into any log line that formats a record, and
/// the bytes are the one field nobody reading a log wants. What a reader needs is which client,
/// which version, and whether the component is the size they deployed.
impl std::fmt::Debug for TokenHookRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenHookRecord")
            .field("precompiled", &self.precompiled)
            .field("client_id", &self.client_id)
            .field("component_bytes", &self.component.len())
            .field("payload_version", &self.payload_version)
            .finish()
    }
}
