// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-process WASM component hooks (issue #114).
//!
//! # What this is for
//!
//! An identity platform's extensibility story is usually one of two bad trades. Remote hooks
//! put a network round trip on the login path: Auth0 Actions is remote Node with a twenty
//! second budget, and Okta's inline hooks block a login behind a three second HTTP call.
//! In-process hooks avoid the hop and buy an upgrade tax instead, because a native plugin ABI
//! or an embedded interpreter binds the host's internals to somebody else's code.
//!
//! The component model is the way out that those precedents did not have: a version-stable
//! ABI, a real sandbox, and microsecond invocation. The numbers recorded on issue #114 for a
//! hook that decodes a payload, walks a claim list and re-encodes:
//!
//! | | measured p95 | the criterion's gate |
//! |---|---|---|
//! | cold (deserialize + instantiate + call) | 0.127 ms | 1 ms |
//! | warm (call) | 1.08 us | 100 us |
//!
//! Those are a laptop's numbers, not the pinned runner's, and criterion 4's benchmark job is
//! what decides the gate. What they establish is that the runtime is not the reason it would
//! fail.
//!
//! # The three things this crate is careful about
//!
//! **What a hook can reach** is [`Sandbox`], and the mechanism is absence rather than refusal:
//! a guest imports an interface only if it uses one, so a hook that wants a socket fails to
//! instantiate against a linker that has none. See that module for what is deliberately left
//! out, and for the one capability that cannot be delivered this way.
//!
//! **What a hook can consume** is [`Limits`]. Three bounds, because fuel cannot see a hook that
//! blocks and neither one can see a hook that allocates.
//!
//! **What a hook is allowed to say** is NOT here. [`LoadedHook::customize`] returns the claims
//! a hook asked for, unfiltered, and `ironauth-oidc::claims_mapping::filter_hook_claims` is
//! what decides which of them may be minted. Keeping the transport and the fence apart means
//! the fence is a step visible in the caller rather than a thing this crate is trusted to have
//! remembered.

mod engine;
mod error;
mod limits;
mod sandbox;

pub use engine::{Customization, HookEngine, LoadedHook, Request};
pub use error::{AbortKind, HookError};
pub use limits::Limits;
pub use sandbox::{FrozenClock, Sandbox};
