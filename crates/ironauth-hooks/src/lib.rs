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
//! a hook asked for, unfiltered. `filter_hook_claims`, in `ironauth-oidc`'s claims-mapping
//! module, is what decides which of them may be minted. Keeping the transport and the fence apart means
//! the fence is a step visible in the caller rather than a thing this crate is trusted to have
//! remembered.

mod engine;
mod error;
mod limits;
mod sandbox;

pub use engine::{Customization, HookEngine, LoadedHook, Request};
pub use error::{AbortKind, HookError};
pub use limits::Limits;
pub use sandbox::{FROZEN_RESOLUTION_NS, Observed, Sandbox};

/// The shipped guest fixtures, as bytes, for tests in other crates.
///
/// The build script compiles `guests/` and hands each artifact's path to this crate through an
/// environment variable, so only this crate can `include_bytes!` one. The dispatch that RUNS a
/// hook lives in `ironauth-oidc`, and the test that matters -- M11's exit criterion, a WASM hook
/// customizing a real token -- has to drive a real component through a real issuance.
///
/// Feature-gated, because these are test data: a claim-shaping guest compiled into the server
/// would be several hundred kilobytes of WASM nothing ever executes.
#[cfg(feature = "testing")]
pub mod fixtures {
    /// A hook that adds `tier` to the access token and echoes everything else untouched.
    ///
    /// The well-behaved one. What makes it the right fixture for an end-to-end test is that
    /// `tier` is a name the protected-claim fence ALLOWS -- so a token that lacks it afterwards
    /// means the dispatch did not run, rather than that the fence did its job.
    pub const GOOD: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_GOOD"));

    /// The TypeScript sample, and the only fixture here that is not compiled from Rust.
    ///
    /// Issue #114 criterion 1 asks for a Rust hook AND a TypeScript hook customizing claims
    /// through `token.customize`. `guests-ts/src/token-customize.ts` is that hook, and this is
    /// the component built from it, committed rather than built (see `guests-ts/build.mjs`).
    ///
    /// IT IS ELEVEN MEGABYTES, because a JavaScript hook carries a JavaScript engine. That is
    /// not an aside: it is the number the admin surface's upload cap has to admit, and it is
    /// why `ironauth-admin` pins that cap against `.len()` here rather than against a number
    /// someone chose. Nothing outside a test should reach for this constant.
    pub const TS_TOKEN_CUSTOMIZE: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE"));

    /// A hook that imports `wasi:sockets`, which the sandbox does not link.
    ///
    /// The sandbox suite runs it directly to show the capability being refused. It is exported
    /// here so the DISPATCH can be tested against an unloadable component too: a refusal that
    /// the dispatch does not remember is one it pays a full cranelift compile for on every
    /// request, which is a different defect from the sandbox failing to refuse.
    pub const NET_ESCAPE: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_NET_ESCAPE"));

    /// A hook that spins until its fuel runs out.
    pub const FUEL_BOMB: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_FUEL_BOMB"));

    /// A hook that returns an error of its own rather than a customization.
    pub const DECLINER: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_DECLINER"));

    /// A hook that returns `sub` and `iss` -- the identity and the issuer.
    ///
    /// Issue #113 criterion 5's "or hook" half. It also returns one claim the fence ALLOWS, so
    /// a test can tell "the fence dropped the forged claims" from "the hook never ran", which
    /// are the same observation without it.
    pub const CLAIM_FORGER: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_CLAIM_FORGER"));

    /// A hook that REMOVES `email` and adds a marker.
    ///
    /// The WIT contract is a replace, so dropping a claim means not echoing it. The marker is
    /// what lets a test tell a removal from a hook that never ran.
    pub const CLAIM_STRIPPER: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_CLAIM_STRIPPER"));

    /// A hook written the way a MACHINE-GRANT author writes one.
    ///
    /// Echoes `access_token_claims` faithfully, adds a marker, and returns an EMPTY
    /// `id_token_claims`, because the three grants that mint one access token have no ID token
    /// to fill. That makes it the discriminator for WHICH LIST the host hands a machine
    /// client's existing claims over in: neither `good` nor `echo-only` can catch putting them
    /// in the ID-token list, because both echo that list back.
    ///
    /// It also reports the request's SUBJECT into the access list. `echo-request` reports it
    /// into the ID-token list, which a machine grant discards, so this is the only fixture that
    /// can observe the subject on those three doors at all.
    pub const ECHO_ACCESS_ONLY: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_ECHO_ACCESS_ONLY"));

    /// A hook that returns every SCALAR request field as a claim.
    ///
    /// Already used by the sandbox suite to prove the TRANSPORT carries each field. Exported
    /// here because that is a different question from whether each DOOR fills them in
    /// correctly: `grant_type` is a plain string that every mint site passes as a literal, so a
    /// door that copied the wrong one from its neighbour would look identical to one that got
    /// it right. Issue #113 criterion 1 asks for the grant to be identified in the payload, and
    /// this is what lets an end-to-end test read back which grant the guest was told it was.
    pub const ECHO_REQUEST: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_ECHO_REQUEST"));

    /// A hook that echoes both claim lists unchanged, plus a marker.
    ///
    /// The identity under the replace contract, and the shape that exposes a cap on hook OUTPUT
    /// silently capping the TOKEN: a deployment with more than 32 extra claims deploying a
    /// do-nothing hook must not lose any of them.
    pub const ECHO_ONLY: &[u8] = include_bytes!(env!("IRONAUTH_GUEST_ECHO_ONLY"));
}
