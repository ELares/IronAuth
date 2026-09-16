// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hot-state seam: one classified interface over an optional accelerator (issue #146).
//!
//! # What this is for, in the covenant's own words
//!
//! > IronAuth runs complete on PostgreSQL alone, forever. IronCache and IronBus are strictly
//! > optional accelerators **behind documented interfaces** with safe defaults; they are never
//! > prerequisites, and CI verifies both modes.
//!
//! This crate is that documented interface. Everything an accelerator could hold -- a JWKS, a
//! tenant config, an introspection result, a one-time-use marker, a rate counter -- is meant to
//! reach it through [`HotState`].
//!
//! BOTH IMPLEMENTATIONS SHIP. `ironauth-store`'s `hot_state::PgHotState` is the one that is
//! always there and is what makes the covenant's "complete on PostgreSQL alone" true of this
//! seam. [`ironcache::IronCacheHotState`] is the accelerator in front of it, behind the
//! off-by-default `ironcache` feature, because a deployment that never attaches one should not
//! compile a client for it. [`Tiered`] composes them.
//!
//! WHAT IS STILL ABSENT IS TRAFFIC, which is a narrower statement than the one that used to be
//! here and is the accurate one. This said "no request path reaches any of them yet". One does:
//! `IssuerRegistry::jwks_json` reads [`registry::JWKS`] while serving the published document and
//! writes it on the miss, in production source on the public plane. What no shipped binary does
//! is INSTALL an implementation, so that call site is inert in every deployment and the
//! remaining six uses have no call site at all.
//!
//! For the JWKS use, inert is now a measured decision rather than an unfinished one. The
//! accelerator is consulted after the entry is already resolved, so a hit saves the render and
//! cannot save a database read. `docs/UNIT-COSTS.md` measures both sides: the render is 1.3 us
//! and the cheapest socket round trip on that machine is 20 us, so installing an implementation
//! there would trade a microsecond of serialization for sixteen times as much waiting. The seam
//! pays where the alternative to a hop is a QUERY, which is what the other uses are.
//!
//! The general rule still holds and is why this paragraph exists: a use added to the registry
//! does not become live by being declared, and a call site does not become live by being written.
//!
//! # The industry keeps relearning why this has to be a seam
//!
//! Keycloak keeps one-time-use and login-failure state in Infinispan, which makes a cluster a
//! prerequisite -- the exact shape the covenant forbids. Ory Hydra's key resolution degrades
//! under saturation from an in-process lock plus database tail latency. Logto's Redis wrapper
//! shows the defensive posture that works: reads time-boxed and short-circuited to a miss,
//! writes bounded, so a stalled cache can never hold a request.
//!
//! # Every use declares what it is allowed to lose
//!
//! A cache is not one thing. Losing a JWKS entry costs a database read; losing a one-time-use
//! marker can mean a code redeemed twice. Those cannot share a failure policy, and a codebase
//! where each caller decides for itself has no policy at all -- it has as many as it has call
//! sites, and no way to review them.
//!
//! So a caller cannot reach this interface without a [`HotUse`], which names the use and
//! declares its [`Class`]. `scripts/hotstate-classification.sh` refuses a call whose use is not
//! in [`registry`], which is what makes "every trait use is classified" a property of the build
//! rather than of somebody's diligence.
//!
//! # The bounds live here, not in the callers
//!
//! A stall bound written per call site is a bound somebody forgets. [`Bounded`] wraps any
//! implementation and enforces both time boxes for every use. The one thing that must not happen
//! is a request waiting on a cache.
//!
//! WHAT A STALL MEANS IS THE USE'S TO SAY. A stalled read reads as a miss for a use that can
//! survive a silent accelerator, because its caller goes to the store either way; a use that
//! cannot survive one is told, so its class decides rather than the wrapper deciding for it.

#![forbid(unsafe_code)]

mod bounded;
mod class;
#[cfg(feature = "ironcache")]
pub mod ironcache;
pub mod registry;
mod state;
mod tiered;

pub use bounded::{Bounded, Bounds};
pub use class::{Class, HotUse, OnLoss, Reach};
pub use state::{Answer, HotError, HotState, Ttl};
pub use tiered::{POPULATE_TTL_SECS, Tiered};
