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
//! THE POSTGRES IMPLEMENTATION SHIPS, in `ironauth-store` (`hot_state::PgHotState`), and it is
//! what makes the covenant's "complete on PostgreSQL alone" true of this seam. The IronCache one
//! it accelerates is still to come.
//!
//! WHAT IS STILL ABSENT IS CALLERS. [`registry`] declares seven uses and no request path reaches
//! any of them yet, so this crate is a contract with an implementation and no traffic. That is
//! worth stating here rather than discovering: a use added to the registry does not become live
//! by being declared.
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
pub mod registry;
mod state;
mod tiered;

pub use bounded::{Bounded, Bounds};
pub use class::{Class, HotUse, OnLoss, Reach};
pub use state::{Answer, HotError, HotState, Ttl};
pub use tiered::{POPULATE_TTL_SECS, Tiered};
