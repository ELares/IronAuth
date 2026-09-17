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
//! accelerator is consulted after the entry is already resolved, so a hit cannot save a database
//! read of any shape; it saves the render, and it ADDS the UTF-8 check and JSON validation parse
//! that accepting the bytes requires. `docs/UNIT-COSTS.md` measures both sides. For a fresh
//! environment's three published keys the net saving is about 0.6 us, against a 20 us round trip
//! on the same machine, and it is negative at one published key.
//!
//! THAT IS SPECIFIC TO THIS USE, and an earlier version of this paragraph generalised it wrongly.
//! It said the seam pays "where the alternative to a hop is a QUERY", which a review showed is
//! too coarse: a cache hit costs a round trip, so it returns only what the operation costs ABOVE
//! one round trip. The JWKS read is unusual in costing almost nothing above it, because the
//! entry is already in hand. A SCOPED read is the opposite: `begin_scoped` pays BEGIN, an
//! isolation level, two `set_config` calls and a COMMIT around a query under row-level security,
//! measured at 166 us against a 20 us hop. Those uses are worth accelerating.
//!
//! HOW MUCH DEPENDS ON THE TIER, AND ON THE WIRING. `HotStateRepo::get` goes through
//! `begin_scoped` as well, so a hit against `PgHotState` pays the same six round trips as the
//! read it stands in front of: 145 us against 166 us, thirteen per cent, bought with a write on
//! every miss and an invalidation feed to keep correct. Wired one-for-one in front of a single
//! repository call, the Postgres tier buys nothing.
//!
//! What a hit replaces is however many scoped transactions the cached answer stands in front of,
//! and that is a wiring choice. A resolved tenant config is three of them, around 500 us, which
//! one hit turns into 145. `docs/UNIT-COSTS.md` works the cases through.
//!
//! AN ATTACHED IRONCACHE IS THE OTHER ANSWER, and it is now measured rather than assumed: a
//! `GET` hit costs 32 to 33 us, against 145 us for the Postgres tier and 162 us for the scoped
//! read either would front. That is an eighty per cent saving where the Postgres tier gives
//! thirteen. The seam is worth attaching an accelerator to; it is not worth much without one.
//!
//! The accelerator figure comes from a different instrument than the database ones, a Python
//! client against `pgbench`, and a C client doing the same loop measured about 4 us less, so it
//! overstates the hop. `docs/UNIT-COSTS.md` carries that caveat and two others.
//!
//! For the write-shaped uses the Postgres tier is worse than nothing: a marker or a counter
//! would be a second scoped WRITE in the same request. Where that tier IS the right answer is as
//! shared state rather than speed, holding flow state that survives the node that created it.
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
