// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM tuning defaults, pinned ACROSS the two crates that each declare them
//! (issue #135).
//!
//! `ironauth_config::ScimConfig::default()` is what an operator gets when they never open
//! the `[scim]` section, and `ironauth_scim::ScimLimits::default()` is what the surface
//! gets when nothing hands it a configuration -- which is every test in that crate, and any
//! future embedder. They are the same two numbers written twice, in two crates that cannot
//! see each other: `ironauth-scim` does not depend on `ironauth-config`, so neither
//! `Default` impl can be written in terms of the other and nothing in either crate can
//! notice them drifting apart.
//!
//! # Why this file exists at all
//!
//! Because `ScimConfig`'s doc comment CLAIMED it did. The comment justifying the second copy
//! of these numbers read "`scim_settings_pin.rs` in the `ironauth` crate asserts the two
//! agree, because this crate cannot see that one" -- and a reviewer found that no such file
//! existed. The pattern had been copied from `outbox_settings_pin.rs` without the pin. So
//! the numbers agreed only by coincidence, under a sentence saying they were checked. (For
//! `max_scan` "coincidence" is too strong -- the SCIM side is derived from the store's list
//! cap -- but `max_results` is two hand-written literals and nothing compared them.)
//!
//! # What drifting would actually cost
//!
//! `max_scan` is load bearing. `ScimLimits::scan_bound` clamps it to the store's list cap,
//! and the whole reason that clamp exists is that a bound ABOVE the cap makes the `tooMany`
//! refusal unreachable and the surface truncates a member listing silently -- which a
//! provisioning client reads as "these are all the members" and acts on by deprovisioning
//! everyone it did not see. `validate_scim` refuses that in the config crate. If the SCIM
//! crate's own default drifted above the cap, every deployment that never opens the section
//! would take the unvalidated path.
//!
//! This crate is the one place that depends on both, so this is where the pin can live.

#[test]
fn the_scim_crate_defaults_are_the_configuration_defaults() {
    let configured = ironauth_config::ScimConfig::default();
    let crate_side = ironauth_scim::ScimLimits::default();

    assert_eq!(
        configured.max_results as usize, crate_side.max_results,
        "ScimConfig::default().max_results and ScimLimits::default().max_results have \
         drifted; an operator who never opens [scim] and a caller who hands the surface no \
         configuration would get different page bounds"
    );
    assert_eq!(
        configured.max_scan as usize, crate_side.max_scan,
        "ScimConfig::default().max_scan and ScimLimits::default().max_scan have drifted"
    );
}

#[test]
fn neither_default_exceeds_the_bound_that_makes_the_refusal_reachable() {
    // The property `max_scan` actually has to satisfy, asserted on BOTH sides rather than
    // only on the configured one. `validate_scim` refuses a configured value above the cap,
    // but nothing refuses the SCIM crate's own default -- it is what every deployment that
    // never opens the section, and every test in that crate, actually runs on.
    let cap = usize::try_from(ironauth_store::MANAGEMENT_LIST_HARD_CAP).expect("a small cap");
    // NOT asserted on the SCIM side: `ScimLimits::default().max_scan` IS a const-eval of
    // `MANAGEMENT_LIST_HARD_CAP`, so `cap <= cap` is a tautology with both sides tracing to
    // one constant. A reviewer caught that, and it also corrects this file's header: the two
    // defaults do not agree by coincidence on this field, the SCIM side is DERIVED from the
    // store cap. The config side is a hand-written literal and is the one that can drift.
    assert!(
        ironauth_config::ScimConfig::default().max_scan as usize <= cap,
        "the configured default scan bound exceeds the store's list cap, so the tooMany \
         refusal is unreachable and a large listing truncates silently"
    );
    // And a page can be filled, which is the other half validate_scim enforces.
    assert!(ironauth_scim::ScimLimits::default().max_results >= 1);
    assert!(
        ironauth_scim::ScimLimits::default().max_results
            <= ironauth_scim::ScimLimits::default().max_scan,
        "a page larger than the scan bound can never be filled"
    );
}
