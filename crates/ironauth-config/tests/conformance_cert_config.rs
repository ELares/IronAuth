// SPDX-License-Identifier: MIT OR Apache-2.0

//! Confinement proof for the OIDF conformance cert config (issue #37).
//!
//! The conformance harness runs against a certification-representative
//! deployment (deploy/conformance/ironauth.toml) that flips ON a set of
//! legacy/downgrade OP-profile toggles. Every one is a security downgrade.
//! These tests load BOTH the shipped default config and the cert config through
//! the real strict loader and assert two properties at once:
//!
//!   1. The cert config PARSES under the strict, deny-unknown-fields schema (a
//!      broken cert config is a silent conformance-bootstrap failure).
//!   2. The downgrades are CONFINED to the cert config: the cert file turns them
//!      on, and the shipped default keeps every one OFF. This is what makes the
//!      downgrades unable to become the default posture: editing the cert file
//!      cannot weaken the default, and if the default ever drifts these tests go
//!      red.

use std::path::{Path, PathBuf};

use ironauth_config::Config;

/// Absolute path to a repo-root-relative file. The crate manifest dir is
/// `<repo>/crates/ironauth-config`, so the repo root is two levels up. No
/// clock or entropy reads (both are banned in this workspace outside
/// ironauth-env).
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

/// The full set of cert-only downgrade toggles this harness turns on. Reading a
/// bool off the parsed config keeps the two assertions below in lockstep.
fn downgrades(config: &Config) -> [(&'static str, bool); 6] {
    [
        (
            "oidc.enable_response_type_id_token",
            config.oidc.enable_response_type_id_token,
        ),
        (
            "oidc.enable_response_type_code_id_token",
            config.oidc.enable_response_type_code_id_token,
        ),
        (
            "oidc.enable_response_type_none",
            config.oidc.enable_response_type_none,
        ),
        (
            "oidc.enable_response_mode_form_post",
            config.oidc.enable_response_mode_form_post,
        ),
        (
            "oidc.registration_enabled",
            config.oidc.registration_enabled,
        ),
        (
            "oidc.registration_rate_limit_disabled",
            config.oidc.registration_rate_limit == 0,
        ),
    ]
}

#[test]
fn cert_config_parses_under_the_strict_schema() {
    // A parse or validation error here means the cert deployment would fail to
    // boot, silently taking the whole conformance run with it.
    let loaded = Config::load(repo_path("deploy/conformance/ironauth.toml"))
        .expect("cert config parses and validates under the strict schema");
    assert!(
        loaded.config.oidc.enabled,
        "the cert config must enable the OIDC provider"
    );
}

#[test]
fn cert_config_turns_every_downgrade_on() {
    let loaded =
        Config::load(repo_path("deploy/conformance/ironauth.toml")).expect("cert config loads");
    for (name, on) in downgrades(&loaded.config) {
        assert!(on, "cert config must enable the downgrade {name}");
    }
    // The Dynamic profile needs anonymous registration and a relaxed quota.
    assert_eq!(
        loaded.config.oidc.registration_mode,
        ironauth_config::RegistrationMode::Open,
        "cert config must open DCR for the Dynamic profile"
    );
    assert!(
        loaded.config.oidc.registration_max_clients >= 10_000,
        "cert config must raise the DCR client cap for the suite's registrations"
    );
}

#[test]
fn shipped_default_config_stays_hardened() {
    // The shipped compose config is the posture a real operator inherits. Every
    // downgrade must be OFF here. If this fails, a downgrade has leaked out of
    // the cert file into the default, which is exactly what confinement forbids.
    let loaded =
        Config::load(repo_path("deploy/ironauth.toml")).expect("shipped default config loads");
    for (name, on) in downgrades(&loaded.config) {
        assert!(
            !on,
            "shipped default config must keep the downgrade {name} OFF"
        );
    }
}

#[test]
fn library_defaults_stay_hardened() {
    // Belt and suspenders: the type-level default (an empty config file) must
    // also keep every downgrade off, so the hardened posture does not depend on
    // any file being present.
    let config = Config::default();
    for (name, on) in downgrades(&config) {
        assert!(!on, "library default must keep the downgrade {name} OFF");
    }
    assert!(
        !config.oidc.enabled,
        "the OIDC provider must be off by default"
    );
}
