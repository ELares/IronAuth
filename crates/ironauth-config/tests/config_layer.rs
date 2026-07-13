// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end tests over the public surface: real files on disk, the full
//! load path, and the experimental acknowledgment gate lifecycle.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ironauth_config::{Config, Feature, FeatureRegistry, Warning};

/// A unique scratch path per call without entropy or clock reads (both are
/// banned outside ironauth-env): process id plus a process-wide counter.
fn scratch_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ironauth-config-test-{}-{n}-{tag}",
        std::process::id()
    ))
}

/// RAII cleanup so failed assertions do not strand files in the temp dir.
struct TempFile(PathBuf);

impl TempFile {
    fn with_contents(tag: &str, contents: &str) -> Self {
        let path = scratch_path(tag);
        std::fs::write(&path, contents).expect("temp file writes");
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn unknown_key_in_a_real_file_names_the_file_line_and_key() {
    let file = TempFile::with_contents(
        "unknown-key.toml",
        "[server]\nbind = \"0.0.0.0:8443\"\ntls_cert = \"/nope\"\n",
    );
    let err = Config::load(&file.0).expect_err("unknown key must abort");
    let msg = err.to_string();
    let expected_prefix = format!("invalid config {}:3:1", file.0.display());
    assert!(msg.contains(&expected_prefix), "{msg}");
    assert!(msg.contains("tls_cert"), "{msg}");
    assert!(msg.contains("bind"), "expected-fields list missing: {msg}");
}

#[test]
fn missing_file_names_the_path() {
    let path = scratch_path("does-not-exist.toml");
    let err = Config::load(&path).expect_err("missing file");
    assert!(
        err.to_string().contains(&path.display().to_string()),
        "{err}"
    );
}

#[test]
fn secret_file_form_resolves_and_redacts_end_to_end() {
    let secret_file = TempFile::with_contents("db-password", "hunter2\n");
    let config_file = TempFile::with_contents(
        "secret-file.toml",
        &format!(
            "[database]\npassword = {{ file = '{}' }}\n",
            secret_file.0.display()
        ),
    );

    let loaded = Config::load(&config_file.0).expect("valid config");
    assert!(loaded.warnings.is_empty(), "indirection must not warn");

    let secret = loaded.config.database.password.as_ref().expect("present");
    let resolved = secret.resolve().expect("file readable");
    assert_eq!(resolved.expose(), "hunter2");

    // The value must be absent from every rendering of the config.
    let debug = format!("{:?}", loaded.config);
    assert!(!debug.contains("hunter2"), "leak: {debug}");
}

#[test]
fn secret_resolve_error_names_the_path_only() {
    let missing = scratch_path("gone-secret");
    let config = Config::from_toml_str(
        &format!(
            "[database]\npassword = {{ file = '{}' }}\n",
            missing.display()
        ),
        "<inline>",
    )
    .expect("valid config")
    .config;
    let err = config
        .database
        .password
        .expect("present")
        .resolve()
        .expect_err("file is missing");
    let msg = err.to_string();
    assert!(msg.contains(&missing.display().to_string()), "{msg}");
}

#[test]
fn literal_secret_warns_through_the_load_path() {
    let config_file =
        TempFile::with_contents("literal.toml", "[database]\npassword = \"hunter2\"\n");
    let loaded = Config::load(&config_file.0).expect("valid config");
    assert_eq!(loaded.warnings.len(), 1);
    assert!(matches!(
        &loaded.warnings[0],
        Warning::LiteralSecret { key } if key == "database.password"
    ));
}

/// The full node-oidc-provider-style acknowledgment lifecycle against the
/// registered sample flag.
#[test]
fn ack_gate_lifecycle_unset_then_acked_then_stale() {
    let registry = FeatureRegistry::builtin();

    // 1. Enabled without an ack: refuse to boot, name the feature, the
    //    required version, and the changelog pointer.
    let unacked = parse("[features.\"sample-experimental\"]\nenabled = true\n");
    let err = registry.validate(&unacked).expect_err("no ack");
    let msg = err.to_string();
    assert!(msg.contains("sample-experimental"), "{msg}");
    assert!(msg.contains("0.1.0-exp.1"), "{msg}");
    assert!(msg.contains("crates/ironauth-config/CHANGELOG.md"), "{msg}");

    // 2. The exact current version acked: boots.
    let acked =
        parse("[features.\"sample-experimental\"]\nenabled = true\nack = \"0.1.0-exp.1\"\n");
    registry.validate(&acked).expect("exact ack boots");
    assert!(registry.is_enabled(&acked, "sample-experimental"));

    // 3. Simulated breaking bump: the same config against a registry where
    //    the feature moved to 0.2.0-exp.1 refuses to boot, calls the ack
    //    stale, and points at the changelog.
    let mut bumped = FeatureRegistry::new();
    bumped.register(Feature::experimental(
        "sample-experimental",
        "simulated breaking bump of the sample flag",
        "0.2.0-exp.1",
        "crates/ironauth-config/CHANGELOG.md",
    ));
    let err = bumped.validate(&acked).expect_err("stale ack");
    let msg = err.to_string();
    assert!(
        msg.contains("0.1.0-exp.1"),
        "must name the stale ack: {msg}"
    );
    assert!(
        msg.contains("0.2.0-exp.1"),
        "must name the required version: {msg}"
    );
    assert!(msg.contains("crates/ironauth-config/CHANGELOG.md"), "{msg}");
}

#[test]
fn wrong_type_for_a_known_key_aborts_with_position() {
    let err =
        Config::from_toml_str("[server]\nbind = 8443\n", "ironauth.toml").expect_err("wrong type");
    let msg = err.to_string();
    assert!(msg.contains("ironauth.toml:2"), "{msg}");
    assert!(msg.contains("string"), "{msg}");
}

fn parse(input: &str) -> Config {
    Config::from_toml_str(input, "<inline>")
        .expect("test config parses")
        .config
}
