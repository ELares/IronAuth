// SPDX-License-Identifier: MIT OR Apache-2.0
//! Builds the guest fixtures the sandbox tests run against.
//!
//! # Why this fails loudly instead of skipping
//!
//! Every adversarial test in `tests/sandbox.rs` needs a real component: a hook that spins, one
//! that allocates, one that opens a socket. Those cannot be written in Rust-the-host, so they
//! are compiled here from `guests/`, which needs the `wasm32-wasip2` target.
//!
//! The obvious alternative is to skip the tests when the target is missing. That would make
//! every sandbox guarantee in this crate silently unverified on any machine that had not run
//! one `rustup` command, and a security test that quietly does not run is worse than no test:
//! the suite still reports green. So a missing target is a BUILD FAILURE with the exact command
//! to fix it, and CI installs the target rather than tolerating its absence.
//!
//! The cost is real and worth naming: anyone building this crate needs the target. It is one
//! rustup command and it is the price of the tests meaning anything.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The fixtures, as `(crate name, the env var the tests read)`.
const GUESTS: &[(&str, &str)] = &[
    ("good", "IRONAUTH_GUEST_GOOD"),
    ("fuel_bomb", "IRONAUTH_GUEST_FUEL_BOMB"),
    ("memory_bomb", "IRONAUTH_GUEST_MEMORY_BOMB"),
    ("net_escape", "IRONAUTH_GUEST_NET_ESCAPE"),
    ("wall_clock_escape", "IRONAUTH_GUEST_WALL_CLOCK_ESCAPE"),
    ("monotonic_reader", "IRONAUTH_GUEST_MONOTONIC_READER"),
    ("decliner", "IRONAUTH_GUEST_DECLINER"),
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let guests = manifest.join("guests");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("out dir")).join("guests");

    println!("cargo:rerun-if-changed=guests");
    println!("cargo:rerun-if-changed=wit");

    // A separate target directory, not the host workspace's. Sharing one would have cargo
    // contend on the same lock as the build that invoked this script, which deadlocks.
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
        .current_dir(&guests)
        .env("CARGO_TARGET_DIR", &out)
        // Inherited RUSTFLAGS are for the host target and are wrong here; a host `-C
        // target-cpu` in particular makes the guest build fail in a way that reads as a bug in
        // this script.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .status()
        .expect("failed to run cargo for the guest fixtures");

    assert!(
        status.success(),
        "\n\
         The WASM guest fixtures failed to build.\n\
         \n\
         If the error above is about a missing `wasm32-wasip2` target, run:\n\
         \n\
             rustup target add wasm32-wasip2\n\
         \n\
         These fixtures are not optional. They are the hooks that spin, allocate, and try to\n\
         open a socket, and without them the sandbox tests in this crate verify nothing. They\n\
         are built rather than skipped so that a green suite means the sandbox was tested.\n"
    );

    let release = out.join("wasm32-wasip2").join("release");
    for (guest, var) in GUESTS {
        let artifact = release.join(format!("{guest}.wasm"));
        assert!(
            Path::new(&artifact).exists(),
            "guest `{guest}` built without producing {}",
            artifact.display()
        );
        println!("cargo:rustc-env={var}={}", artifact.display());
    }
}
