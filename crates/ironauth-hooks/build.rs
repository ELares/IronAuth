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
    ("random_escape", "IRONAUTH_GUEST_RANDOM_ESCAPE"),
    ("fs_escape", "IRONAUTH_GUEST_FS_ESCAPE"),
    ("echo_request", "IRONAUTH_GUEST_ECHO_REQUEST"),
    ("echo_access_only", "IRONAUTH_GUEST_ECHO_ACCESS_ONLY"),
    ("wall_clock_escape", "IRONAUTH_GUEST_WALL_CLOCK_ESCAPE"),
    ("monotonic_reader", "IRONAUTH_GUEST_MONOTONIC_READER"),
    ("sleeper", "IRONAUTH_GUEST_SLEEPER"),
    ("instant_waiter", "IRONAUTH_GUEST_INSTANT_WAITER"),
    ("pollable_leak", "IRONAUTH_GUEST_POLLABLE_LEAK"),
    ("poll_bomb", "IRONAUTH_GUEST_POLL_BOMB"),
    ("decliner", "IRONAUTH_GUEST_DECLINER"),
    // Returns `sub` and `iss` (issue #113 criterion 5, the "or hook" half): the fence on what a
    // hook RETURNS had no guest that exercised it, so deleting it left every test green.
    ("chain_observer", "IRONAUTH_GUEST_CHAIN_OBSERVER"),
    ("claim_forger", "IRONAUTH_GUEST_CLAIM_FORGER"),
    // REMOVES a claim (issue #114). The WIT contract is a replace, and the first dispatch merged
    // -- so a hook deployed to strip a claim produced a token that still carried it, and nothing
    // measured that because no guest removed anything.
    ("claim_stripper", "IRONAUTH_GUEST_CLAIM_STRIPPER"),
    // Echoes both lists unchanged (issue #114). Echoing is where a cap on hook OUTPUT silently
    // becomes a cap on the TOKEN, and no fixture echoed enough claims to reach the 32-claim
    // bound.
    ("echo_only", "IRONAUTH_GUEST_ECHO_ONLY"),
    // Refuses MORE than the fence will REPORT (issue #114 criterion 5). The refusal list
    // is capped at sixty-four per token and every other fixture refuses a handful, so
    // `refusals_not_reported` was zero on every test in the tree -- and a draft report
    // that threw the count away read exactly like one that carried it.
    ("claim_flood", "IRONAUTH_GUEST_CLAIM_FLOOD"),
];

/// The committed TypeScript component, relative to this crate's root.
///
/// Not built here, unlike every fixture above. Building it needs Node, an npm install, and a
/// JavaScript engine to embed; running `npm install` from a build script would put a network
/// fetch in the path of every build of this crate. `guests-ts/build.mjs` carries the full
/// reasoning and is what produces this file.
const TS_GUEST: &str = "guests-ts/dist/token-customize.wasm";

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

    // The TypeScript component is committed rather than built, and it is checked with the same
    // severity as a missing Rust fixture: absent means BUILD FAILURE, never a skipped test.
    // Criterion 1 asks for a Rust hook AND a TypeScript hook customizing claims in the
    // integration suite, and a TypeScript test that quietly does not run would leave half of
    // that criterion unverified while the suite reported green.
    let ts_guest = manifest.join(TS_GUEST);
    println!("cargo:rerun-if-changed={}", ts_guest.display());
    assert!(
        ts_guest.exists(),
        "\n\
         The committed TypeScript hook component is missing:\n\
         \n\
             {}\n\
         \n\
         It is built by hand, not by this script. To rebuild it:\n\
         \n\
             cd crates/ironauth-hooks/guests-ts && npm install && npm run build\n\
         \n\
         See guests-ts/build.mjs for why it is committed rather than built here.\n",
        ts_guest.display()
    );
    println!(
        "cargo:rustc-env=IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE={}",
        ts_guest.display()
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
