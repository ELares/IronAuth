// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth binary entry point.
//!
//! M1 scaffold scope: version and help output only. The server skeleton
//! arrives with the M1 issue "Build the single-binary server skeleton with
//! observability and trusted-proxy policy"; argument parsing stays
//! dependency-free until the config layer defines the real surface.

use std::process::ExitCode;

/// Semantic version of this build, injected by Cargo.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version" | "-V" | "version") => {
            println!("ironauth {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help" | "-h" | "help") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("ironauth: unknown argument '{other}'");
            eprintln!("run 'ironauth --help' for usage");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("ironauth {VERSION}");
    println!("A standards-first OpenID Connect identity platform.");
    println!();
    println!("USAGE:");
    println!("  ironauth [--version | --help]");
    println!();
    println!("The server, worker, and admin commands land with milestone M1;");
    println!("track progress at https://github.com/ELares/IronAuth/milestones");
}
