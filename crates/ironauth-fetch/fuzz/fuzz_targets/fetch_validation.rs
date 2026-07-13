// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target over URL parsing and destination validation, the two pure gates
//! the connector consults before it ever opens a socket.
//!
//! The target drives [`ironauth_fetch::parse_target`] over arbitrary strings
//! (proving the parser never panics and that a parsed IP-literal host always
//! classifies) and [`ironauth_fetch::classify`] over arbitrary IPv4 and IPv6
//! addresses (proving the deny policy is total over the whole address space).
//! The same input space has stable, in-CI coverage in
//! `tests/adversarial_table.rs`, so this crate is a nightly-only deepening, not
//! the only coverage. Run locally with `cargo +nightly fuzz run fetch_validation`.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use ironauth_fetch::{classify, parse_target};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Input {
    /// An arbitrary string fed to the URL parser.
    Url(String),
    /// Four bytes interpreted as an IPv4 address for the classifier.
    V4([u8; 4]),
    /// Sixteen bytes interpreted as an IPv6 address for the classifier.
    V6([u8; 16]),
}

fuzz_target!(|input: Input| {
    match input {
        Input::Url(raw) => {
            if let Ok(target) = parse_target(&raw) {
                // A parsed literal host must always classify without panicking.
                if let Some(ip) = target.literal_ip {
                    let _ = classify(ip);
                }
                // Rendering the Host header must never panic on a parsed target.
                let _ = target.host_header();
            }
        }
        Input::V4(octets) => {
            let _ = classify(IpAddr::V4(Ipv4Addr::from(octets)));
        }
        Input::V6(octets) => {
            let _ = classify(IpAddr::V6(Ipv6Addr::from(octets)));
        }
    }
});
