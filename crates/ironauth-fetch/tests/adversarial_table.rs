// SPDX-License-Identifier: MIT OR Apache-2.0

//! A stable, in-CI adversarial table over crafted URLs and addresses, covering
//! the same input space as the cargo-fuzz target (`fuzz/fuzz_targets`) so the
//! parse-and-validate logic has coverage on every lane, not only under nightly
//! fuzzing. It exercises the pure, exported functions [`parse_target`] and
//! [`classify`]; no network is touched.

use std::net::IpAddr;

use ironauth_fetch::policy::BlockClass;
use ironauth_fetch::target::Scheme;
use ironauth_fetch::{TargetError, classify, parse_target};

/// The whole point of resolve-then-validate: a URL whose host is a denied IP
/// literal is caught at the address check, whatever spelling routed it there.
#[test]
fn denied_ip_literal_urls_classify_as_blocked() {
    let cases: &[(&str, BlockClass)] = &[
        (
            "http://169.254.169.254/latest/meta-data/",
            BlockClass::LinkLocal,
        ),
        ("https://169.254.169.254/", BlockClass::LinkLocal),
        ("http://127.0.0.1:8080/admin", BlockClass::Loopback),
        ("http://10.0.0.1/", BlockClass::Private),
        ("http://172.16.0.1/", BlockClass::Private),
        ("http://192.168.100.100/", BlockClass::Private),
        ("http://100.64.0.1/", BlockClass::SharedCgn),
        ("http://198.18.0.99/", BlockClass::Benchmarking),
        ("http://192.0.2.1/", BlockClass::Documentation),
        ("http://0.0.0.0/", BlockClass::Unspecified),
        ("http://255.255.255.255/", BlockClass::Reserved),
        ("http://[::1]/", BlockClass::Loopback),
        ("http://[::]/", BlockClass::Unspecified),
        ("http://[fe80::1]/", BlockClass::LinkLocal),
        ("http://[fc00::abcd]/", BlockClass::Private),
        ("http://[fd12:3456:789a::1]/", BlockClass::Private),
        ("http://[fec0::1]/", BlockClass::SiteLocal),
        ("http://[ff02::1]/", BlockClass::Multicast),
        ("http://[2001:db8::1]/", BlockClass::Documentation),
        ("http://[64:ff9b::1]/", BlockClass::EmbeddedIpv4),
        ("http://[2002:c0a8:0101::1]/", BlockClass::EmbeddedIpv4),
        // The IPv4-in-IPv6 bypass family, including the metadata address.
        ("http://[::ffff:169.254.169.254]/", BlockClass::LinkLocal),
        ("http://[::ffff:127.0.0.1]/", BlockClass::Loopback),
        ("http://[::ffff:10.9.8.7]/", BlockClass::Private),
        ("http://[::127.0.0.1]/", BlockClass::Loopback),
        ("http://[::192.168.0.1]/", BlockClass::Private),
    ];
    for (url, expected) in cases {
        let target = parse_target(url).unwrap_or_else(|e| panic!("{url} should parse: {e}"));
        let ip = target
            .literal_ip
            .unwrap_or_else(|| panic!("{url} should be an IP literal"));
        assert_eq!(classify(ip), Some(*expected), "{url}");
    }
}

/// Public IP literals parse and are allowed by the policy.
#[test]
fn public_ip_literal_urls_are_allowed() {
    for url in [
        "https://93.184.216.34/",
        "http://8.8.8.8/",
        "https://[2606:2800:220:1:248:1893:25c8:1946]/",
    ] {
        let target = parse_target(url).expect("valid");
        let ip = target.literal_ip.expect("ip literal");
        assert_eq!(classify(ip), None, "{url} should be allowed");
    }
}

/// Dangerous URLs are rejected at parse time. Non-http(s) schemes that carry an
/// authority are named unsupported; userinfo is named; and anything the URI
/// grammar itself refuses is malformed. Every one is an `Err`: nothing dangerous
/// reaches the network.
#[test]
fn dangerous_urls_are_rejected_at_parse() {
    let named: &[(&str, TargetError)] = &[
        ("ftp://example.com/", TargetError::UnsupportedScheme),
        ("gopher://169.254.169.254/", TargetError::UnsupportedScheme),
        ("javascript:alert(1)", TargetError::UnsupportedScheme),
        ("//example.com/", TargetError::UnsupportedScheme),
        (
            "https://user:secret@169.254.169.254/",
            TargetError::UserinfoPresent,
        ),
        ("https://admin@internal/", TargetError::UserinfoPresent),
    ];
    for (url, expected) in named {
        assert_eq!(parse_target(url), Err(expected.clone()), "{url}");
    }

    // These are refused by the URI grammar before the scheme check; the security
    // property is only that they are rejected.
    for url in [
        "file:///etc/passwd",
        "data:text/plain;base64,AAAA",
        "example.com/path",
        "",
        "https://",
        "https:///path",
        "not a url",
    ] {
        assert!(parse_target(url).is_err(), "{url} must be rejected");
    }
}

/// Scheme, host, and port normalize as expected for a spread of valid inputs.
#[test]
fn valid_urls_normalize_consistently() {
    let target = parse_target("https://Example.COM/A/B?x=1").expect("valid");
    assert_eq!(target.scheme, Scheme::Https);
    assert_eq!(target.port, 443);
    assert_eq!(target.path_and_query, "/A/B?x=1");

    let target = parse_target("http://host.example:8080").expect("valid");
    assert_eq!(target.scheme, Scheme::Http);
    assert_eq!(target.port, 8080);
    assert_eq!(target.path_and_query, "/");
}

/// A broad classification sweep over crafted addresses, asserting denied and
/// allowed both hold at the range boundaries.
#[test]
fn classification_sweep_holds_at_boundaries() {
    let denied: &[&str] = &[
        "10.0.0.0",
        "10.255.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.255.255",
        "127.0.0.0",
        "127.255.255.255",
        "169.254.0.0",
        "169.254.255.255",
        "100.64.0.0",
        "100.127.255.255",
        "198.18.0.0",
        "198.19.255.255",
        "224.0.0.0",
        "239.255.255.255",
        "240.0.0.0",
        "::1",
        "::",
        "fe80::",
        "febf::ffff",
        "fc00::",
        "fdff:ffff::",
        "ff00::",
        "ffff::",
    ];
    for addr in denied {
        let ip: IpAddr = addr.parse().expect("addr");
        assert!(classify(ip).is_some(), "{addr} must be denied");
    }

    let allowed: &[&str] = &[
        "9.255.255.255",
        "11.0.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "223.255.255.255",
        "8.8.8.8",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ];
    for addr in allowed {
        let ip: IpAddr = addr.parse().expect("addr");
        assert_eq!(classify(ip), None, "{addr} must be allowed");
    }
}
