// SPDX-License-Identifier: MIT OR Apache-2.0

//! The destination deny policy: classify a resolved IP address and refuse every
//! loopback, private, link-local, and special-use range.
//!
//! The policy is deny-by-range, never allow-by-host: a hostname that resolves to
//! ANY denied address blocks the whole fetch. The ranges are enumerated
//! explicitly (each commented with why it is refused) rather than delegated to
//! the standard library's classification helpers, several of which
//! (`is_shared`, `is_benchmarking`, `is_reserved`, the IPv6 unicast predicates)
//! are still unstable, and because an SSRF deny list must be auditable line by
//! line.
//!
//! Correctness hinges on the embedded-IPv4 forms. An attacker who cannot use a
//! bare `169.254.169.254` will try `::ffff:169.254.169.254` (IPv4-mapped),
//! `::169.254.169.254` (IPv4-compatible), a NAT64 or 6to4 wrapper, and so on.
//! [`classify`] extracts the embedded IPv4 address from every such form and runs
//! the IPv4 policy against it, then refuses the wrapping form outright: a DNS
//! answer for a normal name yields a bare `Ipv4Addr` for an A record, so a
//! v4-in-v6 literal reaching this layer is always a crafted bypass attempt.
//!
//! This deny set is deliberately not configurable. Loosening it (for example to
//! reach a metadata endpoint) reintroduces the very SSRF class the fetcher
//! exists to close; the knobs that ARE tunable are the response caps and the
//! scheme allowance, not which addresses count as internal.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why a resolved address was refused. The variant is an internal diagnostic
/// (it feeds a bounded-cardinality metric label and a structured log field); it
/// is never handed to a caller, whose error is the uniform
/// [`crate::FetchError::Blocked`] so the policy leaks no oracle for internal
/// topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockClass {
    /// `0.0.0.0/8` (this network) or the IPv6 unspecified `::`.
    Unspecified,
    /// IPv4 `127.0.0.0/8` or IPv6 `::1`.
    Loopback,
    /// IPv4 `10/8`, `172.16/12`, `192.168/16`, or IPv6 unique-local `fc00::/7`.
    Private,
    /// Carrier-grade NAT shared space, `100.64.0.0/10` (RFC 6598).
    SharedCgn,
    /// IPv4 `169.254.0.0/16` (the cloud metadata range that holds
    /// `169.254.169.254`) or IPv6 link-local `fe80::/10`.
    LinkLocal,
    /// Deprecated IPv6 site-local, `fec0::/10`.
    SiteLocal,
    /// IPv4 `224.0.0.0/4` or IPv6 `ff00::/8` multicast.
    Multicast,
    /// IPv4 `240.0.0.0/4` reserved-for-future-use (includes the limited
    /// broadcast `255.255.255.255`).
    Reserved,
    /// Documentation ranges reserved for examples, never live hosts
    /// (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).
    Documentation,
    /// IPv4 `198.18.0.0/15` (RFC 2544 benchmarking).
    Benchmarking,
    /// IETF protocol-assignment special-use blocks (`192.0.0.0/24`,
    /// `192.88.99.0/24`, IPv6 `2001::/23`, discard-only `100::/64`).
    ProtocolAssignment,
    /// A transitional wrapper that embeds an IPv4 address (IPv4-mapped,
    /// IPv4-compatible, NAT64 `64:ff9b::/96`, or 6to4 `2002::/16`) whose
    /// embedded address is itself public, refused because the wrapping form has
    /// no legitimate use for an outbound OP fetch.
    EmbeddedIpv4,
}

impl BlockClass {
    /// A stable, bounded-cardinality label for metrics and structured logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            BlockClass::Unspecified => "unspecified",
            BlockClass::Loopback => "loopback",
            BlockClass::Private => "private",
            BlockClass::SharedCgn => "shared_cgn",
            BlockClass::LinkLocal => "link_local",
            BlockClass::SiteLocal => "site_local",
            BlockClass::Multicast => "multicast",
            BlockClass::Reserved => "reserved",
            BlockClass::Documentation => "documentation",
            BlockClass::Benchmarking => "benchmarking",
            BlockClass::ProtocolAssignment => "protocol_assignment",
            BlockClass::EmbeddedIpv4 => "embedded_ipv4",
        }
    }
}

/// A fixed-length IPv4 CIDR block, matched by masking the address to bits.
struct Cidr4 {
    /// Network address, as the big-endian integer form of the base IPv4 address.
    base: u32,
    /// Prefix length in bits (`0..=32`).
    prefix: u32,
    /// The class charged when an address falls inside this block.
    class: BlockClass,
}

impl Cidr4 {
    /// Whether `addr` falls inside this block.
    fn contains(&self, addr: u32) -> bool {
        // A `/0` would shift by 32 (undefined for u32), but the table holds no
        // `/0`; every prefix is `>= 8`, so the shift is always well defined.
        let mask = u32::MAX << (32 - self.prefix);
        (addr & mask) == (self.base & mask)
    }
}

/// A fixed-length IPv6 CIDR block, matched by masking the address to bits.
struct Cidr6 {
    /// Network address, as the big-endian integer form of the base IPv6 address.
    base: u128,
    /// Prefix length in bits (`0..=128`).
    prefix: u32,
    /// The class charged when an address falls inside this block.
    class: BlockClass,
}

impl Cidr6 {
    /// Whether `addr` falls inside this block.
    fn contains(&self, addr: u128) -> bool {
        let mask = u128::MAX << (128 - self.prefix);
        (addr & mask) == (self.base & mask)
    }
}

/// The denied IPv4 ranges. Order does not matter (the ranges are disjoint);
/// every non-globally-routable and special-use block is listed with its reason.
const DENY_V4: &[Cidr4] = &[
    // 0.0.0.0/8: "this network" / current network; 0.0.0.0 is the unspecified
    // address. Never a routable destination (RFC 1122).
    Cidr4 {
        base: 0x0000_0000,
        prefix: 8,
        class: BlockClass::Unspecified,
    },
    // 10.0.0.0/8: RFC 1918 private.
    Cidr4 {
        base: 0x0A00_0000,
        prefix: 8,
        class: BlockClass::Private,
    },
    // 100.64.0.0/10: RFC 6598 carrier-grade NAT shared space.
    Cidr4 {
        base: 0x6440_0000,
        prefix: 10,
        class: BlockClass::SharedCgn,
    },
    // 127.0.0.0/8: loopback.
    Cidr4 {
        base: 0x7F00_0000,
        prefix: 8,
        class: BlockClass::Loopback,
    },
    // 169.254.0.0/16: link-local. Holds the cloud metadata service address
    // 169.254.169.254, the primary SSRF target.
    Cidr4 {
        base: 0xA9FE_0000,
        prefix: 16,
        class: BlockClass::LinkLocal,
    },
    // 172.16.0.0/12: RFC 1918 private.
    Cidr4 {
        base: 0xAC10_0000,
        prefix: 12,
        class: BlockClass::Private,
    },
    // 192.0.0.0/24: IETF protocol assignments (RFC 6890).
    Cidr4 {
        base: 0xC000_0000,
        prefix: 24,
        class: BlockClass::ProtocolAssignment,
    },
    // 192.0.2.0/24: TEST-NET-1 documentation.
    Cidr4 {
        base: 0xC000_0200,
        prefix: 24,
        class: BlockClass::Documentation,
    },
    // 192.88.99.0/24: deprecated 6to4 relay anycast.
    Cidr4 {
        base: 0xC058_6300,
        prefix: 24,
        class: BlockClass::ProtocolAssignment,
    },
    // 192.168.0.0/16: RFC 1918 private.
    Cidr4 {
        base: 0xC0A8_0000,
        prefix: 16,
        class: BlockClass::Private,
    },
    // 198.18.0.0/15: RFC 2544 benchmarking.
    Cidr4 {
        base: 0xC612_0000,
        prefix: 15,
        class: BlockClass::Benchmarking,
    },
    // 198.51.100.0/24: TEST-NET-2 documentation.
    Cidr4 {
        base: 0xC633_6400,
        prefix: 24,
        class: BlockClass::Documentation,
    },
    // 203.0.113.0/24: TEST-NET-3 documentation.
    Cidr4 {
        base: 0xCB00_7100,
        prefix: 24,
        class: BlockClass::Documentation,
    },
    // 224.0.0.0/4: multicast.
    Cidr4 {
        base: 0xE000_0000,
        prefix: 4,
        class: BlockClass::Multicast,
    },
    // 240.0.0.0/4: reserved for future use; includes 255.255.255.255, the
    // limited broadcast address.
    Cidr4 {
        base: 0xF000_0000,
        prefix: 4,
        class: BlockClass::Reserved,
    },
];

/// The denied IPv6 ranges (after the embedded-IPv4 forms are peeled off in
/// [`classify_v6`]). Unspecified and loopback are handled ahead of this table.
const DENY_V6: &[Cidr6] = &[
    // 64:ff9b::/96: the "well-known" NAT64 prefix; embeds an IPv4 address.
    Cidr6 {
        base: 0x0064_ff9b_0000_0000_0000_0000_0000_0000,
        prefix: 96,
        class: BlockClass::EmbeddedIpv4,
    },
    // 64:ff9b:1::/48: the RFC 8215 local-use NAT64 prefix; also embeds an IPv4
    // address (for example 64:ff9b:1::a9fe:a9fe is the metadata service under
    // the local NAT64 prefix), so it must be denied alongside the well-known one.
    Cidr6 {
        base: 0x0064_ff9b_0001_0000_0000_0000_0000_0000,
        prefix: 48,
        class: BlockClass::EmbeddedIpv4,
    },
    // 100::/64: discard-only address block (RFC 6666).
    Cidr6 {
        base: 0x0100_0000_0000_0000_0000_0000_0000_0000,
        prefix: 64,
        class: BlockClass::ProtocolAssignment,
    },
    // 2001::/23: IETF protocol assignments (Teredo 2001::/32, ORCHIDv2,
    // benchmarking, and friends all live here).
    Cidr6 {
        base: 0x2001_0000_0000_0000_0000_0000_0000_0000,
        prefix: 23,
        class: BlockClass::ProtocolAssignment,
    },
    // 2001:db8::/32: documentation.
    Cidr6 {
        base: 0x2001_0db8_0000_0000_0000_0000_0000_0000,
        prefix: 32,
        class: BlockClass::Documentation,
    },
    // 2002::/16: 6to4; embeds an IPv4 address in the prefix.
    Cidr6 {
        base: 0x2002_0000_0000_0000_0000_0000_0000_0000,
        prefix: 16,
        class: BlockClass::EmbeddedIpv4,
    },
    // 3fff::/20: documentation (RFC 9637), reserved for examples like 2001:db8.
    Cidr6 {
        base: 0x3fff_0000_0000_0000_0000_0000_0000_0000,
        prefix: 20,
        class: BlockClass::Documentation,
    },
    // Known limitation: the enumerated-wrapper approach denies the standard
    // IPv4-in-IPv6 embeddings above (mapped, compatible, NAT64, 6to4), but does
    // not decode ISATAP (`...::5efe:a.b.c.d`) or SRv6 uSID embeddings. Reaching
    // an internal address through those requires nonstandard tunnel
    // infrastructure between the OP and the target; on a normal deployment DNS
    // never yields such an address and the direct forms are already denied.
    // fc00::/7: unique-local addresses (the IPv6 analogue of RFC 1918).
    Cidr6 {
        base: 0xfc00_0000_0000_0000_0000_0000_0000_0000,
        prefix: 7,
        class: BlockClass::Private,
    },
    // fe80::/10: link-local unicast.
    Cidr6 {
        base: 0xfe80_0000_0000_0000_0000_0000_0000_0000,
        prefix: 10,
        class: BlockClass::LinkLocal,
    },
    // fec0::/10: deprecated site-local.
    Cidr6 {
        base: 0xfec0_0000_0000_0000_0000_0000_0000_0000,
        prefix: 10,
        class: BlockClass::SiteLocal,
    },
    // ff00::/8: multicast.
    Cidr6 {
        base: 0xff00_0000_0000_0000_0000_0000_0000_0000,
        prefix: 8,
        class: BlockClass::Multicast,
    },
];

/// Classify a resolved address. Returns `Some(class)` if the address is denied
/// (the fetch must be blocked), `None` if it is an acceptable global-unicast
/// destination.
///
/// This is the single decision point the connector consults for EVERY resolved
/// address; it is also exported so the fuzz target and the stable adversarial
/// table exercise the exact function the connector uses.
#[must_use]
pub fn classify(ip: IpAddr) -> Option<BlockClass> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Classify an IPv4 address against [`DENY_V4`].
fn classify_v4(v4: Ipv4Addr) -> Option<BlockClass> {
    let bits = v4.to_bits();
    DENY_V4
        .iter()
        .find(|net| net.contains(bits))
        .map(|net| net.class)
}

/// Classify an IPv6 address, peeling off the embedded-IPv4 forms first.
fn classify_v6(v6: Ipv6Addr) -> Option<BlockClass> {
    // Unspecified (::) and loopback (::1) are exact addresses handled up front;
    // both would also match the embedded-IPv4 extraction below (as 0.0.0.0 and
    // 0.0.0.1), so classify them here for the precise reason.
    if v6.is_unspecified() {
        return Some(BlockClass::Unspecified);
    }
    if v6.is_loopback() {
        return Some(BlockClass::Loopback);
    }
    // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) both surface
    // through `to_ipv4`. Extract the embedded IPv4 and run the IPv4 policy so a
    // denied address cannot hide inside a v6 literal; if the embedded address is
    // itself public, still refuse the wrapping form (see the module docs).
    if let Some(embedded) = v6.to_ipv4() {
        return Some(classify_v4(embedded).unwrap_or(BlockClass::EmbeddedIpv4));
    }
    let bits = v6.to_bits();
    DENY_V6
        .iter()
        .find(|net| net.contains(bits))
        .map(|net| net.class)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().expect("test ipv4 literal"))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().expect("test ipv6 literal"))
    }

    #[test]
    fn cloud_metadata_address_is_link_local() {
        assert_eq!(classify(v4("169.254.169.254")), Some(BlockClass::LinkLocal));
    }

    #[test]
    fn private_and_loopback_ranges_are_denied() {
        assert_eq!(classify(v4("10.0.0.1")), Some(BlockClass::Private));
        assert_eq!(classify(v4("172.16.5.4")), Some(BlockClass::Private));
        assert_eq!(classify(v4("172.31.255.255")), Some(BlockClass::Private));
        assert_eq!(classify(v4("192.168.1.1")), Some(BlockClass::Private));
        assert_eq!(classify(v4("127.0.0.1")), Some(BlockClass::Loopback));
        assert_eq!(classify(v4("0.0.0.0")), Some(BlockClass::Unspecified));
        assert_eq!(classify(v4("100.64.0.1")), Some(BlockClass::SharedCgn));
        assert_eq!(classify(v4("198.18.0.1")), Some(BlockClass::Benchmarking));
        assert_eq!(classify(v4("192.0.2.1")), Some(BlockClass::Documentation));
        assert_eq!(classify(v4("255.255.255.255")), Some(BlockClass::Reserved));
        assert_eq!(classify(v4("224.0.0.1")), Some(BlockClass::Multicast));
    }

    #[test]
    fn every_special_use_range_has_a_denied_representative() {
        // The ranges not exercised elsewhere, so every DENY_V4 / DENY_V6 entry
        // has at least one explicit assertion.
        assert_eq!(
            classify(v4("192.0.0.1")),
            Some(BlockClass::ProtocolAssignment)
        );
        assert_eq!(
            classify(v4("192.88.99.1")),
            Some(BlockClass::ProtocolAssignment)
        );
        assert_eq!(
            classify(v4("198.51.100.1")),
            Some(BlockClass::Documentation)
        );
        assert_eq!(classify(v4("203.0.113.1")), Some(BlockClass::Documentation));
        assert_eq!(classify(v6("100::1")), Some(BlockClass::ProtocolAssignment));
        assert_eq!(
            classify(v6("2001::1")),
            Some(BlockClass::ProtocolAssignment)
        );
        // RFC 9637 documentation prefix.
        assert_eq!(classify(v6("3fff::1")), Some(BlockClass::Documentation));
        // Just outside 3fff::/20 is ordinary global unicast.
        assert_eq!(classify(v6("3fff:1000::1")), None);
    }

    #[test]
    fn local_nat64_prefix_cannot_smuggle_the_metadata_address() {
        // 64:ff9b:1::/48 is the RFC 8215 local-use NAT64 prefix; without an
        // explicit deny entry, 64:ff9b:1::a9fe:a9fe (the metadata service under
        // the local NAT64 prefix) would classify as allowed.
        assert_eq!(
            classify(v6("64:ff9b:1::a9fe:a9fe")),
            Some(BlockClass::EmbeddedIpv4)
        );
        assert_eq!(classify(v6("64:ff9b:1::1")), Some(BlockClass::EmbeddedIpv4));
    }

    #[test]
    fn boundaries_of_private_blocks_are_respected() {
        // 172.16.0.0/12 spans 172.16.0.0 through 172.31.255.255 only.
        assert_eq!(classify(v4("172.15.255.255")), None);
        assert_eq!(classify(v4("172.32.0.0")), None);
        // 100.64.0.0/10 spans 100.64 through 100.127; 100.128 is public.
        assert_eq!(classify(v4("100.128.0.1")), None);
        // 198.18.0.0/15 spans 198.18 and 198.19; 198.20 is public.
        assert_eq!(classify(v4("198.20.0.1")), None);
    }

    #[test]
    fn ordinary_public_addresses_are_allowed() {
        assert_eq!(classify(v4("93.184.216.34")), None);
        assert_eq!(classify(v4("8.8.8.8")), None);
        assert_eq!(classify(v4("1.1.1.1")), None);
        assert_eq!(classify(v6("2606:2800:220:1:248:1893:25c8:1946")), None);
    }

    #[test]
    fn ipv6_special_ranges_are_denied() {
        assert_eq!(classify(v6("::1")), Some(BlockClass::Loopback));
        assert_eq!(classify(v6("::")), Some(BlockClass::Unspecified));
        assert_eq!(classify(v6("fc00::1")), Some(BlockClass::Private));
        assert_eq!(classify(v6("fd12:3456::1")), Some(BlockClass::Private));
        assert_eq!(classify(v6("fe80::1")), Some(BlockClass::LinkLocal));
        assert_eq!(classify(v6("fec0::1")), Some(BlockClass::SiteLocal));
        assert_eq!(classify(v6("ff02::1")), Some(BlockClass::Multicast));
        assert_eq!(classify(v6("2001:db8::1")), Some(BlockClass::Documentation));
        assert_eq!(classify(v6("64:ff9b::1")), Some(BlockClass::EmbeddedIpv4));
        assert_eq!(classify(v6("2002::1")), Some(BlockClass::EmbeddedIpv4));
    }

    #[test]
    fn ipv4_mapped_and_compatible_forms_cannot_smuggle_a_denied_address() {
        // The crux bypass: a denied IPv4 wrapped in an IPv6 literal. The
        // embedded address is extracted and classified with its precise reason.
        assert_eq!(
            classify(v6("::ffff:169.254.169.254")),
            Some(BlockClass::LinkLocal)
        );
        assert_eq!(classify(v6("::ffff:127.0.0.1")), Some(BlockClass::Loopback));
        assert_eq!(classify(v6("::ffff:10.0.0.1")), Some(BlockClass::Private));
        // IPv4-compatible form (::a.b.c.d) of a private address.
        assert_eq!(classify(v6("::192.168.0.1")), Some(BlockClass::Private));
        // A public IPv4 wrapped in a v6 literal is still refused as a
        // non-canonical form, never allowed through.
        assert_eq!(
            classify(v6("::ffff:93.184.216.34")),
            Some(BlockClass::EmbeddedIpv4)
        );
    }

    #[test]
    fn every_block_class_has_a_distinct_stable_label() {
        // The labels feed a bounded-cardinality metric; a collision would merge
        // two reasons into one series.
        let classes = [
            BlockClass::Unspecified,
            BlockClass::Loopback,
            BlockClass::Private,
            BlockClass::SharedCgn,
            BlockClass::LinkLocal,
            BlockClass::SiteLocal,
            BlockClass::Multicast,
            BlockClass::Reserved,
            BlockClass::Documentation,
            BlockClass::Benchmarking,
            BlockClass::ProtocolAssignment,
            BlockClass::EmbeddedIpv4,
        ];
        let mut labels: Vec<&str> = classes.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "block-class labels must be distinct");
    }
}
