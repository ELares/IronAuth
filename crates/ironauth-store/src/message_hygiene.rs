// SPDX-License-Identifier: MIT OR Apache-2.0

//! Send hygiene: recipient normalization, suppression and dedup (issue #111).
//!
//! Three of issue #111's acceptance criteria are decided here, and all three turn on the same
//! question: when are two written addresses the SAME mailbox?
//!
//! - duplicate verification sends within the dedup window collapse to one delivery;
//! - sends to suppressed addresses are blocked and recorded with a queryable reason;
//! - the per-recipient rate limit is keyed on a recipient, which first has to be identified.
//!
//! Pure and sans-IO. The window index is passed in rather than derived, so this crate reads no
//! clock and the boundary cases are testable with fixed numbers.
//!
//! # The normalization decision, and the letter of the spec it departs from
//!
//! RFC 5321 section 2.4 is explicit: the domain is case-insensitive, and the local part is
//! case-SENSITIVE and may only be interpreted by the receiving host. By the letter,
//! `Ada@example.test` and `ada@example.test` are different mailboxes.
//!
//! [`normalize_recipient`] lowercases BOTH anyway, and that is a deliberate departure. Consider
//! what each error costs:
//!
//! - Treating them as DIFFERENT: a user who unsubscribed as `Ada@example.test` keeps receiving
//!   mail sent to `ada@example.test`. That is a compliance failure and a complaint, and the
//!   sender's domain reputation pays for it.
//! - Treating them as the SAME: two genuinely distinct mailboxes on a host that honours case
//!   share a suppression entry and a dedup window. Essentially no mail host in service does
//!   this; the ones that did are gone.
//!
//! The first error is common and expensive, the second is theoretical. What is NOT done is any
//! provider-specific folding: gmail-style dot-stripping and `+tag` removal are refused, because
//! they are guesses about a host's routing that would silently merge addresses that really are
//! distinct at any host not following that convention.
//!
//! Both the suppression check and the dedup key use the SAME normalization, deliberately.
//! Splitting them would mean an address could be suppressed under one identity and deduplicated
//! under another, and the two rules would disagree about who the recipient is.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

/// Why a send was blocked. Stored so the block is queryable rather than a silent drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// The exact address is on the suppression list.
    AddressSuppressed,
    /// The address's DOMAIN is suppressed, which blocks every mailbox under it.
    DomainSuppressed,
}

impl BlockReason {
    /// A stable, value-free description.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AddressSuppressed => "the recipient address is on the suppression list",
            Self::DomainSuppressed => "the recipient's domain is on the suppression list",
        }
    }
}

/// Normalize a recipient address into the identity every hygiene rule keys on.
///
/// Trims surrounding whitespace and lowercases the whole address. Returns [`None`] for anything
/// without exactly one `@` with a non-empty side each, which is not a mailbox and must not be
/// silently turned into one.
///
/// See the module documentation for why the local part is lowercased despite RFC 5321 section
/// 2.4, and why provider-specific folding is refused.
#[must_use]
pub fn normalize_recipient(address: &str) -> Option<String> {
    let trimmed = address.trim();
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    // Whitespace anywhere inside an address is not a mailbox; accepting it would let two
    // spellings of one address key differently.
    if trimmed.chars().any(char::is_whitespace) {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// The domain half of an already-normalized address.
fn domain_of(normalized: &str) -> Option<&str> {
    normalized.split_once('@').map(|(_, domain)| domain)
}

/// Whether `address` is suppressed, and why.
///
/// `suppressed_addresses` and `suppressed_domains` are expected to hold NORMALIZED values; a
/// caller that stores raw input will silently under-match, which is why
/// [`normalize_recipient`] is applied to both sides at the point of writing.
///
/// An address that does not normalize is treated as suppressed under
/// [`BlockReason::AddressSuppressed`]: it is not a mailbox, so there is nothing to send to, and
/// the block is recorded rather than the send failing somewhere further down with less context.
#[must_use]
pub fn suppression_check(
    address: &str,
    suppressed_addresses: &BTreeSet<String>,
    suppressed_domains: &BTreeSet<String>,
) -> Option<BlockReason> {
    let Some(normalized) = normalize_recipient(address) else {
        return Some(BlockReason::AddressSuppressed);
    };
    if suppressed_addresses.contains(&normalized) {
        return Some(BlockReason::AddressSuppressed);
    }
    // The domain check is separate and reported separately: an operator suppressing a whole
    // domain after a bounce storm needs to see that reason, not "address suppressed" for
    // thousands of addresses they never listed.
    let domain = domain_of(&normalized)?;
    if suppressed_domains.contains(domain) {
        return Some(BlockReason::DomainSuppressed);
    }
    None
}

/// The window index an instant falls in, given a window length.
///
/// Fixed windows rather than a sliding one, on purpose. A sliding window needs the timestamps
/// of prior sends; a fixed window needs one integer, which makes the dedup key a pure function
/// of things a caller already has. The cost is a boundary: two sends either side of a window
/// edge are NOT duplicates even if they are a second apart. For "do not send the same
/// verification email twice in a minute" that is an acceptable miss, and it is stated here
/// rather than discovered.
///
/// # Panics
///
/// Never; `window_seconds` of zero is treated as one, so a misconfiguration degrades to
/// per-second windows instead of dividing by zero.
#[must_use]
pub fn window_index(epoch_seconds: u64, window_seconds: u64) -> u64 {
    epoch_seconds / window_seconds.max(1)
}

/// The dedup key for one intended send.
///
/// Two sends collapse when their `kind`, normalized recipient and window index all agree. The
/// key is a SHA-256 digest rather than the parts joined, so it can be stored and indexed
/// without putting a recipient address in a key column that gets logged, exported and copied
/// into support tickets.
///
/// The parts are length-prefixed before hashing. Joining with a separator would let a crafted
/// `kind` and recipient collide with a different pair: with a plain `:`, the pair
/// `("verify:a", "b@x")` and `("verify", "a:b@x")` hash identically, so one message kind could
/// be made to suppress another's sends.
///
/// Returns [`None`] when the address is not a mailbox; there is nothing to deduplicate.
#[must_use]
pub fn dedup_key(kind: &str, address: &str, window: u64) -> Option<String> {
    let normalized = normalize_recipient(address)?;
    let mut hasher = Sha256::new();
    for part in [kind.as_bytes(), normalized.as_bytes()] {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    hasher.update(window.to_be_bytes());
    Some(hex(&hasher.finalize()))
}

/// Lowercase hex of a digest.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{BlockReason, dedup_key, normalize_recipient, suppression_check, window_index};

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// The whole address is lowercased, departing from RFC 5321 section 2.4 deliberately.
    ///
    /// Treating `Ada@` and `ada@` as different mailboxes means a user who unsubscribed as one
    /// keeps receiving mail sent to the other, which is a compliance failure that costs the
    /// sender's domain reputation. The opposite error requires a mail host that honours local
    /// part case, which is essentially extinct.
    #[test]
    fn normalization_folds_case_in_both_halves() {
        assert_eq!(
            normalize_recipient("Ada@Example.TEST").expect("a mailbox"),
            "ada@example.test"
        );
        assert_eq!(
            normalize_recipient("  ada@example.test  ").expect("a mailbox"),
            "ada@example.test"
        );
    }

    /// Provider-specific folding is REFUSED. Stripping dots or `+tags` is a guess about one
    /// host's routing that would merge addresses genuinely distinct at any other host.
    #[test]
    fn normalization_does_not_apply_provider_specific_folding() {
        assert_ne!(
            normalize_recipient("a.da@example.test"),
            normalize_recipient("ada@example.test"),
        );
        assert_ne!(
            normalize_recipient("ada+news@example.test"),
            normalize_recipient("ada@example.test"),
        );
    }

    #[test]
    fn a_non_mailbox_does_not_normalize() {
        for value in [
            "",
            "no-at-sign",
            "@example.test",
            "ada@",
            "a@b@c",
            "ada @example.test",
            "ada@exa mple.test",
        ] {
            assert_eq!(
                normalize_recipient(value),
                None,
                "{value:?} is not a mailbox"
            );
        }
    }

    /// Suppression matches regardless of the case it was written in, on either side.
    #[test]
    fn suppression_matches_across_case() {
        let addresses = set(&["ada@example.test"]);
        let domains = BTreeSet::new();
        for written in [
            "ada@example.test",
            "Ada@Example.Test",
            "  ADA@EXAMPLE.TEST ",
        ] {
            assert_eq!(
                suppression_check(written, &addresses, &domains),
                Some(BlockReason::AddressSuppressed),
                "{written} must be suppressed"
            );
        }
        assert_eq!(
            suppression_check("other@example.test", &addresses, &domains),
            None,
            "an unlisted address must still be sendable"
        );
    }

    /// A suppressed domain blocks every mailbox under it, and reports a DIFFERENT reason.
    ///
    /// An operator suppressing a whole domain after a bounce storm needs to see that, not
    /// "address suppressed" for thousands of addresses they never listed.
    #[test]
    fn a_suppressed_domain_blocks_its_mailboxes_with_its_own_reason() {
        let addresses = BTreeSet::new();
        let domains = set(&["bounced.test"]);
        assert_eq!(
            suppression_check("anyone@bounced.test", &addresses, &domains),
            Some(BlockReason::DomainSuppressed),
        );
        assert_eq!(
            suppression_check("anyone@other.test", &addresses, &domains),
            None,
        );
        // A domain entry must not match a SUBSTRING: `notbounced.test` is a different domain.
        assert_eq!(
            suppression_check("anyone@notbounced.test", &addresses, &domains),
            None,
            "domain suppression must not match by substring"
        );
    }

    /// The address check runs first, so an address listed explicitly reports as such even when
    /// its domain is also suppressed.
    #[test]
    fn an_explicit_address_entry_takes_precedence_over_its_domain() {
        let addresses = set(&["ada@bounced.test"]);
        let domains = set(&["bounced.test"]);
        assert_eq!(
            suppression_check("ada@bounced.test", &addresses, &domains),
            Some(BlockReason::AddressSuppressed),
        );
    }

    /// Something that is not a mailbox is blocked rather than attempted.
    #[test]
    fn a_malformed_address_is_blocked_not_sent() {
        assert_eq!(
            suppression_check("not-an-address", &BTreeSet::new(), &BTreeSet::new()),
            Some(BlockReason::AddressSuppressed),
        );
    }

    #[test]
    fn the_window_index_advances_once_per_window() {
        assert_eq!(window_index(0, 60), 0);
        assert_eq!(window_index(59, 60), 0);
        assert_eq!(window_index(60, 60), 1);
        assert_eq!(window_index(119, 60), 1);
        // A zero window degrades to one second rather than dividing by zero.
        assert_eq!(window_index(5, 0), 5);
    }

    /// Duplicates inside one window collapse; the next window is a new send.
    #[test]
    fn the_dedup_key_collapses_a_window_and_reopens_on_the_next() {
        let first = dedup_key("verify", "ada@example.test", 100).expect("a key");
        let same = dedup_key("verify", "Ada@Example.Test", 100).expect("a key");
        assert_eq!(
            first, same,
            "the same mailbox in the same window is one send"
        );
        let next = dedup_key("verify", "ada@example.test", 101).expect("a key");
        assert_ne!(first, next, "a new window is a new send");
    }

    /// The kind and the recipient both participate, or one message type would suppress another.
    #[test]
    fn the_dedup_key_separates_kinds_and_recipients() {
        let verify = dedup_key("verify", "ada@example.test", 1).expect("a key");
        let reset = dedup_key("reset", "ada@example.test", 1).expect("a key");
        let other = dedup_key("verify", "bob@example.test", 1).expect("a key");
        assert_ne!(verify, reset, "a reset must not be suppressed by a verify");
        assert_ne!(verify, other, "one recipient must not suppress another");
    }

    /// THE collision property: length prefixing, so no crafted pair can collide.
    ///
    /// With a plain separator, `("verify:a", "b@x.test")` and `("verify", "a:b@x.test")` hash
    /// identically, which would let one message kind be made to suppress another's sends.
    #[test]
    fn the_dedup_key_cannot_be_made_to_collide_by_choosing_a_kind() {
        let left = dedup_key("verify:a", "b@x.test", 1).expect("a key");
        let right = dedup_key("verify", "a:b@x.test", 1).expect("a key");
        assert_ne!(left, right);
        let dotted = dedup_key("verify.a", "b@x.test", 1).expect("a key");
        assert_ne!(dotted, dedup_key("verify", "a.b@x.test", 1).expect("a key"));
    }

    /// The key is a digest, so a recipient address never lands in a key column.
    #[test]
    fn the_dedup_key_does_not_carry_the_address() {
        let key = dedup_key("verify", "ada@example.test", 1).expect("a key");
        assert_eq!(key.len(), 64, "a hex sha256");
        assert!(
            !key.contains("ada"),
            "the address must not survive into the key"
        );
        assert!(!key.contains("example"));
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_malformed_address_has_no_dedup_key() {
        assert_eq!(dedup_key("verify", "not-an-address", 1), None);
    }

    #[test]
    fn every_block_reason_describes_itself_distinctly() {
        let all = [
            BlockReason::AddressSuppressed,
            BlockReason::DomainSuppressed,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for reason in all {
            assert!(reason.as_str().len() > 20);
            assert!(seen.insert(reason.as_str()), "{reason:?} shares its text");
        }
        assert_eq!(seen.len(), all.len());
    }
}
