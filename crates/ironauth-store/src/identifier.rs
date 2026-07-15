// SPDX-License-Identifier: MIT OR Apache-2.0

//! The central identifier canonicalization seam (issue #54).
//!
//! Canonicalization drift is a recurring CVE generator: when each endpoint
//! normalizes a login handle its own way, a value that looks the same to a human
//! (or that folds to the same account) is treated as two different identities by
//! the login path, the lockout counter, and the access-control check, and the gap
//! between those views is the vulnerability (Authelia CVE-2026-47203 /
//! CVE-2025-24806 / CVE-2026-48794, Zitadel CVE-2025-31124). The one durable fix,
//! which nobody ships as an explicit seam, is a SINGLE canonicalization function
//! applied exactly ONCE at the boundary, so every comparison, uniqueness check,
//! and (future, M7) lockout / access decision operates only on the canonical form.
//!
//! This module is that seam. [`canonicalize_identifier`] is the ONE entry point;
//! it is the only place a [`CanonicalIdentifier`] is minted (the type's fields are
//! private, so no other module can fabricate one), which makes "route through the
//! seam" a property the compiler enforces rather than a convention. The store's
//! flexible-identifier blind index, uniqueness constraint, and identifier-first
//! resolution all take a `&CanonicalIdentifier`, so a raw handle can never reach a
//! comparison site without first passing through here. `scripts/canonicalization-seam.sh`
//! is a belt-and-suspenders CI lint that backstops the type-level guarantee.
//!
//! ## The canonicalization policy
//!
//! [`canonicalize_identifier`] is TOTAL (it never panics on any input) and
//! IDEMPOTENT (`canonicalize(canonicalize(x)) == canonicalize(x)`), verified by the
//! property tests below and the `canonicalize_identifier` fuzz target. It applies,
//! in order:
//!
//!   1. Strip Unicode invisible and control characters everywhere in the input:
//!      every C0/C1 control, plus the zero-width, bidirectional-format, and
//!      default-ignorable code points a homoglyph or direction-override attack
//!      hides in a handle (see [`is_invisible_or_control`]). A tab, a newline, a
//!      zero-width joiner, and a right-to-left override all vanish, so two handles
//!      that differ only by invisible padding are ONE identifier.
//!   2. Apply Unicode NFKC (Normalization Form KC): compatibility decomposition
//!      then canonical composition. This folds the large confusable class of
//!      compatibility variants (fullwidth ASCII, circled and superscript forms,
//!      ligatures) onto their ordinary forms, and composes combining sequences, so
//!      `Ａ` and `A` are the same starter.
//!   3. Trim leading and trailing Unicode whitespace.
//!   4. Apply the per-type policy (see below).
//!
//! ### Per-type case folding and shape (RFC 8264 / RFC 8265 PRECIS, informative)
//!
//!   * `email`: split on the LAST `@`; when the result is a nonempty local part and
//!     a nonempty domain, case-fold BOTH parts and recombine `local@domain`.
//!     Folding the domain is uncontroversial (DNS is case-insensitive). Folding the
//!     local part is a DELIBERATE, DOCUMENTED policy choice: RFC 5321 permits
//!     case-sensitive local parts, but every mainstream mailbox provider treats
//!     them case-insensitively, and a case-sensitive login handle is a canonical
//!     enumeration / duplicate-account footgun, so IronAuth folds it. An input with
//!     no usable `@` shape falls back to a whole-string fold (still total).
//!   * `username`: Unicode case-fold the whole value (the PRECIS
//!     `UsernameCaseMapped` profile's case-mapping rule, approximated by Unicode
//!     lowercase, which is deterministic and idempotent).
//!   * `phone`: STRUCTURAL E.164 (ITU-T E.164) normalization: keep only ASCII
//!     digits and emit `+<digits>`. This strips every visual separator (spaces,
//!     hyphens, parentheses, the fullwidth digits already folded by NFKC) so
//!     `+1 (415) 555-0100` and `+14155550100` are one identifier. It does NOT infer
//!     a country code from a national number (that needs a region context and a
//!     libphonenumber-scale table, out of scope here and a heavy dependency): a
//!     caller submits an already-international number. An input with no digits folds
//!     as a plain string so it stays distinct rather than collapsing to `+`.
//!
//! Case folding uses Unicode lowercase (`str::to_lowercase`) rather than full
//! Unicode case folding: lowercase is in the standard library (no new dependency),
//! is deterministic, and is idempotent, and it collapses the mixed-case
//! enumeration class the named CVEs exploit. Full caseless matching of the rare
//! characters where lowercase and case-fold diverge is a later refinement.

use unicode_normalization::UnicodeNormalization;

/// The kind of a login identifier (issue #54). Each kind has its own canonical
/// form and case-folding policy; the kind is bound into the blind index so the
/// SAME string as an email and as a username never produces a colliding uniqueness
/// tag. Which trait fields are identifiers, and of which kind, is declared by the
/// #53 behavior annotations (`x-ironauth: { identifier: true, verification: ... }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentifierType {
    /// An email address. Canonical form folds both the local part and the domain.
    Email,
    /// A username / login name. Canonical form is the Unicode case-fold.
    Username,
    /// A telephone number. Canonical form is structural E.164 (`+<digits>`).
    Phone,
}

impl IdentifierType {
    /// The stable wire tag stored in `user_identifiers.identifier_type` and bound
    /// into the blind index and the seal AAD.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            IdentifierType::Email => "email",
            IdentifierType::Username => "username",
            IdentifierType::Phone => "phone",
        }
    }

    /// Parse a stored / submitted wire tag back to the typed kind. Returns [`None`]
    /// for any unknown value (the caller treats it as a uniform not-found).
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "email" => Some(IdentifierType::Email),
            "username" => Some(IdentifierType::Username),
            "phone" => Some(IdentifierType::Phone),
            _ => None,
        }
    }
}

/// A canonicalized login identifier: the output of [`canonicalize_identifier`], and
/// the ONLY value the store's flexible-identifier blind index, uniqueness check,
/// and resolution API accept.
///
/// Its fields are private and it is constructed nowhere but [`canonicalize_identifier`],
/// so a raw handle cannot reach a comparison site without passing through the seam:
/// the "canonicalize exactly once, before every comparison" invariant is enforced
/// by the type system, not merely by review. Carries its [`IdentifierType`] so the
/// blind index binds the kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalIdentifier {
    kind: IdentifierType,
    value: String,
}

impl CanonicalIdentifier {
    /// The identifier kind this canonical form was produced for.
    #[must_use]
    pub fn kind(&self) -> IdentifierType {
        self.kind
    }

    /// The canonical string. Every comparison, blind index, and uniqueness check
    /// operates on exactly these bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// The one canonicalization seam (issue #54): produce the canonical form of a raw
/// login identifier of a given [`IdentifierType`].
///
/// This is the SINGLE entry point every comparison, uniqueness check, and
/// resolution routes through, and the ONLY constructor of a [`CanonicalIdentifier`].
/// It is TOTAL (never panics on any input, including arbitrary or invalid Unicode)
/// and IDEMPOTENT (canonicalizing an already-canonical value returns it unchanged).
/// See the module documentation for the full, per-type policy.
#[must_use]
pub fn canonicalize_identifier(kind: IdentifierType, raw: &str) -> CanonicalIdentifier {
    // 1. Strip invisible and control characters everywhere.
    let stripped: String = raw
        .chars()
        .filter(|&c| !is_invisible_or_control(c))
        .collect();
    // 2. NFKC compatibility normalization, then 3. trim surrounding whitespace.
    let normalized: String = stripped.nfkc().collect();
    let base = normalized.trim();
    // 4. Per-type shape and case folding.
    let value = match kind {
        IdentifierType::Email => canonical_email(base),
        IdentifierType::Username => case_fold(base),
        IdentifierType::Phone => canonical_phone(base),
    };
    CanonicalIdentifier { kind, value }
}

/// Unicode case-fold approximated by lowercase, re-normalized to NFKC so the output
/// is stable under a second pass. Lowercasing an NFKC string can, for a few code
/// points, yield a non-NFKC sequence; the trailing NFKC restores the form without
/// changing case, so `case_fold(case_fold(x)) == case_fold(x)`.
fn case_fold(value: &str) -> String {
    value.to_lowercase().nfkc().collect()
}

/// The canonical email form: fold the local part and the domain independently and
/// recombine. Splitting on the LAST `@` keeps a quoted `@` inside the local part
/// with the local part, and folding never introduces or moves an `@`, so the split
/// is stable under a second pass (idempotence).
fn canonical_email(base: &str) -> String {
    match base.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            format!("{}@{}", case_fold(local), case_fold(domain))
        }
        // No usable `@` shape: fold the whole value so it stays a distinct
        // identifier rather than being silently reshaped.
        _ => case_fold(base),
    }
}

/// The canonical phone form: structural E.164. Keep only ASCII digits and prefix a
/// single `+`. An input with no digits is folded as a plain string so two distinct
/// non-numeric inputs stay distinct (they do not both collapse to a bare `+`).
fn canonical_phone(base: &str) -> String {
    let digits: String = base.chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        case_fold(base)
    } else {
        format!("+{digits}")
    }
}

/// Whether a character is stripped as an invisible or control character (step 1 of
/// canonicalization). Covers every Unicode control character (C0, C1, DEL, and the
/// line/paragraph separators, via [`char::is_control`]) plus the curated set of
/// zero-width, bidirectional-format, and default-ignorable code points that carry
/// no visible glyph and exist mainly to smuggle a difference past a naive
/// comparator. The set is explicit (not a Unicode-category lookup) so it needs no
/// property-table dependency and every stripped code point is auditable here.
fn is_invisible_or_control(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    matches!(c,
        '\u{00AD}'                       // SOFT HYPHEN
        | '\u{061C}'                     // ARABIC LETTER MARK
        | '\u{115F}' | '\u{1160}'        // HANGUL CHOSEONG / JUNGSEONG FILLER
        | '\u{17B4}' | '\u{17B5}'        // KHMER vowel inherent AQ / AA
        | '\u{180B}'..='\u{180F}'        // MONGOLIAN free variation / vowel separators
        | '\u{200B}'..='\u{200F}'        // ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
        | '\u{202A}'..='\u{202E}'        // bidi embeddings and overrides
        | '\u{2060}'..='\u{2064}'        // WORD JOINER .. INVISIBLE PLUS
        | '\u{2066}'..='\u{206F}'        // bidi isolates and deprecated format
        | '\u{3164}'                     // HANGUL FILLER
        | '\u{FE00}'..='\u{FE0F}'        // variation selectors 1..16
        | '\u{FEFF}'                     // ZERO WIDTH NO-BREAK SPACE / BOM
        | '\u{FFA0}'                     // HALFWIDTH HANGUL FILLER
        | '\u{FFF9}'..='\u{FFFB}'        // interlinear annotation anchors
        | '\u{1BCA0}'..='\u{1BCA3}'      // Shorthand format controls
        | '\u{1D173}'..='\u{1D17A}'      // musical beam/slur/phrase format
        | '\u{E0000}'..='\u{E0FFF}'      // Tags and variation selectors supplement
    )
}

/// The per-environment identifier UNIQUENESS mode (issue #54). Uniqueness is a
/// POLICY choice, not a fixed rule baked into a schema constraint: a greenfield
/// identity model bakes in scoped uniqueness on day one rather than retrofitting it
/// later (Zitadel #9535, Auth0's multi-year path to non-unique emails). The mode is
/// the authoritative value the store enforces; its safe default and the operator
/// setting live in `ironauth_config` (`identifiers.uniqueness`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniquenessMode {
    /// Environment-wide (tenant + environment) uniqueness: a canonical identifier
    /// of a given kind maps to at most one user in the whole environment. The safe
    /// default.
    EnvironmentWide,
    /// Organization-scoped uniqueness: a canonical identifier is unique within an
    /// org, so two users in DIFFERENT orgs may share one. Meaningful once M10 org
    /// membership ships; until then (and for any user with no org membership) it
    /// falls back to the environment-wide scope, so a membership-free user is
    /// checked exactly as under [`UniquenessMode::EnvironmentWide`].
    OrgScoped,
    /// Non-unique mode: multiple users may share one canonical identifier.
    /// Identifier-first login still resolves deterministically (it returns every
    /// matching user's methods; the factor step, M7, disambiguates).
    NonUnique,
}

impl UniquenessMode {
    /// The uniqueness discriminator stored on a new identifier row for `self`,
    /// given the user's org membership context (`org` is the user's owning org id
    /// when org membership applies, else [`None`]).
    ///
    /// A `Some(key)` row participates in the partial unique index (a second row
    /// with the same key + kind + canonical blind index is rejected); a `None` row
    /// is exempt (non-unique mode). Environment-wide mode uses a constant key, so
    /// the index collapses to per-(scope, kind, canonical) uniqueness. Org-scoped
    /// mode keys on the org id, falling back to the environment-wide constant for a
    /// membership-free user.
    #[must_use]
    pub fn uniqueness_key(self, org: Option<&str>) -> Option<String> {
        match self {
            UniquenessMode::EnvironmentWide => Some("env".to_string()),
            UniquenessMode::OrgScoped => {
                Some(org.map_or_else(|| "env".to_string(), |id| format!("org:{id}")))
            }
            UniquenessMode::NonUnique => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonicalize and return the bare string, for terse assertions.
    fn canon(kind: IdentifierType, raw: &str) -> String {
        canonicalize_identifier(kind, raw).as_str().to_string()
    }

    #[test]
    fn email_folds_case_on_both_parts() {
        assert_eq!(
            canon(IdentifierType::Email, "Ada.Lovelace@Example.COM"),
            "ada.lovelace@example.com"
        );
    }

    #[test]
    fn username_folds_case() {
        assert_eq!(
            canon(IdentifierType::Username, "AdaLovelace"),
            "adalovelace"
        );
    }

    #[test]
    fn phone_normalizes_to_structural_e164() {
        assert_eq!(
            canon(IdentifierType::Phone, "+1 (415) 555-0100"),
            "+14155550100"
        );
        // Fullwidth digits are folded by NFKC, then reduced to E.164.
        assert_eq!(
            canon(IdentifierType::Phone, "\u{FF0B}\u{FF11}\u{FF12}\u{FF13}"),
            "+123"
        );
    }

    #[test]
    fn invisible_and_control_characters_are_stripped() {
        // Zero-width space, zero-width joiner, a right-to-left override, a BOM, a
        // soft hyphen, and a bare tab all vanish, so the padded handle equals the
        // clean one.
        let padded = "a\u{200B}d\u{200D}m\u{202E}i\u{FEFF}n\u{00AD}\t";
        assert_eq!(canon(IdentifierType::Username, padded), "admin");
    }

    #[test]
    fn mixed_case_and_invisibles_resolve_identically_the_cve_class() {
        // The canonicalization-mismatch CVE class: three "visually or semantically
        // the same" spellings of one handle must produce ONE canonical form.
        let a = canon(IdentifierType::Email, "USER@Example.com");
        let b = canon(IdentifierType::Email, "user\u{200B}@example.COM");
        let c = canon(IdentifierType::Email, "  \u{FEFF}User@Example.com  ");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn fullwidth_homoglyph_folds_to_ascii() {
        // Fullwidth Latin "ADMIN" (U+FF21..) is a classic homoglyph-adjacent
        // spoof; NFKC folds it to ASCII, then case folding lowercases it.
        let fullwidth = "\u{FF21}\u{FF24}\u{FF2D}\u{FF29}\u{FF2E}";
        assert_eq!(canon(IdentifierType::Username, fullwidth), "admin");
    }

    #[test]
    fn canonicalization_is_total_and_never_panics_on_odd_input() {
        // Empty, whitespace-only, all-invisible, lone combining marks, and a raw
        // control soup all canonicalize without panicking.
        for kind in [
            IdentifierType::Email,
            IdentifierType::Username,
            IdentifierType::Phone,
        ] {
            let _ = canon(kind, "");
            let _ = canon(kind, "   \t\n  ");
            let _ = canon(kind, "\u{200B}\u{200D}\u{FEFF}");
            let _ = canon(kind, "\u{0301}\u{0301}@\u{0301}");
            let _ = canon(kind, "@@@");
            let _ = canon(kind, "\u{1F4A9}\u{0000}\u{FFFF}");
        }
    }

    #[test]
    fn canonicalization_is_idempotent_over_an_adversarial_corpus() {
        // A property test without a proptest dependency: a corpus that mixes the
        // stressors the fuzz target explores. canonicalize(canonicalize(x)) must
        // equal canonicalize(x) for every kind.
        let corpus = [
            "",
            "  ",
            "Ada.Lovelace@Example.COM",
            "USER\u{200B}NAME",
            "\u{FF21}\u{FF24}\u{FF2D}\u{FF29}\u{FF2E}",
            "+1 (415) 555-0100",
            "\u{FF0B}\u{FF11}\u{FF12}\u{FF13}",
            "a@b@c.example",
            "@@@",
            "\u{0301}combining",
            "MiXeD\u{00AD}Case\u{202E}Handle",
            "\u{1F600}emoji@domain.test",
            "no-at-sign",
            "  spaced out  ",
            "ﬁligature",
        ];
        for kind in [
            IdentifierType::Email,
            IdentifierType::Username,
            IdentifierType::Phone,
        ] {
            for raw in corpus {
                let once = canonicalize_identifier(kind, raw);
                let twice = canonicalize_identifier(kind, once.as_str());
                assert_eq!(
                    once, twice,
                    "not idempotent for {kind:?} on {raw:?}: {once:?} vs {twice:?}"
                );
            }
        }
    }

    #[test]
    fn uniqueness_key_encodes_the_mode() {
        assert_eq!(
            UniquenessMode::EnvironmentWide
                .uniqueness_key(None)
                .as_deref(),
            Some("env")
        );
        assert_eq!(
            UniquenessMode::EnvironmentWide
                .uniqueness_key(Some("org_x"))
                .as_deref(),
            Some("env")
        );
        assert_eq!(
            UniquenessMode::OrgScoped.uniqueness_key(None).as_deref(),
            Some("env")
        );
        assert_eq!(
            UniquenessMode::OrgScoped
                .uniqueness_key(Some("org_x"))
                .as_deref(),
            Some("org:org_x")
        );
        assert_eq!(
            UniquenessMode::NonUnique.uniqueness_key(Some("org_x")),
            None
        );
    }

    #[test]
    fn identifier_type_wire_round_trips() {
        for kind in [
            IdentifierType::Email,
            IdentifierType::Username,
            IdentifierType::Phone,
        ] {
            assert_eq!(IdentifierType::from_wire(kind.as_str()), Some(kind));
        }
        assert_eq!(IdentifierType::from_wire("carrier-pigeon"), None);
    }
}
