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
//!   1. Strip Unicode invisible and control characters everywhere in the input by
//!      Unicode PROPERTY, not a hand-curated code-point list. A character is removed
//!      when its `General_Category` is Control (Cc), Format (Cf), `Line_Separator`
//!      (Zl), or `Paragraph_Separator` (Zp), OR when it carries the derived
//!      `Default_Ignorable_Code_Point` property (see [`is_invisible_or_control`]). This
//!      is a property predicate over the whole Unicode range rather than a list with
//!      gaps, so every zero-width joiner, bidirectional override, combining grapheme
//!      joiner (U+034F), reserved default-ignorable (U+2065), line/paragraph
//!      separator (U+2028/U+2029), and variation selector vanishes, and two handles
//!      that differ only by invisible padding are ONE identifier.
//!   2. Apply Unicode NFKC (Normalization Form KC): compatibility decomposition
//!      then canonical composition. This folds the large confusable class of
//!      compatibility variants (fullwidth ASCII, circled and superscript forms,
//!      ligatures) onto their ordinary forms, composes combining sequences (so `Ａ`
//!      and `A` are the same starter), and maps compatibility spaces (a no-break
//!      space U+00A0, a figure space U+2007) onto the ordinary space so step 3 can
//!      remove them.
//!   3. Strip ALL whitespace everywhere in the value, not merely at the ends: any
//!      character with the Unicode `White_Space` property (Zs plus the ASCII
//!      whitespace controls) is removed. A login identifier has no legitimate
//!      internal whitespace, so `ad min` and `admin` are ONE identifier; removing
//!      interior whitespace (rather than trimming only the ends) closes the
//!      internal-space smuggling variant that a trim-only pass leaves open.
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
//!     no usable `@` shape yields an EMPTY canonical form and is refused at the write
//!     boundary (`ActingUserIdentifierRepo::add`): an email must have an `@` shape, and
//!     a shapeless value must not be stored as a username-like fold.
//!   * `username`: Unicode case-fold the whole value (the PRECIS
//!     `UsernameCaseMapped` profile's case-mapping rule).
//!   * `phone`: STRUCTURAL E.164 (ITU-T E.164) normalization: keep only ASCII
//!     digits and emit `+<digits>`. This strips every visual separator (spaces,
//!     hyphens, parentheses, the fullwidth digits already folded by NFKC) so
//!     `+1 (415) 555-0100` and `+14155550100` are one identifier. It does NOT infer
//!     a country code from a national number (that needs a region context and a
//!     libphonenumber-scale table, out of scope here and a heavy dependency): a
//!     caller submits an already-international number. An input with no digits yields
//!     an EMPTY canonical form (refused at the write boundary) rather than a bare `+`.
//!
//! Case folding uses full Unicode Default Case Folding
//! (`caseless::default_case_fold_str`, the Unicode 3.13 default case-fold mapping),
//! re-normalized to NFKC afterward for idempotence. This is stronger than
//! `str::to_lowercase`: it folds the case pairs where simple lowercasing diverges,
//! so the German sharp s (`STRASSE` and `straße`), the Greek final sigma (`ΟΔΟΣ` and
//! `οδοσ`), and the other full-fold expansions collapse to ONE canonical form rather
//! than staying two distinct login handles.
//!
//! ### Documented structural limitations (NOT bugs; out of scope for this seam)
//!
//!   * Cross-script CONFUSABLES (a Cyrillic `а` U+0430 vs a Latin `a` U+0061, and
//!     the like) are NOT folded: that needs a UTS-39 confusable-skeleton mapping,
//!     which is a separate, deliberately-scoped-out mechanism. Two visually
//!     identical handles in different scripts remain distinct canonical forms here.
//!   * NFKC OVER-folds a few compatibility pairs (the `ﬁ` ligature to `fi`, some
//!     circled and stylistic forms): distinct source strings can share one canonical
//!     form. This is the accepted cost of compatibility normalization; it errs toward
//!     collapsing rather than splitting an identity, which is the safe direction for
//!     a login handle.
//!   * The phone policy MERGES a number and the same number with an extension (the
//!     extension digits are not separated), because structural E.164 keeps only the
//!     digits. A caller that must distinguish an extension carries it out of band.

use caseless::default_case_fold_str;
use unicode_normalization::UnicodeNormalization;
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

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

    /// Whether the canonical form is EMPTY (a degenerate identifier): the input was
    /// all whitespace / all invisible characters, or (for an email) carried no `@`
    /// shape and no usable content. An empty canonical form is not a real identifier:
    /// the write boundary refuses to store one (so an all-invisible submission cannot
    /// squat the empty slot), and resolution of one returns nothing rather than
    /// matching a row. See [`ActingUserIdentifierRepo::add`] and
    /// [`UserIdentifierRepo::resolve`].
    ///
    /// [`ActingUserIdentifierRepo::add`]: crate::ActingUserIdentifierRepo::add
    /// [`UserIdentifierRepo::resolve`]: crate::UserIdentifierRepo::resolve
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
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
    // 1. Strip invisible / control / format / separator / default-ignorable
    //    characters everywhere, by Unicode property.
    let stripped: String = raw
        .chars()
        .filter(|&c| !is_invisible_or_control(c))
        .collect();
    // 2. NFKC compatibility normalization (also maps compatibility spaces onto the
    //    ordinary space so step 3 removes them).
    let normalized: String = stripped.nfkc().collect();
    // 3. Strip ALL whitespace, interior included: a login identifier carries no
    //    legitimate whitespace, so `ad min` and `admin` are one identifier.
    let base: String = normalized.chars().filter(|c| !c.is_whitespace()).collect();
    // 4. Per-type shape and case folding.
    let value = match kind {
        IdentifierType::Email => canonical_email(&base),
        IdentifierType::Username => case_fold(&base),
        IdentifierType::Phone => canonical_phone(&base),
    };
    CanonicalIdentifier { kind, value }
}

/// Full Unicode Default Case Folding (`caseless::default_case_fold_str`), then
/// re-normalized to NFKC so the output is stable under a second pass. Full folding
/// (not simple lowercase) collapses the case pairs where lowercasing diverges, so
/// the sharp s folds to `ss` and the Greek final sigma folds to a medial sigma;
/// the trailing NFKC restores the normalization form without changing case, so
/// `case_fold(case_fold(x)) == case_fold(x)`.
fn case_fold(value: &str) -> String {
    default_case_fold_str(value).nfkc().collect()
}

/// The canonical email form: fold the local part and the domain independently and
/// recombine. Splitting on the LAST `@` keeps a quoted `@` inside the local part
/// with the local part, and folding never introduces or moves an `@`, so the split
/// is stable under a second pass (idempotence). An input with no usable `@` shape
/// (no `@`, or an empty local part or domain) yields an EMPTY canonical form rather
/// than a whole-string fold: the write boundary refuses to store a shapeless value
/// as an email, so a username-like fold cannot masquerade as an email row.
fn canonical_email(base: &str) -> String {
    match base.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            format!("{}@{}", case_fold(local), case_fold(domain))
        }
        _ => String::new(),
    }
}

/// The canonical phone form: structural E.164. Keep only ASCII digits and prefix a
/// single `+`. An input with no digits yields an EMPTY canonical form (refused at
/// the write boundary) rather than a bare `+` or a plain-string fold.
fn canonical_phone(base: &str) -> String {
    let digits: String = base.chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        String::new()
    } else {
        format!("+{digits}")
    }
}

/// Whether a character is stripped in step 1 of canonicalization, decided by Unicode
/// PROPERTY rather than a hand-maintained code-point list. A character is stripped
/// when its `General_Category` is Control (Cc), Format (Cf), `Line_Separator` (Zl),
/// or `Paragraph_Separator` (Zp), OR when it carries the derived `Default_Ignorable`
/// property. This is a total predicate over the whole Unicode range, so a homoglyph
/// or direction-override attack cannot exploit a gap in a curated list: every
/// zero-width joiner, bidirectional control, combining grapheme joiner, reserved
/// default-ignorable code point, and variation selector is removed.
fn is_invisible_or_control(c: char) -> bool {
    matches!(
        c.general_category(),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    ) || is_default_ignorable(c)
}

/// Whether a character carries the Unicode `Default_Ignorable_Code_Point` derived
/// property (`DerivedCoreProperties`). These are code points meant to have no visible
/// rendering when unsupported (the combining grapheme joiner U+034F, the Hangul and
/// Mongolian fillers, the variation selectors, the reserved-but-ignorable ranges
/// such as U+2065, U+FFF0..U+FFF8, and the tag/variation-selector supplement). Many
/// are NOT Cf/Cc (U+034F is a combining mark, the fillers are letters, the reserved
/// ones are unassigned), so category alone misses them; this predicate is the exact
/// derived-property range set from the Unicode data file (authoritative, not a
/// best-effort list) rather than a curated guess.
fn is_default_ignorable(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                       // SOFT HYPHEN
        | '\u{034F}'                     // COMBINING GRAPHEME JOINER
        | '\u{061C}'                     // ARABIC LETTER MARK
        | '\u{115F}'..='\u{1160}'        // HANGUL CHOSEONG / JUNGSEONG FILLER
        | '\u{17B4}'..='\u{17B5}'        // KHMER vowel inherent AQ / AA
        | '\u{180B}'..='\u{180F}'        // MONGOLIAN variation selectors / vowel separator
        | '\u{200B}'..='\u{200F}'        // ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
        | '\u{202A}'..='\u{202E}'        // bidi embeddings and overrides
        | '\u{2060}'..='\u{206F}'        // WORD JOINER .. deprecated format (incl. U+2065)
        | '\u{3164}'                     // HANGUL FILLER
        | '\u{FE00}'..='\u{FE0F}'        // variation selectors 1..16
        | '\u{FEFF}'                     // ZERO WIDTH NO-BREAK SPACE / BOM
        | '\u{FFA0}'                     // HALFWIDTH HANGUL FILLER
        | '\u{FFF0}'..='\u{FFF8}'        // reserved default-ignorable
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
            "adm\u{034F}in",
            "gap\u{2065}handle",
            "line\u{2028}sep",
            "para\u{2029}sep",
            "nb\u{00A0}sp@ex\u{2007}ample.com",
            "STRASSE",
            "straße",
            "ΟΔΟΣ",
            "οδο\u{03C3}",
            "ADMİN",
            "ad min",
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

    /// The three identifier kinds, for looping an assertion over every one.
    const ALL_KINDS: [IdentifierType; 3] = [
        IdentifierType::Email,
        IdentifierType::Username,
        IdentifierType::Phone,
    ];

    #[test]
    fn property_based_strip_removes_the_curated_list_survivors() {
        // HIGH 1: the code points that survived the old curated `matches!` list and
        // made "admin" and an invisibly-padded spelling DIFFERENT canonical forms.
        // U+034F (combining grapheme joiner, category Mn, NOT Cf), U+2065 (the gap in
        // the 2060..2064 / 2066..206F list, category Cn), U+2028 (Zl) and U+2029 (Zp)
        // are line/paragraph separators (NOT is_control), and an internal no-break
        // space (NFKC-mapped to a regular space that a trim-only pass leaves interior).
        // Each must vanish, so the padded handle equals the clean one for EVERY kind.
        for pad in [
            '\u{034F}', // COMBINING GRAPHEME JOINER
            '\u{2065}', // reserved default-ignorable (list gap)
            '\u{2028}', // LINE SEPARATOR (Zl)
            '\u{2029}', // PARAGRAPH SEPARATOR (Zp)
            '\u{00A0}', // NO-BREAK SPACE (internal)
            '\u{2007}', // FIGURE SPACE (internal)
        ] {
            let padded = format!("adm{pad}in");
            for kind in ALL_KINDS {
                assert_eq!(
                    canon(kind, &padded),
                    canon(kind, "admin"),
                    "{kind:?}: {pad:?} must be stripped so the padded handle equals the clean one",
                );
            }
            // For a username the clean canonical form is the non-empty "admin", so
            // this proves the character was removed, not that both sides collapsed to
            // an empty degenerate form.
            assert_eq!(canon(IdentifierType::Username, &padded), "admin");
        }
    }

    #[test]
    fn internal_whitespace_is_stripped_not_only_trimmed() {
        // A login identifier has no legitimate interior whitespace: "ad min" and
        // "admin" are one identifier, closing the internal-space smuggling variant a
        // trim-only pass leaves open.
        assert_eq!(canon(IdentifierType::Username, "ad min"), "admin");
        assert_eq!(
            canon(IdentifierType::Email, "a d@ex ample.com"),
            "ad@example.com"
        );
    }

    #[test]
    fn case_folding_is_full_default_fold_not_simple_lowercase() {
        // MEDIUM 2: full Unicode Default Case Folding folds the case pairs where
        // `str::to_lowercase` diverges. Each pair below is DISTINCT under the old
        // lowercase policy and ONE identifier under full folding.

        // German sharp s: lowercase leaves "ß" untouched (so "straße" stays "straße",
        // distinct from "strasse"); full folding maps "ß" -> "ss".
        assert_eq!(
            canon(IdentifierType::Username, "STRASSE"),
            canon(IdentifierType::Username, "straße"),
        );
        assert_eq!(canon(IdentifierType::Username, "straße"), "strasse");

        // Greek sigma: a medial sigma and a final sigma fold to one letter. "ΟΔΟΣ"
        // lowercases (context-sensitively) to a FINAL sigma "οδος", which is distinct
        // from the medial-sigma spelling "οδοσ"; full folding maps both to the medial
        // sigma, so the two are one identifier.
        assert_eq!(
            canon(IdentifierType::Username, "ΟΔΟΣ"),
            canon(IdentifierType::Username, "οδο\u{03C3}"), // medial sigma
        );

        // Turkish dotted capital I folds to "i" + COMBINING DOT ABOVE under the
        // default (non-tailored) mapping, identically to its decomposed spelling, and
        // (correctly) stays DISTINCT from a plain ASCII "admin" (the dot is a real
        // difference). Folding and lowercasing agree on this code point; it is
        // asserted for completeness of the named vectors.
        assert_eq!(
            canon(IdentifierType::Username, "ADMİN"),
            canon(IdentifierType::Username, "admi\u{0307}n"),
        );
        assert_ne!(
            canon(IdentifierType::Username, "ADMİN"),
            canon(IdentifierType::Username, "admin"),
        );
    }

    #[test]
    fn degenerate_inputs_canonicalize_to_an_empty_form() {
        // MEDIUM 3: an all-invisible / whitespace-only input, an email with no `@`
        // shape, and a phone with no digits all canonicalize to the EMPTY form, which
        // the write boundary refuses to store (so it cannot squat the empty slot).
        for kind in ALL_KINDS {
            assert!(canonicalize_identifier(kind, "").is_empty());
            assert!(canonicalize_identifier(kind, "   \t\n  ").is_empty());
            assert!(canonicalize_identifier(kind, "\u{200B}\u{2065}\u{FEFF}").is_empty());
        }
        // An email with no usable `@` shape is empty (not a username-like whole-string
        // fold).
        assert!(canonicalize_identifier(IdentifierType::Email, "no-at-sign").is_empty());
        assert!(canonicalize_identifier(IdentifierType::Email, "local@").is_empty());
        assert!(canonicalize_identifier(IdentifierType::Email, "@domain.test").is_empty());
        // A phone with no digits is empty (not a bare "+").
        assert!(canonicalize_identifier(IdentifierType::Phone, "not-a-number").is_empty());
        // A real value is NOT empty.
        assert!(!canonicalize_identifier(IdentifierType::Email, "a@b.test").is_empty());
        assert!(!canonicalize_identifier(IdentifierType::Username, "u").is_empty());
        assert!(!canonicalize_identifier(IdentifierType::Phone, "+123").is_empty());
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
