// SPDX-License-Identifier: MIT OR Apache-2.0

//! Message-template resolution across the scope hierarchy and locale fallback (issue #111).
//!
//! A verification email can be defined at four levels and in many locales. This module answers
//! exactly one question, purely and with no IO: given every template that exists for a message
//! kind, and the recipient's preferred locale, WHICH ONE renders?
//!
//! Storage, rendering, and send hygiene are the rest of issue #111 and are not here. Keeping
//! the choice separate from the sending is what lets it be exhaustively tested: the resolution
//! rules below have thirteen distinct outcomes, and none of them need a database or an SMTP
//! server to exercise.
//!
//! # Level beats locale, and that is a decision
//!
//! Two dimensions vary at once, so one of them has to be resolved first, and the two answers
//! genuinely differ. Suppose an organization defines the template only in English while the
//! tenant defines it in Brazilian Portuguese, and the recipient prefers `pt-BR`:
//!
//! - LEVEL FIRST (what this module does): the organization's English template renders. The
//!   organization overrode the template because its content must be used, and quietly falling
//!   back to the tenant's copy would send that recipient another party's branding and wording.
//!   A wrong-language email from the right sender is a nuisance; a right-language email from
//!   the wrong sender is a trust failure.
//! - LOCALE FIRST: the tenant's `pt-BR` template renders, and the organization's override is
//!   silently skipped for exactly those recipients who most need it localized.
//!
//! Issue #111 states the scope fallback as "org to environment to tenant to default, and locale
//! fallback applied", which reads as locale fallback applied WITHIN the chosen level, and that
//! is what is implemented. It is one function, so reversing it is cheap if the product decides
//! otherwise; what would not be cheap is discovering later that the two dimensions were never
//! ordered deliberately.
//!
//! # Relationship to the shared policy engine
//!
//! Issue #619 asks for this selection to route through `resolve_org_policy`. It cannot yet:
//! every field in that engine NARROWS (a lower level may only tighten what a higher one
//! allows), and a template override is a SELECTION with no ordering, so it inverts that
//! invariant rather than fitting it. The combinator that reconciles the two is #619's subject.
//! This module is deliberately shaped to make that later: the precedence order is one array,
//! written once.

use std::collections::BTreeMap;

/// Where a template was defined. Ordered from weakest precedence to strongest.
///
/// [`Ord`] is derived and is LOAD-BEARING: resolution picks the maximum available level, so a
/// new variant inserted in the wrong position silently changes which template renders. Add new
/// levels at the position their precedence demands, and extend
/// [`TemplateLevel::PRECEDENCE`] in the same edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TemplateLevel {
    /// The template IronAuth ships. Always present, so resolution cannot fail.
    Default,
    /// Defined for the whole tenant.
    Tenant,
    /// Defined for one environment of that tenant.
    Environment,
    /// Defined by one organization inside that environment.
    Organization,
}

impl TemplateLevel {
    /// Every level, strongest precedence FIRST, which is the order resolution walks.
    ///
    /// Exhaustive by construction: the array is the single source of the order, and the
    /// `every_level_appears_exactly_once_in_precedence` test pins it against the variant list
    /// so a level added without a precedence position fails rather than being skipped at
    /// resolution time, which would look like "the override did not take effect".
    pub const PRECEDENCE: [Self; 4] = [
        Self::Organization,
        Self::Environment,
        Self::Tenant,
        Self::Default,
    ];
}

/// A locale tag, normalized for matching.
///
/// Comparison is case-insensitive on the language and region subtags, because `pt-BR`, `pt-br`
/// and `PT-br` are the same locale and arrive from user agents, admin forms and imported
/// configuration in all three shapes. Storing the normalized form means matching never has to
/// remember to normalize, which is the step that gets forgotten.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Locale(String);

impl Locale {
    /// Normalize and wrap a locale tag. Underscores are accepted as separators (`pt_BR`), since
    /// POSIX-style tags arrive from imported configuration.
    #[must_use]
    pub fn new(tag: &str) -> Self {
        Self(tag.trim().replace('_', "-").to_ascii_lowercase())
    }

    /// The normalized tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The base language of this tag: `pt-br` yields `pt`, and `pt` yields itself.
    ///
    /// Only the FIRST subtag is kept, so a three-part tag like `zh-hant-tw` falls back to `zh`
    /// rather than to `zh-hant`. That is a deliberate simplification: an intermediate fallback
    /// would need the full BCP 47 truncation rules, and no shipped template set uses one. The
    /// `locale_fallback_walks_to_the_base_language` test states the limit so it is a known
    /// bound rather than an assumption.
    #[must_use]
    pub fn base_language(&self) -> Self {
        match self.0.split_once('-') {
            Some((language, _)) => Self(language.to_owned()),
            None => self.clone(),
        }
    }
}

/// One stored template, identified by where it was defined and in which locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateCandidate {
    /// Where this template was defined.
    pub level: TemplateLevel,
    /// The locale it is written in.
    pub locale: Locale,
    /// An opaque handle to the stored body. This module never inspects it.
    pub body_ref: String,
}

/// The template resolution chose, and the reasoning that produced it.
///
/// The `level` and `locale` travel WITH the body deliberately. A caller that logs only the body
/// cannot answer "why did this recipient get English?", which is the single most common support
/// question about a localized template system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTemplate {
    /// The chosen template's body handle.
    pub body_ref: String,
    /// The level it came from.
    pub level: TemplateLevel,
    /// The locale it is actually written in, which may not be the one requested.
    pub locale: Locale,
    /// True when the requested locale was unavailable and a fallback was used. Lets a caller
    /// surface "this message was sent in English" without re-deriving the comparison.
    pub locale_fallback_applied: bool,
}

/// Resolve which template renders.
///
/// `candidates` may contain any mixture of levels and locales, in any order, including
/// duplicates for the same `(level, locale)`; the LAST duplicate wins, matching a store that
/// upserts. `requested` is the recipient's preferred locale and `default_locale` is the
/// environment's configured fallback.
///
/// The order of preference, highest first:
///
/// 1. the strongest LEVEL that has any template at all, then within that level:
/// 2. the exact requested locale,
/// 3. the requested locale's base language (`pt-br` accepts `pt`),
/// 4. any regional variant of the requested language (`pt` accepts `pt-br`),
/// 5. the environment's default locale, then ITS base language,
/// 6. failing all of that, the level's lexicographically first locale, so a level that defines
///    a template always renders something rather than falling through to a weaker level. A
///    level with templates is an intentional override, and silently skipping it because none of
///    them matched the locale is the branding leak this ordering exists to prevent.
///
/// Returns [`None`] only when `candidates` is empty. Callers are expected to include the
/// shipped [`TemplateLevel::Default`] template, which makes [`None`] a programming error rather
/// than a runtime outcome.
#[must_use]
pub fn resolve_template(
    candidates: &[TemplateCandidate],
    requested: &Locale,
    default_locale: &Locale,
) -> Option<ResolvedTemplate> {
    // Group by level, keyed by locale. BTreeMap so rule 6's "lexicographically first" is a
    // real, stable order rather than whatever a hash map happened to yield: an unstable
    // tie-break would make the same inputs render different templates on different runs.
    let mut by_level: BTreeMap<TemplateLevel, BTreeMap<Locale, &TemplateCandidate>> =
        BTreeMap::new();
    for candidate in candidates {
        by_level
            .entry(candidate.level)
            .or_default()
            .insert(candidate.locale.clone(), candidate);
    }

    for level in TemplateLevel::PRECEDENCE {
        let Some(at_level) = by_level.get(&level) else {
            continue;
        };
        if at_level.is_empty() {
            continue;
        }
        let (chosen, exact) = choose_locale(at_level, requested, default_locale);
        return Some(ResolvedTemplate {
            body_ref: chosen.body_ref.clone(),
            level: chosen.level,
            locale: chosen.locale.clone(),
            locale_fallback_applied: !exact,
        });
    }
    None
}

/// Pick a locale within ONE level, returning the candidate and whether it was an exact match.
fn choose_locale<'a>(
    at_level: &BTreeMap<Locale, &'a TemplateCandidate>,
    requested: &Locale,
    default_locale: &Locale,
) -> (&'a TemplateCandidate, bool) {
    if let Some(found) = at_level.get(requested) {
        return (found, true);
    }
    // The requested language without its region, then any region of that language.
    //
    // These two steps OVERLAP: `first_of_language` would also find a bare `pt`, because the
    // map is ordered and `pt` sorts before `pt-br`. The explicit lookup is kept anyway so the
    // preference is stated rather than resting on lexicographic ordering, and a mutation
    // sweep confirms removing it changes no outcome today. The behaviour it guarantees is
    // pinned by `a_bare_language_is_preferred_over_a_regional_variant`.
    let base = requested.base_language();
    if let Some(found) = at_level.get(&base) {
        return (found, false);
    }
    if let Some(found) = first_of_language(at_level, &base) {
        return (found, false);
    }
    // The environment's default, and its base language.
    if let Some(found) = at_level.get(default_locale) {
        return (found, false);
    }
    let default_base = default_locale.base_language();
    if let Some(found) = at_level.get(&default_base) {
        return (found, false);
    }
    if let Some(found) = first_of_language(at_level, &default_base) {
        return (found, false);
    }
    // Rule 6. The map is non-empty (the caller checked), so this cannot panic.
    let fallback = at_level
        .values()
        .next()
        .expect("the level was checked non-empty before choose_locale");
    (fallback, false)
}

/// The first template at this level whose base language is `language`.
fn first_of_language<'a>(
    at_level: &BTreeMap<Locale, &'a TemplateCandidate>,
    language: &Locale,
) -> Option<&'a TemplateCandidate> {
    at_level
        .iter()
        .find(|(locale, _)| locale.base_language() == *language)
        .map(|(_, candidate)| *candidate)
}

#[cfg(test)]
mod tests {
    use super::{Locale, ResolvedTemplate, TemplateCandidate, TemplateLevel, resolve_template};

    const EN: &str = "en";

    fn candidate(level: TemplateLevel, locale: &str) -> TemplateCandidate {
        TemplateCandidate {
            level,
            locale: Locale::new(locale),
            // The body handle encodes its own identity, so an assertion naming the wrong
            // template reads as the wrong string rather than as an opaque mismatch.
            body_ref: format!("{level:?}/{locale}"),
        }
    }

    fn resolve(candidates: &[TemplateCandidate], requested: &str) -> Option<ResolvedTemplate> {
        resolve_template(candidates, &Locale::new(requested), &Locale::new(EN))
    }

    /// The precedence array is the single source of resolution order, so it must list every
    /// variant exactly once. A level added without a precedence entry would never be selected,
    /// and the symptom (an override that "does not take effect") points nowhere near the cause.
    #[test]
    fn every_level_appears_exactly_once_in_precedence() {
        let mut listed = TemplateLevel::PRECEDENCE.to_vec();
        listed.sort_unstable();
        listed.dedup();
        assert_eq!(
            listed.len(),
            TemplateLevel::PRECEDENCE.len(),
            "a level is listed twice in PRECEDENCE"
        );
        // Every variant, written out. An added variant fails to compile in the match below
        // before it can fail silently at resolution.
        let all = [
            TemplateLevel::Default,
            TemplateLevel::Tenant,
            TemplateLevel::Environment,
            TemplateLevel::Organization,
        ];
        for level in all {
            let exhaustive = match level {
                TemplateLevel::Default
                | TemplateLevel::Tenant
                | TemplateLevel::Environment
                | TemplateLevel::Organization => level,
            };
            assert!(
                TemplateLevel::PRECEDENCE.contains(&exhaustive),
                "{level:?} is not in PRECEDENCE, so it would never be selected"
            );
        }
    }

    /// Precedence is strongest-first, which is what makes an override an override.
    #[test]
    fn precedence_is_ordered_strongest_first() {
        assert_eq!(
            TemplateLevel::PRECEDENCE,
            [
                TemplateLevel::Organization,
                TemplateLevel::Environment,
                TemplateLevel::Tenant,
                TemplateLevel::Default,
            ]
        );
        assert!(TemplateLevel::Organization > TemplateLevel::Environment);
        assert!(TemplateLevel::Environment > TemplateLevel::Tenant);
        assert!(TemplateLevel::Tenant > TemplateLevel::Default);
    }

    /// The whole hierarchy, one level at a time, which is issue #111's criterion 3.
    #[test]
    fn each_level_overrides_every_weaker_one() {
        let all = [
            candidate(TemplateLevel::Default, EN),
            candidate(TemplateLevel::Tenant, EN),
            candidate(TemplateLevel::Environment, EN),
            candidate(TemplateLevel::Organization, EN),
        ];
        // Peel the strongest level off one at a time; each time, the next strongest wins.
        for expected in [
            TemplateLevel::Organization,
            TemplateLevel::Environment,
            TemplateLevel::Tenant,
            TemplateLevel::Default,
        ] {
            let available: Vec<_> = all
                .iter()
                .filter(|entry| entry.level <= expected)
                .cloned()
                .collect();
            let resolved = resolve(&available, EN).expect("a template");
            assert_eq!(resolved.level, expected, "with levels up to {expected:?}");
            assert_eq!(resolved.body_ref, format!("{expected:?}/en"));
        }
    }

    /// The exact locale wins within a level, and is reported as no fallback.
    #[test]
    fn an_exact_locale_match_is_used_and_reported_as_exact() {
        let candidates = [
            candidate(TemplateLevel::Environment, EN),
            candidate(TemplateLevel::Environment, "pt-BR"),
        ];
        let resolved = resolve(&candidates, "pt-BR").expect("a template");
        assert_eq!(resolved.locale, Locale::new("pt-BR"));
        assert!(!resolved.locale_fallback_applied);
    }

    /// Locale matching ignores case and accepts the POSIX underscore form.
    #[test]
    fn locale_matching_normalizes_case_and_separator() {
        let candidates = [candidate(TemplateLevel::Environment, "pt_br")];
        for requested in ["pt-BR", "PT-br", "pt_BR", "pt-br"] {
            let resolved = resolve(&candidates, requested).expect("a template");
            assert!(
                !resolved.locale_fallback_applied,
                "{requested} must match exactly after normalization"
            );
        }
    }

    /// `pt-BR` falls back to `pt`, and the fallback is REPORTED so a caller can say so.
    #[test]
    fn locale_fallback_walks_to_the_base_language() {
        let candidates = [
            candidate(TemplateLevel::Environment, EN),
            candidate(TemplateLevel::Environment, "pt"),
        ];
        let resolved = resolve(&candidates, "pt-BR").expect("a template");
        assert_eq!(resolved.locale, Locale::new("pt"));
        assert!(resolved.locale_fallback_applied);

        // The documented BOUND: a three-part tag falls to its FIRST subtag, not to an
        // intermediate one. `zh-hant-tw` reaches `zh`, and does not stop at `zh-hant`.
        assert_eq!(Locale::new("zh-Hant-TW").base_language(), Locale::new("zh"));
    }

    /// When both the bare language and a regional variant exist, the BARE one is used.
    ///
    /// A recipient asking for a region nobody has a template for should get the neutral
    /// `pt` copy, not Brazilian Portuguese chosen because it happened to be found first.
    /// Two rules in `choose_locale` can deliver this, which is why it is pinned on the
    /// OUTCOME rather than on whichever branch produces it.
    #[test]
    fn a_bare_language_is_preferred_over_a_regional_variant() {
        let candidates = [
            candidate(TemplateLevel::Environment, EN),
            candidate(TemplateLevel::Environment, "pt-AR"),
            candidate(TemplateLevel::Environment, "pt"),
            candidate(TemplateLevel::Environment, "pt-BR"),
        ];
        let resolved = resolve(&candidates, "pt-PT").expect("a template");
        assert_eq!(
            resolved.locale,
            Locale::new("pt"),
            "the neutral copy, not whichever region sorted first"
        );
        assert!(resolved.locale_fallback_applied);
    }

    /// A bare language accepts a regional variant, so `pt` finds `pt-BR`.
    #[test]
    fn a_bare_language_accepts_a_regional_variant() {
        let candidates = [
            candidate(TemplateLevel::Environment, EN),
            candidate(TemplateLevel::Environment, "pt-BR"),
        ];
        let resolved = resolve(&candidates, "pt").expect("a template");
        assert_eq!(resolved.locale, Locale::new("pt-BR"));
        assert!(resolved.locale_fallback_applied);
    }

    /// The environment default is reached only after the requested language is exhausted.
    #[test]
    fn the_default_locale_is_the_next_resort_not_the_first() {
        let candidates = [
            candidate(TemplateLevel::Environment, EN),
            candidate(TemplateLevel::Environment, "fr"),
        ];
        // French is requested and present: the default must NOT pre-empt it.
        assert_eq!(
            resolve(&candidates, "fr").expect("a template").locale,
            Locale::new("fr")
        );
        // German is requested and absent: now the default applies.
        let resolved = resolve(&candidates, "de").expect("a template");
        assert_eq!(resolved.locale, Locale::new(EN));
        assert!(resolved.locale_fallback_applied);
    }

    /// THE design decision, asserted rather than left to be inferred.
    ///
    /// The organization defines only English; the tenant has the recipient's `pt-BR`. Level
    /// beats locale, so the organization's English renders. Sending the tenant's Portuguese
    /// here would put another party's branding in front of that recipient, which is a worse
    /// failure than a wrong-language email from the right sender.
    #[test]
    fn a_level_override_wins_even_when_a_weaker_level_has_the_requested_locale() {
        let candidates = [
            candidate(TemplateLevel::Tenant, "pt-BR"),
            candidate(TemplateLevel::Organization, EN),
        ];
        let resolved = resolve(&candidates, "pt-BR").expect("a template");
        assert_eq!(resolved.level, TemplateLevel::Organization);
        assert_eq!(resolved.locale, Locale::new(EN));
        assert!(
            resolved.locale_fallback_applied,
            "the caller must be able to tell the recipient did not get their locale"
        );
    }

    /// A level that defines templates always renders one, even with no locale match at all.
    ///
    /// Falling through to a weaker level here is the branding leak the ordering exists to
    /// prevent: the organization's override was configured deliberately.
    #[test]
    fn a_level_with_no_matching_locale_still_wins_over_a_weaker_level() {
        let candidates = [
            candidate(TemplateLevel::Tenant, EN),
            candidate(TemplateLevel::Organization, "ja"),
        ];
        let resolved = resolve(&candidates, "de").expect("a template");
        assert_eq!(resolved.level, TemplateLevel::Organization);
        assert_eq!(resolved.locale, Locale::new("ja"));
    }

    /// The last-written duplicate wins, matching a store that upserts.
    #[test]
    fn a_duplicate_level_and_locale_takes_the_last_one() {
        let mut later = candidate(TemplateLevel::Environment, EN);
        later.body_ref = "the-upserted-one".to_owned();
        let candidates = [candidate(TemplateLevel::Environment, EN), later];
        assert_eq!(
            resolve(&candidates, EN).expect("a template").body_ref,
            "the-upserted-one"
        );
    }

    /// Input order must not change the outcome; only level and locale may.
    #[test]
    fn the_result_does_not_depend_on_candidate_order() {
        let candidates = [
            candidate(TemplateLevel::Default, EN),
            candidate(TemplateLevel::Organization, "pt-BR"),
            candidate(TemplateLevel::Tenant, "fr"),
            candidate(TemplateLevel::Environment, EN),
        ];
        let forward = resolve(&candidates, "pt-BR").expect("a template");
        let mut reversed = candidates.to_vec();
        reversed.reverse();
        let backward = resolve(&reversed, "pt-BR").expect("a template");
        assert_eq!(forward, backward);
        assert_eq!(forward.level, TemplateLevel::Organization);
    }

    /// Empty input is the only [`None`], and it means the caller forgot the shipped default.
    #[test]
    fn no_candidates_resolves_to_nothing() {
        assert!(resolve(&[], EN).is_none());
    }
}
