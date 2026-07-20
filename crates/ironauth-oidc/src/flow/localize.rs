// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pure locale resolution and localize engine (issue #86, PR 2).
//!
//! Localization keys on the STABLE NUMERIC message id and the structured context, never on a
//! copy string (the flow message registry, `message.rs`): a locale bundle is a map of numeric
//! [`MessageId`] to a PLAIN TEXT render, and the compiled English [`REGISTRY`] is the ultimate
//! fallback. This module is I/O-free and unit-testable:
//!
//! - [`resolve_locale`] runs RFC 4647 section 3.4 "Lookup" over an end user's `ui_locales`
//!   priority list against the installed bundles: for each requested tag it tries the exact
//!   tag, then progressively truncates the last subtag (`fr-CA` to `fr`) until it matches an
//!   installed locale; no requested tag matches falls back to the environment default. It
//!   returns a [`ResolvedLocale`] carrying the resolved primary tag (for `<html lang>`), the
//!   text direction (for `<html dir>`), and the resolved bundle chain;
//! - [`localize`] resolves one message id down that SAME chain, ending at the compiled `en`
//!   registry default, so a partial bundle still renders (mixed, never blank), then
//!   interpolates the declared context placeholders. It returns PLAIN TEXT.
//!
//! # The plain-text security invariant
//!
//! A bundle string is PLAIN TEXT (a label, title, or error), rendered through the SAME
//! `escape_html` the compiled default text is. A locale string is NEVER rich text, is NEVER
//! sanitized HTML, and can NEVER carry markup: [`localize`] returns a `String` the renderer
//! escapes, and this module never touches the branding sanitizer or any raw-HTML path. A
//! hostile bundle string containing `<script>` therefore renders as inert escaped text, proven
//! by the render-path test.

use std::collections::{BTreeMap, BTreeSet};

use super::message::{MessageContext, MessageId, spec_for};

/// The text direction a resolved locale renders in (issue #86): the value the document shell
/// sets on `<html dir>`. `Ltr` is the default and emits no attribute (the HTML default), so an
/// unlocalized or left-to-right page is byte-identical to before PR 2; `Rtl` emits `dir="rtl"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextDirection {
    /// Left-to-right (the default; emits no `dir` attribute).
    Ltr,
    /// Right-to-left (emits `dir="rtl"`).
    Rtl,
}

impl TextDirection {
    /// The wire value (`ltr` / `rtl`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TextDirection::Ltr => "ltr",
            TextDirection::Rtl => "rtl",
        }
    }
}

/// The primary language subtags rendered right-to-left (issue #86): the canonical RTL script
/// languages (Arabic, Hebrew, Persian, Urdu, and the standard others), plus the legacy `he`
/// alias `iw` and the legacy `yi` alias `ji`. A tag whose primary subtag is one of these
/// renders `dir="rtl"`; every other tag is left-to-right.
const RTL_PRIMARY_SUBTAGS: &[&str] = &[
    "ar", "arc", "ckb", "dv", "fa", "he", "iw", "ji", "ps", "sd", "syr", "ug", "ur", "yi",
];

/// A conservative, validated BCP 47 language tag (issue #86), normalized to lowercase so
/// matching is case-insensitive per RFC 4647. Deliberately stricter than the full grammar (1
/// to 35 characters of ASCII letters, digits, and hyphens, no leading/trailing/doubled
/// hyphen), so a hostile or malformed value never becomes a tag, an `<html lang>`, or a stored
/// locale key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LanguageTag(String);

impl LanguageTag {
    /// Parse and normalize a raw tag, or [`None`] for a malformed one.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 35 {
            return None;
        }
        let ok = trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if !ok || trimmed.starts_with('-') || trimmed.ends_with('-') || trimmed.contains("--") {
            return None;
        }
        Some(Self(trimmed.to_ascii_lowercase()))
    }

    /// The normalized tag string (for `<html lang>` and as the stored natural key).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The primary language subtag (everything before the first hyphen).
    #[must_use]
    pub fn primary_subtag(&self) -> &str {
        self.0.split('-').next().unwrap_or(&self.0)
    }

    /// The text direction this tag renders in, derived from the primary language subtag
    /// (issue #86): the canonical RTL set renders right-to-left, every other tag left-to-right.
    #[must_use]
    pub fn direction(&self) -> TextDirection {
        if RTL_PRIMARY_SUBTAGS.contains(&self.primary_subtag()) {
            TextDirection::Rtl
        } else {
            TextDirection::Ltr
        }
    }

    /// This tag with its last subtag dropped (`fr-ca` to `fr`), or [`None`] when the tag has a
    /// single subtag: the RFC 4647 section 3.4 progressive truncation step. Per that section, when
    /// dropping the last subtag leaves a single character (singleton) subtag at the end, that
    /// subtag is removed too (`en-x-foo` truncates straight to `en`, never probing `en-x`), because
    /// a singleton like `x` introduces a private use sequence that is meaningless without the
    /// subtag that followed it.
    #[must_use]
    fn parent(&self) -> Option<Self> {
        let (mut prefix, _) = self.0.rsplit_once('-')?;
        if let Some((head, last)) = prefix.rsplit_once('-') {
            if last.len() == 1 {
                prefix = head;
            }
        } else if prefix.len() == 1 {
            // The remaining tag is itself a lone singleton (for example `x` from `x-foo`); there
            // is no meaningful parent to probe.
            return None;
        }
        Some(Self(prefix.to_owned()))
    }
}

/// One installed locale bundle (issue #86): a BCP 47 tag and its map of numeric message id to
/// the PLAIN TEXT render. Built from a stored `locale_bundles` row's entries JSON; a malformed
/// or non-string entry is skipped (defensive; ingest already validated it), so a corrupt row
/// degrades to the per-id registry fallback rather than rendering wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocaleBundle {
    tag: LanguageTag,
    entries: BTreeMap<u32, String>,
}

impl LocaleBundle {
    /// Build a bundle from a validated entries map.
    #[must_use]
    pub fn new(tag: LanguageTag, entries: BTreeMap<u32, String>) -> Self {
        Self { tag, entries }
    }

    /// Parse a bundle from a stored entries JSON object (a map of numeric message id string to
    /// the plain text render). A parse fault or a non-object yields an EMPTY bundle, so a
    /// corrupt row falls through to the per-id registry default rather than erroring the page.
    #[must_use]
    pub fn parse(tag: LanguageTag, entries_json: &str) -> Self {
        let mut entries = BTreeMap::new();
        if let Ok(serde_json::Value::Object(map)) =
            serde_json::from_str::<serde_json::Value>(entries_json)
        {
            for (key, value) in map {
                if let (Ok(id), serde_json::Value::String(text)) = (key.parse::<u32>(), value) {
                    entries.insert(id, text);
                }
            }
        }
        Self { tag, entries }
    }

    /// The bundle's language tag.
    #[must_use]
    pub fn tag(&self) -> &LanguageTag {
        &self.tag
    }

    /// The plain-text render for `id` in this bundle, or [`None`] when this bundle does not
    /// translate it (the per-id fallback then continues down the chain).
    #[must_use]
    fn get(&self, id: MessageId) -> Option<&str> {
        self.entries.get(&id.0).map(String::as_str)
    }
}

/// A resolved locale (issue #86): the primary tag for `<html lang>`, the text direction for
/// `<html dir>`, and the resolved bundle chain the per-id fallback walks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLocale {
    primary: LanguageTag,
    direction: TextDirection,
    chain: Vec<LocaleBundle>,
}

impl ResolvedLocale {
    /// The primary language tag (for `<html lang>`): the tag actually rendered, so discovery's
    /// honest set holds (never a language the page cannot produce).
    #[must_use]
    pub fn primary(&self) -> &LanguageTag {
        &self.primary
    }

    /// The text direction (for `<html dir>`).
    #[must_use]
    pub fn direction(&self) -> TextDirection {
        self.direction
    }
}

impl Default for ResolvedLocale {
    /// The neutral default: English, left-to-right, no installed bundle. Every id then resolves
    /// to the compiled `en` registry, so a bundle-less environment renders byte-identical
    /// English to before PR 2.
    fn default() -> Self {
        Self {
            primary: LanguageTag("en".to_owned()),
            direction: TextDirection::Ltr,
            chain: Vec::new(),
        }
    }
}

/// RFC 4647 section 3.4 "Lookup" for one requested tag against the installed bundles: try the
/// exact tag, then progressively truncate the last subtag until a bundle matches. Returns the
/// matched bundle's tag, or [`None`] when nothing along the truncation matches.
fn lookup<'a>(
    requested: &LanguageTag,
    installed: &'a BTreeMap<LanguageTag, LocaleBundle>,
) -> Option<&'a LocaleBundle> {
    let mut candidate = Some(requested.clone());
    while let Some(tag) = candidate {
        if let Some(bundle) = installed.get(&tag) {
            return Some(bundle);
        }
        candidate = tag.parent();
    }
    None
}

/// Resolve the end user's `ui_locales` priority list against the installed bundles (issue #86).
///
/// `ui_locales` is split on whitespace in priority order; each requested tag is looked up by
/// RFC 4647 section 3.4 (exact, then progressively truncated). Every distinct matched bundle is
/// appended to the chain in priority order. The environment default bundle (when installed) is
/// appended as the final bundle-level fallback, and the primary tag is the first matched tag
/// (or the environment default when nothing matched), so `ui_locales=fr-CA` with no French
/// bundle falls through to the default. [`localize`] then ends the per-id fallback at the
/// compiled `en` registry.
#[must_use]
pub fn resolve_locale(
    ui_locales: Option<&str>,
    env_default: &LanguageTag,
    installed: &BTreeMap<LanguageTag, LocaleBundle>,
) -> ResolvedLocale {
    let mut chain: Vec<LocaleBundle> = Vec::new();
    let mut seen: BTreeSet<LanguageTag> = BTreeSet::new();
    if let Some(raw) = ui_locales {
        for token in raw.split_whitespace() {
            let Some(tag) = LanguageTag::parse(token) else {
                continue;
            };
            if let Some(bundle) = lookup(&tag, installed) {
                if seen.insert(bundle.tag.clone()) {
                    chain.push(bundle.clone());
                }
            }
        }
    }
    let primary = chain
        .first()
        .map_or_else(|| env_default.clone(), |bundle| bundle.tag.clone());
    // The environment default bundle is the final bundle-level fallback before the compiled
    // registry, so a partial requested bundle still resolves the default's strings before English.
    if let Some(default_bundle) = installed.get(env_default) {
        if seen.insert(default_bundle.tag.clone()) {
            chain.push(default_bundle.clone());
        }
    }
    let direction = primary.direction();
    ResolvedLocale {
        primary,
        direction,
        chain,
    }
}

/// Localize one message id against a resolved locale (issue #86): resolve the plain-text
/// template for `id` down the resolved bundle chain, ending at the compiled `en` [`REGISTRY`]
/// default (a partial bundle still renders, mixed, never blank), then interpolate the declared
/// context placeholders. Returns PLAIN TEXT the renderer escapes.
#[must_use]
pub fn localize(id: MessageId, context: &MessageContext, locale: &ResolvedLocale) -> String {
    let template = locale
        .chain
        .iter()
        .find_map(|bundle| bundle.get(id))
        .or_else(|| spec_for(id).map(|spec| spec.text))
        .unwrap_or("");
    interpolate(template, context)
}

/// Substitute each `{key}` placeholder in `template` with the context value for `key`. Only
/// keys the context carries are substituted; an unreferenced placeholder is left verbatim (the
/// admin ingest validation already restricts a bundle's placeholders to the id's declared
/// context keys, so this cannot leak unintended context). The result is plain text.
fn interpolate(template: &str, context: &MessageContext) -> String {
    if context.0.is_empty() || !template.contains('{') {
        return template.to_owned();
    }
    let mut out = template.to_owned();
    for (key, value) in &context.0 {
        let needle = format!("{{{key}}}");
        if out.contains(&needle) {
            out = out.replace(&needle, value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        LanguageTag, LocaleBundle, ResolvedLocale, TextDirection, localize, resolve_locale,
    };
    use crate::flow::message::{
        LOGIN_IDENTIFIER_LABEL, LOGIN_SUBMIT_LABEL, LOGIN_TITLE, MessageContext,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn tag(raw: &str) -> LanguageTag {
        LanguageTag::parse(raw).expect("valid tag")
    }

    fn bundle(raw: &str, entries: &[(u32, &str)]) -> LocaleBundle {
        let map: BTreeMap<u32, String> = entries
            .iter()
            .map(|(id, text)| (*id, (*text).to_owned()))
            .collect();
        LocaleBundle::new(tag(raw), map)
    }

    fn installed(bundles: Vec<LocaleBundle>) -> BTreeMap<LanguageTag, LocaleBundle> {
        bundles.into_iter().map(|b| (b.tag().clone(), b)).collect()
    }

    #[test]
    fn language_tag_parse_normalizes_and_rejects_hostile_input() {
        assert_eq!(tag("FR-CA").as_str(), "fr-ca");
        assert!(LanguageTag::parse("\"><script>").is_none());
        assert!(LanguageTag::parse("").is_none());
        assert!(LanguageTag::parse("-fr").is_none());
        assert!(LanguageTag::parse("fr--ca").is_none());
    }

    #[test]
    fn direction_is_rtl_for_the_canonical_set_only() {
        for rtl in ["ar", "he", "fa", "ur", "ar-EG", "he-IL"] {
            assert_eq!(tag(rtl).direction(), TextDirection::Rtl, "{rtl}");
        }
        for ltr in ["en", "fr", "fr-CA", "de", "es-419", "zh-Hans"] {
            assert_eq!(tag(ltr).direction(), TextDirection::Ltr, "{ltr}");
        }
    }

    #[test]
    fn fr_ca_falls_through_fr_to_the_env_default() {
        // The acceptance criterion: ui_locales=fr-CA with only an `fr` bundle installed
        // resolves to `fr` (the truncation step), and with NO French bundle it falls to the
        // env default.
        let with_fr = installed(vec![bundle("fr", &[(LOGIN_TITLE.0, "Se connecter")])]);
        let resolved = resolve_locale(Some("fr-CA"), &tag("en"), &with_fr);
        assert_eq!(resolved.primary().as_str(), "fr");
        assert_eq!(
            localize(LOGIN_TITLE, &MessageContext::empty(), &resolved),
            "Se connecter"
        );

        // No French bundle at all: fall to the env default (en registry).
        let empty = installed(vec![]);
        let fallback = resolve_locale(Some("fr-CA"), &tag("en"), &empty);
        assert_eq!(fallback.primary().as_str(), "en");
        assert_eq!(
            localize(LOGIN_TITLE, &MessageContext::empty(), &fallback),
            "Sign in",
            "the compiled en registry is the ultimate fallback"
        );
    }

    #[test]
    fn rfc4647_truncation_drops_a_trailing_singleton_subtag_with_its_predecessor() {
        // RFC 4647 section 3.4: truncating `en-x-foo` removes `foo` and then the singleton `x`
        // together, so lookup probes `en` directly and never `en-x`. Install BOTH `en-x` and `en`;
        // the resolve must pick `en`, proving the `en-x` step was skipped.
        let map = installed(vec![
            bundle("en-x", &[(LOGIN_TITLE.0, "singleton bundle")]),
            bundle("en", &[(LOGIN_TITLE.0, "Sign in (en)")]),
        ]);
        let resolved = resolve_locale(Some("en-x-foo"), &tag("en"), &map);
        assert_eq!(resolved.primary().as_str(), "en");
        assert_eq!(
            localize(LOGIN_TITLE, &MessageContext::empty(), &resolved),
            "Sign in (en)",
            "the singleton en-x step is skipped per RFC 4647 section 3.4"
        );
    }

    #[test]
    fn a_partial_bundle_falls_back_per_id_never_blank() {
        // A French bundle that translates only the title: the title is French, every other id
        // falls through to the compiled English registry (mixed, never blank).
        let map = installed(vec![bundle("fr", &[(LOGIN_TITLE.0, "Se connecter")])]);
        let resolved = resolve_locale(Some("fr"), &tag("en"), &map);
        assert_eq!(
            localize(LOGIN_TITLE, &MessageContext::empty(), &resolved),
            "Se connecter"
        );
        assert_eq!(
            localize(LOGIN_IDENTIFIER_LABEL, &MessageContext::empty(), &resolved),
            "Identifier",
            "an untranslated id falls back to the compiled English default"
        );
        assert!(
            !localize(LOGIN_SUBMIT_LABEL, &MessageContext::empty(), &resolved).is_empty(),
            "no id ever renders blank"
        );
    }

    #[test]
    fn a_fully_translated_bundle_renders_every_id_in_that_locale() {
        let map = installed(vec![bundle(
            "fr",
            &[
                (LOGIN_TITLE.0, "Se connecter"),
                (LOGIN_IDENTIFIER_LABEL.0, "Identifiant"),
                (LOGIN_SUBMIT_LABEL.0, "Se connecter"),
            ],
        )]);
        let resolved = resolve_locale(Some("fr"), &tag("en"), &map);
        assert_eq!(
            localize(LOGIN_IDENTIFIER_LABEL, &MessageContext::empty(), &resolved),
            "Identifiant"
        );
    }

    #[test]
    fn interpolation_substitutes_only_declared_context_keys() {
        // A bundle string with a {provider} placeholder is filled from the context value.
        let map = installed(vec![bundle(
            "fr",
            &[(
                crate::flow::message::FEDERATION_CONTINUE_LABEL.0,
                "Continuer avec {provider}",
            )],
        )]);
        let resolved = resolve_locale(Some("fr"), &tag("en"), &map);
        let context = MessageContext::one("provider", "Acme");
        assert_eq!(
            localize(
                crate::flow::message::FEDERATION_CONTINUE_LABEL,
                &context,
                &resolved
            ),
            "Continuer avec Acme"
        );
    }

    #[test]
    fn a_bundle_string_with_markup_is_returned_as_plain_text() {
        // The plain-text invariant at the engine boundary: localize returns the string verbatim
        // (the RENDER path escapes it). It is never sanitized or treated as markup here.
        let hostile = "<script>alert(1)</script>";
        let map = installed(vec![bundle("fr", &[(LOGIN_TITLE.0, hostile)])]);
        let resolved = resolve_locale(Some("fr"), &tag("en"), &map);
        assert_eq!(
            localize(LOGIN_TITLE, &MessageContext::empty(), &resolved),
            hostile,
            "localize returns plain text verbatim; escaping is the renderer's job"
        );
    }

    #[test]
    fn the_priority_list_builds_the_chain_in_order() {
        // ui_locales lists de then fr: both bundles join the chain in that order, so a de miss
        // falls to fr before English.
        let map = installed(vec![
            bundle("de", &[(LOGIN_TITLE.0, "Anmelden")]),
            bundle("fr", &[(LOGIN_IDENTIFIER_LABEL.0, "Identifiant")]),
        ]);
        let resolved = resolve_locale(Some("de fr"), &tag("en"), &map);
        assert_eq!(resolved.primary().as_str(), "de");
        assert_eq!(
            localize(LOGIN_TITLE, &MessageContext::empty(), &resolved),
            "Anmelden"
        );
        assert_eq!(
            localize(LOGIN_IDENTIFIER_LABEL, &MessageContext::empty(), &resolved),
            "Identifiant",
            "a de miss falls to the next requested bundle (fr) before English"
        );
    }

    #[test]
    fn the_env_default_bundle_is_the_final_fallback() {
        // With a requested locale that does not translate an id, the ENV DEFAULT bundle
        // resolves it before the English registry.
        let map = installed(vec![
            bundle("fr", &[(LOGIN_TITLE.0, "Se connecter")]),
            bundle("es", &[(LOGIN_IDENTIFIER_LABEL.0, "Identificador")]),
        ]);
        // Request fr; env default es. The fr bundle lacks the identifier label, so es (the env
        // default) supplies it.
        let resolved = resolve_locale(Some("fr"), &tag("es"), &map);
        assert_eq!(
            localize(LOGIN_IDENTIFIER_LABEL, &MessageContext::empty(), &resolved),
            "Identificador"
        );
    }

    #[test]
    fn the_default_resolved_locale_is_neutral_english() {
        let resolved = ResolvedLocale::default();
        assert_eq!(resolved.primary().as_str(), "en");
        assert_eq!(resolved.direction(), TextDirection::Ltr);
        assert_eq!(
            localize(LOGIN_TITLE, &MessageContext::empty(), &resolved),
            "Sign in"
        );
    }

    #[test]
    fn parse_skips_malformed_entries() {
        // A corrupt entries blob degrades to an empty bundle (per-id registry fallback), never
        // an error or a wrong render.
        let good = LocaleBundle::parse(tag("fr"), "{\"1010001\":\"Se connecter\"}");
        assert!(good.get(LOGIN_TITLE).is_some());
        let bad = LocaleBundle::parse(tag("fr"), "not json");
        assert!(bad.get(LOGIN_TITLE).is_none());
        // A non-numeric key and a non-string value are both skipped.
        let mixed = LocaleBundle::parse(
            tag("fr"),
            "{\"abc\":\"x\",\"1010001\":5,\"1010002\":\"Id\"}",
        );
        assert!(mixed.get(LOGIN_TITLE).is_none());
        assert_eq!(mixed.get(LOGIN_IDENTIFIER_LABEL), Some("Id"));
    }

    #[test]
    fn distinct_matched_tags_are_deduplicated_in_the_chain() {
        // fr-CA and fr both resolve (by truncation) to the installed fr bundle; it appears once.
        let map = installed(vec![bundle("fr", &[(LOGIN_TITLE.0, "Se connecter")])]);
        let resolved = resolve_locale(Some("fr-CA fr"), &tag("en"), &map);
        let tags: BTreeSet<&str> = std::iter::once(resolved.primary().as_str()).collect();
        assert!(tags.contains("fr"));
        assert_eq!(
            localize(LOGIN_TITLE, &MessageContext::empty(), &resolved),
            "Se connecter"
        );
    }
}
