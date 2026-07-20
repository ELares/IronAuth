// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe branding (issue #86): the sanitizer, the bounded typed design tokens, and
//! the resolved per-environment brand the hosted flow render app renders.
//!
//! The whole subsystem holds one structural rule: branding is expressible ONLY
//! through data that cannot become script. Three type-level walls enforce it, none
//! bypassable by an operator:
//!
//! 1. rich text passes the ONE allowlist sanitizer ([`sanitize`]) and becomes an
//!    unconstructable-except-via-sanitizer [`SanitizedRichText`]
//!    (see [`sanitize`](self::sanitize));
//! 2. design tokens are a closed set of validated scalars ([`DesignTokens`]) emitted
//!    as CSS custom properties in a server-authored stylesheet, never inline
//!    (see [`tokens`](self::tokens));
//! 3. everything else (the product name, the wordmark, the brand token) stays a
//!    plain, server-known string rendered through [`crate::pages::escape_html`].
//!
//! Per the owner ruling, PR1 ships PER-ENVIRONMENT branding only (one default brand
//! per environment). Per-domain / per-client SELECTION is PR3 and per-organization
//! branding is deferred to M10; this module reserves the seam without building it.

mod sanitize;
mod select;
mod tokens;

pub use sanitize::{SanitizedRichText, sanitize};
pub use select::{BrandCandidate, normalize_host, select_brand};
pub use tokens::{Color, DesignTokens, FontFamily, Radius, Space, tokens_to_css};

use std::collections::BTreeMap;

/// The closed set of named rich-text slots a brand may fill (issue #86). An operator
/// cannot invent an arbitrary slot name that maps to an arbitrary DOM location: each
/// slot renders at a FIXED, server-authored position in the flow page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlotId {
    /// A legal / consent footer rendered at the bottom of every flow page.
    FooterLegal,
    /// A help blurb rendered near the top of a login page.
    LoginHelp,
    /// A notice rendered on the consent surface.
    ConsentNotice,
}

impl SlotId {
    /// Every slot id, in a stable order (for the stored-JSON round trip).
    pub const ALL: [SlotId; 3] = [
        SlotId::FooterLegal,
        SlotId::LoginHelp,
        SlotId::ConsentNotice,
    ];

    /// The stable wire key this slot serializes under in the stored slot map.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SlotId::FooterLegal => "footer_legal",
            SlotId::LoginHelp => "login_help",
            SlotId::ConsentNotice => "consent_notice",
        }
    }

    /// Parse a stored wire key back to a slot id, or [`None`] for an unknown key (a
    /// key an older or hostile blob might carry): an unknown slot is ignored, never
    /// rendered at a guessed location.
    #[must_use]
    pub fn parse(key: &str) -> Option<Self> {
        SlotId::ALL.into_iter().find(|slot| slot.as_str() == key)
    }
}

/// The sanitized rich-text slots of a brand (issue #86): a fixed map from [`SlotId`]
/// to [`SanitizedRichText`]. Every value can ONLY be a sanitizer output, so a slot
/// can never carry unsanitized markup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrandSlots {
    slots: BTreeMap<SlotId, SanitizedRichText>,
}

impl BrandSlots {
    /// Build slots from RAW operator input, sanitizing each value at ingest (issue
    /// #86): the management-write path. An empty sanitized result is dropped (an empty
    /// slot renders nothing). This is the ONLY ingest constructor, so a slot value is
    /// sanitized before it is ever stored.
    #[must_use]
    pub fn from_raw<I: IntoIterator<Item = (SlotId, String)>>(raw: I) -> Self {
        let mut slots = BTreeMap::new();
        for (id, value) in raw {
            let clean = sanitize(&value);
            if !clean.is_empty() {
                slots.insert(id, clean);
            }
        }
        Self { slots }
    }

    /// Parse stored slots (a JSON object of wire-key to string) and RE-SANITIZE each
    /// value (issue #86). Re-sanitizing on read is idempotent for a value that was
    /// sanitized at ingest, and it makes the rendered output safe even if the stored
    /// blob were ever tampered with (defense in depth). An unknown or hostile key is
    /// ignored. A blob that is not a JSON object yields no slots.
    #[must_use]
    pub fn from_stored_json(json: &str) -> Self {
        let parsed: BTreeMap<String, String> = serde_json::from_str(json).unwrap_or_default();
        let mut slots = BTreeMap::new();
        for (key, value) in parsed {
            if let Some(id) = SlotId::parse(&key) {
                let clean = sanitize(&value);
                if !clean.is_empty() {
                    slots.insert(id, clean);
                }
            }
        }
        Self { slots }
    }

    /// Serialize the sanitized slots to the stored JSON object (wire-key to sanitized
    /// string). The stored value is already safe markup.
    #[must_use]
    pub fn to_stored_json(&self) -> String {
        let map: BTreeMap<&str, &str> = self
            .slots
            .iter()
            .map(|(id, value)| (id.as_str(), value.as_str()))
            .collect();
        serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_owned())
    }

    /// The sanitized value for a slot, if present.
    #[must_use]
    pub fn get(&self, id: SlotId) -> Option<&SanitizedRichText> {
        self.slots.get(&id)
    }

    /// Whether no slot is filled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

/// A resolved per-environment brand for rendering (issue #86): the product
/// name/wordmark, the sanitized rich-text slots, and the design tokens (plus the
/// optional dark-mode variants). Every field is either a plain server-known string
/// (escaped on render), a [`SanitizedRichText`] slot, or a typed token, so a brand
/// can never carry raw HTML or CSS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brand {
    /// The product name rendered as a plain-text wordmark, escaped on render.
    pub product_name: String,
    /// Whether to show the wordmark header.
    pub show_wordmark: bool,
    /// An optional plain-text brand token badge, escaped on render.
    pub brand_token: Option<String>,
    /// The sanitized rich-text slots.
    pub slots: BrandSlots,
    /// The light-mode design tokens.
    pub tokens: DesignTokens,
    /// The dark-mode token variants, if authored (else dark mode reuses the neutral
    /// built-in dark block).
    pub tokens_dark: Option<DesignTokens>,
}

impl Brand {
    /// Resolve a brand from its STORED parts (issue #86): the plain product fields,
    /// the serialized token JSON, and the serialized slot JSON. The tokens are parsed
    /// with a NEUTRAL fallback (a malformed or hostile token blob renders the neutral
    /// default, never an injected value), and the slots are re-sanitized on read. So
    /// a brand read from the store is always safe to render regardless of what the
    /// row holds.
    #[must_use]
    pub fn from_stored(
        product_name: String,
        show_wordmark: bool,
        brand_token: Option<String>,
        tokens_json: &str,
        tokens_dark_json: Option<&str>,
        slots_json: &str,
    ) -> Self {
        let tokens = serde_json::from_str(tokens_json).unwrap_or_default();
        let tokens_dark = tokens_dark_json.and_then(|json| serde_json::from_str(json).ok());
        Self {
            product_name,
            show_wordmark,
            brand_token,
            slots: BrandSlots::from_stored_json(slots_json),
            tokens,
            tokens_dark,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Brand, BrandSlots, DesignTokens, SlotId};

    #[test]
    fn slots_sanitize_at_ingest_and_round_trip_through_storage() {
        let slots = BrandSlots::from_raw([
            (
                SlotId::FooterLegal,
                "<p>See our <a href=\"https://acme.test/legal\">terms</a><script>alert(1)</script></p>"
                    .to_owned(),
            ),
            (
                SlotId::LoginHelp,
                "<img src=x onerror=alert(1)>Need help?".to_owned(),
            ),
        ]);
        // The stored JSON is already sanitized: no script, no handler.
        let json = slots.to_stored_json();
        let lower = json.to_ascii_lowercase();
        assert!(!lower.contains("<script"), "{json}");
        assert!(!lower.contains("onerror"), "{json}");
        assert!(lower.contains("terms"), "{json}");
        // Round-trips through storage and stays inert.
        let read = BrandSlots::from_stored_json(&json);
        assert_eq!(read, slots);
        let footer = read.get(SlotId::FooterLegal).expect("footer present");
        assert!(
            footer.as_str().contains("https://acme.test/legal"),
            "{footer:?}"
        );
    }

    #[test]
    fn an_unknown_slot_key_is_ignored_on_read() {
        let read = BrandSlots::from_stored_json(
            "{\"footer_legal\":\"<b>hi</b>\",\"evil_slot\":\"<script>x</script>\"}",
        );
        assert!(read.get(SlotId::FooterLegal).is_some());
        // The unknown key contributes nothing (no way to render it at a chosen spot).
        assert_eq!(read.to_stored_json(), "{\"footer_legal\":\"<b>hi</b>\"}");
    }

    #[test]
    fn a_hostile_token_blob_falls_back_to_neutral_on_read() {
        // A tampered token blob (a hostile color) fails to parse and the brand renders
        // the neutral default tokens, never the injected value.
        let brand = Brand::from_stored(
            "Acme".to_owned(),
            true,
            None,
            "{\"color_bg\":\"red;}body{x:1}\"}",
            None,
            "{}",
        );
        assert_eq!(brand.tokens, DesignTokens::default());
    }

    #[test]
    fn a_well_formed_brand_reads_back_its_tokens() {
        let tokens = DesignTokens::default();
        let json = serde_json::to_string(&tokens).unwrap();
        let brand = Brand::from_stored("Acme".to_owned(), true, None, &json, None, "{}");
        assert_eq!(brand.tokens, tokens);
        assert!(brand.slots.is_empty());
    }
}
