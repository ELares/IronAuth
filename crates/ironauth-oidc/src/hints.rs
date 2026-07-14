// SPDX-License-Identifier: MIT OR Apache-2.0

//! The typed interaction-hint seam (issue #16): the parsed `login_hint`,
//! `logout_hint`, `ui_locales`, `claims_locales`, and `display` values carried
//! from the authorization request into the interaction (login/registration/
//! consent) layer.
//!
//! These parameters are NON-security hints: they steer the hosted UI (a prefilled
//! identifier, a language preference, a layout hint) and, later, an upstream
//! identity-provider connection. They are produced ONCE at `/authorize` and threaded
//! to the interaction layer through the resuming `return_to`, then reconstructed at
//! each interaction page from that `return_to`. Modelling them as one typed struct
//! is deliberately the seam upstream identity-provider forwarding (M8) plugs into:
//! M8 forwards these same fields to an upstream provider without re-plumbing the
//! authorization endpoint. This issue provides the seam only; it does NOT forward
//! anything upstream and it does NOT add a logout endpoint (`logout_hint` is
//! accepted and carried for a later logout surface, never acted on here).
//!
//! Every value here is UNTRUSTED request input. The interaction pages that reflect
//! a hint (the login `login_hint` prefill, the `ui_locales` language attribute) run
//! it through the page escaper first, so no hint can break out of its HTML context.

use crate::util::query_get;

/// The OIDC `display` value: how the OP should present the authentication and
/// consent UI (OIDC Core 3.1.2.1).
///
/// The bootstrap renders one minimal responsive layout, so only `page` is
/// meaningfully honored (and advertised in discovery); `popup`, `touch`, and `wap`
/// PARSE and are carried on the context, but degrade to the page layout rather than
/// being refused, so a client that asks for one is never rejected. An unrecognized
/// `display` value is ignored (dropped to the default), per the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Display {
    /// `page`: a full-page view (the default and the only layout the bootstrap
    /// renders).
    #[default]
    Page,
    /// `popup`: a popup-window view. Carried; degrades to the page layout.
    Popup,
    /// `touch`: a touch-optimized view. Carried; degrades to the page layout.
    Touch,
    /// `wap`: a feature-phone view. Carried; degrades to the page layout.
    Wap,
}

impl Display {
    /// Every `display` value this build can represent.
    pub const ALL: &'static [Display] =
        &[Display::Page, Display::Popup, Display::Touch, Display::Wap];

    /// The `display` values the bootstrap page context meaningfully HONORS (renders
    /// a distinct-or-default layout for) and therefore advertises: only `page`
    /// today. The others parse (accepted, not refused) and fall back to the page
    /// layout, so advertising only `page` avoids an advertise/refuse mismatch.
    pub const SUPPORTED: &'static [Display] = &[Display::Page];

    /// The wire / metadata `display` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Display::Page => "page",
            Display::Popup => "popup",
            Display::Touch => "touch",
            Display::Wap => "wap",
        }
    }

    /// Parse a wire `display` value. Returns [`None`] for every unrecognized value,
    /// which the caller treats as absent (the default `page`), per OIDC Core.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "page" => Some(Display::Page),
            "popup" => Some(Display::Popup),
            "touch" => Some(Display::Touch),
            "wap" => Some(Display::Wap),
            _ => None,
        }
    }
}

/// The parsed, typed interaction hints for one authorization request (issue #16).
///
/// Produced at `/authorize` from the request parameters and carried through the
/// resuming `return_to`; reconstructed at each interaction page with
/// [`InteractionHints::from_query`]. The default is all-absent (`page` display),
/// which the server-authored notice pages use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InteractionHints {
    login_hint: Option<String>,
    logout_hint: Option<String>,
    ui_locales: Option<String>,
    claims_locales: Option<String>,
    display: Option<Display>,
}

impl InteractionHints {
    /// Build the hints from the raw authorization-request parameter values. Each
    /// string is trimmed and an empty value is treated as absent; an unrecognized
    /// `display` is dropped to the default.
    #[must_use]
    pub fn from_request(
        login_hint: Option<&str>,
        logout_hint: Option<&str>,
        ui_locales: Option<&str>,
        claims_locales: Option<&str>,
        display: Option<&str>,
    ) -> Self {
        Self {
            login_hint: clean(login_hint),
            logout_hint: clean(logout_hint),
            ui_locales: clean(ui_locales),
            claims_locales: clean(claims_locales),
            display: display.map(str::trim).and_then(Display::parse),
        }
    }

    /// Reconstruct the hints from a resuming `/authorize?...` query string (the
    /// part after `?`), reading each hint parameter back out of it. This is how the
    /// interaction pages recover the hints the authorization request carried.
    #[must_use]
    pub fn from_query(query: &str) -> Self {
        let login_hint = query_get(query, "login_hint");
        let logout_hint = query_get(query, "logout_hint");
        let ui_locales = query_get(query, "ui_locales");
        let claims_locales = query_get(query, "claims_locales");
        let display = query_get(query, "display");
        Self::from_request(
            login_hint.as_deref(),
            logout_hint.as_deref(),
            ui_locales.as_deref(),
            claims_locales.as_deref(),
            display.as_deref(),
        )
    }

    /// The `login_hint`: the identifier to prefill on the login page.
    #[must_use]
    pub fn login_hint(&self) -> Option<&str> {
        self.login_hint.as_deref()
    }

    /// The `logout_hint`: carried for a later logout surface, never acted on here.
    #[must_use]
    pub fn logout_hint(&self) -> Option<&str> {
        self.logout_hint.as_deref()
    }

    /// The `ui_locales`: the space-separated end-user UI language preference.
    #[must_use]
    pub fn ui_locales(&self) -> Option<&str> {
        self.ui_locales.as_deref()
    }

    /// The `claims_locales`: the space-separated claim-value language preference.
    #[must_use]
    pub fn claims_locales(&self) -> Option<&str> {
        self.claims_locales.as_deref()
    }

    /// The requested `display`, defaulting to [`Display::Page`] when absent.
    #[must_use]
    pub fn display(&self) -> Display {
        self.display.unwrap_or_default()
    }

    /// The canonical `display` value to carry across the interaction round-trip, or
    /// [`None`] when the request named none (so no default is injected).
    #[must_use]
    pub fn display_param(&self) -> Option<&'static str> {
        self.display.map(Display::as_str)
    }

    /// The primary language subtag for the page `lang` attribute: the first
    /// `ui_locales` tag when it is a well-formed BCP 47-ish token, else `en` (the
    /// language the bootstrap pages are written in). The returned value is reflected
    /// into an HTML attribute, so it is additionally escaped by the page; the
    /// charset guard here keeps only a conservative token so nothing exotic reaches
    /// the attribute in the first place.
    #[must_use]
    pub fn lang(&self) -> &str {
        self.ui_locales
            .as_deref()
            .and_then(|locales| locales.split_whitespace().next())
            .filter(|tag| is_language_tag(tag))
            .unwrap_or("en")
    }
}

/// Trim a raw hint value and treat an empty result as absent.
fn clean(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Whether `tag` is a conservative BCP 47-ish language tag: 1 to 35 characters of
/// ASCII letters, digits, or hyphens. Deliberately stricter than the full grammar
/// (it only gates what may become an HTML `lang` attribute), so a hostile or
/// malformed value never reaches the page.
fn is_language_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 35
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_parses_the_four_values_and_rejects_the_rest() {
        for display in Display::ALL {
            assert_eq!(Display::parse(display.as_str()), Some(*display));
        }
        assert_eq!(Display::parse(" page "), Some(Display::Page));
        for unknown in ["", "PAGE", "screen", "  "] {
            assert!(Display::parse(unknown).is_none(), "{unknown:?}");
        }
    }

    #[test]
    fn only_page_is_advertised_as_supported() {
        assert_eq!(Display::SUPPORTED, &[Display::Page]);
        // The default is page, so an absent display renders the supported layout.
        assert_eq!(Display::default(), Display::Page);
    }

    #[test]
    fn from_request_trims_and_treats_empty_as_absent() {
        let hints = InteractionHints::from_request(
            Some("  ada@example.test  "),
            Some(""),
            Some("fr-CA en"),
            Some("   "),
            Some("popup"),
        );
        assert_eq!(hints.login_hint(), Some("ada@example.test"));
        assert_eq!(hints.logout_hint(), None, "empty logout_hint is absent");
        assert_eq!(hints.ui_locales(), Some("fr-CA en"));
        assert_eq!(hints.claims_locales(), None, "blank claims_locales absent");
        assert_eq!(hints.display(), Display::Popup);
        assert_eq!(hints.display_param(), Some("popup"));
    }

    #[test]
    fn absent_display_defaults_to_page_without_injecting_a_param() {
        let hints = InteractionHints::from_request(None, None, None, None, None);
        assert_eq!(hints.display(), Display::Page, "default layout");
        assert_eq!(
            hints.display_param(),
            None,
            "no display is carried when none was requested"
        );
        assert_eq!(hints.lang(), "en", "default language");
    }

    #[test]
    fn unknown_display_is_dropped_to_the_default() {
        let hints = InteractionHints::from_request(None, None, None, None, Some("hologram"));
        assert_eq!(hints.display(), Display::Page);
        assert_eq!(hints.display_param(), None);
    }

    #[test]
    fn lang_uses_the_primary_ui_locale_or_falls_back_to_en() {
        assert_eq!(
            InteractionHints::from_request(None, None, Some("de-DE fr"), None, None).lang(),
            "de-DE"
        );
        // A hostile primary tag is rejected by the charset guard and falls back.
        assert_eq!(
            InteractionHints::from_request(None, None, Some("\"><script>"), None, None).lang(),
            "en"
        );
    }

    #[test]
    fn from_query_round_trips_the_carried_hints() {
        // The canonical carried query (percent-encoded values) is read back into the
        // identical typed hints, so a hint survives the interaction round-trip.
        let query = "client_id=cli_x&login_hint=ada%40example.test&ui_locales=fr&display=touch&\
             logout_hint=sess-9&claims_locales=en";
        let hints = InteractionHints::from_query(query);
        assert_eq!(hints.login_hint(), Some("ada@example.test"));
        assert_eq!(hints.logout_hint(), Some("sess-9"));
        assert_eq!(hints.ui_locales(), Some("fr"));
        assert_eq!(hints.claims_locales(), Some("en"));
        assert_eq!(hints.display(), Display::Touch);
    }
}
