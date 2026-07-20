// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bounded, typed design tokens (issue #86): the branding data model that
//! becomes CSS custom properties.
//!
//! Every token is a strongly typed scalar with a VALIDATED grammar, never a free CSS
//! string. This is the type-level wall that kills the CSS-injection class before a
//! value can ever reach the served stylesheet:
//!
//! - colors are a [`Color`] newtype that accepts ONLY a `#hex` literal
//!   (`#rgb`/`#rgba`/`#rrggbb`/`#rrggbbaa`); a value like
//!   `red;} body{background:url(javascript:...)` fails to parse and is never stored;
//! - typography is a closed [`FontFamily`] enum mapping to a FIXED, server-authored
//!   safe font stack, never an operator string (an arbitrary `font-family` could
//!   smuggle a `}` to break out of the rule);
//! - spacing and radii are clamped numerics ([`Space`], [`Radius`]) rendered into a
//!   fixed unit, so only digits and `px` can appear.
//!
//! Because every emitted value passed one of these grammars, [`tokens_to_css`]
//! provably emits CSS free of `}`/`;` breakout, `url()`, `expression()`, and `<`, so
//! the served `:root { ... }` variables are safe under the strict `style-src 'self'`
//! CSP with no `unsafe-inline`. Dark mode is a parallel [`DesignTokens`] rendered
//! through the SAME grammar, so it too carries no custom CSS input.

use std::fmt::Write as _;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A CSS color restricted to a `#hex` literal (issue #86): the ONLY color grammar
/// branding accepts. Parsing rejects anything that is not `#` followed by exactly 3,
/// 4, 6, or 8 hexadecimal digits, so no keyword, `url()`, `var()`, function, `;`, or
/// `}` can ever reach the stylesheet through a color value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Color(String);

impl Color {
    /// Parse a color from a `#hex` literal, or [`None`] if it is not EXACTLY `#`
    /// followed by 3/4/6/8 hex digits. This is the type boundary that closes the
    /// CSS-injection class for color values.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let hex = raw.strip_prefix('#')?;
        if !matches!(hex.len(), 3 | 4 | 6 | 8) {
            return None;
        }
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        // Normalize the hex digits to lowercase so two spellings of one color produce
        // one canonical stored + emitted value.
        Some(Self(format!("#{}", hex.to_ascii_lowercase())))
    }

    /// The canonical `#hex` string, safe to emit as a CSS value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Color {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Color {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Color::parse(&raw).ok_or_else(|| {
            serde::de::Error::custom("color must be a #hex literal (3/4/6/8 hex digits)")
        })
    }
}

/// The closed, server-known font-family allowlist (issue #86): typography is chosen
/// from this fixed set, never an operator string. Each variant maps to a FIXED, safe
/// font stack authored here, so a hostile `font-family` (which could smuggle a `}`
/// breakout) is impossible by construction. Remote fonts are blocked by the CSP
/// regardless, so every stack is a system/generic family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FontFamily {
    /// The platform system UI font (the neutral default).
    #[default]
    SystemUi,
    /// A neutral sans-serif stack.
    Sans,
    /// A serif stack.
    Serif,
    /// A monospace stack.
    Mono,
    /// A rounded system stack, falling back to system UI.
    Rounded,
}

impl FontFamily {
    /// The FIXED, server-authored CSS font stack for this family. Every stack is a
    /// closed literal built only from generic families and unquoted system font
    /// keywords, so it carries no `;`, `}`, `url()`, or quote that could break the
    /// CSS rule.
    #[must_use]
    pub fn stack(self) -> &'static str {
        match self {
            FontFamily::SystemUi => "system-ui, sans-serif",
            FontFamily::Sans => "Arial, Helvetica, sans-serif",
            FontFamily::Serif => "Georgia, Cambria, serif",
            FontFamily::Mono => "ui-monospace, SFMono-Regular, Menlo, monospace",
            FontFamily::Rounded => "ui-rounded, system-ui, sans-serif",
        }
    }
}

/// A spacing scalar clamped to `0..=64` and rendered in `px` (issue #86). A numeric
/// only token: no injection is possible because only digits and the fixed unit can
/// appear in the emitted value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space(u8);

impl Space {
    /// The clamped range upper bound (pixels).
    pub const MAX: u8 = 64;

    /// A spacing value, CLAMPED to `0..=64`. An out-of-range input is clamped, never
    /// rejected, so a hostile large value becomes a safe bound rather than a failure.
    #[must_use]
    pub fn new(pixels: u8) -> Self {
        Self(pixels.min(Self::MAX))
    }

    /// The pixel magnitude.
    #[must_use]
    pub fn pixels(self) -> u8 {
        self.0
    }
}

impl Serialize for Space {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for Space {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::new(u8::deserialize(deserializer)?))
    }
}

/// A corner-radius scalar clamped to `0..=32` and rendered in `px` (issue #86).
/// Numeric only, exactly like [`Space`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Radius(u8);

impl Radius {
    /// The clamped range upper bound (pixels).
    pub const MAX: u8 = 32;

    /// A radius value, CLAMPED to `0..=32`.
    #[must_use]
    pub fn new(pixels: u8) -> Self {
        Self(pixels.min(Self::MAX))
    }

    /// The pixel magnitude.
    #[must_use]
    pub fn pixels(self) -> u8 {
        self.0
    }
}

impl Serialize for Radius {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for Radius {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::new(u8::deserialize(deserializer)?))
    }
}

/// The closed, typed set of design tokens (issue #86): the branding scalars that
/// become CSS custom properties. Every field is a validated scalar, never a free CSS
/// string, so the emitted stylesheet is safe by construction. A parallel
/// [`DesignTokens`] carries the dark-mode variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesignTokens {
    /// The page background color.
    pub color_bg: Color,
    /// The primary foreground / text color.
    pub color_fg: Color,
    /// The accent (primary action) color.
    pub color_accent: Color,
    /// The foreground color on the accent (button text).
    pub color_accent_fg: Color,
    /// The error / alert color.
    pub color_error: Color,
    /// The surface (input / card) color.
    pub color_surface: Color,
    /// The border color.
    pub color_border: Color,
    /// The font family (a closed allowlist enum).
    pub font_family: FontFamily,
    /// The corner radius (clamped px).
    pub radius: Radius,
    /// The base spacing unit (clamped px).
    pub space: Space,
}

impl Default for DesignTokens {
    /// The NEUTRAL default tokens: the same values the unbranded stylesheet uses, so
    /// a brand that overrides nothing renders exactly today's neutral pages.
    fn default() -> Self {
        Self {
            color_bg: Color::parse("#f5f5f5").expect("valid"),
            color_fg: Color::parse("#1a1a1a").expect("valid"),
            color_accent: Color::parse("#2f5bde").expect("valid"),
            color_accent_fg: Color::parse("#ffffff").expect("valid"),
            color_error: Color::parse("#b00020").expect("valid"),
            color_surface: Color::parse("#ffffff").expect("valid"),
            color_border: Color::parse("#bbbbbb").expect("valid"),
            font_family: FontFamily::SystemUi,
            radius: Radius::new(6),
            space: Space::new(16),
        }
    }
}

impl DesignTokens {
    /// Emit the `--name: value;` custom-property pairs for these tokens into `out`
    /// (no wrapping selector). Every value passed a typed grammar, so the output
    /// carries no `}`/`;` breakout, `url()`, `expression()`, or `<`.
    fn write_variables(&self, out: &mut String) {
        // `write!` into a String is infallible; the results are discarded deliberately.
        let _ = write!(out, "--color-bg:{};", self.color_bg.as_str());
        let _ = write!(out, "--color-fg:{};", self.color_fg.as_str());
        let _ = write!(out, "--color-accent:{};", self.color_accent.as_str());
        let _ = write!(out, "--color-accent-fg:{};", self.color_accent_fg.as_str());
        let _ = write!(out, "--color-error:{};", self.color_error.as_str());
        let _ = write!(out, "--color-surface:{};", self.color_surface.as_str());
        let _ = write!(out, "--color-border:{};", self.color_border.as_str());
        let _ = write!(out, "--font-family:{};", self.font_family.stack());
        let _ = write!(out, "--radius:{}px;", self.radius.pixels());
        let _ = write!(out, "--space:{}px;", self.space.pixels());
    }
}

/// Render the design tokens to a `:root { ... }` custom-property block plus, when
/// dark-mode variants are present, a `@media (prefers-color-scheme: dark)` override
/// (issue #86). Every value is a typed scalar, so the emitted CSS is CSP-clean: no
/// inline style, no `url()`, no external host, no breakout.
#[must_use]
pub fn tokens_to_css(light: &DesignTokens, dark: Option<&DesignTokens>) -> String {
    let mut out = String::new();
    out.push_str(":root{");
    light.write_variables(&mut out);
    out.push('}');
    if let Some(dark) = dark {
        out.push_str("@media (prefers-color-scheme:dark){:root{");
        dark.write_variables(&mut out);
        out.push_str("}}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Color, DesignTokens, FontFamily, Radius, Space, tokens_to_css};

    #[test]
    fn a_valid_hex_color_parses_and_normalizes() {
        assert_eq!(Color::parse("#FFF").unwrap().as_str(), "#fff");
        assert_eq!(Color::parse("#2F5BDE").unwrap().as_str(), "#2f5bde");
        assert_eq!(Color::parse("#11223344").unwrap().as_str(), "#11223344");
        assert_eq!(Color::parse("#abcd").unwrap().as_str(), "#abcd");
    }

    #[test]
    fn a_hostile_color_is_rejected_at_the_type_boundary() {
        // The CSS-injection payloads a color field would be attacked with all fail to
        // parse, so they can never reach the stylesheet.
        for hostile in [
            "red",
            "red;} body{background:url(javascript:alert(1))}",
            "#fff;color:red",
            "url(javascript:alert(1))",
            "var(--x)",
            "#12",
            "#1234567",
            "#gggggg",
            "#ffffff ",
            " #ffffff",
            "rgb(1,2,3)",
            "#",
            "",
            "expression(alert(1))",
        ] {
            assert!(
                Color::parse(hostile).is_none(),
                "hostile color must be rejected: {hostile:?}"
            );
        }
    }

    #[test]
    fn spacing_and_radii_clamp_hostile_magnitudes() {
        assert_eq!(Space::new(255).pixels(), Space::MAX);
        assert_eq!(Radius::new(255).pixels(), Radius::MAX);
        assert_eq!(Space::new(8).pixels(), 8);
    }

    #[test]
    fn a_font_family_maps_to_a_fixed_safe_stack() {
        // Every stack is a fixed literal with no breakout character.
        for family in [
            FontFamily::SystemUi,
            FontFamily::Sans,
            FontFamily::Serif,
            FontFamily::Mono,
            FontFamily::Rounded,
        ] {
            let stack = family.stack();
            for forbidden in ['}', ';', '<', '>', '"', '\'', '\\'] {
                assert!(
                    !stack.contains(forbidden),
                    "font stack {stack:?} must carry no breakout character {forbidden:?}"
                );
            }
            assert!(!stack.contains("url("), "no url() in {stack:?}");
        }
    }

    #[test]
    fn tokens_to_css_emits_only_safe_variables() {
        let light = DesignTokens::default();
        let dark = DesignTokens {
            color_bg: Color::parse("#141414").unwrap(),
            color_fg: Color::parse("#eeeeee").unwrap(),
            ..DesignTokens::default()
        };
        let css = tokens_to_css(&light, Some(&dark));
        // The variables are present.
        assert!(css.contains(":root{"), "{css}");
        assert!(css.contains("--color-bg:#f5f5f5;"), "{css}");
        assert!(
            css.contains("--font-family:system-ui, sans-serif;"),
            "{css}"
        );
        assert!(css.contains("--radius:6px;"), "{css}");
        // The dark block is present with the dark values.
        assert!(
            css.contains("@media (prefers-color-scheme:dark){:root{--color-bg:#141414;"),
            "{css}"
        );
        // CSP-clean: no url(), no external host, no breakout, no inline-style vector.
        assert!(!css.contains("url("), "{css}");
        assert!(!css.contains("http"), "{css}");
        assert!(!css.contains('<'), "{css}");
        assert!(!css.contains("expression("), "{css}");
        // The braces are balanced (only the block openers/closers).
        assert_eq!(
            css.matches('{').count(),
            css.matches('}').count(),
            "balanced braces: {css}"
        );
    }

    #[test]
    fn design_tokens_round_trip_through_json_and_reject_a_hostile_color() {
        let tokens = DesignTokens::default();
        let json = serde_json::to_string(&tokens).expect("serialize");
        let back: DesignTokens = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tokens, back);
        // A stored blob carrying a hostile color fails to deserialize, so the renderer
        // falls back to the neutral default rather than emitting it.
        let hostile = json.replace("#f5f5f5", "red;}body{x:url(javascript:1)}");
        assert!(
            serde_json::from_str::<DesignTokens>(&hostile).is_err(),
            "a hostile stored color must fail to deserialize"
        );
    }
}
