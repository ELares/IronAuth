// SPDX-License-Identifier: MIT OR Apache-2.0

//! The branding rich-text sanitizer (issue #86): the security core of safe
//! branding.
//!
//! # Why this exists
//!
//! Branding lets an operator author a small amount of rich text for a fixed set of
//! named page slots (a legal footer, a login help blurb, a consent notice). The
//! obvious implementation, a free HTML or CSS field, is a stored-XSS trap: Casdoor's
//! `formCss` / `pageHtml` customization produced deliberate script execution in the
//! auth origin (CVE-2026-5468). The structural lesson is that branding must be
//! expressible ONLY through data that cannot become script. This module is the ONE
//! place any rich text becomes safe markup.
//!
//! # The guarantee
//!
//! [`sanitize`] is the ONLY constructor of [`SanitizedRichText`], whose inner string
//! is private. A page renders a rich-text slot ONLY by emitting a
//! [`SanitizedRichText`], so "no branding rich-text field reaches a page
//! unsanitized" is a COMPILE-TIME property, not a review convention: there is no way
//! to obtain a [`SanitizedRichText`] except by passing input through the allowlist
//! sanitizer. The rendered output is the sanitized safe-markup string, the ONE place
//! the flow render app emits pre-sanitized HTML rather than [`crate::pages::escape_html`]
//! escaped text.
//!
//! # The allowlist (owner ruling, the minimal subset)
//!
//! The sanitizer is the vetted [`ammonia`] allowlist sanitizer (built on html5ever,
//! a real HTML parser, so mutation XSS is handled by construction), configured to
//! EXACTLY this subset and nothing else:
//!
//! - tags: `b i strong em u p br a`;
//! - attributes: `href` on `a` only (no `style`, `class`, `id`, or `on*` anywhere);
//! - URL schemes: `https` only, so a `javascript:`, `data:`, `vbscript:`, or
//!   protocol-relative href is dropped (the link is kept, its href removed);
//! - a forced `rel="noopener noreferrer nofollow"` on every surviving link, and no
//!   `target`;
//! - the content of `script` and `style` (and other executable/embedding elements)
//!   is REMOVED, not kept as text, so no `url()`, `@import`, or inline script leaks.
//!
//! Because no `style`/`class` attribute and no CSS field exist anywhere in the model,
//! a `url()` / `expression()` sink cannot appear; because only `https` links survive,
//! a scripting scheme cannot appear; because the output is reserialized from a parsed
//! DOM, it is always well formed.
//!
//! # The output is a FIXED POINT, and that took a loop
//!
//! [`sanitize`] returns a value the allowlist leaves alone: `sanitize(sanitize(x)) ==
//! sanitize(x)` for every input. Two live paths rest on that. The render path
//! re-sanitizes a stored slot on read (defense in depth), and it must not rewrite a
//! value that was already safe. The config-promotion import wall asks "is this string
//! already sanitizer output" and refuses a slot that is not, so a value IronAuth
//! EXPORTED has to survive its own wall.
//!
//! A single `ammonia` pass does not give that. An element outside the allowlist can
//! suppress the implied `</p>`, leaving one `<p>` nested inside another; stripping the
//! element keeps its children, so the pass emits `<p>` inside `<p>`, which no parser
//! can produce, and the next parse unfolds it. [`sanitize`] therefore applies the
//! allowlist until a pass changes nothing, within a small measured budget, and fails
//! closed on the empty fragment if the budget runs out. Inertness never depends on the
//! budget: every pass is `ammonia`-cleaned, so any pass the loop stops on is safe
//! markup. Only the fixed-point property needs the loop.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// A rich-text HTML fragment that has passed the branding allowlist sanitizer
/// ([`sanitize`]) and is therefore SAFE to emit into a page verbatim (issue #86).
///
/// The inner string is PRIVATE and the ONLY way to construct a value is through
/// [`sanitize`], so a page that renders a [`SanitizedRichText`] renders allowlisted
/// safe markup by construction. This is the type-level wall that makes "no branding
/// rich text reaches a page unsanitized" a compile-time property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedRichText(String);

impl SanitizedRichText {
    /// The sanitized safe-markup string, for the ONE renderer path that emits
    /// pre-sanitized HTML (documented safe: it is ammonia-allowlisted output).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the sanitized fragment is empty (for example the input was blank or
    /// consisted only of stripped markup), so the renderer can skip an empty slot.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The shared, lazily built allowlist sanitizer, configured to the minimal subset
/// (see the module documentation). Built once; every [`sanitize`] call reuses it.
fn sanitizer() -> &'static ammonia::Builder<'static> {
    static SANITIZER: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    SANITIZER.get_or_init(|| {
        let mut builder = ammonia::Builder::empty();
        // The closed tag allowlist: bold/italic emphasis, underline, paragraph, line
        // break, and anchor. Any other tag is dropped (its text content kept, the tag
        // removed), except the clean-content tags below whose content is removed too.
        builder.tags(HashSet::from([
            "b", "i", "strong", "em", "u", "p", "br", "a",
        ]));
        // The ONLY allowed attribute anywhere: href on an anchor. No style, class, id,
        // or on* handler can survive on any element.
        builder.tag_attributes(HashMap::from([("a", HashSet::from(["href"]))]));
        // Clear the GENERIC attributes ammonia otherwise allows on every tag (its default
        // set includes `lang` and `title`): the owner ruling permits EXACTLY `a[href]` and
        // nothing else, so a `title=` (or any other generic attribute) must not survive on a
        // `<p>` or any element. `Builder::empty()` clears the tag allowlist but NOT this set,
        // so it is cleared explicitly here.
        builder.generic_attributes(HashSet::new());
        builder.generic_attribute_prefixes(HashSet::new());
        // https ONLY: a javascript:, data:, or vbscript: href is rejected (the anchor
        // survives, its href removed), so a scripting or data scheme can never reach the
        // page.
        builder.url_schemes(HashSet::from(["https"]));
        // DENY relative and protocol-relative hrefs: ammonia passes relative URLs through by
        // default, so a network-path-relative `//evil.test/x` (which has no scheme and would
        // inherit the page https scheme, reaching an external host) or a path-relative
        // `/foo` would otherwise survive. Denying them leaves ONLY absolute https URLs, the
        // exact allowlist ruling (a[href] on an https-only scheme).
        builder.url_relative(ammonia::UrlRelative::Deny);
        // Force a safe rel on every surviving link and never emit a target.
        builder.link_rel(Some("noopener noreferrer nofollow"));
        // Remove the CONTENT of executable / embedding / raw-text elements entirely
        // (not merely the tag), so no inline script, no `@import url()` CSS, and no
        // embedded object leaks even as text. Defense in depth: none of these tags is
        // in the allowlist above, so their tags are already dropped; this also strips
        // their inner text.
        builder.clean_content_tags(HashSet::from([
            "script", "style", "iframe", "object", "embed", "svg", "math", "noscript", "template",
            "title", "textarea", "form", "link", "meta", "base",
        ]));
        builder
    })
}

/// The pass budget [`sanitize_to_fixed_point`] spends before it FAILS CLOSED.
///
/// Justified by measurement, not by taste. Over 200,000 pseudorandom fragments drawn
/// from an adversarial tag vocabulary (`select`, `button`, `table`, `form`, the
/// clean-content tags, stray `<`/`>`), the worst input needed THREE passes to reach a
/// pass that changed nothing: one to strip, one to unfold the nesting that stripping
/// left behind, one to observe the fixed point. 421 inputs needed three, 196,800
/// needed two, 2,779 were already fixed points, and NONE needed four. The shipped
/// bypass corpus needs two, and the nightly fuzzer's crash input needs three. Six is
/// twice the measured worst case, so a future html5ever or `ammonia` that reshapes a
/// pass differently has room to move before an operator's slot starts emptying.
///
/// The budget is not a performance cost in the ordinary case: the loop stops at the
/// FIRST pass that changes nothing, so already-sanitized input (the render path's
/// re-sanitize on read) costs one pass and raw markup costs two.
const MAX_SANITIZE_PASSES: usize = 6;

/// Apply the allowlist repeatedly until a pass changes nothing, spending at most
/// `max_passes` passes, and FAIL CLOSED with the empty fragment if the budget runs out
/// before a pass changes nothing.
///
/// # Why a loop is needed at all
///
/// One `ammonia` pass is not a fixed point. A non-allowlisted element that suppresses
/// the implied `</p>` (`select` and `button` both do) leaves a second `<p>` as a
/// DESCENDANT of the first; dropping the non-allowlisted wrapper keeps its children in
/// place, so the pass emits `<p>a<p>b</p></p>`. No parser can produce a `<p>` inside a
/// `<p>`, so the next parse unfolds it into siblings and the value moves. The nightly
/// `branding_sanitize` fuzz target found this, and the seed corpus entry
/// `seed_regression_select_nested_p` pins the exact input.
///
/// # Why failing closed is the safe end of the budget
///
/// The alternative, returning the last pass unchecked, would put the idempotence
/// property back at the mercy of the bound: an input needing one pass more than the
/// budget would silently reintroduce the exact defect this loop exists to remove.
/// Returning the empty fragment instead makes idempotence UNCONDITIONAL rather than
/// bounded, because the empty fragment is a fixed point of the allowlist for free
/// (`clean("") == ""`), so `sanitize(sanitize(x)) == sanitize(x)` holds for EVERY input
/// with no appeal to how large the budget is. The cost is a dropped slot in a case no
/// measurement has ever produced: an empty slot renders nothing ([`SanitizedRichText::is_empty`]),
/// and [`crate::branding::BrandSlots::from_raw`] drops it rather than storing it, so
/// the failure degrades to "this slot shows nothing", never to unstable or unsafe
/// markup. `the_pass_budget_fails_closed_rather_than_returning_an_unstable_value` drives
/// that branch directly, by handing the loop a budget of two for an input needing three.
///
/// Inertness does NOT rest on the budget either: every value this returns is either
/// `ammonia` output or the empty string, so it is allowlisted markup whichever pass it
/// stops on.
fn sanitize_to_fixed_point(input: &str, max_passes: usize) -> String {
    let mut current = input.to_owned();
    for _ in 0..max_passes {
        let next = sanitizer().clean(&current).to_string();
        if next == current {
            // A pass that changes nothing PROVES a fixed point: re-sanitizing this
            // value again, on read or at an import wall, returns it byte for byte.
            return current;
        }
        current = next;
    }
    // The budget ran out without a pass that changed nothing. Fail CLOSED: see above.
    String::new()
}

/// Sanitize untrusted rich text to the minimal branding allowlist (issue #86): the
/// ONE constructor of [`SanitizedRichText`].
///
/// The result contains only the allowlisted tags (`b i strong em u p br a`), only an
/// `https` `href` on an anchor (with a forced `rel`), and NO script, `on*` handler,
/// `style`, `url()`, or non-https scheme. It is well formed (reserialized from a
/// parsed DOM).
///
/// It is also a FIXED POINT of the allowlist: `sanitize(sanitize(x)) == sanitize(x)`
/// for every input, so re-sanitizing on read (defense in depth) never changes a safe
/// value, and a value IronAuth exported is accepted by an import wall that asks "is
/// this already sanitizer output" (`ironauth_admin::brands::promoted_brand_faults`).
/// A single `ammonia` pass does NOT have that property; [`sanitize_to_fixed_point`]
/// explains why, what the pass budget is, and what happens if it runs out.
#[must_use]
pub fn sanitize(input: &str) -> SanitizedRichText {
    SanitizedRichText(sanitize_to_fixed_point(input, MAX_SANITIZE_PASSES))
}

#[cfg(test)]
mod tests {
    use super::{MAX_SANITIZE_PASSES, sanitize, sanitize_to_fixed_point};

    /// The Casdoor-class stored-XSS bypass corpus (issue #86): every entry is a
    /// stored-XSS payload of the kind a branding rich-text slot would be attacked
    /// with. Each is fed through [`sanitize`] and asserted to produce ZERO executable
    /// or dangerous output. The build FAILS on any bypass, so a regression that let a
    /// payload through would fail CI here.
    const BYPASS_CORPUS: &[&str] = &[
        // Classic inline script.
        "<script>alert(1)</script>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<script src=//evil.test/x.js></script>",
        // Event-handler injection on assorted elements.
        "<img src=x onerror=alert(1)>",
        "<b onmouseover=alert(1)>hover</b>",
        "<p onclick=\"alert(1)\">click</p>",
        "<a href=\"https://ok.test\" onclick=\"alert(1)\">link</a>",
        // Scripting-scheme hrefs, including whitespace, mixed case, and entities.
        "<a href=\"javascript:alert(1)\">x</a>",
        "<a href=\" javascript:alert(1)\">x</a>",
        "<a href=\"JaVaScRiPt:alert(1)\">x</a>",
        "<a href=\"java\tscript:alert(1)\">x</a>",
        "<a href=\"&#106;avascript:alert(1)\">x</a>",
        "<a href=\"&#x6a;avascript:alert(1)\">x</a>",
        // data: and vbscript: hrefs.
        "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>",
        "<a href=\"vbscript:msgbox(1)\">x</a>",
        // Control-char / whitespace prefixed scheme evasion (a browser strips the leading
        // C0 control or space before parsing the scheme): a prefixed javascript: must be
        // rejected outright, and a prefixed https URL, while inert, must not read as a
        // non-https href.
        "<a href=\"\u{2}javascript:alert(1)\">x</a>",
        "<a href=\"\tjavascript:alert(1)\">x</a>",
        "<a href=\"  javascript:alert(1)\">x</a>",
        // Scheme split by tabs/newlines (the WHATWG URL parser removes them everywhere): a
        // split javascript:/data: must be rejected, and a split https URL, while inert, must
        // not read as non-https.
        "<a href=\"j\nava\nscript:alert(1)\">x</a>",
        "<a href=\"java\tscript:alert(1)\">x</a>",
        "<a href=\"da\nta:text/html,<b>x</b>\">x</a>",
        "<a href=\"http\ns\n\n:l\">x</a>",
        "<a href=\"\u{2}https://ok.test/\">x</a>",
        // An inert substring inside a quoted href VALUE must not read as a handler: a
        // (safe) https URL whose path/query contains ` onerror=` is not an event handler.
        "<a href=\"https://ok.test/x? onerror=1\">link</a>",
        // Protocol-relative and non-https schemes.
        "<a href=\"//evil.test/x\">x</a>",
        "<a href=\"http://evil.test/x\">x</a>",
        // Style / CSS breakout attempts.
        "<style>@import url(//evil.test/x.css)</style>",
        "<p style=\"background:url(javascript:alert(1))\">x</p>",
        "<div style=\"expression(alert(1))\">x</div>",
        "<b style=\"color:red;} body{display:none\">x</b>",
        // Embedding elements.
        "<iframe src=\"https://evil.test\"></iframe>",
        "<object data=\"https://evil.test\"></object>",
        "<embed src=\"https://evil.test\">",
        // SVG / MathML XSS.
        "<svg onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext><script>alert(1)</script></mtext></math>",
        // Mutation XSS: a real HTML parser is required to neutralize this.
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
        // Nested / malformed / broken nesting.
        "<a href=\"https://ok.test\"><script>alert(1)</a></script>",
        "<b><i><script>alert(1)</b></i>",
        "<<script>alert(1)</script>",
        "<img src=`x` onerror=alert(1)>",
        // Meta / base / link injection.
        "<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
        "<base href=\"javascript:alert(1)//\">",
        "<link rel=stylesheet href=//evil.test/x.css>",
        // Attribute-based handlers and id/class smuggling.
        "<p id=x class=y onfocus=alert(1) tabindex=1>x</p>",
        // Generic-attribute smuggling: `title`/`lang` are NOT in the allowlist and must be
        // stripped, not merely escaped (the fuzzer surfaced that ammonia's `empty()` does
        // not clear its default generic attributes; the config clears them explicitly).
        "<p title=\"</noscript><img src=x onerror=a>\" lang=\"en\">x</p>",
        "<Uoscript><p title=\"</noscript><img src=x onerror=a title=>\">",
    ];

    /// The TREE-RESHAPING corpus: inputs whose FIRST allowlist pass emits markup that a
    /// second parse reshapes, so a single pass is not a fixed point. `BYPASS_CORPUS` cannot
    /// reach this branch (every entry there settles in one pass), which is exactly why the
    /// idempotence test passed while the property was false; the nightly `branding_sanitize`
    /// fuzz target found it instead.
    ///
    /// The mechanism, MEASURED (see the crate CHANGELOG): a non-allowlisted element that
    /// suppresses the implied `</p>` (`select` and `button` both do; `div`, `span`, and
    /// `table` do not) leaves the second `<p>` as a DESCENDANT of the first. Dropping the
    /// non-allowlisted wrapper keeps its children in place, so the first pass emits
    /// `<p>a<p>b</p></p>`. A `<p>` inside a `<p>` is not markup any parser can produce, so
    /// the next parse unfolds it into siblings, and the value moves.
    const TREE_RESHAPING_CORPUS: &[&str] = &[
        // The minimized shapes.
        "<p>a<select><p>b",
        "<p>a<button><p>b",
        "<p>a<select ><p>b",
        // Stacked wrappers, so a deep nest is covered rather than only a single level.
        "<p>a<select><p>b<select><p>c<select><p>d",
        "<p>a<button><p>b<button><p>c<button><p>d<button><p>e<button><p>f",
        "<p><button><p><button><p><button><p><button><p>x",
        // The shape a stacked wrapper reaches after one pass, fed in directly.
        "<p>a<p>b</p></p>",
        // The worst input the randomized sweep found.
        "<</select><<p></select><span></button> <button><svg><li><p>",
    ];

    /// The exact bytes of the nightly fuzzer's crash input, pinned in the fuzz seed corpus
    /// so this case is exercised every run of that target FOREVER, and read from that file
    /// here so the unit test and the seed corpus cannot drift apart (deleting the seed
    /// breaks the build).
    const FUZZER_CRASH_INPUT: &[u8] =
        include_bytes!("../../fuzz/corpus/branding_sanitize/seed_regression_select_nested_p");

    /// Assert a sanitized fragment is INERT, robustly against inert escaped TEXT. In the
    /// output every text `<` is escaped to `&lt;` and every text `"` to `&quot;`, so a
    /// literal `<script` or a real `href="` can only appear inside an ACTUAL tag, never as
    /// text. A fragment is inert when:
    ///
    /// - it emits none of the dangerous ELEMENTS (a `<tag` substring means an actual
    ///   element, since a text `<` would be `&lt;`); and
    /// - inside every `<...>` tag region there is no `on*` event handler and no `style=`
    ///   attribute, and any `href` value is `https` (the only attribute the allowlist
    ///   permits, https-only). Text between tags is deliberately ignored, so an inert
    ///   escaped `onerror=` sitting in text is not a false positive.
    fn assert_inert(payload: &str, out: &str) {
        let lower = out.to_ascii_lowercase();
        for tag in [
            "<script",
            "</script",
            "<style",
            "<svg",
            "<iframe",
            "<object",
            "<embed",
            "<img",
            "<math",
            "<meta",
            "<base",
            "<link",
            "<form",
            "<noscript",
            "<template",
            "<textarea",
            "<foreignobject",
        ] {
            assert!(
                !lower.contains(tag),
                "bypass: payload {payload:?} emitted a dangerous element {tag:?}: {out:?}"
            );
        }
        let mut cursor = 0;
        while let Some(rel) = lower[cursor..].find('<') {
            let start = cursor + rel;
            // ammonia escapes a `>` inside an attribute value to `&gt;`, so the first `>`
            // always ends the tag; the region is a complete `<...>` opening.
            let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
            let region = &lower[start..end];
            assert_tag_region_inert(payload, region, out);
            cursor = end + 1;
            if cursor >= lower.len() {
                break;
            }
        }
    }

    /// Assert one `<...>` tag region carries no `on*` handler and no `style` attribute NAME,
    /// and that any `href` value is https. The check is QUOTE-AWARE: an inert substring
    /// sitting inside a quoted attribute VALUE (a mangled URL containing ` onerror=`, say)
    /// cannot false-positive, because an attribute NAME is always outside quotes.
    fn assert_tag_region_inert(payload: &str, region: &str, out: &str) {
        // The attribute-name skeleton: the region with every double-quoted value removed.
        let mut skeleton = String::with_capacity(region.len());
        let mut in_quote = false;
        for ch in region.chars() {
            if ch == '"' {
                in_quote = !in_quote;
                continue;
            }
            if !in_quote {
                skeleton.push(ch);
            }
        }
        assert!(
            !skeleton.contains(" on"),
            "bypass: payload {payload:?} left an on* handler attribute: {out:?}"
        );
        assert!(
            !skeleton.contains("style="),
            "bypass: payload {payload:?} left a style attribute: {out:?}"
        );
        if let Some(h) = region.find("href=\"") {
            // The href VALUE runs to the next quote. Determine its EFFECTIVE scheme the way
            // the WHATWG URL parser (which ammonia uses) does: remove every ASCII tab and
            // newline from ANYWHERE in the value, then strip the leading C0 control and ASCII
            // whitespace. So a cosmetic control-char prefix or a scheme split by newlines
            // (`http\ns\n:l` -> `https:l`) on an inert https URL is not a false positive,
            // while a genuine non-https scheme (a split `j\nava\nscript:`) still fails.
            // ammonia was verified to REJECT every such scripting/data scheme, dropping the
            // href, so only a real https URL ever survives.
            let raw = region[h + "href=\"".len()..]
                .split('"')
                .next()
                .unwrap_or("");
            let stripped: String = raw
                .chars()
                .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
                .collect();
            let value = stripped
                .trim_start_matches(|c: char| c.is_ascii_control() || c.is_ascii_whitespace());
            assert!(
                value.starts_with("https"),
                "bypass: payload {payload:?} left a non-https href: {out:?}"
            );
        }
    }

    #[test]
    fn the_bypass_corpus_produces_zero_dangerous_output() {
        let crash = String::from_utf8_lossy(FUZZER_CRASH_INPUT);
        for payload in BYPASS_CORPUS
            .iter()
            .chain(TREE_RESHAPING_CORPUS)
            .chain(&[crash.as_ref()])
        {
            let out = sanitize(payload);
            assert_inert(payload, out.as_str());
        }
    }

    #[test]
    fn the_allowlisted_markup_survives_intact() {
        // The genuine 95% need: bold a word, emphasize, and add an https link with a
        // forced rel. All of this survives.
        let out = sanitize(
            "<p>Read the <strong>terms</strong> and <em>privacy</em> \
             <a href=\"https://example.test/legal\">policy</a>.</p>",
        );
        let text = out.as_str();
        assert!(text.contains("<strong>terms</strong>"), "{text}");
        assert!(text.contains("<em>privacy</em>"), "{text}");
        assert!(text.contains("<p>"), "{text}");
        // The link survives with an https href and a forced safe rel.
        assert!(
            text.contains("href=\"https://example.test/legal\""),
            "{text}"
        );
        assert!(
            text.contains("rel=\"noopener noreferrer nofollow\""),
            "{text}"
        );
        assert!(
            !text.contains("target="),
            "no target is ever emitted: {text}"
        );
    }

    #[test]
    fn a_disallowed_tag_keeps_its_text_but_drops_the_tag() {
        // A heading is not allowlisted: the tag is dropped, its text kept (never
        // passed through as a live tag).
        let out = sanitize("<h1>Welcome</h1> to <span class=x>Acme</span>");
        let text = out.as_str();
        assert!(!text.contains("<h1>"), "{text}");
        assert!(!text.contains("<span"), "{text}");
        assert!(text.contains("Welcome"), "{text}");
        assert!(text.contains("Acme"), "{text}");
    }

    #[test]
    fn generic_attributes_are_stripped_not_merely_escaped() {
        // The owner allowlist permits EXACTLY a[href]; a generic attribute like `title` or
        // `lang` (which ammonia allows by default) must be REMOVED, so no attribute other
        // than an https href ever survives on any element.
        let out = sanitize("<p title=\"t\" lang=\"en\" data-x=\"y\">hello</p>");
        let text = out.as_str();
        assert_eq!(
            text, "<p>hello</p>",
            "only the allowlisted tag survives: {text}"
        );
        assert!(!text.contains("title="), "{text}");
        assert!(!text.contains("lang="), "{text}");
    }

    #[test]
    fn a_non_https_link_is_stripped_of_its_href() {
        // The anchor may survive but never with a non-https href.
        let out = sanitize("<a href=\"javascript:alert(1)\">x</a>");
        let lower = out.as_str().to_ascii_lowercase();
        assert!(!lower.contains("javascript:"), "{lower}");
        assert!(
            !lower.contains("href="),
            "the scripting href is dropped: {lower}"
        );
    }

    #[test]
    fn sanitize_is_idempotent() {
        // Sanitizing already-sanitized output is a fixed point, so re-sanitizing on
        // read (defense in depth) never changes a safe value. The corpus MUST include
        // the tree-reshaping inputs: without them the loop below cannot reach the branch
        // it claims to cover, which is how a one-pass sanitizer passed this test for as
        // long as it did.
        let crash = String::from_utf8_lossy(FUZZER_CRASH_INPUT);
        for payload in BYPASS_CORPUS
            .iter()
            .chain(TREE_RESHAPING_CORPUS)
            .chain(&[crash.as_ref()])
            .chain(&["<p>Hello <strong>world</strong> <a href=\"https://ok.test\">link</a></p>"])
        {
            let once = sanitize(payload);
            let twice = sanitize(once.as_str());
            assert_eq!(
                once.as_str(),
                twice.as_str(),
                "sanitize must be idempotent for {payload:?}"
            );
        }
    }

    #[test]
    fn the_nightly_fuzzer_crash_input_is_a_fixed_point() {
        // The exact bytes that made the `branding_sanitize` fuzz target red on main. A
        // single allowlist pass left `<p>` nested inside `<p>`, which the next parse
        // unfolded into siblings, so the value moved on every read.
        let input = String::from_utf8_lossy(FUZZER_CRASH_INPUT);
        let once = sanitize(&input);
        assert_eq!(
            once.as_str(),
            sanitize(once.as_str()).as_str(),
            "the pinned crash input must be a fixed point"
        );
        // The specific shape: the paragraphs are SIBLINGS, never nested, so no further
        // parse can reshape them.
        assert!(
            !once.as_str().contains("<p><p>") && !once.as_str().contains("</p></p>"),
            "no paragraph nests inside another: {}",
            once.as_str()
        );
        assert_inert("the pinned fuzzer crash input", once.as_str());
    }

    #[test]
    fn the_pass_budget_fails_closed_rather_than_returning_an_unstable_value() {
        // The budget's exhausted branch is REACHABLE and TESTED, not a comment. A tree
        // reshaping input needs three passes; give it two and the sanitizer must refuse
        // to hand back the value it could not prove stable.
        let needs_three = "<p>a<select><p>b";
        assert_eq!(
            sanitize_to_fixed_point(needs_three, 2),
            "",
            "a budget too small to prove a fixed point yields the empty fragment"
        );
        // The empty fragment IS a fixed point, so idempotence survives the failure.
        assert_eq!(sanitize_to_fixed_point("", MAX_SANITIZE_PASSES), "");
        // One more pass and the value converges, so the failure above is the budget and
        // not a sanitizer that empties everything.
        assert_eq!(
            sanitize_to_fixed_point(needs_three, 3),
            "<p>a</p><p>b</p><p></p>"
        );
    }

    #[test]
    fn the_measured_worst_case_leaves_headroom_under_the_shipped_budget() {
        // The bound is JUSTIFIED, and the justification is checked rather than asserted
        // in prose: the worst corpus entry converges strictly inside the shipped budget,
        // so a value is never emptied by the fail-closed branch in practice.
        let crash = String::from_utf8_lossy(FUZZER_CRASH_INPUT);
        let mut worst = 0;
        for payload in BYPASS_CORPUS
            .iter()
            .chain(TREE_RESHAPING_CORPUS)
            .chain(&[crash.as_ref()])
        {
            // Count the passes UNBOUNDED: allowlist passes until one changes nothing.
            let mut current = (*payload).to_owned();
            let mut passes = 0;
            loop {
                let next = super::sanitizer().clean(&current).to_string();
                passes += 1;
                assert!(passes < 32, "no fixed point at all for {payload:?}");
                if next == current {
                    break;
                }
                current = next;
            }
            // The SHIPPED budget reaches that same converged value, so the fail-closed
            // branch is never what answers for a corpus entry.
            assert_eq!(
                sanitize(payload).as_str(),
                current,
                "the shipped budget converges rather than failing closed for {payload:?}"
            );
            worst = worst.max(passes);
        }
        assert_eq!(worst, 3, "the measured worst case is three passes");
        assert!(
            MAX_SANITIZE_PASSES >= worst * 2,
            "the shipped budget keeps at least double the measured worst case"
        );
    }

    #[test]
    fn empty_and_plain_text_sanitize_cleanly() {
        assert!(sanitize("").is_empty());
        assert_eq!(sanitize("just plain text").as_str(), "just plain text");
        // Angle brackets in plain text are neutralized by the parser (kept as escaped
        // text, never a live tag).
        let out = sanitize("2 < 3 and 4 > 1");
        assert!(!out.as_str().contains("<3"), "{}", out.as_str());
    }
}
