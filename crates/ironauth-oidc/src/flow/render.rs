// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hosted flow render app (issue #85, PR 1): the in process, server rendered page app
//! that turns a [`Flow`] object into a full themed HTML page over the SAME primitives the
//! bootstrap pages use.
//!
//! Architecture (option B1, the owner ruling): the in process pages stay server rendered
//! Rust. This module is a GENERIC renderer over the flow contract, not journey specific
//! code. It walks `flow.ui.nodes` in their already deterministic order ([`Ui::new`] sort)
//! and dispatches on the typed [`NodeAttributes`] (input vs text), so ANY journey (login,
//! registration, MFA, recovery, federation) and any FUTURE node group renders with no page
//! code change (the forward compatibility acceptance criterion). Every human string is a
//! numeric [`MessageId`](super::message::MessageId); this renderer emits the default English
//! `Message.text`, and issue #86 localizes by id without touching the renderer.
//!
//! Hardening is REUSED verbatim, never re implemented:
//!
//! - every reflected value passes through [`pages::escape_html`] (context correct: element
//!   text AND double quoted attributes), so a hostile message or node value is escaped
//!   (the reflected parameter injection class stays closed by construction);
//! - the response headers (the strict CSP, `X-Frame-Options: DENY`, `Referrer-Policy:
//!   same-origin`, `nosniff`, `no-store`) are attached by [`pages::flow_html`] /
//!   [`pages::flow_login_html`] at the transport call site, exactly as the bootstrap pages
//!   attach them through `secure_html`;
//! - the document shell ([`pages::document_styled`]) gives the `<html lang>`, viewport, the
//!   `data-display` layout hint, the robots noindex, and the issue #42 non production
//!   environment banner FOR FREE;
//! - the passkey conditional-UI ceremony reuses the bootstrap `PASSKEY_SCRIPT` and nonce CSP
//!   ([`pages::passkey_block`] + [`pages::flow_login_csp`]), so a flow login or step up that
//!   presents the passkey node group runs the ceremony IDENTICALLY to the bootstrap login.
//!
//! The theme seam ([`PageTheme`]) is a BOUNDED, server known struct (product wordmark, an
//! optional per environment brand token), escape safe by construction (never operator HTML,
//! the same discipline as `pages.rs`). Issue #85 ships the seam with a neutral default; issue
//! #86 fills safe branding and localization.

use super::message::{self, Message};
use super::model::{Autocomplete, Flow, FlowStateTag, InputType, Node, NodeAttributes, NodeGroup};
use crate::hints::InteractionHints;
use crate::pages;

/// The bounded, server known theme render context (issue #85, the seam issue #86 fills). It
/// carries NO customer supplied HTML: every field is a server known string escaped on render,
/// so branding stays escape safe by construction (the `pages.rs` "no customer supplied HTML
/// anywhere" discipline). The default is neutral.
#[derive(Debug, Clone)]
pub struct PageTheme {
    /// The product name rendered as a plain text wordmark in the page header. A bounded,
    /// server known string, escaped on render; NEVER operator HTML.
    pub product_name: String,
    /// Whether to show the product wordmark header. The neutral default shows it; issue #86
    /// may hide it per environment.
    pub show_wordmark: bool,
    /// An optional per environment brand token (a bounded, server known label, escaped on
    /// render): the seam issue #86 fills with safe branding. NEVER operator HTML.
    pub brand_token: Option<String>,
    /// The per environment sanitized rich-text slots (issue #86). Each slot value is a
    /// [`SanitizedRichText`](crate::branding::SanitizedRichText), which can ONLY be an
    /// allowlist-sanitizer output, so a slot renders safe markup by construction. The
    /// neutral default carries no slots (an unbranded page renders no extra chrome).
    pub slots: crate::branding::BrandSlots,
}

impl Default for PageTheme {
    fn default() -> Self {
        Self {
            product_name: "IronAuth".to_owned(),
            show_wordmark: true,
            brand_token: None,
            slots: crate::branding::BrandSlots::default(),
        }
    }
}

/// A rendered flow page (issue #85): the full HTML document plus, when the passkey
/// conditional-UI ceremony was emitted, the script nonce the caller serves the nonce CSP
/// with. A `None` nonce means the plain flow CSP ([`pages::flow_html`]); a `Some` nonce means
/// the passkey ceremony CSP ([`pages::flow_login_html`]).
pub struct RenderedPage {
    /// The full HTML document.
    pub body: String,
    /// The ceremony script nonce, when a passkey node group was rendered as the ceremony.
    pub passkey_nonce: Option<String>,
}

/// Render a flow object into a full themed page (issue #85). `scope_path` is the
/// `/t/{tenant}/e/{environment}` prefix (server known), used for the served stylesheet href
/// and the ceremony endpoints; `passkey` is the conditional-UI wiring, present only when
/// WebAuthn is enabled for this request. When the flow carries a passkey node group AND that
/// wiring is present, the ceremony is rendered under the nonce CSP; otherwise the page uses
/// the plain flow CSP. The body is escaped at every interpolation via [`pages::escape_html`].
#[must_use]
pub(crate) fn render_flow_page(
    flow: &Flow,
    theme: &PageTheme,
    hints: &InteractionHints,
    environment_banner: Option<&str>,
    scope_path: &str,
    passkey: Option<&pages::PasskeyUi<'_>>,
) -> RenderedPage {
    let has_passkey_group = flow
        .ui
        .nodes
        .iter()
        .any(|node| node.group == NodeGroup::Passkey);
    // The ceremony is emitted only when a passkey node group is present AND the WebAuthn
    // wiring (nonce + scope path + signal gate) is available for this request. When emitted,
    // the passkey nodes are rendered AS the ceremony (the button plus the nonce guarded
    // script), never as raw inputs, so a flow login or step up that presents the passkey
    // group behaves identically to the bootstrap login page.
    let ceremony = passkey.filter(|_| has_passkey_group);

    let title = Message::of(flow_title(flow)).text;

    let mut inner = String::new();
    inner.push_str(&brand_header(theme));
    inner.push_str("<main class=\"page\">");
    inner.push_str("<h1>");
    inner.push_str(&pages::escape_html(&title));
    inner.push_str("</h1>");

    // The login-help rich-text slot (issue #86): rendered at a FIXED position just under
    // the title, from the brand's sanitized slot markup.
    if let Some(slot) = theme.slots.get(crate::branding::SlotId::LoginHelp) {
        push_slot(&mut inner, "data-brand-slot", slot);
    }

    // Flow level messages (errors and info not attached to a single node).
    for message in &flow.ui.messages {
        inner.push_str(&message_block(message));
    }

    inner.push_str("<form method=\"post\" action=\"");
    inner.push_str(&pages::escape_html(&flow.ui.action));
    inner.push_str("\">");
    for node in &flow.ui.nodes {
        // When the ceremony renders the passkey group, skip its raw nodes here; they are the
        // ceremony (below), driven by the nonce guarded script, not plain form inputs.
        if ceremony.is_some() && node.group == NodeGroup::Passkey {
            continue;
        }
        render_node(&mut inner, node);
    }
    inner.push_str("</form>");

    // The passkey conditional-UI ceremony: the SAME button plus nonce guarded PASSKEY_SCRIPT
    // the bootstrap login page emits, served under the SAME nonce CSP. Kept CSP clean (no
    // unsafe-inline); the nonce the caller serves matches the one script here.
    let passkey_nonce = match ceremony {
        Some(ui) => {
            inner.push_str(&pages::passkey_block(ui));
            Some(ui.nonce.to_owned())
        }
        None => None,
    };
    // The legal/consent footer rich-text slot (issue #86): rendered at a FIXED position at
    // the bottom of the page, from the brand's sanitized slot markup.
    if let Some(slot) = theme.slots.get(crate::branding::SlotId::FooterLegal) {
        push_slot(&mut inner, "data-brand-footer", slot);
    }
    inner.push_str("</main>");

    let stylesheet_href = format!("{scope_path}/pages.css");
    let body = pages::document_styled(
        &pages::escape_html(&title),
        &inner,
        hints.lang(),
        hints.display().as_str(),
        environment_banner,
        Some(&stylesheet_href),
    );
    RenderedPage {
        body,
        passkey_nonce,
    }
}

/// The bounded theme wordmark header (issue #85): the product name plus an optional brand
/// token, each escaped on render. Empty when the theme hides the wordmark and carries no
/// token, so a neutral render adds no chrome.
fn brand_header(theme: &PageTheme) -> String {
    let mut out = String::new();
    let wordmark = theme.show_wordmark && !theme.product_name.is_empty();
    if !wordmark && theme.brand_token.is_none() {
        return out;
    }
    out.push_str("<header data-brand>");
    if wordmark {
        out.push_str("<span data-product-name>");
        out.push_str(&pages::escape_html(&theme.product_name));
        out.push_str("</span>");
    }
    if let Some(token) = &theme.brand_token {
        out.push_str("<span data-brand-token>");
        out.push_str(&pages::escape_html(token));
        out.push_str("</span>");
    }
    out.push_str("</header>");
    out
}

/// Emit a branding rich-text slot at a fixed, server-authored position (issue #86).
///
/// This is the ONE place the flow render app emits PRE-SANITIZED HTML verbatim rather than
/// [`pages::escape_html`] escaped text. It is safe because the value is a
/// [`SanitizedRichText`](crate::branding::SanitizedRichText), whose ONLY constructor is the
/// ammonia allowlist sanitizer: the inner string is guaranteed to contain only the
/// allowlisted tags (`b i strong em u p br a`), an `https` `href` with a forced `rel`, and
/// NO script, `on*` handler, `style`, or non-https scheme. The wrapping element and its
/// `data-*` hook are fixed server-authored tokens. Every OTHER value on the page stays
/// escaped; only a sanitized slot is emitted raw.
fn push_slot(out: &mut String, hook: &str, slot: &crate::branding::SanitizedRichText) {
    out.push_str("<div ");
    out.push_str(hook);
    out.push('>');
    // SAFETY (XSS): `slot` is allowlist-sanitized markup (see the function doc); emitting it
    // verbatim is the intended, documented single raw-HTML path.
    out.push_str(slot.as_str());
    out.push_str("</div>");
}

/// Render a flow level or node level message as a styled block (issue #85), keyed on its kind
/// so an error is distinguishable from an info or success note WITHOUT the copy. The text is
/// escaped; the kind selects a fixed, server known role or class.
fn message_block(message: &Message) -> String {
    match message.kind {
        message::MessageKind::Error => {
            format!(
                "<p role=\"alert\">{}</p>",
                pages::escape_html(&message.text)
            )
        }
        message::MessageKind::Success => {
            format!(
                "<p role=\"status\" class=\"success\">{}</p>",
                pages::escape_html(&message.text)
            )
        }
        message::MessageKind::Info => {
            format!(
                "<p class=\"message\">{}</p>",
                pages::escape_html(&message.text)
            )
        }
    }
}

/// The page title message id for a flow's state (issue #84/#85), so the render heads the
/// right page. The title is a registered message, localized like every other by its id.
fn flow_title(flow: &Flow) -> message::MessageId {
    match flow.state {
        FlowStateTag::RegistrationDetails | FlowStateTag::RegistrationAck => {
            message::REGISTER_TITLE
        }
        FlowStateTag::MfaChallenge => message::MFA_CHALLENGE_TITLE,
        FlowStateTag::MfaEnroll => message::MFA_ENROLL_TITLE,
        FlowStateTag::RecoveryStart | FlowStateTag::RecoveryAck => message::RECOVERY_TITLE,
        FlowStateTag::FederationStart => message::FEDERATION_TITLE,
        FlowStateTag::IdentifierPassword | FlowStateTag::Completed => message::LOGIN_TITLE,
    }
}

/// Render one node into the page body (issue #85, the generic node renderer). Dispatches on
/// the typed [`NodeAttributes`], so a node of ANY group (including a group unknown to this
/// code) renders via the same input or text path. Every interpolated value is escaped.
fn render_node(body: &mut String, node: &Node) {
    match &node.attributes {
        NodeAttributes::Input {
            name,
            input_type,
            value,
            required,
            autocomplete,
            disabled,
        } => {
            let labelled = node.label.is_some()
                && !matches!(input_type, InputType::Hidden | InputType::Submit);
            if labelled {
                if let Some(label) = &node.label {
                    body.push_str("<label>");
                    body.push_str(&pages::escape_html(&label.text));
                    body.push(' ');
                }
            }
            // Attribute order is deliberate: `type` then `name` then `value` are kept
            // ADJACENT (no attribute between `name` and `value`) so the hidden flow field
            // renders as `name="flow" value="..."`, the shape the cross transport equivalence
            // suites read the flow id back from.
            body.push_str("<input type=\"");
            body.push_str(input_type_attr(*input_type));
            body.push_str("\" name=\"");
            body.push_str(&pages::escape_html(name));
            body.push('"');
            if let Some(value) = value {
                body.push_str(" value=\"");
                body.push_str(&pages::escape_html(value));
                body.push('"');
            }
            if let Some(hint) = autocomplete {
                body.push_str(" autocomplete=\"");
                body.push_str(autocomplete_attr(*hint));
                body.push('"');
            }
            if *required {
                body.push_str(" required");
            }
            if *disabled {
                body.push_str(" disabled");
            }
            body.push('>');
            if labelled {
                body.push_str("</label>");
            }
            for message in &node.messages {
                body.push_str("<span class=\"error\">");
                body.push_str(&pages::escape_html(&message.text));
                body.push_str("</span>");
            }
        }
        NodeAttributes::Text { message } => {
            body.push_str("<p>");
            body.push_str(&pages::escape_html(&message.text));
            body.push_str("</p>");
        }
    }
}

/// The HTML `type` attribute for a typed input (issue #85). A fixed, server known token, so
/// there is nothing to escape.
fn input_type_attr(input_type: InputType) -> &'static str {
    match input_type {
        InputType::Text => "text",
        InputType::Password => "password",
        InputType::Email => "email",
        InputType::Tel => "tel",
        InputType::Hidden => "hidden",
        InputType::Checkbox => "checkbox",
        InputType::Submit => "submit",
    }
}

/// The HTML `autocomplete` token for a typed hint (issue #85). A fixed, server known token
/// (the kebab case wire value the contract already publishes), so there is nothing to escape.
fn autocomplete_attr(hint: Autocomplete) -> &'static str {
    match hint {
        Autocomplete::Username => "username",
        Autocomplete::CurrentPassword => "current-password",
        Autocomplete::NewPassword => "new-password",
        Autocomplete::OneTimeCode => "one-time-code",
        Autocomplete::Webauthn => "webauthn",
    }
}

#[cfg(test)]
mod tests {
    use super::{PageTheme, render_flow_page};
    use crate::flow::message::{Message, MessageContext, MessageId, MessageKind};
    use crate::flow::model::{
        Autocomplete, CONTRACT_VERSION, Flow, FlowStateTag, InputType, Journey, Node,
        NodeAttributes, NodeGroup, Transport, Ui,
    };
    use crate::hints::InteractionHints;
    use crate::pages;

    const SCOPE_PATH: &str = "/t/tnt/e/env";

    /// A hostile string that must never survive unescaped into the HTML.
    const HOSTILE: &str = "<script>alert('xss')</script>";

    fn flow_with(
        state: FlowStateTag,
        journey: Journey,
        nodes: Vec<Node>,
        messages: Vec<Message>,
    ) -> Flow {
        Flow {
            contract_version: CONTRACT_VERSION,
            id: "flw_test0000000000000000000000".to_owned(),
            journey,
            state,
            transport: Transport::Browser,
            expires_at: 900,
            request_url: None,
            ui: Ui::new(
                format!("{SCOPE_PATH}/flow/{}", journey.as_str()),
                "POST".to_owned(),
                nodes,
                messages,
            ),
        }
    }

    fn input(group: NodeGroup, seq: u16, name: &str, ty: InputType, value: Option<&str>) -> Node {
        Node::input(
            group,
            seq,
            NodeAttributes::Input {
                name: name.to_owned(),
                input_type: ty,
                value: value.map(str::to_owned),
                required: false,
                autocomplete: None,
                disabled: false,
            },
            None,
        )
    }

    fn error_message(text: &str) -> Message {
        Message {
            id: MessageId(4_100_001),
            kind: MessageKind::Error,
            text: text.to_owned(),
            context: MessageContext::empty(),
        }
    }

    fn render_default(flow: &Flow) -> super::RenderedPage {
        render_flow_page(
            flow,
            &PageTheme::default(),
            &InteractionHints::default(),
            None,
            SCOPE_PATH,
            None,
        )
    }

    #[test]
    fn a_full_document_is_rendered_with_the_served_stylesheet_and_no_passkey_by_default() {
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![input(
                NodeGroup::Default,
                0,
                "identifier",
                InputType::Text,
                None,
            )],
            Vec::new(),
        );
        let page = render_default(&flow);
        assert!(page.body.starts_with("<!doctype html>"), "{}", page.body);
        assert!(
            page.body.contains("<form method=\"post\""),
            "a form renders"
        );
        // The ONE served same origin stylesheet is linked, no external host.
        assert!(
            page.body
                .contains("<link rel=\"stylesheet\" href=\"/t/tnt/e/env/pages.css\">"),
            "the served stylesheet is linked: {}",
            page.body
        );
        assert!(
            !page.body.contains("http://"),
            "no external host in the page"
        );
        assert!(
            !page.body.to_lowercase().contains("https://"),
            "no external host in the page"
        );
        // No passkey ceremony without a passkey node group.
        assert!(
            page.passkey_nonce.is_none(),
            "no passkey ceremony by default"
        );
        assert!(
            !page.body.contains("<script"),
            "no script without a passkey node"
        );
    }

    #[test]
    fn every_journey_state_renders_a_titled_page() {
        // The generic renderer heads every journey and state, so pages render for each state.
        for (state, journey) in [
            (FlowStateTag::IdentifierPassword, Journey::Login),
            (FlowStateTag::RegistrationDetails, Journey::Registration),
            (FlowStateTag::RegistrationAck, Journey::Registration),
            (FlowStateTag::MfaChallenge, Journey::Login),
            (FlowStateTag::MfaEnroll, Journey::Login),
            (FlowStateTag::RecoveryStart, Journey::Recovery),
            (FlowStateTag::RecoveryAck, Journey::Recovery),
            (FlowStateTag::FederationStart, Journey::Federation),
        ] {
            let flow = flow_with(
                state,
                journey,
                vec![input(
                    NodeGroup::Default,
                    0,
                    "identifier",
                    InputType::Text,
                    None,
                )],
                Vec::new(),
            );
            let page = render_default(&flow);
            assert!(page.body.contains("<h1>"), "{state:?} heads a page");
            assert!(
                page.body.contains("<main"),
                "{state:?} renders the main region"
            );
        }
    }

    #[test]
    fn a_hostile_node_value_and_message_are_escaped() {
        // A reflected node value and an attached node message carrying HTML/script are escaped
        // (the reflected-parameter injection class stays closed).
        let mut node = input(
            NodeGroup::Default,
            0,
            "identifier",
            InputType::Text,
            Some(HOSTILE),
        );
        node.messages.push(error_message(HOSTILE));
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![node],
            vec![error_message(HOSTILE)],
        );
        let page = render_default(&flow);
        assert!(
            !page.body.contains("<script>alert"),
            "the hostile markup is never emitted raw: {}",
            page.body
        );
        assert!(
            page.body.contains("&lt;script&gt;"),
            "the hostile markup is escaped: {}",
            page.body
        );
    }

    #[test]
    fn a_hostile_action_and_id_are_escaped() {
        let mut flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![input(
                NodeGroup::Default,
                0,
                "identifier",
                InputType::Text,
                None,
            )],
            Vec::new(),
        );
        flow.ui.action = format!("/x\"{HOSTILE}");
        let page = render_default(&flow);
        assert!(
            !page.body.contains("\"><script>"),
            "action cannot break out: {}",
            page.body
        );
        assert!(page.body.contains("&lt;script&gt;"), "action is escaped");
    }

    #[test]
    fn an_unknown_node_group_renders_via_the_generic_renderer() {
        // A node whose group the page code does NOT special-case (here EmailOtp, no dedicated
        // rendering) still renders its typed input via the generic attribute path. This is the
        // forward-compatibility acceptance criterion: a new auth method renders with no page
        // code change.
        let flow = flow_with(
            FlowStateTag::MfaChallenge,
            Journey::Login,
            vec![input(
                NodeGroup::EmailOtp,
                0,
                "novel_field",
                InputType::Text,
                None,
            )],
            Vec::new(),
        );
        let page = render_default(&flow);
        assert!(
            page.body.contains("name=\"novel_field\""),
            "the unknown-group node renders generically: {}",
            page.body
        );
    }

    #[test]
    fn the_hidden_flow_field_keeps_the_name_value_adjacency() {
        // The cross-transport equivalence suites read the flow id back from `name="flow"
        // value="..."`; the generic renderer must keep `name` and `value` adjacent.
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![input(
                NodeGroup::Default,
                5,
                "flow",
                InputType::Hidden,
                Some("flw_abc"),
            )],
            Vec::new(),
        );
        let page = render_default(&flow);
        assert!(
            page.body.contains("name=\"flow\" value=\"flw_abc\""),
            "hidden flow field adjacency preserved: {}",
            page.body
        );
    }

    #[test]
    fn a_passkey_node_group_renders_the_nonce_guarded_ceremony_under_the_nonce_csp() {
        // The §4 cutover gap: a flow login/step-up presenting the passkey node group emits the
        // SAME nonce-guarded conditional-UI ceremony the bootstrap login page does, under the
        // nonce CSP (no unsafe-inline; the nonce matches the CSP).
        let nonce = "0123456789abcdef0123456789abcdef";
        let ui = pages::PasskeyUi {
            nonce,
            scope_path: SCOPE_PATH,
            signal_api: false,
        };
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![
                input(NodeGroup::Default, 0, "identifier", InputType::Text, None),
                input(NodeGroup::Passkey, 0, "passkey", InputType::Submit, None),
            ],
            Vec::new(),
        );
        let page = render_flow_page(
            &flow,
            &PageTheme::default(),
            &InteractionHints::default(),
            None,
            SCOPE_PATH,
            Some(&ui),
        );
        assert_eq!(
            page.passkey_nonce.as_deref(),
            Some(nonce),
            "the ceremony reports its nonce so the caller serves the nonce CSP"
        );
        assert!(
            page.body.contains(&format!("<script nonce=\"{nonce}\">")),
            "the ceremony script carries the nonce: {}",
            page.body
        );
        assert!(
            page.body.contains("passkey-btn"),
            "the passkey button renders"
        );
        // The CSP the caller serves pins exactly this nonce and carries NO unsafe-inline.
        let csp = pages::flow_login_csp(nonce);
        assert!(
            csp.contains(&format!("script-src 'nonce-{nonce}'")),
            "{csp}"
        );
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        assert!(csp.contains("style-src 'self'"), "{csp}");
        assert!(!csp.contains("unsafe-inline"), "{csp}");
    }

    #[test]
    fn no_passkey_ceremony_without_the_webauthn_wiring() {
        // A passkey node group but NO wiring (WebAuthn disabled): no ceremony, plain flow CSP.
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![input(
                NodeGroup::Passkey,
                0,
                "passkey",
                InputType::Submit,
                None,
            )],
            Vec::new(),
        );
        let page = render_default(&flow);
        assert!(page.passkey_nonce.is_none(), "no nonce without wiring");
        assert!(
            !page.body.contains("<script"),
            "no ceremony script without wiring"
        );
    }

    #[test]
    fn a_non_default_theme_escapes_the_brand_token() {
        // The theme seam is a bounded server-known struct; a brand token carrying HTML is
        // escaped by construction (never operator HTML).
        let theme = PageTheme {
            product_name: "Acme Login".to_owned(),
            show_wordmark: true,
            brand_token: Some(HOSTILE.to_owned()),
            slots: crate::branding::BrandSlots::default(),
        };
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![input(
                NodeGroup::Default,
                0,
                "identifier",
                InputType::Text,
                None,
            )],
            Vec::new(),
        );
        let page = render_flow_page(
            &flow,
            &theme,
            &InteractionHints::default(),
            None,
            SCOPE_PATH,
            None,
        );
        assert!(
            page.body.contains("Acme Login"),
            "the product wordmark renders"
        );
        assert!(
            !page.body.contains("<script>alert"),
            "the brand token is never emitted raw: {}",
            page.body
        );
        assert!(
            page.body.contains("&lt;script&gt;"),
            "the brand token is escaped"
        );
    }

    #[test]
    fn branding_slots_render_sanitized_markup_at_fixed_positions() {
        // Issue #86: a brand's rich-text slots render as pre-sanitized markup at fixed
        // positions. A slot carrying a stored-XSS payload is inert (it was sanitized at
        // ingest AND is re-sanitized on the way into the theme), while the allowlisted
        // markup survives.
        use crate::branding::{BrandSlots, SlotId};
        let slots = BrandSlots::from_raw([
            (
                SlotId::LoginHelp,
                "<p>Trouble? <a href=\"https://acme.test/help\">Get help</a><script>alert(1)</script></p>"
                    .to_owned(),
            ),
            (
                SlotId::FooterLegal,
                "<img src=x onerror=alert(1)><strong>Legal</strong>".to_owned(),
            ),
        ]);
        let theme = PageTheme {
            product_name: "Acme".to_owned(),
            show_wordmark: true,
            brand_token: None,
            slots,
        };
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![input(
                NodeGroup::Default,
                0,
                "identifier",
                InputType::Text,
                None,
            )],
            Vec::new(),
        );
        let page = render_flow_page(
            &flow,
            &theme,
            &InteractionHints::default(),
            None,
            SCOPE_PATH,
            None,
        );
        // The allowlisted markup survives verbatim.
        assert!(
            page.body.contains("<strong>Legal</strong>"),
            "the sanitized footer markup renders: {}",
            page.body
        );
        assert!(
            page.body.contains("href=\"https://acme.test/help\""),
            "the sanitized https link renders: {}",
            page.body
        );
        // The slots sit at their fixed hooks.
        assert!(page.body.contains("<div data-brand-slot>"), "{}", page.body);
        assert!(
            page.body.contains("<div data-brand-footer>"),
            "{}",
            page.body
        );
        // Zero dangerous output survived either slot.
        let lower = page.body.to_ascii_lowercase();
        assert!(!lower.contains("<script"), "no script survives: {lower}");
        assert!(!lower.contains("onerror"), "no handler survives: {lower}");
        assert!(!lower.contains("<img"), "no img survives: {lower}");
    }

    #[test]
    fn a_neutral_theme_renders_no_branding_slots() {
        // The neutral default carries no slots, so an unbranded page adds no slot chrome.
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![input(
                NodeGroup::Default,
                0,
                "identifier",
                InputType::Text,
                None,
            )],
            Vec::new(),
        );
        let page = render_default(&flow);
        assert!(!page.body.contains("data-brand-slot"), "{}", page.body);
        assert!(!page.body.contains("data-brand-footer"), "{}", page.body);
    }

    #[test]
    fn autocomplete_and_input_types_render() {
        let flow = flow_with(
            FlowStateTag::IdentifierPassword,
            Journey::Login,
            vec![Node::input(
                NodeGroup::Default,
                0,
                NodeAttributes::Input {
                    name: "identifier".to_owned(),
                    input_type: InputType::Email,
                    value: None,
                    required: true,
                    autocomplete: Some(Autocomplete::Username),
                    disabled: false,
                },
                Some(error_message("Identifier")),
            )],
            Vec::new(),
        );
        let page = render_default(&flow);
        assert!(
            page.body.contains("type=\"email\""),
            "the typed input renders"
        );
        assert!(
            page.body.contains("autocomplete=\"username\""),
            "the autocomplete hint renders"
        );
        assert!(page.body.contains(" required"), "required renders");
    }
}
