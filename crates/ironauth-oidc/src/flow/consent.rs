// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consent as flow contract nodes (issue #88, PR 1): the consent screen the bootstrap
//! `/consent` page hand-rolled, rendered instead as the ONE typed flow object both transports
//! render.
//!
//! This is a RENDER move only: the consent DECISION ENGINE (when consent is required) lives
//! UNCHANGED in [`crate::authorize::resolve_consent_gate`]; this module owns only the
//! rendering of "consent is required" and the recording of the resulting decision. The gate,
//! having decided consent is required, launches this journey (behind the same hosted-pages
//! cutover the login and registration journeys use) instead of redirecting to the bootstrap
//! `/consent` page.
//!
//! ## Server authoritative decision
//!
//! The requesting client and the requested scopes come from the flow's PERSISTED authorize
//! context (the `return_to` resume URL, validated at flow creation and re-validated here),
//! never from arbitrary submitted fields. The decision is read from the dedicated `decision`
//! action node ONLY, so an injected `scope`/`client`/`decision`-shaped field can change
//! neither the granted scope nor the decision target.
//!
//! ## Allow and deny
//!
//! On ALLOW, the grant is recorded for the AUTHENTICATED subject (from the session cookie)
//! through the EXISTING [`ActingConsentRepo::grant_with_expiry`](ironauth_store::ActingConsentRepo::grant_with_expiry)
//! with the SAME remembered TTL and audit the bootstrap page uses (reused verbatim through
//! [`crate::consent::remembered_expiry`]), then the browser resumes the `return_to` so
//! `/authorize` issues the code. On DENY, NO grant is recorded and the browser is routed BACK
//! through `/authorize` carrying the internal `consent_denied` marker, so the authorize
//! endpoint's own negotiated response-mode error path returns `access_denied` to the client's
//! `redirect_uri` (RFC 6749), with no partial grant and no response-mode logic duplicated
//! here.

use serde_json::Value;

use ironauth_store::{CorrelationId, FlowRecord, Scope};

use super::message::{self, Message, MessageContext};
use super::model::{InputType, Node, NodeAttributes, NodeGroup, Transport};
use super::{FlowError, Submission};
use crate::interaction;
use crate::state::OidcState;

/// The requesting client's identity as the consent screen renders it (issue #88): the display
/// name, the optional registered logo, and whether the client has been verified. Assembled from
/// the [`ClientRecord`](ironauth_store::ClientRecord) at render time; a pure value so the golden
/// corpus builds the SAME nodes with a fixed fixture and no store.
pub(super) struct ConsentClient {
    /// The client's human-facing display name.
    pub(super) display_name: String,
    /// The client's registered logo URI, or [`None`] when it registered none.
    pub(super) logo_uri: Option<String>,
    /// Whether the client has been verified by an administrator (its `verified_at` is set).
    pub(super) verified: bool,
}

/// The outcome of one consent transition (issue #88): a resolved redirect target. The decision
/// is already applied (an allow recorded the grant; a deny recorded nothing), so the driver
/// consumes the single-use flow and redirects the browser (or hands the native client the
/// redirect affordance).
pub(super) enum ConsentStep {
    /// The subject allowed the request: the grant is recorded; resume `redirect_to` (the
    /// `/authorize` resume) so the code is issued.
    Allow {
        /// The `/authorize` resume URL to redirect to.
        redirect_to: String,
    },
    /// The subject denied the request: no grant recorded; `redirect_to` routes back through
    /// `/authorize` with the internal deny marker so `access_denied` is returned to the client.
    Deny {
        /// The `/authorize` deny URL to redirect to.
        redirect_to: String,
    },
}

/// The consent node set (issue #88): the client-identity nodes (name, optional logo, and the
/// verification badge), the requested-scope descriptions, and the allow/deny action controls,
/// plus the browser-only hidden `flow` node. PURE: it takes the already-resolved client and
/// scope set, so the live engine and the golden corpus build byte-identical nodes.
///
/// PR 1 renders the FULL requested scope set; scope-diff (rendering only the requested scopes
/// not already granted) is deferred to PR 2.
#[must_use]
pub(super) fn consent_nodes(
    transport: Transport,
    flow_id: &str,
    client: &ConsentClient,
    scopes: &[String],
) -> Vec<Node> {
    let mut nodes = Vec::new();
    // The client identity: the display name and optional logo ride the message context (never
    // the copy string), so a locale bundle keys on the id while the numeric registry stays
    // finite. The verification badge is a distinct message id per state.
    let mut identity_context = std::collections::BTreeMap::new();
    identity_context.insert("client_name".to_owned(), client.display_name.clone());
    if let Some(logo) = &client.logo_uri {
        identity_context.insert("logo_uri".to_owned(), logo.clone());
    }
    nodes.push(text_node(
        NodeGroup::ClientIdentity,
        0,
        Message::with_context(
            message::CONSENT_CLIENT_NAME,
            MessageContext(identity_context),
        ),
    ));
    let badge = if client.verified {
        message::CONSENT_CLIENT_VERIFIED
    } else {
        message::CONSENT_CLIENT_UNVERIFIED
    };
    nodes.push(text_node(NodeGroup::ClientIdentity, 1, Message::of(badge)));

    // The requested scopes: an intro then one description node per scope. A well known scope
    // resolves to its stable description id; an unregistered/custom scope resolves to the ONE
    // generic id carrying the raw token in the context (the issue #87 one-id pattern).
    if !scopes.is_empty() {
        nodes.push(text_node(
            NodeGroup::Scope,
            0,
            Message::of(message::CONSENT_SCOPES_INTRO),
        ));
        for (index, token) in scopes.iter().enumerate() {
            // The intro occupies sequence 0, so the per-scope nodes start at 1 and keep the
            // requested order deterministically.
            let sequence = u16::try_from(index + 1).unwrap_or(u16::MAX);
            nodes.push(text_node(NodeGroup::Scope, sequence, scope_message(token)));
        }
    }

    // The allow and deny action controls: ONE node name (`decision`) with two values, so the
    // clicked button's value is the decision the engine reads server authoritatively. Named
    // `decision` (not the generic `method`) so it reaches the engine as a node value on both
    // transports.
    nodes.push(Node::input(
        NodeGroup::Submit,
        0,
        NodeAttributes::Input {
            name: "decision".to_owned(),
            input_type: InputType::Submit,
            value: Some("allow".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::CONSENT_ALLOW_LABEL)),
    ));
    nodes.push(Node::input(
        NodeGroup::Submit,
        1,
        NodeAttributes::Input {
            name: "decision".to_owned(),
            input_type: InputType::Submit,
            value: Some("deny".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::CONSENT_DENY_LABEL)),
    ));

    if matches!(transport, Transport::Browser) {
        nodes.push(Node::input(
            NodeGroup::Default,
            5,
            NodeAttributes::Input {
                name: "flow".to_owned(),
                input_type: InputType::Hidden,
                value: Some(flow_id.to_owned()),
                required: true,
                autocomplete: None,
                disabled: false,
                constraints: None,
            },
            None,
        ));
    }
    nodes
}

/// A block-of-copy node carrying `message` in `group` at `sequence` (issue #88).
fn text_node(group: NodeGroup, sequence: u16, message: Message) -> Node {
    Node {
        group,
        attributes: NodeAttributes::Text { message },
        label: None,
        messages: Vec::new(),
        sequence,
    }
}

/// The scope description message for one requested scope token (issue #88): a stable id per
/// well known scope, or the generic id carrying the raw token in the `scope` context for any
/// unregistered/custom scope (mirrors the issue #87 signup field one-id pattern).
fn scope_message(token: &str) -> Message {
    match token {
        "openid" => Message::of(message::CONSENT_SCOPE_OPENID),
        "profile" => Message::of(message::CONSENT_SCOPE_PROFILE),
        "email" => Message::of(message::CONSENT_SCOPE_EMAIL),
        "offline_access" => Message::of(message::CONSENT_SCOPE_OFFLINE_ACCESS),
        "address" => Message::of(message::CONSENT_SCOPE_ADDRESS),
        "phone" => Message::of(message::CONSENT_SCOPE_PHONE),
        "admin" => Message::of(message::CONSENT_SCOPE_ADMIN),
        "management" => Message::of(message::CONSENT_SCOPE_MANAGEMENT),
        other => Message::with_context(
            message::CONSENT_SCOPE_GENERIC,
            MessageContext::one("scope", other),
        ),
    }
}

/// Build the consent start nodes for the driver's transition INTO the consent prompt (issue
/// #88): parse the requesting client and requested scopes from the flow's PERSISTED authorize
/// context (`return_to`), read the client record for its identity, and render the pure node set.
/// Returns an EMPTY node set on any absence (no resume, cross-scope, or an unreadable client),
/// so a consent flow with no resolvable context renders nothing rather than faulting; the
/// decision path re-derives the context server authoritatively.
pub(super) async fn consent_start_nodes(
    state: &OidcState,
    scope: Scope,
    transport: Transport,
    flow_id: &str,
    return_to: Option<&str>,
) -> Vec<Node> {
    let Some(resume) = interaction::parse_resume(return_to) else {
        return Vec::new();
    };
    if resume.scope != scope {
        return Vec::new();
    }
    let Ok(record) = state
        .store()
        .scoped(scope)
        .clients()
        .get(&resume.client_id)
        .await
    else {
        return Vec::new();
    };
    let client = ConsentClient {
        display_name: record.display_name,
        logo_uri: record.logo_uri,
        verified: record.verified_at_unix_micros.is_some(),
    };
    let scopes = requested_scopes(resume.oauth_scope.as_deref());
    consent_nodes(transport, flow_id, &client, &scopes)
}

/// The requested OAuth scope tokens from the resume's `scope` value, in request order (issue
/// #88). An absent or empty scope yields an empty list.
fn requested_scopes(oauth_scope: Option<&str>) -> Vec<String> {
    oauth_scope
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Advance the consent prompt one transition (issue #88): re-derive the client and scopes from
/// the PERSISTED authorize context (never the submission), read the decision from the dedicated
/// `decision` action node, and either record the grant and resume, or record nothing and route
/// to `access_denied`.
///
/// # Errors
///
/// [`FlowError::NotFound`] when the flow's resume context is missing, cross-scope, or (on an
/// allow) the session no longer resolves; [`FlowError::Store`] on a genuine persistence fault.
pub(super) async fn advance_consent(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
) -> Result<ConsentStep, FlowError> {
    // The client and scopes are SERVER AUTHORITATIVE: they come from the flow's persisted
    // `return_to` (validated at creation), re-validated here, never from the submission.
    let return_to = record.return_to.as_deref().ok_or(FlowError::NotFound)?;
    let resume = interaction::parse_resume(Some(return_to)).ok_or(FlowError::NotFound)?;
    if resume.scope != scope {
        return Err(FlowError::NotFound);
    }
    // The decision is read ONLY from the dedicated action node, so an injected arbitrary field
    // cannot change it (and the granted scope comes from `resume`, not the submission).
    let allow = submission
        .node_values
        .get("decision")
        .and_then(Value::as_str)
        == Some("allow");
    if !allow {
        // Deny: record nothing; route back through `/authorize` with the internal deny marker so
        // the authorize endpoint returns `access_denied` through the negotiated response mode.
        return Ok(ConsentStep::Deny {
            redirect_to: deny_redirect(return_to),
        });
    }
    // Allow: record the grant for the AUTHENTICATED subject (from the session cookie), never a
    // submitted value. A lapsed session fails closed (the flow is not consumed by this branch,
    // so the driver returns a uniform not found rather than granting for an unknown subject).
    let session = interaction::resolve_session(state, scope, headers)
        .await
        .ok_or(FlowError::NotFound)?;
    let actor = interaction::subject_actor(state, scope, &session.subject);
    let client_id = resume.client_id.to_string();
    // Reuse the bootstrap page's remembered-consent TTL verbatim: a `remembered`-mode client's
    // consent lapses after the configured TTL; an `explicit`/`implicit` one never expires.
    let expires_at = crate::consent::remembered_expiry(state, scope, &resume.client_id).await;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .consents()
        .grant_with_expiry(
            state.env(),
            &session.subject,
            &client_id,
            resume.oauth_scope.as_deref(),
            expires_at,
        )
        .await
        .map_err(|_| FlowError::Store)?;
    Ok(ConsentStep::Allow {
        redirect_to: return_to.to_owned(),
    })
}

/// The deny redirect target (issue #88): the `/authorize` resume URL carrying the internal
/// `consent_denied` marker, so the authorize endpoint returns `access_denied` through the
/// negotiated response mode. The resume URL always begins `/authorize?`, so the marker is
/// appended with `&`.
fn deny_redirect(return_to: &str) -> String {
    format!("{return_to}&consent_denied=1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> ConsentClient {
        ConsentClient {
            display_name: "Acme".to_owned(),
            logo_uri: Some("https://acme.example.test/logo.png".to_owned()),
            verified: false,
        }
    }

    fn node_names(nodes: &[Node]) -> Vec<String> {
        nodes
            .iter()
            .map(|node| match &node.attributes {
                NodeAttributes::Input { name, .. } => name.clone(),
                NodeAttributes::Text { message } => format!("text:{}", message.id.0),
            })
            .collect()
    }

    #[test]
    fn consent_nodes_render_identity_scopes_and_allow_deny() {
        let scopes = vec!["openid".to_owned(), "profile".to_owned()];
        // The browser transport renders the client-identity node, the verification badge, the
        // scope intro plus one node per requested scope, the allow and deny controls, and the
        // hidden flow node.
        let browser = consent_nodes(Transport::Browser, "flw_x", &client(), &scopes);
        assert_eq!(
            node_names(&browser),
            vec![
                format!("text:{}", message::CONSENT_CLIENT_NAME.0),
                format!("text:{}", message::CONSENT_CLIENT_UNVERIFIED.0),
                format!("text:{}", message::CONSENT_SCOPES_INTRO.0),
                format!("text:{}", message::CONSENT_SCOPE_OPENID.0),
                format!("text:{}", message::CONSENT_SCOPE_PROFILE.0),
                "decision".to_owned(),
                "decision".to_owned(),
                "flow".to_owned(),
            ]
        );
        // The API transport renders the SAME set minus the browser-only hidden flow node.
        let api = consent_nodes(Transport::Api, "flw_x", &client(), &scopes);
        assert_eq!(
            node_names(&api),
            vec![
                format!("text:{}", message::CONSENT_CLIENT_NAME.0),
                format!("text:{}", message::CONSENT_CLIENT_UNVERIFIED.0),
                format!("text:{}", message::CONSENT_SCOPES_INTRO.0),
                format!("text:{}", message::CONSENT_SCOPE_OPENID.0),
                format!("text:{}", message::CONSENT_SCOPE_PROFILE.0),
                "decision".to_owned(),
                "decision".to_owned(),
            ]
        );
    }

    #[test]
    fn one_scope_node_per_requested_scope_and_custom_scopes_use_the_generic_id() {
        let scopes = vec![
            "openid".to_owned(),
            "urn:acme:widgets".to_owned(),
            "management".to_owned(),
        ];
        let nodes = consent_nodes(Transport::Api, "flw_x", &client(), &scopes);
        let scope_texts: Vec<u32> = nodes
            .iter()
            .filter(|node| node.group == NodeGroup::Scope && node.sequence > 0)
            .filter_map(|node| match &node.attributes {
                NodeAttributes::Text { message } => Some(message.id.0),
                NodeAttributes::Input { .. } => None,
            })
            .collect();
        assert_eq!(
            scope_texts,
            vec![
                message::CONSENT_SCOPE_OPENID.0,
                message::CONSENT_SCOPE_GENERIC.0,
                message::CONSENT_SCOPE_MANAGEMENT.0,
            ],
            "one node per scope, custom scopes use the generic id"
        );
        // The custom scope's raw token rides the context, not a bespoke id.
        let generic = nodes
            .iter()
            .find_map(|node| match &node.attributes {
                NodeAttributes::Text { message }
                    if message.id == message::CONSENT_SCOPE_GENERIC =>
                {
                    Some(message)
                }
                _ => None,
            })
            .expect("a generic scope node");
        assert_eq!(
            generic.context.0.get("scope").map(String::as_str),
            Some("urn:acme:widgets")
        );
    }

    #[test]
    fn the_verified_badge_reflects_the_client_verification_state() {
        let mut verified = client();
        verified.verified = true;
        let nodes = consent_nodes(Transport::Api, "flw_x", &verified, &[]);
        let badge = nodes
            .iter()
            .find(|node| node.group == NodeGroup::ClientIdentity && node.sequence == 1)
            .expect("a verification badge node");
        match &badge.attributes {
            NodeAttributes::Text { message } => {
                assert_eq!(message.id, message::CONSENT_CLIENT_VERIFIED);
            }
            NodeAttributes::Input { .. } => panic!("the badge is a text node"),
        }
    }

    #[test]
    fn the_decision_is_read_only_from_the_action_node() {
        // An arbitrary injected field is not the `decision` node, so it cannot flip a deny into
        // an allow: only `decision == "allow"` allows.
        let mut deny = Submission::default();
        deny.node_values
            .insert("scope".to_owned(), Value::String("admin".to_owned()));
        deny.node_values
            .insert("allow".to_owned(), Value::String("true".to_owned()));
        assert!(
            deny.node_values.get("decision").and_then(Value::as_str) != Some("allow"),
            "no decision node means not an allow"
        );
        let mut allow = Submission::default();
        allow
            .node_values
            .insert("decision".to_owned(), Value::String("allow".to_owned()));
        assert_eq!(
            allow.node_values.get("decision").and_then(Value::as_str),
            Some("allow")
        );
    }

    #[test]
    fn the_deny_redirect_carries_the_internal_marker() {
        assert_eq!(
            deny_redirect("/authorize?client_id=cli_x&scope=openid"),
            "/authorize?client_id=cli_x&scope=openid&consent_denied=1"
        );
    }
}
