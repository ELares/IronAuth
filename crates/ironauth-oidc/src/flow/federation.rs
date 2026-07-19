// SPDX-License-Identifier: MIT OR Apache-2.0

//! The federation journey (issue #84): a LAUNCHER over the EXISTING outbound federation
//! authorize leg and its callback. The engine owns NO federation security; it only expresses
//! federation as a flow state.
//!
//! The flow presents the federation node group (a "continue with {provider}" affordance) whose
//! submission produces a [`Redirect`](super::Continuation::Redirect) to the EXISTING
//! `GET /t/{tenant}/e/{env}/federation/{connector}/authorize` route, threading the flow's
//! `return_to` (the pending local `/authorize` to resume). That route and the EXISTING
//! `federation_callback` complete the login UNCHANGED: they mint the honest
//! [`AuthMethod::Federated`](crate::authn::AuthMethod) session (acr `urn:ironauth:acr:federated`,
//! unranked, upstream amr passthrough), consult the #78 [`link_decision`](crate::account_linking::link_decision)
//! anti takeover guard (a manual link still needs the #78 fresh re-auth of the target), and
//! apply the #77 broker overlay. NONE of that is bypassed, because the flow launcher does not
//! reimplement it; it only builds the URL the existing pipeline already secures.
//!
//! # Native JSON transport: the redirect is honestly deferred
//!
//! A federated first factor is an inherently browser leg (an OAuth redirect that lands on the
//! callback and completes with a session cookie). The API transport therefore returns the
//! authorize URL as the [`Redirect`](super::Continuation::Redirect) affordance and DEFERS the
//! in JSON resume: a native client opens the URL in a browser, and the EXISTING callback
//! completes it through the cookie/redirect path. This mirrors PR 2's passkey deferral (a
//! ceremony the pure JSON transport cannot itself drive); the flow presents the affordance and
//! the browser leg does the rest.

use ironauth_store::Scope;

use super::message::{self, Message};
use super::model::{InputType, Node, NodeAttributes, NodeGroup, Transport};
use crate::util::percent_encode_query;

/// Build the federation launcher nodes (issue #84): the Oidc "continue with {provider}" submit
/// affordance whose submission the driver turns into the redirect to the existing authorize
/// leg. The provider slug rides the label's structured context (never the copy string), so i18n
/// keys on the message id and the context. On the browser transport a hidden `flow` node
/// carries the flow id back on the form post.
#[must_use]
pub(super) fn start_nodes(transport: Transport, flow_id: &str, connector: &str) -> Vec<Node> {
    let mut nodes = Vec::new();
    nodes.push(Node::input(
        NodeGroup::Oidc,
        0,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("federation".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
        },
        Some(Message::with_context(
            message::FEDERATION_CONTINUE_LABEL,
            message::MessageContext::one("provider", connector),
        )),
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
            },
            None,
        ));
    }
    nodes
}

/// The URL of the EXISTING outbound federation authorize leg for `connector`, threading the
/// flow's `return_to` (issue #84). The launcher only CONSTRUCTS this URL; the existing route
/// validates the connector and the resume target, persists the single use correlation row, and
/// redirects to the upstream provider, and the existing callback finalizes the login. The
/// connector and the resume target are percent encoded so a hostile value cannot break out of
/// the path or the query (an unknown connector is a uniform not found at the existing route).
#[must_use]
pub(super) fn authorize_url(scope: Scope, connector: &str, return_to: &str) -> String {
    format!(
        "/t/{}/e/{}/federation/{}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        percent_encode_query(connector),
        percent_encode_query(return_to),
    )
}
