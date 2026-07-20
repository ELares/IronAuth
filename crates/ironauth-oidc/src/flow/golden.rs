// SPDX-License-Identifier: MIT OR Apache-2.0

//! The golden flow object corpus (issue #84, PR 4): a committed, byte stable set of
//! representative flow objects, one per journey per state, on BOTH transports.
//!
//! Why it exists. The published JSON Schema ([`super::schema`]) locks the flow object's
//! TYPE shape (which fields exist, of which type). The golden corpus locks the RENDERED
//! shape the engine actually emits: the exact node set, the deterministic node ORDER (issue
//! #84 hardening 1), the node groups, the attached message ids, and the per transport deltas
//! (the `ui.action` and the browser only hidden `flow` node). A breaking change to any
//! journey's rendered flow changes a golden, so the committed `docs/flow-golden.json` diff
//! FAILS CI (the freshness gate `scripts/flow-golden.sh`), exactly like the schema gate. New
//! journeys or node groups are ADDITIVE: they add goldens without touching the existing ones.
//!
//! Determinism. Every golden is built from the SAME pure node builders the live engine calls
//! (`login::start_nodes`, `registration::ack_nodes`, and so on), through the SAME
//! [`Ui::new`] deterministic sort and the SAME `contract_version`, with a FIXED flow id and
//! expiry substituted for the per flow entropy and clock, so the corpus is reproducible with
//! no database and no wall clock. Because each golden IS a serialized [`Flow`], it is schema
//! valid by construction (the schema is `schema_for!(Flow)`); the PR 4 corpus test also
//! asserts each golden validates against the published `docs/flow-schema.json`.

use serde_json::{Value, json};

use super::message::{self, Message};
use super::model::{CONTRACT_VERSION, Flow, FlowStateTag, Journey, Node, Transport, Ui};
use super::submit_action_for;
use super::{federation, login, mfa, recovery, registration};
use crate::totp::FlowEnrollBegin;

/// The fixed flow id every golden carries in place of the per flow entropy, so the corpus is
/// reproducible. Shaped like a real scope embedded `flw_` id but with a stable body.
pub const GOLDEN_FLOW_ID: &str = "flw_golden00000000000000000000";

/// The fixed flow expiry (unix seconds) every golden carries in place of the app clock, so the
/// corpus is reproducible.
pub const GOLDEN_EXPIRES_AT: i64 = 900;

/// The fixed tenant slug the golden `ui.action` paths embed.
pub const GOLDEN_TENANT: &str = "tnt_golden";

/// The fixed environment slug the golden `ui.action` paths embed.
pub const GOLDEN_ENVIRONMENT: &str = "env_golden";

/// A fixed local resume target the federation launcher goldens reflect in `request_url`, so
/// that state's `request_url` is a stable value (a real launcher always carries one).
const GOLDEN_RESUME: &str = "/authorize?client_id=cli_golden";

/// The federation connector slug the federation launcher goldens name.
const GOLDEN_CONNECTOR: &str = "acme-oidc";

/// One named golden flow object (issue #84): the stable name (the key in `docs/flow-golden.json`
/// and the diff a breaking change trips) plus the flow object itself.
#[derive(Debug, Clone)]
pub struct GoldenFlow {
    /// The stable golden name (`<journey>_<state>_<transport>`).
    pub name: &'static str,
    /// The rendered flow object.
    pub flow: Flow,
}

impl GoldenFlow {
    /// The golden flow object as a JSON value (the committed snapshot form).
    ///
    /// # Panics
    ///
    /// Panics only if a [`Flow`] fails to serialize, a compile time impossibility for these
    /// types (a programming error, never a runtime one).
    #[must_use]
    pub fn as_json(&self) -> Value {
        serde_json::to_value(&self.flow).expect("a flow object serializes")
    }
}

/// Assemble one golden from a state's nodes and flow level messages (issue #84), through the
/// SAME deterministic ordering and contract stamping the live `build_flow` uses, with the
/// fixed golden id and expiry.
fn golden(
    name: &'static str,
    transport: Transport,
    journey: Journey,
    state: FlowStateTag,
    nodes: Vec<Node>,
    messages: Vec<Message>,
    request_url: Option<&str>,
) -> GoldenFlow {
    let ui = Ui::new(
        submit_action_for(GOLDEN_TENANT, GOLDEN_ENVIRONMENT, transport, journey),
        "POST".to_owned(),
        nodes,
        messages,
    );
    GoldenFlow {
        name,
        flow: Flow {
            contract_version: CONTRACT_VERSION,
            id: GOLDEN_FLOW_ID.to_owned(),
            journey,
            state,
            transport,
            expires_at: GOLDEN_EXPIRES_AT,
            request_url: request_url.map(str::to_owned),
            ui,
        },
    }
}

/// The full golden corpus (issue #84, PR 4): every representative flow object, one per journey
/// per state, on BOTH transports. Ordered deterministically (the `Vec` order is the file order
/// too). The names are stable; the corpus only grows (additive), so an existing golden never
/// silently changes.
#[must_use]
pub fn golden_flows() -> Vec<GoldenFlow> {
    // A fixed TOTP enrollment fixture in place of a live enroll ceremony, so the `mfa_enroll`
    // goldens are reproducible with no database. The material is a stable, obviously synthetic
    // placeholder (never a real secret).
    let begin = FlowEnrollBegin {
        credential_id: "tot_golden00000000000000000000".to_owned(),
        otpauth_uri: "otpauth://totp/IronAuth:golden@example.test\
                      ?secret=GOLDENSECRETGOLDENSECRET&issuer=IronAuth&algorithm=SHA1\
                      &digits=6&period=30"
            .to_owned(),
        secret: "GOLD ENSE CRET GOLD ENSE CRET".to_owned(),
    };

    let mut corpus = Vec::new();
    for transport in [Transport::Api, Transport::Browser] {
        push_transport_goldens(&mut corpus, transport, &begin);
    }
    corpus
}

/// Push every representative golden for one transport (issue #84): the same journey/state set
/// as its sibling transport, so the corpus carries each state on both.
fn push_transport_goldens(
    corpus: &mut Vec<GoldenFlow>,
    transport: Transport,
    begin: &FlowEnrollBegin,
) {
    let suffix = transport.as_str();
    let id = GOLDEN_FLOW_ID;

    // Login: the start state, plus the uniform authentication failure (an error carrying
    // flow, the anti enumeration crux render).
    corpus.push(golden(
        leaked(format!("login_start_{suffix}")),
        transport,
        Journey::Login,
        FlowStateTag::IdentifierPassword,
        login::start_nodes(transport, id),
        Vec::new(),
        None,
    ));
    corpus.push(golden(
        leaked(format!("login_incorrect_{suffix}")),
        transport,
        Journey::Login,
        FlowStateTag::IdentifierPassword,
        login::uniform_incorrect_render(transport, id),
        Vec::new(),
        None,
    ));

    // Registration: the details state, plus the uniform closed mode acknowledgment.
    corpus.push(golden(
        leaked(format!("registration_details_{suffix}")),
        transport,
        Journey::Registration,
        FlowStateTag::RegistrationDetails,
        registration::start_nodes(transport, id),
        Vec::new(),
        None,
    ));
    corpus.push(golden(
        leaked(format!("registration_ack_{suffix}")),
        transport,
        Journey::Registration,
        FlowStateTag::RegistrationAck,
        registration::ack_nodes(),
        vec![Message::of(message::REGISTER_ACK)],
        None,
    ));

    // MFA: the challenge and the enrollment states (reached from a login flow).
    corpus.push(golden(
        leaked(format!("mfa_challenge_{suffix}")),
        transport,
        Journey::Login,
        FlowStateTag::MfaChallenge,
        mfa::challenge_start_nodes(transport, id),
        Vec::new(),
        None,
    ));
    corpus.push(golden(
        leaked(format!("mfa_enroll_{suffix}")),
        transport,
        Journey::Login,
        FlowStateTag::MfaEnroll,
        mfa::enroll_nodes(transport, id, begin, false),
        Vec::new(),
        None,
    ));

    // Recovery: the identifier start, the uniform acknowledgment plus code entry, and the
    // acknowledgment re-rendered with the uniform incorrect code error (an error carrying
    // flow).
    corpus.push(golden(
        leaked(format!("recovery_start_{suffix}")),
        transport,
        Journey::Recovery,
        FlowStateTag::RecoveryStart,
        recovery::start_nodes(transport, id),
        Vec::new(),
        None,
    ));
    corpus.push(golden(
        leaked(format!("recovery_ack_{suffix}")),
        transport,
        Journey::Recovery,
        FlowStateTag::RecoveryAck,
        recovery::ack_nodes(transport, id, false),
        vec![Message::of(message::RECOVERY_ACK)],
        None,
    ));
    corpus.push(golden(
        leaked(format!("recovery_ack_code_error_{suffix}")),
        transport,
        Journey::Recovery,
        FlowStateTag::RecoveryAck,
        recovery::ack_nodes(transport, id, true),
        vec![Message::of(message::RECOVERY_ACK)],
        None,
    ));

    // Federation: the launcher (the Oidc "continue with" affordance), which carries a
    // resume target.
    corpus.push(golden(
        leaked(format!("federation_start_{suffix}")),
        transport,
        Journey::Federation,
        FlowStateTag::FederationStart,
        federation::start_nodes(transport, id, GOLDEN_CONNECTOR),
        Vec::new(),
        Some(GOLDEN_RESUME),
    ));
}

/// The golden corpus as the committed `docs/flow-golden.json` payload (issue #84): the contract
/// version plus every golden keyed by its stable name. The `scripts/flow-golden.sh` gate stamps
/// the "do not edit by hand" comment and diffs this against the committed file.
#[must_use]
pub fn golden_corpus() -> Value {
    let mut flows = serde_json::Map::new();
    for golden in golden_flows() {
        flows.insert(golden.name.to_owned(), golden.as_json());
    }
    json!({
        "contract_version": CONTRACT_VERSION,
        "flows": Value::Object(flows),
    })
}

/// Leak a per transport golden name into a `'static str`. The corpus is a small fixed set built
/// once per process (a test or the schema example binary), so the deliberate, bounded leak keeps
/// the [`GoldenFlow::name`] a `'static` handle without threading owned strings through the whole
/// corpus. Never called on a hot path.
fn leaked(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}
