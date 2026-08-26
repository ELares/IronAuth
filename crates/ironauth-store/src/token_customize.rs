// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pre-token hook's event contract (issue #113, acceptance criteria 1 and 6).
//!
//! > One pre-token hook shaping BOTH the ID token and the access token in a single invocation,
//! > with an explicitly versioned event payload registered in the schema registry.
//!
//! > Uniform across every grant type ... all fire the same hook with the same versioned schema
//! > (grant type identified in the payload).
//!
//! This module is that contract, and nothing else. It defines what a `token.customize`
//! invocation carries; the transport that delivers it and the layer that applies the result are
//! separate.
//!
//! # Why the contract lands before the hook
//!
//! Because two issues bind to it. #113 dispatches `token.customize` through the HTTP target
//! machinery, and #114's WASM transport carries "the same event contract ... so implementations
//! can migrate transports unchanged". A contract defined inside whichever transport shipped
//! first would be that transport's shape, and the second one would inherit an accident. (The
//! migrate-transports-unchanged requirement is issue #113's own text, describing what #114 must
//! honour.)
//!
//! # ONE invocation, BOTH tokens
//!
//! The payload carries the ID-token claims and the access-token claims together, and that is
//! the criterion rather than a convenience. A hook invoked once per token would see two
//! independent views of one login and could make them disagree -- a `groups` in the ID token
//! that does not match the `groups` the resource server is authorizing against. Handing over
//! both halves at once makes that disagreement something a hook has to write on purpose.
//!
//! # Why this is NOT in the event catalog
//!
//! It was, for about an hour, and the catalog refused it: every registered type there must be
//! PAST TENSE, and the assertion that enforces it says why -- "an event records what BECAME
//! TRUE; the imperative form is the AUDIT vocabulary, and conflating the two is the defect this
//! rule exists to prevent."
//!
//! `token.customize` is imperative because it is not an announcement. It is a REQUEST whose
//! response the caller uses: `flow_target::Invocation::Sync` describes exactly this shape --
//! "the flow waits; the response can mutate the in-flight data". Renaming it to something
//! past-tense would have been worse than the rule it dodged, since the hook runs BEFORE the
//! token exists and `token.customized` would name something that has not happened.
//!
//! So the schema lives here, beside the type it describes. WHAT THAT COSTS, stated rather than
//! glossed, because it is not nothing:
//!
//! * `token.customize` appears in neither `docs/events/catalog.json` nor `docs/EVENTS.md`, so
//!   an integrator implementing this hook has no published description of it. That is a real
//!   gap, and it belongs with the dispatch, which is where such a doc has something to
//!   describe.
//! * `scripts/event-registry-compat.py` no longer covers it, so a BREAKING narrowing of this
//!   schema under an unchanged version is not caught by that gate. The
//!   `the_struct_and_the_schema_describe_the_same_fields` test and `REGISTERED_VERSIONS` are
//!   what replace it here, and they are NARROWER: they catch a field appearing or disappearing
//!   and an unregistered version, not every narrowing a field could suffer.
//!
//! The alternative was to take the naming argument to its conclusion and add an entry to the
//! catalog's `IRREGULAR_PAST_FORMS`. That list is for past forms not ending in -ed;
//! `customize` is not a past form at all, so using it would have been dodging the rule rather
//! than satisfying it.
//!
//! # The version is a TYPE, not a literal at each call site
//!
//! Criterion 6 asks that the version be "explicit in every hook invocation" and that emitting
//! an unregistered one fail. A `u32` written by hand at each dispatch site satisfies the letter
//! and not the intent: the fifth site to be added is the one that writes `1` after the schema
//! moved to `2`. [`TokenCustomizePayload`] carries it, so a site cannot spell it at all.
//!
//! And the version is answered against [`REGISTERED_VERSIONS`], not a floor. The first version
//! of this schema said `minimum: 1`, so bumping the constant to `2` validated happily and left
//! every test, lint and gate green -- explicit and unchecked at the same time, which is the
//! half of the criterion that matters.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Every version of this contract the registry knows.
///
/// A LIST, not a floor. The schema emits it as an `enum`, so a payload claiming a version
/// nobody registered does not validate -- which is criterion 6's second half, and it did not
/// hold when the schema said `minimum: 1`: bumping the constant to 2 left every test, every
/// lint and every gate green, so the version was explicit and unchecked at the same time.
///
/// A LIST rather than a single number because a contract that gains a version does not
/// instantly lose the old one: a dispatcher on 2 and a hook still speaking 1 have to coexist
/// through a rollout.
pub const REGISTERED_VERSIONS: &[u32] = &[1];

/// The version this build EMITS, which must be one of [`REGISTERED_VERSIONS`].
///
/// Bumping it without adding the new number to that list makes every payload fail validation
/// immediately, in this module's own tests. That is the direction the criterion asks for: an
/// unregistered version cannot be emitted rather than being emitted and misread.
pub const TOKEN_CUSTOMIZE_VERSION: u32 = 1;

/// The request type name.
///
/// NOT carried in the payload today, so a receiver cannot discriminate on it: it exists for the
/// dispatcher to route on and for the two transports to agree on a name. If it is still unread
/// when the dispatch lands, it should either go into the payload as a fixed field or go away.
pub const TOKEN_CUSTOMIZE_EVENT: &str = "token.customize";

/// What one `token.customize` invocation carries.
///
/// Serialized as the event payload. Every field is present in every invocation, whatever the
/// grant: a hook that had to ask "does this grant have a subject" by checking for a missing key
/// would be reading the grant type out of the payload's SHAPE, and the shape is not the place
/// that fact lives.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenCustomizePayload {
    /// The payload version, explicit in every invocation (criterion 6).
    pub payload_version: u32,
    /// Which grant is being exchanged, as the wire `grant_type` value.
    ///
    /// The criterion asks for the grant to be "identified in the payload" precisely so one hook
    /// can serve all of them: a hook that wants to add a claim only on refresh reads this
    /// rather than being registered against a different event.
    pub grant_type: String,
    /// The OAuth client the tokens are for.
    pub client_id: String,
    /// The pseudonymous subject, or [`None`] for a grant with no user.
    ///
    /// `client_credentials` has a service-account principal and no human, and the criterion
    /// requires the same schema across grants -- so this is nullable rather than absent, and a
    /// hook reads `grant_type` to know which case it is in rather than inferring it from a
    /// missing field.
    pub subject: Option<String>,
    /// The claims destined for the ID token, after declarative mapping.
    pub id_token_claims: BTreeMap<String, serde_json::Value>,
    /// The claims destined for the access token, after declarative mapping.
    ///
    /// AFTER mapping, because #113 specifies the layering: "declarative mappings apply first,
    /// then the hook sees and may refine the result". A hook handed the raw claims would be
    /// deciding against a state no token is ever built from.
    pub access_token_claims: BTreeMap<String, serde_json::Value>,
}

/// The JSON Schema a `token.customize` payload must satisfy.
///
/// `additionalProperties: false`, so a field nobody registered cannot ride along into a hook
/// that would then act on it. Every field is required, including `payload_version`: a hook
/// reading a payload without one would be guessing which contract it is holding.
#[must_use]
pub fn payload_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "payload_version": {"enum": REGISTERED_VERSIONS},
            "grant_type": {"type": "string", "minLength": 1},
            "client_id": {"type": "string", "minLength": 1},
            "subject": {"type": ["string", "null"]},
            "id_token_claims": {"type": "object"},
            "access_token_claims": {"type": "object"}
        },
        "required": [
            "payload_version", "grant_type", "client_id", "subject",
            "id_token_claims", "access_token_claims"
        ]
    })
}

/// Why a payload was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadRejected {
    /// The failures, as `pointer: message`, in the order the validator reported them.
    pub failures: Vec<String>,
}

impl core::fmt::Display for PayloadRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "payload does not match its schema: {}",
            self.failures.join("; ")
        )
    }
}

impl std::error::Error for PayloadRejected {}

/// Check a payload against [`payload_schema`].
///
/// A dispatcher calls this before sending. The point is that a malformed invocation is refused
/// HERE rather than at the hook, which would have to decide what to do with a payload it cannot
/// read -- and whose failure policy would then fire for a reason that is ours, not the hook's.
///
/// # Errors
///
/// [`PayloadRejected`] carrying every schema failure.
///
/// # Panics
///
/// If [`payload_schema`] stops being a valid JSON Schema, which is a compile-time constant in
/// this file and so is a programming error rather than a runtime condition.
pub fn validate_payload(payload: &serde_json::Value) -> Result<(), PayloadRejected> {
    let schema = crate::trait_schema::TraitSchema::compile(&payload_schema().to_string())
        .expect("the payload schema is a compile-time constant and compiles");
    let failures = schema.validate(payload);
    if failures.is_empty() {
        return Ok(());
    }
    Err(PayloadRejected {
        failures: failures
            .iter()
            .map(|failure| format!("{}: {}", failure.pointer, failure.message))
            .collect(),
    })
}

impl TokenCustomizePayload {
    /// Build a payload at the registered version.
    ///
    /// The version is not a parameter. A call site cannot spell it, so it cannot spell it
    /// wrong, and the registry stays the only thing that decides which versions exist.
    #[must_use]
    pub fn new(
        grant_type: &str,
        client_id: &str,
        subject: Option<&str>,
        id_token_claims: BTreeMap<String, serde_json::Value>,
        access_token_claims: BTreeMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            payload_version: TOKEN_CUSTOMIZE_VERSION,
            grant_type: grant_type.to_owned(),
            client_id: client_id.to_owned(),
            subject: subject.map(ToOwned::to_owned),
            id_token_claims,
            access_token_claims,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TOKEN_CUSTOMIZE_VERSION, TokenCustomizePayload, validate_payload};
    use std::collections::BTreeMap;

    fn claims(pairs: &[(&str, serde_json::Value)]) -> BTreeMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect()
    }

    fn payload(grant: &str, subject: Option<&str>) -> serde_json::Value {
        serde_json::to_value(TokenCustomizePayload::new(
            grant,
            "cli_app",
            subject,
            claims(&[("email", serde_json::json!("ada@example.test"))]),
            claims(&[("groups", serde_json::json!(["eng"]))]),
        ))
        .expect("serializes")
    }

    /// The struct's fields and the schema's properties are THE SAME SET.
    ///
    /// They are two descriptions of one contract and only one drift direction was bound: a
    /// field added to the schema and not the struct was caught (the payload would lack a
    /// required key), and a field added to the STRUCT and not the schema was not -- it would
    /// simply never be described, and an integrator reading the schema would not know it
    /// exists.
    #[test]
    fn the_struct_and_the_schema_describe_the_same_fields() {
        let built = payload("authorization_code", Some("usr_ada"));
        let from_struct: std::collections::BTreeSet<String> = built
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        let schema = super::payload_schema();
        let from_schema: std::collections::BTreeSet<String> = schema["properties"]
            .as_object()
            .expect("properties")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            from_struct, from_schema,
            "every field the type serializes must be described, and nothing else"
        );
        let required: std::collections::BTreeSet<String> = schema["required"]
            .as_array()
            .expect("required")
            .iter()
            .map(|name| name.as_str().expect("a string").to_owned())
            .collect();
        assert_eq!(
            required, from_schema,
            "and every described field is required: this contract has no optional halves"
        );
    }

    /// CRITERION 6. What the builder produces satisfies the schema that describes it.
    ///
    /// The tie between the type and its contract. Without it the two are two descriptions of
    /// one thing that can drift: a field added to the struct and not the schema is refused at
    /// dispatch and never delivered, and the reverse is the same defect mirrored.
    #[test]
    fn the_built_payload_satisfies_its_schema() {
        validate_payload(&payload("authorization_code", Some("usr_ada")))
            .expect("the builder's output matches the schema");
    }

    /// CRITERION 1. The SAME schema accepts every grant, including the one with no user.
    ///
    /// A schema that only took the grants with a subject would force a second contract for
    /// `client_credentials`, which is the thing "uniform across every grant type" forbids.
    #[test]
    fn every_grant_fits_the_same_schema() {
        for (grant, subject) in [
            ("authorization_code", Some("usr_ada")),
            ("refresh_token", Some("usr_ada")),
            // No human. The subject is null, and the schema takes it.
            ("client_credentials", None),
            (
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                Some("usr_ada"),
            ),
            (
                "urn:ietf:params:oauth:grant-type:device_code",
                Some("usr_ada"),
            ),
            (
                "urn:ietf:params:oauth:grant-type:token-exchange",
                Some("usr_ada"),
            ),
            ("urn:openid:params:grant-type:ciba", Some("usr_ada")),
        ] {
            let built = payload(grant, subject);
            validate_payload(&built).unwrap_or_else(|error| {
                panic!("the {grant} grant must fit the one schema: {error}")
            });
            // READ BACK, or the seven rows differ in what they feed and not in what they
            // prove: a builder that ignored its `grant_type` argument entirely passed the
            // validate-only version of this loop seven times over.
            assert_eq!(
                built["grant_type"],
                serde_json::json!(grant),
                "the payload must name the grant that fired"
            );
            assert_eq!(
                built["subject"],
                subject.map_or(serde_json::Value::Null, |s| serde_json::json!(s)),
                "and carry the subject, or null where there is no human"
            );
        }
    }

    /// Every argument lands in ITS OWN field.
    ///
    /// Swapping the two claim bags survived every other test here, because they all checked
    /// that the payload was VALID and none checked that it was RIGHT. A hook handed the access
    /// token's claims under `id_token_claims` would refine the wrong half of the login, and
    /// the schema cannot tell: both are objects.
    #[test]
    fn each_argument_lands_in_its_own_field() {
        let built = serde_json::to_value(TokenCustomizePayload::new(
            "refresh_token",
            "cli_distinct",
            Some("usr_distinct"),
            claims(&[("id_only", serde_json::json!(true))]),
            claims(&[("access_only", serde_json::json!(true))]),
        ))
        .expect("serializes");

        assert_eq!(built["grant_type"], serde_json::json!("refresh_token"));
        assert_eq!(built["client_id"], serde_json::json!("cli_distinct"));
        assert_eq!(built["subject"], serde_json::json!("usr_distinct"));
        assert_eq!(
            built["id_token_claims"],
            serde_json::json!({"id_only": true}),
            "the ID-token bag must be the ID-token bag"
        );
        assert_eq!(
            built["access_token_claims"],
            serde_json::json!({"access_only": true}),
            "and the access-token bag must not be the other one"
        );
    }

    /// The version is explicit IN THE PAYLOAD, and the builder is what sets it.
    #[test]
    fn the_version_is_in_the_payload_and_no_call_site_spells_it() {
        assert_eq!(
            payload("refresh_token", Some("usr_ada"))["payload_version"],
            serde_json::json!(TOKEN_CUSTOMIZE_VERSION),
            "criterion 6 asks for the version to be explicit in every invocation, and a hook \
             reads the payload"
        );
    }

    /// Every way a payload can be malformed is refused.
    #[test]
    fn a_payload_that_does_not_match_the_schema_is_refused() {
        // A field nobody registered. `additionalProperties: false` stops it reaching a hook
        // that would then act on it.
        let mut smuggled = payload("authorization_code", Some("usr_ada"));
        smuggled["unregistered_field"] = serde_json::json!("smuggled");
        assert!(
            validate_payload(&smuggled).is_err(),
            "an unregistered field"
        );

        // A required field missing: a hook that could not tell which grant fired would be
        // reading the grant out of the payload's shape.
        let mut incomplete = payload("authorization_code", Some("usr_ada"));
        incomplete
            .as_object_mut()
            .expect("an object")
            .remove("grant_type");
        assert!(validate_payload(&incomplete).is_err(), "grant_type missing");

        // The version absent, which would leave a hook guessing which contract it holds.
        let mut versionless = payload("authorization_code", Some("usr_ada"));
        versionless
            .as_object_mut()
            .expect("an object")
            .remove("payload_version");
        assert!(validate_payload(&versionless).is_err(), "version missing");

        // A version NOBODY REGISTERED. This is criterion 6's second half, and it did not hold
        // when the schema said `minimum: 1`: 2 validated happily, so bumping the constant
        // without registering the schema left every test, lint and gate green.
        for version in [0, 2, 99] {
            let mut wrong = payload("authorization_code", Some("usr_ada"));
            wrong["payload_version"] = serde_json::json!(version);
            assert!(
                validate_payload(&wrong).is_err(),
                "version {version} is not in REGISTERED_VERSIONS and must not validate"
            );
        }

        // An EMPTY grant type is not a grant type; without minLength a hook would branch on "".
        let mut blank = payload("authorization_code", Some("usr_ada"));
        blank["grant_type"] = serde_json::json!("");
        assert!(validate_payload(&blank).is_err(), "empty grant type");
    }

    /// The refusal says WHAT failed, not merely that something did.
    #[test]
    fn the_refusal_names_the_failures() {
        let mut broken = payload("authorization_code", Some("usr_ada"));
        broken
            .as_object_mut()
            .expect("an object")
            .remove("client_id");
        let rejected = validate_payload(&broken).expect_err("must be refused");
        assert!(
            !rejected.failures.is_empty() && rejected.to_string().contains("client_id"),
            "a dispatcher needs to know which field, got {rejected:?}"
        );
    }
}
