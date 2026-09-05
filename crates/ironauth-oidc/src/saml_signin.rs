//! Turning a consumed SAML assertion into a local session (issue #139).
//!
//! # The four reasons the last change refused to do this, and what answers each
//!
//! [`crate::saml_route`]'s module doc records why an earlier version of the assertion consumer
//! was taken apart rather than kept. Each objection is a constraint on this module, so each is
//! answered here rather than left for a reader to reconstruct.
//!
//! 1. IT CROSSED ORGANIZATIONS. The identifier seam resolves per ENVIRONMENT, so any identity
//!    provider with a key pinned anywhere in the environment could mint a session for any
//!    account in it. NOTHING HERE RESOLVES AN IDENTIFIER. The local user is keyed on
//!    [`crate::federation::federated_external_id`] namespaced by the connection's OWN
//!    `idp_entity_id`, which is the value a response's `Issuer` was already required to equal.
//!    A different identity provider produces a different key and therefore a different user,
//!    and no assertion can name an account that another provider created.
//! 2. IT BYPASSED THE ANTI-TAKEOVER GATE. `account_linking` decides whether an upstream identity
//!    may be MERGED into an existing local account, and answers `AutoLink` from exactly one arm.
//!    This module never asks, because it never merges: it takes the same branch the federated
//!    callback calls the safe default, provisioning a separate identity keyed on the composite.
//!    Linking a SAML identity to a local account is a decision an operator has not been offered
//!    yet, and taking it silently here is the defect the objection names.
//! 3. THE POPULATION IT NAMED COULD NOT USE IT. Requiring a VERIFIED local identifier would sign
//!    in none of the accounts this exists to serve, because the SCIM inbound server in this same
//!    milestone deliberately writes `verified: false`. Nothing here requires one: a first
//!    assertion CREATES the person.
//! 4. ITS ONLY REACHABLE MODE WAS THE ONE #139 REQUIRES OFF. That objection is spent. The start
//!    endpoint issues real `AuthnRequest`s, so a solicited response is now the ordinary case,
//!    and `allow_unsolicited` remains off by default and is enforced before this module runs.
//!
//! # The mapper is the shared one, and that is a criterion rather than a preference
//!
//! #139 requires attribute mapping and `NameID` handling to "round-trip through the shared JIT
//! mapper with per-connection config". The mapper is
//! [`ironauth_connector::claim_mapping::evaluate`] -- the same function, not a parallel one --
//! and the per-connection config is the `attribute_mapping` column. What this module supplies is
//! the ADAPTER: a SAML assertion is a list of `Attribute` elements and a `NameID`, and the
//! evaluator reads a JSON claims object, so [`claims_from_assertion`] is where one becomes the
//! other. Everything downstream of that call is the OIDC path verbatim, including the trait
//! schema type-check and the self-service visibility class.
//!
//! # What this does not do
//!
//! It does not consult `account_linking`, for the reason above. It does not capture upstream
//! tokens: there are none, because SAML returns an assertion rather than a token grant. It does
//! not apply the broker overlay, which reads an `ocn_` org connection this connection has no row
//! in -- discovery routing is the change that gives SAML one, and the overlay becomes reachable
//! with it rather than being deliberately skipped forever.

use axum::http::HeaderMap;
use axum::response::Response;
use ironauth_connector::ClaimMapping;
use ironauth_connector::claim_mapping::{ClaimSources, TraitDocument, TraitSchemaView, evaluate};
use ironauth_saml::attributes::Value as AttributeValue;
use ironauth_store::{
    NewMembership, OrgMembershipId, SamlConnection, Scope, StoreError, TraitSchema, UserId,
};
use serde_json::{Map, Value as JsonValue};

use crate::authn::AuthenticationEvent;
use crate::federation::{StoreTraitSchema, VerifiedUpstreamIdentity, provision_federated_user};
use crate::interaction;
use crate::saml_acs::Consumed;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The claim name the `NameID` arrives under.
///
/// `sub`, BECAUSE THAT IS WHAT THE SHARED MAPPER'S DEFAULT SUBJECT RULE READS. The evaluator
/// resolves its subject from `sub` unless a mapping names another field, so putting the `NameID`
/// anywhere else would make every connection that does not override the rule fail to resolve a
/// subject at all. The value is also what the identity key is built from, so the two agree by
/// construction rather than by a caller remembering to keep them in step.
const SUBJECT_CLAIM: &str = "sub";

/// The claim name the `NameID`'s `Format` arrives under, when the assertion carried one.
///
/// PRESENT ONLY WHEN THE PROVIDER SENT ONE. SAML Core 2.2.2 says an omitted `Format` MEANS
/// `unspecified`, and `saml_acs` deliberately does not fill it in so that "said unspecified" and
/// "said nothing" stay distinguishable. Defaulting it here would undo that one layer up, and a
/// mapping that wants the default can write it.
const NAMEID_FORMAT_CLAIM: &str = "nameid_format";

/// Sign in the person a consumed assertion names, provisioning them on first sight.
///
/// The response is a redirect carrying the session cookies, to the `RelayState` the START
/// endpoint recorded when it issued the request -- never to a location the POST carried, which
/// is an attacker-controlled parameter and an open redirect with extra steps.
pub(crate) async fn sign_in(
    state: &OidcState,
    scope: Scope,
    connection: &SamlConnection,
    consumed: &Consumed,
    headers: &HeaderMap,
) -> Response {
    let claims = claims_from_assertion(consumed);
    let (trait_doc, schema_version) = match map_traits(state, scope, connection, &claims).await {
        Ok(mapped) => mapped,
        Err(response) => return response,
    };
    // THE IDENTITY KEY IS THE CONNECTION'S OWN `idp_entity_id`, never the mapped subject and
    // never a value out of the document. `consume` already required the response's `Issuer` to
    // equal this column, so the namespace is one the assertion was checked against rather than
    // one it chose.
    let identity = VerifiedUpstreamIdentity {
        subject: consumed.accepted.name_id.clone(),
        email: mapped_email(&trait_doc),
        // NO `amr` AND NO `acr` PASSTHROUGH, because this build reads no `AuthnContext`.
        // Asserting an empty list is honest; inventing `["pwd"]` because a SAML login usually
        // involves a password would be this server claiming a factor it did not witness.
        upstream_amr: Vec::new(),
        upstream_acr: None,
        // NO UPSTREAM `auth_time`: `AuthnStatement`'s `AuthnInstant` is not among the fields
        // `Accepted` carries, so the honest answer is the instant this deployment accepted the
        // assertion rather than a guess at when the person authenticated upstream.
        auth_time_secs: None,
        // THE SAME CLAIMS THE MAPPING WAS EVALUATED AGAINST, so a reader of the provisioned
        // identity and the mapping see one document. They are not ID-token claims and this build
        // has no second consumer of the field, but handing over a different set than the one the
        // traits came from is the kind of divergence that is invisible until it matters.
        claims,
    };

    let user_id = match provision_federated_user(
        state,
        scope,
        &connection.id.to_string(),
        &connection.idp_entity_id,
        &identity,
        &trait_doc,
        schema_version,
        // NO `ocn_` ORG CONNECTION. That column stamps the routed org connection a federated
        // login came through, and a SAML connection has no such row today. The organization is
        // recorded below, from the column the SAML connection actually carries.
        None,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(StoreError::TraitsInvalid(_)) => {
            tracing::warn!(
                target: "ironauth.saml",
                connection = %connection.id,
                "a SAML attribute mapping targets a trait an end user may not write",
            );
            return server_error();
        }
        Err(_) => return server_error(),
    };

    if ensure_membership(state, scope, connection, &user_id)
        .await
        .is_err()
    {
        return server_error();
    }

    let event = AuthenticationEvent::federated(epoch_micros(state.now()), &[], None);
    let actor = interaction::user_actor(&user_id);
    // THE CENTRAL LIFECYCLE FENCE IS THE ONLY THING between a blocked, disabled or waitlisted
    // account and a session here, exactly as on the federated callback: this path runs no
    // `can_authenticate` pre-check of its own, because the identity provider, not this server,
    // decided who the human is.
    // ONE ANSWER FOR A FENCED ACCOUNT AND FOR A FAULT, so this endpoint is not an account-state
    // oracle to whoever posted -- which on an ACS is anybody who can reach it.
    let Ok(cookies) =
        interaction::establish_session(state, scope, &user_id.to_string(), &event, actor, headers)
            .await
    else {
        return server_error();
    };

    interaction::redirect_setting_cookie(consumed.relay_state.as_deref().unwrap_or("/"), &cookies)
}

/// Evaluate the connection's attribute mapping against the assertion's claims.
///
/// SPLIT OUT BECAUSE IT IS THE HALF WITH NO SIDE EFFECTS: everything here reads configuration
/// and computes a document, and nothing it does is visible if the sign-in later fails. Returning
/// the rendered failure rather than an error type keeps all four of its distinct faults -- an
/// unreadable schema, a schema that will not compile, a column that is not a mapping, and a
/// mapping that does not evaluate -- answering with the one page they all deserve, while each
/// still logs the sentence that tells the operator which it was.
///
/// The second element is the active schema VERSION, which provisioning stamps on the identity so
/// a later reader knows which schema the stored traits were validated against.
async fn map_traits(
    state: &OidcState,
    scope: Scope,
    connection: &SamlConnection,
    claims: &Map<String, JsonValue>,
) -> Result<(TraitDocument, Option<i32>), Response> {
    // THE ACTIVE TRAIT SCHEMA, compiled once, exactly as the federated callback does. A schema
    // that will not compile is a server-side fault rather than a login the person can fix, so it
    // fails closed WITHOUT provisioning: half-provisioning on a bad schema would leave an
    // account that no later login can complete.
    let Ok(active_schema) = state.store().scoped(scope).trait_schemas().active().await else {
        return Err(server_error());
    };
    let compiled = match active_schema
        .as_ref()
        .map(|version| TraitSchema::compile(&version.schema_json))
    {
        Some(Ok(schema)) => Some(schema),
        Some(Err(_)) => return Err(server_error()),
        None => None,
    };

    let schema_view = compiled.as_ref().map(StoreTraitSchema);
    let schema_arg: Option<&dyn TraitSchemaView> = schema_view
        .as_ref()
        .map(|view| view as &dyn TraitSchemaView);

    // THE COLUMN IS JSON AND THE EVALUATOR TAKES A PARSED SHAPE, so the parse is here and its
    // failure is an operator fault rather than a person's. `ClaimMapping` is `deny_unknown_fields`
    // and `default`, so `{}` is a valid mapping meaning "map nothing", which is what a connection
    // an operator has not configured attributes on arrives with -- and which provisions a minimal
    // identity rather than refusing the login.
    //
    // IT WOULD BE BETTER REFUSED AT CONFIG TIME, which is the posture
    // `connectors::refuse_admin_only_claim_mapping` already takes on the OIDC side for the
    // neighbouring fault. There is no SAML connection-config surface to put it on yet: #140 owns
    // it. Until then a malformed column breaks the END USER for something only the operator can
    // fix, and saying so here is better than a comment implying the gate exists.
    let mapping: ClaimMapping = match serde_json::from_value(connection.attribute_mapping.clone()) {
        Ok(mapping) => mapping,
        Err(error) => {
            tracing::warn!(
                target: "ironauth.saml",
                connection = %connection.id,
                reason = %error,
                "a SAML connection's attribute_mapping column is not a claim mapping",
            );
            return Err(server_error());
        }
    };
    let trait_doc: TraitDocument = match evaluate(
        &mapping,
        &ironauth_connector::Quirks::default(),
        ClaimSources {
            id_token: claims,
            // NO SECOND SOURCE, AND THAT IS NOT A GAP. `userinfo` exists because an OIDC
            // connector may fetch claims from a second endpoint after the token exchange. A SAML
            // assertion is one document: everything the provider is willing to say arrives in
            // it, so a second source would have nothing to hold.
            userinfo: None,
        },
        schema_arg,
        None,
    ) {
        Ok(document) => document,
        // A MAPPING FAULT IS THE OPERATOR'S, NOT THE PERSON'S, and there is nothing the person
        // signing in can do about it -- so it is a server error to them and a log line naming
        // the connection for whoever configured it.
        Err(error) => {
            tracing::warn!(
                target: "ironauth.saml",
                connection = %connection.id,
                reason = %error,
                "a SAML connection's attribute mapping could not be evaluated",
            );
            return Err(server_error());
        }
    };

    Ok((
        trait_doc,
        active_schema.as_ref().map(|version| version.version),
    ))
}

/// The assertion as the shared mapper's claims object.
///
/// # Why a `Vec<Value>` becomes a scalar sometimes and an array other times
///
/// SAML gives every attribute a LIST of values, and almost every real attribute has exactly one.
/// A mapping that reads `email` wants the string, not `["ada@globex.example"]`, and every
/// connector mapping in this codebase is written against OIDC claims where a single value is a
/// scalar. Collapsing a one-element list is what makes one mapping language serve both.
///
/// AN EMPTY LIST IS `null`, NOT ABSENT. SAML says an `Attribute` with no values means "not
/// populated for this person", which a directory emits when a field is cleared. Dropping it
/// would make a cleared field indistinguishable from one the provider never sent, and a mapping
/// that clears a trait on the upstream clearing it is the behaviour an operator expects.
fn claims_from_assertion(consumed: &Consumed) -> Map<String, JsonValue> {
    let mut claims = Map::new();
    claims.insert(
        SUBJECT_CLAIM.to_owned(),
        JsonValue::String(consumed.accepted.name_id.clone()),
    );
    if let Some(format) = consumed.accepted.name_id_format.as_ref() {
        claims.insert(
            NAMEID_FORMAT_CLAIM.to_owned(),
            JsonValue::String(format.clone()),
        );
    }

    for attribute in &consumed.statement.attributes {
        // A PROVIDER-SUPPLIED `Name` THAT COLLIDES WITH `sub` DOES NOT WIN. The subject is the
        // one claim whose value the identity key is built from, and letting an attribute
        // overwrite it would let a provider name one person in the `NameID` and another in the
        // claims the mapping reads.
        if attribute.name == SUBJECT_CLAIM {
            continue;
        }
        let mut values = attribute.values.iter().filter_map(|value| match value {
            AttributeValue::Text(text) => Some(JsonValue::String(text.clone())),
            // A NON-TEXT VALUE IS SKIPPED RATHER THAN STRINGIFIED. Its Rust spelling is not
            // something a mapping can be written against, and rendering it would put a debug
            // form into somebody's identity traits.
            _ => None,
        });
        let mapped = match (values.next(), values.next()) {
            (None, _) => JsonValue::Null,
            (Some(single), None) => single,
            (Some(first), Some(second)) => {
                let mut all = vec![first, second];
                all.extend(values);
                JsonValue::Array(all)
            }
        };
        insert_at_path(&mut claims, &attribute.name, mapped);
    }
    claims
}

/// Insert `value` at the shared mapper's DOTTED PATH for `name`.
///
/// # Why this is not a flat insert
///
/// The shared evaluator resolves a rule's `source` with `resolve_path`, which SPLITS ON `.` and
/// descends. A flat insert therefore makes every SAML attribute whose `Name` contains a dot
/// unaddressable -- and a dotted `Name` is not an edge case in SAML, it is the norm: LDAP-derived
/// attributes arrive as `urn:oid:0.9.2342.19200300.100.1.3`, and Entra sends
/// `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, whose hostname has two.
/// An operator writing the attribute name they see in their identity provider would get a
/// mapping that silently resolves nothing, and a REQUIRED trait would fail every login with no
/// hint that the name was the problem.
///
/// Placing each attribute at the path its own `Name` splits into makes the name the operator
/// writes the name that resolves, for dotted and undotted alike -- an undotted name is a
/// one-segment path, so this is a flat insert for the ordinary case.
///
/// # The collision rule, and why the loser is the later one
///
/// Two attributes named `a` and `a.b` cannot both be placed: one needs `a` to be a scalar and the
/// other needs it to be an object. Document order decides, and a later attribute that cannot be
/// placed is DROPPED rather than overwriting what is there. Overwriting would make the resolved
/// value depend on an ordering the identity provider chooses, which is a worse failure than a
/// missing one: a missing required trait fails the login loudly, and a silently reordered one
/// signs somebody in as the wrong person's address.
fn insert_at_path(root: &mut Map<String, JsonValue>, name: &str, value: JsonValue) {
    let mut segments = name.split('.').peekable();
    let mut current = root;
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            current.entry(segment.to_owned()).or_insert(value);
            return;
        }
        let next = current
            .entry(segment.to_owned())
            .or_insert_with(|| JsonValue::Object(Map::new()));
        match next {
            JsonValue::Object(object) => current = object,
            // A SCALAR IS ALREADY THERE, so this attribute has nowhere to go. See the collision
            // rule above: the earlier one keeps its place.
            _ => return,
        }
    }
}

/// The mapped `email` trait, when the mapping produced one.
///
/// READ OUT OF THE MAPPED DOCUMENT rather than out of the raw attributes, because which
/// attribute carries an address is exactly what the per-connection mapping decides: Okta sends
/// `email`, Entra sends a schemas.xmlsoap.org URI, and an operator may map neither.
fn mapped_email(trait_doc: &TraitDocument) -> Option<String> {
    trait_doc
        .traits
        .get("email")
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
}

/// Record the person as a member of the connection's organization, if they are not already.
///
/// THE ORGANIZATION COMES FROM THE CONNECTION ROW, which is the whole point of migration 0196's
/// sentence that "a trust anchor that reached two organizations would let one customer's identity
/// provider assert another customer's users". The membership is what makes a SAML sign-in mean
/// the same thing as an OIDC one to every reader downstream of it.
///
/// IDEMPOTENT BY READ-THEN-WRITE, and a race between two assertions for the same new person is
/// the reason the read is not treated as authoritative: whichever loses the insert has a
/// membership either way, so a duplicate-key error is success rather than a failure to report.
async fn ensure_membership(
    state: &OidcState,
    scope: Scope,
    connection: &SamlConnection,
    user_id: &UserId,
) -> Result<(), StoreError> {
    let scoped = state.store().scoped(scope);
    if scoped
        .org_memberships()
        .for_user_in_org(&connection.organization_id, user_id)
        .await?
        .is_some()
    {
        return Ok(());
    }

    let actor = interaction::user_actor(user_id);
    let correlation = ironauth_store::CorrelationId::generate(state.env());
    let membership_id = OrgMembershipId::generate(state.env(), &scope);
    match scoped
        .acting(actor, correlation)
        .org_memberships()
        .create(
            state.env(),
            NewMembership {
                id: &membership_id,
                organization_id: &connection.organization_id,
                user_id,
                // NO METADATA. The row records that this person is in this organization; WHY is
                // recorded by the identity's own federated external id, which names the
                // connection's identity provider. Stamping a second, unvalidated copy here would
                // be a fact with two homes.
                metadata: None,
            },
            epoch_micros(state.now()),
            None,
        )
        .await
    {
        // THE RACE LOSER ALREADY HAS WHAT THIS FUNCTION EXISTS TO GUARANTEE, which is why a
        // conflict shares the success arm. Two assertions for one new person arrive together,
        // both read no membership, and one insert wins; the other must not fail a login over a
        // row that is now present.
        Ok(_) | Err(StoreError::Conflict) => Ok(()),
        Err(error) => Err(error),
    }
}

/// The generic failure this module answers with, which never says what broke.
fn server_error() -> Response {
    use axum::response::IntoResponse as _;

    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::response::Html(
            "<!doctype html><meta charset=\"utf-8\"><title>Sign-in unavailable</title>\
             <p>This response was accepted, but the sign-in could not be completed.</p>\
             <p>Try again; if it persists, your administrator should check this connection.</p>",
        ),
    )
        .into_response()
}
