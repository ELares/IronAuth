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
//!    account in it. NOTHING HERE RESOLVES AN IDENTIFIER: the local user is keyed on
//!    [`saml_external_id`], which namespaces the `NameID` by the CONNECTION.
//!
//!    THE CONNECTION, NOT ITS `idp_entity_id`, and an earlier version of this module used the
//!    entity id and was wrong. Migration 0196 makes `idp_entity_id` unique per `(tenant,
//!    environment, ORGANIZATION)` and its own comment explains why: "a customer with two
//!    organizations in this environment signs both into their ONE identity provider tenant, so
//!    both connections carry the same `idp_entity_id`". Two connections in different
//!    organizations may therefore share that string while pinning DIFFERENT certificates, and
//!    keying on it collapsed them to one local user -- so whoever held the second connection's
//!    key could sign in as the first organization's people. The connection id is unique per
//!    scope and IS the trust boundary: one connection is one set of pinned certificates in one
//!    organization.
//! 2. IT BYPASSED THE CRATE'S ANTI-TAKEOVER GATE. `account_linking` decides whether an upstream
//!    identity may be MERGED into an existing local account, and answers `AutoLink` from exactly
//!    one arm. This module never asks, because it never merges: it takes the branch the
//!    federated callback calls the safe default, provisioning a separate identity keyed on the
//!    composite. Offering the link is a decision an operator has not been given a surface for.
//! 3. THE POPULATION IT NAMED COULD NOT USE IT. Requiring a VERIFIED local identifier would sign
//!    in none of the accounts this exists to serve, because the SCIM inbound server in this same
//!    milestone deliberately writes `verified: false`. Nothing here requires one: a first
//!    assertion CREATES the person.
//! 4. ITS ONLY REACHABLE MODE WAS THE ONE #139 REQUIRES OFF. That objection is spent: the start
//!    endpoint issues real `AuthnRequest`s, so a solicited response is the ordinary case.
//!
//! # The order of the writes is load-bearing
//!
//! THE LIFECYCLE FENCE COMES BEFORE THE ORGANIZATION MEMBERSHIP, and an earlier version had it
//! the other way. `establish_session` is where a blocked, disabled or waitlisted account is
//! refused, and it is the ONLY such check on this path -- the identity provider, not this
//! server, decided who the human is. Joining somebody to an organization before that check runs
//! means an unauthenticated cross-site POST writes an org membership for an account this
//! deployment refuses to authenticate. The membership is therefore written AFTER the session is
//! minted, so nothing lands for a person who is not admitted.
//!
//! A LIVE IDENTITY PROVIDER ACCOUNT RE-JOINS THE ORGANIZATION on its next login, because that is
//! what just-in-time provisioning means: the directory is the source of truth for who belongs.
//! An operator who wants somebody out removes them upstream, disables the local account, or
//! disables the connection -- and each of those is enforced before this line is reached.
//!
//! # The mapper is the shared one, and that is a criterion rather than a preference
//!
//! #139 requires attribute mapping and `NameID` handling to "round-trip through the shared JIT
//! mapper with per-connection config". The mapper is
//! [`ironauth_connector::claim_mapping::evaluate`] -- the same function, not a parallel one --
//! and the per-connection config is the `attribute_mapping` column. What this module supplies is
//! the ADAPTER: a SAML assertion is a list of `Attribute` elements and a `NameID`, and the
//! evaluator reads a JSON claims object, so [`claims_from_assertion`] is where one becomes the
//! other. Everything downstream of that call is the OIDC path verbatim.
//!
//! # What this does not do
//!
//! It does not consult `account_linking`, for the reason above. It does not capture upstream
//! tokens: there are none, because SAML returns an assertion rather than a token grant. It does
//! not apply the broker overlay, which reads an `ocn_` org connection this connection has no row
//! in -- discovery routing is the change that gives SAML one.

use axum::http::HeaderMap;
use axum::response::Response;
use ironauth_connector::ClaimMapping;
use ironauth_connector::claim_mapping::{ClaimSources, TraitDocument, TraitSchemaView, evaluate};
use ironauth_saml::attributes::Value as AttributeValue;
use ironauth_store::{
    CorrelationId, NewMembership, OrgMembershipId, SamlConnection, Scope, StoreError, TraitSchema,
    UserId,
};
use serde_json::{Map, Value as JsonValue};

use crate::authn::AuthenticationEvent;
use crate::federation::{StoreTraitSchema, provision_federated_user};
use crate::interaction;
use crate::saml_acs::Consumed;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The claim name the `NameID` arrives under.
///
/// `sub`, BECAUSE THAT IS WHAT THE SHARED MAPPER'S DEFAULT SUBJECT RULE READS. The evaluator
/// resolves its subject from `sub` unless a mapping names another field, so putting the `NameID`
/// anywhere else would make every connection that does not override the rule fail to resolve a
/// subject at all.
const SUBJECT_CLAIM: &str = "sub";

/// The claim name the `NameID`'s `Format` arrives under, when the assertion carried one.
const NAMEID_FORMAT_CLAIM: &str = "nameid_format";

/// The `NameID` formats that name a DIFFERENT string on every login.
///
/// REFUSED, BECAUSE AN IDENTITY KEY THAT CHANGES IS NOT AN IDENTITY. SAML Core 8.3.8 says a
/// `transient` identifier has no meaning beyond the session it was issued for, and a conformant
/// identity provider mints a fresh opaque value each time. Keyed on that, every login provisions
/// a NEW local user and a NEW organization membership, so a person signing in daily accumulates
/// an account a day and an operator's member list fills with strangers who are all one person.
///
/// THE REFUSAL IS HERE RATHER THAN AT THE ASSERTION, deliberately: `saml_acs` compares the
/// document's `Format` to the connection's column and is right to admit a transient one, because
/// the assertion IS well formed. What cannot be done with it is name somebody durably, and that
/// is this module's question. The connection's column also travels outward -- the metadata
/// document advertises it and every `AuthnRequest` carries it as `NameIDPolicy` -- so a
/// connection configured this way is asking its provider for exactly what it cannot use.
const UNUSABLE_NAMEID_FORMATS: [&str; 1] = ["urn:oasis:names:tc:SAML:2.0:nameid-format:transient"];

/// The local identity key for a `NameID` on a connection.
///
/// NAMESPACED BY THE CONNECTION, which is the trust boundary: one connection is one set of
/// pinned certificates belonging to one organization. See objection 1 in the module doc for what
/// namespacing by `idp_entity_id` did instead.
///
/// A DISTINCT PREFIX FROM THE OIDC ONE, so the two can never collide. `federated_external_id`
/// builds `federated:v1:...` from an OIDC connector's ISSUER, and SAML entity ids are commonly
/// issuer-shaped URLs -- so sharing the prefix would let a SAML connection whose `idp_entity_id`
/// was set to an existing connector's issuer resolve that connector's users. The lengths are
/// interleaved for the same reason they are in the federated form: without them, a key is a
/// concatenation that two different pairs can produce.
#[must_use]
pub fn saml_external_id(connection_id: &str, name_id: &str) -> String {
    format!(
        "saml:v1:{}:{connection_id}:{}:{name_id}",
        connection_id.len(),
        name_id.len()
    )
}

/// Why an assertion could not be turned into a claims object.
///
/// ONE VARIANT, CARRYING THE NAME THAT COLLIDED, because every case is the same operator-visible
/// fault: two things want one key. See [`claims_from_assertion`] for why that is refused rather
/// than resolved.
struct ClaimsConflict {
    name: String,
}

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
    // A FORMAT THAT NAMES A DIFFERENT STRING EVERY TIME cannot key an account. Refused before
    // anything is written, because the first write is what would create the duplicate.
    if UNUSABLE_NAMEID_FORMATS.contains(&connection.nameid_format.as_str()) {
        tracing::warn!(
            target: "ironauth.saml",
            connection = %connection.id,
            format = %connection.nameid_format,
            "a SAML connection asks its identity provider for a NameID format that cannot \
             identify anybody across logins",
        );
        return server_error();
    }

    let claims = match claims_from_assertion(consumed) {
        Ok(claims) => claims,
        Err(conflict) => {
            tracing::warn!(
                target: "ironauth.saml",
                connection = %connection.id,
                name = %conflict.name,
                "a SAML assertion carries two values for one claim name, so which one a mapping \
                 would read is not decidable",
            );
            return server_error();
        }
    };
    let (trait_doc, schema_version) = match map_traits(state, scope, connection, &claims).await {
        Ok(mapped) => mapped,
        Err(response) => return response,
    };

    // NO `VerifiedUpstreamIdentity`. An earlier version built one, filling `email` from the
    // mapped document and writing paragraphs justifying an empty `amr`, `acr` and `auth_time`.
    // None of it reached a write: the shared provisioner read the struct exactly twice, both
    // `subject`, to build the two values this now passes directly. The struct is gone from its
    // signature, so the dead fields cannot come back unnoticed.
    //
    // THE KEY AND THE HANDLE ARE BUILT HERE, not inside the shared provisioner, because they are
    // the one thing the two federation protocols must NOT share. See [`saml_external_id`].
    let external_id = saml_external_id(&connection.id.to_string(), &consumed.accepted.name_id);
    let handle = format!("saml:{}:{}", connection.id, consumed.accepted.name_id);

    let user_id = match provision_federated_user(
        state,
        scope,
        &external_id,
        &handle,
        &trait_doc,
        schema_version,
        // NO `ocn_` ORG CONNECTION. That column stamps the routed org connection a federated
        // login came through, and a SAML connection has no such row today. The organization is
        // recorded below, from the column the SAML connection carries.
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

    let event = AuthenticationEvent::federated(epoch_micros(state.now()), &[], None);
    let actor = interaction::user_actor(&user_id);
    // THE CENTRAL LIFECYCLE FENCE IS THE ONLY THING between a blocked, disabled or waitlisted
    // account and a session here, exactly as on the federated callback: this path runs no
    // `can_authenticate` pre-check of its own, because the identity provider, not this server,
    // decided who the human is.
    let cookies = match interaction::establish_session(
        state,
        scope,
        &user_id.to_string(),
        &event,
        actor,
        headers,
    )
    .await
    {
        Ok(cookies) => cookies,
        // A REFUSED ACCOUNT AND A BROKEN DATABASE ARE DIFFERENT ANSWERS, and an earlier version
        // collapsed them into one 500 under a "not an account-state oracle" heading. That
        // reversed the decision the federated callback makes on the same fence: it answers an
        // ordinary refusal page for a fenced account and a 500 only for a fault. Reporting a
        // server fault for a deliberate administrative state sends an operator hunting a bug.
        // Neither page names a lifecycle state, so neither is an oracle; what differs is which
        // of them is true.
        Err(interaction::EstablishSessionError::NotAuthenticatable) => return refused_account(),
        Err(interaction::EstablishSessionError::Store) => return server_error(),
    };

    // AFTER THE FENCE. See "the order of the writes is load-bearing" in the module doc.
    if ensure_membership(state, scope, connection, &user_id)
        .await
        .is_err()
    {
        return server_error();
    }

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
    // failure is an operator fault rather than a person's. `ClaimMapping` is
    // `deny_unknown_fields` and `default`, so `{}` is a valid mapping meaning "map nothing",
    // which is what a connection an operator has configured no attributes on arrives with --
    // and which provisions a minimal identity rather than refusing the login.
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

/// The assertion as the shared mapper's claims object, or the name that two values wanted.
///
/// # Why a `Vec<Value>` becomes a scalar sometimes and an array other times
///
/// SAML gives every attribute a LIST of values, and almost every real attribute has exactly one.
/// A mapping that reads `email` wants the string, not `["ada@globex.example"]`, and every
/// connector mapping in this codebase is written against OIDC claims where a single value is a
/// scalar. Collapsing a one-element list is what makes one mapping language serve both.
///
/// # Why a collision is a refusal and not a choice
///
/// Three different things can want one key: the `NameID` and an attribute literally named `sub`;
/// two `Attribute` elements sharing a `Name` (SAML admits them as distinct when their
/// `NameFormat` differs, and the claims object has nowhere to put the format); and an attribute
/// named `a` beside one named `a.b`, which the dotted path below cannot hold at once.
///
/// AN EARLIER VERSION PICKED THE FIRST ONE SILENTLY and justified it as avoiding a value that
/// "depends on an ordering the identity provider chooses". It does not avoid that: first-wins
/// and last-wins BOTH select by the order the provider chose, so the justification did not
/// distinguish the rule it defended from the one it rejected. What it did do was hand a mapping
/// author a value they did not ask for -- an operator who maps `email` and gets the `NameID`, or
/// the wrong one of two `email` attributes, sees a login that works and an identity that is
/// subtly the wrong person's.
///
/// So a collision refuses the whole sign-in. It is deterministic, it names the key in the log,
/// and the operator's fix -- remap, or ask their provider to stop sending the duplicate -- is
/// one they can only make if they are told.
fn claims_from_assertion(consumed: &Consumed) -> Result<Map<String, JsonValue>, ClaimsConflict> {
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
        let mut values = attribute.values.iter().filter_map(|value| match value {
            AttributeValue::Text(text) => Some(JsonValue::String(text.clone())),
            // A NON-TEXT VALUE IS SKIPPED RATHER THAN STRINGIFIED. Its Rust spelling is not
            // something a mapping can be written against, and rendering it would put a debug
            // form into somebody's identity traits.
            _ => None,
        });
        let mapped = match (values.next(), values.next()) {
            // AN ATTRIBUTE WITH NO USABLE VALUES IS NOT INSERTED. SAML says an empty `Attribute`
            // means "not populated for this person", and an earlier version inserted JSON `null`
            // to preserve that against "the provider sent nothing". The shared evaluator's
            // `resolve_rule` skips a resolved `null` exactly as it skips an absent key, so the
            // distinction reached no consumer -- and a key present with a null value would still
            // COLLIDE with a later attribute of the same name, refusing a sign-in over a value
            // nothing could read.
            (None, _) => continue,
            (Some(single), None) => single,
            (Some(first), Some(second)) => {
                let mut all = vec![first, second];
                all.extend(values);
                JsonValue::Array(all)
            }
        };
        insert_at_path(&mut claims, &attribute.name, mapped)?;
    }
    Ok(claims)
}

/// Insert `value` at the shared mapper's DOTTED PATH for `name`, or name the key that collided.
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
fn insert_at_path(
    root: &mut Map<String, JsonValue>,
    name: &str,
    value: JsonValue,
) -> Result<(), ClaimsConflict> {
    let conflict = || ClaimsConflict {
        name: name.to_owned(),
    };
    let mut segments = name.split('.').peekable();
    let mut current = root;
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            if current.contains_key(segment) {
                return Err(conflict());
            }
            current.insert(segment.to_owned(), value);
            return Ok(());
        }
        let next = current
            .entry(segment.to_owned())
            .or_insert_with(|| JsonValue::Object(Map::new()));
        match next {
            JsonValue::Object(object) => current = object,
            // A SCALAR IS ALREADY AT AN INTERIOR SEGMENT, so `a` and `a.b` both want `a`.
            _ => return Err(conflict()),
        }
    }
    Ok(())
}

/// Record the person as a member of the connection's organization, if they are not already.
///
/// THE ORGANIZATION COMES FROM THE CONNECTION ROW, which is the whole point of migration 0196's
/// sentence that "a trust anchor that reached two organizations would let one customer's identity
/// provider assert another customer's users". The membership is what makes a SAML sign-in mean
/// the same thing as an OIDC one to every reader downstream of it.
///
/// IT EMITS `organization.member_added`, and an earlier version called the four-argument
/// `create`, which forwards no event. That is not cosmetic: the outbound SCIM push shipped in
/// this same milestone drives its steady state entirely from the event feed, so a membership
/// committed without an envelope is a person who exists in this deployment and never reaches the
/// downstream directory. A JIT membership is exactly the case that push exists to carry.
///
/// IDEMPOTENT IN THE STORE, WITH NO PRE-READ. An earlier version read `for_user_in_org` first
/// and returned early, and a test claimed to measure that guard -- but deleting it changed no
/// answer, because `create`'s own `INSERT ... ON CONFLICT DO NOTHING` already returns the same
/// conflict for a live row, which this treats as success. A branch whose removal is invisible is
/// not a guard, it is a second copy of one, and the copy could drift: it sees only LIVE rows
/// while the insert also revives soft-deleted ones, so the two disagreed about a person an
/// operator had removed.
///
/// So the race is handled where races belong. Two assertions for one new person arrive together,
/// one insert wins, and the loser has a membership either way.
async fn ensure_membership(
    state: &OidcState,
    scope: Scope,
    connection: &SamlConnection,
    user_id: &UserId,
) -> Result<(), StoreError> {
    let scoped = state.store().scoped(scope);
    let membership_id = OrgMembershipId::generate(state.env(), &scope);
    let subject = membership_id.to_string();
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "organization.member_added",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        epoch_micros(state.now()) / 1000,
        &serde_json::json!({
            "membership_id": subject,
            "organization_id": connection.organization_id.to_string(),
            "user_id": user_id.to_string(),
        }),
    );
    let domain_event = envelope
        .as_ref()
        .map(|envelope| ironauth_store::DomainEvent {
            id: &event_id,
            subject: &subject,
            envelope,
        });

    let actor = interaction::user_actor(user_id);
    let correlation = CorrelationId::generate(state.env());
    match scoped
        .acting(actor, correlation)
        .org_memberships()
        .create_with_event(
            state.env(),
            NewMembership {
                id: &membership_id,
                organization_id: &connection.organization_id,
                user_id,
                // NO METADATA. The row records that this person is in this organization; WHY is
                // recorded by the identity's own external id, which names the connection.
                metadata: None,
            },
            epoch_micros(state.now()),
            None,
            domain_event.as_ref(),
            None,
        )
        .await
    {
        // THE RACE LOSER ALREADY HAS WHAT THIS FUNCTION EXISTS TO GUARANTEE, which is why a
        // conflict shares the success arm.
        Ok(_) | Err(StoreError::Conflict) => Ok(()),
        Err(error) => Err(error),
    }
}

/// The page for an account this deployment will not authenticate.
///
/// IT NAMES NO LIFECYCLE STATE: waitlisted, blocked, disabled and deleted are one answer, so
/// this is not an oracle. What it is not is a 500, which would report a server fault for a
/// deliberate administrative decision.
fn refused_account() -> Response {
    page(
        axum::http::StatusCode::FORBIDDEN,
        "<p>This response was accepted, but this account cannot sign in here.</p>\
         <p>Contact your administrator.</p>",
    )
}

/// The generic failure this module answers with, which never says what broke.
fn server_error() -> Response {
    page(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "<p>This response was accepted, but the sign-in could not be completed.</p>\
         <p>Try again; if it persists, your administrator should check this connection.</p>",
    )
}

/// An uncacheable outcome page carrying `body`, which is always a sentence written in this file.
fn page(status: axum::http::StatusCode, body: &'static str) -> Response {
    use axum::response::IntoResponse as _;

    (
        status,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::response::Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Sign-in unavailable</title>{body}"
        )),
    )
        .into_response()
}
