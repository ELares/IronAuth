// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity chaining / ID-JAG, the receiving side's ADMISSION rules (issue #133, PROTOTYPE).
//!
//! # What this file can and cannot answer
//!
//! It drives `identity_chaining::admit` against verified tokens, so it answers what the three
//! extra checks accept and refuse. It says nothing about whether the jwt-bearer grant reaches
//! them; the grant's own DB-backed suite does that, and the distinction has produced a blocker
//! in every prototype in this series.
//!
//! # Why every refusal here is an attack
//!
//! The three checks are what make an identity assertion different from an ordinary bearer
//! assertion from the same trusted issuer:
//!
//! - without the MEDIA TYPE, an issuer trusted to federate a workload can speak for a user;
//! - without the CLIENT BINDING, the assertion is a bearer token for whoever intercepts it;
//! - without the SCOPE CEILING, a local subject mapping can widen what the authoritative domain
//!   granted.
//!
//! Each is driven by minting the honest assertion and changing exactly one thing.
//!
//! No database.

use ironauth_env::ManualClock;
use ironauth_jose::{
    EmissionOptions, ExpectedTyp, JwkSet, JwsAlgorithm, SigningKey, VerificationPolicy,
    VerifiedToken, sign_jws, trusted_keys_from_jwks, verify,
};
use ironauth_oidc::identity_chaining::{
    ID_JAG_DRAFT, ID_JAG_TYP, IDENTITY_CHAINING_DRAFT, IdentityAssertionRefusal, admit,
    is_identity_assertion,
};
use serde_json::{Value, json};

const REMOTE_ISSUER: &str = "https://idp.domain-a.example";
const LOCAL_AUDIENCE: &str = "https://ironauth.domain-b.example/t/acme/e/prod";
const PRESENTER: &str = "cli_the_calling_app";
const USER: &str = "alice@domain-a.example";
const NOW: u64 = 1_800_000_000;
/// Whether the presenter authenticated with a real credential. Every case below says yes
/// except `a_public_presenter_cannot_spend_an_identity_assertion`, which is the whole point of
/// the parameter: the client binding is only a control if satisfying it costs something.
const CONFIDENTIAL: bool = true;

fn key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("idp-kid".to_owned()), &[19_u8; 32]).expect("a key")
}

/// An assertion as domain A's IdP mints it, verified as this deployment would verify it.
fn assertion(typ: &str, claims: &Value) -> VerifiedToken {
    let token = sign_jws(
        &key(),
        serde_json::to_vec(claims)
            .expect("claims serialize")
            .as_slice(),
        &EmissionOptions::new().with_typ(typ), // invariant-allow: typ-via-declaration -- the ID-JAG media type is the DRAFT's, minted by a foreign IdP, not an IronAuth profile
    )
    .expect("sign");
    let trusted = trusted_keys_from_jwks(
        JwkSet::from_signing_keys([&key()])
            .expect("set")
            .to_json()
            .expect("json")
            .as_bytes(),
    );
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        trusted,
        REMOTE_ISSUER.to_owned(),
        LOCAL_AUDIENCE.to_owned(),
        // As the grant does: `typ` is not a separator the ordinary path reads, which is exactly
        // why the prototype has to check it AFTER verification.
        ExpectedTyp::ForeignIssuer,
    )
    .expect("a policy");
    let clock = ManualClock::new(std::time::UNIX_EPOCH + std::time::Duration::from_secs(NOW));
    verify(&token, &policy, &clock).expect("the assertion verifies")
}

fn claims(client: &str, scope: Option<&str>) -> Value {
    let mut body = json!({
        "iss": REMOTE_ISSUER,
        "sub": USER,
        "aud": LOCAL_AUDIENCE,
        "client_id": client,
        "iat": NOW - 10,
        "exp": NOW + 300,
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    body
}

/// The assertion as an honest IdP mints it.
///
/// The media type comes from `ID_JAG_TYP` rather than a literal, so this fixture alone would
/// keep passing if the constant were redefined. The literal spellings are pinned in
/// `an_ordinary_bearer_assertion_is_not_an_identity_assertion` below and again in
/// `tests/jwt_bearer.rs`, which re-spells it deliberately; do not remove either.
fn honest() -> VerifiedToken {
    assertion(
        ID_JAG_TYP,
        &claims(PRESENTER, Some("orders.read orders.write")),
    )
}

#[test]
fn an_honest_identity_assertion_is_admitted_with_the_scope_it_authorized() {
    let verified = honest();
    assert!(is_identity_assertion(&verified));
    assert_eq!(
        admit(&verified, PRESENTER, CONFIDENTIAL, None),
        Ok(vec!["orders.read".to_owned(), "orders.write".to_owned()]),
        "with no request of its own, the client gets exactly what the assertion authorized"
    );
}

#[test]
fn an_ordinary_bearer_assertion_is_not_an_identity_assertion() {
    // THE SEPARATOR. Without the media-type check, every assertion an issuer is trusted for is
    // also an identity assertion -- so an issuer registered to federate a CI workload could
    // present one that speaks for a person.
    for typ in ["JWT", "at+jwt", "oauth-id-jag", "id-jag+jwt"] {
        let verified = assertion(typ, &claims(PRESENTER, Some("orders.read")));
        assert!(
            !is_identity_assertion(&verified),
            "{typ} is not the media type"
        );
        assert_eq!(
            admit(&verified, PRESENTER, CONFIDENTIAL, None),
            Err(IdentityAssertionRefusal::NotAnIdentityAssertion)
        );
    }

    // And the spellings that ARE it, because the prefix is optional and case-insensitive.
    for typ in [
        "oauth-id-jag+jwt",
        "application/oauth-id-jag+jwt",
        "Application/OAUTH-ID-JAG+JWT",
    ] {
        let verified = assertion(typ, &claims(PRESENTER, Some("orders.read")));
        assert!(is_identity_assertion(&verified), "{typ} is the media type");
    }
}

#[test]
fn a_public_presenter_cannot_spend_an_identity_assertion() {
    // What makes the client binding below a control rather than a spelling requirement. A
    // public client authenticates by naming itself, so an interceptor reads the bound client id
    // off the stolen assertion and sends it: the binding costs nothing and the assertion is a
    // bearer token again.
    let verified = honest();
    assert_eq!(
        admit(&verified, PRESENTER, false, None),
        Err(IdentityAssertionRefusal::PresenterNotConfidential),
        "an assertion perfect in every other way is refused to a public presenter"
    );

    // The control: the SAME assertion, presented by a client that authenticated.
    assert!(
        admit(&verified, PRESENTER, CONFIDENTIAL, None).is_ok(),
        "and admitted once the presenter proved it is that client"
    );

    // The check runs AFTER the media type, so an ordinary bearer assertion from a public
    // client -- which this grant permits deliberately -- is refused as "not an identity
    // assertion" rather than for the presenter. That ordering is what keeps the ordinary path
    // untouched.
    let ordinary = assertion("JWT", &claims(PRESENTER, Some("orders.read")));
    assert_eq!(
        admit(&ordinary, PRESENTER, false, None),
        Err(IdentityAssertionRefusal::NotAnIdentityAssertion)
    );
}

#[test]
fn an_assertion_naming_another_client_is_refused() {
    // THE INTERCEPTION. The draft binds the assertion to the client that will present it, so
    // one captured by another client of this same deployment is inert. Without this the
    // assertion is a bearer token for whoever holds it.
    let verified = assertion(ID_JAG_TYP, &claims("cli_someone_else", Some("orders.read")));
    assert_eq!(
        admit(&verified, PRESENTER, CONFIDENTIAL, None),
        Err(IdentityAssertionRefusal::ClientMismatch)
    );

    // And one naming NOBODY is refused too: an unbound assertion is the same bearer token with
    // the binding left out rather than contradicted.
    let unbound = assertion(ID_JAG_TYP, &claims("", Some("orders.read")));
    assert_eq!(
        admit(&unbound, PRESENTER, CONFIDENTIAL, None),
        Err(IdentityAssertionRefusal::ClientMismatch)
    );
}

#[test]
fn the_assertions_scope_is_a_ceiling_and_not_a_default() {
    // THE CEILING. What the authoritative domain said the user authorized bounds what this one
    // issues; a receiving side that ignored it would let a local subject mapping widen a remote
    // grant, which is the whole trust story of a chain inverted.
    let verified = honest();

    // A subset is honoured.
    assert_eq!(
        admit(&verified, PRESENTER, CONFIDENTIAL, Some("orders.read")),
        Ok(vec!["orders.read".to_owned()])
    );

    // Anything outside it is refused, INCLUDING a request that merely adds to a valid subset --
    // a check that only looked at the first scope, or that intersected instead of refusing,
    // would pass this partially.
    assert_eq!(
        admit(
            &verified,
            PRESENTER,
            CONFIDENTIAL,
            Some("orders.read admin")
        ),
        Err(IdentityAssertionRefusal::ScopeExceedsAssertion)
    );
    assert_eq!(
        admit(&verified, PRESENTER, CONFIDENTIAL, Some("admin")),
        Err(IdentityAssertionRefusal::ScopeExceedsAssertion)
    );

    // An assertion carrying NO scope has no ceiling, so there is nothing to issue against.
    // Treating it as "everything the mapping allows" is exactly the widening above.
    let scopeless = assertion(ID_JAG_TYP, &claims(PRESENTER, None));
    assert_eq!(
        admit(&scopeless, PRESENTER, CONFIDENTIAL, None),
        Err(IdentityAssertionRefusal::NoScope)
    );
    let empty = assertion(ID_JAG_TYP, &claims(PRESENTER, Some("   ")));
    assert_eq!(
        admit(&empty, PRESENTER, CONFIDENTIAL, None),
        Err(IdentityAssertionRefusal::NoScope),
        "whitespace is not a scope"
    );
}

#[test]
fn the_pinned_draft_revisions_are_the_ones_the_acknowledgment_names() {
    // The cross-crate pin, from the side that can import both.
    assert_eq!(
        IDENTITY_CHAINING_DRAFT,
        "draft-ietf-oauth-identity-chaining-16"
    );
    assert_eq!(
        ID_JAG_DRAFT,
        "draft-ietf-oauth-identity-assertion-authz-grant-04"
    );
    assert_eq!(
        format!("{IDENTITY_CHAINING_DRAFT}+{ID_JAG_DRAFT}"),
        ironauth_config::IDENTITY_CHAINING_VERSION,
        "the acknowledgment names BOTH revisions, so either moving invalidates it"
    );
}
