// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native SSO's binding rules (issue #133, PROTOTYPE).
//!
//! # What this file can and cannot answer
//!
//! It drives `native_sso::admit` and `native_sso::ds_hash` directly, so it answers what the
//! binding accepts and refuses. It says nothing about whether the token exchange reaches them,
//! which is the DB-backed suite's job -- and in this series that distinction has produced a
//! blocker in every prototype.
//!
//! # The property under test
//!
//! An ID token is an authentication RECEIPT, not a credential, and this deployment's exchange
//! refuses one as a `subject_token` for that reason. Native SSO may relax that ONLY because the
//! device secret travels with it and `ds_hash` binds the two: a stolen ID token is inert without
//! the secret, and a stolen secret is inert without the matching ID token.
//!
//! So the tests below are all about the pair. Each mints the honest pair and breaks exactly one
//! thing.
//!
//! No database.

use ironauth_jose::JwsAlgorithm;
use ironauth_oidc::native_sso::{
    DEVICE_SECRET_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, NATIVE_SSO_SPEC, NativeSsoRefusal, admit,
    ds_hash, is_native_sso_pair,
};

const SECRET: &str = "ds_a7f3c1e9b2d84610a5c7e3f1b9d2648a";
const ALG: JwsAlgorithm = JwsAlgorithm::EdDsa;

/// The `ds_hash` an ID token carries when it was issued beside `secret`.
fn bound(secret: &str) -> String {
    ds_hash(ALG, secret)
}

#[test]
fn the_honest_pair_is_admitted() {
    assert_eq!(
        admit(
            ID_TOKEN_TOKEN_TYPE,
            Some(DEVICE_SECRET_TOKEN_TYPE),
            Some(bound(SECRET).as_str()),
            ALG,
            SECRET,
        ),
        Ok(())
    );
}

#[test]
fn both_token_types_are_required_and_neither_alone_will_do() {
    // THE HOLE THIS PROTOTYPE MUST NOT OPEN. The exchange refuses an ID token as a
    // `subject_token` deliberately: it is an authentication receipt for one client, not a
    // credential to trade. Native SSO relaxes that only for the PAIR, so a request naming the
    // ID-token subject type WITHOUT the device-secret actor type must not be recognized as a
    // partially formed Native SSO exchange -- it is exactly the confused-deputy request the
    // ordinary shape check exists to refuse.
    let claims = bound(SECRET);

    assert!(!is_native_sso_pair(ID_TOKEN_TOKEN_TYPE, None));
    assert_eq!(
        admit(
            ID_TOKEN_TOKEN_TYPE,
            None,
            Some(claims.as_str()),
            ALG,
            SECRET
        ),
        Err(NativeSsoRefusal::NotNativeSso),
        "an ID token subject with no device secret is not a Native SSO exchange"
    );

    // And the actor type alone, over an ordinary access-token subject: also not this.
    assert!(!is_native_sso_pair(
        "urn:ietf:params:oauth:token-type:access_token",
        Some(DEVICE_SECRET_TOKEN_TYPE)
    ));
    assert_eq!(
        admit(
            "urn:ietf:params:oauth:token-type:access_token",
            Some(DEVICE_SECRET_TOKEN_TYPE),
            Some(claims.as_str()),
            ALG,
            SECRET,
        ),
        Err(NativeSsoRefusal::NotNativeSso)
    );

    // A device secret presented under some OTHER actor type is not it either. The types are
    // the declaration RFC 8693 requires; sniffing the value would be the thing that section
    // exists to stop.
    assert!(!is_native_sso_pair(
        ID_TOKEN_TOKEN_TYPE,
        Some("urn:ietf:params:oauth:token-type:access_token")
    ));

    // Only the exact pair.
    assert!(is_native_sso_pair(
        ID_TOKEN_TOKEN_TYPE,
        Some(DEVICE_SECRET_TOKEN_TYPE)
    ));
}

#[test]
fn an_id_token_with_no_ds_hash_is_refused() {
    // EVERY ID TOKEN THIS DEPLOYMENT HAS EVER ISSUED lacks `ds_hash`, because the claim is
    // stamped only beside a device secret. If a missing binding were read as "unbound, so
    // allow", every one of them would become a credential redeemable for a sibling app's
    // tokens -- which is the entire risk of relaxing the subject type.
    assert_eq!(
        admit(
            ID_TOKEN_TOKEN_TYPE,
            Some(DEVICE_SECRET_TOKEN_TYPE),
            None,
            ALG,
            SECRET,
        ),
        Err(NativeSsoRefusal::NoBinding)
    );

    // An EMPTY one is not a binding either: a bound-satisfied-by-empty check would admit any
    // secret against a token carrying `"ds_hash": ""`.
    assert_eq!(
        admit(
            ID_TOKEN_TOKEN_TYPE,
            Some(DEVICE_SECRET_TOKEN_TYPE),
            Some(""),
            ALG,
            SECRET,
        ),
        Err(NativeSsoRefusal::NoBinding)
    );
}

#[test]
fn a_secret_from_another_sign_in_does_not_open_this_id_token() {
    // THE THEFT. An attacker with one half of the pair has nothing: the ID token is bound to
    // the secret it was issued beside, so a different secret -- from another sign-in, another
    // device, or invented -- does not match.
    let claims = bound(SECRET);
    for wrong in [
        "ds_0000000000000000000000000000000000",
        "",
        SECRET.trim_end_matches('a'),
        &format!("{SECRET}a"),
    ] {
        assert_eq!(
            admit(
                ID_TOKEN_TOKEN_TYPE,
                Some(DEVICE_SECRET_TOKEN_TYPE),
                Some(claims.as_str()),
                ALG,
                wrong,
            ),
            Err(NativeSsoRefusal::BindingMismatch),
            "{wrong:?} must not open an ID token bound to a different secret"
        );
    }
}

#[test]
fn the_binding_is_algorithm_paired_exactly_as_at_hash_is() {
    // `ds_hash` follows `at_hash`: the digest pairs with the ID TOKEN's signing algorithm. A
    // token signed with one and verified against another produces a different hash, so the
    // algorithm has to travel with the claims rather than be assumed.
    let claims = bound(SECRET);
    assert_eq!(
        admit(
            ID_TOKEN_TOKEN_TYPE,
            Some(DEVICE_SECRET_TOKEN_TYPE),
            Some(claims.as_str()),
            JwsAlgorithm::Rs256,
            SECRET,
        ),
        Err(NativeSsoRefusal::BindingMismatch),
        "the same secret under a different algorithm is a different hash, and admitting it \
         would mean the digest choice is not part of the binding"
    );

    // And the hashes really do differ, so the case above is not passing for some other reason.
    assert_ne!(
        ds_hash(JwsAlgorithm::EdDsa, SECRET),
        ds_hash(JwsAlgorithm::Rs256, SECRET)
    );
}

#[test]
fn the_pinned_specification_revision_is_the_one_the_acknowledgment_names() {
    assert_eq!(NATIVE_SSO_SPEC, "openid-connect-native-sso-1_0-ID2");
}
