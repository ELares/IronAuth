// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID Connect Native SSO for Mobile Apps 1.0, Implementer's Draft 2 (issue #133, PROTOTYPE).
//!
//! # The problem it exists for
//!
//! A vendor ships three apps on one phone. The person signs in to the first and is asked to sign
//! in again by the second, because on mobile there is no shared browser session to ride: each
//! app gets its own `ASWebAuthenticationSession` or Custom Tab, and the platforms have spent a
//! decade making sure one app cannot read another's cookies. That is the correct platform
//! behaviour and it is why the usual web answer does not exist here.
//!
//! Native SSO gives the family a shared secret instead of a shared cookie. The first app asks
//! for the `device_sso` scope and receives a **device secret** alongside its tokens. A sibling
//! app then presents *the first app's ID token together with that device secret* and receives
//! its OWN tokens, for the same person, without a second sign-in.
//!
//! # Why the ID token alone is not enough, and why that matters here
//!
//! An ID token is an authentication RECEIPT. It says a person signed in, and it is deliberately
//! not a credential: it is audienced to one client, it is often logged, and this deployment's
//! own token exchange refuses to accept one as a `subject_token` for exactly that reason.
//!
//! So the device secret is what makes the pair a credential, and `ds_hash` is what binds them:
//! the ID token carries the hash of the device secret it was issued beside, so a stolen ID token
//! is inert without the secret and a stolen secret is inert without the matching ID token. The
//! two must be presented together and must be about the same sign-in.
//!
//! That is the whole reason this prototype may relax the exchange's `subject_token_type` rule at
//! all, and it is why the relaxation is JOINT: admitting an ID token subject on its own would
//! be precisely the confused-deputy hole `check_request_shape` documents and refuses.
//!
//! # What is built here
//!
//! The two pure halves, so they can be tested without a database:
//!
//! - [`ds_hash`], the binding value, computed through the SAME primitive `at_hash` uses;
//! - [`admit`], the rule deciding whether an exchange request is a Native SSO one and whether
//!   the presented pair agrees.
//!
//! The storage, the issuance and the exchange wiring compose on these.
//!
//! # What a graduation still needs
//!
//! - **The `DPoP` binding decision.** The draft has an open question about whether the device
//!   secret should be sender-constrained. It is a bearer secret here, which is the draft's
//!   current shape and the sharpest edge in it.
//! - **No cross-device protection.** A device secret exfiltrated from one phone works from
//!   anywhere; nothing binds it to the device beyond the name.

use ironauth_jose::JwsAlgorithm;

/// The specification this prototype pins, exactly.
pub const NATIVE_SSO_SPEC: &str = "openid-connect-native-sso-1_0-ID2";

/// The scope a client asks for to receive a device secret.
///
/// The draft's own name. A client that does not ask gets no secret and nothing changes for it,
/// which is what keeps this inert for every existing client.
pub const DEVICE_SSO_SCOPE: &str = "device_sso";

/// The `actor_token_type` a sibling app presents its device secret under (draft section 3.2).
pub const DEVICE_SECRET_TOKEN_TYPE: &str = "urn:openid:params:token-type:device-secret";

/// The `subject_token_type` a sibling app presents the first app's ID token under (RFC 8693).
pub const ID_TOKEN_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";

/// The ID token claim binding the token to the device secret it was issued beside.
pub const DS_HASH_CLAIM: &str = "ds_hash";

/// The binding value: the left-most half of the digest of the device secret, base64url encoded.
///
/// The SAME construction and the SAME primitive as `at_hash` (OIDC Core 3.1.3.6), which is what
/// the draft specifies. It is [`crate::token_hash::left_half_hash`] rather than a local digest
/// for a reason this repository has already paid for once: a second hand-rolled copy of a vetted
/// comparison drifted from it and shipped a refusal of conforming input. A hash is worse, because
/// a drifted one does not refuse -- it simply never matches, and the failure looks like a client
/// bug.
///
/// `alg` is the ID token's signing algorithm, so the digest pairs with it exactly as `at_hash`
/// does.
#[must_use]
pub fn ds_hash(alg: JwsAlgorithm, device_secret: &str) -> String {
    crate::token_hash::left_half_hash(alg, device_secret)
}

/// Why a Native SSO exchange was refused.
///
/// Every variant answers the exchange's uniform error on the wire. They are distinguished for
/// the operator, not for the caller: which half of a presented pair was wrong is exactly what an
/// attacker probing the endpoint would want to learn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSsoRefusal {
    /// The request did not name BOTH the ID-token subject type and the device-secret actor
    /// type. Not a Native SSO exchange, and the caller gets the ordinary refusal for whatever
    /// it did name.
    NotNativeSso,
    /// The subject ID token carries no `ds_hash`, so it was not issued beside a device secret
    /// and nothing binds the pair. An ID token without it is an authentication receipt, and
    /// admitting one would make every ID token this deployment ever issued a credential.
    NoBinding,
    /// The presented device secret does not hash to the ID token's `ds_hash`. The two halves
    /// are from different sign-ins, which is what an attacker holding one of them produces.
    BindingMismatch,
}

/// Whether a request names the Native SSO pair, by its two token types.
///
/// BOTH or neither. A request naming only the ID-token subject type is not a partially formed
/// Native SSO exchange, it is the confused-deputy request the ordinary shape check refuses, and
/// this returning `true` for it would be the whole hole.
#[must_use]
pub fn is_native_sso_pair(subject_token_type: &str, actor_token_type: Option<&str>) -> bool {
    subject_token_type == ID_TOKEN_TOKEN_TYPE
        && actor_token_type.is_some_and(|actor| actor == DEVICE_SECRET_TOKEN_TYPE)
}

/// Check that a presented (ID token, device secret) pair is bound to each other.
///
/// `bound_ds_hash` is the `ds_hash` claim of an ID token this deployment has ALREADY VERIFIED.
/// The VALUE rather than the claim set, so this function cannot be handed an unverified payload
/// to read a claim out of: extracting it is the caller's step, and the caller is the only place
/// that has a verified token.
///
/// `alg` is the algorithm that ID token was signed with, so the digest matches the one stamped
/// at issuance.
///
/// # Errors
///
/// [`NativeSsoRefusal`]. Every variant is the same refusal on the wire.
pub fn admit(
    subject_token_type: &str,
    actor_token_type: Option<&str>,
    bound_ds_hash: Option<&str>,
    alg: JwsAlgorithm,
    presented_device_secret: &str,
) -> Result<(), NativeSsoRefusal> {
    if !is_native_sso_pair(subject_token_type, actor_token_type) {
        return Err(NativeSsoRefusal::NotNativeSso);
    }
    let bound = bound_ds_hash
        .filter(|hash| !hash.is_empty())
        .ok_or(NativeSsoRefusal::NoBinding)?;
    // Constant time, because this compares a value derived from a SECRET against one the caller
    // supplied half of. A byte-at-a-time comparison here leaks the expected hash one position
    // per request, and the whole point of `ds_hash` is that holding the ID token does not give
    // you the secret.
    let computed = ds_hash(alg, presented_device_secret);
    if !crate::client_auth::constant_time_eq(bound.as_bytes(), computed.as_bytes()) {
        return Err(NativeSsoRefusal::BindingMismatch);
    }
    Ok(())
}

/// How long a device secret stays redeemable.
///
/// Clamped at the mint rather than configured, for the same reason the transaction-token
/// prototype clamps its lifetime: this is a bearer credential for an app FAMILY, it cannot be
/// revoked by the apps holding it, and a deployment that set this to a year would have created a
/// year-long key to every sibling app's tokens. Thirty days is the draft's own suggestion and is
/// long enough that the feature does what it exists to do.
pub const DEVICE_SECRET_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// Whether a granted scope asks for a device secret.
///
/// Exact token match over whitespace, never a substring: `device_sso_admin` contains
/// `device_sso` and must not be read as asking for one.
#[must_use]
pub fn wants_device_secret(granted_scope: Option<&str>) -> bool {
    granted_scope.is_some_and(|scope| {
        scope
            .split_whitespace()
            .any(|token| token == DEVICE_SSO_SCOPE)
    })
}

/// The SHA-256 digest a device secret is STORED under.
///
/// Distinct from [`ds_hash`], which is the ID-token binding value, and the two are deliberately
/// different functions of the same input: `ds_hash` is truncated to half the digest and paired
/// with the ID token's signing algorithm (the draft requires that, because it follows
/// `at_hash`), while the stored digest is the full SHA-256 and independent of any algorithm. A
/// single value used for both would make the ID token's public `ds_hash` claim a lookup key into
/// the device-secret table.
#[must_use]
pub fn storage_digest(device_secret: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(device_secret.as_bytes());
    hasher.finalize().into()
}

/// What a sibling inherits from the sign-in the device secret came from.
///
/// The granted scope MINUS `device_sso` itself. The scope is a request for a device secret, and
/// app A already received one: passing it along would let every sibling mint a further secret
/// from a bootstrap, so one sign-in could fan out into an unbounded family of independent
/// credentials, each with its own thirty-day life. A sibling that genuinely needs its own secret
/// can ask for the scope in its own sign-in.
#[must_use]
pub fn inheritable_scope(granted_scope: &str) -> std::collections::BTreeSet<String> {
    granted_scope
        .split_whitespace()
        .filter(|token| *token != DEVICE_SSO_SCOPE)
        .map(ToOwned::to_owned)
        .collect()
}
