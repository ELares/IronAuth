// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minting the ID token and the access token through the one signing core.
//!
//! Both tokens are compact JWSs signed by [`ironauth_jose::sign_jws`] with the
//! target environment's signing key, so every token IronAuth issues round-trips
//! through the same hardened verify path.
//!
//! # The ID token's conditional claims (issue #14)
//!
//! Beyond the REQUIRED claims (`iss`, `sub`, `aud`, `exp`, `iat`), the ID token
//! carries the OIDC Core errata set 2 conditional claims:
//!
//! - `sub` is capped at 255 ASCII characters and refused (never truncated) at
//!   issuance if it violates the cap (see [`crate::subject::subject_within_cap`]).
//! - `nonce` is echoed EXACTLY when the authorization request carried one, and is
//!   absent otherwise.
//! - `auth_time` is emitted when the request asked for `max_age` or the client
//!   registered `require_auth_time`, and is always the truthful recorded
//!   authentication instant. The decision is frozen onto the code at issuance:
//!   the code carries `auth_time` ONLY when it is due, so here it is emitted iff
//!   present.
//! - `acr` and `amr` are DERIVED from the recorded authentication event's
//!   methods ([`crate::authn`]), never from a request parameter.
//! - `azp` is omitted: the code flow's ID token has a single audience equal to
//!   the authorized party and uses no extension beyond Core (errata set 2 §2).
//! - `at_hash` and `c_hash` are computed by [`crate::token_hash`] and consumed by
//!   the front-channel/hybrid path (issue #17); a token-endpoint ID token never
//!   carries `at_hash`, and the code flow never carries `c_hash`. They are wired
//!   as optional inputs here so #17 can supply them without a second minter.

use std::time::SystemTime;

use ironauth_jose::{EmissionOptions, SigningKey, sign_jws};
use ironauth_store::{IssuedTokenId, Scope, TokenKind};
use serde_json::json;

use crate::authn;
use crate::state::OidcState;
use crate::subject;

/// The tokens minted for one successful code exchange, plus the recorded `jti`s
/// so the caller can persist them against the grant.
pub struct IssuedTokens {
    /// The compact access-token JWS.
    pub access_token: String,
    /// The compact ID-token JWS.
    pub id_token: String,
    /// The access token's `jti` (recorded against the grant).
    pub access_jti: IssuedTokenId,
    /// The ID token's `jti` (recorded against the grant).
    pub id_jti: IssuedTokenId,
    /// The access-token lifetime in seconds (the `expires_in` of the response).
    pub expires_in_secs: i64,
}

/// Everything the claims need that is specific to one exchange.
pub struct MintRequest<'a> {
    /// The `(tenant, environment)` scope the tokens belong to.
    pub scope: Scope,
    /// The per-environment issuer.
    pub issuer: &'a str,
    /// The authenticated end-user subject.
    pub subject: &'a str,
    /// The client the tokens are for (the ID token audience and the access
    /// token's `client_id`).
    pub client_id: &'a str,
    /// The bound OIDC `nonce`, echoed into the ID token when present.
    pub nonce: Option<&'a str>,
    /// The granted OAuth `scope` value, echoed into the access token when present.
    pub oauth_scope: Option<&'a str>,
    /// The recorded authentication method tokens (space-separated RFC 8176
    /// values), the single source `amr` and the achieved `acr` derive from.
    pub auth_methods: &'a str,
    /// The recorded authentication instant in epoch microseconds, present ONLY
    /// when the ID token must carry `auth_time`; [`None`] omits the claim.
    pub auth_time_unix_micros: Option<i64>,
    /// The access-token hash for a front-channel ID token (issue #17). The token
    /// endpoint always passes [`None`]: a token-endpoint ID token never carries
    /// `at_hash`.
    pub at_hash: Option<&'a str>,
    /// The authorization-code hash for a hybrid ID token (issue #17). The code
    /// flow always passes [`None`]: it never carries `c_hash`.
    pub c_hash: Option<&'a str>,
    /// Extra standard claims to place in the ID token (issue #15): the claims the
    /// `claims` request parameter's `id_token` member selected, and (only when the
    /// environment sets the non-conform `conformIdTokenClaims`) the scope-derived
    /// claims. Empty by default, so the spec-conform ID token stays lean and these
    /// claims are served from `UserInfo` instead. Protocol/REQUIRED claims always
    /// win: an entry whose name is already set (for example `sub`) is never
    /// overwritten.
    pub extra_claims: &'a serde_json::Map<String, serde_json::Value>,
}

/// Why building the ID token claims failed. Every variant is fail-closed at
/// issuance (the caller maps it to an opaque `server_error`) and none leaks the
/// offending value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdTokenError {
    /// The `sub` exceeds the 255 ASCII-character cap or is not ASCII. Refused
    /// rather than truncated (a truncated subject could collide two users).
    SubjectOutOfBounds,
}

/// Build the ID token claim set (OIDC Core errata set 2), enforcing the `sub`
/// cap and the conditional claim rules. Pure: it takes the already-resolved
/// instants and identifiers, so it is exercised without a store or a signer.
///
/// # Errors
///
/// [`IdTokenError::SubjectOutOfBounds`] if `subject` violates the 255 ASCII
/// cap; issuance fails closed rather than truncating.
pub(crate) fn build_id_token_claims(
    request: &MintRequest<'_>,
    iat: i64,
    exp: i64,
    jti: &str,
) -> Result<serde_json::Value, IdTokenError> {
    // sub cap: refuse, never truncate (OIDC Core errata set 2 §2).
    if !subject::subject_within_cap(request.subject) {
        return Err(IdTokenError::SubjectOutOfBounds);
    }

    // The REQUIRED claims (iss, sub, aud, exp, iat) plus the recorded jti.
    let mut claims = json!({
        "iss": request.issuer,
        "sub": request.subject,
        "aud": request.client_id,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    });

    // nonce: echoed EXACTLY when the request carried one, absent otherwise.
    if let Some(nonce) = request.nonce {
        claims["nonce"] = json!(nonce);
    }

    // acr and amr: DERIVED from the recorded authentication event, never from a
    // request parameter. amr reflects the factors actually used; acr is the
    // achieved level (never a copied-through requested value).
    let methods = authn::parse_methods(request.auth_methods);
    claims["amr"] = json!(authn::amr_values(&methods));
    claims["acr"] = json!(authn::achieved_acr(&methods));

    // auth_time: present iff frozen onto the code (max_age requested or the
    // client registered require_auth_time), always the truthful recorded instant
    // (in epoch SECONDS, like iat/exp). The max_age=0 case still records a real
    // auth_time, so it is emitted here truthfully.
    if let Some(auth_micros) = request.auth_time_unix_micros {
        claims["auth_time"] = json!(auth_micros.div_euclid(1_000_000));
    }

    // at_hash / c_hash: dormant seams for the front-channel/hybrid path (#17).
    // The token endpoint passes None for both, so a token-endpoint ID token
    // carries neither.
    if let Some(at_hash) = request.at_hash {
        claims["at_hash"] = json!(at_hash);
    }
    if let Some(c_hash) = request.c_hash {
        claims["c_hash"] = json!(c_hash);
    }

    // azp is deliberately omitted: aud is the single client, which IS the
    // authorized party, and the code flow uses no extension beyond Core, so
    // errata set 2 §2 leaves azp out.

    // Extra standard claims (issue #15): the claims-parameter `id_token` member,
    // and (only under the non-conform conformIdTokenClaims override) the
    // scope-derived claims. Protocol/REQUIRED claims always win, so an extra claim
    // whose name is already set is never overwritten (it cannot shadow sub, iss,
    // aud, exp, iat, nonce, acr, amr, or auth_time).
    if let serde_json::Value::Object(claims_object) = &mut claims {
        for (name, value) in request.extra_claims {
            claims_object
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }

    Ok(claims)
}

/// Mint the ID token and access token for a successful exchange.
///
/// The `jti`s are drawn from the entropy seam (via [`IssuedTokenId::generate`]),
/// embedded in each token, and returned so the caller records them against the
/// grant. Both tokens are signed with the environment's default key.
///
/// # Errors
///
/// Returns `Err(())` if the environment has no signing key, the signing backend
/// fails, or the ID token claims are refused (an out-of-bounds `sub`); the caller
/// maps that to a token-endpoint `server_error`, so issuance fails closed.
pub fn mint(
    state: &OidcState,
    signer: &SigningKey,
    request: &MintRequest<'_>,
) -> Result<IssuedTokens, ()> {
    let now = state.now();
    let iat = epoch_secs(now);
    let access_exp = iat.saturating_add(secs(state.access_token_ttl()));

    let access_jti = IssuedTokenId::generate(state.env(), &request.scope);
    let id_jti = IssuedTokenId::generate(state.env(), &request.scope);

    // ID token (OIDC Core errata set 2): the REQUIRED claims plus the conditional
    // rules, built and cap-checked before signing so a refused sub fails closed.
    let id_claims =
        build_id_token_claims(request, iat, access_exp, &id_jti.to_string()).map_err(|error| {
            tracing::error!(
                ?error,
                "refusing to issue an ID token with an invalid subject"
            );
        })?;
    let id_token = sign_jws(
        signer,
        &serde_json::to_vec(&id_claims).map_err(|_| ())?,
        &EmissionOptions::new().with_typ("JWT"),
    )
    .map_err(|_| ())?;

    // Access token as a signed JWT (RFC 9068 at+jwt): issuer, subject, audience,
    // client_id, iat, exp, jti, and the granted scope when present.
    let mut access_claims = json!({
        "iss": request.issuer,
        "sub": request.subject,
        "aud": request.client_id,
        "client_id": request.client_id,
        "iat": iat,
        "exp": access_exp,
        "jti": access_jti.to_string(),
    });
    if let Some(scope) = request.oauth_scope {
        access_claims["scope"] = json!(scope);
    }
    let access_token = sign_jws(
        signer,
        &serde_json::to_vec(&access_claims).map_err(|_| ())?,
        &EmissionOptions::new().with_typ("at+jwt"),
    )
    .map_err(|_| ())?;

    Ok(IssuedTokens {
        access_token,
        id_token,
        access_jti,
        id_jti,
        expires_in_secs: secs(state.access_token_ttl()),
    })
}

impl IssuedTokens {
    /// The two tokens as `(id, kind)` records for the store.
    #[must_use]
    pub fn records(&self) -> [(IssuedTokenId, TokenKind); 2] {
        [
            (self.access_jti, TokenKind::Access),
            (self.id_jti, TokenKind::Id),
        ]
    }
}

/// Whole seconds of a duration as an `i64` (saturating).
fn secs(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

/// Seconds since the Unix epoch for a wall-clock instant.
fn epoch_secs(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_env::Env;
    use ironauth_store::{EnvironmentId, TenantId};

    /// An empty extra-claims map for the pure claim-builder tests (the spec-conform
    /// default, so the ID token stays lean).
    fn empty_extra() -> &'static serde_json::Map<String, serde_json::Value> {
        use std::sync::OnceLock;
        static EMPTY: OnceLock<serde_json::Map<String, serde_json::Value>> = OnceLock::new();
        EMPTY.get_or_init(serde_json::Map::new)
    }

    /// A minimal request over a throwaway scope, for the pure claim builder.
    fn request<'a>(subject: &'a str, auth_methods: &'a str) -> MintRequest<'a> {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 1);
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        MintRequest {
            scope,
            issuer: "https://issuer.test/t/x/e/y",
            subject,
            client_id: "cli_example",
            nonce: None,
            oauth_scope: None,
            auth_methods,
            auth_time_unix_micros: None,
            at_hash: None,
            c_hash: None,
            extra_claims: empty_extra(),
        }
    }

    #[test]
    fn required_claims_are_present_and_amr_acr_derive_from_the_event() {
        let claims = build_id_token_claims(&request("usr_abc", "pwd"), 1000, 1300, "tok_1")
            .expect("claims build");
        assert_eq!(claims["iss"], "https://issuer.test/t/x/e/y");
        assert_eq!(claims["sub"], "usr_abc");
        assert_eq!(claims["aud"], "cli_example");
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["exp"], 1300);
        assert_eq!(claims["jti"], "tok_1");
        assert_eq!(claims["amr"], json!(["pwd"]));
        assert_eq!(claims["acr"], "urn:ironauth:acr:pwd");
        // Not requested: nonce, auth_time, at_hash, c_hash, and azp are absent.
        for absent in ["nonce", "auth_time", "at_hash", "c_hash", "azp"] {
            assert!(claims.get(absent).is_none(), "{absent} must be absent");
        }
    }

    #[test]
    fn an_over_length_subject_fails_closed() {
        // A sub over the 255 ASCII cap is refused at issuance, never truncated.
        let over = "u".repeat(subject::MAX_SUBJECT_LEN + 1);
        assert_eq!(
            build_id_token_claims(&request(&over, "pwd"), 1, 2, "tok"),
            Err(IdTokenError::SubjectOutOfBounds),
        );
        // Exactly at the cap is admitted.
        let at = "u".repeat(subject::MAX_SUBJECT_LEN);
        assert!(build_id_token_claims(&request(&at, "pwd"), 1, 2, "tok").is_ok());
        // A non-ASCII sub is refused even within the length cap.
        assert_eq!(
            build_id_token_claims(&request("usr_café", "pwd"), 1, 2, "tok"),
            Err(IdTokenError::SubjectOutOfBounds),
        );
    }

    #[test]
    fn nonce_is_echoed_exactly_when_present() {
        let mut req = request("usr_abc", "pwd");
        req.nonce = Some("n-once-123");
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["nonce"], "n-once-123");
    }

    #[test]
    fn auth_time_is_present_and_truthful_only_when_required_including_zero() {
        // Frozen onto the code: present iff Some, always the truthful instant, in
        // epoch seconds. A recorded 1_700_000_123_456789us is 1_700_000_123s.
        let mut req = request("usr_abc", "pwd");
        req.auth_time_unix_micros = Some(1_700_000_123_456_789);
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["auth_time"], 1_700_000_123_i64);

        // The max_age=0 case still records a real (epoch-zero) auth_time, which is
        // emitted truthfully rather than omitted.
        req.auth_time_unix_micros = Some(0);
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["auth_time"], 0_i64);

        // Not required: omitted.
        req.auth_time_unix_micros = None;
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(claims.get("auth_time").is_none());
    }

    #[test]
    fn extra_claims_land_in_the_id_token_but_never_shadow_protocol_claims() {
        // Issue #15: the conformIdTokenClaims override / id_token claims-member
        // places extra standard claims in the ID token, but a protocol claim
        // (here a hostile `sub`) is never overwritten.
        let extra = json!({ "email": "ada@example.test", "sub": "attacker" })
            .as_object()
            .cloned()
            .expect("object");
        let mut req = request("usr_abc", "pwd");
        req.extra_claims = &extra;
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["email"], "ada@example.test", "extra claim lands");
        assert_eq!(claims["sub"], "usr_abc", "protocol sub is never shadowed");
    }

    #[test]
    fn the_default_id_token_carries_no_extra_claims() {
        // The spec-conform default (empty extra_claims) keeps the ID token lean.
        let claims =
            build_id_token_claims(&request("usr_abc", "pwd"), 1, 2, "tok").expect("claims");
        for absent in ["email", "name", "phone_number", "address"] {
            assert!(claims.get(absent).is_none(), "{absent} stays at UserInfo");
        }
    }

    #[test]
    fn front_channel_hashes_are_included_only_when_supplied() {
        // The token endpoint passes None (verified above). When #17 supplies
        // them, they land verbatim.
        let mut req = request("usr_abc", "pwd");
        req.at_hash = Some("at-hash-value");
        req.c_hash = Some("c-hash-value");
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["at_hash"], "at-hash-value");
        assert_eq!(claims["c_hash"], "c-hash-value");
    }
}
