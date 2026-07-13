// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minting the ID token and the access token through the one signing core.
//!
//! Both tokens are compact JWSs signed by [`ironauth_jose::sign_jws`] with the
//! target environment's signing key, so every token IronAuth issues round-trips
//! through the same hardened verify path. The claim CONTENTS here are deliberately
//! minimal: a valid ID token (issuer, subject, audience, `iat`, `exp`, and the
//! bound `nonce` when present) and a valid access token. The conditional ID-token
//! claim rules (`acr`, `amr`, `auth_time`, and the rest) are #14 and are out of
//! scope; this issue only needs a valid token to prove the flow end to end.

use std::time::SystemTime;

use ironauth_jose::{EmissionOptions, SigningKey, sign_jws};
use ironauth_store::{IssuedTokenId, Scope, TokenKind};
use serde_json::json;

use crate::state::OidcState;

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
}

/// Mint the ID token and access token for a successful exchange.
///
/// The `jti`s are drawn from the entropy seam (via [`IssuedTokenId::generate`]),
/// embedded in each token, and returned so the caller records them against the
/// grant. Both tokens are signed with the environment's default key.
///
/// # Errors
///
/// Returns `Err(())` if the environment has no signing key or the signing backend
/// fails; the caller maps that to a token-endpoint `server_error`.
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

    // ID token (OIDC Core 2): issuer, subject, audience (the client), iat, exp,
    // and the bound nonce when present. Minimal by design (#14 owns the rest).
    let mut id_claims = json!({
        "iss": request.issuer,
        "sub": request.subject,
        "aud": request.client_id,
        "iat": iat,
        "exp": access_exp,
        "jti": id_jti.to_string(),
    });
    if let Some(nonce) = request.nonce {
        id_claims["nonce"] = json!(nonce);
    }
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
