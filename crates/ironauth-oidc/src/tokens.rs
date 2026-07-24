// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minting the ID token and the access token through the one signing core.
//!
//! Both tokens are compact JWSs signed by [`ironauth_jose::sign_jws_with_policy`]
//! with the target environment's signing key UNDER its algorithm policy, so every
//! token IronAuth issues round-trips through the same hardened verify path and an
//! environment can never emit a token in an algorithm its policy forbids (issue
//! #194): the policy refuses a wrong-algorithm key BEFORE any signing happens.
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
//!
//! # The access token's format and claims (issue #29)
//!
//! The access token takes the format the resolved [`AccessTokenTarget`] selects:
//!
//! - **`at+jwt`** (the default, and what the OIDC/`UserInfo` flow uses): a signed
//!   JWT with the header `typ = at+jwt` and the RFC 9068 section 2.2 claims
//!   (`iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`, `scope` when granted),
//!   plus `acr` and (when frozen onto the code as due) `auth_time` from the
//!   authentication event. Its `aud` is the client id when no resource server is
//!   targeted, so [`crate::userinfo`]'s `aud == client` check keeps working, or the
//!   resource server's audience when one is. No PII beyond these protocol claims.
//! - **opaque** (a resource server, or an environment, may select it): an
//!   `ira_at_` reference token whose state lives only in the store as a digest;
//!   there is no offline validation, only the internal store resolve (the
//!   `UserInfo` consumer, and the RFC 7662 introspection endpoint in issue #22).
//!   The token SELF-DECLARES its `(tenant, environment)` scope through an embedded
//!   routing handle (its own `jti`, a scoped id), exactly as an at+jwt's `jti`
//!   does, so a GLOBAL consumer can recover the scope and run the scoped,
//!   RLS-bound resolve; the 256-bit random suffix is the secret, and only the
//!   digest of the WHOLE token is ever stored.
//!
//! The format selection is resolved in the async handler
//! ([`OidcState::resolve_access_token_target`]) and handed into the pure [`mint`],
//! so the crypto stays pure and testable while the resource-server lookup awaits.

use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_jose::{
    Confirmation, EmissionOptions, SigningKey, SigningPolicy, sign_jws_with_policy,
};
use ironauth_store::{
    IssuedTokenId, RefreshTokenId, Scope, TokenFormat, opaque_access_token_digest,
    refresh_token_digest,
};
use serde_json::json;

use crate::authn;
use crate::state::OidcState;
use crate::subject;

/// The scannable prefix on every opaque ACCESS token (issue #29): `ira` (the
/// product namespace), `at` (access token). Documented alongside its detection
/// regex in `docs/design/TOKEN-FORMATS.md` for secret-scanner registration. The
/// sibling refresh-token prefix `ira_rt_` is reserved there for consistency;
/// refresh tokens are issue #21.
pub const OPAQUE_ACCESS_TOKEN_PREFIX: &str = "ira_at_";

/// The scannable prefix on every REFRESH token (issue #21): `ira` (the product
/// namespace), `rt` (refresh token). Documented alongside its detection regex in
/// `docs/design/TOKEN-FORMATS.md` for secret-scanner registration. A refresh token
/// is a scope-declaring reference credential exactly like an opaque access token:
/// `ira_rt_<jti>~<secret>`, where `<jti>` is a `rft_` scoped id embedding its
/// `(tenant, environment)` (so the GLOBAL `/token` endpoint recovers the scope and
/// runs the RLS-scoped digest resolve) and `<secret>` is 256 bits from the entropy
/// seam. Only the SHA-256 digest of the WHOLE token is stored.
pub const OPAQUE_REFRESH_TOKEN_PREFIX: &str = "ira_rt_";

/// The delimiter between an opaque access token's scope-declaring routing handle
/// and its secret random suffix (issue #29). Chosen because it is a valid RFC 7235
/// Bearer `token68` character yet appears in NEITHER the base64url alphabet
/// (`[A-Za-z0-9_-]`) NOR a scoped identifier's wire form, so the two segments can
/// never collide and the split is unambiguous. It is not `.`, so an opaque token
/// still carries no dots and can never be mistaken for a compact JWS.
pub const OPAQUE_ACCESS_TOKEN_DELIMITER: char = '~';

/// The number of random bytes in an opaque access token: 32 bytes = 256 bits of
/// entropy, drawn from the ironauth-env seam (never raw `getrandom`), so an
/// opaque token cannot be guessed or enumerated.
const OPAQUE_ACCESS_TOKEN_BYTES: usize = 32;

/// The reserved access-token claim names a per-client STATIC custom claim may NEVER
/// set (issue #23). The client-credentials mint DROPS any custom claim whose name is
/// in this set, so a per-client `custom_token_claims` config can never forge or
/// inject a claim that carries protocol, authentication-context, binding, or session
/// meaning. This is the single enforcement point (the mint), so the guard holds even
/// for a value written straight into the store's `custom_token_claims` column.
///
/// It is a comprehensive DENYLIST of reserved names (NOT an allowlist): a custom
/// claim exists precisely to carry ARBITRARY business data, so anything not reserved
/// here is admitted. Each class below is reserved for a distinct reason:
///
/// - **Protocol claims** (RFC 9068 section 2.2 + the JWT registered claims of RFC
///   7519): the token's own identity, audience, lifetime, and validity window. A
///   business claim has no business restating `iss`/`sub`/`aud`/`exp`/... or moving
///   `nbf`. `typ`/`token_type` are reserved for defense in depth: the `at+jwt` header
///   `typ` is set separately via [`EmissionOptions`] (so a PAYLOAD `typ` is harmless),
///   but reserving both avoids ever confusing a lax verifier that reads the payload.
/// - **Authentication-context claims** (OIDC): `acr`/`amr`/`auth_time`/`nonce`/`azp`.
///   A machine token must NEVER assert a human authentication context; the M2M claim
///   builder ([`build_client_credentials_access_token_claims`]) DELIBERATELY omits
///   `acr`/`amr`/`auth_time`, so allowing a custom claim to re-inject one would defeat
///   the exact invariant that builder exists to guarantee.
/// - **Binding / security claims**: `cnf` (RFC 7800). A self-asserted confirmation key
///   would undermine sender-constrained (`DPoP` / mTLS proof-of-possession) token
///   binding once it lands; only the issuer may state `cnf`.
/// - **Hash / session claims** (OIDC): `at_hash`/`c_hash`/`sid`. IronAuth computes and
///   emits these itself where they belong; a self-asserted value carries security
///   meaning it must never be allowed to forge.
pub(crate) const PROTECTED_ACCESS_TOKEN_CLAIMS: &[&str] = &[
    // Protocol claims (RFC 9068 section 2.2 + RFC 7519 registered).
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "client_id",
    "scope",
    "typ",
    "token_type",
    // Authentication-context claims (OIDC): a machine token asserts no human auth.
    "acr",
    "amr",
    "auth_time",
    "nonce",
    "azp",
    // Binding / security claims: only the issuer may state a confirmation key.
    "cnf",
    // Hash / session claims (OIDC): IronAuth emits these itself where they belong.
    "at_hash",
    "c_hash",
    "sid",
    // Organization context (issue #94): the DURABLE org_id is resolved from an
    // authoritative membership check and issuer-set only; a client custom claim must
    // never self-assert an organization context.
    "org_id",
];

/// The resolved target for an access token: the audience(s) it is minted for, the
/// format it takes, and its lifetime (issue #29, extended for RFC 8707 resource
/// indicators in issue #28).
///
/// Resolved by the async handler from the targeted resource server(s) (or the
/// environment default) via [`OidcState::resolve_access_token_target`], then handed
/// into the pure [`mint`]. This is the seam issue #28 feeds: it resolves the
/// audience(s) from the RFC 8707 `resource` request parameter and passes them here
/// without reshaping the mint. The no-resource case passes a single audience (the
/// client id), preserving `UserInfo`'s `aud == client` check.
#[derive(Debug, Clone)]
pub struct AccessTokenTarget {
    /// The `aud` of the minted access token: ALWAYS non-empty. One entry for the
    /// no-resource case (the client id, so `UserInfo`'s `aud == client` check keeps
    /// working) or a single targeted resource server; multiple entries when several
    /// resources are requested (RFC 8707 / RFC 9068 permit an `aud` array).
    pub audiences: Vec<String>,
    /// The format to emit (an RFC 9068 `at+jwt` or an opaque reference token).
    pub format: TokenFormat,
    /// The access-token lifetime.
    pub ttl: Duration,
}

impl AccessTokenTarget {
    /// The `aud` claim value for this target (issue #28): a JSON STRING for a single
    /// audience (the common no-resource / single-resource case, keeping the wire form
    /// identical to before #28), or a JSON ARRAY for multiple (RFC 9068 permits
    /// either). Never empty by construction.
    #[must_use]
    pub fn aud_claim(&self) -> serde_json::Value {
        match self.audiences.as_slice() {
            [single] => json!(single),
            many => json!(many),
        }
    }

    /// The PRIMARY audience (the first): the value recorded as an opaque token's
    /// `audience` column, and the fallback single audience. Never panics: the
    /// audience set is non-empty by construction.
    #[must_use]
    pub fn primary_audience(&self) -> &str {
        self.audiences.first().map_or("", String::as_str)
    }
}

/// A minted access token: the string handed to the client plus what the store
/// records for it (issue #29). An `at+jwt` records its `jti` in `issued_tokens`;
/// an opaque token records its digest and metadata in `opaque_access_tokens`.
pub enum MintedAccessToken {
    /// An RFC 9068 `at+jwt`: the compact JWS and its `jti` (recorded in
    /// `issued_tokens` for grant-chain status, exactly as before issue #29).
    Jwt {
        /// The compact access-token JWS.
        token: String,
        /// The access token's `jti`, recorded against the grant.
        jti: IssuedTokenId,
    },
    /// An opaque reference token: the plaintext handed to the client (NEVER
    /// stored) plus the digest-only record fields for `opaque_access_tokens`.
    Opaque {
        /// The `ira_at_...` plaintext token, returned to the client and never
        /// persisted.
        token: String,
        /// The SHA-256 hex digest of `token`, the only token material stored.
        digest: String,
        /// The token's logical `jti` (a `tok_` id), recorded in the row.
        jti: IssuedTokenId,
        /// The full audience set the token targets (issue #28): recorded on the row
        /// so introspection reports it. Always non-empty; its first entry is the
        /// primary `audience` column, and the whole array is recorded when it has
        /// more than one member.
        audiences: Vec<String>,
        /// The token's expiry, in microseconds since the Unix epoch (clock seam).
        expires_at_unix_micros: i64,
    },
}

impl MintedAccessToken {
    /// The token string to return in the token response, whichever format it is.
    #[must_use]
    pub fn token(&self) -> &str {
        match self {
            MintedAccessToken::Jwt { token, .. } | MintedAccessToken::Opaque { token, .. } => token,
        }
    }
}

/// The tokens minted for one successful code exchange, plus the recorded `jti`s
/// so the caller can persist them against the grant.
pub struct IssuedTokens {
    /// The minted access token (an `at+jwt` or an opaque reference token).
    pub access: MintedAccessToken,
    /// The compact ID-token JWS.
    pub id_token: String,
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
    /// The per-(client, session) `sid` claim (issue #32): the OP session identifier
    /// the ID token carries, stable for the lifetime of the (client, session) pair
    /// and distinct across pairs, so OIDC Back-Channel Logout can target exactly this
    /// (client, session). The token endpoint resolves it from the authenticating SSO
    /// session through the per-client session store, so it is emitted here as a
    /// LEGITIMATE issuer claim (a self-asserted custom claim named `sid` is still
    /// blocklisted; see [`PROTECTED_ACCESS_TOKEN_CLAIMS`]). [`None`] when no session
    /// backed the exchange (no `sid` is then emitted).
    pub sid: Option<&'a str>,
    /// The DURABLE organization context (an `org_` id) frozen onto the session and
    /// grant (issue #94, PR-B1): the token endpoint reads it back from the grant and
    /// emits it as the `org_id` claim on BOTH the ID token and the access token. It is
    /// a PROTECTED, issuer-only claim (see [`PROTECTED_ACCESS_TOKEN_CLAIMS`]) resolved
    /// from an AUTHORITATIVE membership check, never from a client parameter's claim of
    /// membership, so a client can never self-assert it. [`None`] when the session
    /// resolved no org (a member-less user, a multi-org user who named none, or a
    /// machine token, which asserts no human org context); no claim is then emitted.
    pub org_id: Option<&'a str>,
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
    /// The per-client ID-token signing key (issue #30): the environment key of the
    /// algorithm this client negotiated as its `id_token_signed_response_alg` at
    /// dynamic registration. When [`Some`], the ID token (ONLY the ID token, never
    /// the access token) is signed with this key, so the algorithm DCR recorded and
    /// echoed at registration is the algorithm the ID token is actually signed
    /// under. [`None`] signs the ID token with the environment default `signer`,
    /// exactly as before DCR (every non-DCR client, and any DCR client whose
    /// negotiated algorithm IS the environment default). The caller resolves it from
    /// the environment key set, so it is always a key the policy permits.
    pub id_token_signer: Option<&'a SigningKey>,
    /// The proof-of-possession confirmation to bind the ACCESS token to (RFC 7800,
    /// issue #368): the [`Confirmation::Jkt`] of a `DPoP` proof key when a valid
    /// proof accompanied the code exchange. [`Some`] embeds a `cnf` claim in the
    /// at+jwt (making it sender-constrained); [`None`] leaves it a plain bearer
    /// token. Issuer-set ONLY: `cnf` is a PROTECTED access-token claim (see
    /// [`PROTECTED_ACCESS_TOKEN_CLAIMS`]), so a client can never self-assert a
    /// binding, and it is placed here by the token endpoint after it has itself
    /// validated the proof. The ID token never carries it (binding is an access
    /// token property).
    pub confirmation: Option<&'a Confirmation>,
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
    // The LOCAL factors IronAuth actually performed, plus the honest UPSTREAM `amr`
    // passthrough for a FEDERATED login (issue #75). The passthrough is emitted VERBATIM,
    // never converted into a local method (which would falsely claim IronAuth ran it): for a
    // pure federated login the local set is empty ([`AuthMethod::Federated`] emits no `amr`),
    // so the token's `amr` is exactly what the upstream asserted, and if the upstream
    // asserted none the token asserts none.
    let mut amr: Vec<String> = authn::amr_values(&methods)
        .into_iter()
        .map(str::to_owned)
        .collect();
    for upstream in authn::federated_amr_from_auth_methods(request.auth_methods) {
        if !amr.contains(&upstream) {
            amr.push(upstream);
        }
    }
    claims["amr"] = json!(amr);
    claims["acr"] = json!(authn::achieved_acr(&methods));

    // auth_time: present iff frozen onto the code (max_age requested or the
    // client registered require_auth_time), always the truthful recorded instant
    // (in epoch SECONDS, like iat/exp). The max_age=0 case still records a real
    // auth_time, so it is emitted here truthfully.
    if let Some(auth_micros) = request.auth_time_unix_micros {
        claims["auth_time"] = json!(auth_micros.div_euclid(1_000_000));
    }

    // sid (issue #32): the OP session identifier, present in EVERY code-flow ID
    // token (the token endpoint resolves it from the authenticating SSO session
    // through the per-client session store). It is stable per (client, session) and
    // distinct across clients, so it is the join key OIDC Back-Channel Logout targets
    // and the reason discovery can truthfully advertise
    // backchannel_logout_session_supported. Emitted here as a legitimate issuer claim.
    if let Some(sid) = request.sid {
        claims["sid"] = json!(sid);
    }

    // org_id (issue #94, PR-B1): the DURABLE organization context frozen onto the
    // session and grant, resolved from an authoritative membership check at
    // authorization, emitted here as a legitimate issuer claim. It is set BEFORE the
    // extra-claims fold below and is a PROTECTED access-token claim, so a client
    // custom claim named `org_id` can never shadow or forge it. Absent when the
    // session resolved no org.
    if let Some(org_id) = request.org_id {
        claims["org_id"] = json!(org_id);
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

/// Build the RFC 9068 access-token claim set for an `at+jwt` (issue #29). Pure,
/// so it is exercised without a store or a signer.
///
/// Carries the RFC 9068 section 2.2 claims: `iss`, `exp`, `aud`, `sub`,
/// `client_id`, `iat`, `jti`, and `scope` when a scope was granted. `aud` is the
/// resolved `audience` (the client id for the no-resource case, so `UserInfo`'s
/// `aud == client` check keeps working; a resource server's audience when one is
/// targeted). `client_id` is ALWAYS the OAuth client. Because this token results
/// from a user-authentication (code) flow, it also carries `acr` (the achieved
/// authentication context, derived from the recorded authentication event, never
/// a request parameter) and, when the authentication instant was frozen onto the
/// code as due, `auth_time`. Claims hygiene: no PII beyond these protocol claims
/// (no `email`/`name`/`address`/`phone`); scope-derived claims stay at `UserInfo`.
pub(crate) fn build_access_token_claims(
    request: &MintRequest<'_>,
    iat: i64,
    exp: i64,
    jti: &str,
    audience: &serde_json::Value,
) -> serde_json::Value {
    let mut claims = json!({
        "iss": request.issuer,
        "sub": request.subject,
        "aud": audience,
        "client_id": request.client_id,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    });
    if let Some(scope) = request.oauth_scope {
        claims["scope"] = json!(scope);
    }
    // acr: the achieved authentication context of the code flow, derived from the
    // recorded authentication event (issue #14's `authn`), never a request value.
    let methods = authn::parse_methods(request.auth_methods);
    claims["acr"] = json!(authn::achieved_acr(&methods));
    // auth_time: present iff frozen onto the code as due (max_age requested or the
    // client registered require_auth_time), always the truthful recorded instant
    // in epoch SECONDS, exactly as the ID token emits it.
    if let Some(auth_micros) = request.auth_time_unix_micros {
        claims["auth_time"] = json!(auth_micros.div_euclid(1_000_000));
    }
    // org_id (issue #94, PR-B1): the DURABLE organization context frozen onto the
    // grant, emitted as a legitimate issuer claim (it is in PROTECTED_ACCESS_TOKEN_CLAIMS,
    // so a client custom claim can never self-assert it). Absent when the session
    // resolved no org; a client-credentials (M2M) token never sets it (no human org
    // context), which its distinct builder guarantees by omission.
    if let Some(org_id) = request.org_id {
        claims["org_id"] = json!(org_id);
    }
    // cnf (RFC 7800 / RFC 9449, issue #368): bind the access token to the DPoP proof
    // key when a valid proof accompanied issuance. `cnf` is issuer-reserved (it is in
    // PROTECTED_ACCESS_TOKEN_CLAIMS), so embedding it HERE is the only way it can be
    // set: a client cannot self-assert a binding. Absent for a plain bearer token.
    if let Some(confirmation) = request.confirmation {
        if let serde_json::Value::Object(object) = &mut claims {
            confirmation.embed_in_claims(object);
        }
    }
    claims
}

/// Everything a client-credentials (M2M) access token needs (issue #23). Distinct
/// from [`MintRequest`] because a machine token has no user, no nonce, no
/// authentication event, and no ID token: only the RFC 9068 protocol claims, the
/// stable service-account `sub`, and the per-client static custom claims.
pub struct ClientCredentialsMintRequest<'a> {
    /// The `(tenant, environment)` scope the token belongs to.
    pub scope: Scope,
    /// The per-environment issuer.
    pub issuer: &'a str,
    /// The STABLE service-account principal id (a `sva_` id): the token's `sub`,
    /// DISTINCT from `client_id` and consistent across issuances.
    pub subject: &'a str,
    /// The authenticated OAuth client (the token's `client_id`).
    pub client_id: &'a str,
    /// The granted OAuth `scope` value, echoed into the token when present.
    pub oauth_scope: Option<&'a str>,
    /// The per-client STATIC custom claims to embed. A custom claim can never set a
    /// reserved claim name (see [`PROTECTED_ACCESS_TOKEN_CLAIMS`]). Custom claims are
    /// an at+jwt feature ONLY: an opaque access token carries no embedded claims by
    /// design, so when the resolved format is opaque these claims are dropped (and the
    /// mint warns), their metadata surfacing instead through #22 introspection.
    pub custom_claims: &'a serde_json::Map<String, serde_json::Value>,
}

/// Build the RFC 9068 access-token claim set for a CLIENT-CREDENTIALS (M2M) token
/// (issue #23). Pure, so it is exercised without a store or a signer.
///
/// Carries the RFC 9068 section 2.2 claims (`iss`, `exp`, `aud`, `sub`,
/// `client_id`, `iat`, `jti`, and `scope` when granted), where `sub` is the STABLE
/// service-account principal id (DISTINCT from `client_id`, per RFC 9068) and
/// `client_id` is the OAuth client. It deliberately carries NO `acr` and NO
/// `auth_time`: unlike [`build_access_token_claims`] (a user-authentication flow),
/// a client-credentials token results from no user authentication event, so
/// asserting an authentication context would be false. It reuses the SAME signing
/// core and opaque mint as every other access token; only the claim set differs.
///
/// The per-client STATIC custom claims are merged last, and a custom claim can NEVER
/// override a protected registered claim: any name in [`PROTECTED_ACCESS_TOKEN_CLAIMS`]
/// is skipped, and the protocol claims are already present (so even a non-protected
/// name never shadows one). Claims hygiene otherwise mirrors the code flow: no PII.
pub(crate) fn build_client_credentials_access_token_claims(
    request: &ClientCredentialsMintRequest<'_>,
    iat: i64,
    exp: i64,
    jti: &str,
    audience: &serde_json::Value,
) -> serde_json::Value {
    let mut claims = json!({
        "iss": request.issuer,
        "sub": request.subject,
        "aud": audience,
        "client_id": request.client_id,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    });
    if let Some(scope) = request.oauth_scope {
        claims["scope"] = json!(scope);
    }
    // Merge the per-client static custom claims. A custom claim can NEVER override a
    // protected registered claim: an explicitly protected name is skipped, and the
    // `or_insert_with` keeps a protocol claim that is already present, so a hostile
    // `{"sub":"attacker"}` never shadows the real subject even if it were written
    // straight into the store.
    if let serde_json::Value::Object(object) = &mut claims {
        for (name, value) in request.custom_claims {
            if PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&name.as_str()) {
                continue;
            }
            object.entry(name.clone()).or_insert_with(|| value.clone());
        }
    }
    claims
}

/// Mint the client-credentials (M2M) access token (issue #23), in whichever format
/// the resolved `target` selects, through the SAME policy-enforced signing core and
/// opaque mint as every other access token. There is no ID token and no refresh
/// token (RFC 6749 4.4.3): this mints ONLY the access token and returns it plus its
/// lifetime in seconds.
///
/// # Errors
///
/// Returns `Err(())` if `signer`'s algorithm is not permitted by `policy` or the
/// signing backend fails; the caller maps that to a token-endpoint `server_error`,
/// so a signing failure fails the issuance closed. The opaque path is infallible.
pub fn mint_client_credentials_access_token(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &ClientCredentialsMintRequest<'_>,
    target: &AccessTokenTarget,
) -> Result<(MintedAccessToken, i64), ()> {
    let now = state.now();
    let iat = epoch_secs(now);
    let access_exp = iat.saturating_add(secs(target.ttl));
    let minted = match target.format {
        TokenFormat::AtJwt => {
            let jti = IssuedTokenId::generate(state.env(), &request.scope);
            let claims = build_client_credentials_access_token_claims(
                request,
                iat,
                access_exp,
                &jti.to_string(),
                &target.aud_claim(),
            );
            let token = sign_jws_with_policy(
                policy,
                signer,
                &serde_json::to_vec(&claims).map_err(|_| ())?,
                &EmissionOptions::new().with_typ("at+jwt"),
            )
            .map_err(|_| ())?;
            MintedAccessToken::Jwt { token, jti }
        }
        // Opaque tokens carry no claims, so this is the exact same reference token as
        // every other grant mints (shared helper), only its stored metadata differs.
        // Consequently a client's configured custom claims CANNOT ride on an opaque
        // token: an opaque token is a reference credential with no embedded payload by
        // design, and its metadata surfaces only through the #22 introspection resolve;
        // custom claims are an at+jwt feature. This is NOT silent: when custom claims
        // are configured but the resolved resource-server/environment format is opaque,
        // warn (without the claim VALUES, honoring the log-scrubbing rule) so the drop
        // is observable rather than a silent gap. Storing the claims in the opaque row
        // is deliberately out of scope here (cross-cutting with introspection, #22).
        TokenFormat::Opaque => {
            if !request.custom_claims.is_empty() {
                tracing::warn!(
                    "client custom claims are configured but the resolved access-token \
                     format is opaque; custom claims are an at+jwt feature and are not \
                     embedded in an opaque reference token (they surface via #22 \
                     introspection instead)"
                );
            }
            mint_opaque_access(state, &request.scope, target, now)
        }
    };
    Ok((minted, secs(target.ttl)))
}

/// Generate an opaque access token (issue #29): the scannable `ira_at_` prefix, a
/// SCOPE-DECLARING routing handle (`jti`, a `tok_` scoped id embedding its
/// `(tenant, environment)`), the [`OPAQUE_ACCESS_TOKEN_DELIMITER`], and 256 bits of
/// entropy from the ironauth-env seam.
///
/// The routing handle lets a GLOBAL consumer (the `UserInfo` endpoint, and the RFC
/// 7662 introspection endpoint in issue #22) recover the token's scope and run the
/// scoped, RLS-bound store resolve, exactly as an at+jwt's `jti` carries its scope;
/// the endpoints are global and every other bearer credential IronAuth issues is a
/// scoped identifier, so the opaque token declares its scope the same way. The
/// handle is a NON-secret id (it is also the stored `jti` and the introspection
/// handle); the 256-bit random suffix is the secret. The plaintext is returned to
/// the client and never stored; only the digest of the WHOLE token is persisted, so
/// a database dump still yields nothing replayable.
fn generate_opaque_access_token(state: &OidcState, jti: &IssuedTokenId) -> String {
    let mut bytes = [0_u8; OPAQUE_ACCESS_TOKEN_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    format!(
        "{OPAQUE_ACCESS_TOKEN_PREFIX}{jti}{OPAQUE_ACCESS_TOKEN_DELIMITER}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Mint the ID token and the access token for a successful exchange (issue #29).
///
/// The ID token is ALWAYS a signed `at+jwt`-adjacent JWT (OIDC Core), signed with
/// the environment key; its lifetime is the environment access-token lifetime, as
/// before. The access token takes the resolved `target`'s format: an RFC 9068
/// `at+jwt` (signed, `jti` recorded in `issued_tokens`) or an opaque reference
/// token (random + digest, recorded in `opaque_access_tokens`), with the target's
/// audience and lifetime. The `jti`s are drawn from the entropy seam.
///
/// # Errors
///
/// Returns `Err(())` if the environment has no signing key, `signer`'s algorithm
/// is not permitted by `policy`, the signing backend fails, or the ID token claims
/// are refused (an out-of-bounds `sub`); the caller maps that to a token-endpoint
/// `server_error`, so issuance fails closed. The opaque path cannot fail (entropy
/// draw and hashing are infallible), but the ID token is always signed, so a
/// signing failure still fails the whole exchange closed.
pub fn mint(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
    target: &AccessTokenTarget,
) -> Result<IssuedTokens, ()> {
    let now = state.now();
    let iat = epoch_secs(now);
    // The ID token keeps the environment access-token lifetime (unchanged); the
    // access token uses the target lifetime (a resource server may shorten it).
    let id_exp = iat.saturating_add(secs(state.access_token_ttl()));
    let access_ttl_secs = secs(target.ttl);

    let id_jti = IssuedTokenId::generate(state.env(), &request.scope);

    // ID token (OIDC Core errata set 2): the REQUIRED claims plus the conditional
    // rules, built and cap-checked before signing so a refused sub fails closed.
    let id_claims =
        build_id_token_claims(request, iat, id_exp, &id_jti.to_string()).map_err(|error| {
            tracing::error!(
                ?error,
                "refusing to issue an ID token with an invalid subject"
            );
        })?;
    // The ID token is signed with the per-client key when the client negotiated a
    // non-default `id_token_signed_response_alg` at registration (issue #30), else
    // the environment default. The access token below always uses the environment
    // default `signer`.
    let id_signer = request.id_token_signer.unwrap_or(signer);
    let id_token = sign_jws_with_policy(
        policy,
        id_signer,
        &serde_json::to_vec(&id_claims).map_err(|_| ())?,
        &EmissionOptions::new().with_typ("JWT"),
    )
    .map_err(|_| ())?;

    let access = mint_access(state, signer, policy, request, target, now)?;

    Ok(IssuedTokens {
        access,
        id_token,
        id_jti,
        expires_in_secs: access_ttl_secs,
    })
}

/// Mint ONLY an access token (the refresh-token grant, issue #21). It reuses the
/// EXACT same access-token claim assembly and signing path as [`mint`] and returns
/// the token plus its lifetime in seconds. A refreshed exchange never re-mints an
/// ID token (no new authentication happened), so this is the lean minter the
/// refresh grant uses; the ID token and its `auth_time`/`nonce` stay with the
/// original code exchange.
///
/// # Errors
///
/// Returns `Err(())` if `signer`'s algorithm is not permitted by `policy` or the
/// signing backend fails; the caller maps that to a token-endpoint `server_error`,
/// so a signing failure fails the refresh closed. The opaque path is infallible.
pub fn mint_access_token(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
    target: &AccessTokenTarget,
) -> Result<(MintedAccessToken, i64), ()> {
    let now = state.now();
    let access = mint_access(state, signer, policy, request, target, now)?;
    Ok((access, secs(target.ttl)))
}

/// Mint the access token for `target`, in whichever format it selects (issue #29,
/// #21). Shared by the code exchange ([`mint`]) and the refresh grant
/// ([`mint_access_token`]), so a refreshed access token is byte-shaped identically
/// to a freshly issued one.
fn mint_access(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
    target: &AccessTokenTarget,
    now: SystemTime,
) -> Result<MintedAccessToken, ()> {
    let iat = epoch_secs(now);
    let access_exp = iat.saturating_add(secs(target.ttl));
    match target.format {
        // RFC 9068 at+jwt: the header typ is `at+jwt` and the claims carry the
        // section 2.2 set, signed through the same policy-enforced core as the ID
        // token, so an algorithm the policy forbids is refused before signing.
        TokenFormat::AtJwt => {
            let jti = IssuedTokenId::generate(state.env(), &request.scope);
            let claims = build_access_token_claims(
                request,
                iat,
                access_exp,
                &jti.to_string(),
                &target.aud_claim(),
            );
            let token = sign_jws_with_policy(
                policy,
                signer,
                &serde_json::to_vec(&claims).map_err(|_| ())?,
                &EmissionOptions::new().with_typ("at+jwt"),
            )
            .map_err(|_| ())?;
            Ok(MintedAccessToken::Jwt { token, jti })
        }
        // Opaque: a scope-declaring reference token; only its digest and metadata
        // are stored (the caller records them in the redeem transaction). The token
        // embeds its own `jti` as the routing handle, so the digest is over the
        // WHOLE token (handle + secret) the client presents.
        TokenFormat::Opaque => Ok(mint_opaque_access(state, &request.scope, target, now)),
    }
}

/// Mint an OPAQUE access token for `target` (issue #29): the scope-declaring
/// `ira_at_` reference token plus its digest and metadata for `opaque_access_tokens`.
/// An opaque token carries no claims, so this is shared verbatim by the code
/// exchange, the refresh grant, and the client-credentials grant (issue #23): every
/// opaque access token IronAuth issues is byte-shaped identically regardless of the
/// grant that minted it.
fn mint_opaque_access(
    state: &OidcState,
    scope: &Scope,
    target: &AccessTokenTarget,
    now: SystemTime,
) -> MintedAccessToken {
    let jti = IssuedTokenId::generate(state.env(), scope);
    let token = generate_opaque_access_token(state, &jti);
    let digest = opaque_access_token_digest(&token);
    let expires_at_unix_micros = epoch_micros(now).saturating_add(micros(target.ttl));
    MintedAccessToken::Opaque {
        token,
        digest,
        jti,
        audiences: target.audiences.clone(),
        expires_at_unix_micros,
    }
}

/// A freshly minted refresh token (issue #21): the plaintext handed to the client
/// (NEVER stored) plus the digest-only material the store records.
pub struct MintedRefreshToken {
    /// The `ira_rt_...` plaintext token, returned to the client and never persisted.
    pub token: String,
    /// The SHA-256 hex digest of `token`, the only token material stored.
    pub digest: String,
    /// The token's logical `rft_` identifier (its embedded routing handle).
    pub jti: RefreshTokenId,
}

/// Mint a refresh token under `scope` (issue #21): a fresh `rft_` routing handle,
/// the [`OPAQUE_REFRESH_TOKEN_PREFIX`], the [`OPAQUE_ACCESS_TOKEN_DELIMITER`], and
/// 256 bits of entropy from the ironauth-env seam, exactly mirroring the opaque
/// access token. The whole-token SHA-256 digest is what the store persists; a
/// forged handle resolves to nothing (the digest binds the handle to the secret,
/// so a token cannot be relocated to another scope), and a database dump yields
/// nothing replayable.
#[must_use]
pub fn mint_refresh_token(state: &OidcState, scope: &Scope) -> MintedRefreshToken {
    let jti = RefreshTokenId::generate(state.env(), scope);
    let mut bytes = [0_u8; OPAQUE_ACCESS_TOKEN_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    let token = format!(
        "{OPAQUE_REFRESH_TOKEN_PREFIX}{jti}{OPAQUE_ACCESS_TOKEN_DELIMITER}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    );
    let digest = refresh_token_digest(&token);
    MintedRefreshToken { token, digest, jti }
}

/// Mint ONLY an ID token, for the front-channel `id_token` and `code id_token`
/// flows (issue #17). It reuses the EXACT same claim assembly
/// ([`build_id_token_claims`]) and signing path as [`mint`]; it never mints an
/// access token, because the authorization endpoint never issues one (RFC 9700
/// 2.1.2, a permanent non-goal). The ID token's lifetime matches a token-endpoint
/// ID token (the configured access-token lifetime), and its `jti` is drawn from
/// the entropy seam and returned so the caller can record it against the grant (or
/// simply meter it, for the stateless implicit flow).
///
/// The hybrid flow supplies [`MintRequest::c_hash`] (the hash of the issued
/// `code`); the pure implicit flow leaves it `None`. Both leave
/// [`MintRequest::at_hash`] `None`: no access token exists to hash.
///
/// # Errors
///
/// `Err(())` if the ID token claims are refused (an out-of-bounds `sub`),
/// `signer`'s algorithm is not permitted by `policy`, or the signing backend
/// fails; the caller maps that to a `server_error` returned via the negotiated
/// response mode, so the front channel fails closed.
pub fn mint_id_token(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
) -> Result<(String, IssuedTokenId), ()> {
    let now = state.now();
    let iat = epoch_secs(now);
    let exp = iat.saturating_add(secs(state.access_token_ttl()));
    let id_jti = IssuedTokenId::generate(state.env(), &request.scope);
    let id_claims =
        build_id_token_claims(request, iat, exp, &id_jti.to_string()).map_err(|error| {
            tracing::error!(
                ?error,
                "refusing to issue a front-channel ID token with an invalid subject"
            );
        })?;
    // Honor a per-client ID-token signing key when supplied (issue #30), else the
    // environment default. The front-channel caller passes [`None`]: a DCR client
    // registers `response_types = ["code"]` only, so it can never reach this path,
    // and the front-channel `c_hash` algorithm is derived from the same `signer`.
    let id_signer = request.id_token_signer.unwrap_or(signer);
    let id_token = sign_jws_with_policy(
        policy,
        id_signer,
        &serde_json::to_vec(&id_claims).map_err(|_| ())?,
        &EmissionOptions::new().with_typ("JWT"),
    )
    .map_err(|_| ())?;
    Ok((id_token, id_jti))
}

/// Whole seconds of a duration as an `i64` (saturating).
fn secs(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

/// Whole microseconds of a duration as an `i64` (saturating).
fn micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

/// Seconds since the Unix epoch for a wall-clock instant.
fn epoch_secs(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Microseconds since the Unix epoch for a wall-clock instant (the opaque token's
/// expiry is stored in this unit, matching the store's clock-seam convention).
fn epoch_micros(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
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
            sid: None,
            org_id: None,
            at_hash: None,
            c_hash: None,
            extra_claims: empty_extra(),
            id_token_signer: None,
            confirmation: None,
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
    fn a_federated_login_mints_the_honest_upstream_amr_passthrough_and_federated_acr() {
        // Issue #75, PR B, the honesty crux AT THE MINT: the auth_methods string a federated
        // callback persists (federated + the encoded upstream amr passthrough) flows verbatim
        // to build_id_token_claims, which emits the UPSTREAM's asserted amr VERBATIM (never a
        // fabricated local factor) and the federated-context acr.
        let event = authn::AuthenticationEvent::federated(
            0,
            &["hwk".to_owned(), "mfa".to_owned()],
            Some("aal2"),
        );
        let auth_methods = event.methods_token();
        let claims = build_id_token_claims(&request("usr_fed", &auth_methods), 1, 2, "tok")
            .expect("claims build");
        // The minted amr is EXACTLY the upstream passthrough; no local factor is invented.
        assert_eq!(claims["amr"], json!(["hwk", "mfa"]));
        assert!(!claims["amr"].as_array().unwrap().iter().any(|v| v == "pwd"));
        assert_eq!(claims["acr"], "urn:ironauth:acr:federated");

        // When the upstream asserted NO amr, the minted token asserts none.
        let silent = authn::AuthenticationEvent::federated(0, &[], None).methods_token();
        let claims =
            build_id_token_claims(&request("usr_fed", &silent), 1, 2, "tok").expect("claims build");
        assert_eq!(claims["amr"], json!([] as [&str; 0]));
        assert_eq!(claims["acr"], "urn:ironauth:acr:federated");
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
    fn org_id_is_emitted_and_a_client_custom_claim_can_never_forge_it() {
        // Issue #94, PR-B1: org_id is a PROTECTED, issuer-set claim. When the session
        // resolved an org it is emitted on both tokens, and it is set BEFORE the
        // extra-claims fold, so a hostile custom claim named `org_id` can never shadow
        // or forge it (the id-token protocol-claim-wins fold), and it is in
        // PROTECTED_ACCESS_TOKEN_CLAIMS (the access-token custom-claim guard).
        let extra = json!({ "org_id": "org_forged" })
            .as_object()
            .cloned()
            .expect("object");
        let mut req = request("usr_abc", "pwd");
        req.org_id = Some("org_real");
        req.extra_claims = &extra;
        let id_claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(
            id_claims["org_id"], "org_real",
            "the protocol org_id wins over a forged custom claim"
        );
        let at_claims = build_access_token_claims(&req, 1, 2, "tok", &json!("cli_example"));
        assert_eq!(
            at_claims["org_id"], "org_real",
            "access token carries org_id"
        );
        assert!(
            PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&"org_id"),
            "org_id is a protected access-token claim"
        );

        // With no resolved org the claim is absent on both tokens (a no-org login is
        // byte-identical to before the feature). The access token merges no client
        // custom claims at all on the code flow, so its org_id can only ever come from
        // the issuer; the ID token's protocol-claim-wins fold protects a SET org_id,
        // and in practice a client can never place `org_id` into the ID token's
        // extra-claims bag (assembled only from the subject's stored claims and the
        // scope-derived standard claims, never a protocol-namespace claim like org_id).
        let empty = serde_json::Map::new();
        req.org_id = None;
        req.extra_claims = &empty;
        let id_none = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(id_none.get("org_id").is_none(), "no org, no id-token claim");
        let at_none = build_access_token_claims(&req, 1, 2, "tok", &json!("cli_example"));
        assert!(
            at_none.get("org_id").is_none(),
            "no org, no access-token claim"
        );
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

    #[test]
    fn access_token_carries_the_rfc9068_required_claims() {
        // Issue #29: the at+jwt access token carries every RFC 9068 section 2.2
        // required claim, well formed, plus scope and the derived acr.
        let mut req = request("usr_abc", "pwd");
        req.oauth_scope = Some("openid profile");
        let claims = build_access_token_claims(&req, 1000, 1300, "tok_at", &json!("cli_example"));
        assert_eq!(claims["iss"], "https://issuer.test/t/x/e/y");
        assert_eq!(claims["exp"], 1300);
        assert_eq!(claims["sub"], "usr_abc");
        assert_eq!(claims["client_id"], "cli_example");
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["jti"], "tok_at");
        assert_eq!(claims["scope"], "openid profile");
        // acr is derived from the authentication event, never a request parameter.
        assert_eq!(claims["acr"], "urn:ironauth:acr:pwd");
        // Every RFC 9068 required claim is present and a well-formed type.
        for name in ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"] {
            assert!(claims.get(name).is_some(), "{name} must be present");
        }
        assert!(claims["exp"].is_number() && claims["iat"].is_number());
    }

    #[test]
    fn access_token_aud_is_the_resolved_audience_not_always_the_client() {
        // The no-resource case passes the client id (so UserInfo keeps working);
        // a resource server passes its own audience. client_id is ALWAYS the OAuth
        // client, whatever the audience is.
        let req = request("usr_abc", "pwd");
        let default = build_access_token_claims(&req, 1, 2, "tok", &json!("cli_example"));
        assert_eq!(default["aud"], "cli_example");
        assert_eq!(default["client_id"], "cli_example");

        let rs = build_access_token_claims(&req, 1, 2, "tok", &json!("https://api.example/orders"));
        assert_eq!(rs["aud"], "https://api.example/orders");
        assert_eq!(rs["client_id"], "cli_example", "client_id stays the client");
    }

    #[test]
    fn access_token_auth_time_is_present_only_when_frozen_onto_the_code() {
        // auth_time appears (in epoch seconds) only when the authentication instant
        // was frozen onto the code as due, exactly like the ID token.
        let mut req = request("usr_abc", "pwd");
        assert!(
            build_access_token_claims(&req, 1, 2, "tok", &json!("cli_example"))
                .get("auth_time")
                .is_none(),
            "auth_time is absent when not frozen onto the code"
        );
        req.auth_time_unix_micros = Some(1_700_000_123_456_789);
        let claims = build_access_token_claims(&req, 1, 2, "tok", &json!("cli_example"));
        assert_eq!(claims["auth_time"], 1_700_000_123_i64);
    }

    #[test]
    fn access_token_payload_carries_no_pii_beyond_the_protocol_claims() {
        // Claims hygiene: even when the granted scope names PII scopes, the access
        // token payload never carries the PII itself (it stays at UserInfo).
        let mut req = request("usr_abc", "pwd");
        req.oauth_scope = Some("openid profile email address phone");
        req.auth_time_unix_micros = Some(1_700_000_000_000_000);
        let claims = build_access_token_claims(&req, 1, 2, "tok", &json!("cli_example"));
        let object = claims.as_object().expect("object");
        // The payload is exactly the protocol claim set, nothing else.
        let mut names: Vec<&str> = object.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "acr",
                "aud",
                "auth_time",
                "client_id",
                "exp",
                "iat",
                "iss",
                "jti",
                "scope",
                "sub"
            ],
            "the access token payload is exactly the protocol claims"
        );
        for pii in ["email", "name", "given_name", "phone_number", "address"] {
            assert!(
                object.get(pii).is_none(),
                "{pii} must not be in the payload"
            );
        }
    }

    /// A minimal client-credentials mint request over a throwaway scope.
    fn cc_request<'a>(
        subject: &'a str,
        custom: &'a serde_json::Map<String, serde_json::Value>,
    ) -> ClientCredentialsMintRequest<'a> {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 1);
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        ClientCredentialsMintRequest {
            scope,
            issuer: "https://issuer.test/t/x/e/y",
            subject,
            client_id: "cli_example",
            oauth_scope: None,
            custom_claims: custom,
        }
    }

    #[test]
    fn client_credentials_claims_carry_the_rfc9068_set_and_no_auth_context() {
        // Issue #23: the M2M token carries the RFC 9068 protocol claims, with sub the
        // service-account principal (DISTINCT from client_id) and NO acr / auth_time
        // (there was no user authentication event to derive them from).
        let empty = serde_json::Map::new();
        let mut req = cc_request("sva_principal", &empty);
        req.oauth_scope = Some("read write");
        let claims = build_client_credentials_access_token_claims(
            &req,
            1000,
            1300,
            "tok_at",
            &json!("cli_example"),
        );
        assert_eq!(claims["iss"], "https://issuer.test/t/x/e/y");
        assert_eq!(claims["sub"], "sva_principal");
        assert_ne!(
            claims["sub"], claims["client_id"],
            "sub is distinct from client_id"
        );
        assert_eq!(claims["aud"], "cli_example");
        assert_eq!(claims["client_id"], "cli_example");
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["exp"], 1300);
        assert_eq!(claims["jti"], "tok_at");
        assert_eq!(claims["scope"], "read write");
        assert!(claims.get("acr").is_none(), "no acr on a machine token");
        assert!(
            claims.get("auth_time").is_none(),
            "no auth_time on a machine token"
        );
        assert!(claims.get("nonce").is_none(), "no nonce on a machine token");
    }

    #[test]
    fn a_custom_claim_never_sets_a_reserved_claim() {
        // A hostile custom-claims config naming EVERY reserved claim (protocol,
        // authentication-context, binding, and hash/session) plus a benign one. The
        // protocol claims the machine token emits keep their real values; the
        // reserved-but-not-emitted claims are dropped entirely (a machine token
        // carries no auth context and no self-asserted cnf); only the benign lands.
        let custom = json!({
            // Protocol claims (must keep their real minted values).
            "sub": "attacker",
            "iss": "https://evil.test",
            "aud": "https://evil.test/api",
            "client_id": "cli_attacker",
            "exp": 9_999_999_999_i64,
            "iat": 0,
            "nbf": 0,
            "jti": "forged",
            "scope": "admin",
            "typ": "forged+jwt",
            "token_type": "mac",
            // Authentication-context claims (a machine token must assert none).
            "acr": "urn:evil:acr:high",
            "amr": ["mfa", "hwk"],
            "auth_time": 123,
            "nonce": "evil-nonce",
            "azp": "cli_attacker",
            // Binding / session / hash claims (only the issuer may state these).
            "cnf": { "jkt": "evil-thumbprint" },
            "at_hash": "evil-at-hash",
            "c_hash": "evil-c-hash",
            "sid": "evil-session",
            // Organization context (issue #94): a machine token asserts no human org.
            "org_id": "org_evil",
            // A benign business claim, which is admitted.
            "department": "payments"
        })
        .as_object()
        .cloned()
        .expect("object");
        let mut req = cc_request("sva_real", &custom);
        req.oauth_scope = Some("read");
        let claims = build_client_credentials_access_token_claims(
            &req,
            1000,
            1300,
            "tok_real",
            &json!("cli_example"),
        );
        // The emitted protocol claims keep their real minted values.
        assert_eq!(claims["sub"], "sva_real", "protected sub is never shadowed");
        assert_eq!(claims["iss"], "https://issuer.test/t/x/e/y");
        assert_eq!(claims["aud"], "cli_example");
        assert_eq!(claims["client_id"], "cli_example");
        assert_eq!(claims["exp"], 1300);
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["jti"], "tok_real");
        assert_eq!(
            claims["scope"], "read",
            "the granted scope wins over a custom scope"
        );
        // The reserved names the machine token does NOT emit must stay absent: a
        // custom claim can never inject an authentication context, a binding key, a
        // hash/session claim, or an out-of-band nbf/typ/token_type.
        for reserved_absent in [
            "nbf",
            "typ",
            "token_type",
            "acr",
            "amr",
            "auth_time",
            "nonce",
            "azp",
            "cnf",
            "at_hash",
            "c_hash",
            "sid",
            "org_id",
        ] {
            assert!(
                claims.get(reserved_absent).is_none(),
                "{reserved_absent} must never be injected by a custom claim"
            );
        }
        // The benign, non-reserved business claim is admitted.
        assert_eq!(
            claims["department"], "payments",
            "a benign custom claim lands"
        );
        // Sanity: every name the guard reserves is one it recognises, so none of the
        // hostile values above could have slipped through under a different spelling.
        for reserved in PROTECTED_ACCESS_TOKEN_CLAIMS {
            assert_ne!(
                claims.get(*reserved),
                custom.get(*reserved),
                "{reserved} must never carry the hostile custom value"
            );
        }
    }
}
