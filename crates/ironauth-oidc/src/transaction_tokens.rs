// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction tokens, PROTOTYPE (issue #133).
//!
//! # What this is, and what it is not
//!
//! One of the five version-tagged prototypes issue #133 asks for. It is EXPERIMENTAL, off by
//! default, and enabling it requires acknowledging the exact draft revision named by
//! [`TRANSACTION_TOKENS_DRAFT`]. It is not a supported token type: the exchange refuses the
//! requested type as unsupported when the flag is off, exactly as it refuses any unknown one,
//! so a deployment that has not opted in cannot tell the type has a meaning here.
//!
//! # The problem it exists for
//!
//! A request enters a trust domain at the edge, authenticated as a person. It then fans out
//! across a dozen internal services, and each hop has to know THREE things the original access
//! token cannot carry together: which person, which workload is asking now, and what the
//! original request was authorized to do. The usual answers are all bad. Passing the user's
//! access token inward makes every service a confused deputy holding a credential good at the
//! edge. Minting service-to-service tokens loses the user. Passing a header nobody signs loses
//! everything the moment one hop is compromised.
//!
//! `draft-ietf-oauth-transaction-tokens` answers it with a short-lived signed JWT, scoped to
//! ONE transaction inside ONE trust domain, carrying the user, the workload, and the
//! authorization context together.
//!
//! # What this prototype mints
//!
//! A `txn_token` JWT (the draft's media type; it carries no `+jwt` suffix, which is the draft's
//! choice) with:
//!
//! | claim | from | why |
//! |---|---|---|
//! | `iss` | this environment's issuer | who signed it |
//! | `aud` | the configured trust domain | where it may be spent, and NOWHERE else |
//! | `sub` | the REVALIDATED subject token | which person the request is for |
//! | `txn` | a fresh id | the transaction every hop shares |
//! | `rctx` | the authenticated client | which workload asked for THIS token |
//! | `azd` | the subject token's scopes | what the original request was authorized to do |
//! | `purp` | the request's `purpose`, when given | what this transaction is for |
//! | `iat`, `exp` | the clock | short, and bounded here rather than configured |
//!
//! `sub` comes from the token the exchange REVALIDATED, never from a claim read out of an
//! unverified payload; that is the token-exchange module's central invariant and this composes
//! on it rather than beside it.
//!
//! # Why the audience is the whole security story
//!
//! A transaction token is INTRA-domain by construction: it names the trust domain as its
//! audience, and a service outside that domain has no reason to accept it. That is the only
//! thing standing between "a short-lived internal assertion" and "a bearer credential that
//! escaped". So the audience is operator-configured and REQUIRED: with none set, the type is
//! refused rather than minted against a default, because a default trust domain is a trust
//! domain nobody chose.
//!
//! # What a graduation still needs
//!
//! Stated plainly so nothing here reads as finished.
//!
//! - **`azd` is the subject token's scope set, not RFC 9396 authorization details.** The draft's
//!   `azd` is a rich object describing what was authorized; this carries what IronAuth actually
//!   knows about the original request. A deployment making decisions on `azd` would need the
//!   richer shape, and the edge would need to have carried it in.
//! - **No replay recording, and no `txn` reuse across a call chain.** Every request mints a
//!   fresh transaction id, so two hops of one logical transaction get two ids. The draft's model
//!   is that the FIRST hop mints and later hops REQUEST A REPLACEMENT carrying the same `txn`;
//!   the replacement flow is not implemented.
//! - **No `sub_id`.** The draft allows a structured subject identifier (RFC 9493); this carries
//!   the plain `sub` the subject token carried.
//! - **One trust domain per environment.** A deployment with several would need the domain to
//!   be a per-request choice, which means deciding who may name which one.

use ironauth_jose::{EmissionOptions, SigningKey, TokenTyp, sign_jws};
use serde_json::{Value, json};

/// The EXACT draft revision this prototype implements.
///
/// It doubles as the experimental acknowledgment version: an operator enabling the feature
/// acknowledges this string, and a revision that changes the wire shape bumps it and invalidates
/// every acknowledgment in the wild.
pub const TRANSACTION_TOKENS_DRAFT: &str = "draft-ietf-oauth-transaction-tokens-09";

/// The RFC 8693 `requested_token_type` that asks for a transaction token.
pub const TRANSACTION_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:txn_token";

/// The longest a transaction token may live.
///
/// A transaction token is spent inside one trust domain over the life of one request, so its
/// lifetime is the request's, not a session's. Bounded HERE rather than configured because a
/// prototype that let an operator tune this would be inviting them to tune the one property
/// that makes an unreplayed, unrevoked internal assertion safe.
pub const MAX_LIFETIME_SECS: i64 = 300;

/// Why a transaction token was not minted.
///
/// Carried for the caller to map onto the exchange's own wire errors. Nothing here reaches a
/// client verbatim: the exchange answers its uniform refusals, exactly as it does for every
/// other reason it declines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionTokenRefusal {
    /// The feature is armed but no trust domain is configured, so there is nowhere the token
    /// could be spent. Refused rather than minted against a default.
    NoTrustDomain,
    /// The claims could not be serialised, or the signature failed.
    Mint,
}

/// Everything one transaction token carries.
///
/// A struct rather than seven positional arguments: five of them are strings, and a transposed
/// pair would mint a token naming the wrong person or the wrong workload while compiling
/// cleanly.
pub struct TransactionTokenRequest<'a> {
    /// This environment's issuer.
    pub issuer: &'a str,
    /// The trust domain the token may be spent in. Empty is a refusal, not a default.
    pub trust_domain: &'a str,
    /// The person, from the REVALIDATED subject token.
    pub subject: &'a str,
    /// The workload asking: the authenticated client.
    pub requester: &'a str,
    /// What the original request was authorized to do.
    pub authorization_context: &'a [String],
    /// What this transaction is for, when the caller said.
    pub purpose: Option<&'a str>,
    /// The transaction id every hop of this request shares.
    pub transaction_id: &'a str,
    /// Now, in seconds since the epoch.
    pub now_unix_seconds: i64,
    /// How long it lives, clamped to [`MAX_LIFETIME_SECS`].
    pub lifetime_secs: i64,
}

/// Mint one transaction token.
///
/// # Errors
///
/// [`TransactionTokenRefusal::NoTrustDomain`] when no audience is configured;
/// [`TransactionTokenRefusal::Mint`] on a serialisation or signing failure.
pub fn mint(
    key: &SigningKey,
    request: &TransactionTokenRequest<'_>,
) -> Result<String, TransactionTokenRefusal> {
    if request.trust_domain.is_empty() {
        return Err(TransactionTokenRefusal::NoTrustDomain);
    }
    // CLAMPED, not trusted. The caller resolves a lifetime from config and this is the last
    // place that can be wrong about it; a bound applied only where the value is read is a bound
    // one refactor away from not applying.
    let lifetime = request.lifetime_secs.clamp(1, MAX_LIFETIME_SECS);
    let mut claims = serde_json::Map::new();
    claims.insert("iss".to_owned(), json!(request.issuer));
    claims.insert("aud".to_owned(), json!(request.trust_domain));
    claims.insert("sub".to_owned(), json!(request.subject));
    claims.insert("txn".to_owned(), json!(request.transaction_id));
    claims.insert("rctx".to_owned(), json!({ "workload": request.requester }));
    claims.insert(
        "azd".to_owned(),
        json!({ "scope": request.authorization_context }),
    );
    if let Some(purpose) = request.purpose {
        claims.insert("purp".to_owned(), json!(purpose));
    }
    claims.insert("iat".to_owned(), json!(request.now_unix_seconds));
    claims.insert(
        "exp".to_owned(),
        json!(request.now_unix_seconds.saturating_add(lifetime)),
    );

    let payload =
        serde_json::to_vec(&Value::Object(claims)).map_err(|_| TransactionTokenRefusal::Mint)?;
    let options = EmissionOptions::new().with_token_typ(TokenTyp::TransactionToken);
    sign_jws(key, &payload, &options).map_err(|_| TransactionTokenRefusal::Mint)
}

// ===========================================================================
// The exchange seam.
// ===========================================================================

/// What the exchange knows when it reaches the transaction-token branch.
///
/// Every field comes from something the endpoint already VERIFIED: the subject from a
/// revalidated token, the requester from an authenticated client, the context from the subject
/// token's own scopes. Nothing here is read out of an unverified payload, which is the property
/// that lets this compose on the exchange rather than duplicate it.
pub struct ExchangeInputs<'a> {
    /// The RFC 8693 `requested_token_type`, if the caller named one.
    pub requested_type: Option<&'a str>,
    /// The person, from the revalidated subject token.
    pub subject: &'a str,
    /// The workload, from the authenticated client.
    pub requester: &'a str,
    /// What the subject token was authorized to do.
    pub authorization_context: &'a std::collections::BTreeSet<String>,
    /// What this transaction is for, when the caller said. The exchange's `scope` parameter,
    /// which in this profile is the caller's statement of purpose rather than a narrowing.
    pub purpose: Option<&'a str>,
}

/// Mint a transaction token if this request asked for one and the deployment can issue one.
///
/// Returns `Ok(None)` when the requested type is not a transaction token, when the feature is
/// not armed, or when no trust domain is configured. All three fall through to the ordinary
/// type negotiation, which refuses an unknown requested type as unsupported -- so an unarmed
/// deployment answers a `txn_token` request exactly as it answers a request for any URI it does
/// not implement, and the type's existence here is not observable.
///
/// # Errors
///
/// [`crate::TokenError::ServerError`] if the mint fails, which means the environment's
/// signing key or the claim serialisation is broken. A refusal to mint is never reported as a
/// client error: the client asked for something this deployment offers.
pub fn try_exchange(
    state: &crate::state::OidcState,
    scope: ironauth_store::Scope,
    entry: &std::sync::Arc<crate::issuer::IssuerEntry>,
    inputs: &ExchangeInputs<'_>,
) -> Result<Option<axum::response::Response>, crate::TokenError> {
    if inputs.requested_type != Some(TRANSACTION_TOKEN_TYPE) {
        return Ok(None);
    }
    // BOTH conditions, and neither implies the other: the flag says the operator accepts a
    // draft-stage wire format, the domain says where the token may be spent. `transaction_token_
    // domain` is `None` unless the boot path resolved both, so this one read answers both.
    let Some(trust_domain) = state.transaction_token_domain() else {
        return Ok(None);
    };

    // The environment's ACTIVE signer, chosen by the same rotation policy every other mint on
    // this issuer uses. `None` means this environment has no live key, which is a deployment
    // fault rather than anything the caller did.
    let Some(key) = entry.keyset().active_signer(state.now()) else {
        return Err(crate::TokenError::ServerError);
    };
    let now = crate::util::epoch_micros(state.now()) / 1_000_000;
    let transaction_id = format!(
        "txn_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let context: Vec<String> = inputs.authorization_context.iter().cloned().collect();
    let token = mint(
        key,
        &TransactionTokenRequest {
            issuer: &state.issuer_for(&scope),
            trust_domain,
            subject: inputs.subject,
            requester: inputs.requester,
            authorization_context: &context,
            purpose: inputs.purpose,
            transaction_id: &transaction_id,
            now_unix_seconds: now,
            lifetime_secs: MAX_LIFETIME_SECS,
        },
    )
    .map_err(|_| crate::TokenError::ServerError)?;

    Ok(Some(transaction_token_response(&token)))
}

/// The RFC 8693 response shape for an issued transaction token.
///
/// `issued_token_type` names what was ACTUALLY issued, which RFC 8693 section 2.2.1 requires and
/// which matters more here than usual: a caller that asked for a transaction token and received
/// an access token would have a credential with entirely different reach, and the field is how
/// it can tell without parsing the token.
fn transaction_token_response(token: &str) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({
            "access_token": token,
            "issued_token_type": TRANSACTION_TOKEN_TYPE,
            "token_type": "N_A",
            "expires_in": MAX_LIFETIME_SECS,
        })),
    )
        .into_response()
}
