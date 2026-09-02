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
//! | `azd` | the exchange's DECIDED scope | what THIS request was authorized to do |
//! | `act` | the exchange's decision, for a DELEGATION | who is acting for the subject |
//! | `purp` | NOT SET by the exchange path | see below |
//!
//! An ABSENT `act` is ambiguous by design: it means a downscope OR an impersonation, because
//! RFC 8693 section 1.1 defines impersonation as the actor not being distinguishable in the
//! token. A verifier cannot tell the two apart, and is not meant to; the audit row's `mode=`
//! is where that distinction lives, which is why the row records it.
//! | `iat`, `exp` | the clock | short, and bounded here rather than configured |
//!
//! `sub` comes from the token the exchange REVALIDATED, never from a claim read out of an
//! unverified payload; that is the token-exchange module's central invariant and this composes
//! on it rather than beside it.
//!
//! # Why `purp` is minted-but-never-set
//!
//! [`mint`] carries `purp` because it is part of the token shape the draft defines, and the
//! exchange path passes `None`. The draft defines the CLAIM and defines no request parameter
//! that carries it, and the only free string a caller can send on this endpoint is `scope`,
//! which means NARROW TO THIS everywhere else here. Reading it as a purpose would make one
//! parameter mean two things depending on a requested token type: the kind of overload a caller
//! gets wrong once and an implementer never notices. A graduation that wants `purp` should
//! define a parameter for it.
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
//! - **`azd` is the exchange's decided scope, not RFC 9396 authorization details.** The draft's
//!   `azd` is a rich object describing what was authorized; this carries the narrowed scope this
//!   exchange settled on, which is what THIS request may do. A deployment making decisions on `azd` would need the
//!   richer shape, and the edge would need to have carried it in.
//! - **No replay recording, and no `txn` reuse across a call chain.** Every request mints a
//!   fresh transaction id, so two hops of one logical transaction get two ids. The draft's model
//!   is that the FIRST hop mints and later hops REQUEST A REPLACEMENT carrying the same `txn`;
//!   the replacement flow is not implemented.
//! - **No `sub_id`.** The draft allows a structured subject identifier (RFC 9493); this carries
//!   the plain `sub` the subject token carried.
//! - **One trust domain per PROCESS, shared by every tenant.** The domain is a single
//!   `OidcConfig` field read once at boot, while the issuer is per (tenant, environment) -- so
//!   every tenant this process serves mints with the SAME `aud`. For a multi-tenant deployment
//!   that is the wrong axis, and it is the first thing a graduation has to change: the field
//!   would have to be per environment, which means deciding who may name which domain.

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

/// The longest a `purp` may be.
///
/// It is the only claim here that could come from a caller rather than from verified state, so
/// it is the only one that needs a bound. Generous against any real purpose string and small
/// against a hostile one.
pub const MAX_PURPOSE_BYTES: usize = 256;

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
    /// The purpose exceeded [`MAX_PURPOSE_BYTES`].
    PurposeTooLong,
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
    /// The actor chain, for a DELEGATION. Absent for a downscope and deliberately absent for an
    /// impersonation, which RFC 8693 section 1.1 defines as the actor not being distinguishable
    /// in the token; accountability for that mode is the audit row.
    pub act: Option<&'a Value>,
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
    // CLAMPED. The exchange path passes the maximum, so today this is the identity -- it is a
    // guard for a caller that resolves a lifetime from somewhere else, which is what a
    // graduation adding per-deployment tuning would be. Kept rather than deleted because the
    // whole mitigation for an unrevocable, unreplay-checked bearer token is that it expires
    // soon, and that bound should not live only at the one site that happens to set it.
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
        // BOUNDED. Every other claim here comes from verified state; a purpose would be
        // caller-supplied text signed by the environment key, and nothing caps a form field on
        // this plane. Megabytes of it would produce a token past the verifier's own size cap
        // that can therefore never verify -- a mint that always fails at the far end. Refused
        // rather than truncated: a silently shortened purpose is a different statement.
        if purpose.len() > MAX_PURPOSE_BYTES {
            return Err(TransactionTokenRefusal::PurposeTooLong);
        }
        claims.insert("purp".to_owned(), json!(purpose));
    }
    if let Some(act) = request.act {
        claims.insert("act".to_owned(), act.clone());
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
/// Every field comes from something the endpoint already VERIFIED or DECIDED: the subject from a
/// revalidated token, the requester from an authenticated client, and the context from the
/// exchange's own decision, which is the NARROWED scope after the impersonation policy, the
/// registered-grant list, the confidential-client requirement and the widening check have all
/// run. Nothing here is read from an unverified payload and nothing skips a control.
pub struct ExchangeInputs<'a> {
    /// The authenticated client, for the audit row's target.
    pub client_id: &'a ironauth_store::ClientId,
    /// The workload asking, as a string for the token's `rctx`.
    pub requester: &'a str,
    /// The person, from the revalidated subject token.
    pub subject: &'a str,
    /// What this exchange was DECIDED to authorize: the narrowed scope, not the subject token's
    /// full set. A caller that asked for less must not receive a token asserting more.
    pub authorization_context: &'a std::collections::BTreeSet<String>,
    /// Whether this was a downscope, a delegation, or an impersonation.
    ///
    /// Recorded in the audit row and the log line, because for a transaction token neither the
    /// token nor a grant carries it otherwise. Impersonation in particular is default-denied
    /// and, per issue #125, has to be recorded on every use.
    pub mode: &'a str,
    /// The actor chain the decision produced, present for a DELEGATION.
    ///
    /// Delegation is the mode with no per-client policy flag: its only accountability control
    /// is that `act` rides in the issued token, naming the party acting for the subject. A
    /// transaction token that dropped it would be indistinguishable from a downscope, so a
    /// service in the trust domain could not tell "this request is Alice's" from "this request
    /// is B acting for Alice".
    pub act: Option<&'a serde_json::Value>,
}

/// Mint a transaction token and record that it was minted.
///
/// Reached only when the caller asked for one AND the deployment can issue one, both of which
/// the exchange resolved before running its policy checks -- so by here every refusal that
/// applies to an ordinary exchange has already fired.
///
/// # Errors
///
/// [`crate::TokenError::ServerError`] if this environment has no live signing key, if the mint
/// fails, or if the audit row cannot be written. The last is not pedantry: a transaction token
/// is not revocable and not introspectable, so the audit row is the ONLY record that it exists,
/// and minting one nobody can trace would be worse than refusing.
pub async fn issue_transaction_token(
    state: &crate::state::OidcState,
    scope: ironauth_store::Scope,
    entry: &std::sync::Arc<crate::issuer::IssuerEntry>,
    inputs: &ExchangeInputs<'_>,
) -> Result<axum::response::Response, crate::TokenError> {
    let Some(trust_domain) = state.transaction_token_domain() else {
        // Unreachable: the caller resolved this before deciding. Kept as a refusal rather than
        // an `expect` because a second caller is exactly the kind of thing that gets added.
        return Err(crate::TokenError::ServerError);
    };
    // The environment's signer under ITS OWN rotation policy, which is what every other mint on
    // this issuer uses. `keyset().active_signer()` was wrong twice over: it ignores the policy
    // (so it can pick an algorithm the policy bans) and it breaks ties on insertion order, and
    // every environment provisions three day-one keys sharing one activation instant -- so
    // roughly a third of deployments would have signed transaction tokens with RS256 while
    // every other token from the same issuer was EdDSA.
    let Some(key) = entry.signer(state.now()) else {
        return Err(crate::TokenError::ServerError);
    };

    let now = crate::util::epoch_micros(state.now()) / 1_000_000;
    // The transaction id, which the audit row records. `CorrelationId` already carries its own
    // `req_` prefix, so prefixing again produced `txn_req_...`; the id is used verbatim.
    let transaction_id = ironauth_store::CorrelationId::generate(state.env()).to_string();
    let context: Vec<String> = inputs.authorization_context.iter().cloned().collect();
    let token = mint(
        key,
        &TransactionTokenRequest {
            issuer: &state.issuer_for(&scope),
            trust_domain,
            subject: inputs.subject,
            requester: inputs.requester,
            authorization_context: &context,
            // NO `purp`. The draft defines the claim and defines no request parameter that
            // carries it, and the exchange's `scope` -- the only free string a caller can send
            // here -- means NARROW TO THIS everywhere else on this endpoint. Repurposing it
            // would make one parameter mean two things depending on a token type, which is the
            // kind of overload a caller gets wrong once and an implementer never notices.
            purpose: None,
            act: inputs.act,
            transaction_id: &transaction_id,
            now_unix_seconds: now,
            lifetime_secs: MAX_LIFETIME_SECS,
        },
    )
    .map_err(|_| crate::TokenError::ServerError)?;

    // BEFORE the token leaves. A record written afterwards is one a crash can lose while the
    // credential is already out, and this row is the only record that the token exists at all.
    //
    // Attributed to the CLIENT, through the same helper the sibling write one function away
    // uses, not to a freshly generated service id. A throwaway actor means filtering the log by
    // a compromised client's identity returns every other door's rows and none of these.
    state
        .store()
        .scoped(scope)
        .acting(
            crate::util::client_service_actor(ironauth_store::StoredClientId::Registered(
                inputs.client_id,
            )),
            ironauth_store::CorrelationId::generate(state.env()),
        )
        .authorization()
        .record_transaction_token(
            state.env(),
            inputs.client_id,
            inputs.subject,
            &transaction_id,
            inputs.mode,
        )
        .await
        .map_err(|error| {
            tracing::error!(?error, "recording a transaction-token mint failed");
            crate::TokenError::ServerError
        })?;

    tracing::info!(
        client_id = %inputs.requester,
        txn = %transaction_id,
        mode = inputs.mode,
        delegated = inputs.act.is_some(),
        "transaction token issued (issue #133, PROTOTYPE)"
    );
    Ok(transaction_token_response(&token))
}

/// The RFC 8693 response shape for an issued transaction token.
///
/// `issued_token_type` names what was ACTUALLY issued, which RFC 8693 section 2.2.1 requires and
/// which matters more here than usual: a caller that asked for a transaction token and received
/// an access token would have a credential with entirely different reach, and the field is how
/// it can tell without parsing the token.
fn transaction_token_response(token: &str) -> axum::response::Response {
    // Through `token_ok`, the shared success shape every other token-endpoint response uses.
    // The hand-rolled version set `Cache-Control` and dropped `Pragma: no-cache`, which RFC
    // 6749 section 5.1 requires alongside it -- a second spelling of "the token response" that
    // had already drifted from the first on its first outing.
    crate::token::token_ok(
        &json!({
            "access_token": token,
            "issued_token_type": TRANSACTION_TOKEN_TYPE,
            "token_type": "N_A",
            "expires_in": MAX_LIFETIME_SECS,
        })
        .to_string(),
    )
}
