// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8693 token-exchange grant (issue #125).
//!
//! An authenticated client presents a `subject_token` it already holds and receives a
//! strictly weaker one. Optionally it also presents an `actor_token`, and then the actor
//! stays visible in the issued token's `act` chain.
//!
//! # The whole grant is built around REVALIDATION
//!
//! Every published CVE in this family is the same bug, and it is not a parsing bug: the
//! 2026 Zitadel privilege escalation, Casdoor's cross-organization signature bypass, and
//! Casdoor's acceptance of a revoked JWT are all exchanges that inherited trust from the
//! step which issued the subject token instead of checking it again. Dex's
//! `AllowedConnectors` bypass is the sibling shape: a client restriction enforced in some
//! grant handlers and not others.
//!
//! So this handler treats NOTHING about a presented token as true merely because this
//! server once signed it. Both tokens are re-resolved through
//! [`crate::introspection::revalidate`], which is the same scope-bound path an external
//! caller gets: it parses the token's `jti` IN the authenticated client's scope (so a
//! token from another tenant or environment simply does not resolve), asks the STORE
//! whether the grant is still live (so a revoked token is dead even while its signature
//! verifies), and verifies the signature and expiry against the token's own audience.
//!
//! That is a deliberate structural choice rather than a set of checks to remember. There
//! is no field on this path that is read from an unverified payload, and no branch that
//! skips a check because an earlier handler is believed to have run one.
//!
//! # How the mode is DERIVED, and why that is the security control
//!
//! RFC 8693 has no `mode` parameter, so the mode is inferred from what was presented:
//!
//! - An `actor_token` is present: **delegation**. The actor is recorded in `act`, nesting
//!   onto any chain the subject token already carried, so a multi-hop path stays legible.
//! - No actor token, and the subject token was issued to THIS client: **downscoping**. The
//!   client is narrowing its own token, which needs no extra permission because it can
//!   only ever end up with less than it already had.
//! - No actor token, and the subject token was issued to a DIFFERENT client:
//!   **impersonation**. The client is taking over a credential that is not its own and
//!   asking for the result to name nobody but the subject.
//!
//! That third case is the one that has to be earned. It is exactly the Zitadel shape (a
//! client escalating by exchanging a token it did not receive), and #125 requires it be
//! "disabled unless a per-client policy allows it, audited on every use". Deriving it this
//! way means a client cannot reach impersonation by omitting a parameter: presenting
//! somebody else's token without declaring yourself the actor IS the request to
//! impersonate, whether or not the caller thought of it that way, and it is default-denied.
//!
//! # Errors are opaque on the wire and specific in the log
//!
//! RFC 8693 section 2.2.2 requires the wire error to be opaque, and #125 says so directly
//! ("out-of-band diagnostics in the admin log view, opaque errors on the wire"). Every
//! refusal below therefore maps to `invalid_grant` or `invalid_target`, while the store's
//! typed denial (which names the rule that refused, and for a widened scope names the
//! scopes) is recorded out of band. A client learns that its exchange was refused and
//! never which of its guesses was closest.

use axum::http::HeaderMap;
use axum::response::Response;
use ironauth_store::grant_restriction::{ClientGrantPolicy, GrantType as StoreGrantType};
use ironauth_store::token_exchange::{ExchangeDenial, ExchangeMode, ExchangeRequest};
use ironauth_store::token_exchange_decision::{ExchangeDecisionInput, ExchangeRefusal, decide};
use ironauth_store::token_type_negotiation::{DefaultAccessFormat, IssuedTokenType, type_uri};
use ironauth_store::{
    ClientCredentialsAccess, CorrelationId, GrantId, IssueClientCredentials, NewOpaqueAccessToken,
    Scope, StoredClientId,
};
use serde_json::Value;

use crate::client_auth::{self, ClientAuthError, ClientAuthInputs, ClientAuthMethod};
use crate::error::TokenError;
use crate::introspection::IntrospectionClaims;
use crate::registry::GrantType;
use crate::state::OidcState;
use crate::token::TokenParams;
use crate::token::map_store_error;
use crate::tokens::{self, ClientCredentialsMintRequest, MintedAccessToken};
use crate::util::{client_service_actor, epoch_micros};

/// One presented token, after full revalidation.
struct ValidatedToken {
    /// The token's subject, as this server derives it.
    subject: String,
    /// The client the token was ISSUED to, which is what decides downscope vs impersonation.
    client_id: Option<String>,
    /// The scopes it actually carries.
    scope: std::collections::BTreeSet<String>,
    /// The audiences it is actually valid for.
    audience: std::collections::BTreeSet<String>,
    /// The `act` chain it already carries, for nesting.
    act: Option<Value>,
}

/// Split a space-separated OAuth list into a set, dropping empties.
fn space_set(raw: Option<&str>) -> std::collections::BTreeSet<String> {
    raw.unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// The RFC 8693 token-exchange grant.
///
/// # Errors
///
/// [`TokenError`] per the module documentation: `invalid_request` for a malformed request,
/// `invalid_client` for a failed authentication, `invalid_target` for an unknown target,
/// and an opaque `invalid_grant` for every refusal that concerns the tokens themselves.
pub async fn token_exchange_grant(
    state: &OidcState,
    headers: &HeaderMap,
    params: TokenParams,
    resources: &[String],
) -> Result<Response, TokenError> {
    // 1. The request has to be COHERENT before anything is authenticated.
    let subject_token = check_request_shape(&params)?;

    // 2-3. Authenticate the client and run the shared grant-restriction seam.
    let (scope, authenticated, client_id) =
        authenticate_for_exchange(state, headers, &params).await?;
    let client_id_str = authenticated.client_id.clone();

    // 4. Resolve the issuer BEFORE revalidating either token.
    //
    //    A fenced environment (suspended or offboarded) can mint nothing, and in one the
    //    signature check below cannot complete either, so revalidating first would answer
    //    a perfectly valid subject token with `invalid_grant`. That is precisely the harm
    //    `grant_issuer_entry` documents: a 4xx tells a conforming client to throw away a
    //    credential that is still good, where the 503 tells it to retry.
    //
    //    Ordering it here does NOT make the 503 an environment-existence oracle. The
    //    caller has already authenticated as a client of THIS scope, so it has proven the
    //    environment exists; the oracle the ordering rule guards against is an
    //    unauthenticated prober, which cannot reach this line.
    let entry = crate::token::grant_issuer_entry(state, scope).await?;

    // 5. Revalidate BOTH presented tokens IN FULL. Nothing below reads a field from an
    //    unverified payload; see the module docs for why this is the whole point.
    let subject = revalidated(state, scope, subject_token).await?;
    let actor = match params.actor_token.as_deref() {
        Some(token) => Some(revalidated(state, scope, token).await?),
        None => None,
    };

    // 6. FENCE EVERY principal this exchange would give authority to (issue #52's
    //    invariant, and the mint registry in docs/design/USER-BOUND-MINT-SITES.md).
    //
    //    This mint is user bound and NOTHING else reaches it. There is no live SSO session
    //    between the presented subject token and this mint, so the session cascade cannot
    //    fence it; the registry's rule for that case is the DIRECT read, and this is it.
    //    Without it a blocked, disabled, or deleted user's still-valid access token could
    //    be exchanged for a fresh one, extending their reach past the very act that was
    //    supposed to end it, and an exchange can be repeated indefinitely.
    //
    //    BOTH principals are fenced, not just the subject. In a delegation the issued token
    //    names the actor as the party driving it, so a blocked actor with a still-valid
    //    token would keep acting for other people through this endpoint after being
    //    stopped. Fencing the subject alone would close the obvious half and leave the half
    //    that grants somebody ELSE's authority open, which is the worse of the two.
    //
    //    The principal is discriminated STRUCTURALLY rather than assumed to be a user: a
    //    subject token minted by the client-credentials grant carries an `sva_` service
    //    account, which bears no lifecycle at all. Fencing that would query the `users`
    //    table for an id that is not in it and fail closed on every legitimate machine
    //    exchange, which is the same trap `fence_mapped_principal` documents next door.
    fence_principal(state, scope, &subject.subject).await?;
    if let Some(actor) = &actor {
        fence_principal(state, scope, &actor.subject).await?;
    }

    // 7. Derive the mode (see the module docs). Presenting a token that was issued to
    //    another client, without naming yourself as the actor, IS a request to
    //    impersonate, and it is default-denied below.
    let mode = if actor.is_some() {
        ExchangeMode::Delegation
    } else if subject.client_id.as_deref() == Some(client_id_str.as_str()) {
        ExchangeMode::Downscope
    } else {
        ExchangeMode::Impersonation
    };

    // What the client asked to narrow TO. The RFC 8707 `resource` parameter and the RFC
    // 8693 `audience` parameter both name a target service, so they are unioned: they are
    // the same request expressed two ways, and honouring only one would let the other
    // silently widen.
    let mut requested_audience = space_set(params.audience.as_deref());
    requested_audience.extend(resources.iter().cloned());

    // WANTS A TRANSACTION TOKEN (issue #133, PROTOTYPE), and can have one: the draft is
    // acknowledged and a trust domain is configured. Resolved here so the decision below runs
    // with the txn URI HIDDEN from the type negotiator, which would otherwise refuse it as
    // unsupported before any policy ran.
    //
    // Hiding it is what makes every control apply. The first version returned BEFORE `decide`,
    // and `decide` is the only place the impersonation policy, the registered-grant list and
    // the confidential-client requirement are enforced -- so a PUBLIC client registered for
    // another grant could present somebody else's access token and receive a signed assertion
    // naming that person, which every service in the trust domain accepts. On main the same
    // request is `invalid_grant`. With the type hidden, the negotiator settles the ordinary
    // access-token type, every refusal fires exactly as it does for any other exchange, and the
    // decision's NARROWED scope is what the transaction token then carries.
    let wants_transaction_token = params.requested_token_type.as_deref()
        == Some(crate::transaction_tokens::TRANSACTION_TOKEN_TYPE)
        && state.transaction_token_domain().is_some();

    let policy = ClientGrantPolicy {
        allowed: registered_grants(&authenticated.grant_types),
        confidential: authenticated.auth_method != ClientAuthMethod::None,
    };
    // Both policy flags come off the registration that JUST authenticated, never from a
    // second read. A separate query could return a different row than the one verified,
    // and for the impersonation flag that difference decides whether this client may take
    // over another client's token.
    let impersonation_allowed = authenticated.token_exchange_impersonation_allowed;
    let refresh_allowed = authenticated.token_exchange_refresh_allowed;

    let decision = decide(&ExchangeDecisionInput {
        client_policy: &policy,
        impersonation_allowed,
        refresh_allowed,
        default_format: match state.default_access_token_format() {
            ironauth_store::TokenFormat::AtJwt => DefaultAccessFormat::Jwt,
            ironauth_store::TokenFormat::Opaque => DefaultAccessFormat::Opaque,
        },
        exchange: ExchangeRequest {
            subject_scope: subject.scope.clone(),
            subject_audience: subject.audience.clone(),
            requested_scope: space_set(params.scope.as_deref()),
            requested_audience: requested_audience.clone(),
            actor_present: actor.is_some(),
            mode,
        },
        requested_type: if wants_transaction_token {
            None
        } else {
            params.requested_token_type.as_deref()
        },
        existing_act: subject.act.as_ref(),
        actor_subject: actor.as_ref().map(|token| token.subject.as_str()),
    })
    .map_err(|refusal| refused(&client_id_str, mode, &refusal))?;

    // A refresh token from an exchange needs its own family and rotation policy, which
    // this grant does not open. The negotiation above only permits the type for a client
    // explicitly configured for it, so reaching here means the configuration promises
    // something the handler cannot yet deliver: fail closed rather than quietly issue an
    // access token where a refresh token was asked for and allowed.
    if decision.token_type == IssuedTokenType::RefreshToken {
        tracing::error!(
            client_id = %client_id_str,
            "a client is configured for exchanged refresh tokens, which this grant does not issue"
        );
        return Err(TokenError::ServerError);
    }

    // The transaction token, now that every control has run and the scope is the NARROWED one.
    if wants_transaction_token {
        return crate::transaction_tokens::issue_transaction_token(
            state,
            scope,
            &entry,
            &crate::transaction_tokens::ExchangeInputs {
                client_id: &client_id,
                requester: &client_id_str,
                subject: &subject.subject,
                authorization_context: &decision.scope,
            },
        )
        .await;
    }

    issue(
        state,
        scope,
        &entry,
        &client_id_str,
        client_id,
        &subject,
        &decision,
        &requested_audience,
        mode,
    )
    .await
}

/// This client's mapping and hook, applied to an EMPTY source document.
///
/// Issue #113 criterion 1 does not name token exchange, and the per-client static claims stay
/// out of an exchanged token for the reason given at the mint below. But leaving one of the
/// three `ClientCredentialsMintRequest` doors unhooked would recreate the exact hole this
/// change closes, and it would be the door hardest to notice, because it is the one nobody
/// thinks of as a grant.
///
/// A hook here shapes a token minted FOR ANOTHER SUBJECT. That is a real capability and an
/// operator should have it (an exchange is where downstream routing claims belong), but it is
/// worth stating plainly rather than arriving at silently.
///
/// # Errors
///
/// [`TokenError::ServerError`] when the mapping cannot be read or the hook does not complete.
/// Fail-closed, as at every other door: shaping that did not happen can mean an entitlement
/// the operator meant to strip is still in the token.
async fn shaped_claims(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    subject: &str,
) -> Result<crate::claims_mapping_at_issuance::MappedAccessClaims, TokenError> {
    crate::claims_mapping_at_issuance::apply_to_machine_token(
        crate::claims_mapping_at_issuance::Issuance::for_state(state),
        scope,
        client_id,
        // The wire value, from the registry, not a literal beside it. Issue #113 asks the
        // grant to be identified in the payload, and a hook that gates on it is reading
        // this string: a door with its own copy can hand a guest a grant name the
        // endpoint does not accept, and only a test comparing two literals would notice.
        crate::registry::GrantType::TokenExchange.as_str(),
        Some(subject),
        &serde_json::Map::new(),
    )
    .await
    .map_err(|_| TokenError::ServerError)
}

/// Mint, persist, and audit the exchanged token.
///
/// The token goes through the SAME grant chain as every other issuance, which is what
/// makes it revocable and introspectable. That matters more here than anywhere else: an
/// exchange mints a credential from a credential, so a token that outlived revocation
/// would let one compromised subject token be laundered into a fresh one indefinitely.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is an independent input \
    already validated by the caller; bundling them into a struct would move the \
    parameter list rather than shorten it"
)]
#[allow(
    clippy::too_many_lines,
    reason = "two lines over the pedantic bound. The body is the RFC 8693 exchange \
    in order, and every step reads a value the step before it produced"
)]
async fn issue(
    state: &OidcState,
    scope: Scope,
    entry: &std::sync::Arc<crate::issuer::IssuerEntry>,
    client_id_str: &str,
    client_id: ironauth_store::ClientId,
    subject: &ValidatedToken,
    decision: &ironauth_store::token_exchange_decision::ExchangeDecision,
    requested_audience: &std::collections::BTreeSet<String>,
    mode: ExchangeMode,
) -> Result<Response, TokenError> {
    // The audience the issued token carries.
    //
    // Two paths, and the difference is not cosmetic. When the client named a target, it is
    // resolved through the shared resource-indicator machinery, so an unknown or
    // disallowed one fails with `invalid_target` (RFC 8707, #125's last criterion). When
    // it named none, the token INHERITS the subject token's audiences verbatim and no
    // lookup happens: inheriting cannot widen anything, and requiring the inherited
    // audience to be a registered resource server would break plain downscoping of a token
    // whose audience is simply the client id.
    let target = if requested_audience.is_empty() {
        let mut inherited = state
            .resolve_access_token_target(&scope, &[], client_id_str)
            .await
            .map_err(|_| TokenError::ServerError)?;
        inherited.audiences = decision.audience.iter().cloned().collect();
        inherited
    } else {
        let targets: Vec<String> = decision.audience.iter().cloned().collect();
        state
            .resolve_access_token_target(&scope, &targets, client_id_str)
            .await
            .map_err(|error| match error {
                crate::state::ResourceTargetError::InvalidTarget => TokenError::InvalidTarget,
                crate::state::ResourceTargetError::ServerError => TokenError::ServerError,
            })?
    };

    let granted_scope = decision
        .scope
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let granted_scope = (!granted_scope.is_empty()).then_some(granted_scope.as_str());

    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    let custom_claims = shaped_claims(state, scope, client_id_str, &subject.subject).await?;
    // Resolved BEFORE the mint, through the one shared helper (issue #126).
    let (workload_org, workload_roles) =
        crate::token::resolve_workload_org_and_roles(state, scope, &subject.subject).await?;
    // And the agent gate (issue #130), through ITS one shared helper. Issue #130 names token
    // exchange as an issuance path for an agent, so it has to be gated by the same set: a
    // control that only one of three doors applies is not a control.
    let agent =
        crate::token::gate_agent_issuance(state, scope, client_id_str, granted_scope).await?;
    let (minted, expires_in) = tokens::mint_client_credentials_access_token(
        state,
        signer,
        entry.policy(),
        &ClientCredentialsMintRequest {
            scope,
            issuer: &issuer,
            // The SUBJECT's subject, not the client's: an exchange issues a token for the
            // identity the subject token represented, which is the entire point.
            subject: &subject.subject,
            // The machine identity's organization and roles (issue #126), resolved through the
            // ONE shared helper so all three doors that mint under a service-account principal
            // answer alike. `(None, None)` for a subject that is not one.
            org_id: workload_org.as_deref(),
            roles: workload_roles.as_ref(),
            client_id: client_id_str,
            oauth_scope: granted_scope,
            // An exchange carries no `clients.custom_token_claims`. Those describe the
            // client's own SERVICE ACCOUNT, so putting them on a token that speaks for a user
            // conflates two identities.
            //
            // The client's declarative MAPPING does run, and a `static` rule in it WILL reach
            // this token. Review flagged that as a contradiction of the sentence above, and it
            // is only a contradiction if the reason is "config must not decorate another
            // subject". It is not: a client's mapping already shapes the tokens it causes to be
            // minted for interactive users, so a `static` rule landing here is the same power
            // rather than a new one, and the authorization-bearing names are fenced from both
            // mappings and hooks. `the_mapping_reaches_an_exchanged_token` pins it so it stays
            // a decision. What separates the two is identity, not origin.
            custom_claims: &custom_claims,
            act: decision.act.as_ref(),
            // The GATE applies here; the identity claims do NOT. An exchange mints for the SUBJECT
            // the exchanged token represented, so `agent_id` beside a `sub` that is someone else
            // would say the token belongs to an agent while its own subject says it does not. The
            // agent is the actor at this door, and RFC 8693 `act` is where an actor belongs.
            agent: None,
        },
        &target,
    )
    .map_err(|()| TokenError::ServerError)?;

    let grant_id = GrantId::generate(state.env(), &scope);
    let access = match &minted {
        MintedAccessToken::Jwt { jti, .. } => ClientCredentialsAccess::Jwt { jti },
        MintedAccessToken::Opaque {
            digest,
            jti,
            audiences,
            expires_at_unix_micros,
            ..
        } => ClientCredentialsAccess::Opaque(NewOpaqueAccessToken {
            token_digest: digest.as_str(),
            grant_id: None,
            subject: subject.subject.as_str(),
            client_id: client_id_str,
            audience: audiences.first().map_or("", String::as_str),
            audiences,
            scope: granted_scope,
            jti,
            expires_at_unix_micros: *expires_at_unix_micros,
            dpop_jkt: None,
        }),
    };

    // Persist and AUDIT in one transaction (#125: "every exchange emits an audit event").
    // The row records the acting client and the subject; the mode is logged alongside,
    // because impersonation is only defensible if every use of it is recorded.
    tracing::info!(
        client_id = %client_id_str,
        mode = ?mode,
        scope = granted_scope.unwrap_or(""),
        delegated = decision.act.is_some(),
        "token exchange issued"
    );
    state
        .store()
        .scoped(scope)
        .acting(
            client_service_actor(StoredClientId::Registered(&client_id)),
            CorrelationId::generate(state.env()),
        )
        .authorization()
        .issue_token_exchange(
            state.env(),
            IssueClientCredentials {
                grant_id: &grant_id,
                client_id: &client_id,
                subject: subject.subject.as_str(),
                created_at_unix_micros: epoch_micros(state.now()),
                access,
            },
        )
        .await
        .map_err(|error| {
            // An exchange that mints but cannot persist would hand out a token that is
            // neither revocable nor introspectable, so this fails the request. The cause is
            // logged because a silent server_error here is indistinguishable from a signing
            // fault, and the two have completely different remedies.
            tracing::error!(?error, client_id = %client_id_str, "persisting a token exchange failed");
            map_store_error(error)
        })?;

    // The issuance row, AFTER the token exists (issue #130).
    if let Some(agent) = &agent {
        crate::token::record_agent_issuance(state, scope, agent, granted_scope).await;
    }
    Ok(response(&minted, expires_in, granted_scope))
}

/// The RFC 8693 section 2.2.1 success response.
///
/// `issued_token_type` is REQUIRED and is what tells the client what it actually got,
/// which need not be what it asked for.
fn response(minted: &MintedAccessToken, expires_in: i64, scope: Option<&str>) -> Response {
    let mut body = serde_json::json!({
        "access_token": minted.token(),
        "issued_token_type": type_uri::ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(scope) = scope {
        body["scope"] = serde_json::json!(scope);
    }
    crate::token::token_ok(&body.to_string())
}

/// Refuse the exchange when a principal it would give authority to cannot authenticate.
///
/// Applied to the subject AND, in a delegation, to the actor: see the call site for why
/// both, and for why this is the DIRECT read rather than the session cascade. The wire
/// answer is the uniform opaque `invalid_grant`, so a caller cannot use the endpoint to
/// probe which accounts are fenced; a store fault is a `server_error`, because minting on
/// an unread lifecycle is the failure this exists to prevent.
async fn fence_principal(
    state: &OidcState,
    scope: Scope,
    principal: &str,
) -> Result<(), TokenError> {
    match crate::jwt_bearer::MappedPrincipal::classify(principal, &scope) {
        // Carries no lifecycle: a service account or workload principal. The fence does
        // not apply and MUST not, or every machine exchange fails closed.
        crate::jwt_bearer::MappedPrincipal::Workload => Ok(()),
        // A user id from another tenant or environment is lifecycle bearing but
        // unfenceable from here, so it is refused rather than minted unchecked.
        crate::jwt_bearer::MappedPrincipal::ForeignUser => Err(TokenError::InvalidGrant),
        crate::jwt_bearer::MappedPrincipal::User => {
            match crate::token::subject_can_authenticate(state, scope, principal).await {
                Ok(true) => Ok(()),
                Ok(false) => {
                    tracing::warn!("refusing a token exchange for a fenced principal");
                    Err(TokenError::InvalidGrant)
                }
                Err(_) => Err(TokenError::ServerError),
            }
        }
    }
}

/// Authenticate the client and run the shared grant-restriction seam.
///
/// Returns the client's `(tenant, environment)` scope, the authentication record (which
/// carries the exchange policy read off the very registration that authenticated), and the
/// parsed client id.
///
/// The seam runs FIRST among the post-authentication checks and before any token content
/// is looked at, so a client not registered for this grant learns nothing about the tokens
/// it sent.
async fn authenticate_for_exchange(
    state: &OidcState,
    headers: &HeaderMap,
    params: &TokenParams,
) -> Result<
    (
        Scope,
        crate::client_auth::AuthenticatedClient,
        ironauth_store::ClientId,
    ),
    TokenError,
> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: params.client_id.as_deref(),
        client_secret: params.client_secret.as_deref(),
        client_assertion: params.client_assertion.as_deref(),
        client_assertion_type: params.client_assertion_type.as_deref(),
    };
    let via_basic = is_basic_scheme(authorization);
    // Recover the scope from the CLAIMED client id so the scoped authentication can run,
    // exactly as the client-credentials grant does. A parse failure, or a client id
    // declaring no valid scope, is a uniform invalid_client.
    let presented = crate::client_auth::parse_presented(
        inputs.authorization,
        inputs.client_id,
        inputs.client_secret,
        inputs.client_assertion,
        inputs.client_assertion_type,
    )
    .map_err(|_| TokenError::InvalidClient { via_basic })?;
    let scope = ironauth_store::ClientId::parse_declared_scope(presented.client_id())
        .map(|id| id.scope())
        .map_err(|_| TokenError::InvalidClient { via_basic })?;
    let authenticated = client_auth::authenticate_client(state, scope, inputs)
        .await
        .map_err(|error| match error {
            ClientAuthError::InvalidRequest(message) => {
                TokenError::InvalidRequest(message.to_owned())
            }
            ClientAuthError::InvalidClient { via_basic } => TokenError::InvalidClient { via_basic },
        })?;

    crate::token::enforce_registered_grant_for(state, &authenticated, GrantType::TokenExchange)?;

    let client_id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(&authenticated.client_id)
        .map_err(|_| TokenError::InvalidClient { via_basic })?;
    Ok((scope, authenticated, client_id))
}

/// Check the RFC 8693 request shape, returning the `subject_token` to exchange.
///
/// Runs BEFORE authentication, so it must disclose nothing: every answer here depends only
/// on the parameters the caller itself sent, never on stored state.
///
/// RFC 8693 section 2.1 makes each token's type EXPLICIT rather than sniffed, and this
/// enforces that literally. A caller cannot have one kind of token read as another, which
/// is what stops an ID token (an authentication receipt for one client, not a credential
/// to trade) or a refresh token (already redeemable by its own grant, under its own
/// rotation policy) from becoming a second, less-guarded path to what the first path
/// controls.
fn check_request_shape(params: &TokenParams) -> Result<&str, TokenError> {
    let subject_token = required(params.subject_token.as_deref(), "subject_token is required")?;
    let subject_type = required(
        params.subject_token_type.as_deref(),
        "subject_token_type is required",
    )?;
    if subject_type != type_uri::ACCESS_TOKEN {
        return Err(TokenError::InvalidRequest(
            "subject_token_type must name an access token".to_owned(),
        ));
    }
    // An actor token and its type travel together: a type without a token describes
    // nothing, and a token without a type is the sniffing this grant refuses to do.
    match (
        params.actor_token.as_deref(),
        params.actor_token_type.as_deref(),
    ) {
        (Some(_), None) => Err(TokenError::InvalidRequest(
            "actor_token_type is required with actor_token".to_owned(),
        )),
        (None, Some(_)) => Err(TokenError::InvalidRequest(
            "actor_token is required with actor_token_type".to_owned(),
        )),
        (Some(_), Some(actor_type)) if actor_type != type_uri::ACCESS_TOKEN => Err(
            TokenError::InvalidRequest("actor_token_type must name an access token".to_owned()),
        ),
        _ => Ok(subject_token),
    }
}

/// Require a present, non-blank parameter.
fn required<'a>(value: Option<&'a str>, message: &str) -> Result<&'a str, TokenError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenError::InvalidRequest(message.to_owned()))
}

/// Whether the `Authorization` header presents the Basic scheme, so a failed
/// authentication carries the RFC 6749 5.2 `WWW-Authenticate: Basic` header.
fn is_basic_scheme(authorization: Option<&str>) -> bool {
    authorization.is_some_and(|value| {
        let value = value.trim_start();
        value.len() >= 6 && value.as_bytes()[..6].eq_ignore_ascii_case(b"basic ")
    })
}

/// The client's registered grants, parsed from the space-separated registration.
fn registered_grants(grant_types: &str) -> Vec<StoreGrantType> {
    grant_types
        .split_whitespace()
        .filter_map(|wire| {
            StoreGrantType::ALL
                .into_iter()
                .find(|grant| grant.as_wire() == wire)
        })
        .collect()
}

/// Revalidate one presented token IN FULL, or refuse.
///
/// Delegates to the introspection resolver, so the checks are the ones an external caller
/// gets and cannot drift from them: scope-bound `jti` parse (cross-tenant and
/// cross-environment), the store as revocation authority, and signature plus expiry.
///
/// Every failure is the SAME opaque `invalid_grant`. A distinct error per cause would turn
/// this endpoint into the token-scanning oracle RFC 7662 section 4 warns about, letting a
/// client with one valid credential learn which of its guesses were real tokens.
async fn revalidated(
    state: &OidcState,
    scope: Scope,
    token: &str,
) -> Result<ValidatedToken, TokenError> {
    let claims: IntrospectionClaims = crate::introspection::revalidate(state, scope, token)
        .await
        .ok_or(TokenError::InvalidGrant)?;
    // A refresh token resolves but is not an access token, and must not be exchangeable
    // through a parameter that claimed it was one.
    if !claims.is_access_token {
        return Err(TokenError::InvalidGrant);
    }
    let subject = claims.sub.ok_or(TokenError::InvalidGrant)?;
    Ok(ValidatedToken {
        subject,
        client_id: claims.client_id,
        scope: space_set(claims.scope.as_deref()),
        audience: claims.aud.into_iter().collect(),
        act: claims.act,
    })
}

/// Record a refusal out of band and return the OPAQUE wire error.
///
/// The mapping is deliberate: only an unknown or disallowed TARGET gets its own wire code,
/// because RFC 8707 defines `invalid_target` for exactly that and a client has to be able
/// to tell "this service does not exist" from "you may not have it". Everything else is
/// one `invalid_grant`.
fn refused(client_id: &str, mode: ExchangeMode, refusal: &ExchangeRefusal) -> TokenError {
    let reason = match refusal {
        ExchangeRefusal::Grant(denial) => denial.as_str(),
        ExchangeRefusal::Narrowing(denial) => denial.as_str(),
        ExchangeRefusal::TokenType(denial) => denial.as_str(),
        ExchangeRefusal::ActChain(error) => error.as_str(),
    };
    tracing::warn!(
        client_id = %client_id,
        mode = ?mode,
        reason,
        "refusing a token exchange"
    );
    // A refusal ABOUT THE REQUESTED TARGET gets RFC 8707's `invalid_target`; everything
    // else is the opaque `invalid_grant`.
    //
    // The line is drawn there because a target mistake is the one a client can act on: it
    // named a service, and either this deployment does not serve it or this token may not
    // reach it. Collapsing that into `invalid_grant` tells a client its TOKEN was bad when
    // its token was fine, which sends it to re-authenticate instead of to its
    // configuration. Scope and mode refusals stay opaque, because there the useful detail
    // is exactly the detail that would enumerate what the caller does hold.
    if matches!(
        refusal,
        ExchangeRefusal::Narrowing(ExchangeDenial::AudienceWidened(_))
    ) {
        return TokenError::InvalidTarget;
    }
    TokenError::InvalidGrant
}
