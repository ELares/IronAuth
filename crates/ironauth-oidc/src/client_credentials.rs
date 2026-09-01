// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `client_credentials` grant (RFC 6749 4.4, issue #23): an authenticated
//! confidential client obtains a machine-to-machine (M2M) access token for its own
//! first-class SERVICE-ACCOUNT PRINCIPAL.
//!
//! The exchange:
//!
//! 1. Recover the `(tenant, environment)` scope from the CLAIMED client id (a `cli_`
//!    id embeds it), so the RLS-scoped client authentication can run. The claim is
//!    unverified here; the client then proves possession of its secret within this
//!    scope, exactly as a management key declares its scope then proves its secret.
//! 2. AUTHENTICATE the client through the ONE shared seam
//!    ([`client_auth::authenticate_client`]): RFC 6749 4.4 REQUIRES client
//!    authentication, so a PUBLIC client (auth method `none`, which proves nothing)
//!    is refused as `invalid_client`.
//! 3. Validate the requested `scope` against the M2M policy (`invalid_scope` for an
//!    out-of-policy request): the unconditional [`DISALLOWED_M2M_SCOPES`] floor,
//!    then the per-client scope allowlist issue #98 added
//!    ([`ironauth_store::ClientScopePolicy`]), which can only narrow further.
//! 4. Resolve the client's STABLE service-account principal (minted lazily on the
//!    first issuance, read back every time after), which is the token's `sub`.
//! 5. Mint ONLY the access token (at+jwt or opaque per the #29 target), carrying the
//!    RFC 9068 claims plus the per-client STATIC custom claims. No ID token (there is
//!    no user) and NO refresh token (RFC 6749 4.4.3).
//! 6. Persist a fresh machine GRANT and record the access token against it, so the
//!    token is revocable and introspectable by the #22 endpoints by construction
//!    (the SAME grant-chain the code/refresh tokens use).
//!
//! # Covenant: no metering on the issuance path
//!
//! There is deliberately NO metering, counting-for-billing, or quota hook anywhere
//! in this module (a covenant of the M2M path). `scripts/no-m2m-metering.sh` asserts
//! it as a CI lint; the audit row written by `issue_client_credentials` is a
//! SECURITY audit (who/what/when for revocation and forensics), not a meter.

use axum::http::{HeaderMap, header};
use axum::response::Response;
use ironauth_store::{
    ClientCredentialsAccess, ClientId, ClientScopePolicy, CorrelationId, GrantId,
    IssueClientCredentials, NewOpaqueAccessToken, Scope, StoreError, StoredClientId,
};
use serde_json::json;

use crate::client_auth::{
    self, AuthenticatedClient, ClientAuthError, ClientAuthInputs, ClientAuthMethod, parse_presented,
};
use crate::error::TokenError;
use crate::state::OidcState;
use crate::token::{TokenParams, map_store_error, token_ok};
use crate::tokens::{self, ClientCredentialsMintRequest, MintedAccessToken};
use crate::util::{client_service_actor, epoch_micros};

/// OAuth scope values a client-credentials (machine) request may NOT ask for (issue
/// #23). Both are user/OIDC-centric and meaningless for an M2M principal:
///
/// - `openid` triggers OIDC and an ID token, which requires an authenticated end
///   user; a client-credentials token has a machine `sub`, no user.
/// - `offline_access` requests a refresh token, which RFC 6749 4.4.3 forbids on this
///   grant.
///
/// A request naming either is an out-of-policy `invalid_scope`.
///
/// # This is a FLOOR BENEATH the per-client allowlist, never a thing it replaces
///
/// Issue #98 added the per-client allowlist ([`ironauth_store::ClientScopePolicy`]),
/// and this list keeps its full force underneath it. [`validate_m2m_scope`] applies
/// the denylist FIRST and unconditionally, so a client whose configured allowlist
/// literally names `openid` can request NOTHING rather than an ID token: a
/// misconfigured or maliciously written allowlist can only ever narrow what a machine
/// may ask for, never widen it past this floor.
const DISALLOWED_M2M_SCOPES: &[&str] = &["openid", "offline_access"];

/// The ATTESTATION path (issue #133, PROTOTYPE), or `None` when it was not attempted.
///
/// Extracted so the grant reads as one flow rather than two: everything after it is identical
/// for a client that proved a secret and one that proved possession of an attested key, and a
/// second copy of that would be a second place for the two to disagree.
///
/// Client credentials is the grant an attested instance uses -- an instance holding no
/// registered secret is asking for its own token, not a user's -- so this is where the
/// prototype plugs in. The other grants are unchanged, which is the point of a prototype.
///
/// # Errors
///
/// [`TokenError::InvalidRequest`] when more than one authentication method is presented;
/// [`TokenError::InvalidClient`] for a missing or unparseable `client_id` and for every
/// authentication failure.
async fn attested_client(
    state: &OidcState,
    headers: &HeaderMap,
    params: &TokenParams,
    authorization: Option<&str>,
) -> Result<Option<(Scope, AuthenticatedClient)>, TokenError> {
    // BOTH headers, or this is not an attestation attempt. One alone is not a partial attempt
    // to be helped along: treating it as one would give an unauthenticated prober a way to
    // tell the method's presence from its absence, because the request would take a different
    // path and could answer differently.
    let (Some(attestation), Some(proof)) = (
        headers
            .get(crate::attestation_client_auth::ATTESTATION_HEADER)
            .and_then(|value| value.to_str().ok()),
        headers
            .get(crate::attestation_client_auth::ATTESTATION_POP_HEADER)
            .and_then(|value| value.to_str().ok()),
    ) else {
        return Ok(None);
    };

    // WITH THE FEATURE OFF, these headers mean nothing and must change nothing. Checking the
    // registry first is what keeps that true: the mixing refusal below used to run before it,
    // so a deployment that had never enabled the prototype started answering 400 to a request
    // with perfectly good Basic credentials that happened to carry the two headers -- where it
    // had answered 200. A prototype that is off has to be invisible, not merely inert.
    if state.attesters().is_none() {
        return Ok(None);
    }

    // Mixing methods is refused rather than resolved. RFC 6749 section 2.3 forbids more than
    // one authentication method on a request, and resolving it in either direction would be a
    // downgrade an attacker chooses.
    //
    // ALL FOUR of the other credential inputs, not the two that came to mind. The first
    // version named the Authorization header and `client_secret`, so a request carrying the
    // attestation headers AND a `client_assertion` was silently resolved in favour of the
    // attestation -- the exact thing the sentence above says cannot happen. And it was
    // over-broad in the other direction: it fired on ANY Authorization scheme, while
    // `parse_presented` deliberately ignores a non-Basic one, so a Bearer header alongside
    // these would have been a 400 where the secret path ignores it.
    if is_basic_scheme(authorization)
        || params.client_secret.is_some()
        || params.client_assertion.is_some()
        || params.client_assertion_type.is_some()
    {
        return Err(TokenError::InvalidRequest(
            "more than one client authentication method was presented".to_owned(),
        ));
    }
    let claimed = params
        .client_id
        .as_deref()
        .ok_or(TokenError::InvalidClient { via_basic: false })?;
    let scope = ClientId::parse_declared_scope(claimed)
        .map(|id| id.scope())
        .map_err(|_| TokenError::InvalidClient { via_basic: false })?;
    let authenticated =
        client_auth::authenticate_attested(state, scope, claimed, attestation, proof)
            .await
            .map_err(|error| match error {
                ClientAuthError::InvalidRequest(message) => {
                    TokenError::InvalidRequest(message.to_owned())
                }
                ClientAuthError::InvalidClient { via_basic } => {
                    TokenError::InvalidClient { via_basic }
                }
            })?;
    Ok(Some((scope, authenticated)))
}

/// The `client_credentials` grant handler (issue #23).
pub async fn client_credentials_grant(
    state: &OidcState,
    headers: &HeaderMap,
    params: TokenParams,
) -> Result<Response, TokenError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    let attested = attested_client(state, headers, &params, authorization).await?;

    let inputs = ClientAuthInputs {
        authorization,
        client_id: params.client_id.as_deref(),
        client_secret: params.client_secret.as_deref(),
        client_assertion: params.client_assertion.as_deref(),
        client_assertion_type: params.client_assertion_type.as_deref(),
    };

    // 1 and 2, or the attested pair already computed above. The two authentication paths
    // CONVERGE here on purpose: everything below -- the registered-grant check, the public-
    // client refusal, the scope allowlist, the issuance -- is the same for a client that
    // proved a secret and one that proved possession of an attested key, and a second copy of
    // it would be a second place for the two to disagree.
    let (scope, authenticated, via_basic) = if let Some((scope, authenticated)) = attested {
        (scope, authenticated, false)
    } else {
        {
            // Recover the scope from the CLAIMED client id so the scoped authentication can
            // run. A parse failure or a client id that declares no valid scope is a uniform
            // invalid_client (a Basic attempt drives the 401 WWW-Authenticate).
            let presented = parse_presented(
                inputs.authorization,
                inputs.client_id,
                inputs.client_secret,
                inputs.client_assertion,
                inputs.client_assertion_type,
            )
            .map_err(|_| TokenError::InvalidClient {
                via_basic: is_basic_scheme(authorization),
            })?;
            let via_basic = presented.via_basic();
            let scope = ClientId::parse_declared_scope(presented.client_id())
                .map(|id| id.scope())
                .map_err(|_| TokenError::InvalidClient { via_basic })?;

            // Authenticate the client (RFC 6749 4.4 REQUIRES it). The shared seam verifies the
            // secret in scope and records any failure out of band, so enforcement matches the
            // code and refresh grants.
            let authenticated = client_auth::authenticate_client(state, scope, inputs)
                .await
                .map_err(|error| match error {
                    ClientAuthError::InvalidRequest(message) => {
                        TokenError::InvalidRequest(message.to_owned())
                    }
                    ClientAuthError::InvalidClient { via_basic } => {
                        TokenError::InvalidClient { via_basic }
                    }
                })?;
            (scope, authenticated, via_basic)
        }
    };
    // The ONE shared grant-restriction seam (issue #763): this client must be
    // registered for the grant it just presented.
    crate::token::enforce_registered_grant_for(
        state,
        &authenticated,
        crate::registry::GrantType::ClientCredentials,
    )?;
    let client_id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(&authenticated.client_id)
        .map_err(|_| TokenError::InvalidClient { via_basic })?;

    // A PUBLIC client (auth method `none`) authenticates with nothing, so it can
    // never satisfy the client-credentials grant's mandatory client authentication
    // (RFC 6749 4.4). Refuse it as invalid_client.
    let record = state
        .store()
        .scoped(scope)
        .clients()
        .auth_record(&client_id)
        .await
        .map_err(map_store_error)?;
    if record.auth_method == ClientAuthMethod::None.as_str() {
        return Err(TokenError::InvalidClient { via_basic });
    }

    // 3. Validate the requested scope against the M2M policy: the unconditional
    //    denylist floor, then the client's own scope allowlist (issue #98), read here
    //    because the client has proven who it is and the read fails closed.
    let policy = load_scope_policy(state, scope, &client_id, via_basic).await?;
    // BOTH refusal kinds are `invalid_scope` here, and on THIS grant that is the whole
    // spec-correct answer. RFC 6749 4.4 requires client authentication, and it has
    // already run two steps above, so nobody reaches this line who has not proven they
    // are the client whose allowlist this is: naming the allowlist as the reason
    // discloses that client's configuration to that client. The jwt-bearer grant
    // permits a PUBLIC presenting client and therefore cannot answer this way; it maps
    // the two kinds apart in `jwt_bearer::resolve_machine_scope`. Matched exhaustively
    // rather than with a wildcard so a third refusal kind has to be decided here too.
    let requested_scope =
        validate_m2m_scope(params.scope.as_deref(), &policy).map_err(|refusal| match refusal {
            M2mScopeRefusal::Floor | M2mScopeRefusal::Allowlist => TokenError::InvalidScope,
        })?;

    // 4-6. Resolve the principal, mint the access token, persist the machine grant,
    //      and build the response.
    mint_and_persist(state, scope, &client_id, requested_scope.as_deref()).await
}

/// Resolve the client's service-account principal, mint the M2M access token, record
/// it against a fresh machine grant, and build the `200 OK` response (issue #23,
/// steps 4-6 of the exchange). Split out of [`client_credentials_grant`] so each half
/// stays readable; the client is already authenticated and its scope proven.
#[allow(
    clippy::too_many_lines,
    reason = "one line over the pedantic bound. The body is a straight sequence of \
    steps (resolve the principal, mint, build the access record, persist), and \
    splitting it would put the mint and the persist that makes it revocable in \
    different functions, which is exactly the seam that must not be easy to skip"
)]
async fn mint_and_persist(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    requested_scope: Option<&str>,
) -> Result<Response, TokenError> {
    // The STABLE service-account principal (the token's sub), minted lazily on the
    // first issuance and read back every time after, so `sub` is consistent across
    // issuances and DISTINCT from client_id.
    let principal = state
        .store()
        .scoped(scope)
        .acting(
            client_service_actor(StoredClientId::Registered(client_id)),
            CorrelationId::generate(state.env()),
        )
        .service_accounts()
        .ensure(state.env(), client_id)
        .await
        .map_err(map_store_error)?;
    let subject = principal.to_string();
    let client_id_str = client_id.to_string();

    // THE AGENT GATE (issue #130), through the ONE shared helper every door that mints a
    // machine token calls. Resolved BEFORE anything is minted, so a refusal costs no signing
    // and leaves no token behind. `None` for an ordinary machine identity.
    let agent =
        crate::token::gate_agent_issuance(state, scope, &client_id_str, requested_scope).await?;

    // The per-client STATIC custom claims (fail-open: a malformed stored config
    // under-claims rather than failing issuance; the protected-claim guard is in the
    // mint regardless).
    let static_claims = load_custom_claims(state, scope, client_id).await;
    // The mapping and the hook (issue #113 criterion 1). A machine token is the one an operator
    // most wants to shape -- entitlement tiers, tenant tags, downstream routing -- and until
    // this call it was the one grant with no extension point at all.
    //
    // Fail-CLOSED, unlike `load_custom_claims` above, and the two sit next to each other so the
    // difference is visible: a static claim blob that will not parse under-claims, while a
    // mapping or hook that will not run means the operator's shaping did not happen, and a
    // shaped claim is as likely to REMOVE an entitlement as add one.
    let custom_claims = crate::claims_mapping_at_issuance::apply_to_machine_token(
        crate::claims_mapping_at_issuance::Issuance::for_state(state),
        scope,
        &client_id_str,
        // The wire value, from the registry, not a literal beside it. Issue #113 asks the
        // grant to be identified in the payload, and a hook that gates on it is reading
        // this string: a door with its own copy can hand a guest a grant name the
        // endpoint does not accept, and only a test comparing two literals would notice.
        crate::registry::GrantType::ClientCredentials.as_str(),
        Some(&subject),
        &static_claims,
    )
    .await
    .map_err(|_| TokenError::ServerError)?;

    // Resolve the access-token target: format (per resource-server config / env
    // default) and the default M2M audience (per config). The client-credentials
    // grant does not compose with RFC 8707 resource indicators in issue #28 (there is
    // no prior authorization to downscope from), so it always resolves the no-resource
    // target: the configurable default audience. The empty-resource branch is
    // infallible, so a failure here can only be an internal error.
    let default_audience = state.client_credentials_default_audience(&scope, &client_id_str);
    let target = state
        .resolve_access_token_target(&scope, &[], &default_audience)
        .await
        .map_err(|_| TokenError::ServerError)?;

    // Mint ONLY the access token: no ID token, and NO refresh token (RFC 6749 4.4.3).
    let entry = crate::token::grant_issuer_entry(state, scope).await?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    // Resolved BEFORE the mint, through the one shared helper (issue #126).
    let (workload_org, workload_roles) =
        crate::token::resolve_workload_org_and_roles(state, scope, &subject).await?;
    let (minted, expires_in) = tokens::mint_client_credentials_access_token(
        state,
        signer,
        entry.policy(),
        &ClientCredentialsMintRequest {
            scope,
            issuer: &issuer,
            subject: &subject,
            // The machine identity's organization and roles (issue #126), resolved through the
            // ONE shared helper so all three doors that mint under a service-account principal
            // answer alike. `(None, None)` for a subject that is not one.
            org_id: workload_org.as_deref(),
            roles: workload_roles.as_ref(),
            client_id: &client_id_str,
            oauth_scope: requested_scope,
            custom_claims: &custom_claims,
            // A machine token acts for itself: never an `act` chain (issue #125).
            act: None,
            agent: agent.as_ref().map(|a| tokens::AgentTokenIdentity {
                agent_id: a.agent_id.as_str(),
                linked_user_id: a.linked_user_id.as_str(),
                organization_id: a.organization_id.as_str(),
            }),
        },
        &target,
    )
    .map_err(|()| TokenError::ServerError)?;

    // Persist a fresh machine grant + record the access token against it, so the token
    // is revocable and introspectable by the #22 endpoints by construction.
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
            // Bound to THIS grant by the issuing method, so left None here.
            grant_id: None,
            subject: subject.as_str(),
            client_id: client_id_str.as_str(),
            audience: audiences.first().map_or("", String::as_str),
            audiences,
            scope: requested_scope,
            jti,
            expires_at_unix_micros: *expires_at_unix_micros,
            // The client-credentials grant carries no DPoP proof: a bearer token.
            dpop_jkt: None,
        }),
    };
    state
        .store()
        .scoped(scope)
        .acting(
            client_service_actor(StoredClientId::Registered(client_id)),
            CorrelationId::generate(state.env()),
        )
        .authorization()
        .issue_client_credentials(
            state.env(),
            IssueClientCredentials {
                grant_id: &grant_id,
                client_id,
                subject: subject.as_str(),
                created_at_unix_micros: epoch_micros(state.now()),
                access,
            },
        )
        .await
        .map_err(map_store_error)?;

    // The issuance row, AFTER the token exists (issue #130).
    if let Some(agent) = &agent {
        crate::token::record_agent_issuance(state, scope, agent, requested_scope).await;
    }
    Ok(client_credentials_response(
        &minted,
        expires_in,
        requested_scope,
    ))
}

/// Whether the `Authorization` header presents the Basic scheme, so a failed
/// authentication carries the RFC 6749 5.2 `WWW-Authenticate: Basic` header. Safe on
/// any bytes: it compares the ASCII scheme token without slicing on a char boundary.
fn is_basic_scheme(authorization: Option<&str>) -> bool {
    authorization.is_some_and(|value| {
        let value = value.trim_start();
        value.len() >= 6 && value.as_bytes()[..6].eq_ignore_ascii_case(b"basic ")
    })
}

/// Read the presenting client's per-client scope allowlist (issue #98) before the
/// machine-grant scope check, on the DATA plane under forced row-level security.
///
/// Fails CLOSED, deliberately unlike [`load_custom_claims`] next door. An
/// under-claimed custom claim costs the client a claim; an unread allowlist would
/// cost the deployment its delegation restriction, so a store fault is a
/// `server_error` and a client that no longer resolves is `invalid_client`, never a
/// silently unrestricted issuance.
///
/// # It is a SECOND read of a row the caller already has, and that is filed
///
/// Both callers have already read this client's row: `client_credentials_grant`
/// through `clients().auth_record`, the jwt-bearer grant through
/// `authenticate_client`. This opens another `begin_scoped` transaction (BEGIN, the
/// isolation level, two `set_config` calls for the row-level-security scope, the
/// query, COMMIT) for ONE column of it, so a machine-token issuance pays roughly six
/// extra round trips it does not need. Not a defect, and deliberately not fixed
/// inside issue #98: folding `allowed_scopes` onto the existing `auth_record` read is
/// tracked as issue #427, which also records what a fix must not regress (this
/// fail-closed mapping, the store's fail-safe parse, and the control plane's
/// column-scoped `UPDATE` monopoly). [`ironauth_store::ClientScopePolicyRepo`] stays
/// either way: the CONTROL plane reads through it too.
pub(crate) async fn load_scope_policy(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    via_basic: bool,
) -> Result<ClientScopePolicy, TokenError> {
    state
        .store()
        .scoped(scope)
        .client_scope_policies()
        .get(client_id)
        .await
        .map_err(|error| match error {
            StoreError::NotFound => TokenError::InvalidClient { via_basic },
            other => {
                tracing::error!(error = %other, "could not read the client scope allowlist");
                TokenError::ServerError
            }
        })
}

/// Whether one requested scope token is permitted by the client's allowlist (issue
/// #98). [`None`] means "no per-client allowlist configured", so any token is
/// admitted; a [`Some`] allowlist restricts the client to EXACTLY its entries (an
/// empty allowlist admits nothing). Shaped as the twin of
/// `resource::resource_on_allowlist`.
///
/// This decides ADMISSION only. It never rescues a token the denylist floor has
/// already refused, because [`validate_m2m_scope`] runs that floor first.
fn scope_on_allowlist(token: &str, policy: &ClientScopePolicy) -> bool {
    match &policy.allowed_scopes {
        None => true,
        Some(allowed) => allowed.iter().any(|entry| entry == token),
    }
}

/// Why [`validate_m2m_scope`] refused a requested machine-grant `scope`, returned
/// instead of a wire error so each grant decides for ITSELF what to answer.
///
/// The two kinds disclose different things and that is the entire reason this type
/// exists rather than one shared [`TokenError::InvalidScope`]:
///
/// - [`M2mScopeRefusal::Floor`] is [`DISALLOWED_M2M_SCOPES`], a PUBLIC COMPILE-TIME
///   CONSTANT. Answering it on the wire tells a caller nothing that is not already
///   readable in the source, so the spec-exact `invalid_scope` is free.
/// - [`M2mScopeRefusal::Allowlist`] is PER-CLIENT, OPERATOR-WRITTEN configuration. A
///   wire answer that depends on it is a READ of that configuration, one scope token
///   per request.
///
/// On `client_credentials` the distinction costs nothing, because the grant REQUIRES
/// client authentication and the reader is therefore always the client whose
/// allowlist it is. On the jwt-bearer grant a PUBLIC (`none`) presenting client is
/// deliberately permitted and the scope check runs BEFORE the assertion is touched,
/// so the same answer would be an UNAUTHENTICATED enumeration oracle; see
/// `jwt_bearer::resolve_machine_scope`, which folds the allowlist refusal into that
/// grant's uniform `invalid_grant` and records the specific reason out of band.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum M2mScopeRefusal {
    /// A requested token is on [`DISALLOWED_M2M_SCOPES`], the unconditional floor.
    Floor,
    /// A requested token is outside the client's configured allowlist (issue #98).
    Allowlist,
}

/// Validate a requested machine-grant `scope` against the M2M policy (issue #23,
/// widened with the per-client allowlist in issue #98), returning the normalized
/// granted scope (whitespace-collapsed) or [`None`] when none was requested.
///
/// Shared with the jwt-bearer assertion grant (issue #26): a mapped-identity
/// assertion-grant token is a machine token with no interactive user, so it is
/// governed by the SAME policy, reusing this one helper rather than duplicating the
/// check. On that grant the allowlist is the PRESENTING client's, which is the
/// client the token is minted for. One policy, two grants, but NOT one wire answer:
/// the refusal comes back as a [`M2mScopeRefusal`] and each grant maps it, because
/// only one of the two has authenticated the caller by this point.
///
/// # Two layers, in this order, and the order is the security property
///
///   1. [`DISALLOWED_M2M_SCOPES`], the unconditional FLOOR. `openid` and
///      `offline_access` are refused whatever the client's allowlist says.
///   2. The per-client allowlist, which can only narrow further.
///
/// Running the floor first is what makes an allowlist that names `openid` a client
/// that can request nothing rather than a client that can request an ID token. A
/// stored allowlist is operator-written configuration, and a configuration mistake
/// must not be able to buy back a refusal the protocol layer makes.
/// `an_allowlist_naming_openid_is_still_refused` pins it.
///
/// # No charset validation, and the asymmetry that follows
///
/// The split is `split_whitespace()` and nothing validates a scope token's
/// CHARACTERS, here or anywhere else in IronAuth. The allowlist validates a request
/// against ITSELF and against no registry (discovery still serves a hard-coded
/// `SCOPES_SUPPORTED`). So `read:orders` is a legal scope token here while being an
/// ILLEGAL permission slug under issue #98's permission grammar. The two vocabularies
/// are deliberately different and neither is being converged onto the other.
///
/// # Errors
///
/// [`M2mScopeRefusal::Floor`] if any requested token is on the floor's denylist;
/// [`M2mScopeRefusal::Allowlist`] if any is outside a configured allowlist. The
/// CALLER picks the wire error, because the two refusals disclose different things
/// and the two grants are not equally exposed. See [`M2mScopeRefusal`].
pub(crate) fn validate_m2m_scope(
    raw: Option<&str>,
    policy: &ClientScopePolicy,
) -> Result<Option<String>, M2mScopeRefusal> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    // Layer 1: the floor. Unconditional, and BEFORE the allowlist is even read.
    if tokens
        .iter()
        .any(|token| DISALLOWED_M2M_SCOPES.contains(token))
    {
        return Err(M2mScopeRefusal::Floor);
    }
    // Layer 2: the per-client allowlist, which narrows and never widens.
    if !tokens.iter().all(|token| scope_on_allowlist(token, policy)) {
        return Err(M2mScopeRefusal::Allowlist);
    }
    Ok(Some(tokens.join(" ")))
}

/// Load a client's per-client STATIC custom claims within scope (issue #23).
///
/// Fail-open: a store read error, an absent config, or a stored value that is not a
/// JSON OBJECT all yield an empty map (logged), so a misconfiguration under-claims
/// rather than bricking every issuance for the client. The protected-registered-claim
/// guard lives in the mint regardless, so this never returns claims that could
/// override `iss`/`sub`/`aud`/... anyway.
async fn load_custom_claims(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
) -> serde_json::Map<String, serde_json::Value> {
    let raw = match state
        .store()
        .scoped(scope)
        .clients()
        .custom_token_claims(client_id)
        .await
    {
        Ok(Some(raw)) => raw,
        Ok(None) => return serde_json::Map::new(),
        Err(error) => {
            tracing::warn!(%error, "could not read client custom claims; issuing without them");
            return serde_json::Map::new();
        }
    };
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(serde_json::Value::Object(object)) => object,
        // A non-object stored config (array/scalar/null) is a misconfiguration:
        // under-claim rather than fail the issuance.
        Ok(_) => {
            tracing::warn!("client custom claims are not a JSON object; issuing without them");
            serde_json::Map::new()
        }
        Err(error) => {
            tracing::warn!(%error, "client custom claims are not valid JSON; issuing without them");
            serde_json::Map::new()
        }
    }
}

/// Build the `200 OK` client-credentials token response (RFC 6749 4.4.3 / 5.1): the
/// access token, its type and lifetime, and the granted scope when present. There is
/// deliberately NO `refresh_token` (RFC 6749 4.4.3 forbids it on this grant) and no
/// `id_token` (there is no user).
fn client_credentials_response(
    minted: &MintedAccessToken,
    expires_in: i64,
    scope: Option<&str>,
) -> Response {
    let mut body = json!({
        "access_token": minted.token(),
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    token_ok(&body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No allowlist configured: the client may ask for anything the floor permits.
    fn unrestricted() -> ClientScopePolicy {
        ClientScopePolicy {
            allowed_scopes: None,
        }
    }

    /// An allowlist naming exactly `values`.
    fn allowing(values: &[&str]) -> ClientScopePolicy {
        ClientScopePolicy {
            allowed_scopes: Some(values.iter().map(|value| (*value).to_owned()).collect()),
        }
    }

    /// The granted scope of an accepted request. Panics if the request was refused,
    /// so a test that expects an acceptance cannot silently pass on a refusal.
    /// [`TokenError`] is not [`PartialEq`], hence the pair of helpers rather than a
    /// bare `assert_eq!`.
    #[track_caller]
    fn granted(raw: &str, policy: &ClientScopePolicy) -> Option<String> {
        validate_m2m_scope(Some(raw), policy).expect("the request must be accepted")
    }

    /// Assert a request is refused, and refused for the EXACT kind given.
    ///
    /// The kind is asserted rather than merely "refused" because the two kinds no
    /// longer answer the same thing on the wire: the jwt-bearer grant maps
    /// [`M2mScopeRefusal::Allowlist`] into its uniform `invalid_grant` and only
    /// [`M2mScopeRefusal::Floor`] to `invalid_scope`. A test that accepted either
    /// would let the two swap silently and re-open the enumeration oracle.
    #[track_caller]
    fn refused(raw: &str, policy: &ClientScopePolicy, expected: M2mScopeRefusal) {
        match validate_m2m_scope(Some(raw), policy) {
            Err(actual) => assert_eq!(actual, expected, "`{raw}` was refused for the wrong reason"),
            Ok(granted) => panic!("`{raw}` must be refused, but it granted {granted:?}"),
        }
    }

    /// A NULL column still admits everything the floor allows, so migration 0096
    /// changes the behaviour of every client already registered by nothing at all.
    #[test]
    fn no_allowlist_admits_everything_the_floor_allows() {
        let policy = unrestricted();
        assert!(
            validate_m2m_scope(None, &policy)
                .expect("no requested scope is accepted")
                .is_none()
        );
        assert!(
            granted("   ", &policy).is_none(),
            "blank is no scope at all"
        );
        assert_eq!(
            granted("read:orders  write:orders", &policy).as_deref(),
            Some("read:orders write:orders"),
            "whitespace is collapsed and every token passes"
        );
        // The floor still bites with no allowlist configured.
        refused("openid", &policy, M2mScopeRefusal::Floor);
        refused("offline_access", &policy, M2mScopeRefusal::Floor);
    }

    /// A configured allowlist RESTRICTS to exactly its members, and the empty
    /// allowlist admits nothing.
    #[test]
    fn a_configured_allowlist_restricts_and_the_empty_one_admits_nothing() {
        let policy = allowing(&["read:orders", "write:orders"]);
        assert_eq!(
            granted("read:orders", &policy).as_deref(),
            Some("read:orders")
        );
        assert_eq!(
            granted("read:orders write:orders", &policy).as_deref(),
            Some("read:orders write:orders")
        );
        // One token outside the allowlist refuses the WHOLE request; a partial grant
        // would hand back a token the client did not ask for.
        refused("read:orders admin", &policy, M2mScopeRefusal::Allowlist);
        refused("admin", &policy, M2mScopeRefusal::Allowlist);
        // Membership is exact: no prefix, no case folding, no substring.
        refused("read:order", &policy, M2mScopeRefusal::Allowlist);
        refused("READ:ORDERS", &policy, M2mScopeRefusal::Allowlist);

        // The empty allowlist is a real, maximally restrictive value: the client may
        // request no scope at all. Requesting NONE is still fine (there is nothing to
        // refuse), which is the same shape the resource allowlist has.
        let empty = allowing(&[]);
        assert!(
            validate_m2m_scope(None, &empty)
                .expect("requesting nothing is not a refusal")
                .is_none()
        );
        refused("read:orders", &empty, M2mScopeRefusal::Allowlist);
    }

    /// THE FLOOR SURVIVES THE ALLOWLIST. An operator who writes `openid` into a
    /// client's allowlist gets a client that can request nothing, not a client that
    /// can request an ID token.
    ///
    /// This is the assertion that makes the denylist a FLOOR BENEATH the allowlist
    /// rather than a default the allowlist replaces. Making the denylist conditional
    /// on the allowlist being absent, or dropping the denylist arm when a token is
    /// allowlisted, turns the first three cases here green in the wrong direction.
    #[test]
    fn an_allowlist_naming_openid_is_still_refused() {
        let policy = allowing(&["openid", "offline_access", "read:orders"]);
        // The refusal KIND is the assertion, not merely the refusal: a token that IS on
        // the allowlist still comes back as the FLOOR, which is what proves the floor
        // ran first rather than the allowlist happening to agree.
        refused("openid", &policy, M2mScopeRefusal::Floor);
        refused("offline_access", &policy, M2mScopeRefusal::Floor);
        refused("read:orders openid", &policy, M2mScopeRefusal::Floor);
        // The rest of that same allowlist still works, so the refusal is about the two
        // floor values and not about the allowlist being rejected wholesale.
        assert_eq!(
            granted("read:orders", &policy).as_deref(),
            Some("read:orders")
        );
    }

    /// The EMPTY allowlist is what a malformed stored value reads as
    /// (`ClientScopePolicyRepo::get`), so this is the OIDC-side half of the fail-safe
    /// direction: the store maps corruption to `Some(vec![])` and this layer maps
    /// `Some(vec![])` to a refusal. The store-side half is
    /// `a_malformed_allowlist_denies_everything`.
    #[test]
    fn the_fail_safe_empty_allowlist_refuses_every_scoped_request() {
        let empty = allowing(&[]);
        // `openid` is paired with the FLOOR rather than the allowlist because the floor
        // runs first and answers first, even under a value that would refuse it anyway.
        for (requested, kind) in [
            ("read:orders", M2mScopeRefusal::Allowlist),
            ("a b c", M2mScopeRefusal::Allowlist),
            ("openid", M2mScopeRefusal::Floor),
            ("anything", M2mScopeRefusal::Allowlist),
        ] {
            refused(requested, &empty, kind);
        }
        // The bound, pinned here as a DECISION rather than left to the name: a request
        // that names NO scope still succeeds, because `scope` is optional in OAuth and a
        // scopeless token is the least authority token there is. Asserting it in the same
        // test that refuses every named scope stops the two halves drifting into prose
        // that disagrees, which is what happened before this line existed.
        assert!(
            matches!(validate_m2m_scope(None, &empty), Ok(None)),
            "an empty allowlist must not refuse a request that asks for nothing"
        );
    }
}
