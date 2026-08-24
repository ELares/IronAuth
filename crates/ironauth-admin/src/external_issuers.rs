// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registering external assertion issuers and their subject mappings (issue #126).
//!
//! Workload identity federation's enforcement half shipped and was well covered: assertion
//! verification, per-issuer JWKS resolution through the SSRF-hardened fetcher, audience
//! narrowing, the algorithm pin, subject mapping with claim conditions, deny-by-default, and
//! an issuance audit carrying the external issuer and subject.
//!
//! Nothing could turn it on. `external_assertion_issuers` and
//! `external_assertion_subject_mappings` were writable only from the store repository: no
//! management route, no `IaC` resource, no config field, no CLI command. Every registration in
//! the tree came from a test harness calling the repository directly, which an operator cannot
//! do, so issue #126's first two criteria were unreachable rather than undemonstrated. The
//! sibling module for issue #112 names the same shape: a control that ships its enforcement
//! and not its granting path is a control nobody can turn on.
//!
//! ## Why disabling AND deleting are both here
//!
//! Revoking trust in a compromised issuer is the operation an operator needs FASTEST, and an
//! API that can add a trust anchor but not remove one is worse than an incomplete API. Both
//! resources therefore ship their enable/disable route beside their create.
//!
//! Delete is here too, and the pair is not redundant. Disable is REVOCATION: the row stays,
//! the listing still shows what was once trusted, and the switch flips back, which is what an
//! incident responder wants. Delete is CORRECTION: it frees the natural key.
//!
//! An earlier draft of this surface shipped disable alone, on the reasoning above, and that
//! was wrong rather than merely spare. Both tables carry a UNIQUE constraint on their natural
//! key with no `enabled` predicate, so a parked row keeps occupying it and re-registering the
//! same issuer answers 409 forever. The configuration columns are immutable to both planes,
//! and the `iss` string is dictated by the external platform, so an issuer that rotated the
//! keys behind a pinned inline `jwks` could never be repointed and every workload behind it
//! would stay unable to authenticate. Deleting costs nothing an incident responder needs:
//! `audit_log` holds no foreign key here, so the registration, every toggle, and the deletion
//! all survive in the place built to keep them. See migration 0153.
//!
//! A disabled issuer is refused by the grant exactly as an unregistered one is, and stays
//! visible here; a deleted one is gone, and its mappings survive it, because a mapping names
//! the issuer STRING rather than the row.
//!
//! ## What a listing returns, and what it must not
//!
//! `jwks` is an issuer's PUBLIC key set and `jwks_uri` is a public URL, so both are returned.
//! There is no secret on either resource: an external issuer authenticates by signing, so
//! IronAuth holds only public material for it. That is worth stating because the sibling
//! flow-target surface DOES hold a secret name and has to be careful; this one has nothing to
//! be careful with, and a reader should not have to infer that from an absence.
//!
//! ## Why the mapping list shows disabled rows
//!
//! `AssertionSubjectMappingRepo::resolve` filters them out, because the grant asks which
//! mapping APPLIES. This asks what EXISTS. An operator who cannot see a disabled mapping
//! cannot re-enable it and cannot tell it from one that was never created.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One registered external issuer, as an operator reads it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ExternalIssuerView {
    /// The `xai_` identifier.
    pub id: String,
    /// The `iss` an assertion must carry to be judged against this anchor.
    pub issuer: String,
    /// The pinned JWKS document, verbatim, or null when the issuer is resolved by URI.
    /// PUBLIC key material: an external issuer authenticates by signing, so nothing secret
    /// is held for it.
    pub jwks: Option<String>,
    /// The JWKS URL, fetched and cached through the SSRF-hardened fetcher, or null when the
    /// document is pinned inline.
    pub jwks_uri: Option<String>,
    /// A space-separated per-issuer algorithm allowlist, intersected with the deployment's
    /// own set, or null to accept the deployment set unchanged. It can only NARROW.
    pub signing_alg_allow: Option<String>,
    /// A space-separated per-issuer audience allowlist, intersected with the deployment's
    /// acceptable audiences, or null to accept them unchanged. It can only NARROW.
    pub audience_allow: Option<String>,
    /// Whether the grant will judge assertions against this anchor. A disabled issuer is
    /// refused exactly as an unregistered one is.
    pub enabled: bool,
}

/// A page of registered issuers.
#[derive(Debug, Serialize, ToSchema)]
pub struct ExternalIssuerList {
    /// The issuers registered in this environment, oldest first.
    pub issuers: Vec<ExternalIssuerView>,
}

/// The body to register an external issuer.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterExternalIssuerRequest {
    /// The `iss` an assertion must carry. Compared exactly, never by prefix.
    pub issuer: String,
    /// A pinned JWKS document. Exactly one of `jwks` and `jwks_uri` must be present: an
    /// issuer with neither has no key to verify against and would refuse every assertion,
    /// and an issuer with both leaves which one wins unstated.
    #[serde(default)]
    pub jwks: Option<String>,
    /// A JWKS URL to resolve and cache.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// An optional space-separated algorithm allowlist. Narrowing only.
    #[serde(default)]
    pub signing_alg_allow: Option<String>,
    /// An optional space-separated audience allowlist. Narrowing only.
    #[serde(default)]
    pub audience_allow: Option<String>,
}

/// The identifier a registration minted.
#[derive(Debug, Serialize, ToSchema)]
pub struct ExternalIssuerCreated {
    /// The `xai_` identifier.
    pub id: String,
}

/// The body to enable or disable a registered resource.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetEnabledRequest {
    /// Whether the resource should be live.
    pub enabled: bool,
}

/// One subject mapping, as an operator reads it.
#[derive(Debug, Serialize, ToSchema)]
pub struct SubjectMappingView {
    /// The `asm_` identifier.
    pub id: String,
    /// The external issuer this rule maps from.
    pub issuer: String,
    /// The external `sub` this rule maps from.
    pub external_subject: String,
    /// An optional additional claim NAME the assertion must carry with `match_value`, or
    /// null when the (issuer, subject) pair alone is the rule.
    pub match_claim: Option<String>,
    /// The value `match_claim` must equal, or null when `match_claim` is null.
    pub match_value: Option<String>,
    /// The registered machine identity a matched assertion is issued as (the token's `sub`).
    pub principal: String,
    /// Whether the rule is live. A disabled rule is listed and does not fire.
    pub enabled: bool,
}

/// A page of subject mappings.
#[derive(Debug, Serialize, ToSchema)]
pub struct SubjectMappingList {
    /// The mappings registered in this environment, oldest first, INCLUDING disabled ones.
    pub mappings: Vec<SubjectMappingView>,
}

/// The body to author a subject mapping.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSubjectMappingRequest {
    /// The external issuer to map from. Must name a registered issuer.
    pub issuer: String,
    /// The external `sub` to map from.
    pub external_subject: String,
    /// An optional additional claim gate. Both `match_claim` and `match_value` must be
    /// present together or both absent; a database CHECK enforces it and this rejects the
    /// half-set form at the edge so the caller gets a message rather than a constraint.
    #[serde(default)]
    pub match_claim: Option<String>,
    /// The value the optional `match_claim` must equal.
    #[serde(default)]
    pub match_value: Option<String>,
    /// The registered machine identity a matched assertion is issued as: an `sva_` service
    /// account that already exists in this environment. It becomes the issued token's `sub`,
    /// so a principal naming nothing would mint tokens no reader can attribute. Refused at
    /// authoring time rather than at the first assertion.
    pub principal: String,
}

/// The identifier a mapping creation minted.
#[derive(Debug, Serialize, ToSchema)]
pub struct SubjectMappingCreated {
    /// The `asm_` identifier.
    pub id: String,
}

/// Mint the event a write on this surface announces.
///
/// `subject` is the ordering key, and it is the resource's NATURAL key rather than its row
/// id. The row id would order a single row's own events correctly and get the one sequence
/// this surface exists to support exactly wrong: a repoint is delete-then-register, which is
/// two DIFFERENT rows, so under row-id keys the two events land in different ordering groups
/// and can be delivered in either order. A receiver reconciling by issuer string, which is
/// why both payloads carry it, would then apply `registered` before `deleted` and conclude an
/// issuer is untrusted while it is live: literally the inversion this key exists to prevent.
///
/// The natural key is the issuer string for an anchor and `(issuer, external_subject)` for a
/// mapping, which is what the unique constraints are on, so every event about one trust
/// relationship is serialized whatever row happens to carry it. The mapping key joins its two
/// halves with a newline, and a crafted collision between two mappings would only
/// over-serialize their deliveries, never reorder anything.
///
/// The envelope comes from the REGISTRY (`event_catalog::envelope`) rather than the local
/// builder, which is what every other producer in this crate but four does. The local one hardcodes
/// `PAYLOAD_SCHEMA_VERSION = 1` and accepts any type string; the registry one looks the
/// version up and returns `None` for an unregistered or wrongly-scoped type. A hand-passed
/// version is a second declaration of the same fact, and a later bump on one of these six
/// types would stamp the stale number and make the fan-out refuse every delivery permanently.
fn pending(
    state: &AdminState,
    scope: ironauth_store::Scope,
    event_type: &str,
    subject: &str,
    payload: &serde_json::Value,
) -> Result<crate::events::PendingEvent, ApiError> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    // `None` means the type is unregistered or is not environment scoped. Both are programmer
    // errors this module cannot recover from, and failing here means the WRITE never happens,
    // rather than committing a row whose notice is undeliverable.
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        payload,
    )
    .ok_or(ApiError::Internal)?;
    Ok(crate::events::PendingEvent {
        id,
        subject: subject.to_owned(),
        envelope,
    })
}

fn issuer_view(record: ironauth_store::ExternalAssertionIssuerRecord) -> ExternalIssuerView {
    ExternalIssuerView {
        id: record.id.to_string(),
        issuer: record.issuer,
        jwks: record.jwks,
        jwks_uri: record.jwks_uri,
        signing_alg_allow: record.signing_alg_allow,
        audience_allow: record.audience_allow,
        enabled: record.enabled,
    }
}

fn mapping_view(record: ironauth_store::AssertionSubjectMappingRecord) -> SubjectMappingView {
    SubjectMappingView {
        id: record.id.to_string(),
        issuer: record.issuer,
        external_subject: record.external_subject,
        match_claim: record.match_claim,
        match_value: record.match_value,
        principal: record.principal,
        enabled: record.enabled,
    }
}

/// The ordering key for a mapping's events: its natural key, the pair the unique constraint
/// is on.
fn mapping_key(issuer: &str, external_subject: &str) -> String {
    format!("{issuer}\n{external_subject}")
}

/// Whether `issuer` is an issuer THIS deployment serves, for any tenant and environment.
///
/// `IssuerRegistry::issuer_for` builds every one as `{base}/t/{tenant}/e/{environment}`, so
/// the tail is the identifying part and the base is not needed. Both segments must be scoped
/// identifiers of the right level, which is what keeps a third-party issuer that happens to
/// use a `/t/.../e/...` path from being refused.
fn names_a_scope_of_this_deployment(issuer: &str) -> bool {
    let mut segments = issuer.rsplit('/');
    let (Some(environment), Some(e_marker), Some(tenant), Some(t_marker)) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    t_marker == "t"
        && e_marker == "e"
        && ironauth_store::TenantId::parse(tenant).is_ok()
        && ironauth_store::EnvironmentId::parse(environment).is_ok()
}

/// The JWK members that mean a document carries PRIVATE key material.
///
/// RFC 7517/7518: `d` is the private exponent or scalar for RSA, EC and OKP; `p`, `q`, `dp`,
/// `dq`, `qi` and `oth` are the RSA CRT factors; `k` is a symmetric key. Any of them makes the
/// document a private key set rather than the public one an external issuer publishes.
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Refuse an inline key set that carries private material.
///
/// `trusted_keys_from_jwks` reads only the PUBLIC members of each JWK, so a key set exported
/// with its private half attached parses to a perfectly usable verify key and would otherwise
/// be accepted, bound into the row verbatim, and handed back by the listing. That listing is
/// `management.read`, while writing it takes `management.write_config` plus a fresh sudo
/// elevation, so the material would cross a privilege boundary downward: an auditor or
/// help-desk credential could read a private key an operator pasted by mistake.
///
/// The mistake is an ordinary one rather than exotic. Exporting a key set with the private
/// half attached is one flag in every JOSE library (`export(private_key=True)`,
/// `to_dict()` on a private key), and an operator copying "our JWKS" out of a KMS or a
/// library shell can easily produce one.
///
/// IronAuth needs only the public half: an external issuer authenticates by SIGNING, and this
/// deployment only ever verifies. So there is no legitimate reason to accept a private member,
/// and refusing is both safe and the only way the module's "there is no secret on either
/// resource" claim becomes something the surface ENFORCES rather than merely hopes.
fn reject_private_key_material(jwks: &str) -> Result<(), ApiError> {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(jwks) else {
        // Not JSON at all. `trusted_keys_from_jwks` will find no key and the caller gets the
        // no-usable-key refusal, which is the more useful message for this input.
        return Ok(());
    };
    let keys = document
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .map_or_else(Vec::new, |keys| keys.iter().collect());
    for key in keys {
        if let Some(member) = PRIVATE_JWK_MEMBERS
            .iter()
            .find(|member| key.get(**member).is_some())
        {
            return Err(ApiError::BadRequest(format!(
                "jwks carries the private member `{member}`. An external issuer authenticates \
                 by signing and this deployment only verifies, so only the PUBLIC key set \
                 belongs here; the registered document is readable by any credential holding \
                 management.read. Re-export the key set without its private half"
            )));
        }
    }
    Ok(())
}

/// The longest an `iss` or an external `sub` may be.
///
/// Not a taste judgement. Both are components of a btree UNIQUE index
/// (`(tenant, environment, issuer)` and the mappings' four-column key), and Postgres refuses
/// an index row over `BTMaxItemSize`, about 2704 bytes at the default page size, with SQLSTATE
/// 54000. That is neither a unique violation nor a check violation, so the store maps it to
/// `StoreError::Database` and the caller gets an opaque 500 instead of a reason.
///
/// The BINDING index is not either table's own unique key, which is the part worth writing
/// down. A mapping's ordering key is `issuer + "\n" + external_subject`, so the outbox's
/// `(tenant, environment, consumer, ordering_key, sequence)` index carries TWO capped fields at
/// once. Measured against 26-byte level identifiers: the issuers key reaches ~1076 bytes, the
/// mappings key ~2100, and the outbox key ~2122. So 1024 holds with roughly 550 bytes of
/// headroom, and the outbox index is what would fail first. Raising this constant much past
/// 1300 would blow that index while both table keys still looked fine.
///
/// The sibling caps in this crate exist for DIFFERENT reasons and are not precedent for the
/// number: `brands::MAX_SLOT_BYTES` and `locales::MAX_LOCALE_STRING_BYTES` bound render cost
/// for values stored inside a JSON blob and indexed by nothing, and
/// `flow_versions::MAX_JOURNEY_ID_BYTES` bounds a key's size without reference to an index.
/// `MAX_SLOT_BYTES` is 8192, three times the btree limit, which is only safe because that
/// value never reaches an index. Do not copy any of them for a column that does.
const MAX_TRUST_STRING_BYTES: usize = 1024;

/// Refuse a value that cannot be stored, or whose whitespace would be silently rewritten.
fn reject_unstorable(field: &str, value: &str) -> Result<(), ApiError> {
    if value.len() > MAX_TRUST_STRING_BYTES {
        return Err(ApiError::BadRequest(format!(
            "{field} is {} bytes, over the {MAX_TRUST_STRING_BYTES} byte limit; it forms part \
             of a unique index, which would refuse the row with an error this surface cannot \
             turn into a useful message",
            value.len()
        )));
    }
    reject_untrimmed(field, value)
}

/// Refuse a value whose surrounding whitespace would be silently rewritten.
///
/// REFUSED rather than trimmed, and the difference is the whole point. Both `iss` and `sub`
/// are compared BYTE FOR BYTE by the grant, deliberately: `jwt_bearer.rs` documents that
/// `str::trim` strips the entire Unicode `White_Space` set, and that normalizing the subject
/// once made every registered mapping reachable by about twenty five distinct strings, since
/// a git ref may legally contain U+00A0, U+2028, U+202F and U+3000.
///
/// So trimming here would be an authorization SUBSTITUTION performed silently at authoring
/// time: an operator who writes a subject ending in a non-breaking space gets a rule that
/// fires for the plain ref instead, which is a different and usually far more broadly
/// writable one. An earlier draft of this change did exactly that. Refusing gets the same
/// protection against a value pasted out of a spreadsheet, and tells the operator.
fn reject_untrimmed(field: &str, value: &str) -> Result<(), ApiError> {
    if value != value.trim() {
        return Err(ApiError::BadRequest(format!(
            "{field} has leading or trailing whitespace. It is compared byte for byte against \
             what the external issuer signs, so it is refused rather than silently trimmed: \
             sending the trimmed value would change which assertions match"
        )));
    }
    Ok(())
}

/// Validate a registration body, returning the refusal an operator can act on.
///
/// Every rule here is enforced at AUTHORING time rather than left to the first assertion,
/// and that is the point of the whole surface. The grant fails CLOSED on each of these, so a
/// mistake produces an anchor that is registered, listed, shown as enabled, and authenticates
/// nothing, which an operator cannot tell apart from a workload broken at the other end.
///
/// Each check runs the SAME function the grant runs, never a restatement of what it accepts:
/// `trusted_keys_from_jwks` is what `resolve_issuer_keys` calls, `JwsAlgorithm::from_jose_name`
/// intersected with the supported set is what `allowed_algs` computes, and `parse_target` is
/// what the fetcher applies to a `jwks_uri`. An earlier draft got both of those wrong, in two
/// different ways. The algorithm check read the same `supported` list it reads now, and
/// compared the operator's raw spelling against it WITHOUT normalizing through
/// `from_jose_name` first, so `Ed25519` (the fully-specified name for `EdDSA`) was refused
/// even though the verifier honours it: a missing normalization rather than a wrong list. The
/// URI check was a genuine restatement, `starts_with("https://")`, which
/// accepts `https://` alone and `https://user@host/` (both unfetchable) and rejects `HTTPS://`
/// (which the fetcher accepts, since RFC 3986 makes the scheme case insensitive).
fn validate_registration(request: &RegisterExternalIssuerRequest) -> Result<(), ApiError> {
    if request.issuer.trim().is_empty() {
        return Err(ApiError::BadRequest("issuer must not be empty".to_owned()));
    }
    reject_unstorable("issuer", &request.issuer)?;
    match (request.jwks.as_deref(), request.jwks_uri.as_deref()) {
        (None, None) => {
            return Err(ApiError::BadRequest(
                "exactly one of jwks and jwks_uri is required: an issuer with neither has no \
                 key to verify against and would refuse every assertion"
                    .to_owned(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "jwks and jwks_uri are mutually exclusive: supplying both leaves which one is \
                 authoritative unstated"
                    .to_owned(),
            ));
        }
        // An inline key set must yield at least one key THIS core can verify with. Checked by
        // running the verifier's own reader rather than by parsing the JSON: a document that
        // is valid JSON, and even a valid JWK Set, still resolves to nothing if every key in
        // it uses an unsupported type or curve.
        (Some(inline), None) => {
            reject_private_key_material(inline)?;
            if ironauth_jose::trusted_keys_from_jwks(inline.as_bytes()).is_empty() {
                return Err(ApiError::BadRequest(
                    "jwks contains no key this server can verify with, so the issuer would \
                     refuse every assertion: supply a JWK Set with at least one supported \
                     asymmetric public key"
                        .to_owned(),
                ));
            }
        }
        // Run the fetcher's own parser. It resolves no DNS and opens no socket, so it is a
        // pure syntactic check here, and it refuses the whole class this route must not
        // accept: a missing host, userinfo, a zero port, a malformed authority, and any
        // scheme but https.
        (None, Some(uri)) => match ironauth_fetch::parse_target(uri) {
            Ok(target) if target.scheme == ironauth_fetch::Scheme::Https => {
                // An IP LITERAL the fetch policy will always refuse. `classify` is pure and
                // resolves nothing, so this adds no network side effect on an operator-supplied
                // URL; it just declines to register an anchor whose keys can never be fetched.
                // A hostname that RESOLVES to a blocked address genuinely cannot be checked
                // here and is deliberately left to the fetcher.
                if let Some(ip) = target.literal_ip {
                    if let Some(class) = ironauth_fetch::classify(ip) {
                        return Err(ApiError::BadRequest(format!(
                            "jwks_uri points at {ip}, which the SSRF-hardened fetcher refuses \
                             ({class:?}), so the issuer could never obtain a key"
                        )));
                    }
                }
            }
            Ok(_) => {
                return Err(ApiError::BadRequest(
                    "jwks_uri must be an https URL: keys are fetched through the \
                     SSRF-hardened fetcher, which resolves nothing over any other scheme"
                        .to_owned(),
                ));
            }
            Err(error) => {
                return Err(ApiError::BadRequest(format!(
                    "jwks_uri is not a URL the hardened fetcher can resolve ({error:?}), so \
                     the issuer would never obtain a key"
                )));
            }
        },
    }
    validate_narrowing_allowlists(request)
}

/// The two OPTIONAL allowlists, which narrow and never widen.
///
/// Both fail closed the same way: an allowlist whose intersection with what the deployment
/// supports is empty leaves the issuer accepting nothing at all. They are validated together
/// because they are the same hazard, and because shipping a checked `signing_alg_allow` beside
/// an unchecked `audience_allow` is the asymmetry a reviewer found in the first draft.
fn validate_narrowing_allowlists(request: &RegisterExternalIssuerRequest) -> Result<(), ApiError> {
    if let Some(list) = request.signing_alg_allow.as_deref() {
        if list.split_whitespace().next().is_none() {
            return Err(ApiError::BadRequest(
                "signing_alg_allow is empty: omit it to accept the supported set, rather than \
                 pinning an allowlist that permits no algorithm"
                    .to_owned(),
            ));
        }
        // `allowed_algs` in the grant is `from_jose_name` filtered by the supported asymmetric
        // set, so that pair is what a name has to survive. An unrecognised name is DROPPED
        // there rather than emptying the list, so one typo beside a good name does not stop
        // the issuer working; it silently registers a NARROWER policy than the operator wrote,
        // which is why the whole list is refused instead of the bad entry quietly discarded.
        let supported = ironauth_oidc::assertion_signing_alg_values();
        let unknown: Vec<&str> = list
            .split_whitespace()
            .filter(|name| {
                ironauth_jose::JwsAlgorithm::from_jose_name(name)
                    .is_none_or(|alg| !supported.iter().any(|ok| ok == alg.as_jose_name()))
            })
            .collect();
        if !unknown.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "signing_alg_allow names {unknown:?}, which this server cannot verify with. \
                 The allowlist only narrows, and an unrecognised name is ignored rather than \
                 honoured, so accepting this would register a narrower policy than the one \
                 written. Supported: {supported:?}"
            )));
        }
    }
    if let Some(list) = request.audience_allow.as_deref() {
        // Same hazard as the algorithm pin: the grant intersects this with the audiences the
        // deployment accepts, and an empty intersection means the issuer can address nothing.
        // The VALUES cannot be checked here (which audiences are acceptable is the token
        // endpoint's configuration, not this plane's), so this refuses the one case that is
        // unambiguously wrong: an allowlist that lists nothing.
        if list.split_whitespace().next().is_none() {
            return Err(ApiError::BadRequest(
                "audience_allow is empty: omit it to accept the deployment's audience policy, \
                 rather than pinning an allowlist that permits no audience"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

/// List the external issuers registered in this environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/external-issuers",
    operation_id = "listExternalIssuers",
    tag = "external-issuers",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The registered issuers", body = ExternalIssuerList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent", body = ErrorBody)
    )
)]
pub async fn list_external_issuers(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    // No liveness fence on a READ, matching every sibling listing: a soft-deleted environment
    // stays readable and only writes refuse it.

    let issuers = state
        .store()
        .scoped(scope)
        .external_assertion_issuers()
        .list()
        .await?
        .into_iter()
        .map(issuer_view)
        .collect();
    let body =
        serde_json::to_string(&ExternalIssuerList { issuers }).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Register an external assertion issuer as a trust anchor.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/external-issuers",
    operation_id = "registerExternalIssuer",
    tag = "external-issuers",
    request_body = RegisterExternalIssuerRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The registered issuer", body = ExternalIssuerCreated),
        (status = 400, description = "Malformed request, an empty issuer, or neither or both of jwks and jwks_uri", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 409, description = "An issuer with this `iss` is already registered here", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn register_external_issuer(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    //
    // Registering a trust anchor is the most consequential write on this surface: it decides
    // whose signature can mint a token here. It is sudo-fenced for the same reason every
    // other trust-shaping write is.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let request: RegisterExternalIssuerRequest = parse_json(&body)?;
    validate_registration(&request)?;

    // This deployment must not be registered as a foreign issuer of its own, in ANY of its
    // scopes. The JOSE core reads an external assertion under `ExpectedTyp::ForeignIssuer`,
    // which by construction does not enforce `typ`, and that policy's own doc scopes the
    // hazard to the DEPLOYMENT rather than to one environment: "a deployment that registered
    // its own issuer and JWKS as a foreign party would have its own tokens reach the signature
    // check with `typ` unread". Both it and the grant relied on the mitigation that no
    // operator could register such an anchor, and this route is what removed it.
    //
    // Matched on the SHAPE of the tail rather than this scope's own ids, and both halves of
    // that are load bearing. Not the registry: `AdminState`'s is optional
    // (`install_signing_registry` leaves it uninstalled when no data-plane connection is
    // configured), so a check gated on it silently would not run, which is measured, an
    // earlier draft did not fire in its own test. Not this scope's ids either: every issuer
    // this deployment mints is `{base}/t/{tenant}/e/{environment}`, so registering ANOTHER
    // environment's issuer evades a same-scope check while reaching the same hazard, and that
    // one is exploitable rather than untidy, because the default audience policy accepts the
    // deployment-wide token endpoint URL.
    //
    // ACCIDENTAL false positives are not a concern: both segments must parse as `ten_`/`env_`
    // scoped identifiers, which are canonical base64 of 16 random bytes, so a third-party
    // issuer does not collide by chance.
    //
    // One DELIBERATE false positive is accepted, and is worth stating rather than glossing:
    // federating with a DIFFERENT IronAuth deployment is refused, because its issuer has the
    // same shape and this plane cannot see the base URL that would tell the two apart. That is
    // the safe direction to err, and if it ever needs to be allowed the fix is to compare
    // against the configured issuer base rather than to loosen the shape.
    if names_a_scope_of_this_deployment(&request.issuer) {
        return Err(ApiError::BadRequest(
            "issuer names an issuer this deployment serves: registering a deployment as a \
             foreign trust anchor of itself, or of another of its own environments, would let \
             its own tokens reach the external assertion path, which does not enforce `typ`"
                .to_owned(),
        ));
    }

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let id = ironauth_store::ExternalIssuerId::generate(state.env(), &scope);
    let created = serde_json::to_string(&ExternalIssuerCreated { id: id.to_string() })
        .map_err(|_| ApiError::Internal)?;
    // Minted BEFORE the write and handed to it, so the event and the row commit together.
    let announcement = pending(
        &state,
        scope,
        crate::events::EXTERNAL_ISSUER_REGISTERED,
        &request.issuer,
        &serde_json::json!({
            "issuer_id": id.to_string(),
            "issuer": request.issuer,
            "enabled": true,
        }),
    )?;
    let write = state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .external_assertion_issuers()
        .register_with_event(
            state.env(),
            ironauth_store::NewExternalAssertionIssuer {
                id: &id,
                issuer: &request.issuer,
                jwks: request.jwks.as_deref(),
                jwks_uri: request.jwks_uri.as_deref(),
                signing_alg_allow: request.signing_alg_allow.as_deref(),
                audience_allow: request.audience_allow.as_deref(),
                // Registered LIVE. An anchor that had to be enabled in a second call would
                // leave the common path a two-step, and the disable route below is how an
                // operator parks one.
                enabled: true,
            },
            Some(ironauth_store::IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                response_body: &created,
            }),
            Some(&announcement.domain_event()),
        )
        .await;

    match write {
        Ok(()) => Ok(json(StatusCode::CREATED, created)),
        // A replay that RACED the first attempt: both passed the pre-check above, and the
        // loser's insert hit the replay table's unique key. Answering with the stored
        // response is the same answer the winner got, which is what idempotency promises.
        Err(ironauth_store::StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// Enable or disable a registered external issuer.
#[utoipa::path(
    patch,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/external-issuers/{issuer_id}",
    operation_id = "setExternalIssuerEnabled",
    tag = "external-issuers",
    request_body = SetEnabledRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("issuer_id" = String, Path, description = "The `xai_` identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The issuer's state was set"),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment or issuer is absent", body = ErrorBody)
    )
)]
pub async fn set_external_issuer_enabled(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, issuer_id)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let request: SetEnabledRequest = parse_json(&body)?;
    // Parsed IN SCOPE, so an identifier belonging to another tenant is the uniform not-found
    // rather than a cross-scope read. No Idempotency-Key: this is a PATCH setting a boolean to
    // a value the caller states, so replaying it reaches the same state, which is what the
    // header exists to guarantee for creates that would otherwise mint a second row.
    let id = ironauth_store::ExternalIssuerId::parse_in_scope(&issuer_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    // Read first, so the event can carry the NATURAL key it is ordered on. The toggle
    // would otherwise know only the row id, and a repoint's events would fall into a
    // different ordering group from this one.
    let record = state
        .store()
        .scoped(scope)
        .external_assertion_issuers()
        .by_issuer_id(&id)
        .await?
        .ok_or(ApiError::NotFound)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .external_assertion_issuers()
        .set_enabled_with_event(
            state.env(),
            &id,
            request.enabled,
            Some(
                &pending(
                    &state,
                    scope,
                    crate::events::EXTERNAL_ISSUER_ENABLED_CHANGED,
                    &record.issuer,
                    // The issuer string travels WITH the toggle, not just as its ordering
                    // key. The natural key is what a receiver reconciles trust by, and the
                    // toggle was the one event on this resource from which it could not be
                    // recovered: a receiver holding only `issuer_id` would have to have seen
                    // the registration to know which issuer just stopped being honoured.
                    &serde_json::json!({
                        "issuer_id": id.to_string(),
                        "issuer": record.issuer,
                        "enabled": request.enabled,
                    }),
                )?
                .domain_event(),
            ),
        )
        .await?;
    Ok(no_content())
}

/// List the subject mappings registered in this environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/subject-mappings",
    operation_id = "listSubjectMappings",
    tag = "external-issuers",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The registered mappings, including disabled ones", body = SubjectMappingList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent", body = ErrorBody)
    )
)]
pub async fn list_subject_mappings(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;

    let mappings = state
        .store()
        .scoped(scope)
        .external_assertion_subject_mappings()
        .list()
        .await?
        .into_iter()
        .map(mapping_view)
        .collect();
    let body =
        serde_json::to_string(&SubjectMappingList { mappings }).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Author a subject mapping from an external subject to an IronAuth principal.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/subject-mappings",
    operation_id = "createSubjectMapping",
    tag = "external-issuers",
    request_body = CreateSubjectMappingRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The authored mapping", body = SubjectMappingCreated),
        (status = 400, description = "Malformed request, one half of the claim gate without the other, an unregistered issuer, or a principal that is not a registered machine identity", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 409, description = "A mapping for this issuer and subject already exists", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
#[allow(clippy::too_many_lines)]
pub async fn create_subject_mapping(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // A mapping decides WHICH principal a foreign subject becomes, so it shapes trust as
    // directly as the anchor does and carries the same fence.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let request: CreateSubjectMappingRequest = parse_json(&body)?;
    // An empty external subject is not merely useless, it is unrepresentable downstream: the
    // `subject_mapping.created` schema requires a non-empty string, so the row would be
    // written and its event would fail catalog validation at fan-out and dead-letter, leaving
    // a live mapping no receiver was ever told about.
    if request.external_subject.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "external_subject must not be empty: it is the `sub` an assertion has to carry \
             for this rule to fire"
                .to_owned(),
        ));
    }
    reject_unstorable("issuer", &request.issuer)?;
    reject_unstorable("external_subject", &request.external_subject)?;
    // Both halves of the claim gate, or neither. A database CHECK enforces this too, but a
    // constraint violation reaches the caller as an opaque conflict, and half-setting the gate
    // is an ordinary mistake with an obvious remedy.
    // Both halves must be supplied together, checked FIRST so the two emptiness messages below
    // are only ever reached by a request where a gate really would be authored. Reversed, a
    // caller sending `match_value: ""` and no `match_claim` was told the gate they did not write
    // would fire too broadly, instead of that the halves come as a pair, which is the message
    // that names their actual mistake.
    if request.match_claim.is_some() != request.match_value.is_some() {
        return Err(ApiError::BadRequest(
            "match_claim and match_value must be supplied together or not at all: one without \
             the other leaves what the gate compares unstated"
                .to_owned(),
        ));
    }

    // Whitespace on either half is REFUSED rather than trimmed, exactly as on the issuer and the
    // subject and for the same reason: the grant compares both byte for byte (`claims().get()`
    // is an exact key lookup and the value an exact string compare), so rewriting either would
    // silently author a different gate than the one written.
    //
    // Deliberately NOT length-capped, unlike the issuer and the subject. Those are capped because
    // each is a component of a btree unique key or of the outbox ordering key, where an oversized
    // value becomes an opaque 500. Neither claim-gate half is in ANY index: migration 0020 puts
    // this table's only unique key on (tenant, environment, issuer, external_subject) and creates
    // no other, and `mapping_key` carries neither. Capping here would refuse a legitimate long
    // gate (a base64 workload attestation, a composite repository-and-ref value) and hand the
    // operator the index reason for it, which would be false.
    if let Some(claim) = request.match_claim.as_deref() {
        reject_untrimmed("match_claim", claim)?;
    }
    if let Some(value) = request.match_value.as_deref() {
        reject_untrimmed("match_value", value)?;
    }

    // Neither half may be EMPTY, for two different reasons the messages keep straight. Both are
    // reachable only with the other half present, since the pairing check has already run, so
    // each states a consequence that really would occur.
    if request.match_claim.as_deref().is_some_and(str::is_empty) {
        return Err(ApiError::BadRequest(
            "match_claim must not be empty: an empty claim name matches no assertion, so the \
             rule would be live and fire for nothing"
                .to_owned(),
        ));
    }
    if request.match_value.as_deref().is_some_and(str::is_empty) {
        return Err(ApiError::BadRequest(
            "match_value must not be empty: the gate would then fire for any assertion whose \
             `match_claim` is present and empty, which is broader than it looks"
                .to_owned(),
        ));
    }

    // Replay BEFORE the preconditions below, which is the convention nine sibling handlers
    // state in the same words: a genuine replay must return the original response even if
    // the world moved underneath it. Round 1 of review had these the other way round, and
    // adding the anchor DELETE in the same round is what made that reachable. A caller that
    // created a mapping, then deleted the anchor (the incident revocation, or the documented
    // rotate-and-repoint), then retried its create would have been told 400 `no external
    // issuer is registered` for a mapping row that exists, is enabled, and re-arms the moment
    // that issuer string is registered again.
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // Checked AFTER the replay, so a retry of a request that already succeeded is answered
    // from the stored response rather than re-evaluated against a world that has since
    // changed. The mapping must name a REGISTERED anchor and a REGISTERED machine identity. Neither is
    // enforced by a foreign key: `issuer` is the issuer STRING an assertion carries rather than
    // the anchor's row id, and `principal` is a free text column the grant copies into the
    // token's `sub`. So a typo in either one is accepted by the database and produces a rule
    // that silently matches nothing, or one that mints tokens for a subject no reader can
    // resolve. An operator cannot detect either from the surface, which is why both are
    // refused at authoring time rather than discovered at 3am.
    let anchor = state
        .store()
        .scoped(scope)
        .external_assertion_issuers()
        .by_issuer(&request.issuer)
        .await?;
    if anchor.is_none() {
        return Err(ApiError::BadRequest(format!(
            "no external issuer is registered as `{}` in this environment: register the trust \
             anchor before mapping subjects from it, or correct the issuer",
            request.issuer
        )));
    }

    // Checked by EXISTENCE, not by shape. A well-formed `sva_` identifier for an account that
    // was never created, or one belonging to another environment, is exactly the case a syntax
    // check would wave through: `parse_in_scope` already refuses the foreign scope, and
    // `exists` is what refuses the plausible-but-absent.
    let machine_identity =
        ironauth_store::ServiceAccountId::parse_in_scope(&request.principal, &scope).map_err(
            |_| {
                ApiError::BadRequest(
                    "principal must name a registered machine identity in this environment (an \
                 `sva_` service account): a federated assertion is issued AS that identity, and \
                 a principal that resolves to nothing mints a token no reader can attribute"
                        .to_owned(),
                )
            },
        )?;
    if !state
        .store()
        .scoped(scope)
        .service_accounts()
        .exists(&machine_identity)
        .await?
    {
        return Err(ApiError::BadRequest(format!(
            "no machine identity `{machine_identity}` exists in this environment"
        )));
    }

    let id = ironauth_store::AssertionMappingId::generate(state.env(), &scope);
    let created = serde_json::to_string(&SubjectMappingCreated { id: id.to_string() })
        .map_err(|_| ApiError::Internal)?;
    let announcement = pending(
        &state,
        scope,
        crate::events::SUBJECT_MAPPING_CREATED,
        &mapping_key(&request.issuer, &request.external_subject),
        &serde_json::json!({
            "mapping_id": id.to_string(),
            "issuer": request.issuer,
            "external_subject": request.external_subject,
            "principal": request.principal,
        }),
    )?;
    let write = state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .external_assertion_subject_mappings()
        .create_with_event(
            state.env(),
            ironauth_store::NewAssertionSubjectMapping {
                id: &id,
                issuer: &request.issuer,
                external_subject: &request.external_subject,
                match_claim: request.match_claim.as_deref(),
                match_value: request.match_value.as_deref(),
                principal: &request.principal,
            },
            Some(ironauth_store::IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                response_body: &created,
            }),
            Some(&announcement.domain_event()),
        )
        .await;

    match write {
        Ok(()) => Ok(json(StatusCode::CREATED, created)),
        Err(ironauth_store::StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// Enable or disable a subject mapping.
#[utoipa::path(
    patch,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/subject-mappings/{mapping_id}",
    operation_id = "setSubjectMappingEnabled",
    tag = "external-issuers",
    request_body = SetEnabledRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("mapping_id" = String, Path, description = "The `asm_` identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The mapping's state was set"),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment or mapping is absent", body = ErrorBody)
    )
)]
pub async fn set_subject_mapping_enabled(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, mapping_id)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let request: SetEnabledRequest = parse_json(&body)?;
    let id = ironauth_store::AssertionMappingId::parse_in_scope(&mapping_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    // Read first, so the event can carry the NATURAL key it is ordered on. The toggle
    // would otherwise know only the row id, and a repoint's events would fall into a
    // different ordering group from this one.
    let record = state
        .store()
        .scoped(scope)
        .external_assertion_subject_mappings()
        .by_id(&id)
        .await?
        .ok_or(ApiError::NotFound)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .external_assertion_subject_mappings()
        .set_enabled_with_event(
            state.env(),
            &id,
            request.enabled,
            Some(
                &pending(
                    &state,
                    scope,
                    crate::events::SUBJECT_MAPPING_ENABLED_CHANGED,
                    &mapping_key(&record.issuer, &record.external_subject),
                    // Carries its natural key, for the reason the anchor toggle does.
                    &serde_json::json!({
                        "mapping_id": id.to_string(),
                        "issuer": record.issuer,
                        "external_subject": record.external_subject,
                        "enabled": request.enabled,
                    }),
                )?
                .domain_event(),
            ),
        )
        .await?;
    Ok(no_content())
}

/// Remove a registered external issuer.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/external-issuers/{issuer_id}",
    operation_id = "deleteExternalIssuer",
    tag = "external-issuers",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("issuer_id" = String, Path, description = "The `xai_` identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The registration was removed"),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment or issuer is absent", body = ErrorBody)
    )
)]
pub async fn delete_external_issuer(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, issuer_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let id = ironauth_store::ExternalIssuerId::parse_in_scope(&issuer_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    // Read BEFORE the delete: the event carries the issuer string, and after the row is gone
    // there is nothing left to read it from. An event naming only the id would be
    // unreconcilable against a receiver's own records, since the id resolves to nothing.
    let record = state
        .store()
        .scoped(scope)
        .external_assertion_issuers()
        .by_issuer_id(&id)
        .await?
        .ok_or(ApiError::NotFound)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .external_assertion_issuers()
        .delete_with_event(
            state.env(),
            &id,
            Some(
                &pending(
                    &state,
                    scope,
                    crate::events::EXTERNAL_ISSUER_DELETED,
                    &record.issuer,
                    &serde_json::json!({
                        "issuer_id": id.to_string(),
                        "issuer": record.issuer,
                    }),
                )?
                .domain_event(),
            ),
        )
        .await?;
    Ok(no_content())
}

/// Remove a subject mapping.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/subject-mappings/{mapping_id}",
    operation_id = "deleteSubjectMapping",
    tag = "external-issuers",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("mapping_id" = String, Path, description = "The `asm_` identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The mapping was removed"),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment or mapping is absent", body = ErrorBody)
    )
)]
pub async fn delete_subject_mapping(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, mapping_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let id = ironauth_store::AssertionMappingId::parse_in_scope(&mapping_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    // Read before the delete, for the reason the issuer delete gives: the natural key travels
    // on the event and cannot be recovered once the row is gone.
    let record = state
        .store()
        .scoped(scope)
        .external_assertion_subject_mappings()
        .by_id(&id)
        .await?
        .ok_or(ApiError::NotFound)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .external_assertion_subject_mappings()
        .delete_with_event(
            state.env(),
            &id,
            Some(
                &pending(
                    &state,
                    scope,
                    crate::events::SUBJECT_MAPPING_DELETED,
                    &mapping_key(&record.issuer, &record.external_subject),
                    &serde_json::json!({
                        "mapping_id": id.to_string(),
                        "issuer": record.issuer,
                        "external_subject": record.external_subject,
                    }),
                )?
                .domain_event(),
            ),
        )
        .await?;
    Ok(no_content())
}
