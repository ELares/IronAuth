// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SESSION TOKENIZER (issue #119): turning a valid opaque session into a short-lived JWT.
//!
//! A tokenizer template is per-environment configuration naming an audience, a TTL, a claims
//! mapper, and its own key set. `POST .../session/tokenize?tokenize_as=<template>` presents the
//! ordinary session cookie and receives a JWT that a service mesh, a third-party API, or an edge
//! worker verifies against the template's own published JWKS with NO database call.
//!
//! # The bound is the feature
//!
//! Verifying without a database call means the underlying session's revocation cannot reach a
//! token that has already been minted. Revocation takes effect at the next MINT, and the
//! template's TTL is the exact width of the window in between. That is why the TTL is bounded
//! here and in the table rather than left to configuration, why the docs state the revocation
//! window as a function of it, and why the default range this ships with is sixty to a hundred
//! and twenty seconds.
//!
//! What revocation DOES reach immediately is the mint. [`mint`] takes an
//! [`AuthenticatedSession`], which only [`crate::interaction::resolve_session`] produces, and
//! that resolution is the store's own liveness guard: revoked, ended, superseded and expired
//! sessions do not resolve. There is no second path to a token.
//!
//! # A mint SLIDES the session's idle window, and that is worth knowing before you build on it
//!
//! [`crate::interaction::resolve_session`] slides the idle window on every successful resolve,
//! because a successful resolve is evidence the session is not idle. A tokenize call is a
//! successful resolve, so it slides too.
//!
//! For a user clicking around an app that is right: minting a token IS activity. For a BACKGROUND
//! re-mint loop it is not, and the consequence is worth stating rather than discovering: an SDK
//! that re-mints every sixty seconds in a tab nobody is looking at holds that session open
//! indefinitely, and the environment's idle timeout stops meaning what its name says.
//!
//! Nothing here changes that behaviour, because the fix belongs to whatever introduces a
//! background re-mint rather than to the endpoint it calls: a re-mint has to be able to say it is
//! a re-mint. Until then, a deployment relying on the idle timeout should know that this endpoint
//! refreshes it.
//!
//! # One claims mapper, not two
//!
//! A template's rules are `Vec<MappingRule>`: the SAME vocabulary and the SAME validator
//! `claims_mappings` uses, because a second rule shape would be a second answer to "may a mapping
//! write `sub`", and the first time the two answers differed one of them would be wrong in
//! production.
//!
//! One rule is refused HERE that the shared validator accepts, and the reason is this surface
//! rather than the rule: [`MappingRule::Place`] names a token to put a claim in, and a template
//! mints exactly one token. A placement rule here would be inert whatever it said. The shared
//! module's own header calls that outcome out by name -- "quietly inert forever" -- as the thing
//! a config-time refusal exists to prevent, so this refuses it at config time.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_jose::{EmissionOptions, SigningKey, TokenTyp, sign_jws};
use ironauth_store::session_token_store::SessionTokenKeyRecord;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::claims_mapping::{self, Destination, MappingRefusal, MappingRule};
use crate::interaction::{self, AuthenticatedSession};
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::parse_scope;

/// The shortest lifetime a template may configure, in seconds.
///
/// A TTL shorter than the clock skew a verifier tolerates is a token that is expired on arrival
/// for some verifiers and not others, which reads as an intermittent outage rather than as a
/// configuration mistake. Thirty seconds is comfortably above the sixty-second skew allowance a
/// typical verifier applies in the other direction.
pub const MIN_TTL_SECONDS: i32 = 30;

/// The longest lifetime a template may configure, in seconds.
///
/// Fifteen minutes. This is the ceiling on the revocation window, which is the one property of
/// this feature an operator cannot get back by any other means: a token already minted verifies
/// until it expires no matter what happens to the session behind it.
pub const MAX_TTL_SECONDS: i32 = 900;

/// The documented default range, in seconds, that the docs and the SDK re-mint cadence quote.
///
/// Not enforced -- a template may configure anything between [`MIN_TTL_SECONDS`] and
/// [`MAX_TTL_SECONDS`] -- but stated here so the number in the documentation and the number an
/// operator sees have one source.
pub const DEFAULT_TTL_RANGE_SECONDS: (i32, i32) = (60, 120);

/// The most rules a template may carry.
///
/// Matches the table's own CHECK, and the pairing is TESTED from both sides rather than asserted:
/// one test writes exactly this many rules and expects success, another writes one more and
/// expects the refusal to come from HERE rather than from the database. A bound stated in two
/// artifacts is only equal if something measures it.
pub const MAX_TEMPLATE_RULES: usize = 32;

/// The longest a template name may be, matching the table's CHECK.
pub const MAX_TEMPLATE_NAME_BYTES: usize = 64;

/// The longest an audience may be, matching the table's CHECK.
pub const MAX_AUDIENCE_BYTES: usize = 255;

/// Domain separation for the derived session reference. Public, like every pepper in this tree:
/// it separates domains, it is not a secret.
const SESSION_REFERENCE_PEPPER: &str = "ironauth.session_tokenizer.v1.sid";

/// Why a template configuration was refused, at CONFIGURATION time.
///
/// Every variant is reachable from the management write path and none from the mint: a template
/// that reaches the mint has already been through [`validate_template`].
/// DELIBERATELY NOT `#[non_exhaustive]`, unlike most public error enums in this workspace.
///
/// The management surface turns each variant into the sentence an operator reads, and a
/// `non_exhaustive` enum would force a wildcard arm there. A wildcard arm is how a variant added
/// later gets some other variant's message: the code keeps compiling and the operator is told
/// the wrong thing. `claims_mapping::RefusalReason` is exhaustive for the same reason, and its
/// own match carries the note "a catch-all arm would give a future reason the wrong token
/// silently".
///
/// The cost is that adding a variant is a breaking change for an out-of-workspace matcher. That
/// is the right trade for an enum whose whole purpose is to be rendered to a human.
#[derive(Debug, Clone, PartialEq)]
pub enum TemplateError {
    /// The name is empty, or longer than [`MAX_TEMPLATE_NAME_BYTES`].
    Name,
    /// The audience is empty, or longer than [`MAX_AUDIENCE_BYTES`].
    ///
    /// An audience is REQUIRED and not merely bounded. RFC 8725 section 3.9 asks for an audience
    /// restriction on every token, and a template with none would mint a token every verifier in
    /// the estate accepts, which is the confused-deputy shape the per-template key set exists to
    /// prevent, reached through the claim set instead of through the key.
    Audience,
    /// The TTL is outside `[MIN_TTL_SECONDS, MAX_TTL_SECONDS]`.
    Ttl,
    /// The rules document is not a JSON array of rules this version understands.
    ///
    /// Carries the serde message, because an operator writing a rule list needs to know WHICH
    /// field this version did not know: `deny_unknown_fields` means an unrecognized member is as
    /// likely to be the part that restricts something as the part that adds it.
    Unreadable(String),
    /// More than [`MAX_TEMPLATE_RULES`] rules.
    ///
    /// Refused HERE rather than by the table's CHECK, which is the correction to what
    /// `claims_mappings` shipped: its own module header records that an over-long document
    /// "passes `validate` and is refused by the table's CHECK constraint, which surfaces as a
    /// 500 rather than an audited 400".
    TooManyRules {
        /// How many rules the document carried.
        count: usize,
    },
    /// A `place` rule, which names a token that does not exist on this surface.
    ///
    /// See the module header: a template mints ONE token, so a placement rule is inert whatever
    /// it says, and inert-but-accepted is the outcome a config-time refusal exists to prevent.
    PlacementRule {
        /// Which rule, by position, so an operator can find it in a list of thirty.
        rule_index: usize,
    },
    /// The shared claims-mapping validator refused a rule (a protected claim, a malformed name,
    /// an expression that will not compile or costs too much).
    Mapping(MappingRefusal),
}

/// A template's configuration, validated.
///
/// Constructing one is the only way to reach [`mint`], so a template that was never validated
/// cannot mint a token. The fields are private for that reason: a caller that could assemble one
/// field by field could assemble an unvalidated one.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedTemplate {
    name: String,
    audience: String,
    ttl_seconds: i32,
    rules: Vec<MappingRule>,
}

impl ValidatedTemplate {
    /// The template's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The audience every token from this template carries.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The configured lifetime in seconds, which is also the revocation window.
    #[must_use]
    pub fn ttl_seconds(&self) -> i32 {
        self.ttl_seconds
    }

    /// The validated rules.
    #[must_use]
    pub fn rules(&self) -> &[MappingRule] {
        &self.rules
    }
}

/// Validate a template configuration, at CONFIGURATION time.
///
/// The management write path calls this before storing, and the mint path calls it again on the
/// document it read back. Twice is deliberate and is the same fail-closed reasoning
/// `claims_mapping::parse` states: a stored document that no longer validates is a downgrade, a
/// hand-edited row, or corruption, and treating it as "no mapping" would mint the UNFILTERED
/// claim set. Failing the mint is the safe direction.
///
/// # Errors
///
/// [`TemplateError`], naming which part of the configuration was refused.
pub fn validate_template(
    name: &str,
    audience: &str,
    ttl_seconds: i32,
    rules_json: &str,
) -> Result<ValidatedTemplate, TemplateError> {
    if name.is_empty() || name.len() > MAX_TEMPLATE_NAME_BYTES {
        return Err(TemplateError::Name);
    }
    if audience.is_empty() || audience.len() > MAX_AUDIENCE_BYTES {
        return Err(TemplateError::Audience);
    }
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(TemplateError::Ttl);
    }
    let rules =
        claims_mapping::parse(rules_json).map_err(|e| TemplateError::Unreadable(e.to_string()))?;
    if rules.len() > MAX_TEMPLATE_RULES {
        return Err(TemplateError::TooManyRules { count: rules.len() });
    }
    for (rule_index, rule) in rules.iter().enumerate() {
        if matches!(rule, MappingRule::Place { .. }) {
            return Err(TemplateError::PlacementRule { rule_index });
        }
    }
    claims_mapping::validate(&rules).map_err(TemplateError::Mapping)?;
    Ok(ValidatedTemplate {
        name: name.to_owned(),
        audience: audience.to_owned(),
        ttl_seconds,
        rules,
    })
}

/// The per-(template, session) reference a minted token carries as `sid`.
///
/// NEVER the session id itself, and this is the decision in this module with a security
/// consequence rather than a design preference. The session id IS the cookie value: it is the
/// bearer credential the browser presents. A token minted for a third-party API travels off this
/// origin by construction, so putting the session id in it would hand that credential to every
/// audience an operator configures a template for.
///
/// So it is a peppered, one-way SHA-256 digest of the issuer, the template name and the session
/// id, exactly as `session_mgmt::op_browser_state` derives the OP browser state and for the same
/// preimage-resistance reason. Keying it on the TEMPLATE as well as the issuer means two
/// templates' tokens for one session carry DIFFERENT references, so two audiences cannot collude
/// to discover they are looking at the same session.
#[must_use]
pub fn session_reference(issuer: &str, template: &str, session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_REFERENCE_PEPPER.as_bytes());
    hasher.update(b"\x00");
    hasher.update(issuer.as_bytes());
    hasher.update(b"\x00");
    hasher.update(template.as_bytes());
    hasher.update(b"\x00");
    hasher.update(session_id.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// The claim source a template's rules run against: what the SESSION knows, and nothing else.
///
/// Deliberately not the user's trait bag. A tokenized session JWT is verified with no database
/// call by an audience the operator names, so every claim in it is disclosed to that audience
/// for the whole TTL with no way to withdraw it. The session's own attributes are the set that
/// is already implied by "this subject is signed in", and widening the source to profile data is
/// a disclosure decision that belongs to a later change with its own criterion, not a default.
///
/// `sub` and `sid` are in the source so a rule may COPY them under another name (a rename of a
/// protected claim copies rather than moves, which `claims_mapping` implements and tests). They
/// are re-stamped by [`mint`] afterwards regardless, so no rule can displace them.
fn claim_source(session: &AuthenticatedSession, sid: &str) -> BTreeMap<String, Value> {
    let mut source = BTreeMap::new();
    source.insert("sub".to_owned(), json!(session.subject));
    source.insert("sid".to_owned(), json!(sid));
    source.insert(
        "auth_time".to_owned(),
        json!(session.auth_time_unix_micros / 1_000_000),
    );
    // `amr` as an ARRAY, which is what RFC 8176 and OpenID Connect Core section 2 define it as.
    // The store holds the same values space-separated because that is how the ID token carries
    // the achieved `acr` derivation; splitting here rather than storing a second encoding keeps
    // one source of truth for what the session recorded.
    let amr: Vec<Value> = session
        .auth_methods
        .split_whitespace()
        .map(|m| json!(m))
        .collect();
    if !amr.is_empty() {
        source.insert("amr".to_owned(), Value::Array(amr));
    }
    // NO `act` CLAIM, because an impersonated session never reaches here: `tokenize` refuses
    // one before the mint. See its own doc for why. An `act` arm written here would be a branch
    // nothing can reach, which is worse than absent -- it would read as though impersonated
    // minting were supported and merely disclosed.
    source
}

/// Why a mint failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum MintError {
    /// The template's rules were refused while being applied.
    Mapping(MappingRefusal),
    /// The stored key material is not a usable Ed25519 seed.
    KeyMaterial,
    /// The signing backend refused.
    Sign,
    /// The claim set could not be serialized, which does not happen for well-formed JSON and is
    /// surfaced for completeness.
    Serialize,
}

/// Reconstruct a template's live signing key from its stored record.
///
/// One algorithm and one material kind, which the table also CHECKs. There is no matrix to get
/// wrong here, unlike the issuer key loader, and that is the point of the table admitting one of
/// each: an unrepresentable state needs no branch to reject it.
///
/// # Errors
///
/// [`MintError::KeyMaterial`] if the stored seed is not a usable Ed25519 seed.
pub fn load_template_key(record: &SessionTokenKeyRecord) -> Result<SigningKey, MintError> {
    SigningKey::ed25519_from_seed(Some(record.id.to_string()), record.material.expose())
        .map_err(|_| MintError::KeyMaterial)
}

/// Mint a tokenized session JWT.
///
/// `now_unix_seconds` is the application clock seam, never the system clock, so a test can pin
/// the whole lifetime.
///
/// # The protocol claims are stamped AFTER the mapping, always
///
/// `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti` and `sid` are written over whatever the rules
/// left. `claims_mapping::validate` already refuses a rule that writes any of them, so this is
/// the second fence rather than the first -- and it is the one that holds if the first is ever
/// narrowed, which is the arrangement `scope_claims` describes as "the mint fold is the second
/// fence and must not be narrower than the FIRST".
///
/// # Errors
///
/// [`MintError`], naming which stage refused.
pub fn mint(
    template: &ValidatedTemplate,
    key: &SigningKey,
    issuer: &str,
    session: &AuthenticatedSession,
    now_unix_seconds: i64,
    jti: &str,
) -> Result<String, MintError> {
    let sid = session_reference(issuer, &template.name, &session.session_id.to_string());
    let source = claim_source(session, &sid);
    // `Destination::TwoTokens` with the ID-token projection, and the reason is measurable rather
    // than stylistic: a claim no rule places goes to the ID token under that destination, and a
    // template carries no `place` rules because `validate_template` refuses them. So the
    // ID-token projection is EVERY claim the rules produced.
    //
    // `a_template_projection_carries_every_mapped_claim` pins that equivalence, so the coupling
    // between "placement rules are refused" and "this projection is complete" is measured rather
    // than assumed.
    let mapped = claims_mapping::apply_for(&template.rules, &source, Destination::TwoTokens)
        .map_err(MintError::Mapping)?;
    let mut claims = serde_json::Map::new();
    for (name, value) in mapped.id_token {
        claims.insert(name, value);
    }
    let exp = now_unix_seconds.saturating_add(i64::from(template.ttl_seconds));
    claims.insert("iss".to_owned(), json!(issuer));
    claims.insert("sub".to_owned(), json!(session.subject));
    claims.insert("aud".to_owned(), json!(template.audience));
    claims.insert("iat".to_owned(), json!(now_unix_seconds));
    claims.insert("nbf".to_owned(), json!(now_unix_seconds));
    claims.insert("exp".to_owned(), json!(exp));
    claims.insert("jti".to_owned(), json!(jti));
    claims.insert("sid".to_owned(), json!(sid));
    let payload = serde_json::to_vec(&Value::Object(claims)).map_err(|_| MintError::Serialize)?;
    let options = EmissionOptions::new().with_token_typ(TokenTyp::SessionToken);
    sign_jws(key, &payload, &options).map_err(|_| MintError::Sign)
}

// ===========================================================================
// The HTTP surface.
// ===========================================================================

/// `POST /t/{tenant}/e/{environment}/session/tokenize?tokenize_as=<template>`.
///
/// Presents the ordinary session cookie and returns a short-lived JWT minted from the named
/// template. The response body carries the token, the template's audience, and the number of
/// seconds it is valid for, which is what an SDK schedules its re-mint against.
///
/// # An IMPERSONATED session is refused
///
/// A tokenized JWT is a credential an audience the operator named accepts for its whole TTL with
/// no way to withdraw it, and the audience is a third party whose verifier IronAuth does not
/// write. It may or may not read `act`. Minting under impersonation would therefore hand a
/// support operator a credential that some verifiers treat as the user, with no revocation path
/// short of the TTL, and afterwards it is indistinguishable from the user having done it.
///
/// That is the same reasoning `account::authenticate` gives for its own default, applied here
/// where it is stronger, so this refuses rather than disclosing.
///
/// # No `Cache-Control` reasoning is needed, and no CSRF check is right
///
/// The state-changing account POSTs carry a same-origin check because they change the account.
/// This one changes nothing: it reads a session and returns a token derived from it. A CSRF
/// check here would be a check against a threat that does not exist -- an attacker who can make
/// the browser call this cannot READ the response cross-origin, which is what the same-origin
/// policy already guarantees. What DOES matter is that the response is never cached, which
/// `no-store` says outright.
pub async fn tokenize(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<TokenizeQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found_json();
    };
    let Some(session) = interaction::resolve_session(&state, scope, &headers).await else {
        // The SAME response a revoked session gets, because it IS the same answer: the store's
        // liveness guard is what makes this endpoint honour revocation, and it reports absent,
        // expired, revoked, ended and superseded identically. Criterion 3 lives here.
        return unauthenticated();
    };
    if session.impersonation.is_some() {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": "impersonation_forbidden",
                "error_description": "A tokenized session JWT cannot be minted while \
                                      impersonating a user: it is a credential a third-party \
                                      audience accepts for its full lifetime, and nothing can \
                                      withdraw it before then.",
            }),
        );
    }
    let record = match state
        .store()
        .scoped(scope)
        .session_token_templates()
        .get(&query.tokenize_as)
        .await
    {
        Ok(Some(record)) => record,
        // An unknown template is a 404 and never a 400: the name is chosen by the caller, and
        // distinguishing "no such template" from "malformed name" would let a caller enumerate
        // which templates an environment has.
        Ok(None) => return not_found_json(),
        Err(_) => return server_error(),
    };
    // Validated AGAIN, on the document read back. See `validate_template`: a stored document
    // that no longer validates is a downgrade or a hand-edited row, and minting it unmapped
    // would emit MORE than the operator configured.
    let Ok(template) = validate_template(
        &record.name,
        &record.audience,
        record.ttl_seconds,
        &record.rules_json,
    ) else {
        return server_error();
    };
    let now = state.now();
    let now_micros = epoch_micros(now);
    let key_record = match state
        .store()
        .scoped(scope)
        .session_token_templates()
        .signing_key(&template.name, now_micros)
        .await
    {
        Ok(Some(key)) => key,
        // A template with no ACTIVE key cannot mint, and this says SO rather than returning the
        // generic fault below.
        //
        // Not a 404, because the template exists: the caller already named it and got past the
        // uniform not-found, so nothing is disclosed by being specific from here on. And not the
        // generic message, because the two are different problems with different fixes -- "no
        // signing key is active" points an operator at the template, while the generic one
        // points them at the store. An earlier draft returned the same body for both and carried
        // this comment anyway, which is a comment describing a distinction the code did not make.
        Ok(None) => return no_active_key(),
        Err(_) => return server_error(),
    };
    let Ok(key) = load_template_key(&key_record) else {
        return server_error();
    };
    let issuer = state.issuer_for(&scope);
    let mut jti_bytes = [0_u8; 16];
    state.env().entropy().fill_bytes(&mut jti_bytes);
    let jti = URL_SAFE_NO_PAD.encode(jti_bytes);
    let Ok(token) = mint(
        &template,
        &key,
        &issuer,
        &session,
        now_micros / 1_000_000,
        &jti,
    ) else {
        return server_error();
    };
    let mut response = json_response(
        StatusCode::OK,
        json!({
            "token": token,
            "token_type": TokenTyp::SessionToken.media_type(),
            "audience": template.audience(),
            "expires_in": template.ttl_seconds(),
        }),
    );
    // NEVER cached, anywhere. The body is a bearer credential.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// `GET /t/{tenant}/e/{environment}/session/token-mode`: whether this environment runs the
/// OPT-IN short-lived JWT session mode, and if so, against which template (issue #119
/// criterion 4).
///
/// An SDK reads this at start-up to learn which of two things it is doing:
///
/// - `{"enabled": false}` -- check the session statefully, which is what every environment does
///   until somebody turns this on. THIS IS THE DEFAULT AND A FRESH ENVIRONMENT ANSWERS IT.
/// - `{"enabled": true, "template": "...", "ttl_seconds": N, "jwks_uri": "..."}` -- mint a
///   session JWT from that template and re-mint it every `ttl_seconds`.
///
/// # Public, and what that does and does not disclose
///
/// Unauthenticated, like discovery and like the JWKS routes, because an SDK has to read it
/// BEFORE it has a session to present. What it discloses is one template name, its TTL, and its
/// JWKS URL -- configuration a verifier needs and which the published key set already implies
/// for anyone who knows the name. It discloses nothing about any session, any subject, or any
/// other template: a template not named by the mode is not mentioned here.
///
/// # It answers `enabled: false` for a mode pointed at a template that is gone
///
/// The foreign key cascades a template delete into a mode delete, so this state should not
/// arise. It is still answered fail-CLOSED rather than as an error, because "the mode is off"
/// sends an SDK to the stateful check, which is exactly where it should be when the tokenizer
/// cannot mint. An error would send it to its own failure handling for a condition that has a
/// correct answer.
pub async fn token_mode(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found_json();
    };
    let templates = state.store().scoped(scope).session_token_templates();
    let Ok(mode) = state
        .store()
        .scoped(scope)
        .session_jwt_mode()
        .template()
        .await
    else {
        return server_error();
    };
    let Some(template_name) = mode else {
        return json_response(StatusCode::OK, json!({ "enabled": false }));
    };
    let record = match templates.get(&template_name).await {
        Ok(Some(record)) => record,
        // See the doc: fail CLOSED to "off" rather than erroring.
        Ok(None) => return json_response(StatusCode::OK, json!({ "enabled": false })),
        Err(_) => return server_error(),
    };
    json_response(
        StatusCode::OK,
        json!({
            "enabled": true,
            "template": record.name,
            "ttl_seconds": record.ttl_seconds,
            "audience": record.audience,
            // BUILT FROM `issuer_for`, which is the one function that knows how a
            // per-environment URL is spelled. Rebuilding the `/t/../e/..` prefix here would be a
            // second place that has to agree with the router, and the first time they disagreed
            // this endpoint would hand every SDK a URL that 404s.
            "jwks_uri": format!(
                "{}/session-tokens/{}/jwks.json",
                state.issuer_for(&scope),
                record.name
            ),
        }),
    )
}

/// The `tokenize_as` query parameter: which template to mint from.
#[derive(serde::Deserialize)]
pub struct TokenizeQuery {
    /// The template name. Named `tokenize_as` because that is the spelling the prior art
    /// established (Ory Kratos' `whoami?tokenize_as=`), and an operator moving between the two
    /// should not have to learn a second word for one idea.
    tokenize_as: String,
}

/// A JSON response at `status` with `no-store` caching. A tokenize response carries a bearer
/// credential and every refusal names a session, so none of them may be cached by a shared
/// proxy.
#[allow(clippy::needless_pass_by_value)]
fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// A `401` for a request with no session, or one that no longer resolves.
///
/// ONE response for every reason, which is what makes criterion 3 hold without a second check:
/// absent, expired, revoked, ended and superseded are indistinguishable here because the store's
/// read guard reports them identically, so nothing about the session's fate leaks and nothing
/// about it can be special-cased into a mint.
fn unauthenticated() -> Response {
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error": "unauthenticated",
            "error_description": "Sign in to mint a session token.",
        }),
    )
}

/// The uniform `404`, byte-identical for a malformed scope and for a template that does not
/// exist, so it is never an existence oracle for an environment's template names.
fn not_found_json() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        json!({
            "error": "not_found",
            "error_description": "No such resource.",
        }),
    )
}

/// The `500` for a template that exists but has no key active right now.
///
/// SPECIFIC where [`server_error`] is generic, because the caller has already proved the template
/// exists and the operator's next action differs: this one is fixed at the template, and the
/// generic one is fixed at the store.
fn no_active_key() -> Response {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({
            "error": "template_has_no_active_key",
            "error_description": "This session token template has no signing key active right \
                                  now, so it cannot mint a token.",
        }),
    )
}

/// A generic `500` that never reveals what failed.
fn server_error() -> Response {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({
            "error": "server_error",
            "error_description": "The request could not be processed.",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(json: &str) -> Result<ValidatedTemplate, TemplateError> {
        validate_template("orders", "https://orders.example", 60, json)
    }

    #[test]
    fn a_placement_rule_is_refused_at_configuration_time() {
        let err = rules(r#"[{"kind":"place","name":"dept","placement":"access_token"}]"#)
            .expect_err("a place rule names a token this surface does not mint");
        assert_eq!(err, TemplateError::PlacementRule { rule_index: 0 });
    }

    #[test]
    fn a_placement_rule_is_refused_wherever_it_sits_in_the_list() {
        // The index is REPORTED, so a rule list of thirty tells the operator which line to fix.
        // A first-rule-only check would pass this and leave the inert rule installed.
        let err = rules(
            r#"[{"kind":"static","name":"tier","value":"gold"},
                {"kind":"place","name":"tier","placement":"both"}]"#,
        )
        .expect_err("a place rule anywhere in the list is inert here");
        assert_eq!(err, TemplateError::PlacementRule { rule_index: 1 });
    }

    #[test]
    fn a_rule_writing_a_protected_claim_is_refused_by_the_shared_validator() {
        let err = rules(r#"[{"kind":"static","name":"sub","value":"someone-else"}]"#)
            .expect_err("sub is protected");
        assert!(matches!(err, TemplateError::Mapping(_)), "{err:?}");
    }

    #[test]
    fn the_ttl_bound_is_refused_on_both_sides() {
        assert_eq!(
            validate_template("t", "https://a.example", MIN_TTL_SECONDS - 1, "[]"),
            Err(TemplateError::Ttl)
        );
        assert_eq!(
            validate_template("t", "https://a.example", MAX_TTL_SECONDS + 1, "[]"),
            Err(TemplateError::Ttl)
        );
        assert!(validate_template("t", "https://a.example", MIN_TTL_SECONDS, "[]").is_ok());
        assert!(validate_template("t", "https://a.example", MAX_TTL_SECONDS, "[]").is_ok());
    }

    #[test]
    fn the_documented_default_range_sits_inside_the_enforced_bound() {
        // The docs quote a range and the table enforces a different pair of numbers. This is what
        // makes the sentence in the documentation true rather than merely written.
        let (low, high) = DEFAULT_TTL_RANGE_SECONDS;
        assert!(low >= MIN_TTL_SECONDS && high <= MAX_TTL_SECONDS);
        assert!(low < high);
    }

    #[test]
    fn an_audience_is_required() {
        assert_eq!(
            validate_template("t", "", 60, "[]"),
            Err(TemplateError::Audience)
        );
    }

    #[test]
    fn the_rule_count_is_refused_here_and_not_by_the_database() {
        let one_too_many = (0..=MAX_TEMPLATE_RULES)
            .map(|i| format!(r#"{{"kind":"static","name":"c{i}","value":1}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let err = rules(&format!("[{one_too_many}]")).expect_err("one rule over the bound");
        assert_eq!(
            err,
            TemplateError::TooManyRules {
                count: MAX_TEMPLATE_RULES + 1
            }
        );
        let exactly = (0..MAX_TEMPLATE_RULES)
            .map(|i| format!(r#"{{"kind":"static","name":"c{i}","value":1}}"#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            rules(&format!("[{exactly}]")).is_ok(),
            "the bound must admit exactly MAX_TEMPLATE_RULES, or it is tighter than the table's"
        );
    }

    #[test]
    fn an_unreadable_document_names_what_could_not_be_read() {
        let err = rules(r#"[{"kind":"rename","from":"a","to":"b","sneaky":true}]"#)
            .expect_err("deny_unknown_fields");
        assert!(matches!(err, TemplateError::Unreadable(_)), "{err:?}");
    }

    #[test]
    fn a_template_projection_carries_every_mapped_claim() {
        // The coupling `mint` relies on, MEASURED rather than assumed: with no `place` rule in
        // the list -- which `validate_template` guarantees -- the ID-token projection under
        // `Destination::TwoTokens` is EVERY claim the rules produced, and the access-token
        // projection is empty. If that ever stopped holding, `mint` would silently drop claims
        // an operator configured, and every other test here would still pass.
        let template = rules(
            r#"[{"kind":"static","name":"tier","value":"gold"},
                {"kind":"rename","from":"amr","to":"methods"}]"#,
        )
        .expect("the rule list validates");
        let mut source = BTreeMap::new();
        source.insert("sub".to_owned(), json!("usr_1"));
        source.insert("sid".to_owned(), json!("ref"));
        source.insert("amr".to_owned(), json!(["pwd"]));
        let mapped = claims_mapping::apply_for(template.rules(), &source, Destination::TwoTokens)
            .expect("a validated rule list applies");
        assert!(
            mapped.access_token.is_empty(),
            "no rule placed anything, so nothing may reach the other projection: {:?}",
            mapped.access_token
        );
        for name in ["sub", "sid", "tier", "methods"] {
            assert!(
                mapped.id_token.contains_key(name),
                "{name} was produced by the rules and must be in the projection mint reads"
            );
        }
        // AND `amr` IS STILL THERE, which is not what this test first asserted.
        //
        // Measured, and worth keeping written down because it changes what an operator can do
        // with this source set: `amr` is one of the twenty-five names the mint treats as
        // issuer-set, so `claims_mapping` COPIES it on a rename instead of moving it -- deleting
        // a protected claim is overriding it. An operator who renames `amr` to publish it under
        // a house name gets BOTH names in the token, and a template cannot be used to take `amr`
        // out of one.
        assert!(
            mapped.id_token.contains_key("amr"),
            "a protected claim is copied by a rename, never moved"
        );
    }

    #[test]
    fn a_session_reference_is_not_the_session_id_and_does_not_contain_it() {
        let reference = session_reference("https://iss.example", "orders", "ses_secret_value");
        assert_ne!(reference, "ses_secret_value");
        assert!(!reference.contains("ses_secret_value"));
    }

    #[test]
    fn a_session_reference_differs_per_template_so_two_audiences_cannot_collude() {
        let a = session_reference("https://iss.example", "orders", "ses_abc");
        let b = session_reference("https://iss.example", "billing", "ses_abc");
        assert_ne!(
            a, b,
            "one session must not be linkable across two templates by its reference"
        );
    }

    #[test]
    fn a_session_reference_is_stable_for_one_session_and_template() {
        let a = session_reference("https://iss.example", "orders", "ses_abc");
        let b = session_reference("https://iss.example", "orders", "ses_abc");
        assert_eq!(a, b);
        let other = session_reference("https://iss.example", "orders", "ses_xyz");
        assert_ne!(a, other);
    }

    #[test]
    fn a_session_reference_is_keyed_by_the_issuer() {
        let a = session_reference("https://one.example", "orders", "ses_abc");
        let b = session_reference("https://two.example", "orders", "ses_abc");
        assert_ne!(a, b);
    }
}
