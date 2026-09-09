// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security Event Tokens: the RFC 8417 framing a Shared Signals transmitter mints (issue #143).
//!
//! A SET is a JWT whose payload carries an `events` object rather than an authentication
//! result. This module builds that payload and signs it through the SAME per-environment
//! issuer and hardened JOSE core an ID token and a Logout Token go through, so a SET cannot be
//! signed by a key, an algorithm or under a `typ` the rest of the system does not agree with.
//!
//! # What this module does NOT decide
//!
//! It does not decide WHAT happened. [`SecurityEvent`] carries an event type URI and an opaque
//! payload, and this module never inspects either: the CAEP and RISC vocabularies -- which URI
//! means "the session was revoked" and what its payload must contain -- are the next issue's,
//! and [`EVENTS_SUPPORTED`] is deliberately empty until they land. A transmitter that named
//! event types it cannot produce would publish that list in its discovery document, which is
//! the one place a receiver reads to decide what to ask for.
//!
//! # The subject is an RFC 9493 identifier, rendered per stream, at the TOP LEVEL
//!
//! A receiver keys its users its own way, so SSF negotiates the identifier FORMAT per stream.
//! [`SubjectIdentifier`] is the rendered side of the same three formats
//! [`ironauth_store::SsfSubjectFormat`] stores, and the two are kept honest by
//! [`SubjectIdentifier::format`], which answers the stored enum rather than a string literal.
//!
//! It travels as the top-level `sub_id` claim, which SSF 1.0 section 3.1.2 makes a MUST for a
//! new event type -- the same section forbids naming the primary subject with an in-event
//! `subject` member instead.
//!
//! # `jti` comes from the caller
//!
//! RFC 8417 requires a `jti` and receivers dedup on it, so a re-delivery of one event MUST
//! carry the same one. Minting it here would produce a fresh value per attempt and turn every
//! retry into a new event in the receiver's log, which is the defect `backchannel`'s logout
//! token records having had. The caller owns it, mints it once when the delivery is enqueued,
//! and carries it on the immutable payload.

use ironauth_env::Env;
use ironauth_jose::{EmissionOptions, TokenTyp, sign_jws_with_policy};
use ironauth_store::{Scope, SsfSubjectFormat};

use crate::issuer::IssuerRegistry;

/// The event type URIs this build can transmit.
///
/// EMPTY, and that is a statement rather than a placeholder. #143 ships the SSF framing and the
/// delivery machinery; the CAEP and RISC vocabularies are the next issue's. A discovery document
/// advertising an event type nothing emits would tell a receiver to request a signal it will
/// never be sent, and a receiver cannot distinguish that from a quiet period.
pub const EVENTS_SUPPORTED: &[&str] = &[];

/// One subject, in the RFC 9493 format its stream negotiated.
///
/// Only the three formats [`SsfSubjectFormat`] stores are representable, so a stream cannot ask
/// for a rendering this build does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectIdentifier {
    /// RFC 9493 section 3.2.2.
    Email {
        /// The address.
        email: String,
    },
    /// RFC 9493 section 3.2.3: the issuer and subject pair.
    IssSub {
        /// The issuer that minted the subject.
        iss: String,
        /// The subject, as that issuer spells it.
        sub: String,
    },
    /// RFC 9493 section 3.2.4.
    Opaque {
        /// The identifier this transmitter chose.
        id: String,
    },
}

impl SubjectIdentifier {
    /// The stored format this identifier renders.
    ///
    /// Answers the enum rather than a string so a caller matching a stream's negotiated format
    /// against what it built cannot compare two independently-written literals.
    #[must_use]
    pub fn format(&self) -> SsfSubjectFormat {
        match self {
            Self::Email { .. } => SsfSubjectFormat::Email,
            Self::IssSub { .. } => SsfSubjectFormat::IssSub,
            Self::Opaque { .. } => SsfSubjectFormat::Opaque,
        }
    }

    /// The RFC 9493 JSON object.
    ///
    /// `format` is taken from [`Self::format`] rather than written again here: the two would
    /// otherwise be independent spellings of the same fact, and a subject rendered under one
    /// format while labelled another is a subject the receiver resolves to the wrong person.
    #[must_use]
    pub fn render(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        object.insert(
            "format".to_owned(),
            serde_json::Value::String(self.format().as_str().to_owned()),
        );
        match self {
            Self::Email { email } => {
                object.insert("email".to_owned(), serde_json::Value::String(email.clone()));
            }
            Self::IssSub { iss, sub } => {
                object.insert("iss".to_owned(), serde_json::Value::String(iss.clone()));
                object.insert("sub".to_owned(), serde_json::Value::String(sub.clone()));
            }
            Self::Opaque { id } => {
                object.insert("id".to_owned(), serde_json::Value::String(id.clone()));
            }
        }
        serde_json::Value::Object(object)
    }
}

/// One event, as it appears inside a SET's `events` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    /// The event type URI, which is the KEY under `events`.
    pub event_type: String,
    /// The event's own members, rendered as the value under that key.
    ///
    /// A `Map` rather than a `Value`, so an event body that is not a JSON object cannot be
    /// built. RFC 8417's `events` values are objects; the first version of this took a `Value`
    /// and silently DROPPED a scalar, which turned a caller's mistake into a SET that reported
    /// the event with none of its detail.
    pub payload: serde_json::Map<String, serde_json::Value>,
}

/// Everything one SET says, before it is signed.
#[derive(Debug, Clone)]
pub struct SetToMint<'a> {
    /// The stream's audience, which becomes `aud`.
    pub audience: &'a [String],
    /// The dedup handle. Minted ONCE per event by the caller; see the module header.
    pub jti: &'a str,
    /// Who the event is about.
    pub subject: &'a SubjectIdentifier,
    /// What happened.
    pub event: &'a SecurityEvent,
}

/// Why a SET could not be minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// The environment has no usable signing key right now.
    NoSigningKey,
    /// The claim set or the signature could not be produced.
    Signing,
}

/// Build the RFC 8417 claim set.
///
/// Separated from the signing so it can be asserted on directly. A test that could only read
/// the claims back through a verifier would be comparing this code to itself.
#[must_use]
pub fn build_set_claims(issuer: &str, iat: i64, spec: &SetToMint<'_>) -> serde_json::Value {
    // THE SUBJECT IS A TOP-LEVEL `sub_id`, which SSF 1.0 section 3.1.2 makes a MUST for a new
    // event type -- and the same section says such a type MUST NOT use the `subject` member
    // inside `events` to name its primary subject. The carve-out in section 3.1.1, which lets
    // an event type defined in CAEP or RISC ALSO carry an in-event `subject`, does not reach
    // anything here: this build defines no event types at all (see `EVENTS_SUPPORTED`).
    //
    // An earlier version of this put the subject only in the event payload and cited SSF 1.0
    // for it. SSF says the reverse.
    let events = {
        let mut events = serde_json::Map::new();
        events.insert(
            spec.event.event_type.clone(),
            serde_json::Value::Object(spec.event.payload.clone()),
        );
        events
    };

    let mut claims = serde_json::Map::new();
    claims.insert(
        "iss".to_owned(),
        serde_json::Value::String(issuer.to_owned()),
    );
    claims.insert("iat".to_owned(), serde_json::Value::from(iat));
    claims.insert(
        "jti".to_owned(),
        serde_json::Value::String(spec.jti.to_owned()),
    );
    // ALWAYS AN ARRAY, even for one audience. RFC 7519 permits the single-string form and
    // receivers differ on which they accept; the array is the shape every one of them parses,
    // and a transmitter that switched shapes on the audience COUNT would work against a
    // receiver until the day a second audience was configured.
    // OMITTED WHEN EMPTY, not rendered as `[]`. RFC 8417 makes `aud` optional, and an empty
    // array is strictly worse than its absence: no receiver's audience check can ever match it,
    // so the SET would be undeliverable to everyone while looking well formed. The stream that
    // supplies this cannot be created with an empty audience -- 0216 refuses it and the surface
    // refuses it first -- so this arm is a floor under a caller that bypassed both.
    if !spec.audience.is_empty() {
        claims.insert(
            "aud".to_owned(),
            serde_json::Value::Array(
                spec.audience
                    .iter()
                    .map(|entry| serde_json::Value::String(entry.clone()))
                    .collect(),
            ),
        );
    }
    claims.insert("sub_id".to_owned(), spec.subject.render());
    claims.insert("events".to_owned(), serde_json::Value::Object(events));
    // NO `exp`, and for SSF that is a MUST NOT rather than a preference: SSF 1.0 section 4.1.7
    // says "The \"exp\" claim MUST NOT be used in SETs". RFC 8417 section 2.2 gives the reason
    // -- "a SET represents something that has already occurred and is historical in nature.
    // Therefore, its use is NOT RECOMMENDED" -- and an expiry would make a receiver that was
    // down through the window discard the events it most needs. Freshness is the delivery
    // layer's problem, and replay is what `jti` is for.
    serde_json::Value::Object(claims)
}

/// Mint and sign one SET for one environment.
///
/// # Errors
///
/// [`MintError::NoSigningKey`] when the environment has no signer available at `now`;
/// [`MintError::Signing`] when the claim set cannot be serialized or the JWS cannot be produced.
pub async fn mint_set(
    issuers: &IssuerRegistry,
    env: &Env,
    scope: Scope,
    spec: &SetToMint<'_>,
) -> Result<String, MintError> {
    let now = env.clock().now_utc();
    let entry = issuers
        .entry_for(&scope, now)
        .await
        .ok_or(MintError::NoSigningKey)?;
    let signer = entry.signer(now).ok_or(MintError::NoSigningKey)?;
    let policy = entry.policy();
    let issuer = issuers.issuer_for(&scope);
    let iat = i64::try_from(
        now.duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| MintError::Signing)?
            .as_secs(),
    )
    .map_err(|_| MintError::Signing)?;
    let claims = build_set_claims(&issuer, iat, spec);
    let payload = serde_json::to_vec(&claims).map_err(|_| MintError::Signing)?;
    // THE `typ` COMES FROM THE PROFILE LIST, not a literal here. RFC 8417 section 2.3 makes
    // stamping `secevent+jwt` a SHOULD, and `ironauth_jose::TokenTyp` is the one declaration
    // binding a profile to its media type, so the spelling a verifier requires and the spelling
    // stamped here cannot drift.
    sign_jws_with_policy(
        policy,
        signer,
        &payload,
        &EmissionOptions::new().with_token_typ(TokenTyp::SecurityEventToken),
    )
    .map_err(|_| MintError::Signing)
}
