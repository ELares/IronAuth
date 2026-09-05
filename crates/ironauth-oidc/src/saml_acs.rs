// SPDX-License-Identifier: MIT OR Apache-2.0

//! The decision an assertion consumer service makes, and the state it consumes making it.
//!
//! # What this is, and why it is here rather than in `ironauth-saml`
//!
//! `ironauth-saml` is the choke point through which hostile SAML XML enters: it verifies a
//! signature against pinned keys and decides what is still true afterwards. It touches no
//! database, has no clock, and until this module existed it had NO DEPENDENTS AT ALL -- three
//! merged pieces of machinery and nothing calling any of them.
//!
//! This is the first caller. It is the part that cannot be pure: resolving which connection a
//! response arrived for, loading the keys an operator pinned, spending the outstanding request
//! exactly once, and admitting the assertion id exactly once. Every one of those is a row.
//!
//! # The order is the security property
//!
//! 1. RESOLVE THE CONNECTION BY THE URL THE RESPONSE ARRIVED AT, never by the `Issuer` inside
//!    it. The document says who it is from; only the endpoint says who it is for, and reading
//!    the document to decide which keys to check it against is the shape of CVE-2026-9090.
//! 2. VERIFY against the keys pinned on that connection. `TrustAnchor` is a raw key, so nothing
//!    in the response can become an anchor.
//! 3. CHECK the conditions, with the connection's own audience, recipient and skew.
//! 4. SPEND THE REQUEST, once. `consume_request` is an `UPDATE ... WHERE consumed_at IS NULL`,
//!    so two responses answering one sign-in race and exactly one wins.
//! 5. ADMIT THE ASSERTION, once. Same shape, on the assertion id.
//!
//! STEPS 4 AND 5 COME LAST AND IN THAT ORDER, and both are after every stateless check. A
//! response that fails its signature or its audience must not consume the request it names --
//! otherwise anyone who can post a malformed response to the ACS can spend a legitimate user's
//! outstanding request and turn their sign-in into "unknown request".
//!
//! # What this module deliberately does not do
//!
//! No HTTP: the POST-binding route, its form parsing and its redirect are the next piece, and
//! keeping them out means this decision is testable against a real database without one. No JIT
//! provisioning and no session: those need the attribute mapping, which #139's criterion 6 is
//! blocked on for the reason recorded on the issue. This answers WHO the assertion says signed
//! in and WHAT it said about them; turning that into a local identity is the next step.

use ironauth_saml::{
    ASSERTION_NS, Accepted, ConditionError, Expectations, Limits, Statement, TrustAnchor,
    Unreadable, VerifyError, attributes, check, verify,
};
use ironauth_store::{SamlCertificate, SamlConnection, SamlConnectionId, SamlKeyKind, StoreError};

/// What SAML Core 2.2.2 says an omitted `NameID` `Format` means.
const UNSPECIFIED_NAMEID: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

/// XSD's `collapse` whiteSpace facet: the four characters it treats as whitespace, folded to
/// single spaces with the ends trimmed.
///
/// EXACTLY FOUR, not `char::is_whitespace`. XSD's `whiteSpace` facet folds the whitespace of
/// XML 1.0's `S` production, which is `#x20 | #x9 | #xD | #xA` and nothing else, so folding a NO-BREAK SPACE or an ideographic space would make this
/// reader treat as one value a pair a schema-aware reader sees as two. `ironauth-saml` makes the
/// same choice in two places, for the same reason.
fn collapse(text: &str) -> String {
    text.split(['\u{9}', '\u{a}', '\u{d}', ' '])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the assertion consumer service concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumed {
    /// The connection the response was resolved to.
    pub connection_id: SamlConnectionId,
    /// Who the identity provider says this is, and until when it may be believed.
    pub accepted: Accepted,
    /// What the assertion said about them.
    pub statement: Statement,
    /// The `RelayState` recorded when the request was issued, for a solicited response.
    ///
    /// FROM THE STORE, NEVER FROM THE RESPONSE. `RelayState` is a binding parameter an attacker
    /// controls in transit, and it is where a service provider puts the URL to return to -- so
    /// taking the posted one is an open redirect with extra steps. The value here is the one
    /// this deployment recorded when it issued the request.
    ///
    /// [`None`] FOR THREE DIFFERENT REASONS, and a caller must not read it as any one of them:
    /// an unsolicited response, which has no request to have recorded one; a solicited response
    /// whose request recorded no `RelayState`, which is the ordinary shape for a sign-in with
    /// nowhere particular to return to; and a solicited response whose request recorded an
    /// EMPTY one, which [`consume`] folds into `None` rather than handing back a return
    /// location that is not one. "Was this solicited" is answered by `accepted.in_response_to`,
    /// which is the field for that question.
    pub relay_state: Option<String>,
    /// The browser binding recorded when the request was issued, for the TRANSPORT to compare
    /// against the cookie it holds (issue #139).
    ///
    /// [`None`] FOR TWO REASONS AND A CALLER MUST TREAT THEM ALIKE: an unsolicited response,
    /// which answers no request and so has no row to carry one, and a request issued by a build
    /// before migration 0200 added the column. Neither can be checked, and neither is a pass:
    /// what makes the absence safe is that unsolicited responses are refused unless a connection
    /// opted in, and that a pre-0200 request drains inside its own five-minute TTL.
    ///
    /// IT IS A DIGEST, so holding it is not holding the secret that satisfies it.
    pub browser_binding_sha256: Option<Vec<u8>>,
}

/// Why an assertion was not consumed.
///
/// # Every variant is a thing somebody can act on
///
/// A caller renders these to an operator through the connection-test flow #140 owns, so each one
/// names a different fix.
///
/// WHAT THEY DO CARRY: a variant past [`Self::Signature`] may quote the document, and several
/// do -- this enum's own `found`, the `found` inside several [`ConditionError`] variants, and
/// [`Unreadable::Duplicate`]'s `name` and `name_format`, which are document text under different
/// names. Anyone auditing which fields can carry identity-provider strings should read that as
/// "any field on any variant past `Signature`", not as a list of fields called `found`. An earlier version of this sentence said none of them did, which
/// was false through the wrapped types before round 1 and false at this enum's own level after
/// it. Quoting is SAFE HERE and deliberately not in those crates, because reaching any variant
/// past `Signature` requires a signature by a certificate the operator pinned: the document is
/// the identity provider's, not an attacker's. `VerifyError` sits before that gate and so
/// quotes nothing.
///
/// NOT `Clone`, `PartialEq` or `Eq`, because [`StoreError`] is none of those -- and wrapping it
/// in something comparable to make the enum comparable would be inventing an equality for a
/// database failure. Tests match on the variant instead, which is what they mean anyway.
#[derive(Debug)]
pub enum AcsError {
    /// No active connection is served at this URL, in this scope.
    ///
    /// NOT "unknown issuer". The URL is what resolves a response, so the operator's question is
    /// which connection is supposed to be answering here -- and telling them about the `Issuer`
    /// inside the document would point them at a value the document chose.
    NoConnection,
    /// The connection has nothing pinned at all.
    ///
    /// SEPARATE FROM A FAILED SIGNATURE. An operator who has not pinned a certificate yet gets
    /// told that -- rather than "the signature did not verify", which sends them to look at
    /// their identity provider.
    NoTrustAnchor,
    /// Certificates are pinned, and not one of them could be turned into a key.
    ///
    /// SEPARATE FROM [`Self::NoTrustAnchor`] BECAUSE THE FIX DIFFERS: "pin a certificate" and
    /// "the rows you have are not usable" send an operator to two different places, and telling
    /// somebody staring at three pinned rows that they have none is the wrong sentence.
    ///
    /// WHAT CAN ACTUALLY PRODUCE IT is narrower than an earlier version of this doc said. It
    /// claimed an expiry -- "the one they will hit years after setup" -- and a key kind this
    /// build cannot verify with. Neither reaches here: [`anchors`] does not read the validity
    /// columns, deliberately and for the reason written there, and every [`SamlKeyKind`] maps to
    /// a [`TrustAnchor`] (a kind the store cannot parse fails the whole read instead). The one
    /// producer is an `rsa` row whose exponent is absent, which migration 0197's CHECK forbids.
    /// So in practice this names SCHEMA DRIFT -- a row the database should not be holding -- and
    /// it exists because the alternative to answering it is a panic in an endpoint anybody can
    /// post to.
    AllCertificatesUnusable {
        /// How many are pinned, none of them usable.
        pinned: usize,
    },
    /// The signature did not verify, or the document was not one this server will read.
    Signature(VerifyError),
    /// The signature held and a condition did not.
    Condition(ConditionError),
    /// The signature and conditions held and the attributes could not be read.
    Attributes(Unreadable),
    /// The response names a request this deployment did not issue, or already spent.
    ///
    /// COVERS BOTH, and deliberately: "already spent" and "never issued" are the same fact from
    /// the endpoint's side one moment later, and distinguishing them tells somebody replaying a
    /// captured response whether their first attempt worked.
    UnknownRequest,
    /// The response is unsolicited and this connection does not accept those.
    UnsolicitedRefused,
    /// The assertion carries attributes encrypted for a key this pipeline was not given.
    ///
    /// SEPARATE FROM [`Self::EncryptionRequired`], which is about a CONNECTION SETTING this
    /// build cannot honour. This one is about a DOCUMENT: the connection asked for nothing
    /// special and the identity provider encrypted some attributes anyway, which this cannot
    /// read and will not quietly drop.
    EncryptedAttributes {
        /// How many `EncryptedAttribute` elements were passed over.
        count: usize,
    },
    /// The connection requires an encrypted assertion and this pipeline does not decrypt.
    ///
    /// ITS OWN VARIANT BECAUSE THE OPERATOR'S SITUATION IS SPECIFIC: they set a column this
    /// build cannot honour. Silently accepting cleartext would be a control that configures
    /// nothing, and folding it into a generic refusal would send them looking at their identity
    /// provider for a limitation on this side.
    EncryptionRequired,
    /// The `NameID` carries a `Format` other than the one this connection is configured for.
    WrongNameIdFormat {
        /// What the connection expects.
        expected: String,
        /// What the assertion carried, if it carried one.
        found: Option<String>,
    },
    /// This assertion has been admitted before.
    Replayed,
    /// The store could not be reached, or refused the write.
    Store(StoreError),
}

impl core::fmt::Display for AcsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoConnection => f.write_str("no active SAML connection is served at this URL"),
            Self::NoTrustAnchor => f.write_str("the connection has no pinned certificate at all"),
            Self::AllCertificatesUnusable { pinned } => write!(
                f,
                "none of the connection's {pinned} pinned certificates could be read as a key, \
                 which means a stored row this server should not be holding"
            ),
            Self::Signature(error) => write!(f, "the response did not verify: {error}"),
            Self::Condition(error) => write!(f, "the assertion was refused: {error}"),
            Self::Attributes(error) => write!(f, "the attributes could not be read: {error}"),
            Self::UnknownRequest => {
                f.write_str("the response does not answer a sign-in this server started")
            }
            Self::UnsolicitedRefused => {
                f.write_str("this connection does not accept unsolicited responses")
            }
            Self::EncryptedAttributes { count } => write!(
                f,
                "the assertion carries {count} encrypted attribute(s) this server cannot read"
            ),
            Self::EncryptionRequired => f.write_str(
                "this connection requires an encrypted assertion, which this server does not yet \
                 decrypt",
            ),
            Self::WrongNameIdFormat { expected, found } => match found {
                Some(found) => write!(
                    f,
                    "the assertion's NameID Format is {found:?} and this connection expects \
                     {expected:?}"
                ),
                None => write!(
                    f,
                    "the assertion's NameID names no Format and this connection expects \
                     {expected:?}"
                ),
            },
            Self::Replayed => f.write_str("this assertion has already been used"),
            Self::Store(error) => write!(f, "the store refused the sign-in: {error}"),
        }
    }
}

impl core::error::Error for AcsError {}

impl From<StoreError> for AcsError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// The pinned keys on a connection, as anchors the verifier will take.
///
/// # A certificate this build cannot verify with is SKIPPED, not fatal
///
/// A connection may hold several pinned certificates -- that is what makes a rollover possible,
/// and #141 owns the expiry alerting over them. If one of them is a kind this build has no
/// verifier for, the others must still work: refusing the whole connection would turn "one of
/// your three certificates is unusable" into "nobody can sign in", which is the wrong blast
/// radius for a configuration problem.
///
/// AN EMPTY RESULT IS TWO DIFFERENT ANSWERS at the call site: [`AcsError::NoTrustAnchor`] when
/// nothing is pinned, and [`AcsError::AllCertificatesUnusable`] when rows exist and none of them
/// became a key. An earlier version of this paragraph said the empty result was always the first
/// and that a one-element list could not tell "skipped" from "fatal" apart; both stopped being
/// true when the variants were split, and a one-element list is exactly what tells them apart
/// now. What SKIPPING still buys is the multi-certificate case -- one bad row among three must
/// not lock the connection out, which is what a rollover is made of.
///
/// EXPIRY IS NOT CHECKED HERE, and a later round of review tried to add the check before
/// reading this paragraph, so it is worth stating what holds it up. What is pinned on a
/// connection is KEY MATERIAL -- `public_key` plus `key_kind`, verified against a fingerprint an
/// operator compared by hand -- and not a chain anybody walks. The certificate's `notAfter` is a
/// statement by an issuer nobody here consults; the trust decision is the pinning itself. This
/// is the same position Shibboleth's explicit-key trust engine takes, and it is the majority
/// behaviour among SAML service providers, because the failure mode of the alternative is an
/// enterprise-wide lockout at midnight on a date nobody was watching.
///
/// SO THE COLUMNS ARE NOT DEAD, they belong to a different consumer: `not_after_unix_micros` is
/// what #141's expiry alerting reads, which is the mechanism that actually gets a certificate
/// rotated -- a warning weeks early, rather than a locked door on the day.
fn anchors(certificates: &[SamlCertificate]) -> Vec<TrustAnchor> {
    certificates
        .iter()
        .filter_map(|certificate| match certificate.key_kind {
            SamlKeyKind::EcdsaP256 => Some(TrustAnchor::EcdsaP256(certificate.public_key.clone())),
            SamlKeyKind::EcdsaP384 => Some(TrustAnchor::EcdsaP384(certificate.public_key.clone())),
            // THE EXPONENT IS REQUIRED FOR RSA AND THE COLUMN ENFORCES IT, so its absence here is
            // a row that should not exist. Skipped rather than unwrapped: a panic in the ACS is
            // a denial of service somebody can reach by posting a response.
            SamlKeyKind::Rsa => {
                certificate
                    .rsa_exponent
                    .as_ref()
                    .map(|exponent| TrustAnchor::Rsa {
                        modulus: certificate.public_key.clone(),
                        exponent: exponent.clone(),
                    })
            }
        })
        .collect()
}

/// What the caller supplies that this module cannot derive.
pub struct Acs<'a> {
    /// The connection the ACS URL resolved to, and the certificates pinned on it.
    pub connection: &'a SamlConnection,
    /// The pinned certificates.
    pub certificates: &'a [SamlCertificate],
    /// The clock, as an argument, for the reason `ironauth-saml` takes one.
    pub now_unix_secs: i64,
    /// Bounds on the document itself.
    pub limits: &'a Limits,
}

/// Verify and check a response, without touching the store.
///
/// SPLIT OUT SO THE STATELESS HALF IS TESTABLE WITHOUT A DATABASE, and so the ORDER is visible:
/// everything here happens before anything is spent, which is what stops a malformed response
/// from consuming a legitimate user's outstanding request.
///
/// # Errors
///
/// [`AcsError`], but never [`AcsError::Store`], [`AcsError::UnknownRequest`] or
/// [`AcsError::Replayed`] -- those need the store.
pub fn examine(acs: &Acs<'_>, response: &[u8]) -> Result<(Accepted, Statement), AcsError> {
    let anchors = anchors(acs.certificates);
    if anchors.is_empty() {
        // WHICH EMPTINESS THIS IS decides what the operator does next, so the two are not one
        // error. Nothing pinned is a setup step; rows that exist and cannot be read is a stored
        // row the schema should have refused, and those are different conversations.
        return Err(if acs.certificates.is_empty() {
            AcsError::NoTrustAnchor
        } else {
            AcsError::AllCertificatesUnusable {
                pinned: acs.certificates.len(),
            }
        });
    }
    let assertion = verify(response, acs.limits, &anchors, ASSERTION_NS, "Assertion")
        .map_err(AcsError::Signature)?;

    // WHICH REQUEST THIS ANSWERS IS READ FROM THE ASSERTION, and that is safe here for one
    // reason: the signature has already verified against a key the operator pinned. What the
    // value is NOT is authorization -- it names a request, it does not prove this deployment
    // issued one. `consume` proves that, and only the store can.
    //
    // Read through `ironauth-saml`'s own accessor, which shares the direct-child walk `check`
    // uses. A second reader of `InResponseTo` in a second crate would be the two-readers-disagree
    // defect this whole stack is built against.
    let carried = ironauth_saml::correlation(&assertion);

    let expectations = Expectations {
        issuer: &acs.connection.idp_entity_id,
        audience: &acs.connection.sp_entity_id,
        recipient: &acs.connection.acs_url,
        // WHAT THE ASSERTION CARRIED, and an earlier comment here claimed more than that: it
        // said a connection that does not correlate still refuses a response naming a request,
        // "because `carried` is `None` only when there is none". Both halves were wrong, and
        // the second contradicts the block twenty lines below. `correlation` and `check` read
        // `InResponseTo` through the SAME `bearer_confirmation_data` walk, so this value is a
        // copy of what `check` is about to look at: the comparison can only ever agree, and
        // `ConditionError::UnknownRequest` is unreachable from this call site. It is passed
        // anyway because `check`'s contract is that the caller states its expectation, and a
        // future caller correlating from its own outstanding-request table -- rather than from
        // the document -- gets the guard for free.
        in_response_to: carried.as_deref(),
        clock_skew_secs: i64::from(acs.connection.clock_skew_secs),
        max_age_secs: i64::from(acs.connection.max_assertion_age_secs),
    };
    let accepted =
        check(&assertion, &expectations, acs.now_unix_secs).map_err(AcsError::Condition)?;

    // THE UNSOLICITED DECISION COMES AFTER `check`, and an earlier version made it before.
    // `correlation` answers `None` for TWO different documents: one carrying no `InResponseTo`,
    // and one whose bearer confirmation cannot be read at all -- two of them, none, or no
    // `Subject`. Deciding on `carried.is_none()` reported the malformed one as
    // `UnsolicitedRefused`, which names a switch an operator could flip and that would not fix
    // it, while the real fault went unnamed. After `check`, a malformed subject is already
    // `Condition(Malformed)` and this sees only documents that are genuinely unsolicited.
    //
    // NOTHING IS SPENT EITHER WAY: both are stateless, and the caller spends nothing until this
    // whole function has returned.
    if accepted.in_response_to.is_none() && !acs.connection.allow_unsolicited {
        return Err(AcsError::UnsolicitedRefused);
    }

    // AND THE CONNECTION'S OWN TWO REMAINING CONTROLS, which an earlier version read from the row
    // and then ignored. A column that configures nothing is worse than no column, because an
    // operator sets it and believes it.
    if acs.connection.require_encrypted_assertion {
        // NOT IMPLEMENTED, SO REFUSED. `ironauth-saml` can decrypt, but this pipeline is not
        // wired to it and the connection's private key is not plumbed here. A connection that
        // demands encryption and gets cleartext must not sign anybody in, and the operator has
        // to be told which of the two it is.
        return Err(AcsError::EncryptionRequired);
    }
    // SAML CORE 2.2.2 GIVES AN OMITTED `Format` A MEANING: it is
    // `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`, not "no value". An earlier
    // version compared `Option<String>` against the column raw, so a connection configured for
    // `unspecified` refused every conformant document that left the attribute off -- two
    // spellings of one value, two outcomes, and nobody on that connection could sign in.
    // COLLAPSED ON BOTH SIDES for the same reason `attributes.rs` collapses the sibling
    // `NameFormat`: `Format` is an `xsd:anyURI`, and XSD gives that type the `collapse`
    // whiteSpace facet, so a padded spelling is the same value to every schema-aware reader.
    let expected_format = collapse(&acs.connection.nameid_format);
    let found_format = collapse(
        accepted
            .name_id_format
            .as_deref()
            .unwrap_or(UNSPECIFIED_NAMEID),
    );
    // A COLUMN THAT COLLAPSES TO NOTHING CONFIGURES NOTHING, and collapsing both sides is what
    // opened that: migration 0196 only asks that `nameid_format` be non-empty, so a single space
    // -- a paste artefact -- is storable, and it collapses to `""`. A document carrying
    // `Format=""` or `Format="   "` collapses to `""` as well, so the two would compare equal and
    // a check whose job is to stop a transient `NameID` being keyed as a persistent one would be
    // vacuous on that connection. The raw comparison this replaced refused that pair by accident;
    // this refuses it on purpose, and fails closed rather than inventing a default the operator
    // did not choose.
    if expected_format.is_empty() || found_format != expected_format {
        // THE FORMAT IS PART OF THE IDENTITY, not decoration. `transient` names somebody for one
        // session and `persistent` names them forever; accepting a transient `NameID` where a
        // connection was configured for a persistent one keys an account to a value that will
        // never be seen again -- and accepting a persistent one where transient was configured
        // stores a correlatable identifier the operator chose not to.
        return Err(AcsError::WrongNameIdFormat {
            expected: acs.connection.nameid_format.clone(),
            found: accepted.name_id_format.clone(),
        });
    }

    let statement = attributes(&assertion).map_err(AcsError::Attributes)?;
    if statement.encrypted > 0 {
        // AN ATTRIBUTE THIS PIPELINE CANNOT READ IS NOT AN ATTRIBUTE THAT IS ABSENT. An earlier
        // version of this comment justified the refusal by saying the withheld attributes "feed
        // the connection's mapping, so a dropped one is a trait the operator configured" -- and
        // this module never reads `connection.attribute_mapping`, while `Statement::encrypted`'s
        // own doc says a count CANNOT tell whether a withheld attribute is one the mapping
        // wants. The sentence asserted exactly what the upstream contract says is impossible.
        //
        // WHAT IS ACTUALLY TRUE: an `EncryptedAttribute` carries its `Name` INSIDE the
        // ciphertext, so nothing on this side can tell whether it mattered. The choice is
        // between signing somebody in from a document whose contents are partly unknown, and
        // refusing. It refuses, because the unknown part can be a group membership and signing
        // somebody in without one is signing them in with the wrong authorization. Making that
        // governable needs a column, and a column needs an operator to set it, so it belongs
        // with the connection API rather than being inferred here from a mapping whose default
        // is `{}` on every row that exists.
        return Err(AcsError::EncryptedAttributes {
            count: statement.encrypted,
        });
    }
    Ok((accepted, statement))
}

/// Verify, check, and then SPEND the state exactly once.
///
/// # The order, and why every step of it is load-bearing
///
/// [`examine`] runs first and completely: signature, issuer, audience, time bounds, recipient,
/// correlation shape, attributes. NOTHING IS SPENT UNTIL IT PASSES. A response that fails any of
/// those must not consume the request it names -- otherwise anybody who can post bytes to this
/// endpoint can spend a legitimate user's outstanding request and turn their sign-in into
/// "unknown request", which is a denial of service with no authentication required.
///
/// Then, in this order:
///
/// 1. THE REQUEST, for a solicited response. `consume_request` is an
///    `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now`, so two responses answering one
///    sign-in race in the database and exactly one wins. Its `RETURNING relay_state` is where
///    the return URL comes from -- the store's copy, never the posted one.
/// 2. THE ASSERTION ID. `admit_assertion` is an `INSERT ... ON CONFLICT DO NOTHING`, so the same
///    assertion presented twice inserts once and the second is [`AcsError::Replayed`].
///
/// THE REQUEST IS SPENT BEFORE THE ASSERTION IS ADMITTED, and that is a SOLICITED-PATH property.
/// An earlier version of this paragraph ranked it the other way round -- "matters for the
/// unsolicited path more" -- and then refuted itself in the next clause: an unsolicited response
/// has no request, so only one write happens and one write has no order. What the order buys is
/// entirely here: a solicited response that loses the race for its request never consumes a
/// replay slot it did not use, so the same assertion presented against a legitimately re-issued
/// request is still admissible rather than permanently burnt.
///
/// WHAT THE UNSOLICITED PATH RELIES ON is the other half of the same pair: with no request to
/// spend, the assertion id is the ONLY thing standing between a captured response and unlimited
/// replay. That is why the connection has to opt in before this path exists at all.
///
/// # Errors
///
/// [`AcsError`].
pub async fn consume(
    replay: &ironauth_store::SamlReplayRepo<'_>,
    acs: &Acs<'_>,
    response: &[u8],
) -> Result<Consumed, AcsError> {
    let (accepted, statement) = examine(acs, response)?;
    let now_micros = acs.now_unix_secs.saturating_mul(1_000_000);

    let spent = match &accepted.in_response_to {
        Some(request_id) => {
            // TWO DIFFERENT ANSWERS THAT ARE EASY TO SWAP, and swapping them is a real defect
            // in both directions -- so they are written out rather than funnelled through `?`:
            //
            // `Err(NotFound)` is the request being ABSENT: never issued here, already spent, or
            // expired. All three are one refusal, deliberately: "already spent" and "never
            // issued" are the same fact one moment apart, and distinguishing them would tell
            // somebody replaying a captured response whether their first attempt worked.
            //
            // `Ok(None)` is the request being FOUND with no `RelayState` recorded, which is the
            // ordinary shape for a sign-in with nowhere particular to return to. Reading it as
            // "unknown request" would refuse every such sign-in.
            match replay
                .consume_request(&acs.connection.id, request_id, now_micros)
                .await
            {
                Ok(spent) => Some(spent),
                Err(StoreError::NotFound) => return Err(AcsError::UnknownRequest),
                Err(other) => return Err(AcsError::Store(other)),
            }
        }
        // AN UNSOLICITED RESPONSE HAS NO REQUEST TO SPEND. [`examine`] has already refused this
        // unless the connection opted in.
        None => None,
    };
    let relay_state = spent
        .as_ref()
        .and_then(|spent| spent.relay_state.clone())
        .filter(|value| !value.is_empty());
    // THE BINDING COMES BACK FROM THE SAME SPEND, because the spend can only happen once: a
    // second read would be of a row this one has already marked consumed. The comparison is the
    // TRANSPORT's, not this module's -- the value it is compared against is in a cookie, and
    // this module touches no HTTP.
    let browser_binding_sha256 = spent.and_then(|spent| spent.browser_binding_sha256);

    // REMEMBERED UNTIL `expires_at_unix_secs`, which is the earliest of the assertion's own
    // expiry, the confirmation's, this connection's ceiling, and the skew that admitted it. A
    // cache told to forget it sooner would forget it while it could still be presented.
    //
    // NOT YET MEASURABLE FROM OUTSIDE, and worth saying rather than leaving the paragraph above
    // reading like a tested property. Nothing reads this column: 0198 ships the table without a
    // sweep, so `admit_assertion` conflicts on the primary key whatever the expiry says, and
    // replacing the value with `i64::MAX` or with `seen_at + 1` changes no test's answer. The
    // only thing that catches a wrong value today is the table's own `CHECK (expires_at >
    // seen_at)`. The sweep is what turns this into a real bound, and the test that pins it
    // belongs with the sweep -- filed here rather than asserted, because a comment claiming a
    // measured property is worse than one admitting an unmeasured one.
    replay
        .admit_assertion(
            &acs.connection.id,
            &accepted.assertion_id,
            now_micros,
            accepted.expires_at_unix_secs.saturating_mul(1_000_000),
        )
        .await
        .map_err(|error| match error {
            // `ON CONFLICT DO NOTHING` inserts nothing for an id already there, and the repo
            // reports that as a conflict rather than a success -- which is the whole point.
            ironauth_store::StoreError::Conflict => AcsError::Replayed,
            other => AcsError::Store(other),
        })?;

    Ok(Consumed {
        connection_id: acs.connection.id,
        accepted,
        statement,
        relay_state,
        browser_binding_sha256,
    })
}
