// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity chaining and ID-JAG, the RECEIVING side, PROTOTYPE (issue #133).
//!
//! # What this is, and what it is not
//!
//! One of the five version-tagged prototypes issue #133 asks for. EXPERIMENTAL, off by default,
//! and enabling it requires acknowledging the exact draft revisions named by
//! [`IDENTITY_CHAINING_DRAFT`] and [`ID_JAG_DRAFT`]. The RECEIVING side only, which is what the
//! issue asks to be built first: this deployment ACCEPTS an identity assertion from another
//! trust domain. It does not yet request one.
//!
//! # The problem
//!
//! A user signs in at trust domain A. An application there needs to call an API in trust domain
//! B, as that user. Neither domain's tokens are valid in the other, and the usual answers are
//! bad in familiar ways: replicating the user into B loses the authoritative source, a shared
//! secret between A and B is a credential that outlives every incident, and passing A's token
//! to B makes B trust A's audience.
//!
//! Identity chaining composes the answer out of two RFCs this deployment already implements. The
//! requesting app exchanges its token at A for an **identity assertion** naming the user and
//! scoped to B (RFC 8693), then presents that assertion at B as an authorization grant (RFC
//! 7523). B never sees A's access token, and A never issues a token valid at B's RESOURCES:
//! the assertion authorizes nothing by itself, it only says who signed in and which client may
//! present it.
//!
//! # Why this is layered ON the jwt-bearer grant rather than beside it
//!
//! The second leg IS an RFC 7523 assertion grant, and IronAuth already has one: a per-scope
//! registry of trusted external issuers with an enable switch, a hardened verification path, a
//! registered subject mapping that is deny-by-default, single-use `jti` spending, and a
//! lifecycle fence on the mapped principal. Building a parallel path would mean a second copy of
//! every one of those, and the copy is where they stop agreeing.
//!
//! So this adds requirements and removes none. Everything the ordinary grant refuses, the
//! ID-JAG path still refuses; what it adds is the four checks that make an identity assertion
//! different from an ordinary bearer assertion:
//!
//! - **The media type.** `draft-ietf-oauth-identity-assertion-authz-grant` gives the assertion
//!   its own `typ`, and that is the whole separator: without it, any assertion an issuer is
//!   trusted for is also an identity assertion, and an issuer trusted to federate one workload
//!   could speak for a user.
//! - **The requesting client is NAMED in the assertion.** The draft binds the assertion to the
//!   client that will present it, so an assertion intercepted by another client of the same
//!   deployment is inert. Without this the assertion is a bearer token for anyone who holds it.
//! - **The presenting client is CONFIDENTIAL.** Which is what makes the naming above a
//!   control rather than a spelling requirement: a public client authenticates by naming
//!   itself, so an interceptor satisfies the binding by reading the client id off the
//!   assertion it stole. The ordinary grant permits a public presenter on purpose, because
//!   there the assertion IS the authorization grant and nothing claims to bind it.
//! - **The assertion's scope is a CEILING on the token's `scope`.** What A said the user
//!   authorized bounds the `scope` B issues. A receiving side that ignored it would let a
//!   registered mapping widen what the authoritative domain granted.
//!
//!   THE CEILING REACHES `scope` AND NOTHING ELSE, which is worth stating because the sentence
//!   above invites the wider reading. The minted token also carries `org_id` and `roles`,
//!   resolved from the LOCAL principal the subject maps to, and the assertion does not bound
//!   those. That is consistent with what this grant is -- B mints its own token under its own
//!   local identity -- but a resource server that authorizes on `roles` rather than on scope
//!   sees no ceiling at all. See the graduation list.
//!
//! # What a graduation still needs
//!
//! - **The ceiling does not reach the local authorization claims.** `org_id` and `roles` come
//!   from the mapped local principal. Bounding them needs a decision this prototype does not
//!   make: whether a chained identity should carry the local principal's authority at all, or
//!   only what the authoritative domain named.
//!
//! - **The REQUESTING side.** This accepts an assertion; it does not mint one. That is the
//!   other half of the chain and the half that needs a policy for which downstream domains a
//!   client may ask about.
//! - **No `jti` requirement.** The ordinary grant treats `jti` as optional because RFC 7523
//!   does, and this inherits that: an identity assertion without one has no replay protection
//!   beyond its expiry. The draft is stricter, and a graduation should be too.
//! - **Trust is per issuer, not per (issuer, domain) pair.** An issuer registered for workload
//!   federation becomes able to present identity assertions the moment the flag is on, unless an
//!   operator registers it separately. The registry has no column for "may speak for users", and
//!   adding one is a change to the GA external-issuer surface that a prototype does not get to
//!   make. **This is the sharpest edge here** and it is why the flag is off by default.

use ironauth_jose::VerifiedToken;

/// The identity-chaining draft this prototype targets.
///
/// Approved and in the RFC Editor queue, so it should acquire an RFC number; the acknowledgment
/// names the draft until it does, and the renumbering will be a version bump like any other.
pub const IDENTITY_CHAINING_DRAFT: &str = "draft-ietf-oauth-identity-chaining-16";

/// The ID-JAG draft whose assertion shape the receiving side accepts.
pub const ID_JAG_DRAFT: &str = "draft-ietf-oauth-identity-assertion-authz-grant-04";

/// The media type an identity assertion carries.
///
/// The separator between "an assertion this issuer is trusted for" and "an assertion that speaks
/// for a USER in another domain". Checked on the VERIFIED token, never on the presented header.
pub const ID_JAG_TYP: &str = "oauth-id-jag+jwt";

/// Why an identity assertion was refused, beyond the ordinary grant's own refusals.
///
/// The client sees the same `invalid_grant` every other assertion failure produces: a caller
/// that learned which of these fired would know how far a forged assertion got. The caller maps
/// each variant onto its OWN `ClientAuthDiagnosticReason` for the out-of-band sink, so an
/// operator can separate an interception from a misconfigured issuer even though the wire
/// cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAssertionRefusal {
    /// The assertion does not carry the ID-JAG media type, so it is an ordinary bearer
    /// assertion being presented as an identity one.
    NotAnIdentityAssertion,
    /// The presenting client is PUBLIC, so it authenticated with nothing but its own
    /// non-secret identifier.
    ///
    /// This is what makes [`Self::ClientMismatch`] mean anything. The ordinary jwt-bearer
    /// grant permits a public presenting client deliberately -- the assertion IS the
    /// authorization grant, so no client credential is required for a WORKLOAD to trade one.
    /// An identity assertion speaks for a PERSON and is bound to the client it was minted
    /// for, and for a `none` client "authenticating as `cli_x`" is typing `cli_x` into the
    /// form. Anyone who intercepted the assertion could satisfy the binding for free, and the
    /// assertion would be exactly the bearer token the binding exists to stop it being.
    PresenterNotConfidential,
    /// The assertion names a DIFFERENT client than the presenter.
    ///
    /// Kept apart from [`Self::Unbound`] because only this one is an attack. An assertion
    /// minted for another client arriving here is an interception; an assertion with no
    /// `client_id` at all is an issuer that did not set the claim. An operator pages on the
    /// first and files a ticket for the second, so recording both under one reason makes the
    /// alert built on it fire for a misconfiguration.
    ClientMismatch,
    /// The assertion names NO client, so it is bound to nobody.
    ///
    /// Refused for the same reason a mismatch is -- an unbound assertion is a bearer token
    /// with the binding left out rather than contradicted -- but it is a misconfigured issuer,
    /// not an interception. See [`Self::ClientMismatch`].
    Unbound,
    /// The assertion carries no scope, so there is no ceiling and nothing to issue against.
    NoScope,
    /// The request asked for scope the assertion does not authorize.
    ScopeExceedsAssertion,
}

/// Whether a verified assertion IS an identity assertion.
///
/// Read from the VERIFIED token's media type. A presented header is not evidence of anything:
/// the whole point of checking `typ` after verification is that the signature covers it.
#[must_use]
pub fn is_identity_assertion(verified: &VerifiedToken) -> bool {
    ironauth_jose::foreign_media_type_is(verified.token_typ(), ID_JAG_TYP)
}

/// The extra checks an identity assertion must pass, on top of everything the ordinary
/// assertion grant already enforced.
///
/// `presenting_client` is the client that authenticated at the token endpoint,
/// `presenter_is_confidential` says whether that authentication proved anything beyond
/// possession of the client's public identifier, and `requested_scope` is what it asked for.
/// The assertion's own `scope` is the ceiling.
///
/// Returns the scope the token may carry: the assertion's set when the request named none, or
/// the request's when it named a subset. NEVER the union, and never the request's alone.
///
/// # Errors
///
/// [`IdentityAssertionRefusal`]. Every variant is the same uniform refusal on the wire; the
/// caller records a distinct out-of-band reason per variant.
pub fn admit(
    verified: &VerifiedToken,
    presenting_client: &str,
    presenter_is_confidential: bool,
    requested_scope: Option<&str>,
) -> Result<Vec<String>, IdentityAssertionRefusal> {
    if !is_identity_assertion(verified) {
        return Err(IdentityAssertionRefusal::NotAnIdentityAssertion);
    }

    // THE BINDING BELOW HAS TO COST SOMETHING. A public client authenticates by naming
    // itself, so an interceptor satisfies `client_id` by sending the id printed in the
    // assertion it just stole.
    //
    // THE BINDING IS CHECKED FIRST, and the order is about the RECORD rather than the answer.
    // Both refuse, so a caller cannot tell them apart either way. But an assertion naming
    // another client is an INTERCEPTION and is the one refusal here an operator should be
    // paged on, while a public presenter is usually a deployment that has not finished
    // configuring. Checking the presenter first would report the cheapest interception --
    // replaying a stolen assertion through any public client, which open registration makes
    // free -- as the benign reason, and the alert built on the page-worthy one would never
    // fire for the attack it was built for.
    let named = verified
        .claims()
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .filter(|client| !client.is_empty())
        .ok_or(IdentityAssertionRefusal::Unbound)?;
    if named != presenting_client {
        return Err(IdentityAssertionRefusal::ClientMismatch);
    }

    // AND THE BINDING ABOVE HAS TO COST SOMETHING. A public client authenticates by naming
    // itself, so satisfying `client_id` costs an interceptor nothing: it reads the id off the
    // assertion. Refusing a public presenter is what turns the check above from a spelling
    // requirement into a control. Both are needed and neither implies the other.
    //
    // Checked after the media type, so an ordinary bearer assertion from a public client --
    // which this grant permits on purpose -- is untouched.
    if !presenter_is_confidential {
        return Err(IdentityAssertionRefusal::PresenterNotConfidential);
    }

    // THE CEILING. What the authoritative domain said the user authorized bounds what this one
    // issues; a receiving side that ignored it would let a local mapping widen a remote grant.
    let authorized: Vec<String> = verified
        .claims()
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .map(|scope| dedup(scope.split_whitespace().map(ToOwned::to_owned)))
        .unwrap_or_default();
    if authorized.is_empty() {
        return Err(IdentityAssertionRefusal::NoScope);
    }

    let Some(requested) = requested_scope else {
        return Ok(authorized);
    };
    let requested: Vec<String> = dedup(requested.split_whitespace().map(ToOwned::to_owned));
    if requested.is_empty() {
        return Ok(authorized);
    }
    if requested.iter().any(|scope| !authorized.contains(scope)) {
        return Err(IdentityAssertionRefusal::ScopeExceedsAssertion);
    }
    Ok(requested)
}

/// Preserve order, drop repeats.
///
/// The scope string is a FOREIGN issuer's, and this is the one place in the grant where a
/// party outside this deployment chooses it. `read:orders read:orders` is not wrong, and the
/// machine-grant validator is happy to pass it through, but it would reach the token's `scope`
/// claim and every log line downstream exactly as written. Normalizing here costs nothing and
/// keeps a remote party from choosing how this deployment's own claims are spelled.
fn dedup(scopes: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    scopes.filter(|scope| seen.insert(scope.clone())).collect()
}
