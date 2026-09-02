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
//! 7523). B never sees A's access token, and A never issues a credential valid at B.
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
//! ID-JAG path still refuses; what it adds is the three checks that make an identity assertion
//! different from an ordinary bearer assertion:
//!
//! - **The media type.** `draft-ietf-oauth-identity-assertion-authz-grant` gives the assertion
//!   its own `typ`, and that is the whole separator: without it, any assertion an issuer is
//!   trusted for is also an identity assertion, and an issuer trusted to federate one workload
//!   could speak for a user.
//! - **The requesting client is NAMED in the assertion.** The draft binds the assertion to the
//!   client that will present it, so an assertion intercepted by another client of the same
//!   deployment is inert. Without this the assertion is a bearer token for anyone who holds it.
//! - **The assertion's scope is a CEILING.** What A said the user authorized bounds what B
//!   issues. A receiving side that ignored it would let a registered mapping widen what the
//!   authoritative domain granted.
//!
//! # What a graduation still needs
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
/// Carried for the caller to map onto the grant's uniform wire error. The client sees the same
/// `invalid_grant` every other assertion failure produces: a caller that learned which of these
/// fired would know how far a forged assertion got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAssertionRefusal {
    /// The assertion does not carry the ID-JAG media type, so it is an ordinary bearer
    /// assertion being presented as an identity one.
    NotAnIdentityAssertion,
    /// The assertion names no client, or names a different one than the presenter.
    ClientMismatch,
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
    media_type_is(verified.token_typ(), ID_JAG_TYP)
}

/// The extra checks an identity assertion must pass, on top of everything the ordinary
/// assertion grant already enforced.
///
/// `presenting_client` is the client that authenticated at the token endpoint, and
/// `requested_scope` is what it asked for. The assertion's own `scope` is the ceiling.
///
/// Returns the scope the token may carry: the assertion's set when the request named none, or
/// the request's when it named a subset. NEVER the union, and never the request's alone.
///
/// # Errors
///
/// [`IdentityAssertionRefusal`], for diagnostics. Every variant is the same uniform refusal on
/// the wire.
pub fn admit(
    verified: &VerifiedToken,
    presenting_client: &str,
    requested_scope: Option<&str>,
) -> Result<Vec<String>, IdentityAssertionRefusal> {
    if !is_identity_assertion(verified) {
        return Err(IdentityAssertionRefusal::NotAnIdentityAssertion);
    }

    // BOUND TO THE PRESENTER. The draft names the client the assertion is for, so one
    // intercepted by another client of this same deployment is inert. Without this the
    // assertion is a bearer token for whoever holds it, which is exactly what a chained
    // identity must not be.
    let named = verified
        .claims()
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .filter(|client| !client.is_empty())
        .ok_or(IdentityAssertionRefusal::ClientMismatch)?;
    if named != presenting_client {
        return Err(IdentityAssertionRefusal::ClientMismatch);
    }

    // THE CEILING. What the authoritative domain said the user authorized bounds what this one
    // issues; a receiving side that ignored it would let a local mapping widen a remote grant.
    let authorized: Vec<String> = verified
        .claims()
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .map(|scope| scope.split_whitespace().map(ToOwned::to_owned).collect())
        .unwrap_or_default();
    if authorized.is_empty() {
        return Err(IdentityAssertionRefusal::NoScope);
    }

    let Some(requested) = requested_scope else {
        return Ok(authorized);
    };
    let requested: Vec<String> = requested
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    if requested.is_empty() {
        return Ok(authorized);
    }
    if requested.iter().any(|scope| !authorized.contains(scope)) {
        return Err(IdentityAssertionRefusal::ScopeExceedsAssertion);
    }
    Ok(requested)
}

/// Compare a media type, with the optional and case-insensitive `application/` prefix.
///
/// The same comparison `attestation_client_auth` performs, for the same reason: `TokenTyp` names
/// only profiles IronAuth mints, and this one is a foreign party's.
fn media_type_is(header_typ: Option<&str>, expected: &str) -> bool {
    const APPLICATION_PREFIX: &str = "application/";
    let Some(candidate) = header_typ else {
        return false;
    };
    let stripped = candidate
        .get(..APPLICATION_PREFIX.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(APPLICATION_PREFIX))
        .map_or(candidate, |_| &candidate[APPLICATION_PREFIX.len()..]);
    stripped.eq_ignore_ascii_case(expected)
}
