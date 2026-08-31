// SPDX-License-Identifier: MIT OR Apache-2.0

//! How a management call says it ARRIVED (issue #123 criterion 5).
//!
//! > Every admin MCP mutation appears in the audit stream attributed to the machine identity
//! > with the MCP entry path marked.
//!
//! The attribution half already worked: `actor_kind` and `actor_id` name the machine identity,
//! and an MCP server authenticating with a scoped API key IS that identity. What nothing
//! recorded is whether the same identity called directly or through an agent tool, and an
//! operator investigating "why did this key delete a client at 3am" needs to tell those apart.
//!
//! # A SEPARATE EXTRACTOR, not a field on `Principal`
//!
//! `Principal` is an enum whose variants carry what AUTHENTICATION established. The entry path
//! is not that: it is unauthenticated, caller-declared, and orthogonal to who the caller is.
//! Folding it into the credential type would put a value nobody verified beside values the
//! platform proved, in a type whose whole job is to say what was proved.
//!
//! Taking it as its own extractor also makes the wiring VISIBLE. A handler that records the
//! entry path names [`DeclaredEntryPath`] in its signature, so "which handlers record this" is a
//! question the compiler can answer rather than one somebody greps for.
//!
//! # What it is worth
//!
//! See [`ironauth_store::EntryPath`]: self-declared provenance, not an authenticated fact. It is
//! not a privilege and cannot become one -- the caller is already authenticated and already
//! authorized for the operation, and lying about their own provenance changes nothing they can
//! do. Read it as a `User-Agent` is read.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ironauth_store::EntryPath;

use crate::error::ApiError;
use crate::state::AdminState;

/// The header a caller declares its entry path in.
pub const ENTRY_PATH_HEADER: &str = "x-ironauth-entry-path";

/// The entry path this request declared, if any.
///
/// [`None`] means "not recorded", which is what a direct API call has. It does NOT mean "arrived
/// directly": that would be a claim about something nobody measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredEntryPath(pub Option<EntryPath>);

impl FromRequestParts<AdminState> for DeclaredEntryPath {
    // INFALLIBLE, and that is the decision worth defending. A header this version does not
    // recognise yields `None` and the request proceeds.
    //
    // Refusing would let a client break its own management operations by sending a value a newer
    // agent tool introduced -- turning a provenance HINT into an availability dependency, which
    // is far more damage than an unrecorded hint. The header is not a control; nothing is
    // permitted or denied by it.
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let declared = parts
            .headers
            .get(ENTRY_PATH_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(EntryPath::parse);
        Ok(Self(declared))
    }
}
