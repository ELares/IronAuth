// SPDX-License-Identifier: MIT OR Apache-2.0

//! What THIS credential may do (issue #123 criterion 4).
//!
//! > Each MCP tool declares the management scopes it requires, and calls fail closed when the
//! > presented key lacks them; a key scoped to read-only exposes no mutating tools.
//!
//! The failing-closed half is already true of every endpoint: `require_permission` refuses a
//! restricted credential and always has. What needed this endpoint is the second half. For an
//! agent tool server to EXPOSE no mutating tools, it has to know what its own key holds -- and
//! before this there was no way to ask. The alternative is an operator hand-configuring the
//! server with the scopes they believe the key has, and a configuration that drifts from the key
//! lists tools that then fail, which is precisely "exposes a mutating tool".
//!
//! # This is not a way to map a credential
//!
//! `require_permission`'s refusal deliberately does NOT enumerate what a credential holds,
//! because an error that listed a credential's authority would turn a denied call into a way to
//! map it. This endpoint looks like the opposite and is not, for one reason: it answers ONLY
//! about the credential presenting it.
//!
//! There is no key parameter and there cannot be one. Telling the holder of a credential what
//! that credential can do discloses nothing -- they hold it, and they can discover the same
//! thing by trying. What it saves is the trying, which is the whole point for a tool server
//! deciding what to advertise.
//!
//! # Why it is classified `management.read` rather than left open
//!
//! "Any authenticated caller may ask about itself" is tempting and would be a second
//! authorization rule on a surface that has one. Every read here is `management.read`, and a
//! credential that cannot read is a credential no agent tool server can usefully drive anyway --
//! it would advertise nothing.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;
use crate::views::CallerView;

/// Report what the presenting credential is and may do.
#[utoipa::path(
    get,
    path = "/v1/me",
    operation_id = "getCaller",
    tag = "operators",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The presenting credential's own plane, scope and permissions", body = CallerView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "The credential is not granted management.read", body = ErrorBody)
    )
)]
pub async fn get_caller(
    State(_state): State<AdminState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;

    let view = match &principal {
        Principal::Operator { .. } => CallerView {
            plane: "operator".to_owned(),
            tenant_id: None,
            environment_id: None,
            // NULL AND NOT THE FULL LIST, because those are different facts and a tool server
            // acts on the difference. An operator's authority is not a set of management
            // permissions at all -- it is the operator plane, which is broader than any of them
            // and includes tenant lifecycle that no permission names. Rendering it as "all six"
            // would be a smaller claim than the truth.
            permissions: None,
            unrestricted: true,
        },
        Principal::ManagementKey { scope, grants, .. } => CallerView {
            plane: "management_key".to_owned(),
            tenant_id: Some(scope.tenant().to_string()),
            environment_id: Some(scope.environment().to_string()),
            // `None` grants means UNRESTRICTED, not "no permissions" -- migration 0118 added the
            // column NULL so every key minted before delegated administration kept its authority.
            // Reporting an empty list for one would tell a tool server to advertise nothing,
            // which is the opposite of true.
            permissions: grants.map(|held| {
                ManagementPermission::ALL
                    .iter()
                    .filter(|permission| held.holds(**permission))
                    .map(|permission| permission.as_slug().to_owned())
                    .collect()
            }),
            unrestricted: grants.is_none(),
        },
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
