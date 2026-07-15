// SPDX-License-Identifier: MIT OR Apache-2.0

//! The resource-type classification catalog (issue #41).
//!
//! Every first-class resource type carries an explicit promotable / runtime /
//! environment-identity classification, declared once in the schema
//! (`ironauth_store::classification`) and served here as machine-readable API
//! metadata. The snapshot export (5.3) and the promotion engine (5.4) consume
//! this catalog rather than maintaining a parallel list, so the "does this travel
//! in a config snapshot?" decision has one source of truth. A CI lint
//! (`scripts/classification-lint.sh`) plus an exhaustive match in the store fail
//! the build if a resource type ever lands unclassified.
//!
//! The catalog is static schema metadata (not tenant data), so it is readable by
//! any authenticated management credential: presenting a valid credential is
//! enough, with no plane or scope restriction.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::ResourceType;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{ResourceTypeView, ResourceTypesList};

/// List every resource type and its promotion classification.
#[utoipa::path(
    get,
    path = "/v1/resource-types",
    operation_id = "listResourceTypes",
    tag = "resource-model",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The resource-type classification catalog", body = ResourceTypesList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody)
    )
)]
pub async fn list_resource_types(
    State(_state): State<AdminState>,
    _principal: Principal,
) -> Result<Response, ApiError> {
    let list = ResourceTypesList {
        items: ResourceType::ALL
            .into_iter()
            .map(ResourceTypeView::from)
            .collect(),
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
