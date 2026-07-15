// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operator-plane read endpoints (issue #41).
//!
//! The operator is the root of the four-level resource model: the platform
//! deployment itself, above every tenant. A single-binary deployment self-
//! bootstraps exactly one operator, and tenants reference it by foreign key, so
//! the operator plane is exposed here as a documented READ surface (list and get)
//! rather than a mutable CRUD: creating or deleting the deployment root through
//! the API is out of the resource model this issue completes (a deployment
//! provisions its operator out of band, the same way it provisions its database
//! roles). Operator identifiers embed neither a tenant nor an environment, and
//! both endpoints are operator-plane: a management key here is the LOUD
//! wrong-plane error.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{OperatorList, OperatorView};

/// List operators (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/operators",
    operation_id = "listOperators",
    tag = "operators",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of operators", body = OperatorList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_operators(
    State(state): State<AdminState>,
    principal: Principal,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .operators()
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OperatorList {
        items: rows.into_iter().map(OperatorView::from).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one operator.
#[utoipa::path(
    get,
    path = "/v1/operators/{operator_id}",
    operation_id = "getOperator",
    tag = "operators",
    params(("operator_id" = String, Path, description = "The operator identifier")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The operator", body = OperatorView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
pub async fn get_operator(
    State(state): State<AdminState>,
    principal: Principal,
    Path(operator_id): Path<String>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let operators = state.store().management().operators();
    let id = operators.parse_id(&operator_id)?;
    let record = operators.get(&id).await?;
    let body =
        serde_json::to_string(&OperatorView::from(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
