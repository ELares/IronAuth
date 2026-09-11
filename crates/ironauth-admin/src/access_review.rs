// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exporting an organization's access review (issue #145 criterion 1).
//!
//! # What the caller gets
//!
//! One row per PATH by which a member holds a role -- direct, through a named group, or the
//! organization's default -- plus one `none` row for a member who holds nothing. Both member
//! kinds are covered: a service account is an organization member and resolves through the
//! same closure, so an export of "who has which role" that listed only people would leave a
//! machine identity off the evidence.
//!
//! The rows come from `ManagementStore::access_review`, which loops the effective-grant
//! resolvers rather than writing a second SQL answer to the same question. That module's
//! header says why; the short version is that an evidence file which quietly disagrees with
//! the tokens being issued is worse than no evidence file.
//!
//! # Two formats, one column list
//!
//! `format=jsonl` (the default) and `format=csv`. The header and the JSON keys come from one
//! shared constant, so a consumer that pins both cannot find them disagreeing.
//!
//! # Audited, and a GET that writes exactly one row
//!
//! Every export writes one `access_review.export` row naming the organization and the row
//! COUNT, never the rows: the identity export (#58) follows the same rule, because a bulk read
//! of sensitive material is OBSERVABLE, never obstructed.
//!
//! It matters more here than for an ordinary listing. This export is the ONLY management read
//! that discloses an organization's MACHINE members: `getOrgMembershipEffectiveRoles` resolves
//! through a lookup filtering `owner_kind = 'user'`, `listMemberships` filters the same way,
//! and no GET lists service-account memberships. So for those rows the export widens ACCESS,
//! not convenience, and an untraced bulk read of them would be exactly the gap the evidence is
//! meant to close.
//!
//! THAT MAKES IT A READ WHICH MOVES ONE ROW, and the soft-deleted-environment sweep names it:
//! organization-addressed READS must keep answering there, so an audited read must be able to
//! write its audit row there, and `documented_write_row_effects` records the delta.
//!
//! # Two designs were tried and rejected, both by review
//!
//! An unaudited GET shipped first, justified by the claim that no audited-write helper accepts
//! an `IdempotencyWrite`. That was false -- `write_audited` hands its closure the transaction
//! and roughly thirty store writes call `insert_idempotency` inside it -- and the gap it
//! excused was the machine-member disclosure above.
//!
//! A keyed POST replaced it and is worse in two structural ways. The replay store has no
//! content-type column, so `replay_if_stored` answers every replay `application/json` and a
//! replayed CSV arrives mislabelled. And storing the replay puts the WHOLE export --
//! every membership id, subject id, role slug and group -- into `idempotency_keys`, a table
//! with 24-hour retention, no scope columns and no row-level security. That is the second copy
//! this module refuses to put in the audit row, in a weaker place. Neither is fixable without
//! a schema change, and neither buys anything a GET does not already give.
//!
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::access_review::{to_csv, to_jsonl};
use serde::Deserialize;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::response::{csv, ndjson};
use crate::state::AdminState;
use ironauth_store::CorrelationId;

/// Which serialization the caller wants.
#[derive(Debug, Deserialize)]
pub struct AccessReviewQuery {
    /// `jsonl` (the default) or `csv`.
    #[serde(default)]
    format: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/access-review",
    operation_id = "exportOrganizationAccessReview",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("format" = Option<String>, Query, description = "jsonl (default) or csv")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One row per path by which a member holds a role. `application/x-ndjson` by default, `text/csv; charset=utf-8` when format=csv", body = String, content_type = "application/x-ndjson"),
        (status = 400, description = "An unknown format was asked for", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The organization is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn export_organization_access_review(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<AccessReviewQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;

    // AN UNKNOWN FORMAT IS REFUSED, not defaulted. A caller asking for `xlsx` and receiving
    // JSON Lines under a 200 has an evidence pipeline that silently reads the wrong thing.
    let format = match query.format.as_deref() {
        None | Some("jsonl") => Format::Jsonl,
        Some("csv") => Format::Csv,
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "unknown format {other}; this endpoint serves jsonl and csv"
            )));
        }
    };

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;

    let rows = state
        .store()
        .management()
        .access_review(
            scope,
            &org_id,
            state.max_group_depth(),
            // THE INSTANT, only when the exploratory feature is acknowledged. An access
            // review that omitted a role the member actually holds would answer its own
            // question -- who has which role -- falsely, and a time-boxed elevation is
            // exactly the row an auditor came to find. With the flag off this is the same
            // export it was before the feature existed, save two always-empty columns.
            state
                .access_requests_enabled()
                .then(|| state.now_unix_micros()),
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    let body = match format {
        Format::Jsonl => to_jsonl(&rows),
        Format::Csv => to_csv(&rows),
    };
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .record_access_review_audit(state.env(), scope, &org_id, rows.len())
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(match format {
        Format::Jsonl => ndjson(StatusCode::OK, body),
        Format::Csv => csv(StatusCode::OK, body),
    })
}

/// The two serializations this endpoint serves.
enum Format {
    /// One JSON object per line.
    Jsonl,
    /// RFC 4180, header first.
    Csv,
}
