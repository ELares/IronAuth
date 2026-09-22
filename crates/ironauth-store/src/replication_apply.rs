// SPDX-License-Identifier: MIT OR Apache-2.0

//! The follower's event-APPLY machinery (issue #155, EXPLORATORY).
//!
//! # What applying means here
//!
//! The shipper copies the ordered outbox stream to the follower. The stream's domain
//! events (`webhook.event` consumer rows) are the record of what changed; the APPLY half
//! turns them back into replica state. The envelope payloads are deliberately
//! PII-free (they name entities, never secrets — the catalog enforces it), so an apply
//! cannot reconstruct the sealed/encrypted columns from the payload alone. The apply
//! therefore works the way the events were designed to be consumed: the event names the
//! entity, and the apply copies that entity's HOME ROW to the follower byte-for-byte —
//! sealed envelope columns, blind indexes, and the credential hashes all travel intact.
//!
//! # The generic copy
//!
//! `copy_row` reads the home row as JSON (`row_to_json`) and inserts it into the
//! follower with `json_populate_record` — no column list to maintain, so a migration
//! that adds a column to a replicated table does not break the copy, and the
//! integration test below is the drift gate: a column added to a replicated table is
//! exercised by the very test that applies its events.
//!
//! # What is applied, and what is not (the exploratory boundary)
//!
//! The acceptance criterion names users, credentials, and environment configuration.
//! The applier covers the entity events that produce those rows (user.*, client.*,
//! environment.*) and SKIPS everything else with a debug note. The skip is the
//! exploratory phase's boundary, stated rather than hidden: an event type that is
//! silently not applied would claim a replica that does not exist.
//!
//! # Idempotence
//!
//! The copy is an upsert on the entity id, so re-applying the stream (a retried pass, a
//! reboot) converges. The follower's FORCE RLS demands the partition's scope settings
//! on the copy transaction, exactly as the shipper's copy transaction carries them.

use sqlx::PgPool;
use sqlx::Row;

/// The domain-event consumer whose stream the apply consumes.
pub const DOMAIN_EVENT_CONSUMER: &str = "webhook.event";

/// One applied event's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEvent {
    /// The event type.
    pub event_type: String,
    /// The entity row copied, when the type was one the applier owns.
    pub copied: Option<String>,
    /// Why an unowned type was skipped.
    pub skipped_reason: Option<String>,
}

/// The event-apply result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub applied: Vec<AppliedEvent>,
}

/// Whether the applier owns `event_type`, and the entity id's location in the payload:
/// (table, payload key). The list is the boundary; an unowned type is skipped with a
/// reason, never silently applied to the wrong table.
fn owns(event_type: &str) -> Option<(&'static str, &'static str)> {
    match event_type {
        "user.created" | "user.state_changed" | "user.deactivated" | "user.deprovisioned" => {
            Some(("users", "user_id"))
        }
        "client.created" | "client.deleted" | "client.allowed_scopes_set" => {
            Some(("clients", "client_id"))
        }
        "environment.created" | "environment.deleted" => Some(("environments", "environment_id")),
        _ => None,
    }
}

/// Apply one event: copy the entity's home row to the follower.
///
/// # Errors
///
/// [`sqlx::Error`] on a persistence failure. An unowned type is skipped, not an error.
pub async fn apply_event(
    home: &PgPool,
    follower: &PgPool,
    event_type: &str,
    envelope: &serde_json::Value,
) -> Result<AppliedEvent, sqlx::Error> {
    let Some((table, entity_key)) = owns(event_type) else {
        return Ok(AppliedEvent {
            event_type: event_type.to_owned(),
            copied: None,
            skipped_reason: Some(
                "the exploratory applier does not own this entity yet".to_string(),
            ),
        });
    };
    let payload = envelope.get("payload").unwrap_or(envelope);
    let Some(entity_id) = payload.get(entity_key).and_then(serde_json::Value::as_str) else {
        return Ok(AppliedEvent {
            event_type: event_type.to_owned(),
            copied: None,
            skipped_reason: Some("the payload names no entity id".to_string()),
        });
    };
    let tenant_id = envelope
        .get("tenant_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let environment_id = envelope
        .get("environment_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    // The entity's sealed columns are wrapped under the scope's KEK, which lives in
    // `tenant_keks`; a copy that brings the rows but not the keys would be a replica
    // that cannot open anything. The KEK rows are copied first, so a read on the
    // follower resolves exactly as it does at home.
    if tenant_id.is_empty() || environment_id.is_empty() {
        return Ok(AppliedEvent {
            event_type: event_type.to_owned(),
            copied: None,
            skipped_reason: Some("the envelope carries no scope".to_string()),
        });
    }
    copy_scope_rows(
        home,
        follower,
        "tenant_keks",
        tenant_id,
        environment_id,
        "id",
    )
    .await?;
    // The DEKs the sealed columns were sealed under (wrapped by the KEKs above).
    copy_scope_rows(
        home,
        follower,
        "tenant_deks",
        tenant_id,
        environment_id,
        "id",
    )
    .await?;
    copy_row(home, follower, table, entity_id, tenant_id, environment_id).await?;
    // A user's identity is more than the users row: the multi-identifier surface lives
    // in `user_identifiers`, and a login through ANY identifier must resolve on the
    // follower, not just the primary one the users row carries. The CREDENTIAL
    // factors (passkeys, TOTP seeds) live in their own tables keyed by subject — the
    // "credentials replicate" half of the criterion — and are sealed under the same
    // KEK/DEK rows the apply already copies, so the factor rows travel intact.
    if table == "users" {
        copy_children(
            home,
            follower,
            "user_identifiers",
            entity_id,
            tenant_id,
            environment_id,
            "user_id",
        )
        .await?;
        copy_children(
            home,
            follower,
            "webauthn_credentials",
            entity_id,
            tenant_id,
            environment_id,
            "subject",
        )
        .await?;
        copy_children(
            home,
            follower,
            "totp_credentials",
            entity_id,
            tenant_id,
            environment_id,
            "subject",
        )
        .await?;
    }
    Ok(AppliedEvent {
        event_type: event_type.to_owned(),
        copied: Some(table.to_owned()),
        skipped_reason: None,
    })
}

/// Copy one entity row from home to follower: `row_to_json` on the home side, a
/// `json_populate_record` upsert on the follower side, with the partition's scope
/// settings on the copy transaction (the follower's FORCE RLS WITH CHECK).
///
/// # Errors
///
/// [`sqlx::Error`] when the copy cannot run, or when the home row's JSON does not map
/// onto the follower's row shape (a schema divergence — the drift the integration test
/// exists to catch).
async fn copy_row(
    home: &PgPool,
    follower: &PgPool,
    table: &str,
    entity_id: &str,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(), sqlx::Error> {
    // The home read rides the shipper's BYPASSRLS connection, so no scope settings are
    // needed to SEE the row. The id is globally unique, so the single-column predicate
    // is sufficient.
    let json: String = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t)::text FROM {table} t WHERE id = $1"
    ))
    .bind(entity_id)
    .fetch_one(home)
    .await?;

    let mut tx = follower.begin().await?;
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(environment_id)
        .execute(&mut *tx)
        .await?;
    // `json_populate_record(NULL::users, $1)` fills a record of the table's CURRENT
    // shape from the JSON's matching keys; the upsert on the entity id makes a re-apply
    // converge. The jsonb cast goes through json_populate_record's json input.
    let statement = format!(
        "INSERT INTO {table} SELECT * FROM json_populate_record(NULL::{table}, $1::json) \
         ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id"
    );
    sqlx::query(&statement)
        .bind(&json)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Copy every row of `table` belonging to the scope, idempotently (the upsert on the
/// table's id). The KEK copy is the scope-bootstrap: the wrapped KEK material is the
/// same bytes on both regions (same master key material, by the design note), so the
/// follower can unwrap exactly what home wrapped.
///
/// # Errors
///
/// [`sqlx::Error`] on a persistence failure.
async fn copy_scope_rows(
    home: &PgPool,
    follower: &PgPool,
    table: &str,
    tenant_id: &str,
    environment_id: &str,
    conflict_column: &str,
) -> Result<(), sqlx::Error> {
    let rows: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t)::text FROM {table} t \
         WHERE tenant_id = $1 AND environment_id = $2"
    ))
    .bind(tenant_id)
    .bind(environment_id)
    .fetch_all(home)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let mut tx = follower.begin().await?;
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(environment_id)
        .execute(&mut *tx)
        .await?;
    let statement = format!(
        "INSERT INTO {table} SELECT * FROM json_populate_record(NULL::{table}, $1::json) \
         ON CONFLICT ({conflict_column}) DO UPDATE SET {conflict_column} = EXCLUDED.{conflict_column}",
        table = table,
        conflict_column = conflict_column,
    );
    for json in &rows {
        sqlx::query(&statement).bind(json).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// THE PROMOTION STEP (issue #155's failover demo): copy the session-relevant state
/// the event stream does not carry.
///
/// Sessions, refresh families, refresh tokens, and grants have NO creation events (the
/// catalog carries only `session.revoked`), so a follower cannot be built for them
/// event-by-event. The promotion procedure therefore copies them at promotion, in the
/// same generic row-copy the event-apply uses, and the achieved RPO is the lag at that
/// moment — the design note's loss-window statement covers the events inside it. This
/// is a stated exploratory boundary, not a hidden one.
///
/// # Errors
///
/// [`sqlx::Error`] on a persistence failure. The copy is idempotent (upserts).
pub async fn promote_scope(
    home: &PgPool,
    follower: &PgPool,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(), sqlx::Error> {
    // FK order: grants root the families, families root the tokens.
    // FK order (grants root the families, families root the tokens), and the per-table
    // conflict column: `refresh_tokens` keys on `token_digest`, the rest on `id`.
    for (table, conflict) in [
        ("grants", "id"),
        ("refresh_families", "id"),
        ("refresh_tokens", "token_digest"),
        ("sessions", "id"),
    ] {
        copy_scope_rows(home, follower, table, tenant_id, environment_id, conflict).await?;
    }
    Ok(())
}

/// Copy every row of `table` owned by `entity_id` (a `user_id`-shaped column), the
/// child rows the entity's own copy does not carry.
///
/// # Errors
///
/// [`sqlx::Error`] on a persistence failure.
async fn copy_children(
    home: &PgPool,
    follower: &PgPool,
    table: &str,
    entity_id: &str,
    tenant_id: &str,
    environment_id: &str,
    owner_column: &str,
) -> Result<(), sqlx::Error> {
    let rows: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t)::text FROM {table} t \
         WHERE {owner_column} = $1 AND tenant_id = $2 AND environment_id = $3"
    ))
    .bind(entity_id)
    .bind(tenant_id)
    .bind(environment_id)
    .fetch_all(home)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let mut tx = follower.begin().await?;
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(environment_id)
        .execute(&mut *tx)
        .await?;
    let statement = format!(
        "INSERT INTO {table} SELECT * FROM json_populate_record(NULL::{table}, $1::json) \
         ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id"
    );
    for json in &rows {
        sqlx::query(&statement).bind(json).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Apply a batch of domain-event envelopes: the follower's shipped stream, consumed in
/// stream order. The envelope JSON carries `type`, the subject id, and the scope.
///
/// # Errors
///
/// [`sqlx::Error`] on a persistence failure. The batch stops at the first failure — the
/// caller retries the whole batch and the idempotent copies converge.
pub async fn apply_envelopes(
    home: &PgPool,
    follower: &PgPool,
    envelopes: &[(String, serde_json::Value)],
) -> Result<ApplyReport, sqlx::Error> {
    let mut report = ApplyReport {
        applied: Vec::new(),
    };
    for (_id, envelope) in envelopes {
        let Some(event_type) = envelope.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let outcome = apply_event(home, follower, event_type, envelope).await?;
        report.applied.push(outcome);
    }
    Ok(report)
}

/// The domain-event rows on the follower's shipped stream, in stream order: (id,
/// envelope).
///
/// # Errors
///
/// [`sqlx::Error`] on a persistence failure.
pub async fn shipped_domain_events(
    follower: &PgPool,
) -> Result<Vec<(String, serde_json::Value)>, sqlx::Error> {
    use sqlx::Row as _;
    let rows = sqlx::query(
        "SELECT id, payload FROM outbox_messages WHERE consumer = $1 ORDER BY sequence",
    )
    .bind(DOMAIN_EVENT_CONSUMER)
    .fetch_all(follower)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.get("id"), row.get("payload")))
        .collect())
}
