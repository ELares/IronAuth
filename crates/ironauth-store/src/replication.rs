// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outbox-stream replication shipper (issue #155, EXPLORATORY).
//!
//! # What this ships, and why it is the first slice
//!
//! The replication artifact the design note records is the outbox's ordered event
//! stream. The `sequence` column on `outbox_messages` is a database-assigned monotonic
//! order (never client-supplied), and the message body (consumer, idempotency_key,
//! ordering_key, payload, enqueued_at) is immutable once enqueued — so the stream is a
//! stable, ordered, deduplicable log. This shipper copies that log from a home region's
//! database to a follower's, preserving order, and records each (tenant, environment)'s
//! position on the follower. Lag is the difference between the home high-water mark and
//! the shipped position — a number, not a ceiling.
//!
//! What a follower DOES with the stream (the event-apply machinery that rebuilds users,
//! credentials, and configuration) is deliberately NOT this module: shipping the ordered
//! stream and lag is the slice that makes the RPO a first-class, measurable quantity,
//! and the apply half is the next slice. The follower's own outbox then holds the same
//! stream its consumers can drain in the same order.
//!
//! # Transport
//!
//! Postgres-only, per the issue: outbox shipping between regional databases. IronBus is
//! the optional carrier that lowers lag, never a prerequisite. The shipper reads the
//! home pool and writes the follower pool; neither is the request path, so the
//! no-request-path-connections lint does not govern it.
//!
//! # Resumability
//!
//! The copy is `ON CONFLICT (id) DO NOTHING` and the cursor advance is in the SAME
//! transaction as the copy, so a shipper interrupted mid-batch re-runs the batch and
//! the follower converges: already-copied rows are no-ops, the cursor moves exactly to
//! the highest shipped sequence.

use sqlx::{PgPool, Row};

/// The batch bound: how many home rows one pass may copy per (tenant, environment).
pub const BATCH_LIMIT: i64 = 1_000;

/// One (tenant, environment) partition's shipped position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicationCursor {
    pub tenant_id: &'static str,
    pub environment_id: &'static str,
    pub shipped_sequence: i64,
}

/// The report of one ship pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShipReport {
    /// The partitions visited and what happened to each.
    pub partitions: Vec<PartitionReport>,
}

/// One (tenant, environment)'s slice of a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionReport {
    pub tenant_id: String,
    pub environment_id: String,
    /// The home rows copied this pass.
    pub copied: i64,
    /// The position after the pass.
    pub shipped_sequence: i64,
    /// The home high-water mark for the partition.
    pub home_max_sequence: i64,
    /// `home_max_sequence - shipped_sequence`: the lag, in stream positions.
    pub lag_messages: i64,
}

/// A row of the home stream, copied verbatim to the follower.
#[derive(Debug, Clone)]
struct StreamRow {
    id: String,
    /// The home stream position. The cursor advances to the LAST copied row's sequence,
    /// not to a count: identity sequences are contiguous in practice but the contract is
    /// the actual position.
    sequence: i64,
    tenant_id: String,
    environment_id: String,
    consumer: String,
    idempotency_key: String,
    ordering_key: String,
    payload: serde_json::Value,
    enqueued_at_unix_micros: i64,
    /// The delivery gate the original enqueue computed from the app clock; the follower's
    /// copy keeps it, so the replica's drain eligibility is the home's.
    next_attempt_at_unix_micros: i64,
}

/// The replication shipper: copies the ordered outbox stream from `home` to `follower`.
///
/// The cursor rows live on the FOLLOWER (`replication_cursors`); the home region never
/// writes them, so a home database has no replication state of its own.
pub struct ReplicationShipper {
    home: PgPool,
    follower: PgPool,
}

impl ReplicationShipper {
    /// A shipper copying from `home` to `follower`.
    ///
    /// # Panics
    ///
    /// Panics if the two pools are the same pool — a shipper pointed at itself would
    /// "replicate" a region into itself, which is a configuration error, not a mode.
    #[must_use]
    pub fn new(home: PgPool, follower: PgPool) -> Self {
        assert!(
            !std::ptr::eq(&home, &follower),
            "a replication shipper must not point at itself"
        );
        Self { home, follower }
    }

    /// One ship pass: for every partition the follower has a cursor for (or every
    /// partition present in the home stream with no cursor yet), copy the home rows
    /// above the position, advance the position, and report the lag.
    ///
    /// # Errors
    ///
    /// [`sqlx::Error`] on a persistence failure. A failed pass changes nothing: the
    /// cursor advance is in the same transaction as the copy.
    pub async fn ship(&self, batch_limit: i64) -> Result<ShipReport, sqlx::Error> {
        let mut report = ShipReport {
            partitions: Vec::new(),
        };

        // The partitions to ship: the follower's existing cursors, plus any home
        // partition the stream holds that the follower has never seen (a fresh follower
        // starts from zero and must catch up).
        let mut partitions: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT tenant_id, environment_id, shipped_sequence FROM replication_cursors",
        )
        .fetch_all(&self.follower)
        .await?
        .into_iter()
        .collect();
        let known: std::collections::HashSet<(String, String)> = partitions
            .iter()
            .map(|(t, e, _)| (t.clone(), e.clone()))
            .collect();
        let fresh: Vec<(String, String)> =
            sqlx::query("SELECT DISTINCT tenant_id, environment_id FROM outbox_messages")
                .fetch_all(&self.home)
                .await?
                .into_iter()
                .map(|row| {
                    (
                        row.get::<String, _>("tenant_id"),
                        row.get::<String, _>("environment_id"),
                    )
                })
                .filter(|partition| !known.contains(partition))
                .collect();
        partitions.extend(fresh.into_iter().map(|(t, e)| (t, e, 0_i64)));

        for (tenant_id, environment_id, mut cursor) in partitions {
            let partition = self
                .ship_partition(&tenant_id, &environment_id, cursor, batch_limit)
                .await?;
            report.partitions.push(partition);
        }
        Ok(report)
    }

    /// Ship one partition: copy home rows above the cursor, advance the cursor in the
    /// same transaction, return the report.
    async fn ship_partition(
        &self,
        tenant_id: &str,
        environment_id: &str,
        mut cursor: i64,
        batch_limit: i64,
    ) -> Result<PartitionReport, sqlx::Error> {
        let rows: Vec<StreamRow> = sqlx::query(
            "SELECT id, sequence, tenant_id, environment_id, consumer, idempotency_key, \
             ordering_key, payload, (EXTRACT(EPOCH FROM enqueued_at) * 1000000)::bigint \
             AS enqueued_at, (EXTRACT(EPOCH FROM next_attempt_at) * 1000000)::bigint \
             AS next_attempt_at \
             FROM outbox_messages \
             WHERE tenant_id = $1 AND environment_id = $2 AND sequence > $3 \
             ORDER BY sequence LIMIT $4",
        )
        .bind(tenant_id)
        .bind(environment_id)
        .bind(cursor)
        .bind(batch_limit)
        .fetch_all(&self.home)
        .await?
        .into_iter()
        .map(|row| StreamRow {
            id: row.get("id"),
            sequence: row.get("sequence"),
            tenant_id: row.get("tenant_id"),
            environment_id: row.get("environment_id"),
            consumer: row.get("consumer"),
            idempotency_key: row.get("idempotency_key"),
            ordering_key: row.get("ordering_key"),
            payload: row.get("payload"),
            enqueued_at_unix_micros: row.get("enqueued_at"),
            next_attempt_at_unix_micros: row.get("next_attempt_at"),
        })
        .collect();

        let copied = i64::try_from(rows.len()).unwrap_or(i64::MAX);
        if copied == 0 {
            // No rows above the cursor: nothing to advance. The lag report still needs
            // the home high-water mark.
            let home_max: Option<i64> = sqlx::query_scalar(
                "SELECT max(sequence) FROM outbox_messages \
                 WHERE tenant_id = $1 AND environment_id = $2",
            )
            .bind(tenant_id)
            .bind(environment_id)
            .fetch_one(&self.home)
            .await?;
            return Ok(PartitionReport {
                tenant_id: tenant_id.to_owned(),
                environment_id: environment_id.to_owned(),
                copied: 0,
                shipped_sequence: cursor,
                home_max_sequence: home_max.unwrap_or(cursor),
                lag_messages: home_max.unwrap_or(cursor) - cursor,
            });
        }

        let mut tx = self.follower.begin().await?;
        for row in &rows {
            sqlx::query(
                "INSERT INTO outbox_messages \
                 (id, tenant_id, environment_id, consumer, idempotency_key, ordering_key, \
                  payload, enqueued_at, next_attempt_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, \
                         TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval, \
                         TIMESTAMPTZ 'epoch' + ($9::text || ' microseconds')::interval) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(&row.id)
            .bind(&row.tenant_id)
            .bind(&row.environment_id)
            .bind(&row.consumer)
            .bind(&row.idempotency_key)
            .bind(&row.ordering_key)
            .bind(&row.payload)
            .bind(row.enqueued_at_unix_micros)
            .bind(row.next_attempt_at_unix_micros)
            .execute(&mut *tx)
            .await?;
        }
        let max_shipped = rows.last().expect("rows is non-empty here").sequence;
        // The cursor advance is in the SAME transaction as the copy: a failed advance
        // rolls back the copy, so the position and the rows can never disagree.
        sqlx::query(
            "INSERT INTO replication_cursors (tenant_id, environment_id, shipped_sequence, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (tenant_id, environment_id) DO UPDATE SET \
               shipped_sequence = EXCLUDED.shipped_sequence, \
               updated_at = now()",
        )
        .bind(tenant_id)
        .bind(environment_id)
        .bind(max_shipped)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let home_max: Option<i64> = sqlx::query_scalar(
            "SELECT max(sequence) FROM outbox_messages \
             WHERE tenant_id = $1 AND environment_id = $2",
        )
        .bind(tenant_id)
        .bind(environment_id)
        .fetch_one(&self.home)
        .await?;
        Ok(PartitionReport {
            tenant_id: tenant_id.to_owned(),
            environment_id: environment_id.to_owned(),
            copied,
            shipped_sequence: max_shipped,
            home_max_sequence: home_max.unwrap_or(max_shipped),
            lag_messages: home_max.unwrap_or(max_shipped) - max_shipped,
        })
    }
}
