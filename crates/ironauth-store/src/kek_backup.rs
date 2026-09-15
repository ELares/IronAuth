// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integrity-checking a KEK hierarchy backup (issue #153, criterion 4).
//!
//! Criterion 4 asks that backups "fail restore loudly on checksum or key mismatch". The key
//! mismatch half is the wrap AAD, which already refuses: a KEK sealed under one master key
//! cannot be unwrapped under another, and `kek_recovery.rs` proves it. This is the checksum
//! half.
//!
//! # What a checksum here is actually protecting against
//!
//! Not an attacker. Every blob in a KEK backup is sealed under a master key held outside the
//! database, so tampering with one produces a blob that fails to unwrap: the AEAD is the
//! integrity mechanism for the CONTENT.
//!
//! What the AEAD cannot see is the backup as a WHOLE. A truncated file, a restore that
//! silently skipped rows, a partial upload, a concatenation of two different backups: each
//! produces a set of rows that are individually valid and collectively wrong. The failure
//! mode is a restore that succeeds, reports success, and leaves a subset of tenants
//! permanently unreadable, discovered one at a time as each one signs in.
//!
//! So the manifest binds the SET: how many rows, and a digest over all of them in a fixed
//! order.
//!
//! # Why verification happens before any write
//!
//! A restore that writes what it can and fails partway is worse than one that refuses: it
//! leaves a database that is neither the old state nor the new one, and the operator running
//! it is already having a bad day. Verification is a separate step that touches nothing.

use sha2::{Digest, Sha256};

/// One backed-up KEK row.
///
/// The whole row, not just the blob. The wrap AAD binds the scope, the version and the
/// master key id, so a restore that put the blob back under a different version produces a
/// row that exists and cannot be opened, and that failure looks like a successful restore
/// until somebody reads a secret.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackedUpKek {
    /// The KEK identifier.
    pub id: String,
    /// The owning tenant.
    pub tenant_id: String,
    /// The environment within it.
    pub environment_id: String,
    /// The KEK version.
    pub version: i32,
    /// Which master key sealed this KEK.
    pub master_key_id: String,
    /// The sealed material. Empty after a crypto-shred, which is a valid state to back up.
    #[serde(with = "blob_hex")]
    pub wrapped_kek: Vec<u8>,
    /// The row's status.
    pub status: String,
    /// When the row was created, as RFC 3339.
    ///
    /// Carried because the column has a `now()` DEFAULT: a restore that omits it silently
    /// stamps every KEK in the deployment with the incident date. A review measured exactly
    /// that, `created_at` moving from the provisioning instant to the restore instant on
    /// every row, and nothing failed.
    pub created_at: String,
    /// When the row was crypto-shredded, as RFC 3339, or [`None`] if it was not.
    ///
    /// This is the erasure record. The migration that added it calls the destroyed row
    /// "retained as evidence", and a seven-column export dropped it: after a restore, a
    /// shredded row still said the key was destroyed and no longer said WHEN. An erasure
    /// attestation, or a regulator asking when tenant T's key was destroyed, had no answer,
    /// and the row looked superficially correct so nobody noticed.
    pub destroyed_at: Option<String>,
}

/// Bytes as lowercase hex in the backup file, so a KEK blob survives a round trip through a
/// text transport (a copy-paste, a ticket attachment, a log) without a base64 variant or a
/// JSON array of integers making the file unreadable to an operator checking it by eye.
mod blob_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize `bytes` as lowercase hex.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        serializer.serialize_str(&out)
    }

    /// Deserialize lowercase hex back to bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() % 2 != 0 {
            return Err(serde::de::Error::custom("odd-length hex"));
        }
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

impl BackedUpKek {
    /// This row's digest, over every field the restore writes.
    ///
    /// EVERY field, because each one is either bound into the wrap AAD or decides which row
    /// this is. A digest over the blob alone would pass a backup whose rows had been
    /// re-pointed at other scopes, which is the shape that produces individually valid rows
    /// and a collectively wrong database.
    fn digest(&self, hasher: &mut Sha256) {
        // Length-prefixed, so that a field ending where the next begins cannot be moved
        // between them without changing the digest. Concatenating `a` + `bc` and `ab` + `c`
        // is otherwise the same bytes.
        let mut field = |bytes: &[u8]| {
            hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(bytes);
        };
        field(self.id.as_bytes());
        field(self.tenant_id.as_bytes());
        field(self.environment_id.as_bytes());
        field(&self.version.to_be_bytes());
        field(self.master_key_id.as_bytes());
        field(&self.wrapped_kek);
        field(self.status.as_bytes());
        field(self.created_at.as_bytes());
        // A length-prefixed marker rather than the bare string, so an absent `destroyed_at`
        // and an empty one cannot digest alike.
        match self.destroyed_at.as_deref() {
            None => field(b"\x00"),
            Some(at) => {
                field(b"\x01");
                field(at.as_bytes());
            }
        }
    }
}

/// What a backup claims about itself.
///
/// # It has to leave the process, or it attests nothing
///
/// A review made this point and it is the difference between a check and a decoration: the
/// only call an operator could write against the first version of this module was
/// `verify(rows, &manifest_for(rows))`, which compares a value with itself and returns `Ok`
/// for any deterministic digest, including one taken over an export that had already lost
/// every row. A manifest is a claim recorded at BACKUP time and presented at RESTORE time, so
/// it must survive being written to a file, carried on a different medium from the rows it
/// describes, and read back. [`Manifest::encode`] and [`Manifest::decode`] are that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// How many rows the backup should contain.
    pub rows: usize,
    /// A digest over every row, in a fixed order.
    pub digest: [u8; 32],
}

impl Manifest {
    /// The manifest as one line: `rows=<n> sha256=<64 hex>`.
    ///
    /// Deliberately a line a human can read, compare by eye, and paste into a ticket. The
    /// point of storing it apart from the backup is that a transfer which damages the rows
    /// does not silently damage the claim about them, and that only works if an operator can
    /// keep the claim somewhere the rows are not.
    #[must_use]
    pub fn encode(&self) -> String {
        use std::fmt::Write as _;

        let mut hex = String::with_capacity(64);
        for byte in self.digest {
            let _ = write!(hex, "{byte:02x}");
        }
        format!("rows={} sha256={hex}", self.rows)
    }

    /// Parse a manifest written by [`Manifest::encode`].
    ///
    /// # Errors
    ///
    /// [`ManifestParseError`] if the line is not that shape. Refused rather than
    /// best-guessed: a manifest that parses into something other than what was written is a
    /// check that passes for the wrong reason, which is worse than no check.
    pub fn decode(line: &str) -> Result<Self, ManifestParseError> {
        let line = line.trim();
        let (rows, digest) = line.split_once(' ').ok_or(ManifestParseError::Malformed)?;
        let rows: usize = rows
            .strip_prefix("rows=")
            .ok_or(ManifestParseError::Malformed)?
            .parse()
            .map_err(|_| ManifestParseError::Malformed)?;
        let hex = digest
            .strip_prefix("sha256=")
            .ok_or(ManifestParseError::Malformed)?;
        if hex.len() != 64 {
            return Err(ManifestParseError::Malformed);
        }
        let mut bytes = [0_u8; 32];
        for (at, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16)
                .map_err(|_| ManifestParseError::Malformed)?;
        }
        Ok(Self {
            rows,
            digest: bytes,
        })
    }
}

/// A manifest line that is not the shape [`Manifest::encode`] writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestParseError {
    /// The line is not `rows=<n> sha256=<64 hex>`.
    Malformed,
}

impl std::fmt::Display for ManifestParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a manifest is `rows=<n> sha256=<64 hex characters>`")
    }
}

impl std::error::Error for ManifestParseError {}

/// Why a backup cannot be restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupError {
    /// The backup holds a different number of rows than the manifest claims.
    ///
    /// Reported separately from a digest mismatch because the remedy differs: a count
    /// mismatch is a truncated or partial transfer, and the operator wants the rest of the
    /// file rather than a different backup.
    RowCount {
        /// What the manifest claims.
        expected: usize,
        /// What the backup holds.
        found: usize,
    },
    /// The rows do not digest to what the manifest claims.
    DigestMismatch,
    /// Two rows claim the same identity, so a restore would silently keep one.
    DuplicateRow {
        /// The repeated identifier.
        id: String,
    },
    /// Two rows claim the same scope and version under different ids.
    ///
    /// The collision a restore actually hits. `tenant_keks` has `UNIQUE (tenant_id,
    /// environment_id, version)`, so two rows with different ids on one scope and version
    /// pass an id-keyed duplicate scan and then abort the insert partway. That is exactly the
    /// "two backups concatenated" case this module names as its reason to exist, and a review
    /// demonstrated it verifying `Ok` and then dying on the unique constraint with one row of
    /// four written.
    DuplicateScopeVersion {
        /// The tenant whose scope repeats.
        tenant_id: String,
        /// The environment within it.
        environment_id: String,
        /// The repeated version.
        version: i32,
    },
}

/// The manifest for `rows`.
///
/// The rows are digested in the order given. A caller exports them ordered by id, and
/// [`verify`] sorts before digesting so a backup that survives a reordering transfer still
/// verifies: the SET is what is being attested, not the file layout.
#[must_use]
pub fn manifest_for(rows: &[BackedUpKek]) -> Manifest {
    let mut sorted: Vec<&BackedUpKek> = rows.iter().collect();
    sorted.sort_by(|left, right| left.id.cmp(&right.id));
    let mut hasher = Sha256::new();
    // The COUNT is hashed first, so appending a row cannot be absorbed by the concatenation
    // of the ones before it.
    //
    // REDUNDANT TODAY, and kept deliberately. A sweep found that removing this line leaves
    // every test green, and that is the honest answer rather than a coverage gap: each row
    // contributes length-prefixed fields, so appending one changes the digest anyway, and
    // `verify` compares the count explicitly before it ever reaches the digest. Two
    // independent mechanisms already cover it.
    //
    // It stays because it costs one hash update and it is the guard that survives a change
    // to either of the others. A future encoding that drops the length prefixes, or a caller
    // that digests without going through `verify`, would make it load-bearing again, and by
    // then nobody would think to add it.
    hasher.update(
        u64::try_from(sorted.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for row in sorted {
        row.digest(&mut hasher);
    }
    Manifest {
        rows: rows.len(),
        digest: hasher.finalize().into(),
    }
}

/// Check `rows` against `manifest`, touching nothing.
///
/// # Errors
///
/// [`BackupError`] naming what does not match. A caller must not write any row until this
/// returns `Ok`: a partial restore leaves a database that is neither the old state nor the
/// new one.
pub fn verify(rows: &[BackedUpKek], manifest: &Manifest) -> Result<(), BackupError> {
    if rows.len() != manifest.rows {
        return Err(BackupError::RowCount {
            expected: manifest.rows,
            found: rows.len(),
        });
    }
    // A duplicate would make the row count right and the restore wrong: the second insert
    // either conflicts or overwrites, and either way one scope's KEK is missing.
    let mut ids: Vec<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    ids.sort_unstable();
    if let Some(window) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(BackupError::DuplicateRow {
            id: window[0].to_owned(),
        });
    }
    // And the collision the DATABASE enforces, which is not the one above. `tenant_keks` has
    // `UNIQUE (tenant_id, environment_id, version)`, so two rows with different ids on one
    // scope and version clear the id scan and then abort the restore partway: verification
    // promised to prevent exactly that.
    let mut scopes: Vec<(&str, &str, i32)> = rows
        .iter()
        .map(|row| {
            (
                row.tenant_id.as_str(),
                row.environment_id.as_str(),
                row.version,
            )
        })
        .collect();
    scopes.sort_unstable();
    if let Some(pair) = scopes.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(BackupError::DuplicateScopeVersion {
            tenant_id: pair[0].0.to_owned(),
            environment_id: pair[0].1.to_owned(),
            version: pair[0].2,
        });
    }
    if manifest_for(rows).digest != manifest.digest {
        return Err(BackupError::DigestMismatch);
    }
    Ok(())
}

/// Export every KEK row, refusing a connection that cannot see them all.
///
/// # The refusal is the important half
///
/// `tenant_keks` is FORCE ROW LEVEL SECURITY. On the application role, which is the role a
/// deployment's `database.url` names and the one an operator has a DSN for, a bare
/// a bare SELECT over the KEK table returns ZERO ROWS AND NO ERROR. A review pasted the runbook's
/// own SQL into three roles and measured `owner=Ok(3) app=Ok(0) control=Ok(0)`.
///
/// An empty export then passes every check that exists: the row count matches its own
/// manifest, the digest matches, and the runbook's "verify the export is not empty blobs"
/// is vacuously true because there are no blobs. The backup is discovered worthless during
/// the key loss it was taken for.
///
/// So this refuses rather than returning what it can see, the same way [`crate::rekey`] does
/// for the same reason: an empty answer from a restricted role is indistinguishable from an
/// empty database, and it is the answer that would be given most confidently on the
/// deployment with the most tenants.
///
/// # Errors
///
/// [`StoreError::Encryption`] if the connection is subject to row-level security, and
/// [`StoreError::Database`] on a read failure.
pub async fn export(pool: &sqlx::PgPool) -> Result<Vec<BackedUpKek>, crate::StoreError> {
    use sqlx::Row as _;

    let unrestricted: bool = sqlx::query(
        "SELECT rolsuper OR rolbypassrls AS unrestricted \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(pool)
    .await?
    .get("unrestricted");
    if !unrestricted {
        return Err(crate::StoreError::Encryption);
    }

    crate::repository::all_keks_for_backup(pool).await
}

/// What a restore did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RestoreReport {
    /// Rows written.
    pub restored: usize,
    /// Rows already present, byte-identical, and therefore left alone.
    ///
    /// Non-zero is the ordinary shape of a RE-RUN, which is why it is reported rather than
    /// refused: an operator whose restore died mid-incident runs it again.
    pub already_present: usize,
}

/// Why a restore refused.
///
/// Not `Clone`, `PartialEq` or `Eq`, because [`StoreError`] is none of those. A test that
/// wants to assert on a variant matches on it.
///
/// [`StoreError`]: crate::StoreError
#[derive(Debug)]
pub enum RestoreError {
    /// The backup does not match its manifest. Nothing was written.
    Backup(BackupError),
    /// A row is already present with DIFFERENT contents, so the restore stopped.
    ///
    /// Refused rather than overwritten. The row in the database may be newer than the backup
    /// (a rotation since), or it may be a crypto-shred the backup predates, and writing the
    /// backup over it would undo an erasure the deployment promised. Nothing is written.
    Conflict {
        /// The row that differs.
        id: String,
    },
    /// The database refused the write.
    Store(crate::StoreError),
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backup(error) => write!(f, "the backup does not verify: {error:?}"),
            Self::Conflict { id } => write!(
                f,
                "{id} is already present with different contents; the database has moved on \
                 since this backup and overwriting it could undo a crypto-shred"
            ),
            Self::Store(error) => write!(f, "the database refused the restore: {error:?}"),
        }
    }
}

impl std::error::Error for RestoreError {}

/// Verify `rows` against `manifest`, then write them in ONE transaction.
///
/// # Nothing, or all of it
///
/// The documented restore used to be a per-row INSERT loop with no transaction, no conflict
/// handling and no re-run guidance, which is the outcome this module's header says the design
/// exists to prevent: "a restore that writes what it can and fails partway is worse than one
/// that refuses". A review ran it against a database holding one retained row and got
/// "duplicate key value violates unique constraint `tenant_keks_pkey`; rows present = 2 of 3",
/// then a re-run that inserted 0 of 3 because the rows already written collided. The operator
/// was left with a database that was neither the old state nor the new one, and an error
/// naming a constraint rather than which tenants got in.
///
/// One transaction, so the database is the old state or the new one. And re-running is safe:
/// a row already present and BYTE-IDENTICAL is counted, not rewritten, so the second run of an
/// interrupted restore converges instead of dying on its own first half.
///
/// # Errors
///
/// [`RestoreError::Backup`] before anything is written, [`RestoreError::Conflict`] if the
/// database holds a different row under the same id, [`RestoreError::Store`] on a write
/// failure. In every case the transaction is rolled back.
pub async fn restore(
    pool: &sqlx::PgPool,
    rows: &[BackedUpKek],
    manifest: &Manifest,
) -> Result<RestoreReport, RestoreError> {
    // BEFORE ANY WRITE. The whole reason verification is a separate step.
    verify(rows, manifest).map_err(RestoreError::Backup)?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|error| RestoreError::Store(crate::StoreError::Database(error)))?;
    let mut report = RestoreReport::default();
    for row in rows {
        let existing = crate::repository::kek_identity_for_restore(&mut tx, &row.id)
            .await
            .map_err(RestoreError::Store)?;
        if let Some((master_key_id, wrapped_kek, status)) = existing {
            let same = master_key_id == row.master_key_id
                && wrapped_kek == row.wrapped_kek
                && status == row.status;
            if same {
                report.already_present += 1;
                continue;
            }
            return Err(RestoreError::Conflict { id: row.id.clone() });
        }
        crate::repository::insert_backed_up_kek(&mut tx, row)
            .await
            .map_err(RestoreError::Store)?;
        report.restored += 1;
    }
    tx.commit()
        .await
        .map_err(|error| RestoreError::Store(crate::StoreError::Database(error)))?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How one case corrupts a row.
    type Mutate = fn(&mut BackedUpKek);

    /// A row on its OWN scope.
    ///
    /// The scope used to be the same `tnt_1 / env_1 / v1` on every row, which is a shape the
    /// database forbids: `tenant_keks` has `UNIQUE (tenant_id, environment_id, version)`. The
    /// fixture was three rows that could never coexist in the table they model, and adding the
    /// scope-collision check to `verify` is what surfaced it. Giving each row its own tenant
    /// is both realistic and what makes the collision test below mean something: it has to
    /// construct the collision deliberately rather than inherit it.
    fn row(id: &str, tenant: &str) -> BackedUpKek {
        BackedUpKek {
            id: id.to_owned(),
            tenant_id: tenant.to_owned(),
            environment_id: "env_1".to_owned(),
            version: 1,
            master_key_id: "master-1".to_owned(),
            wrapped_kek: vec![1, 2, 3, 4],
            status: "active".to_owned(),
            created_at: "2026-01-01T00:00:00.000000+00".to_owned(),
            destroyed_at: None,
        }
    }

    fn backup() -> Vec<BackedUpKek> {
        vec![
            row("kek_a", "tnt_1"),
            row("kek_b", "tnt_2"),
            row("kek_c", "tnt_3"),
        ]
    }

    /// AN INTACT BACKUP VERIFIES. The floor: a check that refuses everything is not a check.
    #[test]
    fn an_intact_backup_verifies() {
        let rows = backup();
        assert_eq!(verify(&rows, &manifest_for(&rows)), Ok(()));
    }

    /// A TRUNCATED BACKUP IS REFUSED, and the count is named.
    ///
    /// The failure this exists for: a partial transfer produces rows that are each
    /// individually valid and collectively wrong, and a restore that accepts them succeeds,
    /// reports success, and leaves a subset of tenants permanently unreadable, discovered one
    /// at a time as each one signs in.
    #[test]
    fn a_truncated_backup_is_refused_with_the_count() {
        let rows = backup();
        let manifest = manifest_for(&rows);
        let short = &rows[..2];
        assert_eq!(
            verify(short, &manifest),
            Err(BackupError::RowCount {
                expected: 3,
                found: 2
            }),
            "a count mismatch means fetch the rest of the file, not a different backup"
        );
    }

    /// A TAMPERED OR CORRUPTED ROW IS REFUSED.
    #[test]
    fn a_changed_row_is_refused() {
        let rows = backup();
        let manifest = manifest_for(&rows);
        let cases: [(&str, Mutate); 6] = [
            ("the sealed material", |r| {
                r.wrapped_kek = vec![9, 9, 9, 9];
            }),
            ("the version", |r| {
                r.version = 2;
            }),
            ("the master key id", |r| {
                r.master_key_id = "master-2".to_owned();
            }),
            // `tnt_elsewhere`, NOT `tnt_2`. The row this table mutates is `rows[1]`, whose
            // tenant IS `tnt_2` since the fixture gave each row its own scope, so the old
            // value made this case a no-op: it changed nothing, the digest matched, and the
            // assertion that a changed tenant is refused was measuring an unchanged row. The
            // suite caught it because the expectation is `Err`, not because anyone noticed.
            ("the tenant", |r| {
                r.tenant_id = "tnt_elsewhere".to_owned();
            }),
            ("the environment", |r| {
                r.environment_id = "env_2".to_owned();
            }),
            ("the status", |r| {
                r.status = "destroyed".to_owned();
            }),
        ];
        for (what, mutate) in cases {
            let mut tampered = rows.clone();
            mutate(&mut tampered[1]);
            assert_eq!(
                verify(&tampered, &manifest),
                Err(BackupError::DigestMismatch),
                "changing {what} must be refused"
            );
        }
    }

    /// A ROW RE-POINTED AT ANOTHER SCOPE IS REFUSED.
    ///
    /// This is why the digest covers every field rather than the blob alone. A backup whose
    /// rows have been moved between scopes is individually valid everywhere and collectively
    /// wrong, and the wrap AAD catches it only when somebody tries to open one.
    #[test]
    fn a_row_moved_to_another_scope_is_refused() {
        let rows = backup();
        let manifest = manifest_for(&rows);
        let mut moved = rows.clone();
        moved[0].tenant_id = "tnt_other".to_owned();
        assert_eq!(verify(&moved, &manifest), Err(BackupError::DigestMismatch));
    }

    /// A DUPLICATE IS REFUSED, even though the count is right.
    ///
    /// The second insert either conflicts or overwrites, and either way one scope's KEK is
    /// missing from the restored database while the row count says everything arrived.
    #[test]
    fn a_duplicated_row_is_refused_even_with_the_right_count() {
        let rows = vec![
            row("kek_a", "tnt_1"),
            row("kek_a", "tnt_2"),
            row("kek_c", "tnt_3"),
        ];
        let manifest = Manifest {
            rows: 3,
            digest: manifest_for(&rows).digest,
        };
        assert_eq!(
            verify(&rows, &manifest),
            Err(BackupError::DuplicateRow {
                id: "kek_a".to_owned()
            }),
            "a duplicate passes a count check and still loses a tenant"
        );
    }

    /// REORDERING DOES NOT BREAK A BACKUP. The SET is what is attested, not the file layout.
    ///
    /// The counterweight: a digest sensitive to order would fail on any transfer that sorts
    /// differently, and an operator would stop trusting the check rather than the file.
    #[test]
    fn a_reordered_backup_still_verifies() {
        let rows = backup();
        let manifest = manifest_for(&rows);
        let reordered = vec![rows[2].clone(), rows[0].clone(), rows[1].clone()];
        assert_eq!(verify(&reordered, &manifest), Ok(()));
    }

    /// FIELDS CANNOT BE SHIFTED ACROSS THEIR BOUNDARY.
    ///
    /// Length-prefixing is why. Without it, a tenant of `ab` with an environment of `c`
    /// digests the same as a tenant of `a` with an environment of `bc`, so a row moved
    /// between two adjacent scopes would verify.
    #[test]
    fn a_boundary_shift_between_adjacent_fields_is_refused() {
        let mut left = row("kek_a", "tnt_1");
        left.tenant_id = "ab".to_owned();
        left.environment_id = "c".to_owned();
        let mut right = row("kek_a", "tnt_1");
        right.tenant_id = "a".to_owned();
        right.environment_id = "bc".to_owned();

        assert_ne!(
            manifest_for(&[left]).digest,
            manifest_for(&[right]).digest,
            "concatenation without length prefixes would make these identical"
        );
    }

    /// AN EMPTY BACKUP VERIFIES AGAINST AN EMPTY MANIFEST AND NOT AGAINST A FULL ONE.
    ///
    /// The degenerate case that a count check alone would pass in the dangerous direction: a
    /// restore of nothing, reported as success.
    #[test]
    fn an_empty_backup_does_not_satisfy_a_manifest_that_expects_rows() {
        let rows = backup();
        let manifest = manifest_for(&rows);
        assert_eq!(
            verify(&[], &manifest),
            Err(BackupError::RowCount {
                expected: 3,
                found: 0
            })
        );
        assert_eq!(verify(&[], &manifest_for(&[])), Ok(()));
    }

    /// A SHREDDED ROW BACKS UP AND VERIFIES. An empty blob is a valid state, not corruption.
    #[test]
    fn a_shredded_row_is_a_valid_thing_to_back_up() {
        let mut shredded = row("kek_a", "tnt_1");
        shredded.wrapped_kek = Vec::new();
        shredded.status = "destroyed".to_owned();
        let rows = vec![shredded];
        assert_eq!(verify(&rows, &manifest_for(&rows)), Ok(()));
    }
    /// A MANIFEST MUST SURVIVE LEAVING THE PROCESS.
    ///
    /// Until it did, the only call an operator could write was
    /// `verify(rows, &manifest_for(rows))`, which compares a value with itself and returns
    /// `Ok` for any deterministic digest, including one over an export that lost every row.
    #[test]
    fn a_manifest_round_trips_through_its_text_form() {
        let manifest = manifest_for(&backup());
        let line = manifest.encode();
        assert_eq!(
            Manifest::decode(&line).expect("the line this module wrote parses"),
            manifest
        );
        // And the line is the thing a human copies, so its shape is part of the contract.
        assert!(line.starts_with("rows=3 sha256="), "got {line}");
        assert_eq!(line.len(), "rows=3 sha256=".len() + 64);
    }

    /// A MANIFEST THAT DOES NOT PARSE IS REFUSED, NOT BEST-GUESSED.
    ///
    /// A manifest that parses into something other than what was written is a check that
    /// passes for the wrong reason, which is worse than no check at all.
    #[test]
    fn a_malformed_manifest_is_refused() {
        let good = manifest_for(&backup()).encode();
        for (line, what) in [
            (String::new(), "empty"),
            ("rows=3".to_owned(), "no digest"),
            (good.replace("rows=", "count="), "the wrong key"),
            (
                good.replace("sha256=", "sha512="),
                "the wrong algorithm name",
            ),
            (good[..good.len() - 1].to_owned(), "a truncated digest"),
            (format!("{good}0"), "an over-long digest"),
            (good.replace("rows=3", "rows=x"), "a non-numeric count"),
        ] {
            assert_eq!(
                Manifest::decode(&line),
                Err(ManifestParseError::Malformed),
                "{what} must be refused: {line}"
            );
        }
    }

    /// TWO ROWS ON ONE SCOPE AND VERSION ARE REFUSED, EVEN UNDER DIFFERENT IDS.
    ///
    /// The duplicate scan keyed on `id` alone, but the collision a restore actually hits is
    /// `UNIQUE (tenant_id, environment_id, version)`. A review concatenated a scope into a
    /// backup twice, which is the case this module names as its own motivation, and got
    /// `verify = Ok(())` followed by a restore that died on the unique constraint with one row
    /// of four written.
    #[test]
    fn two_rows_on_one_scope_and_version_are_refused_under_different_ids() {
        let mut rows = backup();
        let mut collision = rows[0].clone();
        collision.id = "kek_elsewhere".to_owned();
        rows.push(collision);
        let manifest = manifest_for(&rows);
        assert_eq!(
            verify(&rows, &manifest),
            Err(BackupError::DuplicateScopeVersion {
                tenant_id: "tnt_1".to_owned(),
                environment_id: "env_1".to_owned(),
                version: 1,
            }),
            "the id scan passes this and the DATABASE does not"
        );
    }
}
