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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub wrapped_kek: Vec<u8>,
    /// The row's status.
    pub status: String,
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
    }
}

/// What a backup claims about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// How many rows the backup should contain.
    pub rows: usize,
    /// A digest over every row, in a fixed order.
    pub digest: [u8; 32],
}

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
    if manifest_for(rows).digest != manifest.digest {
        return Err(BackupError::DigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How one case corrupts a row.
    type Mutate = fn(&mut BackedUpKek);

    fn row(id: &str) -> BackedUpKek {
        BackedUpKek {
            id: id.to_owned(),
            tenant_id: "tnt_1".to_owned(),
            environment_id: "env_1".to_owned(),
            version: 1,
            master_key_id: "master-1".to_owned(),
            wrapped_kek: vec![1, 2, 3, 4],
            status: "active".to_owned(),
        }
    }

    fn backup() -> Vec<BackedUpKek> {
        vec![row("kek_a"), row("kek_b"), row("kek_c")]
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
            ("the tenant", |r| {
                r.tenant_id = "tnt_2".to_owned();
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
        let rows = vec![row("kek_a"), row("kek_a"), row("kek_c")];
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
        let mut left = row("kek_a");
        left.tenant_id = "ab".to_owned();
        left.environment_id = "c".to_owned();
        let mut right = row("kek_a");
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
        let mut shredded = row("kek_a");
        shredded.wrapped_kek = Vec::new();
        shredded.status = "destroyed".to_owned();
        let rows = vec![shredded];
        assert_eq!(verify(&rows, &manifest_for(&rows)), Ok(()));
    }
}
