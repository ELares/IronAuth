// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rewrapping every tenant KEK under a new platform master key (issue #153).
//!
//! # What a rekey is, and why it is this small
//!
//! Envelope encryption puts a per-tenant KEK between the platform master key and the
//! per-record DEKs. Rotating the master therefore does NOT touch any encrypted column: it
//! rewraps each KEK, and every DEK underneath stays exactly as it is. A deployment with
//! millions of sealed rows and a few hundred tenants rewraps a few hundred small blobs.
//!
//! One row's rewrap is three steps:
//!
//! 1. unwrap `wrapped_kek` with the OLD master, under the AAD naming the old master's id;
//! 2. wrap the same KEK with the NEW master, under the AAD naming the new master's id;
//! 3. write back `wrapped_kek` and `master_key_id` together.
//!
//! The AAD binds the master key id (see `kek_wrap_aad`), which is what makes step 2 a
//! different ciphertext rather than a re-encoding, and what makes a KEK wrapped under one
//! master refuse to open under another.
//!
//! # Resumability is the predicate, not machinery
//!
//! Rows are selected by `master_key_id = <old>`. A row this run has already rewrapped no
//! longer matches, so an interrupted run resumes by being run again: no cursor, no progress
//! table, no lease, and no way for a crash to leave a row half-written (each row commits in
//! its own transaction). Running it twice is a no-op the second time.
//!
//! That also means the operation is defined by where it is GOING, not by how far it got,
//! which is the property that makes "interrupted rekey resumes cleanly and converges"
//! (criterion 3) true by construction rather than by test.
//!
//! # Why this runs as the schema owner
//!
//! `tenant_keks` is FORCE ROW LEVEL SECURITY and its column grants cover
//! `(wrapped_kek, status, destroyed_at)` for the data and control roles -- deliberately NOT
//! `master_key_id`, which only a rekey writes. Rather than widen a grant so a least-privilege
//! role can rotate platform key material, this is an operator-plane tool that connects as the
//! role migrations run as, exactly like `ironauth doctor` and `ironauth migrate`. A superuser
//! bypasses row-level security and column privileges, so it sees every tenant's row and can
//! write the column, and no migration is needed to permit it.
//!
//! [`Rekey::run`] refuses to proceed on a connection that row-level security applies to,
//! because on such a connection the scan returns zero rows for every tenant and "nothing to
//! do" is indistinguishable from "done".
//!
//! # What this does NOT do
//!
//! # Running it online, which needs the server to hold both generations
//!
//! This used to say a server "holds ONE master key, so between the first rewrapped row and the
//! last, a live process cannot open both shapes", and that online rekey needed a master key RING
//! on the read path first. The ring exists now: `MasterKey::with_previous` carries superseded
//! generations, `database.previous_master_keys` configures them, and both unwrap sites pick the
//! key for the generation each ROW records.
//!
//! So the KEK half of a rotation can now be served:
//!
//! 1. Set `master_key` to the incoming secret and `master_key_id` to its new name, and list the
//!    OUTGOING generation under `previous_master_keys`. Restart. Every node can now open both
//!    shapes and writes new work under the incoming master.
//! 2. Run this. Rows move one at a time and either shape is readable throughout.
//! 3. Once it reports nothing remaining, drop the `previous_master_keys` entry and restart.
//!
//! STEP 1 BEFORE STEP 2, AND STEP 3 STRICTLY AFTER. Running this before the nodes carry the ring
//! strands every row it has already moved; dropping the predecessor before the run converges
//! strands every row it has not.
//!
//! # THE BLIND INDEXES DO NOT SURVIVE A CHANGE OF SECRET, and this does not fix them
//!
//! That sequence keeps ENVELOPE reads working. It does not keep LOOKUPS working, and an operator
//! reading only the steps above would find that out from their users.
//!
//! Every blind index in the store is `master.blind_index(context)`, derived from the master's
//! material directly rather than through a KEK: the user identifier, the external id, the
//! recovery code, the invitation identifier, the risk-signal subject, the abuse subject, the
//! trait login, the routing identifier. This module rewraps `tenant_keks` and touches none of
//! them, so after a rotation to a DIFFERENT SECRET every stored index was computed under a key
//! nothing derives any more, and a login by identifier stops finding the user it should.
//!
//! Verified rather than reasoned: two masters derived from different secrets produce different
//! indexes for the same context, and two derived from the SAME secret produce the same one
//! whatever ids they carry, because `derive` keys off the secret alone.
//!
//! So a rotation is safe today in exactly one shape: CHANGING THE ID while keeping the secret,
//! which moves rows to a new generation name and leaves every index intact. Changing the secret
//! needs the indexes rebuilt, which means reading each sealed identifier and recomputing its
//! index under the new master. That is not a rewrap and this module does not do it.
//!
//! The ring is still the right foundation for the eventual fix: a rebuild has to run while both
//! generations are readable, which is what it provides.
//!
//! Also not covered: a test driving the sequence against a live server under load, which is what
//! criterion 2 asks for. The ring's own behaviour is tested (a mixed database served by one key
//! value, new work never written under a predecessor, a missing generation failing closed).

use ironauth_env::Entropy;
use ironauth_jose::{Kek, MasterKey, Sealed};
use sqlx::{PgPool, Row};

use crate::error::StoreError;
use crate::id::{EnvironmentId, TenantId};
use crate::scope::Scope;

/// What one rekey run did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RekeyReport {
    /// KEKs rewrapped by this run.
    pub rewrapped: usize,
    /// KEKs already under the target master when this run started. Non-zero on a resumed
    /// run, and equal to the total on a second run of a completed rekey.
    pub already_current: usize,
    /// Rows left under the old master because they are destroyed. A crypto-shredded KEK's
    /// `wrapped_kek` is an empty blob that no master can open, and rewrapping is meaningless
    /// for a key whose whole point is to be unrecoverable.
    pub skipped_destroyed: usize,
    /// Rows that CHANGED between being read and being written, so the guarded write matched
    /// nothing and left them alone.
    ///
    /// Almost always a concurrent crypto-shred, which is exactly the row a rotation must not
    /// touch: writing back the bytes read before the shred would restore recoverable key
    /// material for a tenant being erased. Counted rather than retried, because the right
    /// response is for a human to look.
    pub contended: usize,
    /// Live KEKs NOT on the target master when the run finished, counted AFTER the loop.
    ///
    /// Non-zero means the rotation is incomplete: KEKs are provisioned lazily under whichever
    /// master the inserting process holds, so a server still running during the rotation can
    /// add rows the work set never saw. Re-running converges.
    ///
    /// Counted against the TARGET rather than the source (it was `remaining_under_old`, keyed
    /// on `from`). Keyed on the source it could not see a row parked on a THIRD master, which
    /// is what a retargeted rotation leaves: `old -> mid` stops part way, then `old -> new`
    /// runs, and the rows on `mid` are outside both the work set and the count. The run said
    /// it had converged, the operator destroyed `old`, and those tenants went dark. Keyed on
    /// the target, a stray anywhere is still a stray.
    pub remaining_off_target: usize,
}

/// Rewrap every live tenant KEK from one platform master key to another.
pub struct Rekey<'a> {
    pool: &'a PgPool,
    from: &'a MasterKey,
    to: &'a MasterKey,
    entropy: &'a dyn Entropy,
    /// A hook run ONCE, after the work set is read and before the first row is written.
    ///
    /// The compare-and-swap on the write exists for exactly one ordering: a row changes
    /// between the snapshot and the write-back. Nothing could produce that ordering from
    /// outside, because the snapshot is taken inside `run`, so the guard's own test
    /// committed its shred BEFORE the call and was refused by the status check on the READ
    /// instead, never reaching the write at all. A review traced the execution and found the
    /// guard unreached; the test's doc claimed the opposite.
    ///
    /// `testing` only, so no production build can carry a seam into the middle of a
    /// key-rotation write loop.
    #[cfg(feature = "testing")]
    after_snapshot: Option<Box<dyn Fn() -> BoxFuture<'a, ()> + 'a>>,
}

/// A boxed future, so the `testing` hook can be an async closure without a generic parameter
/// leaking into [`Rekey`]'s public shape.
#[cfg(feature = "testing")]
type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl<'a> Rekey<'a> {
    /// Build a rekey from the old master to the new one.
    ///
    /// Entropy is supplied rather than taken from the environment so a test can drive the
    /// same nonces twice and compare ciphertexts.
    #[must_use]
    pub fn new(
        pool: &'a PgPool,
        from: &'a MasterKey,
        to: &'a MasterKey,
        entropy: &'a dyn Entropy,
    ) -> Self {
        Self {
            pool,
            from,
            to,
            entropy,
            #[cfg(feature = "testing")]
            after_snapshot: None,
        }
    }

    /// Run `hook` once, after the work set is read and before the first row is written.
    ///
    /// The seam the compare-and-swap on the write needs in order to be testable at all: see
    /// [`Rekey::after_snapshot`]. `testing` only.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn with_after_snapshot(mut self, hook: impl Fn() -> BoxFuture<'a, ()> + 'a) -> Self {
        self.after_snapshot = Some(Box::new(hook));
        self
    }

    /// Rewrap every live KEK, committing each row on its own.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if a KEK does not open under the old master, which means
    /// the wrong key was supplied and the run stops rather than continuing past a row it
    /// could not read. [`StoreError::Database`] on any database failure.
    pub async fn run(&self) -> Result<RekeyReport, StoreError> {
        if self.from.id() == self.to.id() {
            return Err(StoreError::Encryption);
        }
        // REFUSE A CONNECTION ROW-LEVEL SECURITY APPLIES TO.
        //
        // tenant_keks is FORCE ROW LEVEL SECURITY, so on a restricted role the scan below
        // returns zero rows for every tenant and the run reports a tidy "nothing to do".
        // That is indistinguishable from a completed rekey, and it is the answer that would
        // be given most confidently on the deployment with the most tenants.
        if !self.sees_every_row().await? {
            return Err(StoreError::Encryption);
        }
        let mut report = RekeyReport::default();

        // Every live row still under the old master. The statement itself lives in the
        // repository module, where the query audit requires SQL against a scoped table to
        // live; see `keks_under_master` for why an unscoped read is the right shape here.
        let rows = crate::repository::keks_under_master(self.pool, self.from.id()).await?;

        report.already_current =
            crate::repository::count_keks_under_master(self.pool, self.to.id()).await?;

        // The work set is read; the writes have not started. This is the only point at which
        // a test can produce the ordering the write guard exists for.
        #[cfg(feature = "testing")]
        if let Some(hook) = self.after_snapshot.as_ref() {
            hook().await;
        }

        for row in &rows {
            if row.status == "destroyed" {
                report.skipped_destroyed += 1;
                continue;
            }
            let scope = parse_scope(&row.tenant_id, &row.environment_id)?;
            let kek = self.unwrap_under_old(scope, row.version, row.wrapped_kek.clone())?;
            let resealed = self.to.wrap_kek(
                self.entropy,
                &crate::repository::kek_wrap_aad(scope, row.version, self.to.id()),
                &kek,
            );
            // Guarded on the bytes and the master this row was READ with, and refusing a
            // destroyed row outright. The status above is the SNAPSHOT's, and a shred that
            // landed since would not be seen there; the predicate is what actually protects
            // the erasure.
            let written = crate::repository::store_rewrapped_kek(
                self.pool,
                &row.id,
                &row.wrapped_kek,
                self.from.id(),
                // The SNAPSHOT'S status, not the literal "active". Binding "active" refused
                // every `'retired'` row, which is what `rotate_kek` leaves beside the version
                // that replaced it, so such a row was counted as contention on every run and
                // the rotation never converged.
                &row.status,
                resealed.as_bytes(),
                self.to.id(),
            )
            .await?;
            if written {
                report.rewrapped += 1;
            } else {
                report.contended += 1;
            }
        }

        // The closing check the snapshot cannot give. Counted after the loop, so it sees rows
        // that appeared during it, and keyed on the TARGET so it also sees rows that are on
        // neither master (a retargeted rotation leaves them on the one in between).
        report.remaining_off_target =
            crate::repository::count_live_keks_off_master(self.pool, self.to.id()).await?;
        Ok(report)
    }

    fn unwrap_under_old(
        &self,
        scope: Scope,
        version: i32,
        wrapped: Vec<u8>,
    ) -> Result<Kek, StoreError> {
        let aad = crate::repository::kek_wrap_aad(scope, version, self.from.id());
        Ok(self.from.unwrap_kek(&aad, &Sealed::from_bytes(wrapped)?)?)
    }

    /// Whether the connected role sees past row-level security.
    ///
    /// The same question `ironauth doctor` asks, for the same reason: a restricted role
    /// makes every scan return nothing, and nothing looks like success.
    async fn sees_every_row(&self) -> Result<bool, StoreError> {
        let row = sqlx::query(
            "SELECT rolsuper OR rolbypassrls AS unrestricted \
             FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(self.pool)
        .await?;
        Ok(row.get::<bool, _>("unrestricted"))
    }
}

/// The AAD binds the scope, so a row whose ids do not parse cannot be rewrapped into a form
/// anything could open. Refused rather than guessed.
fn parse_scope(tenant: &str, environment: &str) -> Result<Scope, StoreError> {
    let tenant = TenantId::parse(tenant).map_err(|_| StoreError::Encryption)?;
    let environment = EnvironmentId::parse(environment).map_err(|_| StoreError::Encryption)?;
    Ok(Scope::new(tenant, environment))
}
