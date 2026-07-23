// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operator-invokable backfill of the day-one signing algorithms (issue #93).
//!
//! Issue #93 makes every NEW environment provision all three JWKS signing
//! algorithms (`EdDSA` + `ES256` + `RS256`) at creation. Environments created
//! BEFORE that change carry only their `EdDSA` day-one key, so the compatibility
//! wizard's `ES256`/`RS256` recommendations would be unsignable there. No SQL
//! migration can generate key material, so this is a control-plane routine: it
//! iterates every `(tenant, environment)` scope (the same scope-enumeration the
//! back-channel logout worker uses, issue #34) and provisions ONLY the missing of
//! `{ES256, RS256}` into each, reusing the audited, RLS-scoped signing-key provision
//! path.
//!
//! It is IDEMPOTENT: it reads each scope's existing keys and provisions an
//! algorithm only when absent, so a second sequential run is a no-op. There is
//! deliberately no `unique(environment, algorithm)` constraint, because key rotation
//! keeps two non-retired keys of the same algorithm during its prepublish overlap;
//! correctness of the no-op comes from the presence check, so the routine is a single
//! non-concurrent job. Two concurrent runs against the same scope (for example a
//! fleet where every replica enables the on-start flag at once) can each observe an
//! algorithm absent and both insert it, yielding a duplicate key. Such a duplicate is
//! HARMLESS (both are the environment's own keys off its own entropy and both publish
//! in the JWKS); to avoid it, run the backfill from a single replica (see the
//! `backfill_signing_algorithms_on_start` config doc). Key material is generated off
//! the entropy seam exactly as the day-one provisioning path does, and is loaded and
//! signed only through `ring`.
//!
//! ORDERING against the issuer cache (issue #204): the in-process issuer registry
//! keyset cache does NOT invalidate, so a long-lived server that already cached an
//! environment as `EdDSA`-only keeps serving `EdDSA`-only until it restarts. Run
//! this routine AT OR BEFORE a deploy rollout, so the fresh server processes load
//! all three algorithms on their first `entry_for` for each scope.

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::{
    ActorRef, CorrelationId, NewSigningKey, Scope, ServiceId, SigningKeyId, SigningKeyMaterialKind,
    Store, StoreError,
};

/// The JOSE algorithm names the backfill ensures are present, paired with the
/// keygen that produces each one's material. `EdDSA` is deliberately absent: it is
/// the one algorithm every legacy environment already has.
const BACKFILLED_ALGORITHMS: [&str; 2] = ["ES256", "RS256"];

/// The outcome of one backfill run over every environment scope.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BackfillReport {
    /// How many environment scopes were scanned.
    pub scopes_scanned: usize,
    /// How many signing keys were newly provisioned (0 on a fully idempotent rerun).
    pub keys_provisioned: usize,
    /// How many scopes failed and were skipped (the run continues past a failure so
    /// one bad scope does not strand the rest of the fleet).
    pub scopes_failed: usize,
}

/// Why the backfill could not proceed for a scope.
#[derive(Debug)]
pub enum BackfillError {
    /// A persistence read or write failed.
    Store(StoreError),
    /// Fresh `ES256`/`RS256` key generation failed (it does not in practice).
    KeyGeneration,
}

impl std::fmt::Display for BackfillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackfillError::Store(error) => write!(f, "backfill store error: {error}"),
            BackfillError::KeyGeneration => f.write_str("backfill key generation failed"),
        }
    }
}

impl std::error::Error for BackfillError {}

impl From<StoreError> for BackfillError {
    fn from(error: StoreError) -> Self {
        BackfillError::Store(error)
    }
}

/// Provision every missing day-one signing algorithm (`ES256`, `RS256`) into every
/// environment (issue #93), idempotently.
///
/// `control_store` enumerates the `(tenant, environment)` scopes (it reads the
/// non-RLS `environments` table, so it MUST be the control-plane role). `data_store`
/// reads each scope's existing keys and provisions the missing ones under forced
/// row-level security (the data-plane role, which holds the scoped INSERT grant on
/// `signing_keys`). In a single-role dev deployment the two may be the same handle.
///
/// A per-scope failure is logged and counted, and the run continues; the returned
/// [`BackfillReport`] tallies what happened. The routine is safe to run more than
/// once (a rerun provisions nothing), but must not be run CONCURRENTLY with itself
/// against the same scope.
///
/// # Errors
///
/// [`StoreError`] only if enumerating the scopes fails; per-scope failures are
/// absorbed into `scopes_failed` rather than aborting the whole run.
pub async fn backfill_signing_algorithms(
    env: &Env,
    control_store: &Store,
    data_store: &Store,
) -> Result<BackfillReport, StoreError> {
    let scopes = control_store.management().list_environment_scopes().await?;
    let mut report = BackfillReport::default();
    for scope in scopes {
        report.scopes_scanned += 1;
        match backfill_scope(env, data_store, scope).await {
            Ok(provisioned) => report.keys_provisioned += provisioned,
            Err(error) => {
                report.scopes_failed += 1;
                tracing::warn!(
                    %error,
                    tenant = %scope.tenant(),
                    environment = %scope.environment(),
                    "signing-algorithm backfill failed for a scope; continuing"
                );
            }
        }
    }
    Ok(report)
}

/// Backfill one scope: provision whichever of `{ES256, RS256}` it does not already
/// have. Returns how many keys were newly provisioned (0, 1, or 2).
async fn backfill_scope(
    env: &Env,
    data_store: &Store,
    scope: Scope,
) -> Result<usize, BackfillError> {
    let existing = data_store.scoped(scope).signing_keys().list().await?;
    let activate_at_micros = now_unix_micros(env);
    let mut provisioned = 0;
    for algorithm in BACKFILLED_ALGORITHMS {
        // Presence check FIRST: idempotent, so a rerun (or a scope that a newer
        // env-create already gave all three) provisions nothing.
        if existing.iter().any(|key| key.algorithm == algorithm) {
            continue;
        }
        let (material_kind, material) = generate_material(env, algorithm)?;
        provision_one(
            env,
            data_store,
            scope,
            algorithm,
            material_kind,
            &material,
            activate_at_micros,
        )
        .await?;
        provisioned += 1;
    }
    Ok(provisioned)
}

/// Generate fresh private material for one backfilled algorithm, off the entropy
/// seam. Signing stays on `ring`: this only produces the DER the `ring` loader reads.
fn generate_material(
    env: &Env,
    algorithm: &str,
) -> Result<(SigningKeyMaterialKind, Vec<u8>), BackfillError> {
    match algorithm {
        "ES256" => {
            let der = ironauth_jose::generate_ecdsa_p256_pkcs8_der(env.entropy())
                .map_err(|_| BackfillError::KeyGeneration)?;
            Ok((SigningKeyMaterialKind::EcdsaPkcs8, der))
        }
        "RS256" => {
            let der = ironauth_jose::generate_rsa_pkcs1_der(env.entropy())
                .map_err(|_| BackfillError::KeyGeneration)?;
            Ok((SigningKeyMaterialKind::RsaPkcs1Der, der))
        }
        // Unreachable: BACKFILLED_ALGORITHMS is the only caller and lists exactly
        // these two. Fail closed rather than provision an unknown algorithm.
        _ => Err(BackfillError::KeyGeneration),
    }
}

/// Provision one signing key into `scope` through the SAME audited, RLS-scoped
/// provision path the manual and day-one flows use, live from `activate_at_micros`.
async fn provision_one(
    env: &Env,
    data_store: &Store,
    scope: Scope,
    algorithm: &str,
    material_kind: SigningKeyMaterialKind,
    material: &[u8],
    activate_at_micros: i64,
) -> Result<(), BackfillError> {
    let id = SigningKeyId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    let correlation = CorrelationId::generate(env);
    data_store
        .scoped(scope)
        .acting(actor, correlation)
        .signing_keys()
        .provision(
            env,
            NewSigningKey {
                id: &id,
                algorithm,
                material_kind,
                material,
                publish_at_micros: activate_at_micros,
                activate_at_micros,
                retire_at_micros: None,
                expire_at_micros: None,
            },
        )
        .await?;
    Ok(())
}

/// The current wall-clock instant as epoch microseconds, read through the time
/// seam (never a raw clock), so a backfilled key's lifecycle instants are
/// deterministic under a manual clock in tests.
fn now_unix_micros(env: &Env) -> i64 {
    let micros = env
        .clock()
        .now_utc()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros());
    i64::try_from(micros).unwrap_or(i64::MAX)
}
