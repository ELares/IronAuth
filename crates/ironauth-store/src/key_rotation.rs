// SPDX-License-Identifier: MIT OR Apache-2.0

//! The automated signing-key rotation state machine (issue #160).
//!
//! # The four states, and where they live
//!
//! The M2 JWKS discipline already defined the lifecycle columns on `signing_keys`
//! (`publish_at`, `activate_at`, `retire_at`, `expire_at`) and the serving rules
//! (published from `publish_at`, withdrawn after `expire_at`). The state machine
//! DRIVES those columns on a timer:
//!
//! - **pending** - a successor provisioned with `publish_at` in the past and
//!   `activate_at` in the future: it appears in the JWKS (pre-publication, sized to
//!   cache TTL + max token lifetime + buffer) but signs nothing yet.
//! - **current** - `activate_at` reached, `retire_at` NULL: the head, signing every
//!   new token.
//! - **retiring** - a successor was promoted and this key's `retire_at` was set at
//!   the handoff instant; it stays published until the last token it signed expires.
//! - **retired** - `expire_at` reached: withdrawn from the JWKS by the serving
//!   filter, the row kept for audit.
//!
//! # The tick
//!
//! One [`advance`](RotationStateMachine::advance) call per environment per timer
//! pass. The tick is idempotent: re-running it at the same instant does nothing new,
//! so a crashed timer simply re-takes the pass.
//!
//! 1. **Seed the successor** when the pre-publication point arrives: the current
//!    head's rotation instant (`activate_at + cadence`) minus the pre-publication
//!    window has passed and no pending successor exists. The successor is provisioned
//!    through the audited `provision` path.
//! 2. **Promote** when the pending successor's `activate_at` arrives: the outgoing
//!    head gets `retire_at = now` and `expire_at = now + max_token_lifetime + buffer`,
//!    with both audit rows in one transaction (`ActingSigningKeyRepo::promote`).
//! 3. **Withdraw** is the serving filter's act; the tick records the
//!    `signing_key.retired` audit row.

use crate::audit::Action;
use crate::repository::NewSigningKey;
use crate::repository::SigningKeyMaterialKind;
use crate::{ActingContext, ActorRef, CorrelationId, Scope, SigningKeyId, Store, StoreError};
use ironauth_env::Env;
use ironauth_jose::{generate_ecdsa_p256_pkcs8_der, generate_rsa_pkcs1_der};

/// The algorithms the rotation covers, in a FIXED generation order (reproducible under
/// a fixed test entropy source, mirroring the day-one provisioning).
const ALGORITHMS: [(&str, SigningKeyMaterialKind); 3] = [
    ("EdDSA", SigningKeyMaterialKind::Ed25519Seed),
    ("ES256", SigningKeyMaterialKind::EcdsaPkcs8),
    ("RS256", SigningKeyMaterialKind::RsaPkcs1Der),
];

/// The default cadence: about 90 days, per the issue's design.
pub const DEFAULT_CADENCE_SECS: u64 = 90 * 24 * 60 * 60;

/// The default pre-publication window: cache TTL + max token lifetime + buffer.
pub const DEFAULT_PRE_PUBLICATION_SECS: u64 = 24 * 60 * 60;

/// The default retirement buffer: how long past the last signed token's expiry a
/// retiring key stays published.
pub const DEFAULT_RETIREMENT_BUFFER_SECS: u64 = 24 * 60 * 60;

/// The rotation policy for one environment: cadence, the pre-publication window, and
/// the retirement buffer. Configurable per environment with these safe defaults (the
/// tunability principle: config with a safe default, not a baked-in choice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Seconds between a key's activation and its successor's activation.
    pub cadence_secs: u64,
    /// Seconds before the rotation instant the successor appears in the JWKS.
    pub pre_publication_secs: u64,
    /// Seconds past the last signed token's expiry a retiring key stays published.
    pub retirement_buffer_secs: u64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            cadence_secs: DEFAULT_CADENCE_SECS,
            pre_publication_secs: DEFAULT_PRE_PUBLICATION_SECS,
            retirement_buffer_secs: DEFAULT_RETIREMENT_BUFFER_SECS,
        }
    }
}

/// The result of one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationReport {
    /// The successor keys provisioned this tick (algorithm, kid).
    pub provisioned: Vec<(String, String)>,
    /// The keys promoted this tick (algorithm, kid).
    pub promoted: Vec<(String, String)>,
    /// The keys whose retirement columns were set this tick (algorithm, kid).
    pub retiring: Vec<(String, String)>,
    /// The keys whose expiry passed this tick (algorithm, kid).
    pub retired: Vec<(String, String)>,
}

/// One signing key's lifecycle view for the machine.
struct KeyLifecycle {
    id: SigningKeyId,
    algorithm: String,
    activate_at_micros: i64,
    retire_at_micros: Option<i64>,
    expire_at_micros: Option<i64>,
}

/// The remote-key verification seam (issue #161): before a REMOTE-REFERENCE
/// successor is stored, the machine asks the backend to ensure the key exists
/// (a pre-provisioned vault key named by the kid). An outage (the backend down)
/// errors, and the machine then refuses to promote - the previous current key
/// stays active, which is the issue's outage criterion.
pub trait RemoteKeyProvisioner: Send + Sync {
    /// Ensure the remote key named `kid` exists for `algorithm`.
    ///
    /// # Errors
    ///
    /// On any backend failure (a timeout, a missing key, an auth refusal); the
    /// machine treats every error the same: no successor, no promotion.
    fn ensure_remote_key(&self, kid: &str, algorithm: &str) -> Result<(), ()>;
}

/// How the machine seeds successors (issue #161).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedMode {
    /// Generate the material locally and store it (the encrypted-at-rest key
    /// store; the default).
    Local,
    /// Store a REMOTE reference (the kid names a pre-provisioned key in an
    /// external backend's boundary); the backend must confirm the key exists
    /// before the reference is stored.
    RemoteReference,
}

/// The rotation state machine for one scope.
pub struct RotationStateMachine<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
    seed_mode: SeedMode,
    provisioner: Option<&'a (dyn RemoteKeyProvisioner + Send + Sync)>,
}

impl<'a> RotationStateMachine<'a> {
    /// A machine for `scope`, acting as `actor` with `correlation`.
    #[must_use]
    pub fn new(
        store: &'a Store,
        scope: Scope,
        actor: ActorRef,
        correlation: CorrelationId,
    ) -> Self {
        Self {
            store,
            scope,
            acting: ActingContext::new(actor, correlation),
            seed_mode: SeedMode::Local,
            provisioner: None,
        }
    }

    /// Select the seeding mode (issue #161): `RemoteReference` with a
    /// [`RemoteKeyProvisioner`] for a deployment whose signing backend is
    /// external.
    #[must_use]
    pub fn with_remote_seeding(
        mut self,
        provisioner: &'a (dyn RemoteKeyProvisioner + Send + Sync),
    ) -> Self {
        self.seed_mode = SeedMode::RemoteReference;
        self.provisioner = Some(provisioner);
        self
    }

    /// One timer tick: seed successors due for pre-publication, promote due pending
    /// keys (retiring their predecessors), and record withdrawn keys.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a persistence failure; a failed tick changes nothing (each
    /// transition is one transaction) and a retry converges.
    pub async fn advance(
        &self,
        env: &Env,
        policy: RotationPolicy,
        now_micros: i64,
        max_token_lifetime_secs: u64,
    ) -> Result<RotationReport, StoreError> {
        let mut report = RotationReport {
            provisioned: Vec::new(),
            promoted: Vec::new(),
            retiring: Vec::new(),
            retired: Vec::new(),
        };
        let keys = self.store.scoped(self.scope).signing_keys().list().await?;
        let lifecycles: Vec<KeyLifecycle> = keys
            .into_iter()
            .map(|key| KeyLifecycle {
                id: key.id,
                algorithm: key.algorithm,
                activate_at_micros: key.activate_at_unix_micros,
                retire_at_micros: key.retire_at_unix_micros,
                expire_at_micros: key.expire_at_unix_micros,
            })
            .collect();

        for (algorithm, material_kind) in ALGORITHMS {
            let algo_keys: Vec<&KeyLifecycle> = lifecycles
                .iter()
                .filter(|key| key.algorithm == algorithm)
                .collect();
            let Some(head) = algo_keys
                .iter()
                .filter(|key| {
                    key.retire_at_micros.is_none() && key.activate_at_micros <= now_micros
                })
                .max_by_key(|key| key.activate_at_micros)
            else {
                // No live head for this algorithm: the environment's day-one set
                // decides which algorithms it signs with, and the machine seeds
                // nothing for an algorithm the environment does not use.
                continue;
            };
            let rotation_micros = head
                .activate_at_micros
                .saturating_add(micros(policy.cadence_secs));
            let seed_due =
                now_micros >= rotation_micros.saturating_sub(micros(policy.pre_publication_secs));
            let has_pending = algo_keys
                .iter()
                .any(|key| key.retire_at_micros.is_none() && key.activate_at_micros > now_micros);

            // 1. SEED THE SUCCESSOR when the pre-publication point is due.
            if seed_due && !has_pending {
                let key = self
                    .seed_successor(env, algorithm, material_kind, rotation_micros, policy)
                    .await?;
                report
                    .provisioned
                    .push((algorithm.to_owned(), key.to_string()));
            }

            // 2. PROMOTE: when a key's activation instant arrived, it IS the head by the
            //    derived definition (activate_at <= now, retire NULL). The transition
            //    that remains is retiring the PREVIOUS head (the newest other key still
            //    without retirement) in the same transaction as the two audit rows.
            let outgoing = algo_keys
                .iter()
                .filter(|key| key.retire_at_micros.is_none() && key.id != head.id)
                .max_by_key(|key| key.activate_at_micros);
            if let Some(outgoing) = outgoing {
                if outgoing.activate_at_micros < head.activate_at_micros {
                    let expire_micros = now_micros
                        .saturating_add(micros(max_token_lifetime_secs))
                        .saturating_add(micros(policy.retirement_buffer_secs));
                    self.store
                        .scoped(self.scope)
                        .acting(self.acting.actor(), self.acting.correlation())
                        .signing_keys()
                        .promote(env, &head.id, &outgoing.id, now_micros, expire_micros)
                        .await?;
                    report
                        .promoted
                        .push((algorithm.to_owned(), head.id.to_string()));
                    report
                        .retiring
                        .push((algorithm.to_owned(), outgoing.id.to_string()));
                }
            }

            // 3. WITHDRAW: the serving filter handles the JWKS side; record the keys
            //    whose expiry passed - idempotently, so a re-taken pass (a crashed
            //    timer) does not re-audit a withdrawal that already happened.
            for key in algo_keys.iter().filter(|key| {
                key.expire_at_micros
                    .is_some_and(|expire| expire <= now_micros)
            }) {
                let wrote = self
                    .store
                    .scoped(self.scope)
                    .acting(self.acting.actor(), self.acting.correlation())
                    .signing_keys()
                    .mark_withdrawn(env, &key.id)
                    .await?;
                if wrote {
                    report
                        .retired
                        .push((algorithm.to_owned(), key.id.to_string()));
                }
            }
        }
        Ok(report)
    }

    /// Provision a pending successor: published `pre_publication` before the rotation
    /// instant, active at the rotation instant. The material is minted off the entropy
    /// seam, the same generation the day-one set uses. Audited (`signing_key.provision`)
    /// in the same transaction.
    async fn seed_successor(
        &self,
        env: &Env,
        algorithm: &str,
        material_kind: SigningKeyMaterialKind,
        rotation_micros: i64,
        policy: RotationPolicy,
    ) -> Result<SigningKeyId, StoreError> {
        let id = SigningKeyId::generate(env, &self.scope);
        let (material_kind, material): (SigningKeyMaterialKind, Vec<u8>) = match self.seed_mode {
            // A remote deployment: the kid names a pre-provisioned key in the
            // backend's boundary. The provisioner MUST confirm it exists first -
            // an outage (the backend down) errors, and the machine then refuses to
            // promote, leaving the previous current key active (issue #161's
            // outage criterion).
            SeedMode::RemoteReference => {
                let Some(provisioner) = self.provisioner else {
                    return Err(StoreError::Invalid);
                };
                provisioner
                    .ensure_remote_key(&id.to_string(), algorithm)
                    .map_err(|()| StoreError::Invalid)?;
                (
                    SigningKeyMaterialKind::RemoteReference,
                    id.to_string().into_bytes(),
                )
            }
            SeedMode::Local => {
                let material: Vec<u8> = match material_kind {
                    SigningKeyMaterialKind::Ed25519Seed => {
                        let mut seed = [0_u8; 32];
                        env.entropy().fill_bytes(&mut seed);
                        seed.to_vec()
                    }
                    SigningKeyMaterialKind::EcdsaPkcs8 => {
                        generate_ecdsa_p256_pkcs8_der(env.entropy())
                            .map_err(|_| StoreError::Encryption)?
                    }
                    SigningKeyMaterialKind::RsaPkcs1Der => {
                        generate_rsa_pkcs1_der(env.entropy()).map_err(|_| StoreError::Encryption)?
                    }
                    SigningKeyMaterialKind::RemoteReference => {
                        return Err(StoreError::Invalid);
                    }
                };
                (material_kind, material)
            }
        };
        let key = NewSigningKey {
            id: &id,
            algorithm,
            material_kind,
            material: &material,
            publish_at_micros: rotation_micros.saturating_sub(micros(policy.pre_publication_secs)),
            activate_at_micros: rotation_micros,
            retire_at_micros: None,
            expire_at_micros: None,
        };
        self.store
            .scoped(self.scope)
            .acting(self.acting.actor(), self.acting.correlation())
            .signing_keys()
            .provision(env, key)
            .await?;
        Ok(id)
    }

    /// THE BREAK-GLASS OPERATION (issue #160): for every algorithm the environment
    /// signs with, mint a FRESH successor and rotate to it immediately, withdrawing the
    /// current key NOW (no pre-publication, no retirement window - the verification
    /// breakage that entails is the documented price of a compromise). Refuses without
    /// `confirmed`, and the invocation is audited with the acting actor.
    ///
    /// # Errors
    ///
    /// [`StoreError::Invalid`] if `confirmed` is false; [`StoreError`] otherwise if a
    /// transition fails (each rotation is one transaction, so a failure rolls back).
    pub async fn break_glass(
        &self,
        env: &Env,
        now_micros: i64,
        confirmed: bool,
    ) -> Result<RotationReport, StoreError> {
        // The confirmation check comes FIRST: a refused invocation must leave no trace
        // (no successor provisioned, nothing audited).
        if !confirmed {
            return Err(StoreError::Invalid);
        }
        let mut report = RotationReport {
            provisioned: Vec::new(),
            promoted: Vec::new(),
            retiring: Vec::new(),
            retired: Vec::new(),
        };
        let keys = self.store.scoped(self.scope).signing_keys().list().await?;
        for (algorithm, material_kind) in ALGORITHMS {
            let Some(head) = keys
                .iter()
                .filter(|key| {
                    key.algorithm == algorithm
                        && key.retire_at_unix_micros.is_none()
                        && key.activate_at_unix_micros <= now_micros
                })
                .max_by_key(|key| key.activate_at_unix_micros)
            else {
                continue;
            };
            let successor_id = self
                .seed_successor(
                    env,
                    algorithm,
                    material_kind,
                    now_micros,
                    RotationPolicy {
                        cadence_secs: 0,
                        pre_publication_secs: 0,
                        retirement_buffer_secs: 0,
                    },
                )
                .await?;
            self.store
                .scoped(self.scope)
                .acting(self.acting.actor(), self.acting.correlation())
                .signing_keys()
                .break_glass(env, &successor_id, &head.id, now_micros, confirmed)
                .await?;
            report
                .provisioned
                .push((algorithm.to_owned(), successor_id.to_string()));
            report
                .promoted
                .push((algorithm.to_owned(), successor_id.to_string()));
            report
                .retired
                .push((algorithm.to_owned(), head.id.to_string()));
        }
        Ok(report)
    }
}

/// One signing key's ADMIN-SURFACE view (issue #160): the derived state and the
/// instants that matter to an operator, including the next scheduled rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationKeyView {
    /// The JOSE kid.
    pub kid: String,
    /// The JOSE algorithm.
    pub algorithm: String,
    /// The derived state.
    pub state: KeyState,
    /// The pre-publication instant, epoch microseconds.
    pub publish_at_unix_micros: i64,
    /// The activation instant, epoch microseconds.
    pub activate_at_unix_micros: i64,
    /// The handoff instant, when this key is no longer the head (absent while head).
    pub retire_at_unix_micros: Option<i64>,
    /// The expiry instant, when the JWKS withdraws it (absent while published).
    pub expire_at_unix_micros: Option<i64>,
    /// The next rotation instant for the key that is the head: its activation plus the
    /// cadence. The successor is seeded a pre-publication window before it.
    pub next_rotation_at_unix_micros: Option<i64>,
}

/// The four derived states of the rotation machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Published, not yet signing.
    Pending,
    /// Signing every new token.
    Current,
    /// A successor took over; still published until its last token expires.
    Retiring,
    /// Expired and withdrawn from the JWKS; kept for audit.
    Retired,
}

/// The admin-surface projection of the machine: every key's derived state and the
/// next scheduled rotation for the current head, under `policy` at `now_micros`.
#[must_use]
pub fn rotation_key_views(
    records: &[crate::SigningKeyRecord],
    policy: RotationPolicy,
    now_micros: i64,
) -> Vec<RotationKeyView> {
    records
        .iter()
        .map(|key| {
            let state = if key
                .expire_at_unix_micros
                .is_some_and(|expire| expire <= now_micros)
            {
                KeyState::Retired
            } else if key.retire_at_unix_micros.is_some() {
                KeyState::Retiring
            } else if key.activate_at_unix_micros > now_micros {
                KeyState::Pending
            } else {
                KeyState::Current
            };
            RotationKeyView {
                kid: key.id.to_string(),
                algorithm: key.algorithm.clone(),
                state,
                publish_at_unix_micros: key.publish_at_unix_micros,
                activate_at_unix_micros: key.activate_at_unix_micros,
                retire_at_unix_micros: key.retire_at_unix_micros,
                expire_at_unix_micros: key.expire_at_unix_micros,
                next_rotation_at_unix_micros: if state == KeyState::Current {
                    Some(
                        key.activate_at_unix_micros
                            .saturating_add(micros(policy.cadence_secs)),
                    )
                } else {
                    None
                },
            }
        })
        .collect()
}

/// Seconds to microseconds, saturating.
fn micros(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(1_000_000)).unwrap_or(i64::MAX)
}

/// The audit actions the machine emits, exported for the contract gate's scan.
pub const ACTIONS: &[Action] = &[
    Action::SigningKeyProvision,
    Action::SigningKeyPromoted,
    Action::SigningKeyRetiring,
    Action::SigningKeyRetired,
];
