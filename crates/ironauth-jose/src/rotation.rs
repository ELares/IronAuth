// SPDX-License-Identifier: MIT OR Apache-2.0

//! JWKS serving discipline: pre-publication, active-signer selection, and
//! retired-key retention.
//!
//! Getting key rotation wrong is where OSS providers silently break relying
//! parties. Two failure modes matter:
//!
//! - Publishing a new key only when it starts signing. A relying party that
//!   cached the JWKS a moment earlier has never seen the new `kid`, so every
//!   token minted with it fails to verify until the cache expires.
//! - Withdrawing a retired key the instant it stops signing. Tokens it already
//!   signed are still in flight and still valid; a relying party that refetches
//!   the JWKS now cannot find their key and rejects live tokens.
//!
//! A [`KeySet`] models each key's lifecycle as four instants and answers two
//! questions deterministically against a caller-supplied clock reading: which
//! key signs now ([`KeySet::active_signer`]), and which keys are published now
//! ([`KeySet::published_jwks`]). The timing is governed by [`RotationParams`]:
//!
//! - **Pre-publish lead**: a key is published at least
//!   `cache_ttl + max_token_lifetime + prepublish_buffer` before it first signs,
//!   so it is in every relying party's cache before its first token appears.
//! - **Retention**: a retired key stays published for `max_token_lifetime` after
//!   it stops signing, which is the longest any token it signed can still be
//!   valid, so no in-flight token is ever orphaned from its key.
//!
//! This module ships the choreography PRIMITIVES only (a [`KeySet::rotate`]
//! command plus these publish/retain rules). A timer-driven rotation state
//! machine and break-glass are a later milestone; nothing here reads a clock of
//! its own (the caller passes `now` from the [`ironauth_env`] clock seam), so the
//! whole choreography is deterministic under a manual clock in tests.

use std::time::{Duration, SystemTime};

use crate::jwks::JwkSet;
use crate::policy::JwsAlgorithm;
use crate::signing_key::{SigningKey, SigningKeyError};
use crate::signing_policy::SigningPolicy;

/// The timing parameters that govern pre-publication and retention.
///
/// All three are environment-dependent knobs with safe defaults (the tunability
/// principle): they can be tightened for a known deployment, but the pre-publish
/// and retain rules derived from them are not optional.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationParams {
    /// The `max-age` a relying party may cache the JWKS for. A new key must be
    /// published at least this long before first use so a just-refreshed cache
    /// still learns it in time.
    pub cache_ttl: Duration,
    /// The longest lifetime any token this issuer mints can have. Bounds how long
    /// a retired key's tokens can still be in flight, and therefore how long the
    /// key must be retained after it stops signing.
    pub max_token_lifetime: Duration,
    /// Extra head-room added to the pre-publish lead beyond `cache_ttl +
    /// max_token_lifetime`, to absorb clock skew and propagation delay.
    pub prepublish_buffer: Duration,
}

impl RotationParams {
    /// The minimum time a key must be published before it first signs:
    /// `cache_ttl + max_token_lifetime + prepublish_buffer`.
    #[must_use]
    pub fn prepublish_lead(&self) -> Duration {
        self.cache_ttl
            .saturating_add(self.max_token_lifetime)
            .saturating_add(self.prepublish_buffer)
    }

    /// How long a retired key stays published after it stops signing: exactly
    /// `max_token_lifetime`, the longest any token it signed can still be valid.
    #[must_use]
    pub fn retention_after_retire(&self) -> Duration {
        self.max_token_lifetime
    }
}

/// The lifecycle instants of one signing key.
///
/// `retire_at` and `expire_at` are `None` while the key is the current head (it
/// has no scheduled successor yet); [`KeySet::rotate`] fills them in when a
/// successor is scheduled.
// Every field is a lifecycle INSTANT, so the shared `_at` suffix is the intended
// vocabulary here, not accidental repetition.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug)]
struct KeyLifecycle {
    /// When the key first appears in the published JWKS (pre-publication).
    publish_at: SystemTime,
    /// When the key becomes the active signer (first use).
    activate_at: SystemTime,
    /// When the key stops being the active signer (a successor took over).
    retire_at: Option<SystemTime>,
    /// When the last token this key signed has expired; after this the key is
    /// withdrawn from the published JWKS.
    expire_at: Option<SystemTime>,
}

/// One signing key together with its lifecycle.
struct ManagedKey {
    key: SigningKey,
    lifecycle: KeyLifecycle,
}

/// An issuer's ordered signing keys, each with a publish/activate/retire/expire
/// lifecycle.
///
/// Build it with [`KeySet::bootstrap`] (the genesis key) and evolve it with
/// [`KeySet::rotate`] (the manual rotation command). Query it with
/// [`KeySet::active_signer`] (which key signs now) and [`KeySet::published_jwks`]
/// (which keys are published now, filtered by policy).
pub struct KeySet {
    keys: Vec<ManagedKey>,
}

impl KeySet {
    /// Start a key set from its genesis key, which becomes active (and published)
    /// at `activate_at`.
    ///
    /// The genesis key is exempt from the pre-publish lead: there is no prior
    /// JWKS for relying parties to have cached, so it is published and activated
    /// together.
    #[must_use]
    pub fn bootstrap(initial: SigningKey, activate_at: SystemTime) -> Self {
        Self {
            keys: vec![ManagedKey {
                key: initial,
                lifecycle: KeyLifecycle {
                    publish_at: activate_at,
                    activate_at,
                    retire_at: None,
                    expire_at: None,
                },
            }],
        }
    }

    /// Add a concurrent, always-active key that is published and active from
    /// `activate_at`.
    ///
    /// This is how a fresh environment holds its `EdDSA`, `ES256`, and `RS256`
    /// keys from day one: each algorithm's day-one key is added here, published
    /// together, so switching a client between algorithms is a policy flip with no
    /// JWKS propagation delay. Rotating any one of them later is
    /// [`KeySet::rotate`].
    pub fn add(&mut self, key: SigningKey, activate_at: SystemTime) {
        self.keys.push(ManagedKey {
            key,
            lifecycle: KeyLifecycle {
                publish_at: activate_at,
                activate_at,
                retire_at: None,
                expire_at: None,
            },
        });
    }

    /// The manual rotation command: schedule `next` to become the active signer
    /// for its algorithm at `activate_at`.
    ///
    /// This applies both discipline rules at once:
    ///
    /// - `next` is pre-published at `activate_at - prepublish_lead` (saturating to
    ///   the Unix epoch if that underflows), so it is in every relying party's
    ///   cache before it first signs.
    /// - the current active key OF THE SAME ALGORITHM, if any, is retired at
    ///   `activate_at` and retained in the published JWKS until `activate_at +
    ///   retention_after_retire` (the last moment a token it signed can still be
    ///   valid). Other algorithms' keys are untouched.
    ///
    /// # Errors
    ///
    /// [`RotationError::NonMonotonicActivation`] if `activate_at` is not strictly
    /// after the current same-algorithm key's activation, which would make the
    /// active signer ambiguous.
    pub fn rotate(
        &mut self,
        next: SigningKey,
        activate_at: SystemTime,
        params: RotationParams,
    ) -> Result<(), RotationError> {
        if let Some(head) = self.head_index_for(next.algorithm()) {
            if activate_at <= self.keys[head].lifecycle.activate_at {
                return Err(RotationError::NonMonotonicActivation);
            }
            // Retire the current same-algorithm head at the successor's activation
            // and retain it for one max-token-lifetime beyond, the longest any
            // token it signed lives. `checked_add` returns None only on an
            // astronomically distant timestamp overflow; treating that as "no
            // scheduled withdrawal" (retain forever) is the fail-safe direction,
            // since it never orphans an in-flight token.
            self.keys[head].lifecycle.retire_at = Some(activate_at);
            self.keys[head].lifecycle.expire_at =
                activate_at.checked_add(params.retention_after_retire());
        }

        // Pre-publish the successor a full lead before its first use.
        let publish_at = activate_at
            .checked_sub(params.prepublish_lead())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        self.keys.push(ManagedKey {
            key: next,
            lifecycle: KeyLifecycle {
                publish_at,
                activate_at,
                retire_at: None,
                expire_at: None,
            },
        });
        Ok(())
    }

    /// The key that signs at `now` under `policy`: the active key of the first
    /// algorithm the policy permits, in the policy's preference order.
    ///
    /// A policy-banned algorithm's key is never selected here even if it is still
    /// published (the `RS256` downgrade key, for example, stays in the JWKS but is
    /// not chosen to sign unless the policy permits it). `None` if no permitted
    /// algorithm has an active key.
    #[must_use]
    pub fn signer_for_policy(
        &self,
        now: SystemTime,
        policy: &SigningPolicy,
    ) -> Option<&SigningKey> {
        policy
            .allowed()
            .iter()
            .find_map(|&algorithm| self.active_signer_for(now, algorithm))
    }

    /// The active key of `algorithm` at `now`: among keys of that algorithm whose
    /// activation window covers `now`, the most recently activated. `None` if that
    /// algorithm has no active key.
    #[must_use]
    pub fn active_signer_for(
        &self,
        now: SystemTime,
        algorithm: JwsAlgorithm,
    ) -> Option<&SigningKey> {
        self.keys
            .iter()
            .filter(|managed| managed.key.algorithm() == algorithm && Self::is_active(managed, now))
            .max_by_key(|managed| managed.lifecycle.activate_at)
            .map(|managed| &managed.key)
    }

    /// The single active key at `now`, ignoring algorithm: the most recently
    /// activated key whose activation window covers `now`. Useful for a
    /// single-lineage set; when several algorithms are active, prefer
    /// [`KeySet::signer_for_policy`].
    #[must_use]
    pub fn active_signer(&self, now: SystemTime) -> Option<&SigningKey> {
        self.keys
            .iter()
            .filter(|managed| Self::is_active(managed, now))
            // If two windows ever overlapped, the most recently activated key
            // wins; the boundary is half-open so a single lineage has exactly one.
            .max_by_key(|managed| managed.lifecycle.activate_at)
            .map(|managed| &managed.key)
    }

    /// The active signer's `kid` at `now`, if any (single-lineage helper).
    #[must_use]
    pub fn active_kid(&self, now: SystemTime) -> Option<&str> {
        self.active_signer(now).and_then(SigningKey::kid)
    }

    /// Whether `managed` is the active signer at `now`: activated and not yet
    /// retired.
    fn is_active(managed: &ManagedKey, now: SystemTime) -> bool {
        managed.lifecycle.activate_at <= now
            && managed
                .lifecycle
                .retire_at
                .is_none_or(|retire| now < retire)
    }

    /// The published JWKS at `now`, filtered by `policy`.
    ///
    /// A key is published while `publish_at <= now` and it has not yet expired
    /// (`expire_at` is `None` or `now < expire_at`). Of those, a key is included
    /// only if `policy` retains its algorithm ([`SigningPolicy::retains_in_jwks`]):
    /// policy-permitted algorithms are published, and the `RS256` key is always
    /// published regardless of policy (the downgrade covenant).
    ///
    /// # Errors
    ///
    /// [`SigningKeyError::MalformedPublicKey`] if any published key's public
    /// projection cannot be formed, indicating corrupt key material.
    pub fn published_jwks(
        &self,
        now: SystemTime,
        policy: &SigningPolicy,
    ) -> Result<JwkSet, SigningKeyError> {
        let published = self
            .published_keys(now)
            .filter(|managed| policy.retains_in_jwks(managed.key.algorithm()))
            .map(|managed| &managed.key);
        JwkSet::from_signing_keys(published)
    }

    /// The `kid`s published at `now` under `policy`, in insertion order. A
    /// convenience for tests and diagnostics.
    #[must_use]
    pub fn published_kids(&self, now: SystemTime, policy: &SigningPolicy) -> Vec<String> {
        self.published_keys(now)
            .filter(|managed| policy.retains_in_jwks(managed.key.algorithm()))
            .filter_map(|managed| managed.key.kid().map(str::to_owned))
            .collect()
    }

    /// The signing keys published at `now`, before policy filtering: every key
    /// whose publish window has opened and that has not yet expired.
    ///
    /// These are exactly the keys any currently-valid token could have been
    /// signed by (the retention rule keeps a retired key published for one
    /// max-token-lifetime), so they are the trusted verifying set an issuer's own
    /// token-verification path checks a presented token against. Unlike
    /// [`KeySet::published_jwks`] this hands back the private [`SigningKey`]s (from
    /// which the caller takes each public verifying projection), not the serialized
    /// public JWK Set.
    #[must_use]
    pub fn published_signing_keys(&self, now: SystemTime) -> Vec<&SigningKey> {
        self.published_keys(now)
            .map(|managed| &managed.key)
            .collect()
    }

    /// The algorithms of every key ever provisioned in this set (full history),
    /// in insertion order. Used to assert `kid` uniqueness across history.
    #[must_use]
    pub fn all_kids(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter_map(|managed| managed.key.kid().map(str::to_owned))
            .collect()
    }

    /// Whether every key in the set carries a `kid` unique across the set's full
    /// history. A published JWKS and `kid`-based selection are ambiguous
    /// otherwise.
    #[must_use]
    pub fn kids_are_unique(&self) -> bool {
        let kids = self.all_kids();
        if kids.len() != self.keys.len() {
            // Some key has no `kid` at all.
            return false;
        }
        let mut seen = std::collections::HashSet::with_capacity(kids.len());
        kids.iter().all(|kid| seen.insert(kid.as_str()))
    }

    /// The keys published at `now`, before policy filtering.
    fn published_keys(&self, now: SystemTime) -> impl Iterator<Item = &ManagedKey> {
        self.keys.iter().filter(move |managed| {
            managed.lifecycle.publish_at <= now
                && managed
                    .lifecycle
                    .expire_at
                    .is_none_or(|expire| now < expire)
        })
    }

    /// The index of the current head for `algorithm`: the not-yet-retired key of
    /// that algorithm with the latest activation, or `None` if `algorithm` has no
    /// un-retired key yet (a first key of that algorithm being rotated in).
    fn head_index_for(&self, algorithm: JwsAlgorithm) -> Option<usize> {
        self.keys
            .iter()
            .enumerate()
            .filter(|(_, managed)| {
                managed.key.algorithm() == algorithm && managed.lifecycle.retire_at.is_none()
            })
            .max_by_key(|(_, managed)| managed.lifecycle.activate_at)
            .map(|(index, _)| index)
    }
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material: only the lifecycle shape and count.
        f.debug_struct("KeySet")
            .field("keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}

/// Whether the RS256 downgrade key is present among a set of published
/// algorithms. A small helper for callers assembling discovery metadata.
#[must_use]
pub fn includes_downgrade_key(algorithms: &[JwsAlgorithm]) -> bool {
    algorithms.contains(&JwsAlgorithm::Rs256)
}

/// Why a [`KeySet::rotate`] was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum RotationError {
    /// The successor's activation time was not strictly after the current head
    /// key's activation, so the active-signer window would be ambiguous.
    NonMonotonicActivation,
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotationError::NonMonotonicActivation => {
                f.write_str("a rotated-in key must activate strictly after the current key")
            }
        }
    }
}

impl std::error::Error for RotationError {}
