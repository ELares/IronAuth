// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scoped repositories: the only path to tenant-scoped tables, and the single
//! audited-write primitive every mutation must flow through.
//!
//! Everything in this module is constructed *from* a [`Scope`] and applies that
//! scope to every query itself. A caller can neither omit the scope nor pass a
//! different tenant per call, so a cross-tenant read is not expressible. This
//! is the compile-time half of the isolation model; every method also sets the
//! transaction-local row-level-security session variables, so the database
//! enforces the same boundary a third time beneath the application.
//!
//! This is the single module permitted to name a tenant-scoped table in SQL
//! (`clients`, `organizations`, `audit_log`). `scripts/query-audit.sh` fails the
//! build if a scoped-table query appears in any other source file, closing the
//! raw-pool bypass that module visibility already blocks across crates.
//!
//! # Reads versus writes
//!
//! Reads ([`ClientRepo`], [`AuditRepo`]) need no actor. Writes do: a mutation is
//! only reachable through [`ScopedStore::acting`], which demands an
//! [`ActorRef`] and a [`CorrelationId`]. So the acting context is required at the
//! type level for every write and for no read.
//!
//! # The audited-write primitive
//!
//! Every mutation routes through the single private [`write_audited`] function.
//! It opens one scoped transaction, runs the caller's data change, writes
//! exactly one [`audit_log`](crate::audit) row in that same transaction, and only
//! then commits. Every public mutator ([`ActingClientRepo::create`],
//! [`ActingClientRepo::delete`], and every future one) is a thin wrapper over it,
//! so a mutation cannot commit without its audit row and a failed mutation
//! commits neither.
//!
//! This module is the enforcement boundary, and the enforcement is at the
//! crate/API level rather than a language-level impossibility. Outside this
//! module nothing can reach a scoped table at all: the pool is crate private,
//! module visibility blocks other crates, `scripts/query-audit.sh` fails the
//! build on scoped-table SQL anywhere else, and Postgres row-level security sits
//! beneath all of it. So no caller can commit a scoped write off the audited
//! path. Within this one module the discipline is a reviewed invariant: a future
//! in-module mutator must route through [`write_audited`] rather than commit its
//! own transaction. Keeping the committing write path a single private function
//! is what makes that invariant a one-line review rather than a per-handler
//! audit. This is enforcement by construction at the module boundary, not
//! handler discipline spread across the codebase.

use std::fmt;
use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_jose::{Aad, BlindIndex, Dek, Kek, MasterKey, Sealed};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Postgres, Row, Transaction};

use crate::audit::{ActingContext, Action, ActorRef};
use crate::classification::ResourceType;
use crate::custom_domain::{
    AcmeChallengeRecord, ChallengeOutcome, ChallengeStatus, ChallengeType, CustomDomainRecord,
    VerificationStatus,
};
use crate::environment::{EnvironmentType, GuardrailSet};
use crate::error::StoreError;
use crate::id::{
    AcmeChallengeId, AssertionMappingId, AuditId, AuditTarget, AuthorizationCodeId,
    BackChannelDeliveryId, ClientId, ClientSessionId, ConsentId, CorrelationId, CredentialId,
    CustomDomainId, DcrPolicyId, DekId, DeviceCodeId, EncryptedSecretId, EnvironmentId,
    EnvironmentSecretId, ExternalIssuerId, GrantId, InitialAccessTokenId, IssuedTokenId, KekId,
    ManagementKeyId, OperatorId, OrganizationId, PushedRequestId, RefreshFamilyId, RefreshTokenId,
    ResourceServerId, ServiceAccountId, SessionEventId, SessionId, SigningKeyId, TenantId, UserId,
    VariableId,
};
use crate::scope::Scope;
use crate::store::Store;

/// A store bound to one `(tenant, environment)` scope. Hands out the per-kind
/// read repositories, and the acting entry point for writes.
pub struct ScopedStore<'a> {
    store: &'a Store,
    scope: Scope,
}

impl<'a> ScopedStore<'a> {
    /// Bind a store to a scope. Crate-internal: callers reach this only through
    /// [`Store::scoped`], which is what makes the scope non-optional.
    pub(crate) fn new(store: &'a Store, scope: Scope) -> Self {
        Self { store, scope }
    }

    /// The read-only OAuth client repository for this scope. Reads need no
    /// actor; to create or delete, go through [`ScopedStore::acting`].
    #[must_use]
    pub fn clients(&self) -> ClientRepo<'a> {
        ClientRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// This scope's data-plane serving state (issue #46): whether the data plane
    /// must serve or FENCE it. A scope the control plane has suspended, or a
    /// deleted/offboarded tenant, reads [`EnvironmentServingState::Suspended`]; a
    /// scope with no stored serving row reads [`EnvironmentServingState::Active`]
    /// (the safe default). Read under this scope's forced row-level security, so a
    /// scope can only ever observe its own serving state. The OIDC data-plane
    /// issuer-load path consults this and refuses a suspended scope fail closed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn environment_state(&self) -> Result<EnvironmentServingState, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT serving_status FROM environment_states \
             WHERE tenant_id = $1 AND environment_id = $2",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(EnvironmentServingState::Active),
            Some(row) => Ok(match row.get::<String, _>("serving_status").as_str() {
                "suspended" => EnvironmentServingState::Suspended,
                // Any other value (only 'active' passes the CHECK) is served.
                _ => EnvironmentServingState::Active,
            }),
        }
    }

    /// The read-only audit-log repository for this scope. The log is append-only:
    /// rows are written only by the audited-write primitive, and this reads them
    /// back within scope.
    #[must_use]
    pub fn audit(&self) -> AuditRepo<'a> {
        AuditRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only OIDC authorization repository for this scope (issue #12).
    /// Reads a token's active state and a code's bindings; the mutating
    /// operations (issue, redeem) live on [`ActingStore::authorization`].
    #[must_use]
    pub fn authorization(&self) -> AuthorizationRepo<'a> {
        AuthorizationRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only bootstrap user repository for this scope (issue #20).
    /// Authenticates a login handle against its stored Argon2id hash; the
    /// mutating registration lives on [`ActingStore::users`].
    #[must_use]
    pub fn users(&self) -> UserRepo<'a> {
        UserRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only bootstrap session repository for this scope (issue #20).
    /// Resolves a session cookie to its subject; the mutating create lives on
    /// [`ActingStore::sessions`].
    #[must_use]
    pub fn sessions(&self) -> SessionRepo<'a> {
        SessionRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The per-client session repository for this scope (issue #32): resolve or
    /// create the per-(client, session) `sid` the ID token carries. Off the audited
    /// path (session-tracking infra), so it lives on the read store like the replay
    /// caches even though its `ensure_sid` may INSERT.
    #[must_use]
    pub fn client_sessions(&self) -> ClientSessionRepo<'a> {
        ClientSessionRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The durable session-ended outbox drain for this scope (issue #35): the seam the
    /// back-channel logout worker (#34) and the external webhooks (M11) consume the
    /// session-ended fan-out off. Off the audited path (drain bookkeeping, like the
    /// device-code poll), even though its claim/mark mutate the two lifecycle columns:
    /// the durable record of an end is the outbox row and its audit sibling, both
    /// written when the session flipped, never the drain.
    #[must_use]
    pub fn session_events(&self) -> SessionEventOutboxRepo<'a> {
        SessionEventOutboxRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The per-RP back-channel-logout delivery queue for this scope (issue #34): the
    /// at-least-once work queue the back-channel logout worker drains. Off the audited
    /// path (delivery bookkeeping, like the outbox drain), even though its explode/claim/
    /// mark mutate lifecycle columns: the durable record of the session end is the #35
    /// outbox row and its audit sibling, not a delivery attempt.
    #[must_use]
    pub fn backchannel_deliveries(&self) -> BackChannelDeliveryRepo<'a> {
        BackChannelDeliveryRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only session fleet-ops repository for this scope (issue #32): list and
    /// inspect sessions as searchable management resources (the mutating revoke lives
    /// on [`ActingStore::sessions`]). Reports revoked/rotated/ended sessions too,
    /// unlike the auth read path [`ScopedStore::sessions`].
    #[must_use]
    pub fn session_fleet(&self) -> SessionFleetRepo<'a> {
        SessionFleetRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only refresh-family fleet-ops repository for this scope (issue #32):
    /// list and inspect refresh-token families as searchable management resources.
    #[must_use]
    pub fn refresh_family_fleet(&self) -> RefreshFamilyFleetRepo<'a> {
        RefreshFamilyFleetRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only account-credential repository for this scope (issue #61): list a
    /// subject's OWN enrolled credentials; enroll and remove live on
    /// [`ActingStore::account_credentials`]. Every read is subject-bound, so a
    /// credential of another subject is not reachable.
    #[must_use]
    pub fn account_credentials(&self) -> AccountCredentialRepo<'a> {
        AccountCredentialRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only consent repository for this scope (issue #20). Reads whether
    /// a subject has consented to a client; the mutating grant lives on
    /// [`ActingStore::consents`].
    #[must_use]
    pub fn consents(&self) -> ConsentRepo<'a> {
        ConsentRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only signing-key repository for this scope (issue #19). Lists and
    /// fetches the environment's signing keys; provisioning lives on
    /// [`ActingStore::signing_keys`]. The scope is fixed here, so a key of another
    /// tenant or environment is not reachable.
    #[must_use]
    pub fn signing_keys(&self) -> SigningKeyRepo<'a> {
        SigningKeyRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only environment-guardrail repository for this scope (issue #42).
    /// Resolves the environment's typed [`GuardrailSet`] from the scope-forced
    /// `environment_guardrails` projection, so the data plane can enforce the
    /// redirect guardrail (an `http` loopback is rejected in a `prod` environment)
    /// without reading the environments level table. The scope is fixed here, so a
    /// request can only ever read its own environment's guardrails.
    #[must_use]
    pub fn environment_guardrails(&self) -> EnvironmentGuardrailRepo<'a> {
        EnvironmentGuardrailRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only resource-server repository for this scope (issue #29). Reads
    /// a registered resource server by audience so the mint can select its
    /// access-token format; registration lives on [`ActingStore::resource_servers`].
    #[must_use]
    pub fn resource_servers(&self) -> ResourceServerRepo<'a> {
        ResourceServerRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only refresh-token repository for this scope (issue #21). Resolves
    /// a presented refresh token's live state by its digest; the mutating
    /// operations (issue a family, rotate/redeem, revoke on logout) live on
    /// [`ActingStore::refresh`].
    #[must_use]
    pub fn refresh(&self) -> RefreshRepo<'a> {
        RefreshRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only service-account repository for this scope (issue #23).
    /// Resolves a client's STABLE service-account principal id (the client-
    /// credentials `sub`); the lazy mint lives on [`ActingStore::service_accounts`].
    #[must_use]
    pub fn service_accounts(&self) -> ServiceAccountRepo<'a> {
        ServiceAccountRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The single-use JWT-assertion `jti` replay cache for this scope (issue #25).
    /// Records an accepted assertion's `jti`; a second use of the same `jti` is a
    /// REPLAY, which the shared database enforces ACROSS nodes. It is a
    /// replay-prevention cache, not a business mutation, so (like
    /// `idempotency_keys`) it is deliberately off the audited-write path and needs
    /// no acting context.
    #[must_use]
    pub fn client_assertion_jtis(&self) -> ClientAssertionJtiRepo<'a> {
        ClientAssertionJtiRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The out-of-band client-authentication diagnostics sink for this scope (issue
    /// #25). Records the rich, structured detail of a failed client authentication
    /// for the future M9 admin view; it is a diagnostic log, not a business
    /// mutation, so (like `idempotency_keys`) it is deliberately off the
    /// audited-write path and needs no acting context.
    #[must_use]
    pub fn client_auth_diagnostics(&self) -> ClientAuthDiagnosticsRepo<'a> {
        ClientAuthDiagnosticsRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only registered external assertion issuer repository for this scope
    /// (issue #26). Resolves the trust anchor an inbound JWT bearer assertion's `iss`
    /// names, so the grant can verify the assertion against the issuer's keys;
    /// registration lives on [`ActingStore::external_assertion_issuers`].
    #[must_use]
    pub fn external_assertion_issuers(&self) -> ExternalAssertionIssuerRepo<'a> {
        ExternalAssertionIssuerRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only subject-mapping repository for the JWT bearer assertion grant in
    /// this scope (issue #26). Resolves the explicit rule that maps a verified
    /// external (issuer + `sub`) to an IronAuth principal; authoring lives on
    /// [`ActingStore::external_assertion_subject_mappings`]. An unmapped subject
    /// resolves to `None`, and the grant rejects it (never auto-provisions).
    #[must_use]
    pub fn external_assertion_subject_mappings(&self) -> AssertionSubjectMappingRepo<'a> {
        AssertionSubjectMappingRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The single-use external-issuer JWT-assertion `jti` replay cache for this scope
    /// (issue #26). Records an accepted assertion's `jti` keyed by the EXTERNAL
    /// issuer, so an external issuer's `jti` can never collide with a client
    /// assertion's `jti` (they live in distinct tables). Like the #25 client cache it
    /// is a replay-prevention cache, not a business mutation, so it is deliberately
    /// off the audited-write path and needs no acting context.
    #[must_use]
    pub fn external_assertion_jtis(&self) -> ExternalAssertionJtiRepo<'a> {
        ExternalAssertionJtiRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only pushed-authorization-request repository for this scope (RFC
    /// 9126, issue #27). PEEKS a `request_uri`'s stored parameters WITHOUT consuming
    /// them, so the authorization endpoint can resolve a PAR reference across the
    /// login/consent interaction round-trip; the single-use consume lives on
    /// [`ActingStore::pushed_authorization_requests`].
    #[must_use]
    pub fn pushed_authorization_requests(&self) -> PushedRequestRepo<'a> {
        PushedRequestRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only DCR policy repository for this scope (issue #31). Resolves a
    /// named, reusable policy object to its primitives (at initial-access-token
    /// mint time) and lists policies for the management API; authoring lives on
    /// [`ActingStore::dcr_policies`].
    #[must_use]
    pub fn dcr_policies(&self) -> DcrPolicyRepo<'a> {
        DcrPolicyRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The DCR initial-access-token repository for this scope (issue #31). CONSUMES
    /// a presented token (validating expiry and usage limit and incrementing the
    /// use count atomically), returning its policy-chain snapshot; minting lives on
    /// [`ActingStore::initial_access_tokens`]. The consume is a credential-use
    /// counter, not a business mutation, so (like the jti replay cache) it is
    /// deliberately off the audited-write path and commits its own transaction.
    #[must_use]
    pub fn initial_access_tokens(&self) -> InitialAccessTokenRepo<'a> {
        InitialAccessTokenRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The endpoint-local DCR registration rate limiter for this scope (issue #31).
    /// A fixed-window counter keyed by source and by initial access token, using
    /// the application clock seam for the window. A counter cache, not a business
    /// mutation, so (like `idempotency_keys`) it is off the audited-write path and
    /// commits its own transaction. Later delegates to the M15 layered limiter (out
    /// of scope here).
    #[must_use]
    pub fn dcr_rate_limiter(&self) -> DcrRateLimiterRepo<'a> {
        DcrRateLimiterRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-and-bookkeeping device-authorization repository for this scope (issue
    /// #24, RFC 8628). Resolves a presented device code at the token-endpoint poll,
    /// looks up a flow by a submitted user code on the verification page, records a
    /// failed user-code match, and reads a client's device-grant profile. The
    /// approval and denial mutations (the audited business events) live on
    /// [`ActingStore::device_codes`]; polling and failed-attempt bookkeeping are
    /// high-frequency counter mutations kept off the audited-write path (like the DCR
    /// rate counters), so they live here.
    #[must_use]
    pub fn device_codes(&self) -> DeviceCodeRepo<'a> {
        DeviceCodeRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only envelope-encryption repository for this scope (issue #48):
    /// decrypt an encrypted secret value, and inspect the scope's active KEK/DEK
    /// versions. Decryption needs the platform master key; the mutating lifecycle
    /// (provision, rotate, crypto-shred, write) lives on [`ActingStore::envelope`].
    #[must_use]
    pub fn envelope(&self) -> EnvelopeRepo<'a> {
        EnvelopeRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only custom-domain repository for this scope (issue #47): look a
    /// domain up by name or id, list an environment's domains, and read a domain's
    /// ACME challenges. Registration, challenge results, and certificate storage
    /// (the audited mutations) live on [`ActingStore::custom_domains`].
    #[must_use]
    pub fn custom_domains(&self) -> CustomDomainRepo<'a> {
        CustomDomainRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only environment-variable repository for this scope (issue #45):
    /// read a non-secret named config value, list an environment's variables, and
    /// find the variables that REFERENCE a given name (the referent check a delete
    /// consults). Writes (set, delete) live on [`ActingStore::environment_variables`].
    #[must_use]
    pub fn environment_variables(&self) -> EnvironmentVariableRepo<'a> {
        EnvironmentVariableRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only environment-secret repository for this scope (issue #45): read
    /// a secret's METADATA (name, version, updated-at, never the value), list an
    /// environment's secrets, and OPEN a secret's sealed value under the platform
    /// master key (the apply-time resolution path). Writes (put, delete) live on
    /// [`ActingStore::environment_secrets`].
    #[must_use]
    pub fn environment_secrets(&self) -> EnvironmentSecretRepo<'a> {
        EnvironmentSecretRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// Enter an acting context (who is acting, and under which correlation id).
    /// The returned store hands out the *mutating* repositories, so every write
    /// carries an actor and a correlation id into its audit row.
    #[must_use]
    pub fn acting(&self, actor: ActorRef, correlation: CorrelationId) -> ActingStore<'a> {
        ActingStore {
            store: self.store,
            scope: self.scope,
            acting: ActingContext::new(actor, correlation),
        }
    }
}

/// A scope-and-actor bound store: the door to the mutating repositories.
pub struct ActingStore<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl<'a> ActingStore<'a> {
    /// The mutating OAuth client repository for this scope and actor.
    #[must_use]
    pub fn clients(&self) -> ActingClientRepo<'a> {
        ActingClientRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating OIDC authorization repository for this scope and actor
    /// (issue #12): issue a code and its grant, redeem a code (single use, which
    /// also records the issued tokens and, on a genuine reuse, revokes the grant
    /// chain), and record issued tokens. Every mutation carries the actor and
    /// correlation id into its audit row.
    #[must_use]
    pub fn authorization(&self) -> ActingAuthorizationRepo<'a> {
        ActingAuthorizationRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating bootstrap user repository for this scope and actor (issue
    /// #20): register a user with an Argon2id password hash, audited.
    #[must_use]
    pub fn users(&self) -> ActingUserRepo<'a> {
        ActingUserRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating bootstrap session repository for this scope and actor (issue
    /// #20): create a session at login or registration, audited.
    #[must_use]
    pub fn sessions(&self) -> ActingSessionRepo<'a> {
        ActingSessionRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating account-credential repository for this scope and actor (issue
    /// #61): enroll and remove a subject's OWN credentials, audited and
    /// subject-bound. The last-usable-credential guardrail is enforced on removal.
    #[must_use]
    pub fn account_credentials(&self) -> ActingAccountCredentialRepo<'a> {
        ActingAccountCredentialRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating consent repository for this scope and actor (issue #20):
    /// record a subject's consent to a client, audited (idempotent per
    /// (subject, client)).
    #[must_use]
    pub fn consents(&self) -> ActingConsentRepo<'a> {
        ActingConsentRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating signing-key repository for this scope and actor (issue #19).
    /// Provisions a day-one key or a manually rotated-in successor; every
    /// provision writes its audit row in the same transaction.
    #[must_use]
    pub fn signing_keys(&self) -> ActingSigningKeyRepo<'a> {
        ActingSigningKeyRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating envelope-encryption repository for this scope and actor (issue
    /// #48): provision the scope's KEK and DEK, rotate the KEK (re-wrapping every
    /// DEK online with no payload rewrite), rotate the DEK (versioning new writes),
    /// crypto-shred the KEK (making all of the scope's data permanently
    /// unreadable), write an encrypted secret, and re-encrypt a secret onto the
    /// active DEK version. Every mutation writes its audit row in the same
    /// transaction.
    #[must_use]
    pub fn envelope(&self) -> ActingEnvelopeRepo<'a> {
        ActingEnvelopeRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating custom-domain repository for this scope and actor (issue #47):
    /// register a domain and open its ACME challenge, record a challenge result
    /// (verifying or failing the domain), and store an issued certificate (its
    /// private key sealed under the scope's envelope DEK). Every mutation writes
    /// its audit row in the same transaction.
    #[must_use]
    pub fn custom_domains(&self) -> ActingCustomDomainRepo<'a> {
        ActingCustomDomainRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating environment-variable repository for this scope and actor (issue
    /// #45): set a non-secret named config value (a first write or an overwrite,
    /// optionally under an Idempotency-Key) and delete one (rejected while a live
    /// variable value still references it). Every mutation writes its audit row in
    /// the same transaction.
    #[must_use]
    pub fn environment_variables(&self) -> ActingEnvironmentVariableRepo<'a> {
        ActingEnvironmentVariableRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating environment-secret repository for this scope and actor (issue
    /// #45): put a secret (its plaintext value sealed under the scope's envelope
    /// DEK, issue #48, write-only) and delete one. Every mutation writes its audit
    /// row in the same transaction, and no secret value is ever recorded in it.
    #[must_use]
    pub fn environment_secrets(&self) -> ActingEnvironmentSecretRepo<'a> {
        ActingEnvironmentSecretRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating resource-server repository for this scope and actor (issue
    /// #29): register a resource server (its audience, token format, and optional
    /// lifetime), audited in the same transaction.
    #[must_use]
    pub fn resource_servers(&self) -> ActingResourceServerRepo<'a> {
        ActingResourceServerRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating refresh-token repository for this scope and actor (issue #21):
    /// open a family at first issuance, rotate/redeem a presented refresh token
    /// (with reuse detection), and revoke a session's session-bound families at RP
    /// logout. Every mutation carries the actor and correlation id into its audit
    /// row.
    #[must_use]
    pub fn refresh(&self) -> ActingRefreshRepo<'a> {
        ActingRefreshRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating service-account repository for this scope and actor (issue
    /// #23): lazily mint a client's stable service-account principal at its first
    /// client-credentials issuance, audited (idempotent per client).
    #[must_use]
    pub fn service_accounts(&self) -> ActingServiceAccountRepo<'a> {
        ActingServiceAccountRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating pushed-authorization-request repository for this scope and actor
    /// (RFC 9126, issue #27): push a validated authorization request behind a
    /// one-time `request_uri`, and atomically consume it exactly once at the
    /// authorization endpoint. Both the push and the consume audit in the same
    /// transaction as the state change.
    #[must_use]
    pub fn pushed_authorization_requests(&self) -> ActingPushedRequestRepo<'a> {
        ActingPushedRequestRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating DCR policy repository for this scope and actor (issue #31):
    /// create a named, reusable policy object, audited (`dcr.policy_created`) in the
    /// same transaction.
    #[must_use]
    pub fn dcr_policies(&self) -> ActingDcrPolicyRepo<'a> {
        ActingDcrPolicyRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating DCR initial-access-token repository for this scope and actor
    /// (issue #31): mint a token (its plaintext returned once, only the hash
    /// stored), audited (`dcr.iat_minted`) in the same transaction.
    #[must_use]
    pub fn initial_access_tokens(&self) -> ActingInitialAccessTokenRepo<'a> {
        ActingInitialAccessTokenRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating device-authorization repository for this scope and actor (issue
    /// #24, RFC 8628): issue a flow (`device_code.issue`), approve one after an
    /// authenticated human's explicit confirmation (`device_code.approve`, which
    /// opens the grant in the same transaction), deny one (`device_code.deny`), and
    /// atomically redeem an approved flow at the token endpoint (recording the issued
    /// tokens). Every business mutation carries the actor and correlation id into its
    /// audit row.
    #[must_use]
    pub fn device_codes(&self) -> ActingDeviceCodeRepo<'a> {
        ActingDeviceCodeRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating external assertion issuer repository for this scope and actor
    /// (issue #26): register a trust anchor (its key source, signing-alg allowlist,
    /// and enable switch) for the JWT bearer assertion grant, audited
    /// (`external_assertion_issuer.register`) in the same transaction.
    #[must_use]
    pub fn external_assertion_issuers(&self) -> ActingExternalAssertionIssuerRepo<'a> {
        ActingExternalAssertionIssuerRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }

    /// The mutating subject-mapping repository for the JWT bearer assertion grant in
    /// this scope and actor (issue #26): author an explicit rule mapping an external
    /// (issuer + `sub`) to an IronAuth principal, audited
    /// (`external_assertion_subject_mapping.create`) in the same transaction.
    #[must_use]
    pub fn external_assertion_subject_mappings(&self) -> ActingAssertionSubjectMappingRepo<'a> {
        ActingAssertionSubjectMappingRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        }
    }
}

/// A record read back from the `clients` table, always within scope.
// The registration flags crossed clippy's `struct_excessive_bools` threshold when
// the #21 consent-mode knobs and the #27 require-PAR flag landed together; each is
// an independent per-client registration attribute, not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRecord {
    /// The client identifier (embeds its tenant and environment).
    pub id: ClientId,
    /// The human-facing display name.
    pub display_name: String,
    /// Whether the client registered `require_auth_time`: when true, every ID
    /// token issued to it carries `auth_time` even without a `max_age` request
    /// (issue #14).
    pub require_auth_time: bool,
    /// The registered `token_endpoint_auth_method` wire string
    /// (`client_secret_basic`, `client_secret_post`, or `none`). A `none` client
    /// is PUBLIC and, per RFC 9700 2.1.1, must use PKCE (issue #13).
    pub auth_method: String,
    /// The client's registered redirect URIs, the set the authorization endpoint
    /// matches a presented `redirect_uri` against by exact string (issue #13).
    /// Empty for a client that registered none (which therefore cannot complete an
    /// authorization request until it registers one).
    pub redirect_uris: Vec<String>,
    /// The client's registered POST-LOGOUT redirect URIs (issue #33): the set the
    /// RP-Initiated Logout `end_session` endpoint matches a presented
    /// `post_logout_redirect_uri` against by exact string (RFC 9700 section 2.1),
    /// honoring a redirect ONLY on an exact match with a verifiable `id_token_hint`.
    /// Empty for a client that registered none (which therefore never gets a
    /// post-logout redirect; the logout renders a neutral logged-out page instead).
    pub post_logout_redirect_uris: Vec<String>,
    /// The client's registered OIDC Front-Channel Logout 1.0 URI (issue #39): the
    /// endpoint the OP loads in a hidden iframe during logout so the RP clears its
    /// own session. [`None`] means the client did NOT opt in and participates in no
    /// front-channel logout (the per-client half of the two-part gate; the
    /// environment `frontchannel_logout_enabled` flag is the other).
    pub frontchannel_logout_uri: Option<String>,
    /// Whether the OP MUST append `iss` and this client's OWN per-(client, session)
    /// `sid` to its `frontchannel_logout_uri` (issue #39, OIDC Front-Channel Logout
    /// 1.0 `frontchannel_logout_session_required`). `false` (the default) appends
    /// neither. It never carries another client's `sid`.
    pub frontchannel_logout_session_required: bool,
    /// The client's consent mode (issue #21): the stored `consent_mode` string
    /// (`explicit`, `implicit`, or `remembered`). Drives whether the authorization
    /// endpoint prompts for consent, skips it (first-party), or honors a remembered
    /// decision for a TTL. An unrecognized stored value is treated as `explicit`.
    pub consent_mode: String,
    /// Whether the client skips the consent screen entirely (issue #21): an
    /// orthogonal quick knob that auto-grants like the `implicit` mode.
    pub skip_consent: bool,
    /// Whether a SKIPPED consent (implicit or `skip_consent`) is persisted as a
    /// consent row (issue #21). `false` is the performance knob: skip the screen
    /// AND write no consent row.
    pub store_skipped_consent: bool,
    /// Whether this client requires a pushed authorization request (RFC 9126
    /// section 5, issue #27): when true, a plain (non-PAR) authorization request
    /// from this client is rejected with `invalid_request`. The environment-wide
    /// switch (config) applies on top of this per-client flag.
    pub require_pushed_authorization_requests: bool,
    /// Whether this client is under the unverified-client quarantine (issue #31):
    /// a client from open (or low-trust) self-service registration starts
    /// quarantined. While quarantined, the authorization/consent path IGNORES the
    /// client's `implicit`/`skip_consent` first-party carve-outs (consent is ALWAYS
    /// shown) and RESTRICTS its effective redirect-URI set to the https subset,
    /// until an admin verifies it. Defaults to false for every non-DCR client.
    pub quarantined: bool,
}

/// One relying party that participates in a front-channel logout for a given SSO
/// session (issue #39): the join of a live `client_sessions` row to its `clients` row
/// where the client registered a `frontchannel_logout_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontchannelLogoutParticipant {
    /// The client's registered `frontchannel_logout_uri` (an `https` URL): the endpoint
    /// the OP loads in a hidden iframe on logout.
    pub frontchannel_logout_uri: String,
    /// Whether `iss` and this client's OWN `sid` must be appended
    /// (`frontchannel_logout_session_required`).
    pub session_required: bool,
    /// The client's OWN per-(client, session) `sid` for the session being ended. It is
    /// this client's row's `sid`, so a participant only ever learns its own `sid`, never
    /// another client's.
    pub sid: String,
}

/// A client's RFC 8707 resource-indicator policy, read within scope (issue #28).
///
/// The authorization and token endpoints read this to decide which resources a
/// client may request and how a request with NO `resource` parameter is treated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResourcePolicy {
    /// The per-client allowed-resource allowlist: the resource URIs this client may
    /// request. [`None`] means NO per-client allowlist is configured, in which case
    /// the client may request any resource that is a registered resource server in
    /// its environment (the resource-server registry is itself the allowlist); a
    /// [`Some`] set further RESTRICTS the client to exactly its entries. An empty
    /// [`Some`] set means the client may request NO resource at all.
    pub allowed_resources: Option<Vec<String>>,
    /// Whether the client REFUSES a request that carries no `resource` parameter
    /// (the stored `resource_indicator_policy` is `refuse`). `false` (the default,
    /// for a `default_audience` or unset policy) keeps the existing no-resource
    /// behavior: the token's audience is the client id.
    pub require_resource_indicator: bool,
}

/// The client-authentication metadata for a client, read within scope (issue
/// #20). The token endpoint uses it to enforce the client's registered
/// authentication method and verify a presented secret against the stored hash.
///
/// [`fmt::Debug`] is hand written: the `secret_hash` is a stored credential
/// hash, so a struct dump or a `tracing` field never spills it (its presence is
/// reported as a bool instead).
#[derive(Clone, PartialEq, Eq)]
pub struct ClientAuthRecord {
    /// The client's display name (shown on the consent screen).
    pub display_name: String,
    /// The registered `token_endpoint_auth_method` wire string
    /// (`client_secret_basic`, `client_secret_post`, `private_key_jwt`,
    /// `client_secret_jwt`, or `none`).
    pub auth_method: String,
    /// The SHA-256 hex hash of the client's secret, or `None` for a public
    /// (method `none`) or JWT-assertion client that has no stored secret.
    pub secret_hash: Option<String>,
    /// The client's inline `jwks` (a JWK Set JSON document), for a
    /// `private_key_jwt` client that registered its verification keys inline;
    /// `None` if unset. At most one of `jwks`/`jwks_uri` is set (a database CHECK
    /// enforces this). Public key material, not a secret.
    pub jwks: Option<String>,
    /// The client's `jwks_uri`, for a `private_key_jwt` client whose verification
    /// keys are fetched (through the SSRF-hardened fetcher) rather than inline;
    /// `None` if unset.
    pub jwks_uri: Option<String>,
    /// The client's registered `token_endpoint_auth_signing_alg`: the single JWS
    /// algorithm its assertions must be signed with (a per-client allowlist), or
    /// `None` to allow the supported asymmetric set.
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// The client's refresh-token rotation override (issue #21): `Some("always")`
    /// to rotate on every refresh, `Some("threshold")` to rotate only past the
    /// configured fraction of TTL, or `None` to derive the policy from the client's
    /// posture (a public client always rotates; a confidential one rotates past the
    /// threshold). An unrecognized stored value is treated as `None` by the reader.
    pub refresh_rotation: Option<String>,
}

impl fmt::Debug for ClientAuthRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientAuthRecord")
            .field("display_name", &self.display_name)
            .field("auth_method", &self.auth_method)
            .field("has_secret", &self.secret_hash.is_some())
            .field("has_jwks", &self.jwks.is_some())
            .field("jwks_uri", &self.jwks_uri)
            .field(
                "token_endpoint_auth_signing_alg",
                &self.token_endpoint_auth_signing_alg,
            )
            .field("refresh_rotation", &self.refresh_rotation)
            .finish()
    }
}

/// The registration parameters for a JWT-assertion client (issue #25), created
/// through [`ActingClientRepo::create_jwt_auth`].
#[derive(Debug, Clone, Copy)]
pub struct NewJwtAuthClient<'a> {
    /// The client's display name.
    pub display_name: &'a str,
    /// The `token_endpoint_auth_method` wire string (`private_key_jwt` or
    /// `client_secret_jwt`).
    pub auth_method: &'a str,
    /// The inline `jwks` (a JWK Set JSON document), or `None`. At most one of
    /// `jwks`/`jwks_uri` may be set.
    pub jwks: Option<&'a str>,
    /// The `jwks_uri`, or `None`.
    pub jwks_uri: Option<&'a str>,
    /// The pinned `token_endpoint_auth_signing_alg`, or `None` to allow the
    /// supported asymmetric set.
    pub signing_alg: Option<&'a str>,
}

/// A dynamically registered client's stored configuration (issue #30), read
/// within scope for the RFC 7592 read/update/delete surface and for
/// authenticating a presented registration access token.
///
/// [`fmt::Debug`] is hand written: `registration_access_token_hash` is a stored
/// credential hash, so a struct dump or a `tracing` field never spills it (its
/// presence is reported as a bool instead), exactly like [`ClientAuthRecord`].
#[derive(Clone, PartialEq, Eq)]
pub struct DynamicClientRecord {
    /// The client identifier (embeds its tenant and environment).
    pub id: ClientId,
    /// The human-facing display name (`client_name`).
    pub display_name: String,
    /// The registered `token_endpoint_auth_method` wire string.
    pub auth_method: String,
    /// The registered redirect URI set.
    pub redirect_uris: Vec<String>,
    /// The RFC 8252 `application_type` (`web` or `native`), or `None` for a client
    /// that predates DCR.
    pub application_type: Option<String>,
    /// The negotiated `id_token_signed_response_alg`, or `None` for a pre-DCR
    /// client.
    pub id_token_signed_response_alg: Option<String>,
    /// The client's inline `jwks` (a JWK Set JSON document), or `None`.
    pub jwks: Option<String>,
    /// The client's `jwks_uri`, or `None`.
    pub jwks_uri: Option<String>,
    /// The pinned `token_endpoint_auth_signing_alg` for `private_key_jwt`, or
    /// `None`.
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// The RFC 7592 client configuration endpoint URL, or `None` for a pre-DCR
    /// client.
    pub registration_client_uri: Option<String>,
    /// The SHA-256 (hex) hash of the RFC 7592 registration access token. The
    /// management surface compares a presented token's hash against this in
    /// constant time; `None` means the client is not a DCR registration.
    pub registration_access_token_hash: Option<String>,
    /// Creation time in microseconds since the Unix epoch (the DCR response's
    /// `client_id_issued_at`).
    pub created_at_unix_micros: i64,
    /// Whether the client is under the unverified-client quarantine (issue #31).
    pub quarantined: bool,
    /// When an admin verified the client (lifted the quarantine), in microseconds
    /// since the Unix epoch, or `None` while unverified.
    pub verified_at_unix_micros: Option<i64>,
    /// The resolved policy-chain snapshot (JSON primitive list as text) that bound
    /// this client's registration, re-applied to every RFC 7592 update so the SAME
    /// policy constrains the client for its lifetime (issue #31); `None` for a
    /// client registered without a policy.
    pub dcr_policy_chain: Option<String>,
}

impl fmt::Debug for DynamicClientRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicClientRecord")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("auth_method", &self.auth_method)
            .field("redirect_uris", &self.redirect_uris)
            .field("application_type", &self.application_type)
            .field(
                "id_token_signed_response_alg",
                &self.id_token_signed_response_alg,
            )
            .field("has_jwks", &self.jwks.is_some())
            .field("jwks_uri", &self.jwks_uri)
            .field(
                "token_endpoint_auth_signing_alg",
                &self.token_endpoint_auth_signing_alg,
            )
            .field("registration_client_uri", &self.registration_client_uri)
            .field(
                "has_registration_access_token",
                &self.registration_access_token_hash.is_some(),
            )
            .field("created_at_unix_micros", &self.created_at_unix_micros)
            .field("quarantined", &self.quarantined)
            .field("verified_at_unix_micros", &self.verified_at_unix_micros)
            .field("has_dcr_policy_chain", &self.dcr_policy_chain.is_some())
            .finish()
    }
}

/// The parameters for a Dynamic Client Registration (issue #30, RFC 7591),
/// created through [`ActingClientRepo::register_dynamic`]. The OIDC layer has
/// already validated the metadata, negotiated the algorithm, and hashed the
/// secret and the registration access token; the repository stores them and mints
/// the identifier.
#[derive(Debug, Clone, Copy)]
pub struct NewDynamicClient<'a> {
    /// The `client_name` / display name (non-empty).
    pub display_name: &'a str,
    /// The validated `token_endpoint_auth_method` wire string
    /// (`client_secret_basic`, `client_secret_post`, `private_key_jwt`, or `none`).
    pub auth_method: &'a str,
    /// The SHA-256 (hex) of the generated client secret, for a confidential
    /// (`basic`/`post`) client; `None` for a public or `private_key_jwt` client.
    pub secret_hash: Option<&'a str>,
    /// The validated redirect URI set (already RFC 8252 / application-type
    /// checked by the OIDC layer; the repository re-checks registrability).
    pub redirect_uris: &'a [String],
    /// The RFC 8252 `application_type` (`web` or `native`).
    pub application_type: &'a str,
    /// The negotiated `id_token_signed_response_alg`.
    pub id_token_signed_response_alg: &'a str,
    /// The inline `jwks`, or `None` (mutually exclusive with `jwks_uri`).
    pub jwks: Option<&'a str>,
    /// The `jwks_uri`, or `None`.
    pub jwks_uri: Option<&'a str>,
    /// The pinned `token_endpoint_auth_signing_alg`, or `None`.
    pub token_endpoint_auth_signing_alg: Option<&'a str>,
    /// The SHA-256 (hex) of the freshly minted registration access token.
    pub registration_access_token_hash: &'a str,
    /// The base of the RFC 7592 client configuration endpoint
    /// (`{issuer}/connect/register`); the repository appends `/{client_id}` once
    /// the identifier is minted.
    pub registration_uri_base: &'a str,
    /// Whether the client starts under the unverified-client quarantine (issue
    /// #31): true for an open (or low-trust) self-service registration, false for
    /// one an admin policy or verification pre-clears.
    pub quarantined: bool,
    /// The resolved policy-chain snapshot (JSON primitive list as text) that bound
    /// this registration, persisted so RFC 7592 updates re-apply the SAME policy
    /// (issue #31); `None` when no policy applied.
    pub dcr_policy_chain: Option<&'a str>,
}

/// The result of a Dynamic Client Registration: the minted identifier and the RFC
/// 7592 client configuration endpoint URL built from it.
#[derive(Debug, Clone)]
pub struct DynamicClientRegistration {
    /// The freshly minted client identifier.
    pub id: ClientId,
    /// The RFC 7592 client configuration endpoint URL
    /// (`{issuer}/connect/register/{client_id}`).
    pub registration_client_uri: String,
}

/// The full-replacement parameters for an RFC 7592 update (issue #30), applied
/// through [`ActingClientRepo::update_dynamic`]. Every update ROTATES the
/// registration access token: the new hash is stored and the old hash no longer
/// matches. The client secret is deliberately NOT rotated by an update (it is kept
/// as registered), so this struct carries no secret.
#[derive(Debug, Clone, Copy)]
pub struct DynamicClientUpdate<'a> {
    /// The replacement `client_name` / display name (non-empty).
    pub display_name: &'a str,
    /// The replacement `token_endpoint_auth_method` wire string.
    pub auth_method: &'a str,
    /// The replacement redirect URI set (already validated by the OIDC layer; the
    /// repository re-checks registrability).
    pub redirect_uris: &'a [String],
    /// The replacement `application_type`.
    pub application_type: &'a str,
    /// The re-negotiated `id_token_signed_response_alg`.
    pub id_token_signed_response_alg: &'a str,
    /// The replacement inline `jwks`, or `None`.
    pub jwks: Option<&'a str>,
    /// The replacement `jwks_uri`, or `None`.
    pub jwks_uri: Option<&'a str>,
    /// The replacement pinned `token_endpoint_auth_signing_alg`, or `None`.
    pub token_endpoint_auth_signing_alg: Option<&'a str>,
    /// The SHA-256 (hex) of the NEWLY ROTATED registration access token.
    pub registration_access_token_hash: &'a str,
}

/// The read-only repository for tenant-scoped OAuth clients.
///
/// The scope is fixed at construction and applied to every statement; there is
/// no constructor or method that takes a tenant or environment argument. Writes
/// live on [`ActingClientRepo`], reachable only with an acting context.
pub struct ClientRepo<'a> {
    // Both fields private: no crate can retarget the scope or reach the pool.
    store: &'a Store,
    scope: Scope,
}

impl ClientRepo<'_> {
    /// Parse an untrusted client identifier under this repository's scope.
    ///
    /// This is the oracle-free boundary for request handlers: a malformed
    /// identifier and one belonging to another tenant both return the uniform
    /// [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<ClientId, StoreError> {
        Ok(ClientId::parse_in_scope(raw, &self.scope)?)
    }

    /// Fetch a client by identifier, within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such client is visible in this scope
    /// (absent, or belonging to another tenant or environment: the outcomes are
    /// indistinguishable).
    pub async fn get(&self, id: &ClientId) -> Result<ClientRecord, StoreError> {
        // Defense in depth: an identifier minted under another scope is a miss
        // here regardless of what the database would say.
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, display_name, require_auth_time, token_endpoint_auth_method, \
             redirect_uris, post_logout_redirect_uris, \
             frontchannel_logout_uri, frontchannel_logout_session_required, \
             consent_mode, skip_consent, \
             store_skipped_consent, \
             require_pushed_authorization_requests, quarantined FROM clients \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        self.row_to_record(&row)
    }

    /// List every client in this scope, oldest first.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(&self) -> Result<Vec<ClientRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, display_name, require_auth_time, token_endpoint_auth_method, \
             redirect_uris, post_logout_redirect_uris, \
             frontchannel_logout_uri, frontchannel_logout_session_required, \
             consent_mode, skip_consent, \
             store_skipped_consent, \
             require_pushed_authorization_requests, quarantined FROM clients \
             WHERE tenant_id = $1 AND environment_id = $2 ORDER BY created_at, id",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter().map(|row| self.row_to_record(row)).collect()
    }

    /// Count the dynamically registered (`dcr_registered`) clients in this scope
    /// (issue #31), for the per-environment registration quota. Counts only
    /// self-service DCR clients (the abuse surface the quota bounds), not clients
    /// created through the management API or the seeding paths.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn count_dynamic(&self) -> Result<i64, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let count: i64 = sqlx::query(
            "SELECT COUNT(*) AS n FROM clients \
             WHERE tenant_id = $1 AND environment_id = $2 AND dcr_registered = true",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_one(&mut *tx)
        .await?
        .get("n");
        tx.commit().await?;
        Ok(count)
    }

    /// Read a client's authentication metadata within scope (issue #20): its
    /// display name, its registered `token_endpoint_auth_method`, and the stored
    /// SHA-256 hash of its secret (or `None` for a public client). The token
    /// endpoint uses this to enforce the registered method and verify a presented
    /// secret. A client absent in this scope is the uniform
    /// [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such client is visible in this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn auth_record(&self, id: &ClientId) -> Result<ClientAuthRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT display_name, token_endpoint_auth_method, secret_hash, \
             jwks, jwks_uri, token_endpoint_auth_signing_alg, refresh_rotation FROM clients \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        Ok(ClientAuthRecord {
            display_name: row.get("display_name"),
            auth_method: row.get("token_endpoint_auth_method"),
            secret_hash: row.get("secret_hash"),
            jwks: row.get("jwks"),
            jwks_uri: row.get("jwks_uri"),
            token_endpoint_auth_signing_alg: row.get("token_endpoint_auth_signing_alg"),
            refresh_rotation: row.get("refresh_rotation"),
        })
    }

    /// The client's stored `id_token_signed_response_alg` within scope (issue #30),
    /// or `None` when the client expressed no per-client preference (a client that
    /// predates DCR, whose column is NULL) or is absent in this scope.
    ///
    /// The token endpoint reads this to sign THAT client's ID token with the
    /// algorithm the client negotiated at registration, so the algorithm DCR
    /// recorded and echoed is the algorithm the ID token is actually signed under.
    /// A `None` (absent or no preference) leaves the mint on the environment default
    /// signer, exactly as before DCR.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn id_token_signing_alg(&self, id: &ClientId) -> Result<Option<String>, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id_token_signed_response_alg FROM clients \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.and_then(|row| row.get::<Option<String>, _>("id_token_signed_response_alg")))
    }

    /// The client's stored STATIC custom-claims configuration within scope (issue
    /// #23), as the raw JSON text of the stored `custom_token_claims` JSONB, or
    /// `None` when the client configured none (the column is NULL) or is absent in
    /// this scope.
    ///
    /// The client-credentials mint reads this and embeds the object's members into
    /// the issued access token, with the protected-registered-claim guard applied
    /// in the mint (a custom claim can never override `iss`/`sub`/`aud`/`exp`/`iat`/
    /// `jti`/`client_id`/`scope`). The value is opaque JSON to the store; the OIDC
    /// layer parses and validates it.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn custom_token_claims(&self, id: &ClientId) -> Result<Option<String>, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // Read the JSONB back as text (::text) so the store stays agnostic to the
        // claim shape; the OIDC layer parses it.
        let row = sqlx::query(
            "SELECT custom_token_claims::text AS custom_token_claims FROM clients \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.and_then(|row| row.get::<Option<String>, _>("custom_token_claims")))
    }

    /// Read a client's RFC 8707 resource-indicator policy within scope (issue #28):
    /// its per-client allowed-resource allowlist and whether it refuses a
    /// no-`resource` request. A client absent in this scope (or minted in another) is
    /// the uniform [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope or no client
    /// matches; [`StoreError::Database`] on a persistence failure.
    pub async fn resource_policy(&self, id: &ClientId) -> Result<ClientResourcePolicy, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT allowed_resources, resource_indicator_policy FROM clients \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        // A NULL allowlist column is "no per-client allowlist"; a present one parses
        // to the exact (possibly empty) set. A parse failure falls SAFE to an empty
        // allowlist (the most restrictive reading), never to "no restriction".
        let allowed_resources = row
            .get::<Option<String>, _>("allowed_resources")
            .map(|text| serde_json::from_str::<Vec<String>>(&text).unwrap_or_default());
        let require_resource_indicator = row
            .get::<Option<String>, _>("resource_indicator_policy")
            .as_deref()
            == Some("refuse");
        Ok(ClientResourcePolicy {
            allowed_resources,
            require_resource_indicator,
        })
    }

    /// Read a dynamically registered client's stored configuration within scope
    /// (issue #30), for the RFC 7592 read/update/delete surface and for
    /// authenticating a presented registration access token.
    ///
    /// ONLY a DCR-origin client (`dcr_registered`) is a dynamic registration: a
    /// client created by any other path is the uniform [`StoreError::NotFound`]
    /// here, so the RFC 7592 endpoint cannot be turned into an oracle for the
    /// existence of a non-DCR client. A client absent in this scope (or minted in
    /// another) is likewise the uniform not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no DCR client with this identifier is visible in
    /// this scope; [`StoreError::Database`] on a persistence failure.
    pub async fn dynamic_registration(
        &self,
        id: &ClientId,
    ) -> Result<DynamicClientRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, display_name, token_endpoint_auth_method, redirect_uris, \
             application_type, id_token_signed_response_alg, jwks, jwks_uri, \
             token_endpoint_auth_signing_alg, registration_client_uri, \
             registration_access_token_hash, dcr_registered, \
             quarantined, dcr_policy_chain, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM verified_at) * 1000000)::bigint AS verified_us \
             FROM clients \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        // A client not created through dynamic registration is not manageable
        // through the RFC 7592 surface: report it as not found, uniformly.
        let dcr_registered: bool = row.get("dcr_registered");
        if !dcr_registered {
            return Err(StoreError::NotFound);
        }
        Ok(DynamicClientRecord {
            id: ClientId::parse_in_scope(&row.get::<String, _>("id"), &self.scope)?,
            display_name: row.get("display_name"),
            auth_method: row.get("token_endpoint_auth_method"),
            redirect_uris: row.get("redirect_uris"),
            application_type: row.get("application_type"),
            id_token_signed_response_alg: row.get("id_token_signed_response_alg"),
            jwks: row.get("jwks"),
            jwks_uri: row.get("jwks_uri"),
            token_endpoint_auth_signing_alg: row.get("token_endpoint_auth_signing_alg"),
            registration_client_uri: row.get("registration_client_uri"),
            registration_access_token_hash: row.get("registration_access_token_hash"),
            created_at_unix_micros: row.get("created_us"),
            quarantined: row.get("quarantined"),
            verified_at_unix_micros: row.get("verified_us"),
            dcr_policy_chain: row.get("dcr_policy_chain"),
        })
    }

    /// Turn a row into a [`ClientRecord`], reconstructing the typed identifier.
    fn row_to_record(&self, row: &PgRow) -> Result<ClientRecord, StoreError> {
        let id_text: String = row.get("id");
        // The row came back through the scope filter and row-level security, so
        // it is in scope by construction; re-parse to the typed identifier.
        let id = ClientId::parse_in_scope(&id_text, &self.scope)?;
        Ok(ClientRecord {
            id,
            display_name: row.get("display_name"),
            require_auth_time: row.get("require_auth_time"),
            auth_method: row.get("token_endpoint_auth_method"),
            redirect_uris: row.get("redirect_uris"),
            post_logout_redirect_uris: row.get("post_logout_redirect_uris"),
            frontchannel_logout_uri: row.get("frontchannel_logout_uri"),
            frontchannel_logout_session_required: row.get("frontchannel_logout_session_required"),
            consent_mode: row.get("consent_mode"),
            skip_consent: row.get("skip_consent"),
            store_skipped_consent: row.get("store_skipped_consent"),
            require_pushed_authorization_requests: row.get("require_pushed_authorization_requests"),
            quarantined: row.get("quarantined"),
        })
    }
}

/// The mutating repository for tenant-scoped OAuth clients.
///
/// Reachable only through [`ScopedStore::acting`], so every mutation carries an
/// actor and correlation id. Its mutators do not commit their own transactions;
/// they route through the module's single audited-write primitive, which is the
/// only committing write path and always writes the audit row in the same
/// transaction.
pub struct ActingClientRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingClientRepo<'_> {
    /// Create a client in this scope and return its fresh identifier. Writes a
    /// `client.create` audit row in the same transaction. The client is PUBLIC
    /// (its `token_endpoint_auth_method` defaults to `none`, no secret): a
    /// confidential client is created with [`create_confidential`](Self::create_confidential).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create(&self, env: &Env, display_name: &str) -> Result<ClientId, StoreError> {
        self.create_inner(env, display_name, false).await
    }

    /// Create a CONFIDENTIAL client that authenticates at the token endpoint with
    /// a secret (issue #20). `auth_method` is the wire string
    /// (`client_secret_basic` or `client_secret_post`) and `secret_hash` is the
    /// SHA-256 hex of the generated secret; the plaintext secret is shown once at
    /// creation by the caller and never reaches the database. Writes a
    /// `client.create` audit row in the same transaction, returning the fresh
    /// identifier.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create_confidential(
        &self,
        env: &Env,
        display_name: &str,
        auth_method: &str,
        secret_hash: &str,
    ) -> Result<ClientId, StoreError> {
        let id = ClientId::generate(env, &self.scope);
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientCreate,
                target: &id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO clients \
                     (id, tenant_id, environment_id, display_name, \
                      token_endpoint_auth_method, secret_hash) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(display_name)
                .bind(auth_method)
                .bind(secret_hash)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Set a client's device-authorization grant allowlist and display logo (issue
    /// #24). `grant_types` is the space-separated OAuth grant-type list (the device
    /// endpoint permits a client only when this contains the `device_code` URN, so the
    /// device grant is opt-in per client); `logo_uri` is the client's registered logo
    /// rendered on the verification page (the browser loads it), or [`None`] for no
    /// logo. Writes a `client.configure` audit row in the same transaction. Both
    /// columns are data-plane configuration, covered by the 0019 column-scoped grant.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the client id is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn set_device_grant(
        &self,
        env: &Env,
        client_id: &ClientId,
        grant_types: &str,
        logo_uri: Option<&str>,
    ) -> Result<(), StoreError> {
        if client_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let grant_types = grant_types.to_owned();
        let logo_uri = logo_uri.map(ToOwned::to_owned);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientConfigure,
                target: client_id,
            },
            async move |tx| {
                sqlx::query(
                    "UPDATE clients SET grant_types = $1, logo_uri = $2 \
                     WHERE id = $3 AND tenant_id = $4 AND environment_id = $5",
                )
                .bind(&grant_types)
                .bind(logo_uri.as_deref())
                .bind(client_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Create a client that authenticates at the token endpoint with a JWT
    /// assertion (issue #25): `private_key_jwt` (verification keys from `jwks`
    /// inline or `jwks_uri` by reference) or `client_secret_jwt`. No secret hash is
    /// stored (the asymmetric case keeps only public keys; the symmetric case is a
    /// documented, correctly-erroring path that stores no retrievable secret).
    /// `signing_alg` optionally pins the single JWS algorithm the client's
    /// assertions must be signed with. Writes a `client.create` audit row in the
    /// same transaction, returning the fresh identifier.
    ///
    /// A `private_key_jwt` client MUST register EXACTLY ONE key source (`jwks` XOR
    /// `jwks_uri`): a keyless one would register but fail EVERY request silently (no
    /// key to verify its assertion against), and two sources are ambiguous. The
    /// database CHECK `clients_private_key_jwt_has_one_key` (with the older
    /// `clients_client_keys_exclusive`) enforces this, so a misconfiguration fails
    /// LOUD as a [`StoreError::Conflict`] at registration rather than per request. A
    /// `client_secret_jwt` registration is refused outright here, because the method
    /// is inert (see `client_auth.rs`) and no key CHECK expresses it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if the method is the inert `client_secret_jwt`, or if
    /// a `private_key_jwt` client sets neither or both key sources (the key CHECK
    /// fails); [`StoreError::Database`] on a persistence failure.
    pub async fn create_jwt_auth(
        &self,
        env: &Env,
        client: NewJwtAuthClient<'_>,
    ) -> Result<ClientId, StoreError> {
        // client_secret_jwt is inert (IronAuth stores no retrievable secret to key
        // the HMAC; see client_auth.rs). Registering a client for it would silently
        // fail every request, and no DB CHECK expresses "reject this method", so
        // refuse the misconfiguration here at registration. The private_key_jwt
        // exactly-one-key rule is enforced by the DB CHECK below (mapped to Conflict).
        if client.auth_method == "client_secret_jwt" {
            return Err(StoreError::Conflict);
        }
        let id = ClientId::generate(env, &self.scope);
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientCreate,
                target: &id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "INSERT INTO clients \
                     (id, tenant_id, environment_id, display_name, \
                      token_endpoint_auth_method, jwks, jwks_uri, \
                      token_endpoint_auth_signing_alg) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(client.display_name)
                .bind(client.auth_method)
                .bind(client.jwks)
                .bind(client.jwks_uri)
                .bind(client.signing_alg)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => Ok(()),
                    // A key-source CHECK violation (both jwks and jwks_uri set, or a
                    // keyless private_key_jwt) is a caller-facing conflict, not a
                    // persistence fault.
                    Err(error) if is_check_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Delete a client by identifier, within scope. Writes a `client.delete`
    /// audit row in the same transaction; a no-op delete (nothing in scope
    /// matched) writes no audit row and rolls back.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such client is visible in this scope.
    pub async fn delete(&self, env: &Env, id: &ClientId) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientDelete,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "DELETE FROM clients \
                     WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                // A delete that matched nothing is a uniform not-found. Erroring
                // here short-circuits the audited write before the audit insert,
                // so a no-op delete leaves no audit row (we audit real mutations).
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Create a PUBLIC client that registered `require_auth_time` (issue #14):
    /// every ID token issued to it carries `auth_time` even without a `max_age`
    /// request. Writes a `client.create` audit row in the same transaction,
    /// returning the fresh identifier.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create_requiring_auth_time(
        &self,
        env: &Env,
        display_name: &str,
    ) -> Result<ClientId, StoreError> {
        let id = ClientId::generate(env, &self.scope);
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientCreate,
                target: &id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO clients \
                     (id, tenant_id, environment_id, display_name, require_auth_time) \
                     VALUES ($1, $2, $3, $4, true)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(display_name)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Register (replace) the set of redirect URIs a client is allowed to use, in
    /// scope (issue #13). Every URI is validated as an RFC 8252 redirect target
    /// ([`redirect_uri_is_registrable`](crate::redirect_uri_is_registrable)) BEFORE
    /// anything is written, so a malformed scheme is rejected at registration time
    /// (as it is at authorization time) and never enters the registered set. On
    /// success the client's `redirect_uris` become exactly `uris`, and a
    /// `client.redirect_uris.register` audit row is written in the same
    /// transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidRedirectUri`] if any entry is not a registrable
    /// redirect target (nothing is written); [`StoreError::NotFound`] if no such
    /// client is visible in this scope; [`StoreError::Database`] on a persistence
    /// failure.
    pub async fn register_redirect_uris(
        &self,
        env: &Env,
        id: &ClientId,
        uris: &[&str],
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        // Validate the whole set before touching the database, so a malformed
        // entry rejects the registration wholesale rather than storing a partial
        // set.
        for uri in uris {
            if !crate::redirect::redirect_uri_is_registrable(uri) {
                return Err(StoreError::InvalidRedirectUri);
            }
        }
        // The environment's TYPED guardrail (issue #42): a PROD environment
        // hard-requires https redirect URIs, so an http loopback that a dev/staging
        // environment accepts is rejected here BEFORE it enters the registered set.
        // Registrability is already established above, so the only remaining
        // guardrail failure is the production https-only rule.
        let guardrails = self
            .store
            .scoped(self.scope)
            .environment_guardrails()
            .guardrails()
            .await?;
        for uri in uris {
            if let Err(violation) = guardrails.check_redirect_uri(uri) {
                return Err(StoreError::GuardrailViolation(violation));
            }
        }
        let owned: Vec<String> = uris.iter().map(|uri| (*uri).to_owned()).collect();
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientRedirectUrisRegister,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients SET redirect_uris = $1 \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
                )
                .bind(&owned)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                // A no-op update (nothing in scope matched) is a uniform not-found;
                // erroring here short-circuits before the audit insert, so it
                // leaves no audit row (we audit real mutations only).
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Register a client's POST-LOGOUT redirect URIs (issue #33), replacing the set
    /// wholesale. Each entry is validated as an RFC 8252 redirect target by the SAME
    /// registrability rule the authorization redirect URIs use (a claimed https URL,
    /// an http loopback IP-literal, or a reverse-domain private-use scheme) BEFORE
    /// anything is written, so a malformed scheme is rejected at registration time and
    /// never enters the set. On success the client's `post_logout_redirect_uris` become
    /// exactly `uris`, and a `client.post_logout_redirect_uris.register` audit row is
    /// written in the same transaction.
    ///
    /// The RP-Initiated Logout endpoint honors a presented `post_logout_redirect_uri`
    /// only on an EXACT string match against this set AND only with a verifiable
    /// `id_token_hint`, so registering here is what lets a redirect ever happen; a
    /// client that registers none never gets a post-logout redirect.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidRedirectUri`] if any entry is not a registrable redirect
    /// target (nothing is written); [`StoreError::NotFound`] if no such client is
    /// visible in this scope; [`StoreError::Database`] on a persistence failure.
    pub async fn register_post_logout_redirect_uris(
        &self,
        env: &Env,
        id: &ClientId,
        uris: &[&str],
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        // Validate the whole set before touching the database, so a malformed entry
        // rejects the registration wholesale rather than storing a partial set.
        for uri in uris {
            if !crate::redirect::redirect_uri_is_registrable(uri) {
                return Err(StoreError::InvalidRedirectUri);
            }
        }
        let owned: Vec<String> = uris.iter().map(|uri| (*uri).to_owned()).collect();
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientPostLogoutRedirectUrisRegister,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients SET post_logout_redirect_uris = $1 \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
                )
                .bind(&owned)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                // A no-op update (nothing in scope matched) is a uniform not-found;
                // erroring here short-circuits before the audit insert, so it leaves
                // no audit row (we audit real mutations only).
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Register a client's OIDC Front-Channel Logout 1.0 opt-in (issue #39): its
    /// `frontchannel_logout_uri` (the endpoint the OP loads in a hidden iframe on
    /// logout so the RP clears its own session) and whether `iss` and the RP's OWN
    /// per-(client, session) `sid` must be appended
    /// (`frontchannel_logout_session_required`). Passing `uri = None` CLEARS the
    /// registration (the client then participates in no front-channel logout).
    ///
    /// A `Some` URI MUST be an `https` URL: OIDC Front-Channel Logout 1.0 requires it,
    /// and the value is loaded cross-origin in the end user's browser. It is validated
    /// BEFORE anything is written, so a non-`https` scheme is rejected at registration
    /// time and never enters the row. On success a
    /// `client.frontchannel_logout.register` audit row is written in the same
    /// transaction.
    ///
    /// This is the per-client half of the two-part gate; the environment
    /// `frontchannel_logout_enabled` flag is the other. With NO registered URI, the
    /// `end_session` flow never sends this client a front-channel iframe, even where
    /// the environment feature is enabled.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidRedirectUri`] if `uri` is `Some` and not an `https` URL
    /// (nothing is written); [`StoreError::NotFound`] if no such client is visible in
    /// this scope; [`StoreError::Database`] on a persistence failure.
    pub async fn register_frontchannel_logout(
        &self,
        env: &Env,
        id: &ClientId,
        uri: Option<&str>,
        session_required: bool,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        // A registered front-channel logout URI MUST be https (OIDC Front-Channel
        // Logout 1.0 section 2): it is loaded cross-origin in the end user's browser,
        // so a plaintext or non-http scheme is refused before anything is written.
        if let Some(uri) = uri {
            if !uri.starts_with("https://") {
                return Err(StoreError::InvalidRedirectUri);
            }
        }
        let owned_uri: Option<String> = uri.map(str::to_owned);
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientFrontchannelLogoutRegister,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients SET frontchannel_logout_uri = $1, \
                     frontchannel_logout_session_required = $2 \
                     WHERE id = $3 AND tenant_id = $4 AND environment_id = $5",
                )
                .bind(owned_uri.as_deref())
                .bind(session_required)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                // A no-op update (nothing in scope matched) is a uniform not-found;
                // erroring here short-circuits before the audit insert, so it leaves
                // no audit row (we audit real mutations only).
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Register a client's Back-Channel Logout endpoint (issue #34): the
    /// `backchannel_logout_uri` the OP POSTs a signed Logout Token to when the client's
    /// session ends, and the `backchannel_logout_session_required` flag. The URI is
    /// validated as an https target BEFORE anything is written (a back-channel POST is
    /// outbound and must be https; the SSRF-hardened fetcher blocks a private resolved
    /// address at delivery regardless). Passing `None` for the URI CLEARS the
    /// registration, so the client stops being a participant. Writes one
    /// `client.backchannel_logout.register` audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidRedirectUri`] if a present URI is not an https URL (nothing
    /// is written); [`StoreError::NotFound`] if the id is out of scope or no client
    /// matches; [`StoreError::Database`] on a persistence failure.
    pub async fn register_backchannel_logout(
        &self,
        env: &Env,
        id: &ClientId,
        uri: Option<&str>,
        session_required: bool,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        // A back-channel logout POST is outbound HTTPS: reject a non-https target at
        // registration (defense in depth; the fetcher still blocks a private resolved
        // address at delivery). An empty string is treated as absent.
        let uri = uri.filter(|value| !value.is_empty());
        if let Some(value) = uri {
            if !value.starts_with("https://") {
                return Err(StoreError::InvalidRedirectUri);
            }
        }
        let owned = uri.map(str::to_owned);
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientBackchannelLogoutRegister,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients \
                     SET backchannel_logout_uri = $1, backchannel_logout_session_required = $2 \
                     WHERE id = $3 AND tenant_id = $4 AND environment_id = $5",
                )
                .bind(owned.as_deref())
                .bind(session_required)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Configure a client's consent mode and refresh-rotation policy (issue #21) in
    /// one audited update.
    ///
    /// `consent_mode` is `explicit` (always prompt unless a covering consent
    /// exists), `implicit` (trusted first-party: never prompt, auto-grant), or
    /// `remembered` (prompt, then honor the recorded consent for the TTL).
    /// `skip_consent` is the orthogonal quick knob (skip the screen like
    /// `implicit`); `store_skipped_consent` is whether a skipped consent still
    /// persists a row (the Ory Hydra performance knob). `refresh_rotation` overrides
    /// the rotation policy: `Some("always")`, `Some("threshold")`, or `None` to
    /// derive it from the client's posture. Writes one `client.configure` audit row
    /// in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the id is out of scope or no client matches;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn configure_policy(
        &self,
        env: &Env,
        id: &ClientId,
        consent_mode: &str,
        skip_consent: bool,
        store_skipped_consent: bool,
        refresh_rotation: Option<&str>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let consent_mode = consent_mode.to_owned();
        let refresh_rotation = refresh_rotation.map(str::to_owned);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientConfigure,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients \
                     SET consent_mode = $1, skip_consent = $2, \
                         store_skipped_consent = $3, refresh_rotation = $4 \
                     WHERE id = $5 AND tenant_id = $6 AND environment_id = $7",
                )
                .bind(&consent_mode)
                .bind(skip_consent)
                .bind(store_skipped_consent)
                .bind(refresh_rotation.as_deref())
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Set a client's RFC 8707 resource-indicator policy (issue #28): its per-client
    /// allowed-resource allowlist and whether it refuses a no-`resource` request.
    /// Writes a `client.resource_indicator_policy.set` audit row in the same
    /// transaction.
    ///
    /// `allowed_resources` is [`None`] to CLEAR the per-client allowlist (the client
    /// may then request any registered resource server), or [`Some`] to set the exact
    /// allowlist (an empty slice means the client may request NO resource).
    /// `require_resource_indicator` maps to the stored `refuse` / `default_audience`
    /// policy string. Only the two resource-indicator columns are touched, under the
    /// migration's column-scoped `UPDATE` grant.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the id is out of scope or no client matches;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn set_resource_indicator_policy(
        &self,
        env: &Env,
        id: &ClientId,
        allowed_resources: Option<&[String]>,
        require_resource_indicator: bool,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        // The store owns the JSON encoding of the allowlist (a Some(empty) allowlist
        // is a real, restrictive value, so it is stored as `[]`, distinct from a NULL
        // "no allowlist"). The policy column is the wire string the CHECK permits.
        let allowed_json = allowed_resources
            .map(|values| serde_json::to_string(values).unwrap_or_else(|_| "[]".to_owned()));
        let policy = if require_resource_indicator {
            "refuse"
        } else {
            "default_audience"
        };
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientResourceIndicatorPolicySet,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients \
                     SET allowed_resources = $1, resource_indicator_policy = $2 \
                     WHERE id = $3 AND tenant_id = $4 AND environment_id = $5",
                )
                .bind(allowed_json.as_deref())
                .bind(policy)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Set (or clear) a client's `require_pushed_authorization_requests` flag (RFC
    /// 9126 section 5, issue #27), auditing
    /// `client.require_pushed_authorization_requests.set` in the same transaction.
    /// When set, the authorization endpoint rejects a plain (non-PAR) request from
    /// this client. Dynamic Client Registration (#30) and the management surface
    /// reuse this; today it is the one path that toggles the per-client requirement.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such client is visible in this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn set_require_pushed_authorization_requests(
        &self,
        env: &Env,
        id: &ClientId,
        required: bool,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientRequirePushedAuthorizationSet,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients SET require_pushed_authorization_requests = $1 \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
                )
                .bind(required)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Set (or clear) a client's STATIC custom-claims configuration within scope
    /// (issue #23), writing a `client.custom_claims.set` audit row in the same
    /// transaction.
    ///
    /// `claims_json` is the JSON text of a claims OBJECT to embed into the client's
    /// client-credentials access tokens, or `None` to clear the configuration. The
    /// store persists it verbatim as JSONB (an invalid document is rejected by the
    /// JSONB cast as [`StoreError::Database`], defense in depth). The store does NOT
    /// filter protected registered claim names: the MINT is the SINGLE enforcement
    /// point for the protected-claim guard (a custom claim can never set a reserved
    /// name, per `PROTECTED_ACCESS_TOKEN_CLAIMS` in the OIDC layer), so the guard
    /// holds even for a value written straight into this column. A client absent in
    /// this scope is the uniform [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such client is visible in this scope;
    /// [`StoreError::Database`] on a persistence failure (including a malformed JSON
    /// document).
    pub async fn set_custom_token_claims(
        &self,
        env: &Env,
        id: &ClientId,
        claims_json: Option<&str>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let claims_json = claims_json.map(str::to_owned);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientCustomClaimsSet,
                target: id,
            },
            async move |tx| {
                // The bind is text; the ::jsonb cast validates it is a JSON document
                // (a malformed value fails here rather than at read time). NULL
                // clears the configuration.
                let result = sqlx::query(
                    "UPDATE clients SET custom_token_claims = $1::jsonb \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
                )
                .bind(claims_json)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Register a client through Dynamic Client Registration (issue #30, RFC
    /// 7591), returning the minted identifier and the RFC 7592 client
    /// configuration endpoint URL. Writes a `client.registered` audit row in the
    /// same transaction.
    ///
    /// The OIDC layer has already validated the metadata, negotiated the
    /// `id_token_signed_response_alg`, generated and hashed the client secret and
    /// the registration access token, and fetched any `jwks_uri` through the
    /// SSRF-hardened fetcher. The repository re-validates every redirect URI as an
    /// RFC 8252 registrable target (defense in depth) BEFORE any write, stores the
    /// hashes (never a plaintext credential), marks the row `dcr_registered`, and
    /// builds `registration_client_uri` from the freshly minted identifier.
    ///
    /// `max_clients` is the per-environment registered-client quota (issue #31):
    /// `Some(n)` enforces it ATOMICALLY inside this transaction under a per-scope
    /// advisory lock, so two concurrent registrations cannot both slip past the cap
    /// (only DCR registrations take the lock, so it serializes register-vs-register
    /// only, per scope). `None` skips the quota (unbounded).
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidRedirectUri`] if any redirect URI is not registrable
    /// (nothing is written); [`StoreError::QuotaExceeded`] if the environment is at
    /// its registered-client cap (nothing is written); [`StoreError::Conflict`] if a
    /// `private_key_jwt` registration violates the key-source CHECK (both or neither
    /// of `jwks`/`jwks_uri`); [`StoreError::Database`] on a persistence failure.
    pub async fn register_dynamic(
        &self,
        env: &Env,
        params: NewDynamicClient<'_>,
        max_clients: Option<i64>,
    ) -> Result<DynamicClientRegistration, StoreError> {
        for uri in params.redirect_uris {
            if !crate::redirect::redirect_uri_is_registrable(uri) {
                return Err(StoreError::InvalidRedirectUri);
            }
        }
        let id = ClientId::generate(env, &self.scope);
        let registration_client_uri = format!(
            "{}/{}",
            params.registration_uri_base.trim_end_matches('/'),
            id
        );
        let scope = self.scope;
        let redirect_uris: Vec<String> = params.redirect_uris.to_vec();
        let client_uri = registration_client_uri.clone();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientRegistered,
                target: &id,
            },
            async move |tx| {
                // Enforce the quota atomically: take a per-scope advisory lock (held
                // until this transaction commits or rolls back) so a concurrent pair
                // of registrations serialize, then count and compare inside the same
                // transaction as the INSERT. This is the ONLY user of the TWO-argument
                // advisory-lock space keyed on the two scope strings; the
                // config-promotion apply deliberately uses the single-argument form
                // (a disjoint lock space), so the two operations never contend.
                if let Some(max) = max_clients {
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
                        .bind(scope.tenant().to_string())
                        .bind(scope.environment().to_string())
                        .execute(&mut **tx)
                        .await?;
                    let count: i64 = sqlx::query(
                        "SELECT COUNT(*) AS n FROM clients \
                         WHERE tenant_id = $1 AND environment_id = $2 \
                         AND dcr_registered = true",
                    )
                    .bind(scope.tenant().to_string())
                    .bind(scope.environment().to_string())
                    .fetch_one(&mut **tx)
                    .await?
                    .get("n");
                    if count >= max {
                        return Err(StoreError::QuotaExceeded);
                    }
                }
                let result = sqlx::query(
                    "INSERT INTO clients \
                     (id, tenant_id, environment_id, display_name, \
                      token_endpoint_auth_method, secret_hash, redirect_uris, \
                      application_type, id_token_signed_response_alg, jwks, jwks_uri, \
                      token_endpoint_auth_signing_alg, registration_client_uri, \
                      registration_access_token_hash, quarantined, dcr_policy_chain, \
                      dcr_registered) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                             $15, $16, true)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(params.display_name)
                .bind(params.auth_method)
                .bind(params.secret_hash)
                .bind(&redirect_uris)
                .bind(params.application_type)
                .bind(params.id_token_signed_response_alg)
                .bind(params.jwks)
                .bind(params.jwks_uri)
                .bind(params.token_endpoint_auth_signing_alg)
                .bind(&client_uri)
                .bind(params.registration_access_token_hash)
                .bind(params.quarantined)
                .bind(params.dcr_policy_chain)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => Ok(()),
                    // A key-source CHECK violation (both jwks and jwks_uri, or a
                    // keyless private_key_jwt) is a caller-facing conflict.
                    Err(error) if is_check_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await?;
        Ok(DynamicClientRegistration {
            id,
            registration_client_uri,
        })
    }

    /// Apply an RFC 7592 update to a dynamically registered client (issue #30),
    /// ROTATING its registration access token in the same transaction. Writes a
    /// `client.updated` audit row.
    ///
    /// This is a full replacement of the DCR-managed metadata (display name, auth
    /// method, redirect URIs, application type, negotiated algorithm, and the
    /// `jwks`/`jwks_uri` pair) PLUS a mandatory registration-access-token rotation:
    /// `registration_access_token_hash` becomes the new hash, so the superseded
    /// token stops matching immediately. The client SECRET is deliberately left
    /// unchanged. The `WHERE` clause filters on `dcr_registered`, so only a
    /// DCR-origin client is updatable through this path.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidRedirectUri`] if any redirect URI is not registrable
    /// (nothing is written); [`StoreError::NotFound`] if no DCR client with this
    /// identifier is visible in this scope; [`StoreError::Conflict`] on a key-source
    /// CHECK violation; [`StoreError::Database`] on a persistence failure.
    pub async fn update_dynamic(
        &self,
        env: &Env,
        id: &ClientId,
        update: DynamicClientUpdate<'_>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        for uri in update.redirect_uris {
            if !crate::redirect::redirect_uri_is_registrable(uri) {
                return Err(StoreError::InvalidRedirectUri);
            }
        }
        let scope = self.scope;
        let redirect_uris: Vec<String> = update.redirect_uris.to_vec();
        // When the update transitions the client to a method that carries no
        // secret (`none` / `private_key_jwt`), NULL out any stored `secret_hash`
        // so no dead credential material lingers. Only the two secret-based methods
        // keep the existing hash (an update never mints a new secret, and the
        // validation layer already refuses a transition INTO a secret method for a
        // client that has none).
        let keep_secret = matches!(
            update.auth_method,
            "client_secret_basic" | "client_secret_post"
        );
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientUpdated,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients SET display_name = $1, token_endpoint_auth_method = $2, \
                     redirect_uris = $3, application_type = $4, \
                     id_token_signed_response_alg = $5, jwks = $6, jwks_uri = $7, \
                     token_endpoint_auth_signing_alg = $8, registration_access_token_hash = $9, \
                     secret_hash = CASE WHEN $13 THEN secret_hash ELSE NULL END \
                     WHERE id = $10 AND tenant_id = $11 AND environment_id = $12 \
                     AND dcr_registered = true",
                )
                .bind(update.display_name)
                .bind(update.auth_method)
                .bind(&redirect_uris)
                .bind(update.application_type)
                .bind(update.id_token_signed_response_alg)
                .bind(update.jwks)
                .bind(update.jwks_uri)
                .bind(update.token_endpoint_auth_signing_alg)
                .bind(update.registration_access_token_hash)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(keep_secret)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(outcome) if outcome.rows_affected() == 0 => Err(StoreError::NotFound),
                    Ok(_) => Ok(()),
                    Err(error) if is_check_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await
    }

    /// Verify a dynamically registered client (issue #31), lifting its
    /// unverified-client quarantine: sets `quarantined = false` and stamps
    /// `verified_at` from the application clock seam, in one audited update
    /// (`dcr.client_verified`). Idempotent: verifying an already-verified client
    /// re-stamps `verified_at`. Filters on `dcr_registered`, so only a DCR-origin
    /// client is verifiable through this path.
    ///
    /// `idempotency` writes the caller's Idempotency-Key replay row in the SAME
    /// transaction as the verify and its audit row.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no DCR client with this identifier is visible in
    /// this scope; [`StoreError::IdempotencyConflict`] if a concurrent request
    /// already stored this Idempotency-Key; [`StoreError::Database`] on a persistence
    /// failure.
    pub async fn verify_dynamic_client(
        &self,
        env: &Env,
        id: &ClientId,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let verified_micros = epoch_micros(env.clock().now_utc());
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::DcrClientVerified,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE clients \
                     SET quarantined = false, \
                         verified_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
                     AND dcr_registered = true",
                )
                .bind(verified_micros)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Record a DCR abuse-control audit event (issue #31) that has no data change
    /// of its own: a policy rejection, a quota hit, or a rate-limit hit. These are
    /// security events the SIEM stream must see even though no row is mutated, so
    /// they route through the audited-write primitive with a no-op mutation and a
    /// typed `action` and `target` (the offending initial access token, or the
    /// environment). This is the ONE deliberate exception to "audit real mutations
    /// only": an abuse refusal is itself the event of record.
    ///
    /// `detail` is an OPTIONAL operator-safe dimension recorded on the row (a policy
    /// rejection passes the offending property name so an operator reading the audit
    /// table alone gets the actionable reason). It is never attacker-controlled free
    /// text; the wire response stays opaque regardless.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn record_dcr_event<T: AuditTarget>(
        &self,
        env: &Env,
        action: Action,
        target: &T,
        detail: Option<&str>,
    ) -> Result<(), StoreError> {
        write_audited_detailed(
            AuditedWrite {
                store: self.store,
                scope: self.scope,
                acting: &self.acting,
                env,
                action,
                target,
            },
            async move |_tx| Ok(()),
            false,
            detail,
        )
        .await
    }

    /// Shared body of the client-create path. `poison_after_audit` is always
    /// `false` for the public mutator; the testing-only atomicity probe passes
    /// `true` to force a rollback after the data and audit inserts.
    async fn create_inner(
        &self,
        env: &Env,
        display_name: &str,
        poison_after_audit: bool,
    ) -> Result<ClientId, StoreError> {
        let id = ClientId::generate(env, &self.scope);
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientCreate,
                target: &id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO clients (id, tenant_id, environment_id, display_name) \
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(display_name)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            poison_after_audit,
        )
        .await?;
        Ok(id)
    }

    /// Testing-only atomicity probe: run a real `create` (the client insert and
    /// its audit insert), then force a guaranteed error inside the same
    /// transaction, so a test can assert that neither the client row nor the
    /// audit row survives. This exercises the exact production write path plus a
    /// trailing poison statement; the public [`create`](Self::create) never
    /// poisons. It always returns an error.
    ///
    /// # Errors
    ///
    /// Always errors (that is the point): the injected failure rolls the whole
    /// transaction back.
    #[cfg(feature = "testing")]
    pub async fn create_injecting_post_audit_failure(
        &self,
        env: &Env,
        display_name: &str,
    ) -> Result<ClientId, StoreError> {
        self.create_inner(env, display_name, true).await
    }
}

// ===========================================================================
// Dynamic Client Registration abuse controls (issue #31).
//
// The named, reusable policy objects, the SHA-256-hashed initial access tokens,
// and the endpoint-local rate counters that WRAP the issue-#30 registration
// endpoint. All three tables are tenant-scoped with forced row-level security and
// route through the SAME scope filter as the rest of the data plane. Policy
// authoring and token minting are audited business mutations; token consume and
// the rate counter are credential/counter caches off the audited-write path.
// ===========================================================================

/// A named, reusable DCR policy object read back within scope (issue #31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcrPolicyRecord {
    /// The policy identifier (`pol_...`, embeds its scope).
    pub id: DcrPolicyId,
    /// The operator-facing policy name, unique per scope.
    pub name: String,
    /// The ordered primitive list as JSON text (parsed by the OIDC policy engine).
    pub primitives: String,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// The parameters to create a DCR policy (issue #31).
#[derive(Debug, Clone, Copy)]
pub struct NewDcrPolicy<'a> {
    /// The policy name (unique per scope).
    pub name: &'a str,
    /// The ordered primitive list as JSON text (already validated by the caller).
    pub primitives: &'a str,
}

/// The result of consuming a DCR initial access token (issue #31): the token's
/// identifier and its resolved policy-chain snapshot (JSON primitive list as text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedInitialAccessToken {
    /// The consumed token's identifier.
    pub id: InitialAccessTokenId,
    /// The token's policy-chain snapshot (JSON primitive list as text; `"[]"` for
    /// an unconstrained token).
    pub policy_chain: String,
}

/// The parameters to mint a DCR initial access token (issue #31). The OIDC/admin
/// layer has already generated the plaintext token, hashed it, and resolved the
/// attached policy chain to its primitive snapshot; the repository stores the hash
/// (never the plaintext) and mints the identifier.
#[derive(Debug, Clone, Copy)]
pub struct NewInitialAccessToken<'a> {
    /// The SHA-256 (hex) of the plaintext token. The plaintext is NEVER stored.
    pub token_hash: &'a str,
    /// The resolved policy-chain snapshot as JSON text (`"[]"` for unconstrained).
    pub policy_chain: &'a str,
    /// The token's expiry in microseconds since the Unix epoch (from the clock seam).
    pub expires_at_unix_micros: i64,
    /// The maximum number of registrations the token may authorize, or `None` for
    /// unlimited (within the expiry).
    pub max_uses: Option<i32>,
}

/// The read-only DCR policy repository (issue #31), scope-fixed at construction.
pub struct DcrPolicyRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl DcrPolicyRepo<'_> {
    /// Parse an untrusted policy identifier under this scope (the oracle-free
    /// boundary: a malformed or cross-scope id is the uniform not-found).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<DcrPolicyId, StoreError> {
        Ok(DcrPolicyId::parse_in_scope(raw, &self.scope)?)
    }

    /// Resolve a policy by NAME within scope (issue #31), returning its primitive
    /// list. Used when minting an initial access token to resolve an attached
    /// policy chain to its snapshot. A name absent in this scope is
    /// [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no policy of that name is visible in this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn by_name(&self, name: &str) -> Result<DcrPolicyRecord, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, name, primitives, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM dcr_policies \
             WHERE name = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(name)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        self.row_to_record(&row)
    }

    /// List the policies in this scope, oldest first, for keyset pagination (issue
    /// #31): `limit` rows after the optional `after` cursor.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<DcrPolicyRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let capped = limit.clamp(1, MANAGEMENT_LIST_HARD_CAP + 1);
        let rows = match after {
            Some(cursor) => {
                sqlx::query(
                    "SELECT id, name, primitives, \
                     (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
                     FROM dcr_policies \
                     WHERE tenant_id = $1 AND environment_id = $2 \
                     AND (created_at, id) > \
                         (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4) \
                     ORDER BY created_at, id LIMIT $5",
                )
                .bind(self.scope.tenant().to_string())
                .bind(self.scope.environment().to_string())
                .bind(cursor.created_at_unix_micros)
                .bind(&cursor.id)
                .bind(capped)
                .fetch_all(&mut *tx)
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT id, name, primitives, \
                     (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
                     FROM dcr_policies \
                     WHERE tenant_id = $1 AND environment_id = $2 \
                     ORDER BY created_at, id LIMIT $3",
                )
                .bind(self.scope.tenant().to_string())
                .bind(self.scope.environment().to_string())
                .bind(capped)
                .fetch_all(&mut *tx)
                .await?
            }
        };
        tx.commit().await?;
        rows.iter().map(|row| self.row_to_record(row)).collect()
    }

    /// List EVERY policy in this scope, ordered by `name` (issue #43). The name is
    /// unique per scope, so this is a total, stable order with no volatile
    /// tiebreaker (unlike the cursor-paginated [`Self::list`], which orders by
    /// `created_at` for keyset pagination). The canonical snapshot export
    /// (`crate::snapshot`) reads it to emit the promotable DCR-policy set
    /// deterministically, independent of insertion time.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list_all(&self) -> Result<Vec<DcrPolicyRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, name, primitives, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM dcr_policies \
             WHERE tenant_id = $1 AND environment_id = $2 \
             ORDER BY name",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter().map(|row| self.row_to_record(row)).collect()
    }

    fn row_to_record(&self, row: &PgRow) -> Result<DcrPolicyRecord, StoreError> {
        Ok(DcrPolicyRecord {
            id: DcrPolicyId::parse_in_scope(&row.get::<String, _>("id"), &self.scope)?,
            name: row.get("name"),
            primitives: row.get("primitives"),
            created_at_unix_micros: row.get("created_us"),
        })
    }
}

/// The mutating DCR policy repository (issue #31), reachable only with an acting
/// context so every create carries an actor and correlation id into its audit row.
pub struct ActingDcrPolicyRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingDcrPolicyRepo<'_> {
    /// Create a named, reusable DCR policy object (issue #31), auditing
    /// `dcr.policy_created` in the same transaction. Returns the minted identifier.
    ///
    /// `idempotency` writes the caller's Idempotency-Key replay row in the SAME
    /// transaction as the create and its audit row.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if a policy of the same name already exists in this
    /// scope; [`StoreError::IdempotencyConflict`] if a concurrent request already
    /// stored this Idempotency-Key; [`StoreError::Database`] on a persistence failure.
    /// The `id` and `created_at_micros` are supplied by the caller (minted from the
    /// entropy seam and the clock seam), so the HTTP response can be built before the
    /// write and stored verbatim for idempotent replay, exactly like the management
    /// create paths.
    pub async fn create(
        &self,
        env: &Env,
        id: &DcrPolicyId,
        created_at_micros: i64,
        params: NewDcrPolicy<'_>,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let id = *id;
        let scope = self.scope;
        let created_micros = created_at_micros;
        let name = params.name.to_owned();
        let primitives = params.primitives.to_owned();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::DcrPolicyCreate,
                target: &id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "INSERT INTO dcr_policies \
                     (id, tenant_id, environment_id, name, primitives, created_at) \
                     VALUES ($1, $2, $3, $4, $5, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&name)
                .bind(&primitives)
                .bind(created_micros)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => {}
                    Err(error) if is_unique_violation(&error) => return Err(StoreError::Conflict),
                    Err(error) => return Err(error.into()),
                }
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }
}

/// The DCR initial-access-token repository (issue #31): CONSUME only. Minting is
/// the audited [`ActingInitialAccessTokenRepo`]. Consume is a credential-use
/// counter (not a business mutation), so it commits its own transaction off the
/// audited-write path, exactly like the jti replay cache.
pub struct InitialAccessTokenRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl InitialAccessTokenRepo<'_> {
    /// Atomically consume a presented initial access token by its hash (issue #31):
    /// increment its use count IF it is unexpired and under its usage limit, all in
    /// one UPDATE so a usage limit cannot be raced past. Returns the consumed
    /// token's id and policy-chain snapshot on success, or [`StoreError::NotFound`]
    /// when the hash matches no token, the token is expired, or its usage limit is
    /// already reached (all indistinguishable, so the endpoint is never an oracle).
    ///
    /// `now_micros` comes from the application clock seam, so expiry is deterministic
    /// under a manual clock in tests.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no usable token matches; [`StoreError::Database`]
    /// on a persistence failure.
    pub async fn consume(
        &self,
        token_hash: &str,
        now_micros: i64,
    ) -> Result<ConsumedInitialAccessToken, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "UPDATE dcr_initial_access_tokens \
             SET use_count = use_count + 1 \
             WHERE token_hash = $1 AND tenant_id = $2 AND environment_id = $3 \
             AND expires_at > TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
             AND (max_uses IS NULL OR use_count < max_uses) \
             RETURNING id, policy_chain",
        )
        .bind(token_hash)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(now_micros)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        Ok(ConsumedInitialAccessToken {
            id: InitialAccessTokenId::parse_in_scope(&row.get::<String, _>("id"), &self.scope)?,
            policy_chain: row.get("policy_chain"),
        })
    }
}

/// The mutating DCR initial-access-token repository (issue #31): MINT only, audited.
pub struct ActingInitialAccessTokenRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingInitialAccessTokenRepo<'_> {
    /// Mint an initial access token (issue #31), storing only its hash and its
    /// resolved policy-chain snapshot, and auditing `dcr.iat_minted` in the same
    /// transaction. Returns the minted identifier. The plaintext token is generated
    /// and returned by the caller; it never touches the database.
    ///
    /// `idempotency` writes the caller's Idempotency-Key replay row in the SAME
    /// transaction as the mint and its audit row, so a retried mint returns the
    /// original (no-plaintext) response and mints no second token.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] on a token-hash collision (a 256-bit-entropy token
    /// makes this effectively impossible); [`StoreError::IdempotencyConflict`] if a
    /// concurrent request already stored this Idempotency-Key;
    /// [`StoreError::Database`] on a persistence failure.
    /// The `id` and `created_at_micros` are supplied by the caller (minted from the
    /// entropy and clock seams), so the HTTP response can be built before the write
    /// and stored verbatim for idempotent replay, exactly like the management create
    /// paths.
    pub async fn mint(
        &self,
        env: &Env,
        id: &InitialAccessTokenId,
        created_at_micros: i64,
        params: NewInitialAccessToken<'_>,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let id = *id;
        let scope = self.scope;
        let created_micros = created_at_micros;
        let token_hash = params.token_hash.to_owned();
        let policy_chain = params.policy_chain.to_owned();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::DcrInitialAccessTokenMint,
                target: &id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "INSERT INTO dcr_initial_access_tokens \
                     (id, tenant_id, environment_id, token_hash, policy_chain, \
                      expires_at, max_uses, use_count, created_at) \
                     VALUES ($1, $2, $3, $4, $5, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                             $7, 0, \
                             TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&token_hash)
                .bind(&policy_chain)
                .bind(params.expires_at_unix_micros)
                .bind(params.max_uses)
                .bind(created_micros)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => {}
                    Err(error) if is_unique_violation(&error) => return Err(StoreError::Conflict),
                    Err(error) => return Err(error.into()),
                }
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }
}

/// The endpoint-local DCR registration rate limiter (issue #31): a fixed-window
/// counter per (scope, key). A counter cache, not a business mutation, so it
/// commits its own transaction off the audited-write path (like `idempotency_keys`).
pub struct DcrRateLimiterRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl DcrRateLimiterRepo<'_> {
    /// Record one hit against `rate_key` in the current fixed window and report
    /// whether it is WITHIN `limit` (issue #31). The upsert either starts a fresh
    /// window (when the stored window has rolled over) or increments the current
    /// one, atomically, so concurrent registrations cannot race past the limit. The
    /// window is `window_secs` seconds long and both the now-instant and the rollover
    /// comparison use the application clock seam (`now_micros`), so it is
    /// deterministic under a manual clock in tests.
    ///
    /// Returns `true` when the post-increment count is at or below `limit` (the
    /// request is allowed) and `false` when it exceeds it (rate limited). A
    /// `limit` of 0 disables the check (always allowed).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn check_and_increment(
        &self,
        rate_key: &str,
        limit: i64,
        window_secs: i64,
        now_micros: i64,
    ) -> Result<bool, StoreError> {
        if limit <= 0 {
            return Ok(true);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let count: i32 = sqlx::query(
            "INSERT INTO dcr_rate_counters \
             (tenant_id, environment_id, rate_key, window_start, count) \
             VALUES ($1, $2, $3, \
                     TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval, 1) \
             ON CONFLICT (tenant_id, environment_id, rate_key) DO UPDATE SET \
                 count = CASE \
                     WHEN dcr_rate_counters.window_start + ($5::text || ' seconds')::interval \
                          <= TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
                     THEN 1 ELSE dcr_rate_counters.count + 1 END, \
                 window_start = CASE \
                     WHEN dcr_rate_counters.window_start + ($5::text || ' seconds')::interval \
                          <= TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
                     THEN TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
                     ELSE dcr_rate_counters.window_start END \
             RETURNING count",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(rate_key)
        .bind(now_micros)
        .bind(window_secs)
        .fetch_one(&mut *tx)
        .await?
        .get("count");
        tx.commit().await?;
        Ok(i64::from(count) <= limit)
    }
}

// ===========================================================================
// OIDC authorization-code grant (issue #12).
//
// The data-plane, tenant-scoped persistence behind the public authorization and
// token endpoints: the single-use authorization codes, the grants that are the
// revocation spine, and the issued-token records that make grant-chain
// revocation observable. Everything below routes through the SAME scope filter
// and (for writes) the SAME audited-write primitive as the rest of the data
// plane, so the OIDC surface is isolated by construction like every other one.
// ===========================================================================

/// The kind of an issued token: an access token or an ID token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// An access token (`at+jwt`).
    Access,
    /// An ID token.
    Id,
}

impl TokenKind {
    /// The stable wire string recorded in `issued_tokens.token_kind`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenKind::Access => "access",
            TokenKind::Id => "id",
        }
    }
}

/// One token to record against a grant when it is issued.
#[derive(Debug, Clone, Copy)]
pub struct IssuedTokenRecord {
    /// The token identifier (its `jti`), embedding its scope.
    pub id: IssuedTokenId,
    /// Whether it is an access or an ID token.
    pub kind: TokenKind,
}

/// The active state of an issued token, derived from its grant's revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStatus {
    /// The token's issued row exists and its grant is not revoked.
    Active,
    /// The token's issued row exists but its grant chain was revoked.
    Revoked,
    /// No issued token with this identifier is recorded in scope.
    Unknown,
}

/// An access token resolved from its `jti` back to the grant it was issued from
/// (issue #15). The `UserInfo` endpoint resolves the presented Bearer token's
/// `jti` through this so it can build the response from the AUTHORITATIVE grant
/// state (the local subject and the client), and honor grant-chain revocation.
///
/// The lookup is scope-bound (the `jti` embeds its own scope, the query filters
/// on it, and row-level security sits beneath), so an access token minted in one
/// environment never resolves under another. It matches ONLY the access-token
/// row (`token_kind = 'access'`), so an ID token's `jti` never resolves here.
///
/// [`fmt::Debug`] is hand written and redacting: `subject` is end-user detail
/// that must not reach a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessTokenResolution {
    /// The local end-user subject the grant was issued for (a `usr_` id string).
    /// This is the input to the SHARED subject-derivation function, so `UserInfo`
    /// derives a `sub` byte-identical to the one the ID token carried.
    pub subject: String,
    /// The OAuth client the grant (and thus the token) belongs to.
    pub client_id: String,
    /// The canonical JSON form of the `claims` request parameter frozen onto the
    /// grant (OIDC Core 5.5), or [`None`] when the request carried none. `UserInfo`
    /// applies its `userinfo` member to the response (issue #15).
    pub claims_request: Option<String>,
    /// Whether the grant chain is live (not revoked): a revoked grant flips every
    /// one of its tokens inactive, so `UserInfo` must reject the token.
    pub active: bool,
}

impl fmt::Debug for AccessTokenResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessTokenResolution")
            .field("client_id", &self.client_id)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

/// The revocation-relevant locator for a presented access token (issue #22): the
/// GRANT it hangs off (the revocation spine) and the CLIENT that owns it.
///
/// The RFC 7009 revocation endpoint reads this to decide two things WITHOUT an
/// existence oracle: whether the presented token belongs to the CLIENT that
/// authenticated (a token owned by a different client is treated as unknown), and
/// which grant to revoke. Because the append-only `issued_tokens` /
/// `opaque_access_tokens` rows derive their active state ONLY from
/// `grants.revoked_at`, revoking a token is revoking its grant chain, so the
/// `grant_id` here is the revocation target. `grant_id` is [`None`] only for an
/// opaque token minted outside the authorization-code flow (a `grant_id`-NULL row,
/// which the current mint never produces); such a token has no grant spine to
/// revoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantOwner {
    /// The grant the token hangs off, when one is recorded. Revoking it flips the
    /// active state of every token derived from it (RFC 7009 cascade).
    pub grant_id: Option<GrantId>,
    /// The client the grant (and thus the token) belongs to. The revocation
    /// endpoint compares it against the authenticated client for the foreign-client
    /// check.
    pub client_id: String,
}

/// Everything the authorization endpoint binds into a freshly issued code and
/// its grant. The `code_id`, `grant_id`, and `client_id` are all scoped
/// identifiers minted (or resolved) under the caller's scope, so a mismatch is a
/// uniform not-found.
///
/// [`fmt::Debug`] is hand written and redacting: the code value is a bearer
/// secret and the subject/redirect/nonce carry end-user detail, so a struct dump
/// or a `tracing` field never spills them.
#[derive(Clone, Copy)]
pub struct IssueCode<'a> {
    /// The `ac_` code identifier (also the code value returned to the client).
    pub code_id: &'a AuthorizationCodeId,
    /// The `grt_` grant identifier this code belongs to.
    pub grant_id: &'a GrantId,
    /// The OAuth client the code is bound to.
    pub client_id: &'a ClientId,
    /// The redirect URI the code is bound to (re-checked at redemption).
    pub redirect_uri: &'a str,
    /// The bound OIDC `nonce`, if the authorization request carried one.
    pub nonce: Option<&'a str>,
    /// The bound PKCE `code_challenge`, if present.
    pub code_challenge: Option<&'a str>,
    /// The bound PKCE `code_challenge_method`, if present.
    pub code_challenge_method: Option<&'a str>,
    /// The authenticated end-user subject the tokens will be minted for.
    pub subject: &'a str,
    /// The requested OAuth `scope` value, if any.
    pub oauth_scope: Option<&'a str>,
    /// The recorded authentication method tokens frozen onto the code
    /// (space-separated RFC 8176 values). The ID token's `amr` and achieved
    /// `acr` derive from these (issue #14).
    pub auth_methods: &'a str,
    /// The recorded authentication instant in epoch microseconds, set ONLY when
    /// the ID token must carry `auth_time` (`max_age` requested or the client
    /// registered `require_auth_time`); [`None`] omits the claim (issue #14).
    pub auth_time_micros: Option<i64>,
    /// The authenticating session handle (a seam for later M2 issues).
    pub session_ref: Option<&'a str>,
    /// The recorded consent handle (a seam for later M2 issues).
    pub consent_ref: Option<&'a str>,
    /// The canonical JSON form of the `claims` request parameter (OIDC Core 5.5),
    /// or [`None`] when the request carried none. Frozen onto the grant and the
    /// code so the ID token (`id_token` member) and `UserInfo` (`userinfo` member)
    /// can honor it after the request itself is gone (issue #15).
    pub claims_request: Option<&'a str>,
    /// The RFC 8707 resource audiences APPROVED at authorization (issue #28), the
    /// ceiling a later code exchange or refresh may downscope from but never expand
    /// beyond. Frozen onto BOTH the grant (read by the refresh path) and the code
    /// (read by the code-exchange path), exactly as `claims_request` is. An empty
    /// slice means no resource was approved (the default-audience case) and is
    /// stored as NULL.
    pub granted_resources: &'a [String],
    /// The code's expiry, in microseconds since the Unix epoch (clock seam).
    pub expires_at_micros: i64,
    /// The code's creation time, in microseconds since the Unix epoch.
    pub created_at_micros: i64,
}

impl fmt::Debug for IssueCode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The code identifier redacts itself (it is a bearer secret); the
        // end-user fields are omitted entirely via finish_non_exhaustive so a
        // debug dump cannot spill the subject, redirect, nonce, or challenge.
        f.debug_struct("IssueCode")
            .field("code_id", &self.code_id)
            .field("grant_id", &self.grant_id)
            .field("client_id", &self.client_id)
            .field("expires_at_micros", &self.expires_at_micros)
            .field("created_at_micros", &self.created_at_micros)
            .finish_non_exhaustive()
    }
}

/// The bindings read back when a code is atomically consumed. The token endpoint
/// re-checks every one against the presented request before issuing tokens.
///
/// [`fmt::Debug`] is hand written and redacting: the subject, redirect, nonce,
/// and challenge are end-user detail that must not reach a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeBindings {
    /// The grant this code belongs to (the revocation spine).
    pub grant_id: GrantId,
    /// The client the code was bound to at authorization time.
    pub client_id: String,
    /// The redirect URI the code was bound to.
    pub redirect_uri: String,
    /// The bound OIDC `nonce`, if any.
    pub nonce: Option<String>,
    /// The bound PKCE `code_challenge`, if any.
    pub code_challenge: Option<String>,
    /// The bound PKCE `code_challenge_method`, if any.
    pub code_challenge_method: Option<String>,
    /// The authenticated subject.
    pub subject: String,
    /// The requested OAuth `scope` value, if any.
    pub oauth_scope: Option<String>,
    /// The recorded authentication method tokens frozen onto the code at
    /// issuance (space-separated RFC 8176 values). The ID token's `amr` and
    /// achieved `acr` derive from these (issue #14).
    pub auth_methods: String,
    /// The recorded authentication instant, in microseconds since the Unix
    /// epoch, present ONLY when the ID token must carry `auth_time` (the request
    /// asked for `max_age`, or the client registered `require_auth_time`). A
    /// [`None`] means the `auth_time` claim is omitted (issue #14).
    pub auth_time_unix_micros: Option<i64>,
    /// The canonical JSON form of the `claims` request parameter frozen onto the
    /// code (OIDC Core 5.5), or [`None`] when the request carried none. The token
    /// endpoint applies its `id_token` member to the ID token at mint (issue #15).
    pub claims_request: Option<String>,
    /// The RFC 8707 resource audiences APPROVED at authorization (issue #28),
    /// frozen onto the code. The token endpoint narrows the issued access token to
    /// a requested subset of these; a requested resource outside this set is an
    /// expansion beyond the grant and is rejected. Empty when no resource was
    /// approved (the default-audience case).
    pub granted_resources: Vec<String>,
    /// The authenticating SSO session (a `ses_` id) the grant was opened under
    /// (issue #32), read from the grant this code belongs to. The token endpoint
    /// derives the per-(client, session) `sid` claim from it (via the per-client
    /// session store), so the ID token carries a `sid` that is stable per (client,
    /// session) and distinct across clients. [`None`] when no session backed the
    /// grant (no `sid` is then emitted).
    pub session_ref: Option<String>,
}

impl fmt::Debug for CodeBindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeBindings")
            .field("grant_id", &self.grant_id)
            .field("client_id", &self.client_id)
            .field("code_challenge_method", &self.code_challenge_method)
            .finish_non_exhaustive()
    }
}

/// The outcome of redeeming an authorization code.
///
/// The store does the whole single-use decision (it holds the clock seam and the
/// atomic UPDATE), so the token endpoint only maps an outcome to a response. The
/// four cases are distinguished because they must behave differently: only
/// [`Consumed`](RedeemOutcome::Consumed) returns tokens, only
/// [`Reused`](RedeemOutcome::Reused) revokes the grant chain, and
/// [`RetryWithinGrace`](RedeemOutcome::RetryWithinGrace) is a benign replay that
/// must NOT revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemOutcome {
    /// This call won the single-use race: the code is now consumed, and the
    /// issued-token rows and the `authorization_code.redeem` audit row were
    /// written in the SAME transaction as the consume. The token endpoint returns
    /// the tokens it pre-signed.
    Consumed,
    /// The code was already consumed, but within the reuse grace window: a benign
    /// double-submit or an immediate client retry. No revocation and no reuse
    /// audit; the token endpoint returns a plain `invalid_grant`.
    RetryWithinGrace,
    /// The code was already consumed beyond the grace window: a genuine reuse. The
    /// grant chain was revoked and the reuse audited, both in this transaction, so
    /// every token issued from the code now derives as revoked through the grant
    /// chain (RFC 9700). The token endpoint returns a plain `invalid_grant`.
    Reused,
    /// The code is absent or expired: a plain `invalid_grant` with no reuse.
    Invalid,
}

/// The read-only OIDC authorization repository: derives a token's active state
/// from its grant (issue #12).
pub struct AuthorizationRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl AuthorizationRepo<'_> {
    /// Parse an untrusted authorization-code identifier under this scope. A
    /// malformed code and one minted in another scope both return the uniform
    /// not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if malformed or out of scope.
    pub fn parse_code_id(&self, raw: &str) -> Result<AuthorizationCodeId, StoreError> {
        Ok(AuthorizationCodeId::parse_in_scope(raw, &self.scope)?)
    }

    /// Read a code's bindings WITHOUT consuming it. The token endpoint re-checks
    /// every binding (client, redirect, PKCE) against the presented request and
    /// mints the tokens BEFORE the atomic [`redeem`](ActingAuthorizationRepo::redeem),
    /// so a wrong-binding presentation or a signing failure never burns the
    /// one-time code. Returns the row's bindings whatever the code's state
    /// (unconsumed, consumed, or expired): the authoritative single-use and
    /// reuse/grace decision is made later by `redeem`, not here. A code absent in
    /// this scope is a uniform [`None`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn load_code(
        &self,
        code_id: &AuthorizationCodeId,
    ) -> Result<Option<CodeBindings>, StoreError> {
        if code_id.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // JOIN the grant to read its session_ref (issue #32): the authenticating SSO
        // session the token endpoint derives the per-client `sid` from. Both tables are
        // scope-filtered and RLS-forced, and the composite JOIN keeps a code and its
        // grant in the SAME (tenant, environment).
        let row = sqlx::query(
            "SELECT ac.grant_id, ac.client_id, ac.redirect_uri, ac.nonce, ac.code_challenge, \
             ac.code_challenge_method, ac.subject, ac.oauth_scope, ac.auth_methods, \
             ac.claims_request, ac.granted_resources, \
             (EXTRACT(EPOCH FROM ac.auth_time) * 1000000)::bigint AS auth_time_us, \
             g.session_ref AS session_ref \
             FROM authorization_codes ac \
             JOIN grants g \
               ON g.id = ac.grant_id \
              AND g.tenant_id = ac.tenant_id \
              AND g.environment_id = ac.environment_id \
             WHERE ac.id = $1 AND ac.tenant_id = $2 AND ac.environment_id = $3",
        )
        .bind(code_id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => Ok(Some(bindings_from_row(&row, &self.scope)?)),
        }
    }

    /// The active state of an issued token by its `jti`, within scope. A token is
    /// [`TokenStatus::Active`] only while its issued row exists and its grant is
    /// not revoked; a revoked grant flips every one of its tokens to
    /// [`TokenStatus::Revoked`]. Unknown (absent or out of scope) is uniform.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn token_status(&self, jti: &IssuedTokenId) -> Result<TokenStatus, StoreError> {
        if jti.scope() != self.scope {
            return Ok(TokenStatus::Unknown);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT (g.revoked_at IS NULL) AS active \
             FROM issued_tokens t \
             JOIN grants g ON g.id = t.grant_id \
             AND g.tenant_id = t.tenant_id AND g.environment_id = t.environment_id \
             WHERE t.id = $1 AND t.tenant_id = $2 AND t.environment_id = $3",
        )
        .bind(jti.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(match row {
            None => TokenStatus::Unknown,
            Some(row) if row.get::<bool, _>("active") => TokenStatus::Active,
            Some(_) => TokenStatus::Revoked,
        })
    }

    /// Resolve an ACCESS token's `jti` back to the grant it was issued from
    /// (issue #15), within scope. Returns the local subject, the client, and the
    /// grant's live state, or [`None`] when no access token with this identifier
    /// is recorded in scope (absent, out of scope, or an ID-token `jti`).
    ///
    /// The `UserInfo` endpoint uses this to build its response from authoritative
    /// grant state and to honor grant-chain revocation: a revoked grant comes back
    /// with `active = false`, and the caller rejects the token. The match is
    /// filtered to `token_kind = 'access'`, so presenting an ID token's `jti` here
    /// is a uniform [`None`] (an ID token is not a `UserInfo` credential).
    ///
    /// Scope isolation is the same three-layer guarantee as [`token_status`](Self::token_status):
    /// the `jti` embeds its own scope (checked here), the query filters on the
    /// caller's `(tenant, environment)`, and forced row-level security sits beneath.
    /// So an access token minted in one environment never resolves under another.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn resolve_access_token(
        &self,
        jti: &IssuedTokenId,
    ) -> Result<Option<AccessTokenResolution>, StoreError> {
        if jti.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT g.subject AS subject, g.client_id AS client_id, \
             g.claims_request AS claims_request, (g.revoked_at IS NULL) AS active \
             FROM issued_tokens t \
             JOIN grants g ON g.id = t.grant_id \
             AND g.tenant_id = t.tenant_id AND g.environment_id = t.environment_id \
             WHERE t.id = $1 AND t.token_kind = 'access' \
             AND t.tenant_id = $2 AND t.environment_id = $3",
        )
        .bind(jti.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| AccessTokenResolution {
            subject: row.get("subject"),
            client_id: row.get("client_id"),
            claims_request: row.get("claims_request"),
            active: row.get("active"),
        }))
    }

    /// Resolve a presented OPAQUE access token back to its live claims (issue
    /// #29), within scope. This is the INTERNAL resolve the RFC 7662 introspection
    /// endpoint (issue #22) will expose over HTTP: there is NO offline validation
    /// path for an opaque token, so verification is exclusively this store lookup.
    ///
    /// The presented token is hashed with [`opaque_access_token_digest`] and
    /// matched against the stored `token_digest` within the caller's scope, so a
    /// token minted in one environment never resolves under another (the query
    /// filters on the caller's `(tenant, environment)` and forced row-level
    /// security sits beneath). Returns the claims ONLY when the row exists, its
    /// grant (when present) is not revoked, and it has not expired at `now_micros`
    /// (compared against the application clock seam, never the database clock);
    /// otherwise [`None`]. The digest, not the token, is stored, so a leaked
    /// database row cannot be replayed as a valid token.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn resolve_opaque_access_token(
        &self,
        presented_token: &str,
        now_micros: i64,
    ) -> Result<Option<ActiveOpaqueToken>, StoreError> {
        let digest = opaque_access_token_digest(presented_token);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // LEFT JOIN grants so a token with no grant (grant_id NULL) still resolves,
        // while a token whose grant chain was revoked comes back inactive. Expiry is
        // compared against the application clock (bound as epoch microseconds).
        // expires_at/created_at are read back as epoch microseconds (an exact bigint
        // on PostgreSQL 14+, where EXTRACT(EPOCH ...) is numeric), so the seam issue
        // #22's introspection response consumes carries the token's `exp` and `iat`.
        let row = sqlx::query(
            "SELECT t.subject AS subject, t.client_id AS client_id, t.audience AS audience, \
             t.audiences AS audiences, t.scope AS scope, t.jti AS jti, \
             (EXTRACT(EPOCH FROM t.expires_at) * 1000000)::bigint AS expires_us, \
             (EXTRACT(EPOCH FROM t.created_at) * 1000000)::bigint AS issued_us \
             FROM opaque_access_tokens t \
             LEFT JOIN grants g ON g.id = t.grant_id \
             AND g.tenant_id = t.tenant_id AND g.environment_id = t.environment_id \
             WHERE t.token_digest = $1 AND t.tenant_id = $2 AND t.environment_id = $3 \
             AND t.expires_at > TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
             AND (t.grant_id IS NULL OR g.revoked_at IS NULL)",
        )
        .bind(&digest)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(now_micros)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| {
            let audience: String = row.get("audience");
            // The recorded audience array, or a single-element fallback to the
            // primary audience for a single-resource / no-resource token (whose
            // `audiences` column is NULL). Always non-empty.
            let mut audiences =
                resource_array_from_json(row.get::<Option<String>, _>("audiences").as_deref());
            if audiences.is_empty() {
                audiences.push(audience.clone());
            }
            ActiveOpaqueToken {
                subject: row.get("subject"),
                client_id: row.get("client_id"),
                audience,
                audiences,
                scope: row.get("scope"),
                jti: row.get("jti"),
                expires_at_unix_micros: row.get("expires_us"),
                issued_at_unix_micros: row.get("issued_us"),
            }
        }))
    }

    /// Locate the grant and owning client of an `at+jwt` access token by its `jti`,
    /// within scope, for revocation (issue #22). Returns [`None`] when no access
    /// token with this identifier is recorded in scope (absent, out of scope, or an
    /// ID-token `jti`).
    ///
    /// Unlike [`resolve_access_token`](Self::resolve_access_token), this does NOT
    /// filter on the grant's revoked state: a token whose grant is ALREADY revoked
    /// still locates, so a second revocation of it is a benign idempotent no-op (RFC
    /// 7009 returns 200 for an already-invalid token) rather than a false "unknown".
    /// The scope isolation is the same three-layer guarantee as
    /// [`resolve_access_token`](Self::resolve_access_token).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn grant_for_access_token(
        &self,
        jti: &IssuedTokenId,
    ) -> Result<Option<GrantOwner>, StoreError> {
        if jti.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT g.id AS grant_id, g.client_id AS client_id \
             FROM issued_tokens t \
             JOIN grants g ON g.id = t.grant_id \
             AND g.tenant_id = t.tenant_id AND g.environment_id = t.environment_id \
             WHERE t.id = $1 AND t.token_kind = 'access' \
             AND t.tenant_id = $2 AND t.environment_id = $3",
        )
        .bind(jti.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => Ok(Some(GrantOwner {
                grant_id: Some(GrantId::parse_in_scope(
                    &row.get::<String, _>("grant_id"),
                    &self.scope,
                )?),
                client_id: row.get("client_id"),
            })),
        }
    }

    /// Locate the grant and owning client of an OPAQUE access token by the presented
    /// token, within scope, for revocation (issue #22). Returns [`None`] when no such
    /// token is recorded in scope.
    ///
    /// Like [`grant_for_access_token`](Self::grant_for_access_token) this does NOT
    /// filter on expiry or grant-revoked state, so a second revocation, or a revoke
    /// of an already-expired token, locates and is a benign idempotent no-op rather
    /// than a false "unknown". The presented token is hashed with
    /// [`opaque_access_token_digest`] and matched within scope, so a token minted in
    /// one environment never locates under another. `grant_id` is [`None`] for a
    /// `grant_id`-NULL row (a token minted outside the authorization-code flow),
    /// which has no grant spine to revoke.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn grant_for_opaque_token(
        &self,
        presented_token: &str,
    ) -> Result<Option<GrantOwner>, StoreError> {
        let digest = opaque_access_token_digest(presented_token);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT grant_id, client_id FROM opaque_access_tokens \
             WHERE token_digest = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(&digest)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => {
                let grant_id = match row.get::<Option<String>, _>("grant_id") {
                    Some(text) => Some(GrantId::parse_in_scope(&text, &self.scope)?),
                    None => None,
                };
                Ok(Some(GrantOwner {
                    grant_id,
                    client_id: row.get("client_id"),
                }))
            }
        }
    }
}

/// The mutating OIDC authorization repository (issue #12). Reachable only through
/// [`ScopedStore::acting`], so every mutation carries an actor and correlation
/// id. Issue and record route through the module's single audited-write
/// primitive; redeem is the one bespoke committing path (it folds the atomic
/// single-use consume, the issued-token rows, and its audit row into one
/// transaction, and classifies a zero-row consume as a benign grace retry, a
/// genuine reuse, or an invalid code), documented at its call site.
pub struct ActingAuthorizationRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingAuthorizationRepo<'_> {
    /// Issue an authorization code and its grant in one audited transaction.
    ///
    /// The grant row is inserted first (the code and any future token reference
    /// it), then the code row, then exactly one `authorization_code.issue` audit
    /// row, all in the same transaction: a code cannot exist without its grant or
    /// its audit row.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if any supplied identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn issue(&self, env: &Env, code: IssueCode<'_>) -> Result<(), StoreError> {
        if code.code_id.scope() != self.scope
            || code.grant_id.scope() != self.scope
            || code.client_id.scope() != self.scope
        {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::AuthorizationCodeIssue,
                target: code.code_id,
            },
            async move |tx| {
                let granted_resources = resource_array_to_json(code.granted_resources);
                sqlx::query(
                    "INSERT INTO grants \
                     (id, tenant_id, environment_id, client_id, subject, session_ref, \
                      consent_ref, claims_request, granted_resources, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                             TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval)",
                )
                .bind(code.grant_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(code.client_id.to_string())
                .bind(code.subject)
                .bind(code.session_ref)
                .bind(code.consent_ref)
                .bind(code.claims_request)
                .bind(granted_resources.as_deref())
                .bind(code.created_at_micros)
                .execute(&mut **tx)
                .await?;
                sqlx::query(
                    "INSERT INTO authorization_codes \
                     (id, tenant_id, environment_id, grant_id, client_id, redirect_uri, nonce, \
                      code_challenge, code_challenge_method, subject, oauth_scope, auth_methods, \
                      claims_request, granted_resources, auth_time, expires_at, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                             CASE WHEN $15::bigint IS NULL THEN NULL \
                                  ELSE TIMESTAMPTZ 'epoch' \
                                       + ($15::text || ' microseconds')::interval END, \
                             TIMESTAMPTZ 'epoch' + ($16::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($17::text || ' microseconds')::interval)",
                )
                .bind(code.code_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(code.grant_id.to_string())
                .bind(code.client_id.to_string())
                .bind(code.redirect_uri)
                .bind(code.nonce)
                .bind(code.code_challenge)
                .bind(code.code_challenge_method)
                .bind(code.subject)
                .bind(code.oauth_scope)
                .bind(code.auth_methods)
                .bind(code.claims_request)
                .bind(granted_resources.as_deref())
                .bind(code.auth_time_micros)
                .bind(code.expires_at_micros)
                .bind(code.created_at_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Atomically redeem a code, enforcing single use in ONE statement, and (on
    /// the winning call) record the issued tokens and the redeem audit in the SAME
    /// transaction as the consume.
    ///
    /// The caller has already re-checked every binding and PRE-SIGNED `tokens`
    /// against those bindings (see [`AuthorizationRepo::load_code`]); this is the
    /// authoritative single-use gate that decides whether those tokens are handed
    /// out. Doing the binding re-check and the signing before this call means a
    /// wrong-binding presentation or a signing failure never burns the one-time
    /// code.
    ///
    /// The consume is a single `UPDATE ... SET consumed_at = <now> WHERE id = $1
    /// AND consumed_at IS NULL AND expires_at > <now> RETURNING grant_id`.
    /// Postgres serializes concurrent updates of the one row, so exactly one
    /// caller sees `consumed_at` NULL and gets [`RedeemOutcome::Consumed`]; every
    /// other concurrent exchange affects zero rows. The transaction is pinned to
    /// READ COMMITTED (in [`begin_scoped`]) so a losing concurrent writer BLOCKS
    /// on the row lock and then re-reads the committed `consumed_at`, matching
    /// zero rows rather than aborting with a serialization error. No in-memory
    /// marker is used, so single use holds across N stateless nodes.
    ///
    /// On the winning branch the issued-token rows and exactly one
    /// `authorization_code.redeem` audit row are written in this same
    /// transaction, so tokens can never be handed out without their issued rows
    /// (the revocation reach) or their audit row.
    ///
    /// Zero rows is classified against the reuse grace window (see
    /// [`classify_miss`](Self::classify_miss)): a still-present, already-consumed
    /// code within `reuse_grace` is a benign [`RetryWithinGrace`] (no revoke); one
    /// beyond the window is a genuine [`Reused`] (revoke the grant chain and audit
    /// it, in this transaction); anything else (absent or expired) is
    /// [`Invalid`].
    ///
    /// [`Consumed`]: RedeemOutcome::Consumed
    /// [`RetryWithinGrace`]: RedeemOutcome::RetryWithinGrace
    /// [`Reused`]: RedeemOutcome::Reused
    /// [`Invalid`]: RedeemOutcome::Invalid
    ///
    /// `now` flows from the application clock seam (bound as epoch microseconds),
    /// never the database clock, so expiry and the grace comparison are
    /// deterministic under a manual clock. Note that each stateless node reads its
    /// OWN clock, so a code's usable lifetime and the grace boundary can shift by
    /// up to the inter-node clock skew; keep nodes NTP-synced and the code TTL
    /// well above expected skew (the default TTL is 60s).
    ///
    /// This is the one committing write in the module that does not go through
    /// [`write_audited`] as a thin wrapper (it must fold the consume, the token
    /// rows, and the audit into one transaction and classify zero rows), but it
    /// still writes every audit row in the SAME transaction as its mutation.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the code, the grant, or any token identifier is
    /// out of this scope; [`StoreError::Database`] on a persistence failure.
    pub async fn redeem(
        &self,
        env: &Env,
        code_id: &AuthorizationCodeId,
        grant_id: &GrantId,
        tokens: &[IssuedTokenRecord],
        opaque: Option<NewOpaqueAccessToken<'_>>,
        reuse_grace: Duration,
    ) -> Result<RedeemOutcome, StoreError> {
        if code_id.scope() != self.scope
            || grant_id.scope() != self.scope
            || tokens.iter().any(|t| t.id.scope() != self.scope)
            || opaque.as_ref().is_some_and(|opaque| {
                opaque.jti.scope() != self.scope
                    || opaque
                        .grant_id
                        .is_some_and(|grant| grant.scope() != self.scope)
            })
        {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let grace_micros = i64::try_from(reuse_grace.as_micros()).unwrap_or(i64::MAX);

        let mut tx = begin_scoped(self.store, scope).await?;
        let won = sqlx::query(
            "UPDATE authorization_codes \
             SET consumed_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
             AND consumed_at IS NULL \
             AND expires_at > TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             RETURNING grant_id",
        )
        .bind(now_micros)
        .bind(code_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = won {
            // Won the single-use race. Record the issued tokens and the redeem
            // audit in this same transaction, then commit them with the consume.
            let grant_text: String = row.get("grant_id");
            for token in tokens {
                sqlx::query(
                    "INSERT INTO issued_tokens \
                     (id, tenant_id, environment_id, grant_id, token_kind) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(token.id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&grant_text)
                .bind(token.kind.as_str())
                .execute(&mut *tx)
                .await?;
            }
            // An opaque access token (issue #29) records ONLY its digest and
            // metadata here, in the SAME transaction as the consume, so it can no
            // more be handed out without its stored row than an at+jwt jti can. The
            // grant is the consumed code's grant (grant_text), so grant-chain
            // revocation reaches the opaque token exactly as it reaches an at+jwt.
            if let Some(opaque) = &opaque {
                sqlx::query(
                    "INSERT INTO opaque_access_tokens \
                     (token_digest, tenant_id, environment_id, grant_id, subject, \
                      client_id, audience, audiences, scope, jti, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                             TIMESTAMPTZ 'epoch' + ($11::text || ' microseconds')::interval)",
                )
                .bind(opaque.token_digest)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&grant_text)
                .bind(opaque.subject)
                .bind(opaque.client_id)
                .bind(opaque.audience)
                .bind(resource_array_to_json(opaque.audiences))
                .bind(opaque.scope)
                .bind(opaque.jti.to_string())
                .bind(opaque.expires_at_unix_micros)
                .execute(&mut *tx)
                .await?;
            }
            let spec = AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::AuthorizationCodeRedeem,
                target: code_id,
            };
            insert_audit_row(&mut tx, &spec, None).await?;
            tx.commit().await?;
            return Ok(RedeemOutcome::Consumed);
        }
        // Zero rows: the code never existed, is expired, or was already consumed.
        // Classify against the grace window; classify_miss owns the commit.
        self.classify_miss(env, tx, code_id, now_micros, grace_micros)
            .await
    }

    /// Classify a redeem that consumed zero rows, and commit its transaction.
    ///
    /// Reads the code row (still under the open, scope-pinned transaction): absent
    /// or present-but-unconsumed (that is, expired) is [`RedeemOutcome::Invalid`];
    /// present-and-consumed within `grace_micros` of its `consumed_at` is the
    /// benign [`RedeemOutcome::RetryWithinGrace`]; beyond the window it is a
    /// genuine [`RedeemOutcome::Reused`], which revokes the grant chain and writes
    /// the `authorization_code.reuse` audit row in this transaction.
    async fn classify_miss(
        &self,
        env: &Env,
        mut tx: Transaction<'_, Postgres>,
        code_id: &AuthorizationCodeId,
        now_micros: i64,
        grace_micros: i64,
    ) -> Result<RedeemOutcome, StoreError> {
        let scope = self.scope;
        let row = sqlx::query(
            "SELECT grant_id, (consumed_at IS NOT NULL) AS consumed, \
             (EXTRACT(EPOCH FROM consumed_at) * 1000000)::bigint AS consumed_us \
             FROM authorization_codes \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(code_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;

        // Absent (never issued, or a concurrent expiry sweep removed it), or
        // present but unconsumed (the UPDATE's expiry guard is why it missed):
        // both are a plain invalid_grant with no reuse.
        let Some(row) = row.filter(|row| row.get::<bool, _>("consumed")) else {
            tx.commit().await?;
            return Ok(RedeemOutcome::Invalid);
        };
        let consumed_us: i64 = row.get("consumed_us");
        if now_micros.saturating_sub(consumed_us) <= grace_micros {
            // Within the grace window: a benign double-submit or immediate retry.
            // Do NOT revoke and do NOT audit a reuse.
            tx.commit().await?;
            return Ok(RedeemOutcome::RetryWithinGrace);
        }

        // Beyond the window: a genuine reuse. Revoke the grant chain and audit it
        // in this transaction, so every token issued from the code derives as
        // revoked through the grant chain.
        let grant_text: String = row.get("grant_id");
        let revoked = sqlx::query(
            "UPDATE grants SET revoked_at = \
             TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
             AND revoked_at IS NULL",
        )
        .bind(now_micros)
        .bind(&grant_text)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
        // A concurrent reuse may have already revoked the chain; audit only the
        // revocation that actually flipped the grant, so the reuse audit is
        // written exactly once.
        if revoked.rows_affected() > 0 {
            let grant_id = GrantId::parse_in_scope(&grant_text, &scope)?;
            let spec = AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::AuthorizationCodeReuse,
                target: &grant_id,
            };
            insert_audit_row(&mut tx, &spec, None).await?;
        }
        tx.commit().await?;
        Ok(RedeemOutcome::Reused)
    }

    /// Record the tokens issued from a grant, in one audited transaction. Called
    /// after the tokens are signed, so the recorded `jti`s match the tokens on
    /// the wire and grant-chain revocation can reach them.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the grant or any token is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn record_issued_tokens(
        &self,
        env: &Env,
        grant_id: &GrantId,
        tokens: &[IssuedTokenRecord],
    ) -> Result<(), StoreError> {
        if grant_id.scope() != self.scope || tokens.iter().any(|t| t.id.scope() != self.scope) {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let tokens = tokens.to_vec();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TokenIssue,
                target: grant_id,
            },
            async move |tx| {
                for token in &tokens {
                    sqlx::query(
                        "INSERT INTO issued_tokens \
                         (id, tenant_id, environment_id, grant_id, token_kind) \
                         VALUES ($1, $2, $3, $4, $5)",
                    )
                    .bind(token.id.to_string())
                    .bind(scope.tenant().to_string())
                    .bind(scope.environment().to_string())
                    .bind(grant_id.to_string())
                    .bind(token.kind.as_str())
                    .execute(&mut **tx)
                    .await?;
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Issue a client-credentials access token and its grant in one audited
    /// transaction (issue #23).
    ///
    /// The client-credentials grant (RFC 6749 4.4) has NO authorization code and no
    /// user: the tokens are minted directly for a machine principal. To make the
    /// issued token revocable and introspectable by the SAME mechanism the #22
    /// revoke/introspect endpoints consume (the grant chain), this mints a fresh
    /// grant rooted at the service-account principal and records the access token
    /// against it, exactly as a code exchange records its tokens against the code's
    /// grant. The grant row is inserted first (the token references it), then the
    /// access-token row (an `issued_tokens` row for an at+jwt, or an
    /// `opaque_access_tokens` row for an opaque token), then exactly one
    /// `token.issue` audit row, all in the same transaction: a token cannot exist
    /// without its grant or its audit row, and revoking the grant flips the token's
    /// observable active state (the revocation reach #22 will use).
    ///
    /// There is deliberately NO refresh-token family opened here (RFC 6749 4.4.3): a
    /// client-credentials issuance never returns a refresh token.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if any supplied identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn issue_client_credentials(
        &self,
        env: &Env,
        request: IssueClientCredentials<'_>,
    ) -> Result<(), StoreError> {
        self.issue_machine_grant(env, request, Action::TokenIssue)
            .await
    }

    /// Persist a JWT bearer assertion grant's short-lived access token against a
    /// fresh grant (issue #26), audited as [`Action::JwtBearerAssertionIssue`] in the
    /// same transaction, so the mapped-identity token is revocable and
    /// introspectable by the #22 endpoints by construction (the SAME grant chain the
    /// code/refresh/client-credentials tokens use). It REUSES the machine-grant
    /// persistence shape ([`IssueClientCredentials`]): `subject` is the MAPPED
    /// principal (the token's `sub`), `client_id` is the presenting OAuth client, and
    /// there is NO refresh token (RFC 7521 4.1). The audit action is distinct so a
    /// federation issuance is legible in the trail as such, not as an M2M issuance.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if any identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn issue_jwt_bearer_assertion(
        &self,
        env: &Env,
        request: IssueClientCredentials<'_>,
    ) -> Result<(), StoreError> {
        self.issue_machine_grant(env, request, Action::JwtBearerAssertionIssue)
            .await
    }

    /// The shared body behind [`Self::issue_client_credentials`] and
    /// [`Self::issue_jwt_bearer_assertion`]: open a subject-bearing grant (no
    /// session, no consent, no user flow) and record the minted access token against
    /// it, auditing `action` in the same transaction. Both callers persist an
    /// identical grant + access-token shape; only the audit verb differs.
    async fn issue_machine_grant(
        &self,
        env: &Env,
        request: IssueClientCredentials<'_>,
        action: Action,
    ) -> Result<(), StoreError> {
        let in_scope = request.grant_id.scope() == self.scope
            && request.client_id.scope() == self.scope
            && match &request.access {
                ClientCredentialsAccess::Jwt { jti } => jti.scope() == self.scope,
                ClientCredentialsAccess::Opaque(opaque) => opaque.jti.scope() == self.scope,
            };
        if !in_scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action,
                target: request.grant_id,
            },
            async move |tx| {
                // The grant is the machine principal's grant: no session, no consent,
                // no claims_request (this is not a user flow). subject is the stable
                // `sva_` service-account principal id, so grant-chain revocation and
                // the #22 introspection resolve read it exactly as they read a user
                // grant's subject.
                sqlx::query(
                    "INSERT INTO grants \
                     (id, tenant_id, environment_id, client_id, subject, session_ref, \
                      consent_ref, claims_request, created_at) \
                     VALUES ($1, $2, $3, $4, $5, NULL, NULL, NULL, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval)",
                )
                .bind(request.grant_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(request.client_id.to_string())
                .bind(request.subject)
                .bind(request.created_at_unix_micros)
                .execute(&mut **tx)
                .await?;
                match &request.access {
                    ClientCredentialsAccess::Jwt { jti } => {
                        sqlx::query(
                            "INSERT INTO issued_tokens \
                             (id, tenant_id, environment_id, grant_id, token_kind) \
                             VALUES ($1, $2, $3, $4, 'access')",
                        )
                        .bind(jti.to_string())
                        .bind(scope.tenant().to_string())
                        .bind(scope.environment().to_string())
                        .bind(request.grant_id.to_string())
                        .execute(&mut **tx)
                        .await?;
                    }
                    ClientCredentialsAccess::Opaque(opaque) => {
                        // The opaque row carries THIS grant, so grant-chain revocation
                        // reaches the opaque token exactly as it reaches an at+jwt.
                        sqlx::query(
                            "INSERT INTO opaque_access_tokens \
                             (token_digest, tenant_id, environment_id, grant_id, subject, \
                              client_id, audience, audiences, scope, jti, expires_at) \
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                                     TIMESTAMPTZ 'epoch' + ($11::text || ' microseconds')::interval)",
                        )
                        .bind(opaque.token_digest)
                        .bind(scope.tenant().to_string())
                        .bind(scope.environment().to_string())
                        .bind(request.grant_id.to_string())
                        .bind(opaque.subject)
                        .bind(opaque.client_id)
                        .bind(opaque.audience)
                        .bind(resource_array_to_json(opaque.audiences))
                        .bind(opaque.scope)
                        .bind(opaque.jti.to_string())
                        .bind(opaque.expires_at_unix_micros)
                        .execute(&mut **tx)
                        .await?;
                    }
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Revoke a grant chain at the RFC 7009 revocation endpoint (issue #22),
    /// returning whether this call is the one that flipped it.
    ///
    /// The append-only `issued_tokens` / `opaque_access_tokens` rows derive their
    /// active state ONLY from `grants.revoked_at`, so revoking a token IS revoking
    /// its grant: every access token minted from this grant (an at+jwt, an opaque
    /// reference token, or a refreshed one) immediately resolves as inactive, and so
    /// does any refresh family rooted at it. This is the RFC 7009 access-token
    /// revoke, and the cascade for a refresh-token revoke reaches the derived access
    /// tokens the same way (through [`ActingRefreshRepo::revoke_family`], which calls
    /// the same `grants` UPDATE alongside the family spine).
    ///
    /// The revoke is a bespoke committing path (like the code redeem): the `revoked_at`
    /// UPDATE and its `token.revoke` audit row share one transaction, and the audit
    /// row is written ONLY when this call actually flipped a live grant (`revoked_at
    /// IS NULL`), so a second revocation of an already-revoked token is a benign
    /// idempotent no-op with no spurious audit row. `now` flows from the application
    /// clock seam, never the database clock.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `grant_id` is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn revoke_grant(&self, env: &Env, grant_id: &GrantId) -> Result<bool, StoreError> {
        if grant_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, scope).await?;
        let revoked = sqlx::query(
            "UPDATE grants \
             SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 AND revoked_at IS NULL",
        )
        .bind(now_micros)
        .bind(grant_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
        let flipped = revoked.rows_affected() > 0;
        if flipped {
            let spec = AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TokenRevoke,
                target: grant_id,
            };
            insert_audit_row(&mut tx, &spec, None).await?;
        }
        tx.commit().await?;
        Ok(flipped)
    }
}

/// The persistence for one client-credentials issuance (issue #23): the machine
/// grant to open and the access token to record against it. Passed to
/// [`ActingAuthorizationRepo::issue_client_credentials`].
#[derive(Debug)]
pub struct IssueClientCredentials<'a> {
    /// The fresh grant this issuance is rooted at (the revocation spine the #22
    /// revoke/introspect endpoints consume).
    pub grant_id: &'a GrantId,
    /// The authenticated OAuth client the token is for.
    pub client_id: &'a ClientId,
    /// The stable service-account principal id (a `sva_` id): the token's `sub` and
    /// the grant's subject. DISTINCT from `client_id`.
    pub subject: &'a str,
    /// The issuance instant in epoch microseconds, from the application clock seam.
    pub created_at_unix_micros: i64,
    /// The minted access token to record against the grant.
    pub access: ClientCredentialsAccess<'a>,
}

/// The access token a client-credentials issuance records against its grant (issue
/// #23): an at+jwt records only its `jti` in `issued_tokens`; an opaque token
/// records its digest and metadata in `opaque_access_tokens`.
#[derive(Debug)]
pub enum ClientCredentialsAccess<'a> {
    /// An RFC 9068 at+jwt: its `jti` recorded in `issued_tokens`.
    Jwt {
        /// The access token's `jti`.
        jti: &'a IssuedTokenId,
    },
    /// An opaque reference token: its digest and metadata for `opaque_access_tokens`
    /// (the embedded `grant_id` is bound by the issuing method, so any `grant_id`
    /// set here is ignored).
    Opaque(NewOpaqueAccessToken<'a>),
}

/// The read-only service-account repository (issue #23): resolve a client's STABLE
/// service-account principal id (the client-credentials `sub`).
///
/// The scope is fixed at construction and applied to every statement. Minting the
/// principal lazily lives on [`ActingServiceAccountRepo`], reachable only with an
/// acting context.
pub struct ServiceAccountRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ServiceAccountRepo<'_> {
    /// The stable service-account principal for `client_id` within scope (issue
    /// #23), or [`None`] if the client has not yet had one minted (it is minted
    /// lazily at the first client-credentials issuance) or is out of this scope.
    ///
    /// The returned id is the client-credentials access token's `sub`: STABLE
    /// (stored once and read back every time) and DISTINCT from the client id.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure; a stored value that does
    /// not parse in this scope (which the isolation FK and INSERT make unreachable)
    /// is [`StoreError::NotFound`].
    pub async fn principal_for(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<ServiceAccountId>, StoreError> {
        if client_id.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id FROM service_accounts \
             WHERE client_id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(client_id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => {
                let raw: String = row.get("id");
                Ok(Some(ServiceAccountId::parse_in_scope(&raw, &self.scope)?))
            }
        }
    }
}

/// The mutating service-account repository (issue #23): lazily mint a client's
/// stable service-account principal. Reachable only through
/// [`ScopedStore::acting`], so the mint carries an actor and correlation id.
pub struct ActingServiceAccountRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingServiceAccountRepo<'_> {
    /// Resolve `client_id`'s service-account principal, minting it (audited) if this
    /// is the client's FIRST client-credentials issuance (issue #23).
    ///
    /// The principal id is STABLE: minted once and read back on every subsequent
    /// issuance, so a client's `sub` is consistent across issuances. The mint is
    /// idempotent under a race: a concurrent first-issuance that lost the
    /// `UNIQUE (tenant, environment, client_id)` insert is caught (the
    /// unique-violation maps to a re-read of the winner's principal), so two
    /// simultaneous first calls still agree on one principal and neither fails.
    ///
    /// A first mint writes exactly one `service_account.create` audit row in the
    /// same transaction as the INSERT; resolving an existing principal writes
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `client_id` is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn ensure(
        &self,
        env: &Env,
        client_id: &ClientId,
    ) -> Result<ServiceAccountId, StoreError> {
        if client_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        // Read first: an already-minted principal is returned without a write (so no
        // audit row for a resolve), and its id is the stable `sub`.
        if let Some(existing) = self.read(client_id).await? {
            return Ok(existing);
        }
        let id = ServiceAccountId::generate(env, &self.scope);
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let result = write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ServiceAccountCreate,
                target: &id,
            },
            async move |tx| {
                let insert = sqlx::query(
                    "INSERT INTO service_accounts \
                     (id, tenant_id, environment_id, client_id, created_at) \
                     VALUES ($1, $2, $3, $4, \
                             TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(client_id.to_string())
                .bind(now_micros)
                .execute(&mut **tx)
                .await;
                match insert {
                    Ok(_) => Ok(()),
                    // A concurrent first-issuance already minted the principal (the
                    // UNIQUE(tenant, environment, client_id) fired): a benign race, not
                    // a fault. Surface it as a Conflict so the caller re-reads the
                    // winner rather than writing a duplicate.
                    Err(error) if is_unique_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await;
        match result {
            Ok(()) => Ok(id),
            // The race loser reads back the winner's principal, so both callers agree
            // on the one stable principal. The unique violation means the winner has
            // committed (Postgres holds the conflicting insert until the other
            // transaction commits or rolls back), so this re-read always finds it; a
            // None here is unreachable and surfaces as the uniform not-found.
            Err(StoreError::Conflict) => self.read(client_id).await?.ok_or(StoreError::NotFound),
            Err(other) => Err(other),
        }
    }

    /// Read the existing principal for `client_id` within scope (the pre-mint check
    /// and the race-loser re-read), or [`None`] if none is minted yet.
    async fn read(&self, client_id: &ClientId) -> Result<Option<ServiceAccountId>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id FROM service_accounts \
             WHERE client_id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(client_id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => {
                let raw: String = row.get("id");
                Ok(Some(ServiceAccountId::parse_in_scope(&raw, &self.scope)?))
            }
        }
    }
}

/// A pushed authorization request to store behind a one-time `request_uri` (RFC
/// 9126, issue #27). The `id` is the `par_` reference minted under the caller's
/// scope; the `request_params` is the serialized authorization request the PAR
/// endpoint validated (opaque to the store), and `client_id` is the AUTHENTICATED
/// pushing client the request is bound to.
///
/// [`fmt::Debug`] is hand written and redacting: `request_params` may carry
/// end-user request detail and must not reach a log line.
#[derive(Clone, Copy)]
pub struct PushRequest<'a> {
    /// The `par_` reference identifier, minted under this scope.
    pub id: &'a PushedRequestId,
    /// The AUTHENTICATED pushing client the request is bound to. A `request_uri`
    /// presented under a different `client_id` at `/authorize` is rejected.
    pub client_id: &'a str,
    /// The serialized authorization-request parameters (an application-owned JSON
    /// document), replayed verbatim when the `request_uri` is consumed.
    pub request_params: &'a str,
    /// The `request_uri` expiry in epoch microseconds, from the application clock
    /// seam (never the database clock).
    pub expires_at_micros: i64,
    /// The push instant in epoch microseconds, from the application clock seam.
    pub created_at_micros: i64,
}

impl fmt::Debug for PushRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushRequest")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field("expires_at_micros", &self.expires_at_micros)
            .finish_non_exhaustive()
    }
}

/// The outcome of consuming a pushed-authorization-request `request_uri` (RFC 9126,
/// issue #27).
///
/// The store owns the whole single-use decision (the atomic UPDATE under the clock
/// seam), so the authorization endpoint only maps an outcome to behavior. A
/// mismatched presenting client, an expired request, and an already-consumed request
/// all collapse to [`Invalid`](ConsumePushedRequest::Invalid): the caller returns a
/// uniform `invalid_request`, and none of those misses burns the pending request.
///
/// [`fmt::Debug`] is hand written and redacting: the replayed `request_params` may
/// carry end-user request detail.
#[derive(Clone, PartialEq, Eq)]
pub enum ConsumePushedRequest {
    /// This call won the single-use race: the request is now consumed and its
    /// serialized parameters are returned for replay. The consume audit row was
    /// written in the SAME transaction as the consume.
    Consumed {
        /// The serialized authorization-request parameters to replay verbatim.
        request_params: String,
    },
    /// The `request_uri` was absent, expired, already consumed, or presented under a
    /// different `client_id` than it was bound to. A uniform miss with no state
    /// change; the caller returns `invalid_request`.
    Invalid,
}

impl fmt::Debug for ConsumePushedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsumePushedRequest::Consumed { .. } => {
                f.debug_struct("Consumed").finish_non_exhaustive()
            }
            ConsumePushedRequest::Invalid => f.write_str("Invalid"),
        }
    }
}

/// The read-only pushed-authorization-request repository (RFC 9126, issue #27).
///
/// It PEEKS a `request_uri`'s stored parameters WITHOUT consuming them, so the
/// authorization endpoint can resolve a PAR reference at EVERY interaction hop (the
/// login and consent resume round-trips) while deferring the single-use consume to
/// the moment of code issuance ([`ActingPushedRequestRepo::consume`]). A peek proves
/// only that the reference resolves; it changes no state and writes no audit row.
pub struct PushedRequestRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl PushedRequestRepo<'_> {
    /// Read the stored authorization-request parameters for a LIVE (unconsumed,
    /// unexpired) `request_uri` bound to `presenting_client_id`, or [`None`] on any
    /// miss (absent, expired, already consumed, or presented under a different
    /// client). This does NOT consume the reference: single use is enforced only by
    /// [`ActingPushedRequestRepo::consume`] at issuance, so a login or consent
    /// interaction can re-present the same `request_uri` across the round-trip
    /// without burning it before an authenticated, consenting subject receives a code.
    ///
    /// The `client_id` filter is IN the query, so a reference presented under a
    /// different client resolves to [`None`] (RFC 9126 client binding), exactly like
    /// the consume, and a peek never reveals or burns another client's request. A
    /// forged or expired reference is likewise a uniform [`None`].
    ///
    /// `now` flows from the application clock seam (bound as epoch microseconds),
    /// never the database clock, so expiry is deterministic under a manual clock,
    /// consistent with the consume.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the reference identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn read(
        &self,
        env: &Env,
        id: &PushedRequestId,
        presenting_client_id: &str,
    ) -> Result<Option<String>, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, scope).await?;
        let row = sqlx::query(
            "SELECT request_params FROM pushed_authorization_requests \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 \
             AND client_id = $4 \
             AND consumed_at IS NULL \
             AND expires_at > TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval",
        )
        .bind(id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(presenting_client_id)
        .bind(now_micros)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| row.get::<String, _>("request_params")))
    }
}

/// The mutating pushed-authorization-request repository (RFC 9126, issue #27).
/// Reachable only through [`ScopedStore::acting`], so every push and consume carries
/// an actor and correlation id. The push routes through the module's single audited
/// write primitive; the consume is a bespoke committing path (it folds the atomic
/// single-use consume and its audit row into one transaction, exactly as the
/// authorization-code redeem does), documented at its call site.
pub struct ActingPushedRequestRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingPushedRequestRepo<'_> {
    /// Store a validated authorization request behind a one-time `request_uri`,
    /// auditing `pushed_authorization_request.push` in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the reference identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn push(&self, env: &Env, request: PushRequest<'_>) -> Result<(), StoreError> {
        if request.id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::PushedAuthorizationRequestPush,
                target: request.id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO pushed_authorization_requests \
                     (id, tenant_id, environment_id, client_id, request_params, expires_at, \
                      created_at) \
                     VALUES ($1, $2, $3, $4, $5, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
                )
                .bind(request.id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(request.client_id)
                .bind(request.request_params)
                .bind(request.expires_at_micros)
                .bind(request.created_at_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Atomically consume a `request_uri` exactly once, enforcing single use, expiry,
    /// AND the client binding in ONE statement, returning the stored parameters on
    /// the winning call.
    ///
    /// The consume is a single `UPDATE ... SET consumed_at = <now> WHERE id = $1 AND
    /// consumed_at IS NULL AND expires_at > <now> AND client_id = <presenter>
    /// RETURNING request_params`. Postgres serializes concurrent updates of the one
    /// row (READ COMMITTED, pinned in [`begin_scoped`]), so exactly one caller sees
    /// `consumed_at` NULL and gets [`ConsumePushedRequest::Consumed`]; every other
    /// concurrent presentation affects zero rows. Because the `client_id` filter is
    /// IN the statement, a request presented under a DIFFERENT `client_id` matches
    /// zero rows: it is a uniform miss AND it never burns the pending request, so the
    /// legitimate client's `request_uri` stays live (RFC 9126 client binding). Reuse
    /// and expiry likewise miss.
    ///
    /// On the winning branch exactly one `pushed_authorization_request.consume` audit
    /// row is written in this same transaction. A zero-row miss (reuse, expiry,
    /// absent, or client mismatch) writes no audit row and returns
    /// [`ConsumePushedRequest::Invalid`].
    ///
    /// `now` flows from the application clock seam (bound as epoch microseconds),
    /// never the database clock, so expiry is deterministic under a manual clock.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the reference identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn consume(
        &self,
        env: &Env,
        id: &PushedRequestId,
        presenting_client_id: &str,
    ) -> Result<ConsumePushedRequest, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());

        let mut tx = begin_scoped(self.store, scope).await?;
        let won = sqlx::query(
            "UPDATE pushed_authorization_requests \
             SET consumed_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
             AND client_id = $5 \
             AND consumed_at IS NULL \
             AND expires_at > TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             RETURNING request_params",
        )
        .bind(now_micros)
        .bind(id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(presenting_client_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = won else {
            // Zero rows: absent, expired, already consumed, or presented under a
            // different client_id. A uniform miss with no state change and no audit.
            tx.commit().await?;
            return Ok(ConsumePushedRequest::Invalid);
        };
        let request_params: String = row.get("request_params");
        let spec = AuditedWrite {
            store: self.store,
            scope,
            acting: &self.acting,
            env,
            action: Action::PushedAuthorizationRequestConsume,
            target: id,
        };
        insert_audit_row(&mut tx, &spec, None).await?;
        tx.commit().await?;
        Ok(ConsumePushedRequest::Consumed { request_params })
    }
}

// ===========================================================================
// Per-environment signing keys (issue #19).
//
// The persistence half of issuer and key isolation: every signing key is a
// tenant-scoped row, isolated exactly like `clients`, so the signing core's key
// lookup structurally cannot express a cross-tenant read. The row id is a `sik_`
// scoped identifier that doubles as the JOSE `kid`, so a kid is unique across an
// issuer's whole key history by construction. Everything below routes through the
// SAME scope filter and (for the provision) the SAME audited-write primitive as
// the rest of the data plane.
// ===========================================================================

/// The encoding of a stored signing key's private material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeyMaterialKind {
    /// A raw 32-byte Ed25519 seed (RFC 8032).
    Ed25519Seed,
    /// An ECDSA PKCS#8 v1 document (P-256 or P-384).
    EcdsaPkcs8,
    /// An RSA PKCS#1 `RSAPrivateKey` DER document.
    RsaPkcs1Der,
}

impl SigningKeyMaterialKind {
    /// The stable wire string recorded in `signing_keys.material_kind`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningKeyMaterialKind::Ed25519Seed => "ed25519_seed",
            SigningKeyMaterialKind::EcdsaPkcs8 => "ecdsa_pkcs8",
            SigningKeyMaterialKind::RsaPkcs1Der => "rsa_pkcs1_der",
        }
    }

    /// Parse a stored `material_kind` value.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "ed25519_seed" => Some(SigningKeyMaterialKind::Ed25519Seed),
            "ecdsa_pkcs8" => Some(SigningKeyMaterialKind::EcdsaPkcs8),
            "rsa_pkcs1_der" => Some(SigningKeyMaterialKind::RsaPkcs1Der),
            _ => None,
        }
    }
}

/// Private signing-key material, wrapped so it never prints or logs.
///
/// The bytes are exposed only through [`SigningKeyMaterial::expose`], at the one
/// call site that reconstructs a live signing key. A struct dump or a `tracing`
/// field renders `<redacted>` instead.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKeyMaterial(Vec<u8>);

impl SigningKeyMaterial {
    /// The raw material bytes, for reconstructing a signing key.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render private key material: only that it is present and its size.
        f.debug_struct("SigningKeyMaterial")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A signing key to provision, all values minted or resolved under the caller's
/// scope. The four lifecycle instants are epoch microseconds from the application
/// clock seam (never the database clock). `Debug` redacts the material.
#[derive(Clone, Copy)]
pub struct NewSigningKey<'a> {
    /// The `sik_` identifier (also the JOSE `kid`), minted under this scope.
    pub id: &'a SigningKeyId,
    /// The JOSE algorithm name (for example `EdDSA`, `ES256`, `RS256`).
    pub algorithm: &'a str,
    /// How the private material is encoded.
    pub material_kind: SigningKeyMaterialKind,
    /// The private key material bytes.
    pub material: &'a [u8],
    /// When the key first appears in the published JWKS, in epoch microseconds.
    pub publish_at_micros: i64,
    /// When the key first signs, in epoch microseconds.
    pub activate_at_micros: i64,
    /// When a successor takes over, in epoch microseconds (absent while head).
    pub retire_at_micros: Option<i64>,
    /// When the key is withdrawn from the JWKS, in epoch microseconds (absent
    /// while not retired).
    pub expire_at_micros: Option<i64>,
}

impl fmt::Debug for NewSigningKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSigningKey")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("material_kind", &self.material_kind)
            .field("publish_at_micros", &self.publish_at_micros)
            .field("activate_at_micros", &self.activate_at_micros)
            .finish_non_exhaustive()
    }
}

/// A signing key read back from the `signing_keys` table, always within scope.
/// `Debug` redacts the private material.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKeyRecord {
    /// The `sik_` identifier (also the JOSE `kid`), embedding its scope.
    pub id: SigningKeyId,
    /// The JOSE algorithm name.
    pub algorithm: String,
    /// How the private material is encoded.
    pub material_kind: SigningKeyMaterialKind,
    /// The private key material, redacted in `Debug`.
    pub material: SigningKeyMaterial,
    /// When the key first appears in the published JWKS, in epoch microseconds.
    pub publish_at_unix_micros: i64,
    /// When the key first signs, in epoch microseconds.
    pub activate_at_unix_micros: i64,
    /// When a successor takes over, in epoch microseconds (absent while head).
    pub retire_at_unix_micros: Option<i64>,
    /// When the key is withdrawn from the JWKS, in epoch microseconds (absent
    /// while not retired).
    pub expire_at_unix_micros: Option<i64>,
}

impl fmt::Debug for SigningKeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeyRecord")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("material_kind", &self.material_kind)
            .field("publish_at_unix_micros", &self.publish_at_unix_micros)
            .field("activate_at_unix_micros", &self.activate_at_unix_micros)
            .field("retire_at_unix_micros", &self.retire_at_unix_micros)
            .field("expire_at_unix_micros", &self.expire_at_unix_micros)
            .finish_non_exhaustive()
    }
}

/// The read-only repository for a scope's signing keys (issue #19).
pub struct SigningKeyRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl SigningKeyRepo<'_> {
    /// Parse an untrusted signing-key identifier under this scope. A malformed
    /// identifier and one minted in another scope both return the uniform
    /// not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<SigningKeyId, StoreError> {
        Ok(SigningKeyId::parse_in_scope(raw, &self.scope)?)
    }

    /// Fetch a signing key by identifier, within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such key is visible in this scope.
    pub async fn get(&self, id: &SigningKeyId) -> Result<SigningKeyRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, algorithm, material_kind, key_material, \
             (EXTRACT(EPOCH FROM publish_at) * 1000000)::bigint AS publish_us, \
             (EXTRACT(EPOCH FROM activate_at) * 1000000)::bigint AS activate_us, \
             (EXTRACT(EPOCH FROM retire_at) * 1000000)::bigint AS retire_us, \
             (EXTRACT(EPOCH FROM expire_at) * 1000000)::bigint AS expire_us \
             FROM signing_keys \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        signing_key_from_row(&row, &self.scope)
    }

    /// Every signing key in this scope, oldest first (the key history for this
    /// environment's issuer).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure, or if a stored row fails
    /// to decode.
    pub async fn list(&self) -> Result<Vec<SigningKeyRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, algorithm, material_kind, key_material, \
             (EXTRACT(EPOCH FROM publish_at) * 1000000)::bigint AS publish_us, \
             (EXTRACT(EPOCH FROM activate_at) * 1000000)::bigint AS activate_us, \
             (EXTRACT(EPOCH FROM retire_at) * 1000000)::bigint AS retire_us, \
             (EXTRACT(EPOCH FROM expire_at) * 1000000)::bigint AS expire_us \
             FROM signing_keys \
             WHERE tenant_id = $1 AND environment_id = $2 \
             ORDER BY created_at, id",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| signing_key_from_row(row, &self.scope))
            .collect()
    }
}

/// The read-only environment-guardrail repository for one scope (issue #42).
///
/// Reads the environment's typed [`GuardrailSet`] from the scope-forced
/// `environment_guardrails` projection (a definer view keyed on the same scope
/// session variables the repository binds), so the data-plane registration paths
/// enforce the two-class guardrail asymmetry (an `http` loopback redirect is
/// registrable in a `dev`/`staging` environment and rejected in `prod`) WITHOUT a
/// direct grant on the environments level table.
pub struct EnvironmentGuardrailRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl EnvironmentGuardrailRepo<'_> {
    /// Resolve this environment's typed guardrail set, derived from its persisted
    /// `kind`.
    ///
    /// The read is scope-bound: the projection returns only the row whose
    /// `(tenant, environment)` matches the bound scope, so a request can never read
    /// another environment's kind. A `kind` outside the closed set (impossible under
    /// the column CHECK) fails closed as a database error rather than a coerced
    /// default.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the environment has no projection row in scope
    /// (an unprovisioned or cross-scope environment); [`StoreError::Database`] on a
    /// persistence fault or an unparseable stored kind.
    pub async fn guardrails(&self) -> Result<GuardrailSet, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT kind FROM environment_guardrails \
             WHERE tenant_id = $1 AND environment_id = $2",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        let kind_text: String = row.get("kind");
        let kind = EnvironmentType::parse(&kind_text).map_err(|e| {
            StoreError::Database(sqlx::Error::Decode(
                format!("unknown environment kind: {}", e.value).into(),
            ))
        })?;
        Ok(GuardrailSet::for_kind(kind))
    }
}

/// The mutating signing-key repository (issue #19). Reachable only through
/// [`ScopedStore::acting`], so every provision carries an actor and correlation
/// id, and routes through the module's single audited-write primitive.
pub struct ActingSigningKeyRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingSigningKeyRepo<'_> {
    /// Provision a signing key (a day-one key or a manually rotated-in successor)
    /// and audit `signing_key.provision` in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn provision(&self, env: &Env, key: NewSigningKey<'_>) -> Result<(), StoreError> {
        if key.id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::SigningKeyProvision,
                target: key.id,
            },
            async move |tx| insert_signing_key_row(tx, &scope, &key).await,
            false,
        )
        .await
    }
}

/// Insert one signing key row into the CURRENT scoped transaction. The
/// transaction must already be bound to `scope` (the row-level-security policy on
/// `signing_keys` keys on it), and `key.id` must belong to `scope`.
///
/// Shared by the manual [`ActingSigningKeyRepo::provision`] path and the day-one
/// key provisioned inside environment creation (issue #42), so the two never
/// drift.
async fn insert_signing_key_row(
    tx: &mut Transaction<'_, Postgres>,
    scope: &Scope,
    key: &NewSigningKey<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO signing_keys \
         (id, tenant_id, environment_id, algorithm, material_kind, key_material, \
          publish_at, activate_at, retire_at, expire_at) \
         VALUES ($1, $2, $3, $4, $5, $6, \
                 TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval, \
                 TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval, \
                 CASE WHEN $9::bigint IS NULL THEN NULL ELSE \
                     TIMESTAMPTZ 'epoch' + ($9::text || ' microseconds')::interval END, \
                 CASE WHEN $10::bigint IS NULL THEN NULL ELSE \
                     TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval END)",
    )
    .bind(key.id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(key.algorithm)
    .bind(key.material_kind.as_str())
    .bind(key.material)
    .bind(key.publish_at_micros)
    .bind(key.activate_at_micros)
    .bind(key.retire_at_micros)
    .bind(key.expire_at_micros)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Reconstruct a [`SigningKeyRecord`] from a row read within scope.
fn signing_key_from_row(row: &PgRow, scope: &Scope) -> Result<SigningKeyRecord, StoreError> {
    let id_text: String = row.get("id");
    let id = SigningKeyId::parse_in_scope(&id_text, scope)?;
    let kind_text: String = row.get("material_kind");
    let material_kind = SigningKeyMaterialKind::parse(&kind_text).ok_or_else(|| {
        StoreError::Database(sqlx::Error::Decode(
            format!("unknown signing key material kind: {kind_text}").into(),
        ))
    })?;
    let material: Vec<u8> = row.get("key_material");
    Ok(SigningKeyRecord {
        id,
        algorithm: row.get("algorithm"),
        material_kind,
        material: SigningKeyMaterial(material),
        publish_at_unix_micros: row.get("publish_us"),
        activate_at_unix_micros: row.get("activate_us"),
        retire_at_unix_micros: row.get("retire_us"),
        expire_at_unix_micros: row.get("expire_us"),
    })
}

// ===========================================================================
// Resource servers and opaque access tokens (issue #29).
//
// The persistence half of per-resource-server access-token formats: a registry
// mapping an audience to the token format that resource server receives, and the
// digest-only store for opaque reference tokens. Both are tenant-scoped rows
// isolated exactly like every other data-plane table, reached only through the
// scoped repository (ironauth_app), so the format selection and the opaque-token
// resolve are structurally scope-bound like every other read.
// ===========================================================================

/// The access-token format a resource server receives (issue #29).
///
/// An `at+jwt` is a self-contained RFC 9068 signed JWT; an opaque token is a
/// random reference token whose state lives only in the store (digest-only). The
/// mint selects the format from the targeted resource server, defaulting to the
/// environment default when no resource server is targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFormat {
    /// An RFC 9068 `at+jwt` signed access token.
    AtJwt,
    /// An opaque, digest-only reference access token.
    Opaque,
}

impl TokenFormat {
    /// The stable wire string recorded in `resource_servers.token_format`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenFormat::AtJwt => "at_jwt",
            TokenFormat::Opaque => "opaque",
        }
    }

    /// Parse a stored `token_format` value. Returns [`None`] for an unknown value
    /// (a row a newer build wrote), so the caller fails closed rather than
    /// guessing a format.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "at_jwt" => Some(TokenFormat::AtJwt),
            "opaque" => Some(TokenFormat::Opaque),
            _ => None,
        }
    }
}

/// A resource server read back from the `resource_servers` table, always within
/// scope (issue #29). The mint reads it by audience to select the access-token
/// format and lifetime a registered protected API receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServerRecord {
    /// The `rsv_` identifier (embeds its tenant and environment).
    pub id: ResourceServerId,
    /// The resource-server identifier / resource URI a token targets.
    pub audience: String,
    /// The access-token format this resource server receives.
    pub token_format: TokenFormat,
    /// The per-resource-server access-token lifetime in seconds, or [`None`] to
    /// fall back to the environment default lifetime.
    pub access_token_ttl_secs: Option<i64>,
}

/// A resource server to register (issue #29). The `id` is minted under the
/// caller's scope; the `audience` is unique per environment.
#[derive(Debug, Clone, Copy)]
pub struct NewResourceServer<'a> {
    /// The `rsv_` identifier, minted under this scope.
    pub id: &'a ResourceServerId,
    /// The resource-server identifier / resource URI a token targets.
    pub audience: &'a str,
    /// The access-token format this resource server receives.
    pub token_format: TokenFormat,
    /// The per-resource-server access-token lifetime in seconds, or [`None`] for
    /// the environment default.
    pub access_token_ttl_secs: Option<i64>,
}

/// The read-only resource-server repository (issue #29).
pub struct ResourceServerRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ResourceServerRepo<'_> {
    /// Fetch a resource server by its `audience` within scope, or [`None`] when no
    /// resource server with that audience is registered in this scope (absent, or
    /// belonging to another tenant or environment: the outcomes are
    /// indistinguishable). The mint calls this to select the access-token format
    /// for a targeted resource/audience.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure, or if a stored row fails
    /// to decode (an unknown token format).
    pub async fn by_audience(
        &self,
        audience: &str,
    ) -> Result<Option<ResourceServerRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, audience, token_format, access_token_ttl_secs FROM resource_servers \
             WHERE audience = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(audience)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => Ok(Some(resource_server_from_row(&row, &self.scope)?)),
        }
    }

    /// List every resource server registered in this scope, ordered by
    /// `audience` (issue #43). The audience is unique per environment, so this is
    /// a total, stable order with no volatile tiebreaker: the canonical snapshot
    /// export (`crate::snapshot`) reads it to emit the promotable resource-server
    /// registry deterministically.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure, or if a stored row fails
    /// to decode (an unknown token format).
    pub async fn list(&self) -> Result<Vec<ResourceServerRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, audience, token_format, access_token_ttl_secs FROM resource_servers \
             WHERE tenant_id = $1 AND environment_id = $2 ORDER BY audience",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| resource_server_from_row(row, &self.scope))
            .collect()
    }
}

/// The mutating resource-server repository (issue #29). Reachable only through
/// [`ScopedStore::acting`], so every registration carries an actor and
/// correlation id and routes through the audited-write primitive.
pub struct ActingResourceServerRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingResourceServerRepo<'_> {
    /// Register a resource server and audit `resource_server.register` in the same
    /// transaction, returning nothing (the caller minted the id).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope;
    /// [`StoreError::Conflict`] if the audience is already registered in this
    /// environment; [`StoreError::Database`] on a persistence failure.
    pub async fn register(
        &self,
        env: &Env,
        server: NewResourceServer<'_>,
    ) -> Result<(), StoreError> {
        if server.id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ResourceServerRegister,
                target: server.id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "INSERT INTO resource_servers \
                     (id, tenant_id, environment_id, audience, token_format, access_token_ttl_secs) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(server.id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(server.audience)
                .bind(server.token_format.as_str())
                .bind(server.access_token_ttl_secs)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => Ok(()),
                    // A duplicate audience is a caller-facing conflict (the audience
                    // is taken), not a persistence fault. Erroring here rolls the
                    // audited write back, so a rejected registration leaves neither a
                    // resource-server row nor an audit row.
                    Err(error) if is_unique_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await
    }
}

/// Reconstruct a [`ResourceServerRecord`] from a row read within scope.
fn resource_server_from_row(
    row: &PgRow,
    scope: &Scope,
) -> Result<ResourceServerRecord, StoreError> {
    let id_text: String = row.get("id");
    let id = ResourceServerId::parse_in_scope(&id_text, scope)?;
    let format_text: String = row.get("token_format");
    let token_format = TokenFormat::parse(&format_text).ok_or_else(|| {
        StoreError::Database(sqlx::Error::Decode(
            format!("unknown resource-server token format: {format_text}").into(),
        ))
    })?;
    Ok(ResourceServerRecord {
        id,
        audience: row.get("audience"),
        token_format,
        access_token_ttl_secs: row.get("access_token_ttl_secs"),
    })
}

/// The outcome of recording a JWT-assertion `jti` (issue #25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JtiOutcome {
    /// The `jti` was recorded: this is its first (and single) use.
    Recorded,
    /// The `jti` was already present: a REPLAY, so the assertion is rejected.
    Replayed,
}

/// The single-use JWT-assertion `jti` replay cache (issue #25).
///
/// This is the cross-node replay-prevention store. Recording an accepted
/// assertion's `jti` is an INSERT into one shared table; a primary-key conflict is
/// a REPLAY. Because every server node inserts into the SAME row space, the
/// database enforces single use across nodes: two nodes that race the same `jti`
/// cannot both insert it, so exactly one sees [`JtiOutcome::Recorded`] and the
/// other [`JtiOutcome::Replayed`].
///
/// The recording is deliberately OFF the audited-write path (it is a security
/// cache, not a business mutation, exactly like `idempotency_keys`); it is still
/// confined to this repository module and RLS-scoped.
pub struct ClientAssertionJtiRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ClientAssertionJtiRepo<'_> {
    /// Record `jti` for `client_id` as single-use in this scope, first pruning any
    /// already-expired rows.
    ///
    /// `expires_at_micros` is the last instant the assertion could still be
    /// replayed (its `exp` PLUS the configured skew), so a pruned row can never
    /// remove a `jti` whose assertion is still acceptable. The prune uses the
    /// application clock seam (`env`), never the database clock, so it is
    /// deterministic under a manual clock in tests.
    ///
    /// Returns [`JtiOutcome::Recorded`] on the first use and [`JtiOutcome::Replayed`]
    /// when the `jti` was already present (a second use, from this or any other
    /// node).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn record(
        &self,
        env: &Env,
        client_id: &str,
        jti: &str,
        expires_at_micros: i64,
    ) -> Result<JtiOutcome, StoreError> {
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // Prune rows whose last-replayable instant has passed. Only these are
        // removed, so a still-valid assertion's jti is never dropped.
        sqlx::query(
            "DELETE FROM client_assertion_jtis \
             WHERE tenant_id = $1 AND environment_id = $2 \
             AND expires_at <= TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(now_micros)
        .execute(&mut *tx)
        .await?;
        let result = sqlx::query(
            "INSERT INTO client_assertion_jtis \
             (tenant_id, environment_id, client_id, jti, expires_at) \
             VALUES ($1, $2, $3, $4, \
                     TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval)",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(client_id)
        .bind(jti)
        .bind(expires_at_micros)
        .execute(&mut *tx)
        .await;
        match result {
            Ok(_) => {
                tx.commit().await?;
                Ok(JtiOutcome::Recorded)
            }
            // A primary-key conflict is a replay: the jti was already used. Roll
            // back (the prune, if any, need not persist) and report the replay.
            Err(error) if is_unique_violation(&error) => {
                tx.rollback().await?;
                Ok(JtiOutcome::Replayed)
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// A bounded-cardinality reason a client authentication OR a JWT bearer assertion
/// grant validation failed (issues #25 and #26), recorded in the diagnostics sink.
/// No attacker-controlled free text, so it is safe as a metric-like dimension and
/// never an oracle on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthDiagnosticReason {
    /// The presented credentials could not be parsed into one coherent attempt
    /// (more than one method, a malformed header, a missing or conflicting id).
    Unparsable,
    /// The client is unknown in this scope, or its identifier was malformed.
    UnknownClient,
    /// The presented method did not match the client's single registered method.
    MethodMismatch,
    /// A presented secret did not match the client's stored hash.
    BadSecret,
    /// A JWT assertion did not verify (bad signature, wrong iss/sub/aud, expired,
    /// unsupported or disallowed algorithm, or unresolvable keys).
    AssertionInvalid,
    /// A JWT assertion's `jti` was replayed (already used).
    ReplayedJti,
    /// The `client_secret_jwt` method is registered but unsupported: IronAuth
    /// stores no retrievable secret to key its HMAC, so it fails closed.
    ClientSecretJwtUnsupported,
    /// A JWT bearer assertion grant assertion named an `iss` that is not a
    /// registered, ENABLED external issuer in this scope (issue #26).
    AssertionIssuerUntrusted,
    /// A JWT bearer assertion grant assertion verified, but its (issuer, `sub`)
    /// names no registered subject-mapping rule (or the rule's optional claim gate
    /// did not match): the subject is rejected, never auto-provisioned (issue #26).
    AssertionSubjectUnmapped,
}

impl ClientAuthDiagnosticReason {
    /// The stable wire string recorded in the diagnostics row.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClientAuthDiagnosticReason::Unparsable => "unparsable",
            ClientAuthDiagnosticReason::UnknownClient => "unknown_client",
            ClientAuthDiagnosticReason::MethodMismatch => "method_mismatch",
            ClientAuthDiagnosticReason::BadSecret => "bad_secret",
            ClientAuthDiagnosticReason::AssertionInvalid => "assertion_invalid",
            ClientAuthDiagnosticReason::ReplayedJti => "replayed_jti",
            ClientAuthDiagnosticReason::ClientSecretJwtUnsupported => {
                "client_secret_jwt_unsupported"
            }
            ClientAuthDiagnosticReason::AssertionIssuerUntrusted => "assertion_issuer_untrusted",
            ClientAuthDiagnosticReason::AssertionSubjectUnmapped => "assertion_subject_unmapped",
        }
    }
}

/// How long a client-authentication diagnostic is retained before the on-insert
/// prune reclaims it (issue #25), in epoch microseconds (the unit the clock seam and
/// the prune bind). Seven days is enough for the M9 admin view to surface a recent
/// burst of failures, while bounding the table so the pre-grant reuse of the
/// `authenticate_client` seam by #22 introspection/revocation cannot grow it without
/// limit from unauthenticated requests. 7 days in microseconds is well within `i64`.
const DIAGNOSTIC_RETENTION_MICROS: i64 = 7 * 24 * 60 * 60 * 1_000_000;

/// A client-authentication failure diagnostic to record (issue #25). Carries the
/// rich, structured detail kept OFF the wire.
#[derive(Debug, Clone, Copy)]
pub struct NewClientAuthDiagnostic<'a> {
    /// The client identifier the attempt claimed (best effort on a failure).
    pub client_id: &'a str,
    /// The token-endpoint authentication method the attempt used.
    pub auth_method: &'a str,
    /// The bounded-cardinality failure reason.
    pub reason: ClientAuthDiagnosticReason,
    /// The assertion header's `kid`, if the attempt presented a JWT assertion.
    pub key_id: Option<&'a str>,
    /// The assertion header's `alg`, if the attempt presented a JWT assertion.
    pub signing_alg: Option<&'a str>,
}

/// A read-back client-authentication diagnostic row (issue #25), for the future
/// M9 admin view and for tests asserting a failure was recorded out of band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthDiagnosticRecord {
    /// The client identifier the attempt claimed.
    pub client_id: String,
    /// The authentication method the attempt used.
    pub auth_method: String,
    /// The bounded-cardinality failure reason (see [`ClientAuthDiagnosticReason`]).
    pub failure_reason: String,
    /// The assertion header `kid`, if any.
    pub key_id: Option<String>,
    /// The assertion header `alg`, if any.
    pub signing_alg: Option<String>,
}

/// The out-of-band client-authentication diagnostics sink (issue #25).
///
/// Records a failed client authentication's rich, structured detail (the method
/// attempted, the bounded-cardinality reason, and the assertion header's key id
/// and algorithm) for the future M9 admin view, so the wire can stay a uniform,
/// opaque `invalid_client` with no oracle. Append-only and deliberately off the
/// audited-write path (a diagnostic is a log entry, not a business mutation),
/// mirroring `idempotency_keys`.
pub struct ClientAuthDiagnosticsRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ClientAuthDiagnosticsRepo<'_> {
    /// Record a client-authentication failure diagnostic in this scope, first
    /// pruning any rows past their retention window. The event time comes from the
    /// application clock seam (`env`), so both the recorded time and the prune are
    /// deterministic under a manual clock in tests.
    ///
    /// The prune bounds the table: issue #22 introspection/revocation reuses the
    /// `authenticate_client` seam PRE-grant, where an unauthenticated caller reaches
    /// this sink, so without retention it would grow one row per request. The window
    /// is [`DIAGNOSTIC_RETENTION_MICROS`], long enough for the M9 admin view. This is
    /// a growth bound, NOT rate limiting.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn record(
        &self,
        env: &Env,
        diagnostic: NewClientAuthDiagnostic<'_>,
    ) -> Result<(), StoreError> {
        let id = random_diagnostic_id(env);
        let occurred_micros = epoch_micros(env.clock().now_utc());
        let expires_micros = occurred_micros.saturating_add(DIAGNOSTIC_RETENTION_MICROS);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // Prune rows past their retention window before inserting (prune-then-insert,
        // exactly like the jti cache). Bounds the table under the pre-grant reuse by
        // #22; only already-expired rows are removed.
        sqlx::query(
            "DELETE FROM client_auth_diagnostics \
             WHERE tenant_id = $1 AND environment_id = $2 \
             AND expires_at <= TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(occurred_micros)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO client_auth_diagnostics \
             (id, tenant_id, environment_id, client_id, auth_method, failure_reason, \
              key_id, signing_alg, occurred_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, \
                     TIMESTAMPTZ 'epoch' + ($9::text || ' microseconds')::interval, \
                     TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval)",
        )
        .bind(id)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(diagnostic.client_id)
        .bind(diagnostic.auth_method)
        .bind(diagnostic.reason.as_str())
        .bind(diagnostic.key_id)
        .bind(diagnostic.signing_alg)
        .bind(occurred_micros)
        .bind(expires_micros)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Read every recorded diagnostic for `client_id` in this scope, oldest first.
    /// For the future M9 admin view and for tests asserting a failure was recorded.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn for_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<ClientAuthDiagnosticRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT client_id, auth_method, failure_reason, key_id, signing_alg \
             FROM client_auth_diagnostics \
             WHERE client_id = $1 AND tenant_id = $2 AND environment_id = $3 \
             ORDER BY occurred_at, id",
        )
        .bind(client_id)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .iter()
            .map(|row| ClientAuthDiagnosticRecord {
                client_id: row.get("client_id"),
                auth_method: row.get("auth_method"),
                failure_reason: row.get("failure_reason"),
                key_id: row.get("key_id"),
                signing_alg: row.get("signing_alg"),
            })
            .collect())
    }
}

// ===========================================================================
// The JWT bearer assertion grant trust and mapping stores (issue #26).
// ===========================================================================

/// A registered external assertion issuer read back within scope (issue #26): the
/// trust anchor an inbound JWT bearer assertion's `iss` names, plus its key source,
/// signing-alg allowlist, and enable switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAssertionIssuerRecord {
    /// The `xai_` identifier (embeds its tenant and environment).
    pub id: ExternalIssuerId,
    /// The external issuer's `iss` claim value.
    pub issuer: String,
    /// The inline pinned JWK Set JSON, or [`None`] when keys are at `jwks_uri`.
    pub jwks: Option<String>,
    /// The issuer's JWKS URL (fetched through the SSRF-hardened fetcher), or [`None`]
    /// when keys are pinned inline. At most one of `jwks`/`jwks_uri` is set.
    pub jwks_uri: Option<String>,
    /// An OPTIONAL space-separated JOSE algorithm allowlist for this issuer's
    /// assertions; [`None`] means the supported asymmetric set applies.
    pub signing_alg_allow: Option<String>,
    /// The enable switch. A disabled issuer's assertions are rejected exactly as an
    /// unregistered issuer's are.
    pub enabled: bool,
}

/// An external assertion issuer to register (issue #26). The `id` is minted under
/// the caller's scope; the `issuer` is unique per environment. Exactly one of
/// `jwks`/`jwks_uri` must be set (a database CHECK enforces it).
#[derive(Debug, Clone, Copy)]
pub struct NewExternalAssertionIssuer<'a> {
    /// The `xai_` identifier, minted under this scope.
    pub id: &'a ExternalIssuerId,
    /// The external issuer's `iss` claim value.
    pub issuer: &'a str,
    /// The inline pinned JWK Set JSON, or [`None`] to register a `jwks_uri` instead.
    pub jwks: Option<&'a str>,
    /// The issuer's JWKS URL, or [`None`] to register inline `jwks` instead.
    pub jwks_uri: Option<&'a str>,
    /// The OPTIONAL space-separated JOSE algorithm allowlist, or [`None`].
    pub signing_alg_allow: Option<&'a str>,
    /// The enable switch to register the issuer with.
    pub enabled: bool,
}

/// The read-only registered external assertion issuer repository (issue #26).
pub struct ExternalAssertionIssuerRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ExternalAssertionIssuerRepo<'_> {
    /// Fetch a registered external assertion issuer by its `issuer` string within
    /// scope, or [`None`] when none is registered (absent, or belonging to another
    /// tenant or environment: indistinguishable). The JWT bearer grant calls this to
    /// resolve the trust anchor an assertion's `iss` names before verifying it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure, or if a stored row fails to
    /// decode (an out-of-scope identifier).
    pub async fn by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Option<ExternalAssertionIssuerRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, issuer, jwks, jwks_uri, signing_alg_allow, enabled \
             FROM external_assertion_issuers \
             WHERE issuer = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(issuer)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => {
                let id_text: String = row.get("id");
                let id = ExternalIssuerId::parse_in_scope(&id_text, &self.scope)?;
                Ok(Some(ExternalAssertionIssuerRecord {
                    id,
                    issuer: row.get("issuer"),
                    jwks: row.get("jwks"),
                    jwks_uri: row.get("jwks_uri"),
                    signing_alg_allow: row.get("signing_alg_allow"),
                    enabled: row.get("enabled"),
                }))
            }
        }
    }
}

/// The mutating external assertion issuer repository (issue #26). Reachable only
/// through [`ScopedStore::acting`], so every registration carries an actor and
/// correlation id and routes through the audited-write primitive.
pub struct ActingExternalAssertionIssuerRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingExternalAssertionIssuerRepo<'_> {
    /// Register an external assertion issuer and audit
    /// `external_assertion_issuer.register` in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope;
    /// [`StoreError::Conflict`] if the issuer is already registered in this
    /// environment, or the key source is not exactly one of `jwks`/`jwks_uri` (the
    /// database CHECK); [`StoreError::Database`] on a persistence failure.
    pub async fn register(
        &self,
        env: &Env,
        issuer: NewExternalAssertionIssuer<'_>,
    ) -> Result<(), StoreError> {
        if issuer.id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ExternalAssertionIssuerRegister,
                target: issuer.id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "INSERT INTO external_assertion_issuers \
                     (id, tenant_id, environment_id, issuer, jwks, jwks_uri, \
                      signing_alg_allow, enabled) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind(issuer.id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(issuer.issuer)
                .bind(issuer.jwks)
                .bind(issuer.jwks_uri)
                .bind(issuer.signing_alg_allow)
                .bind(issuer.enabled)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => Ok(()),
                    // A duplicate issuer OR a CHECK violation (not exactly one key
                    // source) is a caller-facing conflict, not a persistence fault:
                    // erroring here rolls the audited write back, so a rejected
                    // registration leaves neither an issuer row nor an audit row.
                    Err(error) if is_unique_violation(&error) || is_check_violation(&error) => {
                        Err(StoreError::Conflict)
                    }
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await
    }

    /// Toggle a registered external assertion issuer's enable switch (issue #26),
    /// auditing `external_assertion_issuer.set_enabled` in the same transaction.
    ///
    /// This is the data-plane REVOCATION capability: DISABLING a compromised or
    /// decommissioned issuer makes the grant reject its assertions exactly as an
    /// unregistered issuer's are (the grant filters on `enabled`). The COLUMN-SCOPED
    /// `GRANT UPDATE (enabled)` is the enforcement: this path can flip only `enabled`,
    /// never the issuer's identity, key source, or signing-alg allowlist. Idempotent:
    /// re-setting the same value still updates the one row.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope or names no
    /// issuer visible here; [`StoreError::Database`] on a persistence failure.
    pub async fn set_enabled(
        &self,
        env: &Env,
        id: &ExternalIssuerId,
        enabled: bool,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ExternalAssertionIssuerSetEnabled,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE external_assertion_issuers SET enabled = $1 \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
                )
                .bind(enabled)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }
}

/// A registered subject-mapping rule read back within scope (issue #26): the
/// explicit rule that maps an external (issuer + `sub`), optionally gated on an
/// additional claim, to an IronAuth principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionSubjectMappingRecord {
    /// The `asm_` identifier (embeds its tenant and environment).
    pub id: AssertionMappingId,
    /// The external issuer this rule maps from.
    pub issuer: String,
    /// The external `sub` this rule maps from.
    pub external_subject: String,
    /// An OPTIONAL additional claim NAME the assertion must carry with
    /// `match_value` for the rule to fire; [`None`] when the (issuer, sub) match
    /// alone suffices.
    pub match_claim: Option<String>,
    /// The value the OPTIONAL `match_claim` must equal; [`None`] when `match_claim`
    /// is [`None`].
    pub match_value: Option<String>,
    /// The IronAuth principal the mapped token is issued under (the token's `sub`).
    pub principal: String,
}

/// A subject-mapping rule to author (issue #26). The `id` is minted under the
/// caller's scope; one rule per (issuer, `external_subject`) per environment. The
/// optional claim gate is all-or-nothing (both `match_claim`/`match_value` set, or
/// both [`None`]); a database CHECK enforces it.
#[derive(Debug, Clone, Copy)]
pub struct NewAssertionSubjectMapping<'a> {
    /// The `asm_` identifier, minted under this scope.
    pub id: &'a AssertionMappingId,
    /// The external issuer this rule maps from.
    pub issuer: &'a str,
    /// The external `sub` this rule maps from.
    pub external_subject: &'a str,
    /// The OPTIONAL additional claim NAME, or [`None`].
    pub match_claim: Option<&'a str>,
    /// The OPTIONAL additional claim VALUE, or [`None`] (paired with `match_claim`).
    pub match_value: Option<&'a str>,
    /// The IronAuth principal the mapped token is issued under.
    pub principal: &'a str,
}

/// The read-only subject-mapping repository for the JWT bearer assertion grant
/// (issue #26).
pub struct AssertionSubjectMappingRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl AssertionSubjectMappingRepo<'_> {
    /// Resolve the ENABLED mapping rule for a verified external (`issuer`,
    /// `external_subject`) within scope, or [`None`] when no enabled rule is
    /// registered. The lookup FILTERS on `enabled = true`, so a DISABLED (revoked)
    /// mapping resolves to [`None`] and the grant rejects the subject exactly as an
    /// absent one. The grant applies the rule's OPTIONAL claim gate itself against the
    /// verified claims, then issues the token under `principal`. A [`None`] here is the
    /// reject-by-default posture: an unmapped subject is rejected, never
    /// auto-provisioned.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure, or if a stored row fails to
    /// decode (an out-of-scope identifier).
    pub async fn resolve(
        &self,
        issuer: &str,
        external_subject: &str,
    ) -> Result<Option<AssertionSubjectMappingRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, issuer, external_subject, match_claim, match_value, principal \
             FROM external_assertion_subject_mappings \
             WHERE issuer = $1 AND external_subject = $2 \
             AND tenant_id = $3 AND environment_id = $4 AND enabled = true",
        )
        .bind(issuer)
        .bind(external_subject)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => {
                let id_text: String = row.get("id");
                let id = AssertionMappingId::parse_in_scope(&id_text, &self.scope)?;
                Ok(Some(AssertionSubjectMappingRecord {
                    id,
                    issuer: row.get("issuer"),
                    external_subject: row.get("external_subject"),
                    match_claim: row.get("match_claim"),
                    match_value: row.get("match_value"),
                    principal: row.get("principal"),
                }))
            }
        }
    }
}

/// The mutating subject-mapping repository for the JWT bearer assertion grant (issue
/// #26). Reachable only through [`ScopedStore::acting`], so every mapping carries an
/// actor and correlation id and routes through the audited-write primitive.
pub struct ActingAssertionSubjectMappingRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingAssertionSubjectMappingRepo<'_> {
    /// Author a subject-mapping rule and audit
    /// `external_assertion_subject_mapping.create` in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope;
    /// [`StoreError::Conflict`] if a rule for the same (issuer, `external_subject`) is
    /// already registered, or the claim gate is half-configured (the database CHECK);
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create(
        &self,
        env: &Env,
        mapping: NewAssertionSubjectMapping<'_>,
    ) -> Result<(), StoreError> {
        if mapping.id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ExternalAssertionSubjectMappingCreate,
                target: mapping.id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "INSERT INTO external_assertion_subject_mappings \
                     (id, tenant_id, environment_id, issuer, external_subject, \
                      match_claim, match_value, principal) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind(mapping.id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(mapping.issuer)
                .bind(mapping.external_subject)
                .bind(mapping.match_claim)
                .bind(mapping.match_value)
                .bind(mapping.principal)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => Ok(()),
                    Err(error) if is_unique_violation(&error) || is_check_violation(&error) => {
                        Err(StoreError::Conflict)
                    }
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await
    }

    /// Toggle a subject-mapping rule's enable switch (issue #26), auditing
    /// `external_assertion_subject_mapping.set_enabled` in the same transaction.
    ///
    /// This is the data-plane REVOCATION capability: DISABLING a mis-authored or
    /// decommissioned mapping makes the resolve return no rule, so the grant rejects
    /// the subject exactly as an unmapped one (never auto-provisions). The
    /// COLUMN-SCOPED `GRANT UPDATE (enabled)` is the enforcement: this path can flip
    /// only `enabled`, never the rule's issuer, subject, claim gate, or principal.
    /// Idempotent: re-setting the same value still updates the one row.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is out of this scope or names no
    /// mapping visible here; [`StoreError::Database`] on a persistence failure.
    pub async fn set_enabled(
        &self,
        env: &Env,
        id: &AssertionMappingId,
        enabled: bool,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ExternalAssertionSubjectMappingSetEnabled,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE external_assertion_subject_mappings SET enabled = $1 \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
                )
                .bind(enabled)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }
}

/// The single-use external-issuer JWT-assertion `jti` replay cache (issue #26).
///
/// REUSES the #25 client-assertion prune-then-insert single-use mechanism (a
/// primary-key conflict on insert is a REPLAY, enforced across nodes because every
/// node inserts into one shared table), but keyed by the EXTERNAL ISSUER rather than
/// the OAuth client id, in a DISTINCT table, so an external issuer's `jti` can never
/// collide with a client-assertion `jti`. Deliberately off the audited-write path (a
/// security cache, not a business mutation), like the #25 cache and
/// `idempotency_keys`, but still RLS-scoped.
pub struct ExternalAssertionJtiRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ExternalAssertionJtiRepo<'_> {
    /// Record `jti` for external `issuer` as single-use in this scope, first pruning
    /// any already-expired rows.
    ///
    /// `expires_at_micros` is the last instant the assertion could still be replayed
    /// (its `exp` plus the configured skew plus one second; see the migration note),
    /// so a pruned row can never remove a `jti` whose assertion is still acceptable.
    /// The prune uses the application clock seam (`env`), never the database clock, so
    /// it is deterministic under a manual clock in tests. Returns
    /// [`JtiOutcome::Recorded`] on the first use and [`JtiOutcome::Replayed`] when the
    /// `jti` was already present (a second use, from this or any other node).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn record(
        &self,
        env: &Env,
        issuer: &str,
        jti: &str,
        expires_at_micros: i64,
    ) -> Result<JtiOutcome, StoreError> {
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // Prune rows whose last-replayable instant has passed. Only these are removed,
        // so a still-valid assertion's jti is never dropped.
        sqlx::query(
            "DELETE FROM external_assertion_jtis \
             WHERE tenant_id = $1 AND environment_id = $2 \
             AND expires_at <= TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(now_micros)
        .execute(&mut *tx)
        .await?;
        let result = sqlx::query(
            "INSERT INTO external_assertion_jtis \
             (tenant_id, environment_id, issuer, jti, expires_at) \
             VALUES ($1, $2, $3, $4, \
                     TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval)",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(issuer)
        .bind(jti)
        .bind(expires_at_micros)
        .execute(&mut *tx)
        .await;
        match result {
            Ok(_) => {
                tx.commit().await?;
                Ok(JtiOutcome::Recorded)
            }
            // A primary-key conflict is a replay: the (issuer, jti) was already used.
            Err(error) if is_unique_violation(&error) => {
                tx.rollback().await?;
                Ok(JtiOutcome::Replayed)
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// A random 128-bit hex identifier for a diagnostics row, drawn from the
/// application entropy seam (never the crate's own RNG), so it is deterministic
/// under a seeded stream in tests and leaks no ordering or count.
fn random_diagnostic_id(env: &Env) -> String {
    use std::fmt::Write as _;
    let mut bytes = [0_u8; 16];
    env.entropy().fill_bytes(&mut bytes);
    bytes
        .iter()
        .fold(String::with_capacity(32), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// An opaque access token to record, digest-only (issue #29). The plaintext token
/// is NEVER carried here: only its SHA-256 hex `token_digest` (compute it with
/// [`opaque_access_token_digest`]) plus the token's metadata. `Debug` redacts the
/// end-user subject.
#[derive(Clone, Copy)]
pub struct NewOpaqueAccessToken<'a> {
    /// The SHA-256 hex digest of the token (the lookup key). NEVER the plaintext.
    pub token_digest: &'a str,
    /// The grant this token was issued from (the revocation spine), where
    /// applicable.
    pub grant_id: Option<&'a GrantId>,
    /// The authenticated end-user subject.
    pub subject: &'a str,
    /// The OAuth client the token belongs to.
    pub client_id: &'a str,
    /// The PRIMARY audience the token targets (a resource server's audience or the
    /// client id): the first requested-and-allowlisted resource, or the client id
    /// for the no-resource case. Kept for backward compatibility with the existing
    /// single-audience introspection reporting.
    pub audience: &'a str,
    /// The FULL requested-and-allowlisted audience set (issue #28, RFC 8707). An
    /// empty slice means "no explicit multi-audience set" (a single-resource or
    /// no-resource token), which the store records as SQL NULL and introspection
    /// falls back to `[audience]`; a non-empty slice records the whole array so
    /// introspection reports it (RFC 7662 permits an `aud` array). The store owns
    /// the JSON encoding.
    pub audiences: &'a [String],
    /// The granted OAuth scope value, if any.
    pub scope: Option<&'a str>,
    /// The token's logical identifier (a `tok_` scoped id).
    pub jti: &'a IssuedTokenId,
    /// The token's expiry, in microseconds since the Unix epoch (clock seam).
    pub expires_at_unix_micros: i64,
}

impl fmt::Debug for NewOpaqueAccessToken<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewOpaqueAccessToken")
            .field("jti", &self.jti)
            .field("client_id", &self.client_id)
            .field("audience", &self.audience)
            .field("expires_at_unix_micros", &self.expires_at_unix_micros)
            .finish_non_exhaustive()
    }
}

/// An opaque access token resolved from a presented token back to its live claims
/// (issue #29). Returned by [`AuthorizationRepo::resolve_opaque_access_token`],
/// the INTERNAL resolve the RFC 7662 introspection endpoint (issue #22) will
/// expose. `Debug` redacts the end-user subject.
#[derive(Clone, PartialEq, Eq)]
pub struct ActiveOpaqueToken {
    /// The authenticated end-user subject.
    pub subject: String,
    /// The OAuth client the token belongs to.
    pub client_id: String,
    /// The PRIMARY audience the token targets (the first recorded audience, or the
    /// client id for the no-resource case).
    pub audience: String,
    /// The FULL recorded audience set (issue #28, RFC 8707), for the RFC 7662
    /// introspection response. A single-resource or no-resource token has exactly
    /// one entry (`[audience]`); a multi-resource token has the whole array. Always
    /// non-empty (it falls back to `[audience]` when no explicit array was stored).
    pub audiences: Vec<String>,
    /// The granted OAuth scope value, if any.
    pub scope: Option<String>,
    /// The token's logical identifier (a `tok_` id string).
    pub jti: String,
    /// The token's expiry, in microseconds since the Unix epoch (the clock seam
    /// value the row was written with). The RFC 7662 introspection response (issue
    /// #22) reports this as `exp`. Reading it does NOT change the resolve semantics:
    /// an expired token still resolves to [`None`] (the query filters on `expires_at`
    /// against the caller's `now_micros`), so this field is always in the future of
    /// the `now_micros` that resolved the token.
    pub expires_at_unix_micros: i64,
    /// The token's issuance time, in microseconds since the Unix epoch, read from the
    /// row's `created_at`. The introspection response (issue #22) reports this as
    /// `iat`.
    pub issued_at_unix_micros: i64,
}

impl fmt::Debug for ActiveOpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveOpaqueToken")
            .field("client_id", &self.client_id)
            .field("audience", &self.audience)
            .field("jti", &self.jti)
            .finish_non_exhaustive()
    }
}

/// The SHA-256 hex digest of an opaque token, the lookup key stored in
/// `opaque_access_tokens.token_digest` (issue #29).
///
/// The one canonical digest for the format: the mint hashes the token with this
/// to store it, and [`AuthorizationRepo::resolve_opaque_access_token`] hashes the
/// presented token with this to look it up, so the two can never disagree. The
/// plaintext token never reaches the database; only this one-way digest does.
#[must_use]
pub fn opaque_access_token_digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Reconstruct [`CodeBindings`] from a consumed-code row.
fn bindings_from_row(row: &PgRow, scope: &Scope) -> Result<CodeBindings, StoreError> {
    let grant_text: String = row.get("grant_id");
    let grant_id = GrantId::parse_in_scope(&grant_text, scope)?;
    Ok(CodeBindings {
        grant_id,
        client_id: row.get("client_id"),
        redirect_uri: row.get("redirect_uri"),
        nonce: row.get("nonce"),
        code_challenge: row.get("code_challenge"),
        code_challenge_method: row.get("code_challenge_method"),
        subject: row.get("subject"),
        oauth_scope: row.get("oauth_scope"),
        auth_methods: row.get("auth_methods"),
        auth_time_unix_micros: row.get("auth_time_us"),
        claims_request: row.get("claims_request"),
        granted_resources: resource_array_from_json(
            row.get::<Option<String>, _>("granted_resources").as_deref(),
        ),
        session_ref: row.get::<Option<String>, _>("session_ref"),
    })
}

/// Serialize a resource/audience string array to the canonical JSON text stored in
/// the RFC 8707 resource-indicator columns (issue #28). An EMPTY slice serializes to
/// [`None`] (the store binds SQL NULL), so a no-resource grant/code/token carries no
/// array and reads back as empty. This is the ONE place the array shape is encoded,
/// so the write and the [`resource_array_from_json`] read cannot disagree.
fn resource_array_to_json(values: &[String]) -> Option<String> {
    if values.is_empty() {
        None
    } else {
        serde_json::to_string(values).ok()
    }
}

/// Parse a stored JSON resource/audience array back to a vector (issue #28). A NULL
/// column, an empty string, or malformed JSON all read as an EMPTY vector: a pre-#28
/// row (NULL) and a decode failure both fail SAFE to "no resources recorded" (the
/// most restrictive reading: an empty granted set is a ceiling nothing can expand
/// past), never erroring an otherwise-valid resolve.
fn resource_array_from_json(raw: Option<&str>) -> Vec<String> {
    raw.and_then(|text| serde_json::from_str::<Vec<String>>(text).ok())
        .unwrap_or_default()
}

// ===========================================================================
// Refresh token rotation, families, and reuse detection (issue #21).
//
// A refresh token is a scope-declaring reference credential of the form
// `ira_rt_<jti>~<secret>` (mirroring the opaque access token): only the SHA-256
// DIGEST of the whole token is stored, so a database dump yields nothing
// replayable. Every refresh token belongs to a FAMILY rooted at one authorization
// grant; the family is the revocation spine. Rotation supersedes a presented token
// with a fresh successor; presenting a superseded token OUTSIDE the grace window
// is a genuine reuse that revokes the whole family and emits one typed reuse event.
// Everything below routes through the SAME scope filter as the rest of the data
// plane; the redeem is a bespoke committing path (like the code redeem) that folds
// the consume, the successor, the access token, and the audit into one
// transaction.
// ===========================================================================

/// The SHA-256 hex digest of a refresh token, the lookup key stored in
/// `refresh_tokens.token_digest` (issue #21).
///
/// The one canonical digest for the format: the mint hashes the whole
/// `ira_rt_<jti>~<secret>` token with this to store it, and
/// [`RefreshRepo::load`]/[`ActingRefreshRepo::redeem`] hash the presented token
/// with this to look it up, so the two can never disagree. The plaintext token
/// never reaches the database; only this one-way digest does.
#[must_use]
pub fn refresh_token_digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The SHA-256 hex digest of a device code (issue #24, RFC 8628), the poll lookup
/// key stored in `device_codes.device_code_digest`.
///
/// The one canonical digest for the format: the device-authorization endpoint hashes
/// the whole `ira_dc_<jti>~<secret>` device code with this to store it, and
/// [`DeviceCodeRepo::poll`] hashes the presented device code with this to look it up,
/// so the two can never disagree. The plaintext device code never reaches the
/// database; only this one-way digest does, so a database dump yields nothing
/// replayable.
#[must_use]
pub fn device_code_digest(token: &str) -> String {
    sha256_hex(token)
}

/// The SHA-256 hex hash of a NORMALIZED user code (issue #24, RFC 8628), the match
/// key stored in `device_codes.user_code_hash`.
///
/// The caller MUST normalize the user code first (uppercase, separators stripped;
/// see the OIDC layer's `normalize_user_code`), so a user who types the code with or
/// without its display hyphen, in any case, matches the same row. The plaintext user
/// code is never stored; only this one-way hash is, so a database dump cannot recover
/// an enterable code.
#[must_use]
pub fn user_code_hash(normalized_user_code: &str) -> String {
    sha256_hex(normalized_user_code)
}

/// The lowercase hex SHA-256 of a string. Shared by the device-code digest and the
/// user-code hash (issue #24), matching the encoding of the other digest helpers.
fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The live state of a presented refresh token, resolved from its digest (issue
/// #21). The token endpoint reads this to decide the rotation policy and to mint
/// the refreshed access token; the authoritative single-use and reuse decision is
/// made later by [`ActingRefreshRepo::redeem`], not here.
///
/// [`fmt::Debug`] is hand written and redacting: `subject` is end-user detail.
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshTokenResolution {
    /// The family this token belongs to (the revocation spine).
    pub family_id: RefreshFamilyId,
    /// The grant the family is rooted at.
    pub grant_id: GrantId,
    /// The generation counter of this token within the family.
    pub generation: i64,
    /// The local end-user subject the refreshed tokens are minted for.
    pub subject: String,
    /// The OAuth client the family belongs to.
    pub client_id: String,
    /// The granted OAuth scope value the family was issued against, if any.
    pub scope: Option<String>,
    /// The RFC 8707 resource audiences approved at the original authorization
    /// (issue #28), read from the family's grant. A refresh may downscope to a
    /// subset of these but can NEVER expand beyond them; empty means no resource
    /// was approved (the default-audience case).
    pub granted_resources: Vec<String>,
    /// The recorded authentication method tokens the refreshed access token's
    /// `acr`/`amr` derive from.
    pub auth_methods: String,
    /// Whether this is an `offline_access` family (survives RP logout) or a
    /// session-bound one.
    pub offline: bool,
    /// When this generation was issued, in epoch microseconds.
    pub issued_at_unix_micros: i64,
    /// The idle expiry of this generation, in epoch microseconds.
    pub idle_expires_at_unix_micros: i64,
    /// The family's absolute (hard-cap) expiry, in epoch microseconds.
    pub family_absolute_expires_at_unix_micros: i64,
    /// Whether this token has already been rotated away from (superseded).
    pub rotated: bool,
    /// Whether the family and its grant are both live (not revoked). A revoked
    /// family or grant makes every token in it inactive.
    pub active: bool,
}

impl fmt::Debug for RefreshTokenResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshTokenResolution")
            .field("family_id", &self.family_id)
            .field("client_id", &self.client_id)
            .field("generation", &self.generation)
            .field("offline", &self.offline)
            .field("rotated", &self.rotated)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

/// The first-issued refresh token opening a new family (issue #21). Recorded by
/// [`ActingRefreshRepo::issue`] after a successful code exchange. Only the digest
/// is carried, never the plaintext token.
#[derive(Clone, Copy)]
pub struct NewRefreshFamily<'a> {
    /// The `rff_` family identifier, minted under this scope.
    pub family_id: &'a RefreshFamilyId,
    /// The generation-0 token's `rft_` identifier (the embedded routing handle).
    pub token_jti: &'a RefreshTokenId,
    /// The SHA-256 hex digest of the generation-0 token. NEVER the plaintext.
    pub token_digest: &'a str,
    /// The grant the family is rooted at.
    pub grant_id: &'a GrantId,
    /// The authenticated end-user subject.
    pub subject: &'a str,
    /// The OAuth client the family belongs to.
    pub client_id: &'a str,
    /// The granted OAuth scope value, if any.
    pub scope: Option<&'a str>,
    /// The recorded authentication method tokens frozen onto the family.
    pub auth_methods: &'a str,
    /// Whether this is an `offline_access` family (survives RP logout).
    pub offline: bool,
    /// When the family was created, in epoch microseconds (clock seam).
    pub created_at_unix_micros: i64,
    /// The generation-0 token's idle expiry, in epoch microseconds.
    pub idle_expires_at_unix_micros: i64,
    /// The family's absolute (hard-cap) expiry, in epoch microseconds.
    pub absolute_expires_at_unix_micros: i64,
}

impl fmt::Debug for NewRefreshFamily<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewRefreshFamily")
            .field("family_id", &self.family_id)
            .field("token_jti", &self.token_jti)
            .field("client_id", &self.client_id)
            .field("offline", &self.offline)
            .finish_non_exhaustive()
    }
}

/// The outcome of opening a refresh-token family ([`ActingRefreshRepo::issue`], issue
/// #21 / #32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshFamilyOpenOutcome {
    /// The family and its generation-0 token were recorded.
    Opened,
    /// A SESSION-BOUND (non-offline) family was refused because the SSO session it
    /// would hang off is no longer live: it was revoked (an RP logout, an operator
    /// revoke) in the window between the token endpoint's liveness read and this
    /// open, and that revoke's cascade already ran, so opening the family would leave
    /// it outliving the logout that should have killed it. NOTHING was written. The
    /// token grant maps this to `invalid_grant`. An offline family (survives logout
    /// per issue #21) and a grant with no session are never refused this way.
    SessionNotLive,
}

/// A rotated successor refresh token to record when a presented token rotates
/// (issue #21). Only the digest is carried, never the plaintext.
#[derive(Clone, Copy)]
pub struct RotatedRefreshToken<'a> {
    /// The successor's `rft_` identifier.
    pub jti: &'a RefreshTokenId,
    /// The SHA-256 hex digest of the successor token. NEVER the plaintext.
    pub token_digest: &'a str,
    /// The successor's generation counter (the predecessor's generation plus one),
    /// matching the `integer` generation column.
    pub generation: i32,
    /// The successor's idle expiry, in epoch microseconds (clock seam).
    pub idle_expires_at_unix_micros: i64,
}

/// The inputs to redeeming (refreshing) a presented refresh token (issue #21).
///
/// The caller has already resolved the token's state ([`RefreshRepo::load`]),
/// decided the rotation policy (`rotate`), pre-signed the access token, and
/// pre-generated the successor refresh token; this is the authoritative single-use
/// gate that decides whether those are handed out. A `successor` is supplied even
/// when `rotate` is false so that whichever concurrent caller WINS the atomic rotate
/// has its successor ready; a within-grace loser leaves its own pre-generated
/// successor unused (it mints no new leaf, so the family cannot fork).
#[derive(Clone, Copy)]
pub struct RefreshRedeem<'a> {
    /// The presented refresh token, hashed to its digest for the lookup.
    pub presented_token: &'a str,
    /// Whether the rotation policy says to rotate a LIVE (non-superseded) token:
    /// `true` for a public/unbound client always, `true` for a confidential/bound
    /// client only past the TTL threshold. When `false`, a live token is left in
    /// place and only a fresh access token is recorded.
    pub rotate: bool,
    /// The pre-generated successor refresh token, recorded ONLY by the winner of the
    /// atomic rotate (a policy rotation). A within-grace loser leaves it unused.
    pub successor: RotatedRefreshToken<'a>,
    /// The refreshed access (and optional ID) token records to write against the
    /// grant, so grant-chain revocation reaches them.
    pub access_records: &'a [IssuedTokenRecord],
    /// The refreshed opaque access token to record, when the format is opaque.
    pub opaque: Option<NewOpaqueAccessToken<'a>>,
    /// The rotation grace window: within this of a token's rotation, a duplicate
    /// presentation is a benign concurrent refresh; beyond it, a genuine reuse.
    pub grace: Duration,
}

/// The outcome of redeeming a refresh token (issue #21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRedeemOutcome {
    /// The presented (live) token was consumed and a successor plus a fresh access
    /// token recorded. The token endpoint returns the new refresh and access tokens.
    Rotated,
    /// The presented token was already superseded but within the grace window: a
    /// benign concurrent refresh (multi-tab, retry, or a lost rotation response). A
    /// fresh access token was recorded WITHOUT revoking the family and WITHOUT
    /// minting a second successor leaf, so N concurrent within-grace refreshes
    /// CONVERGE on the winner's single live leaf (no family fork). The token endpoint
    /// returns the access token and OMITS the refresh token (RFC 6749 5.1 makes it
    /// optional): the well-behaved client keeps the winner's rotated token.
    RefreshedWithinGrace,
    /// The presented (live) token was NOT rotated (a confidential/bound client
    /// under the TTL threshold): a fresh access token was recorded and the SAME
    /// refresh token is returned.
    NotRotated,
    /// The presented token was superseded OUTSIDE the grace window: a genuine reuse.
    /// The whole family was revoked and the typed reuse event emitted EXACTLY once
    /// (only the revocation that flipped the family emits it). `invalid_grant`.
    Reused,
    /// The token is absent, expired (idle or family hard cap), or its family/grant
    /// is already revoked. `invalid_grant`, with no reuse event.
    Invalid,
}

/// The read-only refresh-token repository (issue #21).
pub struct RefreshRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl RefreshRepo<'_> {
    /// Resolve a presented refresh token's live state by its digest, within scope,
    /// or [`None`] when no such token is recorded in this scope. Does NOT filter on
    /// expiry or rotation: it returns the raw state (idle/absolute expiry instants,
    /// `rotated`, `active`) so the token endpoint can decide the rotation policy and
    /// mint the refreshed access token; the authoritative single-use and reuse
    /// decision is made by [`ActingRefreshRepo::redeem`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure, or if a stored id fails to
    /// parse back in scope.
    pub async fn load(
        &self,
        presented_token: &str,
    ) -> Result<Option<RefreshTokenResolution>, StoreError> {
        let digest = refresh_token_digest(presented_token);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT rt.family_id AS family_id, rt.generation AS generation, \
             (rt.rotated_at IS NOT NULL) AS rotated, \
             (EXTRACT(EPOCH FROM rt.issued_at) * 1000000)::bigint AS issued_us, \
             (EXTRACT(EPOCH FROM rt.idle_expires_at) * 1000000)::bigint AS idle_us, \
             f.grant_id AS grant_id, f.subject AS subject, f.client_id AS client_id, \
             f.scope AS scope, f.auth_methods AS auth_methods, f.offline AS offline, \
             g.granted_resources AS granted_resources, \
             (EXTRACT(EPOCH FROM f.absolute_expires_at) * 1000000)::bigint AS abs_us, \
             (f.revoked_at IS NULL) AS family_live, (g.revoked_at IS NULL) AS grant_live \
             FROM refresh_tokens rt \
             JOIN refresh_families f ON f.id = rt.family_id \
             AND f.tenant_id = rt.tenant_id AND f.environment_id = rt.environment_id \
             JOIN grants g ON g.id = f.grant_id \
             AND g.tenant_id = f.tenant_id AND g.environment_id = f.environment_id \
             WHERE rt.token_digest = $1 AND rt.tenant_id = $2 AND rt.environment_id = $3",
        )
        .bind(&digest)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => Ok(Some(refresh_resolution_from_row(&row, &self.scope)?)),
        }
    }

    /// Count `family`'s LIVE leaves in scope: refresh-token rows that are neither
    /// rotated (superseded) nor in a revoked family (issue #21). The rotation
    /// invariant is that this is ALWAYS at most one, even under concurrent
    /// within-grace refreshes: a family never forks into two sibling live leaves, so
    /// this is the ground-truth check a concurrency test asserts.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the family is out of scope; [`StoreError::Database`]
    /// on a persistence failure.
    pub async fn live_leaf_count(&self, family: &RefreshFamilyId) -> Result<i64, StoreError> {
        if family.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let count: i64 = sqlx::query(
            "SELECT COUNT(*) AS n FROM refresh_tokens rt \
             JOIN refresh_families f ON f.id = rt.family_id \
             AND f.tenant_id = rt.tenant_id AND f.environment_id = rt.environment_id \
             WHERE rt.family_id = $1 AND rt.tenant_id = $2 AND rt.environment_id = $3 \
             AND rt.rotated_at IS NULL AND f.revoked_at IS NULL",
        )
        .bind(family.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_one(&mut *tx)
        .await?
        .get("n");
        tx.commit().await?;
        Ok(count)
    }

    /// Count the refresh-token rows recorded in this scope: the `(refresh_families,
    /// refresh_tokens)` row counts visible under the scope's forced row-level
    /// security. Used by the client-credentials test (issue #23) to prove at the
    /// DATABASE that a machine-token issuance opened NO refresh family and minted NO
    /// refresh token (RFC 6749 4.4.3 forbids a refresh token on that grant), so the
    /// no-refresh guarantee holds beyond the token-response body.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn count_in_scope(&self) -> Result<(i64, i64), StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT \
             (SELECT COUNT(*) FROM refresh_families \
              WHERE tenant_id = $1 AND environment_id = $2) AS families, \
             (SELECT COUNT(*) FROM refresh_tokens \
              WHERE tenant_id = $1 AND environment_id = $2) AS tokens",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_one(&mut *tx)
        .await?;
        let families: i64 = row.get("families");
        let tokens: i64 = row.get("tokens");
        tx.commit().await?;
        Ok((families, tokens))
    }
}

/// The mutating refresh-token repository (issue #21). Reachable only through
/// [`ScopedStore::acting`], so every mutation carries an actor and correlation id.
/// [`issue`](Self::issue) and [`revoke_session_bound`](Self::revoke_session_bound)
/// route through the module's audited-write primitive; [`redeem`](Self::redeem) is
/// the one bespoke committing path (it folds the consume, the successor, the access
/// token, and the audit into one transaction and classifies a superseded-token
/// presentation as a benign within-grace refresh or a genuine reuse), like the code
/// redeem, and still writes every audit row in the SAME transaction as its mutation.
pub struct ActingRefreshRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingRefreshRepo<'_> {
    /// Open a refresh-token family at first issuance: record the family and its
    /// generation-0 token, plus a `refresh_token.issue` audit row, in one
    /// transaction. Reads the grant's `session_ref` (so an RP logout can later
    /// revoke a session-bound family) inside the SAME statement that opens the
    /// family. Called after a successful code exchange (or an approved device flow).
    ///
    /// # A dead session gets no session-bound family
    ///
    /// For a SESSION-BOUND (non-offline) family the open is guarded, in that same
    /// statement, by the live-session predicate the auth read path uses, so a session
    /// that was revoked in the window after the token endpoint's liveness read but
    /// before this open yields no row: nothing is inserted and this returns
    /// [`RefreshFamilyOpenOutcome::SessionNotLive`] (the grant path maps it to
    /// `invalid_grant`). That closes the check-then-act window in which a logout's
    /// cascade, already run, would otherwise miss a freshly opened family and let it
    /// outlive the logout. An offline family (survives logout per issue #21) and a
    /// grant with no session both open unconditionally.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if any supplied identifier is out of scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn issue(
        &self,
        env: &Env,
        family: NewRefreshFamily<'_>,
    ) -> Result<RefreshFamilyOpenOutcome, StoreError> {
        if family.family_id.scope() != self.scope
            || family.token_jti.scope() != self.scope
            || family.grant_id.scope() != self.scope
        {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let tenant = scope.tenant().to_string();
        let environment = scope.environment().to_string();
        // Liveness comparison time from the application clock seam, never the DB
        // clock, so it stays deterministic under a manual test clock.
        let now_micros = epoch_micros(env.clock().now_utc());
        // Bespoke committing path (like the redeem): the family open, its
        // generation-0 token, and the issue audit share ONE transaction, and a
        // refused open writes NONE of them.
        let mut tx = begin_scoped(self.store, scope).await?;
        // PART 1 (issue #32): serialize a SESSION-BOUND open against a CONCURRENT
        // session revoke with an explicit row lock on the bound session, taken in THIS
        // transaction BEFORE the family row is written (see lock_bound_session_live for
        // the full ordering argument). The single-statement EXISTS guard below closes
        // only the fully-SEQUENTIAL window; the FOR UPDATE lock is what closes the
        // concurrent race. An offline family (survives logout per issue #21) and a grant
        // with no session are NOT session-bound and are neither locked nor gated.
        if !family.offline
            && !lock_bound_session_live(&mut tx, scope, family.grant_id, now_micros).await?
        {
            // The bound session is not (or no longer) live: open nothing, write no
            // token and no issue audit, and report the refusal.
            tx.commit().await?;
            return Ok(RefreshFamilyOpenOutcome::SessionNotLive);
        }
        // Open the family reading the grant's session_ref in the SAME statement, and
        // for a SESSION-BOUND (non-offline) family ONLY when that session is still
        // live. This closes the check-then-act window between the token endpoint's
        // liveness read and this open: an RP logout that commits in between (its
        // cascade already run over the families that existed then) would otherwise
        // leave a fresh session-bound family bound to a now-dead session, outliving
        // the logout that should have killed it. An offline family (offline = true)
        // deliberately survives logout (issue #21), and a grant with no session
        // (session_ref NULL) is not session-bound; both open unconditionally. When
        // the session is dead the SELECT yields no row, nothing is inserted, and this
        // reports SessionNotLive (the token grant maps it to invalid_grant). The
        // liveness predicate is the SAME one the session read path applies.
        let inserted = sqlx::query(
            "INSERT INTO refresh_families \
             (id, tenant_id, environment_id, grant_id, subject, client_id, scope, \
              auth_methods, session_ref, offline, created_at, absolute_expires_at) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, g.session_ref, $9, \
                    TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval, \
                    TIMESTAMPTZ 'epoch' + ($11::text || ' microseconds')::interval \
             FROM grants g \
             WHERE g.id = $4 AND g.tenant_id = $2 AND g.environment_id = $3 \
             AND ($9 OR g.session_ref IS NULL OR EXISTS ( \
                 SELECT 1 FROM sessions s \
                 WHERE s.id = g.session_ref AND s.tenant_id = $2 AND s.environment_id = $3 \
                 AND s.revoked_at IS NULL AND s.ended_at IS NULL AND s.superseded_by IS NULL \
                 AND COALESCE(s.absolute_expires_at, s.expires_at) > \
                     TIMESTAMPTZ 'epoch' + ($12::text || ' microseconds')::interval \
                 AND (s.idle_expires_at IS NULL OR s.idle_expires_at > \
                      TIMESTAMPTZ 'epoch' + ($12::text || ' microseconds')::interval)))",
        )
        .bind(family.family_id.to_string())
        .bind(&tenant)
        .bind(&environment)
        .bind(family.grant_id.to_string())
        .bind(family.subject)
        .bind(family.client_id)
        .bind(family.scope)
        .bind(family.auth_methods)
        .bind(family.offline)
        .bind(family.created_at_unix_micros)
        .bind(family.absolute_expires_at_unix_micros)
        .bind(now_micros)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted == 0 {
            // No live session backed a session-bound family (or the grant vanished):
            // open nothing, write no token and no issue audit, and report the refusal.
            tx.commit().await?;
            return Ok(RefreshFamilyOpenOutcome::SessionNotLive);
        }
        sqlx::query(
            "INSERT INTO refresh_tokens \
             (token_digest, tenant_id, environment_id, family_id, jti, generation, \
              predecessor_jti, issued_at, idle_expires_at) \
             VALUES ($1, $2, $3, $4, $5, 0, NULL, \
                     TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                     TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
        )
        .bind(family.token_digest)
        .bind(&tenant)
        .bind(&environment)
        .bind(family.family_id.to_string())
        .bind(family.token_jti.to_string())
        .bind(family.created_at_unix_micros)
        .bind(family.idle_expires_at_unix_micros)
        .execute(&mut *tx)
        .await?;
        let spec = AuditedWrite {
            store: self.store,
            scope,
            acting: &self.acting,
            env,
            action: Action::RefreshTokenIssue,
            target: family.family_id,
        };
        insert_audit_row(&mut tx, &spec, None).await?;
        tx.commit().await?;
        Ok(RefreshFamilyOpenOutcome::Opened)
    }

    /// Atomically redeem (refresh) a presented refresh token, with reuse detection.
    ///
    /// In one transaction the presented token's family, grant, expiry, and rotation
    /// state are read, and then:
    ///
    /// - a token whose family or grant is already revoked, or whose idle timeout or
    ///   family hard cap has passed, is [`RefreshRedeemOutcome::Invalid`];
    /// - a token that is ALREADY superseded is classified against the grace window:
    ///   within it, only a fresh access token is recorded without revoking and
    ///   without minting a second successor leaf
    ///   ([`RefreshRedeemOutcome::RefreshedWithinGrace`]); beyond it, the whole family
    ///   is revoked and the reuse event emitted EXACTLY once
    ///   ([`RefreshRedeemOutcome::Reused`]);
    /// - a LIVE token with `rotate` set is atomically consumed (superseded) and a
    ///   successor plus access token recorded ([`RefreshRedeemOutcome::Rotated`]); a
    ///   concurrent loser that misses the single-row consume re-reads and classifies
    ///   against the grace window exactly as an already-superseded token does, so N
    ///   parallel refreshes all succeed within the window and CONVERGE on the one live
    ///   leaf (the winner's successor): a within-grace loser mints NO new leaf, so a
    ///   family never forks into two sibling live leaves;
    /// - a LIVE token with `rotate` unset records only a fresh access token and
    ///   leaves the token in place ([`RefreshRedeemOutcome::NotRotated`]).
    ///
    /// `now` flows from the application clock seam (never the database clock). This
    /// is a bespoke committing path (like the code redeem) that still writes every
    /// audit row in the SAME transaction as its mutation.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the successor or any access-token identifier is
    /// out of scope; [`StoreError::Database`] on a persistence failure.
    pub async fn redeem(
        &self,
        env: &Env,
        redeem: RefreshRedeem<'_>,
    ) -> Result<RefreshRedeemOutcome, StoreError> {
        if redeem.successor.jti.scope() != self.scope
            || redeem
                .access_records
                .iter()
                .any(|t| t.id.scope() != self.scope)
            || redeem
                .opaque
                .as_ref()
                .is_some_and(|opaque| opaque.jti.scope() != self.scope)
        {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let grace_micros = i64::try_from(redeem.grace.as_micros()).unwrap_or(i64::MAX);
        let digest = refresh_token_digest(redeem.presented_token);

        let mut tx = begin_scoped(self.store, scope).await?;
        let Some(row) = sqlx::query(
            "SELECT rt.jti AS jti, rt.family_id AS family_id, f.grant_id AS grant_id, \
             (rt.rotated_at IS NOT NULL) AS rotated, \
             (EXTRACT(EPOCH FROM rt.rotated_at) * 1000000)::bigint AS rotated_us, \
             (EXTRACT(EPOCH FROM rt.idle_expires_at) * 1000000)::bigint AS idle_us, \
             (EXTRACT(EPOCH FROM f.absolute_expires_at) * 1000000)::bigint AS abs_us, \
             (f.revoked_at IS NULL) AS family_live, (g.revoked_at IS NULL) AS grant_live, \
             (f.offline OR f.session_ref IS NULL OR EXISTS ( \
                 SELECT 1 FROM sessions s \
                 WHERE s.id = f.session_ref AND s.tenant_id = f.tenant_id \
                 AND s.environment_id = f.environment_id \
                 AND s.revoked_at IS NULL AND s.ended_at IS NULL AND s.superseded_by IS NULL \
                 AND COALESCE(s.absolute_expires_at, s.expires_at) > \
                     TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
                 AND (s.idle_expires_at IS NULL OR s.idle_expires_at > \
                      TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval))) AS session_live \
             FROM refresh_tokens rt \
             JOIN refresh_families f ON f.id = rt.family_id \
             AND f.tenant_id = rt.tenant_id AND f.environment_id = rt.environment_id \
             JOIN grants g ON g.id = f.grant_id \
             AND g.tenant_id = f.tenant_id AND g.environment_id = f.environment_id \
             WHERE rt.token_digest = $1 AND rt.tenant_id = $2 AND rt.environment_id = $3",
        )
        .bind(&digest)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(now_micros)
        .fetch_optional(&mut *tx)
        .await?
        else {
            // Absent (or out of scope): a plain invalid_grant with no reuse.
            tx.commit().await?;
            return Ok(RefreshRedeemOutcome::Invalid);
        };

        let family_text: String = row.get("family_id");
        let grant_text: String = row.get("grant_id");
        let jti_text: String = row.get("jti");
        // A revoked family or grant (a prior reuse, an RP logout, or a code-reuse
        // grant revoke) makes the token inactive: invalid_grant, and NO reuse event
        // (the event, if any, was already emitted when the family was revoked).
        if !row.get::<bool, _>("family_live") || !row.get::<bool, _>("grant_live") {
            tx.commit().await?;
            return Ok(RefreshRedeemOutcome::Invalid);
        }
        // PART 2 (issue #32, defence in depth): a SESSION-BOUND (non-offline) family
        // re-validates its bound session is still live here, under the SAME predicate
        // the open used. This guarantees the property we actually want -- a
        // session-bound refresh token never mints after its session dies -- directly at
        // the redeem, independent of whether any revoke cascade ever reached the family.
        // Even if a family were somehow left orphaned (a missed cascade), a redeem
        // against a dead session is invalid_grant, not a fresh mint. offline_access
        // (survives logout, issue #21) and a grant with no session are session_live by
        // construction, so RP-logout offline redemption is unaffected.
        if !row.get::<bool, _>("session_live") {
            tx.commit().await?;
            return Ok(RefreshRedeemOutcome::Invalid);
        }
        // Idle timeout or family hard cap passed: invalid_grant.
        if row.get::<i64, _>("idle_us") <= now_micros || row.get::<i64, _>("abs_us") <= now_micros {
            tx.commit().await?;
            return Ok(RefreshRedeemOutcome::Invalid);
        }

        // Already superseded: classify against the grace window regardless of the
        // rotation policy (a superseded token is being reused).
        if row.get::<bool, _>("rotated") {
            let rotated_us: i64 = row.get("rotated_us");
            return self
                .classify_superseded(
                    env,
                    tx,
                    &family_text,
                    &grant_text,
                    rotated_us,
                    now_micros,
                    grace_micros,
                    &redeem,
                )
                .await;
        }

        // A live (non-superseded) leaf token: apply the rotation policy.
        self.redeem_live_leaf(
            env,
            tx,
            &family_text,
            &jti_text,
            &grant_text,
            &digest,
            now_micros,
            grace_micros,
            &redeem,
        )
        .await
    }

    /// Redeem a LIVE (non-superseded) leaf refresh token in the open transaction
    /// (issue #21), committing it. With `rotate` unset a confidential/bound client
    /// under the TTL threshold records only a fresh access token and leaves the token
    /// in place ([`RefreshRedeemOutcome::NotRotated`]). With `rotate` set the token is
    /// atomically consumed: the single winner records the successor and access token
    /// ([`RefreshRedeemOutcome::Rotated`]); a concurrent loser that missed the
    /// single-row consume re-reads the rotation instant and classifies against the
    /// grace window exactly as an already-superseded token does.
    #[allow(clippy::too_many_arguments)]
    async fn redeem_live_leaf(
        &self,
        env: &Env,
        mut tx: Transaction<'_, Postgres>,
        family_text: &str,
        jti_text: &str,
        grant_text: &str,
        digest: &str,
        now_micros: i64,
        grace_micros: i64,
        redeem: &RefreshRedeem<'_>,
    ) -> Result<RefreshRedeemOutcome, StoreError> {
        let scope = self.scope;
        if !redeem.rotate {
            // No rotation (a confidential/bound client under the threshold): record
            // only a fresh access token against the grant, leave the token in place.
            record_refresh_access(&mut tx, scope, grant_text, redeem).await?;
            let spec = AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TokenIssue,
                target: &GrantId::parse_in_scope(grant_text, &scope)?,
            };
            insert_audit_row(&mut tx, &spec, None).await?;
            tx.commit().await?;
            return Ok(RefreshRedeemOutcome::NotRotated);
        }

        // Rotate: atomically consume this live token. Postgres serializes the
        // single-row UPDATE, so exactly one concurrent caller sets rotated_at.
        let won = sqlx::query(
            "UPDATE refresh_tokens \
             SET rotated_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
                 successor_jti = $2 \
             WHERE token_digest = $3 AND tenant_id = $4 AND environment_id = $5 \
             AND rotated_at IS NULL",
        )
        .bind(now_micros)
        .bind(redeem.successor.jti.to_string())
        .bind(digest)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;

        if won.rows_affected() > 0 {
            // Won the single-use race: record the successor and the access token in
            // this same transaction.
            insert_refresh_generation(
                &mut tx,
                scope,
                family_text,
                &redeem.successor,
                Some(jti_text),
                now_micros,
            )
            .await?;
            record_refresh_access(&mut tx, scope, grant_text, redeem).await?;
            let spec = AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::RefreshTokenRotate,
                target: &RefreshFamilyId::parse_in_scope(family_text, &scope)?,
            };
            insert_audit_row(&mut tx, &spec, None).await?;
            tx.commit().await?;
            return Ok(RefreshRedeemOutcome::Rotated);
        }

        // Missed the consume: a concurrent refresh rotated this token first. Re-read
        // its rotated_at and classify against the grace window, so a within-window
        // concurrent refresh still succeeds and a beyond-window reuse revokes.
        let rotated_us: i64 = sqlx::query(
            "SELECT (EXTRACT(EPOCH FROM rotated_at) * 1000000)::bigint AS rotated_us \
             FROM refresh_tokens \
             WHERE token_digest = $1 AND tenant_id = $2 AND environment_id = $3 \
             AND rotated_at IS NOT NULL",
        )
        .bind(digest)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?
        .map_or(now_micros, |r| r.get("rotated_us"));
        self.classify_superseded(
            env,
            tx,
            family_text,
            grant_text,
            rotated_us,
            now_micros,
            grace_micros,
            redeem,
        )
        .await
    }

    /// Classify a presentation of an ALREADY-superseded refresh token (issue #21),
    /// and commit its transaction. Within the grace window of `rotated_us` it is a
    /// benign concurrent refresh: ONLY a fresh access token is recorded (bound to the
    /// family's grant) without revoking, so the user is not locked out. A second
    /// successor leaf is deliberately NOT minted: the winner of the atomic rotate
    /// already minted the family's one live successor, so a within-grace loser (or any
    /// within-grace repeat presentation) converges on that single live leaf instead of
    /// forking the family into two independent, never-reconciled chains. Beyond the
    /// window it is a genuine reuse: the whole family is revoked and the reuse audit
    /// written in this transaction, EXACTLY once (only the revoke that flips
    /// `revoked_at` emits it).
    #[allow(clippy::too_many_arguments)]
    async fn classify_superseded(
        &self,
        env: &Env,
        mut tx: Transaction<'_, Postgres>,
        family_text: &str,
        grant_text: &str,
        rotated_us: i64,
        now_micros: i64,
        grace_micros: i64,
        redeem: &RefreshRedeem<'_>,
    ) -> Result<RefreshRedeemOutcome, StoreError> {
        let scope = self.scope;
        // The benign window is strictly [0, grace): a token whose OWN rotation was
        // strictly within grace is a concurrent refresh; at or beyond it, reuse.
        if now_micros.saturating_sub(rotated_us) < grace_micros {
            // Within the grace window: a benign concurrent refresh (multi-tab, retry,
            // or a lost rotation response). Record ONLY a fresh access token bound to
            // the family's grant, without revoking. Deliberately mint NO new successor
            // leaf: the winner of the atomic rotate already minted the family's single
            // live successor, and creating a second leaf here would FORK the family
            // into two independent live chains that never present each other's tokens,
            // so reuse detection would never fire. Not minting keeps EXACTLY ONE live
            // leaf, so N concurrent within-grace refreshes converge (no fork). The
            // predecessor's successor is unchanged; `redeem.successor` is intentionally
            // left unused here (it is only consumed by the atomic-rotate winner).
            record_refresh_access(&mut tx, scope, grant_text, redeem).await?;
            let spec = AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                // No rotation happened: this is a plain access-token issue against the
                // grant, mirroring the confidential under-threshold NotRotated path.
                action: Action::TokenIssue,
                target: &GrantId::parse_in_scope(grant_text, &scope)?,
            };
            insert_audit_row(&mut tx, &spec, None).await?;
            tx.commit().await?;
            return Ok(RefreshRedeemOutcome::RefreshedWithinGrace);
        }

        // Beyond the grace window: a genuine reuse. Revoke the whole family (and
        // record that the revocation was a reuse) so every generation is inactive.
        let revoked = sqlx::query(
            "UPDATE refresh_families \
             SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
                 reuse_detected_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
             AND revoked_at IS NULL",
        )
        .bind(now_micros)
        .bind(family_text)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
        // Only the revoke that actually flipped the family emits the typed reuse
        // event, so it is written EXACTLY once per incident even under concurrent
        // reuse presentations.
        if revoked.rows_affected() > 0 {
            let spec = AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::RefreshTokenReuse,
                target: &RefreshFamilyId::parse_in_scope(family_text, &scope)?,
            };
            insert_audit_row(&mut tx, &spec, None).await?;
        }
        tx.commit().await?;
        Ok(RefreshRedeemOutcome::Reused)
    }

    /// Revoke a session's SESSION-BOUND refresh-token families at RP logout (issue
    /// #21), returning how many families were revoked. The `offline_access` families
    /// are left intact by construction (`offline = false` filter), so a token issued
    /// with `offline_access` survives RP logout (OIDC Back-Channel Logout 2.7) while
    /// one issued without it is invalidated with the session. Writes one
    /// `refresh_family.revoke` audit row in the same transaction. This is NOT a
    /// reuse, so `reuse_detected_at` is left unset and no reuse event is emitted.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the session id is out of scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn revoke_session_bound(
        &self,
        env: &Env,
        session: &SessionId,
    ) -> Result<u64, StoreError> {
        if session.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut revoked_count: u64 = 0;
        let count_out = &mut revoked_count;
        let session_text = session.to_string();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::RefreshFamilyRevoke,
                target: session,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE refresh_families \
                     SET revoked_at = \
                         TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE session_ref = $2 AND tenant_id = $3 AND environment_id = $4 \
                     AND offline = false AND revoked_at IS NULL",
                )
                .bind(now_micros)
                .bind(&session_text)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                *count_out = result.rows_affected();
                Ok(())
            },
            false,
        )
        .await?;
        Ok(revoked_count)
    }

    /// Revoke a single refresh-token FAMILY and its grant chain at the RFC 7009
    /// revocation endpoint (issue #22), returning whether this call flipped anything.
    ///
    /// Revoking a refresh token does two things (RFC 7009 section 2.1): it
    /// invalidates the refresh token, and it SHOULD invalidate the access tokens
    /// issued from the same authorization grant. Both happen here in ONE transaction:
    /// the family's `revoked_at` is set (invalidating every generation of the refresh
    /// token, reusing the #21 family spine) AND the grant's `revoked_at` is set
    /// (cascading to every derived access token, which resolve their active state
    /// from `grants.revoked_at`). This is NOT a reuse, so `reuse_detected_at` is left
    /// unset. One `refresh_family.revoke` audit row is written in the same
    /// transaction when either spine actually flipped (idempotent: a second
    /// revocation writes nothing). `now` flows from the application clock seam.
    ///
    /// Both `WHERE ... IS NULL` guards make the two updates independent and
    /// idempotent, so this correctly finishes a partial revocation too (for example
    /// a family a #21 reuse already revoked WITHOUT revoking its grant): the grant is
    /// still revoked here, so the derived access tokens are invalidated as RFC 7009
    /// requires.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `family_id` or `grant_id` is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn revoke_family(
        &self,
        env: &Env,
        family_id: &RefreshFamilyId,
        grant_id: &GrantId,
    ) -> Result<bool, StoreError> {
        if family_id.scope() != self.scope || grant_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, scope).await?;
        // Revoke the family spine (every refresh generation), reusing the #21 model.
        let family_revoked = sqlx::query(
            "UPDATE refresh_families \
             SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 AND revoked_at IS NULL",
        )
        .bind(now_micros)
        .bind(family_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
        // Cascade to the derived access tokens by revoking the grant chain (RFC 7009
        // section 2.1: revoking a refresh token SHOULD invalidate the access tokens
        // issued from the same grant).
        let grant_revoked = sqlx::query(
            "UPDATE grants \
             SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 AND revoked_at IS NULL",
        )
        .bind(now_micros)
        .bind(grant_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
        let flipped = family_revoked.rows_affected() > 0 || grant_revoked.rows_affected() > 0;
        if flipped {
            let spec = AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::RefreshFamilyRevoke,
                target: family_id,
            };
            insert_audit_row(&mut tx, &spec, None).await?;
        }
        tx.commit().await?;
        Ok(flipped)
    }
}

/// Insert one refresh-token generation row (a rotated successor) in the current
/// transaction (issue #21). Digest only; the plaintext token is never stored.
async fn insert_refresh_generation(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    family_text: &str,
    successor: &RotatedRefreshToken<'_>,
    predecessor_jti: Option<&str>,
    now_micros: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (token_digest, tenant_id, environment_id, family_id, jti, generation, \
          predecessor_jti, issued_at, idle_expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, \
                 TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval, \
                 TIMESTAMPTZ 'epoch' + ($9::text || ' microseconds')::interval)",
    )
    .bind(successor.token_digest)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(family_text)
    .bind(successor.jti.to_string())
    .bind(successor.generation)
    .bind(predecessor_jti)
    .bind(now_micros)
    .bind(successor.idle_expires_at_unix_micros)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Record the refreshed access (and optional ID) token against the grant in the
/// current transaction (issue #21), so grant-chain revocation reaches it. Mirrors
/// the code redeem's token recording: an `at+jwt` is an `issued_tokens` row, an
/// opaque token an `opaque_access_tokens` row.
async fn record_refresh_access(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    grant_text: &str,
    redeem: &RefreshRedeem<'_>,
) -> Result<(), StoreError> {
    for token in redeem.access_records {
        sqlx::query(
            "INSERT INTO issued_tokens \
             (id, tenant_id, environment_id, grant_id, token_kind) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(token.id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(grant_text)
        .bind(token.kind.as_str())
        .execute(&mut **tx)
        .await?;
    }
    if let Some(opaque) = &redeem.opaque {
        sqlx::query(
            "INSERT INTO opaque_access_tokens \
             (token_digest, tenant_id, environment_id, grant_id, subject, \
              client_id, audience, audiences, scope, jti, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                     TIMESTAMPTZ 'epoch' + ($11::text || ' microseconds')::interval)",
        )
        .bind(opaque.token_digest)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(grant_text)
        .bind(opaque.subject)
        .bind(opaque.client_id)
        .bind(opaque.audience)
        .bind(resource_array_to_json(opaque.audiences))
        .bind(opaque.scope)
        .bind(opaque.jti.to_string())
        .bind(opaque.expires_at_unix_micros)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Reconstruct a [`RefreshTokenResolution`] from a joined row read within scope.
fn refresh_resolution_from_row(
    row: &PgRow,
    scope: &Scope,
) -> Result<RefreshTokenResolution, StoreError> {
    let family_id = RefreshFamilyId::parse_in_scope(&row.get::<String, _>("family_id"), scope)?;
    let grant_id = GrantId::parse_in_scope(&row.get::<String, _>("grant_id"), scope)?;
    Ok(RefreshTokenResolution {
        family_id,
        grant_id,
        generation: i64::from(row.get::<i32, _>("generation")),
        subject: row.get("subject"),
        client_id: row.get("client_id"),
        scope: row.get("scope"),
        granted_resources: resource_array_from_json(
            row.get::<Option<String>, _>("granted_resources").as_deref(),
        ),
        auth_methods: row.get("auth_methods"),
        offline: row.get("offline"),
        issued_at_unix_micros: row.get("issued_us"),
        idle_expires_at_unix_micros: row.get("idle_us"),
        family_absolute_expires_at_unix_micros: row.get("abs_us"),
        rotated: row.get("rotated"),
        active: row.get::<bool, _>("family_live") && row.get::<bool, _>("grant_live"),
    })
}

// ===========================================================================
// Bootstrap login, consent, and session (issue #20).
//
// The tenant-scoped persistence behind the minimal in-process login,
// registration, and consent surfaces: the bootstrap user directory (identifier +
// Argon2id hash), the minimal server-side sessions, and the recorded consent
// decisions. Everything below routes through the SAME scope filter and (for
// writes) the SAME audited-write primitive as the rest of the data plane, so the
// login/consent surface is isolated by construction like every other one.
// ===========================================================================

/// A bootstrap user read back within scope (issue #20): the account the login
/// surface authenticates.
///
/// [`fmt::Debug`] is hand written and redacting: the `password_hash` is a
/// one-way verifier but still sensitive, so a struct dump or a `tracing` field
/// never spills it.
#[derive(Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// The user identifier (embeds its tenant and environment). Its string is the
    /// stable pseudonymous subject the bootstrap mints tokens for.
    pub id: UserId,
    /// The login handle the user typed.
    pub identifier: String,
    /// The Argon2id PHC verifier string. One-way; never the plaintext password.
    pub password_hash: String,
    /// The user's lifecycle state (issue #52). The login read path FENCES a user
    /// whose state cannot authenticate (blocked, disabled, `pending_verification`):
    /// the credential is correct but the account is not permitted to sign in.
    pub state: UserState,
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRecord")
            .field("id", &self.id)
            .field("identifier", &self.identifier)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// A user's lifecycle state (issue #52): a first-class enum with an explicit state
/// machine, distinct from the soft-delete tombstone. Every management-plane
/// transition is validated ([`UserState::can_transition_to`]), audited, and (for a
/// session-ending target) cascades to the user's sessions and refresh families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserState {
    /// A live account that can authenticate.
    Active,
    /// Administratively BLOCKED: cannot authenticate; its live sessions were ended
    /// on the transition. A reversible fence (an operator can move it back).
    Blocked,
    /// DISABLED: cannot authenticate; its live sessions were ended on the
    /// transition. Distinct from blocked so the operator's intent is legible.
    Disabled,
    /// PENDING VERIFICATION: created but not yet verified, so it cannot authenticate
    /// until it is moved to active. A creation-time state, never a transition target.
    PendingVerification,
    /// SCHEDULED for offboarding at a recorded instant. Still able to authenticate
    /// until the worker executes the offboarding (which disables it and cascades).
    ScheduledOffboarding,
}

impl UserState {
    /// The stable wire string stored in `users.state`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            UserState::Active => "active",
            UserState::Blocked => "blocked",
            UserState::Disabled => "disabled",
            UserState::PendingVerification => "pending_verification",
            UserState::ScheduledOffboarding => "scheduled_offboarding",
        }
    }

    /// Reconstruct a state from its wire string. The soft-delete tombstone
    /// (`deleted`) and any unknown tag both return [`None`], so a deleted user
    /// (which the reads already filter out) never surfaces as a live state and a
    /// corrupt row surfaces as an error rather than a panic.
    #[must_use]
    pub fn from_wire(state: &str) -> Option<Self> {
        match state {
            "active" => Some(UserState::Active),
            "blocked" => Some(UserState::Blocked),
            "disabled" => Some(UserState::Disabled),
            "pending_verification" => Some(UserState::PendingVerification),
            "scheduled_offboarding" => Some(UserState::ScheduledOffboarding),
            _ => None,
        }
    }

    /// Whether a user in this state may complete an interactive or OIDC login. The
    /// data-plane read path fences every other state (the credential is correct but
    /// the account is not permitted to sign in), with no wrong-password oracle.
    #[must_use]
    pub fn can_authenticate(&self) -> bool {
        matches!(self, UserState::Active | UserState::ScheduledOffboarding)
    }

    /// Whether entering this state ENDS the user's live sessions: blocking or
    /// disabling a user cascades to its sessions and non-offline refresh families
    /// and publishes to the session-ended fan-out (issue #35).
    #[must_use]
    pub fn ends_sessions(&self) -> bool {
        matches!(self, UserState::Blocked | UserState::Disabled)
    }

    /// Whether this state is a valid INITIAL state for an admin-created user. A
    /// scheduled offboarding needs a timestamp and is only ever reached by a
    /// transition, so it is never a creation-time state.
    #[must_use]
    pub fn is_creatable(&self) -> bool {
        !matches!(self, UserState::ScheduledOffboarding)
    }

    /// The state machine: whether a live user may move from `self` to `to`. A no-op
    /// (same state) is refused, and pending-verification is a creation-time state
    /// only (never a transition target). Every other move between live states is
    /// permitted; the store additionally requires a timestamp for a move to
    /// scheduled-offboarding. An invalid transition is refused fail closed.
    #[must_use]
    pub fn can_transition_to(self, to: UserState) -> bool {
        if self == to {
            return false;
        }
        !matches!(to, UserState::PendingVerification)
    }
}

/// A user as the management-plane surface reports it (issue #52): the searchable
/// metadata and lifecycle state, with the login handle and external id decrypted
/// for display. It NEVER carries the password hash (the #11 secret lesson: a
/// management response must not return a stored credential). Every timestamp is
/// microseconds since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAdminRecord {
    /// The user identifier (a `usr_` id embedding its scope).
    pub id: UserId,
    /// The login handle, decrypted from its sealed column for display.
    pub identifier: String,
    /// The lifecycle state.
    pub state: UserState,
    /// The external correlation id, decrypted for display, or [`None`] when the
    /// user has no external id linked.
    pub external_id: Option<String>,
    /// The scheduled-offboarding instant, present only in the scheduled-offboarding
    /// state.
    pub scheduled_offboarding_at_unix_micros: Option<i64>,
    /// Creation time (the pagination key).
    pub created_at_unix_micros: i64,
    /// The last-mutation instant.
    pub updated_at_unix_micros: i64,
}

/// The management-plane user list filters (issue #52): by lifecycle state, by
/// external id, and by login handle. The external-id and identifier filters are
/// resolved through their per-tenant blind indexes (the plaintext is never stored),
/// so an equality search matches without a plaintext column. The environment
/// dimension is the scope itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserListFilter<'a> {
    /// Only users in this lifecycle state, or [`None`] for all live users.
    pub state: Option<UserState>,
    /// Only the user whose external id equals this value, or [`None`] for all.
    pub external_id: Option<&'a str>,
    /// Only the user whose login handle equals this value, or [`None`] for all.
    pub identifier: Option<&'a str>,
}

/// Everything the admin user create needs, bundled so the repository method stays
/// within the readable-argument-count lint (issue #52).
#[derive(Debug, Clone, Copy)]
pub struct NewAdminUser<'a> {
    /// The caller-supplied user id, or [`None`] to mint a fresh one. A supplied id
    /// already taken in the scope is a [`StoreError::Conflict`] (a 409).
    pub id: Option<&'a UserId>,
    /// The login handle (unique per scope through its blind index).
    pub identifier: &'a str,
    /// The precomputed Argon2id hash, or [`None`] for a credential-less account
    /// (created pending verification / awaiting a credential; it cannot log in
    /// until one is set, which the login fence enforces).
    pub password_hash: Option<&'a str>,
    /// The standard-claim JSON document (issue #15), or [`None`] for `{}`.
    pub claims_json: Option<&'a str>,
    /// The external correlation id to link at creation, or [`None`].
    pub external_id: Option<&'a str>,
    /// The initial lifecycle state (must be a creatable state).
    pub state: UserState,
}

/// The read-only bootstrap user repository (issue #20).
pub struct UserRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl UserRepo<'_> {
    /// Look up a user by login handle within scope. Returns [`None`] when no user
    /// with that handle exists in this scope; the caller (the login surface) then
    /// verifies the password against the returned Argon2id hash, and verifies
    /// against a dummy hash when this is [`None`] so a present and an absent
    /// account take indistinguishable time (user-enumeration hardening).
    ///
    /// The identifier is sealed at rest, so the equality lookup queries the
    /// deterministic blind index (a per-tenant keyed HMAC of the handle) rather
    /// than the plaintext, and the returned record's plaintext handle is recovered
    /// by decrypting the sealed identifier under the row's DEK version.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if no platform master key is configured (the PII
    /// path fails closed rather than fall back to plaintext) or a sealed value
    /// cannot be authenticated and decrypted; [`StoreError::Database`] on a
    /// persistence failure.
    pub async fn by_identifier(&self, identifier: &str) -> Result<Option<UserRecord>, StoreError> {
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        let bidx = user_identifier_blind_index(master, self.scope, identifier);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // A soft-deleted user (a tombstone) never resolves as a login account: the
        // `deleted_at IS NULL` filter reads it as absent, so a deleted user cannot
        // authenticate exactly as an unknown one cannot.
        let row = sqlx::query(
            "SELECT id, identifier_sealed, password_hash, pii_dek_version, state FROM users \
             WHERE identifier_bidx = $1 AND tenant_id = $2 AND environment_id = $3 \
             AND deleted_at IS NULL",
        )
        .bind(bidx.into_bytes())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let id_text: String = row.get("id");
        let id = UserId::parse_in_scope(&id_text, &self.scope)?;
        let dek_version: i32 = row.get("pii_dek_version");
        let sealed: Vec<u8> = row.get("identifier_sealed");
        let state =
            UserState::from_wire(&row.get::<String, _>("state")).ok_or(StoreError::Encryption)?;
        let dek = fetch_dek_by_version(&mut tx, self.scope, master, dek_version).await?;
        let plaintext = dek.open(
            &user_pii_seal_aad(self.scope, USER_IDENTIFIER_PURPOSE, dek_version),
            &Sealed::from_bytes(sealed)?,
        )?;
        tx.commit().await?;
        let identifier = String::from_utf8(plaintext).map_err(|_| StoreError::Encryption)?;
        Ok(Some(UserRecord {
            id,
            identifier,
            password_hash: row.get("password_hash"),
            state,
        }))
    }

    /// Resolve the lifecycle state of a LIVE user by its subject (the `usr_` id
    /// string a refresh-token family carries), within scope (issue #52). Reads ONLY
    /// the `state` column, so it needs no platform master key and decrypts no PII,
    /// and it filters out the soft-delete tombstone (`deleted_at IS NULL`).
    ///
    /// Returns [`None`] when no live user with that subject exists in this scope: an
    /// absent user, a cross-scope subject, a soft-deleted one, or a corrupt/unknown
    /// state tag ([`UserState::from_wire`] rejects the `deleted` tombstone and any
    /// unknown value). The caller treats [`None`] as FAIL CLOSED.
    ///
    /// The refresh-token grant reads this to RE-CHECK the token subject's lifecycle
    /// before minting a fresh access token: a user blocked, disabled, or deleted
    /// AFTER a refresh family was opened must not keep minting tokens, including
    /// through a surviving `offline_access` family (issue #21). This is the
    /// authoritative fence-completeness guarantee, the same class as the issuer
    /// live-fence (a suspended subject must stop authenticating on the NEXT request).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure (which the caller also
    /// treats as fail closed, never fail open).
    pub async fn state_for_subject(&self, subject: &str) -> Result<Option<UserState>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT state FROM users \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
        )
        .bind(subject)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.and_then(|row| UserState::from_wire(&row.get::<String, _>("state"))))
    }

    /// Parse an untrusted user identifier under this scope (issue #52). A malformed
    /// identifier and one minted in another scope both return the uniform not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<UserId, StoreError> {
        Ok(UserId::parse_in_scope(raw, &self.scope)?)
    }

    /// Fetch one live (non-deleted) user by id, within scope, for the management
    /// surface (issue #52). A user absent in this scope (including a cross-scope id
    /// or a soft-deleted one) is the uniform [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such live user is visible in this scope;
    /// [`StoreError::Encryption`] if no master key is configured or a sealed value
    /// cannot be opened; [`StoreError::Database`] on a persistence failure.
    pub async fn get(&self, id: &UserId) -> Result<UserAdminRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, identifier_sealed, pii_dek_version, state, \
             external_id_sealed, external_id_dek_version, \
             (EXTRACT(EPOCH FROM scheduled_offboarding_at) * 1000000)::bigint AS scheduled_us, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint AS updated_us \
             FROM users \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Err(StoreError::NotFound);
        };
        let record = user_admin_record_from_row(&mut tx, self.scope, master, &row).await?;
        tx.commit().await?;
        Ok(record)
    }

    /// Look up a live user by EXTERNAL ID within scope (issue #52). The external id
    /// is a lookup key stored as a per-tenant blind index, so this resolves the
    /// deterministic index rather than a plaintext column. Returns [`None`] when no
    /// user in this scope has claimed that external id.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if no master key is configured or a sealed value
    /// cannot be opened; [`StoreError::Database`] on a persistence failure.
    pub async fn by_external_id(
        &self,
        external_id: &str,
    ) -> Result<Option<UserAdminRecord>, StoreError> {
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        let bidx = user_external_id_blind_index(master, self.scope, external_id);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, identifier_sealed, pii_dek_version, state, \
             external_id_sealed, external_id_dek_version, \
             (EXTRACT(EPOCH FROM scheduled_offboarding_at) * 1000000)::bigint AS scheduled_us, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint AS updated_us \
             FROM users \
             WHERE external_id_bidx = $1 AND tenant_id = $2 AND environment_id = $3 \
             AND deleted_at IS NULL",
        )
        .bind(bidx.into_bytes())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let record = user_admin_record_from_row(&mut tx, self.scope, master, &row).await?;
        tx.commit().await?;
        Ok(Some(record))
    }

    /// One page of live users matching `filter`, ordered by `(created_at, id)`,
    /// starting strictly after `after` (issue #52). The filter searches by
    /// lifecycle state, by external id, and by login handle within this scope; the
    /// external-id and identifier searches resolve their per-tenant blind indexes.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if no master key is configured or a sealed value
    /// cannot be opened; [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        filter: UserListFilter<'_>,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<UserAdminRecord>, StoreError> {
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        let (after_micros, after_id) = split_cursor(after);
        let external_bidx = filter
            .external_id
            .map(|value| user_external_id_blind_index(master, self.scope, value).into_bytes());
        let identifier_bidx = filter
            .identifier
            .map(|value| user_identifier_blind_index(master, self.scope, value).into_bytes());
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, identifier_sealed, pii_dek_version, state, \
             external_id_sealed, external_id_dek_version, \
             (EXTRACT(EPOCH FROM scheduled_offboarding_at) * 1000000)::bigint AS scheduled_us, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint AS updated_us \
             FROM users \
             WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NULL \
             AND ($5::text IS NULL OR state = $5) \
             AND ($6::bytea IS NULL OR external_id_bidx = $6) \
             AND ($7::bytea IS NULL OR identifier_bidx = $7) \
             AND ($3::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4::text)) \
             ORDER BY created_at, id LIMIT $8",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(filter.state.map(|s| s.as_str()))
        .bind(external_bidx)
        .bind(identifier_bidx)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(&mut *tx)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(user_admin_record_from_row(&mut tx, self.scope, master, row).await?);
        }
        tx.commit().await?;
        Ok(out)
    }

    /// Read a user's stored standard-claim document (issue #15) by their subject
    /// (the `usr_` id string), within scope. Returns the raw JSON text of the
    /// user's `claims` object (an empty object `{}` for a user with no releasable
    /// claims), or [`None`] when no such user is visible in this scope.
    ///
    /// The `UserInfo` endpoint resolves an access token to its local subject and
    /// then reads this document, releasing only the members a granted scope or an
    /// explicit claims request selects. The value is opaque JSON text here; the
    /// OIDC layer parses it (the store adds no JSON dependency). `sub` is never
    /// stored or read from here: it is always derived through the shared subject
    /// function.
    ///
    /// The claim document is sealed at rest, so this decrypts it transparently
    /// under the row's DEK version before returning the plaintext JSON.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if no platform master key is configured (the PII
    /// path fails closed) or the sealed claims cannot be authenticated and
    /// decrypted; [`StoreError::Database`] on a persistence failure.
    pub async fn claims_for_subject(&self, subject: &str) -> Result<Option<String>, StoreError> {
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT claims_sealed, pii_dek_version FROM users \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(subject)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let dek_version: i32 = row.get("pii_dek_version");
        let sealed: Vec<u8> = row.get("claims_sealed");
        let dek = fetch_dek_by_version(&mut tx, self.scope, master, dek_version).await?;
        let plaintext = dek.open(
            &user_pii_seal_aad(self.scope, USER_CLAIMS_PURPOSE, dek_version),
            &Sealed::from_bytes(sealed)?,
        )?;
        tx.commit().await?;
        let claims = String::from_utf8(plaintext).map_err(|_| StoreError::Encryption)?;
        Ok(Some(claims))
    }

    /// Read a user's stored Argon2id password verifier by their subject (the `usr_`
    /// id string), within scope. Returns [`None`] when no such user is visible in
    /// this scope (including a cross-scope subject). The self-service password change
    /// (issue #61) reads this to verify the CURRENT password before it writes the new
    /// one; the hash is a one-way verifier, never the plaintext, and is never logged.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn password_hash_for_subject(
        &self,
        subject: &UserId,
    ) -> Result<Option<String>, StoreError> {
        if subject.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT password_hash FROM users \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(subject.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| row.get::<String, _>("password_hash")))
    }
}

/// The mutating bootstrap user repository (issue #20).
pub struct ActingUserRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingUserRepo<'_> {
    /// Register a bootstrap user with a precomputed Argon2id `password_hash`, and
    /// return the fresh identifier. Writes a `user.register` audit row in the same
    /// transaction. The hash is computed by the caller (the registration surface)
    /// through the entropy seam; the plaintext password never reaches the store.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if the login handle is already registered in this
    /// scope; [`StoreError::Database`] on a persistence failure.
    pub async fn register(
        &self,
        env: &Env,
        identifier: &str,
        password_hash: &str,
    ) -> Result<UserId, StoreError> {
        // The registration surface (issue #20) records no standard claims; the
        // column defaults to the empty object, released as no claims by UserInfo.
        self.register_inner(env, identifier, password_hash, "{}")
            .await
    }

    /// Register a bootstrap user with a precomputed Argon2id `password_hash` and a
    /// standard-claim document (issue #15), returning the fresh identifier. The
    /// `claims_json` is the user's OIDC standard claim object as JSON text (for
    /// example `{"email":"a@b.test","email_verified":true}`), stored verbatim and
    /// released selectively by `UserInfo` per the granted scope and any claims
    /// request. Writes a `user.register` audit row in the same transaction.
    ///
    /// There is no separate update path (the bootstrap `users` table grants only
    /// SELECT and INSERT), so a user's claims are set here at registration and are
    /// otherwise fixed until the full identity model lands.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if the login handle is already registered in this
    /// scope; [`StoreError::Database`] on a persistence failure.
    pub async fn register_with_claims(
        &self,
        env: &Env,
        identifier: &str,
        password_hash: &str,
        claims_json: &str,
    ) -> Result<UserId, StoreError> {
        self.register_inner(env, identifier, password_hash, claims_json)
            .await
    }

    /// Ensure the scope has a live KEK and DEK to seal PII under, provisioning each
    /// lazily on first use. Idempotent: an already-provisioned key is a no-op (the
    /// provision path's [`StoreError::Conflict`] is swallowed here), so a repeat
    /// registration never fails on it.
    async fn ensure_scope_keys(&self, env: &Env, master: &MasterKey) -> Result<(), StoreError> {
        let envelope = ActingEnvelopeRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        };
        match envelope.provision_kek(env, master).await {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error),
        }
        match envelope.provision_dek(env, master).await {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Shared body of the registration path: seal the login handle and the claim
    /// document under the scope's active DEK, insert the user (with its blind index
    /// for lookup) and its audit row in one transaction, and map a duplicate login
    /// handle to the caller-facing [`StoreError::Conflict`]. The plaintext handle
    /// and claims never reach a column.
    async fn register_inner(
        &self,
        env: &Env,
        identifier: &str,
        password_hash: &str,
        claims_json: &str,
    ) -> Result<UserId, StoreError> {
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        // The scope needs a live KEK/DEK before the first PII seal; provision them
        // lazily (idempotent) outside the register transaction.
        self.ensure_scope_keys(env, master).await?;
        let id = UserId::generate(env, &self.scope);
        let scope = self.scope;
        // The blind index is deterministic under the master key alone (no DEK), so
        // compute it up front; it is what a later `by_identifier` lookup queries.
        let bidx = user_identifier_blind_index(master, scope, identifier);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::UserRegister,
                target: &id,
            },
            async move |tx| {
                let (dek_version, dek) = fetch_active_dek(tx, scope, master).await?;
                let identifier_sealed = dek.seal(
                    env.entropy(),
                    &user_pii_seal_aad(scope, USER_IDENTIFIER_PURPOSE, dek_version),
                    identifier.as_bytes(),
                );
                let claims_sealed = dek.seal(
                    env.entropy(),
                    &user_pii_seal_aad(scope, USER_CLAIMS_PURPOSE, dek_version),
                    claims_json.as_bytes(),
                );
                let result = sqlx::query(
                    "INSERT INTO users \
                     (id, tenant_id, environment_id, identifier_bidx, identifier_sealed, \
                      password_hash, claims_sealed, pii_dek_version) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(bidx.into_bytes())
                .bind(identifier_sealed.into_bytes())
                .bind(password_hash)
                .bind(claims_sealed.into_bytes())
                .bind(dek_version)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => Ok(()),
                    // A duplicate login handle is a caller-facing conflict (the
                    // handle is taken, caught by the blind-index unique
                    // constraint), not a persistence fault. Erroring here rolls the
                    // audited write back, so a rejected registration leaves neither
                    // a user row nor an audit row.
                    Err(error) if is_unique_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Create a user through the management API (issue #52): the admin create, with
    /// an optional caller-supplied id and an optional external id, in a chosen
    /// initial lifecycle state. Seals the login handle, the claim document, and (when
    /// present) the external id under the scope's active DEK, and writes a
    /// `user.create` audit row in the same transaction. Returns the id (the supplied
    /// one, or a freshly minted one).
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if the supplied id, the login handle, or the external
    /// id is already taken in the scope (a 409); [`StoreError::IdempotencyConflict`]
    /// if the idempotency key is already stored; [`StoreError::Encryption`] if no
    /// master key is configured; [`StoreError::Database`] on a persistence failure.
    pub async fn admin_create(
        &self,
        env: &Env,
        spec: NewAdminUser<'_>,
        created_at_micros: i64,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<UserId, StoreError> {
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        self.ensure_scope_keys(env, master).await?;
        let scope = self.scope;
        // A supplied id must be in THIS scope (a foreign id is the uniform not-found,
        // never a cross-scope create). An absent id mints a fresh one.
        let id = match spec.id {
            Some(supplied) => {
                if supplied.scope() != scope {
                    return Err(StoreError::NotFound);
                }
                *supplied
            }
            None => UserId::generate(env, &scope),
        };
        let identifier_bidx = user_identifier_blind_index(master, scope, spec.identifier);
        let external_id_bidx = spec
            .external_id
            .map(|value| user_external_id_blind_index(master, scope, value).into_bytes());
        let password_hash = spec.password_hash.unwrap_or(USER_UNUSABLE_PASSWORD_HASH);
        let claims_json = spec.claims_json.unwrap_or("{}");
        let external_id = spec.external_id;
        let state = spec.state;
        // created_at and updated_at are bound from the caller's clock read (not the
        // database clock), so the response body built before the write matches the
        // stored row exactly and paging stays deterministic under a manual clock.
        let now_micros = created_at_micros;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::UserCreate,
                target: &id,
            },
            async move |tx| {
                let (dek_version, dek) = fetch_active_dek(tx, scope, master).await?;
                let identifier_sealed = dek.seal(
                    env.entropy(),
                    &user_pii_seal_aad(scope, USER_IDENTIFIER_PURPOSE, dek_version),
                    spec.identifier.as_bytes(),
                );
                let claims_sealed = dek.seal(
                    env.entropy(),
                    &user_pii_seal_aad(scope, USER_CLAIMS_PURPOSE, dek_version),
                    claims_json.as_bytes(),
                );
                let external_id_sealed = external_id.map(|value| {
                    dek.seal(
                        env.entropy(),
                        &user_pii_seal_aad(scope, USER_EXTERNAL_ID_PURPOSE, dek_version),
                        value.as_bytes(),
                    )
                    .into_bytes()
                });
                let external_id_dek_version = external_id.map(|_| dek_version);
                let result = sqlx::query(
                    "INSERT INTO users \
                     (id, tenant_id, environment_id, identifier_bidx, identifier_sealed, \
                      password_hash, claims_sealed, pii_dek_version, state, \
                      external_id_bidx, external_id_sealed, external_id_dek_version, \
                      created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                             TIMESTAMPTZ 'epoch' + ($13::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($13::text || ' microseconds')::interval)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(identifier_bidx.into_bytes())
                .bind(identifier_sealed.into_bytes())
                .bind(password_hash)
                .bind(claims_sealed.into_bytes())
                .bind(dek_version)
                .bind(state.as_str())
                .bind(external_id_bidx)
                .bind(external_id_sealed)
                .bind(external_id_dek_version)
                .bind(now_micros)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => {}
                    // A collision on the id primary key, the login-handle blind index,
                    // or the external-id blind index is a caller-facing conflict (a
                    // 409), never a persistence fault. The audited write rolls back, so
                    // a rejected create leaves neither a user row nor an audit row.
                    Err(error) if is_unique_violation(&error) => return Err(StoreError::Conflict),
                    Err(error) => return Err(error.into()),
                }
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Update a live user's standard-claim profile through the management API (RFC
    /// 7396 semantics are applied by the caller; the store persists the resolved
    /// document). Re-seals the claim JSON under the row's EXISTING DEK version (so the
    /// login handle and claims stay sealed under one version) and writes a
    /// `user.update` audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live user matched in this scope;
    /// [`StoreError::Encryption`] if no master key is configured;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn update_claims(
        &self,
        env: &Env,
        id: &UserId,
        claims_json: &str,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        let scope = self.scope;
        // Pre-read the row's DEK version (and confirm it is live) under this scope's
        // row-level-security variables (the `users` table forces RLS): claims re-seal
        // under the SAME version the identifier is sealed under, so a single
        // pii_dek_version keeps describing both.
        let mut pre = begin_scoped(self.store, scope).await?;
        let row = sqlx::query(
            "SELECT pii_dek_version FROM users \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_optional(&mut *pre)
        .await?;
        pre.commit().await?;
        let dek_version: i32 = row.ok_or(StoreError::NotFound)?.get("pii_dek_version");
        let now_micros = epoch_micros(env.clock().now_utc());
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::UserUpdate,
                target: id,
            },
            async move |tx| {
                let dek = fetch_dek_by_version(tx, scope, master, dek_version).await?;
                let claims_sealed = dek.seal(
                    env.entropy(),
                    &user_pii_seal_aad(scope, USER_CLAIMS_PURPOSE, dek_version),
                    claims_json.as_bytes(),
                );
                let result = sqlx::query(
                    "UPDATE users SET claims_sealed = $1, \
                         updated_at = TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval \
                     WHERE id = $3 AND tenant_id = $4 AND environment_id = $5 \
                     AND deleted_at IS NULL",
                )
                .bind(claims_sealed.into_bytes())
                .bind(now_micros)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Transition a live user's lifecycle state through the management API (issue
    /// #52). Validates the transition against the user state machine (an invalid
    /// transition is refused fail closed), flips the state guarded on the source
    /// state, and, for a session-ending target (block, disable), cascades the user's
    /// sessions and non-offline refresh families and publishes to the session-ended
    /// fan-out, all in ONE audited transaction (`user.state_change`, with the target
    /// state on the audit row's operator-safe detail).
    ///
    /// A move to scheduled-offboarding requires `scheduled_at`; every other target
    /// must pass [`None`]. `hard_kill` (only meaningful for a session-ending target)
    /// also revokes the offline families and their grants.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live user matched in this scope;
    /// [`StoreError::Conflict`] if the transition is invalid or lost a concurrent
    /// race; [`StoreError::IdempotencyConflict`] if the idempotency key is already
    /// stored; [`StoreError::Database`] on a persistence failure.
    pub async fn set_state(
        &self,
        env: &Env,
        id: &UserId,
        to: UserState,
        scheduled_at: Option<i64>,
        hard_kill: bool,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        // A scheduled-offboarding target needs an instant; every other target must
        // not carry one. A mismatch is an invalid request, refused fail closed.
        if (to == UserState::ScheduledOffboarding) != scheduled_at.is_some() {
            return Err(StoreError::Conflict);
        }
        let scope = self.scope;
        // The pre-read must run under this scope's row-level-security variables (the
        // `users` table forces RLS), so read it inside a scoped transaction rather
        // than against the bare pool. The in-transaction UPDATE below re-checks
        // `state = from` so a concurrent change cannot slip an invalid transition in.
        let mut pre = begin_scoped(self.store, scope).await?;
        let row = sqlx::query(
            "SELECT state FROM users \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_optional(&mut *pre)
        .await?;
        pre.commit().await?;
        let from =
            UserState::from_wire(&row.ok_or(StoreError::NotFound)?.get::<String, _>("state"))
                .ok_or(StoreError::NotFound)?;
        if !from.can_transition_to(to) {
            return Err(StoreError::Conflict);
        }
        let now_micros = epoch_micros(env.clock().now_utc());
        let emit = SessionEndedEmit::from_acting(env, &self.acting);
        let subject_text = id.to_string();
        write_audited_detailed(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::UserStateChange,
                target: id,
            },
            async move |tx| {
                insert_idempotency(tx, idempotency).await?;
                let result = sqlx::query(
                    "UPDATE users SET state = $1, \
                         scheduled_offboarding_at = CASE WHEN $2::bigint IS NULL THEN NULL ELSE \
                             TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval END, \
                         updated_at = TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval \
                     WHERE id = $4 AND tenant_id = $5 AND environment_id = $6 \
                     AND deleted_at IS NULL AND state = $7",
                )
                .bind(to.as_str())
                .bind(scheduled_at)
                .bind(now_micros)
                .bind(&subject_text)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(from.as_str())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    // Lost the race: the user changed state or was deleted between the
                    // pre-read and here. Refuse fail closed.
                    return Err(StoreError::Conflict);
                }
                if to.ends_sessions() {
                    cascade_user_sessions_ended(
                        tx,
                        scope,
                        &subject_text,
                        SessionEndCause::UserRevokedAll,
                        now_micros,
                        hard_kill,
                        &emit,
                    )
                    .await?;
                }
                Ok(())
            },
            false,
            Some(to.as_str()),
        )
        .await
    }

    /// Delete a live user through the management API (issue #52): a soft-delete
    /// tombstone that cascades the user's sessions and non-offline refresh families
    /// and publishes to the session-ended fan-out, in ONE audited transaction
    /// (`user.delete`), then reads as a uniform not-found. Retaining the tombstone
    /// keeps the append-only audit log's references to the user legible and keeps the
    /// login lookup resolving it as absent. `hard_kill` also revokes the offline
    /// families and their grants.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live user matched in this scope (absent, or
    /// already deleted: a repeat delete is the uniform not-found);
    /// [`StoreError::IdempotencyConflict`] if the idempotency key is already stored;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn delete(
        &self,
        env: &Env,
        id: &UserId,
        hard_kill: bool,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let emit = SessionEndedEmit::from_acting(env, &self.acting);
        let subject_text = id.to_string();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::UserDelete,
                target: id,
            },
            async move |tx| {
                insert_idempotency(tx, idempotency).await?;
                let result = sqlx::query(
                    "UPDATE users SET state = 'deleted', \
                         deleted_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
                         updated_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
                     AND deleted_at IS NULL",
                )
                .bind(now_micros)
                .bind(&subject_text)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                cascade_user_sessions_ended(
                    tx,
                    scope,
                    &subject_text,
                    SessionEndCause::UserRevokedAll,
                    now_micros,
                    hard_kill,
                    &emit,
                )
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Link an EXTERNAL ID to a live user through the management API (issue #52): a
    /// correlation id from the tenant's own systems, sealed and blind-indexed under
    /// the scope's active DEK, written with a `user.external_id.link` audit row. The
    /// external id is unique per scope, so a value already claimed by another user in
    /// the scope is a conflict.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live user matched in this scope;
    /// [`StoreError::Conflict`] if the external id is already claimed by another user
    /// in the scope; [`StoreError::Encryption`] if no master key is configured;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn link_external_id(
        &self,
        env: &Env,
        id: &UserId,
        external_id: &str,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        let scope = self.scope;
        let bidx = user_external_id_blind_index(master, scope, external_id).into_bytes();
        let now_micros = epoch_micros(env.clock().now_utc());
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::UserExternalIdLink,
                target: id,
            },
            async move |tx| {
                let (dek_version, dek) = fetch_active_dek(tx, scope, master).await?;
                let sealed = dek.seal(
                    env.entropy(),
                    &user_pii_seal_aad(scope, USER_EXTERNAL_ID_PURPOSE, dek_version),
                    external_id.as_bytes(),
                );
                let result = sqlx::query(
                    "UPDATE users SET external_id_bidx = $1, external_id_sealed = $2, \
                         external_id_dek_version = $3, \
                         updated_at = TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
                     WHERE id = $5 AND tenant_id = $6 AND environment_id = $7 \
                     AND deleted_at IS NULL",
                )
                .bind(bidx)
                .bind(sealed.into_bytes())
                .bind(dek_version)
                .bind(now_micros)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(done) if done.rows_affected() == 0 => Err(StoreError::NotFound),
                    Ok(_) => Ok(()),
                    // The external id is already claimed by another user in the scope
                    // (the per-scope partial unique index): a conflict, not a fault.
                    Err(error) if is_unique_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await
    }

    /// Unlink a live user's EXTERNAL ID through the management API (issue #52),
    /// freeing it for another user in the scope, with a `user.external_id.unlink`
    /// audit row. Idempotent in effect: unlinking a user that has no external id
    /// clears nothing and still succeeds.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live user matched in this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn unlink_external_id(&self, env: &Env, id: &UserId) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::UserExternalIdUnlink,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE users SET external_id_bidx = NULL, external_id_sealed = NULL, \
                         external_id_dek_version = NULL, \
                         updated_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
                     AND deleted_at IS NULL",
                )
                .bind(now_micros)
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Execute every DUE scheduled-offboarding in this scope (issue #52): a user in
    /// the scheduled-offboarding state whose instant is at or before `now_micros` is
    /// disabled and its sessions cascaded, fanning out identically to a manual
    /// disable, each in its own audited transaction (`user.offboarding.execute`).
    /// Idempotent: an executed user is no longer scheduled, so a re-run reprocesses
    /// nothing, and a user a concurrent run already flipped is skipped. Returns how
    /// many users were offboarded.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn execute_scheduled_offboardings(
        &self,
        env: &Env,
        now_micros: i64,
    ) -> Result<u64, StoreError> {
        let scope = self.scope;
        // Read the due ids up front; each is then executed in its own audited
        // transaction, guarded on the scheduled state so a concurrent run cannot
        // double-execute one.
        let mut tx = begin_scoped(self.store, scope).await?;
        let due = sqlx::query(
            "SELECT id FROM users \
             WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NULL \
             AND state = 'scheduled_offboarding' \
             AND scheduled_offboarding_at IS NOT NULL \
             AND scheduled_offboarding_at <= \
                 TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval \
             ORDER BY scheduled_offboarding_at, id",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(now_micros)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut executed = 0_u64;
        for row in &due {
            let Ok(id) = UserId::parse_in_scope(&row.get::<String, _>("id"), &scope) else {
                continue;
            };
            let subject_text = id.to_string();
            let emit = SessionEndedEmit::from_acting(env, &self.acting);
            let mut flipped = false;
            let flipped_ref = &mut flipped;
            write_audited(
                AuditedWrite {
                    store: self.store,
                    scope,
                    acting: &self.acting,
                    env,
                    action: Action::UserOffboardingExecute,
                    target: &id,
                },
                async move |tx| {
                    let result = sqlx::query(
                        "UPDATE users SET state = 'disabled', \
                             updated_at = \
                                 TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                         WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
                         AND deleted_at IS NULL AND state = 'scheduled_offboarding'",
                    )
                    .bind(now_micros)
                    .bind(&subject_text)
                    .bind(scope.tenant().to_string())
                    .bind(scope.environment().to_string())
                    .execute(&mut **tx)
                    .await?;
                    if result.rows_affected() == 0 {
                        // A concurrent run already executed this one: skip it (its own
                        // audited transaction wrote the row). Rolling back here leaves
                        // no duplicate audit row.
                        return Err(StoreError::NotFound);
                    }
                    cascade_user_sessions_ended(
                        tx,
                        scope,
                        &subject_text,
                        SessionEndCause::UserRevokedAll,
                        now_micros,
                        false,
                        &emit,
                    )
                    .await?;
                    *flipped_ref = true;
                    Ok(())
                },
                false,
            )
            .await
            .or_else(|error| match error {
                // A concurrently-executed user is a benign skip, not a failure.
                StoreError::NotFound => Ok(()),
                other => Err(other),
            })?;
            if flipped {
                executed += 1;
            }
        }
        Ok(executed)
    }

    /// CHANGE a user's password at the self-service account surface (issue #61):
    /// write the fresh Argon2id `new_password_hash` onto the user, and in the SAME
    /// transaction REVOKE every OTHER session of the user (session-fixation defense),
    /// cascading each to its refresh families through the unified session-ended
    /// fan-out (issue #35) exactly as an admin revoke does. The session named by
    /// `keep` (the one the change is being made from) is preserved so the user is not
    /// signed out of the browser they are actively using; pass [`None`] to revoke
    /// EVERY session. One `account.password.change` audit row targets the user and is
    /// attributed to the acting principal; `step_up_detail` records the operator-safe
    /// step-up policy the sensitive change declared (never attacker-controlled text).
    ///
    /// The caller (the account surface) has already verified the CURRENT password
    /// against the stored verifier and computed `new_password_hash` through the
    /// entropy seam, so no plaintext password ever reaches the store and the hash is
    /// never logged.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `subject` is out of this scope or names no user;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn change_password(
        &self,
        env: &Env,
        subject: &UserId,
        new_password_hash: &str,
        keep: Option<&SessionId>,
        step_up_detail: &str,
    ) -> Result<UserRevocation, StoreError> {
        if subject.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let subject_text = subject.to_string();
        // A cross-scope `keep` is treated as absent (revoke everything): only a
        // same-scope session id can preserve a session.
        let keep_text = keep
            .filter(|keep| keep.scope() == scope)
            .map(ToString::to_string);
        let emit = SessionEndedEmit::from_acting(env, &self.acting);
        let mut outcome = UserRevocation::default();
        let out = &mut outcome;
        write_audited_detailed(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::AccountPasswordChange,
                target: subject,
            },
            async move |tx| {
                // Write the new verifier. A subject that names no user flips no row,
                // which is a NotFound that rolls the whole audited write back (no
                // password change, no session revocation, no audit row).
                let updated = sqlx::query(
                    "UPDATE users SET password_hash = $1 \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
                )
                .bind(new_password_hash)
                .bind(&subject_text)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if updated.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                // Every OTHER live session of the user is revoked in this same
                // transaction. The keep session (the browser making the change) is
                // preserved. Each drives one session-ended cascade and one fan-out
                // event, exactly as an admin revoke does.
                *out = revoke_other_sessions_in_tx(
                    tx,
                    scope,
                    &subject_text,
                    keep_text.as_deref(),
                    SessionEndCause::PasswordChanged,
                    now_micros,
                    &emit,
                )
                .await?;
                Ok(())
            },
            false,
            Some(step_up_detail),
        )
        .await?;
        Ok(outcome)
    }
}

/// The sentinel `password_hash` stored for an admin-created user with no credential
/// (issue #52): not a valid Argon2id PHC string, so it never verifies against any
/// password. Such a user cannot log in until a real credential is set (and the login
/// fence rejects it anyway while it is pending verification).
const USER_UNUSABLE_PASSWORD_HASH: &str = "!";

/// An SSO session read back within scope (issue #20, extended by issue #32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// The authenticated end-user subject the tokens are minted for.
    pub subject: String,
    /// When the subject authenticated, in microseconds since the Unix epoch (the
    /// recorded authentication event's time; the ID token's `auth_time` derives
    /// from it).
    pub auth_time_unix_micros: i64,
    /// The recorded authentication method tokens (space-separated RFC 8176
    /// values, `pwd` for the bootstrap password login). The single source the ID
    /// token's `amr` and achieved `acr` are derived from (issue #14).
    pub auth_methods: String,
    /// The user agent the session was established from, recorded ONLY when the
    /// OFF-BY-DEFAULT device/user-agent binding knob is enabled (issue #32). The
    /// caller compares it against the presenting request when that knob is on.
    pub user_agent: Option<String>,
    /// The peer IP the session was established from, recorded ONLY when the
    /// OFF-BY-DEFAULT peer-IP binding knob is enabled (issue #32). The caller
    /// compares it against the presenting request when that knob is on.
    pub peer_ip: Option<String>,
}

/// The read-only bootstrap session repository (issue #20).
pub struct SessionRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl SessionRepo<'_> {
    /// Resolve a session by id within scope, returning [`None`] when it is absent,
    /// out of scope, revoked, rotated away (superseded), ended, or expired at
    /// `now_micros`.
    ///
    /// This is the milestone-defining read guard (issue #32): a revoked or rotated
    /// session MUST stop resolving IMMEDIATELY, so the query rejects a session whose
    /// `revoked_at`, `ended_at`, or `superseded_by` is set REGARDLESS of expiry. An
    /// expiry-only check could silently no-op a logout (the session would keep
    /// resolving until its lifetime elapsed); guarding on the revocation and rotation
    /// state closes that. Expiry is the idle timeout AND the absolute cap, both
    /// compared against the application clock seam (bound as epoch microseconds),
    /// never the database clock, so resolution is deterministic under a manual clock
    /// in tests. `COALESCE(absolute_expires_at, expires_at)` keeps a pre-#32 row
    /// (which set only `expires_at`) resolving correctly across the expand.
    ///
    /// # The idle window SLIDES on a successful resolve
    ///
    /// `idle_ttl_micros` is the configured idle window, and a successful resolve is
    /// exactly the evidence that the session is NOT idle, so this SLIDES it: it
    /// rewrites `idle_expires_at = now + idle_ttl` and stamps `last_seen_at`. Without
    /// the slide the "idle" timeout would be a second ABSOLUTE cap, killing a
    /// CONTINUOUSLY ACTIVE session at `idle_ttl`, which is neither what an idle timeout
    /// means nor what the setting documents.
    ///
    /// The write does NOT happen on every request (that would be pure hot-path write
    /// amplification: a busy session would write a row on every single resolve). It
    /// fires only once the session is past roughly HALF its idle window, so an active
    /// session writes at most about twice per window while still never expiring out
    /// from under an active user.
    ///
    /// The slide runs in the SAME transaction as the read and re-asserts the FULL
    /// liveness guard (`revoked_at` / `superseded_by` / `ended_at` all still NULL), so
    /// a session revoked concurrently can never be RESURRECTED by a slide. Time is the
    /// application clock seam throughout, never the database clock.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn get(
        &self,
        id: &SessionId,
        now_micros: i64,
        idle_ttl_micros: i64,
    ) -> Result<Option<SessionRecord>, StoreError> {
        if id.scope() != self.scope {
            return Ok(None);
        }
        let id_text = id.to_string();
        let tenant = self.scope.tenant().to_string();
        let environment = self.scope.environment().to_string();
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT subject, auth_methods, user_agent, peer_ip, \
             (EXTRACT(EPOCH FROM auth_time) * 1000000)::bigint AS auth_us, \
             (EXTRACT(EPOCH FROM idle_expires_at) * 1000000)::bigint AS idle_us \
             FROM sessions \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 \
             AND revoked_at IS NULL AND ended_at IS NULL AND superseded_by IS NULL \
             AND COALESCE(absolute_expires_at, expires_at) > \
                 TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
             AND (idle_expires_at IS NULL OR idle_expires_at > \
                  TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval)",
        )
        .bind(&id_text)
        .bind(&tenant)
        .bind(&environment)
        .bind(now_micros)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        // Slide the idle window, but only once the session is past roughly half of it.
        // A pre-#32 row (no idle window) and a non-positive configured window never
        // slide.
        let idle_us: Option<i64> = row.get("idle_us");
        // A let chain (if let ... && cond) would raise the MSRV above 1.85 (let chains
        // stabilized in 1.88), so the boolean guards stay nested inside the if let.
        let should_slide = matches!(idle_us, Some(idle_us)
            if idle_ttl_micros > 0
                && idle_us.saturating_sub(now_micros) < idle_ttl_micros / 2);
        if should_slide {
            sqlx::query(
                "UPDATE sessions \
                 SET idle_expires_at = TIMESTAMPTZ 'epoch' \
                         + (($1 + $2)::text || ' microseconds')::interval, \
                     last_seen_at = TIMESTAMPTZ 'epoch' \
                         + ($1::text || ' microseconds')::interval \
                 WHERE id = $3 AND tenant_id = $4 AND environment_id = $5 \
                 AND revoked_at IS NULL AND superseded_by IS NULL AND ended_at IS NULL",
            )
            .bind(now_micros)
            .bind(idle_ttl_micros)
            .bind(&id_text)
            .bind(&tenant)
            .bind(&environment)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(Some(SessionRecord {
            subject: row.get("subject"),
            auth_time_unix_micros: row.get("auth_us"),
            auth_methods: row.get("auth_methods"),
            user_agent: row.get("user_agent"),
            peer_ip: row.get("peer_ip"),
        }))
    }
}

/// The mutating bootstrap session repository (issue #20).
pub struct ActingSessionRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingSessionRepo<'_> {
    /// Rotate the SSO session identifier at a privilege transition (issue #32):
    /// create a fresh session for `subject` under a new unpredictable `id` and, in
    /// the SAME transaction, INVALIDATE the `prior` id so it stops resolving
    /// immediately (session-fixation defense, OWASP). The prior id is marked
    /// `superseded_by = id`, `ended_at`, and `end_cause = 'rotated'`, so the read
    /// guard in [`SessionRepo::get`] refuses it from the next request on.
    ///
    /// This ALSO carries the M4 session lifetime (the idle timeout and the absolute
    /// cap, both from the application clock seam) and the OFF-BY-DEFAULT binding
    /// metadata (`user_agent`, `peer_ip`). When `prior` is [`None`] (a first login,
    /// no prior cookie) this is a plain create; the audit action reflects that
    /// (`session.create` vs `session.rotate`), so a rotation is never mistaken for a
    /// creation in the audit trail.
    ///
    /// # What happens to the prior session's DEPENDENTS
    ///
    /// The prior session is not necessarily the rotating user's: a rotation happens at
    /// a privilege transition, so a login performed while presenting SOMEBODY ELSE's
    /// session cookie reaches this same path. The two cases MUST diverge, and the
    /// returned [`PriorSessionOutcome`] reports which one was taken:
    ///
    /// - **Same subject** (a re-authentication of the same human in the same browser):
    ///   the prior session's per-client sessions and refresh families are CARRIED
    ///   FORWARD onto the successor. Re-pointing them is what keeps the `sid` STABLE
    ///   across the re-authentication and, critically, keeps them REACHABLE: a
    ///   supersede that moved only the `sessions` row would ORPHAN them (they would
    ///   keep `session_ref = <prior>`, and no cascade on `session_ref = <successor>`
    ///   would ever reach them, so a later logout would not actually revoke the user's
    ///   refresh tokens from the earlier lineage segment).
    /// - **Different subject**: the prior session is TERMINALLY revoked with the full
    ///   cascade and NOTHING is carried, so the incoming user can never inherit the
    ///   outgoing user's refresh families or `sid`s. Re-pointing them unconditionally
    ///   would be a cross-user privilege escalation.
    ///
    /// A prior session that is already revoked, ended, or superseded is left alone
    /// ([`PriorSessionOutcome::None`]): whatever killed it already dealt with its
    /// dependents.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `id` is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn rotate(
        &self,
        env: &Env,
        id: &SessionId,
        prior: Option<&SessionId>,
        params: NewSession<'_>,
    ) -> Result<PriorSessionOutcome, StoreError> {
        self.rotate_inner(env, id, prior, params, false).await
    }

    /// Testing-only atomicity probe (issue #32): run a real `rotate` (the session
    /// insert, the prior-session invalidation, and the audit insert), then force a
    /// guaranteed error inside the SAME transaction, so a test can prove none of
    /// them survives. Always errors.
    ///
    /// # Errors
    ///
    /// Always errors (that is the point): the injected failure rolls the whole
    /// transaction back, so the data change and the audit row are proven joint.
    #[cfg(feature = "testing")]
    pub async fn rotate_injecting_post_audit_failure(
        &self,
        env: &Env,
        id: &SessionId,
        prior: Option<&SessionId>,
        params: NewSession<'_>,
    ) -> Result<PriorSessionOutcome, StoreError> {
        self.rotate_inner(env, id, prior, params, true).await
    }

    /// Shared body of the rotate path. `poison_after_audit` is always `false` for
    /// the public mutator; the testing-only atomicity probe passes `true`.
    async fn rotate_inner(
        &self,
        env: &Env,
        id: &SessionId,
        prior: Option<&SessionId>,
        params: NewSession<'_>,
        poison_after_audit: bool,
    ) -> Result<PriorSessionOutcome, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        // A prior id in ANOTHER scope is treated as absent (no cross-scope
        // supersede): only a same-scope prior session is rotated away.
        let prior = prior.filter(|prior| prior.scope() == scope);
        let prior_text = prior.map(ToString::to_string);
        // A rotation past a real prior session audits as session.rotate; a first
        // login (no prior) audits as session.create.
        let action = if prior_text.is_some() {
            Action::SessionRotate
        } else {
            Action::SessionCreate
        };
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut outcome = PriorSessionOutcome::None;
        let out = &mut outcome;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action,
                target: id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO sessions \
                     (id, tenant_id, environment_id, subject, auth_methods, auth_time, \
                      expires_at, idle_expires_at, absolute_expires_at, last_seen_at, \
                      user_agent, peer_ip) \
                     VALUES ($1, $2, $3, $4, $5, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($9::text || ' microseconds')::interval, \
                             $10, $11)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(params.subject)
                .bind(params.auth_methods)
                .bind(params.auth_time_micros)
                .bind(params.idle_expires_micros)
                .bind(params.absolute_expires_micros)
                .bind(now_micros)
                .bind(params.user_agent)
                .bind(params.peer_ip)
                .execute(&mut **tx)
                .await?;
                if let (Some(prior_id), Some(prior_text)) = (prior, &prior_text) {
                    *out = reconcile_prior_session_at_rotation(
                        PriorReconcile {
                            store: self.store,
                            acting: &self.acting,
                            env,
                            scope,
                            successor: id,
                            prior_id,
                            prior_text,
                            subject: params.subject,
                            now_micros,
                        },
                        tx,
                    )
                    .await?;
                }
                Ok(())
            },
            poison_after_audit,
        )
        .await?;
        Ok(outcome)
    }

    /// Revoke ONE SSO session by id (issue #32), stopping it from resolving
    /// immediately and cascading to its refresh-token families. The revoke sets
    /// `revoked_at`, `revoke_reason`, `ended_at`, and `end_cause` on the session, then
    /// revokes the session-bound (`offline = false`) refresh families it owns
    /// (PRESERVING the `offline_access` families, the #21 offline-survives-logout
    /// semantic) UNLESS `hard_kill` is set, in which case it ALSO revokes the offline
    /// families AND their grants so their access tokens die immediately. The session
    /// row, its per-client sessions, the family cascade, the audit row, and the
    /// optional idempotency record all commit in ONE transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `id` is out of this scope;
    /// [`StoreError::IdempotencyConflict`] if the idempotency key is already stored;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn revoke(
        &self,
        env: &Env,
        id: &SessionId,
        cause: SessionEndCause,
        hard_kill: bool,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<SessionRevocation, StoreError> {
        self.revoke_inner(
            env,
            id,
            RevokeSpec {
                cause,
                hard_kill,
                action: Action::SessionRevoke,
                idempotency,
                poison_after_audit: false,
            },
        )
        .await
    }

    /// Testing-only atomicity probe (issue #32): run a real `revoke` (the session
    /// flip, the family cascade, and the audit insert), then force a guaranteed error
    /// inside the SAME transaction, so a test can prove neither the revocation nor
    /// its audit row survives. Always errors.
    ///
    /// # Errors
    ///
    /// Always errors (that is the point): the injected failure rolls the whole
    /// transaction back, so the revocation and its audit row are proven joint.
    #[cfg(feature = "testing")]
    pub async fn revoke_injecting_post_audit_failure(
        &self,
        env: &Env,
        id: &SessionId,
        cause: SessionEndCause,
    ) -> Result<SessionRevocation, StoreError> {
        self.revoke_inner(
            env,
            id,
            RevokeSpec {
                cause,
                hard_kill: false,
                action: Action::SessionRevoke,
                idempotency: None,
                poison_after_audit: true,
            },
        )
        .await
    }

    /// Revoke a BATCH of SSO sessions by id (issue #32) in ONE transaction that
    /// carries ONE audit row PER session (`sessions.bulk_revoke`), returning how many
    /// sessions were flipped. Scope-fenced: an id in another scope is skipped as a
    /// uniform no-op, exactly like an absent one, so a bulk revoke can never reach
    /// another tenant's sessions. Each session's refresh-family cascade follows the
    /// same offline-preserving rule as [`ActingSessionRepo::revoke`].
    ///
    /// # Errors
    ///
    /// [`StoreError::IdempotencyConflict`] if the idempotency key is already stored;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn bulk_revoke(
        &self,
        env: &Env,
        ids: &[SessionId],
        hard_kill: bool,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<u64, StoreError> {
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        // ONE transaction: every session flip, every cascade, and every per-session
        // audit row commit together or not at all (a partially applied bulk revoke,
        // or a revocation whose audit row is missing, is not representable).
        let mut tx = begin_scoped(self.store, scope).await?;
        insert_idempotency(&mut tx, idempotency).await?;
        let mut flipped = 0_u64;
        for id in ids {
            // Scope-fence: a foreign-scope id is a uniform no-op (never a query).
            if id.scope() != scope {
                continue;
            }
            let outcome = revoke_session_in_tx(
                &mut tx,
                scope,
                id,
                SessionEndCause::BulkRevoked,
                now_micros,
                hard_kill,
                &SessionEndedEmit::from_acting(env, &self.acting),
            )
            .await?;
            if outcome.session_flipped {
                flipped += 1;
            }
            // One audit row per session, so the trail names every revoked session
            // individually rather than reporting an opaque batch.
            insert_audit_row(
                &mut tx,
                &AuditedWrite {
                    store: self.store,
                    scope,
                    acting: &self.acting,
                    env,
                    action: Action::SessionsBulkRevoke,
                    target: id,
                },
                None,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(flipped)
    }

    /// Revoke EVERY session of one user and cascade to their refresh-token families
    /// (issue #32), in ONE audited transaction (`user.sessions.revoke_all`). All of
    /// the user's live sessions are revoked, then the user's session-bound
    /// (`offline = false`) refresh families are revoked (PRESERVING the
    /// `offline_access` families) UNLESS `hard_kill` is set, in which case ALL of the
    /// user's families AND their grants are revoked so every access token dies
    /// immediately. Returns how many sessions and families were flipped.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `subject` is out of this scope;
    /// [`StoreError::IdempotencyConflict`] if the idempotency key is already stored;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn revoke_all_for_user(
        &self,
        env: &Env,
        subject: &UserId,
        hard_kill: bool,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<UserRevocation, StoreError> {
        if subject.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let subject_text = subject.to_string();
        let mut outcome = UserRevocation::default();
        let out = &mut outcome;
        // The session-ended fan-out attributes every one of the user's ended sessions to
        // the SAME actor and request the revoke-all audit row carries (issue #35).
        let emit = SessionEndedEmit::from_acting(env, &self.acting);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::UserSessionsRevokeAll,
                target: subject,
            },
            async move |tx| {
                insert_idempotency(tx, idempotency).await?;
                // RETURNING id hands back EVERY session that actually flipped (an
                // already-ended one returns no row), so exactly one durable session-ended
                // event is enqueued per terminal end (issue #35) and the same ids are
                // handed to the Global Token Revocation receiver (issue #36), below, in
                // this same transaction.
                let revoked = sqlx::query(
                    "UPDATE sessions \
                     SET revoked_at = \
                             TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
                         revoke_reason = 'user_revoked_all', \
                         ended_at = \
                             TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
                         end_cause = 'user_revoked_all' \
                     WHERE subject = $2 AND tenant_id = $3 AND environment_id = $4 \
                     AND revoked_at IS NULL AND ended_at IS NULL \
                     RETURNING id",
                )
                .bind(now_micros)
                .bind(&subject_text)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .fetch_all(&mut **tx)
                .await?;
                out.revoked_session_ids = revoked
                    .iter()
                    .map(|row| row.get::<String, _>("id"))
                    .collect();
                out.sessions_revoked = out.revoked_session_ids.len() as u64;
                for row in &revoked {
                    let session_text: String = row.get("id");
                    enqueue_session_ended_event(
                        tx,
                        &emit,
                        scope,
                        &session_text,
                        &subject_text,
                        SessionEndCause::UserRevokedAll,
                        now_micros,
                    )
                    .await?;
                }
                // The per-client sessions (the sid tier) of every one of the user's
                // sessions end with them, in this same transaction.
                sqlx::query(
                    "UPDATE client_sessions cs \
                     SET revoked_at = \
                             TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
                         revoke_reason = 'user_revoked_all' \
                     WHERE cs.tenant_id = $3 AND cs.environment_id = $4 \
                     AND cs.revoked_at IS NULL \
                     AND EXISTS (SELECT 1 FROM sessions s \
                                 WHERE s.id = cs.session_id AND s.tenant_id = cs.tenant_id \
                                 AND s.environment_id = cs.environment_id AND s.subject = $2)",
                )
                .bind(now_micros)
                .bind(&subject_text)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                cascade_families_for_subject(tx, scope, &subject_text, now_micros, hard_kill, out)
                    .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(outcome)
    }

    /// REVOKE one of the acting user's OWN sessions at the self-service account
    /// surface (issue #61). The revoke is SUBJECT-BOUND in SQL: the session is only
    /// ended when it belongs to `subject`, so a session id of ANOTHER user (even
    /// within the same tenant) is a uniform no-op and is never revoked (defense in
    /// depth behind the surface's own ownership check). A revoked session stops
    /// resolving immediately and cascades through the unified session-ended fan-out
    /// (issue #35) EXACTLY as an admin revoke does; the mutation is audited as
    /// `account.session.revoke` targeting the session and attributed to the end user.
    /// A no-op (foreign or absent session) writes nothing.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `id` or `subject` is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn self_revoke(
        &self,
        env: &Env,
        subject: &UserId,
        id: &SessionId,
    ) -> Result<SessionRevocation, StoreError> {
        if id.scope() != self.scope || subject.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, scope).await?;
        // Subject-bound ownership: only the acting user's OWN session is ended. A
        // session's subject is immutable, so this read-then-act is race free.
        let owns = sqlx::query(
            "SELECT 1 FROM sessions \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND subject = $4",
        )
        .bind(id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(subject.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        if owns.is_none() {
            // A foreign or absent session: a uniform no-op that writes nothing (no
            // revocation, no audit row).
            tx.commit().await?;
            return Ok(SessionRevocation::default());
        }
        let outcome = revoke_session_in_tx(
            &mut tx,
            scope,
            id,
            SessionEndCause::Revoked,
            now_micros,
            false,
            &SessionEndedEmit::from_acting(env, &self.acting),
        )
        .await?;
        insert_audit_row(
            &mut tx,
            &AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::AccountSessionRevoke,
                target: id,
            },
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(outcome)
    }

    /// REVOKE all of the acting user's OTHER sessions at the self-service account
    /// surface (issue #61): the "sign out everywhere else" action. Every live session
    /// of `subject` EXCEPT `keep` (the one making the request) is ended, cascading
    /// each through the unified session-ended fan-out (issue #35). One
    /// `account.sessions.revoke_others` audit row targets the user and is attributed
    /// to the end user; `step_up_detail` records the operator-safe step-up policy the
    /// sensitive change declared. Pass [`None`] for `keep` to end EVERY session.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `subject` is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn self_revoke_others(
        &self,
        env: &Env,
        subject: &UserId,
        keep: Option<&SessionId>,
        step_up_detail: &str,
    ) -> Result<UserRevocation, StoreError> {
        if subject.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let subject_text = subject.to_string();
        let keep_text = keep
            .filter(|keep| keep.scope() == scope)
            .map(ToString::to_string);
        let emit = SessionEndedEmit::from_acting(env, &self.acting);
        let mut outcome = UserRevocation::default();
        let out = &mut outcome;
        write_audited_detailed(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::AccountSessionsRevokeOthers,
                target: subject,
            },
            async move |tx| {
                *out = revoke_other_sessions_in_tx(
                    tx,
                    scope,
                    &subject_text,
                    keep_text.as_deref(),
                    SessionEndCause::Revoked,
                    now_micros,
                    &emit,
                )
                .await?;
                Ok(())
            },
            false,
            Some(step_up_detail),
        )
        .await?;
        Ok(outcome)
    }

    /// Shared body of the single-session revoke path: the data change, the family
    /// cascade, the optional idempotency record, and the audit row in ONE
    /// transaction. `spec.poison_after_audit` is `false` on every production path.
    async fn revoke_inner(
        &self,
        env: &Env,
        id: &SessionId,
        spec: RevokeSpec<'_>,
    ) -> Result<SessionRevocation, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let RevokeSpec {
            cause,
            hard_kill,
            action,
            idempotency,
            poison_after_audit,
        } = spec;
        let mut outcome = SessionRevocation::default();
        let out = &mut outcome;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action,
                target: id,
            },
            async move |tx| {
                insert_idempotency(tx, idempotency).await?;
                *out = revoke_session_in_tx(
                    tx,
                    scope,
                    id,
                    cause,
                    now_micros,
                    hard_kill,
                    &SessionEndedEmit::from_acting(env, &self.acting),
                )
                .await?;
                Ok(())
            },
            poison_after_audit,
        )
        .await?;
        Ok(outcome)
    }
}

/// The inputs the rotation's prior-session reconciliation needs (issue #32), bundled so
/// the helper stays inside the readable-argument-count lint.
struct PriorReconcile<'a> {
    /// The store, for the terminal-branch audit row.
    store: &'a Store,
    /// The acting context, for the terminal-branch audit row.
    acting: &'a ActingContext,
    /// The environment (clock/entropy seam), for the terminal-branch audit row.
    env: &'a Env,
    /// The rotation scope.
    scope: Scope,
    /// The successor session the rotation is creating (the carry target).
    successor: &'a SessionId,
    /// The prior session presented at the rotation.
    prior_id: &'a SessionId,
    /// The prior session id as text (already stringified once).
    prior_text: &'a str,
    /// The subject the successor authenticates (the carry-vs-terminate discriminator).
    subject: &'a str,
    /// The rotation instant, in epoch microseconds.
    now_micros: i64,
}

/// Lock a SESSION-BOUND family's bound session LIVE inside `tx`, to serialize a
/// concurrent refresh-family open against a session revoke (issue #32).
///
/// Reads the grant's `session_ref`; for a session-bound grant it takes SELECT ... FOR
/// UPDATE on that session under the SAME live predicate the auth read path and the
/// family-open INSERT guard apply, and reports whether the session is live under that
/// lock. The caller opens the family only when this returns `true`; on `false` it must
/// refuse with [`RefreshFamilyOpenOutcome::SessionNotLive`], writing nothing.
///
/// Why the lock, not just the INSERT's EXISTS guard: [`begin_scoped`] pins READ
/// COMMITTED, and that EXISTS takes NO lock, so under true concurrency the open's
/// snapshot can still see a session a concurrent revoke is mid-flight on and insert the
/// family, while the revoke's cascade `UPDATE refresh_families` cannot see the open's
/// still-uncommitted family row and misses it. Both commit and a family is left bound
/// to a now-dead session with its own `revoked_at` NULL, which redeem would then mint
/// fresh tokens off after logout. The FOR UPDATE (exactly as
/// [`reconcile_prior_session_at_rotation`] does, and against the SAME
/// `revoke_session_in_tx` `UPDATE sessions`, which locks the row) forces one of two
/// safe orderings: (a) this open locks first, the revoke blocks until the open commits,
/// and the cascade THEN sees and revokes the just-opened family; or (b) the revoke
/// locks and commits first, this FOR UPDATE re-reads the latest row under READ
/// COMMITTED (`EvalPlanQual`), the live predicate now fails, zero rows, and the open
/// refuses. A grant with no session (`session_ref` NULL) is not session-bound and is
/// not locked; the caller skips an offline family entirely (it survives logout, #21).
async fn lock_bound_session_live(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    grant_id: &GrantId,
    now_micros: i64,
) -> Result<bool, StoreError> {
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let Some(grant_row) = sqlx::query(
        "SELECT session_ref FROM grants \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(grant_id.to_string())
    .bind(&tenant)
    .bind(&environment)
    .fetch_optional(&mut **tx)
    .await?
    else {
        // The grant vanished; the INSERT ... SELECT guard finds nothing and refuses.
        return Ok(true);
    };
    let session_ref: Option<String> = grant_row.get("session_ref");
    let Some(session_ref) = session_ref else {
        // Not session-bound: open unconditionally.
        return Ok(true);
    };
    let locked = sqlx::query(
        "SELECT 1 FROM sessions \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 \
         AND revoked_at IS NULL AND ended_at IS NULL AND superseded_by IS NULL \
         AND COALESCE(absolute_expires_at, expires_at) > \
             TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
         AND (idle_expires_at IS NULL OR idle_expires_at > \
              TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval) \
         FOR UPDATE",
    )
    .bind(&session_ref)
    .bind(&tenant)
    .bind(&environment)
    .bind(now_micros)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(locked.is_some())
}

/// Reconcile the PRIOR session at a rotation, inside the open rotation transaction
/// (issue #32), and report what happened to it.
///
/// A rotation happens at a privilege transition, and the prior session is not
/// necessarily the rotating user's. This decides between the two mandatory, opposite
/// behaviors and NEVER conflates them:
///
/// - the prior session is not live any more -> [`PriorSessionOutcome::None`] (whatever
///   killed it already dealt with its dependents);
/// - it belongs to the SAME subject -> supersede it and CARRY its per-client sessions
///   and refresh families onto the successor, so the `sid` stays stable and nothing is
///   orphaned ([`PriorSessionOutcome::Carried`]);
/// - it belongs to a DIFFERENT subject -> TERMINALLY revoke it with the full cascade and
///   carry NOTHING, so the incoming user inherits none of the outgoing user's tokens or
///   sids ([`PriorSessionOutcome::RevokedForeignSubject`]). Carrying here would be a
///   cross-user privilege escalation.
async fn reconcile_prior_session_at_rotation(
    args: PriorReconcile<'_>,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<PriorSessionOutcome, StoreError> {
    let PriorReconcile {
        store,
        acting,
        env,
        scope,
        successor,
        prior_id,
        prior_text,
        subject,
        now_micros,
    } = args;
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    // Classify the prior session under a row lock, and only if it is still LIVE.
    let prior_row = sqlx::query(
        "SELECT subject FROM sessions \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 \
         AND revoked_at IS NULL AND superseded_by IS NULL AND ended_at IS NULL \
         FOR UPDATE",
    )
    .bind(prior_text)
    .bind(&tenant)
    .bind(&environment)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(prior_row) = prior_row else {
        return Ok(PriorSessionOutcome::None);
    };
    let prior_subject: String = prior_row.get("subject");
    let successor_text = successor.to_string();

    if prior_subject != subject {
        // DIFFERENT subject: a login while presenting somebody else's cookie. Terminally
        // revoke the prior session with the full cascade and carry NOTHING (offline
        // families survive, the #21 semantic: another human logging in must not kill the
        // first user's background access). Carrying would be a cross-user escalation.
        revoke_session_in_tx(
            tx,
            scope,
            prior_id,
            SessionEndCause::ReplacedByOtherSubject,
            now_micros,
            false,
            &SessionEndedEmit::from_acting(env, acting),
        )
        .await?;
        // NAME the terminally revoked session in the trail: the rotation's own audit row
        // targets the successor, so without this the revocation would be invisible.
        insert_audit_row(
            tx,
            &AuditedWrite {
                store,
                scope,
                acting,
                env,
                action: Action::SessionRevoke,
                target: prior_id,
            },
            None,
        )
        .await?;
        return Ok(PriorSessionOutcome::RevokedForeignSubject);
    }

    // SAME subject: a re-authentication of the same human in the same browser. Supersede
    // the prior id (it stops resolving at once, the session-fixation defense) and CARRY
    // its lineage onto the successor.
    sqlx::query(
        "UPDATE sessions \
         SET superseded_by = $1, \
             ended_at = TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval, \
             end_cause = 'rotated' \
         WHERE id = $3 AND tenant_id = $4 AND environment_id = $5 \
         AND revoked_at IS NULL AND superseded_by IS NULL AND ended_at IS NULL",
    )
    .bind(&successor_text)
    .bind(now_micros)
    .bind(prior_text)
    .bind(&tenant)
    .bind(&environment)
    .execute(&mut **tx)
    .await?;
    // The per-client sessions move to the successor, so the `sid` is STABLE across the
    // re-authentication (the OIDC sid contract) and a later revoke still ends them.
    sqlx::query(
        "UPDATE client_sessions \
         SET session_id = $1 \
         WHERE session_id = $2 AND tenant_id = $3 AND environment_id = $4 \
         AND revoked_at IS NULL",
    )
    .bind(&successor_text)
    .bind(prior_text)
    .bind(&tenant)
    .bind(&environment)
    .execute(&mut **tx)
    .await?;
    // The refresh families move with them, so a later revoke or logout of the successor
    // CASCADES to the families the pre-rotation lineage opened. Without this the rotation
    // ORPHANS them (they keep session_ref = <prior>, no cascade on <successor> reaches
    // them, and the user's earlier-segment refresh tokens stay valid forever).
    sqlx::query(
        "UPDATE refresh_families \
         SET session_ref = $1 \
         WHERE session_ref = $2 AND tenant_id = $3 AND environment_id = $4 \
         AND revoked_at IS NULL",
    )
    .bind(&successor_text)
    .bind(prior_text)
    .bind(&tenant)
    .bind(&environment)
    .execute(&mut **tx)
    .await?;
    Ok(PriorSessionOutcome::Carried)
}

/// What one single-session revoke does, bundled so the shared body stays inside the
/// readable-argument-count lint (issue #32).
struct RevokeSpec<'a> {
    /// Why the session is ending (recorded in `end_cause`).
    cause: SessionEndCause,
    /// Whether to also revoke the `offline_access` families and their grants.
    hard_kill: bool,
    /// The audit action (a stand-alone revoke vs one item of a bulk revoke).
    action: Action,
    /// The optional Idempotency-Key record, written in the same transaction.
    idempotency: Option<IdempotencyWrite<'a>>,
    /// Testing seam only: force a failure after both inserts, to prove they roll back
    /// together. Always `false` on the production paths.
    poison_after_audit: bool,
}

/// Revoke ONE session inside an OPEN transaction (issue #32): flip the session
/// itself, end its per-client sessions (so per-client back-channel targeting sees
/// them ended too), then cascade to the session's refresh families (offline
/// preserving unless `hard_kill`). Shared by the single-session revoke and the bulk
/// revoke, so both cascades are the same cascade.
async fn revoke_session_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: &SessionId,
    cause: SessionEndCause,
    now_micros: i64,
    hard_kill: bool,
    emit: &SessionEndedEmit<'_>,
) -> Result<SessionRevocation, StoreError> {
    let session_text = id.to_string();
    let cause_str = cause.as_str();
    let mut outcome = SessionRevocation::default();
    // The session itself stops resolving IMMEDIATELY (the read guard rejects a
    // revoked row regardless of expiry, so this can never silently no-op). The
    // RETURNING clause hands back the ended session's subject ONLY when the row
    // actually flipped (a foreign, absent, or already-ended session returns no row),
    // so the session-ended fan-out is driven off the exact same guarded flip: an event
    // is enqueued for a TERMINAL end and never for a no-op.
    let flipped_row = sqlx::query(
        "UPDATE sessions \
         SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
             revoke_reason = $5, \
             ended_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
             end_cause = $5 \
         WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
         AND revoked_at IS NULL AND ended_at IS NULL \
         RETURNING subject",
    )
    .bind(now_micros)
    .bind(&session_text)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(cause_str)
    .fetch_optional(&mut **tx)
    .await?;
    outcome.session_flipped = flipped_row.is_some();
    // The durable session-ended event (issue #35): enqueued in THIS transaction, so it
    // commits with the revocation or not at all (never emitted for a rolled-back
    // revoke, never lost for a committed one). Only on a real terminal flip, so a
    // rotation (which never reaches this function) and a no-op revoke enqueue nothing.
    if let Some(row) = flipped_row {
        let subject: String = row.get("subject");
        enqueue_session_ended_event(tx, emit, scope, &session_text, &subject, cause, now_micros)
            .await?;
    }
    // The per-client sessions (the sid tier) end with their SSO session.
    sqlx::query(
        "UPDATE client_sessions \
         SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
             revoke_reason = $5 \
         WHERE session_id = $2 AND tenant_id = $3 AND environment_id = $4 \
         AND revoked_at IS NULL",
    )
    .bind(now_micros)
    .bind(&session_text)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(cause_str)
    .execute(&mut **tx)
    .await?;
    // Cascade to this session's refresh families: the session-bound families always,
    // the `offline_access` families ONLY on an explicit hard kill (the #21
    // offline-survives-logout semantic, reused here rather than reinvented).
    let families = sqlx::query(
        "UPDATE refresh_families \
         SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
         WHERE session_ref = $2 AND tenant_id = $3 AND environment_id = $4 \
         AND revoked_at IS NULL AND ($5 OR offline = false)",
    )
    .bind(now_micros)
    .bind(&session_text)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(hard_kill)
    .execute(&mut **tx)
    .await?;
    outcome.families_revoked = families.rows_affected();
    if hard_kill {
        // A hard kill also revokes the grants behind this session's families, so the
        // already-issued access tokens (which derive their active state from
        // grants.revoked_at) die immediately, the offline ones included.
        sqlx::query(
            "UPDATE grants \
             SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE tenant_id = $3 AND environment_id = $4 AND revoked_at IS NULL \
             AND id IN (SELECT grant_id FROM refresh_families \
                        WHERE session_ref = $2 AND tenant_id = $3 \
                        AND environment_id = $4)",
        )
        .bind(now_micros)
        .bind(&session_text)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut **tx)
        .await?;
    }
    Ok(outcome)
}

/// The acting context the session-ended fan-out enqueue needs (issue #35): the
/// clock/entropy seam (for the event id and its instant) and the SAME actor and
/// correlation the revocation's audit row carries, so a drained event attributes the
/// end to exactly the principal and request the audit trail does. Bundled so
/// [`revoke_session_in_tx`] stays inside the readable-argument-count lint.
struct SessionEndedEmit<'a> {
    /// The clock/entropy seam: the event id draws from entropy, its instant from the
    /// clock (never a direct process read), so the fan-out is deterministic under test.
    env: &'a Env,
    /// The principal that caused the end (the audit row's actor).
    actor: ActorRef,
    /// The request the end belongs to (the audit row's correlation id).
    correlation: CorrelationId,
}

impl<'a> SessionEndedEmit<'a> {
    /// Build the emit context from the acting context of the surrounding audited
    /// revocation, so the event and the audit row name the same actor and request.
    fn from_acting(env: &'a Env, acting: &ActingContext) -> Self {
        Self {
            env,
            actor: acting.actor(),
            correlation: acting.correlation(),
        }
    }
}

/// Enqueue ONE durable session-ended event into the outbox inside the OPEN revocation
/// transaction (issue #35), so it commits with the session flip or not at all (the
/// transactional-outbox guarantee: never emitted for a rolled-back revoke, never lost
/// for a committed one). Called ONLY on a real terminal flip, so a rotation and a
/// no-op revoke enqueue nothing. The row's `id` is the idempotency key a consumer
/// dedups redelivery on; `sequence`, `claimed_at`, and `delivered_at` are assigned or
/// set later by the drain, never here.
async fn enqueue_session_ended_event(
    tx: &mut Transaction<'_, Postgres>,
    emit: &SessionEndedEmit<'_>,
    scope: Scope,
    session_text: &str,
    subject: &str,
    cause: SessionEndCause,
    occurred_micros: i64,
) -> Result<(), StoreError> {
    let event_id = SessionEventId::generate(emit.env, &scope);
    let actor = emit.actor;
    sqlx::query(
        "INSERT INTO session_ended_events \
         (id, tenant_id, environment_id, session_id, subject, cause, \
          actor_kind, actor_id, correlation_id, occurred_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval)",
    )
    .bind(event_id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(session_text)
    .bind(subject)
    .bind(cause.as_str())
    .bind(actor.kind_str())
    .bind(actor.id_string())
    .bind(emit.correlation.to_string())
    .bind(occurred_micros)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A drained session-ended event (issue #35): the STABLE typed contract a consumer
/// receives off the outbox. It names WHAT ended (never any bearer secret): the scope,
/// the ended SSO session, the user, the terminal cause, the principal that caused it,
/// the request it belongs to, and the instant it ended, plus the monotonic drain
/// `sequence`. The affected (client, session) pairs are NOT denormalized here: they
/// were ended in the same transaction, so a consumer resolves the per-client `sid`s to
/// target by joining `client_sessions` on `session_id` at delivery time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEndedEvent {
    /// The outbox event id (an `sev_` id): the IDEMPOTENCY KEY a consumer dedups on.
    pub id: String,
    /// The monotonic drain-order key the database assigned. It is a best-effort
    /// ordering HINT that sorts the visible undelivered tail, NOT a safe high-water-mark:
    /// under concurrent producers a lower `sequence` can commit after a higher one, so a
    /// consumer must not treat a drained `sequence` as a mark to skip past. Delivery is
    /// at-least-once per row; consumers dedup on `id`.
    pub sequence: i64,
    /// The SSO session (a `ses_` id) that terminally ended.
    pub session_id: String,
    /// The user (a `usr_` id) whose session ended.
    pub subject: String,
    /// The terminal end cause. Never a rotation (a rotation is not a session end).
    pub cause: SessionEndCause,
    /// The principal that caused the end (the audit envelope's actor).
    pub actor: ActorRef,
    /// The request the end belongs to (a `req_` correlation id).
    pub correlation_id: String,
    /// When the session ended, in microseconds since the Unix epoch (clock seam).
    pub occurred_at_unix_micros: i64,
}

/// The columns every outbox read selects, in one place so the claim and the pending
/// read return the identical shape. `sequence` is the drain order; the `occurred_us`
/// projection reconstructs the exact microsecond instant (PostgreSQL 14+ returns a
/// numeric `EXTRACT(EPOCH ...)`, so this is exact on the supported deployment).
const SESSION_EVENT_COLUMNS: &str = "id, sequence, session_id, subject, cause, \
     actor_kind, actor_id, correlation_id, \
     (EXTRACT(EPOCH FROM occurred_at) * 1000000)::bigint AS occurred_us";

/// Reconstruct a [`SessionEndedEvent`] from a selected outbox row. A row whose stored
/// cause or actor does not decode is a corrupt or forward-versioned row; it surfaces
/// as a [`StoreError::Database`] rather than a panic.
fn session_event_from_row(row: &PgRow) -> Result<SessionEndedEvent, StoreError> {
    let cause_str: String = row.get("cause");
    let cause = SessionEndCause::from_wire(&cause_str).ok_or_else(|| {
        StoreError::Database(sqlx::Error::Decode(
            format!("session_ended_events row carries an unknown cause: {cause_str}").into(),
        ))
    })?;
    let actor_kind: String = row.get("actor_kind");
    let actor_id: String = row.get("actor_id");
    let actor = ActorRef::from_parts(&actor_kind, &actor_id)
        .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
    Ok(SessionEndedEvent {
        id: row.get("id"),
        sequence: row.get("sequence"),
        session_id: row.get("session_id"),
        subject: row.get("subject"),
        cause,
        actor,
        correlation_id: row.get("correlation_id"),
        occurred_at_unix_micros: row.get("occurred_us"),
    })
}

/// The session-ended outbox drain (issue #35): the seam the back-channel logout worker
/// (#34) and the external webhooks (M11) consume off. It is a plain (unaudited) scoped
/// repository, like the device-code poll: draining is high-frequency bookkeeping, not
/// an audited business event, and the durable record of the end is the outbox row and
/// its audit sibling, both written when the session flipped.
///
/// Delivery is AT-LEAST-ONCE. [`claim`](SessionEventOutboxRepo::claim) atomically leases
/// a batch of undelivered events (stamping `claimed_at`, skipping rows another worker
/// holds), the consumer acts idempotently, then [`mark_delivered`](SessionEventOutboxRepo::mark_delivered)
/// sets `delivered_at`. A consumer that crashes after acting but before marking sees the
/// event again once its lease lapses, so consumers MUST dedup on the event `id`.
pub struct SessionEventOutboxRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl SessionEventOutboxRepo<'_> {
    /// Atomically CLAIM up to `limit` undelivered session-ended events in this scope,
    /// oldest first, stamping each with a visibility lease that expires `lease` from
    /// now (issue #35). A row another worker holds an unexpired lease on is SKIPPED, so
    /// two workers never claim the same event concurrently; a crashed worker's row
    /// reappears once its lease lapses (at-least-once). `SELECT ... FOR UPDATE SKIP
    /// LOCKED` inside the same statement takes the row locks, so concurrent claimers
    /// never block on each other.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault or an undecodable stored row.
    pub async fn claim(
        &self,
        env: &Env,
        lease: Duration,
        limit: i64,
    ) -> Result<Vec<SessionEndedEvent>, StoreError> {
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let lease_micros = i64::try_from(lease.as_micros()).unwrap_or(i64::MAX);
        // A row is claimable when it is undelivered AND (never claimed OR its lease has
        // lapsed). The outer UPDATE stamps a fresh lease start (`claimed_at = now`); the
        // lease expiry is `claimed_at + lease`, so the reappear condition is
        // `claimed_at < now - lease`, expressed as `claimed_at`'s microseconds below.
        let sql = format!(
            "UPDATE session_ended_events \
             SET claimed_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id IN ( \
                 SELECT id FROM session_ended_events \
                 WHERE tenant_id = $2 AND environment_id = $3 \
                 AND delivered_at IS NULL \
                 AND (claimed_at IS NULL \
                      OR claimed_at < TIMESTAMPTZ 'epoch' \
                         + (($1::bigint - $4)::text || ' microseconds')::interval) \
                 ORDER BY sequence \
                 LIMIT $5 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING {SESSION_EVENT_COLUMNS}"
        );
        let mut tx = begin_scoped(self.store, scope).await?;
        let rows = sqlx::query(&sql)
            .bind(now_micros)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(lease_micros)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        rows.iter().map(session_event_from_row).collect()
    }

    /// Read up to `limit` undelivered session-ended events in this scope, oldest first,
    /// WITHOUT claiming them (issue #35): a read-only peek at the pending tail for
    /// diagnostics and tests. Draining a real consumer goes through
    /// [`claim`](SessionEventOutboxRepo::claim) so the lease and skip-locked semantics apply.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault or an undecodable stored row.
    pub async fn pending(&self, limit: i64) -> Result<Vec<SessionEndedEvent>, StoreError> {
        let scope = self.scope;
        let sql = format!(
            "SELECT {SESSION_EVENT_COLUMNS} FROM session_ended_events \
             WHERE tenant_id = $1 AND environment_id = $2 AND delivered_at IS NULL \
             ORDER BY sequence LIMIT $3"
        );
        let mut tx = begin_scoped(self.store, scope).await?;
        let rows = sqlx::query(&sql)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        rows.iter().map(session_event_from_row).collect()
    }

    /// Mark ONE claimed session-ended event DELIVERED by its `id` (issue #35), so it
    /// never drains again. Idempotent: it flips `delivered_at` only while it is still
    /// NULL, so a double mark (or a mark racing a re-claim after a lapsed lease) sets it
    /// once and reports `false` the second time. A foreign-scope or malformed id is a
    /// uniform no-op (`false`), never an oracle. A column-scoped UPDATE of
    /// `delivered_at` alone, the only mutation a consumer is granted (never a
    /// table-wide UPDATE, the #31 lesson). Returns whether THIS call flipped it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault.
    pub async fn mark_delivered(&self, env: &Env, id: &str) -> Result<bool, StoreError> {
        let scope = self.scope;
        // A malformed or foreign-scope id resolves to a uniform no-op (the anti-oracle
        // boundary), never a query against another tenant's row.
        let Ok(event_id) = SessionEventId::parse_in_scope(id, &scope) else {
            return Ok(false);
        };
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, scope).await?;
        let flipped = sqlx::query(
            "UPDATE session_ended_events \
             SET delivered_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
             AND delivered_at IS NULL",
        )
        .bind(now_micros)
        .bind(event_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(flipped.rows_affected() > 0)
    }
}

/// One per-RP back-channel-logout delivery row (issue #34): the typed contract the
/// worker drains off the delivery queue. It names WHAT to deliver to WHICH relying
/// party (never any bearer secret): the outbox event it was exploded from, the ended
/// SSO session, the target client, THAT client's own `sid` (never another client's),
/// and the RP's registered `logout_uri`, plus the retry state (attempts, last error,
/// and the two terminal markers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutDelivery {
    /// The delivery id (a `bld_` id).
    pub id: String,
    /// The `sev_` session-ended outbox event this delivery was exploded from.
    pub event_id: String,
    /// The SSO session (a `ses_` id) that ended.
    pub session_id: String,
    /// The participating client this token targets.
    pub client_id: String,
    /// The per-(client, session) `sid` THIS client's logout token carries.
    pub sid: String,
    /// The RP's registered `backchannel_logout_uri`, snapshotted at explode time.
    pub logout_uri: String,
    /// The Logout Token `jti`, assigned once at explode time and reused across every
    /// delivery attempt of this row, so a retry re-POSTs the SAME token and the RP dedups
    /// on it.
    pub jti: String,
    /// The number of delivery attempts made so far.
    pub attempts: i32,
    /// The most recent failure reason, if any attempt has failed.
    pub last_error: Option<String>,
    /// When the delivery succeeded (a 2xx), if it did, in epoch microseconds.
    pub delivered_at_unix_micros: Option<i64>,
    /// When the delivery was given up on (the attempts cap), if it was, in epoch
    /// microseconds.
    pub dead_lettered_at_unix_micros: Option<i64>,
}

/// The columns every delivery read selects, in one place so the claim, the pending peek,
/// and the full listing return the identical shape.
const LOGOUT_DELIVERY_COLUMNS: &str = "id, event_id, session_id, client_id, sid, \
     logout_uri, jti, attempts, last_error, \
     (EXTRACT(EPOCH FROM delivered_at) * 1000000)::bigint AS delivered_us, \
     (EXTRACT(EPOCH FROM dead_lettered_at) * 1000000)::bigint AS dead_us";

/// Reconstruct a [`LogoutDelivery`] from a selected row.
fn logout_delivery_from_row(row: &PgRow) -> LogoutDelivery {
    LogoutDelivery {
        id: row.get("id"),
        event_id: row.get("event_id"),
        session_id: row.get("session_id"),
        client_id: row.get("client_id"),
        sid: row.get("sid"),
        logout_uri: row.get("logout_uri"),
        jti: row.get("jti"),
        attempts: row.get("attempts"),
        last_error: row.get("last_error"),
        delivered_at_unix_micros: row.get("delivered_us"),
        dead_lettered_at_unix_micros: row.get("dead_us"),
    }
}

/// The per-RP back-channel-logout delivery queue (issue #34): the at-least-once work
/// queue the delivery worker drains, keyed to one scope.
///
/// A drained session-ended event (issue #35) is EXPLODED into one row per participating
/// relying party (a client that registered a `backchannel_logout_uri`), each carrying
/// that client's OWN `sid`. [`claim_due`](BackChannelDeliveryRepo::claim_due) leases a
/// batch of due, not-yet-terminal rows (`FOR UPDATE SKIP LOCKED`, so multiple workers
/// are safe), the worker POSTs each token, then either
/// [`mark_delivered`](BackChannelDeliveryRepo::mark_delivered) on a 2xx or
/// [`record_failure`](BackChannelDeliveryRepo::record_failure) to schedule a bounded
/// backoff retry or dead-letter it once the attempts cap is reached.
pub struct BackChannelDeliveryRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl BackChannelDeliveryRepo<'_> {
    /// EXPLODE one drained session-ended `event_id` (for the ended `session_id`) into one
    /// delivery row per participating relying party (issue #34), returning how many NEW
    /// rows were queued.
    ///
    /// A participating RP is a client with a per-client session for `session_id` (so it
    /// had an active login) that ALSO registered a non-empty `backchannel_logout_uri`.
    /// Each row snapshots that client's OWN `sid` (never another client's) and its
    /// `logout_uri`, and becomes immediately due (`next_attempt_at = now`). The insert is
    /// idempotent per (event, client) via the unique key, so re-exploding a redelivered
    /// outbox event queues nothing new (at-least-once delivery, dedup by the RP on `jti`).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault.
    pub async fn enqueue_for_event(
        &self,
        env: &Env,
        event_id: &str,
        session_id: &str,
    ) -> Result<u64, StoreError> {
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let tenant = scope.tenant().to_string();
        let environment = scope.environment().to_string();
        let mut tx = begin_scoped(self.store, scope).await?;
        // The participating RPs: a per-client session for this SSO session whose client
        // registered a back-channel logout URI. The per-client session may itself be
        // revoked by the session-end cascade; that is exactly WHY we notify, so no
        // liveness filter on the per-client session here.
        let participants = sqlx::query(
            "SELECT cs.client_id AS client_id, cs.sid AS sid, \
                    c.backchannel_logout_uri AS logout_uri \
             FROM client_sessions cs \
             JOIN clients c \
               ON c.id = cs.client_id \
              AND c.tenant_id = cs.tenant_id \
              AND c.environment_id = cs.environment_id \
             WHERE cs.session_id = $1 AND cs.tenant_id = $2 AND cs.environment_id = $3 \
               AND c.backchannel_logout_uri IS NOT NULL AND c.backchannel_logout_uri <> ''",
        )
        .bind(session_id)
        .bind(&tenant)
        .bind(&environment)
        .fetch_all(&mut *tx)
        .await?;
        let mut queued: u64 = 0;
        for row in &participants {
            let client_id: String = row.get("client_id");
            let sid: String = row.get("sid");
            let logout_uri: String = row.get("logout_uri");
            let delivery_id = BackChannelDeliveryId::generate(env, &scope);
            // The Logout Token jti, minted ONCE here at explode time and carried on the
            // row, so every delivery ATTEMPT of this delivery re-POSTs the SAME token and
            // the RP can dedup a retry on the jti (a fresh jti per attempt would defeat
            // that at-least-once dedup).
            let jti = IssuedTokenId::generate(env, &scope);
            let inserted = sqlx::query(
                "INSERT INTO backchannel_logout_deliveries \
                 (id, tenant_id, environment_id, event_id, session_id, client_id, sid, \
                  logout_uri, jti, next_attempt_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                         TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval) \
                 ON CONFLICT (tenant_id, environment_id, event_id, client_id) DO NOTHING",
            )
            .bind(delivery_id.to_string())
            .bind(&tenant)
            .bind(&environment)
            .bind(event_id)
            .bind(session_id)
            .bind(&client_id)
            .bind(&sid)
            .bind(&logout_uri)
            .bind(jti.to_string())
            .bind(now_micros)
            .execute(&mut *tx)
            .await?;
            queued += inserted.rows_affected();
        }
        tx.commit().await?;
        Ok(queued)
    }

    /// Atomically CLAIM up to `limit` DUE, not-yet-terminal deliveries in this scope
    /// (issue #34), stamping each with a visibility lease that expires `lease` from now.
    /// A row is due when `next_attempt_at <= now` (the backoff gate) and it is neither
    /// delivered nor dead-lettered; a row another worker holds an unexpired lease on is
    /// SKIPPED (`FOR UPDATE SKIP LOCKED`), so two workers never double-deliver and never
    /// block on each other. A crashed worker's row reappears once its lease lapses
    /// (at-least-once).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault.
    pub async fn claim_due(
        &self,
        env: &Env,
        lease: Duration,
        limit: i64,
    ) -> Result<Vec<LogoutDelivery>, StoreError> {
        let scope = self.scope;
        let now_micros = epoch_micros(env.clock().now_utc());
        let lease_micros = i64::try_from(lease.as_micros()).unwrap_or(i64::MAX);
        let sql = format!(
            "UPDATE backchannel_logout_deliveries \
             SET claimed_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id IN ( \
                 SELECT id FROM backchannel_logout_deliveries \
                 WHERE tenant_id = $2 AND environment_id = $3 \
                 AND delivered_at IS NULL AND dead_lettered_at IS NULL \
                 AND next_attempt_at <= TIMESTAMPTZ 'epoch' \
                     + ($1::text || ' microseconds')::interval \
                 AND (claimed_at IS NULL \
                      OR claimed_at < TIMESTAMPTZ 'epoch' \
                         + (($1::bigint - $4)::text || ' microseconds')::interval) \
                 ORDER BY next_attempt_at \
                 LIMIT $5 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING {LOGOUT_DELIVERY_COLUMNS}"
        );
        let mut tx = begin_scoped(self.store, scope).await?;
        let rows = sqlx::query(&sql)
            .bind(now_micros)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(lease_micros)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(rows.iter().map(logout_delivery_from_row).collect())
    }

    /// Read up to `limit` not-yet-terminal deliveries in this scope, oldest gate first,
    /// WITHOUT claiming them (issue #34): a read-only peek for diagnostics and tests.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault.
    pub async fn pending(&self, limit: i64) -> Result<Vec<LogoutDelivery>, StoreError> {
        let scope = self.scope;
        let sql = format!(
            "SELECT {LOGOUT_DELIVERY_COLUMNS} FROM backchannel_logout_deliveries \
             WHERE tenant_id = $1 AND environment_id = $2 \
             AND delivered_at IS NULL AND dead_lettered_at IS NULL \
             ORDER BY next_attempt_at LIMIT $3"
        );
        let mut tx = begin_scoped(self.store, scope).await?;
        let rows = sqlx::query(&sql)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(rows.iter().map(logout_delivery_from_row).collect())
    }

    /// Read up to `limit` deliveries in this scope in ANY state (issue #34), newest
    /// first: the full listing a management status surface and the tests read, including
    /// the delivered and dead-lettered terminal rows the drain peek hides.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault.
    pub async fn list(&self, limit: i64) -> Result<Vec<LogoutDelivery>, StoreError> {
        let scope = self.scope;
        let sql = format!(
            "SELECT {LOGOUT_DELIVERY_COLUMNS} FROM backchannel_logout_deliveries \
             WHERE tenant_id = $1 AND environment_id = $2 \
             ORDER BY created_at DESC, id DESC LIMIT $3"
        );
        let mut tx = begin_scoped(self.store, scope).await?;
        let rows = sqlx::query(&sql)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(rows.iter().map(logout_delivery_from_row).collect())
    }

    /// Mark ONE claimed delivery DELIVERED by its `id` (issue #34), the terminal success
    /// state, so it never drains again. Idempotent: it flips `delivered_at` only while it
    /// is still non-terminal, so a double mark reports `false` the second time. A
    /// foreign-scope or malformed id is a uniform no-op (`false`), never an oracle.
    /// Returns whether THIS call flipped it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault.
    pub async fn mark_delivered(&self, env: &Env, id: &str) -> Result<bool, StoreError> {
        let scope = self.scope;
        let Ok(delivery_id) = BackChannelDeliveryId::parse_in_scope(id, &scope) else {
            return Ok(false);
        };
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, scope).await?;
        let flipped = sqlx::query(
            "UPDATE backchannel_logout_deliveries \
             SET delivered_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
             AND delivered_at IS NULL AND dead_lettered_at IS NULL",
        )
        .bind(now_micros)
        .bind(delivery_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(flipped.rows_affected() > 0)
    }

    /// Record a FAILED delivery attempt on `id` (issue #34): set the new `attempts`
    /// count and the `last_error` label, release the lease, and either schedule the next
    /// backoff retry (`next_attempt_micros = Some`) or DEAD-LETTER the row
    /// (`next_attempt_micros = None`) once the caller decided the attempts cap is reached.
    /// The worker computes the backoff instant and the dead-letter decision from the
    /// application clock and entropy seams, so the schedule is deterministic under a
    /// manual clock; this method only persists that decision. A foreign-scope or
    /// malformed id is a uniform no-op. Returns whether a row was updated.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault.
    pub async fn record_failure(
        &self,
        env: &Env,
        id: &str,
        attempts: i32,
        next_attempt_micros: Option<i64>,
        last_error: &str,
    ) -> Result<bool, StoreError> {
        let scope = self.scope;
        let Ok(delivery_id) = BackChannelDeliveryId::parse_in_scope(id, &scope) else {
            return Ok(false);
        };
        let now_micros = epoch_micros(env.clock().now_utc());
        let mut tx = begin_scoped(self.store, scope).await?;
        // Either schedule the next retry, or dead-letter (give up) now. Both clear the
        // lease so the row is not seen as in-flight; the backoff gate (or the terminal
        // marker) governs re-eligibility.
        let updated = match next_attempt_micros {
            Some(next_micros) => {
                sqlx::query(
                    "UPDATE backchannel_logout_deliveries \
                     SET attempts = $1, last_error = $2, claimed_at = NULL, \
                         next_attempt_at = TIMESTAMPTZ 'epoch' \
                             + ($3::text || ' microseconds')::interval \
                     WHERE id = $4 AND tenant_id = $5 AND environment_id = $6 \
                     AND delivered_at IS NULL AND dead_lettered_at IS NULL",
                )
                .bind(attempts)
                .bind(last_error)
                .bind(next_micros)
                .bind(delivery_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut *tx)
                .await?
            }
            None => {
                sqlx::query(
                    "UPDATE backchannel_logout_deliveries \
                     SET attempts = $1, last_error = $2, claimed_at = NULL, \
                         dead_lettered_at = TIMESTAMPTZ 'epoch' \
                             + ($3::text || ' microseconds')::interval \
                     WHERE id = $4 AND tenant_id = $5 AND environment_id = $6 \
                     AND delivered_at IS NULL AND dead_lettered_at IS NULL",
                )
                .bind(attempts)
                .bind(last_error)
                .bind(now_micros)
                .bind(delivery_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut *tx)
                .await?
            }
        };
        tx.commit().await?;
        Ok(updated.rows_affected() > 0)
    }
}

/// The fields a fresh SSO session carries at rotation/creation (issue #32).
///
/// Times are microseconds since the Unix epoch, all from the application clock
/// seam. `idle_expires_micros` is the idle timeout and `absolute_expires_micros` the
/// hard cap; the read guard rejects the session past either. `user_agent` and
/// `peer_ip` are the searchable fleet metadata AND the inputs of the two
/// OFF-BY-DEFAULT binding knobs; each is [`None`] unless the environment enabled the
/// corresponding knob, so the safe default records neither and binds neither.
#[derive(Debug, Clone, Copy)]
pub struct NewSession<'a> {
    /// The authenticated end-user subject the tokens are minted for.
    pub subject: &'a str,
    /// The recorded authentication method tokens (space-separated RFC 8176 values).
    pub auth_methods: &'a str,
    /// When the subject authenticated, in microseconds since the Unix epoch.
    pub auth_time_micros: i64,
    /// The idle timeout, in microseconds since the Unix epoch.
    pub idle_expires_micros: i64,
    /// The absolute hard-cap expiry, in microseconds since the Unix epoch.
    pub absolute_expires_micros: i64,
    /// The requesting user agent: the device/user-agent binding input, recorded ONLY
    /// when that OFF-BY-DEFAULT knob is enabled ([`None`] otherwise).
    pub user_agent: Option<&'a str>,
    /// The peer IP the session was established from: the peer-IP binding input,
    /// recorded ONLY when that OFF-BY-DEFAULT knob is enabled ([`None`] otherwise).
    pub peer_ip: Option<&'a str>,
}

/// Why a session ended (issue #32): the value recorded in `sessions.end_cause` and
/// carried on the session-ended signal, so a rotation is never mistaken for a
/// terminal end by a consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEndCause {
    /// Ended by an operator revoking a single session through the management API.
    Revoked,
    /// Ended as one item of a bulk revocation.
    BulkRevoked,
    /// Ended by a revoke-everything-for-a-user.
    UserRevokedAll,
    /// Ended by the end user's RP logout.
    LoggedOut,
    /// Ended because a DIFFERENT subject authenticated on the same browser session
    /// (issue #32). This is a TERMINAL end of the outgoing user's session, never a
    /// rotation: the incoming user inherits NOTHING of it (not its per-client
    /// sessions, not its refresh families), and the outgoing user's session-bound
    /// tokens die at the transition. Carrying the lineage forward here instead would
    /// be a cross-user privilege escalation.
    ReplacedByOtherSubject,
    /// Ended because the user CHANGED their password at the self-service account
    /// surface (issue #61): a password change revokes every OTHER session of the
    /// user in the same transaction (session-fixation defense), so a stolen session
    /// cannot outlive the credential it was minted under.
    PasswordChanged,
}

impl SessionEndCause {
    /// The stable wire string recorded in `sessions.end_cause`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionEndCause::Revoked => "revoked",
            SessionEndCause::BulkRevoked => "bulk_revoked",
            SessionEndCause::UserRevokedAll => "user_revoked_all",
            SessionEndCause::LoggedOut => "logged_out",
            SessionEndCause::ReplacedByOtherSubject => "replaced_by_other_subject",
            SessionEndCause::PasswordChanged => "password_changed",
        }
    }

    /// Reconstruct an end cause from the wire string stored on a session-ended event
    /// (issue #35). The inverse of [`SessionEndCause::as_str`]; used only when reading a
    /// drained outbox row back into a typed [`SessionEndedEvent`]. Returns [`None`] for
    /// an unknown tag, so a corrupt or forward-versioned row surfaces as a decode error
    /// rather than a panic.
    #[must_use]
    pub fn from_wire(cause: &str) -> Option<Self> {
        match cause {
            "revoked" => Some(SessionEndCause::Revoked),
            "bulk_revoked" => Some(SessionEndCause::BulkRevoked),
            "user_revoked_all" => Some(SessionEndCause::UserRevokedAll),
            "logged_out" => Some(SessionEndCause::LoggedOut),
            "replaced_by_other_subject" => Some(SessionEndCause::ReplacedByOtherSubject),
            "password_changed" => Some(SessionEndCause::PasswordChanged),
            _ => None,
        }
    }
}

/// What a rotation did with the session the browser previously presented (issue #32).
///
/// A rotation happens at a privilege transition (a login), and the prior session is
/// NOT necessarily the rotating user's: a login performed while presenting somebody
/// else's session cookie reaches the same path. The two cases MUST diverge, and this
/// reports which one the store took, so the caller publishes the truthful lifecycle
/// signal (a rotation is non-terminal; a replacement is terminal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorSessionOutcome {
    /// No live prior session of this scope was presented (no cookie, a cross-scope
    /// cookie, or a session that was already revoked, ended, or rotated away): nothing
    /// was carried and nothing was ended.
    None,
    /// The prior session belonged to the SAME subject, so this is a re-authentication
    /// of the same human in the same browser: its lineage (its per-client sessions,
    /// hence its `sid`s, and its refresh families) was CARRIED FORWARD onto the
    /// successor. The `sid` is therefore STABLE across the re-authentication (the OIDC
    /// contract), and a later revoke of the successor still reaches every dependent
    /// the earlier lineage segment opened, instead of orphaning them.
    Carried,
    /// The prior session belonged to a DIFFERENT subject, so it was terminally REVOKED
    /// with the FULL cascade (its per-client sessions, its refresh families, and, on a
    /// hard kill, its grants). The incoming user inherits nothing.
    RevokedForeignSubject,
}

/// The outcome of revoking one session (issue #32): whether the session itself
/// flipped (it was live) and how many of its refresh families were revoked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionRevocation {
    /// Whether the session was live and is now revoked (false when it was already
    /// revoked or absent).
    pub session_flipped: bool,
    /// How many of the session's refresh families were revoked by the cascade.
    pub families_revoked: u64,
}

/// The outcome of revoking every session of one user (issue #32).
///
/// [`revoked_session_ids`](Self::revoked_session_ids) names EXACTLY the sessions this
/// call flipped live -> revoked (captured with `RETURNING` in the same transaction),
/// so a caller that must fan a terminal session-ended signal out per session (the
/// global-token-revocation receiver, issue #36) emits one signal per truly-revoked
/// session with no list-then-revoke race and no spurious signal for an
/// already-revoked one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserRevocation {
    /// How many of the user's live sessions were revoked.
    pub sessions_revoked: u64,
    /// How many of the user's refresh families were revoked by the cascade.
    pub families_revoked: u64,
    /// The ids of the sessions this call actually revoked (`ses_...`), in no
    /// guaranteed order. Empty when the subject had no live session.
    pub revoked_session_ids: Vec<String>,
}

/// Revoke a user's refresh families inside an OPEN transaction (issue #32): the
/// session-bound (`offline = false`) families always, and (when `hard_kill`) the
/// offline families AND their grants too. Shared by the revoke-everything-for-a-user
/// path so its cascade matches the single-session cascade exactly.
async fn cascade_families_for_subject(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    subject_text: &str,
    now_micros: i64,
    hard_kill: bool,
    out: &mut UserRevocation,
) -> Result<(), StoreError> {
    let families = sqlx::query(
        "UPDATE refresh_families \
         SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
         WHERE subject = $2 AND tenant_id = $3 AND environment_id = $4 \
         AND revoked_at IS NULL AND ($5 OR offline = false)",
    )
    .bind(now_micros)
    .bind(subject_text)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(hard_kill)
    .execute(&mut **tx)
    .await?;
    out.families_revoked = families.rows_affected();
    if hard_kill {
        sqlx::query(
            "UPDATE grants \
             SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE tenant_id = $3 AND environment_id = $4 AND revoked_at IS NULL \
             AND id IN (SELECT grant_id FROM refresh_families \
                        WHERE subject = $2 AND tenant_id = $3 AND environment_id = $4)",
        )
        .bind(now_micros)
        .bind(subject_text)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Revoke every LIVE session of `subject` EXCEPT `keep`, inside an OPEN transaction
/// (issue #61), cascading each through the unified session-ended fan-out (issue #35)
/// and PRESERVING the `offline_access` families (no hard kill). Shared by the
/// self-service password change and the "sign out everywhere else" surface, so both
/// end a user's other sessions exactly the same way. Accumulates the counts and the
/// revoked ids into `out`.
async fn revoke_other_sessions_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    subject_text: &str,
    keep_text: Option<&str>,
    cause: SessionEndCause,
    now_micros: i64,
    emit: &SessionEndedEmit<'_>,
) -> Result<UserRevocation, StoreError> {
    let live = sqlx::query(
        "SELECT id FROM sessions \
         WHERE subject = $1 AND tenant_id = $2 AND environment_id = $3 \
         AND revoked_at IS NULL AND ended_at IS NULL \
         AND ($4::text IS NULL OR id <> $4)",
    )
    .bind(subject_text)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(keep_text)
    .fetch_all(&mut **tx)
    .await?;
    let mut out = UserRevocation::default();
    for row in &live {
        let session_text: String = row.get("id");
        let session_id = SessionId::parse_in_scope(&session_text, &scope)?;
        let revocation =
            revoke_session_in_tx(tx, scope, &session_id, cause, now_micros, false, emit).await?;
        if revocation.session_flipped {
            out.sessions_revoked += 1;
        }
        out.families_revoked += revocation.families_revoked;
        out.revoked_session_ids.push(session_text);
    }
    Ok(out)
}

/// Generate a fresh per-(client, session) `sid` value (issue #32): the `sid_`-tagged
/// opaque claim value, drawn from the entropy seam (never a direct RNG), so it is
/// deterministic under a seeded test entropy and satisfies the determinism-seam
/// invariant. It is NOT `sid = session_id`: an independent 128-bit random value, so
/// it never leaks cross-client correlation to colluding relying parties.
fn generate_sid(env: &Env) -> String {
    use std::fmt::Write as _;
    let mut bytes = [0_u8; 16];
    env.entropy().fill_bytes(&mut bytes);
    let mut sid = String::with_capacity(4 + bytes.len() * 2);
    sid.push_str("sid_");
    for byte in bytes {
        let _ = write!(sid, "{byte:02x}");
    }
    sid
}

/// The per-client session repository (issue #32): the tier-two `sid` store, keyed to
/// one SSO session. Its create is a get-or-create (idempotent per (session, client)),
/// off the audited-write path like the replay caches: it is session TRACKING infra,
/// not a business mutation (the login that opened the SSO session is already
/// audited), so it stays lean on the token path.
pub struct ClientSessionRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ClientSessionRepo<'_> {
    /// Resolve, or create, the per-(client, session) `sid` for `session_id` and
    /// `client_id` within scope, returning the STABLE `sid` claim value the ID token
    /// carries. Idempotent: the first call for a (session, client) pair creates the
    /// row with a fresh entropy-seam `sid`; every later call (a token refresh, a
    /// re-authorization) reads the SAME `sid` back, so the claim is stable per pair.
    /// Two clients of the same SSO session get two rows, so their `sid`s are distinct.
    ///
    /// `now_micros` (the application clock seam) stamps `last_seen_at`.
    ///
    /// # A DEAD session gets no sid
    ///
    /// The INSERT selects its row FROM `sessions` under the SAME liveness guard the
    /// authentication read path uses (not revoked, not ended, not superseded, and
    /// within both the idle and the absolute expiry), so a session that is no longer
    /// live yields no row and this returns [`StoreError::NotFound`]. That is defense in
    /// depth for the token endpoint: an authorization code minted BEFORE a session
    /// revoke and redeemed AFTER it must not be able to mint a brand-new LIVE per-client
    /// session (and a fresh `sid`) bound to a DEAD SSO session, which no cascade would
    /// ever reach.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `session_id` is out of this scope, or if the SSO
    /// session is no longer live;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn ensure_sid(
        &self,
        env: &Env,
        session_id: &SessionId,
        client_id: &str,
        now_micros: i64,
    ) -> Result<String, StoreError> {
        if session_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let cse_id = ClientSessionId::generate(env, &scope);
        let sid = generate_sid(env);
        let mut tx = begin_scoped(self.store, scope).await?;
        let row = sqlx::query(
            "INSERT INTO client_sessions \
             (id, tenant_id, environment_id, session_id, client_id, sid, created_at, last_seen_at) \
             SELECT $1, $2, $3, $4, $5, $6, \
                    TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval, \
                    TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval \
             FROM sessions s \
             WHERE s.id = $4 AND s.tenant_id = $2 AND s.environment_id = $3 \
             AND s.revoked_at IS NULL AND s.ended_at IS NULL AND s.superseded_by IS NULL \
             AND COALESCE(s.absolute_expires_at, s.expires_at) > \
                 TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval \
             AND (s.idle_expires_at IS NULL OR s.idle_expires_at > \
                  TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval) \
             ON CONFLICT (tenant_id, environment_id, session_id, client_id) \
             DO UPDATE SET last_seen_at = \
                 TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval \
             RETURNING sid",
        )
        .bind(cse_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(session_id.to_string())
        .bind(client_id)
        .bind(&sid)
        .bind(now_micros)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        // No row means the SELECT found no LIVE session to hang the per-client session
        // off, so nothing was inserted and no conflict fired: the session is dead.
        row.map(|row| row.get::<String, _>("sid"))
            .ok_or(StoreError::NotFound)
    }

    /// Resolve the SSO session bound to a per-client `sid` within scope (issue #33),
    /// returning [`None`] when no per-client session in scope carries that `sid`.
    ///
    /// RP-Initiated Logout's `id_token_hint` carries the per-(client, session) `sid`
    /// the ID token was minted with; this maps it back to the tier-one SSO `session_id`
    /// the logout then ends, so the hint is what identifies the session to terminate
    /// (not merely the browser cookie). The `sid` is a random per-pair value, so at
    /// most one row matches; the stored `session_id` came back through the row-level
    /// security scope filter, so it is in scope by construction and is re-parsed to the
    /// typed identifier. A `sid` from another tenant simply loads zero rows.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn session_for_sid(&self, sid: &str) -> Result<Option<SessionId>, StoreError> {
        let scope = self.scope;
        let mut tx = begin_scoped(self.store, scope).await?;
        let row = sqlx::query(
            "SELECT session_id FROM client_sessions \
             WHERE sid = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(sid)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let session_text: String = row.get("session_id");
        Ok(SessionId::parse_in_scope(&session_text, &scope).ok())
    }

    /// The relying parties that participate in a front-channel logout for `session_id`
    /// (issue #39): every per-client session of this SSO session whose client registered
    /// a `frontchannel_logout_uri`, joined to that client's registration. Each row
    /// carries the client's OWN `sid`, so the caller can build a per-RP logout iframe URL
    /// that only ever carries that RP's own `sid` (never a co-scoped client's).
    ///
    /// The result is empty for a session with no participating clients (the common case,
    /// and always when no client opted in), so the caller renders no front-channel
    /// iframes. Ordered by `sid` for a deterministic page.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `session_id` is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn frontchannel_participants(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<FrontchannelLogoutParticipant>, StoreError> {
        if session_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let mut tx = begin_scoped(self.store, scope).await?;
        let rows = sqlx::query(
            "SELECT c.frontchannel_logout_uri AS uri, \
             c.frontchannel_logout_session_required AS session_required, cs.sid AS sid \
             FROM client_sessions cs \
             JOIN clients c \
               ON c.id = cs.client_id \
              AND c.tenant_id = cs.tenant_id \
              AND c.environment_id = cs.environment_id \
             WHERE cs.session_id = $1 AND cs.tenant_id = $2 AND cs.environment_id = $3 \
               AND c.frontchannel_logout_uri IS NOT NULL \
             ORDER BY cs.sid",
        )
        .bind(session_id.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .iter()
            .map(|row| FrontchannelLogoutParticipant {
                frontchannel_logout_uri: row.get("uri"),
                session_required: row.get("session_required"),
                sid: row.get("sid"),
            })
            .collect())
    }

    /// Count the per-client session rows in scope (issue #32). A test uses it to prove a
    /// refused code exchange minted NO new per-client session (hence no fresh `sid`).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn count_in_scope(&self) -> Result<i64, StoreError> {
        let scope = self.scope;
        let mut tx = begin_scoped(self.store, scope).await?;
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM client_sessions WHERE tenant_id = $1 AND environment_id = $2",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(count)
    }
}

/// A filter for the session fleet-ops list (issue #32): search sessions by user
/// (subject) and/or by client, within the fixed scope (the environment dimension).
/// An empty filter lists every session in scope.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionFleetFilter<'a> {
    /// The subject (a `usr_` id string) to list sessions for, or [`None`] for all.
    pub subject: Option<&'a str>,
    /// The client id to list sessions that have a per-client session for, or
    /// [`None`] for all.
    pub client_id: Option<&'a str>,
}

/// A session as the management fleet-ops surface reports it (issue #32): the
/// searchable metadata and the full lifecycle state, so an operator can inspect a
/// live, revoked, rotated, or ended session. Every timestamp is microseconds since
/// the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// The session identifier (a `ses_` id string).
    pub id: String,
    /// The authenticated end-user subject.
    pub subject: String,
    /// The recorded authentication method tokens (space-separated RFC 8176 values).
    pub auth_methods: String,
    /// Creation time (the pagination key).
    pub created_at_unix_micros: i64,
    /// When the session was last seen, if recorded.
    pub last_seen_at_unix_micros: Option<i64>,
    /// The idle timeout, if set.
    pub idle_expires_at_unix_micros: Option<i64>,
    /// The absolute hard-cap expiry, if set.
    pub absolute_expires_at_unix_micros: Option<i64>,
    /// When the session was revoked, if it was.
    pub revoked_at_unix_micros: Option<i64>,
    /// When the session ended, if it did (revoked or rotated away).
    pub ended_at_unix_micros: Option<i64>,
    /// Why the session ended (`revoked`, `rotated`, ...), if it ended.
    pub end_cause: Option<String>,
    /// The successor session id if this one was rotated away.
    pub superseded_by: Option<String>,
    /// The recorded user agent: present only when the OFF-BY-DEFAULT device/user-agent
    /// binding knob was enabled when the session was established.
    pub user_agent: Option<String>,
    /// The recorded peer IP: present only when the OFF-BY-DEFAULT peer-IP binding
    /// knob was enabled when the session was established.
    pub peer_ip: Option<String>,
}

/// The read-only session fleet-ops repository (issue #32): list and inspect sessions
/// as searchable resources. Distinct from [`SessionRepo`] (the auth read path, which
/// applies the revocation/expiry guard and resolves only LIVE sessions): the fleet
/// surface deliberately reports revoked, rotated, and ended sessions too, so an
/// operator can inspect the full lifecycle. The scope is fixed, so a session of
/// another tenant or environment is not reachable.
pub struct SessionFleetRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl SessionFleetRepo<'_> {
    /// Parse an untrusted session identifier under this scope. A malformed identifier
    /// and one minted in another scope both return the uniform not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<SessionId, StoreError> {
        Ok(SessionId::parse_in_scope(raw, &self.scope)?)
    }

    /// Inspect one session by id within scope, whatever its lifecycle state. A session
    /// absent in this scope (including a cross-scope id) is the uniform [`None`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn get(&self, id: &SessionId) -> Result<Option<SessionSummary>, StoreError> {
        if id.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, subject, auth_methods, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM last_seen_at) * 1000000)::bigint AS last_seen_us, \
             (EXTRACT(EPOCH FROM idle_expires_at) * 1000000)::bigint AS idle_us, \
             (EXTRACT(EPOCH FROM absolute_expires_at) * 1000000)::bigint AS abs_us, \
             (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint AS revoked_us, \
             (EXTRACT(EPOCH FROM ended_at) * 1000000)::bigint AS ended_us, \
             end_cause, superseded_by, user_agent, peer_ip \
             FROM sessions \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.as_ref().map(session_summary_from_row))
    }

    /// One page of sessions matching `filter`, ordered by `(created_at, id)`,
    /// starting strictly after `after`. The `filter` searches by user and/or client
    /// within this scope; the environment dimension is the scope itself.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        filter: SessionFleetFilter<'_>,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<SessionSummary>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, subject, auth_methods, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM last_seen_at) * 1000000)::bigint AS last_seen_us, \
             (EXTRACT(EPOCH FROM idle_expires_at) * 1000000)::bigint AS idle_us, \
             (EXTRACT(EPOCH FROM absolute_expires_at) * 1000000)::bigint AS abs_us, \
             (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint AS revoked_us, \
             (EXTRACT(EPOCH FROM ended_at) * 1000000)::bigint AS ended_us, \
             end_cause, superseded_by, user_agent, peer_ip \
             FROM sessions \
             WHERE tenant_id = $1 AND environment_id = $2 \
             AND ($5::text IS NULL OR subject = $5) \
             AND ($6::text IS NULL OR EXISTS ( \
                  SELECT 1 FROM client_sessions cs \
                  WHERE cs.session_id = sessions.id \
                  AND cs.tenant_id = sessions.tenant_id \
                  AND cs.environment_id = sessions.environment_id \
                  AND cs.client_id = $6)) \
             AND ($3::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4::text)) \
             ORDER BY created_at, id LIMIT $7",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(filter.subject)
        .bind(filter.client_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.iter().map(session_summary_from_row).collect())
    }
}

/// Reconstruct a [`SessionSummary`] from a fleet-ops session row.
fn session_summary_from_row(row: &PgRow) -> SessionSummary {
    SessionSummary {
        id: row.get("id"),
        subject: row.get("subject"),
        auth_methods: row.get("auth_methods"),
        created_at_unix_micros: row.get("created_us"),
        last_seen_at_unix_micros: row.get("last_seen_us"),
        idle_expires_at_unix_micros: row.get("idle_us"),
        absolute_expires_at_unix_micros: row.get("abs_us"),
        revoked_at_unix_micros: row.get("revoked_us"),
        ended_at_unix_micros: row.get("ended_us"),
        end_cause: row.get("end_cause"),
        superseded_by: row.get("superseded_by"),
        user_agent: row.get("user_agent"),
        peer_ip: row.get("peer_ip"),
    }
}

/// A filter for the refresh-family fleet-ops list (issue #32): search families by
/// user (subject) and/or client, within the fixed scope.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefreshFamilyFleetFilter<'a> {
    /// The subject to list families for, or [`None`] for all.
    pub subject: Option<&'a str>,
    /// The client id to list families for, or [`None`] for all.
    pub client_id: Option<&'a str>,
}

/// A refresh-token family as the management fleet-ops surface reports it (issue #32):
/// searchable metadata and lifecycle state, so families are first-class fleet
/// resources alongside sessions. Every timestamp is microseconds since the Unix
/// epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshFamilySummary {
    /// The family identifier (an `rff_` id string).
    pub id: String,
    /// The authenticated end-user subject the family's tokens are minted for.
    pub subject: String,
    /// The OAuth client the family belongs to.
    pub client_id: String,
    /// The granted OAuth scope the family was issued against, if any.
    pub scope: Option<String>,
    /// The authenticating SSO session (a `ses_` id), if a session backed the grant.
    pub session_ref: Option<String>,
    /// Whether this is an `offline_access` family (survives RP logout) or session
    /// bound.
    pub offline: bool,
    /// Creation time (the pagination key).
    pub created_at_unix_micros: i64,
    /// The absolute hard cap on the family's rotated lifetime.
    pub absolute_expires_at_unix_micros: i64,
    /// When the family was revoked, if it was.
    pub revoked_at_unix_micros: Option<i64>,
}

/// The read-only refresh-family fleet-ops repository (issue #32): list and inspect
/// refresh-token families as searchable fleet resources. The scope is fixed, so a
/// family of another tenant or environment is not reachable.
pub struct RefreshFamilyFleetRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl RefreshFamilyFleetRepo<'_> {
    /// Parse an untrusted family identifier under this scope. A malformed identifier
    /// and one minted in another scope both return the uniform not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<RefreshFamilyId, StoreError> {
        Ok(RefreshFamilyId::parse_in_scope(raw, &self.scope)?)
    }

    /// Inspect one refresh family by id within scope. A family absent in this scope
    /// (including a cross-scope id) is the uniform [`None`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn get(
        &self,
        id: &RefreshFamilyId,
    ) -> Result<Option<RefreshFamilySummary>, StoreError> {
        if id.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, subject, client_id, scope, session_ref, offline, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM absolute_expires_at) * 1000000)::bigint AS abs_us, \
             (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint AS revoked_us \
             FROM refresh_families \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.as_ref().map(refresh_family_summary_from_row))
    }

    /// One page of refresh families matching `filter`, ordered by `(created_at, id)`,
    /// starting strictly after `after`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        filter: RefreshFamilyFleetFilter<'_>,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<RefreshFamilySummary>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, subject, client_id, scope, session_ref, offline, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM absolute_expires_at) * 1000000)::bigint AS abs_us, \
             (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint AS revoked_us \
             FROM refresh_families \
             WHERE tenant_id = $1 AND environment_id = $2 \
             AND ($5::text IS NULL OR subject = $5) \
             AND ($6::text IS NULL OR client_id = $6) \
             AND ($3::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4::text)) \
             ORDER BY created_at, id LIMIT $7",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(filter.subject)
        .bind(filter.client_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.iter().map(refresh_family_summary_from_row).collect())
    }
}

/// Reconstruct a [`RefreshFamilySummary`] from a fleet-ops family row.
fn refresh_family_summary_from_row(row: &PgRow) -> RefreshFamilySummary {
    RefreshFamilySummary {
        id: row.get("id"),
        subject: row.get("subject"),
        client_id: row.get("client_id"),
        scope: row.get("scope"),
        session_ref: row.get("session_ref"),
        offline: row.get("offline"),
        created_at_unix_micros: row.get("created_us"),
        absolute_expires_at_unix_micros: row.get("abs_us"),
        revoked_at_unix_micros: row.get("revoked_us"),
    }
}

// ===========================================================================
// The self-service account-credential registry (issue #61).
//
// A user's enrolled credentials (passkeys, TOTP authenticators, recovery-code
// sets) as a scoped, subject-bound resource. Every read and every write filters
// on the subject, so the surface reaches ONLY the authenticated subject's own
// credentials: a credential id of another subject (or another scope) resolves to
// the uniform not-found and is never actionable. The friendly name is user PII,
// sealed under the scope's envelope DEK (issue #48). This issue ships the registry
// and its authorization contract; the concrete factor material lands with M7.
// ===========================================================================

/// The closed set of self-service credential factor kinds (issue #61). The M7
/// factor issues implement the ceremonies against these; this issue owns the
/// registry and the authorization contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    /// A WebAuthn passkey: a PRIMARY login factor.
    Passkey,
    /// A TOTP authenticator app: a second factor.
    Totp,
    /// A recovery-code set: a backup factor.
    RecoveryCode,
}

impl CredentialType {
    /// The stable wire string (`passkey`, `totp`, `recovery_code`), matching the
    /// migration's `account_credentials_type_known` CHECK.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialType::Passkey => "passkey",
            CredentialType::Totp => "totp",
            CredentialType::RecoveryCode => "recovery_code",
        }
    }

    /// Parse a wire factor kind. Returns [`None`] for any value outside the closed
    /// set (the caller maps that to a client error, never a stored row).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "passkey" => Some(CredentialType::Passkey),
            "totp" => Some(CredentialType::Totp),
            "recovery_code" => Some(CredentialType::RecoveryCode),
            _ => None,
        }
    }

    /// Whether this factor kind can serve as a PRIMARY login credential (a passkey
    /// can; a TOTP or recovery-code set is a second/backup factor). The
    /// last-usable-credential guardrail counts exactly the primary-login factors,
    /// so a user cannot strand themselves by removing their last way to sign in.
    #[must_use]
    pub fn usable_for_login(&self) -> bool {
        matches!(self, CredentialType::Passkey)
    }
}

/// An enrolled credential as the self-service account surface reports it (issue
/// #61): its id, factor kind, decrypted friendly name, whether it is usable as a
/// primary login factor, and the created / last-used timestamps the account UI
/// shows. Every timestamp is microseconds since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCredentialSummary {
    /// The credential identifier (a `crd_` id string).
    pub id: String,
    /// The factor kind wire string (`passkey`, `totp`, `recovery_code`).
    pub credential_type: String,
    /// The user-authored friendly name (decrypted from the sealed column).
    pub friendly_name: String,
    /// Whether this credential is a primary login factor (the guardrail counts it).
    pub usable_for_login: bool,
    /// When the credential was enrolled (the pagination key).
    pub created_at_unix_micros: i64,
    /// When the factor was last used to authenticate, if recorded (M7).
    pub last_used_at_unix_micros: Option<i64>,
}

/// The outcome of a self-service credential removal (issue #61).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRemoveOutcome {
    /// The credential was removed.
    Removed,
    /// No such credential is visible for this subject in this scope (absent,
    /// cross-scope, or another subject's): the uniform not-found, never actionable.
    NotFound,
    /// The removal was BLOCKED by the last-usable-credential guardrail: it would
    /// have removed the subject's last primary-login credential and the request did
    /// not carry the documented recovery acknowledgment, so the user is not silently
    /// stranded. Nothing was removed and no audit row was written.
    BlockedLastCredential,
}

/// The read-only account-credential repository (issue #61): list and inspect a
/// subject's enrolled credentials. The scope is fixed AND every read is
/// subject-bound, so a credential of another subject, tenant, or environment is not
/// reachable.
pub struct AccountCredentialRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl AccountCredentialRepo<'_> {
    /// Parse an untrusted credential identifier under this scope. A malformed
    /// identifier and one minted in another scope both return the uniform not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<CredentialId, StoreError> {
        Ok(CredentialId::parse_in_scope(raw, &self.scope)?)
    }

    /// One page of `subject`'s enrolled credentials, ordered by `(created_at, id)`,
    /// starting strictly after `after`. Filtered on the subject, so it lists ONLY
    /// that subject's own credentials. The friendly name is decrypted from its sealed
    /// column under the row's DEK version.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if no platform master key is configured or a sealed
    /// name cannot be authenticated and decrypted; [`StoreError::Database`] on a
    /// persistence failure.
    pub async fn list(
        &self,
        subject: &UserId,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<AccountCredentialSummary>, StoreError> {
        if subject.scope() != self.scope {
            return Ok(Vec::new());
        }
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        let (after_micros, after_id) = split_cursor(after);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, credential_type, friendly_name_sealed, pii_dek_version, \
             usable_for_login, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM last_used_at) * 1000000)::bigint AS last_used_us \
             FROM account_credentials \
             WHERE tenant_id = $1 AND environment_id = $2 AND subject = $3 \
             AND ($4::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval, $5::text)) \
             ORDER BY created_at, id LIMIT $6",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(subject.to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(&mut *tx)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let dek_version: i32 = row.get("pii_dek_version");
            let sealed: Vec<u8> = row.get("friendly_name_sealed");
            let dek = fetch_dek_by_version(&mut tx, self.scope, master, dek_version).await?;
            let plaintext = dek.open(
                &credential_pii_seal_aad(self.scope, dek_version),
                &Sealed::from_bytes(sealed)?,
            )?;
            let friendly_name = String::from_utf8(plaintext).map_err(|_| StoreError::Encryption)?;
            out.push(AccountCredentialSummary {
                id: row.get("id"),
                credential_type: row.get("credential_type"),
                friendly_name,
                usable_for_login: row.get("usable_for_login"),
                created_at_unix_micros: row.get("created_us"),
                last_used_at_unix_micros: row.get("last_used_us"),
            });
        }
        tx.commit().await?;
        Ok(out)
    }
}

/// The mutating account-credential repository (issue #61): enroll and remove a
/// subject's own credentials, audited and subject-bound.
pub struct ActingAccountCredentialRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingAccountCredentialRepo<'_> {
    /// Ensure the scope has a live KEK and DEK to seal the friendly name under,
    /// provisioning each lazily on first use (idempotent). Mirrors the users-PII
    /// path so a credential name is sealed exactly like the login handle.
    async fn ensure_scope_keys(&self, env: &Env, master: &MasterKey) -> Result<(), StoreError> {
        let envelope = ActingEnvelopeRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        };
        match envelope.provision_kek(env, master).await {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error),
        }
        match envelope.provision_dek(env, master).await {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// ENROLL a credential of `credential_type` named `friendly_name` for `subject`
    /// (issue #61), sealing the name under the scope's DEK (issue #48) and returning
    /// the fresh id. Writes one `account.credential.enroll` audit row targeting the
    /// credential; `step_up_detail` records the operator-safe step-up policy the
    /// sensitive change declared. The credential is bound to `subject`, so a later
    /// list or removal by that subject reaches it and no other subject ever can.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `subject` is out of this scope;
    /// [`StoreError::Encryption`] if no platform master key is configured;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn enroll(
        &self,
        env: &Env,
        subject: &UserId,
        credential_type: CredentialType,
        friendly_name: &str,
        step_up_detail: &str,
    ) -> Result<CredentialId, StoreError> {
        if subject.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let master = self.store.master().ok_or(StoreError::Encryption)?;
        self.ensure_scope_keys(env, master).await?;
        let id = CredentialId::generate(env, &self.scope);
        let scope = self.scope;
        let subject_text = subject.to_string();
        let usable_for_login = credential_type.usable_for_login();
        let type_str = credential_type.as_str();
        write_audited_detailed(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::AccountCredentialEnroll,
                target: &id,
            },
            async move |tx| {
                let (dek_version, dek) = fetch_active_dek(tx, scope, master).await?;
                let name_sealed = dek.seal(
                    env.entropy(),
                    &credential_pii_seal_aad(scope, dek_version),
                    friendly_name.as_bytes(),
                );
                sqlx::query(
                    "INSERT INTO account_credentials \
                     (id, tenant_id, environment_id, subject, credential_type, \
                      friendly_name_sealed, pii_dek_version, usable_for_login) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&subject_text)
                .bind(type_str)
                .bind(name_sealed.into_bytes())
                .bind(dek_version)
                .bind(usable_for_login)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
            Some(step_up_detail),
        )
        .await?;
        Ok(id)
    }

    /// REMOVE `subject`'s credential `id` (issue #61), enforcing the
    /// last-usable-credential guardrail in the SAME transaction it reads the state
    /// in (so a concurrent removal cannot slip two "last" credentials past it).
    ///
    /// The credential is resolved WITH its subject bound, so another subject's id (or
    /// a cross-scope id) is the uniform [`CredentialRemoveOutcome::NotFound`], never
    /// actionable. When the credential is a primary-login factor and it is the
    /// subject's LAST such factor, the removal is BLOCKED
    /// ([`CredentialRemoveOutcome::BlockedLastCredential`]) unless `acknowledge_recovery`
    /// is set (the documented recovery acknowledgment), so a user cannot silently
    /// strand themselves. A successful removal writes one `account.credential.remove`
    /// audit row targeting the credential; a blocked or not-found removal writes
    /// nothing. `step_up_detail` records the operator-safe step-up policy declared.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn remove(
        &self,
        env: &Env,
        subject: &UserId,
        id: &CredentialId,
        acknowledge_recovery: bool,
        step_up_detail: &str,
    ) -> Result<CredentialRemoveOutcome, StoreError> {
        if id.scope() != self.scope || subject.scope() != self.scope {
            return Ok(CredentialRemoveOutcome::NotFound);
        }
        let scope = self.scope;
        let subject_text = subject.to_string();
        let id_text = id.to_string();
        let mut tx = begin_scoped(self.store, scope).await?;
        // Resolve the credential WITH its subject bound: another subject's id finds
        // no row and is the uniform not-found.
        let row = sqlx::query(
            "SELECT usable_for_login FROM account_credentials \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND subject = $4",
        )
        .bind(&id_text)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(&subject_text)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(CredentialRemoveOutcome::NotFound);
        };
        let usable_for_login: bool = row.get("usable_for_login");
        // The guardrail: removing the subject's LAST primary-login credential is
        // blocked unless the recovery acknowledgment is present. Counted inside the
        // same transaction so a concurrent removal cannot race two "last" credentials
        // out from under it.
        if usable_for_login && !acknowledge_recovery {
            let remaining: i64 = sqlx::query(
                "SELECT count(*) AS n FROM account_credentials \
                 WHERE tenant_id = $1 AND environment_id = $2 AND subject = $3 \
                 AND usable_for_login = true AND id <> $4",
            )
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&subject_text)
            .bind(&id_text)
            .fetch_one(&mut *tx)
            .await?
            .get("n");
            if remaining == 0 {
                tx.commit().await?;
                return Ok(CredentialRemoveOutcome::BlockedLastCredential);
            }
        }
        sqlx::query(
            "DELETE FROM account_credentials \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND subject = $4",
        )
        .bind(&id_text)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(&subject_text)
        .execute(&mut *tx)
        .await?;
        insert_audit_row(
            &mut tx,
            &AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::AccountCredentialRemove,
                target: id,
            },
            Some(step_up_detail),
        )
        .await?;
        tx.commit().await?;
        Ok(CredentialRemoveOutcome::Removed)
    }
}

/// A recorded consent decision (issue #196): the `con_` id the grant references
/// AND the `scope` value the decision was made against.
///
/// The authorization endpoint checks a later request's scope against
/// `granted_scope`, so a consent recorded for a narrow scope never silently
/// auto-grants a broader one. `granted_scope` is [`None`] when the consented
/// request carried no `scope` (an empty granted set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedConsent {
    /// The `con_` consent identifier the grant references through its consent seam.
    pub id: String,
    /// The space-separated `scope` value the decision was recorded against, or
    /// [`None`] when the consented request carried no scope.
    pub granted_scope: Option<String>,
    /// The consent's expiry in microseconds since the Unix epoch (issue #21), or
    /// [`None`] when the consent never expires (the `explicit` mode default). A
    /// `remembered`-mode consent stores an expiry; the authorization endpoint
    /// treats a consent past its expiry as absent and re-prompts. The value is read
    /// straight through so the caller compares it against the application clock.
    pub expires_at_unix_micros: Option<i64>,
}

/// The read-only consent repository (issue #20).
pub struct ConsentRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ConsentRepo<'_> {
    /// The recorded consent for `subject` and `client_id` in this scope, or
    /// [`None`] when the subject has not consented to the client. The bootstrap
    /// records consent per (subject, client), so a granted decision skips the
    /// consent prompt on a later authorization for the same client.
    ///
    /// Returns BOTH the `con_` id the grant references AND the `granted_scope` the
    /// decision was made against (issue #196), so the authorization endpoint can
    /// re-prompt when a later request's scope is not a subset of the granted scope
    /// rather than auto-granting the broader scope off the narrower recorded one.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn granted_ref(
        &self,
        subject: &str,
        client_id: &str,
    ) -> Result<Option<GrantedConsent>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, granted_scope, \
             (EXTRACT(EPOCH FROM expires_at) * 1000000)::bigint AS expires_us FROM consents \
             WHERE subject = $1 AND client_id = $2 \
             AND tenant_id = $3 AND environment_id = $4",
        )
        .bind(subject)
        .bind(client_id)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| GrantedConsent {
            id: row.get::<String, _>("id"),
            granted_scope: row.get::<Option<String>, _>("granted_scope"),
            expires_at_unix_micros: row.get::<Option<i64>, _>("expires_us"),
        }))
    }
}

/// The mutating consent repository (issue #20).
pub struct ActingConsentRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingConsentRepo<'_> {
    /// Record `subject`'s consent to `client_id` against `granted_scope`, and
    /// return the ACTUAL consent id the grant references. Writes a `consent.grant`
    /// audit row in the same transaction, whose `target_id` is that same ACTUAL id.
    ///
    /// The write is an UPSERT keyed on (subject, client): a first consent INSERTs a
    /// row; a RE-consent for an already-consented (subject, client) UPDATEs the
    /// stored `granted_scope` in place (issue #196), so broadening a previously
    /// narrow consent is PERSISTED rather than dropped (the old `ON CONFLICT DO
    /// NOTHING` silently kept the narrow scope, which then re-prompted forever).
    ///
    /// A re-consent's UPDATE branch keeps the row's ORIGINAL id, so a freshly
    /// generated id would be a phantom audit target: it is never persisted, and an
    /// investigator pivoting from the real consent row (or from the returned id)
    /// could not find the scope-broadening event. To keep the audit `target_id`
    /// equal to the persisted row id on BOTH a first insert and a re-consent, this
    /// PRE-READS the existing consent row's id for (subject, client) in scope and
    /// uses it as BOTH the INSERT candidate id and the audit target: on a re-consent
    /// `ON CONFLICT` keeps that same id, so `RETURNING id` and the audit target
    /// agree; on a first consent there is no row, so a fresh id is the candidate the
    /// INSERT persists.
    ///
    /// Concurrency note: two TRULY concurrent FIRST grants for the same (subject,
    /// client) both pre-read no row and generate distinct candidate ids; the unique
    /// constraint (tenant, environment, subject, client) still admits exactly one
    /// row (the loser falls to the `DO UPDATE` branch), so no duplicate is created,
    /// but the loser's audit `target_id` names its own discarded candidate rather
    /// than the surviving row. This window is confined to the concurrent
    /// FIRST-consent (both record the same initial scope); a scope-BROADENING
    /// re-consent always finds the existing row in the pre-read and is never subject
    /// to it, so the security-relevant broaden event's audit linkage is always
    /// intact.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn grant(
        &self,
        env: &Env,
        subject: &str,
        client_id: &str,
        granted_scope: Option<&str>,
    ) -> Result<ConsentId, StoreError> {
        self.grant_inner(env, subject, client_id, granted_scope, None)
            .await
    }

    /// Record consent with an EXPIRY (issue #21): the `remembered` consent mode.
    /// `expires_at_micros` is when the recorded consent lapses, in microseconds
    /// since the Unix epoch (the clock seam); `None` records a never-expiring
    /// consent, identical to [`grant`](Self::grant). The authorization endpoint
    /// treats a consent past its expiry as absent and re-prompts, and a re-consent
    /// refreshes the expiry. All the audit and upsert semantics of
    /// [`grant`](Self::grant) hold.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn grant_with_expiry(
        &self,
        env: &Env,
        subject: &str,
        client_id: &str,
        granted_scope: Option<&str>,
        expires_at_micros: Option<i64>,
    ) -> Result<ConsentId, StoreError> {
        self.grant_inner(env, subject, client_id, granted_scope, expires_at_micros)
            .await
    }

    async fn grant_inner(
        &self,
        env: &Env,
        subject: &str,
        client_id: &str,
        granted_scope: Option<&str>,
        expires_at_micros: Option<i64>,
    ) -> Result<ConsentId, StoreError> {
        let scope = self.scope;
        // Pre-read the existing consent row's id for (subject, client) so the INSERT
        // candidate id and the audit target are the row's REAL id, not a fresh id the
        // upsert's UPDATE branch would discard. This read is a separate scoped
        // transaction (the concurrency window is documented on this method); a
        // BROADENING re-consent always finds the row here, so its audit linkage never
        // drifts.
        let candidate = match (ConsentRepo {
            store: self.store,
            scope,
        })
        .granted_ref(subject, client_id)
        .await?
        {
            // A row this scope already wrote parses back in scope by construction; it
            // is checked anyway for defense in depth (the anti-oracle boundary).
            Some(existing) => ConsentId::parse_in_scope(&existing.id, &scope)?,
            None => ConsentId::generate(env, &scope),
        };
        // The upsert's RETURNING id is read out through this slot: the closure runs
        // inside the audited transaction, so it cannot return a value directly.
        let mut stored_id: Option<String> = None;
        let stored_id_out = &mut stored_id;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ConsentGrant,
                // The pre-read candidate is the persisted row id on a first consent
                // and on a re-consent, so the audit row joins to the real consent row.
                target: &candidate,
            },
            async move |tx| {
                let row = sqlx::query(
                    "INSERT INTO consents \
                     (id, tenant_id, environment_id, subject, client_id, granted_scope, \
                      expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, \
                             CASE WHEN $7::bigint IS NULL THEN NULL \
                                  ELSE TIMESTAMPTZ 'epoch' \
                                       + ($7::text || ' microseconds')::interval END) \
                     ON CONFLICT (tenant_id, environment_id, subject, client_id) \
                     DO UPDATE SET granted_scope = EXCLUDED.granted_scope, \
                                   expires_at = EXCLUDED.expires_at \
                     RETURNING id",
                )
                .bind(candidate.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(subject)
                .bind(client_id)
                .bind(granted_scope)
                .bind(expires_at_micros)
                .fetch_one(&mut **tx)
                .await?;
                *stored_id_out = Some(row.get::<String, _>("id"));
                Ok(())
            },
            false,
        )
        .await?;
        // The actual persisted id: the candidate on a first consent or a re-consent
        // (equal to the audit target), or the surviving row's id only in the rare
        // concurrent first-grant window documented above. `fetch_one` guarantees one
        // RETURNING row, so the fallback to the candidate is unreachable and only
        // keeps this panic-free.
        let stored_id = stored_id.unwrap_or_else(|| candidate.to_string());
        let consent_id = ConsentId::parse_in_scope(&stored_id, &self.scope)?;
        Ok(consent_id)
    }
}

/// Whether a database error is a Postgres unique-violation (SQLSTATE 23505).
/// Used to turn a duplicate bootstrap login handle into the caller-facing
/// [`StoreError::Conflict`] rather than an opaque database fault.
fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
        == Some("23505")
}

/// Whether a database error is a Postgres check-constraint violation (SQLSTATE
/// 23514). Used to turn a rejected registration (for example a client that set
/// both `jwks` and `jwks_uri`) into the caller-facing [`StoreError::Conflict`].
fn is_check_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
        == Some("23514")
}

/// A record read back from the `audit_log` table, always within scope. The full
/// mutation envelope: who acted, what they did, on which resource, under which
/// request, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The audit event identifier (embeds its tenant and environment).
    pub id: AuditId,
    /// The action string, for example `client.create`.
    pub action: String,
    /// The acting principal.
    pub actor: ActorRef,
    /// The typed-prefix kind of the target resource, for example `cli`.
    pub target_kind: String,
    /// The target resource identifier in wire form.
    pub target_id: String,
    /// The correlation id of the request that caused the mutation.
    pub correlation_id: CorrelationId,
    /// The event time in microseconds since the Unix epoch, as recorded from the
    /// application clock seam at mutation time.
    pub occurred_at_unix_micros: i64,
    /// An optional operator-safe detail dimension (issue #31): the offending policy
    /// property on a `dcr.policy_rejected` event, `None` for a write that named no
    /// detail. Never attacker-controlled free text.
    pub detail: Option<String>,
}

/// The read-only repository for the append-only audit log.
pub struct AuditRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl AuditRepo<'_> {
    /// Every audit row in this scope, oldest first.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure, or if a stored row
    /// fails to decode into the typed envelope.
    pub async fn list(&self) -> Result<Vec<AuditRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // Exact microsecond read-back requires PostgreSQL 14+, where
        // EXTRACT(EPOCH FROM timestamptz) returns numeric (exact). On older
        // versions it returns double precision and can round by +/- 1 us; the
        // stored value is exact regardless (it is written as an integer
        // microsecond interval), so this only affects the read-back precision.
        let rows = sqlx::query(
            "SELECT id, action, actor_kind, actor_id, target_kind, target_id, \
             correlation_id, detail, \
             (EXTRACT(EPOCH FROM occurred_at) * 1000000)::bigint AS occurred_us \
             FROM audit_log \
             WHERE tenant_id = $1 AND environment_id = $2 \
             ORDER BY occurred_at, recorded_at, id",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| self.row_to_audit_record(row))
            .collect()
    }

    /// Reconstruct a typed [`AuditRecord`] from a row read within scope.
    fn row_to_audit_record(&self, row: &PgRow) -> Result<AuditRecord, StoreError> {
        let id_text: String = row.get("id");
        let id = AuditId::parse_in_scope(&id_text, &self.scope)?;
        let actor_kind: String = row.get("actor_kind");
        let actor_id: String = row.get("actor_id");
        let actor = ActorRef::from_parts(&actor_kind, &actor_id)
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let correlation_text: String = row.get("correlation_id");
        let correlation_id = CorrelationId::parse(&correlation_text)
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        Ok(AuditRecord {
            id,
            action: row.get("action"),
            actor,
            target_kind: row.get("target_kind"),
            target_id: row.get("target_id"),
            correlation_id,
            occurred_at_unix_micros: row.get("occurred_us"),
            detail: row.get("detail"),
        })
    }
}

// ===========================================================================
// Device authorization grant (issue #24, RFC 8628).
//
// The data-plane, tenant-scoped persistence behind the device-authorization
// endpoint (which issues a flow), the verification page (which a human approves or
// denies), and the token endpoint (which the constrained device polls). The device
// code is a digest-only bearer credential exactly like an opaque access token; the
// user code is stored only as a hash. Polling and failed-user-code bookkeeping are
// high-frequency counter mutations kept off the audited-write path (like the DCR
// rate counters and the jti replay cache), so they live on the read repo; the
// issue/approve/deny/redeem business events audit through the standard primitive.
// ===========================================================================

/// Fields to INSERT for a freshly issued device-authorization flow (issue #24). All
/// stored material is a digest or a hash; no plaintext device code or user code is
/// carried. `Debug` shows only the non-secret handle and metadata.
#[derive(Clone, Copy)]
pub struct NewDeviceCode<'a> {
    /// The flow's `dc_` routing handle (the non-secret id embedded in the device
    /// code), stored as the `id` column and used as the audit target.
    pub device_code_id: &'a DeviceCodeId,
    /// The SHA-256 hex digest of the WHOLE device code (the poll lookup key). NEVER
    /// the plaintext device code.
    pub device_code_digest: &'a str,
    /// The SHA-256 hex hash of the NORMALIZED user code (the verification-page match
    /// key). NEVER the plaintext user code.
    pub user_code_hash: &'a str,
    /// The OAuth client the flow belongs to.
    pub client_id: &'a ClientId,
    /// The OAuth scope requested, if any (echoed into the issued tokens).
    pub requested_scope: Option<&'a str>,
    /// The initial minimum polling interval, in seconds.
    pub interval_secs: i32,
    /// A coarse, operator-safe hint of where the flow was initiated (the initiating
    /// request's network source), shown on the verification page.
    pub initiation_hint: Option<&'a str>,
    /// The flow's expiry, in microseconds since the Unix epoch (clock seam).
    pub expires_at_unix_micros: i64,
    /// The flow's creation instant, in microseconds since the Unix epoch (clock seam).
    pub created_at_unix_micros: i64,
}

impl fmt::Debug for NewDeviceCode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewDeviceCode")
            .field("device_code_id", &self.device_code_id)
            .field("client_id", &self.client_id)
            .field("expires_at_unix_micros", &self.expires_at_unix_micros)
            .finish_non_exhaustive()
    }
}

/// The outcome of looking up a submitted user code on the verification page (issue
/// #24). Deliberately coarse so the page stays non-oracular: `Dead` and `NotFound`
/// are both rendered as the same safe error, revealing nothing about whether a
/// (possibly other-scope) code exists.
#[derive(Debug)]
pub enum DeviceUserCodeLookup {
    /// A pending, unexpired flow with attempts remaining: proceed to confirmation.
    Active(ActiveDeviceFlow),
    /// A flow exists but is not approvable (approved, denied, expired, or its failed
    /// -match budget is exhausted): render the same safe error as an absent code.
    Dead,
    /// No flow matches this user code hash in scope.
    NotFound,
}

/// A pending device-authorization flow matched by its user code (issue #24), for the
/// verification page to render the confirmation and bind the human's approval to it.
#[derive(Debug)]
pub struct ActiveDeviceFlow {
    /// The flow's non-secret `dc_` handle, carried through the confirmation.
    pub device_code_id: DeviceCodeId,
    /// The client id string the flow is for (to load the display profile).
    pub client_id: String,
    /// The OAuth scope the device requested, if any (shown to the human).
    pub requested_scope: Option<String>,
    /// The coarse initiation-location hint (shown to the human).
    pub initiation_hint: Option<String>,
}

/// Whether a failed user-code match left the flow alive or invalidated it (issue #24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAttemptOutcome {
    /// The flow is still pending; more attempts remain.
    Alive,
    /// The flow's failed-match budget is exhausted (or it was already terminal): it
    /// is now invalidated (`denied`).
    Died,
}

/// A client's device-verification display profile and grant allowlist (issue #24).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceClientProfile {
    /// The client's human-facing display name.
    pub display_name: String,
    /// The space-separated OAuth grant-type allowlist (the device endpoint requires
    /// this to contain the `device_code` URN).
    pub grant_types: String,
    /// The client's registered logo URI (rendered on the verification page), if any.
    pub logo_uri: Option<String>,
}

/// The outcome of a device-code poll at the token endpoint (issue #24, RFC 8628 3.5).
#[derive(Debug)]
pub enum DevicePollOutcome {
    /// The flow is still awaiting human approval (`authorization_pending`).
    Pending,
    /// The device polled faster than the current interval; the interval was increased
    /// in place and this is the new value (`slow_down`).
    SlowDown {
        /// The new (increased) minimum polling interval, in seconds.
        interval_secs: i64,
    },
    /// The flow was approved: the pre-signing caller now mints tokens and calls
    /// [`ActingDeviceCodeRepo::redeem_approved`] to atomically consume it. Boxed so the
    /// grant linkage (much larger than the other variants) does not bloat every
    /// `DevicePollOutcome` value.
    Approved(Box<ApprovedDeviceGrant>),
    /// The flow was denied by the human or invalidated (`access_denied`).
    Denied,
    /// The flow's TTL has passed (`expired_token`).
    Expired,
    /// No such flow, or it was already redeemed (`invalid_grant`).
    Unknown,
}

/// The linkage an approved device flow hands the token endpoint to mint tokens
/// (issue #24). `Debug` redacts the end-user subject.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedDeviceGrant {
    /// The flow's non-secret handle, for the atomic redeem.
    pub device_code_id: DeviceCodeId,
    /// The grant opened at approval (the revocation spine the tokens hang off).
    pub grant_id: GrantId,
    /// The authenticated end-user subject (a `usr_` id string).
    pub subject: String,
    /// The client the flow belongs to (re-checked against the authenticated caller).
    pub client_id: String,
    /// The granted OAuth scope, if any.
    pub requested_scope: Option<String>,
    /// The authentication methods frozen at approval (the amr/acr source).
    pub auth_methods: String,
    /// The approving human's authentication instant, in epoch microseconds, if present.
    pub auth_time_unix_micros: Option<i64>,
    /// The approving human's SSO session (a `ses_` id string), recorded on the grant at
    /// approval (issue #32). The device flow DOES authenticate a human (at the
    /// verification page), so its ID token carries the per-(client, session) `sid` like
    /// every other flow's; this is what that `sid` resolves from. [`None`] only for a
    /// grant approved before this was recorded.
    pub session_ref: Option<String>,
}

impl fmt::Debug for ApprovedDeviceGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovedDeviceGrant")
            .field("device_code_id", &self.device_code_id)
            .field("grant_id", &self.grant_id)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// The fields the verification page supplies to approve a flow (issue #24).
#[derive(Clone, Copy)]
pub struct DeviceApproval<'a> {
    /// The flow to approve (its non-secret handle).
    pub device_code_id: &'a DeviceCodeId,
    /// The grant to open for it (the revocation spine).
    pub grant_id: &'a GrantId,
    /// The authenticated end-user subject.
    pub subject: &'a str,
    /// The recorded consent decision (a `con_` id string), if any.
    pub consent_ref: Option<&'a str>,
    /// The approving human's SSO session (a `ses_` id string), recorded on the opened
    /// grant (issue #32) so the device flow's ID token can carry the per-(client,
    /// session) `sid` exactly like the code flow's does.
    pub session_ref: Option<&'a str>,
    /// The authentication methods (space-separated RFC 8176 values) from the session.
    pub auth_methods: &'a str,
    /// The approving human's authentication instant, in epoch microseconds, if any.
    pub auth_time_unix_micros: Option<i64>,
    /// The grant's creation instant, in epoch microseconds (clock seam).
    pub created_at_unix_micros: i64,
    /// The current instant, in epoch microseconds, for the pending/expiry re-check.
    pub now_unix_micros: i64,
}

/// Whether an approval attempt confirmed the flow or found it no longer approvable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceApproveOutcome {
    /// The flow was pending and unexpired: it is now approved with its grant opened.
    Approved,
    /// The flow was already approved, denied, expired, or absent: nothing changed.
    NotApprovable,
}

/// Whether the atomic redeem consumed the approved flow or found it already spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRedeemOutcome {
    /// The flow was approved and is now redeemed; the issued tokens were recorded.
    Redeemed,
    /// The flow was no longer approved (already redeemed, or a concurrent poll won):
    /// the pre-signed tokens are dropped and the exchange fails `invalid_grant`.
    NotApprovable,
}

/// The read-and-bookkeeping device-authorization repository (issue #24). Polling and
/// failed-attempt tracking are counter mutations off the audited-write path (like the
/// DCR rate counters), so they commit their own scoped transactions here.
pub struct DeviceCodeRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl DeviceCodeRepo<'_> {
    /// Parse an untrusted device-code id under this scope. A malformed id and one
    /// minted in another scope both return the uniform not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if malformed or out of scope.
    pub fn parse_device_code_id(&self, raw: &str) -> Result<DeviceCodeId, StoreError> {
        Ok(DeviceCodeId::parse_in_scope(raw, &self.scope)?)
    }

    /// Look up the flow a submitted user code names, within scope (issue #24). Returns
    /// [`DeviceUserCodeLookup::Active`] only when the flow is pending, unexpired, and
    /// under its failed-match bound; a flow that exists but is not approvable is a
    /// [`DeviceUserCodeLookup::Dead`], and no matching flow is
    /// [`DeviceUserCodeLookup::NotFound`]. The page renders `Dead` and `NotFound`
    /// identically, so there is no existence oracle. `now_micros` is the application
    /// clock seam.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn lookup_user_code(
        &self,
        submitted_user_code_hash: &str,
        now_micros: i64,
        max_attempts: i64,
    ) -> Result<DeviceUserCodeLookup, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, client_id, requested_scope, initiation_hint, status, failed_attempts, \
             (EXTRACT(EPOCH FROM expires_at) * 1000000)::bigint AS expires_us \
             FROM device_codes \
             WHERE user_code_hash = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(submitted_user_code_hash)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(DeviceUserCodeLookup::NotFound);
        };
        let status: String = row.get("status");
        let expires_us: i64 = row.get("expires_us");
        let failed: i32 = row.get("failed_attempts");
        let approvable =
            status == "pending" && expires_us > now_micros && i64::from(failed) < max_attempts;
        if !approvable {
            return Ok(DeviceUserCodeLookup::Dead);
        }
        let id_text: String = row.get("id");
        let device_code_id = DeviceCodeId::parse_in_scope(&id_text, &self.scope)?;
        Ok(DeviceUserCodeLookup::Active(ActiveDeviceFlow {
            device_code_id,
            client_id: row.get("client_id"),
            requested_scope: row.get("requested_scope"),
            initiation_hint: row.get("initiation_hint"),
        }))
    }

    /// The client's device-verification display profile and grant allowlist, within
    /// scope (issue #24), or [`None`] when the client is absent or out of scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn client_device_profile(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<DeviceClientProfile>, StoreError> {
        if client_id.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT display_name, grant_types, logo_uri FROM clients \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(client_id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| DeviceClientProfile {
            display_name: row.get("display_name"),
            grant_types: row.get("grant_types"),
            logo_uri: row.get("logo_uri"),
        }))
    }

    /// Record one failed user-code match against a specific flow (issue #24, RFC 8628
    /// section 5.1) and report whether it survived. Increments `failed_attempts`
    /// atomically and, once it reaches `max_attempts`, invalidates the flow (status ->
    /// `denied`) in the same statement, so a user code cannot be brute forced past the
    /// bound. Only a pending, unexpired flow accrues attempts; anything else is already
    /// [`DeviceAttemptOutcome::Died`]. An out-of-scope id is a uniform `Died` (no
    /// oracle). `now_micros` is the application clock seam.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn record_failed_user_code(
        &self,
        device_code_id: &DeviceCodeId,
        max_attempts: i64,
        now_micros: i64,
    ) -> Result<DeviceAttemptOutcome, StoreError> {
        if device_code_id.scope() != self.scope {
            return Ok(DeviceAttemptOutcome::Died);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "UPDATE device_codes \
             SET failed_attempts = failed_attempts + 1, \
                 status = CASE WHEN failed_attempts + 1 >= $1 THEN 'denied' ELSE status END \
             WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 AND status = 'pending' \
               AND expires_at > TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval \
             RETURNING status",
        )
        .bind(max_attempts)
        .bind(device_code_id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(now_micros)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(match row {
            Some(row) if row.get::<String, _>("status") == "denied" => DeviceAttemptOutcome::Died,
            Some(_) => DeviceAttemptOutcome::Alive,
            None => DeviceAttemptOutcome::Died,
        })
    }

    /// Resolve a presented device code at the token-endpoint poll and advance its poll
    /// state atomically (issue #24, RFC 8628 sections 3.4 and 3.5).
    ///
    /// The presented device code is hashed with [`device_code_digest`] and matched
    /// within scope (the device code embeds its own scope, checked by the caller, and
    /// forced row-level security sits beneath), so a device code minted in one
    /// environment never resolves under another. The row is taken `FOR UPDATE`, so the
    /// state machine runs without a race:
    ///
    /// - expired flow (past its TTL): [`DevicePollOutcome::Expired`];
    /// - a poll faster than the current interval: the interval is INCREASED in place
    ///   and [`DevicePollOutcome::SlowDown`] is returned (`slow_down` is enforced, not
    ///   merely advised);
    /// - pending: [`DevicePollOutcome::Pending`]; denied: [`DevicePollOutcome::Denied`];
    /// - approved: [`DevicePollOutcome::Approved`] with the grant linkage (the caller
    ///   pre-signs the tokens then calls [`ActingDeviceCodeRepo::redeem_approved`] to
    ///   consume it, so a signing failure never burns the flow);
    /// - absent or already redeemed: [`DevicePollOutcome::Unknown`].
    ///
    /// Every well-paced poll records `last_poll_at` from the application clock seam
    /// (`now_micros`), so `slow_down` bookkeeping is deterministic under a manual clock.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn poll(
        &self,
        presented_device_code: &str,
        now_micros: i64,
        slow_down_increment_secs: i64,
    ) -> Result<DevicePollOutcome, StoreError> {
        let digest = device_code_digest(presented_device_code);
        let tenant = self.scope.tenant().to_string();
        let environment = self.scope.environment().to_string();
        let mut tx = begin_scoped(self.store, self.scope).await?;
        // The approving human's SSO session rides on the grant this flow opened at
        // approval (grants.session_ref, the SAME column the code flow records it in),
        // so the device grant's ID token can carry the per-(client, session) `sid`
        // (issue #32). LEFT JOIN: a pending flow has no grant yet. `FOR UPDATE OF dc`
        // keeps the row lock on device_codes only (the joined grant is read-only here,
        // and an outer-joined row cannot be locked).
        let Some(row) = sqlx::query(
            "SELECT dc.id, dc.client_id, dc.subject, dc.grant_id, dc.requested_scope, \
             dc.auth_methods, dc.status, dc.interval_secs, g.session_ref, \
             (EXTRACT(EPOCH FROM dc.auth_time) * 1000000)::bigint AS auth_time_us, \
             (EXTRACT(EPOCH FROM dc.expires_at) * 1000000)::bigint AS expires_us, \
             (EXTRACT(EPOCH FROM dc.last_poll_at) * 1000000)::bigint AS last_poll_us \
             FROM device_codes dc \
             LEFT JOIN grants g \
             ON g.id = dc.grant_id AND g.tenant_id = dc.tenant_id \
             AND g.environment_id = dc.environment_id \
             WHERE dc.device_code_digest = $1 AND dc.tenant_id = $2 \
             AND dc.environment_id = $3 \
             FOR UPDATE OF dc",
        )
        .bind(&digest)
        .bind(&tenant)
        .bind(&environment)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(DevicePollOutcome::Unknown);
        };

        let status: String = row.get("status");
        let expires_us: i64 = row.get("expires_us");
        let interval_secs: i32 = row.get("interval_secs");
        let last_poll_us: Option<i64> = row.get("last_poll_us");

        // Expiry first (RFC 8628 3.5 expired_token). Mark it expired for hygiene
        // unless tokens were already issued (redeemed stays a plain invalid_grant).
        if expires_us <= now_micros {
            if status != "redeemed" && status != "expired" {
                sqlx::query(
                    "UPDATE device_codes SET status = 'expired' \
                     WHERE device_code_digest = $1 AND tenant_id = $2 AND environment_id = $3",
                )
                .bind(&digest)
                .bind(&tenant)
                .bind(&environment)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            return Ok(if status == "redeemed" {
                DevicePollOutcome::Unknown
            } else {
                DevicePollOutcome::Expired
            });
        }

        // slow_down enforcement (RFC 8628 3.5): a poll sooner than the current interval
        // increases the interval in place and returns slow_down, tracked per device_code.
        let interval_micros = i64::from(interval_secs).saturating_mul(1_000_000);
        let too_fast =
            last_poll_us.is_some_and(|last| now_micros.saturating_sub(last) < interval_micros);
        if too_fast {
            let new_interval = i64::from(interval_secs).saturating_add(slow_down_increment_secs);
            let new_interval_i32 = i32::try_from(new_interval).unwrap_or(i32::MAX);
            sqlx::query(
                "UPDATE device_codes SET interval_secs = $1, \
                 last_poll_at = TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval \
                 WHERE device_code_digest = $3 AND tenant_id = $4 AND environment_id = $5",
            )
            .bind(new_interval_i32)
            .bind(now_micros)
            .bind(&digest)
            .bind(&tenant)
            .bind(&environment)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(DevicePollOutcome::SlowDown {
                interval_secs: new_interval,
            });
        }

        // A well-paced poll: record it, then classify on status.
        sqlx::query(
            "UPDATE device_codes \
             SET last_poll_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
             WHERE device_code_digest = $2 AND tenant_id = $3 AND environment_id = $4",
        )
        .bind(now_micros)
        .bind(&digest)
        .bind(&tenant)
        .bind(&environment)
        .execute(&mut *tx)
        .await?;

        let outcome = match status.as_str() {
            "pending" => DevicePollOutcome::Pending,
            "denied" => DevicePollOutcome::Denied,
            "expired" => DevicePollOutcome::Expired,
            "approved" => approved_device_outcome(&row, &self.scope)?,
            // "redeemed" and anything unexpected: already spent or invalid.
            _ => DevicePollOutcome::Unknown,
        };
        tx.commit().await?;
        Ok(outcome)
    }
}

/// Build the [`DevicePollOutcome::Approved`] linkage from a polled `device_codes` row
/// (issue #24). An approved row missing its grant id is an inconsistent state, so it
/// fails closed to [`DevicePollOutcome::Unknown`] rather than minting against no grant.
fn approved_device_outcome(row: &PgRow, scope: &Scope) -> Result<DevicePollOutcome, StoreError> {
    let Some(grant_text) = row.get::<Option<String>, _>("grant_id") else {
        return Ok(DevicePollOutcome::Unknown);
    };
    let id_text: String = row.get("id");
    Ok(DevicePollOutcome::Approved(Box::new(ApprovedDeviceGrant {
        device_code_id: DeviceCodeId::parse_in_scope(&id_text, scope)?,
        grant_id: GrantId::parse_in_scope(&grant_text, scope)?,
        subject: row.get::<Option<String>, _>("subject").unwrap_or_default(),
        client_id: row.get("client_id"),
        requested_scope: row.get("requested_scope"),
        auth_methods: row
            .get::<Option<String>, _>("auth_methods")
            .unwrap_or_default(),
        auth_time_unix_micros: row.get("auth_time_us"),
        session_ref: row.get::<Option<String>, _>("session_ref"),
    })))
}

/// The mutating device-authorization repository (issue #24). Reachable only through
/// [`ScopedStore::acting`], so every business mutation carries an actor and
/// correlation id. Issue and deny route through the module's audited-write primitive;
/// approve and redeem are bespoke committing paths (they fold a status flip, the grant
/// or the issued-token rows, and their audit row into one transaction), documented at
/// their call sites.
pub struct ActingDeviceCodeRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingDeviceCodeRepo<'_> {
    /// Issue a device-authorization flow: INSERT the digest-only row and exactly one
    /// `device_code.issue` audit row in one transaction (issue #24).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if any supplied identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn issue(&self, env: &Env, new: NewDeviceCode<'_>) -> Result<(), StoreError> {
        if new.device_code_id.scope() != self.scope || new.client_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::DeviceCodeIssue,
                target: new.device_code_id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO device_codes \
                     (device_code_digest, tenant_id, environment_id, id, user_code_hash, \
                      client_id, requested_scope, status, interval_secs, failed_attempts, \
                      initiation_hint, expires_at, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, 0, $9, \
                             TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($11::text || ' microseconds')::interval)",
                )
                .bind(new.device_code_digest)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(new.device_code_id.to_string())
                .bind(new.user_code_hash)
                .bind(new.client_id.to_string())
                .bind(new.requested_scope)
                .bind(new.interval_secs)
                .bind(new.initiation_hint)
                .bind(new.expires_at_unix_micros)
                .bind(new.created_at_unix_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Approve a flow after an authenticated human's explicit confirmation (issue #24,
    /// RFC 8628 3.3). Atomically confirms the flow is still pending and unexpired, opens
    /// its grant (the revocation spine the tokens hang off), flips it to `approved` with
    /// the subject / grant / consent / auth-context linkage, and writes exactly one
    /// `device_code.approve` audit row, all in one transaction. A flow that is no longer
    /// pending is a clean [`DeviceApproveOutcome::NotApprovable`] (nothing is written).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the flow or the grant id is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn approve(
        &self,
        env: &Env,
        approval: DeviceApproval<'_>,
    ) -> Result<DeviceApproveOutcome, StoreError> {
        if approval.device_code_id.scope() != self.scope || approval.grant_id.scope() != self.scope
        {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let tenant = scope.tenant().to_string();
        let environment = scope.environment().to_string();
        let mut tx = begin_scoped(self.store, scope).await?;
        // Lock the row and confirm it is still approvable.
        let Some(row) = sqlx::query(
            "SELECT client_id, status, \
             (EXTRACT(EPOCH FROM expires_at) * 1000000)::bigint AS expires_us \
             FROM device_codes \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 FOR UPDATE",
        )
        .bind(approval.device_code_id.to_string())
        .bind(&tenant)
        .bind(&environment)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(DeviceApproveOutcome::NotApprovable);
        };
        let status: String = row.get("status");
        let expires_us: i64 = row.get("expires_us");
        if status != "pending" || expires_us <= approval.now_unix_micros {
            tx.commit().await?;
            return Ok(DeviceApproveOutcome::NotApprovable);
        }
        let client_id: String = row.get("client_id");
        // Open the grant BEFORE the device_codes.grant_id write (the composite FK
        // requires the grant to exist first).
        sqlx::query(
            "INSERT INTO grants \
             (id, tenant_id, environment_id, client_id, subject, session_ref, consent_ref, \
              claims_request, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, \
                     TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval)",
        )
        .bind(approval.grant_id.to_string())
        .bind(&tenant)
        .bind(&environment)
        .bind(&client_id)
        .bind(approval.subject)
        .bind(approval.session_ref)
        .bind(approval.consent_ref)
        .bind(approval.created_at_unix_micros)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE device_codes \
             SET status = 'approved', subject = $1, grant_id = $2, consent_ref = $3, \
                 auth_methods = $4, \
                 auth_time = CASE WHEN $5::bigint IS NULL THEN NULL \
                                  ELSE TIMESTAMPTZ 'epoch' \
                                       + ($5::text || ' microseconds')::interval END \
             WHERE id = $6 AND tenant_id = $7 AND environment_id = $8",
        )
        .bind(approval.subject)
        .bind(approval.grant_id.to_string())
        .bind(approval.consent_ref)
        .bind(approval.auth_methods)
        .bind(approval.auth_time_unix_micros)
        .bind(approval.device_code_id.to_string())
        .bind(&tenant)
        .bind(&environment)
        .execute(&mut *tx)
        .await?;
        let spec = AuditedWrite {
            store: self.store,
            scope,
            acting: &self.acting,
            env,
            action: Action::DeviceCodeApprove,
            target: approval.device_code_id,
        };
        insert_audit_row(&mut tx, &spec, None).await?;
        tx.commit().await?;
        Ok(DeviceApproveOutcome::Approved)
    }

    /// Deny a pending flow (issue #24, RFC 8628 3.5): flip it to `denied` and write one
    /// `device_code.deny` audit row in the same transaction. Idempotent (a non-pending
    /// flow is left as is), so a double-deny is a benign no-op.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the flow id is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn deny(&self, env: &Env, device_code_id: &DeviceCodeId) -> Result<(), StoreError> {
        if device_code_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::DeviceCodeDeny,
                target: device_code_id,
            },
            async move |tx| {
                sqlx::query(
                    "UPDATE device_codes SET status = 'denied' \
                     WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND status = 'pending'",
                )
                .bind(device_code_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Atomically redeem an approved flow at the token endpoint (issue #24), the
    /// single-use gate. The caller has already PRE-SIGNED `tokens` (and, for an opaque
    /// access token, `opaque`) against the approved flow, exactly as the code grant
    /// pre-signs before its consume, so a signing failure never burns the flow. This
    /// flips `approved -> redeemed` in one statement: the winner records the issued
    /// tokens (and the opaque row) plus one `token.issue` audit row in the SAME
    /// transaction and returns [`DeviceRedeemOutcome::Redeemed`]; a zero-row flip
    /// (already redeemed, or a concurrent poll won) drops the pre-signed tokens and
    /// returns [`DeviceRedeemOutcome::NotApprovable`], so a device code issues tokens at
    /// most once.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if any identifier is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn redeem_approved(
        &self,
        env: &Env,
        device_code_id: &DeviceCodeId,
        grant_id: &GrantId,
        tokens: &[IssuedTokenRecord],
        opaque: Option<NewOpaqueAccessToken<'_>>,
    ) -> Result<DeviceRedeemOutcome, StoreError> {
        if device_code_id.scope() != self.scope
            || grant_id.scope() != self.scope
            || tokens.iter().any(|token| token.id.scope() != self.scope)
        {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let tenant = scope.tenant().to_string();
        let environment = scope.environment().to_string();
        let mut tx = begin_scoped(self.store, scope).await?;
        let flipped = sqlx::query(
            "UPDATE device_codes SET status = 'redeemed' \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND status = 'approved' \
             RETURNING id",
        )
        .bind(device_code_id.to_string())
        .bind(&tenant)
        .bind(&environment)
        .fetch_optional(&mut *tx)
        .await?;
        if flipped.is_none() {
            tx.commit().await?;
            return Ok(DeviceRedeemOutcome::NotApprovable);
        }
        for token in tokens {
            sqlx::query(
                "INSERT INTO issued_tokens \
                 (id, tenant_id, environment_id, grant_id, token_kind) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(token.id.to_string())
            .bind(&tenant)
            .bind(&environment)
            .bind(grant_id.to_string())
            .bind(token.kind.as_str())
            .execute(&mut *tx)
            .await?;
        }
        if let Some(op) = opaque {
            sqlx::query(
                "INSERT INTO opaque_access_tokens \
                 (token_digest, tenant_id, environment_id, grant_id, subject, client_id, \
                  audience, scope, jti, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                         TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval)",
            )
            .bind(op.token_digest)
            .bind(&tenant)
            .bind(&environment)
            .bind(grant_id.to_string())
            .bind(op.subject)
            .bind(op.client_id)
            .bind(op.audience)
            .bind(op.scope)
            .bind(op.jti.to_string())
            .bind(op.expires_at_unix_micros)
            .execute(&mut *tx)
            .await?;
        }
        let spec = AuditedWrite {
            store: self.store,
            scope,
            acting: &self.acting,
            env,
            action: Action::TokenIssue,
            target: grant_id,
        };
        insert_audit_row(&mut tx, &spec, None).await?;
        tx.commit().await?;
        Ok(DeviceRedeemOutcome::Redeemed)
    }
}

/// Begin a transaction with the scope's row-level-security variables bound
/// transaction-locally. Every scoped operation flows through here, so no
/// statement runs without the policy variables in place.
async fn begin_scoped(
    store: &Store,
    scope: Scope,
) -> Result<Transaction<'_, Postgres>, StoreError> {
    let mut tx = store.pool().begin().await?;
    // Pin READ COMMITTED explicitly rather than trusting the server/role default.
    // The single-use redeem depends on it: a losing concurrent writer must BLOCK
    // on the code's row lock and then re-read the committed `consumed_at` (seeing
    // zero rows), not abort with a 40001 serialization error the way REPEATABLE
    // READ or SERIALIZABLE would. Every scoped statement is a short scope-filtered
    // read or a single-row write, so READ COMMITTED is also the correct isolation
    // for the rest of the module. SET TRANSACTION must be the first statement, so
    // it runs before the row-level-security set_config calls below.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    // set_config(name, value, is_local=true): parameterized and reset at
    // transaction end. SET LOCAL cannot take a bind parameter, so this is the
    // injection-safe form.
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Everything the audited-write primitive needs besides the mutation itself:
/// the connection, the scope, the acting context, the clock/entropy seam, and
/// the envelope's action and typed target. The target is any [`AuditTarget`], so
/// a management mutation on a level table (a tenant, an environment) audits
/// through the same primitive as a scoped-resource mutation.
struct AuditedWrite<'a, T: AuditTarget> {
    store: &'a Store,
    scope: Scope,
    acting: &'a ActingContext,
    env: &'a Env,
    action: Action,
    target: &'a T,
}

/// The single committing write path: perform a data mutation and its audit row
/// in one scoped transaction, then commit.
///
/// This is the whole enforcement mechanism. `mutate` runs the caller's data
/// change; [`insert_audit_row`] appends exactly one audit row in the same
/// transaction; only then does the transaction commit. If `mutate` fails, the
/// audit row is never written and nothing commits; if the audit insert fails,
/// the data change never commits. This is the single committing write path in
/// the module, so a mutation without its audit row cannot be committed off it
/// (the module boundary that protects that invariant is described on the module
/// documentation).
///
/// `poison_after_audit` is `false` on every production path; the testing
/// atomicity probe sets it to force a guaranteed in-transaction failure after
/// both inserts, to demonstrate they roll back together.
async fn write_audited<T, M>(
    spec: AuditedWrite<'_, T>,
    mutate: M,
    poison_after_audit: bool,
) -> Result<(), StoreError>
where
    T: AuditTarget,
    M: AsyncFnOnce(&mut Transaction<'_, Postgres>) -> Result<(), StoreError>,
{
    // The overwhelming majority of audited writes carry no detail dimension.
    write_audited_detailed(spec, mutate, poison_after_audit, None).await
}

/// Like [`write_audited`] but records an OPERATOR-SAFE `detail` dimension on the
/// audit row (issue #31): the offending policy property on a DCR abuse event, so an
/// operator working from the audit table alone gets the actionable reason. `detail`
/// is never attacker-controlled free text. Every other audited write goes through
/// [`write_audited`] with no detail, so this is the only path that sets it.
async fn write_audited_detailed<T, M>(
    spec: AuditedWrite<'_, T>,
    mutate: M,
    poison_after_audit: bool,
    detail: Option<&str>,
) -> Result<(), StoreError>
where
    T: AuditTarget,
    M: AsyncFnOnce(&mut Transaction<'_, Postgres>) -> Result<(), StoreError>,
{
    let mut tx = begin_scoped(spec.store, spec.scope).await?;
    // The data change and the audit row share this one transaction.
    mutate(&mut tx).await?;
    insert_audit_row(&mut tx, &spec, detail).await?;
    if poison_after_audit {
        // Testing seam only (production callers pass false): force a guaranteed
        // error after both inserts are staged, so their joint rollback proves
        // the data change and the audit row are in the same transaction.
        sqlx::query("SELECT 1 / 0").execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Insert exactly one audit row into the current transaction, after the data change
/// and before the commit. Called by [`write_audited_detailed`] and by the few custom
/// write paths that inline their own audited transaction.
///
/// `detail` is an OPTIONAL, operator-safe dimension (NULL for almost every write):
/// the offending policy property on a DCR abuse event (issue #31). It is never
/// attacker-controlled free text, so it is safe to persist and read back.
async fn insert_audit_row<T: AuditTarget>(
    tx: &mut Transaction<'_, Postgres>,
    spec: &AuditedWrite<'_, T>,
    detail: Option<&str>,
) -> Result<(), StoreError> {
    let audit_id = AuditId::generate(spec.env, &spec.scope);
    // Event time from the application clock seam, never the database clock, so
    // it is deterministic under a manual clock in tests. Bound as microseconds
    // since the epoch and reconstructed exactly as a timestamptz in SQL.
    let occurred_micros = epoch_micros(spec.env.clock().now_utc());
    let actor = spec.acting.actor();
    sqlx::query(
        "INSERT INTO audit_log \
         (id, tenant_id, environment_id, action, actor_kind, actor_id, \
          target_kind, target_id, correlation_id, occurred_at, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval, $11)",
    )
    .bind(audit_id.to_string())
    .bind(spec.scope.tenant().to_string())
    .bind(spec.scope.environment().to_string())
    .bind(spec.action.as_str())
    .bind(actor.kind_str())
    .bind(actor.id_string())
    .bind(spec.target.audit_target_kind())
    .bind(spec.target.audit_target_id())
    .bind(spec.acting.correlation().to_string())
    .bind(occurred_micros)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Microseconds since the Unix epoch for a wall-clock instant. Negative for
/// pre-epoch times (never reached in practice; kept total for safety).
fn epoch_micros(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_micros()).map_or(i64::MIN, |micros| -micros)
        }
    }
}

// ===========================================================================
// Management (control) plane (issue #11).
//
// The management API mutates the operator, tenant, and environment LEVEL tables
// the data-plane role cannot see, plus the environment-scoped
// `management_credentials` table. Everything below routes through the SAME
// `write_audited` primitive, so every management mutation writes its audit row
// in the same transaction as the data change; a management mutation without its
// audit row is as structurally impossible as a data-plane one.
//
// These repositories are reached only through [`Store::management`], whose pool
// must authenticate as `ironauth_control`. The data-plane [`Store::scoped`] and
// its pool stay entirely separate: control-plane credentials are a distinct
// class from data-plane keys, made real at the pool boundary.
// ===========================================================================

/// The maximum number of rows a management list query returns to the caller in
/// one page. The management API caps the caller-supplied page size below this;
/// this is a last-resort ceiling so an internal caller cannot ask for an
/// unbounded scan. Keep this equal to `ironauth_config::MANAGEMENT_LIST_HARD_CAP`
/// (a cross-crate test in `ironauth-admin` pins the two together).
///
/// The list queries clamp the fetch to `HARD_CAP + 1`, not `HARD_CAP`: the
/// pagination layer over-fetches one extra row as a has-next sentinel, so
/// clamping to `HARD_CAP` exactly would drop that sentinel at a full page and
/// hide the final page. The caller-facing page is still bounded to `HARD_CAP`
/// because the admin layer trims the returned rows to the page size.
///
/// Pagination read-back note: the `(created_at, id)` keyset cursor round-trips
/// `created_at` through `EXTRACT(EPOCH FROM created_at)`, which is exact only on
/// PostgreSQL 14+ (there it returns `numeric`; older versions return `double
/// precision` and can round by +/- 1 microsecond). CI runs PostgreSQL 16, so
/// exact cursor pagination requires PostgreSQL 14+ at deployment.
pub const MANAGEMENT_LIST_HARD_CAP: i64 = 1000;

/// A cursor position for keyset pagination: the `(created_at, id)` of the last
/// row of the previous page. Ordering is by `created_at` then `id`, both stable
/// and total, so paging never loses or duplicates a row.
#[derive(Debug, Clone)]
pub struct CursorPosition {
    /// The `created_at` of the last row of the previous page, in microseconds
    /// since the Unix epoch.
    pub created_at_unix_micros: i64,
    /// The identifier of the last row of the previous page, in wire form.
    pub id: String,
}

/// The original response stored under an Idempotency-Key, replayed verbatim when
/// the same key is presented again so the mutation never runs twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdempotentResponse {
    /// Hash of the original request (method, path, body). A replay whose request
    /// fingerprint differs is a key reused for a different operation.
    pub request_fingerprint: String,
    /// The original HTTP status code.
    pub response_status: u16,
    /// The original response body, replayed byte for byte.
    pub response_body: String,
}

/// A pending Idempotency-Key record, written in the same transaction as the
/// mutation it guards so a stored response and its side effects commit together.
#[derive(Debug, Clone, Copy)]
pub struct IdempotencyWrite<'a> {
    /// The acting credential's audit-actor id (the isolation key here).
    pub credential_ref: &'a str,
    /// The client-supplied Idempotency-Key header value.
    pub key: &'a str,
    /// Hash of the request (method, path, body).
    pub request_fingerprint: &'a str,
    /// The status the caller is about to return.
    pub response_status: u16,
    /// The body the caller is about to return, stored for verbatim replay.
    pub response_body: &'a str,
}

/// A tenant row (management plane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRecord {
    /// The tenant identifier.
    pub id: TenantId,
    /// The operator that owns the tenant.
    pub operator_id: OperatorId,
    /// The human-facing display name.
    pub display_name: String,
    /// The lifecycle status (issue #46): `Active` or `Suspended`. A live tenant is
    /// always one of the two (a deleted tenant is not returned at all).
    pub status: TenantStatus,
    /// The recorded data-residency region (issue #46), or `None` when the
    /// deployment pins no region. Immutable after create; nothing routes by it yet.
    pub home_region: Option<String>,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// A tenant's lifecycle status (issue #46).
///
/// The reversible run-state of a live tenant. It is DISTINCT from deletion: a
/// deleted (offboarded) tenant is a tombstone the reads never return, while a
/// [`TenantStatus::Suspended`] tenant is live, keeps all its data, stays visible to
/// the control plane, and is merely FENCED off the data plane until it is resumed.
/// The valid transitions (active <-> suspended, and either into deletion) are
/// enforced by [`ActingTenantRepo`]; this type only names the two live states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    /// The tenant serves its data plane normally.
    Active,
    /// The tenant is suspended: its data plane is fenced (a structured refusal),
    /// its data is intact, and a resume restores service with no data loss.
    Suspended,
}

impl TenantStatus {
    /// The stable wire string stored in `tenants.status`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
        }
    }

    /// Parse a stored status string. An unrecognized value decodes to `None`
    /// (a corrupt row surfaces as a decode error rather than a silent default).
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(TenantStatus::Active),
            "suspended" => Some(TenantStatus::Suspended),
            _ => None,
        }
    }
}

/// A `(tenant, environment)`'s data-plane serving state (issue #46).
///
/// The data plane reads this (under its own row-level-security scope) to decide
/// whether to serve or fence a scope. It mirrors the tenant lifecycle onto a
/// scoped, data-plane-readable row because the data-plane role cannot read the
/// control-plane tenant/environment level tables. A scope with no stored row reads
/// as [`EnvironmentServingState::Active`] (the safe default: an environment
/// provisioned before this state existed serves normally).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentServingState {
    /// The data plane serves this scope.
    Active,
    /// The data plane fences this scope (a suspended or offboarded tenant).
    Suspended,
}

impl EnvironmentServingState {
    /// Whether the data plane must fence this scope (refuse to serve it).
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        matches!(self, EnvironmentServingState::Suspended)
    }
}

/// An environment row (management plane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentRecord {
    /// The environment identifier.
    pub id: EnvironmentId,
    /// The tenant the environment belongs to.
    pub tenant_id: TenantId,
    /// The human-facing display name.
    pub display_name: String,
    /// The environment's typed kind (dev, staging, or prod), driving its
    /// guardrail class (issue #42).
    pub kind: EnvironmentType,
    /// The configured custom domain, if any. Absent (`None`) when none is
    /// configured; a production environment always has one (the custom-domain
    /// guardrail).
    pub custom_domain: Option<String>,
    /// The recorded per-environment data-residency region pin (issue #46), or
    /// `None` when the environment pins no region. Immutable after create; nothing
    /// routes by it yet.
    pub region: Option<String>,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// The typed attributes of an environment to create (issue #42): its display
/// name, its kind (which drives its guardrail class), and its optional configured
/// custom domain. The management API validates the kind and the guardrails before
/// building this; the store persists it verbatim.
#[derive(Debug, Clone, Copy)]
pub struct NewEnvironment<'a> {
    /// The human-facing display name.
    pub display_name: &'a str,
    /// The environment's typed kind (dev, staging, or prod).
    pub kind: EnvironmentType,
    /// The configured custom domain, if any (a production environment always has
    /// one; the guardrail is enforced before this struct is built).
    pub custom_domain: Option<&'a str>,
    /// The recorded per-environment data-residency region pin (issue #46), or
    /// `None` when the environment pins no region. Validated against the operator's
    /// configured region set at the API layer; immutable after create.
    pub region: Option<&'a str>,
}

/// A management API key row (metadata only; the secret is never stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementCredentialRecord {
    /// The key identifier (embeds its `(tenant, environment)` scope).
    pub id: ManagementKeyId,
    /// The human-facing display name.
    pub display_name: String,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// An operator row: the platform deployment root, above every tenant (issue #41).
/// The operator plane carries no tenant or environment, so its identifier embeds
/// neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorRecord {
    /// The operator identifier (`op_...`, embeds neither tenant nor environment).
    pub id: OperatorId,
    /// The human-facing display name.
    pub display_name: String,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// An organization row (management plane, issue #41): the minimal M5 shell.
/// Organizations live inside environments, so the identifier embeds both the
/// tenant and the environment. M10 extends this shell with membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationRecord {
    /// The organization identifier (`org_...`, embeds its `(tenant, environment)`).
    pub id: OrganizationId,
    /// The human-facing display name.
    pub display_name: String,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// The control-plane entry point: reads and the acting door for writes.
///
/// Reached through [`Store::management`]. Its pool must authenticate as
/// `ironauth_control`.
pub struct ManagementStore<'a> {
    store: &'a Store,
}

impl<'a> ManagementStore<'a> {
    /// Bind the control plane to a store. Crate-internal: callers reach this
    /// only through [`Store::management`].
    pub(crate) fn new(store: &'a Store) -> Self {
        Self { store }
    }

    /// The read-only tenant repository under `operator`.
    #[must_use]
    pub fn tenants(&self, operator: OperatorId) -> TenantRepo<'a> {
        TenantRepo {
            store: self.store,
            operator,
        }
    }

    /// The read-only operator repository. The operator plane is the root of the
    /// four-level model (issue #41); it is not tenant-scoped, so it carries no
    /// scope argument.
    #[must_use]
    pub fn operators(&self) -> OperatorRepo<'a> {
        OperatorRepo { store: self.store }
    }

    /// The read-only environment repository under `tenant`.
    #[must_use]
    pub fn environments(&self, tenant: TenantId) -> EnvironmentRepo<'a> {
        EnvironmentRepo {
            store: self.store,
            tenant,
        }
    }

    /// The read-only organization repository for `scope` (issue #41).
    /// Organizations are environment-scoped, so the repository is constructible
    /// only from a `(tenant, environment)` scope and binds row-level security to
    /// it before every statement.
    #[must_use]
    pub fn organizations(&self, scope: Scope) -> OrganizationRepo<'a> {
        OrganizationRepo {
            store: self.store,
            scope,
        }
    }

    /// List every `(tenant, environment)` scope known to the control plane (issue #34):
    /// the set a per-scope background worker (the back-channel logout delivery worker)
    /// iterates to drain each scope's queue. Requires the control-plane role (it reads
    /// the non-RLS `environments` table the data-plane role cannot see), so it belongs on
    /// the management surface, not the scoped store. Rows whose stored identifiers do not
    /// parse are skipped (defense in depth against a corrupt row).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence fault.
    pub async fn list_environment_scopes(&self) -> Result<Vec<Scope>, StoreError> {
        let rows = sqlx::query("SELECT id, tenant_id FROM environments ORDER BY tenant_id, id")
            .fetch_all(self.store.pool())
            .await?;
        let mut scopes = Vec::with_capacity(rows.len());
        for row in &rows {
            let environment_text: String = row.get("id");
            let tenant_text: String = row.get("tenant_id");
            let (Ok(tenant), Ok(environment)) = (
                TenantId::parse(&tenant_text),
                EnvironmentId::parse(&environment_text),
            ) else {
                continue;
            };
            scopes.push(Scope::new(tenant, environment));
        }
        Ok(scopes)
    }

    /// The read-only management-credential repository for `scope`.
    #[must_use]
    pub fn credentials(&self, scope: Scope) -> ManagementCredentialRepo<'a> {
        ManagementCredentialRepo {
            store: self.store,
            scope,
        }
    }

    /// The idempotency replay store (credential-scoped).
    #[must_use]
    pub fn idempotency(&self) -> IdempotencyRepo<'a> {
        IdempotencyRepo { store: self.store }
    }

    /// Enter an acting context for management writes. Every mutation reached
    /// through the returned store carries an actor and correlation id into its
    /// audit row.
    #[must_use]
    pub fn acting(&self, actor: ActorRef, correlation: CorrelationId) -> ActingManagementStore<'a> {
        ActingManagementStore {
            store: self.store,
            acting: ActingContext::new(actor, correlation),
        }
    }
}

/// The acting door to the mutating management repositories.
pub struct ActingManagementStore<'a> {
    store: &'a Store,
    acting: ActingContext,
}

impl<'a> ActingManagementStore<'a> {
    /// The mutating tenant repository under `operator`.
    #[must_use]
    pub fn tenants(&self, operator: OperatorId) -> ActingTenantRepo<'a> {
        ActingTenantRepo {
            store: self.store,
            acting: self.acting,
            operator,
        }
    }

    /// The mutating environment repository under `tenant`.
    #[must_use]
    pub fn environments(&self, tenant: TenantId) -> ActingEnvironmentRepo<'a> {
        ActingEnvironmentRepo {
            store: self.store,
            acting: self.acting,
            tenant,
        }
    }

    /// The mutating management-credential repository for `scope`.
    #[must_use]
    pub fn credentials(&self, scope: Scope) -> ActingManagementCredentialRepo<'a> {
        ActingManagementCredentialRepo {
            store: self.store,
            acting: self.acting,
            scope,
        }
    }

    /// The mutating organization repository for `scope` (issue #41).
    #[must_use]
    pub fn organizations(&self, scope: Scope) -> ActingOrganizationRepo<'a> {
        ActingOrganizationRepo {
            store: self.store,
            acting: self.acting,
            scope,
        }
    }
}

/// Read-only tenants under one operator.
pub struct TenantRepo<'a> {
    store: &'a Store,
    operator: OperatorId,
}

impl TenantRepo<'_> {
    /// Parse an untrusted tenant identifier. A malformed identifier is the
    /// uniform not-found, exactly like an absent one.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed.
    pub fn parse_id(&self, raw: &str) -> Result<TenantId, StoreError> {
        TenantId::parse(raw).map_err(|_| StoreError::NotFound)
    }

    /// Fetch a live tenant under this operator.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such live tenant exists under this operator
    /// (absent, deactivated, or owned by another operator: indistinguishable).
    pub async fn get(&self, id: &TenantId) -> Result<TenantRecord, StoreError> {
        let row = sqlx::query(
            "SELECT id, operator_id, display_name, status, home_region, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM tenants \
             WHERE id = $1 AND operator_id = $2 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.operator.to_string())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(StoreError::NotFound)?;
        tenant_from_row(&row)
    }

    /// One page of live tenants under this operator, ordered by `(created_at,
    /// id)`. Returns up to `limit` rows starting strictly after `after`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<TenantRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let rows = sqlx::query(
            "SELECT id, operator_id, display_name, status, home_region, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM tenants \
             WHERE operator_id = $1 AND deleted_at IS NULL \
             AND ($2::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval, $3::text)) \
             ORDER BY created_at, id LIMIT $4",
        )
        .bind(self.operator.to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(self.store.pool())
        .await?;
        rows.iter().map(tenant_from_row).collect()
    }
}

/// Read-only environments under one tenant.
pub struct EnvironmentRepo<'a> {
    store: &'a Store,
    tenant: TenantId,
}

impl EnvironmentRepo<'_> {
    /// Parse an untrusted environment identifier. A malformed identifier is the
    /// uniform not-found, exactly like an absent or cross-tenant one.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed.
    pub fn parse_id(&self, raw: &str) -> Result<EnvironmentId, StoreError> {
        EnvironmentId::parse(raw).map_err(|_| StoreError::NotFound)
    }

    /// Fetch a live environment under this tenant. An environment of ANOTHER
    /// tenant is the uniform not-found (the tenant filter is the anti-oracle).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such live environment exists under this
    /// tenant.
    pub async fn get(&self, id: &EnvironmentId) -> Result<EnvironmentRecord, StoreError> {
        let row = sqlx::query(
            "SELECT id, tenant_id, display_name, kind, custom_domain, region, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM environments \
             WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.tenant.to_string())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(StoreError::NotFound)?;
        environment_from_row(&row)
    }

    /// One page of live environments under this tenant, ordered by `(created_at,
    /// id)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<EnvironmentRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let rows = sqlx::query(
            "SELECT id, tenant_id, display_name, kind, custom_domain, region, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM environments \
             WHERE tenant_id = $1 AND deleted_at IS NULL \
             AND ($2::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval, $3::text)) \
             ORDER BY created_at, id LIMIT $4",
        )
        .bind(self.tenant.to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(self.store.pool())
        .await?;
        rows.iter().map(environment_from_row).collect()
    }
}

/// Read-only operators (the operator plane, issue #41).
///
/// The operator plane is the root of the four-level model and is not
/// tenant-scoped: operators carry no row-level security (they are a LEVEL table,
/// like tenants and environments), and their identifiers embed neither a tenant
/// nor an environment.
pub struct OperatorRepo<'a> {
    store: &'a Store,
}

impl OperatorRepo<'_> {
    /// Parse an untrusted operator identifier. A malformed identifier is the
    /// uniform not-found, exactly like an absent one.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed.
    pub fn parse_id(&self, raw: &str) -> Result<OperatorId, StoreError> {
        OperatorId::parse(raw).map_err(|_| StoreError::NotFound)
    }

    /// Fetch one operator by id.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such operator exists.
    pub async fn get(&self, id: &OperatorId) -> Result<OperatorRecord, StoreError> {
        let row = sqlx::query(
            "SELECT id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM operators WHERE id = $1",
        )
        .bind(id.to_string())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(StoreError::NotFound)?;
        operator_from_row(&row)
    }

    /// One page of operators, ordered by `(created_at, id)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<OperatorRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let rows = sqlx::query(
            "SELECT id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM operators \
             WHERE ($1::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, $2::text)) \
             ORDER BY created_at, id LIMIT $3",
        )
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(self.store.pool())
        .await?;
        rows.iter().map(operator_from_row).collect()
    }
}

/// Read-only organizations for one scope (issue #41).
///
/// Organizations live inside environments, so this repository is constructible
/// only from a `(tenant, environment)` scope, binds forced row-level security to
/// it before every statement, and an organization of ANOTHER scope is the
/// uniform not-found (the scope filter is the anti-oracle). The typed
/// [`OrganizationId`] embeds its scope, so a cross-scope id fails to parse in
/// scope before any query runs.
pub struct OrganizationRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl OrganizationRepo<'_> {
    /// Parse an untrusted organization identifier under this scope. A malformed
    /// identifier and one minted in another scope both return the uniform
    /// not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<OrganizationId, StoreError> {
        Ok(OrganizationId::parse_in_scope(raw, &self.scope)?)
    }

    /// Fetch a live organization by id, within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such live organization is visible in this
    /// scope.
    pub async fn get(&self, id: &OrganizationId) -> Result<OrganizationRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM organizations \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        organization_from_row(&row, &self.scope)
    }

    /// One page of live organizations in this scope, ordered by `(created_at,
    /// id)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<OrganizationRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM organizations \
             WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NULL \
             AND ($3::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4::text)) \
             ORDER BY created_at, id LIMIT $5",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| organization_from_row(row, &self.scope))
            .collect()
    }
}

/// Read-only management credentials for one scope.
pub struct ManagementCredentialRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ManagementCredentialRepo<'_> {
    /// Parse an untrusted management-key identifier under this scope. A malformed
    /// identifier and one minted in another scope both return the uniform
    /// not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<ManagementKeyId, StoreError> {
        Ok(ManagementKeyId::parse_in_scope(raw, &self.scope)?)
    }

    /// Fetch a live management key by id, within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such live key is visible in this scope.
    pub async fn get(
        &self,
        id: &ManagementKeyId,
    ) -> Result<ManagementCredentialRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM management_credentials \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        credential_from_row(&row, &self.scope)
    }

    /// One page of live management keys in this scope, ordered by `(created_at,
    /// id)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<ManagementCredentialRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM management_credentials \
             WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NULL \
             AND ($3::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4::text)) \
             ORDER BY created_at, id LIMIT $5",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| credential_from_row(row, &self.scope))
            .collect()
    }

    /// Whether a live key with `id` and this exact `key_hash` exists in scope,
    /// AND its environment and tenant are both live. The authentication
    /// primitive: the caller has already recovered the scope from the presented
    /// token's id half, so this look-up runs within it.
    ///
    /// The joins to `environments` and `tenants` are defense in depth on the
    /// security-critical path: a soft-deleted tenant or environment cascades a
    /// `deleted_at` onto its keys, but joining here additionally rejects a key
    /// whose parent is soft-deleted regardless of the cascade, closing any
    /// create-after-delete or ordering race. Both level tables are unscoped, so
    /// the join sees them even under the credential's row-level-security scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn authenticate(
        &self,
        id: &ManagementKeyId,
        key_hash: &str,
    ) -> Result<bool, StoreError> {
        if id.scope() != self.scope {
            return Ok(false);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT 1 AS ok FROM management_credentials mc \
             JOIN environments e ON e.id = mc.environment_id AND e.tenant_id = mc.tenant_id \
             JOIN tenants t ON t.id = mc.tenant_id \
             WHERE mc.id = $1 AND mc.tenant_id = $2 AND mc.environment_id = $3 \
             AND mc.key_hash = $4 AND mc.deleted_at IS NULL \
             AND e.deleted_at IS NULL AND t.deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(key_hash)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.is_some())
    }
}

/// The idempotency replay store (credential-scoped). See the migration for why
/// isolation here is by credential rather than tenant row-level security.
pub struct IdempotencyRepo<'a> {
    store: &'a Store,
}

impl IdempotencyRepo<'_> {
    /// Look up a stored response for `(credential_ref, key)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn lookup(
        &self,
        credential_ref: &str,
        key: &str,
    ) -> Result<Option<StoredIdempotentResponse>, StoreError> {
        let row = sqlx::query(
            "SELECT request_fingerprint, response_status, response_body \
             FROM idempotency_keys \
             WHERE credential_ref = $1 AND idempotency_key = $2",
        )
        .bind(credential_ref)
        .bind(key)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row.map(|row| {
            let status: i32 = row.get("response_status");
            StoredIdempotentResponse {
                request_fingerprint: row.get("request_fingerprint"),
                response_status: u16::try_from(status).unwrap_or(500),
                response_body: row.get("response_body"),
            }
        }))
    }
}

/// Mutating tenants under one operator.
pub struct ActingTenantRepo<'a> {
    store: &'a Store,
    acting: ActingContext,
    operator: OperatorId,
}

impl ActingTenantRepo<'_> {
    /// Create a tenant and its first environment in one transaction, and audit
    /// the creation scoped to `(new_tenant, new_first_environment)`.
    ///
    /// The operator-plane audit wrinkle: an operator-plane "create tenant" has no
    /// pre-existing `(tenant, environment)` scope to key the audit row on. It is
    /// resolved exactly as the design mandates: the tenant AND its first
    /// environment are created in the same transaction, then the audit row is
    /// written scoped to that fresh `(tenant, environment)` pair (both rows exist
    /// by the time the audit insert runs, so its foreign keys and the row-level
    /// security check are satisfied). The bootstrap operator row is ensured
    /// idempotently in the same transaction (platform self-bootstrap, not a
    /// caller mutation, so it is not itself audited).
    ///
    /// The identifiers are supplied by the caller (minted from the entropy seam)
    /// so the HTTP response can be built before the write and stored verbatim for
    /// idempotent replay.
    ///
    /// # Errors
    ///
    /// [`StoreError::IdempotencyConflict`] if a concurrent request already stored
    /// this Idempotency-Key; [`StoreError::Database`] on a persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        env: &Env,
        tenant_id: &TenantId,
        environment_id: &EnvironmentId,
        created_at_micros: i64,
        operator_display_name: &str,
        tenant_display_name: &str,
        environment: NewEnvironment<'_>,
        home_region: Option<&str>,
        signing_key: NewSigningKey<'_>,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let scope = Scope::new(*tenant_id, *environment_id);
        if signing_key.id.scope() != scope {
            return Err(StoreError::NotFound);
        }
        let operator = self.operator;
        let home_region = home_region.map(str::to_owned);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TenantCreate,
                target: tenant_id,
            },
            async move |tx| {
                // Ensure the (well-known) bootstrap operator exists so the tenant
                // foreign key resolves. Idempotent and not audited: this is the
                // platform bootstrapping itself, like a migration, not a
                // caller-visible mutation.
                sqlx::query(
                    "INSERT INTO operators (id, display_name) VALUES ($1, $2) \
                     ON CONFLICT (id) DO NOTHING",
                )
                .bind(operator.to_string())
                .bind(operator_display_name)
                .execute(&mut **tx)
                .await?;
                // created_at is bound from the application clock seam (not the
                // database clock), so the response body built before the write
                // matches the stored row exactly and paging stays deterministic
                // under a manual clock in tests.
                // The tenant lands 'active' (the column default) with its recorded
                // home_region (issue #46). home_region is bound here on create and
                // never updated after, so it is immutable for the tenant's life.
                sqlx::query(
                    "INSERT INTO tenants (id, operator_id, display_name, home_region, created_at) \
                     VALUES ($1, $2, $3, $4, \
                             TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval)",
                )
                .bind(tenant_id.to_string())
                .bind(operator.to_string())
                .bind(tenant_display_name)
                .bind(home_region.as_deref())
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                sqlx::query(
                    "INSERT INTO environments \
                     (id, tenant_id, display_name, kind, custom_domain, region, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
                )
                .bind(environment_id.to_string())
                .bind(tenant_id.to_string())
                .bind(environment.display_name)
                .bind(environment.kind.as_str())
                .bind(environment.custom_domain)
                .bind(environment.region)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                // Provision the environment's day-one signing key in the SAME
                // transaction (issue #42): the (tenant, environment) scope is
                // already bound (this audited write is scoped to the new pair), so
                // the row-level-security policy on signing_keys is satisfied. The
                // key is the environment's own identity, so a fresh environment
                // serves discovery with its own issuer and disjoint JWKS at once.
                insert_signing_key_row(tx, &scope, &signing_key).await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Suspend a live, ACTIVE tenant (issue #46): flip its status to `suspended`
    /// and FENCE its data plane by marking every one of its environments'
    /// serving state suspended, in one audited transaction. Reversible with
    /// [`ActingTenantRepo::resume`], with no data loss.
    ///
    /// State machine: only an active tenant may be suspended. An already-suspended
    /// tenant is [`StoreError::Conflict`] (an invalid transition, refused fail
    /// closed); an absent or deleted tenant is [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live tenant matched under this operator;
    /// [`StoreError::Conflict`] if the tenant is not currently active.
    pub async fn suspend(
        &self,
        env: &Env,
        id: &TenantId,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        self.transition(
            env,
            id,
            TenantStatus::Active,
            TenantStatus::Suspended,
            Action::TenantSuspend,
            EnvironmentServingState::Suspended,
            idempotency,
        )
        .await
    }

    /// Resume a live, SUSPENDED tenant (issue #46): flip its status back to
    /// `active` and un-fence its data plane by marking every one of its
    /// environments' serving state active, in one audited transaction. Restores
    /// service with no data loss.
    ///
    /// State machine: only a suspended tenant may be resumed. An already-active
    /// tenant is [`StoreError::Conflict`]; an absent or deleted tenant is
    /// [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live tenant matched under this operator;
    /// [`StoreError::Conflict`] if the tenant is not currently suspended.
    pub async fn resume(
        &self,
        env: &Env,
        id: &TenantId,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        self.transition(
            env,
            id,
            TenantStatus::Suspended,
            TenantStatus::Active,
            Action::TenantResume,
            EnvironmentServingState::Active,
            idempotency,
        )
        .await
    }

    /// The shared body of [`ActingTenantRepo::suspend`] and
    /// [`ActingTenantRepo::resume`]: validate the state-machine transition
    /// `from -> to`, flip the tenant status, and cascade the data-plane serving
    /// state to every environment, in one audited transaction.
    #[allow(clippy::too_many_arguments)]
    async fn transition(
        &self,
        env: &Env,
        id: &TenantId,
        from: TenantStatus,
        to: TenantStatus,
        action: Action,
        serving: EnvironmentServingState,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let operator = self.operator;
        // Pre-read the live tenant's status for the state-machine decision: an
        // absent/deleted tenant is a clean NotFound, and a wrong current state is
        // a Conflict (an invalid transition, refused fail closed). The in-transaction
        // UPDATE below re-checks `status = from` so a concurrent change cannot slip
        // an invalid transition through.
        let status_row = sqlx::query(
            "SELECT status FROM tenants \
             WHERE id = $1 AND operator_id = $2 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(operator.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        let Some(status_row) = status_row else {
            return Err(StoreError::NotFound);
        };
        let current = TenantStatus::from_wire(&status_row.get::<String, _>("status"))
            .ok_or(StoreError::NotFound)?;
        if current != from {
            return Err(StoreError::Conflict);
        }

        // The audit scope needs an environment of this tenant; pick the oldest
        // (retained through soft delete, so its row satisfies the audit foreign key).
        let scope_env = sqlx::query(
            "SELECT id FROM environments WHERE tenant_id = $1 ORDER BY created_at, id LIMIT 1",
        )
        .bind(id.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        let Some(scope_env) = scope_env else {
            return Err(StoreError::NotFound);
        };
        let environment = EnvironmentId::parse(&scope_env.get::<String, _>("id"))
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let scope = Scope::new(*id, environment);
        let serving_status = serving_status_str(serving);

        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action,
                target: id,
            },
            async move |tx| {
                let now_micros = epoch_micros(env.clock().now_utc());
                // 1. Flip the tenant status, guarded on the source state so a
                //    concurrent transition cannot double-apply. A level table (no
                //    row-level security).
                let result = sqlx::query(
                    "UPDATE tenants SET status = $1 \
                     WHERE id = $2 AND operator_id = $3 AND deleted_at IS NULL AND status = $4",
                )
                .bind(to.as_str())
                .bind(id.to_string())
                .bind(operator.to_string())
                .bind(from.as_str())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    // Lost the race: the tenant changed state (or was deleted)
                    // between the pre-read and here. Refuse fail closed.
                    return Err(StoreError::Conflict);
                }
                // 2. Cascade the data-plane serving state to every environment.
                //    environment_states carries forced row-level security keyed on
                //    (tenant, environment), so re-scope per environment and UPSERT
                //    its row (an environment provisioned before this table existed
                //    has no row yet; the upsert creates it). This is what a
                //    suspended tenant's data plane reads to fence, and a resumed
                //    tenant's to serve again.
                let env_rows = sqlx::query("SELECT id FROM environments WHERE tenant_id = $1")
                    .bind(id.to_string())
                    .fetch_all(&mut **tx)
                    .await?;
                for env_row in &env_rows {
                    let env_id: String = env_row.get("id");
                    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
                        .bind(&env_id)
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query(
                        "INSERT INTO environment_states \
                         (tenant_id, environment_id, serving_status, updated_at) \
                         VALUES ($1, $2, $3, \
                                 TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval) \
                         ON CONFLICT (tenant_id, environment_id) DO UPDATE \
                         SET serving_status = EXCLUDED.serving_status, \
                             updated_at = EXCLUDED.updated_at",
                    )
                    .bind(id.to_string())
                    .bind(&env_id)
                    .bind(serving_status)
                    .bind(now_micros)
                    .execute(&mut **tx)
                    .await?;
                }
                // 3. Restore the audit scope's row-level-security variables so the
                //    audited-write's audit row (and the idempotency insert) run under
                //    (tenant, oldest environment), after the per-environment
                //    re-scoping above.
                sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
                    .bind(scope.tenant().to_string())
                    .execute(&mut **tx)
                    .await?;
                sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
                    .bind(scope.environment().to_string())
                    .execute(&mut **tx)
                    .await?;
                // Store the idempotency replay row in the SAME transaction as the
                // transition, so a replay returns the original response and writes no
                // second audit row.
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Deactivate a tenant (soft delete) and OFFBOARD it: cascade the
    /// deactivation to its child environments and their management credentials and
    /// FENCE every environment's data plane, all in one audited transaction. This is
    /// the GRACE stage of the offboarding pipeline (issue #46): the tenant enters a
    /// restorable soft-deleted state, its keys are LEFT INTACT (no crypto-shred here,
    /// deferred to the terminal [`ActingTenantRepo::hard_delete`] per the issue's
    /// out-of-scope), so [`ActingTenantRepo::restore`] inside the retention window
    /// brings it back with no data loss. Audited scoped to the tenant and its oldest
    /// environment (which is retained, so the audit foreign key holds).
    ///
    /// The credential and environment cascade is what makes a deleted tenant's
    /// environments stop listing and its keys stop authenticating; the join in
    /// [`ManagementCredentialRepo::authenticate`] is the belt-and-suspenders
    /// backstop for any create-after-delete race. The serving-state fence stops the
    /// data plane serving the offboarded tenant. Nothing is crypto-shredded here: the
    /// keys survive so a restore loses no data; erasure is the terminal purge's job.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live tenant matched under this operator.
    #[allow(clippy::too_many_lines)]
    pub async fn delete(&self, env: &Env, id: &TenantId) -> Result<(), StoreError> {
        // The audit scope needs an environment of this tenant; pick the oldest
        // (it is retained through soft delete, so its row satisfies the audit
        // foreign key). A tenant always has its first environment.
        let scope_env = sqlx::query(
            "SELECT id FROM environments WHERE tenant_id = $1 ORDER BY created_at, id LIMIT 1",
        )
        .bind(id.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        let Some(scope_env) = scope_env else {
            return Err(StoreError::NotFound);
        };
        let environment = EnvironmentId::parse(&scope_env.get::<String, _>("id"))
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let scope = Scope::new(*id, environment);
        let operator = self.operator;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TenantDelete,
                target: id,
            },
            async move |tx| {
                let deleted_micros = epoch_micros(env.clock().now_utc());
                // 1. Soft-delete the tenant itself (a level table, no row-level
                //    security).
                let result = sqlx::query(
                    "UPDATE tenants SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND operator_id = $3 AND deleted_at IS NULL",
                )
                .bind(deleted_micros)
                .bind(id.to_string())
                .bind(operator.to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                // 2. Cascade to the tenant's management credentials. They carry
                //    forced row-level security keyed on (tenant, environment), so
                //    each environment's rows are visible (and updatable) only under
                //    that environment's scope; a single tenant-wide UPDATE would
                //    reach only the audit scope's environment. Re-scope per
                //    environment to mark them all.
                let env_rows = sqlx::query("SELECT id FROM environments WHERE tenant_id = $1")
                    .bind(id.to_string())
                    .fetch_all(&mut **tx)
                    .await?;
                for env_row in &env_rows {
                    let env_id: String = env_row.get("id");
                    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
                        .bind(&env_id)
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query(
                        "UPDATE management_credentials SET deleted_at = \
                         TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                         WHERE tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
                    )
                    .bind(deleted_micros)
                    .bind(id.to_string())
                    .bind(&env_id)
                    .execute(&mut **tx)
                    .await?;
                    // Fence the data plane for the offboarded tenant: mark every
                    // environment's serving state suspended so the data-plane
                    // issuer-load path refuses it (a deleted tenant must not serve).
                    sqlx::query(
                        "INSERT INTO environment_states \
                         (tenant_id, environment_id, serving_status, updated_at) \
                         VALUES ($1, $2, 'suspended', \
                                 TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval) \
                         ON CONFLICT (tenant_id, environment_id) DO UPDATE \
                         SET serving_status = 'suspended', updated_at = EXCLUDED.updated_at",
                    )
                    .bind(id.to_string())
                    .bind(&env_id)
                    .bind(deleted_micros)
                    .execute(&mut **tx)
                    .await?;
                    // NO crypto-shred here (issue #46): the grace delete keeps every
                    // KEK intact so a restore inside the retention window loses no
                    // data. Erasure is deferred to the terminal hard_delete (purge),
                    // which crypto-shreds through the same #48 envelope path once the
                    // window elapses.
                }
                // 3. Cascade to the tenant's environments (a level table, no
                //    row-level security), so reads stop returning them and the
                //    authenticate join rejects the child keys.
                sqlx::query(
                    "UPDATE environments SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE tenant_id = $2 AND deleted_at IS NULL",
                )
                .bind(deleted_micros)
                .bind(id.to_string())
                .execute(&mut **tx)
                .await?;
                // 4. Restore the audit scope's row-level-security variables so the
                //    audited-write's audit row inserts under (tenant, oldest
                //    environment), exactly as it did before the per-environment
                //    re-scoping above.
                sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
                    .bind(scope.tenant().to_string())
                    .execute(&mut **tx)
                    .await?;
                sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
                    .bind(scope.environment().to_string())
                    .execute(&mut **tx)
                    .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Restore a tenant from the GRACE stage of offboarding (issue #46): reverse the
    /// grace delete while it is still INSIDE the configured `retention` window. Clears
    /// the tenant's, its environments', and its management credentials' soft-delete
    /// tombstones and un-fences every environment's data plane, in one audited
    /// transaction, so the tenant serves again with NO data loss (the grace delete
    /// never shredded a key).
    ///
    /// State machine: valid only for a tenant in GRACE (soft-deleted, not yet purged)
    /// whose retention window has NOT elapsed. A tenant that was never deleted, was
    /// already restored, or was terminally purged is [`StoreError::NotFound`]; a
    /// tenant whose retention window has already elapsed is [`StoreError::Conflict`]
    /// (restore is no longer offered; the terminal hard delete is due).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no grace tenant matched under this operator;
    /// [`StoreError::Conflict`] if the retention window has already elapsed.
    #[allow(clippy::too_many_lines)]
    pub async fn restore(
        &self,
        env: &Env,
        id: &TenantId,
        retention: Duration,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let operator = self.operator;
        // Pre-read the grace tenant's deletion instant for the window decision. A row
        // that is not in grace (never deleted, already restored, or purged) is a clean
        // NotFound; a grace row whose window has elapsed is a Conflict (restore is no
        // longer on offer). The in-transaction UPDATE re-checks the grace predicate.
        let grace = sqlx::query(
            "SELECT (EXTRACT(EPOCH FROM deleted_at) * 1000000)::bigint AS deleted_us \
             FROM tenants \
             WHERE id = $1 AND operator_id = $2 \
             AND deleted_at IS NOT NULL AND purged_at IS NULL",
        )
        .bind(id.to_string())
        .bind(operator.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        let Some(grace) = grace else {
            return Err(StoreError::NotFound);
        };
        let deleted_micros: i64 = grace.get("deleted_us");
        let now_micros = epoch_micros(env.clock().now_utc());
        if now_micros.saturating_sub(deleted_micros) >= retention_micros(retention) {
            // The window has elapsed: restore is no longer offered.
            return Err(StoreError::Conflict);
        }

        let scope_env = sqlx::query(
            "SELECT id FROM environments WHERE tenant_id = $1 ORDER BY created_at, id LIMIT 1",
        )
        .bind(id.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        let Some(scope_env) = scope_env else {
            return Err(StoreError::NotFound);
        };
        let environment = EnvironmentId::parse(&scope_env.get::<String, _>("id"))
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let scope = Scope::new(*id, environment);

        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TenantRestore,
                target: id,
            },
            async move |tx| {
                let now_micros = epoch_micros(env.clock().now_utc());
                // 1. Clear the tenant tombstone, guarded on the grace predicate so a
                //    concurrent purge cannot be undone.
                let result = sqlx::query(
                    "UPDATE tenants SET deleted_at = NULL \
                     WHERE id = $1 AND operator_id = $2 \
                     AND deleted_at IS NOT NULL AND purged_at IS NULL",
                )
                .bind(id.to_string())
                .bind(operator.to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                // 2. Per environment: un-fence the data plane and clear the grace
                //    delete's credential tombstones, re-scoping to each environment
                //    for the forced row-level security on management_credentials and
                //    environment_states.
                let env_rows = sqlx::query("SELECT id FROM environments WHERE tenant_id = $1")
                    .bind(id.to_string())
                    .fetch_all(&mut **tx)
                    .await?;
                for env_row in &env_rows {
                    let env_id: String = env_row.get("id");
                    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
                        .bind(&env_id)
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query(
                        "UPDATE management_credentials SET deleted_at = NULL \
                         WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NOT NULL",
                    )
                    .bind(id.to_string())
                    .bind(&env_id)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "INSERT INTO environment_states \
                         (tenant_id, environment_id, serving_status, updated_at) \
                         VALUES ($1, $2, 'active', \
                                 TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval) \
                         ON CONFLICT (tenant_id, environment_id) DO UPDATE \
                         SET serving_status = 'active', updated_at = EXCLUDED.updated_at",
                    )
                    .bind(id.to_string())
                    .bind(&env_id)
                    .bind(now_micros)
                    .execute(&mut **tx)
                    .await?;
                }
                // 3. Clear the environments' tombstones (a level table).
                sqlx::query(
                    "UPDATE environments SET deleted_at = NULL \
                     WHERE tenant_id = $1 AND deleted_at IS NOT NULL",
                )
                .bind(id.to_string())
                .execute(&mut **tx)
                .await?;
                // 4. Restore the audit scope's row-level-security variables.
                sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
                    .bind(scope.tenant().to_string())
                    .execute(&mut **tx)
                    .await?;
                sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
                    .bind(scope.environment().to_string())
                    .execute(&mut **tx)
                    .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// The TERMINAL hard-delete stage of the offboarding pipeline (issue #46):
    /// permitted only AFTER the configured `retention` window has elapsed since the
    /// grace delete. Crypto-shreds every environment's envelope KEK (the erasure,
    /// through the #48 envelope path, gated strictly to this terminal stage) and
    /// stamps `purged_at`, in one audited transaction, so the tenant's sealed PII
    /// becomes cryptographically UNRECOVERABLE and the tenant can no longer be
    /// restored. A sibling tenant is unaffected because every scope has its own KEK.
    ///
    /// State machine: valid only for a tenant in GRACE (soft-deleted, not yet purged)
    /// whose retention window HAS elapsed. Still within the window is
    /// [`StoreError::Conflict`] (the grace period must run first); a never-deleted or
    /// already-purged tenant is [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no grace tenant matched under this operator;
    /// [`StoreError::Conflict`] if the retention window has not yet elapsed.
    #[allow(clippy::too_many_lines)]
    pub async fn hard_delete(
        &self,
        env: &Env,
        id: &TenantId,
        retention: Duration,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let operator = self.operator;
        // Pre-read the grace tenant's deletion instant for the window decision. Only a
        // grace tenant whose window has elapsed may be purged; a grace tenant still
        // within the window is a Conflict (the grace period must run first).
        let grace = sqlx::query(
            "SELECT (EXTRACT(EPOCH FROM deleted_at) * 1000000)::bigint AS deleted_us \
             FROM tenants \
             WHERE id = $1 AND operator_id = $2 \
             AND deleted_at IS NOT NULL AND purged_at IS NULL",
        )
        .bind(id.to_string())
        .bind(operator.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        let Some(grace) = grace else {
            return Err(StoreError::NotFound);
        };
        let deleted_micros: i64 = grace.get("deleted_us");
        let now_micros = epoch_micros(env.clock().now_utc());
        if now_micros.saturating_sub(deleted_micros) < retention_micros(retention) {
            // Still within the retention window: the grace period must run first.
            return Err(StoreError::Conflict);
        }

        let scope_env = sqlx::query(
            "SELECT id FROM environments WHERE tenant_id = $1 ORDER BY created_at, id LIMIT 1",
        )
        .bind(id.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        let Some(scope_env) = scope_env else {
            return Err(StoreError::NotFound);
        };
        let environment = EnvironmentId::parse(&scope_env.get::<String, _>("id"))
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let scope = Scope::new(*id, environment);

        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TenantPurge,
                target: id,
            },
            async move |tx| {
                let purged_micros = epoch_micros(env.clock().now_utc());
                // 1. Stamp the terminal marker, guarded on the grace predicate so a
                //    concurrent restore/purge cannot double-apply.
                let result = sqlx::query(
                    "UPDATE tenants SET purged_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND operator_id = $3 \
                     AND deleted_at IS NOT NULL AND purged_at IS NULL",
                )
                .bind(purged_micros)
                .bind(id.to_string())
                .bind(operator.to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                // 2. Per environment: CRYPTO-SHRED the KEK (issue #46/#48). Overwrite
                //    every not-yet-destroyed KEK version's wrapped bytes with an empty
                //    blob and mark it destroyed, in this SAME audited transaction.
                //    After commit the scope's DEKs can never be unwrapped, so all of
                //    the tenant's envelope-protected PII is permanently unreadable. A
                //    scope that never provisioned a KEK matches no row. The control
                //    role holds exactly this column-scoped UPDATE on tenant_keks.
                let env_rows = sqlx::query("SELECT id FROM environments WHERE tenant_id = $1")
                    .bind(id.to_string())
                    .fetch_all(&mut **tx)
                    .await?;
                for env_row in &env_rows {
                    let env_id: String = env_row.get("id");
                    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
                        .bind(&env_id)
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query(
                        "UPDATE tenant_keks \
                         SET wrapped_kek = $3, status = 'destroyed', \
                             destroyed_at = \
                             TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
                         WHERE tenant_id = $1 AND environment_id = $2 AND status <> 'destroyed'",
                    )
                    .bind(id.to_string())
                    .bind(&env_id)
                    .bind(Vec::<u8>::new())
                    .bind(purged_micros)
                    .execute(&mut **tx)
                    .await?;
                    // 2b. SEVER any BYOK binding for this environment (issue #49) in
                    //     the SAME audited transaction: flip it to 'destroyed', clear
                    //     the external key reference, and stamp destroyed_at. For a
                    //     BYOK scope the customer root is what wrapped the KEK, so
                    //     destroying the platform KEK above AND severing the binding
                    //     here leaves the tenant with no recoverable key by either
                    //     path; the row is retained as erasure evidence. A scope not
                    //     enrolled in BYOK matches no row. The control role holds
                    //     exactly this column-scoped sever UPDATE on the table.
                    sqlx::query(
                        "UPDATE tenant_byok_bindings \
                         SET status = 'destroyed', key_ref = '', \
                             destroyed_at = \
                             TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval \
                         WHERE tenant_id = $1 AND environment_id = $2 AND status <> 'destroyed'",
                    )
                    .bind(id.to_string())
                    .bind(&env_id)
                    .bind(purged_micros)
                    .execute(&mut **tx)
                    .await?;
                }
                // 3. Restore the audit scope's row-level-security variables.
                sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
                    .bind(scope.tenant().to_string())
                    .execute(&mut **tx)
                    .await?;
                sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
                    .bind(scope.environment().to_string())
                    .execute(&mut **tx)
                    .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }
}

/// Mutating environments under one tenant.
pub struct ActingEnvironmentRepo<'a> {
    store: &'a Store,
    acting: ActingContext,
    tenant: TenantId,
}

impl ActingEnvironmentRepo<'_> {
    /// Create an environment under this tenant, audited scoped to `(tenant,
    /// new_environment)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if the parent tenant is not ACTIVE (suspended, or in
    /// the offboarding grace/terminal state): a non-active tenant must not gain a
    /// fresh, unfenced environment (issue #46), the same lifecycle-precondition
    /// convention the tenant transitions use;
    /// [`StoreError::IdempotencyConflict`] on a concurrent Idempotency-Key race;
    /// [`StoreError::Database`] on a persistence failure (including a missing
    /// tenant, which surfaces as the tenant foreign-key violation).
    pub async fn create(
        &self,
        env: &Env,
        environment_id: &EnvironmentId,
        created_at_micros: i64,
        environment: NewEnvironment<'_>,
        signing_key: NewSigningKey<'_>,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let scope = Scope::new(self.tenant, *environment_id);
        if signing_key.id.scope() != scope {
            return Err(StoreError::NotFound);
        }
        let tenant = self.tenant;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvironmentCreate,
                target: environment_id,
            },
            async move |tx| {
                // Lifecycle precondition (issue #46): an environment must not be born
                // under a non-ACTIVE parent tenant. The suspend/offboard cascade fences
                // only the environments that exist at suspend time, and a fresh
                // environment seeds no serving-state row (so it would read Active), so a
                // new environment added under a suspended or grace/terminal-deleted
                // tenant would hand it an unfenced serving surface while the tenant is
                // meant to be off the data plane. Refuse it fail closed. The check
                // shares this audited transaction with the insert below, so it is ATOMIC
                // with it (no time-of-check/time-of-use gap) and nothing (no environment
                // row, no audit row, no idempotency row) is written when it fires. A
                // non-active parent is StoreError::Conflict, the lifecycle-precondition
                // convention the tenant suspend/resume transitions already use, which the
                // control plane maps to a loud 409. A tenant that does not exist AT ALL
                // is left to the foreign-key rejection on the insert (the pre-existing
                // behavior), so an absent parent stays distinct from a suspended one.
                let parent = sqlx::query(
                    "SELECT status, (deleted_at IS NULL AND purged_at IS NULL) AS live \
                     FROM tenants WHERE id = $1",
                )
                .bind(tenant.to_string())
                .fetch_optional(&mut **tx)
                .await?;
                if let Some(row) = parent {
                    let active = row.get::<String, _>("status") == TenantStatus::Active.as_str();
                    let live: bool = row.get("live");
                    if !(active && live) {
                        return Err(StoreError::Conflict);
                    }
                }
                sqlx::query(
                    "INSERT INTO environments \
                     (id, tenant_id, display_name, kind, custom_domain, region, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
                )
                .bind(environment_id.to_string())
                .bind(tenant.to_string())
                .bind(environment.display_name)
                .bind(environment.kind.as_str())
                .bind(environment.custom_domain)
                .bind(environment.region)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                // The environment's day-one signing key, provisioned in the same
                // transaction and scope (issue #42), so the new environment serves
                // discovery with its own issuer and disjoint JWKS immediately and
                // its keys are its own identity from creation.
                insert_signing_key_row(tx, &scope, &signing_key).await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Deactivate an environment (soft delete) under this tenant and CASCADE the
    /// deactivation to its management credentials, in the audited transaction so
    /// it stays atomic. Audited scoped to `(tenant, environment)`. The rows are
    /// retained, so the audit foreign key holds.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live environment matched under this tenant.
    pub async fn delete(&self, env: &Env, id: &EnvironmentId) -> Result<(), StoreError> {
        let scope = Scope::new(self.tenant, *id);
        let tenant = self.tenant;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvironmentDelete,
                target: id,
            },
            async move |tx| {
                let deleted_micros = epoch_micros(env.clock().now_utc());
                let result = sqlx::query(
                    "UPDATE environments SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL",
                )
                .bind(deleted_micros)
                .bind(id.to_string())
                .bind(tenant.to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                // Cascade to this environment's management credentials. The audit
                // scope is exactly (tenant, environment), so the forced row-level
                // security policy already permits a single tenant+environment
                // UPDATE here (no per-environment re-scoping needed, unlike the
                // tenant cascade).
                sqlx::query(
                    "UPDATE management_credentials SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
                )
                .bind(deleted_micros)
                .bind(tenant.to_string())
                .bind(id.to_string())
                .execute(&mut **tx)
                .await?;
                // Fence this environment's data plane (issue #46): a deleted
                // environment must not serve.
                sqlx::query(
                    "INSERT INTO environment_states \
                     (tenant_id, environment_id, serving_status, updated_at) \
                     VALUES ($1, $2, 'suspended', \
                             TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval) \
                     ON CONFLICT (tenant_id, environment_id) DO UPDATE \
                     SET serving_status = 'suspended', updated_at = EXCLUDED.updated_at",
                )
                .bind(tenant.to_string())
                .bind(id.to_string())
                .bind(deleted_micros)
                .execute(&mut **tx)
                .await?;
                // NO crypto-shred here (issue #46): an ordinary environment
                // deactivation keeps its KEK intact. Erasure (the crypto-shred) is the
                // erasure issue's job, reached through the terminal tenant hard_delete
                // (purge) and #48's ActingEnvelopeRepo, never folded into an ordinary
                // delete.
                Ok(())
            },
            false,
        )
        .await
    }
}

/// Mutating management credentials for one scope.
pub struct ActingManagementCredentialRepo<'a> {
    store: &'a Store,
    acting: ActingContext,
    scope: Scope,
}

impl ActingManagementCredentialRepo<'_> {
    /// Mint a management key: store the key HASH (never the secret) and audit
    /// `management_key.create` in the same transaction, scoped to this scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::IdempotencyConflict`] on a concurrent Idempotency-Key race;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create(
        &self,
        env: &Env,
        id: &ManagementKeyId,
        created_at_micros: i64,
        key_hash: &str,
        display_name: &str,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ManagementKeyCreate,
                target: id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO management_credentials \
                     (id, tenant_id, environment_id, key_hash, display_name, created_at) \
                     VALUES ($1, $2, $3, $4, $5, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(key_hash)
                .bind(display_name)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Revoke a management key (soft delete) and audit `management_key.delete`.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live key matched in this scope.
    pub async fn delete(&self, env: &Env, id: &ManagementKeyId) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ManagementKeyDelete,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE management_credentials SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
                     AND deleted_at IS NULL",
                )
                .bind(epoch_micros(env.clock().now_utc()))
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }
}

/// Mutating organizations for one scope (issue #41).
pub struct ActingOrganizationRepo<'a> {
    store: &'a Store,
    acting: ActingContext,
    scope: Scope,
}

impl ActingOrganizationRepo<'_> {
    /// Create an organization in this scope and audit `organization.create` in the
    /// same transaction, scoped to `(tenant, environment)`.
    ///
    /// Containment is enforced structurally on three layers: the typed
    /// [`OrganizationId`] embeds this scope (a foreign id never reaches here), the
    /// forced row-level-security WITH CHECK rejects any row whose scope is not the
    /// bound one, and the `(environment_id, tenant_id)` foreign key rejects a
    /// nonexistent environment. The caller additionally verifies the parent
    /// environment is LIVE before calling, so a soft-deleted parent is a clean
    /// not-found rather than a foreign-key surprise.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the id is not in this scope;
    /// [`StoreError::IdempotencyConflict`] on a concurrent Idempotency-Key race;
    /// [`StoreError::Database`] on a persistence failure (including a nonexistent
    /// environment, which surfaces as the foreign-key violation).
    pub async fn create(
        &self,
        env: &Env,
        id: &OrganizationId,
        created_at_micros: i64,
        display_name: &str,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::OrganizationCreate,
                target: id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO organizations \
                     (id, tenant_id, environment_id, display_name, created_at) \
                     VALUES ($1, $2, $3, $4, \
                             TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(display_name)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Deactivate an organization (soft delete) in this scope and audit
    /// `organization.delete` in the same transaction. The row is retained (only
    /// the column-scoped `deleted_at` is written), so the audit foreign key to it
    /// stays satisfiable.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the id is not in this scope, or no live
    /// organization matched.
    pub async fn delete(&self, env: &Env, id: &OrganizationId) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::OrganizationDelete,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE organizations SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
                     AND deleted_at IS NULL",
                )
                .bind(epoch_micros(env.clock().now_utc()))
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }
}

/// Insert a pending idempotency row, if the caller supplied one. A primary-key
/// collision (a concurrent request already stored this key) surfaces as the
/// distinct [`StoreError::IdempotencyConflict`] so the caller can re-read and
/// replay rather than double-execute.
async fn insert_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    idempotency: Option<IdempotencyWrite<'_>>,
) -> Result<(), StoreError> {
    let Some(idem) = idempotency else {
        return Ok(());
    };
    let result = sqlx::query(
        "INSERT INTO idempotency_keys \
         (credential_ref, idempotency_key, request_fingerprint, response_status, response_body) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(idem.credential_ref)
    .bind(idem.key)
    .bind(idem.request_fingerprint)
    .bind(i32::from(idem.response_status))
    .bind(idem.response_body)
    .execute(&mut **tx)
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if is_idempotency_conflict(&error) => Err(StoreError::IdempotencyConflict),
        Err(error) => Err(error.into()),
    }
}

/// Whether a database error is a primary-key collision on `idempotency_keys`.
fn is_idempotency_conflict(error: &sqlx::Error) -> bool {
    let Some(db) = error.as_database_error() else {
        return false;
    };
    db.code().as_deref() == Some("23505") && db.constraint() == Some("idempotency_keys_pkey")
}

/// The retention window as epoch microseconds (issue #46), saturating to
/// [`i64::MAX`] for a window too large to fit (which just means "effectively
/// never elapses"). Used to compare a grace tenant's age against the configured
/// offboarding retention window.
fn retention_micros(retention: Duration) -> i64 {
    i64::try_from(retention.as_micros()).unwrap_or(i64::MAX)
}

/// The stored `serving_status` wire string for a data-plane serving state (issue
/// #46).
fn serving_status_str(state: EnvironmentServingState) -> &'static str {
    match state {
        EnvironmentServingState::Active => "active",
        EnvironmentServingState::Suspended => "suspended",
    }
}

/// Split an optional cursor into its bound parameters (both `None` when absent).
fn split_cursor(after: Option<&CursorPosition>) -> (Option<i64>, Option<String>) {
    match after {
        Some(cursor) => (Some(cursor.created_at_unix_micros), Some(cursor.id.clone())),
        None => (None, None),
    }
}

/// Reconstruct a [`TenantRecord`] from a row.
fn tenant_from_row(row: &PgRow) -> Result<TenantRecord, StoreError> {
    let decode =
        |e: crate::id::IdParseError| StoreError::Database(sqlx::Error::Decode(Box::new(e)));
    let status_text: String = row.get("status");
    let status = TenantStatus::from_wire(&status_text).ok_or_else(|| {
        // A stored status outside the CHECK set is a corrupt row; surface it as a
        // decode error rather than silently defaulting.
        StoreError::Database(sqlx::Error::Decode(
            format!("unknown tenant status {status_text:?}").into(),
        ))
    })?;
    Ok(TenantRecord {
        id: TenantId::parse(&row.get::<String, _>("id")).map_err(decode)?,
        operator_id: OperatorId::parse(&row.get::<String, _>("operator_id")).map_err(decode)?,
        display_name: row.get("display_name"),
        status,
        home_region: row.get("home_region"),
        created_at_unix_micros: row.get("created_us"),
    })
}

/// Reconstruct an [`EnvironmentRecord`] from a row.
fn environment_from_row(row: &PgRow) -> Result<EnvironmentRecord, StoreError> {
    let decode =
        |e: crate::id::IdParseError| StoreError::Database(sqlx::Error::Decode(Box::new(e)));
    let kind_text: String = row.get("kind");
    let kind = EnvironmentType::parse(&kind_text).map_err(|e| {
        StoreError::Database(sqlx::Error::Decode(
            format!("unknown environment kind in row: {e}").into(),
        ))
    })?;
    Ok(EnvironmentRecord {
        id: EnvironmentId::parse(&row.get::<String, _>("id")).map_err(decode)?,
        tenant_id: TenantId::parse(&row.get::<String, _>("tenant_id")).map_err(decode)?,
        display_name: row.get("display_name"),
        kind,
        custom_domain: row.get("custom_domain"),
        region: row.get("region"),
        created_at_unix_micros: row.get("created_us"),
    })
}

/// Reconstruct an [`OperatorRecord`] from a row.
fn operator_from_row(row: &PgRow) -> Result<OperatorRecord, StoreError> {
    let decode =
        |e: crate::id::IdParseError| StoreError::Database(sqlx::Error::Decode(Box::new(e)));
    Ok(OperatorRecord {
        id: OperatorId::parse(&row.get::<String, _>("id")).map_err(decode)?,
        display_name: row.get("display_name"),
        created_at_unix_micros: row.get("created_us"),
    })
}

/// Reconstruct an [`OrganizationRecord`] from a row read within scope. The stored
/// id is parsed back UNDER the scope, so a corrupt cross-scope row fails to decode
/// rather than being returned.
fn organization_from_row(row: &PgRow, scope: &Scope) -> Result<OrganizationRecord, StoreError> {
    let id_text: String = row.get("id");
    let id = OrganizationId::parse_in_scope(&id_text, scope)?;
    Ok(OrganizationRecord {
        id,
        display_name: row.get("display_name"),
        created_at_unix_micros: row.get("created_us"),
    })
}

/// Reconstruct a [`ManagementCredentialRecord`] from a row read within scope.
fn credential_from_row(
    row: &PgRow,
    scope: &Scope,
) -> Result<ManagementCredentialRecord, StoreError> {
    let id_text: String = row.get("id");
    let id = ManagementKeyId::parse_in_scope(&id_text, scope)?;
    Ok(ManagementCredentialRecord {
        id,
        display_name: row.get("display_name"),
        created_at_unix_micros: row.get("created_us"),
    })
}

// ===========================================================================
// Per-tenant envelope encryption for PII and secrets (issue #48).
//
// The DEK/KEK envelope substrate at the persistence layer. Three tenant-scoped
// tables (tenant_keks, tenant_deks, encrypted_secrets), isolated exactly like
// every other data-plane table and reached only through the scoped repository,
// so a KEK, a DEK, or a ciphertext of another tenant is not expressible. The AEAD
// primitive itself (a standard ring::aead AES-256-GCM DEK/KEK envelope) lives in
// ironauth-jose (the one crate allowed a direct ring dependency); this module
// owns the key lifecycle, the context binding, and the encrypted columns.
//
// Key material and nonces are drawn only from the env.entropy() seam (via the
// ironauth-jose primitive), never an OS RNG. A KEK is stored wrapped under the
// platform master key; a DEK is stored wrapped under its scope's active KEK; a
// secret value is stored sealed under the scope's active DEK, with the tenant,
// environment, purpose, and key version bound as associated data so a ciphertext
// cannot be replayed across a row, tenant, environment, or column. Destroying a
// scope's KEK (the crypto-shred) makes every DEK unwrappable and therefore every
// ciphertext permanently unreadable.
// ===========================================================================

/// The AAD label domain-separating a KEK wrap from every other envelope context.
const KEK_WRAP_LABEL: &str = "ironauth.envelope.kek-wrap.v1";
/// The AAD label domain-separating a DEK wrap from every other envelope context.
const DEK_WRAP_LABEL: &str = "ironauth.envelope.dek-wrap.v1";
/// The AAD label domain-separating a secret-payload seal from every other context.
const SECRET_SEAL_LABEL: &str = "ironauth.envelope.secret.v1";
/// The AAD label domain-separating a sealed `users` PII payload (the login handle
/// or the standard-claim document) from every other envelope context.
const USER_PII_SEAL_LABEL: &str = "ironauth.envelope.user-pii.v1";
/// The AAD label domain-separating the `users.identifier` blind index from every
/// other keyed derivation.
const USER_IDENTIFIER_BIDX_LABEL: &str = "ironauth.envelope.user-identifier-bidx.v1";
/// The AAD label domain-separating a sealed `account_credentials.friendly_name`
/// (the user-authored credential label, issue #61) from every other envelope
/// context, so a credential-name seal never authenticates under another column's.
const CREDENTIAL_PII_SEAL_LABEL: &str = "ironauth.envelope.account-credential-pii.v1";
/// The purpose label bound into a sealed `users.identifier` (the login handle).
const USER_IDENTIFIER_PURPOSE: &str = "identifier";
/// The purpose label bound into a sealed `users.claims` (the standard-claim JSON).
const USER_CLAIMS_PURPOSE: &str = "claims";
/// The purpose label bound into a sealed `users.external_id` (issue #52): the
/// external correlation id from the tenant's own systems.
const USER_EXTERNAL_ID_PURPOSE: &str = "external_id";
/// The AAD label domain-separating the `users.external_id` blind index (issue #52)
/// from every other keyed derivation, including the login-handle blind index, so a
/// value that is BOTH someone's login handle and another user's external id never
/// produces a colliding index tag.
const USER_EXTERNAL_ID_BIDX_LABEL: &str = "ironauth.envelope.user-external-id-bidx.v1";

/// The associated data binding a wrapped KEK to its scope, version, and master
/// key. A KEK wrapped under one context fails to unwrap under any other, so it
/// cannot be lifted into another tenant, environment, or master-key generation.
fn kek_wrap_aad(scope: Scope, version: i32, master_key_id: &str) -> Aad {
    Aad::builder()
        .text(KEK_WRAP_LABEL)
        .text(&scope.tenant().to_string())
        .text(&scope.environment().to_string())
        .version(i64::from(version))
        .text(master_key_id)
        .build()
}

/// The associated data binding a wrapped DEK to its scope and version. It does
/// NOT bind the wrapping KEK version, so a KEK rotation re-wraps a DEK under the
/// same AAD (only the wrapping key changes); using the wrong KEK still fails
/// authentication, so the KEK identity needs no separate AAD field.
fn dek_wrap_aad(scope: Scope, version: i32) -> Aad {
    Aad::builder()
        .text(DEK_WRAP_LABEL)
        .text(&scope.tenant().to_string())
        .text(&scope.environment().to_string())
        .version(i64::from(version))
        .build()
}

/// The associated data binding a sealed secret payload to its scope, column
/// (purpose), and the DEK version that sealed it. A ciphertext lifted to another
/// row, tenant, environment, column, or claimed under another DEK version fails
/// authenticated decryption.
fn secret_seal_aad(scope: Scope, purpose: &str, dek_version: i32) -> Aad {
    Aad::builder()
        .text(SECRET_SEAL_LABEL)
        .text(&scope.tenant().to_string())
        .text(&scope.environment().to_string())
        .text(purpose)
        .version(i64::from(dek_version))
        .build()
}

/// The associated data binding a sealed `users` PII value to its scope, column
/// (purpose: the login handle or the claim document), and the DEK version that
/// sealed it. Shares the row/tenant/environment/column/version replay protection
/// of every other sealed payload; the distinct label keeps a `users` seal from
/// ever authenticating under the generic secret-store context.
fn user_pii_seal_aad(scope: Scope, purpose: &str, dek_version: i32) -> Aad {
    Aad::builder()
        .text(USER_PII_SEAL_LABEL)
        .text(&scope.tenant().to_string())
        .text(&scope.environment().to_string())
        .text(purpose)
        .version(i64::from(dek_version))
        .build()
}

/// The associated data binding a sealed `account_credentials.friendly_name` (the
/// user-authored credential label, issue #61) to its scope and the DEK version that
/// sealed it. Shares the tenant/environment/version replay protection of every
/// other sealed payload; the distinct label keeps a credential-name seal from ever
/// authenticating under the generic secret-store or the users-PII context.
fn credential_pii_seal_aad(scope: Scope, dek_version: i32) -> Aad {
    Aad::builder()
        .text(CREDENTIAL_PII_SEAL_LABEL)
        .text(&scope.tenant().to_string())
        .text(&scope.environment().to_string())
        .version(i64::from(dek_version))
        .build()
}

/// The blind-index context for a `users.identifier`: the label, the scope, and the
/// identifier value, length-prefixed. The master key derives a per-tenant HMAC key
/// over this context, so the same handle in two tenants maps to two different tags
/// (an index collision cannot leak across tenants) and the tag is never a bare
/// unsalted hash of the handle.
fn user_identifier_bidx_aad(scope: Scope, identifier: &str) -> Aad {
    Aad::builder()
        .text(USER_IDENTIFIER_BIDX_LABEL)
        .text(&scope.tenant().to_string())
        .text(&scope.environment().to_string())
        .field(identifier.as_bytes())
        .build()
}

/// The deterministic blind index for `identifier` in `scope` under `master`, the
/// value an equality lookup queries against `users.identifier_bidx`.
fn user_identifier_blind_index(master: &MasterKey, scope: Scope, identifier: &str) -> BlindIndex {
    master.blind_index(&user_identifier_bidx_aad(scope, identifier))
}

/// The blind-index context for a `users.external_id` (issue #52): the label, the
/// scope, and the external-id value, length-prefixed. As with the login handle, the
/// per-tenant HMAC key means the SAME external-id string in two tenants maps to two
/// different tags, so an index collision can never leak or link across tenants.
fn user_external_id_bidx_aad(scope: Scope, external_id: &str) -> Aad {
    Aad::builder()
        .text(USER_EXTERNAL_ID_BIDX_LABEL)
        .text(&scope.tenant().to_string())
        .text(&scope.environment().to_string())
        .field(external_id.as_bytes())
        .build()
}

/// The deterministic blind index for `external_id` in `scope` under `master`, the
/// value an equality lookup and the per-scope unique constraint query against
/// `users.external_id_bidx`.
fn user_external_id_blind_index(master: &MasterKey, scope: Scope, external_id: &str) -> BlindIndex {
    master.blind_index(&user_external_id_bidx_aad(scope, external_id))
}

/// Reconstruct a [`UserAdminRecord`] from a management-plane `users` row, opening
/// the sealed login handle (always) and the sealed external id (when present)
/// through the row's DEK versions. Runs inside the caller's open transaction.
async fn user_admin_record_from_row(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    master: &MasterKey,
    row: &PgRow,
) -> Result<UserAdminRecord, StoreError> {
    let id = UserId::parse_in_scope(&row.get::<String, _>("id"), &scope)?;
    let state =
        UserState::from_wire(&row.get::<String, _>("state")).ok_or(StoreError::Encryption)?;
    let pii_dek_version: i32 = row.get("pii_dek_version");
    let identifier_sealed: Vec<u8> = row.get("identifier_sealed");
    let dek = fetch_dek_by_version(tx, scope, master, pii_dek_version).await?;
    let identifier_bytes = dek.open(
        &user_pii_seal_aad(scope, USER_IDENTIFIER_PURPOSE, pii_dek_version),
        &Sealed::from_bytes(identifier_sealed)?,
    )?;
    let identifier = String::from_utf8(identifier_bytes).map_err(|_| StoreError::Encryption)?;
    let external_id = match (
        row.get::<Option<Vec<u8>>, _>("external_id_sealed"),
        row.get::<Option<i32>, _>("external_id_dek_version"),
    ) {
        (Some(sealed), Some(version)) => {
            let ext_dek = fetch_dek_by_version(tx, scope, master, version).await?;
            let bytes = ext_dek.open(
                &user_pii_seal_aad(scope, USER_EXTERNAL_ID_PURPOSE, version),
                &Sealed::from_bytes(sealed)?,
            )?;
            Some(String::from_utf8(bytes).map_err(|_| StoreError::Encryption)?)
        }
        _ => None,
    };
    Ok(UserAdminRecord {
        id,
        identifier,
        state,
        external_id,
        scheduled_offboarding_at_unix_micros: row.get("scheduled_us"),
        created_at_unix_micros: row.get("created_us"),
        updated_at_unix_micros: row.get("updated_us"),
    })
}

/// Cascade a user's live sessions to ENDED inside an open transaction (issue #52),
/// exactly as the revoke-everything-for-a-user path does (issue #32/#35): flip every
/// live session, enqueue one durable session-ended event per genuine flip (so the
/// unified fan-out delivers back-channel logout to affected relying parties), end the
/// per-client sessions, and cascade the non-offline refresh families (and, on a hard
/// kill, the offline families and their grants). Shared by the block/disable state
/// transition, the delete, and the scheduled-offboarding execution, so each ends
/// sessions identically. The `cause` is the terminal end cause recorded on the
/// session and the event.
async fn cascade_user_sessions_ended(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    subject_text: &str,
    cause: SessionEndCause,
    now_micros: i64,
    hard_kill: bool,
    emit: &SessionEndedEmit<'_>,
) -> Result<UserRevocation, StoreError> {
    let mut out = UserRevocation::default();
    let revoked = sqlx::query(
        "UPDATE sessions \
         SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
             revoke_reason = $5, \
             ended_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
             end_cause = $5 \
         WHERE subject = $2 AND tenant_id = $3 AND environment_id = $4 \
         AND revoked_at IS NULL AND ended_at IS NULL \
         RETURNING id",
    )
    .bind(now_micros)
    .bind(subject_text)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(cause.as_str())
    .fetch_all(&mut **tx)
    .await?;
    out.revoked_session_ids = revoked
        .iter()
        .map(|row| row.get::<String, _>("id"))
        .collect();
    out.sessions_revoked = out.revoked_session_ids.len() as u64;
    for session_text in &out.revoked_session_ids {
        enqueue_session_ended_event(
            tx,
            emit,
            scope,
            session_text,
            subject_text,
            cause,
            now_micros,
        )
        .await?;
    }
    sqlx::query(
        "UPDATE client_sessions cs \
         SET revoked_at = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval, \
             revoke_reason = $5 \
         WHERE cs.tenant_id = $3 AND cs.environment_id = $4 \
         AND cs.revoked_at IS NULL \
         AND EXISTS (SELECT 1 FROM sessions s \
                     WHERE s.id = cs.session_id AND s.tenant_id = cs.tenant_id \
                     AND s.environment_id = cs.environment_id AND s.subject = $2)",
    )
    .bind(now_micros)
    .bind(subject_text)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(cause.as_str())
    .execute(&mut **tx)
    .await?;
    cascade_families_for_subject(tx, scope, subject_text, now_micros, hard_kill, &mut out).await?;
    Ok(out)
}

/// Load and unwrap the scope's active KEK (the highest live version), under the
/// platform master key. Returns [`StoreError::Encryption`] when there is no live
/// KEK (never provisioned, or crypto-shredded): a shredded scope's data is then
/// UNREADABLE, never reported as a missing record.
async fn fetch_active_kek(
    conn: &mut PgConnection,
    scope: Scope,
    master: &MasterKey,
) -> Result<(i32, Kek), StoreError> {
    let row = sqlx::query(
        "SELECT version, master_key_id, wrapped_kek FROM tenant_keks \
         WHERE tenant_id = $1 AND environment_id = $2 AND status = 'active' \
         ORDER BY version DESC LIMIT 1",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_optional(&mut *conn)
    .await?;
    let row = row.ok_or(StoreError::Encryption)?;
    let version: i32 = row.get("version");
    let master_key_id: String = row.get("master_key_id");
    let wrapped: Vec<u8> = row.get("wrapped_kek");
    let kek = master.unwrap_kek(
        &kek_wrap_aad(scope, version, &master_key_id),
        &Sealed::from_bytes(wrapped)?,
    )?;
    Ok((version, kek))
}

/// Load and unwrap a specific KEK version under the master key. Used by KEK
/// rotation to unwrap DEKs that were wrapped under the outgoing KEK.
async fn fetch_kek_by_version(
    conn: &mut PgConnection,
    scope: Scope,
    master: &MasterKey,
    version: i32,
) -> Result<Kek, StoreError> {
    let row = sqlx::query(
        "SELECT master_key_id, wrapped_kek FROM tenant_keks \
         WHERE tenant_id = $1 AND environment_id = $2 AND version = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(version)
    .fetch_optional(&mut *conn)
    .await?;
    let row = row.ok_or(StoreError::Encryption)?;
    let master_key_id: String = row.get("master_key_id");
    let wrapped: Vec<u8> = row.get("wrapped_kek");
    let kek = master.unwrap_kek(
        &kek_wrap_aad(scope, version, &master_key_id),
        &Sealed::from_bytes(wrapped)?,
    )?;
    Ok(kek)
}

/// Load and unwrap a specific DEK version (via the KEK that wrapped it).
async fn fetch_dek_by_version(
    conn: &mut PgConnection,
    scope: Scope,
    master: &MasterKey,
    version: i32,
) -> Result<Dek, StoreError> {
    let row = sqlx::query(
        "SELECT kek_version, wrapped_dek FROM tenant_deks \
         WHERE tenant_id = $1 AND environment_id = $2 AND version = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(version)
    .fetch_optional(&mut *conn)
    .await?;
    let row = row.ok_or(StoreError::Encryption)?;
    let kek_version: i32 = row.get("kek_version");
    let wrapped: Vec<u8> = row.get("wrapped_dek");
    let kek = fetch_kek_by_version(conn, scope, master, kek_version).await?;
    let dek = kek.unwrap_dek(&dek_wrap_aad(scope, version), &Sealed::from_bytes(wrapped)?)?;
    Ok(dek)
}

/// Load and unwrap the scope's active DEK (the highest live version).
async fn fetch_active_dek(
    conn: &mut PgConnection,
    scope: Scope,
    master: &MasterKey,
) -> Result<(i32, Dek), StoreError> {
    let version = active_dek_version(conn, scope)
        .await?
        .ok_or(StoreError::Encryption)?;
    let dek = fetch_dek_by_version(conn, scope, master, version).await?;
    Ok((version, dek))
}

/// The scope's highest live KEK version, or `None` if there is no live KEK.
async fn active_kek_version(
    conn: &mut PgConnection,
    scope: Scope,
) -> Result<Option<i32>, StoreError> {
    let row = sqlx::query(
        "SELECT max(version) AS v FROM tenant_keks \
         WHERE tenant_id = $1 AND environment_id = $2 AND status = 'active'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.get::<Option<i32>, _>("v"))
}

/// The scope's highest live DEK version, or `None` if there is no live DEK.
async fn active_dek_version(
    conn: &mut PgConnection,
    scope: Scope,
) -> Result<Option<i32>, StoreError> {
    let row = sqlx::query(
        "SELECT max(version) AS v FROM tenant_deks \
         WHERE tenant_id = $1 AND environment_id = $2 AND status = 'active'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.get::<Option<i32>, _>("v"))
}

/// The highest KEK version stored for the scope (any status), or `None`.
async fn max_kek_version(conn: &mut PgConnection, scope: Scope) -> Result<Option<i32>, StoreError> {
    let row = sqlx::query(
        "SELECT max(version) AS v FROM tenant_keks \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.get::<Option<i32>, _>("v"))
}

/// The highest DEK version stored for the scope (any status), or `None`.
async fn max_dek_version(conn: &mut PgConnection, scope: Scope) -> Result<Option<i32>, StoreError> {
    let row = sqlx::query(
        "SELECT max(version) AS v FROM tenant_deks \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.get::<Option<i32>, _>("v"))
}

/// The closed set of BYOK KMS driver labels the store accepts, mirroring the
/// migration CHECK and the `ironauth-kms` `KmsProviderKind`. Kept here so an
/// enroll can fail closed on a typo before a raw CHECK violation, and no
/// unroutable binding is ever stored.
const BYOK_PROVIDERS: [&str; 5] = ["local", "aws", "gcp", "azure", "vault"];

/// Whether a BYOK binding row already exists for `scope` (in any status), so a
/// second enroll is a Conflict rather than a silent overwrite.
async fn byok_binding_exists(conn: &mut PgConnection, scope: Scope) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "SELECT 1 AS present FROM tenant_byok_bindings \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.is_some())
}

/// A scope's bring-your-own-key binding as read back (issue #49): the KMS driver
/// label, the OPAQUE external key reference (never key material), and the
/// lifecycle status ('active' or 'destroyed'). A severed binding reads status
/// 'destroyed' with an empty `key_ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByokBinding {
    /// The KMS driver label (one of the closed BYOK provider set).
    pub provider: String,
    /// The opaque external key handle (an ARN, resource name, or key URI). A
    /// non-secret reference, cleared to empty when the binding is severed.
    pub key_ref: String,
    /// The binding lifecycle status: 'active' or 'destroyed'.
    pub status: String,
}

/// The read-only envelope-encryption repository (issue #48): decrypt an encrypted
/// secret and inspect the scope's active key versions. Every query is scope
/// filtered and runs under the row-level-security session variables.
pub struct EnvelopeRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl EnvelopeRepo<'_> {
    /// Decrypt the secret stored under `purpose`, under the platform master key.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no secret is stored under `purpose` in this
    /// scope; [`StoreError::Encryption`] if the ciphertext cannot be
    /// authenticated and decrypted (a crypto-shredded scope, a tampered blob);
    /// [`StoreError::Database`] on a persistence failure. The encryption failure
    /// is deliberately distinct from the missing-record case.
    pub async fn open_secret(
        &self,
        master: &MasterKey,
        purpose: &str,
    ) -> Result<Vec<u8>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT dek_version, ciphertext FROM encrypted_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 AND purpose = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(purpose)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Err(StoreError::NotFound);
        };
        let dek_version: i32 = row.get("dek_version");
        let ciphertext: Vec<u8> = row.get("ciphertext");
        let dek = fetch_dek_by_version(&mut tx, self.scope, master, dek_version).await?;
        let plaintext = dek.open(
            &secret_seal_aad(self.scope, purpose, dek_version),
            &Sealed::from_bytes(ciphertext)?,
        )?;
        tx.commit().await?;
        Ok(plaintext)
    }

    /// The DEK version that currently seals the secret under `purpose` (so a test
    /// or a background worker can observe re-encryption advancing it).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no secret is stored under `purpose`.
    pub async fn secret_dek_version(&self, purpose: &str) -> Result<i32, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT dek_version FROM encrypted_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 AND purpose = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(purpose)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(|r| r.get::<i32, _>("dek_version"))
            .ok_or(StoreError::NotFound)
    }

    /// The scope's bring-your-own-key binding, or `None` if the scope is not
    /// enrolled in BYOK (issue #49). A severed binding reads status 'destroyed'
    /// with an empty key reference (retained as erasure evidence). Carries the
    /// opaque reference only, never key material.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn byok_binding(&self) -> Result<Option<ByokBinding>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT provider, key_ref, status FROM tenant_byok_bindings \
             WHERE tenant_id = $1 AND environment_id = $2",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|r| ByokBinding {
            provider: r.get("provider"),
            key_ref: r.get("key_ref"),
            status: r.get("status"),
        }))
    }

    /// The scope's active KEK version, or `None` if the scope has no live KEK
    /// (never provisioned, or crypto-shredded).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn active_kek_version(&self) -> Result<Option<i32>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let version = active_kek_version(&mut tx, self.scope).await?;
        tx.commit().await?;
        Ok(version)
    }

    /// The scope's active DEK version, or `None` if the scope has no live DEK.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn active_dek_version(&self) -> Result<Option<i32>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let version = active_dek_version(&mut tx, self.scope).await?;
        tx.commit().await?;
        Ok(version)
    }
}

/// The mutating envelope-encryption repository (issue #48). Reachable only through
/// [`ScopedStore::acting`], so every lifecycle mutation carries an actor and a
/// correlation id and routes through the module's single audited-write primitive.
pub struct ActingEnvelopeRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingEnvelopeRepo<'_> {
    /// Provision the scope's day-one KEK: generate a fresh KEK, wrap it under the
    /// platform master key, and store version 1. Audited.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if the scope already has a KEK;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn provision_kek(&self, env: &Env, master: &MasterKey) -> Result<KekId, StoreError> {
        let scope = self.scope;
        let id = KekId::generate(env, &scope);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvelopeKekProvision,
                target: &id,
            },
            async move |tx| {
                if max_kek_version(tx, scope).await?.is_some() {
                    return Err(StoreError::Conflict);
                }
                let kek = Kek::generate(env.entropy());
                let wrapped =
                    master.wrap_kek(env.entropy(), &kek_wrap_aad(scope, 1, master.id()), &kek);
                sqlx::query(
                    "INSERT INTO tenant_keks \
                     (id, tenant_id, environment_id, version, master_key_id, wrapped_kek, status) \
                     VALUES ($1, $2, $3, 1, $4, $5, 'active')",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(master.id())
                .bind(wrapped.into_bytes())
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Enroll this scope in bring-your-own-key (issue #49): record a BYOK binding
    /// so a customer-managed root key (in an external KMS/HSM, or a
    /// customer-supplied key) governs the scope's key hierarchy. `provider` is the
    /// KMS driver label (one of the closed set the store CHECK enforces) and
    /// `key_ref` is the OPAQUE external key handle (an ARN, a resource name, a key
    /// URI); NEITHER is key material, and no customer root key is ever persisted.
    /// The actual wrap/unwrap of the tenant KEK under the customer root is the
    /// `ironauth-kms` driver seam's job; this only records the binding. Audited as
    /// `envelope.byok.enroll`.
    ///
    /// BYOK is EXPERIMENTAL and DEFAULT-OFF; a caller reaches this only when the
    /// operator has enabled it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if the scope is already enrolled;
    /// [`StoreError::Encryption`] if `provider` is not a known KMS driver label
    /// (fail closed rather than store an unroutable binding);
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn enroll_byok(
        &self,
        env: &Env,
        provider: &str,
        key_ref: &str,
    ) -> Result<(), StoreError> {
        // Fail closed on an unknown driver label before touching the database, so a
        // typo never lands as a raw CHECK violation and no unroutable binding is
        // stored. The set mirrors the migration CHECK and the ironauth-kms drivers.
        if !BYOK_PROVIDERS.contains(&provider) {
            return Err(StoreError::Encryption);
        }
        let scope = self.scope;
        let environment = scope.environment();
        // The provider and key reference are moved into the audited closure.
        let provider = provider.to_owned();
        let key_ref = key_ref.to_owned();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvelopeByokEnroll,
                target: &environment,
            },
            async move |tx| {
                let created_micros = epoch_micros(env.clock().now_utc());
                // One binding per scope: a second enroll is a Conflict, surfaced from
                // the primary-key violation rather than a silent overwrite.
                if byok_binding_exists(tx, scope).await? {
                    return Err(StoreError::Conflict);
                }
                sqlx::query(
                    "INSERT INTO tenant_byok_bindings \
                     (tenant_id, environment_id, provider, key_ref, status, created_at) \
                     VALUES ($1, $2, $3, $4, 'active', \
                             TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval)",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&provider)
                .bind(&key_ref)
                .bind(created_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Provision the scope's day-one DEK: generate a fresh DEK, wrap it under the
    /// scope's active KEK, and store version 1. Audited.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] if the scope already has a DEK;
    /// [`StoreError::Encryption`] if the scope has no live KEK to wrap under;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn provision_dek(&self, env: &Env, master: &MasterKey) -> Result<DekId, StoreError> {
        let scope = self.scope;
        let id = DekId::generate(env, &scope);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvelopeDekProvision,
                target: &id,
            },
            async move |tx| {
                if max_dek_version(tx, scope).await?.is_some() {
                    return Err(StoreError::Conflict);
                }
                let (kek_version, kek) = fetch_active_kek(tx, scope, master).await?;
                let dek = Dek::generate(env.entropy());
                let wrapped = kek.wrap_dek(env.entropy(), &dek_wrap_aad(scope, 1), &dek);
                sqlx::query(
                    "INSERT INTO tenant_deks \
                     (id, tenant_id, environment_id, version, kek_version, wrapped_dek, status) \
                     VALUES ($1, $2, $3, 1, $4, $5, 'active')",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(kek_version)
                .bind(wrapped.into_bytes())
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Rotate the scope's KEK online: generate a fresh KEK version, re-wrap EVERY
    /// one of the scope's DEKs under it (unwrap under the outgoing KEK, wrap under
    /// the incoming one), and retire the outgoing KEK. No record payload is
    /// rewritten, so old ciphertext still reads. Audited, all in one transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if the scope has no live KEK to rotate;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn rotate_kek(&self, env: &Env, master: &MasterKey) -> Result<KekId, StoreError> {
        let scope = self.scope;
        let id = KekId::generate(env, &scope);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvelopeKekRotate,
                target: &id,
            },
            async move |tx| {
                // Require a live KEK to rotate; the outgoing KEK stays active until
                // the DEK re-wrap below finishes reading through it.
                let old_version = active_kek_version(tx, scope)
                    .await?
                    .ok_or(StoreError::Encryption)?;
                let new_version = old_version + 1;
                let new_kek = Kek::generate(env.entropy());
                let wrapped_new_kek = master.wrap_kek(
                    env.entropy(),
                    &kek_wrap_aad(scope, new_version, master.id()),
                    &new_kek,
                );
                sqlx::query(
                    "INSERT INTO tenant_keks \
                     (id, tenant_id, environment_id, version, master_key_id, wrapped_kek, status) \
                     VALUES ($1, $2, $3, $4, $5, $6, 'active')",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(new_version)
                .bind(master.id())
                .bind(wrapped_new_kek.into_bytes())
                .execute(&mut **tx)
                .await?;

                // Re-wrap every DEK under the new KEK. The DEK-wrap AAD is
                // constant across the rotation, so this is a cheap re-seal of the
                // 32 key bytes, never a record-payload rewrite.
                let dek_rows = sqlx::query(
                    "SELECT version FROM tenant_deks \
                     WHERE tenant_id = $1 AND environment_id = $2 ORDER BY version",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .fetch_all(&mut **tx)
                .await?;
                for dek_row in &dek_rows {
                    let dek_version: i32 = dek_row.get("version");
                    let dek = fetch_dek_by_version(tx, scope, master, dek_version).await?;
                    let rewrapped =
                        new_kek.wrap_dek(env.entropy(), &dek_wrap_aad(scope, dek_version), &dek);
                    sqlx::query(
                        "UPDATE tenant_deks SET wrapped_dek = $4, kek_version = $5 \
                         WHERE tenant_id = $1 AND environment_id = $2 AND version = $3",
                    )
                    .bind(scope.tenant().to_string())
                    .bind(scope.environment().to_string())
                    .bind(dek_version)
                    .bind(rewrapped.into_bytes())
                    .bind(new_version)
                    .execute(&mut **tx)
                    .await?;
                }

                // Retire the outgoing KEK: it is no longer the active head and no
                // DEK references it, but the row is retained (destroyed only by a
                // crypto-shred).
                sqlx::query(
                    "UPDATE tenant_keks SET status = 'retired' \
                     WHERE tenant_id = $1 AND environment_id = $2 AND version = $3",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(old_version)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Rotate the scope's DEK: generate a fresh DEK version (wrapped under the
    /// active KEK) for NEW writes, and retire the outgoing DEK, which stays
    /// readable so old rows decrypt until background re-encryption advances them.
    /// Audited.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if the scope has no live KEK/DEK;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn rotate_dek(&self, env: &Env, master: &MasterKey) -> Result<DekId, StoreError> {
        let scope = self.scope;
        let id = DekId::generate(env, &scope);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvelopeDekRotate,
                target: &id,
            },
            async move |tx| {
                let current = max_dek_version(tx, scope)
                    .await?
                    .ok_or(StoreError::Encryption)?;
                let new_version = current + 1;
                let (kek_version, kek) = fetch_active_kek(tx, scope, master).await?;
                let dek = Dek::generate(env.entropy());
                let wrapped = kek.wrap_dek(env.entropy(), &dek_wrap_aad(scope, new_version), &dek);
                // Retire the current active DEK (readable, not written to).
                sqlx::query(
                    "UPDATE tenant_deks SET status = 'retired' \
                     WHERE tenant_id = $1 AND environment_id = $2 AND status = 'active'",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                sqlx::query(
                    "INSERT INTO tenant_deks \
                     (id, tenant_id, environment_id, version, kek_version, wrapped_dek, status) \
                     VALUES ($1, $2, $3, $4, $5, $6, 'active')",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(new_version)
                .bind(kek_version)
                .bind(wrapped.into_bytes())
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Crypto-shred the scope's KEK: overwrite every KEK version's wrapped bytes
    /// with an empty blob and mark it destroyed. After this the scope's DEKs can
    /// never be unwrapped, so every one of its ciphertexts is permanently
    /// unreadable (the offboarding property #49 productizes). Audited.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the scope has no KEK to destroy;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn destroy_kek(&self, env: &Env) -> Result<KekId, StoreError> {
        let scope = self.scope;
        // The audit target is the scope's highest KEK version (read out of band).
        let mut probe = begin_scoped(self.store, scope).await?;
        let target_row = sqlx::query(
            "SELECT id FROM tenant_keks \
             WHERE tenant_id = $1 AND environment_id = $2 ORDER BY version DESC LIMIT 1",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_optional(&mut *probe)
        .await?;
        probe.commit().await?;
        let target_text: String = target_row.ok_or(StoreError::NotFound)?.get("id");
        let target = KekId::parse_in_scope(&target_text, &scope)?;

        let destroyed_micros = epoch_micros(env.clock().now_utc());
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvelopeKekDestroy,
                target: &target,
            },
            async move |tx| {
                // Overwrite the wrapped KEK bytes (crypto-shred) and mark every
                // not-yet-destroyed version destroyed, stamping the instant from
                // the application clock seam.
                sqlx::query(
                    "UPDATE tenant_keks \
                     SET wrapped_kek = $3, status = 'destroyed', \
                         destroyed_at = TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
                     WHERE tenant_id = $1 AND environment_id = $2 AND status <> 'destroyed'",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(Vec::<u8>::new())
                .bind(destroyed_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(target)
    }

    /// Write an encrypted secret under `purpose`: seal `plaintext` under the
    /// scope's active DEK with the column context bound as associated data, and
    /// upsert it (one secret per purpose per scope). Audited.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if the scope has no live KEK/DEK to seal under;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn put_secret(
        &self,
        env: &Env,
        master: &MasterKey,
        purpose: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedSecretId, StoreError> {
        let scope = self.scope;
        // Reuse an existing row's id (a stable audit target across overwrites),
        // or mint a fresh one for a first write.
        let mut probe = begin_scoped(self.store, scope).await?;
        let existing = sqlx::query(
            "SELECT id FROM encrypted_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 AND purpose = $3",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(purpose)
        .fetch_optional(&mut *probe)
        .await?;
        probe.commit().await?;
        let id = match existing {
            Some(row) => EncryptedSecretId::parse_in_scope(&row.get::<String, _>("id"), &scope)?,
            None => EncryptedSecretId::generate(env, &scope),
        };
        let updated_micros = epoch_micros(env.clock().now_utc());
        let plaintext = plaintext.to_vec();
        let purpose_owned = purpose.to_string();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EncryptedSecretPut,
                target: &id,
            },
            async move |tx| {
                let (dek_version, dek) = fetch_active_dek(tx, scope, master).await?;
                let sealed = dek.seal(
                    env.entropy(),
                    &secret_seal_aad(scope, &purpose_owned, dek_version),
                    &plaintext,
                );
                sqlx::query(
                    "INSERT INTO encrypted_secrets \
                     (id, tenant_id, environment_id, purpose, dek_version, ciphertext, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval) \
                     ON CONFLICT (tenant_id, environment_id, purpose) DO UPDATE \
                     SET ciphertext = EXCLUDED.ciphertext, dek_version = EXCLUDED.dek_version, \
                         updated_at = EXCLUDED.updated_at",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&purpose_owned)
                .bind(dek_version)
                .bind(sealed.into_bytes())
                .bind(updated_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Re-encrypt the secret under `purpose` from its current DEK version onto the
    /// scope's active DEK version (the observable background re-encryption step a
    /// DEK rotation schedules). The plaintext never changes; only the sealing key
    /// version does. Returns whether the secret advanced (it is a no-op, and not
    /// audited, when the secret is already on the active version). Audited when it
    /// re-encrypts.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no secret is stored under `purpose`;
    /// [`StoreError::Encryption`] if the ciphertext cannot be decrypted (a
    /// crypto-shredded scope); [`StoreError::Database`] on a persistence failure.
    pub async fn reencrypt_secret(
        &self,
        env: &Env,
        master: &MasterKey,
        purpose: &str,
    ) -> Result<bool, StoreError> {
        let scope = self.scope;
        // Pre-check: is the secret already on the active DEK version?
        let mut probe = begin_scoped(self.store, scope).await?;
        let row = sqlx::query(
            "SELECT id, dek_version FROM encrypted_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 AND purpose = $3",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(purpose)
        .fetch_optional(&mut *probe)
        .await?;
        let active = active_dek_version(&mut probe, scope).await?;
        probe.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        let id = EncryptedSecretId::parse_in_scope(&row.get::<String, _>("id"), &scope)?;
        let current: i32 = row.get("dek_version");
        let active = active.ok_or(StoreError::Encryption)?;
        if current == active {
            return Ok(false);
        }

        let purpose_owned = purpose.to_string();
        let updated_micros = epoch_micros(env.clock().now_utc());
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EncryptedSecretReencrypt,
                target: &id,
            },
            async move |tx| {
                // Re-read within the write transaction so the re-encryption is
                // consistent even under a concurrent overwrite.
                let secret_row = sqlx::query(
                    "SELECT dek_version, ciphertext FROM encrypted_secrets \
                     WHERE tenant_id = $1 AND environment_id = $2 AND purpose = $3",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&purpose_owned)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or(StoreError::NotFound)?;
                let old_version: i32 = secret_row.get("dek_version");
                let ciphertext: Vec<u8> = secret_row.get("ciphertext");
                let (active_version, active_dek) = fetch_active_dek(tx, scope, master).await?;
                if old_version == active_version {
                    return Ok(());
                }
                let old_dek = fetch_dek_by_version(tx, scope, master, old_version).await?;
                let plaintext = old_dek.open(
                    &secret_seal_aad(scope, &purpose_owned, old_version),
                    &Sealed::from_bytes(ciphertext)?,
                )?;
                let resealed = active_dek.seal(
                    env.entropy(),
                    &secret_seal_aad(scope, &purpose_owned, active_version),
                    &plaintext,
                );
                sqlx::query(
                    "UPDATE encrypted_secrets \
                     SET ciphertext = $4, dek_version = $5, \
                         updated_at = TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval \
                     WHERE tenant_id = $1 AND environment_id = $2 AND purpose = $3",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&purpose_owned)
                .bind(resealed.into_bytes())
                .bind(active_version)
                .bind(updated_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(true)
    }
}

// ===========================================================================
// Environment-scoped secrets and variables (issue #45).
//
// The per-(tenant, environment) store the config-promotion flagship resolves
// references against. Two tenant-scoped tables, isolated exactly like every other
// scoped table (forced row-level security on the (tenant, environment) session
// variables, reached only through this module). VARIABLES are non-secret
// promotable config (name -> plaintext value, readable). SECRETS are write-only:
// the plaintext is sealed under the scope's envelope DEK (issue #48, the same
// AEAD substrate that seals the users PII columns) and stored as ciphertext on the
// environment_secrets table; a read returns metadata only (name, version,
// updated-at), never the value. The tenant, environment, secret name, and DEK
// version are bound as associated data, so a ciphertext cannot be replayed across
// a row, tenant, environment, secret, or key version.
// ===========================================================================

/// The envelope seal PURPOSE under which an environment secret's value is sealed
/// (issue #45): the secret's name, namespaced so it can never collide with any
/// other envelope purpose (the custom-domain certificate purpose, a users PII
/// purpose). Bound into the seal associated data, so a ciphertext sealed for one
/// secret name never authenticates for another.
fn env_secret_seal_purpose(name: &str) -> String {
    format!("env_secret:{name}")
}

/// One environment variable as read back (issue #45): the non-secret value plus
/// its metadata. A variable value IS readable (it is promotable config), unlike a
/// secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentVariableRecord {
    /// The variable identifier (`var_...`, embeds its `(tenant, environment)`).
    pub id: VariableId,
    /// The variable name (the reference key), unique per scope.
    pub name: String,
    /// The non-secret configuration value.
    pub value: String,
    /// The monotonic write version, bumped on every overwrite.
    pub version: i32,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
    /// Last-write time in microseconds since the Unix epoch.
    pub updated_at_unix_micros: i64,
}

/// One environment secret's METADATA as read back (issue #45): NEVER the value.
/// A read of a secret returns presence and these fields only, the write-only
/// discipline (the #11 secret lesson: a management API that returns a live secret
/// is a leak).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentSecretMetadata {
    /// The secret identifier (`esec_...`, embeds its `(tenant, environment)`).
    pub id: EnvironmentSecretId,
    /// The secret name (the reference key), unique per scope.
    pub name: String,
    /// The monotonic write version, bumped on every overwrite.
    pub version: i32,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
    /// Last-write time in microseconds since the Unix epoch.
    pub updated_at_unix_micros: i64,
}

/// Reconstruct an [`EnvironmentVariableRecord`] from a row read within scope.
fn environment_variable_from_row(
    row: &PgRow,
    scope: &Scope,
) -> Result<EnvironmentVariableRecord, StoreError> {
    let id = VariableId::parse_in_scope(&row.get::<String, _>("id"), scope)?;
    Ok(EnvironmentVariableRecord {
        id,
        name: row.get("name"),
        value: row.get("value"),
        version: row.get("version"),
        created_at_unix_micros: row.get("created_us"),
        updated_at_unix_micros: row.get("updated_us"),
    })
}

/// Reconstruct an [`EnvironmentSecretMetadata`] from a row read within scope. The
/// ciphertext column is deliberately NOT selected into this metadata view.
fn environment_secret_metadata_from_row(
    row: &PgRow,
    scope: &Scope,
) -> Result<EnvironmentSecretMetadata, StoreError> {
    let id = EnvironmentSecretId::parse_in_scope(&row.get::<String, _>("id"), scope)?;
    Ok(EnvironmentSecretMetadata {
        id,
        name: row.get("name"),
        version: row.get("version"),
        created_at_unix_micros: row.get("created_us"),
        updated_at_unix_micros: row.get("updated_us"),
    })
}

/// Read-only environment variables for one scope (issue #45).
pub struct EnvironmentVariableRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl EnvironmentVariableRepo<'_> {
    /// Fetch a variable by name (its value and metadata), within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no variable of that name exists in this scope.
    pub async fn get(&self, name: &str) -> Result<EnvironmentVariableRecord, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, name, value, version, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint AS updated_us \
             FROM environment_variables \
             WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        environment_variable_from_row(&row, &self.scope)
    }

    /// Whether a variable of `name` exists in this scope (the plan-time resolution
    /// check; reads no value).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn exists(&self, name: &str) -> Result<bool, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT 1 AS present FROM environment_variables \
             WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.is_some())
    }

    /// One page of variables in this scope, ordered by `(created_at, id)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<EnvironmentVariableRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, name, value, version, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint AS updated_us \
             FROM environment_variables \
             WHERE tenant_id = $1 AND environment_id = $2 \
             AND ($3::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4::text)) \
             ORDER BY created_at, id LIMIT $5",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| environment_variable_from_row(row, &self.scope))
            .collect()
    }

    /// EVERY variable in this scope (no pagination), ordered by name: the set the
    /// snapshot export (issue #43) projects. A variable is promotable config, so
    /// its name and value both travel in the snapshot.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list_all(&self) -> Result<Vec<EnvironmentVariableRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, name, value, version, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint AS updated_us \
             FROM environment_variables \
             WHERE tenant_id = $1 AND environment_id = $2 ORDER BY name",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| environment_variable_from_row(row, &self.scope))
            .collect()
    }

    /// The names of the variables in this scope whose VALUE is a live reference to
    /// `reference` (issue #45): the referent list a delete of the referenced
    /// variable or secret is rejected with. A variable's own row is never its own
    /// referent (a degenerate self-reference does not block deleting it). A config
    /// field is a referent only when its whole value parses as that exact
    /// reference, never on a literal that merely contains the syntax.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn referents(
        &self,
        reference: &crate::esv::Reference,
    ) -> Result<Vec<String>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT name, value FROM environment_variables \
             WHERE tenant_id = $1 AND environment_id = $2 ORDER BY name",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut referents = Vec::new();
        for row in &rows {
            let name: String = row.get("name");
            let value: String = row.get("value");
            // A variable referencing ITSELF is not a blocker for its own delete.
            if reference.kind == crate::esv::ReferenceKind::Variable && name == reference.name {
                continue;
            }
            if matches!(
                crate::esv::Reference::parse(&value),
                Ok(parsed) if parsed == *reference
            ) {
                referents.push(name);
            }
        }
        Ok(referents)
    }
}

/// Read-only environment secrets for one scope (issue #45). Reads metadata and, on
/// the resolution path, opens a sealed value under the platform master key.
pub struct EnvironmentSecretRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl EnvironmentSecretRepo<'_> {
    /// Fetch a secret's METADATA by name (never its value), within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no secret of that name exists in this scope.
    pub async fn metadata(&self, name: &str) -> Result<EnvironmentSecretMetadata, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, name, version, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint AS updated_us \
             FROM environment_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        environment_secret_metadata_from_row(&row, &self.scope)
    }

    /// Whether a secret of `name` exists in this scope (the plan-time resolution
    /// check; reads no value and opens no ciphertext).
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn exists(&self, name: &str) -> Result<bool, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT 1 AS present FROM environment_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.is_some())
    }

    /// One page of secret METADATA in this scope, ordered by `(created_at, id)`.
    /// No page ever carries a secret value.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<EnvironmentSecretMetadata>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, name, version, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint AS updated_us \
             FROM environment_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 \
             AND ($3::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4::text)) \
             ORDER BY created_at, id LIMIT $5",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP + 1))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| environment_secret_metadata_from_row(row, &self.scope))
            .collect()
    }

    /// Open (decrypt) the secret stored under `name`, under the platform master
    /// key (issue #45): the apply-time value resolution. This is the ONLY read
    /// path that ever returns a secret value, and it is never reached by a list, a
    /// metadata read, the snapshot export, or any audit record.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no secret of that name exists in this scope;
    /// [`StoreError::Encryption`] if the ciphertext cannot be authenticated and
    /// decrypted (a crypto-shredded scope, a tampered blob); [`StoreError::Database`]
    /// on a persistence failure.
    pub async fn open_value(&self, master: &MasterKey, name: &str) -> Result<Vec<u8>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT dek_version, ciphertext FROM environment_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Err(StoreError::NotFound);
        };
        let dek_version: i32 = row.get("dek_version");
        let ciphertext: Vec<u8> = row.get("ciphertext");
        let dek = fetch_dek_by_version(&mut tx, self.scope, master, dek_version).await?;
        let plaintext = dek.open(
            &secret_seal_aad(self.scope, &env_secret_seal_purpose(name), dek_version),
            &Sealed::from_bytes(ciphertext)?,
        )?;
        tx.commit().await?;
        Ok(plaintext)
    }
}

/// The mutating environment-variable repository for one scope and actor (issue #45).
pub struct ActingEnvironmentVariableRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingEnvironmentVariableRepo<'_> {
    /// Set a variable (a first write or an overwrite) and audit
    /// `environment_variable.set` in the same transaction. One value per (scope,
    /// name): a repeat write to the same name overwrites the value in place and
    /// bumps its version, reusing the row's id (a stable audit target across
    /// overwrites). Optionally records an Idempotency-Key in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidName`] if `name` is not a valid reference key;
    /// [`StoreError::IdempotencyConflict`] on a concurrent Idempotency-Key race;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn set(
        &self,
        env: &Env,
        name: &str,
        value: &str,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<VariableId, StoreError> {
        if !crate::esv::name_is_valid(name) {
            return Err(StoreError::InvalidName);
        }
        let scope = self.scope;
        let id = self.existing_variable_id_or_new(env, name).await?;
        let now_micros = epoch_micros(env.clock().now_utc());
        let name_owned = name.to_string();
        let value_owned = value.to_string();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvironmentVariableSet,
                target: &id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO environment_variables \
                     (id, tenant_id, environment_id, name, value, version, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, 1, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval) \
                     ON CONFLICT (tenant_id, environment_id, name) DO UPDATE \
                     SET value = EXCLUDED.value, \
                         version = environment_variables.version + 1, \
                         updated_at = EXCLUDED.updated_at",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&name_owned)
                .bind(&value_owned)
                .bind(now_micros)
                .execute(&mut **tx)
                .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Delete a variable and audit `environment_variable.delete` in the same
    /// transaction (issue #45). REJECTED while a live variable value in the scope
    /// still references it (a rename is create-plus-delete, and the delete is
    /// protected by the referent check); the caller enumerates the referents with
    /// [`EnvironmentVariableRepo::referents`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no variable of that name exists in this scope;
    /// [`StoreError::Conflict`] if the variable is still referenced;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn delete(&self, env: &Env, name: &str) -> Result<(), StoreError> {
        let scope = self.scope;
        // Load the row's id up front (a stable audit target) and fail closed if it
        // is absent.
        let id = self.variable_id(name).await?;
        let reference = crate::esv::Reference {
            kind: crate::esv::ReferenceKind::Variable,
            name: name.to_string(),
        };
        let referents = EnvironmentVariableRepo {
            store: self.store,
            scope,
        }
        .referents(&reference)
        .await?;
        if !referents.is_empty() {
            return Err(StoreError::Conflict);
        }
        let name_owned = name.to_string();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvironmentVariableDelete,
                target: &id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "DELETE FROM environment_variables \
                     WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&name_owned)
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// The id of an existing variable by name, reused so an overwrite keeps a
    /// stable audit target; a fresh id for a first write.
    async fn existing_variable_id_or_new(
        &self,
        env: &Env,
        name: &str,
    ) -> Result<VariableId, StoreError> {
        match self.variable_id(name).await {
            Ok(id) => Ok(id),
            Err(StoreError::NotFound) => Ok(VariableId::generate(env, &self.scope)),
            Err(other) => Err(other),
        }
    }

    /// The stored id of the variable named `name`, or [`StoreError::NotFound`].
    async fn variable_id(&self, name: &str) -> Result<VariableId, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id FROM environment_variables \
             WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        Ok(VariableId::parse_in_scope(
            &row.get::<String, _>("id"),
            &self.scope,
        )?)
    }
}

/// The mutating environment-secret repository for one scope and actor (issue #45).
pub struct ActingEnvironmentSecretRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingEnvironmentSecretRepo<'_> {
    /// Put a secret (a first write or an overwrite): seal `plaintext` under the
    /// scope's active envelope DEK (issue #48), store it as ciphertext, and audit
    /// `environment_secret.put` in the same transaction (issue #45). WRITE-ONLY:
    /// the plaintext is never recorded, not in the row (only ciphertext), not in
    /// the audit envelope, not in any response. One value per (scope, name): a
    /// repeat write overwrites in place, bumps the version, and reuses the row's id.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidName`] if `name` is not a valid reference key;
    /// [`StoreError::Encryption`] if the scope has no key hierarchy to seal under
    /// and one cannot be provisioned; [`StoreError::IdempotencyConflict`] on a
    /// concurrent Idempotency-Key race; [`StoreError::Database`] on a persistence
    /// failure.
    pub async fn put(
        &self,
        env: &Env,
        master: &MasterKey,
        name: &str,
        plaintext: &[u8],
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<EnvironmentSecretId, StoreError> {
        if !crate::esv::name_is_valid(name) {
            return Err(StoreError::InvalidName);
        }
        let scope = self.scope;
        // The scope needs a live KEK/DEK before the first secret seal; provision
        // them lazily (idempotent) outside the put transaction, exactly as the
        // users PII path does.
        self.ensure_scope_keys(env, master).await?;
        let id = self.existing_secret_id_or_new(env, name).await?;
        let now_micros = epoch_micros(env.clock().now_utc());
        let name_owned = name.to_string();
        let plaintext = plaintext.to_vec();
        let purpose = env_secret_seal_purpose(name);
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvironmentSecretPut,
                target: &id,
            },
            async move |tx| {
                let (dek_version, dek) = fetch_active_dek(tx, scope, master).await?;
                let sealed = dek.seal(
                    env.entropy(),
                    &secret_seal_aad(scope, &purpose, dek_version),
                    &plaintext,
                );
                sqlx::query(
                    "INSERT INTO environment_secrets \
                     (id, tenant_id, environment_id, name, dek_version, ciphertext, version, \
                      created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, 1, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval) \
                     ON CONFLICT (tenant_id, environment_id, name) DO UPDATE \
                     SET ciphertext = EXCLUDED.ciphertext, dek_version = EXCLUDED.dek_version, \
                         version = environment_secrets.version + 1, \
                         updated_at = EXCLUDED.updated_at",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&name_owned)
                .bind(dek_version)
                .bind(sealed.into_bytes())
                .bind(now_micros)
                .execute(&mut **tx)
                .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await?;
        Ok(id)
    }

    /// Delete a secret and audit `environment_secret.delete` in the same
    /// transaction (issue #45). REJECTED while a live variable value in the scope
    /// still references it (the same referent protection variables have); the
    /// caller enumerates the referents with [`EnvironmentVariableRepo::referents`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no secret of that name exists in this scope;
    /// [`StoreError::Conflict`] if the secret is still referenced;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn delete(&self, env: &Env, name: &str) -> Result<(), StoreError> {
        let scope = self.scope;
        let id = self.secret_id(name).await?;
        let reference = crate::esv::Reference {
            kind: crate::esv::ReferenceKind::Secret,
            name: name.to_string(),
        };
        let referents = EnvironmentVariableRepo {
            store: self.store,
            scope,
        }
        .referents(&reference)
        .await?;
        if !referents.is_empty() {
            return Err(StoreError::Conflict);
        }
        let name_owned = name.to_string();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvironmentSecretDelete,
                target: &id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "DELETE FROM environment_secrets \
                     WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&name_owned)
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Ensure the scope has a live KEK and DEK to seal a secret under, provisioning
    /// each lazily on first use. Idempotent (a Conflict from an already-provisioned
    /// key is swallowed), exactly as the users PII path does.
    async fn ensure_scope_keys(&self, env: &Env, master: &MasterKey) -> Result<(), StoreError> {
        let envelope = ActingEnvelopeRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
        };
        match envelope.provision_kek(env, master).await {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error),
        }
        match envelope.provision_dek(env, master).await {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// The id of an existing secret by name, reused so an overwrite keeps a stable
    /// audit target; a fresh id for a first write.
    async fn existing_secret_id_or_new(
        &self,
        env: &Env,
        name: &str,
    ) -> Result<EnvironmentSecretId, StoreError> {
        match self.secret_id(name).await {
            Ok(id) => Ok(id),
            Err(StoreError::NotFound) => Ok(EnvironmentSecretId::generate(env, &self.scope)),
            Err(other) => Err(other),
        }
    }

    /// The stored id of the secret named `name`, or [`StoreError::NotFound`].
    async fn secret_id(&self, name: &str) -> Result<EnvironmentSecretId, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id FROM environment_secrets \
             WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        Ok(EnvironmentSecretId::parse_in_scope(
            &row.get::<String, _>("id"),
            &self.scope,
        )?)
    }
}

// ===========================================================================
// Per-environment custom domains with built-in ACME (issue #47, EXPLORATORY).
//
// The persistence half of custom domains: a customer proves control of a domain
// through an ACME challenge, a CA issues a certificate, and the cert plus its
// PRIVATE KEY are stored sealed under the scope's envelope DEK (issue #48). All
// SQL against `custom_domains` and `acme_challenges` lives here, in the one
// scoped-SQL module. The outbound ACME/CA HTTP is NOT here: it is confined to the
// SSRF-hardened `ironauth-fetch` path (the ACME directory client in
// ironauth-oidc), because a custom domain is tenant-controlled and untrusted.
//
// Cross-tenant exclusivity (issue #47 acceptance: one tenant cannot claim
// another tenant's verified domain) is enforced by the DATABASE: a global partial
// unique index on the domain name of VERIFIED rows (migration 0031) is maintained
// across every row irrespective of row-level security, so a second tenant's
// transition to verified for a name already verified elsewhere is refused with a
// unique violation, even though that tenant cannot see the conflicting row.

/// The `encrypted_secrets` purpose under which a domain's sealed certificate
/// bundle (cert chain plus private key) is stored. Bound per domain id so each
/// domain's cert is a distinct sealed secret.
fn cert_secret_purpose(domain: &CustomDomainId) -> String {
    format!("custom_domain_cert:{domain}")
}

/// The deterministic retry backoff after a failed challenge attempt: a capped
/// exponential in the attempt count, computed purely (no clock read), so the
/// schedule a manual clock observes is reproducible. Attempt 0 waits the base
/// interval, each further attempt doubles it, capped at one hour.
fn challenge_backoff(attempts: i32) -> Duration {
    const BASE_SECS: u64 = 60;
    const CAP_SECS: u64 = 3600;
    let shift = u32::try_from(attempts.max(0)).unwrap_or(u32::MAX).min(16);
    let secs = BASE_SECS.saturating_mul(1_u64 << shift).min(CAP_SECS);
    Duration::from_secs(secs)
}

/// Map one `custom_domains` row into a typed record, parsing its ids in scope and
/// its wire-token columns into their enums.
fn row_to_custom_domain(scope: Scope, row: &PgRow) -> Result<CustomDomainRecord, StoreError> {
    let id = CustomDomainId::parse_in_scope(&row.get::<String, _>("id"), &scope)?;
    let cert_secret_id = row
        .get::<Option<String>, _>("cert_secret_id")
        .map(|raw| EncryptedSecretId::parse_in_scope(&raw, &scope))
        .transpose()?;
    Ok(CustomDomainRecord {
        id,
        domain_name: row.get("domain_name"),
        challenge_type: ChallengeType::parse(&row.get::<String, _>("challenge_type"))?,
        verification_status: VerificationStatus::parse(
            &row.get::<String, _>("verification_status"),
        )?,
        cert_secret_id,
        cert_not_after_micros: row.get::<Option<i64>, _>("cert_not_after_us"),
    })
}

/// Map one `acme_challenges` row into a typed record.
fn row_to_acme_challenge(scope: Scope, row: &PgRow) -> Result<AcmeChallengeRecord, StoreError> {
    let id = AcmeChallengeId::parse_in_scope(&row.get::<String, _>("id"), &scope)?;
    let domain_id = CustomDomainId::parse_in_scope(&row.get::<String, _>("domain_id"), &scope)?;
    Ok(AcmeChallengeRecord {
        id,
        domain_id,
        challenge_type: ChallengeType::parse(&row.get::<String, _>("challenge_type"))?,
        token: row.get("token"),
        status: ChallengeStatus::parse(&row.get::<String, _>("status"))?,
        attempts: row.get("attempts"),
        next_attempt_at_micros: row.get::<Option<i64>, _>("next_attempt_us"),
    })
}

/// The read-only custom-domain repository (issue #47). Reads need no actor.
pub struct CustomDomainRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl CustomDomainRepo<'_> {
    /// Fetch a registered domain by its (normalized) name in this scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such domain is registered in this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn get_by_name(&self, domain_name: &str) -> Result<CustomDomainRecord, StoreError> {
        // Look up by the same canonical form registration stored, so a query in
        // any case or with a trailing root dot finds the one registered row.
        let domain_name = crate::custom_domain::normalize_domain(domain_name);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, domain_name, challenge_type, verification_status, cert_secret_id, \
                    (EXTRACT(EPOCH FROM cert_not_after) * 1000000)::bigint AS cert_not_after_us \
             FROM custom_domains \
             WHERE tenant_id = $1 AND environment_id = $2 AND domain_name = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(&domain_name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        row_to_custom_domain(self.scope, &row)
    }

    /// Fetch a registered domain by its id in this scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the id is out of scope or absent;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn get(&self, id: &CustomDomainId) -> Result<CustomDomainRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, domain_name, challenge_type, verification_status, cert_secret_id, \
                    (EXTRACT(EPOCH FROM cert_not_after) * 1000000)::bigint AS cert_not_after_us \
             FROM custom_domains \
             WHERE tenant_id = $1 AND environment_id = $2 AND id = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        row_to_custom_domain(self.scope, &row)
    }

    /// List every registered domain in this scope, newest first.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(&self) -> Result<Vec<CustomDomainRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, domain_name, challenge_type, verification_status, cert_secret_id, \
                    (EXTRACT(EPOCH FROM cert_not_after) * 1000000)::bigint AS cert_not_after_us \
             FROM custom_domains \
             WHERE tenant_id = $1 AND environment_id = $2 \
             ORDER BY created_at DESC, id DESC",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| row_to_custom_domain(self.scope, row))
            .collect()
    }

    /// Fetch an ACME challenge by its id in this scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the id is out of scope or absent;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn get_challenge(
        &self,
        id: &AcmeChallengeId,
    ) -> Result<AcmeChallengeRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, domain_id, challenge_type, token, status, attempts, \
                    (EXTRACT(EPOCH FROM next_attempt_at) * 1000000)::bigint AS next_attempt_us \
             FROM acme_challenges \
             WHERE tenant_id = $1 AND environment_id = $2 AND id = $3",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        row_to_acme_challenge(self.scope, &row)
    }

    /// List the ACME challenges of a domain in this scope, newest first.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn challenges_for(
        &self,
        domain_id: &CustomDomainId,
    ) -> Result<Vec<AcmeChallengeRecord>, StoreError> {
        if domain_id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, domain_id, challenge_type, token, status, attempts, \
                    (EXTRACT(EPOCH FROM next_attempt_at) * 1000000)::bigint AS next_attempt_us \
             FROM acme_challenges \
             WHERE tenant_id = $1 AND environment_id = $2 AND domain_id = $3 \
             ORDER BY created_at DESC, id DESC",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(domain_id.to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| row_to_acme_challenge(self.scope, row))
            .collect()
    }
}

/// The mutating custom-domain repository (issue #47). Reachable only through
/// [`ActingStore::custom_domains`], so every mutation carries an actor.
pub struct ActingCustomDomainRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingCustomDomainRepo<'_> {
    /// Register a custom domain and open its first ACME challenge, auditing
    /// `custom_domain.register` in the same transaction. The domain starts
    /// UNVERIFIED and is never served until a challenge proves control of it.
    ///
    /// The submitted `domain_name` is validated as a plain registrable hostname
    /// before anything is written (see [`domain_is_registrable`]): a value that
    /// could point at internal infrastructure is refused here, and every outbound
    /// ACME/CA request that later mentions the name goes through the SSRF-hardened
    /// fetch path.
    ///
    /// [`domain_is_registrable`]: crate::custom_domain::domain_is_registrable
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if either id is out of this scope;
    /// [`StoreError::InvalidCustomDomain`] if `domain_name` is not a registrable
    /// hostname; [`StoreError::Conflict`] if this environment already registered
    /// the same domain; [`StoreError::Database`] on a persistence failure.
    pub async fn register(
        &self,
        env: &Env,
        domain: &CustomDomainId,
        domain_name: &str,
        challenge_type: ChallengeType,
        challenge: &AcmeChallengeId,
        token: &str,
    ) -> Result<(), StoreError> {
        if domain.scope() != self.scope || challenge.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        // Canonicalize BEFORE the registrability check and BEFORE storing: the
        // cross-tenant exclusivity control is a byte-exact unique index on
        // domain_name, so a raw value would let two tenants each claim the same
        // DNS domain under a different case or a trailing root dot
        // (example.com vs EXAMPLE.com vs example.com.). Normalizing to the
        // canonical lowercase, root-dot-stripped form keys and indexes every
        // registration on the one true name.
        let domain_name = crate::custom_domain::normalize_domain(domain_name);
        if !crate::custom_domain::domain_is_registrable(&domain_name) {
            return Err(StoreError::InvalidCustomDomain);
        }
        let scope = self.scope;
        // The freshly issued challenge is ready to poll now (from the clock seam).
        let next_attempt_micros = epoch_micros(env.clock().now_utc());
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::CustomDomainRegister,
                target: domain,
            },
            async move |tx| {
                let insert_domain = sqlx::query(
                    "INSERT INTO custom_domains \
                     (id, tenant_id, environment_id, domain_name, challenge_type, \
                      verification_status) \
                     VALUES ($1, $2, $3, $4, $5, 'pending')",
                )
                .bind(domain.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&domain_name)
                .bind(challenge_type.as_str())
                .execute(&mut **tx)
                .await;
                match insert_domain {
                    Ok(_) => {}
                    // A domain already registered in THIS environment is a
                    // caller-facing conflict (the per-scope unique), not a
                    // persistence fault. Rolls the whole audited write back.
                    Err(error) if is_unique_violation(&error) => return Err(StoreError::Conflict),
                    Err(error) => return Err(error.into()),
                }
                sqlx::query(
                    "INSERT INTO acme_challenges \
                     (id, tenant_id, environment_id, domain_id, challenge_type, token, status, \
                      attempts, next_attempt_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
                )
                .bind(challenge.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(domain.to_string())
                .bind(challenge_type.as_str())
                .bind(token)
                .bind(next_attempt_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Record the terminal result of an ACME challenge, moving both the challenge
    /// and its domain to the corresponding state in one audited transaction.
    ///
    /// On [`ChallengeOutcome::Valid`] the challenge becomes valid and the domain
    /// VERIFIES (audited `custom_domain.challenge.succeed`). This is the point
    /// cross-tenant exclusivity is enforced: if another tenant already verified
    /// the same domain, the verified-domain unique index refuses the transition
    /// and the whole write rolls back with [`StoreError::Conflict`], leaving the
    /// domain unverified. On [`ChallengeOutcome::Invalid`] the challenge becomes
    /// invalid, its attempt count increments, a deterministic backoff schedules
    /// the next attempt, and the domain moves to FAILED (audited
    /// `custom_domain.challenge.fail`) so the failure surfaces.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if either id is out of scope, or the challenge or
    /// domain is absent; [`StoreError::Conflict`] if the domain is already
    /// verified by another tenant; [`StoreError::Database`] on a persistence
    /// failure.
    pub async fn record_challenge_result(
        &self,
        env: &Env,
        challenge: &AcmeChallengeId,
        domain: &CustomDomainId,
        outcome: ChallengeOutcome,
    ) -> Result<(), StoreError> {
        if challenge.scope() != self.scope || domain.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        let now = env.clock().now_utc();
        let updated_micros = epoch_micros(now);
        let action = match outcome {
            ChallengeOutcome::Valid => Action::CustomDomainChallengeSucceed,
            ChallengeOutcome::Invalid => Action::CustomDomainChallengeFail,
        };
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action,
                target: domain,
            },
            async move |tx| {
                // Move the challenge to its terminal state (on a failure, bump the
                // attempts and schedule the deterministic backoff; on success, clear
                // it). Keyed on BOTH the challenge id and the passed `domain_id`, so a
                // mismatched challenge/domain pair matches no row (NotFound).
                let challenge_row = match outcome {
                    ChallengeOutcome::Valid => sqlx::query(
                        "UPDATE acme_challenges \
                         SET status = 'valid', next_attempt_at = NULL, \
                             updated_at = TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
                         WHERE tenant_id = $1 AND environment_id = $2 \
                               AND id = $3 AND domain_id = $5 RETURNING attempts",
                    )
                    .bind(scope.tenant().to_string())
                    .bind(scope.environment().to_string())
                    .bind(challenge.to_string())
                    .bind(updated_micros)
                    .bind(domain.to_string())
                    .fetch_optional(&mut **tx)
                    .await?,
                    ChallengeOutcome::Invalid => {
                        // Read the current attempt count to compute the next schedule.
                        let current: Option<i32> = sqlx::query(
                            "SELECT attempts FROM acme_challenges \
                             WHERE tenant_id = $1 AND environment_id = $2 \
                                   AND id = $3 AND domain_id = $4",
                        )
                        .bind(scope.tenant().to_string())
                        .bind(scope.environment().to_string())
                        .bind(challenge.to_string())
                        .bind(domain.to_string())
                        .fetch_optional(&mut **tx)
                        .await?
                        .map(|row| row.get::<i32, _>("attempts"));
                        let Some(attempts) = current else {
                            return Err(StoreError::NotFound);
                        };
                        let next_attempts = attempts.saturating_add(1);
                        let backoff = challenge_backoff(attempts);
                        let next_at = epoch_micros(now + backoff);
                        sqlx::query(
                            "UPDATE acme_challenges \
                             SET status = 'invalid', attempts = $4, \
                                 next_attempt_at = TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval, \
                                 updated_at = TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval \
                             WHERE tenant_id = $1 AND environment_id = $2 \
                                   AND id = $3 AND domain_id = $7 RETURNING attempts",
                        )
                        .bind(scope.tenant().to_string())
                        .bind(scope.environment().to_string())
                        .bind(challenge.to_string())
                        .bind(next_attempts)
                        .bind(next_at)
                        .bind(updated_micros)
                        .bind(domain.to_string())
                        .fetch_optional(&mut **tx)
                        .await?
                    }
                };
                challenge_row.ok_or(StoreError::NotFound)?;
                // Move the domain to its corresponding verification state.
                let domain_update = sqlx::query(
                    "UPDATE custom_domains \
                     SET verification_status = $4, \
                         updated_at = TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval \
                     WHERE tenant_id = $1 AND environment_id = $2 AND id = $3 \
                     RETURNING id",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(domain.to_string())
                .bind(outcome.verification_status().as_str())
                .bind(updated_micros)
                .fetch_optional(&mut **tx)
                .await;
                match domain_update {
                    Ok(Some(_)) => Ok(()),
                    Ok(None) => Err(StoreError::NotFound),
                    // The verified-domain partial unique index refused this
                    // transition: another tenant already holds this domain
                    // verified. The whole write rolls back, so nothing changes.
                    Err(error) if is_unique_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await
    }

    /// Store an issued certificate for a verified domain: seal the certificate
    /// bundle (chain plus PRIVATE KEY) under the scope's envelope DEK (issue #48),
    /// point the domain at the sealed secret, and record its not-after instant.
    /// Audits `custom_domain.certificate.store`. The private key never touches a
    /// plaintext column; it lives only as ciphertext in `encrypted_secrets`.
    ///
    /// The scope's KEK/DEK are provisioned lazily on first use (idempotent), so a
    /// domain in a scope that never sealed a secret before still stores its cert.
    ///
    /// A certificate is only ever stored for a domain in the VERIFIED state (its
    /// ownership challenge completed): storing one for a pending or failed domain
    /// is refused with [`StoreError::Conflict`] BEFORE anything is sealed, so an
    /// unverified domain never gains a certificate and no orphan secret is left
    /// behind.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the domain id is out of scope or absent;
    /// [`StoreError::Conflict`] if the domain is not in the verified state;
    /// [`StoreError::Encryption`] if the scope's keys cannot seal the bundle;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn store_certificate(
        &self,
        env: &Env,
        master: &MasterKey,
        domain: &CustomDomainId,
        cert_bundle_pem: &[u8],
        not_after_micros: i64,
    ) -> Result<EncryptedSecretId, StoreError> {
        if domain.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        // A cert may only exist for a domain whose ownership challenge completed.
        // Read the domain up front (NotFound if absent) and require Verified before
        // sealing any key material, so a pending or failed domain is refused
        // without leaving an orphan sealed secret behind.
        let current = CustomDomainRepo {
            store: self.store,
            scope,
        }
        .get(domain)
        .await?;
        if current.verification_status != VerificationStatus::Verified {
            return Err(StoreError::Conflict);
        }
        let envelope = ActingEnvelopeRepo {
            store: self.store,
            scope,
            acting: self.acting,
        };
        // Provision the scope's KEK/DEK lazily (idempotent): a scope that never
        // sealed a secret has no keys yet.
        match envelope.provision_kek(env, master).await {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error),
        }
        match envelope.provision_dek(env, master).await {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error),
        }
        // Seal the cert bundle (including the private key) under the scope's DEK.
        let purpose = cert_secret_purpose(domain);
        let secret_id = envelope
            .put_secret(env, master, &purpose, cert_bundle_pem)
            .await?;
        // Point the domain at the sealed bundle and record the not-after instant.
        let updated_micros = epoch_micros(env.clock().now_utc());
        let secret_for_row = secret_id.to_string();
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::CustomDomainCertificateStore,
                target: domain,
            },
            async move |tx| {
                let updated = sqlx::query(
                    "UPDATE custom_domains \
                     SET cert_secret_id = $4, \
                         cert_not_after = TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval, \
                         updated_at = TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval \
                     WHERE tenant_id = $1 AND environment_id = $2 AND id = $3 \
                     RETURNING id",
                )
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(domain.to_string())
                .bind(&secret_for_row)
                .bind(not_after_micros)
                .bind(updated_micros)
                .fetch_optional(&mut **tx)
                .await?;
                if updated.is_none() {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await?;
        Ok(secret_id)
    }
}

// ===========================================================================
// Server-side config promotion apply (issue #44).
//
// The DIFF and PLAN are pure engine logic in `crate::promotion`; the APPLY is
// here because it is the one step that mutates scoped tables and must write its
// audit trail in the SAME transaction as the changes. Everything runs in a single
// `begin_scoped` transaction so a mid-apply failure rolls back COMPLETELY: no
// partial promotion, ever. Concurrent applies to the SAME target are serialized by a
// transaction-scoped advisory lock taken before the revision read, so the target's
// promotable-config revision is re-derived inside that transaction and checked
// against the plan's captured revision with no lost-update window: a target that
// drifted since the plan (including a concurrent apply that just committed) fails
// cleanly and changes nothing. The lock is per TARGET, not tenant-wide, so applies
// to different environments never contend.
// ===========================================================================

impl ActingStore<'_> {
    /// Transactionally APPLY a promotion plan's source snapshot onto this target
    /// environment (issue #44): all-or-nothing.
    ///
    /// `base_revision` is the plan's captured target revision (from
    /// [`crate::Plan::base_revision`]); apply proceeds only if the target still
    /// carries it. The apply is:
    ///
    /// - IDEMPOTENT: if the target already matches the source's promotable
    ///   configuration (its revision equals the source's), apply changes nothing and
    ///   returns [`PromotionOutcome::NoOp`].
    /// - DRIFT-GUARDED: if the target's current revision is neither the source's nor
    ///   `base_revision`, the plan is stale; apply returns
    ///   [`PromotionApplyError::Drift`] and changes nothing.
    /// - FAIL-CLOSED on references: every reference the source carries is re-checked
    ///   for existence in the target inside the transaction; a missing one is
    ///   [`PromotionApplyError::UnresolvedReference`] and the transaction rolls back.
    /// - ATOMIC and AUDITED: every resource change and one `config_promotion.apply`
    ///   audit row commit together, or none do.
    ///
    /// `poison_after_audit` is `false` on every production path; the atomicity test
    /// sets it to force a guaranteed in-transaction failure AFTER the changes and
    /// the audit row are staged, proving they roll back together.
    ///
    /// # Errors
    ///
    /// [`PromotionApplyError::Drift`] on a stale plan;
    /// [`PromotionApplyError::UnresolvedReference`] on a reference absent in the
    /// target; [`PromotionApplyError::Store`] on a persistence fault.
    #[allow(
        clippy::too_many_lines,
        reason = "the single-transaction apply keeps the drift check, the reference \
                  re-validation, every resource mutation, and the audit write in one \
                  place so their all-or-nothing rollback is legible as one unit"
    )]
    pub async fn apply_promotion(
        &self,
        env: &Env,
        source: &crate::snapshot::Snapshot,
        base_revision: &str,
        poison_after_audit: bool,
    ) -> Result<crate::promotion::PromotionOutcome, crate::promotion::PromotionApplyError> {
        use crate::promotion::{ChangeKind, PromotionApplyError, PromotionOutcome};

        let scope = self.scope;
        let result_revision = crate::promotion::revision(source)?;

        let mut tx = begin_scoped(self.store, scope).await?;

        // Serialize concurrent applies to the SAME target (tenant, environment) with a
        // TRANSACTION-scoped Postgres advisory lock, taken BEFORE the revision read so
        // the drift gate is authoritative under concurrency. `begin_scoped` pins READ
        // COMMITTED and the apply takes no row lock, so without this two applies sharing
        // the same `base_revision` would both read that revision, both pass the drift
        // gate, and both commit: a LOST UPDATE leaving the target in a state no single
        // plan enumerated. Holding this lock, the second apply blocks until the first
        // commits, then re-reads the NOW-CHANGED revision and correctly returns
        // `Drift`, changing nothing. `pg_advisory_xact_lock` auto-releases at
        // commit/rollback; the lock is per TARGET (keyed on a promotion-namespaced
        // hash of the two scope strings), so applies to DIFFERENT environments still
        // run fully concurrently. The single-argument form is used deliberately: it
        // occupies a lock space DISJOINT from the two-argument DCR-quota lock, so a
        // config-promotion apply and a DCR registration to the same scope do NOT
        // needlessly serialize against each other.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!(
                "config-promotion:apply:{}:{}",
                scope.tenant(),
                scope.environment()
            ))
            .execute(&mut *tx)
            .await?;

        // Re-derive the target's current promotable configuration and revision
        // INSIDE the transaction, so the drift check has no TOCTOU window.
        let current = read_promoted_snapshot(&mut tx, scope).await?;
        let current_revision = crate::promotion::revision(&current)?;

        // Idempotent: the target already matches the source's promotable config.
        if current_revision == result_revision {
            tx.commit().await?;
            return Ok(PromotionOutcome::NoOp);
        }
        // Drift: the target changed since the plan was computed.
        if current_revision != base_revision {
            // Dropping `tx` without commit rolls back; nothing was written anyway.
            return Err(PromotionApplyError::Drift {
                expected: base_revision.to_owned(),
                found: current_revision,
            });
        }

        // Re-validate every reference the source carries against the target, inside
        // the transaction, so apply never half-completes on a reference that vanished
        // since the plan (a secret is outside the revision, so its removal is not a
        // drift). A variable reference is satisfied by an existing target variable OR
        // one the source promotes; a secret reference must pre-exist in the target.
        for reference in crate::promotion::collect_references(source) {
            let resolved = match reference.kind {
                crate::esv::ReferenceKind::Variable => {
                    source
                        .resources
                        .variable
                        .iter()
                        .any(|variable| variable.name == reference.name)
                        || current
                            .resources
                            .variable
                            .iter()
                            .any(|variable| variable.name == reference.name)
                }
                crate::esv::ReferenceKind::Secret => {
                    secret_exists_tx(&mut tx, scope, &reference.name).await?
                }
            };
            if !resolved {
                return Err(PromotionApplyError::UnresolvedReference(reference));
            }
        }

        // The diff is computed against the just-read current state, so it is exactly
        // the plan's diff (the drift check proved current == base).
        let plan_diff = crate::promotion::diff(source, &current);
        let now_micros = epoch_micros(env.clock().now_utc());
        let (mut creates, mut updates, mut deletes) = (0_u32, 0_u32, 0_u32);

        for change in plan_diff.changes() {
            match change.kind {
                ChangeKind::Create => creates += 1,
                ChangeKind::Update => updates += 1,
                ChangeKind::Delete => deletes += 1,
            }
            apply_change(&mut tx, scope, env, source, change, now_micros).await?;
        }

        // One audit row, naming the environment and the change counts (operator-safe;
        // no promoted value or secret), written in the SAME transaction.
        let environment_id = scope.environment();
        let detail = format!("create={creates},update={updates},delete={deletes}");
        let spec = AuditedWrite {
            store: self.store,
            scope,
            acting: &self.acting,
            env,
            action: Action::ConfigPromotionApply,
            target: &environment_id,
        };
        insert_audit_row(&mut tx, &spec, Some(&detail)).await?;

        if poison_after_audit {
            // Testing seam only: force a guaranteed error after the changes and the
            // audit row are staged, so their joint rollback proves atomicity.
            sqlx::query("SELECT 1 / 0").execute(&mut *tx).await?;
        }

        tx.commit().await?;
        Ok(PromotionOutcome::Applied(plan_diff))
    }
}

/// Read the target's promotable configuration (the promoted resource types only)
/// as a [`crate::snapshot::Snapshot`], INSIDE the caller's transaction (issue #44).
///
/// Mirrors the ordering the canonical export uses (each array sorted by its natural
/// key in Rust, collation-independent), so the revision computed from this matches
/// the revision the plan captured from the canonical export. The `client` set is
/// left empty: clients are not promoted.
async fn read_promoted_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<crate::snapshot::Snapshot, StoreError> {
    let mut resource_server: Vec<crate::snapshot::ResourceServerSnapshot> = sqlx::query(
        "SELECT audience, token_format, access_token_ttl_secs FROM resource_servers \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(|row| crate::snapshot::ResourceServerSnapshot {
        audience: row.get("audience"),
        token_format: row.get("token_format"),
        access_token_ttl_secs: row.get("access_token_ttl_secs"),
    })
    .collect();
    resource_server.sort_by(|a, b| a.audience.cmp(&b.audience));

    let mut dcr_policy = Vec::new();
    for row in sqlx::query(
        "SELECT name, primitives FROM dcr_policies \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(&mut **tx)
    .await?
    {
        let primitives_text: String = row.get("primitives");
        let primitives: serde_json::Value = serde_json::from_str(&primitives_text)
            .map_err(|error| StoreError::Database(sqlx::Error::Decode(Box::new(error))))?;
        dcr_policy.push(crate::snapshot::DcrPolicySnapshot {
            name: row.get("name"),
            primitives,
        });
    }
    dcr_policy.sort_by(|a, b| a.name.cmp(&b.name));

    let mut variable: Vec<crate::snapshot::VariableSnapshot> = sqlx::query(
        "SELECT name, value FROM environment_variables \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(|row| crate::snapshot::VariableSnapshot {
        name: row.get("name"),
        value: row.get("value"),
    })
    .collect();
    variable.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(crate::snapshot::Snapshot {
        schema_version: crate::snapshot::SNAPSHOT_SCHEMA_VERSION.to_owned(),
        resources: crate::snapshot::SnapshotResources {
            client: Vec::new(),
            resource_server,
            dcr_policy,
            variable,
        },
    })
}

/// Whether a secret of `name` exists in `scope`, read inside the caller's
/// transaction (the apply-time reference re-check; opens no ciphertext).
async fn secret_exists_tx(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    name: &str,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "SELECT 1 AS present FROM environment_secrets \
         WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.is_some())
}

/// Apply one promotion change to the target, inside the caller's transaction
/// (issue #44). Creates mint a fresh target-scoped identifier; updates and deletes
/// match the existing target row by its scope-independent natural key.
async fn apply_change(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    env: &Env,
    source: &crate::snapshot::Snapshot,
    change: &crate::promotion::ResourceChange,
    now_micros: i64,
) -> Result<(), StoreError> {
    match change.resource_type {
        ResourceType::ResourceServer => {
            apply_resource_server_change(tx, scope, env, source, change).await
        }
        ResourceType::DcrPolicy => {
            apply_dcr_policy_change(tx, scope, env, source, change, now_micros).await
        }
        ResourceType::Variable => {
            apply_variable_change(tx, scope, env, source, change, now_micros).await
        }
        // The promotion engine only ever emits changes for the promoted resource
        // types; any other type is a programmer error, surfaced as a not-found
        // rather than a silent skip.
        _ => Err(StoreError::NotFound),
    }
}

/// Apply a resource-server create/update/delete, matched by `audience`.
async fn apply_resource_server_change(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    env: &Env,
    source: &crate::snapshot::Snapshot,
    change: &crate::promotion::ResourceChange,
) -> Result<(), StoreError> {
    use crate::promotion::ChangeKind;
    match change.kind {
        ChangeKind::Create => {
            let server = source
                .resources
                .resource_server
                .iter()
                .find(|server| server.audience == change.key)
                .ok_or(StoreError::NotFound)?;
            let id = ResourceServerId::generate(env, &scope);
            sqlx::query(
                "INSERT INTO resource_servers \
                 (id, tenant_id, environment_id, audience, token_format, access_token_ttl_secs) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(id.to_string())
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&server.audience)
            .bind(&server.token_format)
            .bind(server.access_token_ttl_secs)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
        ChangeKind::Update => {
            let server = source
                .resources
                .resource_server
                .iter()
                .find(|server| server.audience == change.key)
                .ok_or(StoreError::NotFound)?;
            sqlx::query(
                "UPDATE resource_servers \
                 SET token_format = $1, access_token_ttl_secs = $2 \
                 WHERE tenant_id = $3 AND environment_id = $4 AND audience = $5",
            )
            .bind(&server.token_format)
            .bind(server.access_token_ttl_secs)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&server.audience)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
        ChangeKind::Delete => {
            sqlx::query(
                "DELETE FROM resource_servers \
                 WHERE tenant_id = $1 AND environment_id = $2 AND audience = $3",
            )
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&change.key)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
    }
}

/// Apply a DCR-policy create/update/delete, matched by `name`.
async fn apply_dcr_policy_change(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    env: &Env,
    source: &crate::snapshot::Snapshot,
    change: &crate::promotion::ResourceChange,
    now_micros: i64,
) -> Result<(), StoreError> {
    use crate::promotion::ChangeKind;
    match change.kind {
        ChangeKind::Create => {
            let policy = source
                .resources
                .dcr_policy
                .iter()
                .find(|policy| policy.name == change.key)
                .ok_or(StoreError::NotFound)?;
            let primitives = serde_json::to_string(&policy.primitives)
                .map_err(|error| StoreError::Database(sqlx::Error::Decode(Box::new(error))))?;
            let id = DcrPolicyId::generate(env, &scope);
            sqlx::query(
                "INSERT INTO dcr_policies \
                 (id, tenant_id, environment_id, name, primitives, created_at) \
                 VALUES ($1, $2, $3, $4, $5, \
                         TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval)",
            )
            .bind(id.to_string())
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&policy.name)
            .bind(&primitives)
            .bind(now_micros)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
        ChangeKind::Update => {
            let policy = source
                .resources
                .dcr_policy
                .iter()
                .find(|policy| policy.name == change.key)
                .ok_or(StoreError::NotFound)?;
            let primitives = serde_json::to_string(&policy.primitives)
                .map_err(|error| StoreError::Database(sqlx::Error::Decode(Box::new(error))))?;
            sqlx::query(
                "UPDATE dcr_policies SET primitives = $1 \
                 WHERE tenant_id = $2 AND environment_id = $3 AND name = $4",
            )
            .bind(&primitives)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&policy.name)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
        ChangeKind::Delete => {
            sqlx::query(
                "DELETE FROM dcr_policies \
                 WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
            )
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&change.key)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
    }
}

/// Apply an environment-variable create/update/delete, matched by `name`.
async fn apply_variable_change(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    env: &Env,
    source: &crate::snapshot::Snapshot,
    change: &crate::promotion::ResourceChange,
    now_micros: i64,
) -> Result<(), StoreError> {
    use crate::promotion::ChangeKind;
    match change.kind {
        ChangeKind::Create => {
            let variable = source
                .resources
                .variable
                .iter()
                .find(|variable| variable.name == change.key)
                .ok_or(StoreError::NotFound)?;
            let id = VariableId::generate(env, &scope);
            sqlx::query(
                "INSERT INTO environment_variables \
                 (id, tenant_id, environment_id, name, value, version, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, 1, \
                         TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                         TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval)",
            )
            .bind(id.to_string())
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&variable.name)
            .bind(&variable.value)
            .bind(now_micros)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
        ChangeKind::Update => {
            let variable = source
                .resources
                .variable
                .iter()
                .find(|variable| variable.name == change.key)
                .ok_or(StoreError::NotFound)?;
            sqlx::query(
                "UPDATE environment_variables \
                 SET value = $1, version = version + 1, \
                     updated_at = TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval \
                 WHERE tenant_id = $3 AND environment_id = $4 AND name = $5",
            )
            .bind(&variable.value)
            .bind(now_micros)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&variable.name)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
        ChangeKind::Delete => {
            sqlx::query(
                "DELETE FROM environment_variables \
                 WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
            )
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(&change.key)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
    }
}
