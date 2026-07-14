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
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};

use crate::audit::{ActingContext, Action, ActorRef};
use crate::error::StoreError;
use crate::id::{
    AuditId, AuditTarget, AuthorizationCodeId, ClientId, ConsentId, CorrelationId, EnvironmentId,
    GrantId, IssuedTokenId, ManagementKeyId, OperatorId, RefreshFamilyId, RefreshTokenId,
    ResourceServerId, SessionId, SigningKeyId, TenantId, UserId,
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
}

/// A record read back from the `clients` table, always within scope.
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
             redirect_uris, consent_mode, skip_consent, store_skipped_consent FROM clients \
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
             redirect_uris, consent_mode, skip_consent, store_skipped_consent FROM clients \
             WHERE tenant_id = $1 AND environment_id = $2 ORDER BY created_at, id",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter().map(|row| self.row_to_record(row)).collect()
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
            consent_mode: row.get("consent_mode"),
            skip_consent: row.get("skip_consent"),
            store_skipped_consent: row.get("store_skipped_consent"),
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
        let row = sqlx::query(
            "SELECT grant_id, client_id, redirect_uri, nonce, code_challenge, \
             code_challenge_method, subject, oauth_scope, auth_methods, claims_request, \
             (EXTRACT(EPOCH FROM auth_time) * 1000000)::bigint AS auth_time_us \
             FROM authorization_codes \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
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
             t.scope AS scope, t.jti AS jti, \
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
        Ok(row.map(|row| ActiveOpaqueToken {
            subject: row.get("subject"),
            client_id: row.get("client_id"),
            audience: row.get("audience"),
            scope: row.get("scope"),
            jti: row.get("jti"),
            expires_at_unix_micros: row.get("expires_us"),
            issued_at_unix_micros: row.get("issued_us"),
        }))
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
                sqlx::query(
                    "INSERT INTO grants \
                     (id, tenant_id, environment_id, client_id, subject, session_ref, \
                      consent_ref, claims_request, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, \
                             TIMESTAMPTZ 'epoch' + ($9::text || ' microseconds')::interval)",
                )
                .bind(code.grant_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(code.client_id.to_string())
                .bind(code.subject)
                .bind(code.session_ref)
                .bind(code.consent_ref)
                .bind(code.claims_request)
                .bind(code.created_at_micros)
                .execute(&mut **tx)
                .await?;
                sqlx::query(
                    "INSERT INTO authorization_codes \
                     (id, tenant_id, environment_id, grant_id, client_id, redirect_uri, nonce, \
                      code_challenge, code_challenge_method, subject, oauth_scope, auth_methods, \
                      claims_request, auth_time, expires_at, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                             CASE WHEN $14::bigint IS NULL THEN NULL \
                                  ELSE TIMESTAMPTZ 'epoch' \
                                       + ($14::text || ' microseconds')::interval END, \
                             TIMESTAMPTZ 'epoch' + ($15::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($16::text || ' microseconds')::interval)",
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
                      client_id, audience, scope, jti, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                             TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval)",
                )
                .bind(opaque.token_digest)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(&grant_text)
                .bind(opaque.subject)
                .bind(opaque.client_id)
                .bind(opaque.audience)
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
            insert_audit_row(&mut tx, &spec).await?;
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
            insert_audit_row(&mut tx, &spec).await?;
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
            async move |tx| {
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
            },
            false,
        )
        .await
    }
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

/// A bounded-cardinality reason a client authentication failed (issue #25),
/// recorded in the diagnostics sink. No attacker-controlled free text, so it is
/// safe as a metric-like dimension and never an oracle on the wire.
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
    /// The audience the token targets (a resource server's audience or the client
    /// id).
    pub audience: &'a str,
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
    /// The audience the token targets.
    pub audience: String,
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
    })
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
/// gate that decides whether those are handed out. A `successor` is ALWAYS supplied
/// (even when `rotate` is false) because a superseded-token presentation within the
/// grace window mints a fresh successor regardless of the policy.
#[derive(Clone, Copy)]
pub struct RefreshRedeem<'a> {
    /// The presented refresh token, hashed to its digest for the lookup.
    pub presented_token: &'a str,
    /// Whether the rotation policy says to rotate a LIVE (non-superseded) token:
    /// `true` for a public/unbound client always, `true` for a confidential/bound
    /// client only past the TTL threshold. When `false`, a live token is left in
    /// place and only a fresh access token is recorded.
    pub rotate: bool,
    /// The pre-generated successor refresh token, recorded when the token rotates
    /// (a policy rotation, or a within-grace concurrent refresh).
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
    /// benign concurrent refresh (multi-tab, retry). A fresh successor and access
    /// token were recorded WITHOUT revoking the family; the token endpoint returns
    /// them, so the user is not locked out.
    RotatedWithinGrace,
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
    /// revoke a session-bound family) inside the same transaction. Called after a
    /// successful code exchange.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if any supplied identifier is out of scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn issue(&self, env: &Env, family: NewRefreshFamily<'_>) -> Result<(), StoreError> {
        if family.family_id.scope() != self.scope
            || family.token_jti.scope() != self.scope
            || family.grant_id.scope() != self.scope
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
                action: Action::RefreshTokenIssue,
                target: family.family_id,
            },
            async move |tx| {
                // Read the grant's session_ref so a session-bound family can be
                // revoked at RP logout. NULL when no session backed the grant.
                let session_ref: Option<String> = sqlx::query(
                    "SELECT session_ref FROM grants \
                     WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
                )
                .bind(family.grant_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .fetch_optional(&mut **tx)
                .await?
                .and_then(|row| row.get::<Option<String>, _>("session_ref"));
                sqlx::query(
                    "INSERT INTO refresh_families \
                     (id, tenant_id, environment_id, grant_id, subject, client_id, scope, \
                      auth_methods, session_ref, offline, created_at, absolute_expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                             TIMESTAMPTZ 'epoch' + ($11::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($12::text || ' microseconds')::interval)",
                )
                .bind(family.family_id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(family.grant_id.to_string())
                .bind(family.subject)
                .bind(family.client_id)
                .bind(family.scope)
                .bind(family.auth_methods)
                .bind(session_ref)
                .bind(family.offline)
                .bind(family.created_at_unix_micros)
                .bind(family.absolute_expires_at_unix_micros)
                .execute(&mut **tx)
                .await?;
                sqlx::query(
                    "INSERT INTO refresh_tokens \
                     (token_digest, tenant_id, environment_id, family_id, jti, generation, \
                      predecessor_jti, issued_at, idle_expires_at) \
                     VALUES ($1, $2, $3, $4, $5, 0, NULL, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
                )
                .bind(family.token_digest)
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(family.family_id.to_string())
                .bind(family.token_jti.to_string())
                .bind(family.created_at_unix_micros)
                .bind(family.idle_expires_at_unix_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Atomically redeem (refresh) a presented refresh token, with reuse detection.
    ///
    /// In one transaction the presented token's family, grant, expiry, and rotation
    /// state are read, and then:
    ///
    /// - a token whose family or grant is already revoked, or whose idle timeout or
    ///   family hard cap has passed, is [`RefreshRedeemOutcome::Invalid`];
    /// - a token that is ALREADY superseded is classified against the grace window:
    ///   within it, a fresh successor is minted without revoking
    ///   ([`RefreshRedeemOutcome::RotatedWithinGrace`]); beyond it, the whole family
    ///   is revoked and the reuse event emitted EXACTLY once
    ///   ([`RefreshRedeemOutcome::Reused`]);
    /// - a LIVE token with `rotate` set is atomically consumed (superseded) and a
    ///   successor plus access token recorded ([`RefreshRedeemOutcome::Rotated`]); a
    ///   concurrent loser that misses the single-row consume re-reads and classifies
    ///   against the grace window exactly as an already-superseded token does, so N
    ///   parallel refreshes all succeed within the window;
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
             (f.revoked_at IS NULL) AS family_live, (g.revoked_at IS NULL) AS grant_live \
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
                    &jti_text,
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
            insert_audit_row(&mut tx, &spec).await?;
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
            insert_audit_row(&mut tx, &spec).await?;
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
            jti_text,
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
    /// benign concurrent refresh: a fresh successor and access token are recorded
    /// without revoking, so the user is not locked out. Beyond the window it is a
    /// genuine reuse: the whole family is revoked and the reuse audit written in this
    /// transaction, EXACTLY once (only the revoke that flips `revoked_at` emits it).
    #[allow(clippy::too_many_arguments)]
    async fn classify_superseded(
        &self,
        env: &Env,
        mut tx: Transaction<'_, Postgres>,
        family_text: &str,
        predecessor_jti: &str,
        grant_text: &str,
        rotated_us: i64,
        now_micros: i64,
        grace_micros: i64,
        redeem: &RefreshRedeem<'_>,
    ) -> Result<RefreshRedeemOutcome, StoreError> {
        let scope = self.scope;
        if now_micros.saturating_sub(rotated_us) <= grace_micros {
            // Within the grace window: a benign concurrent refresh. Mint a fresh
            // successor (a second live leaf) and a fresh access token WITHOUT
            // revoking, so multi-tab / retry all succeed.
            insert_refresh_generation(
                &mut tx,
                scope,
                family_text,
                &redeem.successor,
                Some(predecessor_jti),
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
            insert_audit_row(&mut tx, &spec).await?;
            tx.commit().await?;
            return Ok(RefreshRedeemOutcome::RotatedWithinGrace);
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
            insert_audit_row(&mut tx, &spec).await?;
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
              client_id, audience, scope, jti, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                     TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval)",
        )
        .bind(opaque.token_digest)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(grant_text)
        .bind(opaque.subject)
        .bind(opaque.client_id)
        .bind(opaque.audience)
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
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRecord")
            .field("id", &self.id)
            .field("identifier", &self.identifier)
            .finish_non_exhaustive()
    }
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
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn by_identifier(&self, identifier: &str) -> Result<Option<UserRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, identifier, password_hash FROM users \
             WHERE identifier = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(identifier)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(None),
            Some(row) => {
                let id_text: String = row.get("id");
                let id = UserId::parse_in_scope(&id_text, &self.scope)?;
                Ok(Some(UserRecord {
                    id,
                    identifier: row.get("identifier"),
                    password_hash: row.get("password_hash"),
                }))
            }
        }
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
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn claims_for_subject(&self, subject: &str) -> Result<Option<String>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT claims FROM users \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(subject)
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| row.get::<String, _>("claims")))
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

    /// Shared body of the registration path: insert the user (with its claim
    /// document) and its audit row in one transaction, mapping a duplicate login
    /// handle to the caller-facing [`StoreError::Conflict`].
    async fn register_inner(
        &self,
        env: &Env,
        identifier: &str,
        password_hash: &str,
        claims_json: &str,
    ) -> Result<UserId, StoreError> {
        let id = UserId::generate(env, &self.scope);
        let scope = self.scope;
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
                let result = sqlx::query(
                    "INSERT INTO users \
                     (id, tenant_id, environment_id, identifier, password_hash, claims) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(identifier)
                .bind(password_hash)
                .bind(claims_json)
                .execute(&mut **tx)
                .await;
                match result {
                    Ok(_) => Ok(()),
                    // A duplicate login handle is a caller-facing conflict (the
                    // handle is taken), not a persistence fault. Erroring here
                    // rolls the audited write back, so a rejected registration
                    // leaves neither a user row nor an audit row.
                    Err(error) if is_unique_violation(&error) => Err(StoreError::Conflict),
                    Err(error) => Err(error.into()),
                }
            },
            false,
        )
        .await?;
        Ok(id)
    }
}

/// A bootstrap session read back within scope (issue #20).
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
}

/// The read-only bootstrap session repository (issue #20).
pub struct SessionRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl SessionRepo<'_> {
    /// Resolve a session by id within scope, returning [`None`] when it is absent,
    /// out of scope, or expired at `now_micros`. Expiry is compared against the
    /// application clock seam (bound as epoch microseconds), never the database
    /// clock, so it is deterministic under a manual clock in tests.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn get(
        &self,
        id: &SessionId,
        now_micros: i64,
    ) -> Result<Option<SessionRecord>, StoreError> {
        if id.scope() != self.scope {
            return Ok(None);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT subject, auth_methods, \
             (EXTRACT(EPOCH FROM auth_time) * 1000000)::bigint AS auth_us \
             FROM sessions \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 \
             AND expires_at > TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(now_micros)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|row| SessionRecord {
            subject: row.get("subject"),
            auth_time_unix_micros: row.get("auth_us"),
            auth_methods: row.get("auth_methods"),
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
    /// Create a session for `subject`, recording the authentication event: the
    /// `auth_methods` (space-separated RFC 8176 method tokens, `pwd` for the
    /// bootstrap password login) and the `auth_time`, both alongside the session
    /// `expires_at`. Times come from the application clock seam (bound as epoch
    /// microseconds). Writes a `session.create` audit row in the same
    /// transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the session id is out of this scope;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create(
        &self,
        env: &Env,
        id: &SessionId,
        subject: &str,
        auth_methods: &str,
        auth_time_micros: i64,
        expires_at_micros: i64,
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
                action: Action::SessionCreate,
                target: id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO sessions \
                     (id, tenant_id, environment_id, subject, auth_methods, auth_time, \
                      expires_at) \
                     VALUES ($1, $2, $3, $4, $5, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                             TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(subject)
                .bind(auth_methods)
                .bind(auth_time_micros)
                .bind(expires_at_micros)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            false,
        )
        .await
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
             correlation_id, \
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
        })
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
    let mut tx = begin_scoped(spec.store, spec.scope).await?;
    // The data change and the audit row share this one transaction.
    mutate(&mut tx).await?;
    insert_audit_row(&mut tx, &spec).await?;
    if poison_after_audit {
        // Testing seam only (production callers pass false): force a guaranteed
        // error after both inserts are staged, so their joint rollback proves
        // the data change and the audit row are in the same transaction.
        sqlx::query("SELECT 1 / 0").execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Insert exactly one audit row into the current transaction. Called only by
/// [`write_audited`], after the data change and before the commit.
async fn insert_audit_row<T: AuditTarget>(
    tx: &mut Transaction<'_, Postgres>,
    spec: &AuditedWrite<'_, T>,
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
          target_kind, target_id, correlation_id, occurred_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval)",
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
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
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
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
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

    /// The read-only environment repository under `tenant`.
    #[must_use]
    pub fn environments(&self, tenant: TenantId) -> EnvironmentRepo<'a> {
        EnvironmentRepo {
            store: self.store,
            tenant,
        }
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
            "SELECT id, operator_id, display_name, \
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
            "SELECT id, operator_id, display_name, \
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
            "SELECT id, tenant_id, display_name, \
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
            "SELECT id, tenant_id, display_name, \
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
        environment_display_name: &str,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let scope = Scope::new(*tenant_id, *environment_id);
        let operator = self.operator;
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
                sqlx::query(
                    "INSERT INTO tenants (id, operator_id, display_name, created_at) \
                     VALUES ($1, $2, $3, \
                             TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval)",
                )
                .bind(tenant_id.to_string())
                .bind(operator.to_string())
                .bind(tenant_display_name)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                sqlx::query(
                    "INSERT INTO environments (id, tenant_id, display_name, created_at) \
                     VALUES ($1, $2, $3, \
                             TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval)",
                )
                .bind(environment_id.to_string())
                .bind(tenant_id.to_string())
                .bind(environment_display_name)
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

    /// Deactivate a tenant (soft delete) and CASCADE the deactivation to its
    /// child environments and their management credentials, all in the audited
    /// transaction so it stays atomic. Audited scoped to the tenant and its
    /// oldest environment (which is retained, so the audit foreign key holds).
    ///
    /// The cascade is what makes a deleted tenant's environments stop listing and
    /// its keys stop authenticating; the join in
    /// [`ManagementCredentialRepo::authenticate`] is the belt-and-suspenders
    /// backstop for any create-after-delete race.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live tenant matched under this operator.
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
    /// [`StoreError::IdempotencyConflict`] on a concurrent Idempotency-Key race;
    /// [`StoreError::Database`] on a persistence failure (including a missing
    /// tenant, which surfaces as the tenant foreign-key violation).
    pub async fn create(
        &self,
        env: &Env,
        environment_id: &EnvironmentId,
        created_at_micros: i64,
        display_name: &str,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let scope = Scope::new(self.tenant, *environment_id);
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
                sqlx::query(
                    "INSERT INTO environments (id, tenant_id, display_name, created_at) \
                     VALUES ($1, $2, $3, \
                             TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval)",
                )
                .bind(environment_id.to_string())
                .bind(tenant.to_string())
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
    Ok(TenantRecord {
        id: TenantId::parse(&row.get::<String, _>("id")).map_err(decode)?,
        operator_id: OperatorId::parse(&row.get::<String, _>("operator_id")).map_err(decode)?,
        display_name: row.get("display_name"),
        created_at_unix_micros: row.get("created_us"),
    })
}

/// Reconstruct an [`EnvironmentRecord`] from a row.
fn environment_from_row(row: &PgRow) -> Result<EnvironmentRecord, StoreError> {
    let decode =
        |e: crate::id::IdParseError| StoreError::Database(sqlx::Error::Decode(Box::new(e)));
    Ok(EnvironmentRecord {
        id: EnvironmentId::parse(&row.get::<String, _>("id")).map_err(decode)?,
        tenant_id: TenantId::parse(&row.get::<String, _>("tenant_id")).map_err(decode)?,
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
