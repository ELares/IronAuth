// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared handler state and the credential-resolution logic.
//!
//! [`AdminState`] carries the control-plane [`Store`], the environment seam, the
//! resolved bootstrap operator token, and the page-size configuration. It is the
//! axum router state, so every handler and the [`crate::auth::Principal`]
//! extractor reach it.
//!
//! In production the store's pool authenticates as the least-privilege
//! `ironauth_control` role (a distinct credential class from the data-plane
//! role), so the `management_credentials` FORCE row-level-security backstop
//! applies beneath the repository layer. The binary selects that DSN from
//! `admin.control_database_url`; in `dev_mode` it may fall back to
//! `database.url`, in which case the role separation and the FORCE-RLS backstop
//! are not enforced (a startup warning says so). See `crate::management_router`
//! and `docs/adr/0005-management-api.md`.

use std::sync::Arc;
use std::time::SystemTime;

use ironauth_config::{
    AdminConfig, IdentifierUniqueness, IdentifiersConfig, SecretError, SecretString,
    TokenClaimsConfig,
};
use ironauth_env::Env;
use ironauth_fetch::txt::TxtLookup;
use ironauth_jose::{ExpectedTyp, JwsAlgorithm, TokenTyp, TrustedKey, VerificationPolicy, verify};
use ironauth_oidc::IssuerRegistry;
use ironauth_store::{
    ActorRef, HumanId, MANAGEMENT_LIST_HARD_CAP, ManagementKeyId, OperatorId, Scope, ServiceId,
    Store, UniquenessMode,
};
use serde_json::Value;

use crate::auth::{ManagementGrants, ManagementPermission, Principal};
use crate::error::ApiError;
use crate::hash::{constant_time_eq, sha256_hex};
use ironauth_store::OrganizationId;

/// The OAuth scope value a console `at+jwt` must carry to reach the management
/// plane (issue #90, PR 2). An ordinary end-user login token for the SAME admin
/// issuer that lacks this scope is rejected, so a broad interactive login cannot
/// be replayed against the management API.
const MANAGEMENT_SCOPE: &str = "ironauth.manage";

/// The seed bytes of the well-known bootstrap identities. The bootstrap operator
/// (operator plane) and its audit service-actor are fixed, well-known identities
/// so they are stable across restarts; the full operator-plane credential class
/// with minted identities lands in M5.
const BOOTSTRAP_SEED: [u8; 16] = [0_u8; 16];

/// The operator id a self-bootstrapping deployment provisions, derived from
/// [`BOOTSTRAP_SEED`] and therefore identical in every process.
///
/// Exposed because a test harness that seeds tenants directly has to give them an owner
/// the API can actually reach: since issue #185 a tenant owned by anybody else is the
/// uniform not-found, so a harness minting a fresh operator per scope would build rows
/// the surface under test cannot see.
#[must_use]
pub fn bootstrap_operator_id() -> OperatorId {
    OperatorId::from_seed_bytes(BOOTSTRAP_SEED)
}

/// The display name recorded for the bootstrap operator row.
pub(crate) const BOOTSTRAP_OPERATOR_DISPLAY_NAME: &str = "IronAuth bootstrap operator";

/// The OIDC-session to management-Principal credential bridge (issue #90, PR 2).
///
/// This is the identity-resolution half of dogfooding: the admin console signs in
/// through IronAuth's OWN OIDC (Authorization Code + PKCE, a public client) against
/// a designated ADMIN ISSUER and receives a short-lived `at+jwt` bound to the
/// management audience. This value carries everything the third resolution arm
/// needs to turn that bearer into a [`Principal`], and NOTHING else:
///
/// - `issuers` is a store-backed [`IssuerRegistry`] built over the SAME data-plane
///   store, master key, and config-derived issuer base the OIDC data plane serves
///   its JWKS and discovery from. It is a SEPARATE `Arc` instance (the boot path
///   builds it independently to avoid reordering the server construction), but it
///   reads the identical RLS-scoped signing-key rows and derives the identical
///   `iss` string, so the trusted keys are equivalent by construction. The
///   verification keys come from the admin issuer's published signing keys ONLY,
///   never an ambient "any issuer" trust anchor. (Sharing the exact `Arc` so the
///   two instances share one key cache is a clean follow-up.)
/// - `issuer_scope` is the admin issuer's `(tenant, environment)`, from which the
///   registry derives BOTH the trusted keys and the exact `iss` string the token
///   must carry (one source of truth: the enforced issuer is the value the
///   registry itself would publish).
/// - `management_audience` is the exact `aud` the token must carry (RFC 8707); it
///   is the cross-RP replay defense.
/// - `operator_subjects` is the fail-closed allowlist: a verified token whose `sub`
///   is a member maps to [`Principal::Operator`]; any other subject is rejected.
///
/// It carries NO secret. Arming it is an operator choice (config-only); when it is
/// absent the management API accepts no `at+jwt` at all (fail closed).
#[derive(Clone)]
pub struct AdminOidcBridge {
    issuers: Arc<IssuerRegistry>,
    issuer_scope: Scope,
    management_audience: String,
    operator_subjects: Vec<String>,
}

impl AdminOidcBridge {
    /// Build the bridge from the shared issuer registry, the admin issuer scope,
    /// the management audience, and the operator-subject allowlist.
    ///
    /// The registry is shared (an `Arc`) with the OIDC data plane so the keys the
    /// arm verifies against are exactly the keys that issuer publishes; the scope,
    /// audience, and allowlist come from the operator's `[admin_spa]` config.
    #[must_use]
    pub fn new(
        issuers: Arc<IssuerRegistry>,
        issuer_scope: Scope,
        management_audience: impl Into<String>,
        operator_subjects: Vec<String>,
    ) -> Self {
        Self {
            issuers,
            issuer_scope,
            management_audience: management_audience.into(),
            operator_subjects,
        }
    }
}

/// Cheaply cloneable state shared by every management handler.
#[derive(Clone)]
pub struct AdminState {
    inner: Arc<Inner>,
}

// The admin state aggregates several independent experimental feature-gate flags (sudo mode,
// signup quarantine, advanced recovery); each is a distinct on/off surface arm, so they read
// clearer as separate bools than folded into an enum.
#[allow(clippy::struct_excessive_bools)]
struct Inner {
    store: Store,
    // The DATA-plane store, when this process could open one (issue #111 criterion 1).
    //
    // The management surface is a control-plane surface and stays one: this is not a second
    // way to reach the same tables. It exists because ONE operation must write a table the
    // control role deliberately cannot -- re-queueing an outbound message -- and `messages`
    // grants the control role SELECT only, on purpose. Its own test says why: "UPDATE here
    // makes the management surface a mailer."
    //
    // So the split is kept and the work moves rather than the grant: the management API
    // decides WHETHER to resend, and the data plane, which is the thing that mails, performs
    // it, exactly as it did for the original send.
    //
    // `None` when no data-plane store could be opened, and every reader fails closed rather
    // than falling back to the control store, which would be the grant widening this avoids.
    data_store: Option<Store>,
    // The WASM hook runtime, when this process built one (issue #114 criterion 5).
    //
    // SHARED with the OIDC data plane rather than built here, and that is not an optimization:
    // a wasmtime `Engine` owns the compiled-code cache, so a second one would mean a draft run
    // compiles a component the issuance path has already compiled -- six and a half seconds for
    // a TypeScript hook -- and would answer about a cache the product does not use.
    //
    // `None` when the process has no engine, and ALWAYS `None` without the `wasm-hooks`
    // feature, because `HookRuntime` is uninhabited there. The draft endpoint then answers a
    // clean refusal rather than being absent from the surface.
    hook_runtime: Option<Arc<ironauth_oidc::token_hook::HookRuntime>>,
    env: Env,
    // Wrapped in SecretString so it cannot leak through Debug/logs; the value is
    // reachable only via `.expose()` at the constant-time comparison site.
    bootstrap_operator_token: Option<SecretString>,
    bootstrap_operator_id: OperatorId,
    bootstrap_operator_actor: ActorRef,
    default_page_size: u32,
    max_page_size: u32,
    // The operator's configured data-residency region set (issue #46). A tenant's
    // home_region and a per-environment region pin must be one of these; empty means
    // residency pinning is unavailable and any pin on a create is refused.
    allowed_regions: Vec<String>,
    // The tenant-offboarding retention window in seconds (issue #46): the grace
    // period a soft-deleted tenant can be restored within.
    offboarding_retention_secs: u64,
    // The outbound lazy-migration credential-verification endpoint (issue #58) used
    // to carry four fields here, mirroring four `AdminConfig` keys. Issue #250 moved
    // its enablement AND its credential into the addressed environment's own sealed
    // per-environment secret (issue #45), so nothing about it is process state any
    // more: `crate::migration` reads it per request, per scope, with no fallback.
    // The inbound lazy-migration hook (issue #56), shared with the OIDC data plane in the
    // same process when one is configured. Held so the management-plane migration-progress
    // endpoint can report THIS node's circuit-breaker state alongside the DB progress
    // counts. `None` when no hook is configured, or on a node that does not run the data
    // plane; the endpoint then reports progress with no breaker block.
    migration_hook: Option<Arc<ironauth_oidc::LazyMigrationHook>>,
    // The federation runtime (issue #76), shared with the OIDC data plane in the same process
    // when federation is enabled. Held so the management-plane per-connector health-diagnostics
    // read reports THIS node's live connector health (the SAME in-memory registry the login path
    // records into). `None` when federation is disabled or on a node that does not run the data
    // plane; the health read then reports every connector as never-exercised.
    federation: Option<Arc<ironauth_oidc::FederationRuntime>>,
    // The deployment-wide organization group nesting bound (issue #97), installed by
    // the boot path from `organizations.max_group_depth` and passed to every group
    // create and reparent. Defaults to the shipped default so a directly-built state
    // behaves like a default deployment. Bounds tree DEPTH only; nothing counted is
    // capped.
    max_group_depth: u32,

    // The AuthZEN batch bound (issue #100), installed on the boot path from
    // `organizations.max_authzen_batch` and read by the batch evaluation handler.
    max_authzen_batch: u32,
    // A TESTING-ONLY override of the usage fold's meterable-event bound (issue #107).
    // `None` in every production build, because the only setter is gated on `testing`, so
    // the shipped bound is always `usage::EXPORT_FOLD_LIMIT`.
    //
    // It exists because `truncated` was UNMEASURABLE on the publish path without it. The
    // flag's whole job is to admit the numbers beside it are a lower bound, and a billing
    // pipeline that ignores it invoices a truncated snapshot as exact -- so it is the last
    // field that should be untested. Reaching the real bound needs ten thousand seeded
    // events, which is not a test; lowering the bound for one request is.
    usage_fold_limit: Option<i64>,
    outbox_visibility_timeout_secs: u64,
    // The deployment-wide login-identifier uniqueness policy (issue #54), installed by
    // the boot path from the top-level `[identifiers]` section and passed to every
    // identifier write so the row's uniqueness discriminator matches the configured
    // scope. Defaults to the shipped default, so a directly-built state behaves like a
    // default deployment. Before this the section was operator-visible and read by
    // nothing (issue #459), which is worse than absent: an operator could set
    // `org_scoped` and get environment-wide behaviour with no signal.
    identifier_uniqueness: UniquenessMode,
    // The deployment-wide token claim budget (issue #98), installed by the boot path
    // from the top-level `[token_claims]` config section. The management plane reads it
    // to report the approach warning a write's resolved permission set earns against the
    // budget; it never refuses a write. Defaults to the shipped defaults so a
    // directly-built state behaves like a default deployment. Bounds a TOKEN's size and
    // what ONE claim carries; nothing stored is capped.
    token_claims: TokenClaimsConfig,
    // Admin sudo mode (session privilege separation, issue #73): whether admin
    // mutations require a recent recorded re-authentication, and the freshness window in
    // seconds. Off by default; when off the mutation guard is a no-op and the admin
    // surface behaves exactly as before.
    sudo_mode_enabled: bool,
    sudo_mode_window_secs: u64,
    // Whether the experimental signup fraud-review-queue surface is armed (issue #82, PR 2).
    // Resolved by the boot path from the strict config feature ladder (the
    // `signup-quarantine` experimental feature enabled AND acked at the exact version) and
    // installed via the builder, NOT an AdminConfig toggle, so an operator cannot arm the
    // review-queue endpoints outside the experimental ack gate. Off by default; when off
    // every signup-quarantine review-queue endpoint answers a uniform 404.
    signup_quarantine_enabled: bool,
    // The AuthZEN agent tool profile (issue #133, PROTOTYPE). Default false: an `agent`
    // subject is then refused exactly as any unrecognised type is, so the endpoint does not
    // reveal that the type has a meaning in this build.
    agent_tool_profile_enabled: bool,
    // Whether the experimental advanced-recovery-modes surface is armed (issue #82, PR 3).
    // Resolved by the boot path from the strict config feature ladder (the
    // `advanced-recovery` experimental feature enabled AND acked at the exact version) and
    // installed via the builder, NOT an AdminConfig toggle, so an operator cannot arm the
    // recovery-approval review-queue endpoints outside the experimental ack gate. Off by
    // default; when off every recovery-approval endpoint answers a uniform 404.
    advanced_recovery_enabled: bool,
    // The OIDC-session credential bridge (issue #90, PR 2), shared with the OIDC data
    // plane. `None` (the default) leaves the management API accepting only the two
    // service credentials (the bootstrap operator token and `mak_` keys); NO `at+jwt` is
    // ever accepted, so the console dogfooding surface is fully inert until an operator
    // arms it in `[admin_spa]`.
    admin_oidc_bridge: Option<AdminOidcBridge>,
    // A store-backed, DATA-plane IssuerRegistry (issue #93), shared with the OIDC data
    // plane so the compatibility wizard resolves an environment's ACTUALLY signable
    // ID-token algorithms from the SAME per-environment signing keys the mint and JWKS
    // read. It also carries the data-plane store the wizard's write through targets: the
    // per-client id_token_signed_response_alg column is data-plane writable only (the
    // control role has no grant on it), so the write flows through this registry's store.
    // None (the default) leaves the wizard's write endpoint failing closed (it cannot
    // confirm signability), so the feature is inert until the boot path installs it.
    signing_registry: Option<Arc<IssuerRegistry>>,
    /// The DNS TXT lookup domain verification performs (issue #96).
    txt_lookup: Option<Arc<dyn TxtLookup>>,
}

/// The ONE place the operator-visible uniqueness setting becomes the store's mode
/// (issue #54). The two enums are deliberately separate types, because the store must
/// not depend on the config crate, and this is the single seam that ties them together.
///
/// Exhaustive with no wildcard, so a fourth mode added to either enum fails to compile
/// here rather than silently mapping to the default. A second copy of this match
/// anywhere would be the shape that rots: one of them gets the new variant and the other
/// keeps compiling.
#[must_use]
pub const fn uniqueness_mode(uniqueness: IdentifierUniqueness) -> UniquenessMode {
    match uniqueness {
        IdentifierUniqueness::EnvironmentWide => UniquenessMode::EnvironmentWide,
        IdentifierUniqueness::OrgScoped => UniquenessMode::OrgScoped,
        IdentifierUniqueness::NonUnique => UniquenessMode::NonUnique,
    }
}

/// The reverse of [`uniqueness_mode`], so a route can REPORT the configured mode.
///
/// It exists so the wire spelling is never hand written. The management API and the
/// config file must name these modes identically (an operator reads one and edits the
/// other), and the config enum already carries `#[serde(rename_all = "snake_case")]`, so
/// converting back and serializing THAT is what makes the two spellings one spelling by
/// construction rather than by two authors agreeing.
pub(crate) const fn uniqueness_setting(mode: UniquenessMode) -> IdentifierUniqueness {
    match mode {
        UniquenessMode::EnvironmentWide => IdentifierUniqueness::EnvironmentWide,
        UniquenessMode::OrgScoped => IdentifierUniqueness::OrgScoped,
        UniquenessMode::NonUnique => IdentifierUniqueness::NonUnique,
    }
}

impl AdminState {
    /// Build the management state from a control-plane store, the environment
    /// seam, and the admin config.
    ///
    /// In production the `store` MUST authenticate as `ironauth_control`, not
    /// `ironauth_app`; the binary selects that DSN (see
    /// [`crate::management_router`]). A `dev_mode` fallback to `database.url` is
    /// permitted with the role separation not enforced.
    ///
    /// # Errors
    ///
    /// [`StateError::Secret`] if the bootstrap operator token secret cannot be
    /// resolved from its file or environment-variable source;
    /// [`StateError::EmptyToken`] if it resolves to an empty value (which would
    /// let an empty `Authorization: Bearer ` authenticate as the operator).
    pub fn new(store: Store, env: Env, config: &AdminConfig) -> Result<Self, StateError> {
        let bootstrap_operator_token = match &config.bootstrap_operator_token {
            Some(secret) => {
                let resolved = secret.resolve().map_err(StateError::Secret)?;
                // Presented bearer tokens are trimmed before comparison, so trim
                // the configured token to match, and fail closed if it is empty
                // or only whitespace. An empty configured token and an empty
                // presented bearer token compare equal in constant time, so an
                // empty configured token would authenticate anyone. Refuse to
                // build the state at all rather than enable that, and refuse
                // loudly at startup rather than silently disabling the operator
                // plane on a whitespace-only value.
                let trimmed = resolved.expose().trim();
                if trimmed.is_empty() {
                    return Err(StateError::EmptyToken);
                }
                Some(SecretString::new(trimmed))
            }
            None => None,
        };
        // Page sizes: a non-zero floor, the default never above the max, and the
        // max never above the store's hard cap. Config load already rejects a
        // configured max above the cap; clamping here is defense in depth for a
        // state built directly (for example in a test).
        let hard_cap = u32::try_from(MANAGEMENT_LIST_HARD_CAP).unwrap_or(u32::MAX);
        // Clamped here as well as at config load, exactly as the page size is: a bound
        // whose only enforcement is at parse time is one a directly built state can exceed.
        let max_authzen_batch = config
            .max_authzen_batch
            .min(ironauth_config::MANAGEMENT_MAX_AUTHZEN_BATCH_CEILING);
        let max_page_size = config.max_page_size.max(1).min(hard_cap);
        let default_page_size = config.default_page_size.max(1).min(max_page_size);
        Ok(Self {
            inner: Arc::new(Inner {
                store,
                // Attached by the boot wiring when a data-plane store is reachable; absent here so
                // a state built without it fails the resend closed rather than silently using
                // the control store.
                data_store: None,
                hook_runtime: None,
                env,
                bootstrap_operator_token,
                bootstrap_operator_id: OperatorId::from_seed_bytes(BOOTSTRAP_SEED),
                bootstrap_operator_actor: ActorRef::service(ServiceId::from_seed_bytes(
                    BOOTSTRAP_SEED,
                )),
                default_page_size,
                max_page_size,
                allowed_regions: config.allowed_regions.clone(),
                offboarding_retention_secs: config.offboarding_retention_secs,
                migration_hook: None,
                federation: None,
                max_group_depth: ironauth_config::ORGANIZATIONS_DEFAULT_MAX_GROUP_DEPTH,
                max_authzen_batch,
                usage_fold_limit: None,
                outbox_visibility_timeout_secs: ironauth_config::OutboxConfig::default()
                    .visibility_timeout_secs,
                identifier_uniqueness: UniquenessMode::EnvironmentWide,
                token_claims: TokenClaimsConfig::default(),
                sudo_mode_enabled: config.sudo_mode_enabled,
                sudo_mode_window_secs: config.sudo_mode_window_secs,
                signup_quarantine_enabled: false,
                agent_tool_profile_enabled: false,
                advanced_recovery_enabled: false,
                admin_oidc_bridge: None,
                signing_registry: None,
                txt_lookup: None,
            }),
        })
    }

    /// Arm the OIDC-session credential bridge (issue #90, PR 2).
    ///
    /// The boot path installs this when `admin_spa` names an admin issuer and a
    /// management audience AND the OIDC data plane is mounted (so a store-backed
    /// [`IssuerRegistry`] exists to share). It is a builder rather than an
    /// `AdminConfig` field precisely so the verification KEY SOURCE is the same
    /// shared registry the data plane serves, not a second key store the admin
    /// plane could drift from. With no bridge installed the third resolution arm
    /// is inert and no `at+jwt` is ever accepted (fail closed).
    #[must_use]
    pub fn with_admin_oidc_bridge(mut self, bridge: AdminOidcBridge) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.admin_oidc_bridge = Some(bridge);
        }
        self
    }

    /// Share a store-backed, DATA-plane [`IssuerRegistry`] with the management plane
    /// (issue #93), so the compatibility wizard can resolve an environment's actually
    /// signable ID-token algorithms and write the per-client column through the data
    /// plane (the only role that can). The boot path installs a registry over the SAME
    /// data-plane store and issuer base the OIDC plane serves its JWKS from; with none
    /// installed the wizard's write endpoint fails closed (it cannot confirm
    /// signability). Kept a builder so the many admin tests need not stand a registry up.
    #[must_use]
    pub fn with_signing_registry(mut self, registry: Arc<IssuerRegistry>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.signing_registry = Some(registry);
        }
        self
    }

    /// Install the DNS TXT lookup domain verification performs (issue #96).
    ///
    /// `None` when the boot path installed none, and the verify endpoint then refuses
    /// rather than pretending: a deployment with no resolver cannot prove domain control,
    /// and answering "not verified" would be indistinguishable from a real refusal.
    #[must_use]
    pub fn with_txt_lookup(mut self, lookup: Arc<dyn TxtLookup>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.txt_lookup = Some(lookup);
        }
        self
    }

    /// The installed DNS TXT lookup, if any.
    #[must_use]
    pub fn txt_lookup(&self) -> Option<&Arc<dyn TxtLookup>> {
        self.inner.txt_lookup.as_ref()
    }

    /// The shared data-plane issuer registry (issue #93), or `None` when the boot path
    /// installed none. The compatibility wizard reads an environment's signable set
    /// through `entry_for` and reaches the data-plane store (for the write through) via
    /// [`IssuerRegistry::store`].
    #[must_use]
    pub(crate) fn signing_registry(&self) -> Option<&IssuerRegistry> {
        self.inner.signing_registry.as_deref()
    }

    /// The DATA-plane store, when one was wired (issue #111 criterion 1).
    ///
    /// Reachable by exactly one caller, the message resend endpoint, and for exactly one
    /// reason: `messages` grants the control role SELECT only, deliberately. See [`Inner`].
    ///
    /// Returning [`None`] is a REFUSAL, not a fallback. A caller that quietly used the
    /// control store instead would produce a permission error at best and, if the grant ever
    /// widened, the mailer-on-the-management-surface this separation exists to prevent.
    #[must_use]
    pub(crate) fn data_store(&self) -> Option<&Store> {
        self.inner.data_store.as_ref()
    }

    /// Share the process's WASM hook runtime with this plane (issue #114 criterion 5).
    ///
    /// Handed the SAME runtime the issuance path holds, for the reason `with_data_store` gives
    /// about pools: two engines would be two compiled-code caches, and a draft run would answer
    /// about the one no login uses.
    #[must_use]
    pub fn with_hook_runtime(
        mut self,
        runtime: Arc<ironauth_oidc::token_hook::HookRuntime>,
    ) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.hook_runtime = Some(runtime);
        }
        self
    }

    /// The shared hook runtime, or [`None`] when this build or this process has none.
    #[must_use]
    pub fn hook_runtime(&self) -> Option<&Arc<ironauth_oidc::token_hook::HookRuntime>> {
        self.inner.hook_runtime.as_ref()
    }

    /// Attach the data-plane store (issue #111 criterion 1).
    ///
    /// Handed the SAME store the issuer registry is built from, so this process opens ONE
    /// data-plane pool rather than two. `connect_data_plane_registry` records why that
    /// matters: two pools were "two chances for one operator-visible value to be derived
    /// differently".
    #[must_use]
    pub fn with_data_store(mut self, store: Store) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.data_store = Some(store);
        }
        self
    }

    /// The shared data-plane issuer registry HANDLE, for the boot-wiring harness only
    /// (issue #414).
    ///
    /// This registry carries the issuer base the console credential bridge enforces
    /// `iss` against and the JWKS cache window this plane caches keys for. Both are
    /// operator-visible values the OIDC data plane also carries, and a second
    /// derivation that disagreed would fail every console login while the data plane
    /// looked healthy, so the harness reads them off BOTH assembled planes through this
    /// and [`ironauth_oidc::OidcState::issuers`]. Gated on `testing`: no production
    /// caller needs the handle, and the in-crate readers keep going through
    /// [`AdminState::signing_registry`].
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn shared_issuer_registry(&self) -> Option<&Arc<IssuerRegistry>> {
        self.inner.signing_registry.as_ref()
    }

    /// Resolve a console `at+jwt` (issue #90, PR 2) to a management [`Principal`].
    ///
    /// This is the THIRD resolution arm, after the bootstrap operator token and the
    /// `mak_` key. It runs ONLY when the bridge is armed and the token is a compact
    /// JWS (three dot-separated segments), so the opaque bootstrap token and the
    /// `mak_` key can never reach it. It does IDENTITY RESOLUTION ONLY: it verifies
    /// the token and maps the subject to an operator, and performs NO authorization
    /// (the existing `require_*` methods do that, unchanged).
    ///
    /// Verification runs through the ONE hardened JOSE path
    /// ([`ironauth_jose::verify`]), the SAME core the OIDC data plane uses (compare
    /// `OidcState::verify_access_token`): the signature is checked against the admin
    /// issuer's PUBLISHED signing keys ONLY, `iss` must equal the issuer the shared
    /// registry derives for the admin scope, `aud` must EQUAL the configured
    /// management audience (the cross-RP replay defense), and `exp`/`nbf`/`iat` and
    /// the algorithm allowlist (which forbids `alg=none` and HMAC/RSA confusion) and
    /// the RFC 9068 `typ == at+jwt` media type are enforced by the policy. It then
    /// additionally requires the `ironauth.manage` scope and a `sub` on the
    /// operator-subject allowlist.
    ///
    /// Returns `Ok(Some(Operator))` for a listed subject, and `Ok(None)` for EVERY
    /// other outcome (bridge disarmed, not a JWS, no keys, any verification failure,
    /// missing scope/typ, or an unlisted subject) so the extractor surfaces one
    /// uniform `Unauthorized` with no oracle. This is fail-closed by construction:
    /// there is no default-grant path.
    ///
    /// # Errors
    ///
    /// This arm never itself returns an `Err`: a store fault reading the shared
    /// registry (the fence read) fails closed to `Ok(None)`. The signature keeps the
    /// `Result` so the extractor can chain it uniformly with the `mak_` arm.
    pub(crate) async fn authenticate_admin_oidc(
        &self,
        token: &str,
    ) -> Result<Option<Principal>, ApiError> {
        let Some(bridge) = self.inner.admin_oidc_bridge.as_ref() else {
            return Ok(None);
        };
        // Shape gate: only a compact JWS (exactly three `.`-separated segments) is
        // ours. The opaque bootstrap token and the `mak_<id>.<secret>` key are not,
        // so they never reach the verify path. `verify` re-checks the structure, so
        // this is a cheap pre-filter, not the trust boundary.
        if token.split('.').count() != 3 {
            return Ok(None);
        }
        // Resolve the admin issuer's registry entry (the SAME keys its JWKS serves).
        // A store-backed registry re-reads the suspension fence here; an unprovisioned,
        // cross-tenant, or fenced scope yields `None` and fails closed.
        let now = self.inner.env.clock().now_utc();
        let Some(entry) = bridge.issuers.entry_for(&bridge.issuer_scope, now).await else {
            return Ok(None);
        };
        // The keys published at `now` are exactly those a currently-valid token could
        // have been signed by; a token's `kid` only selects among them, never
        // introduces one (the #9 verify path).
        let keys = entry.keyset().published_signing_keys(now);
        let trusted: Vec<TrustedKey> = keys
            .iter()
            .filter_map(|key| key.verifying_key().ok())
            .collect();
        if trusted.is_empty() {
            return Ok(None);
        }
        // The allowlist is exactly the algorithms those published keys sign with, so a
        // token's own `alg` header is only ever matched against them (never followed);
        // `alg=none`, HMAC, and RSA/EC confusion are structurally inexpressible.
        let mut algorithms: Vec<JwsAlgorithm> = Vec::new();
        for key in &keys {
            if !algorithms.contains(&key.algorithm()) {
                algorithms.push(key.algorithm());
            }
        }
        // One source of truth for the enforced issuer: the value the shared registry
        // itself would publish for this scope. `aud` is the configured management
        // audience, matched EXACTLY (the cross-RP replay defense).
        let issuer = bridge.issuers.issuer_for(&bridge.issuer_scope);
        // `typ == at+jwt` (RFC 9068 section 4) is part of the policy, so a token
        // minted for a different media type (an id token, a logout token) is refused
        // inside `verify` itself rather than by a check bolted on afterwards that a
        // future edit could drop (issue #192). It is not optional: the policy cannot
        // be constructed without naming the profile it accepts.
        let Ok(policy) = VerificationPolicy::new(
            algorithms,
            trusted,
            issuer,
            bridge.management_audience.clone(),
            ExpectedTyp::Required(TokenTyp::AccessToken),
        ) else {
            return Ok(None);
        };
        let Ok(verified) = verify(token, &policy, self.inner.env.clock()) else {
            return Ok(None);
        };
        // The `ironauth.manage` scope must be present: an ordinary end-user login
        // token for the same issuer, lacking it, is rejected here.
        let has_manage_scope = verified
            .claims()
            .get("scope")
            .and_then(Value::as_str)
            .is_some_and(|scope| scope.split_whitespace().any(|s| s == MANAGEMENT_SCOPE));
        if !has_manage_scope {
            return Ok(None);
        }
        // Map the verified subject to an operator via the fail-closed allowlist. An
        // unlisted (or absent) subject is rejected. The verified subject is matched
        // BYTE EXACT (never trimmed here), like `iss` and `aud`; the allowlist entries
        // are trimmed once at load, so a whitespace padded token subject can never
        // alias a listed operator.
        let Some(subject) = verified.claims().subject().filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        if !bridge
            .operator_subjects
            .iter()
            .any(|listed| listed == subject)
        {
            return Ok(None);
        }
        // Attribute the operator to a HUMAN actor derived deterministically from the
        // verified subject (a public identifier), so audit and idempotency name the
        // person, distinct from the SERVICE actor the token/`mak_` arms record.
        let actor = ActorRef::human(human_id_for_subject(subject));
        Ok(Some(Principal::Operator { actor }))
    }

    /// Arm the experimental signup fraud-review-queue admin surface (issue #82, PR 2).
    ///
    /// The boot path is the ONLY caller: it resolves `enabled` from the strict config
    /// feature ladder (the `signup-quarantine` experimental feature enabled AND acknowledged
    /// at the exact version) and installs the SAME bool it installs on the OIDC data plane. A
    /// builder rather than an `AdminConfig` field precisely so an operator cannot arm the
    /// review-queue endpoints from a plain config toggle and bypass the experimental acknowledgment
    /// gate. When false (the default), every review-queue endpoint answers a uniform 404.
    #[must_use]
    pub fn with_signup_quarantine_enabled(mut self, enabled: bool) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.signup_quarantine_enabled = enabled;
        }
        self
    }

    /// Arm the `AuthZEN` AGENT TOOL PROFILE (issue #133, PROTOTYPE).
    ///
    /// A separate switch from the `AuthZEN` PDP itself, which is GA: this adds a new subject
    /// TYPE (`agent`) to an endpoint operators already run, so a deployment that has not
    /// acknowledged the draft has to keep seeing the refusal it saw before -- otherwise
    /// shipping the prototype would silently widen a live authorization surface.
    ///
    /// When false (the default), an `agent` subject falls into the same
    /// `subject_type_unsupported` refusal every other unrecognised type gets, so the endpoint
    /// does not even reveal that the type has a meaning here.
    #[must_use]
    pub fn with_agent_tool_profile_enabled(mut self, enabled: bool) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.agent_tool_profile_enabled = enabled;
        }
        self
    }

    /// Whether the `AuthZEN` agent tool profile is armed (issue #133).
    #[must_use]
    pub fn agent_tool_profile_enabled(&self) -> bool {
        self.inner.agent_tool_profile_enabled
    }

    /// Whether the experimental signup fraud-review-queue admin surface is armed (issue #82,
    /// PR 2). Every review-queue handler's first action is to return a uniform 404 when this
    /// is false.
    #[must_use]
    pub fn signup_quarantine_enabled(&self) -> bool {
        self.inner.signup_quarantine_enabled
    }

    /// Arm the experimental advanced-recovery-modes admin surface (issue #82, PR 3).
    ///
    /// The boot path is the ONLY caller: it resolves `enabled` from the strict config feature
    /// ladder (the `advanced-recovery` experimental feature enabled AND acknowledged at the
    /// exact version) and installs the SAME bool it installs on the OIDC data plane. A builder
    /// rather than an `AdminConfig` field precisely so an operator cannot arm the
    /// recovery-approval review-queue endpoints from a plain config toggle and bypass the
    /// experimental acknowledgment gate. When false (the default), every recovery-approval
    /// endpoint answers a uniform 404.
    #[must_use]
    pub fn with_advanced_recovery_enabled(mut self, enabled: bool) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.advanced_recovery_enabled = enabled;
        }
        self
    }

    /// Whether the experimental advanced-recovery-modes admin surface is armed (issue #82,
    /// PR 3). Every recovery-approval handler's first action is to return a uniform 404 when
    /// this is false.
    #[must_use]
    pub fn advanced_recovery_enabled(&self) -> bool {
        self.inner.advanced_recovery_enabled
    }

    /// The visibility lease the outbox drains under, needed to report queue depth
    /// (issue #104).
    ///
    /// It comes from `[outbox]` rather than `[admin]`, so it is installed here rather than
    /// read off [`ironauth_config::AdminConfig`]. The depth read needs it because "in
    /// flight" means "leased and the lease has not lapsed", and nothing about a row says
    /// how long its lease was for; a state built without it reports depth against the
    /// shipped default, which is what a test or a boot path that installed nothing gets.
    ///
    /// Getting it WRONG misreports rather than breaks: a lease shorter than the drain's
    /// counts live work as ready, and a longer one counts lapsed work as in flight. The
    /// boot path installs the same value the pools are built from, so the two agree.
    #[must_use]
    pub fn with_outbox_visibility_timeout(mut self, secs: u64) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.outbox_visibility_timeout_secs = secs;
        }
        self
    }

    /// The visibility lease queue depth is reported against.
    #[must_use]
    pub fn outbox_visibility_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.inner.outbox_visibility_timeout_secs)
    }

    /// Install the deployment-wide organization group nesting bound (issue #97).
    ///
    /// The boot path is the only caller and passes `organizations.max_group_depth`
    /// straight from the loaded config. A BUILDER rather than an [`AdminConfig`] field
    /// because the setting lives in the `[organizations]` section, not `[admin]`:
    /// duplicating it under `[admin]` would give one bound two operator-visible names
    /// that could disagree. The value is clamped to
    /// [`ironauth_config::ORGANIZATIONS_MAX_GROUP_DEPTH_CEILING`] here as defense in
    /// depth (config load already refuses a larger one, and the store clamps its own
    /// parameter again regardless of what this passes).
    ///
    /// This bounds tree DEPTH, which is what makes the ancestor walk on the
    /// token-issuance path terminate. It caps nothing that is counted: the number of
    /// groups, roles, members, and assignments an organization may hold is uncapped by
    /// covenant.
    #[must_use]
    pub fn with_max_group_depth(mut self, max_group_depth: u32) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.max_group_depth =
                max_group_depth.min(ironauth_config::ORGANIZATIONS_MAX_GROUP_DEPTH_CEILING);
        }
        self
    }

    /// The configured organization group nesting bound (issue #97), passed to every
    /// group create and reparent. Defaults to
    /// [`ironauth_config::ORGANIZATIONS_DEFAULT_MAX_GROUP_DEPTH`] when the boot path
    /// installed nothing, so a state built directly (for example in a test) matches
    /// the shipped default rather than zero.
    #[must_use]
    pub fn max_group_depth(&self) -> u32 {
        self.inner.max_group_depth
    }

    /// The configured `AuthZEN` batch bound (issue #100), from `admin.max_authzen_batch`.
    #[must_use]
    pub fn max_authzen_batch(&self) -> u32 {
        self.inner.max_authzen_batch
    }

    /// Install the deployment-wide login-identifier uniqueness policy (issue #54).
    ///
    /// The boot path is the only caller and passes the whole `[identifiers]` section
    /// straight from the loaded config. A BUILDER rather than an [`AdminConfig`] field
    /// for the same reason as [`AdminState::with_max_group_depth`]: the setting lives in
    /// its own top-level section, and repeating it under `[admin]` would give one policy
    /// two operator-visible names that could disagree.
    ///
    /// This is the READER that makes the section mean something. Migration 0041 already
    /// named `identifiers.uniqueness` as the source of each row's uniqueness
    /// discriminator, and the store already enforced whatever mode it was handed, but
    /// nothing on either plane ever read the section, so every write got the
    /// environment-wide default no matter what the operator wrote (issue #459). The
    /// management plane installs it here because the identifier management surface is
    /// currently the only production writer; the data plane has no identifier writer to
    /// hand it to yet.
    #[must_use]
    pub fn with_identifiers(mut self, config: &IdentifiersConfig) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            // An exhaustive match with no wildcard, so a fourth mode added to either
            // enum fails to compile here rather than silently mapping to the default.
            // The two enums are deliberately separate types: the store must not depend
            // on the config crate, so this is the one place they are tied together.
            inner.identifier_uniqueness = uniqueness_mode(config.uniqueness);
        }
        self
    }

    /// The configured login-identifier uniqueness policy (issue #54), passed to every
    /// identifier write so the row's uniqueness discriminator matches the configured
    /// scope. Defaults to [`UniquenessMode::EnvironmentWide`] when the boot path
    /// installed nothing, which is both the shipped config default and the safe answer.
    #[must_use]
    pub fn identifier_uniqueness(&self) -> UniquenessMode {
        self.inner.identifier_uniqueness
    }

    /// Install the deployment-wide token claim budget (issue #98).
    ///
    /// The boot path is the only caller and passes the whole `[token_claims]` section
    /// straight from the loaded config, the SAME section it installs on the data plane
    /// through `OidcState::with_token_claims`. The WHOLE section rather than a scalar
    /// builder per key: the five keys are one budget, only meaningful together, and a
    /// per-key builder would let a caller install a threshold without the maximum it is
    /// measured against. A BUILDER rather than an [`AdminConfig`] field because the
    /// section is top level, not `[admin]`: duplicating it under `[admin]` would give one
    /// budget two operator-visible names that could disagree.
    ///
    /// The section is re-clamped through [`TokenClaimsConfig::clamped`] here as defense in
    /// depth. Config load already refuses anything outside the ceilings, so this is a
    /// no-op on the boot path; it matters because a state can also be built directly from
    /// a hand-constructed section that never passed validation.
    ///
    /// The budget bounds a TOKEN's size and what ONE claim carries. It caps nothing this
    /// plane writes: no management endpoint refuses a create or an attach because of any
    /// count or size, so the budget produces no 4xx and no 5xx anywhere on this plane.
    ///
    /// It IS reported in TWO places, over TWO DIFFERENT SETS, and confusing them is the
    /// one mistake this doc exists to prevent (issue #425):
    ///
    ///   * the effective-roles READ carries `permission_budget` on its 200, over one
    ///     MEMBERSHIP'S RESOLVED set (direct roles, the group ancestor closure, and the
    ///     organization's default role, unioned). That is what a token claim would carry,
    ///     so it is the authoritative verdict, and the object states `scope:
    ///     "membership"`;
    ///   * the role-to-permission ATTACH carries `role_permission_budget` on its 201,
    ///     over THAT ROLE'S OWN live mappings including the one just attached, and the
    ///     object states `scope: "role"`. It is there because the write is where the
    ///     operator's attention is.
    ///
    /// The role figure is NEITHER an upper nor a lower bound on the membership figure.
    /// It counts a different set and can be wrong about the membership in either
    /// direction: a soft-deleted PERMISSION is still counted by the role figure and
    /// resolves for no membership, a DISABLED organization stays writable here while
    /// resolving nothing at all, and the figure is a SNAPSHOT taken at the write, which
    /// a concurrent change can outdate in either direction and which an Idempotency-Key
    /// replay reproduces unchanged by design. Only the effective-roles read predicts
    /// what a token will carry.
    ///
    /// Both evaluate through the one `PermissionBudgetView::evaluate` and take every
    /// wire string from `ironauth_config::PermissionOverflow::permissions_status`, the
    /// same source the mint stamps onto the token, so the console, the attach response
    /// and the token cannot disagree about the vocabulary even where they legitimately
    /// disagree about the count.
    #[must_use]
    pub fn with_token_claims(mut self, config: &TokenClaimsConfig) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.token_claims = config.clamped();
        }
        self
    }

    /// The configured token claim budget (issue #98), read by the management plane to
    /// report the approach warning a resolved permission set earns. Defaults to the
    /// shipped [`TokenClaimsConfig::default`] when the boot path installed nothing, so a
    /// state built directly (for example in a test) behaves like a default deployment
    /// rather than pinning every bound to zero.
    #[must_use]
    pub fn token_claims(&self) -> &TokenClaimsConfig {
        &self.inner.token_claims
    }

    /// Share the inbound lazy-migration hook (issue #56) with the management plane, so the
    /// migration-progress endpoint can report this node's circuit-breaker state. The boot
    /// path installs the SAME `Arc` it installs on the OIDC data plane; with no hook
    /// installed the progress endpoint reports the DB counts and no breaker block. Kept a
    /// builder so the many admin tests need not stand a hook up.
    #[must_use]
    pub fn with_migration_hook(mut self, hook: Arc<ironauth_oidc::LazyMigrationHook>) -> Self {
        // The Arc<Inner> is not yet shared at construction time (the caller holds the sole
        // reference right after `new`), so this get_mut succeeds; if it ever did not, the
        // hook is simply not installed rather than panicking.
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.migration_hook = Some(hook);
        }
        self
    }

    /// The installed lazy-migration hook, if any (issue #56).
    ///
    /// Exists so the boot-wiring harness (issue #414) can prove what
    /// [`AdminState::with_migration_hook`] claims: that this plane holds the SAME `Arc`
    /// as the OIDC data plane, not merely an equal configuration. Equality would not
    /// do, because the login path drives the circuit breaker inside this object and
    /// this plane reports THAT breaker's state. Nothing on the management plane reads
    /// the hook through this accessor; the progress endpoint goes through
    /// [`AdminState::migration_breaker_state`]. Gated on `testing` for exactly that
    /// reason: it has no production caller, so the production build's surface is
    /// unchanged.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn migration_hook(&self) -> Option<&Arc<ironauth_oidc::LazyMigrationHook>> {
        self.inner.migration_hook.as_ref()
    }

    /// This node's lazy-migration circuit-breaker state (issue #56), or `None` when no
    /// hook is installed on this node. Reported by the migration-progress endpoint.
    #[must_use]
    pub(crate) fn migration_breaker_state(&self) -> Option<ironauth_oidc::BreakerState> {
        self.inner
            .migration_hook
            .as_ref()
            .map(|hook| hook.breaker_state())
    }

    /// Share the federation runtime (issue #76) with the management plane, so the
    /// per-connector health-diagnostics read reports the live health the OIDC data plane
    /// records into. The boot path installs the SAME `Arc` it installs on the data plane; with
    /// no runtime installed the health read reports every connector as never-exercised. Kept a
    /// builder so the many admin tests need not stand a runtime up.
    #[must_use]
    pub fn with_federation(mut self, runtime: Arc<ironauth_oidc::FederationRuntime>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.federation = Some(runtime);
        }
        self
    }

    /// Lower the usage fold's meterable-event bound for this state (issue #107).
    ///
    /// Gated on `testing`, so a production build has no way to set it and the shipped bound
    /// is always `usage::EXPORT_FOLD_LIMIT`. See the field's comment for why the alternative
    /// (seeding ten thousand events) is not one.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn with_usage_fold_limit(mut self, limit: i64) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.usage_fold_limit = Some(limit);
        }
        self
    }

    /// The overridden usage fold bound, or `None` for the shipped one.
    pub(crate) fn usage_fold_limit(&self) -> Option<i64> {
        self.inner.usage_fold_limit
    }

    /// The installed federation runtime, if any (issue #76).
    ///
    /// Exists for the same reason as [`AdminState::migration_hook`]: the boot-wiring
    /// harness (issue #414) proves this plane holds the SAME `Arc` the login legs
    /// record connector health into, which is what makes the health-diagnostics read
    /// live rather than empty. The health read itself goes through
    /// [`AdminState::connector_health`], not this accessor, so this is gated on
    /// `testing` and the production build's surface is unchanged.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn federation(&self) -> Option<&Arc<ironauth_oidc::FederationRuntime>> {
        self.inner.federation.as_ref()
    }

    /// This node's live health snapshot for one connector (issue #76), read against the admin
    /// clock seam, or `None` when no federation runtime is installed, the connector has never been
    /// exercised on this node, or its recorded health predates the current `fingerprint`.
    ///
    /// `fingerprint` is the connector's current definition version (its store row `updated_at`
    /// micros): passing it lets the read discount a record left by a PRIOR definition, so the
    /// health surface reflects a reconfiguration promptly instead of reporting a stale state.
    #[must_use]
    pub(crate) fn connector_health(
        &self,
        connector_id: &str,
        fingerprint: i64,
    ) -> Option<ironauth_oidc::ConnectorHealthSnapshot> {
        let now = self.inner.env.clock().now_utc();
        self.inner
            .federation
            .as_ref()?
            .health()
            .snapshot(now, connector_id, fingerprint)
    }

    /// Whether `region` is in the operator's configured data-residency region set
    /// (issue #46). Always false when no region set is configured, so a residency
    /// pin can be recorded only against an explicitly allowed value. Governs BOTH a
    /// tenant's `home_region` and a per-environment `region` pin (the same set).
    #[must_use]
    pub fn region_is_allowed(&self, region: &str) -> bool {
        self.inner
            .allowed_regions
            .iter()
            .any(|allowed| allowed == region)
    }

    /// Whether `region` is a permitted tenant `home_region` (issue #46). An alias of
    /// [`AdminState::region_is_allowed`]: the tenant home region and the
    /// per-environment region pin validate against the same configured set.
    #[must_use]
    pub fn home_region_is_allowed(&self, region: &str) -> bool {
        self.region_is_allowed(region)
    }

    /// The configured tenant-offboarding retention window (issue #46): the grace
    /// period during which a soft-deleted tenant can be restored, after which the
    /// terminal hard delete is due. A tunable with a safe default (see
    /// [`ironauth_config::AdminConfig::offboarding_retention_secs`]).
    #[must_use]
    pub fn offboarding_retention(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.inner.offboarding_retention_secs)
    }

    /// Whether admin sudo mode (session privilege separation, issue #73) is active.
    /// When false, the admin mutation freshness guard is a no-op and the surface
    /// behaves exactly as before (the feature is fully inert when off).
    #[must_use]
    pub fn sudo_mode_enabled(&self) -> bool {
        self.inner.sudo_mode_enabled
    }

    /// The admin sudo re-authentication freshness window, in seconds (issue #73): how
    /// long a recorded elevation authorizes admin mutations before a fresh
    /// re-authentication is required.
    #[must_use]
    pub fn sudo_mode_window_secs(&self) -> u64 {
        self.inner.sudo_mode_window_secs
    }

    /// The control-plane store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The environment seam (clock and entropy).
    #[must_use]
    pub fn env(&self) -> &Env {
        &self.inner.env
    }

    /// The default page size when a caller supplies no `limit`.
    #[must_use]
    pub fn default_page_size(&self) -> u32 {
        self.inner.default_page_size
    }

    /// The maximum page size any list endpoint returns.
    #[must_use]
    pub fn max_page_size(&self) -> u32 {
        self.inner.max_page_size
    }

    /// The well-known bootstrap operator id (the owner of tenants in M1).
    #[must_use]
    pub fn bootstrap_operator_id(&self) -> OperatorId {
        self.inner.bootstrap_operator_id
    }

    /// The current wall-clock time in microseconds since the Unix epoch, from the
    /// environment clock seam. Used so a pre-built response body, the stored row,
    /// and the pagination key all share one deterministic timestamp.
    #[must_use]
    pub fn now_unix_micros(&self) -> i64 {
        match self
            .inner
            .env
            .clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
        {
            Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
            Err(_) => 0,
        }
    }

    /// Match a presented token against the bootstrap operator token, in constant
    /// time. Returns the operator principal on a match.
    pub(crate) fn match_operator(&self, token: &str) -> Option<Principal> {
        let configured = self.inner.bootstrap_operator_token.as_ref()?.expose();
        // Defense in depth: an empty configured token never authenticates.
        // `AdminState::new` already refuses to build with an empty token, so this
        // guard is belt and suspenders against a future construction path.
        if configured.is_empty() {
            return None;
        }
        constant_time_eq(token.as_bytes(), configured.as_bytes()).then_some(Principal::Operator {
            actor: self.inner.bootstrap_operator_actor,
        })
    }

    /// Resolve a management-key token `<mak_id>.<secret>` to a principal.
    ///
    /// The scope is recovered from the token's id half (which declares it in the
    /// clear), then possession of the whole token is proven by its stored hash
    /// WITHIN that scope. Returns `None` for a token that is not a management key,
    /// is malformed, or does not match a live key (all surface as unauthorized).
    ///
    /// # Errors
    ///
    /// [`ApiError::Internal`] on a store failure.
    pub(crate) async fn authenticate_management_key(
        &self,
        token: &str,
    ) -> Result<Option<Principal>, ApiError> {
        if !token.starts_with("mak_") {
            return Ok(None);
        }
        let Some((id_part, _secret)) = token.split_once('.') else {
            return Ok(None);
        };
        let Ok(id) = ManagementKeyId::parse_declared_scope(id_part) else {
            return Ok(None);
        };
        let scope = id.scope();
        let hash = sha256_hex(token.as_bytes());
        let Some((stored, confined_to)) = self
            .inner
            .store
            .management()
            .credentials(scope)
            .authenticate_with_grants(&id, &hash)
            .await?
        else {
            return Ok(None);
        };
        let actor = ActorRef::service(ServiceId::from_seed_bytes(id.unique_bytes()));
        // `None` is UNRESTRICTED, which is every credential minted before migration 0118.
        let grants = match stored {
            None => None,
            Some(slugs) => {
                let mut held = ManagementGrants::empty();
                for slug in &slugs {
                    // FAIL CLOSED on a slug this binary does not know. A grant row naming an
                    // unrecognized permission is not a licence: skipping it silently would
                    // leave the credential holding LESS than the row says, which is the safe
                    // direction, but treating the row as unrestricted would be catastrophic.
                    // So an unknown slug contributes nothing and the rest still apply.
                    if let Some(permission) = ManagementPermission::from_slug(slug) {
                        held = held.insert(permission);
                    }
                }
                Some(held)
            }
        };
        // A confinement naming an organization that will not parse IN THIS SCOPE is a
        // foreign-tenant or malformed id. It reads as unconfined ONLY if we ignored it, which
        // would silently widen the credential, so it fails closed instead: the credential does
        // not authenticate at all rather than authenticating with more reach than its row says.
        let organization = match confined_to {
            None => None,
            Some(raw) => match OrganizationId::parse_in_scope(&raw, &scope) {
                Ok(id) => Some(id),
                Err(_) => return Ok(None),
            },
        };
        Ok(Some(Principal::ManagementKey {
            scope,
            actor,
            grants,
            organization,
        }))
    }
}

/// A stable [`HumanId`] derived deterministically from a verified OIDC subject
/// (issue #90, PR 2).
///
/// The subject is a PUBLIC identifier recovered from a cryptographically verified
/// token, so deriving the audit actor's id from it is the exact "derived from other
/// PUBLIC identifier bytes" allowance [`HumanId::from_seed_bytes`] documents (the
/// same shape a management key's service actor uses). It is stable across requests,
/// so every action by one operator attributes to one human actor; and it is a
/// one-way SHA-256 truncation, so the human id column carries no reversible copy of
/// the subject.
fn human_id_for_subject(subject: &str) -> HumanId {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(subject.as_bytes());
    let mut seed = [0_u8; 16];
    seed.copy_from_slice(&digest[..16]);
    HumanId::from_seed_bytes(seed)
}

/// Why the management state could not be built.
#[derive(Debug)]
pub enum StateError {
    /// The bootstrap operator token secret could not be resolved.
    Secret(SecretError),
    /// The bootstrap operator token resolved to an EMPTY value (set-but-empty
    /// env var, empty file, or empty literal). Refused, because an empty
    /// configured token would authenticate an empty presented bearer token as
    /// the operator.
    EmptyToken,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Secret(source) => {
                write!(f, "cannot resolve admin.bootstrap_operator_token: {source}")
            }
            StateError::EmptyToken => write!(
                f,
                "admin.bootstrap_operator_token resolved to an empty value; refusing to enable \
                 the operator plane"
            ),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StateError::Secret(source) => Some(source),
            StateError::EmptyToken => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_config::Secret;
    use sqlx::postgres::PgPoolOptions;

    /// A store over a LAZY pool: parses the URL but never connects, so these
    /// tests stay database-free (no method here touches the store).
    fn lazy_store() -> Store {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://ironauth@localhost/ironauth")
            .expect("lazy pool parses the URL");
        Store::from_pool(pool)
    }

    fn config_with_token(token: Option<&str>) -> AdminConfig {
        AdminConfig {
            bootstrap_operator_token: token.map(|value| Secret::Literal(SecretString::new(value))),
            ..AdminConfig::default()
        }
    }

    #[tokio::test]
    async fn new_refuses_an_empty_or_whitespace_bootstrap_token() {
        // An empty token, and a whitespace-only token (which trims to empty and
        // could never match a trimmed presented token), must both fail closed at
        // startup rather than silently disabling or opening the operator plane.
        // AdminState has no Debug, so match rather than expect_err (which would
        // need to format the Ok value).
        for token in ["", "   ", "\t\n "] {
            match AdminState::new(lazy_store(), Env::system(), &config_with_token(Some(token))) {
                Err(err @ StateError::EmptyToken) => {
                    assert!(err.to_string().contains("empty value"), "{err}");
                }
                Err(other) => panic!("expected EmptyToken for {token:?}, got: {other}"),
                Ok(_) => panic!("an empty or whitespace-only bootstrap token must be refused"),
            }
        }
    }

    #[tokio::test]
    async fn a_configured_token_is_trimmed_to_match_the_trimmed_presented_token() {
        // Presented tokens are trimmed, so a configured token with incidental
        // surrounding whitespace must still match its trimmed form (and must not
        // match the untrimmed spelling).
        let state = AdminState::new(
            lazy_store(),
            Env::system(),
            &config_with_token(Some("  op-secret  ")),
        )
        .expect("a token with surrounding whitespace builds after trimming");
        assert!(state.match_operator("op-secret").is_some(), "trimmed match");
        assert!(
            state.match_operator("  op-secret  ").is_none(),
            "the untrimmed spelling must not match"
        );
    }

    #[tokio::test]
    async fn a_non_empty_token_matches_only_itself() {
        let state = AdminState::new(
            lazy_store(),
            Env::system(),
            &config_with_token(Some("op-secret")),
        )
        .expect("non-empty token builds");
        assert!(state.match_operator("op-secret").is_some(), "exact match");
        assert!(state.match_operator("").is_none(), "empty presented token");
        assert!(state.match_operator("wrong").is_none(), "wrong token");
    }

    #[tokio::test]
    async fn an_unset_token_never_matches() {
        let state = AdminState::new(lazy_store(), Env::system(), &config_with_token(None))
            .expect("unset token builds (operator plane unauthorized)");
        assert!(state.match_operator("anything").is_none());
        assert!(state.match_operator("").is_none());
    }

    #[tokio::test]
    async fn default_page_size_is_clamped_to_max_page_size() {
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new("t"))),
            default_page_size: 500,
            max_page_size: 100,
            ..AdminConfig::default()
        };
        let state = AdminState::new(lazy_store(), Env::system(), &config).expect("builds");
        assert_eq!(state.max_page_size(), 100);
        assert_eq!(
            state.default_page_size(),
            100,
            "default is clamped down to the max"
        );
    }
}
