// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed, non-guessable, non-recyclable identifiers.
//!
//! Every identifier is a random 128-bit payload rendered as a typed-prefixed,
//! URL-safe string (`ten_...`, `env_...`, `op_...`, `cli_...`, `org_...`). The
//! randomness comes only from [`ironauth_env::Env`]'s entropy seam, never from
//! an OS source directly, so identifier minting is deterministic under test and
//! the invariant lints stay satisfied.
//!
//! Two structural properties defeat named CVE classes:
//!
//! - **Non-guessable.** 128 bits of entropy per component means an identifier
//!   cannot be enumerated or predicted (the unauthenticated-enumeration class).
//! - **Non-recyclable.** Identifiers are random, never serial, so a value is
//!   never reissued after deletion (the recycled-identifier leakage class).
//!
//! Scoped resource identifiers ([`ScopedId`], e.g. [`ClientId`]) additionally
//! *embed* their tenant and environment. Parsing one under the wrong scope
//! fails as a uniform [`NotInScope`], indistinguishable from a genuinely absent
//! resource: there is no existence oracle and no error-shape oracle. This is
//! the compile-time-adjacent half of the deny-by-default isolation model; the
//! repository layer and Postgres row-level security are the other two.

use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Env;

use crate::scope::Scope;

/// Bytes of entropy in a single identifier component. 128 bits puts guessing
/// and enumeration out of reach; a scoped identifier carries three such
/// components (tenant, environment, and its own unique payload).
pub const COMPONENT_BYTES: usize = 16;

/// The wire byte length of a [`ScopedId`] payload: tenant, environment, and the
/// resource's own unique component, concatenated.
const SCOPED_BYTES: usize = COMPONENT_BYTES * 3;

/// The kind of a single-level identifier: the marker that fixes its wire
/// prefix. Implementors are zero-size marker types ([`OperatorKind`],
/// [`TenantKind`], [`EnvironmentKind`]).
pub trait LevelKind: Copy + Eq + Hash + fmt::Debug {
    /// The wire prefix, without the trailing underscore (for example `ten`).
    const PREFIX: &'static str;
}

/// The kind of a tenant-scoped resource identifier: the marker that fixes its
/// wire prefix. Implementors are zero-size marker types ([`ClientKind`],
/// [`OrganizationKind`]).
pub trait ScopedKind: Copy + Eq + Hash + fmt::Debug {
    /// The wire prefix, without the trailing underscore (for example `cli`).
    const PREFIX: &'static str;
}

/// Marker for the operator level (the platform deployment). Top of the
/// four-level model; not tenant-scoped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperatorKind;
impl LevelKind for OperatorKind {
    const PREFIX: &'static str = "op";
}

/// Marker for the tenant level (a customer of the operator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantKind;
impl LevelKind for TenantKind {
    const PREFIX: &'static str = "ten";
}

/// Marker for the environment level (for example prod or staging within a
/// tenant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvironmentKind;
impl LevelKind for EnvironmentKind {
    const PREFIX: &'static str = "env";
}

/// Marker for an OAuth client, the worked example of a tenant-scoped resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientKind;
impl ScopedKind for ClientKind {
    const PREFIX: &'static str = "cli";
}

/// Marker for an organization. In milestone M1 organizations are a schema slot
/// only (see the tenancy design doc); the identifier type exists so scoped
/// tables and the isolation harness cover the table from day one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrganizationKind;
impl ScopedKind for OrganizationKind {
    const PREFIX: &'static str = "org";
}

/// Marker for an audit-log event, the tenant-scoped record the audit log writes
/// in the same transaction as every mutation. Scoped like any other resource so
/// audit rows are themselves subject to the tenant-isolation policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditKind;
impl ScopedKind for AuditKind {
    const PREFIX: &'static str = "aud";
}

/// Marker for a management API key (`mak_`), the environment-scoped credential
/// the management API authenticates on (issue #11). A tenant-scoped resource, so
/// its identifier embeds its `(tenant, environment)`: the scope is recoverable
/// from a presented token without a database lookup, and a key minted in one
/// scope parses as a uniform not-found under another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManagementKeyKind;
impl ScopedKind for ManagementKeyKind {
    const PREFIX: &'static str = "mak";
}

/// Marker for a human actor (an interactive user). One of the three actor kinds
/// an audit envelope can name (see [`crate::audit::ActorRef`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HumanKind;
impl LevelKind for HumanKind {
    const PREFIX: &'static str = "hum";
}

/// Marker for a service actor (a machine client acting on its own behalf).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceKind;
impl LevelKind for ServiceKind {
    const PREFIX: &'static str = "svc";
}

/// Marker for an agent actor (an autonomous agent acting for a principal). A
/// first-class actor kind because agent-mediated administration is a stated
/// target surface, and its actions must be attributable in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentKind;
impl LevelKind for AgentKind {
    const PREFIX: &'static str = "agt";
}

/// Marker for a correlation (request) identifier, threaded through the caller
/// context so every audit row can be tied back to the request that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CorrelationKind;
impl LevelKind for CorrelationKind {
    const PREFIX: &'static str = "req";
}

/// A single-level identifier: a typed prefix over a random 128-bit payload.
///
/// Used for the levels that are not themselves tenant-scoped ([`OperatorId`])
/// and for the two scope components ([`TenantId`], [`EnvironmentId`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LevelId<K: LevelKind> {
    bytes: [u8; COMPONENT_BYTES],
    _kind: PhantomData<K>,
}

/// An operator identifier (`op_...`).
pub type OperatorId = LevelId<OperatorKind>;
/// A tenant identifier (`ten_...`).
pub type TenantId = LevelId<TenantKind>;
/// An environment identifier (`env_...`).
pub type EnvironmentId = LevelId<EnvironmentKind>;
/// A human actor identifier (`hum_...`).
pub type HumanId = LevelId<HumanKind>;
/// A service actor identifier (`svc_...`).
pub type ServiceId = LevelId<ServiceKind>;
/// An agent actor identifier (`agt_...`).
pub type AgentId = LevelId<AgentKind>;
/// A correlation (request) identifier (`req_...`).
pub type CorrelationId = LevelId<CorrelationKind>;

impl<K: LevelKind> LevelId<K> {
    /// Mint a fresh identifier from the environment's entropy seam.
    #[must_use]
    pub fn generate(env: &Env) -> Self {
        let mut bytes = [0_u8; COMPONENT_BYTES];
        env.entropy().fill_bytes(&mut bytes);
        Self {
            bytes,
            _kind: PhantomData,
        }
    }

    /// The raw 128-bit payload. Used to embed this level into a [`ScopedId`]
    /// and to bind row-level-security session variables.
    #[must_use]
    pub(crate) fn bytes(&self) -> [u8; COMPONENT_BYTES] {
        self.bytes
    }

    /// Construct a level identifier from fixed seed bytes, for a WELL-KNOWN or
    /// DERIVED identity rather than a freshly minted random one.
    ///
    /// Random identifiers must always come from [`LevelId::generate`] (the
    /// entropy seam). This bypass is only for the two deliberate exceptions the
    /// management API (issue #11) needs: a well-known constant identity (the
    /// bootstrap operator and its audit service-actor, which must be stable
    /// across restarts) and an identity deterministically derived from other
    /// PUBLIC identifier bytes (a management key's audit service-actor, derived
    /// from the key's public unique component so the audit row names the key).
    /// Passing attacker-influenced or low-entropy bytes here would forfeit the
    /// non-guessability property, so callers must pass a constant or
    /// public-derived value only.
    #[must_use]
    pub fn from_seed_bytes(bytes: [u8; COMPONENT_BYTES]) -> Self {
        Self {
            bytes,
            _kind: PhantomData,
        }
    }

    /// Reconstruct from raw payload bytes (internal; used when decoding a
    /// scoped identifier's embedded components).
    pub(crate) fn from_bytes(bytes: [u8; COMPONENT_BYTES]) -> Self {
        Self {
            bytes,
            _kind: PhantomData,
        }
    }

    /// Parse a level identifier from its wire form.
    ///
    /// # Errors
    ///
    /// [`IdParseError`] if the prefix is wrong, the payload is not canonical
    /// URL-safe base64, or the decoded length is not 128 bits. Level
    /// identifiers arrive from trusted configuration and the authenticated
    /// caller context, so a descriptive error is appropriate here; the
    /// oracle-free path is [`ScopedId::parse_in_scope`].
    pub fn parse(raw: &str) -> Result<Self, IdParseError> {
        let bytes = decode_component::<COMPONENT_BYTES>(raw, K::PREFIX)?;
        Ok(Self {
            bytes,
            _kind: PhantomData,
        })
    }
}

impl<K: LevelKind> fmt::Display for LevelId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", K::PREFIX, URL_SAFE_NO_PAD.encode(self.bytes))
    }
}

impl<K: LevelKind> fmt::Debug for LevelId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The identifier is opaque and non-secret; show the wire form so logs
        // and test failures are legible.
        write!(f, "{self}")
    }
}

/// A tenant-scoped resource identifier: a typed prefix over the concatenation
/// of the resource's tenant, its environment, and its own random 128-bit
/// payload.
///
/// Embedding the scope is deliberate. A handle to a [`ScopedId`] cannot be
/// used against another tenant, because parsing one under a mismatched scope
/// (see [`ScopedId::parse_in_scope`]) yields a uniform [`NotInScope`], the same
/// outcome as a resource that never existed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopedId<K: ScopedKind> {
    tenant: TenantId,
    environment: EnvironmentId,
    unique: [u8; COMPONENT_BYTES],
    _kind: PhantomData<K>,
}

/// An OAuth client identifier (`cli_...`), the worked scoped-resource example.
pub type ClientId = ScopedId<ClientKind>;
/// An organization identifier (`org_...`); schema slot only in M1.
pub type OrganizationId = ScopedId<OrganizationKind>;
/// An audit-log event identifier (`aud_...`).
pub type AuditId = ScopedId<AuditKind>;
/// A management API key identifier (`mak_...`), environment-scoped (issue #11).
pub type ManagementKeyId = ScopedId<ManagementKeyKind>;

impl<K: ScopedKind> ScopedId<K> {
    /// Mint a fresh scoped identifier under `scope`, drawing the unique
    /// component from the environment's entropy seam. The tenant and
    /// environment are copied from the scope, so a freshly minted identifier is
    /// always in scope by construction.
    #[must_use]
    pub fn generate(env: &Env, scope: &Scope) -> Self {
        let mut unique = [0_u8; COMPONENT_BYTES];
        env.entropy().fill_bytes(&mut unique);
        Self {
            tenant: scope.tenant(),
            environment: scope.environment(),
            unique,
            _kind: PhantomData,
        }
    }

    /// The tenant this identifier is bound to.
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The environment this identifier is bound to.
    #[must_use]
    pub fn environment(&self) -> EnvironmentId {
        self.environment
    }

    /// The scope this identifier belongs to.
    #[must_use]
    pub fn scope(&self) -> Scope {
        Scope::new(self.tenant, self.environment)
    }

    /// This identifier's own unique 128-bit component. It is PUBLIC (the scope is
    /// the other two components), so it may be used to derive a stable
    /// service-actor identity for a credential ([`LevelId::from_seed_bytes`]).
    #[must_use]
    pub fn unique_bytes(&self) -> [u8; COMPONENT_BYTES] {
        self.unique
    }

    /// Parse a scoped identifier and confirm it belongs to `scope`.
    ///
    /// This is the only identifier entry point a request handler should use on
    /// untrusted input. It is the oracle-free boundary of the isolation model:
    /// a malformed identifier, an identifier of the wrong kind, and an
    /// identifier belonging to another tenant or environment all fail
    /// identically with [`NotInScope`]. A caller therefore cannot learn whether
    /// a cross-scope resource exists.
    ///
    /// # Errors
    ///
    /// [`NotInScope`] on any parse failure or scope mismatch. The error carries
    /// no detail by design.
    pub fn parse_in_scope(raw: &str, scope: &Scope) -> Result<Self, NotInScope> {
        // Any failure below collapses to the same NotInScope: prefix, base64,
        // length, and scope mismatch are indistinguishable to the caller.
        let payload = decode_component::<SCOPED_BYTES>(raw, K::PREFIX).map_err(|_| NotInScope)?;
        let mut tenant = [0_u8; COMPONENT_BYTES];
        let mut environment = [0_u8; COMPONENT_BYTES];
        let mut unique = [0_u8; COMPONENT_BYTES];
        tenant.copy_from_slice(&payload[0..COMPONENT_BYTES]);
        environment.copy_from_slice(&payload[COMPONENT_BYTES..COMPONENT_BYTES * 2]);
        unique.copy_from_slice(&payload[COMPONENT_BYTES * 2..SCOPED_BYTES]);

        let embedded_tenant = TenantId::from_bytes(tenant);
        let embedded_environment = EnvironmentId::from_bytes(environment);
        if embedded_tenant != scope.tenant() || embedded_environment != scope.environment() {
            return Err(NotInScope);
        }
        Ok(Self {
            tenant: embedded_tenant,
            environment: embedded_environment,
            unique,
            _kind: PhantomData,
        })
    }

    /// Parse a scoped identifier WITHOUT enforcing a caller scope, recovering the
    /// `(tenant, environment)` it embeds.
    ///
    /// This is deliberately NOT the request-handler entry point for resolving a
    /// scoped resource: it performs no scope check, so it must NEVER decide
    /// whether untrusted input names an in-scope resource (that path is
    /// [`ScopedId::parse_in_scope`], the anti-oracle boundary). Its one
    /// legitimate use is a self-authenticating credential token (a management API
    /// key, issue #11): the token declares its own scope in the clear, and the
    /// caller then proves possession of the token's SECRET within that scope, so
    /// recovering the declared scope leaks nothing the caller did not present.
    ///
    /// # Errors
    ///
    /// [`IdParseError`] if the prefix is wrong, the payload is not canonical
    /// URL-safe base64, or the decoded length is not three components.
    pub fn parse_declared_scope(raw: &str) -> Result<Self, IdParseError> {
        let payload = decode_component::<SCOPED_BYTES>(raw, K::PREFIX)?;
        let mut tenant = [0_u8; COMPONENT_BYTES];
        let mut environment = [0_u8; COMPONENT_BYTES];
        let mut unique = [0_u8; COMPONENT_BYTES];
        tenant.copy_from_slice(&payload[0..COMPONENT_BYTES]);
        environment.copy_from_slice(&payload[COMPONENT_BYTES..COMPONENT_BYTES * 2]);
        unique.copy_from_slice(&payload[COMPONENT_BYTES * 2..SCOPED_BYTES]);
        Ok(Self {
            tenant: TenantId::from_bytes(tenant),
            environment: EnvironmentId::from_bytes(environment),
            unique,
            _kind: PhantomData,
        })
    }

    /// The wire byte payload (tenant then environment then unique), for binding
    /// the identifier as a query parameter.
    fn payload(&self) -> [u8; SCOPED_BYTES] {
        let mut out = [0_u8; SCOPED_BYTES];
        out[0..COMPONENT_BYTES].copy_from_slice(&self.tenant.bytes());
        out[COMPONENT_BYTES..COMPONENT_BYTES * 2].copy_from_slice(&self.environment.bytes());
        out[COMPONENT_BYTES * 2..SCOPED_BYTES].copy_from_slice(&self.unique);
        out
    }
}

impl<K: ScopedKind> fmt::Display for ScopedId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}_{}",
            K::PREFIX,
            URL_SAFE_NO_PAD.encode(self.payload())
        )
    }
}

impl<K: ScopedKind> fmt::Debug for ScopedId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// A resource identifier that can be named as the target of an audit row.
///
/// An audit row records the typed-prefix kind and the wire form of the resource
/// a mutation acted on. Both single-level identifiers ([`LevelId`], e.g. the
/// [`TenantId`] targeted by `tenant.create`) and tenant-scoped identifiers
/// ([`ScopedId`], e.g. the [`ClientId`] targeted by `client.create`) can be audit
/// targets, so the audited-write primitive is generic over this trait rather than
/// over one identifier shape.
pub trait AuditTarget {
    /// The typed-prefix kind recorded in `audit_log.target_kind` (e.g. `ten`).
    fn audit_target_kind(&self) -> &'static str;

    /// The identifier's wire form recorded in `audit_log.target_id`.
    fn audit_target_id(&self) -> String;
}

impl<K: ScopedKind> AuditTarget for ScopedId<K> {
    fn audit_target_kind(&self) -> &'static str {
        K::PREFIX
    }

    fn audit_target_id(&self) -> String {
        self.to_string()
    }
}

impl<K: LevelKind> AuditTarget for LevelId<K> {
    fn audit_target_kind(&self) -> &'static str {
        K::PREFIX
    }

    fn audit_target_id(&self) -> String {
        self.to_string()
    }
}

/// Decode a typed-prefixed identifier into exactly `N` payload bytes.
///
/// Requires the exact `prefix`, canonical URL-safe base64 (non-canonical
/// trailing bits are rejected), and exactly `N` decoded bytes.
fn decode_component<const N: usize>(raw: &str, prefix: &str) -> Result<[u8; N], IdParseError> {
    let body = raw
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .ok_or(IdParseError::Prefix)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|_| IdParseError::Encoding)?;
    let bytes: [u8; N] = decoded.try_into().map_err(|_| IdParseError::Length)?;
    Ok(bytes)
}

/// Why a level identifier failed to parse. Scoped-resource parsing never
/// surfaces this variant to callers (it collapses to [`NotInScope`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdParseError {
    /// The typed prefix was absent or wrong.
    Prefix,
    /// The payload was not canonical URL-safe base64.
    Encoding,
    /// The decoded payload had the wrong length.
    Length,
}

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdParseError::Prefix => f.write_str("identifier has the wrong typed prefix"),
            IdParseError::Encoding => {
                f.write_str("identifier payload is not canonical URL-safe base64")
            }
            IdParseError::Length => f.write_str("identifier payload has the wrong length"),
        }
    }
}

impl std::error::Error for IdParseError {}

/// The uniform failure of [`ScopedId::parse_in_scope`]: the identifier is
/// malformed, of the wrong kind, or belongs to another tenant or environment.
///
/// Deliberately detail-free. A handler maps it to the same not-found response
/// it returns for an absent resource, so there is no existence oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotInScope;

impl fmt::Display for NotInScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("resource not found")
    }
}

impl std::error::Error for NotInScope {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::SystemTime;

    fn test_env() -> Env {
        // A real (non-deterministic) entropy source for uniqueness/entropy
        // properties; the manual clock is unused here.
        Env::system()
    }

    #[test]
    fn level_id_round_trips_through_parse_display() {
        let env = test_env();
        let id = TenantId::generate(&env);
        let text = id.to_string();
        assert!(text.starts_with("ten_"), "{text}");
        let parsed = TenantId::parse(&text).expect("round-trips");
        assert_eq!(id, parsed);
    }

    #[test]
    fn scoped_id_round_trips_and_embeds_scope() {
        let env = test_env();
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        let id = ClientId::generate(&env, &scope);
        let text = id.to_string();
        assert!(text.starts_with("cli_"), "{text}");
        assert_eq!(id.scope(), scope, "identifier embeds its scope");
        let parsed = ClientId::parse_in_scope(&text, &scope).expect("in scope");
        assert_eq!(id, parsed);
    }

    #[test]
    fn scoped_id_cross_tenant_is_uniform_not_found() {
        let env = test_env();
        let tenant_a = TenantId::generate(&env);
        let tenant_b = TenantId::generate(&env);
        let environment = EnvironmentId::generate(&env);
        let scope_a = Scope::new(tenant_a, environment);
        let scope_b = Scope::new(tenant_b, environment);

        let id_in_b = ClientId::generate(&env, &scope_b);
        let text = id_in_b.to_string();

        // Presented under tenant A's scope: uniform NotInScope, never a distinct
        // "exists but forbidden" signal.
        let cross = ClientId::parse_in_scope(&text, &scope_a);
        assert_eq!(cross, Err(NotInScope));

        // A genuinely malformed identifier fails identically: no format oracle.
        let malformed = ClientId::parse_in_scope("cli_not-base64-!!", &scope_a);
        assert_eq!(malformed, Err(NotInScope));
        let wrong_prefix =
            ClientId::parse_in_scope(&id_in_b.to_string().replacen("cli", "org", 1), &scope_b);
        assert_eq!(wrong_prefix, Err(NotInScope));
    }

    #[test]
    fn scoped_id_cross_environment_is_uniform_not_found() {
        let env = test_env();
        let tenant = TenantId::generate(&env);
        let env_a = EnvironmentId::generate(&env);
        let env_b = EnvironmentId::generate(&env);
        let scope_a = Scope::new(tenant, env_a);
        let scope_b = Scope::new(tenant, env_b);

        let id_in_b = ClientId::generate(&env, &scope_b);
        let cross = ClientId::parse_in_scope(&id_in_b.to_string(), &scope_a);
        assert_eq!(
            cross,
            Err(NotInScope),
            "same tenant, wrong environment still denied"
        );
    }

    #[test]
    fn wrong_prefix_and_bad_length_are_rejected() {
        let env = test_env();
        let id = TenantId::generate(&env);
        let text = id.to_string();
        // Environment parser rejects a tenant-prefixed value.
        assert_eq!(EnvironmentId::parse(&text), Err(IdParseError::Prefix));
        // Truncated payload is the wrong length.
        assert_eq!(
            TenantId::parse(&text[..text.len() - 2]),
            Err(IdParseError::Length)
        );
    }

    #[test]
    fn property_generated_ids_are_unique_and_high_entropy() {
        let env = test_env();
        // Uniqueness: a large batch of freshly minted identifiers never
        // collides (non-recyclable, non-guessable payloads).
        let mut seen = HashSet::new();
        for _ in 0..100_000 {
            let id = TenantId::generate(&env);
            assert!(seen.insert(id.to_string()), "identifier collision");
        }
        // Entropy floor: no byte position is constant across the batch, which a
        // truncated or low-entropy source would violate.
        let mut or_acc = [0_u8; COMPONENT_BYTES];
        let mut and_acc = [0xFF_u8; COMPONENT_BYTES];
        for _ in 0..1_000 {
            let bytes = TenantId::generate(&env).bytes();
            for i in 0..COMPONENT_BYTES {
                or_acc[i] |= bytes[i];
                and_acc[i] &= bytes[i];
            }
        }
        assert_eq!(
            or_acc, [0xFF_u8; COMPONENT_BYTES],
            "some bit never set to 1"
        );
        assert_eq!(
            and_acc, [0x00_u8; COMPONENT_BYTES],
            "some bit never set to 0"
        );
    }

    #[test]
    fn deterministic_env_reproduces_id_stream() {
        // The entropy seam makes minting reproducible under a fixed seed, which
        // is what lets protocol tests assert identifiers byte for byte.
        let (env_a, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 99);
        let (env_b, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 99);
        assert_eq!(
            TenantId::generate(&env_a).to_string(),
            TenantId::generate(&env_b).to_string()
        );
    }
}
