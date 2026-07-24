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

    /// Whether the [`fmt::Debug`] of a [`ScopedId`] of this kind must REDACT the
    /// payload (rendering `prefix_<redacted>` instead of the wire value).
    ///
    /// Most identifiers are opaque, non-secret handles, so their debug output is
    /// the legible wire form. A few identifiers double as bearer secrets: an
    /// authorization code IS the credential the token endpoint redeems, and an
    /// issued token's `jti` is the exact `jti` on the wire. Rendering those in a
    /// `Debug` (a struct field, a `tracing` field, a panic message) would put a
    /// live secret in the logs, so those kinds set this to `true`.
    const REDACT_DEBUG: bool = false;
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

/// Marker for an organization membership (`omb_`), the tenant-scoped join row
/// binding a user into an organization (issue #94). Scoped like every other
/// resource so a membership id minted in one scope parses as a uniform not-found
/// under another. Not a bearer secret (it is the membership's stable handle, like
/// an organization id), so its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrgMembershipKind;
impl ScopedKind for OrgMembershipKind {
    const PREFIX: &'static str = "omb";
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

/// Marker for an OIDC authorization code (`ac_`), the single-use code the
/// authorization-code grant issues and the token endpoint redeems (issue #12).
/// A tenant-scoped resource: the code embeds its `(tenant, environment)` in the
/// clear, so the token endpoint recovers the scope from the presented code
/// exactly as the management API recovers a key's scope, and a code minted in
/// one scope parses as a uniform not-found under another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorizationCodeKind;
impl ScopedKind for AuthorizationCodeKind {
    const PREFIX: &'static str = "ac";
    // The code IS the single-use bearer credential; never render it in a debug
    // or log line.
    const REDACT_DEBUG: bool = true;
}

/// Marker for an OIDC grant (`grt_`), the record linking a code, its session and
/// consent, and every token issued from it (issue #12). The revocation spine:
/// revoking the grant chain invalidates every token issued from it. Tenant
/// scoped like every other resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantKind;
impl ScopedKind for GrantKind {
    const PREFIX: &'static str = "grt";
}

/// Marker for an issued token (`tok_`), the `jti` of an access or ID token
/// recorded against its grant (issue #12). Recording issued tokens is what makes
/// grant-chain revocation observable: a token is active only while its issued
/// row exists and its grant is not revoked. Tenant scoped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IssuedTokenKind;
impl ScopedKind for IssuedTokenKind {
    const PREFIX: &'static str = "tok";
    // The `jti` is the exact identifier on the minted token; keep it out of logs.
    const REDACT_DEBUG: bool = true;
}

/// Marker for a refresh-token FAMILY (`rff_`), the spine rooted at one original
/// authorization grant that every rotated refresh token in the chain belongs to
/// (issue #21). Revoking the family invalidates every generation of refresh token
/// in it (RFC 9700 2.2.2 reuse detection). Tenant scoped like every other
/// resource; not a bearer secret (it is the family's audit/correlation handle,
/// like a grant id), so its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefreshFamilyKind;
impl ScopedKind for RefreshFamilyKind {
    const PREFIX: &'static str = "rff";
}

/// Marker for a single refresh token's logical id (`rft_`), the routing handle
/// embedded in the `ira_rt_<jti>~<secret>` wire token (issue #21), exactly as an
/// opaque access token embeds its `tok_` id. It declares the token's
/// `(tenant, environment)` in the clear so a GLOBAL `/token` endpoint recovers the
/// scope and runs the RLS-scoped digest resolve; the secret suffix and the
/// whole-token digest are what bind it. Because it is one segment of a live bearer
/// credential, its debug form REDACTS the payload (like an issued token's `jti`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefreshTokenKind;
impl ScopedKind for RefreshTokenKind {
    const PREFIX: &'static str = "rft";
    // The `rft_` id is embedded in the presented refresh token; keep it out of logs.
    const REDACT_DEBUG: bool = true;
}

/// Marker for a device-authorization grant's device code (`dc_`), the routing
/// handle embedded in the `ira_dc_<jti>~<secret>` wire device code (issue #24, RFC
/// 8628), exactly as an opaque access token embeds its `tok_` id. It declares the
/// device code's `(tenant, environment)` in the clear so the GLOBAL `/token`
/// endpoint recovers the scope from a presented device code and runs the RLS-scoped
/// digest resolve; the 256-bit secret suffix and the whole-token digest are what
/// bind it. Because it is one segment of a live bearer credential, its debug form
/// REDACTS the payload (like an issued token's `jti` and a refresh token's handle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceCodeKind;
impl ScopedKind for DeviceCodeKind {
    const PREFIX: &'static str = "dc";
    // The `dc_` id is embedded in the presented device code; keep it out of logs.
    const REDACT_DEBUG: bool = true;
}

/// Marker for a bootstrap end user (`usr_`), the account the login and
/// registration surfaces authenticate (issue #20). A tenant-scoped resource: the
/// user id embeds its `(tenant, environment)`, and its string is the stable
/// pseudonymous subject the tokens are minted for in the bootstrap slice. Not a
/// bearer secret (the password is the secret, stored only as a one-way hash), so
/// its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserKind;
impl ScopedKind for UserKind {
    const PREFIX: &'static str = "usr";
}

/// Marker for a bootstrap session (`ses_`), the minimal server-side session the
/// opaque `__Host-` cookie names (issue #20). A tenant-scoped resource: the
/// session id embeds its `(tenant, environment)` in the clear, so the
/// authorization endpoint recovers the scope from the presented cookie without a
/// database lookup, and a session established in one scope parses as a uniform
/// not-found under another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKind;
impl ScopedKind for SessionKind {
    const PREFIX: &'static str = "ses";
    // The session id IS the opaque bearer cookie value; never render it in a
    // debug or log line.
    const REDACT_DEBUG: bool = true;
}

/// Marker for a per-client session (`cse_`), the tier-two row of the two-tier
/// session model that carries the per-(client, session) `sid` claim (issue #32). A
/// tenant-scoped resource: the identifier embeds its `(tenant, environment)`, so a
/// per-client session minted in one scope parses as a uniform not-found under
/// another. It is an INTERNAL tracking row (never a bearer credential and never
/// presented by a caller); the `sid` it carries is a separate opaque value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientSessionKind;
impl ScopedKind for ClientSessionKind {
    const PREFIX: &'static str = "cse";
}

/// Marker for an enrolled account credential (`crd_`), one row in a user's
/// self-service credential registry (a passkey, a TOTP authenticator, or a
/// recovery-code set; issue #61). A tenant-scoped resource: the identifier embeds
/// its `(tenant, environment)`, so a credential id minted in one scope parses as a
/// uniform not-found under another, and a credential is only ever reachable by the
/// subject it is bound to. It is an INTERNAL registry row, never a bearer
/// credential (the factor material and ceremonies are the M7 factor issues).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialKind;
impl ScopedKind for CredentialKind {
    const PREFIX: &'static str = "crd";
}

/// Marker for a remembered device (`tdv_`), one row in a user's trusted-device
/// registry (issue #71): the remember-device second-factor state a subsequent
/// login skips the second factor against. The id is the value the __Host- device
/// cookie names; it embeds its `(tenant, environment)`, so a device minted in one
/// scope parses as a uniform not-found under another, and a device is only ever
/// reachable by the subject it is bound to. The id is NOT a bearer secret on its
/// own: the cookie additionally carries a high-entropy secret whose digest is the
/// server-side state, so a stolen id alone cannot skip anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrustedDeviceKind;
impl ScopedKind for TrustedDeviceKind {
    const PREFIX: &'static str = "tdv";
}

/// Marker for a recovery-flow id (`rcv_`), one row of the account-recovery state
/// machine (issue #81): the first-class recovery request the delay/notification/
/// downgrade-invariant pillars govern. The id embeds its (tenant, environment) so a
/// flow minted in one scope parses as a uniform not-found under another, and a flow
/// is only ever reachable by the subject it targets. The id is NOT a bearer secret:
/// the notification link additionally carries a high-entropy cancellation token whose
/// digest is the server-side state, so a stolen id alone cancels nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryFlowKind;
impl ScopedKind for RecoveryFlowKind {
    const PREFIX: &'static str = "rcv";
}

/// Marker for a headless flow id (`flw_`), one row of the flow state machine
/// (issue #84): the persisted position of a login, registration, MFA, or recovery
/// journey the flow API serves as one JSON flow object. A tenant-scoped resource:
/// the id embeds its `(tenant, environment)`, so a flow minted in one scope parses
/// as a uniform not-found under another, and a flow is only ever loadable within its
/// own scope. The id is NOT a bearer secret: the API transport additionally carries a
/// high-entropy, single-use per step `submit_token` (the machine transport CSRF),
/// so a stolen flow id alone advances nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKind;
impl ScopedKind for FlowKind {
    const PREFIX: &'static str = "flw";
}

/// Marker for a registered WebAuthn passkey credential (`pky_`), one row in the
/// per-user passkey registry (issue #65): the COSE public key, sign counter,
/// AAGUID, transports, BE/BS flags, and the sealed nickname of one authenticator.
/// A tenant-scoped resource: the id embeds its `(tenant, environment)`, so a
/// credential minted in one scope parses as a uniform not-found under another,
/// and a credential is only ever reachable by the subject it is bound to. The
/// stored COSE key is PUBLIC key material, never a bearer secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebauthnCredentialKind;
impl ScopedKind for WebauthnCredentialKind {
    const PREFIX: &'static str = "pky";
}

/// Marker for a single-use WebAuthn ceremony challenge (`wch_`), one row in the
/// short-lived challenge store (issue #65): the random challenge a registration
/// or authentication ceremony was issued, consumed exactly once. A tenant-scoped
/// resource: the id embeds its `(tenant, environment)`, so a handle minted in one
/// scope parses as a uniform not-found under another. The challenge it carries is
/// a public nonce (it is sent to the client in the ceremony options), not a
/// secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebauthnChallengeKind;
impl ScopedKind for WebauthnChallengeKind {
    const PREFIX: &'static str = "wch";
}

/// Marker for an enrolled TOTP authenticator (`tot_`), one row in the per-user
/// TOTP registry (issue #69): the RFC 6238 shared secret SEED sealed under the
/// scope DEK, the parameters, the enrollment status, the single-use last-consumed
/// time-step, and the resync offset. A tenant-scoped resource: the id embeds its
/// `(tenant, environment)`, so a credential minted in one scope parses as a uniform
/// not-found under another, and it is only ever reachable by the subject it is
/// bound to. The seed it points at is SEALED secret material, never a bearer value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TotpCredentialKind;
impl ScopedKind for TotpCredentialKind {
    const PREFIX: &'static str = "tot";
}

/// Marker for a one-time recovery code (`rvc_`), one row in the per-user
/// recovery-code set (issue #69): the Argon2id hash of a single code, single-use.
/// A tenant-scoped resource: the id embeds its `(tenant, environment)`, so a row
/// minted in one scope parses as a uniform not-found under another, and it is only
/// ever reachable by the subject it is bound to. The value it points at is a
/// one-way hash, never a plaintext code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryCodeKind;
impl ScopedKind for RecoveryCodeKind {
    const PREFIX: &'static str = "rvc";
}

/// Marker for a per-scope step-up policy (`sup_`), one row in a tenant's step-up
/// policy set (issue #72): the (acr floor, max auth age) requirement that governs an
/// OAuth scope token. A tenant-scoped resource: the id embeds its (tenant,
/// environment), so a policy minted in one scope parses as a uniform not-found under
/// another. It is an INTERNAL configuration row (never a bearer credential); the
/// values it points at are a public acr string and an age, so its debug form stays
/// legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeStepUpPolicyKind;
impl ScopedKind for ScopeStepUpPolicyKind {
    const PREFIX: &'static str = "sup";
}

/// Marker for an admin sudo elevation (`elv_`), one row in the append-only
/// privilege-elevation ledger (issue #73): a recorded re-authentication event that
/// opens a freshness window for admin mutations. A tenant-scoped resource: the id
/// embeds its (tenant, environment), so an elevation minted in one scope parses as a
/// uniform not-found under another. It is an INTERNAL audit/ledger row (never a bearer
/// credential); the values it points at are a public acr string and two timestamps, so
/// its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdminSudoElevationKind;
impl ScopedKind for AdminSudoElevationKind {
    const PREFIX: &'static str = "elv";
}

/// Marker for a credential-class policy (`ccp_`), one row in a tenant's
/// minimum-credential-class ladder (issue #66): the minimum class (`any` < `mfa` <
/// `passkey` < `attested_passkey`) required of a login for a policy subject (the
/// tenant, a group, or an org). A tenant-scoped resource: the id embeds its (tenant,
/// environment), so a policy minted in one scope parses as a uniform not-found under
/// another. It is an INTERNAL configuration row (never a bearer credential); the
/// values it points at are a public class string and a subject discriminator, so its
/// debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialClassPolicyKind;
impl ScopedKind for CredentialClassPolicyKind {
    const PREFIX: &'static str = "ccp";
}

/// Marker for a per-scope attestation configuration (`atc_`), one row per (tenant,
/// environment) (issue #66): the attestation conveyance mode ('none' or 'direct')
/// the passkey registration path requests. A tenant-scoped resource: the id embeds
/// its (tenant, environment). It is an INTERNAL configuration row (never a bearer
/// credential); the value it points at is a public mode string, so its debug form
/// stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttestationConfigKind;
impl ScopedKind for AttestationConfigKind {
    const PREFIX: &'static str = "atc";
}

/// Marker for a per-scope verified MDS3 BLOB cache (`mbc_`), the SINGLETON row per
/// (tenant, environment) (issue #66, PR B): the extracted, trusted FIDO Metadata
/// Service (MDS3) authenticator entries the 'direct' attestation path evaluates
/// against, plus the raw-BLOB digest and the `no` sequence number a refresh
/// supersedes on. A tenant-scoped resource: the id embeds its (tenant, environment).
/// It is an INTERNAL cache row (never a bearer credential); the payload it points at
/// is PUBLIC authenticator metadata, so its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mds3BlobCacheKind;
impl ScopedKind for Mds3BlobCacheKind {
    const PREFIX: &'static str = "mbc";
}

/// Marker for a per-scope AAGUID allow/deny rule (`aag_`), one row pinning one
/// authenticator model (its 16-byte AAGUID) to a disposition ('allow' or 'deny')
/// (issue #66, PR B): the 'direct' attestation path admits or refuses a specific
/// model against these rules. A tenant-scoped resource: the id embeds its (tenant,
/// environment). It is an INTERNAL configuration row (never a bearer credential); the
/// values it points at are a public AAGUID and a disposition, so its debug form stays
/// legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AaguidRuleKind;
impl ScopedKind for AaguidRuleKind {
    const PREFIX: &'static str = "aag";
}

/// Marker for a flexible login identifier (`uid_`), one row in a user's typed
/// login-identifier set (issue #54): a verified-or-not email, username, or phone a
/// user can log in with. A tenant-scoped resource: the identifier row id embeds its
/// `(tenant, environment)`, so a row minted in one scope parses as a uniform
/// not-found under another. It is an INTERNAL registry row (never a bearer
/// credential); the sensitive value it points at is the sealed / blind-indexed
/// canonical identifier, not this id, so its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserIdentifierKind;
impl ScopedKind for UserIdentifierKind {
    const PREFIX: &'static str = "uid";
}

/// Marker for a user invitation (`inv_`), one pending invitation row (issue #60).
/// A tenant-scoped resource: the identifier embeds its `(tenant, environment)`, so
/// an invitation id minted in one scope parses as a uniform not-found under
/// another. The id doubles as the routing handle embedded in the invite token wire
/// form (`ira_inv_<inv-id>~<secret>`); because that token is a live bearer
/// credential, its debug form REDACTS the payload (like an issued token's `jti` and
/// a refresh token's handle), so an invite id is never rendered into a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvitationKind;
impl ScopedKind for InvitationKind {
    const PREFIX: &'static str = "inv";
    // The `inv_` id is embedded in the presented invite token; keep it out of logs.
    const REDACT_DEBUG: bool = true;
}

/// Marker for a session-ended outbox event (`sev_`), the durable row the session
/// domain enqueues on EVERY terminal session end (issue #35). The transactional-outbox
/// substrate the back-channel logout worker (#34) and the external webhooks (M11)
/// drain off one seam. Tenant scoped like every other resource, so a scope can never
/// drain another tenant's session-ended events; the id doubles as the IDEMPOTENCY KEY a
/// consumer dedups redelivery on. An INTERNAL tracking row, never a bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionEventKind;
impl ScopedKind for SessionEventKind {
    const PREFIX: &'static str = "sev";
}

/// Marker for a per-RP back-channel-logout delivery (`bld_`), one row per participating
/// relying party a drained session-ended event is exploded into (issue #34). It is the
/// at-least-once, per-recipient delivery queue with its own attempts / backoff /
/// dead-letter state, distinct from the shared session-ended outbox (`sev_`). Tenant
/// scoped like every other resource, so a scope can never drain another tenant's
/// back-channel deliveries. An INTERNAL tracking row, never a bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackChannelDeliveryKind;
impl ScopedKind for BackChannelDeliveryKind {
    const PREFIX: &'static str = "bld";
}

/// Marker for a recorded consent decision (`con_`), the row that means a subject
/// authorized a client (issue #20). Tenant scoped like every other resource; the
/// grant's `consent_ref` seam references it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConsentKind;
impl ScopedKind for ConsentKind {
    const PREFIX: &'static str = "con";
}

/// Marker for a federation connector (`cnr_`), one declarative inbound-federation
/// upstream definition per environment (issue #75): the OIDC-shaped connector the
/// generic upstream reads (issuer or explicit endpoints, scopes, client id, PKCE
/// mode, claim mapping, quirks, and the capability matrix). A tenant-scoped
/// resource: the identifier embeds its `(tenant, environment)`, so a connector
/// minted in one scope parses as a uniform not-found under another, and a
/// definition is per-environment with the standard tenant-isolation guarantees.
/// The prefix is `cnr` (NOT the `con` of [`ConsentKind`], which is already the
/// consent-decision prefix: two `ScopedKind`s must not share a wire prefix, or a
/// `ScopedId` of one kind would parse as the other). The upstream client SECRET is
/// never plaintext and never appears in the row's `definition_json` (that document
/// is secret-free); it is sealed INLINE on the connector row itself, in the
/// `client_secret_sealed` bytea under `client_secret_dek_version`, envelope-encrypted
/// under the scope DEK with the seal AAD bound to this IMMUTABLE connector id plus
/// the tenant, environment, and DEK version. Every read projection excludes the
/// sealed column, so a read is secret-free by construction, and because the AAD keys
/// on the id (not the mutable slug), a resealed secret stays decryptable across any
/// definition edit. The id is a public handle, so its debug form stays legible. A
/// connector definition is PROMOTABLE (issue #41): the definition travels in a
/// config snapshot, but the secret's VALUE never does (only a named reference).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectorKind;
impl ScopedKind for ConnectorKind {
    const PREFIX: &'static str = "cnr";
}

/// Marker for a per-environment brand (`brd_`), one named branding definition (design
/// tokens, dark-mode variants, the product wordmark, and the sanitized rich-text slots)
/// per environment (issue #86). A tenant-scoped resource: the id embeds its (tenant,
/// environment), so a brand minted in one scope parses as a uniform not-found under
/// another. A brand is PROMOTABLE (issue #41): the whole definition is non-secret
/// per-environment config that travels in a config snapshot; per-organization branding is
/// deferred to M10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BrandKind;
impl ScopedKind for BrandKind {
    const PREFIX: &'static str = "brd";
}

/// Marker for a per-environment locale bundle (`lcb_`), one installed localization (a BCP47
/// language tag and its map of numeric message id to plain text render) per environment
/// (issue #86, PR 2). A tenant-scoped resource: the id embeds its (tenant, environment), so a
/// bundle minted in one scope parses as a uniform not-found under another. A locale bundle is
/// PROMOTABLE (issue #41): the whole map is non-secret per-environment config that travels in
/// a config snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocaleBundleKind;
impl ScopedKind for LocaleBundleKind {
    const PREFIX: &'static str = "lcb";
}

/// Marker for a per-environment, per-client signup form (`sgf_`), one declarative
/// signup-form-as-data definition per (tenant, environment, client) (issue #87). A
/// tenant-scoped resource: the id embeds its (tenant, environment), so a form minted in
/// one scope parses as a uniform not-found under another. A signup form is PROMOTABLE
/// (issue #41): its field list references identity trait paths as RFC 6901 pointers plus
/// a narrowing-only rule set, all non-secret per-environment config a config snapshot
/// carries and a promotion replays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignupFormKind;
impl ScopedKind for SignupFormKind {
    const PREFIX: &'static str = "sgf";
}

/// Marker for a custom-journey version (`flv_`), one immutable version of a journey artifact in a
/// (tenant, environment) registry (issue #92, PR 5). A tenant-scoped resource: the id embeds its
/// (tenant, environment), so a version id minted in one scope parses as a uniform not-found under
/// another. A custom flow stamps the resolved `flv_` id on its row so it re-resolves the SAME
/// compiled table across submissions (the version it started under cannot change mid-flow). A flow
/// version is PROMOTABLE (issue #41): its whole non-secret artifact travels in a config snapshot.
/// The prefix is `flv` (distinct from the `flw` headless flow id and the `fvp` pin). Not a bearer
/// secret, so its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowVersionKind;
impl ScopedKind for FlowVersionKind {
    const PREFIX: &'static str = "flv";
}

/// Marker for a custom-journey active-version pin (`fvp_`), one row per (tenant, environment,
/// `journey_id`) naming the version a fresh custom flow of that journey is created against (issue
/// #92, PR 5). A tenant-scoped resource: the id embeds its (tenant, environment). The prefix is
/// `fvp` (distinct from the `flv` version it points at). Not a bearer secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowVersionPinKind;
impl ScopedKind for FlowVersionPinKind {
    const PREFIX: &'static str = "fvp";
}

/// Marker for a per environment, per client admin consent pre authorization (`cag_`), one row per
/// (tenant, environment, client) (issue #88, PR 4): the space separated scope set an admin
/// pre authorized for a THIRD PARTY client, the escape from the third party admin consent gate. A
/// tenant scoped resource: the id embeds its (tenant, environment), so a pre authorization minted
/// in one scope parses as a uniform not found under another. It is RUNTIME per environment state
/// (NOT promotable, issue #41): it is never carried in a config snapshot, so a promoted third
/// party client stays locked in the target environment until a target environment admin
/// pre authorizes it. The prefix is `cag` (distinct from the `con` consent decision, the `cnr`
/// connector, the `cli` client, and the `ccp` credential class policy). Not a bearer secret, so
/// its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientAdminGrantKind;
impl ScopedKind for ClientAdminGrantKind {
    const PREFIX: &'static str = "cag";
}

/// Marker for a federation outbound-login correlation-state row (`fls_`), the
/// short-lived single-use row that correlates an upstream authorize leg to its
/// callback (issue #75, PR B). A tenant-scoped resource: the id embeds its (tenant,
/// environment), so a row minted in one scope parses as a uniform not-found under
/// another, and the seal AAD for its PKCE verifier binds to this immutable id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FederationLoginStateKind;
impl ScopedKind for FederationLoginStateKind {
    const PREFIX: &'static str = "fls";
}

/// Marker for an organization to connector binding (`ocn_`), the row that ties an
/// organization to the declarative federation connector describing its upstream and
/// carries the broker overlay policy (issue #77). A tenant-scoped resource: the id
/// embeds its (tenant, environment), so a binding minted in one scope parses as a
/// uniform not-found under another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrgConnectionKind;
impl ScopedKind for OrgConnectionKind {
    const PREFIX: &'static str = "ocn";
}

/// Marker for a routing rule (`rrl_`), the row that maps one selector (an email
/// domain, an app client, or a single user) to an org connection so an inbound login
/// is routed to the right organization's upstream (issue #77). A tenant-scoped
/// resource: the id embeds its (tenant, environment), so a rule minted in one scope
/// parses as a uniform not-found under another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingRuleKind;
impl ScopedKind for RoutingRuleKind {
    const PREFIX: &'static str = "rrl";
}

/// Marker for an upstream token vault row (`utk_`), one per (session, connector)
/// binding that holds the SEALED upstream access and refresh tokens captured after a
/// brokered login (issue #77, PR 3). A tenant-scoped resource: the id embeds its
/// (tenant, environment), so a row minted in one scope parses as a uniform not-found
/// under another, and the seal AAD for its two token ciphertexts binds to the session
/// and the token kind (so an access ciphertext can never be opened as a refresh nor
/// lifted to another session's row). The vault is Runtime (never exported).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpstreamTokenKind;
impl ScopedKind for UpstreamTokenKind {
    const PREFIX: &'static str = "utk";
}

/// Marker for an upstream-token retrieval grant (`utg_`), the authorization config for
/// WHICH client may retrieve a session's captured upstream tokens (issue #77, PR 3).
/// One per (client, org connection) per environment. A tenant-scoped resource holding
/// no secret; Promotable config a snapshot carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpstreamTokenGrantKind;
impl ScopedKind for UpstreamTokenGrantKind {
    const PREFIX: &'static str = "utg";
}

/// Marker for an account link (`alk_`), one row per (local user) to (federated
/// identity) binding of the guarded account linking subsystem (issue #78). A
/// tenant-scoped resource: the id embeds its (tenant, environment), so a link minted
/// in one scope parses as a uniform not found under another. Runtime end user identity
/// state (never exported); its raw federated composite lives only as a keyed blind
/// index and a sealed ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountLinkKind;
impl ScopedKind for AccountLinkKind {
    const PREFIX: &'static str = "alk";
}

/// Marker for a FedCM assertion nonce (`fdn_`), one row of the single-use replay
/// store the IdP-side FedCM id-assertion endpoint consumes (issue #83). A
/// tenant-scoped resource: the id embeds its (tenant, environment), so a nonce row
/// minted in one scope parses as a uniform not found under another. Runtime
/// single-use anti-replay state (never exported); the RP-supplied nonce it records is
/// an opaque anti-replay token, not a bearer credential, so its debug form is not
/// redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FedcmNonceKind;
impl ScopedKind for FedcmNonceKind {
    const PREFIX: &'static str = "fdn";
}

/// Marker for a signing key (`sik_`), an environment's per-issuer signing key
/// (issue #19). A tenant-scoped resource: the identifier embeds its
/// `(tenant, environment)`, so a key row can never be read across a tenant or
/// environment boundary, and the identifier itself doubles as the JOSE `kid`. A
/// `kid` minted from a non-recyclable 128-bit random component is therefore
/// unique across an issuer's whole key history by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningKeyKind;
impl ScopedKind for SigningKeyKind {
    const PREFIX: &'static str = "sik";
}

/// Marker for a resource server (`rsv_`), a registered protected API that OAuth
/// access tokens are minted FOR (issue #29). A tenant-scoped resource: the
/// identifier embeds its `(tenant, environment)`, so a resource-server row can
/// never be read across a tenant or environment boundary. The resource server's
/// `audience` (its resource identifier) is what selects the access-token format
/// the mint emits for it. Not a bearer secret, so its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceServerKind;
impl ScopedKind for ResourceServerKind {
    const PREFIX: &'static str = "rsv";
}

/// Marker for a per-tenant key-encryption key (`kek_`), the envelope-encryption
/// KEK that wraps that scope's data-encryption keys (issue #48). A tenant-scoped
/// resource: the identifier embeds its `(tenant, environment)`, so a KEK row can
/// never be read across a tenant or environment boundary. The KEK material NEVER
/// appears in the id (the id is a public handle); the wrapped key bytes live in
/// the row, sealed under the platform master key. Destroying every KEK version of
/// a scope crypto-shreds all of its envelope-protected data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KekKind;
impl ScopedKind for KekKind {
    const PREFIX: &'static str = "kek";
}

/// Marker for a per-tenant data-encryption key (`dek_`), the envelope-encryption
/// DEK that seals the actual PII and secret payloads (issue #48). A tenant-scoped
/// resource: the identifier embeds its `(tenant, environment)`. The DEK material
/// NEVER appears in the id; the wrapped key bytes live in the row, sealed under
/// the scope's active KEK. New writes use the active DEK version; older versions
/// stay readable until background re-encryption retires them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DekKind;
impl ScopedKind for DekKind {
    const PREFIX: &'static str = "dek";
}

/// Marker for an encrypted secret record (`sec_`), a stored secret value sealed
/// under a scope's DEK (issue #48): the transparent encrypted-column store the
/// envelope substrate protects (TOTP seeds in M7, connector credentials, and
/// environment-scoped secret values all land here from their first write). A
/// tenant-scoped resource: the identifier embeds its `(tenant, environment)`, and
/// the row holds only ciphertext, never a plaintext column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncryptedSecretKind;
impl ScopedKind for EncryptedSecretKind {
    const PREFIX: &'static str = "sec";
}

/// Marker for a per-environment custom domain (`cdom_`), a customer-owned
/// hostname an environment is served under with a built-in-ACME certificate
/// (issue #47). A tenant-scoped resource: the identifier embeds its
/// `(tenant, environment)`, so a domain row can never be read across a tenant or
/// environment boundary. The id is a public handle; the cert PRIVATE KEY never
/// lives on the domain row (it is sealed in `encrypted_secrets`, issue #48). A
/// custom domain is ENVIRONMENT-IDENTITY (issue #41), excluded from every
/// snapshot so a promotion never copies one environment's domain onto another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustomDomainKind;
impl ScopedKind for CustomDomainKind {
    const PREFIX: &'static str = "cdom";
}

/// Marker for an ACME challenge (`chal_`), one verification attempt proving a
/// tenant controls a custom domain before a certificate is issued (issue #47,
/// RFC 8555). A tenant-scoped resource: the identifier embeds its
/// `(tenant, environment)`. The challenge token it carries is a PUBLIC value the
/// tenant serves or publishes, never a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AcmeChallengeKind;
impl ScopedKind for AcmeChallengeKind {
    const PREFIX: &'static str = "chal";
}

/// Marker for an environment-scoped VARIABLE (`var_`), a non-secret named
/// configuration value (an endpoint, a feature toggle, a display string) an
/// environment carries (issue #45). A tenant-scoped resource: the identifier
/// embeds its `(tenant, environment)`, so a variable is never readable across a
/// tenant or environment boundary. A variable is PROMOTABLE (issue #41): its name
/// and value travel in a config snapshot. Its value is not sensitive, so the id
/// and value stay legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VariableKind;
impl ScopedKind for VariableKind {
    const PREFIX: &'static str = "var";
}

/// Marker for an environment-scoped SECRET (`esec_`), a sensitive named value
/// (a connector credential, a webhook signing key) an environment carries (issue
/// #45). A tenant-scoped resource: the identifier embeds its
/// `(tenant, environment)`. The secret is ENVIRONMENT-IDENTITY (issue #41): its
/// VALUE never travels between environments (only a named reference does, resolved
/// per target environment), and the value is sealed under the scope's envelope DEK
/// (issue #48), never a plaintext column. The id is a public handle (it carries no
/// key material), so its debug form stays legible; the sealed value is what is
/// protected, not this reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvironmentSecretKind;
impl ScopedKind for EnvironmentSecretKind {
    const PREFIX: &'static str = "esec";
}

/// Marker for a service-account principal (`sva_`), the first-class machine
/// identity every M2M-capable client maps to (issue #23). A tenant-scoped
/// resource: the identifier embeds its `(tenant, environment)`, so a service
/// account minted in one scope parses as a uniform not-found under another, and
/// two tenants can never share a principal. This is the STABLE `sub` a
/// client-credentials access token carries, distinct from the `cli_` client id and
/// consistent across every issuance. The prefix is `sva` (not the `svc` of the
/// audit-actor [`ServiceKind`], which is a single-level actor id, not a scoped
/// principal). Roles and permissions (RBAC, M10) will attach to this principal;
/// this issue only mints and reads it. Not a bearer secret, so its debug form stays
/// legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceAccountKind;
impl ScopedKind for ServiceAccountKind {
    const PREFIX: &'static str = "sva";
}

/// Marker for a pushed authorization request (`par_`), a request the PAR endpoint
/// (RFC 9126, issue #27) stored for later single-use reference from `/authorize`. A
/// tenant-scoped resource: the identifier embeds its `(tenant, environment)`, so the
/// authorization endpoint recovers the scope from a presented `request_uri`
/// reference exactly as it recovers a code's scope, and a reference minted in one
/// scope parses as a uniform not-found under another. The identifier is the
/// reference portion of the `urn:ietf:params:oauth:request_uri:<id>` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PushedRequestKind;
impl ScopedKind for PushedRequestKind {
    const PREFIX: &'static str = "par";
    // The reference is a single-use handle to a stored request; keep it out of logs
    // exactly as the authorization code and session id are.
    const REDACT_DEBUG: bool = true;
}

/// Marker for a DCR initial access token (`iat_`), the RFC 7591 section 1.2
/// registration authorization the abuse-controls work mints through the
/// management API (issue #31). A tenant-scoped resource: the identifier embeds its
/// `(tenant, environment)`, so a token minted in one scope parses as a uniform
/// not-found under another. The identifier is NOT the credential (the credential
/// is a separate high-entropy secret stored only as a SHA-256 hash); it is the
/// audit/reference handle, so its debug form stays legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InitialAccessTokenKind;
impl ScopedKind for InitialAccessTokenKind {
    const PREFIX: &'static str = "iat";
}

/// Marker for a DCR policy object (`pol_`), the named, reusable set of
/// registration-metadata primitives (force / restrict / reject / default) the
/// abuse-controls work attaches to an initial access token (issue #31). A
/// tenant-scoped resource: the identifier embeds its `(tenant, environment)`, so a
/// policy authored in one scope is never reachable from another. Not a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DcrPolicyKind;
impl ScopedKind for DcrPolicyKind {
    const PREFIX: &'static str = "pol";
}

/// Marker for a registered external assertion issuer (`xai_`), a trust anchor the
/// RFC 7521 / RFC 7523 JWT bearer assertion grant accepts assertions from (issue
/// #26). A tenant-scoped resource: the identifier embeds its
/// `(tenant, environment)`, so an issuer registered in one scope is never reachable
/// from another. The row's external `issuer` string is the lookup key; this id is
/// the row's primary key and the audit target of a registration. Not a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExternalIssuerKind;
impl ScopedKind for ExternalIssuerKind {
    const PREFIX: &'static str = "xai";
}

/// Marker for a subject-mapping rule (`asm_`), the explicit rule that maps an
/// external assertion's (issuer + `sub`) to an IronAuth principal for the JWT
/// bearer assertion grant (issue #26). A tenant-scoped resource: the identifier
/// embeds its `(tenant, environment)`, so a mapping authored in one scope is never
/// reachable from another. This id is the row's primary key and the audit target of
/// a mapping creation. Not a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssertionMappingKind;
impl ScopedKind for AssertionMappingKind {
    const PREFIX: &'static str = "asm";
}

/// Marker for a trait-schema version (`tsc_`), one immutable version in a
/// (tenant, environment) identity-traits schema registry (issue #53). The
/// identifier embeds its scope, so a schema version minted in one scope parses as
/// a uniform not-found under another. This id is the registry row's primary key and
/// the audit target of a schema-version create/activate. Not a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraitSchemaKind;
impl ScopedKind for TraitSchemaKind {
    const PREFIX: &'static str = "tsc";
}

/// Marker for a trait migration/dry-run job (`tmj_`), one queued job that
/// validates or migrates a scope's existing identities against a candidate schema
/// version (issue #53). Tenant scoped, so a job in one scope can never touch
/// another tenant's identities; the id is the job row's primary key and the audit
/// target of the job's create/run. An INTERNAL tracking row, never a bearer
/// credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraitMigrationJobKind;
impl ScopedKind for TraitMigrationJobKind {
    const PREFIX: &'static str = "tmj";
}

/// Marker for a wrapped migration RUN (`mgr_`), one long-running data migration
/// (a streaming bulk import, a schema migration job, or, by design, a tenant move)
/// wrapped in the invariant-checked state machine (issue #59). Tenant scoped, so a
/// run in one scope can never touch another tenant's records; the id is the run
/// row's primary key and the audit target of every state transition. An INTERNAL
/// tracking row, never a bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MigrationRunKind;
impl ScopedKind for MigrationRunKind {
    const PREFIX: &'static str = "mgr";
}

/// Marker for one per-record accounting row of a migration run (`mrr_`, issue #59):
/// one source record the run touched, its accounting bucket, consistency flag, and
/// backfill sentinel. Tenant scoped; the id is the record row's primary key. An
/// INTERNAL tracking row, never a bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MigrationRunRecordKind;
impl ScopedKind for MigrationRunRecordKind {
    const PREFIX: &'static str = "mrr";
}

/// Marker for a credential-abuse ban (`abn_`), one durable, DB-backed ban row over a
/// single regulated dimension (an attacker IP, an account, or a canonical identifier)
/// and a single authentication PATH (issue #64). Tenant scoped; the id is the ban row's
/// primary key and the CLI/admin handle. The per-path key is the account-DoS defense: a
/// `password` ban never governs the `passkey` or `recovery` path (Keycloak
/// CVE-2024-1722). An INTERNAL operational row, never a bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AbuseBanKind;
impl ScopedKind for AbuseBanKind {
    const PREFIX: &'static str = "abn";
}

/// Marker for an email-OTP code (`eot_`), one row in the per-user email-OTP set
/// (issue #68): the Argon2id hash of a single numeric code, single-active per
/// (subject, purpose), single-use. A tenant-scoped resource: the id embeds its
/// `(tenant, environment)`, so a row minted in one scope parses as a uniform
/// not-found under another, and it is only ever reachable by the subject it is bound
/// to. The value it points at is a one-way hash, never a plaintext code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EmailOtpCodeKind;
impl ScopedKind for EmailOtpCodeKind {
    const PREFIX: &'static str = "eot";
}

/// Marker for a scanner-safe magic-link token (`mlk_`), one row in the per-user
/// magic-link set (issue #68): the SHA-256 digest of a high-entropy bearer token,
/// single-active per (subject, purpose), single-use. A tenant-scoped resource: the id
/// embeds its `(tenant, environment)` AND doubles as the routing handle in the token
/// wire form `ira_mlk_<id>~<secret>`, so the scope is recoverable from the token
/// without a database hit. Because that token is a live bearer credential, the id's
/// debug form REDACTS its payload (like an invitation id and an issued token's `jti`),
/// so a magic-link id is never rendered into a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MagicLinkTokenKind;
impl ScopedKind for MagicLinkTokenKind {
    const PREFIX: &'static str = "mlk";
    const REDACT_DEBUG: bool = true;
}

/// Marker for an SMS-OTP code (`sot_`), one row in the per-user SMS-OTP set (issue
/// #70): the Argon2id hash of a single numeric code, single-active per (subject,
/// purpose), single-use. A tenant-scoped resource: the id embeds its `(tenant,
/// environment)`, so a row minted in one scope parses as a uniform not-found under
/// another, and it is only ever reachable by the subject it is bound to. The value
/// it points at is a one-way hash, never a plaintext code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmsOtpCodeKind;
impl ScopedKind for SmsOtpCodeKind {
    const PREFIX: &'static str = "sot";
}

/// Marker for an SMS route-stats row (`srt_`), one per (tenant, environment, route)
/// send-to-verify conversion counter and auto-throttle state (issue #70). An
/// INTERNAL operational row, never a bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmsRouteStatKind;
impl ScopedKind for SmsRouteStatKind {
    const PREFIX: &'static str = "srt";
}

/// Marker for a recorded risk decision (`rsk_`), one row in the per-scope risk
/// decision ledger (issue #79): the LOW/MED/HIGH score, the action taken
/// (allow/block/challenge/notify), and the enumerated contributing signals of a
/// single login evaluation. An INTERNAL, auditable operational row, never a bearer
/// credential; it carries no plaintext PII (only derived signal names, typed values,
/// and counts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RiskDecisionKind;
impl ScopedKind for RiskDecisionKind {
    const PREFIX: &'static str = "rsk";
}

/// Marker for a per-subject login-geo observation (`rgl_`), the last-seen coarse
/// location and instant a login was observed from (issue #79), read by the
/// impossible-travel signal to compute geo-velocity against the current login. A
/// tenant-scoped INTERNAL row; the observed IP, coarse location, and User-Agent are
/// end-user device metadata (PII), sealed under the scope DEK (issue #48), never a
/// plaintext column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RiskLoginGeoKind;
impl ScopedKind for RiskLoginGeoKind {
    const PREFIX: &'static str = "rgl";
}

/// Marker for an ingested third-party risk signal (`rsg_`), one row of the
/// per-scope external-signal store (issue #82, PR 1): a signal delivered by an external
/// fraud/risk source as a signed Security Event Token and folded into the #79 engine as
/// one weighted policy input. A tenant-scoped RUNTIME row (never exported); the raw
/// external subject is stored only as a keyed blind index, never a plaintext column, and
/// the signal carries no bearer secret, so its debug form is not redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RiskSignalKind;
impl ScopedKind for RiskSignalKind {
    const PREFIX: &'static str = "rsg";
}

/// Marker for a signup fraud-review-queue case (`sqn_`), one row of the per-scope
/// `signup_quarantines` table (issue #82, PR 2): a risky human signup the register path
/// quarantined instead of blocking, awaiting an admin release/reject/extend decision. A
/// tenant-scoped RUNTIME row (never exported); it carries no bearer secret and no raw
/// PII (the subject is the opaque `usr_` id), so its debug form is not redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignupQuarantineKind;
impl ScopedKind for SignupQuarantineKind {
    const PREFIX: &'static str = "sqn";
}

/// Marker for an admin-approved recovery approval (`rap_`), one row of the per-scope
/// `recovery_approvals` queue (issue #82, PR 3): a pending admin decision on an
/// admin-approved recovery flow. A tenant-scoped RUNTIME row (never exported); it carries
/// no bearer secret and no raw PII, so its debug form is not redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryApprovalKind;
impl ScopedKind for RecoveryApprovalKind {
    const PREFIX: &'static str = "rap";
}

/// Marker for a designated trusted contact (`rtc_`), one row of the per-scope
/// `recovery_trusted_contacts` enrollment (issue #82, PR 3): a contact a user designated to
/// confirm a recovery out of band. The contact address is sealed under the scope DEK, so the
/// id carries no PII; its debug form is not redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryTrustedContactKind;
impl ScopedKind for RecoveryTrustedContactKind {
    const PREFIX: &'static str = "rtc";
}

/// Marker for a per-flow trusted-contact confirmation (`rcc_`), one row of the per-scope
/// `recovery_contact_confirmations` set (issue #82, PR 3): one contact's single-use
/// out-of-band confirmation of a recovery. Only the confirmation token's digest is stored,
/// so the id carries no live secret; its debug form is not redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryContactConfirmationKind;
impl ScopedKind for RecoveryContactConfirmationKind {
    const PREFIX: &'static str = "rcc";
}

/// Marker for an IDV-gated recovery session (`riv_`), one row of the per-scope
/// `recovery_idv_sessions` set (issue #82, PR 3): the external-verification session bound to
/// a recovery flow, consuming a single-use signed provider callback. A tenant-scoped RUNTIME
/// row (never exported); its debug form is not redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryIdvSessionKind;
impl ScopedKind for RecoveryIdvSessionKind {
    const PREFIX: &'static str = "riv";
}

/// Marker for a "this wasn't me" disavowal token (`dis_`), one row in the per-subject
/// disavowal set (issue #79): the SHA-256 digest of a high-entropy single-use token
/// carried in the new-device notification. The id embeds its `(tenant, environment)`
/// AND doubles as the routing handle in the token wire form `ira_dis_<id>~<secret>`,
/// so the scope is recoverable from the token without a database hit. Because that
/// token is a live bearer credential, the id's debug form REDACTS its payload (like a
/// magic-link id), so a disavowal id is never rendered into a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RiskDisavowalKind;
impl ScopedKind for RiskDisavowalKind {
    const PREFIX: &'static str = "dis";
    const REDACT_DEBUG: bool = true;
}

/// Marker for a proof-of-work challenge (`pow_`), one row in the per-scope `PoW`
/// challenge state (issue #80): a random challenge and a difficulty the server issued,
/// bound to an endpoint plus a request context, single-use and expiring. The id embeds
/// its `(tenant, environment)` AND doubles as the routing handle the client returns with
/// its nonce, so the scope is recoverable from the presented id without a database hit.
/// The challenge is NOT a bearer credential (it is handed to the client to solve), so its
/// debug form is not redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PowChallengeKind;
impl ScopedKind for PowChallengeKind {
    const PREFIX: &'static str = "pow";
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
/// An organization-membership identifier (`omb_...`), the join row binding a user
/// into an organization (issue #94).
pub type OrgMembershipId = ScopedId<OrgMembershipKind>;
/// An audit-log event identifier (`aud_...`).
pub type AuditId = ScopedId<AuditKind>;
/// A management API key identifier (`mak_...`), environment-scoped (issue #11).
pub type ManagementKeyId = ScopedId<ManagementKeyKind>;
/// An OIDC authorization code identifier (`ac_...`), the single-use code the
/// authorization-code grant issues and the token endpoint redeems (issue #12).
pub type AuthorizationCodeId = ScopedId<AuthorizationCodeKind>;
/// An OIDC grant identifier (`grt_...`), the revocation spine (issue #12).
pub type GrantId = ScopedId<GrantKind>;
/// An issued-token identifier (`tok_...`), the `jti` recorded against a grant
/// (issue #12).
pub type IssuedTokenId = ScopedId<IssuedTokenKind>;
/// A refresh-token family identifier (`rff_...`), the revocation spine every
/// rotated refresh token in one grant's chain belongs to (issue #21).
pub type RefreshFamilyId = ScopedId<RefreshFamilyKind>;
/// A refresh token's logical identifier (`rft_...`), the scope-declaring routing
/// handle embedded in the `ira_rt_<jti>~<secret>` wire token (issue #21).
pub type RefreshTokenId = ScopedId<RefreshTokenKind>;
/// A device-authorization device-code identifier (`dc_...`), the scope-declaring
/// routing handle embedded in the `ira_dc_<jti>~<secret>` wire device code (issue
/// #24, RFC 8628). It declares the code's `(tenant, environment)` so the GLOBAL
/// `/token` endpoint recovers the scope and runs the RLS-scoped digest resolve.
pub type DeviceCodeId = ScopedId<DeviceCodeKind>;
/// A bootstrap end-user identifier (`usr_...`), the account the login and
/// registration surfaces authenticate (issue #20).
pub type UserId = ScopedId<UserKind>;
/// A bootstrap session identifier (`ses_...`), the opaque `__Host-` cookie value
/// (issue #20).
pub type SessionId = ScopedId<SessionKind>;
/// A per-client session identifier (`cse_...`), the tier-two row that carries the
/// per-(client, session) `sid` claim of the two-tier session model (issue #32).
pub type ClientSessionId = ScopedId<ClientSessionKind>;
/// An account-credential identifier (`crd_...`), one enrolled credential in a
/// user's self-service credential registry (issue #61).
pub type CredentialId = ScopedId<CredentialKind>;

/// A remembered-device id (`tdv_...`), one row in a user's trusted-device
/// registry and the value the `__Host-` device cookie names (issue #71).
pub type TrustedDeviceId = ScopedId<TrustedDeviceKind>;

/// A recovery-flow id (`rcv_...`), one row of the account-recovery state machine
/// (issue #81) and the routing handle the notification/cancellation links carry.
pub type RecoveryFlowId = ScopedId<RecoveryFlowKind>;

/// A headless-flow id (`flw_...`), one row of the flow state machine (issue #84) and
/// the routing handle both transports carry to load and advance a journey.
pub type FlowId = ScopedId<FlowKind>;

/// A registered WebAuthn passkey credential id (`pky_`, issue #65).
pub type WebauthnCredentialId = ScopedId<WebauthnCredentialKind>;

/// A single-use WebAuthn ceremony challenge handle (`wch_`, issue #65).
pub type WebauthnChallengeId = ScopedId<WebauthnChallengeKind>;
/// An enrolled TOTP authenticator id (`tot_...`), one row in the per-user TOTP
/// registry (issue #69).
pub type TotpCredentialId = ScopedId<TotpCredentialKind>;

/// A one-time recovery code id (`rvc_...`), one row in the per-user recovery-code
/// set (issue #69).
pub type RecoveryCodeId = ScopedId<RecoveryCodeKind>;

/// A per-scope step-up policy id (`sup_...`), one row in a tenant's step-up policy
/// set (issue #72): the (acr floor, max auth age) requirement governing an OAuth
/// scope token.
pub type ScopeStepUpPolicyId = ScopedId<ScopeStepUpPolicyKind>;

/// An admin sudo elevation id (`elv_...`), one row in the append-only
/// privilege-elevation ledger (issue #73): a recorded re-authentication event that
/// opens a freshness window for admin mutations.
pub type AdminSudoElevationId = ScopedId<AdminSudoElevationKind>;

/// A credential-class policy id (`ccp_...`), one row in a tenant's
/// minimum-credential-class ladder (issue #66).
pub type CredentialClassPolicyId = ScopedId<CredentialClassPolicyKind>;

/// A per-scope attestation-config id (`atc_...`), one row per (tenant, environment)
/// carrying the attestation conveyance mode (issue #66).
pub type AttestationConfigId = ScopedId<AttestationConfigKind>;

/// A per-scope MDS3 BLOB cache id (`mbc_...`), the SINGLETON verified FIDO MDS3
/// metadata cache per (tenant, environment) the attestation path evaluates against
/// (issue #66, PR B).
pub type Mds3BlobCacheId = ScopedId<Mds3BlobCacheKind>;

/// A per-scope AAGUID rule id (`aag_...`), one authenticator-model allow/deny rule the
/// 'direct' attestation path consults (issue #66, PR B).
pub type AaguidRuleId = ScopedId<AaguidRuleKind>;

/// A recorded risk-decision id (`rsk_...`), one row in the per-scope risk decision
/// ledger (issue #79): the score, the action taken, and the enumerated contributing
/// signals of a single login evaluation.
pub type RiskDecisionId = ScopedId<RiskDecisionKind>;

/// A per-subject login-geo observation id (`rgl_...`), the last-seen coarse location
/// and instant the impossible-travel signal computes geo-velocity against (issue #79).
pub type RiskLoginGeoId = ScopedId<RiskLoginGeoKind>;

/// A "this wasn't me" disavowal-token id (`dis_...`), one row in the per-subject
/// disavowal set and the routing handle embedded in its single-use token (issue #79).
pub type RiskDisavowalId = ScopedId<RiskDisavowalKind>;

/// An ingested third-party risk-signal id (`rsg_...`), one row of the per-scope
/// external-signal store the #79 engine folds in as a weighted policy input (issue #82).
pub type RiskSignalId = ScopedId<RiskSignalKind>;

/// A signup fraud-review-queue case id (`sqn_...`), one row of the per-scope
/// `signup_quarantines` table a risky signup is parked in for admin review (issue #82).
pub type SignupQuarantineId = ScopedId<SignupQuarantineKind>;

/// An admin-approved recovery approval id (`rap_...`), one row of the per-scope
/// `recovery_approvals` queue an admin decides (issue #82, PR 3).
pub type RecoveryApprovalId = ScopedId<RecoveryApprovalKind>;

/// A designated trusted-contact id (`rtc_...`), one row of the per-scope
/// `recovery_trusted_contacts` enrollment (issue #82, PR 3).
pub type RecoveryTrustedContactId = ScopedId<RecoveryTrustedContactKind>;

/// A per-flow trusted-contact confirmation id (`rcc_...`), one row of the per-scope
/// `recovery_contact_confirmations` set (issue #82, PR 3).
pub type RecoveryContactConfirmationId = ScopedId<RecoveryContactConfirmationKind>;

/// An IDV-gated recovery session id (`riv_...`), one row of the per-scope
/// `recovery_idv_sessions` set (issue #82, PR 3).
pub type RecoveryIdvSessionId = ScopedId<RecoveryIdvSessionKind>;

/// A proof-of-work challenge id (`pow_...`), one row in the per-scope `PoW` challenge
/// state and the routing handle the client returns with its nonce (issue #80).
pub type PowChallengeId = ScopedId<PowChallengeKind>;

/// A flexible-login-identifier row id (`uid_...`), one typed login identifier
/// (email, username, or phone) a user can authenticate with (issue #54).
pub type UserIdentifierId = ScopedId<UserIdentifierKind>;
/// A user-invitation identifier (`inv_...`), one pending invitation and the routing
/// handle embedded in its single-use token (issue #60).
pub type InvitationId = ScopedId<InvitationKind>;
/// A session-ended outbox event identifier (`sev_...`), the durable row enqueued on
/// every terminal session end and the idempotency key a consumer dedups on (issue #35).
pub type SessionEventId = ScopedId<SessionEventKind>;
/// A per-RP back-channel-logout delivery identifier (`bld_...`), one row in the
/// at-least-once delivery queue per participating relying party (issue #34).
pub type BackChannelDeliveryId = ScopedId<BackChannelDeliveryKind>;
/// A recorded-consent identifier (`con_...`), the decision row a grant references
/// (issue #20).
pub type ConsentId = ScopedId<ConsentKind>;
/// A federation connector identifier (`cnr_...`), one declarative
/// inbound-federation upstream definition per environment (issue #75). The prefix
/// is `cnr` (distinct from consent's `con`).
pub type ConnectorId = ScopedId<ConnectorKind>;
/// A per-environment brand identifier (`brd_...`), one named branding definition per
/// environment (issue #86). Promotable.
pub type BrandId = ScopedId<BrandKind>;
/// A per-environment locale bundle identifier (`lcb_...`), one installed localization per
/// environment (issue #86, PR 2). Promotable.
pub type LocaleBundleId = ScopedId<LocaleBundleKind>;
/// A per-environment, per-client signup form identifier (`sgf_...`), one signup-form-as-data
/// definition per (tenant, environment, client) (issue #87). Promotable.
pub type SignupFormId = ScopedId<SignupFormKind>;
/// A custom-journey version identifier (`flv_...`), one immutable version of a journey artifact in
/// a (tenant, environment) registry (issue #92, PR 5). Promotable: the whole non-secret artifact
/// travels in a config snapshot.
pub type FlowVersionId = ScopedId<FlowVersionKind>;
/// A custom-journey active-version pin identifier (`fvp_...`), one row per (tenant, environment,
/// `journey_id`) naming the version a fresh custom flow is created against (issue #92, PR 5).
pub type FlowVersionPinId = ScopedId<FlowVersionPinKind>;
/// A per-environment, per-client admin consent pre-authorization identifier (`cag_...`), one row
/// per (tenant, environment, client) (issue #88, PR 4): the scope set an admin pre-authorized for
/// a third-party client. Runtime (never promoted).
pub type ClientAdminGrantId = ScopedId<ClientAdminGrantKind>;
/// A federation outbound-login correlation-state identifier (`fls_...`), the
/// short-lived single-use row correlating an upstream authorize leg to its callback
/// (issue #75, PR B).
pub type FederationLoginStateId = ScopedId<FederationLoginStateKind>;
/// An organization-to-connector binding identifier (`ocn_...`), one per (organization,
/// connector) binding per environment (issue #77).
pub type OrgConnectionId = ScopedId<OrgConnectionKind>;
/// A routing-rule identifier (`rrl_...`), one per domain / app / user routing rule per
/// environment (issue #77).
pub type RoutingRuleId = ScopedId<RoutingRuleKind>;
/// An upstream token vault identifier (`utk_...`), one per (session, connector) row of
/// sealed captured upstream tokens (issue #77, PR 3).
pub type UpstreamTokenId = ScopedId<UpstreamTokenKind>;
/// An upstream-token retrieval grant identifier (`utg_...`), one per (client, org
/// connection) retrieval authorization (issue #77, PR 3).
pub type UpstreamTokenGrantId = ScopedId<UpstreamTokenGrantKind>;
/// An account-link identifier (`alk_...`), one per (local user) to (federated identity)
/// binding of the guarded account linking subsystem (issue #78).
pub type AccountLinkId = ScopedId<AccountLinkKind>;
/// A FedCM assertion-nonce identifier (`fdn_...`), one row of the single-use replay
/// store the IdP-side FedCM id-assertion endpoint consumes (issue #83).
pub type FedcmNonceId = ScopedId<FedcmNonceKind>;
/// A signing-key identifier (`sik_...`), which doubles as the JOSE `kid` of a
/// per-environment signing key (issue #19).
pub type SigningKeyId = ScopedId<SigningKeyKind>;
/// A resource-server identifier (`rsv_...`), a registered protected API that
/// access tokens are minted for (issue #29). Its `audience` selects the token
/// format the mint emits.
pub type ResourceServerId = ScopedId<ResourceServerKind>;
/// A key-encryption-key identifier (`kek_...`), the per-tenant envelope KEK that
/// wraps a scope's data-encryption keys (issue #48).
pub type KekId = ScopedId<KekKind>;
/// A data-encryption-key identifier (`dek_...`), the per-tenant envelope DEK that
/// seals a scope's PII and secret payloads (issue #48).
pub type DekId = ScopedId<DekKind>;
/// An encrypted-secret identifier (`sec_...`), a stored secret value sealed under
/// a scope's DEK (issue #48).
pub type EncryptedSecretId = ScopedId<EncryptedSecretKind>;
/// A custom-domain identifier (`cdom_...`), a customer-owned hostname an
/// environment is served under with a built-in-ACME certificate (issue #47).
pub type CustomDomainId = ScopedId<CustomDomainKind>;
/// An ACME challenge identifier (`chal_...`), one domain-control verification
/// attempt in the ACME issuance lifecycle (issue #47, RFC 8555).
pub type AcmeChallengeId = ScopedId<AcmeChallengeKind>;
/// An environment-variable identifier (`var_...`), a non-secret named
/// configuration value an environment carries (issue #45). Promotable.
pub type VariableId = ScopedId<VariableKind>;
/// An environment-secret identifier (`esec_...`), a sensitive named value sealed
/// under the scope's envelope DEK (issue #45, #48). Environment-identity.
pub type EnvironmentSecretId = ScopedId<EnvironmentSecretKind>;
/// A pushed-authorization-request identifier (`par_...`), the single-use reference
/// the PAR endpoint returns and `/authorize` consumes (RFC 9126, issue #27). It is
/// the reference portion of the `urn:ietf:params:oauth:request_uri:<id>` value.
pub type PushedRequestId = ScopedId<PushedRequestKind>;
/// A DCR initial-access-token identifier (`iat_...`), the RFC 7591 registration
/// authorization minted through the management API (issue #31). The token itself
/// is a separate secret stored only as a hash; this is its reference handle.
pub type InitialAccessTokenId = ScopedId<InitialAccessTokenKind>;
/// A DCR policy identifier (`pol_...`), a named, reusable set of
/// registration-metadata primitives (issue #31).
pub type DcrPolicyId = ScopedId<DcrPolicyKind>;
/// A service-account principal identifier (`sva_...`), the stable machine `sub` a
/// client-credentials access token carries (issue #23). Distinct from the client's
/// `cli_` id and consistent across issuances.
pub type ServiceAccountId = ScopedId<ServiceAccountKind>;
/// A registered external assertion issuer identifier (`xai_...`), a trust anchor
/// the JWT bearer assertion grant accepts assertions from (issue #26).
pub type ExternalIssuerId = ScopedId<ExternalIssuerKind>;
/// A subject-mapping rule identifier (`asm_...`), the explicit rule mapping an
/// external assertion's (issuer + `sub`) to an IronAuth principal (issue #26).
pub type AssertionMappingId = ScopedId<AssertionMappingKind>;
/// A trait-schema version identifier (`tsc_`), one immutable version in a
/// (tenant, environment) identity-traits schema registry (issue #53).
pub type TraitSchemaId = ScopedId<TraitSchemaKind>;
/// A trait migration/dry-run job identifier (`tmj_`), one queued job over a scope's
/// identities against a candidate schema version (issue #53).
pub type TraitMigrationJobId = ScopedId<TraitMigrationJobKind>;
/// A wrapped migration-run identifier (`mgr_`), one long-running data migration
/// wrapped in the invariant-checked state machine (issue #59).
pub type MigrationRunId = ScopedId<MigrationRunKind>;
/// A migration-run record identifier (`mrr_`), one per-record accounting row of a
/// migration run (issue #59).
pub type MigrationRunRecordId = ScopedId<MigrationRunRecordKind>;
/// A credential-abuse ban identifier (`abn_`), one durable ban row over a regulated
/// dimension and authentication path (issue #64).
pub type AbuseBanId = ScopedId<AbuseBanKind>;
/// An email-OTP code identifier (`eot_...`), one row in the per-user email-OTP set
/// (issue #68). The value it points at is a one-way Argon2id hash, never a plaintext
/// code.
pub type EmailOtpCodeId = ScopedId<EmailOtpCodeKind>;
/// A magic-link token identifier (`mlk_...`), one row in the per-user magic-link set
/// and the scope-declaring routing handle embedded in the `ira_mlk_<id>~<secret>` wire
/// token (issue #68). Its debug form redacts the payload (it is part of a bearer token).
pub type MagicLinkTokenId = ScopedId<MagicLinkTokenKind>;
/// An SMS-OTP code identifier (`sot_...`), one row in the per-user SMS-OTP set
/// (issue #70). Semantically identical to an [`EmailOtpCodeId`]: the value it points
/// at is a one-way Argon2id hash, never a plaintext code.
pub type SmsOtpCodeId = ScopedId<SmsOtpCodeKind>;
/// An SMS route-stats identifier (`srt_...`), one row per (tenant, environment,
/// route) send-to-verify conversion counter (issue #70). An INTERNAL operational
/// row, never a bearer credential.
pub type SmsRouteStatId = ScopedId<SmsRouteStatKind>;

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
        // A few scoped identifiers double as bearer secrets (an authorization
        // code, an issued token's `jti`). For those the debug form redacts the
        // payload so a struct field or a `tracing` field cannot leak the live
        // value; the scope prefix is kept so the record stays legible.
        if K::REDACT_DEBUG {
            write!(f, "{}_<redacted>", K::PREFIX)
        } else {
            write!(f, "{self}")
        }
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
    fn four_level_ids_embed_the_scope_their_level_defines() {
        // The resource-model identifier contract (issue #41), per level: an
        // operator-plane id embeds neither tenant nor environment, a tenant-level
        // id embeds neither in its bytes (it IS the tenant), an environment-level
        // id likewise, and an environment-scoped organization id embeds BOTH.
        let env = test_env();

        // Operator plane: typed, embeds no scope, round-trips.
        let operator = OperatorId::generate(&env);
        assert!(operator.to_string().starts_with("op_"));
        assert_eq!(
            OperatorId::parse(&operator.to_string()).expect("round-trips"),
            operator
        );

        // Organization (environment-scoped): embeds its (tenant, environment).
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        let organization = OrganizationId::generate(&env, &scope);
        assert!(organization.to_string().starts_with("org_"));
        assert_eq!(
            organization.scope(),
            scope,
            "organization id embeds tenant and environment"
        );
    }

    #[test]
    fn property_organization_ids_round_trip_and_deny_cross_scope() {
        // A property sweep over the organization level (issue #41): every freshly
        // minted id round-trips in its own scope, and NONE parses in a foreign
        // tenant or environment. Malformed and wrong-prefix inputs fail identically
        // (no oracle), exactly as the client exemplar does.
        let env = test_env();
        let tenant_a = TenantId::generate(&env);
        let tenant_b = TenantId::generate(&env);
        let env_1 = EnvironmentId::generate(&env);
        let env_2 = EnvironmentId::generate(&env);
        let scope_a = Scope::new(tenant_a, env_1);
        let cross_tenant = Scope::new(tenant_b, env_1);
        let cross_env = Scope::new(tenant_a, env_2);

        for _ in 0..1_000 {
            let id = OrganizationId::generate(&env, &scope_a);
            let text = id.to_string();
            // Round-trips in its own scope.
            assert_eq!(
                OrganizationId::parse_in_scope(&text, &scope_a).expect("in scope"),
                id
            );
            // Denied uniformly in a foreign tenant and a foreign environment.
            assert_eq!(
                OrganizationId::parse_in_scope(&text, &cross_tenant),
                Err(NotInScope)
            );
            assert_eq!(
                OrganizationId::parse_in_scope(&text, &cross_env),
                Err(NotInScope)
            );
        }

        // Malformed and wrong-prefix inputs fail with the same NotInScope.
        assert_eq!(
            OrganizationId::parse_in_scope("org_not-base64-!!", &scope_a),
            Err(NotInScope)
        );
        let a_client = ClientId::generate(&env, &scope_a).to_string();
        assert_eq!(
            OrganizationId::parse_in_scope(&a_client, &scope_a),
            Err(NotInScope),
            "a client id is not an organization id even in the right scope"
        );
    }

    #[test]
    fn property_org_membership_ids_round_trip_and_deny_cross_scope() {
        // A property sweep over the organization-membership level (issue #94):
        // every freshly minted id round-trips in its own scope, and NONE parses in
        // a foreign tenant or environment. Malformed and wrong-prefix inputs fail
        // identically (no oracle), exactly as the organization exemplar does.
        let env = test_env();
        let tenant_a = TenantId::generate(&env);
        let tenant_b = TenantId::generate(&env);
        let env_1 = EnvironmentId::generate(&env);
        let env_2 = EnvironmentId::generate(&env);
        let scope_a = Scope::new(tenant_a, env_1);
        let cross_tenant = Scope::new(tenant_b, env_1);
        let cross_env = Scope::new(tenant_a, env_2);

        for _ in 0..1_000 {
            let id = OrgMembershipId::generate(&env, &scope_a);
            let text = id.to_string();
            assert!(text.starts_with("omb_"));
            // Round-trips in its own scope.
            assert_eq!(
                OrgMembershipId::parse_in_scope(&text, &scope_a).expect("in scope"),
                id
            );
            // Denied uniformly in a foreign tenant and a foreign environment.
            assert_eq!(
                OrgMembershipId::parse_in_scope(&text, &cross_tenant),
                Err(NotInScope)
            );
            assert_eq!(
                OrgMembershipId::parse_in_scope(&text, &cross_env),
                Err(NotInScope)
            );
        }

        // Malformed and wrong-prefix inputs fail with the same NotInScope.
        assert_eq!(
            OrgMembershipId::parse_in_scope("omb_not-base64-!!", &scope_a),
            Err(NotInScope)
        );
        let an_org = OrganizationId::generate(&env, &scope_a).to_string();
        assert_eq!(
            OrgMembershipId::parse_in_scope(&an_org, &scope_a),
            Err(NotInScope),
            "an organization id is not a membership id even in the right scope"
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
    fn secret_scoped_ids_redact_their_debug_but_not_display() {
        let env = test_env();
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));

        // An authorization code and an issued token are bearer secrets: Debug
        // must not reveal the payload, but Display (the wire form) still must.
        let code = AuthorizationCodeId::generate(&env, &scope);
        assert_eq!(format!("{code:?}"), "ac_<redacted>");
        assert!(code.to_string().starts_with("ac_"));
        assert!(!format!("{code:?}").contains(&code.to_string()[3..]));

        let token = IssuedTokenId::generate(&env, &scope);
        assert_eq!(format!("{token:?}"), "tok_<redacted>");
        assert!(token.to_string().starts_with("tok_"));

        // A non-secret handle (a client id) keeps its legible debug form.
        let client = ClientId::generate(&env, &scope);
        assert_eq!(format!("{client:?}"), client.to_string());
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
