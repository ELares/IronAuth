// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minting the ID token and the access token through the one signing core.
//!
//! Both tokens are compact JWSs signed by [`ironauth_jose::sign_jws_with_policy`]
//! with the target environment's signing key UNDER its algorithm policy, so every
//! token IronAuth issues round-trips through the same hardened verify path and an
//! environment can never emit a token in an algorithm its policy forbids (issue
//! #194): the policy refuses a wrong-algorithm key BEFORE any signing happens.
//!
//! # The ID token's conditional claims (issue #14)
//!
//! Beyond the REQUIRED claims (`iss`, `sub`, `aud`, `exp`, `iat`), the ID token
//! carries the OIDC Core errata set 2 conditional claims:
//!
//! - `sub` is capped at 255 ASCII characters and refused (never truncated) at
//!   issuance if it violates the cap (see [`crate::subject::subject_within_cap`]).
//! - `nonce` is echoed EXACTLY when the authorization request carried one, and is
//!   absent otherwise.
//! - `auth_time` is emitted when the request asked for `max_age` or the client
//!   registered `require_auth_time`, and is always the truthful recorded
//!   authentication instant. The decision is frozen onto the code at issuance:
//!   the code carries `auth_time` ONLY when it is due, so here it is emitted iff
//!   present.
//! - `acr` and `amr` are DERIVED from the recorded authentication event's
//!   methods ([`crate::authn`]), never from a request parameter.
//! - `azp` is omitted: the code flow's ID token has a single audience equal to
//!   the authorized party and uses no extension beyond Core (errata set 2 §2).
//! - `at_hash` and `c_hash` are computed by [`crate::token_hash`] and consumed by
//!   the front-channel/hybrid path (issue #17); a token-endpoint ID token never
//!   carries `at_hash`, and the code flow never carries `c_hash`. They are wired
//!   as optional inputs here so #17 can supply them without a second minter.
//!
//! # The access token's format and claims (issue #29)
//!
//! The access token takes the format the resolved [`AccessTokenTarget`] selects:
//!
//! - **`at+jwt`** (the default, and what the OIDC/`UserInfo` flow uses): a signed
//!   JWT with the header `typ = at+jwt` and the RFC 9068 section 2.2 claims
//!   (`iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`, `scope` when granted),
//!   plus `acr` and (when frozen onto the code as due) `auth_time` from the
//!   authentication event. Its `aud` is the client id when no resource server is
//!   targeted, so [`crate::userinfo`]'s `aud == client` check keeps working, or the
//!   resource server's audience when one is. No PII beyond these protocol claims.
//! - **opaque** (a resource server, or an environment, may select it): an
//!   `ira_at_` reference token whose state lives only in the store as a digest;
//!   there is no offline validation, only the internal store resolve (the
//!   `UserInfo` consumer, and the RFC 7662 introspection endpoint in issue #22).
//!   The token SELF-DECLARES its `(tenant, environment)` scope through an embedded
//!   routing handle (its own `jti`, a scoped id), exactly as an at+jwt's `jti`
//!   does, so a GLOBAL consumer can recover the scope and run the scoped,
//!   RLS-bound resolve; the 256-bit random suffix is the secret, and only the
//!   digest of the WHOLE token is ever stored.
//!
//! The format selection is resolved in the async handler
//! ([`OidcState::resolve_access_token_target`]) and handed into the pure [`mint`],
//! so the crypto stays pure and testable while the resource-server lookup awaits.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_jose::{
    Confirmation, EmissionOptions, SigningKey, SigningPolicy, TokenTyp, compact_len,
    protected_header, sign_jws_with_policy,
};
use ironauth_store::{
    IssuedTokenId, RefreshTokenId, Scope, TokenFormat, opaque_access_token_digest,
    refresh_token_digest,
};
use serde_json::json;

use crate::authn;
use crate::permission_budget::{self, PermissionBudget, PermissionBudgetOutcome, PermissionStatus};
use crate::state::OidcState;
use crate::subject;

/// The scannable prefix on every opaque ACCESS token (issue #29): `ira` (the
/// product namespace), `at` (access token). Documented alongside its detection
/// regex in `docs/design/TOKEN-FORMATS.md` for secret-scanner registration. The
/// sibling refresh-token prefix `ira_rt_` is reserved there for consistency;
/// refresh tokens are issue #21.
pub const OPAQUE_ACCESS_TOKEN_PREFIX: &str = "ira_at_";

/// The scannable prefix on every REFRESH token (issue #21): `ira` (the product
/// namespace), `rt` (refresh token). Documented alongside its detection regex in
/// `docs/design/TOKEN-FORMATS.md` for secret-scanner registration. A refresh token
/// is a scope-declaring reference credential exactly like an opaque access token:
/// `ira_rt_<jti>~<secret>`, where `<jti>` is a `rft_` scoped id embedding its
/// `(tenant, environment)` (so the GLOBAL `/token` endpoint recovers the scope and
/// runs the RLS-scoped digest resolve) and `<secret>` is 256 bits from the entropy
/// seam. Only the SHA-256 digest of the WHOLE token is stored.
pub const OPAQUE_REFRESH_TOKEN_PREFIX: &str = "ira_rt_";

/// The delimiter between an opaque access token's scope-declaring routing handle
/// and its secret random suffix (issue #29). Chosen because it is a valid RFC 7235
/// Bearer `token68` character yet appears in NEITHER the base64url alphabet
/// (`[A-Za-z0-9_-]`) NOR a scoped identifier's wire form, so the two segments can
/// never collide and the split is unambiguous. It is not `.`, so an opaque token
/// still carries no dots and can never be mistaken for a compact JWS.
pub const OPAQUE_ACCESS_TOKEN_DELIMITER: char = '~';

/// The number of random bytes in an opaque access token: 32 bytes = 256 bits of
/// entropy, drawn from the ironauth-env seam (never raw `getrandom`), so an
/// opaque token cannot be guessed or enumerated.
const OPAQUE_ACCESS_TOKEN_BYTES: usize = 32;

/// The impersonation a session was started under, for the mint sites that must read it.
///
/// Four flows mint tokens from a session: code exchange, the front-channel implicit and hybrid
/// ID token, the device flow, and FedCM. Each resolves its session differently, so this is the
/// one thing they share, and it exists to stop the four drifting into three that carry `act`
/// and one that does not. A missing `act` is not a cosmetic gap: it is a token that says
/// nobody is acting as this subject when somebody is.
///
/// Fails SOFT to `None`. Every caller has already proved the session live to reach its mint,
/// and a read that faults between those two points must not turn a working login into a server
/// error. The token is then an ordinary one, which is what it would have been anyway.
pub(crate) async fn session_actor(
    state: &crate::state::OidcState,
    scope: ironauth_store::Scope,
    session_id: &ironauth_store::SessionId,
    now_micros: i64,
) -> Option<ironauth_store::SessionImpersonation> {
    state
        .store()
        .scoped(scope)
        .sessions()
        .get(session_id, now_micros, 0)
        .await
        .ok()
        .flatten()
        .and_then(|session| session.impersonation)
}

/// The actor behind an impersonated token (issue #101), shaped for RFC 8693 section 4.1.
///
/// The RFC defines `act` as a JSON object carrying at least `sub`, with further members
/// allowed and a nested `act` for delegation chains. This emits `sub` plus the structured
/// reason, which is the shape M13's token-exchange endpoint can consume unchanged rather than
/// a shape it would have to be redesigned around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenActor<'a> {
    /// The impersonating principal, emitted as `act.sub`.
    pub subject: &'a str,
    /// The structured reason, emitted as `act.reason_code`.
    pub reason_code: &'a str,
}

impl TokenActor<'_> {
    /// The `act` claim value.
    fn to_claim(self) -> serde_json::Value {
        json!({ "sub": self.subject, "reason_code": self.reason_code })
    }
}

/// The reserved access-token claim names a per-client STATIC custom claim may NEVER
/// set (issue #23). The client-credentials mint DROPS any custom claim whose name is
/// in this set, so a per-client `custom_token_claims` config can never forge or
/// inject a claim that carries protocol, authentication-context, binding, or session
/// meaning. This is the single enforcement point (the mint), so the guard holds even
/// for a value written straight into the store's `custom_token_claims` column.
///
/// It is a comprehensive DENYLIST of reserved names (NOT an allowlist): a custom
/// claim exists precisely to carry ARBITRARY business data, so anything not reserved
/// here is admitted. Each class below is reserved for a distinct reason:
///
/// - **Protocol claims** (RFC 9068 section 2.2 + the JWT registered claims of RFC
///   7519): the token's own identity, audience, lifetime, and validity window. A
///   business claim has no business restating `iss`/`sub`/`aud`/`exp`/... or moving
///   `nbf`. `typ`/`token_type` are reserved for defense in depth: the `at+jwt` header
///   `typ` is set separately via [`EmissionOptions`] (so a PAYLOAD `typ` is harmless),
///   but reserving both avoids ever confusing a lax verifier that reads the payload.
/// - **Authentication-context claims** (OIDC): `acr`/`amr`/`auth_time`/`nonce`/`azp`.
///   A machine token must NEVER assert a human authentication context; the M2M claim
///   builder ([`build_client_credentials_access_token_claims`]) DELIBERATELY omits
///   `acr`/`amr`/`auth_time`, so allowing a custom claim to re-inject one would defeat
///   the exact invariant that builder exists to guarantee.
/// - **Binding / security claims**: `cnf` (RFC 7800). A self-asserted confirmation key
///   would undermine sender-constrained (`DPoP` / mTLS proof-of-possession) token
///   binding once it lands; only the issuer may state `cnf`.
/// - **Hash / session claims** (OIDC): `at_hash`/`c_hash`/`sid`. IronAuth computes and
///   emits these itself where they belong; a self-asserted value carries security
///   meaning it must never be allowed to forge.
/// - **Authorization claims**: `org_id` (issue #94), `roles` (issue #97), and
///   `permissions`/`permissions_status` (issue #98). These are the only claims in the
///   set a resource server makes an ACCESS decision on, so a self-asserted one is a
///   privilege escalation rather than a cosmetic lie. All are resolved by the issuer
///   from an authoritative store read. A PERMISSION is the most direct instance of
///   that sentence in the product: it names an API capability, so a forged one is a
///   capability nobody granted. `permissions_status` is protected for a DIFFERENT
///   reason, and it is the one a reader is likely to miss: the marker grants nothing,
///   but forging its ABSENCE, or forging a weaker value, DOWNGRADES the resource
///   server's behaviour by convincing it that a WITHHELD set was simply empty.
pub(crate) const PROTECTED_ACCESS_TOKEN_CLAIMS: &[&str] = &[
    // Protocol claims (RFC 9068 section 2.2 + RFC 7519 registered).
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "client_id",
    "scope",
    "typ",
    "token_type",
    // Authentication-context claims (OIDC): a machine token asserts no human auth.
    "acr",
    "amr",
    "auth_time",
    "nonce",
    "azp",
    // Binding / security claims: only the issuer may state a confirmation key.
    "cnf",
    // Hash / session claims (OIDC): IronAuth emits these itself where they belong.
    "at_hash",
    "c_hash",
    "sid",
    // Organization context (issue #94): the DURABLE org_id is resolved from an
    // authoritative membership check and issuer-set only; a client custom claim must
    // never self-assert an organization context.
    "org_id",
    // Organization roles (issue #97): `roles` is resolved FRESH at issuance from an
    // authoritative store read over the subject's memberships, group memberships, and
    // the group ancestry, and is issuer-set only. A client custom claim must never
    // self-assert a role.
    "roles",
    // RFC 9396 authorization details (issue #131 criterion 4): what the RESOURCE OWNER
    // approved, copied from the stored request the approval decided. Issuer-set only and
    // protected for the sharpest reason on this list: a client custom claim that could write
    // it would let the client state what it was authorized to do, which is the one thing the
    // person on the approval screen was there to decide.
    "authorization_details",
    // Organization permissions (issue #98): `permissions` is resolved FRESH at
    // issuance from an authoritative store read over the mappings of the roles the
    // subject effectively holds, and is issuer-set only. A client custom claim must
    // never self-assert an API capability.
    "permissions",
    // The budget verdict (issue #98). Protected for a reason distinct from the claim
    // above: a client that could self-assert `permissions_status` could SUPPRESS a
    // `pdp_required` marker and convince a resource server that a withheld set was
    // simply an empty one, which is a downgrade the resource server cannot detect.
    "permissions_status",
    // The RFC 8693 section 4.1 actor claim (issue #101). Issuer-set only, and protected for a
    // sharper reason than most of this list: `act` is the record of WHO is acting as the
    // subject. A client that could self-assert it could name any impersonator it liked on a
    // token it obtained honestly, which FORGES an audit trail rather than merely overstating
    // an authorization. The reverse matters too: a client that could set `act` on an ordinary
    // token could make a normal session look like somebody else impersonating it.
    "act",
];

/// The resolved target for an access token: the audience(s) it is minted for, the
/// format it takes, and its lifetime (issue #29, extended for RFC 8707 resource
/// indicators in issue #28).
///
/// Resolved by the async handler from the targeted resource server(s) (or the
/// environment default) via [`OidcState::resolve_access_token_target`], then handed
/// into the pure [`mint`]. This is the seam issue #28 feeds: it resolves the
/// audience(s) from the RFC 8707 `resource` request parameter and passes them here
/// without reshaping the mint. The no-resource case passes a single audience (the
/// client id), preserving `UserInfo`'s `aud == client` check.
#[derive(Debug, Clone)]
pub struct AccessTokenTarget {
    /// The `aud` of the minted access token: ALWAYS non-empty. One entry for the
    /// no-resource case (the client id, so `UserInfo`'s `aud == client` check keeps
    /// working) or a single targeted resource server; multiple entries when several
    /// resources are requested (RFC 8707 / RFC 9068 permit an `aud` array).
    pub audiences: Vec<String>,
    /// The format to emit (an RFC 9068 `at+jwt` or an opaque reference token).
    pub format: TokenFormat,
    /// The access-token lifetime.
    pub ttl: Duration,
    /// Whether EVERY audience this token is minted for has opted in to the issue #98
    /// permission claim (`resource_servers.permission_claims_enabled`).
    ///
    /// UNANIMITY OR SUPPRESS. Computed in
    /// [`OidcState::resolve_access_token_target`](crate::OidcState::resolve_access_token_target)
    /// by folding the per-resource-server opt-in with AND, alongside the existing
    /// format-unanimity and shortest-TTL folds. A token targeting a mix of opted-in
    /// and opted-out resource servers carries NO permission claim and NO
    /// `permissions_status`: there is no per-audience claim shape inside one token,
    /// emitting anyway would be a cross-audience privilege leak, and refusing with
    /// `invalid_target` would be a behaviour change to a shipped path. The
    /// suppression is SILENT and deliberately not reported as an overflow, because it
    /// is a configuration fact the opted-in resource server can determine for itself
    /// from its own opt-in state plus the `aud` array.
    ///
    /// `false` for the no-resource branch BY CONSTRUCTION: that branch returns early
    /// without reading `resource_servers` at all, so there is no row to carry an
    /// opt-in. Every grant that passes no resource (device, client-credentials,
    /// jwt-bearer) therefore can never carry permissions, which is the issue #99
    /// boundary rather than an accident.
    pub permission_claims: bool,
}

impl AccessTokenTarget {
    /// The `aud` claim value for this target (issue #28): a JSON STRING for a single
    /// audience (the common no-resource / single-resource case, keeping the wire form
    /// identical to before #28), or a JSON ARRAY for multiple (RFC 9068 permits
    /// either). Never empty by construction.
    #[must_use]
    pub fn aud_claim(&self) -> serde_json::Value {
        match self.audiences.as_slice() {
            [single] => json!(single),
            many => json!(many),
        }
    }

    /// The PRIMARY audience (the first): the value recorded as an opaque token's
    /// `audience` column, and the fallback single audience. Never panics: the
    /// audience set is non-empty by construction.
    #[must_use]
    pub fn primary_audience(&self) -> &str {
        self.audiences.first().map_or("", String::as_str)
    }

    /// Whether a mint for this target can put a permission claim on the wire at all
    /// (issue #98): the audiences UNANIMOUSLY opted in AND the selected format is one
    /// that carries claims.
    ///
    /// The FORMAT half is not a second policy, it is the same statement
    /// [`mint_access`] makes by answering [`PermissionBudgetOutcome::NotApplicable`]
    /// on the opaque branch without reading the resolved set: a reference token
    /// carries no claims, so there is nothing for an opt-in to apply to. It is
    /// checked HERE, up front, because the caller that resolves the permission set
    /// runs before the mint, and an `opaque` resource server that is opted in
    /// (reachable through a config promotion, which writes both columns with no
    /// management handler in the path) would otherwise pay a store round trip on
    /// every exchange for a set the mint then discards. Worse than the cost: that
    /// read can FAIL, which would turn a combination the threat model documents as
    /// INERT into a 500 that the same request without the opt-in survives.
    #[must_use]
    pub fn emits_permission_claims(&self) -> bool {
        matches!(self.format, TokenFormat::AtJwt) && self.permission_claims
    }
}

/// A minted access token: the string handed to the client plus what the store
/// records for it (issue #29). An `at+jwt` records its `jti` in `issued_tokens`;
/// an opaque token records its digest and metadata in `opaque_access_tokens`.
pub enum MintedAccessToken {
    /// An RFC 9068 `at+jwt`: the compact JWS and its `jti` (recorded in
    /// `issued_tokens` for grant-chain status, exactly as before issue #29).
    Jwt {
        /// The compact access-token JWS.
        token: String,
        /// The access token's `jti`, recorded against the grant.
        jti: IssuedTokenId,
    },
    /// An opaque reference token: the plaintext handed to the client (NEVER
    /// stored) plus the digest-only record fields for `opaque_access_tokens`.
    Opaque {
        /// The `ira_at_...` plaintext token, returned to the client and never
        /// persisted.
        token: String,
        /// The SHA-256 hex digest of `token`, the only token material stored.
        digest: String,
        /// The token's logical `jti` (a `tok_` id), recorded in the row.
        jti: IssuedTokenId,
        /// The full audience set the token targets (issue #28): recorded on the row
        /// so introspection reports it. Always non-empty; its first entry is the
        /// primary `audience` column, and the whole array is recorded when it has
        /// more than one member.
        audiences: Vec<String>,
        /// The token's expiry, in microseconds since the Unix epoch (clock seam).
        expires_at_unix_micros: i64,
    },
}

impl MintedAccessToken {
    /// The token string to return in the token response, whichever format it is.
    #[must_use]
    pub fn token(&self) -> &str {
        match self {
            MintedAccessToken::Jwt { token, .. } | MintedAccessToken::Opaque { token, .. } => token,
        }
    }
}

/// The tokens minted for one successful code exchange, plus the recorded `jti`s
/// so the caller can persist them against the grant.
pub struct IssuedTokens {
    /// The minted access token (an `at+jwt` or an opaque reference token).
    pub access: MintedAccessToken,
    /// The compact ID-token JWS.
    pub id_token: String,
    /// The ID token's `jti` (recorded against the grant).
    pub id_jti: IssuedTokenId,
    /// The access-token lifetime in seconds (the `expires_in` of the response).
    pub expires_in_secs: i64,
    /// What the permission budget decided for the access token (issue #98), handed
    /// back so the ASYNC caller can record the operator-visible event. The claim
    /// shape is already decided and already signed by the time this is seen.
    pub permission_budget: PermissionBudgetOutcome,
}

/// One access token minted on its own (the refresh grant), plus the two things the
/// async caller needs beside it.
///
/// A struct rather than a widening tuple because the third member is the budget
/// verdict and an unnamed `.2` at the call site would say nothing about it.
pub struct MintedRefreshAccess {
    /// The minted access token (an `at+jwt` or an opaque reference token).
    pub access: MintedAccessToken,
    /// The access-token lifetime in seconds (the `expires_in` of the response).
    pub expires_in_secs: i64,
    /// What the permission budget decided (issue #98), for the event the async
    /// caller records. Recording from the refresh hook is NEW observability: the
    /// sink this feeds has never seen the refresh grant.
    pub permission_budget: PermissionBudgetOutcome,
}

/// Everything the claims need that is specific to one exchange.
pub struct MintRequest<'a> {
    /// The `(tenant, environment)` scope the tokens belong to.
    pub scope: Scope,
    /// The per-environment issuer.
    pub issuer: &'a str,
    /// The authenticated end-user subject.
    pub subject: &'a str,
    /// The client the tokens are for (the ID token audience and the access
    /// token's `client_id`).
    pub client_id: &'a str,
    /// The bound OIDC `nonce`, echoed into the ID token when present.
    pub nonce: Option<&'a str>,
    /// The granted OAuth `scope` value, echoed into the access token when present.
    pub oauth_scope: Option<&'a str>,
    /// The recorded authentication method tokens (space-separated RFC 8176
    /// values), the single source `amr` and the achieved `acr` derive from.
    pub auth_methods: &'a str,
    /// The recorded authentication instant in epoch microseconds, present ONLY
    /// when the ID token must carry `auth_time`; [`None`] omits the claim.
    pub auth_time_unix_micros: Option<i64>,
    /// The per-(client, session) `sid` claim (issue #32): the OP session identifier
    /// the ID token carries, stable for the lifetime of the (client, session) pair
    /// and distinct across pairs, so OIDC Back-Channel Logout can target exactly this
    /// (client, session). The token endpoint resolves it from the authenticating SSO
    /// session through the per-client session store, so it is emitted here as a
    /// LEGITIMATE issuer claim (a self-asserted custom claim named `sid` is still
    /// blocklisted; see [`PROTECTED_ACCESS_TOKEN_CLAIMS`]). [`None`] when no session
    /// backed the exchange (no `sid` is then emitted).
    pub sid: Option<&'a str>,
    /// The DURABLE organization context (an `org_` id) frozen onto the session and
    /// grant (issue #94, PR-B1): the token endpoint reads it back from the grant and
    /// emits it as the `org_id` claim on BOTH the ID token and the access token. It is
    /// a PROTECTED, issuer-only claim (see [`PROTECTED_ACCESS_TOKEN_CLAIMS`]) resolved
    /// from an AUTHORITATIVE membership check, never from a client parameter's claim of
    /// membership, so a client can never self-assert it. [`None`] when the session
    /// resolved no org (a member-less user, a multi-org user who named none, or a
    /// machine token, which asserts no human org context); no claim is then emitted.
    pub org_id: Option<&'a str>,
    /// The impersonation this session was established under (issue #101), emitted as the RFC
    /// 8693 section 4.1 `act` claim. [`None`] on an ordinary session, and an ordinary session
    /// must never carry the claim: `act` present is the assertion that somebody other than the
    /// subject is driving, and a token saying so falsely is worse than one that omits it.
    ///
    /// Only the impersonator and the STRUCTURED reason are carried. The written justification
    /// stays in the audit stream, which is where the criterion asks for it and where a reader
    /// is authorized: a token is read by the client, by every resource server it reaches, and
    /// by whatever logs them, and an operator's sentence about an incident does not belong in
    /// all of those places.
    pub actor: Option<TokenActor<'a>>,
    /// The subject's effective organization roles at THIS issuance (issue #97),
    /// emitted as the `roles` claim on the ACCESS TOKEN ONLY.
    ///
    /// Resolved FRESH from the store on every code exchange and every refresh, never
    /// frozen onto the code or the grant the way [`MintRequest::org_id`] is. A role is
    /// an AUTHORIZATION input, so a role granted or revoked after the code was issued
    /// must be reflected on the next token; freezing it would make a revocation
    /// invisible for the whole refresh-family lifetime. A [`BTreeSet`], so the emitted
    /// array is totally ordered and two issuances against identical stored state
    /// produce byte-identical tokens.
    ///
    /// [`None`] when the exchange resolved no organization context (symmetric with
    /// `org_id`): the claim is then ABSENT. [`Some`] of an EMPTY set is distinct and
    /// emits an empty array, meaning "a member of this organization holding no roles".
    ///
    /// # The next-issuance gap (issue #97, stated plainly)
    ///
    /// A role change is invisible to an ALREADY ISSUED access token for its full TTL.
    /// Nothing in IronAuth revokes or re-mints outstanding tokens when a role is
    /// granted or withdrawn, so a withdrawn role stays usable until the access token
    /// carrying it expires. "Next issuance" is the whole contract. What keeps the
    /// window tight is that the REFRESH grant re-resolves this set rather than
    /// replaying a frozen one, so the exposure is ONE ACCESS TOKEN LIFETIME and not
    /// one refresh-family lifetime. An operator who needs immediate withdrawal must
    /// revoke the session or the refresh family. Active invalidation on a role change
    /// is tracked as a follow-up; see the elevation row in `docs/THREAT-MODEL.md`.
    ///
    /// # Access token only, deliberately diverging from `org_id`
    ///
    /// `org_id` rides BOTH tokens; `roles` rides only the access token. Three reasons,
    /// stated here because a reviewer comparing the two fields will ask. Roles are an
    /// authorization input consumed by RESOURCE SERVERS, and a resource server reads
    /// the access token. The ID token is deliberately lean (its scope-derived claims
    /// live at `UserInfo`). And `org_id` is one short string whereas a role set is
    /// UNCAPPED by covenant, so putting it on the ID token would trip the existing
    /// 3072-byte `ID_TOKEN_BLOAT_THRESHOLD_BYTES` growth signal (see
    /// `crate::policy_trace`) for legitimate deployments. That constant is a growth
    /// SIGNAL and never a limit, and this field adds no cap of its own: the role set
    /// is emitted in full, however large. The client-credentials and jwt-bearer paths
    /// carry no roles either, by OMISSION from their own distinct claim builder:
    /// machine roles are issue #99 and must land on both machine paths deliberately.
    pub roles: Option<&'a BTreeSet<String>>,
    /// The subject's effective organization PERMISSIONS at THIS issuance (issue #98),
    /// emitted as the `permissions` claim on the ACCESS TOKEN ONLY.
    ///
    /// Resolved FRESH from the store on every code exchange and every refresh, on
    /// exactly the terms [`MintRequest::roles`] documents and for a stronger version
    /// of the same reason: a permission names an API CAPABILITY, so freezing one
    /// would make a revocation invisible for a whole refresh-family lifetime. A
    /// [`BTreeSet`], so the emitted array is totally ordered and two issuances against
    /// identical stored state are byte-identical, which is what makes a BYTE budget
    /// over it meaningful at all.
    ///
    /// [`None`] when the exchange resolved no organization context OR when the
    /// target's audiences did not UNANIMOUSLY opt in (see
    /// [`AccessTokenTarget::permission_claims`]); the claim is then ABSENT and no
    /// `permissions_status` is emitted either. [`Some`] of an EMPTY set is distinct
    /// and emits an empty array, meaning "in this organization, holding nothing".
    ///
    /// This is NEVER a partial set. When the budget will not accommodate it the WHOLE
    /// claim is withheld and `permissions_status` says so; see
    /// [`crate::permission_budget`]. `mint_access` and not
    /// [`build_access_token_claims`] is what reads this field, because which of the
    /// three claim shapes ships is a budget decision and the budget needs a
    /// serialized size to make it.
    ///
    /// The client-credentials and jwt-bearer paths carry no permissions either, by
    /// OMISSION from their own distinct claim builder: machine principals are issue
    /// #99 and must land on both machine paths deliberately.
    pub permissions: Option<&'a BTreeSet<String>>,
    /// The access-token hash for a front-channel ID token (issue #17). The token
    /// endpoint always passes [`None`]: a token-endpoint ID token never carries
    /// `at_hash`.
    pub at_hash: Option<&'a str>,
    /// The authorization-code hash for a hybrid ID token (issue #17). The code
    /// flow always passes [`None`]: it never carries `c_hash`.
    pub c_hash: Option<&'a str>,
    /// Extra standard claims to place in the ID token (issue #15): the claims the
    /// `claims` request parameter's `id_token` member selected, and (only when the
    /// environment sets the non-conform `conformIdTokenClaims`) the scope-derived
    /// claims. Empty by default, so the spec-conform ID token stays lean and these
    /// claims are served from `UserInfo` instead. Protocol/REQUIRED claims always
    /// win: an entry whose name is already set (for example `sub`) is never
    /// overwritten.
    pub extra_claims: &'a serde_json::Map<String, serde_json::Value>,
    /// Extra claims to place in the ACCESS token (issue #113).
    ///
    /// The counterpart of [`Self::extra_claims`], and separate from it because the two tokens
    /// are read by different parties for different purposes: an ID token is the client's
    /// identity receipt, an access token is what a resource server authorizes against, and a
    /// claim belongs in one, the other, or both by an explicit decision rather than by
    /// arriving through one bag that feeds both.
    ///
    /// Empty on every path but the pre-token hook's. Before this existed, the ID token had a
    /// custom-claim channel and the user-authentication access token had NONE, so a hook
    /// promised both halves of `token_customize`'s contract and only one had anywhere to land.
    ///
    /// # It is folded where the size is measured, and that is not incidental
    ///
    /// [`build_access_token_claims`] is called by the closure `mint_at_jwt` hands to
    /// [`crate::permission_budget::decide`], so a claim placed here is inside the bytes the
    /// budget measures, by construction rather than by a caller remembering to measure after
    /// folding. Folding it in afterwards would let the budget judge a token smaller than the
    /// one that ships, which turns issue #98's size guarantee into a size estimate, and would
    /// make the `roles_only_token_bytes` it reports a measurement of a token that never
    /// existed.
    ///
    /// Fenced against [`PROTECTED_ACCESS_TOKEN_CLAIMS`] at the fold, exactly as
    /// [`Self::extra_claims`] is. The fence is at the CHANNEL, not only at whoever writes into
    /// it: the hook's own fence in `claims_mapping` is the first line, and this one holds for
    /// any future writer that has not been invented yet.
    /// Typed, and that is the fence. A [`MappedAccessClaims`] can only come from
    /// `claims_mapping_at_issuance::apply_to_with_hook`, so a door that mints a token for a client cannot
    /// populate this field without resolving that client's MAPPING -- including a door nobody
    /// has written yet. Review measured why a plain map was not enough: emptying the resolver
    /// call at three of the six existing doors left the whole suite green.
    ///
    /// It does NOT fence the HOOK. Passing `None` for the runtime is a legal call that yields a
    /// legal value of this type, so the type cannot ask whether a door enabled hooks. See
    /// [`MappedAccessClaims`] for which doors are pinned by a test and which are not.
    pub access_extra_claims: &'a crate::claims_mapping_at_issuance::MappedAccessClaims,
    /// The RFC 9396 `authorization_details` the resource owner approved (issue #131
    /// criterion 4), echoed into the ACCESS token.
    ///
    /// Access token only, and not the ID token: this describes what the bearer may DO at a
    /// resource server, which is what an access token is for. An ID token says who the person
    /// is, and a resource server that read authorization from it would be reading the wrong
    /// token.
    pub authorization_details: Option<&'a serde_json::Value>,
    /// The per-client ID-token signing key (issue #30): the environment key of the
    /// algorithm this client negotiated as its `id_token_signed_response_alg` at
    /// dynamic registration. When [`Some`], the ID token (ONLY the ID token, never
    /// the access token) is signed with this key, so the algorithm DCR recorded and
    /// echoed at registration is the algorithm the ID token is actually signed
    /// under. [`None`] signs the ID token with the environment default `signer`,
    /// exactly as before DCR (every non-DCR client, and any DCR client whose
    /// negotiated algorithm IS the environment default). The caller resolves it from
    /// the environment key set, so it is always a key the policy permits.
    pub id_token_signer: Option<&'a SigningKey>,
    /// The proof-of-possession confirmation to bind the ACCESS token to (RFC 7800,
    /// issue #368): the [`Confirmation::Jkt`] of a `DPoP` proof key when a valid
    /// proof accompanied the code exchange. [`Some`] embeds a `cnf` claim in the
    /// at+jwt (making it sender-constrained); [`None`] leaves it a plain bearer
    /// token. Issuer-set ONLY: `cnf` is a PROTECTED access-token claim (see
    /// [`PROTECTED_ACCESS_TOKEN_CLAIMS`]), so a client can never self-assert a
    /// binding, and it is placed here by the token endpoint after it has itself
    /// validated the proof. The ID token never carries it (binding is an access
    /// token property).
    pub confirmation: Option<&'a Confirmation>,
}

/// Why building the ID token claims failed. Every variant is fail-closed at
/// issuance (the caller maps it to an opaque `server_error`) and none leaks the
/// offending value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdTokenError {
    /// The `sub` exceeds the 255 ASCII-character cap or is not ASCII. Refused
    /// rather than truncated (a truncated subject could collide two users).
    SubjectOutOfBounds,
}

/// Build the ID token claim set (OIDC Core errata set 2), enforcing the `sub`
/// cap and the conditional claim rules. Pure: it takes the already-resolved
/// instants and identifiers, so it is exercised without a store or a signer.
///
/// [`MintRequest::roles`] is DELIBERATELY not read here (issue #97), and neither is
/// [`MintRequest::permissions`] (issue #98): both ride the ACCESS token only. Do not
/// "fix" the asymmetry with `org_id` by adding an emission; the reasoning is on those
/// fields' doc comments, and `the_id_token_never_carries_roles` and
/// `the_id_token_never_carries_permissions` pin the two omissions.
///
/// A `permissions` or `permissions_status` arriving through the client-influenced
/// extra-claims bag is DROPPED by the explicit reserved-name filter below, not
/// stamped in. That filter and not insertion order is what protects the no-org case,
/// where the protocol sets no such claim at all.
///
/// # Errors
///
/// [`IdTokenError::SubjectOutOfBounds`] if `subject` violates the 255 ASCII
/// cap; issuance fails closed rather than truncating.
pub(crate) fn build_id_token_claims(
    request: &MintRequest<'_>,
    iat: i64,
    exp: i64,
    jti: &str,
) -> Result<serde_json::Value, IdTokenError> {
    // sub cap: refuse, never truncate (OIDC Core errata set 2 §2).
    if !subject::subject_within_cap(request.subject) {
        return Err(IdTokenError::SubjectOutOfBounds);
    }

    // The REQUIRED claims (iss, sub, aud, exp, iat) plus the recorded jti.
    let mut claims = json!({
        "iss": request.issuer,
        "sub": request.subject,
        "aud": request.client_id,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    });

    // nonce: echoed EXACTLY when the request carried one, absent otherwise.
    if let Some(nonce) = request.nonce {
        claims["nonce"] = json!(nonce);
    }

    // act (RFC 8693 section 4.1, issue #101): present ONLY on a token minted for an
    // impersonation session, absent on every ordinary one. The criterion states both halves,
    // and the absent half is the one a test gets wrong by only ever checking a token it
    // expected to carry the claim.
    if let Some(actor) = request.actor {
        claims["act"] = actor.to_claim();
    }

    // acr and amr: DERIVED from the recorded authentication event, never from a
    // request parameter. amr reflects the factors actually used; acr is the
    // achieved level (never a copied-through requested value).
    let methods = authn::parse_methods(request.auth_methods);
    // The LOCAL factors IronAuth actually performed, plus the honest UPSTREAM `amr`
    // passthrough for a FEDERATED login (issue #75). The passthrough is emitted VERBATIM,
    // never converted into a local method (which would falsely claim IronAuth ran it): for a
    // pure federated login the local set is empty ([`AuthMethod::Federated`] emits no `amr`),
    // so the token's `amr` is exactly what the upstream asserted, and if the upstream
    // asserted none the token asserts none.
    let mut amr: Vec<String> = authn::amr_values(&methods)
        .into_iter()
        .map(str::to_owned)
        .collect();
    for upstream in authn::federated_amr_from_auth_methods(request.auth_methods) {
        if !amr.contains(&upstream) {
            amr.push(upstream);
        }
    }
    claims["amr"] = json!(amr);
    claims["acr"] = json!(authn::achieved_acr(&methods));

    // auth_time: present iff frozen onto the code (max_age requested or the
    // client registered require_auth_time), always the truthful recorded instant
    // (in epoch SECONDS, like iat/exp). The max_age=0 case still records a real
    // auth_time, so it is emitted here truthfully.
    if let Some(auth_micros) = request.auth_time_unix_micros {
        claims["auth_time"] = json!(auth_micros.div_euclid(1_000_000));
    }

    // sid (issue #32): the OP session identifier, present in EVERY code-flow ID
    // token (the token endpoint resolves it from the authenticating SSO session
    // through the per-client session store). It is stable per (client, session) and
    // distinct across clients, so it is the join key OIDC Back-Channel Logout targets
    // and the reason discovery can truthfully advertise
    // backchannel_logout_session_supported. Emitted here as a legitimate issuer claim.
    if let Some(sid) = request.sid {
        claims["sid"] = json!(sid);
    }

    // org_id (issue #94, PR-B1): the DURABLE organization context frozen onto the
    // session and grant, resolved from an authoritative membership check at
    // authorization, emitted here as a legitimate issuer claim. It is set BEFORE the
    // extra-claims fold below and is a PROTECTED access-token claim, so a client
    // custom claim named `org_id` can never shadow or forge it. Absent when the
    // session resolved no org.
    if let Some(org_id) = request.org_id {
        claims["org_id"] = json!(org_id);
    }

    // at_hash / c_hash: dormant seams for the front-channel/hybrid path (#17).
    // The token endpoint passes None for both, so a token-endpoint ID token
    // carries neither.
    if let Some(at_hash) = request.at_hash {
        claims["at_hash"] = json!(at_hash);
    }
    if let Some(c_hash) = request.c_hash {
        claims["c_hash"] = json!(c_hash);
    }

    // azp is deliberately omitted: aud is the single client, which IS the
    // authorized party, and the code flow uses no extension beyond Core, so
    // errata set 2 §2 leaves azp out.

    // Extra standard claims (issue #15): the claims-parameter `id_token` member,
    // and (only under the non-conform conformIdTokenClaims override) the
    // scope-derived claims. A PROTECTED (protocol) claim is set ONLY by the
    // protocol above, NEVER from the client-influenced extra bag: insertion-order
    // "protocol wins" is no protection for a claim the protocol did NOT set on THIS
    // token (for example `org_id` on a no-org session, or `cnf` on a no-binding
    // session), so the reserved set is filtered explicitly here, exactly as the
    // access-token and client-credentials builders do (issue #94). A user claim
    // released through this bag can never be named `org_id`, `sub`, `cnf`, and the
    // rest, so it can never forge one.
    if let serde_json::Value::Object(claims_object) = &mut claims {
        for (name, value) in request.extra_claims {
            if PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&name.as_str()) {
                continue;
            }
            claims_object
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }

    Ok(claims)
}

/// WHICH permission claim an access token carries (issue #98): the three, and only
/// three, states a resource server can observe on the wire.
///
/// A total enum rather than a pair of options, because the states are mutually
/// exclusive and "both `permissions` and `permissions_status`" must be unwritable
/// rather than merely unwritten. There is deliberately no variant carrying a PARTIAL
/// set either, though that one is a weaker guarantee and is worth stating as the
/// weaker thing it is: [`PermissionClaim::Set`] takes any [`BTreeSet`], so an emitter
/// that shortened the set itself would still compile. What the missing variant buys is
/// that truncating has to be a deliberate act at the call site rather than a shape this
/// type offers. The behaviour is held by the mint's tests; see `docs/THREAT-MODEL.md`.
///
/// The three states and what each TELLS the resource server:
///
/// | State | `permissions` | `permissions_status` | Meaning |
/// |---|---|---|---|
/// | [`PermissionClaim::Absent`] | absent | absent | No organization context, OR the target's audiences did not unanimously opt in. |
/// | [`PermissionClaim::Set`] | present (possibly `[]`) | absent | The COMPLETE resolved set. `[]` means "in an organization, holding nothing". |
/// | [`PermissionClaim::Withheld`] | absent | present | The set was withheld for a BUDGET reason, and the value says what to do instead. |
#[derive(Debug, Clone, Copy)]
pub(crate) enum PermissionClaim<'a> {
    /// Emit neither claim. Also the state a MIXED opt-in target reaches, which is why
    /// this variant carries no reason: a suppression for a configuration reason must
    /// be indistinguishable on the wire from "no organization context", and must NOT
    /// be reported as an overflow.
    Absent,
    /// Emit the COMPLETE set as `permissions`.
    Set(&'a BTreeSet<String>),
    /// Emit no `permissions` and say why in `permissions_status`.
    Withheld(PermissionStatus),
}

/// Build the RFC 9068 access-token claim set for an `at+jwt` (issue #29). Pure,
/// so it is exercised without a store or a signer.
///
/// Carries the RFC 9068 section 2.2 claims: `iss`, `exp`, `aud`, `sub`,
/// `client_id`, `iat`, `jti`, and `scope` when a scope was granted. `aud` is the
/// resolved `audience` (the client id for the no-resource case, so `UserInfo`'s
/// `aud == client` check keeps working; a resource server's audience when one is
/// targeted). `client_id` is ALWAYS the OAuth client. Because this token results
/// from a user-authentication (code) flow, it also carries `acr` (the achieved
/// authentication context, derived from the recorded authentication event, never
/// a request parameter) and, when the authentication instant was frozen onto the
/// code as due, `auth_time`. Claims hygiene: no PII beyond these protocol claims
/// (no `email`/`name`/`address`/`phone`); scope-derived claims stay at `UserInfo`.
///
/// `permission` is an EXPLICIT parameter rather than a read of
/// [`MintRequest::permissions`] (issue #98), and the asymmetry with `roles` is
/// deliberate. Which of the three [`PermissionClaim`] shapes ships is a BUDGET
/// decision, and the budget's input is the serialized size of the very claim set
/// being decided, so the decision cannot be made from inside this function; it is
/// made in [`mint_access`], which calls this twice and signs one of the results. A
/// parameter makes that visible at every call site, where a silent read of a request
/// field would let a caller believe a resolved set is emitted when the budget
/// withheld it.
pub(crate) fn build_access_token_claims(
    request: &MintRequest<'_>,
    iat: i64,
    exp: i64,
    jti: &str,
    audience: &serde_json::Value,
    permission: PermissionClaim<'_>,
) -> serde_json::Value {
    let mut claims = json!({
        "iss": request.issuer,
        "sub": request.subject,
        "aud": audience,
        "client_id": request.client_id,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    });
    if let Some(scope) = request.oauth_scope {
        claims["scope"] = json!(scope);
    }
    // acr: the achieved authentication context of the code flow, derived from the
    // recorded authentication event (issue #14's `authn`), never a request value.
    let methods = authn::parse_methods(request.auth_methods);
    claims["acr"] = json!(authn::achieved_acr(&methods));
    // auth_time: present iff frozen onto the code as due (max_age requested or the
    // client registered require_auth_time), always the truthful recorded instant
    // in epoch SECONDS, exactly as the ID token emits it.
    if let Some(auth_micros) = request.auth_time_unix_micros {
        claims["auth_time"] = json!(auth_micros.div_euclid(1_000_000));
    }
    // org_id (issue #94, PR-B1): the DURABLE organization context frozen onto the
    // grant, emitted as a legitimate issuer claim (it is in PROTECTED_ACCESS_TOKEN_CLAIMS,
    // so a client custom claim can never self-assert it). Absent when the session
    // resolved no org; a client-credentials (M2M) token never sets it (no human org
    // context), which its distinct builder guarantees by omission.
    if let Some(org_id) = request.org_id {
        claims["org_id"] = json!(org_id);
    }

    // act (RFC 8693 section 4.1, issue #101), on the ACCESS token as well as the ID token.
    // Both or neither: a resource server authorizing a request is the reader that most needs
    // to know somebody is acting as this subject, and an integration test caught this half
    // missing after the ID token half was wired.
    if let Some(actor) = request.actor {
        claims["act"] = actor.to_claim();
    }
    // roles (issue #97): the subject's effective organization roles, RESOLVED FRESH at
    // this issuance (never replayed from the code or the grant, which is exactly how
    // this differs from org_id above). Emitted on the ACCESS token only: a resource
    // server is what makes an authorization decision, the ID token stays lean, and the
    // set is uncapped by covenant. It is in PROTECTED_ACCESS_TOKEN_CLAIMS, so no client
    // custom claim can self-assert it on any path. The BTreeSet is emitted in its own
    // total order, so two issuances against identical stored state are byte-identical.
    //
    // ABSENT when the exchange resolved no organization context; an EMPTY ARRAY when it
    // resolved an organization in which the subject holds no role. Those two are
    // deliberately distinct: absent means "no org context", empty means "this org, no
    // roles". A client-credentials (M2M) token never sets it (no human org context),
    // which its distinct builder guarantees by omission.
    if let Some(roles) = request.roles {
        claims["roles"] = json!(roles.iter().collect::<Vec<_>>());
    }
    // permissions / permissions_status (issue #98): the subject's effective API
    // capabilities, RESOLVED FRESH at this issuance exactly as `roles` is, and
    // emitted on the ACCESS token only. Both names are in
    // PROTECTED_ACCESS_TOKEN_CLAIMS, so no client-influenced bag can self-assert
    // either on any path. The set is emitted in the BTreeSet's total order, which is
    // what makes the byte budget's measurement reproducible.
    //
    // Which shape ships is decided by the caller, never here: see `PermissionClaim`
    // for the three observable wire states and what each tells a resource server. The
    // two claims are MUTUALLY EXCLUSIVE by construction (the match has no arm setting
    // both), so a resource server never has to reconcile a set with a status.
    match permission {
        PermissionClaim::Absent => {}
        PermissionClaim::Set(permissions) => {
            claims["permissions"] = json!(permissions.iter().collect::<Vec<_>>());
        }
        PermissionClaim::Withheld(status) => {
            claims["permissions_status"] = json!(status.as_str());
        }
    }
    // cnf (RFC 7800 / RFC 9449, issue #368): bind the access token to the DPoP proof
    // key when a valid proof accompanied issuance. `cnf` is issuer-reserved (it is in
    // PROTECTED_ACCESS_TOKEN_CLAIMS), so embedding it HERE is the only way it can be
    // set: a client cannot self-assert a binding. Absent for a plain bearer token.
    if let Some(confirmation) = request.confirmation {
        if let serde_json::Value::Object(object) = &mut claims {
            confirmation.embed_in_claims(object);
        }
    }

    // Extra claims (issue #113): the pre-token hook's accepted access-token claims. Fenced
    // against the reserved set here and not only at the hook, for the reason the ID token's
    // equivalent fold gives: "protocol wins" by insertion order is no protection for a claim
    // the protocol did NOT set on THIS token. `org_id` on a no-org session and `cnf` on a
    // no-binding session are absent rather than present, so an unfenced bag could introduce
    // them rather than merely fail to overwrite them.
    //
    // LAST, after every issuer claim including `cnf`, so `or_insert_with` finds a protocol
    // claim already in place and leaves it. Folding earlier would make the fence the only
    // thing standing between this bag and a protocol claim, and a fence plus an ordering is
    // two reasons where one would do.
    // BEFORE the extra-claims fold, so a claims mapping finds it already in place and the
    // protected list is the second fence rather than the only one.
    if let (serde_json::Value::Object(object), Some(details)) =
        (&mut claims, request.authorization_details)
    {
        object.insert("authorization_details".to_owned(), details.clone());
    }
    if let serde_json::Value::Object(object) = &mut claims {
        for (name, value) in request.access_extra_claims.as_map() {
            if PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&name.as_str()) {
                continue;
            }
            object.entry(name.clone()).or_insert_with(|| value.clone());
        }
    }
    claims
}

/// Everything a client-credentials (M2M) access token needs (issue #23). Distinct
/// from [`MintRequest`] because a machine token has no user, no nonce, no
/// authentication event, and no ID token: only the RFC 9068 protocol claims, the
/// stable service-account `sub`, and the per-client static custom claims.
pub struct ClientCredentialsMintRequest<'a> {
    /// The `(tenant, environment)` scope the token belongs to.
    pub scope: Scope,
    /// The per-environment issuer.
    pub issuer: &'a str,
    /// The STABLE service-account principal id (a `sva_` id): the token's `sub`,
    /// DISTINCT from `client_id` and consistent across issuances.
    pub subject: &'a str,
    /// The authenticated OAuth client (the token's `client_id`).
    pub client_id: &'a str,
    /// The granted OAuth `scope` value, echoed into the token when present.
    pub oauth_scope: Option<&'a str>,
    /// The organization this machine identity belongs to (issue #126), or [`None`] when that
    /// is not a single unambiguous answer.
    ///
    /// A machine identity has no session to have chosen an organization in, the way a user's
    /// is frozen onto the grant at authorization, so this comes from its membership and is
    /// absent when it holds more than one. Emitted as `org_id`, the same claim a user's token
    /// carries, so a resource server reads one shape for both principal kinds.
    pub org_id: Option<&'a str>,
    /// The effective organization roles this identity holds (issue #126), or [`None`] when
    /// there is no unambiguous organization to resolve them in.
    ///
    /// Resolved FRESH at issuance from an authoritative read, exactly as a user's are, and
    /// issuer-set only: `roles` is in [`PROTECTED_ACCESS_TOKEN_CLAIMS`] so a custom claim
    /// cannot self-assert one.
    pub roles: Option<&'a BTreeSet<String>>,
    /// The custom claims to embed: the per-client static ones, AFTER this client's
    /// declarative mapping and its deployed hook have shaped them (issue #113 criterion 1).
    ///
    /// A custom claim can never set a reserved claim name (see
    /// [`PROTECTED_ACCESS_TOKEN_CLAIMS`]). Custom claims are an at+jwt feature ONLY: an opaque
    /// access token carries no embedded claims by design, so when the resolved format is
    /// opaque these claims are dropped (and the mint warns), their metadata surfacing instead
    /// through #22 introspection.
    ///
    /// TYPED, for the same reason [`MintRequest::access_extra_claims`] is, and the type is
    /// deliberately the SAME one. This field was a plain map until issue #113's criterion-1
    /// audit, and that is how three grants -- `client_credentials`, `jwt:bearer` and token
    /// exchange -- came to mint tokens that ran no mapping and no hook. The fence on the other
    /// struct was sound and simply did not extend here, because a fence is a property of a
    /// FIELD and these doors fill in a different one. Both structs now demand the same
    /// evidence, so a door added to either is asked the question.
    ///
    /// Built by `claims_mapping_at_issuance::apply_to_machine_token`, which resolves the
    /// mapping under `claims_mapping::Destination::OneAccessToken` and runs the hook with this
    /// bag as its ACCESS-token list.
    ///
    /// It is NOT the two-token answer with its halves merged. That was the first version and it
    /// inverted `place: id_token`, the rule whose whole meaning is "keep this out of an access
    /// token", by folding an explicitly-excluded claim into the only token there is. A claim
    /// the operator placed in the ID token is not emitted here; an UNPLACED one is, because
    /// nothing was expressed and this is the one token that exists.
    pub custom_claims: &'a crate::claims_mapping_at_issuance::MappedAccessClaims,
    /// The RFC 8693 section 4.1 `act` delegation chain, for a token issued by the
    /// token-exchange grant (issue #125). [`None`] for every other issuance, and the
    /// client-credentials grant always passes [`None`]: `act` asserts that somebody other
    /// than the subject is driving, and a machine token acting for itself must not claim
    /// it.
    ///
    /// Carried as a whole pre-built [`serde_json::Value`] rather than a flat
    /// `(sub, reason)` pair like [`TokenActor`], because a delegation chain NESTS: two
    /// hops are `act.act`, and a flat shape can only ever record the most recent actor.
    /// Losing the earlier hops is not cosmetic; the chain is the evidence a resource
    /// server uses to decide whether this path of delegation was permissible.
    ///
    /// The value is built by the store's `extend_act_chain` from the VALIDATED actor
    /// token and the subject token's existing verified chain, never from a request
    /// parameter, so a client cannot post a chain of its choosing.
    pub act: Option<&'a serde_json::Value>,
}

/// Build the RFC 9068 access-token claim set for a CLIENT-CREDENTIALS (M2M) token
/// (issue #23). Pure, so it is exercised without a store or a signer.
///
/// Carries the RFC 9068 section 2.2 claims (`iss`, `exp`, `aud`, `sub`,
/// `client_id`, `iat`, `jti`, and `scope` when granted), where `sub` is the STABLE
/// service-account principal id (DISTINCT from `client_id`, per RFC 9068) and
/// `client_id` is the OAuth client. It deliberately carries NO `acr` and NO
/// `auth_time`: unlike [`build_access_token_claims`] (a user-authentication flow),
/// a client-credentials token results from no user authentication event, so
/// asserting an authentication context would be false. It reuses the SAME signing
/// core and opaque mint as every other access token; only the claim set differs.
///
/// It likewise carries NO `org_id` (issue #94), NO `roles` (issue #97), and NO
/// `permissions` or `permissions_status` (issue #98). That omission IS the
/// machine-principal guarantee: a machine token asserts no human organization
/// context, no human authorization role, and no human API capability. Attaching any
/// of them to an `sva_` service-account principal is issue #99 and needs its own
/// field here, so it lands on BOTH machine paths (client-credentials and jwt-bearer)
/// at once and deliberately, rather than leaking in through this builder.
///
/// The omission is structural twice over, which is worth stating because one layer
/// alone would be thin. This builder takes a [`ClientCredentialsMintRequest`], which
/// has no permission field to read; and the M2M grants pass no RFC 8707 resource, so
/// [`AccessTokenTarget::permission_claims`] is `false` for them even if one day they
/// did.
///
/// The per-client STATIC custom claims are merged last, and a custom claim can NEVER
/// override a protected registered claim: any name in [`PROTECTED_ACCESS_TOKEN_CLAIMS`]
/// is skipped, and the protocol claims are already present (so even a non-protected
/// name never shadows one). `roles` is in that set, so a stored
/// `custom_token_claims` of `{"roles":["admin"]}` is DROPPED, not emitted. Claims
/// hygiene otherwise mirrors the code flow: no PII.
pub(crate) fn build_client_credentials_access_token_claims(
    request: &ClientCredentialsMintRequest<'_>,
    iat: i64,
    exp: i64,
    jti: &str,
    audience: &serde_json::Value,
) -> serde_json::Value {
    let mut claims = json!({
        "iss": request.issuer,
        "sub": request.subject,
        "aud": audience,
        "client_id": request.client_id,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    });
    if let Some(scope) = request.oauth_scope {
        claims["scope"] = json!(scope);
    }
    // The organization context and roles (issue #126), BEFORE the custom-claims merge so the
    // `or_insert_with` below finds them already in place. Both are also in
    // `PROTECTED_ACCESS_TOKEN_CLAIMS`, so the fence is the second line of defence rather than
    // the only one -- the same arrangement the user-token path uses.
    if let serde_json::Value::Object(object) = &mut claims {
        if let Some(org_id) = request.org_id {
            object.insert("org_id".to_owned(), json!(org_id));
        }
        if let Some(roles) = request.roles {
            object.insert("roles".to_owned(), json!(roles));
        }
    }
    // Merge the per-client static custom claims. A custom claim can NEVER override a
    // protected registered claim: an explicitly protected name is skipped, and the
    // `or_insert_with` keeps a protocol claim that is already present, so a hostile
    // `{"sub":"attacker"}` never shadows the real subject even if it were written
    // straight into the store.
    if let serde_json::Value::Object(object) = &mut claims {
        for (name, value) in request.custom_claims.as_map() {
            if PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&name.as_str()) {
                continue;
            }
            object.entry(name.clone()).or_insert_with(|| value.clone());
        }
    }
    // The delegation chain is set AFTER the custom-claim merge, so it is issuer-only in
    // the strongest sense available here: `act` is in PROTECTED_ACCESS_TOKEN_CLAIMS (so
    // the loop above already skips it), and writing it last means even a future change
    // that loosened that set could not let a stored custom claim decide who is acting.
    if let Some(act) = request.act {
        claims["act"] = act.clone();
    }
    claims
}

/// Mint the client-credentials (M2M) access token (issue #23), in whichever format
/// the resolved `target` selects, through the SAME policy-enforced signing core and
/// opaque mint as every other access token. There is no ID token and no refresh
/// token (RFC 6749 4.4.3): this mints ONLY the access token and returns it plus its
/// lifetime in seconds.
///
/// # Errors
///
/// Returns `Err(())` if `signer`'s algorithm is not permitted by `policy` or the
/// signing backend fails; the caller maps that to a token-endpoint `server_error`,
/// so a signing failure fails the issuance closed. The opaque path is infallible.
pub fn mint_client_credentials_access_token(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &ClientCredentialsMintRequest<'_>,
    target: &AccessTokenTarget,
) -> Result<(MintedAccessToken, i64), ()> {
    let now = state.now();
    let iat = epoch_secs(now);
    let access_exp = iat.saturating_add(secs(target.ttl));
    let minted = match target.format {
        TokenFormat::AtJwt => {
            let jti = IssuedTokenId::generate(state.env(), &request.scope);
            let claims = build_client_credentials_access_token_claims(
                request,
                iat,
                access_exp,
                &jti.to_string(),
                &target.aud_claim(),
            );
            let token = sign_jws_with_policy(
                policy,
                signer,
                &serde_json::to_vec(&claims).map_err(|_| ())?,
                &EmissionOptions::new().with_token_typ(TokenTyp::AccessToken),
            )
            .map_err(|_| ())?;
            MintedAccessToken::Jwt { token, jti }
        }
        // Opaque tokens carry no claims, so this is the exact same reference token as
        // every other grant mints (shared helper), only its stored metadata differs.
        // Consequently a client's configured custom claims CANNOT ride on an opaque
        // token: an opaque token is a reference credential with no embedded payload by
        // design, and its metadata surfaces only through the #22 introspection resolve;
        // custom claims are an at+jwt feature. This is NOT silent: when custom claims
        // are configured but the resolved resource-server/environment format is opaque,
        // warn (without the claim VALUES, honoring the log-scrubbing rule) so the drop
        // is observable rather than a silent gap. Storing the claims in the opaque row
        // is deliberately out of scope here (cross-cutting with introspection, #22).
        TokenFormat::Opaque => {
            if !request.custom_claims.as_map().is_empty() {
                tracing::warn!(
                    "client custom claims are configured but the resolved access-token \
                     format is opaque; custom claims are an at+jwt feature and are not \
                     embedded in an opaque reference token (they surface via #22 \
                     introspection instead)"
                );
            }
            mint_opaque_access(state, &request.scope, target, now)
        }
    };
    Ok((minted, secs(target.ttl)))
}

/// Generate an opaque access token (issue #29): the scannable `ira_at_` prefix, a
/// SCOPE-DECLARING routing handle (`jti`, a `tok_` scoped id embedding its
/// `(tenant, environment)`), the [`OPAQUE_ACCESS_TOKEN_DELIMITER`], and 256 bits of
/// entropy from the ironauth-env seam.
///
/// The routing handle lets a GLOBAL consumer (the `UserInfo` endpoint, and the RFC
/// 7662 introspection endpoint in issue #22) recover the token's scope and run the
/// scoped, RLS-bound store resolve, exactly as an at+jwt's `jti` carries its scope;
/// the endpoints are global and every other bearer credential IronAuth issues is a
/// scoped identifier, so the opaque token declares its scope the same way. The
/// handle is a NON-secret id (it is also the stored `jti` and the introspection
/// handle); the 256-bit random suffix is the secret. The plaintext is returned to
/// the client and never stored; only the digest of the WHOLE token is persisted, so
/// a database dump still yields nothing replayable.
fn generate_opaque_access_token(state: &OidcState, jti: &IssuedTokenId) -> String {
    let mut bytes = [0_u8; OPAQUE_ACCESS_TOKEN_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    format!(
        "{OPAQUE_ACCESS_TOKEN_PREFIX}{jti}{OPAQUE_ACCESS_TOKEN_DELIMITER}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Mint the ID token and the access token for a successful exchange (issue #29).
///
/// The ID token is ALWAYS a signed JWT (OIDC Core, `typ = JWT`), signed with the
/// environment key; its lifetime is the environment's own `id_token_ttl_secs`,
/// independent of the access token's (issue #192). The access token takes the
/// resolved `target`'s format: an RFC 9068 `at+jwt` (signed, `jti` recorded in
/// `issued_tokens`) or an opaque reference token (random + digest, recorded in
/// `opaque_access_tokens`), with the target's audience and lifetime. The `jti`s
/// are drawn from the entropy seam.
///
/// # Errors
///
/// Returns `Err(())` if the environment has no signing key, `signer`'s algorithm
/// is not permitted by `policy`, the signing backend fails, or the ID token claims
/// are refused (an out-of-bounds `sub`); the caller maps that to a token-endpoint
/// `server_error`, so issuance fails closed. The opaque path cannot fail (entropy
/// draw and hashing are infallible), but the ID token is always signed, so a
/// signing failure still fails the whole exchange closed.
pub fn mint(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
    target: &AccessTokenTarget,
) -> Result<IssuedTokens, ()> {
    let now = state.now();
    let iat = epoch_secs(now);
    // The ID token uses the environment's OWN id-token lifetime (issue #192); the
    // access token uses the target lifetime (a resource server may shorten it).
    // These were the same number, read from the same setting, which meant tuning
    // the access token silently retuned the identity receipt.
    let id_exp = iat.saturating_add(secs(state.id_token_ttl()));
    let access_ttl_secs = secs(target.ttl);

    let id_jti = IssuedTokenId::generate(state.env(), &request.scope);

    // ID token (OIDC Core errata set 2): the REQUIRED claims plus the conditional
    // rules, built and cap-checked before signing so a refused sub fails closed.
    let id_claims =
        build_id_token_claims(request, iat, id_exp, &id_jti.to_string()).map_err(|error| {
            tracing::error!(
                ?error,
                "refusing to issue an ID token with an invalid subject"
            );
        })?;
    // The ID token is signed with the per-client key when the client negotiated a
    // non-default `id_token_signed_response_alg` at registration (issue #30), else
    // the environment default. The access token below always uses the environment
    // default `signer`.
    let id_signer = request.id_token_signer.unwrap_or(signer);
    let id_token = sign_jws_with_policy(
        policy,
        id_signer,
        &serde_json::to_vec(&id_claims).map_err(|_| ())?,
        &EmissionOptions::new().with_token_typ(TokenTyp::IdToken),
    )
    .map_err(|_| ())?;

    let (access, permission_budget) = mint_access(state, signer, policy, request, target, now)?;

    Ok(IssuedTokens {
        access,
        id_token,
        id_jti,
        expires_in_secs: access_ttl_secs,
        permission_budget,
    })
}

/// Mint ONLY an access token (the refresh-token grant, issue #21). It reuses the
/// EXACT same access-token claim assembly and signing path as [`mint`] and returns
/// the token plus its lifetime in seconds. A refreshed exchange never re-mints an
/// ID token (no new authentication happened), so this is the lean minter the
/// refresh grant uses; the ID token and its `auth_time`/`nonce` stay with the
/// original code exchange.
///
/// # Errors
///
/// Returns `Err(())` if `signer`'s algorithm is not permitted by `policy` or the
/// signing backend fails; the caller maps that to a token-endpoint `server_error`,
/// so a signing failure fails the refresh closed. The opaque path is infallible.
pub fn mint_access_token(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
    target: &AccessTokenTarget,
) -> Result<MintedRefreshAccess, ()> {
    let now = state.now();
    let (access, permission_budget) = mint_access(state, signer, policy, request, target, now)?;
    Ok(MintedRefreshAccess {
        access,
        expires_in_secs: secs(target.ttl),
        permission_budget,
    })
}

/// Mint the access token for `target`, in whichever format it selects (issue #29,
/// #21). Shared by the code exchange ([`mint`]) and the refresh grant
/// ([`mint_access_token`]), so a refreshed access token is byte-shaped identically
/// to a freshly issued one.
///
/// Also returns what the permission budget decided (issue #98), for the event the
/// async caller records.
///
/// # An OPAQUE access token can never carry permissions
///
/// The opaque branch answers [`PermissionBudgetOutcome::NotApplicable`] unconditionally
/// and does not even look at [`MintRequest::permissions`]. That is not a policy this
/// function applies, it is a restatement of what [`mint_opaque_access`] is: a
/// reference token carries NO claims at all, and `IntrospectionClaims` has no
/// extension point to put one in. Permissions are an `at+jwt` feature or they do not
/// exist. `an_opaque_access_token_can_never_carry_permissions` asserts it rather than
/// leaving it to be inferred from the absence of code.
fn mint_access(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
    target: &AccessTokenTarget,
    now: SystemTime,
) -> Result<(MintedAccessToken, PermissionBudgetOutcome), ()> {
    let iat = epoch_secs(now);
    let access_exp = iat.saturating_add(secs(target.ttl));
    match target.format {
        // RFC 9068 at+jwt: the header typ is `at+jwt` and the claims carry the
        // section 2.2 set, signed through the same policy-enforced core as the ID
        // token, so an algorithm the policy forbids is refused before signing.
        TokenFormat::AtJwt => mint_at_jwt(state, signer, policy, request, target, iat, access_exp),
        // Opaque: a scope-declaring reference token; only its digest and metadata
        // are stored (the caller records them in the redeem transaction). The token
        // embeds its own `jti` as the routing handle, so the digest is over the
        // WHOLE token (handle + secret) the client presents.
        TokenFormat::Opaque => Ok((
            mint_opaque_access(state, &request.scope, target, now),
            PermissionBudgetOutcome::NotApplicable,
        )),
    }
}

/// Mint the RFC 9068 `at+jwt` access token, applying the issue #98 permission budget
/// to decide which of the three [`PermissionClaim`] shapes it carries.
///
/// # The algorithm, and why the size is measured rather than estimated
///
/// With no resolved permission set (no organization context, or a target whose
/// audiences did not unanimously opt in) nothing here runs: the claims are built
/// once, exactly as before issue #98, and the outcome is
/// [`PermissionBudgetOutcome::NotApplicable`]. This is the overwhelmingly common
/// path and it pays nothing.
///
/// With a set in play:
///
/// 1. Build and serialize the claims WITHOUT `permissions` and WITH the
///    `permissions_status` a withholding would carry. That is precisely the token
///    that SHIPS if the budget withholds, so measuring it is the honest value for
///    [`PermissionBudgetOutcome::Withheld::roles_only_token_bytes`]; measuring a
///    form that omitted the status too would under-report by the status claim's own
///    bytes.
/// 2. Hand the ELEMENT count and that measurement to
///    [`crate::permission_budget::decide`], with the full-token measurement as a
///    THUNK. The element bound settles a large set without serializing it at all.
/// 3. If the thunk ran, its serialized bytes are RETAINED and reused for signing, so
///    a mint costs at most two serializations, never three.
///
/// The sizes are [`compact_len`] over [`protected_header`] and the payload, which is
/// EXACT rather than an estimate: `sign_jws` composes its compact form from these
/// same bytes through that same header builder. An estimate would be a lie in the
/// direction that matters, because it would withhold a claim that in fact fit.
///
/// The budget is read from the state's `[token_claims]` section here rather than
/// threaded in on [`MintRequest`]. One source, no wiring point for a caller to miss,
/// and no way for two call sites to hand the mint two different budgets.
fn mint_at_jwt(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
    target: &AccessTokenTarget,
    iat: i64,
    exp: i64,
) -> Result<(MintedAccessToken, PermissionBudgetOutcome), ()> {
    let jti = IssuedTokenId::generate(state.env(), &request.scope);
    let jti_text = jti.to_string();
    let audience = target.aud_claim();
    let options = EmissionOptions::new().with_token_typ(TokenTyp::AccessToken);
    let build = |permission: PermissionClaim<'_>| {
        build_access_token_claims(request, iat, exp, &jti_text, &audience, permission)
    };

    // The header is built ONLY when there is a permission set to weigh. Hoisting it out of the
    // branch made every no-permission mint -- which the comment above calls the overwhelmingly
    // common path -- allocate and serialize a header that `at_jwt_payload` then returns without
    // reading. An empty slice is the honest stand-in on the path that never measures anything.
    let header = if request.permissions.is_some() {
        protected_header(signer, &options).map_err(|_| ())?
    } else {
        Vec::new()
    };
    let (payload, outcome) = at_jwt_payload(
        &PermissionBudget::from_config(state.token_claims()),
        request,
        &header,
        signer.signature_len(),
        &build,
    )?;

    let token = sign_jws_with_policy(policy, signer, &payload, &options).map_err(|_| ())?;
    Ok((MintedAccessToken::Jwt { token, jti }, outcome))
}

/// Decide the permission claim and produce the EXACT bytes that will be signed.
///
/// Extracted from [`mint_at_jwt`] so the decision can be exercised without an [`OidcState`], a
/// signer, or a database. That is not a tidiness refactor: the property this function carries is
/// that **the bytes measured are the bytes signed**, and before it existed the only test of that
/// property compared two calls to the claim builder and never reached
/// [`crate::permission_budget::decide`] at all. A mutation that measured a bag-stripped build
/// while shipping the real one -- literally "the budget judges a token smaller than the one that
/// ships" -- left the whole suite green.
///
/// Returns the payload to sign and what the budget decided.
///
/// # Errors
///
/// `Err(())` if a claim set fails to serialize, which the caller maps to a `server_error` so a
/// mint failure fails closed.
fn at_jwt_payload(
    budget: &PermissionBudget,
    request: &MintRequest<'_>,
    header: &[u8],
    signature_len: usize,
    build: &dyn Fn(PermissionClaim<'_>) -> serde_json::Value,
) -> Result<(Vec<u8>, PermissionBudgetOutcome), ()> {
    let Some(permissions) = request.permissions else {
        return Ok((
            serde_json::to_vec(&build(PermissionClaim::Absent)).map_err(|_| ())?,
            PermissionBudgetOutcome::NotApplicable,
        ));
    };

    let status = PermissionStatus::from(budget.overflow);
    let withheld = serde_json::to_vec(&build(PermissionClaim::Withheld(status))).map_err(|_| ())?;
    let withheld_len = compact_len(header, &withheld, signature_len);
    let mut full: Option<Vec<u8>> = None;
    let outcome = permission_budget::decide(budget, Some(permissions.len()), withheld_len, || {
        let bytes =
            serde_json::to_vec(&build(PermissionClaim::Set(permissions))).map_err(|_| ())?;
        let len = compact_len(header, &bytes, signature_len);
        full = Some(bytes);
        Ok(len)
    })?;
    Ok(match outcome {
        // The thunk necessarily ran to reach this variant, so the retained bytes are present;
        // `ok_or` rather than an unwrap keeps the unreachable case a fail-closed error instead
        // of a panic on the issuance path.
        PermissionBudgetOutcome::Emitted { .. } => (full.ok_or(())?, outcome),
        PermissionBudgetOutcome::Withheld { .. } | PermissionBudgetOutcome::NotApplicable => {
            (withheld, outcome)
        }
    })
}

/// Mint an OPAQUE access token for `target` (issue #29): the scope-declaring
/// `ira_at_` reference token plus its digest and metadata for `opaque_access_tokens`.
/// An opaque token carries no claims, so this is shared verbatim by the code
/// exchange, the refresh grant, and the client-credentials grant (issue #23): every
/// opaque access token IronAuth issues is byte-shaped identically regardless of the
/// grant that minted it.
fn mint_opaque_access(
    state: &OidcState,
    scope: &Scope,
    target: &AccessTokenTarget,
    now: SystemTime,
) -> MintedAccessToken {
    let jti = IssuedTokenId::generate(state.env(), scope);
    let token = generate_opaque_access_token(state, &jti);
    let digest = opaque_access_token_digest(&token);
    let expires_at_unix_micros = epoch_micros(now).saturating_add(micros(target.ttl));
    MintedAccessToken::Opaque {
        token,
        digest,
        jti,
        audiences: target.audiences.clone(),
        expires_at_unix_micros,
    }
}

/// A freshly minted refresh token (issue #21): the plaintext handed to the client
/// (NEVER stored) plus the digest-only material the store records.
pub struct MintedRefreshToken {
    /// The `ira_rt_...` plaintext token, returned to the client and never persisted.
    pub token: String,
    /// The SHA-256 hex digest of `token`, the only token material stored.
    pub digest: String,
    /// The token's logical `rft_` identifier (its embedded routing handle).
    pub jti: RefreshTokenId,
}

/// Mint a refresh token under `scope` (issue #21): a fresh `rft_` routing handle,
/// the [`OPAQUE_REFRESH_TOKEN_PREFIX`], the [`OPAQUE_ACCESS_TOKEN_DELIMITER`], and
/// 256 bits of entropy from the ironauth-env seam, exactly mirroring the opaque
/// access token. The whole-token SHA-256 digest is what the store persists; a
/// forged handle resolves to nothing (the digest binds the handle to the secret,
/// so a token cannot be relocated to another scope), and a database dump yields
/// nothing replayable.
#[must_use]
pub fn mint_refresh_token(state: &OidcState, scope: &Scope) -> MintedRefreshToken {
    let jti = RefreshTokenId::generate(state.env(), scope);
    let mut bytes = [0_u8; OPAQUE_ACCESS_TOKEN_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    let token = format!(
        "{OPAQUE_REFRESH_TOKEN_PREFIX}{jti}{OPAQUE_ACCESS_TOKEN_DELIMITER}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    );
    let digest = refresh_token_digest(&token);
    MintedRefreshToken { token, digest, jti }
}

/// Mint ONLY an ID token, for the front-channel `id_token` and `code id_token`
/// flows (issue #17). It reuses the EXACT same claim assembly
/// ([`build_id_token_claims`]) and signing path as [`mint`]; it never mints an
/// access token, because the authorization endpoint never issues one (RFC 9700
/// 2.1.2, a permanent non-goal). The ID token's lifetime matches a token-endpoint
/// ID token (the configured `id_token_ttl_secs`), and its `jti` is drawn from
/// the entropy seam and returned so the caller can record it against the grant (or
/// simply meter it, for the stateless implicit flow).
///
/// The hybrid flow supplies [`MintRequest::c_hash`] (the hash of the issued
/// `code`); the pure implicit flow leaves it `None`. Both leave
/// [`MintRequest::at_hash`] `None`: no access token exists to hash.
///
/// # Errors
///
/// `Err(())` if the ID token claims are refused (an out-of-bounds `sub`),
/// `signer`'s algorithm is not permitted by `policy`, or the signing backend
/// fails; the caller maps that to a `server_error` returned via the negotiated
/// response mode, so the front channel fails closed.
pub fn mint_id_token(
    state: &OidcState,
    signer: &SigningKey,
    policy: &SigningPolicy,
    request: &MintRequest<'_>,
) -> Result<(String, IssuedTokenId), ()> {
    let now = state.now();
    let iat = epoch_secs(now);
    // The SAME id-token lifetime a token-endpoint ID token gets (issue #192): the
    // front channel does not get a different receipt lifetime from the back one.
    let exp = iat.saturating_add(secs(state.id_token_ttl()));
    let id_jti = IssuedTokenId::generate(state.env(), &request.scope);
    let id_claims =
        build_id_token_claims(request, iat, exp, &id_jti.to_string()).map_err(|error| {
            tracing::error!(
                ?error,
                "refusing to issue a front-channel ID token with an invalid subject"
            );
        })?;
    // Honor a per-client ID-token signing key when supplied (issue #30), else the
    // environment default. The front-channel caller passes [`None`]: a DCR client
    // registers `response_types = ["code"]` only, so it can never reach this path,
    // and the front-channel `c_hash` algorithm is derived from the same `signer`.
    let id_signer = request.id_token_signer.unwrap_or(signer);
    let id_token = sign_jws_with_policy(
        policy,
        id_signer,
        &serde_json::to_vec(&id_claims).map_err(|_| ())?,
        &EmissionOptions::new().with_token_typ(TokenTyp::IdToken),
    )
    .map_err(|_| ())?;
    Ok((id_token, id_jti))
}

/// Whole seconds of a duration as an `i64` (saturating).
fn secs(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

/// Whole microseconds of a duration as an `i64` (saturating).
fn micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

/// Seconds since the Unix epoch for a wall-clock instant.
fn epoch_secs(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Microseconds since the Unix epoch for a wall-clock instant (the opaque token's
/// expiry is stored in this unit, matching the store's clock-seam convention).
fn epoch_micros(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod access_extra_claims_tests {
    use super::*;
    use serde_json::json;

    /// A budget that refuses nothing, built from the shipped config default so this test never
    /// has to name the private overflow enum.
    fn generous_budget() -> crate::permission_budget::PermissionBudget {
        let mut budget = crate::permission_budget::PermissionBudget::from_config(
            &ironauth_config::TokenClaimsConfig::default(),
        );
        budget.max_token_bytes = usize::MAX;
        budget.warn_token_bytes = usize::MAX;
        budget.max_permission_count = 100;
        budget.warn_permission_count = 100;
        budget
    }

    fn bag(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect()
    }

    /// A claim in the access bag reaches the ACCESS token, and so does the next one.
    ///
    /// TWO admissible claims with a protected one BETWEEN them in sort order (`account_tier`,
    /// `aud`, `region`). With a single-entry bag, folding only the first entry
    /// (`.iter().take(1)`) passes: a hook returning two claims would have the alphabetically
    /// later one silently dropped while reporting both as accepted. The protected name sitting
    /// between them also means a fold that stopped AT the fence would drop `region`.
    #[test]
    fn an_access_extra_claim_lands_in_the_access_token() {
        let extra = bag(&[
            ("aud", json!("forged")),
            ("account_tier", json!("gold")),
            ("region", json!("eu")),
        ]);
        let mut req = super::tests::request("usr_abc", "pwd");
        let extra_mapped =
            crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(extra.clone());
        req.access_extra_claims = &extra_mapped;
        let claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(claims["account_tier"], "gold");
        assert_eq!(
            claims["region"], "eu",
            "the second admissible claim must land too, not only the first"
        );
        assert_ne!(
            claims["aud"], "forged",
            "the protected claim sits between the two admissible ones and must still be refused"
        );
    }

    /// The two bags are separate: neither feeds the other's token.
    ///
    /// The whole reason for a second field rather than reusing `extra_claims`. If one bag fed
    /// both, a hook placing a claim in the ID token would silently place it in the access token
    /// too, and the contract's two lists would be one list wearing two names.
    #[test]
    fn the_two_claim_bags_do_not_feed_each_others_tokens() {
        let id_only = bag(&[("id_side", json!(1))]);
        let access_only = bag(&[("access_side", json!(1))]);
        let mut req = super::tests::request("usr_abc", "pwd");
        req.extra_claims = &id_only;
        let access_only_mapped =
            crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(access_only.clone());
        req.access_extra_claims = &access_only_mapped;

        let id = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(id["id_side"], 1);
        assert!(
            id.get("access_side").is_none(),
            "an access-bag claim must not reach the ID token"
        );

        let access = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(access["access_side"], 1);
        assert!(
            access.get("id_side").is_none(),
            "an ID-bag claim must not reach the access token"
        );
    }

    /// The channel is fenced, not merely the writer.
    ///
    /// Every reserved name, not a sample, and asserted for the case that matters most: a claim
    /// the protocol did NOT set on this token. `or_insert_with` would happily insert `cnf` on a
    /// no-binding session, so ordering alone is no fence.
    #[test]
    fn the_access_bag_cannot_set_any_reserved_claim() {
        for name in PROTECTED_ACCESS_TOKEN_CLAIMS {
            let extra = bag(&[(name, json!("forged"))]);
            let mut req = super::tests::request("usr_abc", "pwd");
            req.org_id = None;
            req.confirmation = None;
            let extra_mapped =
                crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(extra.clone());
            req.access_extra_claims = &extra_mapped;
            let claims = build_access_token_claims(
                &req,
                1,
                2,
                "tok",
                &json!("cli_example"),
                PermissionClaim::Absent,
            );
            assert_ne!(
                claims
                    .get(*name)
                    .map(|value| value.as_str() == Some("forged")),
                Some(true),
                "{name} was forged through the access-token extra bag"
            );
        }
    }

    /// Every claim the access-token builder can emit, on EVERY branch, is a PROTECTED name.
    ///
    /// This is the property that makes the fence sufficient, and it is the one worth pinning.
    /// The fold uses `entry().or_insert_with()` so a protocol claim wins on ordering as well as
    /// on the fence, but that ordering is currently unexercisable: the fence drops every
    /// protected name first, and every name the builder emits is protected, so no value ever
    /// reaches the insert whose key the protocol already set. Swapping `or_insert_with` for a
    /// plain `insert` is therefore an EQUIVALENT mutation, verified by running it.
    ///
    /// That equivalence is a fact about today's builder, not a law. The moment someone emits an
    /// issuer claim whose name is NOT in the protected set, the ordering stops being redundant
    /// and starts being the only thing preventing a hook from overwriting it -- and this test
    /// is what turns red to say so.
    ///
    /// EVERY BRANCH. The first version of this test populated `org_id` and one permission
    /// variant and took 10 of the builder's 16 emission sites; an unprotected claim added
    /// beside `cnf`, `act`, `roles` or `permissions_status` went unchecked, and four mutants
    /// proved it. The second version set ten of `MintRequest`'s twelve optional fields, and the
    /// two it missed let a claim gated on `request.permissions` through untouched.
    ///
    /// The fixture sets every optional field the builder could read, including the ones it
    /// ignores today, and the assertion is over the UNION of all THREE permission variants --
    /// the two that emit a claim are mutually exclusive by construction, so no single call can
    /// see the other's. `id_token_signer` is the one field left unset, because it is an
    /// ID-token concern this builder has no access to.
    #[test]
    fn every_claim_the_access_builder_sets_is_protected() {
        let roles = super::tests::role_set(&["admin", "billing"]);
        let permissions: std::collections::BTreeSet<String> =
            ["billing.read".to_owned()].into_iter().collect();
        let confirmation = ironauth_jose::Confirmation::Jkt("thumbprint".to_owned());
        let mut req = super::tests::request("usr_abc", "pwd");
        req.org_id = Some("org_real");
        req.oauth_scope = Some("openid profile");
        req.auth_time_unix_micros = Some(1_700_000_000_000_000);
        // The four the builder ignores TODAY. Setting them costs nothing and fires the moment
        // one of them starts being emitted: adding `claims["session_id"] = json!(sid)` was a
        // real mutant that survived, because a field the fixture leaves None cannot be checked.
        req.nonce = Some("n-once");
        req.sid = Some("sess_1");
        req.at_hash = Some("athash");
        req.c_hash = Some("chash");
        // `permissions` too, and it is not redundant with the loop below: the loop varies the
        // PermissionClaim the caller passes, while this is the field the BUILDER reads. A claim
        // gated on `request.permissions` -- `claims["permission_count"] = json!(resolved.len())`
        // -- is emitted on neither of those loop variants unless this is set, and it passed 848
        // tests unprotected. The builder ignores the field today, so the emitted set and the
        // count of 16 do not move.
        req.permissions = Some(&permissions);
        req.actor = Some(TokenActor {
            subject: "usr_admin",
            reason_code: "support",
        });
        req.roles = Some(&roles);
        req.confirmation = Some(&confirmation);

        let mut emitted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for permission in [
            PermissionClaim::Set(&permissions),
            PermissionClaim::Withheld(PermissionStatus::BudgetExceeded),
            PermissionClaim::Absent,
        ] {
            let claims =
                build_access_token_claims(&req, 1, 2, "tok", &json!("cli_example"), permission);
            for name in claims.as_object().expect("an object").keys() {
                emitted.insert(name.clone());
            }
        }

        // The loop covering nothing, or covering one branch, would satisfy the assertion below.
        // The EXACT count, not a floor. At `>= 15` an unconditional claim could be deleted and
        // the assertion would still hold; an exact count also forces anyone ADDING one to look
        // at this test rather than sail past a threshold.
        assert_eq!(
            emitted.len(),
            16,
            "the fixture must take every branch and emit exactly the known set: {emitted:?}"
        );
        for name in &emitted {
            assert!(
                PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&name.as_str()),
                "`{name}` is emitted by the builder but is NOT protected, so the extra-claims \
                 fence no longer covers everything the protocol sets and the fold's ordering \
                 has become load-bearing: give it its own test"
            );
        }
        // The specific branches the first version missed, named so a fixture that stops
        // populating one of them fails here rather than silently shrinking the check.
        for name in [
            "cnf",
            "act",
            "roles",
            "permissions",
            "permissions_status",
            "scope",
            "auth_time",
            "org_id",
        ] {
            assert!(
                emitted.contains(name),
                "the fixture no longer takes the `{name}` branch, so nothing checks it"
            );
        }
    }

    /// A protocol claim the mint DID set is not overwritten.
    #[test]
    fn a_protocol_claim_wins_over_the_access_bag() {
        let extra = bag(&[
            ("sub", json!("attacker")),
            ("iss", json!("https://evil.test")),
        ]);
        let mut req = super::tests::request("usr_abc", "pwd");
        let extra_mapped =
            crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(extra.clone());
        req.access_extra_claims = &extra_mapped;
        let claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(claims["sub"], "usr_abc");
        assert_ne!(claims["iss"], "https://evil.test");
    }

    /// An access-token extra claim can flip the budget's VERDICT.
    ///
    /// This is the PR's load-bearing claim, asserted on the budget's own decision rather than on
    /// a proxy. The previous version of this test serialized the claim builder twice and
    /// compared lengths; it never constructed a `PermissionBudget` and never called `decide`, so
    /// a mutation that measured a bag-stripped build while SHIPPING the real one -- exactly "the
    /// budget judges a token smaller than the one that ships" -- left the whole suite green.
    ///
    /// The bound is chosen from the measurement: mint once with an empty bag, read the emitted
    /// size, and set `max_token_bytes` to exactly that. The same request with one more claim
    /// must then be over. If the extra claim were folded in after the decision, the second run
    /// would still fit and would still be Emitted.
    #[test]
    fn an_access_extra_claim_can_push_the_budget_over() {
        use crate::permission_budget::{PermissionBudget, PermissionBudgetOutcome};

        let permissions: std::collections::BTreeSet<String> =
            ["billing.read".to_owned(), "billing.write".to_owned()]
                .into_iter()
                .collect();
        let mut req = super::tests::request("usr_abc", "pwd");
        req.permissions = Some(&permissions);

        // A stand-in for the signing header and signature: their exact contents do not matter,
        // only that the SAME values are used for both runs, so the difference between them is
        // the extra claim and nothing else.
        let header = b"header";
        let signature_len = 64;
        let generous = generous_budget();
        let audience = json!("cli_example");
        let build_base = |permission: PermissionClaim<'_>| {
            build_access_token_claims(&req, 1, 2, "tok", &audience, permission)
        };
        let (baseline_bytes, baseline) =
            at_jwt_payload(&generous, &req, header, signature_len, &build_base)
                .expect("baseline mints");
        assert!(
            matches!(baseline, PermissionBudgetOutcome::Emitted { .. }),
            "the baseline must EMIT, or the test measures nothing: {baseline:?}"
        );
        let exactly_fits = super::compact_len(header, &baseline_bytes, signature_len);

        // At exactly the emitted size, the same request still fits.
        let tight = PermissionBudget {
            max_token_bytes: exactly_fits,
            ..generous
        };
        let (_, still_fits) = at_jwt_payload(&tight, &req, header, signature_len, &build_base)
            .expect("mints at the bound");
        assert!(
            matches!(still_fits, PermissionBudgetOutcome::Emitted { .. }),
            "the bound is inclusive of the token that produced it: {still_fits:?}"
        );

        // One more claim, same bound: the budget must now WITHHOLD. It can only know that if the
        // claim is inside the bytes it measured.
        let extra = bag(&[("account_tier", json!("g".repeat(64)))]);
        let mut with_extra = super::tests::request("usr_abc", "pwd");
        with_extra.permissions = Some(&permissions);
        let extra_mapped =
            crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(extra.clone());
        with_extra.access_extra_claims = &extra_mapped;
        let build_extra = |permission: PermissionClaim<'_>| {
            build_access_token_claims(&with_extra, 1, 2, "tok", &audience, permission)
        };
        let (_, over) = at_jwt_payload(&tight, &with_extra, header, signature_len, &build_extra)
            .expect("mints over the bound");
        assert!(
            matches!(over, PermissionBudgetOutcome::Withheld { .. }),
            "an extra claim must be inside what the budget measures, or #98 is an estimate \
             rather than a guarantee: {over:?}"
        );
    }

    /// The size reported for a WITHHELD token is the size of the token that ships.
    ///
    /// The mirror of the emitted-path check, and it needs its own test: under-measuring the
    /// withheld variant does not change the verdict, so the flip test cannot see it. What it
    /// corrupts is `roles_only_token_bytes`, which the module doc calls "the exact compact-token
    /// size of the token that SHIPS" and which an operator reads to decide whether the fallback
    /// is itself over budget. A number measured against a form that never shipped answers that
    /// question wrongly.
    #[test]
    fn a_withheld_token_reports_the_size_it_actually_ships() {
        use crate::permission_budget::{PermissionBudgetOutcome, PermissionWithheldReason};

        let permissions: std::collections::BTreeSet<String> =
            (0..40).map(|index| format!("scope.{index:03}")).collect();
        let extra = bag(&[("account_tier", json!("g".repeat(128)))]);
        let mut req = super::tests::request("usr_abc", "pwd");
        req.permissions = Some(&permissions);
        let extra_mapped =
            crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(extra.clone());
        req.access_extra_claims = &extra_mapped;

        let header = b"header";
        let signature_len = 64;
        // A count bound the set exceeds, so the withholding is certain and the test does not
        // depend on byte arithmetic to reach the branch it is about.
        let mut budget = generous_budget();
        budget.max_permission_count = 5;
        budget.warn_permission_count = 5;

        let audience = json!("cli_example");
        let build = |permission: PermissionClaim<'_>| {
            build_access_token_claims(&req, 1, 2, "tok", &audience, permission)
        };
        let (payload, outcome) =
            at_jwt_payload(&budget, &req, header, signature_len, &build).expect("mints");

        let PermissionBudgetOutcome::Withheld {
            reason,
            roles_only_token_bytes,
            ..
        } = outcome
        else {
            panic!("a count of 40 against a bound of 5 must withhold: {outcome:?}");
        };
        assert_eq!(reason, PermissionWithheldReason::CountExceeded);
        assert_eq!(
            roles_only_token_bytes,
            super::compact_len(header, &payload, signature_len),
            "the reported withheld size must be the size of the payload that ships"
        );
        let text = String::from_utf8(payload).expect("utf-8");
        assert!(
            text.contains("account_tier"),
            "the shipped withheld token carries the extra claim, so the measurement must too"
        );
        assert!(
            !text.contains("\"permissions\":"),
            "a withheld token must not carry the permission claim"
        );
        assert!(
            text.contains("permissions_status"),
            "a withheld token must carry the status marker that tells a resource server WHY, \
             or dropping the marker entirely turns nothing red"
        );
    }

    /// A BYTE-bound withholding also ships the payload it measured.
    ///
    /// The count-bound test cannot see this. `decide` returns `CountExceeded` before it ever
    /// calls the thunk, so the `full` bytes are never produced and the branch that CHOOSES
    /// between `full` and `withheld` is never exercised. Under a byte bound the thunk DOES run,
    /// `full` is `Some`, and returning it on a withholding -- `full.unwrap_or(withheld)` --
    /// ships the oversized token the budget just refused, with every other test green.
    #[test]
    fn a_byte_bound_withholding_ships_the_roles_only_token() {
        use crate::permission_budget::{PermissionBudgetOutcome, PermissionWithheldReason};

        let permissions: std::collections::BTreeSet<String> =
            ["billing.read".to_owned(), "billing.write".to_owned()]
                .into_iter()
                .collect();
        let mut req = super::tests::request("usr_abc", "pwd");
        req.permissions = Some(&permissions);

        let header = b"header";
        let signature_len = 64;
        let audience = json!("cli_example");
        let build = |permission: PermissionClaim<'_>| {
            build_access_token_claims(&req, 1, 2, "tok", &audience, permission)
        };

        // Measure the roles-only form, then set the bound to exactly it: the full form is
        // strictly larger, so the count passes and the BYTES are what withhold.
        let withheld_only = serde_json::to_vec(&build(PermissionClaim::Withheld(
            crate::permission_budget::PermissionStatus::from(generous_budget().overflow),
        )))
        .expect("serialize");
        let bound = super::compact_len(header, &withheld_only, signature_len);

        let mut budget = generous_budget();
        budget.max_token_bytes = bound;
        budget.warn_token_bytes = bound;

        let (payload, outcome) =
            at_jwt_payload(&budget, &req, header, signature_len, &build).expect("mints");
        let PermissionBudgetOutcome::Withheld {
            reason,
            roles_only_token_bytes,
            ..
        } = outcome
        else {
            panic!("the full form must not fit under its own roles-only size: {outcome:?}");
        };
        assert!(
            matches!(reason, PermissionWithheldReason::ByteExceeded { .. }),
            "this test exists to reach the BYTE branch, not the count one: {reason:?}"
        );
        assert_eq!(
            roles_only_token_bytes,
            super::compact_len(header, &payload, signature_len),
            "the reported size must be the size of the payload that ships"
        );
        let text = String::from_utf8(payload).expect("utf-8");
        assert!(
            !text.contains("\"permissions\":"),
            "the SHIPPED payload must be the roles-only one, not the oversized form the budget \
             just refused"
        );
        assert!(text.contains("permissions_status"));
    }

    /// A mint with no permission set reports `NotApplicable` and stamps no marker.
    ///
    /// The extracted function's third branch. Without this, replacing its `PermissionClaim::
    /// Absent` with a withholding stamps `permissions_status` on every token for a subject with
    /// no organization context -- telling every resource server a set was withheld when none
    /// existed -- and nothing turns red.
    #[test]
    fn a_mint_with_no_permission_set_is_not_applicable_and_marks_nothing() {
        use crate::permission_budget::PermissionBudgetOutcome;

        let req = super::tests::request("usr_abc", "pwd");
        assert!(req.permissions.is_none(), "the fixture must have no set");
        let audience = json!("cli_example");
        let build = |permission: PermissionClaim<'_>| {
            build_access_token_claims(&req, 1, 2, "tok", &audience, permission)
        };
        let (payload, outcome) =
            at_jwt_payload(&generous_budget(), &req, b"header", 64, &build).expect("mints");
        assert!(
            matches!(outcome, PermissionBudgetOutcome::NotApplicable),
            "no set in play is NotApplicable: {outcome:?}"
        );
        let text = String::from_utf8(payload).expect("utf-8");
        assert!(!text.contains("\"permissions\":"));
        assert!(
            !text.contains("permissions_status"),
            "a token for a subject with no org context must not claim a set was withheld"
        );
    }

    /// The bytes the budget measured are the bytes that get signed.
    ///
    /// The other half of the same guarantee: a token judged to fit must be the token that
    /// ships. Asserted by re-measuring the returned payload against the bound it was judged
    /// under.
    #[test]
    fn the_measured_payload_is_the_returned_payload() {
        use crate::permission_budget::PermissionBudgetOutcome;

        let permissions: std::collections::BTreeSet<String> =
            ["billing.read".to_owned()].into_iter().collect();
        let extra = bag(&[("account_tier", json!("gold"))]);
        let mut req = super::tests::request("usr_abc", "pwd");
        req.permissions = Some(&permissions);
        let extra_mapped =
            crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(extra.clone());
        req.access_extra_claims = &extra_mapped;

        let header = b"header";
        let signature_len = 64;
        let budget = generous_budget();
        let build = |permission: PermissionClaim<'_>| {
            build_access_token_claims(&req, 1, 2, "tok", &json!("cli_example"), permission)
        };
        let (payload, outcome) =
            at_jwt_payload(&budget, &req, header, signature_len, &build).expect("mints");

        let PermissionBudgetOutcome::Emitted { token_bytes, .. } = outcome else {
            panic!("a generous budget must emit: {outcome:?}");
        };
        assert_eq!(
            token_bytes,
            super::compact_len(header, &payload, signature_len),
            "the size the budget reported must be the size of the payload it returned"
        );
        let text = String::from_utf8(payload).expect("utf-8");
        assert!(
            text.contains("account_tier"),
            "the measured payload must be the one carrying the extra claim"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_env::Env;
    use ironauth_store::{EnvironmentId, TenantId};

    /// An empty extra-claims map for the pure claim-builder tests (the spec-conform
    /// default, so the ID token stays lean).
    fn empty_extra() -> &'static serde_json::Map<String, serde_json::Value> {
        use std::sync::OnceLock;
        static EMPTY: OnceLock<serde_json::Map<String, serde_json::Value>> = OnceLock::new();
        EMPTY.get_or_init(serde_json::Map::new)
    }

    /// The same, for the typed access-token channel. A shared `'static` for the same reason:
    /// `MintRequest` holds borrows, so a temporary at each call site would not outlive it.
    fn empty_mapped_extra() -> &'static crate::claims_mapping_at_issuance::MappedAccessClaims {
        use std::sync::OnceLock;
        static EMPTY: OnceLock<crate::claims_mapping_at_issuance::MappedAccessClaims> =
            OnceLock::new();
        EMPTY.get_or_init(|| {
            crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(serde_json::Map::new())
        })
    }

    /// A minimal request over a throwaway scope, for the pure claim builder.
    /// `pub(super)` so the sibling `access_extra_claims_tests` module can build the same
    /// request these tests do, rather than keeping a second copy that could drift from it.
    pub(super) fn request<'a>(subject: &'a str, auth_methods: &'a str) -> MintRequest<'a> {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 1);
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        MintRequest {
            authorization_details: None,
            actor: None,
            scope,
            issuer: "https://issuer.test/t/x/e/y",
            subject,
            client_id: "cli_example",
            nonce: None,
            oauth_scope: None,
            auth_methods,
            auth_time_unix_micros: None,
            sid: None,
            org_id: None,
            roles: None,
            permissions: None,
            at_hash: None,
            c_hash: None,
            extra_claims: empty_extra(),
            access_extra_claims: empty_mapped_extra(),
            id_token_signer: None,
            confirmation: None,
        }
    }

    /// An owned role set for the `roles`-claim tests, deliberately built in a
    /// NON-alphabetical insertion order so an assertion on the emitted order is about
    /// the [`BTreeSet`] and not about how the test happened to write it down.
    pub(super) fn role_set(slugs: &[&str]) -> BTreeSet<String> {
        slugs.iter().map(|slug| (*slug).to_owned()).collect()
    }

    #[test]
    fn required_claims_are_present_and_amr_acr_derive_from_the_event() {
        let claims = build_id_token_claims(&request("usr_abc", "pwd"), 1000, 1300, "tok_1")
            .expect("claims build");
        assert_eq!(claims["iss"], "https://issuer.test/t/x/e/y");
        assert_eq!(claims["sub"], "usr_abc");
        assert_eq!(claims["aud"], "cli_example");
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["exp"], 1300);
        assert_eq!(claims["jti"], "tok_1");
        assert_eq!(claims["amr"], json!(["pwd"]));
        assert_eq!(claims["acr"], "urn:ironauth:acr:pwd");
        // Not requested: nonce, auth_time, at_hash, c_hash, and azp are absent.
        for absent in ["nonce", "auth_time", "at_hash", "c_hash", "azp"] {
            assert!(claims.get(absent).is_none(), "{absent} must be absent");
        }
    }

    #[test]
    fn a_federated_login_mints_the_honest_upstream_amr_passthrough_and_federated_acr() {
        // Issue #75, PR B, the honesty crux AT THE MINT: the auth_methods string a federated
        // callback persists (federated + the encoded upstream amr passthrough) flows verbatim
        // to build_id_token_claims, which emits the UPSTREAM's asserted amr VERBATIM (never a
        // fabricated local factor) and the federated-context acr.
        let event = authn::AuthenticationEvent::federated(
            0,
            &["hwk".to_owned(), "mfa".to_owned()],
            Some("aal2"),
        );
        let auth_methods = event.methods_token();
        let claims = build_id_token_claims(&request("usr_fed", &auth_methods), 1, 2, "tok")
            .expect("claims build");
        // The minted amr is EXACTLY the upstream passthrough; no local factor is invented.
        assert_eq!(claims["amr"], json!(["hwk", "mfa"]));
        assert!(!claims["amr"].as_array().unwrap().iter().any(|v| v == "pwd"));
        assert_eq!(claims["acr"], "urn:ironauth:acr:federated");

        // When the upstream asserted NO amr, the minted token asserts none.
        let silent = authn::AuthenticationEvent::federated(0, &[], None).methods_token();
        let claims =
            build_id_token_claims(&request("usr_fed", &silent), 1, 2, "tok").expect("claims build");
        assert_eq!(claims["amr"], json!([] as [&str; 0]));
        assert_eq!(claims["acr"], "urn:ironauth:acr:federated");
    }

    #[test]
    fn an_over_length_subject_fails_closed() {
        // A sub over the 255 ASCII cap is refused at issuance, never truncated.
        let over = "u".repeat(subject::MAX_SUBJECT_LEN + 1);
        assert_eq!(
            build_id_token_claims(&request(&over, "pwd"), 1, 2, "tok"),
            Err(IdTokenError::SubjectOutOfBounds),
        );
        // Exactly at the cap is admitted.
        let at = "u".repeat(subject::MAX_SUBJECT_LEN);
        assert!(build_id_token_claims(&request(&at, "pwd"), 1, 2, "tok").is_ok());
        // A non-ASCII sub is refused even within the length cap.
        assert_eq!(
            build_id_token_claims(&request("usr_café", "pwd"), 1, 2, "tok"),
            Err(IdTokenError::SubjectOutOfBounds),
        );
    }

    #[test]
    fn nonce_is_echoed_exactly_when_present() {
        let mut req = request("usr_abc", "pwd");
        req.nonce = Some("n-once-123");
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["nonce"], "n-once-123");
    }

    #[test]
    fn auth_time_is_present_and_truthful_only_when_required_including_zero() {
        // Frozen onto the code: present iff Some, always the truthful instant, in
        // epoch seconds. A recorded 1_700_000_123_456789us is 1_700_000_123s.
        let mut req = request("usr_abc", "pwd");
        req.auth_time_unix_micros = Some(1_700_000_123_456_789);
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["auth_time"], 1_700_000_123_i64);

        // The max_age=0 case still records a real (epoch-zero) auth_time, which is
        // emitted truthfully rather than omitted.
        req.auth_time_unix_micros = Some(0);
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["auth_time"], 0_i64);

        // Not required: omitted.
        req.auth_time_unix_micros = None;
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(claims.get("auth_time").is_none());
    }

    #[test]
    fn extra_claims_land_in_the_id_token_but_never_shadow_protocol_claims() {
        // Issue #15: the conformIdTokenClaims override / id_token claims-member
        // places extra standard claims in the ID token, but a protocol claim
        // (here a hostile `sub`) is never overwritten.
        let extra = json!({ "email": "ada@example.test", "sub": "attacker" })
            .as_object()
            .cloned()
            .expect("object");
        let mut req = request("usr_abc", "pwd");
        req.extra_claims = &extra;
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["email"], "ada@example.test", "extra claim lands");
        assert_eq!(claims["sub"], "usr_abc", "protocol sub is never shadowed");
    }

    #[test]
    fn org_id_is_emitted_and_a_client_custom_claim_can_never_forge_it() {
        // Issue #94, PR-B1: org_id is a PROTECTED, issuer-set claim. When the session
        // resolved an org it is emitted on both tokens, and it is set BEFORE the
        // extra-claims fold, so a hostile custom claim named `org_id` can never shadow
        // or forge it (the id-token protocol-claim-wins fold), and it is in
        // PROTECTED_ACCESS_TOKEN_CLAIMS (the access-token custom-claim guard).
        let extra = json!({ "org_id": "org_forged" })
            .as_object()
            .cloned()
            .expect("object");
        let mut req = request("usr_abc", "pwd");
        req.org_id = Some("org_real");
        req.extra_claims = &extra;
        let id_claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(
            id_claims["org_id"], "org_real",
            "the protocol org_id wins over a forged custom claim"
        );
        let at_claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(
            at_claims["org_id"], "org_real",
            "access token carries org_id"
        );
        assert!(
            PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&"org_id"),
            "org_id is a protected access-token claim"
        );

        // With no resolved org, the claim is absent on both tokens (a no-org login is
        // byte-identical to before the feature) EVEN when a hostile `org_id` is planted
        // in the extra-claims bag: for a no-org session the protocol sets no org_id, so
        // insertion-order "protocol wins" would be no protection; the id-token fold
        // filters PROTECTED_ACCESS_TOKEN_CLAIMS explicitly, so a forged org_id from the
        // bag (or the claims-request parameter) is dropped, not stamped. The access
        // token's own extra-claims bag (issue #113) is fenced identically, and is empty on
        // this path: `req.extra_claims` feeds the ID token only, so a forged `org_id` planted
        // there cannot reach the access token through the access bag either.
        req.org_id = None;
        req.extra_claims = &extra; // still { "org_id": "org_forged" }
        let id_none = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(
            id_none.get("org_id").is_none(),
            "a no-org id token drops a forged org_id from the extra-claims bag"
        );
        let at_none = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert!(
            at_none.get("org_id").is_none(),
            "a no-org access token never carries org_id"
        );
    }

    #[test]
    fn roles_are_emitted_on_the_access_token_in_total_order() {
        // Issue #97: the effective role set lands on the ACCESS token as a JSON array
        // in the BTreeSet's total order, whatever order the resolution produced. Two
        // builds over the same set are byte-identical, which is what makes a diff
        // between two issuances mean "the stored state changed" and nothing else.
        let roles = role_set(&["viewer", "admin", "billing.reader"]);
        let mut req = request("usr_abc", "pwd");
        req.roles = Some(&roles);
        let claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(
            claims["roles"],
            json!(["admin", "billing.reader", "viewer"]),
            "roles are emitted sorted, not in insertion order"
        );
        let again = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(
            serde_json::to_string(&claims).expect("serialize"),
            serde_json::to_string(&again).expect("serialize"),
            "two issuances against identical state are byte-identical"
        );
    }

    #[test]
    fn no_org_context_omits_roles_but_an_empty_set_emits_an_empty_array() {
        // Issue #97: ABSENT and EMPTY are DIFFERENT answers and both are load-bearing.
        // None means "this exchange resolved no organization context", so a resource
        // server sees no roles claim at all and must not read it as "no roles". Some of
        // an empty set means "a member of this organization holding no roles", which is
        // a positive, resolved answer and emits `[]`.
        let mut req = request("usr_abc", "pwd");
        let absent = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert!(
            absent.get("roles").is_none(),
            "no org context emits NO roles claim, not an empty array"
        );

        let empty = role_set(&[]);
        req.roles = Some(&empty);
        let present = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(
            present["roles"],
            json!([] as [&str; 0]),
            "an org member with no roles emits an EMPTY ARRAY, present and resolved"
        );
        assert!(
            present.get("roles").is_some(),
            "the empty case is present, not absent"
        );
    }

    #[test]
    fn a_client_custom_claim_can_never_forge_roles() {
        // Issue #97: `roles` is a PROTECTED, issuer-set claim, so no client-influenced
        // bag can assert one. Proved on all three folds rather than assumed from the
        // denylist's presence, and in BOTH directions: with a real issuer-set value
        // (insertion-order "protocol wins" would cover this one) and with NO issuer-set
        // value (where only the explicit filter can, which is the case that actually
        // needs the denylist entry).
        let hostile = json!({ "roles": ["admin"], "department": "payments" })
            .as_object()
            .cloned()
            .expect("object");
        let real = role_set(&["viewer"]);
        let mut req = request("usr_abc", "pwd");
        req.roles = Some(&real);
        req.extra_claims = &hostile;

        // The ID token never carries roles at all, so a hostile `roles` in the extra
        // bag must be DROPPED there rather than stamped in as the only roles claim the
        // relying party would ever see.
        let id_claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(
            id_claims.get("roles").is_none(),
            "the id token drops a forged roles claim: {id_claims}"
        );
        assert_eq!(
            id_claims["department"], "payments",
            "a benign extra claim still lands, so the drop is targeted"
        );

        // The access token carries the ISSUER's set, never the forged one.
        let at_claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(
            at_claims["roles"],
            json!(["viewer"]),
            "the issuer-resolved roles win over a forged custom claim"
        );

        // With NO org context the access token sets no roles and the id-token fold must
        // still refuse the forgery: this is the case where insertion order protects
        // nothing, so it is the one the denylist entry exists for.
        req.roles = None;
        let id_none = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(
            id_none.get("roles").is_none(),
            "a no-org id token drops a forged roles claim from the extra bag"
        );
        let at_none = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert!(
            at_none.get("roles").is_none(),
            "a no-org access token never carries roles"
        );

        assert!(
            PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&"roles"),
            "roles is a protected access-token claim"
        );
    }

    #[test]
    fn the_id_token_never_carries_roles() {
        // Issue #97, the deliberate divergence from org_id: roles ride the ACCESS token
        // only. Even with a fully resolved, non-empty set the ID token stays lean. If
        // this test ever fails because someone added the emission to
        // build_id_token_claims, read that function's doc comment before "fixing" it.
        let roles = role_set(&["admin", "viewer"]);
        let mut req = request("usr_abc", "pwd");
        req.org_id = Some("org_real");
        req.roles = Some(&roles);
        let id_claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(
            id_claims.get("roles").is_none(),
            "the id token carries NO roles claim: {id_claims}"
        );
        // org_id DOES ride both, so the asymmetry is real and not an accident of the
        // request being empty.
        assert_eq!(id_claims["org_id"], "org_real");
        let at_claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(at_claims["roles"], json!(["admin", "viewer"]));
    }

    // -----------------------------------------------------------------------
    // Issue #98: the permission claims
    // -----------------------------------------------------------------------

    /// An owned permission set, built in a NON-alphabetical insertion order so an
    /// assertion on the emitted order is about the [`BTreeSet`] rather than about how
    /// the test wrote it down.
    fn permission_set(slugs: &[&str]) -> BTreeSet<String> {
        slugs.iter().map(|slug| (*slug).to_owned()).collect()
    }

    /// The `act` claim is emitted for an impersonated token and for no other (issue #101).
    ///
    /// Both halves, because the criterion states both and the ABSENT half is the one a test
    /// gets wrong: checking only a token that was supposed to carry the claim passes just as
    /// well against an implementation that stamps `act` on everything, which would mark every
    /// ordinary session as somebody impersonating its own user.
    #[test]
    fn the_act_claim_marks_an_impersonated_token_and_only_that() {
        let ordinary = request("usr_abc", "pwd");
        let claims = build_id_token_claims(&ordinary, 100, 200, "jti_a").expect("mint");
        assert!(
            claims.get("act").is_none(),
            "an ordinary token carried an actor claim: {claims}"
        );

        let mut impersonated = request("usr_abc", "pwd");
        impersonated.actor = Some(TokenActor {
            subject: "adm_support_engineer",
            reason_code: "support_ticket",
        });
        let claims = build_id_token_claims(&impersonated, 100, 200, "jti_b").expect("mint");
        assert_eq!(
            claims["act"],
            json!({ "sub": "adm_support_engineer", "reason_code": "support_ticket" }),
            "the actor claim must carry the impersonator and the structured reason"
        );
        assert_eq!(
            claims["sub"], "usr_abc",
            "the SUBJECT stays the impersonated user; `act` says who is driving, and swapping \
             the two would make the token authorize the operator instead"
        );
    }

    /// The written justification never reaches a token.
    ///
    /// `TokenActor` has no field for it, so this is a statement about the TYPE rather than
    /// about a handler remembering to strip it. A token is read by the client, by every
    /// resource server it is presented to, and by whatever logs them; the operator sentence
    /// about an incident belongs in the audit stream, which is where the criterion puts it.
    #[test]
    fn the_written_justification_never_reaches_a_token() {
        let mut impersonated = request("usr_abc", "pwd");
        impersonated.actor = Some(TokenActor {
            subject: "adm_support_engineer",
            reason_code: "support_ticket",
        });
        let claims = build_id_token_claims(&impersonated, 100, 200, "jti_c").expect("mint");
        let rendered = claims.to_string();
        assert!(
            !rendered.contains("Ticket"),
            "no free text is carried, so nothing resembling one can appear: {rendered}"
        );
        let act = claims["act"].as_object().expect("act is an object");
        assert_eq!(
            act.len(),
            2,
            "the actor claim carries exactly `sub` and `reason_code`: {act:?}"
        );
    }

    /// A client cannot self-assert `act`.
    ///
    /// The protected-claim list is the control, and this is what says `act` is on it. Without
    /// it a client could name any impersonator it liked on a token it obtained honestly, which
    /// forges an audit trail rather than merely overstating an authorization.
    #[test]
    fn a_client_cannot_self_assert_the_actor_claim() {
        assert!(
            PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&"act"),
            "`act` must be issuer-set only"
        );
    }

    #[test]
    fn the_three_permission_wire_states_are_mutually_exclusive_and_distinguishable() {
        // Issue #98: the WHOLE contract with a resource server is that these three are
        // different answers. Driven over the one pure function that decides the wire
        // shape, so the exclusivity is a property of the emitter and not of any caller
        // happening to pass sensible arguments.
        let held = permission_set(&["orders.write", "billing.read"]);
        let empty = permission_set(&[]);
        let req = request("usr_abc", "pwd");

        // 1. ABSENT: no organization context, or a target that did not unanimously opt
        //    in. NEITHER claim. A mixed-audience suppression reaches exactly this state
        //    and must be indistinguishable from it.
        let absent = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert!(absent.get("permissions").is_none(), "{absent}");
        assert!(absent.get("permissions_status").is_none(), "{absent}");

        // 2. SET: the complete answer, in the set's total order. The empty set is the
        //    SAME state and not the absent one: it says "in this organization, holding
        //    nothing", which is a resolved answer.
        let full = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Set(&held),
        );
        assert_eq!(
            full["permissions"],
            json!(["billing.read", "orders.write"]),
            "sorted, not in insertion order: {full}"
        );
        assert!(
            full.get("permissions_status").is_none(),
            "an emitted set carries NO status: {full}"
        );
        let none_held = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Set(&empty),
        );
        assert_eq!(none_held["permissions"], json!([] as [&str; 0]));
        assert!(none_held.get("permissions").is_some());

        // 3. WITHHELD: the status, and NO set. Never a prefix: the withheld state
        //    carries no set to shorten, so this arm cannot emit one at all.
        for (status, wire) in [
            (PermissionStatus::BudgetExceeded, "budget_exceeded"),
            (PermissionStatus::PdpRequired, "pdp_required"),
        ] {
            let withheld = build_access_token_claims(
                &req,
                1,
                2,
                "tok",
                &json!("cli_example"),
                PermissionClaim::Withheld(status),
            );
            assert_eq!(withheld["permissions_status"], wire, "{withheld}");
            assert!(
                withheld.get("permissions").is_none(),
                "a withholding emits no set, complete or partial: {withheld}"
            );
        }

        // Two builds of the same state are byte-identical, which is what makes the byte
        // budget's measurement mean anything.
        let again = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Set(&held),
        );
        assert_eq!(
            serde_json::to_string(&full).expect("serialize"),
            serde_json::to_string(&again).expect("serialize"),
        );
    }

    #[test]
    fn a_client_custom_claim_can_never_forge_permissions_or_their_status() {
        // Issue #98: BOTH names are protected, for two DIFFERENT reasons. `permissions`
        // names an API capability, so a forged one is a capability nobody granted.
        // `permissions_status` grants nothing, but forging its ABSENCE, or a weaker
        // value, convinces a resource server that a WITHHELD set was simply an empty
        // one, which is a downgrade it cannot detect.
        //
        // Proved through the real forgery paths rather than asserted from the denylist,
        // and in the direction that actually needs the denylist entry: with NO
        // issuer-set value, where insertion-order "protocol wins" protects nothing.
        let hostile = json!({
            "permissions": ["billing.admin"],
            "permissions_status": "pdp_required",
            "department": "payments",
        })
        .as_object()
        .cloned()
        .expect("object");
        let held = permission_set(&["orders.read"]);
        let mut req = request("usr_abc", "pwd");
        req.extra_claims = &hostile;

        // The ID token never carries either claim, so both must be DROPPED there rather
        // than stamped in as the only permission claim a relying party would ever see.
        let id_claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(
            id_claims.get("permissions").is_none(),
            "the id token drops a forged permissions claim: {id_claims}"
        );
        assert!(
            id_claims.get("permissions_status").is_none(),
            "and a forged status: {id_claims}"
        );
        assert_eq!(
            id_claims["department"], "payments",
            "a benign extra claim still lands, so the drop is TARGETED"
        );

        // The access token carries the ISSUER's decision, never the forged one. The access
        // token now has its own extra-claims bag (issue #113, `access_extra_claims`), fenced
        // against PROTECTED_ACCESS_TOKEN_CLAIMS exactly as this one is -- and it is EMPTY on
        // this path, because this test drives `req.extra_claims` only. So the guarantee here is
        // still that the builder's own output is unaffected by the ID-token bag, and the access
        // bag's own fence is proved by `the_access_bag_cannot_set_any_reserved_claim`.
        let at_claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Set(&held),
        );
        assert_eq!(
            at_claims["permissions"],
            json!(["orders.read"]),
            "the issuer-resolved set wins: {at_claims}"
        );
        assert!(
            at_claims.get("permissions_status").is_none(),
            "and the forged status never appears beside it: {at_claims}"
        );

        // The MACHINE path merges a client's STORED custom claims, so it is the fold
        // where a stored `{"permissions": [...]}` would actually be reachable. It is
        // dropped by the same explicit reserved-name filter.
        let cc_request = ClientCredentialsMintRequest {
            org_id: None,
            roles: None,
            scope: req.scope,
            issuer: "https://issuer.test/t/x/e/y",
            subject: "sva_machine",
            client_id: "cli_example",
            oauth_scope: None,
            custom_claims: &crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(
                hostile.clone(),
            ),
            act: None,
        };
        let cc_claims = build_client_credentials_access_token_claims(
            &cc_request,
            1,
            2,
            "tok",
            &json!("cli_example"),
        );
        assert!(
            cc_claims.get("permissions").is_none(),
            "a machine token drops a stored permissions claim: {cc_claims}"
        );
        assert!(
            cc_claims.get("permissions_status").is_none(),
            "and a stored status: {cc_claims}"
        );
        assert_eq!(
            cc_claims["department"], "payments",
            "the machine drop is targeted too"
        );

        for protected in ["permissions", "permissions_status"] {
            assert!(
                PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&protected),
                "{protected} is a protected access-token claim"
            );
        }
    }

    #[test]
    fn the_id_token_never_carries_permissions() {
        // Issue #98, the same divergence from org_id that `roles` makes and for the
        // same reasons. Even with a fully resolved, non-empty set the ID token stays
        // lean. If this fails because someone added an emission to
        // build_id_token_claims, read that function's doc comment before "fixing" it.
        let held = permission_set(&["orders.write"]);
        let mut req = request("usr_abc", "pwd");
        req.org_id = Some("org_real");
        req.permissions = Some(&held);
        let id_claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert!(
            id_claims.get("permissions").is_none(),
            "the id token carries NO permissions claim: {id_claims}"
        );
        assert!(
            id_claims.get("permissions_status").is_none(),
            "and no status: {id_claims}"
        );
        // org_id DOES ride both, so the asymmetry is real rather than an accident of an
        // empty request.
        assert_eq!(id_claims["org_id"], "org_real");
    }

    #[test]
    fn the_machine_claim_builder_has_no_permission_field_to_read() {
        // The issue #99 boundary at the type level: a client-credentials token is built
        // from a request that carries no permission set, so the omission is structural
        // and not a policy this builder applies. A plain, fully populated machine
        // request emits neither claim.
        let request = ClientCredentialsMintRequest {
            org_id: None,
            roles: None,
            scope: {
                let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 1);
                Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env))
            },
            issuer: "https://issuer.test/t/x/e/y",
            subject: "sva_machine",
            client_id: "cli_example",
            oauth_scope: Some("api"),
            custom_claims: empty_mapped_extra(),
            act: None,
        };
        let claims = build_client_credentials_access_token_claims(
            &request,
            1,
            2,
            "tok",
            &json!("cli_example"),
        );
        for absent in ["permissions", "permissions_status", "roles", "org_id"] {
            assert!(
                claims.get(absent).is_none(),
                "a machine token carries no {absent}: {claims}"
            );
        }
    }

    #[test]
    fn the_default_id_token_carries_no_extra_claims() {
        // The spec-conform default (empty extra_claims) keeps the ID token lean.
        let claims =
            build_id_token_claims(&request("usr_abc", "pwd"), 1, 2, "tok").expect("claims");
        for absent in ["email", "name", "phone_number", "address"] {
            assert!(claims.get(absent).is_none(), "{absent} stays at UserInfo");
        }
    }

    #[test]
    fn front_channel_hashes_are_included_only_when_supplied() {
        // The token endpoint passes None (verified above). When #17 supplies
        // them, they land verbatim.
        let mut req = request("usr_abc", "pwd");
        req.at_hash = Some("at-hash-value");
        req.c_hash = Some("c-hash-value");
        let claims = build_id_token_claims(&req, 1, 2, "tok").expect("claims");
        assert_eq!(claims["at_hash"], "at-hash-value");
        assert_eq!(claims["c_hash"], "c-hash-value");
    }

    #[test]
    fn access_token_carries_the_rfc9068_required_claims() {
        // Issue #29: the at+jwt access token carries every RFC 9068 section 2.2
        // required claim, well formed, plus scope and the derived acr.
        let mut req = request("usr_abc", "pwd");
        req.oauth_scope = Some("openid profile");
        let claims = build_access_token_claims(
            &req,
            1000,
            1300,
            "tok_at",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(claims["iss"], "https://issuer.test/t/x/e/y");
        assert_eq!(claims["exp"], 1300);
        assert_eq!(claims["sub"], "usr_abc");
        assert_eq!(claims["client_id"], "cli_example");
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["jti"], "tok_at");
        assert_eq!(claims["scope"], "openid profile");
        // acr is derived from the authentication event, never a request parameter.
        assert_eq!(claims["acr"], "urn:ironauth:acr:pwd");
        // Every RFC 9068 required claim is present and a well-formed type.
        for name in ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"] {
            assert!(claims.get(name).is_some(), "{name} must be present");
        }
        assert!(claims["exp"].is_number() && claims["iat"].is_number());
    }

    #[test]
    fn access_token_aud_is_the_resolved_audience_not_always_the_client() {
        // The no-resource case passes the client id (so UserInfo keeps working);
        // a resource server passes its own audience. client_id is ALWAYS the OAuth
        // client, whatever the audience is.
        let req = request("usr_abc", "pwd");
        let default = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(default["aud"], "cli_example");
        assert_eq!(default["client_id"], "cli_example");

        let rs = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("https://api.example/orders"),
            PermissionClaim::Absent,
        );
        assert_eq!(rs["aud"], "https://api.example/orders");
        assert_eq!(rs["client_id"], "cli_example", "client_id stays the client");
    }

    #[test]
    fn access_token_auth_time_is_present_only_when_frozen_onto_the_code() {
        // auth_time appears (in epoch seconds) only when the authentication instant
        // was frozen onto the code as due, exactly like the ID token.
        let mut req = request("usr_abc", "pwd");
        assert!(
            build_access_token_claims(
                &req,
                1,
                2,
                "tok",
                &json!("cli_example"),
                PermissionClaim::Absent
            )
            .get("auth_time")
            .is_none(),
            "auth_time is absent when not frozen onto the code"
        );
        req.auth_time_unix_micros = Some(1_700_000_123_456_789);
        let claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        assert_eq!(claims["auth_time"], 1_700_000_123_i64);
    }

    #[test]
    fn access_token_payload_carries_no_pii_beyond_the_protocol_claims() {
        // Claims hygiene: even when the granted scope names PII scopes, the access
        // token payload never carries the PII itself (it stays at UserInfo).
        let mut req = request("usr_abc", "pwd");
        req.oauth_scope = Some("openid profile email address phone");
        req.auth_time_unix_micros = Some(1_700_000_000_000_000);
        let claims = build_access_token_claims(
            &req,
            1,
            2,
            "tok",
            &json!("cli_example"),
            PermissionClaim::Absent,
        );
        let object = claims.as_object().expect("object");
        // The payload is exactly the protocol claim set, nothing else.
        let mut names: Vec<&str> = object.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "acr",
                "aud",
                "auth_time",
                "client_id",
                "exp",
                "iat",
                "iss",
                "jti",
                "scope",
                "sub"
            ],
            "the access token payload is exactly the protocol claims"
        );
        for pii in ["email", "name", "given_name", "phone_number", "address"] {
            assert!(
                object.get(pii).is_none(),
                "{pii} must not be in the payload"
            );
        }
    }

    /// A minimal client-credentials mint request over a throwaway scope.
    fn cc_request<'a>(
        subject: &'a str,
        custom: &'a crate::claims_mapping_at_issuance::MappedAccessClaims,
    ) -> ClientCredentialsMintRequest<'a> {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 1);
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        ClientCredentialsMintRequest {
            org_id: None,
            roles: None,
            scope,
            issuer: "https://issuer.test/t/x/e/y",
            subject,
            client_id: "cli_example",
            oauth_scope: None,
            custom_claims: custom,
            act: None,
        }
    }

    #[test]
    fn client_credentials_claims_carry_the_rfc9068_set_and_no_auth_context() {
        // Issue #23: the M2M token carries the RFC 9068 protocol claims, with sub the
        // service-account principal (DISTINCT from client_id) and NO acr / auth_time
        // (there was no user authentication event to derive them from).
        let empty =
            crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(serde_json::Map::new());
        let mut req = cc_request("sva_principal", &empty);
        req.oauth_scope = Some("read write");
        let claims = build_client_credentials_access_token_claims(
            &req,
            1000,
            1300,
            "tok_at",
            &json!("cli_example"),
        );
        assert_eq!(claims["iss"], "https://issuer.test/t/x/e/y");
        assert_eq!(claims["sub"], "sva_principal");
        assert_ne!(
            claims["sub"], claims["client_id"],
            "sub is distinct from client_id"
        );
        assert_eq!(claims["aud"], "cli_example");
        assert_eq!(claims["client_id"], "cli_example");
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["exp"], 1300);
        assert_eq!(claims["jti"], "tok_at");
        assert_eq!(claims["scope"], "read write");
        assert!(claims.get("acr").is_none(), "no acr on a machine token");
        assert!(
            claims.get("auth_time").is_none(),
            "no auth_time on a machine token"
        );
        assert!(claims.get("nonce").is_none(), "no nonce on a machine token");
    }

    #[test]
    fn a_custom_claim_never_sets_a_reserved_claim() {
        // A hostile custom-claims config naming EVERY reserved claim (protocol,
        // authentication-context, binding, and hash/session) plus a benign one. The
        // protocol claims the machine token emits keep their real values; the
        // reserved-but-not-emitted claims are dropped entirely (a machine token
        // carries no auth context and no self-asserted cnf); only the benign lands.
        let custom = json!({
            // Protocol claims (must keep their real minted values).
            "sub": "attacker",
            "iss": "https://evil.test",
            "aud": "https://evil.test/api",
            "client_id": "cli_attacker",
            "exp": 9_999_999_999_i64,
            "iat": 0,
            "nbf": 0,
            "jti": "forged",
            "scope": "admin",
            "typ": "forged+jwt",
            "token_type": "mac",
            // Authentication-context claims (a machine token must assert none).
            "acr": "urn:evil:acr:high",
            "amr": ["mfa", "hwk"],
            "auth_time": 123,
            "nonce": "evil-nonce",
            "azp": "cli_attacker",
            // Binding / session / hash claims (only the issuer may state these).
            "cnf": { "jkt": "evil-thumbprint" },
            "at_hash": "evil-at-hash",
            "c_hash": "evil-c-hash",
            "sid": "evil-session",
            // The RFC 8693 actor claim (issue #101): a forged impersonator on a token the
            // attacker obtained honestly, which is an audit forgery rather than a privilege
            // claim, and the reason `act` is reserved.
            "act": { "sub": "adm_victim", "reason_code": "forged" },
            // Organization context (issue #94): a machine token asserts no human org.
            "org_id": "org_evil",
            // Organization roles (issue #97): a machine token asserts no human
            // authorization role. Machine roles are issue #99 and must land on both
            // machine paths deliberately, never through a stored custom claim.
            "roles": ["admin", "owner"],
            // Organization permissions (issue #98): a machine token asserts no human
            // API capability, and a forged `permissions_status` would let a client
            // suppress a withholding marker. Both are on the same #99 footing as
            // `roles` above.
            "permissions": ["billing.admin"],
            "permissions_status": "pdp_required",
            // A benign business claim, which is admitted.
            "department": "payments"
        })
        .as_object()
        .cloned()
        .expect("object");
        let custom = crate::claims_mapping_at_issuance::MappedAccessClaims::for_test(custom);
        let mut req = cc_request("sva_real", &custom);
        req.oauth_scope = Some("read");
        let claims = build_client_credentials_access_token_claims(
            &req,
            1000,
            1300,
            "tok_real",
            &json!("cli_example"),
        );
        // The emitted protocol claims keep their real minted values.
        assert_eq!(claims["sub"], "sva_real", "protected sub is never shadowed");
        assert_eq!(claims["iss"], "https://issuer.test/t/x/e/y");
        assert_eq!(claims["aud"], "cli_example");
        assert_eq!(claims["client_id"], "cli_example");
        assert_eq!(claims["exp"], 1300);
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["jti"], "tok_real");
        assert_eq!(
            claims["scope"], "read",
            "the granted scope wins over a custom scope"
        );
        // The reserved names the machine token does NOT emit must stay absent: a
        // custom claim can never inject an authentication context, a binding key, a
        // hash/session claim, or an out-of-band nbf/typ/token_type.
        for reserved_absent in [
            "nbf",
            "typ",
            "token_type",
            "acr",
            "amr",
            "auth_time",
            "nonce",
            "azp",
            "cnf",
            "at_hash",
            "c_hash",
            "sid",
            "org_id",
            "roles",
            "permissions",
            "permissions_status",
            "act",
        ] {
            assert!(
                claims.get(reserved_absent).is_none(),
                "{reserved_absent} must never be injected by a custom claim"
            );
        }
        // The benign, non-reserved business claim is admitted.
        assert_eq!(
            claims["department"], "payments",
            "a benign custom claim lands"
        );
        // Sanity: every name the guard reserves is one it recognises, so none of the
        // hostile values above could have slipped through under a different spelling.
        for reserved in PROTECTED_ACCESS_TOKEN_CLAIMS {
            assert_ne!(
                claims.get(*reserved),
                custom.as_map().get(*reserved),
                "{reserved} must never carry the hostile custom value"
            );
        }
    }
}
