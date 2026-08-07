// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential resolution and the two wrong-scope behaviors.
//!
//! A request presents `Authorization: Bearer <token>`. The token is either the
//! config bootstrap operator token (the operator plane) or an environment-scoped
//! management key `mak_...` (the environment plane). Resolution yields a
//! [`Principal`]; the per-endpoint `require_*` methods then enforce scope with
//! the two distinct, both-required behaviors:
//!
//! - a resource-ID probe under a VALID scope for a resource in ANOTHER scope is a
//!   uniform not-found (handled where the resource is resolved, via the store's
//!   scoped parse; the anti-oracle rule);
//! - a credential presented against the WRONG environment or the WRONG plane is a
//!   LOUD [`ApiError::WrongScope`] naming the expected and actual scope.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use ironauth_store::{ActorRef, EnvironmentId, Scope, TenantId};

use crate::error::ApiError;
use crate::state::AdminState;
/// The CLOSED vocabulary of management-plane permissions (issue #102).
///
/// Its own vocabulary, deliberately NOT the organization RBAC permissions from issue #98.
/// Those govern in-product authorization over a tenant's resources; these govern
/// management-plane operations over the tenant itself. Sharing a vocabulary would make a
/// product permission grantable to a management key, and a slug meaning one thing in one
/// table and another here is the shape that rots.
///
/// Closed rather than free-form strings so an unknown grant cannot be written and then
/// silently match nothing at enforcement, which would read as "allowed" to anyone auditing
/// the row and as "denied" to the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagementPermission {
    /// Read any management resource in the scope.
    Read,
    /// Create, update and delete tenant configuration (clients, policies, connections).
    WriteConfig,
    /// Manage users: create, update, delete, and reset credentials and factors.
    WriteUsers,
    /// Manage organizations, their memberships, roles and permissions.
    WriteOrganizations,
    /// Manage management credentials themselves. Deliberately separate from every other
    /// write: a key that can mint keys can escalate to anything, so it must be grantable on
    /// its own rather than riding along with ordinary configuration authority.
    WriteCredentials,
}

impl ManagementPermission {
    /// Every permission, which is what a pin counts and what a parser sweeps.
    pub const ALL: [ManagementPermission; 5] = [
        ManagementPermission::Read,
        ManagementPermission::WriteConfig,
        ManagementPermission::WriteUsers,
        ManagementPermission::WriteOrganizations,
        ManagementPermission::WriteCredentials,
    ];

    /// The stable persistence slug. Exhaustive with no wildcard, so a variant added without a
    /// slug fails to compile rather than serializing as something else.
    #[must_use]
    pub const fn as_slug(self) -> &'static str {
        match self {
            ManagementPermission::Read => "management.read",
            ManagementPermission::WriteConfig => "management.write_config",
            ManagementPermission::WriteUsers => "management.write_users",
            ManagementPermission::WriteOrganizations => "management.write_organizations",
            ManagementPermission::WriteCredentials => "management.write_credentials",
        }
    }

    /// Parse a stored slug. An UNKNOWN slug is [`None`] and the caller must fail closed on it:
    /// a grant row naming a permission this binary does not know is not a licence.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        ManagementPermission::ALL
            .into_iter()
            .find(|candidate| candidate.as_slug() == slug)
    }

    /// This permission's bit in a [`ManagementGrants`] mask.
    const fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

/// A set of [`ManagementPermission`], as a bitmask.
///
/// A mask rather than a `BTreeSet` because [`Principal`] is `Copy` and is passed by value
/// through every handler. Making it heap-backed would force `Clone` on a type the whole
/// admin surface copies freely, which is a large change to pay for a set of at most five.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ManagementGrants(u32);

impl ManagementGrants {
    /// The empty set. Only meaningful as a starting point for [`insert`](Self::insert); a
    /// credential is never STORED with an empty grant set (the 0118 CHECK refuses it).
    #[must_use]
    pub const fn empty() -> Self {
        ManagementGrants(0)
    }

    /// Add a permission.
    #[must_use]
    pub const fn insert(self, permission: ManagementPermission) -> Self {
        ManagementGrants(self.0 | permission.bit())
    }

    /// Whether this set holds `permission`.
    #[must_use]
    pub const fn holds(self, permission: ManagementPermission) -> bool {
        self.0 & permission.bit() != 0
    }

    /// Whether the set is empty, which a stored grant never is.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// The authenticated caller of a management request.
#[derive(Debug, Clone, Copy)]
pub enum Principal {
    /// The bootstrap operator (operator plane). Authorizes tenant CRUD and, in
    /// M1, every environment-plane operation (the full operator-plane credential
    /// class lands in M5).
    Operator {
        /// The audit actor: a service actor with the stable operator id.
        actor: ActorRef,
    },
    /// An environment-scoped management key (environment plane).
    ManagementKey {
        /// The `(tenant, environment)` the key is authorized for.
        scope: Scope,
        /// The audit actor: a service actor carrying the key's identity.
        actor: ActorRef,
        /// The management-plane permissions this key is RESTRICTED to (issue #102), or
        /// [`None`] for an unrestricted key.
        ///
        /// [`None`] is not "no permissions", it is "every permission", and that asymmetry is
        /// deliberate: migration 0118 adds this column NULL, so every credential that existed
        /// before delegated administration keeps exactly the authority it had. A default of
        /// "none" would revoke every key in every deployment at upgrade.
        ///
        /// An empty set is unrepresentable for the same reason the database refuses one: a
        /// credential that may do nothing is indistinguishable from a revoked one, and
        /// revocation already has its own expression.
        grants: Option<ManagementGrants>,
    },
}

impl Principal {
    /// The audit actor for this principal.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        match self {
            Principal::Operator { actor } | Principal::ManagementKey { actor, .. } => *actor,
        }
    }

    /// The isolation key for the idempotency store: this credential's actor id.
    #[must_use]
    pub fn credential_ref(&self) -> String {
        self.actor().id_string()
    }

    /// Require the operator plane. A management key here is the LOUD wrong-plane
    /// error naming its scope.
    ///
    /// # Errors
    ///
    /// [`ApiError::WrongScope`] if the caller is a management key.
    pub fn require_operator(&self) -> Result<ActorRef, ApiError> {
        match self {
            Principal::Operator { actor } => Ok(*actor),
            Principal::ManagementKey { scope, .. } => Err(ApiError::WrongScope {
                expected: "plane=operator".to_owned(),
                actual: scope_label(scope),
                message: "this endpoint requires the operator plane; an environment-scoped \
                          management key was presented"
                    .to_owned(),
            }),
        }
    }

    /// Require that this principal holds `permission` (issue #102).
    ///
    /// The OPERATOR always passes: it is the operator plane, and a restriction on it would be
    /// a different feature (there is no operator-plane grant model and this issue does not
    /// add one).
    ///
    /// An UNRESTRICTED management key (`grants: None`) always passes, which is what makes
    /// this expand-only: every credential minted before delegated administration keeps its
    /// authority, exactly as migration 0118's NULL column intends.
    ///
    /// A RESTRICTED key passes only when its set holds the permission. The refusal is a 403
    /// naming the permission it lacked and never the ones it has, because an error that
    /// enumerated a credential's authority would turn a denied call into a way to map it.
    ///
    /// # Errors
    ///
    /// [`ApiError::Forbidden`] when a restricted key does not hold `permission`.
    pub fn require_permission(&self, permission: ManagementPermission) -> Result<(), ApiError> {
        match self {
            Principal::Operator { .. } => Ok(()),
            Principal::ManagementKey { grants, .. } => match grants {
                None => Ok(()),
                Some(held) if held.holds(permission) => Ok(()),
                // `WrongScope` is this crate's 403 and is reused rather than adding a
                // variant, so the management error surface stays closed. The fields carry the
                // truth: what was REQUIRED, and that the credential is restricted. `actual`
                // deliberately does not enumerate what the credential DOES hold, because an
                // error that listed a credential's authority would turn a denied call into a
                // way to map it.
                Some(_) => Err(ApiError::WrongScope {
                    expected: format!("permission={}", permission.as_slug()),
                    actual: "restricted management credential".to_owned(),
                    message: format!(
                        "this management credential is not granted {}",
                        permission.as_slug()
                    ),
                }),
            },
        }
    }

    /// Require authorization for exactly `(tenant, environment)`. The operator
    /// passes (M1 operator-plane god-mode); a management key must match exactly,
    /// otherwise the LOUD wrong-environment (or wrong-tenant) error.
    ///
    /// # Errors
    ///
    /// [`ApiError::WrongScope`] if a management key's scope does not match.
    pub fn require_environment(
        &self,
        tenant: TenantId,
        environment: EnvironmentId,
    ) -> Result<ActorRef, ApiError> {
        match self {
            Principal::Operator { actor } => Ok(*actor),
            Principal::ManagementKey { scope, actor, .. } => {
                if scope.tenant() == tenant && scope.environment() == environment {
                    Ok(*actor)
                } else {
                    Err(ApiError::WrongScope {
                        expected: scope_label(scope),
                        actual: scope_label(&Scope::new(tenant, environment)),
                        message: "the presented management key is not authorized for the \
                                  requested environment"
                            .to_owned(),
                    })
                }
            }
        }
    }
}

/// A `tenant=..., environment=...` label for an error's scope fields.
fn scope_label(scope: &Scope) -> String {
    format!(
        "tenant={}, environment={}",
        scope.tenant(),
        scope.environment()
    )
}

/// Extract the `Bearer` token from the `Authorization` header.
fn bearer_token(parts: &Parts) -> Result<String, ApiError> {
    let value = parts
        .headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".to_owned()))?;
    let raw = value
        .to_str()
        .map_err(|_| ApiError::Unauthorized("malformed Authorization header".to_owned()))?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or_else(|| {
            ApiError::Unauthorized("expected an Authorization: Bearer token".to_owned())
        })?
        .trim();
    // An empty token (`Authorization: Bearer ` with nothing after it) is never a
    // valid credential; reject it here so it can never reach a constant-time
    // comparison against a (defensively also non-empty) configured token.
    if token.is_empty() {
        return Err(ApiError::Unauthorized("empty bearer token".to_owned()));
    }
    Ok(token.to_owned())
}

impl FromRequestParts<AdminState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts)?;
        if let Some(principal) = state.match_operator(&token) {
            return Ok(principal);
        }
        if let Some(principal) = state.authenticate_management_key(&token).await? {
            return Ok(principal);
        }
        // The third arm (issue #90, PR 2): a console `at+jwt` from the admin issuer,
        // verified through the hardened JOSE path and mapped to an operator via the
        // fail-closed operator-subject allowlist. It runs after the two service
        // credentials because an `at+jwt` is a compact JWS, unambiguous vs the opaque
        // bootstrap token and the `mak_` key; a non-JWS, a disarmed bridge, or any
        // verification failure returns `None` and falls through to the uniform
        // `Unauthorized` below (no oracle). This resolves IDENTITY only; the
        // per-endpoint `require_*` methods still enforce authorization unchanged.
        if let Some(principal) = state.authenticate_admin_oidc(&token).await? {
            return Ok(principal);
        }
        Err(ApiError::Unauthorized(
            "invalid or unknown credential".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use ironauth_config::{AdminConfig, Secret, SecretString};
    use ironauth_env::Env;
    use ironauth_store::Store;
    use sqlx::postgres::PgPoolOptions;

    /// A management state over a LAZY pool (parses the URL, never connects) and a
    /// non-empty operator token. Every assertion below resolves at the extractor
    /// before any store access, so these tests stay database-free.
    fn state() -> AdminState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://ironauth@localhost/ironauth")
            .expect("lazy pool parses the URL");
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new("op-secret"))),
            ..AdminConfig::default()
        };
        AdminState::new(Store::from_pool(pool), Env::system(), &config).expect("state builds")
    }

    fn parts_with_auth(value: Option<&str>) -> Parts {
        let mut builder = Request::builder().method("GET").uri("/v1/tenants");
        if let Some(value) = value {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        builder.body(()).expect("request builds").into_parts().0
    }

    #[test]
    fn bearer_token_rejects_empty_and_missing_and_accepts_a_value() {
        assert!(matches!(
            bearer_token(&parts_with_auth(Some("Bearer "))),
            Err(ApiError::Unauthorized(_))
        ));
        assert!(matches!(
            bearer_token(&parts_with_auth(None)),
            Err(ApiError::Unauthorized(_))
        ));
        assert_eq!(
            bearer_token(&parts_with_auth(Some("Bearer abc"))).expect("token"),
            "abc"
        );
    }

    #[tokio::test]
    async fn empty_bearer_token_is_unauthorized() {
        let mut parts = parts_with_auth(Some("Bearer "));
        let err = Principal::from_request_parts(&mut parts, &state())
            .await
            .expect_err("an empty bearer token must be rejected");
        assert!(matches!(err, ApiError::Unauthorized(_)), "{err:?}");
    }

    #[tokio::test]
    async fn the_operator_token_authenticates_but_a_wrong_one_does_not() {
        let mut ok = parts_with_auth(Some("Bearer op-secret"));
        let principal = Principal::from_request_parts(&mut ok, &state())
            .await
            .expect("the operator token authenticates");
        assert!(matches!(principal, Principal::Operator { .. }));

        let mut wrong = parts_with_auth(Some("Bearer not-the-token"));
        let err = Principal::from_request_parts(&mut wrong, &state())
            .await
            .expect_err("a wrong non-mak token is unauthorized");
        assert!(matches!(err, ApiError::Unauthorized(_)), "{err:?}");
    }
}

#[cfg(test)]
mod grant_tests {
    use super::{ApiError, ManagementGrants, ManagementPermission, Principal};
    use ironauth_env::Env;
    use ironauth_store::{ActorRef, EnvironmentId, Scope, ServiceId, TenantId};

    fn scope(env: &Env) -> Scope {
        Scope::new(TenantId::generate(env), EnvironmentId::generate(env))
    }

    #[test]
    fn every_permission_has_a_distinct_slug_that_round_trips() {
        // The slug is the PERSISTENCE form: a variant whose slug collided with another's
        // would silently grant the wrong permission when a stored row was parsed back.
        let mut slugs: Vec<&str> = ManagementPermission::ALL
            .into_iter()
            .map(ManagementPermission::as_slug)
            .collect();
        slugs.sort_unstable();
        let count = slugs.len();
        slugs.dedup();
        assert_eq!(
            slugs.len(),
            count,
            "two permissions share a slug: {slugs:?}"
        );

        for permission in ManagementPermission::ALL {
            assert_eq!(
                ManagementPermission::from_slug(permission.as_slug()),
                Some(permission),
                "{} does not round-trip through its slug",
                permission.as_slug()
            );
        }
    }

    #[test]
    fn an_unknown_slug_parses_to_none_rather_than_to_a_permission() {
        // A grant row naming a permission this binary does not know is not a licence. It must
        // read as absent so the caller fails closed, never as some nearby variant.
        for unknown in ["management.write", "", "management.read.extra", "admin"] {
            assert_eq!(
                ManagementPermission::from_slug(unknown),
                None,
                "{unknown} parsed to a permission"
            );
        }
    }

    #[test]
    fn a_grant_set_holds_exactly_what_was_inserted() {
        // The mask is bit-indexed by discriminant, so an off-by-one in `bit()` would make one
        // permission answer for another. Asserting every pair catches that; asserting only the
        // inserted one would not.
        let grants = ManagementGrants::empty().insert(ManagementPermission::WriteUsers);
        for permission in ManagementPermission::ALL {
            assert_eq!(
                grants.holds(permission),
                permission == ManagementPermission::WriteUsers,
                "{} holds() disagrees with what was inserted",
                permission.as_slug()
            );
        }
        assert!(!grants.is_empty());
        assert!(ManagementGrants::empty().is_empty());
    }

    #[test]
    fn an_unrestricted_key_passes_and_a_restricted_one_passes_only_what_it_holds() {
        let env = Env::system();
        let scope = scope(&env);
        let actor = ActorRef::service(ServiceId::generate(&env));

        // `None` is UNRESTRICTED, which is what every credential minted before issue #102 is.
        // If this ever became "no permissions", migration 0118 would revoke every key in every
        // deployment at upgrade.
        let unrestricted = Principal::ManagementKey {
            scope,
            actor,
            grants: None,
        };
        for permission in ManagementPermission::ALL {
            assert!(
                unrestricted.require_permission(permission).is_ok(),
                "an unrestricted key was refused {}",
                permission.as_slug()
            );
        }

        let restricted = Principal::ManagementKey {
            scope,
            actor,
            grants: Some(ManagementGrants::empty().insert(ManagementPermission::Read)),
        };
        assert!(
            restricted
                .require_permission(ManagementPermission::Read)
                .is_ok()
        );
        for permission in ManagementPermission::ALL {
            if permission == ManagementPermission::Read {
                continue;
            }
            assert!(
                restricted.require_permission(permission).is_err(),
                "a read-only key was allowed {}",
                permission.as_slug()
            );
        }
    }

    #[test]
    fn a_refusal_names_the_required_permission_and_never_the_held_ones() {
        // An error that enumerated a credential's authority would turn a denied call into a
        // way to map it.
        let env = Env::system();
        let restricted = Principal::ManagementKey {
            scope: scope(&env),
            actor: ActorRef::service(ServiceId::generate(&env)),
            grants: Some(
                ManagementGrants::empty()
                    .insert(ManagementPermission::WriteUsers)
                    .insert(ManagementPermission::WriteConfig),
            ),
        };
        let refusal = restricted
            .require_permission(ManagementPermission::WriteCredentials)
            .expect_err("a restricted key is refused");
        let ApiError::WrongScope {
            expected,
            actual,
            message,
        } = refusal
        else {
            panic!("a permission refusal must be the 403, got {refusal:?}");
        };

        // EXACT equality on all three fields, not a substring search. A substring check only
        // catches a leak spelled the way the checker expects: measured, a mutation that
        // appended `{:?}` of the grant set SURVIVED a slug-substring assertion, because the
        // set renders as a bitmask (`ManagementGrants(6)`) and contains no slug at all. A leak
        // in a different encoding is still a leak, and only pinning the whole message
        // forecloses every encoding at once.
        assert_eq!(
            expected,
            format!(
                "permission={}",
                ManagementPermission::WriteCredentials.as_slug()
            )
        );
        assert_eq!(actual, "restricted management credential");
        assert_eq!(
            message,
            format!(
                "this management credential is not granted {}",
                ManagementPermission::WriteCredentials.as_slug()
            ),
            "the refusal carries something beyond what was REQUIRED; anything extra is a way \
             to map a credential's authority by probing it"
        );
    }
}
