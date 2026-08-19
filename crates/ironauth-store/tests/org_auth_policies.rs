// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-organization authentication policies (issue #95, store layer), over a real
//! database (`DATABASE_URL`).
//!
//! Pins the persistence half of the M10 policy model:
//!
//!   * a policy is STATED for an organization and REMOVED, each audited with the
//!     exact delta wire strings and an operator-safe `detail` that never carries a
//!     domain string or a factor token;
//!   * the write is a whole-document UPSERT keyed on the organization, so there is
//!     exactly ONE live policy per organization and no second key to address it by;
//!   * a removed policy is never REVIVED: the next `set` mints a FRESH id, so
//!     removing a policy cannot be quietly undone in its identity while staying
//!     observationally identical in value;
//!   * the write NORMALIZES the domain list, and does so BEFORE it validates, so the
//!     stored form is exactly the one a submitted address is later matched against;
//!   * a self-contradictory document is refused with a typed error that writes
//!     NEITHER the row nor its audit row, and the storage-engine CHECKs behind it
//!     agree with the Rust validator over a seeded corpus that REACHES every one of
//!     them;
//!   * the typed refusal is never an existence ORACLE: a contradictory document
//!     against an organization the caller cannot see is the uniform not-found, and
//!     the login-path read fails CLOSED on an out-of-scope organization rather than
//!     returning the `None` that means "inherit the level above unchanged";
//!   * organization containment holds against a SECOND organization in the SAME
//!     scope, which row-level security cannot fence;
//!   * forced row-level security hides another scope's policies even with the
//!     app-layer filter subverted, and its WITH CHECK half refuses a FORGED write
//!     claiming another scope; the grants are least-privilege (the data plane is read
//!     only, and the scope and organization columns are immutable by GRANT on BOTH
//!     roles);
//!   * migration 0049's `subject_kind` seam is LIVE: the subject-filtered read
//!     returns the scope-wide row, the acting organization's row, and the rows of the
//!     groups a subject effectively belongs to;
//!   * and there is NO cap on how many policies an environment may hold, or on how
//!     many domains or factors a policy may name.
//!
//! Cross-tenant and cross-environment isolation is additionally exercised through the
//! registered IDOR probes (`crates/ironauth-admin/tests/idor.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, AuthPolicy, AuthPolicyError, CorrelationId, ORG_POLICY_MAX_SESSION_TTL_SECS,
    OrgAuthPolicyId, OrganizationId, Scope, ServiceId, StoreError,
};
use sqlx::Row;

/// The Postgres "insufficient privilege" SQLSTATE. Postgres reports a row-level
/// security refusal and a privilege refusal under this SAME code, which is the trap
/// `assert_denied_in_scope` exists to avoid.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// The Postgres "check violation" SQLSTATE.
const CHECK_VIOLATION: &str = "23514";

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// The current clock-seam time in microseconds since the Unix epoch.
fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

fn tokens(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// Create an organization in `scope` via the control store, returning its id.
async fn create_org(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    display_name: &str,
) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), display_name, None)
        .await
        .expect("create organization");
    id
}

/// State `document` as `org`'s policy, returning the live policy id or the store
/// error so the refusal cases can assert on it.
async fn set_policy(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    document: &AuthPolicy,
) -> Result<OrgAuthPolicyId, StoreError> {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_auth_policies(scope)
        .set(env, org, document, ORG_POLICY_MAX_SESSION_TTL_SECS)
        .await
}

async fn remove_policy(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
) -> Result<OrgAuthPolicyId, StoreError> {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_auth_policies(scope)
        .remove(env, org)
        .await
}

/// The audit actions recorded against `target_id` in `scope`, in order. Read through
/// the OWNER pool so nothing hides behind row-level security.
async fn audit_actions(db: &TestDatabase, scope: Scope, target_id: &str) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT action FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(target_id)
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit rows");
    rows.iter().map(|r| r.get::<String, _>("action")).collect()
}

/// The `detail` dimensions recorded against `target_id`, in order.
async fn audit_details(db: &TestDatabase, scope: Scope, target_id: &str) -> Vec<Option<String>> {
    let rows = sqlx::query(
        "SELECT detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(target_id)
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit details");
    rows.iter()
        .map(|r| r.get::<Option<String>, _>("detail"))
        .collect()
}

/// Every `organization.policy.*` audit row in `scope`, as (action, target) pairs.
/// Used by the refusal tests, which must prove NOTHING was appended anywhere, not
/// merely that a particular target gained no row.
async fn all_policy_audit_rows(db: &TestDatabase, scope: Scope) -> Vec<(String, String)> {
    let rows = sqlx::query(
        "SELECT action, target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 \
           AND action LIKE 'organization.policy.%' \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read policy audit rows");
    rows.iter()
        .map(|r| {
            (
                r.get::<String, _>("action"),
                r.get::<String, _>("target_id"),
            )
        })
        .collect()
}

/// Every stored `org_auth_policies` row in `scope`, live and removed alike, keyed by
/// id and rendered as a stable string. A refusal must leave this BYTE IDENTICAL: a
/// test that asserted only the typed error would pass even if the write had leaked.
async fn policy_snapshot(db: &TestDatabase, scope: Scope) -> BTreeMap<String, String> {
    let rows = sqlx::query(
        "SELECT id, organization_id, mfa_required, allowed_factors, allowed_email_domains, \
                jit_provisioning, invitations_enabled, session_ttl_secs, session_idle_ttl_secs, \
                (deleted_at IS NULL) AS live \
           FROM org_auth_policies \
          WHERE tenant_id = $1 AND environment_id = $2 \
          ORDER BY id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read policy rows");
    rows.iter()
        .map(|row| {
            let id: String = row.get("id");
            let rendered = format!(
                "org={} mfa={:?} factors={:?} domains={:?} jit={:?} invitations={:?} \
                 ttl={:?} idle={:?} live={}",
                row.get::<String, _>("organization_id"),
                row.get::<Option<bool>, _>("mfa_required"),
                row.get::<Option<Vec<String>>, _>("allowed_factors"),
                row.get::<Option<Vec<String>>, _>("allowed_email_domains"),
                row.get::<Option<bool>, _>("jit_provisioning"),
                row.get::<Option<bool>, _>("invitations_enabled"),
                row.get::<Option<i32>, _>("session_ttl_secs"),
                row.get::<Option<i32>, _>("session_idle_ttl_secs"),
                row.get::<bool, _>("live"),
            );
            (id, rendered)
        })
        .collect()
}

/// A deterministic `SplitMix64` stream, seeded from a hard-coded constant so a
/// failure in CI is reproducible from the log alone.
///
/// A file-local generator rather than a crate: the workspace has no property-testing
/// dependency, and `scripts/invariant-lints.sh` bans the `rand` family outright so
/// randomness in tests is always seeded and replayable. This is the repository's
/// existing convention for randomized corpora.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`. `bound` must be nonzero.
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(bound).expect("fits u64"))
            .expect("fits usize")
    }

    fn flip(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

/// The factor pool the agreement corpus draws from: enough of the closed vocabulary
/// to exercise the intersection, and BOTH single primary factors (`email_otp` and
/// `sms`), which are the whole trap, so the MFA-reachability latch is tested on the
/// refusing side rather than only on the happy one.
const CORPUS_FACTOR_POOL: [&str; 7] = [
    "pwd",
    "email_otp",
    "sms",
    "trusted_device",
    "totp",
    "passkey_uv",
    "recovery_code",
];

/// One random policy document for the CHECK-versus-validator corpus.
///
/// Only the ROW-LOCAL dimensions vary, and every one of them is drawn so that the
/// corpus actually REACHES each CHECK migration 0090 carries. A generator that
/// merely produced plausible documents would be structurally blind to three of them:
/// pinning the domain list at NULL never reaches `org_auth_policies_domains_nonempty`
/// at all, and drawing the durations from `1..=5_000` never reaches either
/// `_positive` floor and reaches the `<=` boundary of `_idle_within_absolute` only by
/// accident. So:
///
///   * the domain list takes all THREE shapes the CHECK can distinguish (absent,
///     explicitly empty, and a single registrable entry), all of which are
///     SHAPE-valid to the guard too, so the two verdicts stay comparable;
///   * each duration is absent, ZERO, or a positive value, with zero drawn as its
///     OWN arm rather than as one value in five thousand, so the floor is reached in
///     a large fraction of the corpus rather than in roughly one document of it;
///   * and the idle window is sometimes made EQUAL to the absolute lifetime, which is
///     the exact `<=` boundary a CHECK that was stricter than the guard would
///     separate them on.
///
/// The positive durations stay well inside the deployment ceiling, so the one rule
/// the guard enforces that no CHECK can (the ceiling itself, a config value) never
/// separates the two verdicts.
fn random_corpus_document(rng: &mut Rng) -> AuthPolicy {
    let allowed_factors = if rng.flip() {
        let mut chosen: BTreeSet<String> = BTreeSet::new();
        for token in CORPUS_FACTOR_POOL {
            if rng.flip() {
                chosen.insert(token.to_owned());
            }
        }
        Some(chosen)
    } else {
        None
    };
    let allowed_email_domains = match rng.below(3) {
        0 => None,
        1 => Some(BTreeSet::new()),
        _ => Some(tokens(&["acme.example"])),
    };
    let duration = |rng: &mut Rng| match rng.below(4) {
        0 => None,
        1 => Some(0),
        _ => Some(u32::try_from(rng.below(5_000) + 1).expect("fits u32")),
    };
    let session_ttl_secs = duration(rng);
    let mirror_the_absolute = rng.below(4) == 0;
    let session_idle_ttl_secs = if mirror_the_absolute && session_ttl_secs.is_some() {
        session_ttl_secs
    } else {
        duration(rng)
    };
    AuthPolicy {
        template_override: None,
        mfa_required: if rng.flip() { Some(rng.flip()) } else { None },
        allowed_factors,
        allowed_email_domains,
        jit_provisioning: None,
        invitations_enabled: None,
        session_ttl_secs,
        session_idle_ttl_secs,
        // `duration` answers `Some(0)` a quarter of the time, so the zero this column's
        // CHECK refuses is genuinely reached and the agreement between the CHECK and the
        // Rust validator is measured for it rather than assumed from the session pair.
        access_token_ttl_secs: duration(rng),
    }
}

/// A document that exercises every dimension at once.
///
/// Every field is STATED, never inherited: a fixture that leaves a dimension `None` cannot
/// tell a column that round-trips from a column nothing writes, which is exactly the shape
/// migration 0121's schema test exists to catch.
fn full_document() -> AuthPolicy {
    AuthPolicy {
        template_override: None,
        mfa_required: Some(true),
        allowed_factors: Some(tokens(&["pwd", "totp", "passkey_uv"])),
        allowed_email_domains: Some(tokens(&["acme.example", "contractor.example"])),
        jit_provisioning: Some(false),
        invitations_enabled: Some(true),
        session_ttl_secs: Some(3_600),
        session_idle_ttl_secs: Some(900),
        access_token_ttl_secs: Some(300),
    }
}

#[tokio::test]
async fn a_policy_is_stated_read_back_and_removed_with_its_audit_vocabulary() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;

    // An organization with no policy reads as ABSENT, and that is the normal case
    // rather than an error: it inherits the next level up unchanged.
    assert!(
        db.control_store()
            .management()
            .org_auth_policies(scope)
            .document_for_org(&org)
            .await
            .expect("an absent policy is not an error")
            .is_none()
    );

    let document = full_document();
    let policy_id = set_policy(&db, &env, scope, &org, &document)
        .await
        .expect("state the policy");

    let record = db
        .control_store()
        .management()
        .org_auth_policies(scope)
        .get_for_org(&org)
        .await
        .expect("read the policy back");
    assert_eq!(record.id, policy_id);
    assert_eq!(record.organization_id, org);
    // Every dimension round-trips through the storage engine unchanged, including
    // the two list columns as SETS.
    assert_eq!(record.document, document);

    // The DATA plane can read it: migration 0090 grants it SELECT because the
    // resolution engine runs on the authorization path under the low-privilege role.
    let seen = db
        .store()
        .scoped(scope)
        .org_auth_policies()
        .document_for_org(&org)
        .await
        .expect("the data plane can READ a policy")
        .expect("the policy is present");
    assert_eq!(seen, document);

    // The audit vocabulary, exactly as migration 0090's header records it.
    assert_eq!(
        audit_actions(&db, scope, &policy_id.to_string()).await,
        vec!["organization.policy.set".to_owned()]
    );
    // The detail is a CLOSED token vocabulary. It must not carry a domain string or
    // a factor token: a domain is caller-typed free text and is PII adjacent.
    let details = audit_details(&db, scope, &policy_id.to_string()).await;
    let detail = details
        .first()
        .cloned()
        .flatten()
        .expect("the set action records a detail");
    assert_eq!(
        detail,
        "mfa_required=true factors=restricted domains=set jit=false invitations=true \
         session_ttl=3600 session_idle=900 token_ttl=300"
    );
    assert!(!detail.contains("acme.example"));
    assert!(!detail.contains("totp"));

    // A CHANGE keeps the SAME row and the same id, and appends a second audit row.
    let relaxed = AuthPolicy {
        session_ttl_secs: Some(1_800),
        ..document.clone()
    };
    let same_id = set_policy(&db, &env, scope, &org, &relaxed)
        .await
        .expect("change the policy");
    assert_eq!(
        same_id, policy_id,
        "a change updates the existing row rather than inserting a second one"
    );
    assert_eq!(
        audit_actions(&db, scope, &policy_id.to_string()).await,
        vec![
            "organization.policy.set".to_owned(),
            "organization.policy.set".to_owned()
        ]
    );

    // The WRITE PATH normalizes, and it normalizes BEFORE it validates. Both halves
    // matter and one assertion pins both. Migration 0090's commitment (ii) makes
    // matching EXACT on the normalized form, so a stored `ACME.Example` would
    // silently never match a submitted `acme.example`: a write path that skipped the
    // fold would look correct in every test whose domains were already lowercase.
    // And the padded spelling is only ACCEPTABLE after folding (it is not a
    // registrable hostname before it), so validating the raw document instead would
    // refuse this write outright.
    let unnormalized = AuthPolicy {
        allowed_email_domains: Some(tokens(&["ACME.Example", " acme.example "])),
        ..AuthPolicy::default()
    };
    set_policy(&db, &env, scope, &org, &unnormalized)
        .await
        .expect("a document whose domains normalize to a valid form is accepted");
    assert_eq!(
        db.control_store()
            .management()
            .org_auth_policies(scope)
            .get_for_org(&org)
            .await
            .expect("read the normalized document back")
            .document
            .allowed_email_domains,
        Some(tokens(&["acme.example"])),
        "two spellings of one domain are stored as the ONE normalized form"
    );
}

#[tokio::test]
async fn a_set_replaces_the_whole_document_and_a_remove_soft_deletes_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    let policy_id = set_policy(&db, &env, scope, &org, &full_document())
        .await
        .expect("state the policy");

    // The write is a WHOLE-DOCUMENT replace: an unset dimension is CLEARED, not left
    // behind. A patch-shaped write would leave a stale MFA requirement in place while
    // the operator believed they had removed it.
    let emptied = set_policy(&db, &env, scope, &org, &AuthPolicy::default())
        .await
        .expect("state an empty policy");
    assert_eq!(emptied, policy_id);
    let record = db
        .control_store()
        .management()
        .org_auth_policies(scope)
        .get_for_org(&org)
        .await
        .expect("read back");
    assert_eq!(
        record.document,
        AuthPolicy::default(),
        "every dimension the new document left unset is cleared"
    );

    // Removal is a soft delete: the row is retained (so the removal audit row's target
    // stays resolvable; an application rule, since `audit_log` carries no foreign key
    // here) and the organization reads as having no policy again.
    let removed = remove_policy(&db, &env, scope, &org)
        .await
        .expect("remove the policy");
    assert_eq!(removed, policy_id);
    assert!(
        db.control_store()
            .management()
            .org_auth_policies(scope)
            .document_for_org(&org)
            .await
            .expect("absent again")
            .is_none()
    );
    assert!(matches!(
        db.control_store()
            .management()
            .org_auth_policies(scope)
            .get_for_org(&org)
            .await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        audit_actions(&db, scope, &policy_id.to_string()).await,
        vec![
            "organization.policy.set".to_owned(),
            "organization.policy.set".to_owned(),
            "organization.policy.remove".to_owned()
        ],
        "the state, the emptying replace, and the removal each wrote exactly one row"
    );

    // A repeat remove matches no live row and is the uniform not-found.
    assert!(matches!(
        remove_policy(&db, &env, scope, &org).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn a_removed_policy_is_never_revived_and_a_fresh_one_takes_its_place() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;

    let document = full_document();
    let first = set_policy(&db, &env, scope, &org, &document)
        .await
        .expect("first policy");
    remove_policy(&db, &env, scope, &org)
        .await
        .expect("remove it");

    // The organization is immediately free to receive a NEW policy, because the
    // uniqueness index is PARTIAL over live rows.
    let second = set_policy(&db, &env, scope, &org, &document)
        .await
        .expect("second policy");
    assert_ne!(
        second, first,
        "removing a policy is a security operation: the next set mints a FRESH id \
         rather than reviving the dead row, so the audit trail stays honest about \
         when this policy began"
    );

    // Observationally identical in VALUE, because `set` states every dimension.
    let record = db
        .control_store()
        .management()
        .org_auth_policies(scope)
        .get_for_org(&org)
        .await
        .expect("read back");
    assert_eq!(record.id, second);
    assert_eq!(record.document, document);

    // The dead row is retained, so the audit rows pointing at it stay meaningful.
    assert_eq!(
        audit_actions(&db, scope, &first.to_string()).await,
        vec![
            "organization.policy.set".to_owned(),
            "organization.policy.remove".to_owned()
        ]
    );
    assert_eq!(
        audit_actions(&db, scope, &second.to_string()).await,
        vec!["organization.policy.set".to_owned()]
    );
}

#[tokio::test]
async fn a_contradictory_document_is_refused_and_writes_neither_the_row_nor_its_audit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;

    // A positive control FIRST, so the refusals below cannot pass because the whole
    // operation is simply broken.
    let policy_id = set_policy(&db, &env, scope, &org, &full_document())
        .await
        .expect("a valid document is accepted");
    let before_rows = policy_snapshot(&db, scope).await;
    let before_audit = all_policy_audit_rows(&db, scope).await;
    assert_eq!(before_audit.len(), 1);

    // The trap: `email_otp` and `sms` are SINGLE PRIMARY factors in this codebase
    // (their amr carries no `mfa`), so requiring MFA while permitting only those is
    // unsatisfiable by any login. A validator built on the wrong set would ACCEPT it.
    let contradiction = AuthPolicy {
        mfa_required: Some(true),
        allowed_factors: Some(tokens(&["pwd", "email_otp", "sms"])),
        ..AuthPolicy::default()
    };
    let error = set_policy(&db, &env, scope, &org, &contradiction)
        .await
        .expect_err("an unsatisfiable document is refused");
    let StoreError::OrgAuthPolicyInvalid(ref failures) = error else {
        panic!("expected the typed policy refusal, got {error:?}");
    };
    assert_eq!(
        failures,
        &vec![AuthPolicyError::MfaRequiredWithNoSecondFactor]
    );

    // Three assertions together, never one: the typed error, the stored state BYTE
    // IDENTICAL to before, and NO audit row appended anywhere. A test asserting only
    // the first would pass even if the write had leaked.
    assert_eq!(policy_snapshot(&db, scope).await, before_rows);
    assert_eq!(all_policy_audit_rows(&db, scope).await, before_audit);

    // Every other refusal reaches the same conclusion.
    for (document, expected) in [
        (
            AuthPolicy {
                allowed_factors: Some(tokens(&["pwd", "not_a_factor"])),
                ..AuthPolicy::default()
            },
            AuthPolicyError::UnknownFactor,
        ),
        (
            AuthPolicy {
                allowed_factors: Some(BTreeSet::new()),
                ..AuthPolicy::default()
            },
            AuthPolicyError::EmptyFactorList,
        ),
        (
            AuthPolicy {
                allowed_email_domains: Some(BTreeSet::new()),
                ..AuthPolicy::default()
            },
            AuthPolicyError::EmptyDomainList,
        ),
        (
            AuthPolicy {
                allowed_email_domains: Some(tokens(&["localhost"])),
                ..AuthPolicy::default()
            },
            AuthPolicyError::InvalidEmailDomain,
        ),
        (
            AuthPolicy {
                session_ttl_secs: Some(600),
                session_idle_ttl_secs: Some(900),
                ..AuthPolicy::default()
            },
            AuthPolicyError::IdleExceedsAbsolute,
        ),
        (
            AuthPolicy {
                session_ttl_secs: Some(ORG_POLICY_MAX_SESSION_TTL_SECS + 1),
                ..AuthPolicy::default()
            },
            AuthPolicyError::SessionTtlAboveCeiling,
        ),
        // The FLOOR, on BOTH halves. These two are the cases the CHECK constraints
        // `org_auth_policies_session_ttl_positive` and `_session_idle_positive`
        // refuse: they must be the TYPED refusal here, not a raw database error. A
        // guard that let them through would raise SQLSTATE 23514 MID-transaction,
        // which aborts the transaction the audit row still has to be written in and
        // reaches the caller as an opaque internal fault rather than a 422.
        (
            AuthPolicy {
                session_ttl_secs: Some(0),
                ..AuthPolicy::default()
            },
            AuthPolicyError::NonPositiveSessionLifetime,
        ),
        (
            AuthPolicy {
                session_idle_ttl_secs: Some(0),
                ..AuthPolicy::default()
            },
            AuthPolicyError::NonPositiveSessionLifetime,
        ),
    ] {
        let error = set_policy(&db, &env, scope, &org, &document)
            .await
            .expect_err("the document is refused");
        let StoreError::OrgAuthPolicyInvalid(ref failures) = error else {
            panic!("expected the typed policy refusal, got {error:?}");
        };
        assert_eq!(failures, &vec![expected]);
        assert_eq!(policy_snapshot(&db, scope).await, before_rows);
        assert_eq!(all_policy_audit_rows(&db, scope).await, before_audit);
    }

    // Positive control AFTER: a valid change still lands, so the refusals above are
    // about the documents and not about the surface being broken.
    let again = set_policy(&db, &env, scope, &org, &AuthPolicy::default())
        .await
        .expect("a valid change still lands");
    assert_eq!(again, policy_id);
}

#[tokio::test]
async fn the_deployment_ceiling_a_caller_passes_is_clamped_to_the_stores_own_mirror() {
    // The ceiling arrives as a call PARAMETER because the store deliberately has no
    // dependency on the config crate, and the store clamps it to its OWN mirror so a
    // miswired caller cannot WIDEN the deployment maximum from the outside. The
    // cross-crate test that pins the config and store constants equal states that the
    // store clamps; this is where that claim is executable.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;

    let above_the_mirror = AuthPolicy {
        session_ttl_secs: Some(ORG_POLICY_MAX_SESSION_TTL_SECS + 1),
        ..AuthPolicy::default()
    };
    let error = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_auth_policies(scope)
        .set(
            &env,
            &org,
            &above_the_mirror,
            ORG_POLICY_MAX_SESSION_TTL_SECS * 2,
        )
        .await
        .expect_err("a lifetime above the store's OWN mirror is refused whatever ceiling arrives");
    let StoreError::OrgAuthPolicyInvalid(ref failures) = error else {
        panic!("expected the typed policy refusal, got {error:?}");
    };
    assert_eq!(failures, &vec![AuthPolicyError::SessionTtlAboveCeiling]);
    assert!(policy_snapshot(&db, scope).await.is_empty());
    assert!(all_policy_audit_rows(&db, scope).await.is_empty());

    // Positive control: the very same call with a lifetime AT the mirror lands, so
    // the refusal is about the clamp and not about the surface being broken.
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_auth_policies(scope)
        .set(
            &env,
            &org,
            &AuthPolicy {
                session_ttl_secs: Some(ORG_POLICY_MAX_SESSION_TTL_SECS),
                ..AuthPolicy::default()
            },
            ORG_POLICY_MAX_SESSION_TTL_SECS * 2,
        )
        .await
        .expect("a lifetime at the mirror is accepted");
}

/// Write `document` STRAIGHT at the storage engine as the owner, with the
/// application guard bypassed entirely, and report whether a CHECK constraint
/// refused it. Any row that landed is removed again, because the live partial unique
/// index means only the FIRST insert per organization could succeed.
async fn engine_refuses_with_a_check(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    document: &AuthPolicy,
) -> bool {
    let list = |values: Option<&BTreeSet<String>>| {
        values.map(|set| set.iter().cloned().collect::<Vec<String>>())
    };
    let secs = |value: Option<u32>| {
        value.map(|seconds| i32::try_from(seconds).expect("the corpus stays well inside i32"))
    };
    let outcome = sqlx::query(
        "INSERT INTO org_auth_policies \
         (id, tenant_id, environment_id, organization_id, mfa_required, allowed_factors, \
          allowed_email_domains, session_ttl_secs, session_idle_ttl_secs, \
          access_token_ttl_secs) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(OrgAuthPolicyId::generate(env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(org.to_string())
    .bind(document.mfa_required)
    .bind(list(document.allowed_factors.as_ref()))
    .bind(list(document.allowed_email_domains.as_ref()))
    .bind(secs(document.session_ttl_secs))
    .bind(secs(document.session_idle_ttl_secs))
    // Bound so the CHECK behind the new column is actually reached. Omitting it would
    // leave the column NULL on every corpus row, the CHECK would never fire, and the
    // agreement this helper measures would be an agreement about a column the engine was
    // never shown.
    .bind(secs(document.access_token_ttl_secs))
    .execute(db.owner_pool())
    .await;

    if outcome.is_ok() {
        sqlx::query("DELETE FROM org_auth_policies WHERE tenant_id = $1 AND environment_id = $2")
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .execute(db.owner_pool())
            .await
            .expect("clear the corpus row");
    }
    outcome.as_ref().err().is_some_and(|error| {
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .is_some_and(|code| code == CHECK_VIOLATION)
    })
}

#[tokio::test]
async fn the_check_constraints_agree_with_the_rust_validator_over_a_seeded_corpus() {
    // The highest-value test in the file, because it is exhaustive over a CORPUS
    // rather than over examples. Migration 0090 carries the row-local half of the
    // validation as CHECK constraints, and the Rust guard refuses first (a CHECK
    // raised mid-transaction poisons it and would make the audit row impossible). If
    // the two drifted, the latch would stop being a latch: either a document the
    // guard accepts would be refused by the engine as a raw database error, or a
    // document the guard refuses would be writable by any path that bypassed it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;

    let mut rng = Rng(0x0000_0095_C0DE_0090);
    let mut refused_by_both = 0_usize;
    let mut accepted_by_both = 0_usize;
    // REACH counters, one per CHECK the corpus would otherwise be able to stop
    // exercising without anything failing. An agreement test is only as strong as the
    // documents it draws, so the shapes are counted and asserted below: a generator
    // change that quietly stopped producing empty domain lists, zero durations, or
    // the equal-pair boundary would then fail HERE rather than pass vacuously.
    let mut saw_empty_domains = 0_usize;
    let mut saw_stated_domains = 0_usize;
    let mut saw_zero_duration = 0_usize;
    let mut saw_equal_pair = 0_usize;

    for _ in 0..400 {
        let document = random_corpus_document(&mut rng);
        match document.allowed_email_domains.as_ref() {
            Some(domains) if domains.is_empty() => saw_empty_domains += 1,
            Some(_) => saw_stated_domains += 1,
            None => {}
        }
        if document.session_ttl_secs == Some(0) || document.session_idle_ttl_secs == Some(0) {
            saw_zero_duration += 1;
        }
        // The boundary only PROVES anything when the pair is otherwise acceptable: a
        // pair of zeroes is refused by both sides on the floor rule whatever the
        // `<=` becomes, so it is not counted here.
        if document
            .session_ttl_secs
            .is_some_and(|absolute| absolute > 0)
            && document.session_ttl_secs == document.session_idle_ttl_secs
        {
            saw_equal_pair += 1;
        }
        let guard_verdict =
            ironauth_store::validate_org_policy(&document, ORG_POLICY_MAX_SESSION_TTL_SECS);
        let engine_check_violation =
            engine_refuses_with_a_check(&db, &env, scope, &org, &document).await;

        // The two must agree on the ROW-LOCAL rules. The guard additionally enforces
        // the deployment CEILING, which is a config value and is deliberately not
        // expressible as a CHECK; the corpus stays well under it so the two verdicts
        // are comparable.
        assert_eq!(
            guard_verdict.is_err(),
            engine_check_violation,
            "the Rust guard and the storage-engine CHECKs disagreed about {document:?} \
             (guard: {guard_verdict:?}, engine check violation: {engine_check_violation})"
        );
        if guard_verdict.is_err() {
            refused_by_both += 1;
        } else {
            accepted_by_both += 1;
        }
    }

    // Both sides of the agreement are actually exercised, so a corpus that happened
    // to be all-valid (or all-invalid) could not pass this vacuously.
    assert!(
        refused_by_both > 20,
        "the corpus must exercise the refusal path (saw {refused_by_both})"
    );
    assert!(
        accepted_by_both > 20,
        "the corpus must exercise the acceptance path (saw {accepted_by_both})"
    );

    // And every CHECK is actually REACHED. Without these the corpus could agree with
    // the engine about constraints no document it draws ever touches, which is
    // agreement about nothing: mutating `domains_nonempty` to CHECK (true), or either
    // duration floor to `> -100`, or `idle_within_absolute` from `<=` to `<`, would
    // all leave the assertion above green.
    assert!(
        saw_empty_domains > 20,
        "the corpus must reach org_auth_policies_domains_nonempty (saw {saw_empty_domains})"
    );
    assert!(
        saw_stated_domains > 20,
        "the corpus must also state a VALID domain list, or the domain shapes prove \
         nothing (saw {saw_stated_domains})"
    );
    assert!(
        saw_zero_duration > 20,
        "the corpus must reach the two duration floors (saw {saw_zero_duration})"
    );
    assert!(
        saw_equal_pair > 20,
        "the corpus must reach the idle == absolute boundary of \
         org_auth_policies_idle_within_absolute (saw {saw_equal_pair})"
    );
}

#[tokio::test]
async fn the_closed_factor_vocabulary_is_enforced_by_the_storage_engine() {
    // The CHECK is the LATCH behind the Rust guard, so it must refuse independently
    // of it. Written straight at the engine as the owner, with the application path
    // bypassed entirely: if the CHECK were ever relaxed, the guard would become the
    // only thing standing between an unknown token and a stored policy, and any
    // future write path that skipped the guard would silently succeed.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;

    let write = |factors: Option<Vec<String>>| {
        let id = OrgAuthPolicyId::generate(&env, &scope).to_string();
        sqlx::query(
            "INSERT INTO org_auth_policies \
             (id, tenant_id, environment_id, organization_id, allowed_factors) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(org.to_string())
        .bind(factors)
        .execute(db.owner_pool())
    };

    // Positive control: the WHOLE closed vocabulary is writable, so the refusals
    // below are about the unknown token and not about the constraint being broken.
    let every_known: Vec<String> = ironauth_store::KNOWN_FACTOR_TOKENS
        .iter()
        .map(|token| (*token).to_owned())
        .collect();
    write(Some(every_known))
        .await
        .expect("every token of the closed vocabulary must be writable");
    sqlx::query("DELETE FROM org_auth_policies")
        .execute(db.owner_pool())
        .await
        .expect("clear");

    // An unknown token, an EMPTY list (which would mean "permit nothing", a lockout
    // dressed as a configuration), and a plausible-looking synonym are all refused by
    // the storage engine.
    for factors in [
        vec!["pwd".to_owned(), "not_a_factor".to_owned()],
        Vec::new(),
        vec!["mfa".to_owned()],
        vec!["webauthn".to_owned()],
    ] {
        let result = write(Some(factors.clone())).await;
        assert!(
            result.as_ref().err().is_some_and(|error| error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .is_some_and(|code| code == CHECK_VIOLATION)),
            "{factors:?} must be refused by a CHECK constraint: {result:?}"
        );
    }
}

#[tokio::test]
async fn the_typed_refusal_is_never_an_existence_oracle() {
    // The anti-oracle ORDERING, as an executable assertion. `OrgAuthPolicyInvalid` is
    // an INFORMATIVE error, so if it could be returned for an organization the caller
    // cannot see, it would become an existence oracle over another tenant's
    // organizations. The organization is resolved as a LIVE in-scope row FIRST, and
    // every failure to do so is the uniform not-found.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other_tenant = db.seed_scope(&env).await;
    let other_env = Scope::new(
        scope.tenant(),
        db.seed_environment(&env, scope.tenant()).await,
    );

    let foreign_tenant_org = create_org(&db, &env, other_tenant, "Foreign tenant").await;
    let foreign_env_org = create_org(&db, &env, other_env, "Foreign environment").await;
    let absent = OrganizationId::generate(&env, &scope);
    let soft_deleted = create_org(&db, &env, scope, "Soon gone").await;
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &soft_deleted)
        .await
        .expect("soft delete the organization");

    let contradiction = AuthPolicy {
        mfa_required: Some(true),
        allowed_factors: Some(tokens(&["pwd", "email_otp"])),
        ..AuthPolicy::default()
    };

    // One table-driven assertion comparing RENDERED forms, not five separate tests
    // that each merely assert `NotFound`: the latter would pass even if the messages
    // differed, which is exactly how an oracle survives a test suite.
    let mut rendered: BTreeSet<String> = BTreeSet::new();
    for (label, target) in [
        ("absent", absent),
        ("soft deleted", soft_deleted),
        ("foreign tenant", foreign_tenant_org),
        ("foreign environment", foreign_env_org),
    ] {
        for outcome in [
            set_policy(&db, &env, scope, &target, &contradiction).await,
            set_policy(&db, &env, scope, &target, &AuthPolicy::default()).await,
            remove_policy(&db, &env, scope, &target)
                .await
                .map(|_| OrgAuthPolicyId::generate(&env, &scope)),
        ] {
            let error = outcome
                .err()
                .unwrap_or_else(|| panic!("{label} must be refused"));
            assert!(
                matches!(error, StoreError::NotFound),
                "{label} must be the uniform not-found, never the informative refusal: {error:?}"
            );
            rendered.insert(error.to_string());
        }
    }
    assert_eq!(
        rendered.len(),
        1,
        "every unreachable organization must render BYTE IDENTICALLY: {rendered:?}"
    );

    // And the read side is uniform too.
    let policies = db.control_store().management().org_auth_policies(scope);
    for target in [foreign_tenant_org, foreign_env_org, absent] {
        assert!(matches!(
            policies.get_for_org(&target).await,
            Err(StoreError::NotFound)
        ));
    }

    // The LOGIN-path read, asserted on the read that actually carries the property.
    // `get_for_org` maps its own Ok(None) to NotFound, so every assertion above goes
    // through that MASKING wrapper and would survive `document_for_org` failing OPEN.
    // `document_for_org` is what the enforcement PR threads onto /authorize, and
    // there Ok(None) means exactly "this organization states no policy, inherit the
    // level above unchanged", the identity element of every combinator in the
    // resolution engine. So an OUT-OF-SCOPE organization returning Ok(None) would
    // silently DISCARD that organization's mfa_required and its factor allowlist
    // instead of failing closed, which is the hazard the read's own doc names.
    for (label, target) in [
        ("foreign tenant", foreign_tenant_org),
        ("foreign environment", foreign_env_org),
    ] {
        assert!(
            matches!(
                policies.document_for_org(&target).await,
                Err(StoreError::NotFound)
            ),
            "{label}: an out-of-scope organization must be a LOUD not-found, never Ok(None)"
        );
    }
    // The contrast that makes the assertion above meaningful rather than a blanket
    // "every miss is an error": an IN-SCOPE organization with no policy is the NORMAL
    // case and reads as Ok(None), because it inherits the next level up unchanged.
    assert!(
        policies
            .document_for_org(&absent)
            .await
            .expect("an in-scope organization with no policy is not an error")
            .is_none()
    );

    // Nothing at all was written by any of it.
    assert!(policy_snapshot(&db, scope).await.is_empty());
    assert!(all_policy_audit_rows(&db, scope).await.is_empty());
}

#[tokio::test]
async fn organization_containment_holds_against_a_second_organization_in_the_same_scope() {
    // Row-level security fences (tenant, environment) and NOTHING finer, so nothing
    // in the database stops two organizations of ONE environment from being wired
    // together. The IDOR harness cannot express this case either: its axis is tenant
    // and environment. It is pinned HERE.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = create_org(&db, &env, scope, "Acme").await;
    let globex = create_org(&db, &env, scope, "Globex").await;

    let acme_document = AuthPolicy {
        mfa_required: Some(true),
        ..AuthPolicy::default()
    };
    let globex_document = AuthPolicy {
        session_ttl_secs: Some(1_200),
        ..AuthPolicy::default()
    };
    let acme_policy = set_policy(&db, &env, scope, &acme, &acme_document)
        .await
        .expect("acme policy");
    let globex_policy = set_policy(&db, &env, scope, &globex, &globex_document)
        .await
        .expect("globex policy");
    assert_ne!(acme_policy, globex_policy);

    // Each organization reads its OWN policy and only its own.
    let policies = db.control_store().management().org_auth_policies(scope);
    assert_eq!(
        policies.get_for_org(&acme).await.expect("acme").document,
        acme_document
    );
    assert_eq!(
        policies
            .get_for_org(&globex)
            .await
            .expect("globex")
            .document,
        globex_document
    );

    // The environment-wide list carries both, and each row names its own
    // organization: a list that leaked the pairing would show up here.
    let listed = policies.list(100, None).await.expect("list");
    assert_eq!(listed.len(), 2);
    let pairs: BTreeMap<String, String> = listed
        .iter()
        .map(|record| (record.id.to_string(), record.organization_id.to_string()))
        .collect();
    assert_eq!(pairs.get(&acme_policy.to_string()), Some(&acme.to_string()));
    assert_eq!(
        pairs.get(&globex_policy.to_string()),
        Some(&globex.to_string())
    );

    // Removing Acme's policy leaves Globex's untouched: the mutation is addressed by
    // ORGANIZATION, so there is no second key that could reach across.
    remove_policy(&db, &env, scope, &acme)
        .await
        .expect("remove acme's policy");
    assert!(matches!(
        policies.get_for_org(&acme).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        policies
            .get_for_org(&globex)
            .await
            .expect("globex survives")
            .document,
        globex_document,
        "one organization's removal must not reach a sibling organization's policy"
    );

    // And stating Acme's policy again does not disturb Globex's row.
    set_policy(&db, &env, scope, &acme, &acme_document)
        .await
        .expect("restate acme's policy");
    assert_eq!(
        policies
            .get_for_org(&globex)
            .await
            .expect("globex still intact")
            .document,
        globex_document
    );
}

#[tokio::test]
async fn forced_row_level_security_hides_another_scopes_policies() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let org_a = create_org(&db, &env, scope_a, "Acme A").await;
    let org_b = create_org(&db, &env, scope_b, "Acme B").await;
    // A SECOND organization of scope B, deliberately left with NO policy: the forge
    // probe below targets it so the live partial unique index cannot be what refuses
    // the insert. Aimed at org_b it would fail as a duplicate even with the WITH
    // CHECK removed, and the probe would prove nothing.
    let unclaimed_b = create_org(&db, &env, scope_b, "Unclaimed B").await;
    set_policy(&db, &env, scope_a, &org_a, &full_document())
        .await
        .expect("policy A");
    set_policy(&db, &env, scope_b, &org_b, &full_document())
        .await
        .expect("policy B");

    // With the application-layer scope filter SUBVERTED (no tenant predicate at all),
    // the forced policy still shows the caller only its own rows.
    for (scope, expected_org) in [(scope_a, org_a), (scope_b, org_b)] {
        for pool in [db.app_pool(), db.control_pool()] {
            let mut tx = pool.begin().await.expect("begin");
            bind_scope(
                &mut tx,
                &scope.tenant().to_string(),
                &scope.environment().to_string(),
            )
            .await;
            let rows = sqlx::query("SELECT organization_id FROM org_auth_policies")
                .fetch_all(&mut *tx)
                .await
                .expect("unfiltered read");
            assert_eq!(rows.len(), 1, "row-level security must fence the read");
            assert_eq!(
                rows[0].get::<String, _>("organization_id"),
                expected_org.to_string()
            );
            let _ = tx.rollback().await;
        }
    }

    // The WRITE half of the same policy, which the reads above cannot reach.
    // Migration 0090 promises BYTE-IDENTICAL USING and WITH CHECK, and migration.rs
    // asserts only that a policy of that NAME exists, so without this a WITH CHECK of
    // `true` would let a scope A bound control session INSERT a row claiming scope B
    // with nothing failing. The same step the sibling role and group suites carry.
    {
        let mut tx = db.control_pool().begin().await.expect("begin as scope A");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;
        let forged = OrgAuthPolicyId::generate(&env, &scope_b).to_string();
        let insert = sqlx::query(
            "INSERT INTO org_auth_policies \
             (id, tenant_id, environment_id, organization_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(forged)
        .bind(scope_b.tenant().to_string())
        .bind(scope_b.environment().to_string())
        .bind(unclaimed_b.to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            insert.as_ref().err().is_some_and(|error| error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .is_some_and(|code| code == INSUFFICIENT_PRIVILEGE)),
            "RLS WITH CHECK must reject writing another scope's policy: {insert:?}"
        );
        let _ = tx.rollback().await;
    }
}

#[tokio::test]
async fn the_grants_are_least_privilege_on_both_planes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    set_policy(&db, &env, scope, &org, &full_document())
        .await
        .expect("a policy to attack");

    let pool = db.app_pool();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // Precondition: the low-privilege data-plane role, not a superuser. Without this
    // every probe below is meaningless.
    let who = sqlx::query(
        "SELECT current_user AS u, \
         (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_super",
    )
    .fetch_one(pool)
    .await
    .expect("identify session role");
    assert_eq!(who.get::<String, _>("u"), "ironauth_app");
    assert!(!who.get::<bool, _>("is_super"));

    // Every MUTATING statement is refused as insufficient privilege. A data plane
    // able to rewrite its OWN MFA requirement is the whole threat this table exists
    // to keep away from it.
    for statement in [
        "DELETE FROM org_auth_policies",
        "UPDATE org_auth_policies SET mfa_required = false",
        "UPDATE org_auth_policies SET allowed_factors = ARRAY['pwd']::text[]",
        "UPDATE org_auth_policies SET session_ttl_secs = 2592000",
        "UPDATE org_auth_policies SET deleted_at = now()",
    ] {
        assert_denied_in_scope(pool, &tenant, &environment, &org, statement).await;
    }
    // The forge probe writes a row that is valid in EVERY respect but the grant: the
    // session's own scope, a real organization of that scope, and an all-NULL
    // document every CHECK accepts. If the data plane ever gained INSERT, whether
    // table-wide or column-scoped, this statement would SUCCEED rather than fail with
    // a different error, so the assertion cannot be satisfied by a refusal that has
    // nothing to do with privilege.
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        &org,
        "INSERT INTO org_auth_policies (id, tenant_id, environment_id, organization_id) \
         VALUES ('oap_probe', $1, $2, $3)",
    )
    .await;

    // The scope and organization columns are immutable by GRANT on BOTH roles: not
    // even the control plane, which owns the whole policy lifecycle, may move a
    // policy between scopes or between organizations. That is what keeps the
    // containment invariant from being defeatable by an UPDATE after the fact.
    //
    // Each probe writes the column's OWN CURRENT VALUE, so the resulting row still
    // satisfies the row-level-security WITH CHECK and the ABSENT GRANT is the only
    // thing that can refuse it. Postgres reports a row-level-security refusal and a
    // privilege refusal under the SAME 42501, so a probe that moved the row out of
    // scope (writing the organization id into tenant_id, say) would stay green even
    // if these columns were later granted, which is exactly the trap
    // `assert_denied_in_scope` exists to avoid.
    for (column, value) in [
        ("tenant_id", "$1"),
        ("environment_id", "$2"),
        ("organization_id", "$3"),
        ("id", "id"),
    ] {
        assert_denied_in_scope(
            db.control_pool(),
            &tenant,
            &environment,
            &org,
            &format!(
                "UPDATE org_auth_policies SET {column} = {value} \
                 WHERE tenant_id = $1 AND environment_id = $2 AND organization_id = $3"
            ),
        )
        .await;
    }

    // Positive controls, so the denials above are about those columns and that role
    // rather than about access generally.
    {
        let mut tx = db.control_pool().begin().await.expect("begin control tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        sqlx::query("UPDATE org_auth_policies SET mfa_required = false, deleted_at = now()")
            .execute(&mut *tx)
            .await
            .expect("the control role holds the column-scoped UPDATE a change and a remove need");
        let _ = tx.rollback().await;
    }
    {
        let mut tx = pool.begin().await.expect("begin app tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        sqlx::query("SELECT mfa_required FROM org_auth_policies")
            .fetch_all(&mut *tx)
            .await
            .expect("the data plane holds the SELECT the resolution engine needs");
        let _ = tx.rollback().await;
    }
}

#[tokio::test]
async fn the_credential_class_org_and_group_seam_is_live() {
    // Migration 0049 shipped `subject_kind IN ('tenant', 'group', 'org')` with the
    // group and org rows as an INERT attachment seam awaiting the M10 organization
    // model. Issue #95 is that unlock and issue #97 shipped the real groups, so both
    // become live together. This pins the store-layer half: the subject-filtered read
    // returns exactly the applicable rows. Lifting the composition's
    // `subject_kind == "tenant"` filter is issue #95's enforcement PR, so nothing at
    // the authentication gate changes yet.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = create_org(&db, &env, scope, "Acme").await;
    let globex = create_org(&db, &env, scope, "Globex").await;

    let acting = db
        .store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env));
    acting
        .credential_class_policies()
        .set(&env, "tenant", None, "any")
        .await
        .expect("the scope-wide row");
    acting
        .credential_class_policies()
        .set(&env, "org", Some(&acme.to_string()), "mfa")
        .await
        .expect("acme's org row");
    acting
        .credential_class_policies()
        .set(&env, "org", Some(&globex.to_string()), "attested_passkey")
        .await
        .expect("globex's org row");
    // A group row keys on the group SLUG, which is what issue #97's ONE bounded
    // ancestor closure yields and what an authorization decision already keys on.
    acting
        .credential_class_policies()
        .set(&env, "group", Some("contractors"), "passkey")
        .await
        .expect("a group row");
    acting
        .credential_class_policies()
        .set(&env, "group", Some("interns"), "attested_passkey")
        .await
        .expect("a second group row");

    let repo = db.store().scoped(scope);
    let policies = repo.credential_class_policies();

    // No organization and no groups: exactly the scope-wide row, which is what the
    // composition reads today.
    let applicable = policies
        .applicable(None, &BTreeSet::new())
        .await
        .expect("read");
    assert_eq!(applicable.len(), 1);
    assert_eq!(applicable[0].subject_kind, "tenant");

    // Acme in context, with one of the two group memberships: the scope row, ACME's
    // row (never Globex's), and the `contractors` row (never `interns`).
    let membership: BTreeSet<String> = ["contractors".to_owned()].into_iter().collect();
    let applicable = policies
        .applicable(Some(&acme), &membership)
        .await
        .expect("read");
    let seen: BTreeSet<(String, String)> = applicable
        .iter()
        .map(|row| {
            (
                row.subject_kind.clone(),
                row.subject_ref.clone().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("tenant".to_owned(), String::new()),
            ("org".to_owned(), acme.to_string()),
            ("group".to_owned(), "contractors".to_owned()),
        ]
        .into_iter()
        .collect::<BTreeSet<(String, String)>>(),
        "a sibling organization's floor and an unrelated group's floor must not apply"
    );
    // And the classes really are the ones that were written, so the fold the
    // enforcement PR performs has the right inputs.
    let classes: BTreeMap<String, String> = applicable
        .iter()
        .map(|row| (row.subject_kind.clone(), row.min_class.clone()))
        .collect();
    assert_eq!(classes.get("org"), Some(&"mfa".to_owned()));
    assert_eq!(classes.get("group"), Some(&"passkey".to_owned()));

    // A cross-scope organization simply contributes nothing: it is not an error and
    // not an oracle, because its scope columns cannot match the bound scope.
    let foreign_scope = db.seed_scope(&env).await;
    let foreign_org = create_org(&db, &env, foreign_scope, "Foreign").await;
    let applicable = policies
        .applicable(Some(&foreign_org), &BTreeSet::new())
        .await
        .expect("read");
    assert_eq!(applicable.len(), 1);
    assert_eq!(applicable[0].subject_kind, "tenant");
}

#[tokio::test]
async fn nothing_caps_the_number_of_policies_domains_or_factors() {
    // A project covenant: no cap, quota, or paywall gate on the number of policies an
    // environment may hold, or on the number of domains or factors a policy may name.
    // Asserted rather than merely documented, so a later "safety" cap fails here.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Every factor in the closed vocabulary at once, plus a long domain list.
    let domains: BTreeSet<String> = (0..64)
        .map(|index| format!("tenant{index}.example"))
        .collect();
    let every_factor: BTreeSet<String> = ironauth_store::KNOWN_FACTOR_TOKENS
        .iter()
        .map(|token| (*token).to_owned())
        .collect();
    let generous = AuthPolicy {
        mfa_required: Some(true),
        allowed_factors: Some(every_factor.clone()),
        allowed_email_domains: Some(domains.clone()),
        ..AuthPolicy::default()
    };

    // Many organizations, each with its own policy, all in one environment.
    for index in 0..40 {
        let org = create_org(&db, &env, scope, &format!("Org {index}")).await;
        set_policy(&db, &env, scope, &org, &generous)
            .await
            .unwrap_or_else(|error| panic!("policy {index} must be statable: {error:?}"));
    }
    let listed = db
        .control_store()
        .management()
        .org_auth_policies(scope)
        .list(100, None)
        .await
        .expect("list");
    assert_eq!(listed.len(), 40);
    assert_eq!(listed[0].document.allowed_factors, Some(every_factor));
    assert_eq!(listed[0].document.allowed_email_domains, Some(domains));

    // TWO organizations may claim the SAME domain in one environment, deliberately
    // unlike routing_rules_domain_uniq: routing must pick exactly one IdP for a
    // domain, whereas two organizations may both legitimately accept one. A unique
    // index here would make the second write fail.
    let shared: BTreeSet<String> = ["contractor.example".to_owned()].into_iter().collect();
    let first = create_org(&db, &env, scope, "Claimant one").await;
    let second = create_org(&db, &env, scope, "Claimant two").await;
    for org in [first, second] {
        set_policy(
            &db,
            &env,
            scope,
            &org,
            &AuthPolicy {
                allowed_email_domains: Some(shared.clone()),
                ..AuthPolicy::default()
            },
        )
        .await
        .expect("two organizations may claim the same domain");
    }
}

/// Run `statement` in a scoped transaction on `pool` and assert it is refused as
/// insufficient privilege.
///
/// A statement carrying placeholders binds `$1` and `$2` to the session's OWN
/// (tenant, environment) and `$3` to `organization`, so a probe INSERT writes a row
/// that SATISFIES the row-level-security WITH CHECK (and the organization foreign
/// key), leaving the missing GRANT as the only thing that can refuse it. That
/// distinction is the whole point of the probe: Postgres reports a policy refusal and
/// a privilege refusal under the SAME SQLSTATE (42501), so a probe writing literal
/// foreign scope values would be rejected by the policy no matter how far the grant
/// was widened, and could never observe the grant at all.
async fn assert_denied_in_scope(
    pool: &sqlx::PgPool,
    tenant: &str,
    environment: &str,
    organization: &OrganizationId,
    statement: &str,
) {
    let mut tx = pool.begin().await.expect("begin denied-statement tx");
    bind_scope(&mut tx, tenant, environment).await;
    let mut query = sqlx::query(statement);
    if statement.contains("$1") || statement.contains("$3") {
        query = query
            .bind(tenant)
            .bind(environment)
            .bind(organization.to_string());
    }
    let result = query.execute(&mut *tx).await;
    assert!(
        result.as_ref().err().is_some_and(|error| error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .is_some_and(|code| code == INSUFFICIENT_PRIVILEGE)),
        "statement must be refused as insufficient privilege: {statement:?} -> {result:?}"
    );
    let _ = tx.rollback().await;
}

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does.
async fn bind_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    environment: &str,
) {
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut **tx)
        .await
        .expect("bind tenant scope");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(environment)
        .execute(&mut **tx)
        .await
        .expect("bind environment scope");
}

#[tokio::test]
async fn jit_eligibility_needs_both_the_flag_and_an_exact_domain_match() {
    // Issue #95 criterion 3. Two independent conditions gate provisioning a membership from
    // an email domain, and each one alone is unsafe:
    //
    //   * `allowed_email_domains` alone is a NARROWING FILTER, never a licence. It is an
    //     unverified operator assertion about which domains an organization accepts.
    //   * `jit_provisioning` alone would accept every address in the environment.
    //
    // Matching is EXACT on the normalized domain. A suffix match would let
    // `evil-example.com` satisfy a policy naming `example.com`, which is the classic way
    // domain allow-lists are escaped.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x9c);
    let scope = db.seed_scope(&env).await;

    let both = create_org(&db, &env, scope, "Both").await;
    let flag_off = create_org(&db, &env, scope, "FlagOff").await;
    let no_domain = create_org(&db, &env, scope, "NoDomain").await;

    set_policy(
        &db,
        &env,
        scope,
        &both,
        &AuthPolicy {
            jit_provisioning: Some(true),
            allowed_email_domains: Some(["example.com".to_owned()].into_iter().collect()),
            ..AuthPolicy::default()
        },
    )
    .await
    .expect("both conditions");

    // The domain matches but JIT is OFF. This is the "rejects when disabled" half.
    set_policy(
        &db,
        &env,
        scope,
        &flag_off,
        &AuthPolicy {
            jit_provisioning: Some(false),
            allowed_email_domains: Some(["example.com".to_owned()].into_iter().collect()),
            ..AuthPolicy::default()
        },
    )
    .await
    .expect("flag off");

    // JIT is on but the domain is a DIFFERENT one.
    set_policy(
        &db,
        &env,
        scope,
        &no_domain,
        &AuthPolicy {
            jit_provisioning: Some(true),
            allowed_email_domains: Some(["other.test".to_owned()].into_iter().collect()),
            ..AuthPolicy::default()
        },
    )
    .await
    .expect("other domain");

    let eligible = db
        .store()
        .scoped(scope)
        .org_auth_policies()
        .jit_eligible_orgs("example.com")
        .await
        .expect("jit_eligible_orgs");
    assert_eq!(
        eligible,
        vec![both],
        "only the organization with BOTH the flag and the exact domain is eligible"
    );

    // A domain that merely CONTAINS an allowed one must not match. Asserted separately
    // because a suffix or substring predicate would satisfy the assertion above unchanged.
    for near_miss in ["evil-example.com", "example.com.evil.test", "xample.com"] {
        assert!(
            db.store()
                .scoped(scope)
                .org_auth_policies()
                .jit_eligible_orgs(near_miss)
                .await
                .expect("jit_eligible_orgs")
                .is_empty(),
            "{near_miss} matched a policy that names example.com: the domain check is not exact"
        );
    }
}
