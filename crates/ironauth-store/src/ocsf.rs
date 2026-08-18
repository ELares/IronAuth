// SPDX-License-Identifier: MIT OR Apache-2.0

//! OCSF-native audit mapping and stream separation (issue #109).
//!
//! Every audit action maps onto one of the OCSF IAM classes, and the mapping is EXHAUSTIVE:
//! a test sweeps the action list out of `audit.rs` and fails on the first action nothing
//! classifies. That is the whole design. A mapping with a `_ => Other` arm would compile
//! forever and quietly emit an unclassifiable event for every action added after it was
//! written, which is precisely the "silently accepted junk row" the issue rules out.
//!
//! # The classes
//!
//! | uid  | class                  | what lands here                                  |
//! |------|------------------------|--------------------------------------------------|
//! | 3001 | Account Change         | a principal's own record or credentials change   |
//! | 3002 | Authentication         | a login, a factor, a token, a session start      |
//! | 3003 | Authorize Session      | a session's authority changes, or it ends        |
//! | 3004 | Entity Management      | configuration objects: clients, brands, domains  |
//! | 3005 | User Access Management | who may do what: roles, permissions, grants      |
//!
//! # Two streams, and why the split is by CLASS rather than by table
//!
//! [`AuditStream::Authentication`] carries 3002 and 3003; [`AuditStream::AdminAction`]
//! carries the rest. The issue asks for independent retention, and retention is a policy
//! about WHAT KIND of record this is, not about which code path wrote it. Splitting by class
//! means a new action inherits the right stream from its class, and a class is something a
//! reviewer already had to choose.
//!
//! # Tamper evidence
//!
//! [`chain_link`] hashes each record together with its predecessor's digest, per stream. A
//! modification changes that record's digest, an insertion or a deletion changes the
//! predecessor every later record commits to, and [`verify_chain`] reports the FIRST index
//! that breaks rather than a bare boolean, because "the chain is broken" is not actionable
//! and "record 41 is where it broke" is.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::audit::{Action, ActorRef};

/// An OCSF IAM class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OcsfClass {
    /// 3001: a principal's own record or credentials changed.
    AccountChange,
    /// 3002: an authentication attempt, factor, or token issuance.
    Authentication,
    /// 3003: a session's authority changed, or the session ended.
    AuthorizeSession,
    /// 3004: a configuration entity was managed.
    EntityManagement,
    /// 3005: who may do what changed.
    UserAccessManagement,
}

impl OcsfClass {
    /// The OCSF class uid.
    #[must_use]
    pub fn uid(self) -> u32 {
        match self {
            OcsfClass::AccountChange => 3001,
            OcsfClass::Authentication => 3002,
            OcsfClass::AuthorizeSession => 3003,
            OcsfClass::EntityManagement => 3004,
            OcsfClass::UserAccessManagement => 3005,
        }
    }

    /// The OCSF class name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            OcsfClass::AccountChange => "Account Change",
            OcsfClass::Authentication => "Authentication",
            OcsfClass::AuthorizeSession => "Authorize Session",
            OcsfClass::EntityManagement => "Entity Management",
            OcsfClass::UserAccessManagement => "User Access Management",
        }
    }

    /// Which stream this class is retained on.
    #[must_use]
    pub fn stream(self) -> AuditStream {
        match self {
            OcsfClass::Authentication | OcsfClass::AuthorizeSession => AuditStream::Authentication,
            OcsfClass::AccountChange
            | OcsfClass::EntityManagement
            | OcsfClass::UserAccessManagement => AuditStream::AdminAction,
        }
    }

    /// Every class, for the sweeps.
    pub const ALL: [OcsfClass; 5] = [
        OcsfClass::AccountChange,
        OcsfClass::Authentication,
        OcsfClass::AuthorizeSession,
        OcsfClass::EntityManagement,
        OcsfClass::UserAccessManagement,
    ];
}

/// The two independently retained audit streams (issue #109).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditStream {
    /// Administrative mutations.
    AdminAction,
    /// Authentication and session activity.
    Authentication,
}

impl AuditStream {
    /// The stable wire name, which is what a retention policy and a SIEM sink key on.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuditStream::AdminAction => "admin_action",
            AuditStream::Authentication => "authentication",
        }
    }

    /// Both streams.
    pub const ALL: [AuditStream; 2] = [AuditStream::AdminAction, AuditStream::Authentication];
}

/// The leading segments whose actions are AUTHENTICATION activity (3002).
///
/// A prefix table rather than 232 hand-written arms, and the exhaustiveness test is what
/// makes that safe: an action whose domain appears in no table fails the sweep by name, so
/// the tables cannot silently fall behind the action list.
const AUTHENTICATION_DOMAINS: &[&str] = &[
    "auth",
    "authorization_code",
    "credential",
    "device",
    "dpop",
    "email_otp",
    "login",
    "magic_link",
    "mfa",
    "passkey",
    "password",
    "pow",
    "recovery",
    "sms_otp",
    "token",
    "totp",
    "webauthn",
    // Swallowed by the old fallback and genuinely authentication: each of these is a
    // credential presented, minted, or refused on the login path.
    "abuse",
    "attestation",
    "device_code",
    "external_assertion_issuer",
    "external_assertion_subject_mapping",
    "fedcm",
    "jwt_bearer_assertion",
    "pushed_authorization_request",
    "refresh_family",
    "refresh_token",
    "risk",
    "signup_quarantine",
    // An RFC 8693 exchange MINTS a credential from a credential (issue #125), which is the
    // same event shape as the sibling grants beside it here: `jwt_bearer_assertion` and
    // `device_code` are both "a presented credential was traded for an issued one".
    "token_exchange",
    "trusted_device",
];

/// The leading segments whose actions change a SESSION's authority (3003).
const AUTHORIZE_SESSION_DOMAINS: &[&str] = &[
    "admin_consent",
    "consent",
    "grant",
    "session",
    // Plural, and a DIFFERENT domain from `session`: the bulk-revocation actions live here
    // and the old fallback filed them as configuration.
    "sessions",
    "step_up",
    "sudo",
];

/// The leading segments whose actions change a PRINCIPAL's own record (3001).
const ACCOUNT_CHANGE_DOMAINS: &[&str] = &[
    "account",
    "human",
    "identifier",
    "invitation",
    "service",
    "service_account",
    "signup",
    "trait",
    "trait_schema",
    "user",
];

/// The leading segments whose actions change WHO MAY DO WHAT (3005).
const ACCESS_MANAGEMENT_DOMAINS: &[&str] = &[
    "api_key",
    "ban",
    "client_admin_grant",
    "impersonation",
    "management_credential",
    "org_role",
    "organization",
    "permission",
    "project_grant",
    "role",
    "scope",
    "admin",
    "credential_class",
    "management_key",
];

/// The leading segments whose actions manage a CONFIGURATION entity (3004).
///
/// Enumerated rather than reached by elimination. See the note in [`class_for_wire`] on why
/// the default arm had to go.
const ENTITY_MANAGEMENT_DOMAINS: &[&str] = &[
    "aaguid",
    "brand",
    "client",
    "config_promotion",
    "connector",
    "custom_domain",
    "dcr",
    "email_factor_config",
    "encrypted_secret",
    "envelope",
    "environment",
    "environment_secret",
    "environment_variable",
    "flow_version",
    "locale",
    "mds3",
    "message_template",
    "migration_run",
    "org_connection",
    "resource_server",
    "routing_rule",
    "signing_key",
    "signup_form",
    "sms_config",
    "sms_route",
    "tenant",
    "trait_migration_job",
    "upstream_token",
    "upstream_token_grant",
    "webhook",
];

/// The OCSF class for an action's wire string.
///
/// Returns [`None`] for a domain no table claims, which is what the exhaustiveness test
/// reports. A default arm here would turn every unclassified action into a plausible-looking
/// event nobody chose.
#[must_use]
pub fn class_for_wire(wire: &str) -> Option<OcsfClass> {
    let domain = wire.split_once('.').map_or(wire, |(head, _)| head);
    if AUTHENTICATION_DOMAINS.contains(&domain) {
        return Some(OcsfClass::Authentication);
    }
    if AUTHORIZE_SESSION_DOMAINS.contains(&domain) {
        return Some(OcsfClass::AuthorizeSession);
    }
    if ACCOUNT_CHANGE_DOMAINS.contains(&domain) {
        return Some(OcsfClass::AccountChange);
    }
    if ACCESS_MANAGEMENT_DOMAINS.contains(&domain) {
        return Some(OcsfClass::UserAccessManagement);
    }
    if ENTITY_MANAGEMENT_DOMAINS.contains(&domain) {
        return Some(OcsfClass::EntityManagement);
    }
    // NO fallback. An unlisted domain is UNCLASSIFIED and the exhaustiveness test names it.
    //
    // The first version of this function returned `Some(EntityManagement)` here, and that
    // made the exhaustiveness test vacuous: `is_some()` could never fail, 128 of 232 actions
    // landed in one class, and `sessions.*` and `refresh_token.*` were quietly filed as
    // configuration. A total function with a default arm is not a classification, it is a
    // shrug with a type signature.
    None
}

/// The OCSF class for an action.
/// The OCSF class for an action, or [`None`] when its domain is unclassified.
///
/// Deliberately NOT defaulted: an unclassified action must be a build failure, not an event
/// filed under whichever class happened to be last in the list.
#[must_use]
pub fn class_for(action: Action) -> Option<OcsfClass> {
    class_for_wire(action.as_str())
}

/// The OCSF `actor` object for a principal.
///
/// The three principal kinds round-trip through `type`, which is criterion 5: an agent is
/// not a human with a different id, and a SIEM rule that filters on human activity must be
/// able to say so.
#[must_use]
pub fn actor_object(actor: ActorRef) -> Value {
    json!({
        "user": {
            "uid": actor.id_string(),
            "type": actor.kind_str(),
        }
    })
}

/// Build the OCSF event object for one audit record.
///
/// `occurred_at_unix_ms` is the domain instant, passed in rather than read here so the record
/// says when the thing happened rather than when this ran.
#[must_use]
pub fn ocsf_event(
    action: Action,
    actor: ActorRef,
    tenant_id: &str,
    environment_id: &str,
    occurred_at_unix_ms: i64,
    target: Option<&str>,
) -> Option<Value> {
    // An unclassified action has no class, so there is no OCSF event to build. Returning
    // `None` rather than panicking or substituting a class keeps the one decision in one
    // place: the caller that persists the row is where an unclassified action must fail,
    // and it already does. A panic here would turn our gap into the caller's crash.
    let class = class_for(action)?;
    let mut event = json!({
        "class_uid": class.uid(),
        "class_name": class.name(),
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_name": action.as_str(),
        "time": occurred_at_unix_ms,
        "actor": actor_object(actor),
        "metadata": {
            "product": {"name": "IronAuth", "vendor_name": "IronAuth"},
            "version": "1.1.0",
        },
        "cloud": {
            "provider": "ironauth",
            "account": {"uid": tenant_id},
            "org": {"uid": environment_id},
        },
        "stream": class.stream().as_str(),
    });
    if let Some(target) = target {
        event["resources"] = json!([{"uid": target}]);
    }
    Some(event)
}

/// Build the OCSF event for a STORED audit row, from its wire strings.
///
/// The typed [`ocsf_event`] is for a record being written, where the caller holds an
/// [`Action`] and an [`ActorRef`]. A reader of `audit_log` holds neither: it has the
/// strings that were persisted, and re-parsing them back into typed values would make a
/// row a NEWER build wrote unreadable by an older one rather than merely unclassifiable.
///
/// Returns [`None`] when the action classifies as nothing, which is exactly that
/// rolled-back-binary case. Skipping such a row is the only safe answer: shipping it under
/// a guessed class files it under the wrong dashboard in someone's SIEM.
///
/// The two builders must not drift, so a test asserts they agree field for field on a
/// record expressible both ways.
#[must_use]
pub fn ocsf_event_from_wire(
    action_wire: &str,
    actor_kind: &str,
    actor_id: &str,
    tenant_id: &str,
    environment_id: &str,
    occurred_at_unix_ms: i64,
    target: Option<&str>,
) -> Option<Value> {
    let class = class_for_wire(action_wire)?;
    let mut event = json!({
        "class_uid": class.uid(),
        "class_name": class.name(),
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_name": action_wire,
        "time": occurred_at_unix_ms,
        "actor": {"user": {"uid": actor_id, "type": actor_kind}},
        "metadata": {
            "product": {"name": "IronAuth", "vendor_name": "IronAuth"},
            "version": "1.1.0",
        },
        "cloud": {
            "provider": "ironauth",
            "account": {"uid": tenant_id},
            "org": {"uid": environment_id},
        },
        "stream": class.stream().as_str(),
    });
    if let Some(target) = target {
        event["resources"] = json!([{"uid": target}]);
    }
    Some(event)
}

/// One link of a per-stream hash chain.
///
/// `previous` is the previous record's digest, or the empty string for the first record. The
/// digest covers the previous digest AND the record, which is what makes an insertion or a
/// deletion detectable: every later record commits to the exact sequence before it.
#[must_use]
pub fn chain_link(previous: &str, record: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    // A length prefix, so `previous` and the record cannot be slid across the boundary
    // between them: without it, moving one byte from the end of the digest to the start of
    // the record would hash identically and two different histories would agree.
    hasher.update((previous.len() as u64).to_be_bytes());
    hasher.update(serde_json::to_vec(record).unwrap_or_default().as_slice());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Why a chain failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The index of the FIRST record whose link does not match.
    pub index: usize,
    /// The digest the chain recorded.
    pub recorded: String,
    /// The digest the records actually produce.
    pub computed: String,
}

/// Verify a stream's hash chain.
///
/// Reports the FIRST index that breaks rather than a bare boolean: "the chain is broken" is
/// not actionable and "record 41 is where it broke" is.
///
/// # Errors
///
/// [`ChainBreak`] naming the first mismatching index.
pub fn verify_chain(records: &[(Value, String)]) -> Result<(), ChainBreak> {
    let mut previous = String::new();
    for (index, (record, recorded)) in records.iter().enumerate() {
        let computed = chain_link(&previous, record);
        if &computed != recorded {
            return Err(ChainBreak {
                index,
                recorded: recorded.clone(),
                computed,
            });
        }
        previous = computed;
    }
    Ok(())
}

/// Every action wire string, scanned from `audit.rs`.
///
/// The same scan `event_catalog` and the uniqueness test in `audit.rs` use, and for the same
/// reason: `Action` has no `ALL` to iterate.
///
/// # Panics
///
/// If the scan cannot find the `as_str` body, which means it was renamed or reflowed. An
/// empty sweep would make every exhaustiveness test below pass vacuously.
#[must_use]
pub fn action_wire_strings() -> Vec<String> {
    const SOURCE: &str = include_str!("audit.rs");
    let needle = concat!("pub fn ", "as_str(&self) -> &'static str {");
    let body = SOURCE
        .split_once(needle)
        .map(|(_, rest)| rest)
        .expect("the as_str body is readable");
    let body = body
        .split_once("\n    }\n")
        .map(|(inside, _)| inside)
        .expect("the as_str body is terminated");
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('"') else { break };
        let literal = &rest[..end];
        rest = &rest[end + 1..];
        if !literal.is_empty() {
            out.push(literal.to_owned());
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// How many actions land on each class, for the coverage report the tests assert on.
#[must_use]
pub fn class_histogram() -> BTreeMap<u32, usize> {
    let mut out = BTreeMap::new();
    for wire in action_wire_strings() {
        if let Some(class) = class_for_wire(&wire) {
            *out.entry(class.uid()).or_insert(0) += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{AgentId, HumanId, ServiceId};
    use ironauth_env::Env;

    /// The sweep finds a plausible number of actions.
    ///
    /// A floor, because an empty sweep satisfies every "for each action" assertion below
    /// perfectly and would report total coverage of nothing.
    #[test]
    fn the_action_sweep_finds_a_plausible_number() {
        assert!(
            action_wire_strings().len() >= 100,
            "the action sweep found {} strings; a scan that read nothing would pass every \
             exhaustiveness test here",
            action_wire_strings().len()
        );
    }

    /// EVERY action classifies, and every class is actually used.
    ///
    /// The second half matters: a mapping that funnelled all 232 actions into Entity
    /// Management would be exhaustive and useless, and a SIEM rule written against 3002
    /// would match nothing.
    #[test]
    fn every_action_classifies_and_every_class_is_populated() {
        for wire in action_wire_strings() {
            assert!(
                class_for_wire(&wire).is_some(),
                "`{wire}` maps to no OCSF class"
            );
        }
        let histogram = class_histogram();
        for class in OcsfClass::ALL {
            let count = histogram.get(&class.uid()).copied().unwrap_or(0);
            assert!(
                count > 0,
                "OCSF class {} ({}) has no actions; a SIEM rule written against it would \
                 match nothing, so either the mapping is wrong or the class does not belong",
                class.uid(),
                class.name()
            );
        }
    }

    /// Both streams carry traffic, and the split is the one the module documents.
    #[test]
    fn both_streams_are_populated_and_split_by_class() {
        assert_eq!(
            OcsfClass::Authentication.stream(),
            AuditStream::Authentication
        );
        assert_eq!(
            OcsfClass::AuthorizeSession.stream(),
            AuditStream::Authentication
        );
        for class in [
            OcsfClass::AccountChange,
            OcsfClass::EntityManagement,
            OcsfClass::UserAccessManagement,
        ] {
            assert_eq!(class.stream(), AuditStream::AdminAction);
        }
        let mut per_stream = BTreeMap::new();
        for wire in action_wire_strings() {
            let stream = class_for_wire(&wire).expect("classified").stream();
            *per_stream.entry(stream).or_insert(0_usize) += 1;
        }
        for stream in AuditStream::ALL {
            assert!(
                per_stream.get(&stream).copied().unwrap_or(0) > 0,
                "the `{}` stream carries no actions, so its retention policy governs nothing",
                stream.as_str()
            );
        }
    }

    /// A known authentication action lands on 3002 and a known admin one does not.
    ///
    /// Named actions rather than counts, so a table edit that moved a whole domain to the
    /// wrong class fails here with the action that proves it.
    #[test]
    fn representative_actions_land_on_the_class_a_reader_would_expect() {
        for (wire, expected) in [
            ("token.issue", OcsfClass::Authentication),
            ("webauthn.credential.register", OcsfClass::Authentication),
            ("session.revoke", OcsfClass::AuthorizeSession),
            ("consent.grant", OcsfClass::AuthorizeSession),
            ("user.create", OcsfClass::AccountChange),
            ("account.password.change", OcsfClass::AccountChange),
            ("client.create", OcsfClass::EntityManagement),
            ("webhook.endpoint.create", OcsfClass::EntityManagement),
            ("organization.create", OcsfClass::UserAccessManagement),
            ("permission.create", OcsfClass::UserAccessManagement),
        ] {
            assert_eq!(
                class_for_wire(wire),
                Some(expected),
                "`{wire}` classified as {:?}, expected {expected:?}",
                class_for_wire(wire)
            );
        }
    }

    /// All three principal kinds round-trip through the actor mapping (criterion 5).
    #[test]
    fn every_actor_kind_round_trips_through_the_ocsf_actor() {
        let env = Env::system();
        for (actor, kind) in [
            (ActorRef::Human(HumanId::generate(&env)), "human"),
            (ActorRef::Service(ServiceId::generate(&env)), "service"),
            (ActorRef::Agent(AgentId::generate(&env)), "agent"),
        ] {
            let object = actor_object(actor);
            assert_eq!(
                object["user"]["type"], kind,
                "an agent is not a human with a different id; a SIEM rule filtering on human \
                 activity must be able to say so"
            );
            assert_eq!(object["user"]["uid"], actor.id_string());
        }
    }

    /// The event carries the class, the stream, and the scope.
    #[test]
    fn the_event_carries_its_class_stream_and_scope() {
        let env = Env::system();
        let event = ocsf_event(
            Action::ClientCreate,
            ActorRef::Service(ServiceId::generate(&env)),
            "ten_1",
            "env_1",
            1_700_000_000_000,
            Some("cli_1"),
        )
        .expect("client.create classifies");
        assert_eq!(event["class_uid"], 3004);
        assert_eq!(event["stream"], "admin_action");
        assert_eq!(event["cloud"]["account"]["uid"], "ten_1");
        assert_eq!(event["cloud"]["org"]["uid"], "env_1");
        assert_eq!(event["resources"][0]["uid"], "cli_1");
        assert_eq!(event["time"], 1_700_000_000_000_i64);
    }

    fn chain(records: &[Value]) -> Vec<(Value, String)> {
        let mut previous = String::new();
        let mut out = Vec::new();
        for record in records {
            let link = chain_link(&previous, record);
            out.push((record.clone(), link.clone()));
            previous = link;
        }
        out
    }

    /// An intact chain verifies.
    #[test]
    fn an_intact_chain_verifies() {
        let built = chain(&[json!({"n": 1}), json!({"n": 2}), json!({"n": 3})]);
        assert_eq!(verify_chain(&built), Ok(()));
    }

    /// MODIFYING a stored record breaks the chain, at that record.
    #[test]
    fn modifying_a_record_breaks_the_chain_at_that_record() {
        let mut built = chain(&[json!({"n": 1}), json!({"n": 2}), json!({"n": 3})]);
        built[1].0 = json!({"n": 99});
        let break_at = verify_chain(&built).expect_err("a modified record must break");
        assert_eq!(
            break_at.index, 1,
            "the report must name WHERE it broke; `the chain is broken` is not actionable"
        );
    }

    /// DELETING a record breaks the chain.
    ///
    /// The case a per-record digest alone would miss: each surviving record is individually
    /// intact, and only the link to its predecessor shows the gap.
    #[test]
    fn deleting_a_record_breaks_the_chain() {
        let mut built = chain(&[json!({"n": 1}), json!({"n": 2}), json!({"n": 3})]);
        built.remove(1);
        let break_at = verify_chain(&built).expect_err("a deletion must break the chain");
        assert_eq!(break_at.index, 1);
    }

    /// INSERTING a record breaks the chain.
    #[test]
    fn inserting_a_record_breaks_the_chain() {
        let mut built = chain(&[json!({"n": 1}), json!({"n": 2})]);
        let forged = json!({"n": 1_000});
        built.insert(1, (forged.clone(), chain_link("", &forged)));
        assert!(
            verify_chain(&built).is_err(),
            "an insertion must break the chain"
        );
    }

    /// TRUNCATING the tail is detectable only against an expected head, so the chain alone
    /// verifies a prefix. Asserted so the LIMIT is on the record rather than assumed away.
    ///
    /// A chain is a prefix-consistent structure: lopping off the end leaves a shorter, valid
    /// chain. Detecting truncation needs the expected final digest kept somewhere the
    /// truncator cannot reach, which is a deployment concern rather than a property of the
    /// hash. Saying so here stops somebody reading `verify_chain` as more than it is.
    #[test]
    fn truncation_leaves_a_valid_prefix_which_is_why_the_head_digest_must_be_kept() {
        let built = chain(&[json!({"n": 1}), json!({"n": 2}), json!({"n": 3})]);
        let truncated = &built[..2];
        assert_eq!(
            verify_chain(truncated),
            Ok(()),
            "a truncated chain is a valid prefix; only the retained head digest catches it"
        );
        assert_ne!(
            built.last().map(|(_, digest)| digest),
            truncated.last().map(|(_, digest)| digest),
            "the head digest DOES differ, which is what a keeper of it would compare"
        );
    }

    /// Migration 0133's backfill lists only authentication-stream domains.
    ///
    /// That backfill is the ONE place a domain list appears in SQL, and it exists because
    /// rows written before the split have no stream. It is correct for it to be frozen: it
    /// classifies only the actions that existed when it ran. What would NOT be correct is
    /// for it to have been wrong on the day it was written, or for a domain to later move
    /// out of the authentication stream while old rows stay filed under it. Both are what
    /// this test catches.
    ///
    /// The list is parsed out of the shipped SQL rather than restated here. A copy in the
    /// test would agree with itself and with nothing else.
    #[test]
    fn the_migration_backfill_lists_only_authentication_domains() {
        const PREDICATE: &str = "split_part(action, '.', 1) IN (";
        let sql = include_str!("../migrations/0134_audit_stream_backfill.sql");
        // Past the predicate, not at it: the first `)` after the start of `split_part` is
        // that call's OWN closing paren, and anchoring there parses an empty list. The
        // length guard below is what caught it.
        let open = sql
            .find(PREDICATE)
            .expect("the backfill predicate must be in the migration")
            + PREDICATE.len();
        let close = sql[open..]
            .find(')')
            .expect("the backfill list must be closed")
            + open;
        let listed: Vec<&str> = sql[open..close]
            .split('\'')
            .skip(1)
            .step_by(2)
            .filter(|token| *token != "." && !token.is_empty())
            .collect();

        // Anti-vacuity: an empty or truncated parse would pass every assertion below.
        assert!(
            listed.len() > 30,
            "parsed only {} domains out of the backfill; the parse is broken, not the SQL",
            listed.len()
        );
        assert!(
            listed.contains(&"password") && listed.contains(&"sessions"),
            "the parse lost known entries: {listed:?}"
        );

        for domain in &listed {
            let class = class_for_wire(&format!("{domain}.probe")).unwrap_or_else(|| {
                panic!("the backfill lists `{domain}`, which classifies as nothing")
            });
            assert_eq!(
                class.stream(),
                AuditStream::Authentication,
                "the backfill files `{domain}` under the authentication stream, but the \
                 classifier puts it in {:?}",
                class.stream()
            );
        }
    }

    /// Each class carries its OCSF-spec uid and name, pinned as literals.
    ///
    /// These numbers are the interop contract: a SIEM routes on `class_uid`, so an off-by-one
    /// does not fail anywhere in this repo, it silently files every account change under
    /// somebody else's dashboard. A mutation sweep changed 3001 to 3009 and the whole suite
    /// stayed green, which is how this test came to exist.
    ///
    /// The literals are duplicated from `uid` on purpose. A test that recomputed them from
    /// the same match would agree with any value the match happened to hold.
    #[test]
    fn every_class_carries_its_ocsf_spec_uid_and_name() {
        let expected = [
            (OcsfClass::AccountChange, 3001_u32, "Account Change"),
            (OcsfClass::Authentication, 3002, "Authentication"),
            (OcsfClass::AuthorizeSession, 3003, "Authorize Session"),
            (OcsfClass::EntityManagement, 3004, "Entity Management"),
            (
                OcsfClass::UserAccessManagement,
                3005,
                "User Access Management",
            ),
        ];
        assert_eq!(
            expected.len(),
            OcsfClass::ALL.len(),
            "a class was added or removed without pinning its OCSF uid here"
        );
        for (class, uid, name) in expected {
            assert_eq!(class.uid(), uid, "{name} must keep OCSF class_uid {uid}");
            assert_eq!(class.name(), name, "{name} must keep its OCSF class name");
        }
        // Distinct, and inside the OCSF Identity and Access Management category (3000s).
        let mut uids: Vec<u32> = OcsfClass::ALL.iter().map(|c| c.uid()).collect();
        uids.sort_unstable();
        uids.dedup();
        assert_eq!(
            uids.len(),
            OcsfClass::ALL.len(),
            "two classes share a class_uid"
        );
        assert!(
            uids.iter().all(|u| (3001..=3005).contains(u)),
            "every class must be an OCSF IAM class: {uids:?}"
        );
    }

    /// The typed and wire event builders must not drift.
    ///
    /// Two builders for one shape is a duplication that rots silently: a field added to
    /// one is simply absent from the other's output, and the consumer that notices is a
    /// customer's SIEM. They are compared field for field on a record expressible both
    /// ways.
    #[test]
    fn the_typed_and_wire_event_builders_agree() {
        let env = Env::system();
        let actor = ActorRef::Service(ServiceId::generate(&env));
        let typed = ocsf_event(
            Action::ClientCreate,
            actor,
            "ten_1",
            "env_1",
            1_700_000_000_000,
            Some("cli_1"),
        )
        .expect("client.create classifies");
        let from_wire = ocsf_event_from_wire(
            Action::ClientCreate.as_str(),
            actor.kind_str(),
            &actor.id_string(),
            "ten_1",
            "env_1",
            1_700_000_000_000,
            Some("cli_1"),
        )
        .expect("client.create classifies");
        assert_eq!(
            typed, from_wire,
            "the two builders must produce identical events, or a reader and a writer \
             describe the same audit row differently"
        );
    }

    /// The length prefix stops a byte sliding across the previous/record boundary.
    ///
    /// Without it, two different histories hash identically, and a chain that can be forged
    /// is not tamper evidence.
    ///
    /// The record must be a NUMBER. The first version of this test used JSON strings, and it
    /// passed with the length prefix deleted: `serde_json` wraps a string in quotes, so the
    /// record was already self-delimiting and the concatenation could not collide. The test
    /// asserted a property the code did not have to hold. A number serializes to bare digits
    /// with no delimiter of its own, which is the case the prefix actually defends.
    #[test]
    fn the_length_prefix_separates_the_previous_digest_from_the_record() {
        // Both sides concatenate to the bytes `abc123` when nothing separates them.
        let left = chain_link("abc1", &json!(23));
        let right = chain_link("abc12", &json!(3));
        assert_ne!(
            left, right,
            "the previous digest and the record must not be sliddable across their boundary"
        );
    }
}
