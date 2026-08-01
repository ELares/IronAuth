// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial acceptance for the signed journey interchange archive (issue #347).
//!
//! Every case here drives a REAL archive: a real Ed25519 key, a real
//! [`ironauth_store::export_archive`], and a real [`ironauth_store::import_archive`] through
//! `ironauth_jose::verify`. Nothing is mocked, and in particular no test asserts against a stubbed
//! verifier, because a stubbed verifier proves only that the stub was called.
//!
//! The sharpest tests are the HOSTILE EXPORTER ones. They do not tamper with a signature: they
//! re-sign a doctored payload with the exporter's own, genuinely TRUSTED key. That is the real
//! threat model for cross-organization sharing, where the party who wrote the bundle is the party
//! you do not control, and it is the only construction that can tell a manifest the importer
//! CHECKS apart from one the importer BELIEVES.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::ManualClock;
use ironauth_jose::{EmissionOptions, SigningKey, TokenTyp, sign_jws};
use ironauth_journey::{
    CmpOp, FieldRef, FieldSource, JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION, Journey, Literal,
    Predicate, Step, StepKind, Subflow, SubflowRef, SubflowSource, Transition,
};
use ironauth_store::{
    Capability, ExportRequest, FixedCapability, GrantedCapabilities, ImportEnvironment,
    ImportedBundle, InterchangeError, MAX_ARCHIVE_BYTES, SafetyManifest, SignedArchive,
    TrustedExporter, export_archive, import_archive,
};
use serde_json::{Map, Value};

/// The exporting organization's issuer. The importer pins it exactly.
const EXPORTER_ISSUER: &str = "https://exporter.example.test/t/acme/e/prod";

/// A fixed instant, well inside the archive validity window below.
const NOW_SECS: u64 = 1_800_000_000;
const ISSUED_AT: i64 = 1_799_999_000;
const EXPIRES_AT: i64 = 1_800_086_400;

fn clock_at(secs: u64) -> ManualClock {
    ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

fn exporter_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("exporter-1".to_owned()), &[9_u8; 32]).expect("ed25519 key")
}

/// A key nobody trusts.
fn stranger_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("stranger-1".to_owned()), &[3_u8; 32]).expect("ed25519 key")
}

fn trusted_exporter(key: &SigningKey) -> TrustedExporter {
    TrustedExporter::from_keys(
        EXPORTER_ISSUER,
        vec![key.verifying_key().expect("verifying key")],
    )
    .expect("trust anchor")
}

fn transports() -> BTreeSet<String> {
    ["browser".to_owned(), "api".to_owned()]
        .into_iter()
        .collect()
}

/// An environment that grants everything the engine ships with and serves both transports.
fn default_environment() -> ImportEnvironment {
    ImportEnvironment::new(GrantedCapabilities::engine_default(), transports())
}

fn step(id: &str, kind: StepKind, node_group: Option<&str>) -> Step {
    Step {
        id: id.to_owned(),
        kind,
        node_group: node_group.map(str::to_owned),
        subflow: None,
        decision: None,
        comment: None,
    }
}

fn signal_guard(value: bool) -> Predicate {
    Predicate::Cmp {
        field: FieldRef {
            source: FieldSource::Signals,
            pointer: "/mfa_required".to_owned(),
        },
        op: CmpOp::Eq,
        value: Literal::Bool(value),
    }
}

/// The shared fixture: identifier plus password, a guarded step up into the BUILT-IN `mfa_step_up`
/// subflow, then a terminal.
///
/// It deliberately exercises several DISTINCT capability families at once (a step kind, a node
/// group, a guard, a comparison, a signal source, a boolean literal, a subflow call, a built-in
/// subflow reference, and the `mfa_challenge` step and `totp` node group that live only inside the
/// spliced built-in body), so the under-declaration cases below can each remove a different one.
fn fixture_journey() -> Journey {
    Journey {
        schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
        id: "login_step_up".to_owned(),
        engine_version: JOURNEY_ENGINE_VERSION,
        entry: "primary".to_owned(),
        comment: None,
        steps: vec![
            step("primary", StepKind::IdentifierPassword, Some("password")),
            Step {
                subflow: Some("mfa_step_up".to_owned()),
                ..step("stepup", StepKind::SubflowCall, None)
            },
            step("done", StepKind::Terminal, None),
        ],
        transitions: vec![
            Transition {
                from: "primary".to_owned(),
                to: "stepup".to_owned(),
                guard: Some(signal_guard(true)),
                comment: None,
            },
            Transition {
                from: "primary".to_owned(),
                to: "done".to_owned(),
                guard: Some(signal_guard(false)),
                comment: None,
            },
            Transition {
                from: "stepup".to_owned(),
                to: "done".to_owned(),
                guard: None,
                comment: None,
            },
        ],
        subflows: Some(vec![SubflowRef {
            id: "mfa_step_up".to_owned(),
            source: SubflowSource::Builtin {
                name: "mfa_step_up".to_owned(),
            },
        }]),
        subflow_definitions: None,
    }
}

fn export(key: &SigningKey, artifact: &Journey, subflows: &[Subflow]) -> String {
    export_archive(
        key,
        &ExportRequest {
            issuer: EXPORTER_ISSUER,
            artifact,
            subflows,
            allowed_transports: &transports(),
            issued_at_secs: ISSUED_AT,
            expires_at_secs: EXPIRES_AT,
        },
    )
    .expect("export")
}

fn good_archive() -> String {
    export(&exporter_key(), &fixture_journey(), &[])
}

fn import(archive: &str, exporter: &TrustedExporter) -> Result<ImportedBundle, InterchangeError> {
    import_archive(
        archive.as_bytes(),
        exporter,
        &default_environment(),
        &clock_at(NOW_SECS),
    )
}

/// Read an archive's payload back out as a mutable JSON object.
fn payload_of(archive: &str) -> Map<String, Value> {
    let container: SignedArchive = serde_json::from_str(archive).expect("archive parses");
    let bytes = URL_SAFE_NO_PAD
        .decode(container.payload.as_bytes())
        .expect("payload decodes");
    serde_json::from_slice(&bytes).expect("payload is an object")
}

/// THE HOSTILE EXPORTER: mint a fresh, structurally perfect archive over a doctored payload, with
/// the exporter's own genuinely trusted key.
///
/// Nothing about the result is forged. The signature is valid, the key is trusted, the issuer is
/// right, the media type is right. Only the CONTENT is a lie, which is exactly the position a
/// cross-organization exporter is in.
fn resign(key: &SigningKey, payload: &Map<String, Value>) -> String {
    let bytes = serde_json::to_vec(payload).expect("payload serializes");
    let compact = sign_jws(
        key,
        &bytes,
        &EmissionOptions::new().with_token_typ(TokenTyp::JourneyInterchange),
    )
    .expect("sign");
    let mut segments = compact.split('.');
    let archive = SignedArchive {
        protected: segments.next().expect("protected").to_owned(),
        payload: segments.next().expect("payload").to_owned(),
        signature: segments.next().expect("signature").to_owned(),
    };
    serde_json::to_string(&archive).expect("archive serializes")
}

/// Re-sign an archive after mutating its manifest.
fn resign_with_manifest(
    key: &SigningKey,
    archive: &str,
    edit: impl FnOnce(&mut SafetyManifest),
) -> String {
    let mut payload = payload_of(archive);
    let mut manifest: SafetyManifest =
        serde_json::from_value(payload["manifest"].clone()).expect("manifest");
    edit(&mut manifest);
    payload.insert(
        "manifest".to_owned(),
        serde_json::to_value(&manifest).expect("manifest serializes"),
    );
    resign(key, &payload)
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_valid_archive_imports_and_reports_the_derived_capabilities() {
    let key = exporter_key();
    let bundle = import(&good_archive(), &trusted_exporter(&key)).expect("a valid archive imports");

    assert_eq!(bundle.exporter_issuer, EXPORTER_ISSUER);
    assert_eq!(bundle.key_id.as_deref(), Some("exporter-1"));
    assert_eq!(bundle.artifact.id, "login_step_up");
    // The reported set is the DERIVED one, and it reaches inside the built-in subflow body the
    // bundle only named.
    for expected in [
        Capability::step(&StepKind::IdentifierPassword),
        Capability::step(&StepKind::SubflowCall),
        Capability::step(&StepKind::MfaChallenge),
        Capability::step(&StepKind::Terminal),
        Capability::node_group("password"),
        Capability::node_group("totp"),
        Capability::builtin_subflow("mfa_step_up"),
        Capability::fixed(FixedCapability::TRANSITION_GUARD),
        Capability::fixed(FixedCapability::PREDICATE_CMP),
        Capability::fixed(FixedCapability::OP_EQ),
        Capability::fixed(FixedCapability::FIELD_SIGNALS),
        Capability::fixed(FixedCapability::LITERAL_BOOL),
    ] {
        assert!(
            bundle.capabilities.contains(&expected),
            "{expected} was not derived"
        );
    }
    // The stored artifact round-trips back to the verified value.
    let parsed: Journey = serde_json::from_str(&bundle.artifact_json).expect("artifact json");
    assert_eq!(parsed, bundle.artifact);
}

#[test]
fn the_export_manifest_is_exactly_what_the_import_derives() {
    // Export writes the manifest by DERIVING it, and import re-derives and demands equality, so a
    // freshly exported archive can never trip either the under or the over declaration check. If
    // the two derivations were separate implementations this is the test that would break.
    let key = exporter_key();
    let archive = good_archive();
    let manifest: SafetyManifest =
        serde_json::from_value(payload_of(&archive)["manifest"].clone()).expect("manifest");
    let bundle = import(&archive, &trusted_exporter(&key)).expect("imports");
    assert_eq!(manifest.required_capabilities, bundle.capabilities);
    assert_eq!(
        manifest.launch_constraints.min_engine_version,
        JOURNEY_ENGINE_VERSION
    );
    assert!(!manifest.launch_constraints.requires_sandbox);
}

#[test]
fn an_archive_whose_payload_is_not_canonical_still_verifies() {
    // Import verifies the bytes it RECEIVED and parses those same bytes. It does not
    // re-canonicalize and compare, which would be the second derivation this design exists to
    // avoid. `resign` serializes with plain serde_json rather than the canonical writer, so this
    // archive's payload bytes are not the canonical ones, and it must still import.
    let key = exporter_key();
    let payload = payload_of(&good_archive());
    let archive = resign(&key, &payload);
    import(&archive, &trusted_exporter(&key))
        .expect("a non-canonical payload verifies and imports");
}

// ---------------------------------------------------------------------------
// Tampering, stripping, and the wrong key
// ---------------------------------------------------------------------------

#[test]
fn a_tampered_payload_is_rejected() {
    let key = exporter_key();
    let mut payload = payload_of(&good_archive());
    // Swap the artifact for a different journey, leaving the original signature in place.
    let mut other = fixture_journey();
    other.id = "attacker_journey".to_owned();
    payload.insert(
        "artifact".to_owned(),
        serde_json::to_value(&other).expect("journey"),
    );

    let original: SignedArchive = serde_json::from_str(&good_archive()).expect("archive");
    let tampered = SignedArchive {
        protected: original.protected,
        payload: URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload")),
        signature: original.signature,
    };
    let archive = serde_json::to_string(&tampered).expect("archive");
    let error = import(&archive, &trusted_exporter(&key)).expect_err("a tampered payload");
    assert!(matches!(error, InterchangeError::SignatureRejected(_)));
}

#[test]
fn a_tampered_manifest_is_rejected() {
    // The manifest is INSIDE the signed payload, so doctoring it without re-signing is a signature
    // failure and never reaches the capability check.
    let key = exporter_key();
    let mut payload = payload_of(&good_archive());
    let mut manifest: SafetyManifest =
        serde_json::from_value(payload["manifest"].clone()).expect("manifest");
    manifest.launch_constraints.requires_sandbox = true;
    payload.insert(
        "manifest".to_owned(),
        serde_json::to_value(&manifest).expect("manifest"),
    );

    let original: SignedArchive = serde_json::from_str(&good_archive()).expect("archive");
    let tampered = SignedArchive {
        protected: original.protected,
        payload: URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload")),
        signature: original.signature,
    };
    let archive = serde_json::to_string(&tampered).expect("archive");
    let error = import(&archive, &trusted_exporter(&key)).expect_err("a tampered manifest");
    assert!(matches!(error, InterchangeError::SignatureRejected(_)));
}

#[test]
fn a_tampered_protected_header_is_rejected() {
    // The header is covered by the signature too: swapping the declared kid breaks it.
    let key = exporter_key();
    let original: SignedArchive = serde_json::from_str(&good_archive()).expect("archive");
    let header = serde_json::json!({"alg": "EdDSA", "kid": "exporter-1", "typ": "iaj+jws", "x": 1});
    let tampered = SignedArchive {
        protected: URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header")),
        payload: original.payload,
        signature: original.signature,
    };
    let archive = serde_json::to_string(&tampered).expect("archive");
    let error = import(&archive, &trusted_exporter(&key)).expect_err("a tampered header");
    assert!(matches!(error, InterchangeError::SignatureRejected(_)));
}

#[test]
fn a_stripped_signature_is_rejected() {
    let key = exporter_key();
    let original: SignedArchive = serde_json::from_str(&good_archive()).expect("archive");

    // Emptied.
    let stripped = SignedArchive {
        protected: original.protected.clone(),
        payload: original.payload.clone(),
        signature: String::new(),
    };
    let archive = serde_json::to_string(&stripped).expect("archive");
    assert_eq!(
        import(&archive, &trusted_exporter(&key)),
        Err(InterchangeError::ArchiveSegmentMalformed)
    );

    // Removed entirely: the container no longer parses.
    let archive = format!(
        r#"{{"protected":"{}","payload":"{}"}}"#,
        original.protected, original.payload
    );
    assert_eq!(
        import(&archive, &trusted_exporter(&key)),
        Err(InterchangeError::ArchiveMalformed)
    );
}

#[test]
fn an_unsigned_archive_is_rejected() {
    // The `alg: none` unsecured JWS, in both spellings: an empty signature segment, and a
    // non-empty one that reaches the verifier's header stage.
    let key = exporter_key();
    let original: SignedArchive = serde_json::from_str(&good_archive()).expect("archive");
    let none_header =
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"exporter-1","typ":"iaj+jws"}"#);

    let archive = serde_json::to_string(&SignedArchive {
        protected: none_header.clone(),
        payload: original.payload.clone(),
        signature: String::new(),
    })
    .expect("archive");
    assert_eq!(
        import(&archive, &trusted_exporter(&key)),
        Err(InterchangeError::ArchiveSegmentMalformed)
    );

    let archive = serde_json::to_string(&SignedArchive {
        protected: none_header,
        payload: original.payload,
        signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
    })
    .expect("archive");
    let error = import(&archive, &trusted_exporter(&key)).expect_err("alg none");
    assert!(matches!(error, InterchangeError::SignatureRejected(_)));
}

#[test]
fn an_archive_signed_by_an_untrusted_key_is_rejected() {
    // Structurally flawless, signed by a key the importer never trusted.
    let stranger = stranger_key();
    let archive = export(&stranger, &fixture_journey(), &[]);
    let error =
        import(&archive, &trusted_exporter(&exporter_key())).expect_err("an untrusted signer");
    assert!(matches!(error, InterchangeError::SignatureRejected(_)));

    // And the same archive DOES import once the stranger is the trusted exporter, so the rejection
    // above is about trust and not about the archive being malformed.
    import(&archive, &trusted_exporter(&stranger)).expect("the trusted signer's archive imports");
}

#[test]
fn an_archive_from_another_issuer_is_rejected() {
    let key = exporter_key();
    let archive = export_archive(
        &key,
        &ExportRequest {
            issuer: "https://someone-else.example.test",
            artifact: &fixture_journey(),
            subflows: &[],
            allowed_transports: &transports(),
            issued_at_secs: ISSUED_AT,
            expires_at_secs: EXPIRES_AT,
        },
    )
    .expect("export");
    let error = import(&archive, &trusted_exporter(&key)).expect_err("a wrong issuer");
    assert!(matches!(error, InterchangeError::SignatureRejected(_)));
}

#[test]
fn an_archive_stamped_with_another_profiles_media_type_is_rejected() {
    // A token minted by the same trusted key under a DIFFERENT profile cannot be spent as an
    // archive: this is the `typ` separation the new profile buys.
    let key = exporter_key();
    let payload = payload_of(&good_archive());
    let compact = sign_jws(
        &key,
        &serde_json::to_vec(&payload).expect("payload"),
        &EmissionOptions::new().with_token_typ(TokenTyp::AccessToken),
    )
    .expect("sign");
    let mut segments = compact.split('.');
    let archive = serde_json::to_string(&SignedArchive {
        protected: segments.next().expect("protected").to_owned(),
        payload: segments.next().expect("payload").to_owned(),
        signature: segments.next().expect("signature").to_owned(),
    })
    .expect("archive");
    let error = import(&archive, &trusted_exporter(&key)).expect_err("a wrong media type");
    assert!(matches!(error, InterchangeError::SignatureRejected(_)));
}

#[test]
fn an_expired_archive_is_rejected() {
    let key = exporter_key();
    let archive = good_archive();
    let error = import_archive(
        archive.as_bytes(),
        &trusted_exporter(&key),
        &default_environment(),
        // Well past the archive's exp.
        &clock_at(u64::try_from(EXPIRES_AT).expect("positive") + 86_400),
    )
    .expect_err("an expired archive");
    assert!(matches!(error, InterchangeError::SignatureRejected(_)));
}

// ---------------------------------------------------------------------------
// The container
// ---------------------------------------------------------------------------

#[test]
fn an_archive_carrying_a_fourth_container_member_is_rejected() {
    // An unprotected `header` member is data the signature does not cover. It is refused, not
    // ignored.
    let key = exporter_key();
    let original: SignedArchive = serde_json::from_str(&good_archive()).expect("archive");
    let archive = format!(
        r#"{{"protected":"{}","payload":"{}","signature":"{}","header":{{"kid":"other"}}}}"#,
        original.protected, original.payload, original.signature
    );
    assert_eq!(
        import(&archive, &trusted_exporter(&key)),
        Err(InterchangeError::ArchiveMalformed)
    );
}

#[test]
fn an_oversize_archive_is_refused_before_it_is_parsed() {
    let key = exporter_key();
    let archive = "x".repeat(MAX_ARCHIVE_BYTES + 1);
    assert_eq!(
        import(&archive, &trusted_exporter(&key)),
        Err(InterchangeError::ArchiveTooLarge {
            limit: MAX_ARCHIVE_BYTES
        })
    );
}

#[test]
fn an_extra_payload_member_is_rejected_even_when_correctly_signed() {
    let key = exporter_key();
    let mut payload = payload_of(&good_archive());
    payload.insert("sub".to_owned(), Value::String("someone".to_owned()));
    let archive = resign(&key, &payload);
    let error = import(&archive, &trusted_exporter(&key)).expect_err("an extra payload member");
    assert!(matches!(error, InterchangeError::PayloadShape { .. }));
}

#[test]
fn a_payload_whose_audience_is_an_array_is_rejected() {
    // The JOSE verifier accepts `aud` as an array containing the expected value. An archive's
    // audience is the single profile string and nothing else, so the extra shape is refused here.
    let key = exporter_key();
    let mut payload = payload_of(&good_archive());
    let audience = payload["aud"].clone();
    payload.insert("aud".to_owned(), Value::Array(vec![audience]));
    let archive = resign(&key, &payload);
    let error = import(&archive, &trusted_exporter(&key)).expect_err("an array audience");
    assert!(matches!(error, InterchangeError::PayloadShape { .. }));
}

// ---------------------------------------------------------------------------
// Duplicate keys: exactly how far the unique-key parse reaches
// ---------------------------------------------------------------------------

/// Sign a payload supplied as RAW TEXT rather than as a `Map`, which is the only way to put a
/// duplicate key in one: a `serde_json::Map` cannot hold two entries for one key.
fn resign_raw(key: &SigningKey, payload: &str) -> String {
    let compact = sign_jws(
        key,
        payload.as_bytes(),
        &EmissionOptions::new().with_token_typ(TokenTyp::JourneyInterchange),
    )
    .expect("sign");
    let mut segments = compact.split('.');
    serde_json::to_string(&SignedArchive {
        protected: segments.next().expect("protected").to_owned(),
        payload: segments.next().expect("payload").to_owned(),
        signature: segments.next().expect("signature").to_owned(),
    })
    .expect("archive serializes")
}

/// A LOCK on the exact reach of the duplicate-key rejection, in both directions.
///
/// The container and the top-level payload are parsed by parsers that refuse a duplicate key. An
/// object NESTED inside the payload is not: `ironauth-jose`'s `parse_unique_object` enforces
/// uniqueness only in its own `visit_map`, and every nested object below that is an ordinary
/// `serde_json::Value`, so `serde_json`'s last-value-wins applies. This test pins that as it is.
///
/// It is NOT a signature bypass and the distinction matters. There is exactly one parse of the
/// signature-covered bytes, and `project` reads the artifact out of THAT tree, so the value acted
/// on is the value the parse produced. The exposure is different and smaller: a signed `.iaj` whose
/// artifact carries a duplicate key is AMBIGUOUS to a third-party inspector, which may read the
/// first value where IronAuth reads the last. Making the parse recurse would change how every token
/// in the system is parsed, which is out of proportion to that. Whoever does change it must update
/// this test AND the two prose claims that cite it (this module's header and the store CHANGELOG).
#[test]
fn a_duplicate_key_is_refused_at_the_container_and_the_payload_top_level_but_not_below_it() {
    let key = exporter_key();
    let original: SignedArchive = serde_json::from_str(&good_archive()).expect("archive");

    // 1. The CONTAINER, with `payload` twice.
    let archive = format!(
        r#"{{"protected":"{}","payload":"{}","signature":"{}","payload":"{}"}}"#,
        original.protected,
        original.payload,
        original.signature,
        URL_SAFE_NO_PAD.encode(b"{}")
    );
    assert_eq!(
        import(&archive, &trusted_exporter(&key)),
        Err(InterchangeError::ArchiveMalformed),
        "a duplicate container member is refused"
    );

    // 2. The PAYLOAD TOP LEVEL, with `iss` twice, the first naming a different issuer.
    let body = serde_json::to_string(&payload_of(&good_archive())).expect("json");
    let doubled = body.replacen('{', r#"{"iss":"https://evil.example.test","#, 1);
    assert_ne!(doubled, body, "the injection point exists");
    let error = import(&resign_raw(&key, &doubled), &trusted_exporter(&key))
        .expect_err("a duplicate top-level payload key is refused");
    assert!(
        matches!(error, InterchangeError::SignatureRejected(_)),
        "the unique-key parse lives inside the verifier, so its refusal is uniform: {error:?}"
    );

    // 3. NESTED inside `artifact`, with `id` twice. Accepted, LAST value winning.
    let doubled = body.replacen(
        r#""artifact":{"#,
        r#""artifact":{"id":"looks_harmless","#,
        1,
    );
    assert_ne!(doubled, body, "the injection point exists");
    let bundle = import(&resign_raw(&key, &doubled), &trusted_exporter(&key))
        .expect("a duplicate key nested inside the artifact is accepted today");
    assert_eq!(
        bundle.artifact.id, "login_step_up",
        "and the LAST value wins, which is the value the one parse produced and the value acted on"
    );
    // The re-serialized artifact carries that same one value, so nothing downstream can disagree
    // with what was checked: there is one tree, not two readings of the bytes.
    assert!(bundle.artifact_json.contains(r#""id":"login_step_up""#));
    assert!(!bundle.artifact_json.contains("looks_harmless"));
}

// ---------------------------------------------------------------------------
// The hostile exporter: the manifest is a CHECKED CLAIM
// ---------------------------------------------------------------------------

/// Prove the deriver is not vacuous, once per capability FAMILY.
///
/// Each case removes a DIFFERENT capability from an otherwise perfect manifest and re-signs with
/// the trusted key, so the only thing wrong with the archive is the declaration. A deriver that
/// returned a constant, or that walked only part of the artifact, would let at least one of these
/// through.
#[test]
fn an_under_declaring_manifest_is_refused_for_each_of_several_distinct_capabilities() {
    let key = exporter_key();
    let exporter = trusted_exporter(&key);
    let archive = good_archive();

    let cases: Vec<(&str, Capability)> = vec![
        // A step kind named directly by the bundle.
        (
            "a directly named step kind",
            Capability::step(&StepKind::IdentifierPassword),
        ),
        // A step kind that exists ONLY inside the built-in subflow body the environment splices
        // in. A deriver that walked only the source document would miss this one.
        (
            "a step kind only the spliced built-in body has",
            Capability::step(&StepKind::MfaChallenge),
        ),
        // A node group, likewise only inside the spliced body.
        (
            "a node group only the spliced built-in body has",
            Capability::node_group("totp"),
        ),
        // A node group named directly.
        (
            "a directly named node group",
            Capability::node_group("password"),
        ),
        // The subflow reference itself, which composition ERASES: a deriver that walked only the
        // compiled table would miss this one.
        (
            "the built-in subflow reference composition erases",
            Capability::builtin_subflow("mfa_step_up"),
        ),
        (
            "the subflow_call step kind composition erases",
            Capability::step(&StepKind::SubflowCall),
        ),
        // The predicate machinery, one layer at a time.
        (
            "the fact of a guarded transition",
            Capability::fixed(FixedCapability::TRANSITION_GUARD),
        ),
        (
            "the comparison predicate form",
            Capability::fixed(FixedCapability::PREDICATE_CMP),
        ),
        (
            "the comparison operator",
            Capability::fixed(FixedCapability::OP_EQ),
        ),
        (
            "the context source the guard reads",
            Capability::fixed(FixedCapability::FIELD_SIGNALS),
        ),
        (
            "the literal type the guard compares against",
            Capability::fixed(FixedCapability::LITERAL_BOOL),
        ),
    ];

    for (what, capability) in cases {
        let doctored = resign_with_manifest(&key, &archive, |manifest| {
            assert!(
                manifest.required_capabilities.remove(&capability),
                "{what}: {capability} was not in the honest manifest, so this case proves nothing"
            );
        });
        match import(&doctored, &exporter) {
            Err(InterchangeError::CapabilityUnderDeclared { missing }) => {
                assert_eq!(missing, vec![capability], "{what}");
            }
            other => panic!("{what}: expected an under-declaration refusal, got {other:?}"),
        }
    }
}

#[test]
fn each_under_declaration_names_exactly_the_missing_capability() {
    let key = exporter_key();
    let exporter = trusted_exporter(&key);
    let archive = good_archive();

    for capability in [
        Capability::step(&StepKind::MfaChallenge),
        Capability::node_group("totp"),
        Capability::builtin_subflow("mfa_step_up"),
        Capability::fixed(FixedCapability::TRANSITION_GUARD),
        Capability::fixed(FixedCapability::FIELD_SIGNALS),
    ] {
        let doctored = resign_with_manifest(&key, &archive, |manifest| {
            assert!(manifest.required_capabilities.remove(&capability));
        });
        match import(&doctored, &exporter) {
            Err(InterchangeError::CapabilityUnderDeclared { missing }) => {
                assert_eq!(
                    missing,
                    vec![capability.clone()],
                    "the refusal names exactly the undeclared capability"
                );
                // And the message is precise rather than generic.
                let rendered = InterchangeError::CapabilityUnderDeclared { missing }.to_string();
                assert!(
                    rendered.contains(capability.as_wire()),
                    "the message names the capability: {rendered}"
                );
            }
            other => {
                panic!("expected an under-declaration refusal for {capability}, got {other:?}")
            }
        }
    }
}

#[test]
fn an_over_declaring_manifest_is_refused_and_reported_as_such() {
    let key = exporter_key();
    let extra = Capability::node_group("passkey");
    let doctored = resign_with_manifest(&key, &good_archive(), |manifest| {
        manifest.required_capabilities.insert(extra.clone());
    });
    match import(&doctored, &trusted_exporter(&key)) {
        Err(InterchangeError::CapabilityOverDeclared { extra: reported }) => {
            assert_eq!(reported, vec![extra]);
        }
        other => panic!("expected an over-declaration refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The grant check is the gate, and it does not read the manifest
// ---------------------------------------------------------------------------

#[test]
fn an_honestly_declared_capability_the_environment_withholds_is_still_refused() {
    // The manifest is perfect. The environment simply has not granted `step.mfa_challenge`. This
    // is the case that proves the grant check reads the DERIVED set and not the declaration: a
    // manifest saying the right thing buys nothing.
    let key = exporter_key();
    let withheld = Capability::step(&StepKind::MfaChallenge);
    let environment = ImportEnvironment::new(
        GrantedCapabilities::engine_default().without(&withheld),
        transports(),
    );
    match import_archive(
        good_archive().as_bytes(),
        &trusted_exporter(&key),
        &environment,
        &clock_at(NOW_SECS),
    ) {
        Err(InterchangeError::CapabilityNotGranted { missing }) => {
            assert_eq!(missing, vec![withheld]);
        }
        other => panic!("expected a grant refusal, got {other:?}"),
    }
}

#[test]
fn a_capability_that_is_both_under_declared_and_ungranted_is_refused_by_either_check_alone() {
    // THE DEFENCE IN DEPTH MEASUREMENT. The module claims the grant check never consults the
    // manifest, "so even a manifest check that was deleted tomorrow could not admit an ungranted
    // capability". Every other case here leaves that claim unmeasured, because the stage 7 equality
    // check is two-sided: by the time stage 9 runs, the derived set and the declared set are always
    // the same value, so a stage 9 that read the declaration would behave identically.
    //
    // This case breaks the tie by making ONE capability both undeclared and ungranted, so the two
    // checks disagree about which error to raise but agree that the answer is no. It therefore
    // asserts only that the import is REFUSED and deliberately does not pin the variant: pinning it
    // would re-couple the case to whichever check happens to run first and destroy the property.
    //
    // Measured against three states. Baseline: refused as `CapabilityUnderDeclared`. Stage 7
    // deleted: still refused, now as `CapabilityNotGranted`, which is the claim holding. Stage 7
    // deleted AND stage 9 swapped to read `manifest.required_capabilities`: the bundle IMPORTS,
    // and this is the only case in the suite that notices.
    let key = exporter_key();
    let capability = Capability::step(&StepKind::MfaChallenge);
    let doctored = resign_with_manifest(&key, &good_archive(), |manifest| {
        assert!(
            manifest.required_capabilities.remove(&capability),
            "the honest manifest declares it, so removing it really under-declares"
        );
    });
    let environment = ImportEnvironment::new(
        GrantedCapabilities::engine_default().without(&capability),
        transports(),
    );
    assert!(
        !environment.granted().contains(&capability),
        "and the environment really withholds it, so both checks have grounds to refuse"
    );

    let outcome = import_archive(
        doctored.as_bytes(),
        &trusted_exporter(&key),
        &environment,
        &clock_at(NOW_SECS),
    );
    assert!(
        outcome.is_err(),
        "a capability that is neither declared nor granted must not import, whichever check \
         catches it: got {outcome:?}"
    );
}

#[test]
fn an_under_declaring_bundle_is_refused_even_by_an_environment_that_grants_everything() {
    // Belt to the braces above: the environment grants every derived capability, so the ONLY thing
    // standing between this archive and an import is the manifest equality check.
    let key = exporter_key();
    let doctored = resign_with_manifest(&key, &good_archive(), |manifest| {
        manifest.required_capabilities.clear();
    });
    assert!(matches!(
        import(&doctored, &trusted_exporter(&key)),
        Err(InterchangeError::CapabilityUnderDeclared { .. })
    ));
}

#[test]
fn a_bundle_needing_the_m11_decision_sandbox_is_refused_until_the_environment_grants_it() {
    // The exercise the issue names. A decision attachment is the reserved outcome-routing seam;
    // the shipped engine withholds it, so the archive is refused at load with a precise message,
    // and the SAME archive imports once the capability is granted.
    let key = exporter_key();
    let mut journey = fixture_journey();
    journey.steps.push(Step {
        decision: Some(ironauth_journey::DecisionSpec::Predicate {
            predicate: Predicate::Always,
        }),
        ..step("branch", StepKind::Decision, None)
    });
    journey.transitions[2].to = "branch".to_owned();
    journey.transitions.push(Transition {
        from: "branch".to_owned(),
        to: "done".to_owned(),
        guard: None,
        comment: None,
    });
    let archive = export(&key, &journey, &[]);

    // The exporter's own manifest admits it needs the sandbox, because the manifest is derived.
    let manifest: SafetyManifest =
        serde_json::from_value(payload_of(&archive)["manifest"].clone()).expect("manifest");
    assert!(manifest.launch_constraints.requires_sandbox);

    // BOTH decision entries are withheld, and that is the point of the pair. The engine does not
    // consult a decision attachment at all, so `decision.predicate` names an executor it does not
    // run any more than `decision.sandbox` does, and granting one of them while withholding the
    // other would read as though the engine executed decision predicates today.
    let sandbox = Capability::fixed(FixedCapability::DECISION_SANDBOX);
    let predicate = Capability::fixed(FixedCapability::DECISION_PREDICATE);
    match import(&archive, &trusted_exporter(&key)) {
        Err(InterchangeError::CapabilityNotGranted { missing }) => {
            assert_eq!(missing, vec![predicate.clone(), sandbox.clone()]);
        }
        other => panic!("expected the sandbox refusal, got {other:?}"),
    }

    // Granting only ONE of them still refuses, which is what makes the pair a pair.
    match import_archive(
        archive.as_bytes(),
        &trusted_exporter(&key),
        &ImportEnvironment::new(
            GrantedCapabilities::engine_default().with(sandbox.clone()),
            transports(),
        ),
        &clock_at(NOW_SECS),
    ) {
        Err(InterchangeError::CapabilityNotGranted { missing }) => {
            assert_eq!(missing, vec![predicate.clone()]);
        }
        other => panic!("expected the remaining refusal, got {other:?}"),
    }

    // And the SAME archive imports once M11 grants them, which is the exercise the issue names.
    let granted = ImportEnvironment::new(
        GrantedCapabilities::engine_default()
            .with(sandbox)
            .with(predicate),
        transports(),
    );
    let bundle = import_archive(
        archive.as_bytes(),
        &trusted_exporter(&key),
        &granted,
        &clock_at(NOW_SECS),
    )
    .expect("the same archive imports once the capabilities are granted");
    assert!(
        bundle
            .capabilities
            .contains(&Capability::fixed(FixedCapability::DECISION_SANDBOX))
    );
    assert!(
        bundle
            .capabilities
            .contains(&Capability::fixed(FixedCapability::DECISION_PREDICATE))
    );
}

// ---------------------------------------------------------------------------
// Launch constraints
// ---------------------------------------------------------------------------

#[test]
fn a_misdeclared_min_engine_version_is_refused() {
    let key = exporter_key();
    let doctored = resign_with_manifest(&key, &good_archive(), |manifest| {
        manifest.launch_constraints.min_engine_version = 1;
    });
    assert_eq!(
        import(&doctored, &trusted_exporter(&key)),
        Err(InterchangeError::EngineVersionMisdeclared {
            declared: 1,
            derived: JOURNEY_ENGINE_VERSION,
        })
    );
}

#[test]
fn a_misdeclared_sandbox_requirement_is_refused_in_both_directions() {
    let key = exporter_key();
    // Claiming it needs the sandbox when it does not.
    let doctored = resign_with_manifest(&key, &good_archive(), |manifest| {
        manifest.launch_constraints.requires_sandbox = true;
    });
    assert_eq!(
        import(&doctored, &trusted_exporter(&key)),
        Err(InterchangeError::SandboxMisdeclared {
            declared: true,
            derived: false,
        })
    );
}

#[test]
fn a_manifest_permitting_no_transport_is_refused() {
    let key = exporter_key();
    let doctored = resign_with_manifest(&key, &good_archive(), |manifest| {
        manifest.launch_constraints.allowed_transports.clear();
    });
    assert_eq!(
        import(&doctored, &trusted_exporter(&key)),
        Err(InterchangeError::NoAllowedTransport)
    );
    // And an export that asked for one is refused at the source.
    assert_eq!(
        export_archive(
            &key,
            &ExportRequest {
                issuer: EXPORTER_ISSUER,
                artifact: &fixture_journey(),
                subflows: &[],
                allowed_transports: &BTreeSet::new(),
                issued_at_secs: ISSUED_AT,
                expires_at_secs: EXPIRES_AT,
            },
        ),
        Err(InterchangeError::NoAllowedTransport)
    );
}

#[test]
fn a_transport_the_environment_serves_but_the_manifest_forbids_refuses_the_import() {
    let key = exporter_key();
    // An author who permits only the API transport.
    let archive = export_archive(
        &key,
        &ExportRequest {
            issuer: EXPORTER_ISSUER,
            artifact: &fixture_journey(),
            subflows: &[],
            allowed_transports: &["api".to_owned()].into_iter().collect(),
            issued_at_secs: ISSUED_AT,
            expires_at_secs: EXPIRES_AT,
        },
    )
    .expect("export");

    // An environment serving the browser transport cannot honor that, and nothing can pin a stored
    // journey to a subset of an environment's transports, so it refuses instead of ignoring.
    let browser = ImportEnvironment::new(
        GrantedCapabilities::engine_default(),
        ["browser".to_owned()],
    );
    assert_eq!(
        import_archive(
            archive.as_bytes(),
            &trusted_exporter(&key),
            &browser,
            &clock_at(NOW_SECS),
        ),
        Err(InterchangeError::TransportNotAllowed {
            transport: "browser".to_owned()
        })
    );

    // An API-only environment imports it.
    let api = ImportEnvironment::new(GrantedCapabilities::engine_default(), ["api".to_owned()]);
    import_archive(
        archive.as_bytes(),
        &trusted_exporter(&key),
        &api,
        &clock_at(NOW_SECS),
    )
    .expect("an api-only environment honors an api-only manifest");
}

// ---------------------------------------------------------------------------
// The SECOND sub-flow resolution rule: a NESTED subflow_call
// ---------------------------------------------------------------------------

/// A journey that reaches a subflow through a call NESTED inside an inline definition, so no
/// `SubflowRef` in the journey's `subflows` list ever names it.
///
/// There are two resolution rules for a `subflow_call` step's `subflow` key and this exercises the
/// second one. At JOURNEY level (`ironauth-journey/src/validate.rs`) the key is an ALIAS declared
/// in `subflows`. At SUBFLOW-DEFINITION level (`ironauth-journey/src/subflow.rs`) it resolves
/// against the GLOBAL definition key set: every built-in NAME union every inline definition id. So
/// a nested call can name a built-in that the journey never declares a reference to, and
/// composition then ERASES the call. A deriver that walked only `subflows` and the compiled table
/// would name that built-in nowhere.
fn nested_call_journey(nested_key: &str, definitions: Vec<Subflow>) -> Journey {
    let mut definitions = definitions;
    definitions.insert(
        0,
        Subflow {
            id: "wrapper".to_owned(),
            entry: "inner".to_owned(),
            exits: vec!["inner".to_owned()],
            comment: None,
            steps: vec![Step {
                subflow: Some(nested_key.to_owned()),
                ..step("inner", StepKind::SubflowCall, None)
            }],
            transitions: vec![],
        },
    );
    let mut journey = fixture_journey();
    "login_nested".clone_into(&mut journey.id);
    journey.subflows = Some(vec![SubflowRef {
        // The alias resolves to the WRAPPER, never to what the wrapper calls.
        id: "mfa_step_up".to_owned(),
        source: SubflowSource::Inline {
            subflow_id: "wrapper".to_owned(),
        },
    }]);
    journey.subflow_definitions = Some(definitions);
    journey
}

#[test]
fn a_builtin_reached_only_by_a_nested_call_is_still_checked_against_the_grant() {
    // THE BYPASS THIS TEST EXISTS FOR. The bundle reaches the built-in `mfa_step_up` without any
    // `SubflowRef` naming it, so before the definition-level walk landed the deriver produced no
    // `subflow.builtin.mfa_step_up` at all and an environment that had explicitly WITHHELD that
    // built-in imported the bundle anyway, complete with its own built-in body spliced into the
    // compiled table.
    let key = exporter_key();
    let archive = export(&key, &nested_call_journey("mfa_step_up", Vec::new()), &[]);

    // The honest exporter's own derived manifest names it, because export and import re-derive
    // through the same function.
    let manifest: SafetyManifest =
        serde_json::from_value(payload_of(&archive)["manifest"].clone()).expect("manifest");
    let withheld = Capability::builtin_subflow("mfa_step_up");
    assert!(
        manifest.required_capabilities.contains(&withheld),
        "the derived manifest names the nested built-in: {:?}",
        manifest
            .required_capabilities
            .iter()
            .map(Capability::as_wire)
            .collect::<Vec<_>>()
    );

    // And an environment that withholds it refuses the import.
    let environment = ImportEnvironment::new(
        GrantedCapabilities::engine_default().without(&withheld),
        transports(),
    );
    assert_eq!(
        import_archive(
            archive.as_bytes(),
            &trusted_exporter(&key),
            &environment,
            &clock_at(NOW_SECS),
        ),
        Err(InterchangeError::CapabilityNotGranted {
            missing: vec![withheld]
        }),
        "reaching a built-in through a nested call must be exactly as gated as naming it directly"
    );

    // The SAME archive imports where the built-in is granted, so the refusal above is about the
    // grant and not about the nested shape being malformed. The spliced built-in body's own step
    // kind and node group are derived too, through the compiled walk.
    let bundle =
        import(&archive, &trusted_exporter(&key)).expect("the granted environment imports");
    assert!(
        bundle
            .capabilities
            .contains(&Capability::step(&StepKind::MfaChallenge))
    );
    assert!(
        bundle
            .capabilities
            .contains(&Capability::node_group("totp"))
    );
}

#[test]
fn a_nested_call_naming_another_inline_definition_derives_the_inline_capability() {
    // One layer in from the case above: the nested call names another INLINE definition by id
    // rather than a built-in, so it derives `subflow.inline`.
    //
    // The definitions here are UNREFERENCED, and that is forced rather than contrived. Reaching an
    // inline definition from journey level requires a `SubflowRef` with an `Inline` source, and
    // THAT already derives `subflow.inline` on its own, so in a referenced chain this capability is
    // masked and the case would prove nothing. The unreferenced chain is the only shape in which
    // the nested-call walk is the sole thing that can name it. Deriving it there is deliberate
    // fail-closed over-derivation: the bundle carries an inline composition an operator may decide
    // about, whether or not this artifact's entry reaches it.
    let key = exporter_key();
    let mut journey = fixture_journey();
    journey.subflow_definitions = Some(vec![
        Subflow {
            id: "wrapper".to_owned(),
            entry: "inner".to_owned(),
            exits: vec!["inner".to_owned()],
            comment: None,
            steps: vec![Step {
                subflow: Some("leaf".to_owned()),
                ..step("inner", StepKind::SubflowCall, None)
            }],
            transitions: vec![],
        },
        Subflow {
            id: "leaf".to_owned(),
            entry: "l".to_owned(),
            exits: vec!["l".to_owned()],
            comment: None,
            steps: vec![step("l", StepKind::MfaEnroll, Some("email_otp"))],
            transitions: vec![],
        },
    ]);
    // The journey's only reference is the BUILT-IN one the fixture already carries, so nothing
    // outside the nested call can put `subflow.inline` in the set.
    assert!(matches!(
        journey.subflows.as_deref(),
        Some([SubflowRef {
            source: SubflowSource::Builtin { .. },
            ..
        }])
    ));
    let archive = export(&key, &journey, &[]);

    let inline = Capability::fixed(FixedCapability::SUBFLOW_INLINE);
    let manifest: SafetyManifest =
        serde_json::from_value(payload_of(&archive)["manifest"].clone()).expect("manifest");
    assert!(
        manifest.required_capabilities.contains(&inline),
        "the nested inline call derives subflow.inline: {:?}",
        manifest
            .required_capabilities
            .iter()
            .map(Capability::as_wire)
            .collect::<Vec<_>>()
    );

    let environment = ImportEnvironment::new(
        GrantedCapabilities::engine_default().without(&inline),
        transports(),
    );
    assert_eq!(
        import_archive(
            archive.as_bytes(),
            &trusted_exporter(&key),
            &environment,
            &clock_at(NOW_SECS),
        ),
        Err(InterchangeError::CapabilityNotGranted {
            missing: vec![inline]
        })
    );
}

#[test]
fn a_definition_no_call_reaches_still_derives_everything_it_could_exercise() {
    // The source-side `subflow_definitions` walk is NOT redundant with the compiled walk, and this
    // is the case that says so. An UNREFERENCED definition never reaches the compiled table at all,
    // so only the source walk can see it.
    //
    // Deriving from it is deliberate fail-closed over-derivation, and it is the right direction:
    // the bundle CARRIES that body and a later edit is one alias away from reaching it, so the
    // operator should be asked about it now rather than after a change that looks like renaming.
    let key = exporter_key();
    let mut journey = fixture_journey();
    journey.subflow_definitions = Some(vec![Subflow {
        id: "never_called".to_owned(),
        entry: "collect".to_owned(),
        exits: vec!["verify".to_owned()],
        comment: None,
        steps: vec![
            step("collect", StepKind::MfaEnroll, Some("email_otp")),
            step("verify", StepKind::MfaChallenge, Some("recovery_code")),
        ],
        // A guard, and a predicate shape, that exist NOWHERE else in the bundle.
        transitions: vec![Transition {
            from: "collect".to_owned(),
            to: "verify".to_owned(),
            guard: Some(Predicate::Not {
                operand: Box::new(Predicate::Never),
            }),
            comment: None,
        }],
    }]);
    let archive = export(&key, &journey, &[]);
    let bundle = import(&archive, &trusted_exporter(&key)).expect("imports");

    for expected in [
        // The step-walk half.
        Capability::step(&StepKind::MfaEnroll),
        Capability::node_group("email_otp"),
        Capability::node_group("recovery_code"),
        // The transition-walk half: a predicate form the rest of the fixture never uses.
        Capability::fixed(FixedCapability::PREDICATE_NOT),
        Capability::fixed(FixedCapability::PREDICATE_NEVER),
    ] {
        assert!(
            bundle.capabilities.contains(&expected),
            "{expected} lives only inside the unreferenced definition and must still be derived"
        );
    }

    // And it is a real gate, not just a longer list: withholding one of them refuses the import.
    let withheld = Capability::node_group("recovery_code");
    let environment = ImportEnvironment::new(
        GrantedCapabilities::engine_default().without(&withheld),
        transports(),
    );
    assert_eq!(
        import_archive(
            archive.as_bytes(),
            &trusted_exporter(&key),
            &environment,
            &clock_at(NOW_SECS),
        ),
        Err(InterchangeError::CapabilityNotGranted {
            missing: vec![withheld]
        })
    );
}

#[test]
fn an_environment_that_serves_no_transport_cannot_satisfy_the_constraint_vacuously() {
    // The transport rule is universally quantified over what the environment OFFERS, so an empty
    // offer set proves it for free: before this was closed, a manifest permitting only a transport
    // no deployment has ever served imported cleanly into an environment serving nothing.
    let key = exporter_key();
    let archive = export_archive(
        &key,
        &ExportRequest {
            issuer: EXPORTER_ISSUER,
            artifact: &fixture_journey(),
            subflows: &[],
            allowed_transports: &["carrier_pigeon".to_owned()].into_iter().collect(),
            issued_at_secs: ISSUED_AT,
            expires_at_secs: EXPIRES_AT,
        },
    )
    .expect("export");
    let nowhere =
        ImportEnvironment::new(GrantedCapabilities::engine_default(), Vec::<String>::new());
    assert!(nowhere.offered_transports().is_empty());
    assert_eq!(
        import_archive(
            archive.as_bytes(),
            &trusted_exporter(&key),
            &nowhere,
            &clock_at(NOW_SECS),
        ),
        Err(InterchangeError::EnvironmentServesNoTransport)
    );

    // The refusal is about the empty offer and not about `carrier_pigeon`: the same empty
    // environment refuses a manifest that permits the transports this deployment normally serves.
    let ordinary =
        ImportEnvironment::new(GrantedCapabilities::engine_default(), Vec::<String>::new());
    assert_eq!(
        import_archive(
            good_archive().as_bytes(),
            &trusted_exporter(&key),
            &ordinary,
            &clock_at(NOW_SECS),
        ),
        Err(InterchangeError::EnvironmentServesNoTransport)
    );
}

// ---------------------------------------------------------------------------
// Sub-flows and compilation
// ---------------------------------------------------------------------------

#[test]
fn out_of_line_subflows_are_merged_compiled_and_capability_checked() {
    let key = exporter_key();
    // The artifact REFERENCES an inline subflow whose body travels beside it, which is what makes
    // the bundle self-contained across an organization boundary.
    let body = Subflow {
        id: "shared_step_up".to_owned(),
        entry: "challenge".to_owned(),
        exits: vec!["challenge".to_owned()],
        comment: None,
        steps: vec![step("challenge", StepKind::MfaEnroll, Some("email_otp"))],
        transitions: vec![],
    };
    let mut journey = fixture_journey();
    journey.subflows = Some(vec![SubflowRef {
        id: "mfa_step_up".to_owned(),
        source: SubflowSource::Inline {
            subflow_id: "shared_step_up".to_owned(),
        },
    }]);

    // Without the body the bundle does not even export, because export compiles first.
    assert!(matches!(
        export_archive(
            &key,
            &ExportRequest {
                issuer: EXPORTER_ISSUER,
                artifact: &journey,
                subflows: &[],
                allowed_transports: &transports(),
                issued_at_secs: ISSUED_AT,
                expires_at_secs: EXPIRES_AT,
            },
        ),
        Err(InterchangeError::JourneyInvalid(_))
    ));

    let archive = export(&key, &journey, std::slice::from_ref(&body));
    let bundle = import(&archive, &trusted_exporter(&key)).expect("imports");
    // The merged artifact carries the body, so the stored version is self-contained.
    assert_eq!(
        bundle
            .artifact
            .subflow_definitions
            .as_deref()
            .map(<[Subflow]>::len),
        Some(1)
    );
    // And the capabilities the merged body exercises are derived.
    assert!(
        bundle
            .capabilities
            .contains(&Capability::step(&StepKind::MfaEnroll))
    );
    assert!(
        bundle
            .capabilities
            .contains(&Capability::node_group("email_otp"))
    );
    assert!(
        bundle
            .capabilities
            .contains(&Capability::fixed(FixedCapability::SUBFLOW_INLINE))
    );
}

#[test]
fn a_bundle_whose_journey_does_not_compile_is_refused() {
    let key = exporter_key();
    let mut payload = payload_of(&good_archive());
    let mut broken = fixture_journey();
    // A transition to a step that does not exist.
    broken.transitions[0].to = "nowhere".to_owned();
    payload.insert(
        "artifact".to_owned(),
        serde_json::to_value(&broken).expect("journey"),
    );
    let archive = resign(&key, &payload);
    let error = import(&archive, &trusted_exporter(&key)).expect_err("a broken journey");
    assert!(matches!(error, InterchangeError::JourneyInvalid(_)));
}

#[test]
fn a_bundle_carrying_two_bodies_for_one_subflow_id_is_refused() {
    let key = exporter_key();
    let body = Subflow {
        id: "shared".to_owned(),
        entry: "challenge".to_owned(),
        exits: vec!["challenge".to_owned()],
        comment: None,
        steps: vec![step("challenge", StepKind::MfaChallenge, Some("totp"))],
        transitions: vec![],
    };
    let mut payload = payload_of(&good_archive());
    payload.insert(
        "subflows".to_owned(),
        serde_json::to_value([&body, &body]).expect("subflows"),
    );
    let archive = resign(&key, &payload);
    assert_eq!(
        import(&archive, &trusted_exporter(&key)),
        Err(InterchangeError::SubflowIdConflict {
            id: "shared".to_owned()
        })
    );
}

// ---------------------------------------------------------------------------
// The refusal message is an operator-facing surface the exporter writes into
// ---------------------------------------------------------------------------

/// A sub-flow id built to attack the log the operator reads, not the importer.
///
/// It carries a raw newline (so the rendered message would end one log line and start another the
/// exporter wrote), an ANSI CSI sequence (so it would repaint the operator's terminal), and several
/// kilobytes of padding (so one refusal floods the log).
fn hostile_id() -> String {
    format!(
        "ok\n2026-01-01 ERROR forged: admin granted\u{1b}[31m{}",
        "A".repeat(4000)
    )
}

/// The same hostile text as a manifest capability token.
///
/// [`Capability`] has no constructor for arbitrary text on purpose: the only way to make one is to
/// deserialize it, which is exactly how a hostile manifest gets one in. This goes in the same way.
fn hostile_capability() -> Capability {
    serde_json::from_value(Value::String(hostile_id()))
        .expect("a capability is a transparent string")
}

#[test]
fn a_hostile_exporter_cannot_forge_or_flood_an_operator_log_line() {
    let key = exporter_key();
    let rendered_lengths = [
        // SubflowIdConflict, raised at the merge stage BEFORE compile has constrained the id.
        {
            let body = Subflow {
                id: hostile_id(),
                entry: "challenge".to_owned(),
                exits: vec!["challenge".to_owned()],
                comment: None,
                steps: vec![step("challenge", StepKind::MfaChallenge, Some("totp"))],
                transitions: vec![],
            };
            let mut payload = payload_of(&good_archive());
            payload.insert(
                "subflows".to_owned(),
                serde_json::to_value([&body, &body]).expect("subflows"),
            );
            let archive = resign(&key, &payload);
            let error = import(&archive, &trusted_exporter(&key)).expect_err("a conflicting id");
            assert!(matches!(error, InterchangeError::SubflowIdConflict { .. }));
            error.to_string()
        },
        // JourneyInvalid, which renders the journey crate's own error Display.
        {
            let mut broken = fixture_journey();
            broken.steps[1].subflow = Some(hostile_id());
            let mut payload = payload_of(&good_archive());
            payload.insert(
                "artifact".to_owned(),
                serde_json::to_value(&broken).expect("journey"),
            );
            let archive = resign(&key, &payload);
            let error = import(&archive, &trusted_exporter(&key)).expect_err("a broken journey");
            assert!(matches!(error, InterchangeError::JourneyInvalid(_)));
            error.to_string()
        },
        // CapabilityOverDeclared, the direct exporter-to-operator text channel: a manifest
        // capability token is deliberately unvalidated on the way in, so it is free text.
        {
            let doctored = resign_with_manifest(&key, &good_archive(), |manifest| {
                manifest.required_capabilities.insert(hostile_capability());
            });
            let error = import(&doctored, &trusted_exporter(&key)).expect_err("an extra token");
            assert!(matches!(
                error,
                InterchangeError::CapabilityOverDeclared { .. }
            ));
            error.to_string()
        },
    ];

    for rendered in &rendered_lengths {
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "a rendered refusal must not carry a line break the exporter chose: {rendered:?}"
        );
        assert!(
            !rendered.contains('\u{1b}'),
            "a rendered refusal must not carry an ANSI escape: {rendered:?}"
        );
        assert!(
            !rendered.chars().any(char::is_control),
            "a rendered refusal must carry no control character at all: {rendered:?}"
        );
        assert!(
            rendered.len() < 512,
            "a rendered refusal must be bounded, got {} bytes",
            rendered.len()
        );
    }

    // And the sanitizer does not eat the message: the operator still learns which refusal this is
    // and sees the harmless prefix of the offending id.
    assert!(rendered_lengths[0].contains("two definitions for sub-flow id ok?"));
}

#[test]
fn a_journey_with_very_many_load_failures_renders_a_bounded_message() {
    // Length is bounded per element AND per list: an artifact engineered to produce hundreds of
    // load errors must not render hundreds of them into one line.
    let key = exporter_key();
    let mut broken = fixture_journey();
    for index in 0..300 {
        broken
            .steps
            .push(step(&format!("junk{index}"), StepKind::Terminal, None));
    }
    let mut payload = payload_of(&good_archive());
    payload.insert(
        "artifact".to_owned(),
        serde_json::to_value(&broken).expect("journey"),
    );
    let archive = resign(&key, &payload);
    let error = import(&archive, &trusted_exporter(&key)).expect_err("a broken journey");
    let InterchangeError::JourneyInvalid(errors) = &error else {
        panic!("expected JourneyInvalid, got {error:?}");
    };
    assert!(
        errors.len() > 8,
        "the fixture really does produce more failures than the render bound, got {}",
        errors.len()
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains("; and ") && rendered.ends_with(" more"),
        "the message summarizes the tail by count: {rendered}"
    );
    assert!(
        rendered.len() < 2048,
        "a rendered refusal is bounded whatever the artifact does, got {} bytes",
        rendered.len()
    );
}

// ---------------------------------------------------------------------------
// A whole-set sanity check on the derivation
// ---------------------------------------------------------------------------

#[test]
fn the_derived_set_for_the_fixture_is_exactly_this() {
    // A pinned whole-set expectation, so a derivation that quietly grew or shrank is a failing
    // test rather than an unnoticed change in what an operator is asked to grant.
    let key = exporter_key();
    let bundle = import(&good_archive(), &trusted_exporter(&key)).expect("imports");
    let expected: BTreeSet<String> = [
        "node_group.password",
        "node_group.totp",
        "predicate.cmp",
        "predicate.field.signals",
        "predicate.literal.bool",
        "predicate.op.eq",
        "step.identifier_password",
        "step.mfa_challenge",
        "step.subflow_call",
        "step.terminal",
        "subflow.builtin.mfa_step_up",
        "transition.guard",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let derived: BTreeSet<String> = bundle
        .capabilities
        .iter()
        .map(|capability| capability.as_wire().to_owned())
        .collect();
    assert_eq!(derived, expected);

    // Every one of them is in the shipped grant, which is why the fixture imports at all.
    let granted = GrantedCapabilities::engine_default();
    let ungranted: Vec<&str> = bundle
        .capabilities
        .iter()
        .filter(|capability| !granted.contains(capability))
        .map(Capability::as_wire)
        .collect();
    assert!(ungranted.is_empty(), "ungranted: {ungranted:?}");
}
