// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(feature = "ironcache")]

//! The JWKS accelerator against a REAL IronCache server (issue #146 criteria 2 and 6).
//!
//! # Why a live server and not a double
//!
//! Criterion 2 is about two NODES sharing a document. A test double proves the registry calls
//! the seam; it cannot prove that what one process wrote another process can read, because both
//! sides are the same object. The property this file exists for is exactly the one a double
//! cannot establish.
//!
//! An adversarial review of the first accelerator PR made the same point from the other side:
//! every executed result in it "had to use a test double", and the criterion stayed true by
//! construction.
//!
//! # How it is gated, and why it announces a skip
//!
//! `IRONCACHE_ADDR` names a RESP endpoint (IronCache, or anything speaking its dialect). With it
//! unset these tests SKIP and say so, because a test that silently passes when its subject is
//! absent is worse than one that does not exist: it reports coverage nobody has.
//!
//! Running one locally:
//!
//! ```text
//! ironcache server --bind 127.0.0.1 --port 6399 --metrics-addr off
//! IRONCACHE_ADDR=127.0.0.1:6399 cargo test -p ironauth-oidc --features ironcache,testing \
//!     --test jwks_accelerator
//! ```

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::Harness;
use ironauth_hot::HotState;
use ironauth_oidc::{IssuerRegistry, JwksCacheWindow};
use ironauth_store::Scope;

const BASE: &str = "https://issuer.test";
const TTL: Duration = Duration::from_secs(100);

/// The address, or `None` with a printed skip.
fn addr() -> Option<String> {
    match std::env::var("IRONCACHE_ADDR") {
        Ok(addr) if !addr.trim().is_empty() => Some(addr),
        _ => {
            println!(
                "SKIPPED: IRONCACHE_ADDR is unset, so this ran against no server. It is not \
                 evidence of anything. Start one and set the variable."
            );
            None
        }
    }
}

/// A factory over one shared connection, which is what the binary builds from config.
async fn factory(addr: &str) -> impl Fn(Scope) -> Arc<dyn HotState> + Send + Sync + 'static {
    let connection = ironauth_hot::ironcache::connect(&format!("redis://{addr}"))
        .await
        .expect("connect to IRONCACHE_ADDR");
    move |scope: Scope| {
        Arc::new(ironauth_hot::ironcache::IronCacheHotState::new(
            connection.clone(),
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
        )) as Arc<dyn HotState>
    }
}

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// TWO REGISTRIES, ONE SERVER, ONE DOCUMENT: the property criterion 2 is about.
///
/// The second registry has never loaded this scope and never renders it: it reads what the first
/// one published. That is what "the accelerator is shared across nodes" means, and it is the
/// assertion no test double can make.
#[tokio::test]
async fn a_document_published_by_one_registry_is_served_by_another() {
    let Some(addr) = addr() else {
        return;
    };
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    let first =
        IssuerRegistry::store_backed(BASE, JwksCacheWindow::clamped(300), harness.store().clone())
            .with_entry_ttl(TTL)
            .with_jwks_hot_state(factory(&addr).await);
    let published = first
        .jwks_json(&scope, at(0))
        .await
        .expect("resolves")
        .expect("renders");

    // A SECOND REGISTRY, cold: its own entry cache is empty and it shares nothing in-process
    // with the first. The only thing the two have in common is the IronCache server.
    let second =
        IssuerRegistry::store_backed(BASE, JwksCacheWindow::clamped(300), harness.store().clone())
            .with_entry_ttl(TTL)
            .with_jwks_hot_state(factory(&addr).await);
    let served = second
        .jwks_json(&scope, at(0))
        .await
        .expect("resolves")
        .expect("serves");
    assert_eq!(
        served, published,
        "the second registry must serve the document the first published"
    );

    // AND THAT EQUALITY ON ITS OWN PROVES NOTHING, which is why the rest of this test exists.
    // Both registries read the same store, so they render byte-identical documents whether or
    // not either one ever touches the accelerator. Asserting only `served == published` would
    // pass with the whole seam deleted.
    //
    // So put a DISTINGUISHABLE value under the key the first registry wrote, and require the
    // third registry to serve THAT. Only a read that crossed the process boundary can.
    let sentinel = r#"{"keys":[]}"#;
    let raw = ironauth_hot::ironcache::IronCacheHotState::new(
        ironauth_hot::ironcache::connect(&format!("redis://{addr}"))
            .await
            .expect("connect"),
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    );
    raw.put(
        &ironauth_hot::registry::JWKS,
        &accelerator_key(&harness, &scope, at(0)).await,
        sentinel.as_bytes(),
        ironauth_hot::Ttl::of(TTL),
    )
    .await
    .expect("write the sentinel");

    let third =
        IssuerRegistry::store_backed(BASE, JwksCacheWindow::clamped(300), harness.store().clone())
            .with_entry_ttl(TTL)
            .with_jwks_hot_state(factory(&addr).await);
    let from_cache = third
        .jwks_json(&scope, at(0))
        .await
        .expect("resolves")
        .expect("serves");
    assert_eq!(
        from_cache, sentinel,
        "a cold registry must serve what is IN the shared accelerator, not what it would have \
         rendered; equal-to-rendered is the answer a registry that ignores the cache also gives"
    );
}

/// The key the registry computes for `scope` at `now`: the scope plus its published kids.
///
/// Derived here the same way the registry derives it, which is a weakness worth naming: it is an
/// expectation built the same way as the thing it addresses. It is used only to ADDRESS the
/// entry for the sentinel above, never as the assertion, and if it were wrong the sentinel would
/// simply not be found and the test would fail rather than pass.
async fn accelerator_key(harness: &Harness, scope: &Scope, now: SystemTime) -> String {
    let probe =
        IssuerRegistry::store_backed(BASE, JwksCacheWindow::clamped(300), harness.store().clone())
            .with_entry_ttl(TTL);
    let entry = probe.entry_for(scope, now).await.expect("entry loads");
    let mut kids = entry.keyset().published_kids(now, entry.policy());
    kids.sort();
    format!(
        "{}/{}/{}",
        scope.tenant(),
        scope.environment(),
        kids.join(",")
    )
}

/// ONE TENANT'S DOCUMENT IS NOT ANOTHER'S, through a real server.
///
/// The scope is bound into the IronCache key prefix, and `ironcache.rs` says that prefix IS the
/// tenant isolation: "there is no backstop, nothing here filters, nothing checks". A review
/// found the first version of the registry API took a single scope-bound instance for a registry
/// serving every scope, which would have written every tenant's document under one prefix. This
/// is that property asserted against the server rather than against the type signature.
#[tokio::test]
async fn one_scopes_document_is_invisible_to_another() {
    let Some(addr) = addr() else {
        return;
    };
    let harness = Harness::start_store_backed().await;
    let first_scope = harness.scope();
    // A SECOND ENVIRONMENT with its OWN key, so both scopes render and the comparison is
    // between two real documents rather than between a document and an absence.
    let other_scope = harness.second_scope().await;
    harness
        .provision_signing_key(
            other_scope,
            "ES256",
            ironauth_store::SigningKeyMaterialKind::EcdsaPkcs8,
            common::es256_pkcs8(),
        )
        .await;

    let registry =
        IssuerRegistry::store_backed(BASE, JwksCacheWindow::clamped(300), harness.store().clone())
            .with_entry_ttl(TTL)
            .with_jwks_hot_state(factory(&addr).await);

    let first = registry
        .jwks_json(&first_scope, at(0))
        .await
        .expect("resolves")
        .expect("renders");
    let other = registry
        .jwks_json(&other_scope, at(0))
        .await
        .expect("resolves")
        .expect("renders");

    assert_ne!(
        first, other,
        "two scopes with different signing keys must publish different documents; if these are \
         equal the accelerator served one scope's document for the other"
    );
}
