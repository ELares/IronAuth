// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `OpenFGA` tuple-sync demo (issue #100, criterion 5), against a REAL `OpenFGA` server.
//!
//! The criterion asks for "a demo consumer [that] syncs membership facts from the
//! identity-fact change feed contract into `OpenFGA` tuples and answers a check that
//! `IronAuth` core cannot". This is that consumer, and it is a test rather than a sample
//! directory so it cannot rot: a sample nobody runs is a sample that stops compiling.
//!
//! # The check IronAuth cannot answer
//!
//! `IronAuth` answers "does this subject hold permission P in organization O". It models no
//! documents, no folders, and no parent relationships between them, so it cannot answer "can
//! this user view THIS document" at all, at any price.
//!
//! `OpenFGA` can, and the model here is the smallest thing that shows it: a `document` has a
//! `parent` organization, and its `viewer` relation is DERIVED (`member from parent`). No
//! tuple ever says `usr_1 can view doc_1`; the answer is computed from the membership tuple
//! this consumer synced plus the parent tuple the application owns. That derivation is the
//! whole reason a deployment runs an FGA next to `IronAuth`, and it is exactly what the
//! coarse-claims-plus-fine-PDP architecture says to do.
//!
//! # Running it
//!
//! Needs a live `OpenFGA` at `OPENFGA_URL`. It SKIPS when that is unset, the same shape the
//! `DATABASE_URL` suites use, so a developer without one still gets a green run and CI (or
//! anyone with the binary) gets the real thing:
//!
//! ```text
//! go install github.com/openfga/openfga/cmd/openfga@v1.18.3
//! openfga run --datastore-engine memory --http-addr 127.0.0.1:18080 &
//! OPENFGA_URL=http://127.0.0.1:18080 cargo test -p ironauth-store --features testing \
//!     --test openfga_sync_demo
//! ```
//!
//! No Docker: `OpenFGA` is a Go binary and runs directly, which is also why this demo needs
//! no compose file to be real.

use std::time::Duration;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ironauth_fetch::{
    FetchLimits, FetchPurpose, FetchRequest, Fetcher, RecordingDialer, StaticResolver,
};
use ironauth_store::identity_fact::{IdentityFact, SyncPlan, Tuple, plan};

/// The demo's authorization model: membership is DIRECT, document viewing is DERIVED.
const MODEL: &str = r#"{
  "schema_version": "1.1",
  "type_definitions": [
    { "type": "user" },
    {
      "type": "organization",
      "relations": { "member": { "this": {} } },
      "metadata": {
        "relations": { "member": { "directly_related_user_types": [{ "type": "user" }] } }
      }
    },
    {
      "type": "document",
      "relations": {
        "parent": { "this": {} },
        "viewer": {
          "tupleToUserset": {
            "tupleset": { "relation": "parent" },
            "computedUserset": { "relation": "member" }
          }
        }
      },
      "metadata": {
        "relations": {
          "parent": { "directly_related_user_types": [{ "type": "organization" }] }
        }
      }
    }
  ]
}"#;

/// A minimal `OpenFGA` client over the SSRF-hardened fetcher, which is what a real consumer
/// would use: the FGA endpoint is operator-supplied, so it is outbound traffic like any
/// other and rides the same guarded path.
struct Fga {
    fetcher: Fetcher,
    base: String,
    store: String,
    model: String,
}

impl Fga {
    async fn post(&self, path: &str, body: String) -> serde_json::Value {
        let request = FetchRequest::new(
            FetchPurpose::ClaimsEnrichment,
            axum::http::Method::POST,
            format!("{}{path}", self.base),
        )
        .header(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        )
        .body(body)
        .allow_plaintext_http();
        let response = self
            .fetcher
            .fetch(request)
            .await
            .unwrap_or_else(|error| panic!("POST {path} failed: {error:?}"));
        assert!(
            response.status().is_success(),
            "POST {path} answered {}: {}",
            response.status(),
            String::from_utf8_lossy(response.body())
        );
        serde_json::from_slice(response.body()).unwrap_or(serde_json::Value::Null)
    }

    /// Create a fresh store and install the model, so each run is isolated.
    ///
    /// The fetcher resolves the host to a ROUTABLE address and dials the real local socket,
    /// which is how every outbound suite in this repo reaches an in-process server. The
    /// alternative was to let the demo talk to loopback directly, and the SSRF guard refused
    /// that, correctly: a consumer pointed at an operator-supplied FGA is outbound traffic,
    /// and a demo that disabled the guard to make itself work would be demonstrating the
    /// wrong thing.
    async fn connect(base: String) -> Self {
        let target: SocketAddr = base
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .parse()
            .expect("OPENFGA_URL must be host:port, for example http://127.0.0.1:18080");
        let fetcher = Fetcher::from_parts(
            FetchLimits::default(),
            std::sync::Arc::new(StaticResolver::new(vec![IpAddr::from(Ipv4Addr::new(
                93, 184, 216, 34,
            ))])),
            std::sync::Arc::new(RecordingDialer::new(target)),
        );
        let base = format!("http://fga.example.test:{}", target.port());
        let mut fga = Self {
            fetcher,
            base,
            store: String::new(),
            model: String::new(),
        };
        let created = fga
            .post("/stores", r#"{"name":"ironauth-sync-demo"}"#.to_owned())
            .await;
        created["id"]
            .as_str()
            .expect("a store id")
            .clone_into(&mut fga.store);
        let installed = fga
            .post(
                &format!("/stores/{}/authorization-models", fga.store),
                MODEL.to_owned(),
            )
            .await;
        installed["authorization_model_id"]
            .as_str()
            .expect("a model id")
            .clone_into(&mut fga.model);
        fga
    }

    /// Apply one [`SyncPlan`]: exactly what a production consumer does with a feed batch.
    async fn apply(&self, plan: &SyncPlan) {
        // A purge is a QUERY then a delete, which is why the contract models it as its own
        // variant rather than as a tuple list: no finite list expresses "everything naming
        // this subject", and a consumer that sent one would leave the rest behind.
        for user in &plan.purges {
            // Read is scoped by OBJECT TYPE as well as by user. OpenFGA refuses a read that
            // names only a user ("the object type field is required"), which this demo found
            // by asking a real server rather than by reading the docs, and it is the single
            // most useful thing here for anyone writing a consumer: there is no "delete
            // everything for this subject" call, so a purge must enumerate the object types
            // it could have written.
            //
            // The contract makes that enumerable rather than a guess: `to_tuple_change`
            // only ever produces objects of type `organization`, so this list is complete by
            // construction and a new object type in the mapping is a compile-adjacent change
            // that lands next to this line.
            let mut existing: Vec<serde_json::Value> = Vec::new();
            for object_type in ["organization:"] {
                let listed = self
                    .post(
                        &format!("/stores/{}/read", self.store),
                        serde_json::json!({
                            "tuple_key": { "user": user, "object": object_type }
                        })
                        .to_string(),
                    )
                    .await;
                existing.extend(
                    listed["tuples"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .iter()
                        .map(|entry| {
                            // The stored tuple carries a `condition` the write API rejects,
                            // so only the three key fields are echoed back.
                            serde_json::json!({
                                "user": entry["key"]["user"],
                                "relation": entry["key"]["relation"],
                                "object": entry["key"]["object"],
                            })
                        }),
                );
            }
            if !existing.is_empty() {
                self.post(
                    &format!("/stores/{}/write", self.store),
                    serde_json::json!({
                        "authorization_model_id": self.model,
                        "deletes": { "tuple_keys": existing },
                    })
                    .to_string(),
                )
                .await;
            }
        }
        let as_keys = |tuples: &[Tuple]| {
            tuples
                .iter()
                .map(|tuple| {
                    serde_json::json!({
                        "user": tuple.user,
                        "relation": tuple.relation,
                        "object": tuple.object,
                    })
                })
                .collect::<Vec<_>>()
        };
        // Deletes BEFORE writes, so a batch that both removes and adds never has the removed
        // tuple live alongside the new one.
        if !plan.deletes.is_empty() {
            self.post(
                &format!("/stores/{}/write", self.store),
                serde_json::json!({
                    "authorization_model_id": self.model,
                    "deletes": { "tuple_keys": as_keys(&plan.deletes) },
                })
                .to_string(),
            )
            .await;
        }
        if !plan.writes.is_empty() {
            self.post(
                &format!("/stores/{}/write", self.store),
                serde_json::json!({
                    "authorization_model_id": self.model,
                    "writes": { "tuple_keys": as_keys(&plan.writes) },
                })
                .to_string(),
            )
            .await;
        }
    }

    /// Write a tuple the APPLICATION owns rather than the feed: which organization a
    /// document belongs to is not an identity fact and IronAuth never emits it.
    async fn write_raw(&self, user: &str, relation: &str, object: &str) {
        self.post(
            &format!("/stores/{}/write", self.store),
            serde_json::json!({
                "authorization_model_id": self.model,
                "writes": { "tuple_keys": [{
                    "user": user, "relation": relation, "object": object
                }] },
            })
            .to_string(),
        )
        .await;
    }

    async fn check(&self, user: &str, relation: &str, object: &str) -> bool {
        let answer = self
            .post(
                &format!("/stores/{}/check", self.store),
                serde_json::json!({
                    "authorization_model_id": self.model,
                    "tuple_key": { "user": user, "relation": relation, "object": object },
                })
                .to_string(),
            )
            .await;
        answer["allowed"].as_bool().unwrap_or(false)
    }
}

/// The demo, end to end: sync membership facts, then answer a DERIVED check.
#[tokio::test]
async fn membership_facts_sync_into_openfga_and_answer_a_check_ironauth_cannot() {
    let Ok(base) = std::env::var("OPENFGA_URL") else {
        eprintln!(
            "openfga_sync_demo: SKIPPED, OPENFGA_URL is unset. \
             Run: openfga run --datastore-engine memory --http-addr 127.0.0.1:18080"
        );
        return;
    };
    let fga = tokio::time::timeout(Duration::from_secs(30), Fga::connect(base))
        .await
        .expect("connecting to OpenFGA timed out");

    // The application owns the document hierarchy; IronAuth never emits it, which is the
    // point. The FGA joins what IronAuth knows to what the application knows.
    fga.write_raw("organization:org_1", "parent", "document:doc_1")
        .await;

    // Before any identity fact, nobody can view the document.
    assert!(
        !fga.check("user:usr_1", "viewer", "document:doc_1").await,
        "the document must not be viewable before the membership fact syncs"
    );

    // The feed says the user joined. Exactly the contract's facts, planned and applied.
    let joined = plan(&[
        IdentityFact::UserCreated {
            user_id: "usr_1".to_owned(),
        },
        IdentityFact::MembershipAdded {
            user_id: "usr_1".to_owned(),
            organization_id: "org_1".to_owned(),
            membership_id: "omb_1".to_owned(),
        },
    ]);
    fga.apply(&joined).await;

    // THE CHECK IRONAUTH CANNOT ANSWER. No tuple says "usr_1 can view doc_1"; OpenFGA
    // DERIVES it from the membership this consumer synced plus the parent the application
    // owns. IronAuth models no documents, so it cannot answer this at any price, and that
    // is the whole reason a deployment runs an FGA beside it.
    assert!(
        fga.check("user:usr_1", "viewer", "document:doc_1").await,
        "the derived viewer check must resolve through the synced membership; this is the \
         question the identity-fact feed exists to make answerable"
    );

    // And the revocation direction, which is the one that matters: leaving the organization
    // must take the derived access with it.
    let left = plan(&[IdentityFact::MembershipRemoved {
        user_id: "usr_1".to_owned(),
        organization_id: "org_1".to_owned(),
        membership_id: "omb_1".to_owned(),
    }]);
    fga.apply(&left).await;
    assert!(
        !fga.check("user:usr_1", "viewer", "document:doc_1").await,
        "the user left the organization and can still view the document, so the sync grants \
         access it never revokes"
    );
}

/// A user DELETE purges every tuple naming them, and leaves a bystander's alone.
///
/// The purge is the operation no tuple list expresses, so it is the one a consumer is most
/// likely to implement as "delete the tuples I happen to know about". Driven against a real
/// server because the failure is a tuple left behind, which only a real store can show.
#[tokio::test]
async fn a_user_delete_purges_that_users_tuples_and_leaves_a_bystanders_alone() {
    let Ok(base) = std::env::var("OPENFGA_URL") else {
        eprintln!("openfga_sync_demo: SKIPPED, OPENFGA_URL is unset");
        return;
    };
    let fga = tokio::time::timeout(Duration::from_secs(30), Fga::connect(base))
        .await
        .expect("connecting to OpenFGA timed out");
    fga.write_raw("organization:org_1", "parent", "document:doc_1")
        .await;

    fga.apply(&plan(&[
        IdentityFact::MembershipAdded {
            user_id: "usr_1".to_owned(),
            organization_id: "org_1".to_owned(),
            membership_id: "omb_1".to_owned(),
        },
        IdentityFact::MembershipAdded {
            user_id: "usr_2".to_owned(),
            organization_id: "org_1".to_owned(),
            membership_id: "omb_2".to_owned(),
        },
    ]))
    .await;
    assert!(fga.check("user:usr_1", "viewer", "document:doc_1").await);
    assert!(fga.check("user:usr_2", "viewer", "document:doc_1").await);

    // A delete arrives for ONE of them, in its own batch, as the feed would deliver it.
    fga.apply(&plan(&[IdentityFact::UserDeleted {
        user_id: "usr_1".to_owned(),
    }]))
    .await;

    assert!(
        !fga.check("user:usr_1", "viewer", "document:doc_1").await,
        "a deleted user still resolves through a tuple the purge left behind"
    );
    assert!(
        fga.check("user:usr_2", "viewer", "document:doc_1").await,
        "the purge took a BYSTANDER's access with it, which is the other way this goes wrong"
    );

    // A delete and a DIFFERENT user's add in ONE batch, which is the shape a real feed
    // delivers: batches span subjects. The purge must drop only the deleted user's queued
    // write and leave the newcomer's alone. Without this the batch above never exercises
    // the scoping, because the purge arrives alone and has no sibling write to drop.
    fga.apply(&plan(&[
        IdentityFact::MembershipAdded {
            user_id: "usr_3".to_owned(),
            organization_id: "org_1".to_owned(),
            membership_id: "omb_3".to_owned(),
        },
        IdentityFact::UserDeleted {
            user_id: "usr_2".to_owned(),
        },
    ]))
    .await;
    assert!(
        fga.check("user:usr_3", "viewer", "document:doc_1").await,
        "a purge in the same batch discarded a DIFFERENT user's queued write, so joining at \
         the same moment somebody else leaves silently fails to grant access"
    );
    assert!(
        !fga.check("user:usr_2", "viewer", "document:doc_1").await,
        "the batched delete did not purge"
    );
}
