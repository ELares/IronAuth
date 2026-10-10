// SPDX-License-Identifier: MIT OR Apache-2.0
//! Seed persisted identity policy for protocol tests. This is not a registration API test.
use super::Harness;
use ironauth_store::{ClientId, ClientSubjectPolicy};

pub async fn configure(h: &Harness, client: &ClientId, sector: &str) {
    let current = h
        .store()
        .scoped(h.scope())
        .clients()
        .subject_policy(client)
        .await
        .unwrap();
    let (actor, corr) = h.seeding_actor();
    h.store()
        .scoped(h.scope())
        .acting(actor, corr)
        .clients()
        .set_subject_policy(
            h.env(),
            &current,
            &ClientSubjectPolicy::Pairwise {
                sector_identifier: sector.to_owned(),
                sector_identifier_uri: Some(format!("https://{sector}/redirects.json")),
            },
            &current.redirect_uris,
        )
        .await
        .unwrap();
}
