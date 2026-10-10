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

/// A real stored impersonation session with separate local subject and actor.
/// The test fixture invokes the audited repository, not an admin start endpoint.
pub async fn impersonated_session(
    h: &Harness,
    user: &str,
    impersonator: &str,
) -> (ironauth_store::SessionId, String) {
    use ironauth_store::{NewSession, SessionId, impersonation::Impersonation};
    let session = SessionId::generate(h.env(), &h.scope());
    let (actor, corr) = h.seeding_actor();
    let now = i64::try_from(
        h.env()
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    h.store()
        .scoped(h.scope())
        .acting(actor, corr)
        .sessions()
        .rotate(
            h.env(),
            &session,
            None,
            NewSession {
                impersonation: Some(
                    Impersonation::start(
                        impersonator,
                        "support_ticket",
                        "Private test justification",
                        now,
                        1_800_000_000,
                    )
                    .unwrap(),
                ),
                subject: user,
                auth_methods: "pwd",
                auth_time_micros: now,
                idle_expires_micros: super::FAR_FUTURE_MICROS,
                absolute_expires_micros: super::FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .unwrap();
    (
        session,
        format!("{}={session}", ironauth_oidc::SESSION_COOKIE),
    )
}
