// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit local browser fixture. Uses a disposable database and the real router.
//! Never binds outside loopback and creates no user or profile through test seams.
mod common;
use common::{Harness, PKCE_CHALLENGE, REDIRECT_URI, enc};

#[tokio::test]
#[ignore = "explicit local browser qualification only"]
async fn serve_profile_preview() {
    let directory = std::path::PathBuf::from(
        std::env::var("IRONAUTH_PROFILE_PREVIEW_DIR").expect("private output directory"),
    );
    assert!(directory.is_dir());
    let h = Harness::start().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let authorize = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&prompt=create",
        h.client_id(),
        enc(REDIRECT_URI),
        enc("openid profile")
    );
    std::fs::write(directory.join("server.json"),serde_json::json!({"address":address.to_string(),"authorize":authorize,"client_id":h.client_id().to_string(),"profile":format!("/t/{}/e/{}/profile",h.scope().tenant(),h.scope().environment())}).to_string()).unwrap();
    let stop = directory.join("stop");
    axum::serve(listener, h.router())
        .with_graceful_shutdown(async move {
            for _ in 0..1200 {
                if stop.exists() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        })
        .await
        .unwrap();
    let audits = h.audit_rows_for_action("user.update").await;
    std::fs::write(directory.join("server-result.json"),serde_json::json!({"stopped":true,"profile_audits":audits.len(),"scope":"Real HTTP router and disposable PostgreSQL; browser forwarding transport, not deployed provider or real identity signing keys"}).to_string()).unwrap();
}
