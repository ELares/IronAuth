// SPDX-License-Identifier: MIT OR Apache-2.0
//! SECURITY-lens adversarial tests for issue #323 config-into-HTML injection.
//! Drives the full served document render via the public `router`.

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use ironauth_admin_ui::{RuntimeConfig, router};
use tower::ServiceExt;

async fn render(config: RuntimeConfig) -> String {
    let resp = router(None, config)
        .oneshot(
            Request::builder()
                .uri("/admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Count how many `<script` opening tags appear (the genuine embed has exactly
/// one module script). Any hostile value that injects a new one bumps this.
fn script_tag_count(html: &str) -> usize {
    html.matches("<script").count()
}

/// The genuine served document has exactly one <script> (the module bundle) and
/// exactly the five config meta tags plus viewport/charset.
const BASELINE_SCRIPT_TAGS: usize = 1;

#[tokio::test]
async fn hostile_values_never_break_out_of_the_content_attribute() {
    let hostiles = [
        "\">",
        "\"><script>alert(1)</script>",
        "\"/><meta http-equiv=refresh content=0;url=//evil>",
        "\" onload=\"x",
        "\" onmouseover=alert(1) x=\"",
        "a\nb\r\nc",                              // newline / CR
        "plain\"quote",                           // bare double quote
        "less<than>more",                         // bare angle brackets
        "amp&already&amp;mixed",                  // ampersand ordering
        "content=\"pwn\" name=\"ironauth-issuer", // fake attribute payload
        "'><svg/onload=alert(1)>",                // single-quote breakout attempt
        "\"></meta><script>x</script><meta content=\"",
    ];

    // The genuine document's raw angle-bracket counts (no config injected).
    let baseline = render(RuntimeConfig::default()).await;
    let baseline_open_count = baseline.matches('<').count();
    let baseline_close_count = baseline.matches('>').count();

    for h in hostiles {
        let cfg = RuntimeConfig {
            admin_issuer_path: h.to_owned(),
            console_client_id: h.to_owned(),
            management_audience: h.to_owned(),
        };
        let body = render(cfg).await;

        // (0) THE airtight structural invariant: escaping every `<`/`>` in the
        // injected values means the served document has EXACTLY the same number
        // of raw `<` and `>` as the empty-config baseline. Any breakout that
        // opened even one tag would raise one of these counts.
        assert_eq!(
            body.matches('<').count(),
            baseline_open_count,
            "hostile value {h:?} changed the raw `<` count (a tag was opened):\n{body}"
        );
        assert_eq!(
            body.matches('>').count(),
            baseline_close_count,
            "hostile value {h:?} changed the raw `>` count (a tag was closed):\n{body}"
        );

        // (1) No new <script> tag was injected.
        assert_eq!(
            script_tag_count(&body),
            BASELINE_SCRIPT_TAGS,
            "hostile value {h:?} injected a <script> tag:\n{body}"
        );

        // (2) No RAW attribute breakout. A real breakout requires an unescaped
        // `"` (to close content=) or an unescaped `<`/`>` (to open a tag). We
        // assert none of the injected dangerous sequences survive UNESCAPED.
        // (The literal words like `http-equiv` may survive as inert escaped data
        // inside the content attribute; that is safe. We check the structural
        // characters, not the inert text.)
        assert!(
            !body.contains("<script>alert(1)</script>"),
            "value {h:?} produced an executable script element"
        );
        assert!(
            !body.contains("\" onload=\"x"),
            "value {h:?} produced an unescaped onload handler"
        );
        assert!(
            !body.contains("/><meta http-equiv"),
            "value {h:?} produced an unescaped refresh meta breakout"
        );
        assert!(
            !body.contains("'><svg") && !body.contains("\"><svg"),
            "value {h:?} produced an unescaped svg onload breakout"
        );
        // Structural invariant: no injected value may introduce ANY raw `<` or
        // `>` beyond the genuine document. The genuine embed has a fixed count of
        // `<` and `>`; a breakout raises it. We assert the escaped forms carry
        // the danger instead.
        assert!(
            !body.contains("</meta><script>"),
            "value {h:?} closed a tag and opened a script"
        );

        // (3) The number of `<meta` tags must be exactly the genuine set. A
        // breakout that opens a new <meta> would raise this beyond baseline.
        let meta_count = body.matches("<meta").count();
        assert_eq!(
            meta_count, GENUINE_META_TAGS,
            "hostile value {h:?} changed the meta tag count to {meta_count}:\n{body}"
        );

        // (4) Every literal double-quote inside an injected value must be
        // escaped: after removing the genuine attribute-delimiter quotes there
        // must be no raw `">` breakout right after our injected content.
        assert!(
            !body.contains("content=\"\">"),
            "value {h:?} yielded an empty-then-broken attribute"
        );
    }
}

/// The genuine embed ships 7 meta tags: charset, viewport, and the 5 config tags.
const GENUINE_META_TAGS: usize = 7;

#[tokio::test]
async fn baseline_document_shape_is_what_we_assert_against() {
    let body = render(RuntimeConfig::default()).await;
    assert_eq!(script_tag_count(&body), BASELINE_SCRIPT_TAGS, "{body}");
    assert_eq!(body.matches("<meta").count(), GENUINE_META_TAGS, "{body}");
}

/// A value that itself contains the exact `name="..."` needle of a LATER tag
/// must not be able to redirect a later replacement into itself.
#[tokio::test]
async fn injected_value_cannot_forge_a_later_meta_needle() {
    let cfg = RuntimeConfig {
        // admin-issuer injected first; try to forge the client-id needle.
        admin_issuer_path: "name=\"ironauth-console-client-id\" content=\"HIJACK".to_owned(),
        console_client_id: "REAL-CLIENT".to_owned(),
        management_audience: "REAL-AUD".to_owned(),
    };
    let body = render(cfg).await;
    // The real client-id tag must still receive REAL-CLIENT, escaped-forgery inert.
    assert!(
        body.contains("<meta name=\"ironauth-console-client-id\" content=\"REAL-CLIENT\" />"),
        "the real client-id tag lost its value to a forged needle:\n{body}"
    );
    assert!(
        !body.contains("content=\"HIJACK\""),
        "the forged needle broke out:\n{body}"
    );
}
