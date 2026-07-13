// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared helpers for the server integration tests. Not all helpers are used
//! by every test binary, so dead-code is allowed here.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use ironauth_config::Config;
use ironauth_env::Env;
use ironauth_server::Server;
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;

/// Parse a test config from TOML, panicking on any validation error.
#[must_use]
pub fn config_from(toml: &str) -> Config {
    Config::from_toml_str(toml, "<test>")
        .expect("test config is valid")
        .config
}

/// Build a server from TOML config and the system environment.
#[must_use]
pub fn server_from(toml: &str) -> Server {
    Server::new(config_from(toml), Env::system()).expect("server builds")
}

/// Drive one request through a router and collect status, headers, and body.
pub async fn send(app: Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app.oneshot(req).await.expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// A `GET uri` with no extra headers.
pub async fn get(app: Router, uri: &str) -> (StatusCode, HeaderMap, String) {
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    send(app, req).await
}

/// An in-memory `MakeWriter` that captures every byte written, for asserting on
/// log output.
#[derive(Clone)]
pub struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    /// The captured output as a lossy UTF-8 string.
    #[must_use]
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("capture lock").clone()).into_owned()
    }
}

impl Default for CaptureWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// The `io::Write` handle handed to the subscriber per event.
pub struct CaptureHandle(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureHandle;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureHandle(Arc::clone(&self.0))
    }
}
