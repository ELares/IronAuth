// SPDX-License-Identifier: MIT OR Apache-2.0

//! A raw HTTP/1.1 test server and shared helpers for the adversarial tests.
//!
//! The server speaks the wire protocol by hand so a test can craft responses
//! the higher-level stacks will not (a redirect to a private address, an
//! oversized body, a body that hangs mid-stream) and can capture the exact
//! request head the connector sent. It listens on loopback; the connector still
//! validates a public sentinel address and pins to it, and the injected
//! `RecordingDialer` forwards the pinned connection here.

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A public sentinel address the deny policy accepts. The resolver hands this
/// back so the REAL policy is exercised (a global-unicast address passes), while
/// the `RecordingDialer` forwards the bytes to the loopback test server.
pub const PUBLIC_SENTINEL: &str = "93.184.216.34";

/// A parsed [`PUBLIC_SENTINEL`].
#[must_use]
pub fn public_ip() -> IpAddr {
    PUBLIC_SENTINEL.parse().expect("sentinel is a valid IPv4")
}

/// What the test server does after reading a request.
#[derive(Clone)]
pub enum Behavior {
    /// Respond `200 OK` with this body.
    Body(Vec<u8>),
    /// Respond `200 OK` with a `Content-Length` body of this many bytes.
    Sized(usize),
    /// Respond `302 Found` with this `Location` (and no body).
    Redirect(String),
    /// Send a `200 OK` head and a little body, then hang forever without
    /// finishing the promised `Content-Length`.
    Hang,
}

/// A running test server: its bound address and the request heads it received.
pub struct TestServer {
    /// The loopback address the server bound.
    pub addr: SocketAddr,
    /// Each connection's raw request head, in arrival order.
    pub requests: Arc<Mutex<Vec<String>>>,
}

impl TestServer {
    /// The captured request heads.
    ///
    /// # Panics
    ///
    /// Panics if the capture lock is poisoned by a panicking connection task.
    #[must_use]
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("request lock poisoned").clone()
    }
}

/// Start a test server with the given behavior on a fresh loopback port.
pub async fn start(behavior: Behavior) -> TestServer {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_bg = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let behavior = behavior.clone();
            let requests = Arc::clone(&requests_bg);
            tokio::spawn(async move {
                let head = read_head(&mut socket).await;
                requests.lock().expect("request lock poisoned").push(head);
                respond(&mut socket, &behavior).await;
            });
        }
    });
    TestServer { addr, requests }
}

/// Read a request up to (and including) the end of its headers.
async fn read_head(socket: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match socket.read(&mut chunk).await {
            Ok(n) if n > 0 => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // EOF (Ok(0)) or a read error: nothing more is coming.
            _ => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Write the configured response.
async fn respond(socket: &mut TcpStream, behavior: &Behavior) {
    match behavior {
        Behavior::Body(body) => {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(body).await;
        }
        Behavior::Sized(total) => {
            let head =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n");
            let _ = socket.write_all(head.as_bytes()).await;
            let block = [b'a'; 4096];
            let mut sent = 0_usize;
            while sent < *total {
                let n = (*total - sent).min(block.len());
                if socket.write_all(&block[..n]).await.is_err() {
                    break;
                }
                sent += n;
            }
        }
        Behavior::Redirect(location) => {
            let head = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(head.as_bytes()).await;
        }
        Behavior::Hang => {
            // Promise a body, deliver a sliver, then hang so the connector's
            // total-deadline timeout must fire.
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
                .await;
            let _ = socket.write_all(b"partial").await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}
