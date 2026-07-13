// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lifecycle: a shutdown signal drains the in-flight request and the server
//! exits cleanly within the configured grace deadline, closing its listeners.

mod common;

use std::time::Duration;

use common::config_from;
use ironauth_env::Env;
use ironauth_server::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Reserve an ephemeral port by binding and immediately releasing it. A small
/// reuse race is acceptable in a test.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Poll-connect until the port accepts or the attempt budget is exhausted.
async fn wait_until_accepting(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start accepting on port {port}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drains_in_flight_request_and_exits_cleanly() {
    let public_port = free_port();
    let management_port = free_port();
    let config = config_from(&format!(
        "[server]\n\
         bind = \"127.0.0.1:{public_port}\"\n\
         management_bind = \"127.0.0.1:{management_port}\"\n\
         shutdown_grace_secs = 5\n\
         [database]\n\
         url = \"postgres://ironauth@192.0.2.1:5432/ironauth\"\n"
    ));
    let server = Server::new(config, Env::system()).expect("server builds");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        server
            .run(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    wait_until_accepting(public_port).await;

    // Open a connection and send a request, then fire shutdown while it is in
    // flight. Graceful shutdown must still complete this request.
    let mut stream = TcpStream::connect(("127.0.0.1", public_port))
        .await
        .expect("connect to public plane");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    // Let the server accept and begin handling the connection before signaling
    // shutdown, so this is a genuine in-flight request rather than a race with
    // the accept loop.
    tokio::time::sleep(Duration::from_millis(250)).await;
    shutdown_tx.send(()).expect("signal shutdown");

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .expect("in-flight response completes before timeout")
        .expect("read response");
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "in-flight request must drain to completion: {text}"
    );

    // run() returns Ok well within the grace window.
    let run_result = tokio::time::timeout(Duration::from_secs(6), handle)
        .await
        .expect("run() returns within the grace window")
        .expect("server task did not panic");
    assert!(
        run_result.is_ok(),
        "server must exit cleanly: {run_result:?}"
    );

    // The listener is closed after shutdown.
    assert!(
        TcpStream::connect(("127.0.0.1", public_port))
            .await
            .is_err(),
        "public listener must be closed after shutdown"
    );
}
