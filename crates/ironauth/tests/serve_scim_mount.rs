// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM surface, mounted or not, against the COMPILED binary (issue #135).
//!
//! # Why a subprocess, when three boot-wiring tests already exist
//!
//! Because they stop one layer above the line that matters. `boot_wiring_tests` drives
//! `assemble_planes` and can prove the SCIM STATE was built from the configured limits and
//! that the flag gates it -- but the state is not the surface. The single call
//! `server.mount_public(scim_router(plane.state))` is what turns an assembled state into
//! something a provisioning client can reach, and nothing in process can observe it: `serve`
//! builds its own runtime, binds sockets, and ends in `server.run(...)`.
//!
//! `serve_retention_boot.rs` records the measurement that makes this concrete for this
//! repository: replacing a boot call with a no-op left the whole crate suite green, because
//! every other test stopped above the boot path. Deleting the `mount_public` line here would
//! be the same shape, and this file is the only thing that would notice.
//!
//! # What is pinned, and what each assertion is guarding against
//!
//! With the flag ON: an unauthenticated `GET /scim/v2/ServiceProviderConfig` answers 401 with
//! `Content-Type: application/scim+json`. The status alone is not enough -- an unmounted path
//! answers 404, but so does a mounted route for a resource that does not exist, and a dead
//! process answers nothing at all. The SCIM content type is what only a SCIM handler produces.
//!
//! With the flag OFF: the same path answers 404 and no `application/scim+json` appears
//! anywhere in the response.
//!
//! Both runs first assert `GET /` answers, which distinguishes every one of the above from a
//! process that died or never bound. And both assert the child is STILL RUNNING before
//! believing any answer, because a stale listener from another test answering for a process
//! that exited would make a broken mount look fine.
//!
//! # No HTTP client
//!
//! `scripts/http-audit.sh` greps every crate manifest for a direct HTTP-client dependency,
//! dev-dependencies included, and exempts a bare `TcpStream`. So the requests here are written
//! out by hand over a socket. They are three lines of HTTP/1.1 and nothing here needs more.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ironauth_store::test_support::TestDatabase;

/// How many polls to wait for the binary to log its bound address. Counted rather than timed:
/// a slow boot must read as slow rather than as a missing mount.
const BOOT_POLLS: u32 = 900;
/// The pause between polls.
const POLL: Duration = Duration::from_millis(100);

/// A booted `ironauth serve`, killed on drop so a failing assertion cannot leak a process
/// that would then answer for the NEXT test.
struct ServeProcess {
    child: Child,
    log: std::path::PathBuf,
}

impl Drop for ServeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

impl ServeProcess {
    /// Whether the process is still running.
    ///
    /// Asserted before every answer is believed. A stale listener on the same port would
    /// otherwise let a dead process look like a working mount, which is a failure mode this
    /// repository has already shipped once.
    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// Write a serve config with the SCIM surface on or off.
fn write_config(db: &TestDatabase, scim_enabled: bool, label: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ironauth-serve-scim-{}-{label}.toml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!(
            "[database]\nurl = \"{}\"\n\n\
             [server]\nbind = \"127.0.0.1:0\"\nmanagement_bind = \"127.0.0.1:0\"\n\n\
             [scim]\nenabled = {scim_enabled}\n",
            db.app_url(),
        ),
    )
    .expect("write the serve config");
    path
}

/// Boot the compiled binary and return it with the public port it bound.
fn boot(db: &TestDatabase, scim_enabled: bool, label: &str) -> (ServeProcess, u16) {
    let config = write_config(db, scim_enabled, label);
    let mut log = std::env::temp_dir();
    log.push(format!(
        "ironauth-serve-scim-{}-{label}.log",
        std::process::id()
    ));
    let out = std::fs::File::create(&log).expect("create the serve log");
    let err = out.try_clone().expect("clone the serve log handle");
    let child = Command::new(env!("CARGO_BIN_EXE_ironauth"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("boot the compiled ironauth binary");
    let mut process = ServeProcess { child, log };

    // The bound port comes out of the line the server logs when it starts serving, because
    // `bind = "127.0.0.1:0"` means the kernel chooses it.
    for _ in 0..BOOT_POLLS {
        if let Some(port) = bound_port(&process.log()) {
            let _ = std::fs::remove_file(&config);
            return (process, port);
        }
        assert!(
            process.alive(),
            "the binary exited before it bound a port; log:\n{}",
            process.log()
        );
        std::thread::sleep(POLL);
    }
    panic!(
        "the binary never logged a bound address; log:\n{}",
        process.log()
    );
}

/// The public port out of the `server.public.addr` field the server logs.
fn bound_port(log: &str) -> Option<u16> {
    let line = log
        .lines()
        .find(|line| line.contains("server.public.addr"))?;
    let start = line.find("server.public.addr")?;
    // The field renders as a debug SocketAddr; take the digits after the last colon of the
    // first address-looking run following the key.
    let rest = &line[start..];
    let colon = rest.find("127.0.0.1:")? + "127.0.0.1:".len();
    let digits: String = rest[colon..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// One HTTP/1.1 GET, written by hand. Returns the whole response as text.
fn get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the public plane");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set a read timeout");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .expect("write the request");
    stream.flush().expect("flush the request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read the response");
    String::from_utf8_lossy(&response).into_owned()
}

#[test]
fn the_mounted_scim_surface_answers_on_the_public_plane() {
    let db = futures_lite_block_on(TestDatabase::start());
    let (mut process, port) = boot(&db, true, "on");

    // THE LIVENESS CONTROL FIRST. Every assertion below is about what a path answers, and
    // all of them are satisfied by a dead process in the same way, so this is what makes them
    // mean anything.
    let root = get(port, "/");
    assert!(process.alive(), "the binary died; log:\n{}", process.log());
    assert!(
        root.starts_with("HTTP/1.1 "),
        "the public plane answered nothing at all: {root}"
    );

    let answer = get(port, "/scim/v2/ServiceProviderConfig");
    assert!(process.alive(), "the binary died; log:\n{}", process.log());
    assert!(
        answer.contains("401"),
        "the mounted SCIM surface must refuse an unauthenticated caller: {answer}"
    );
    // THE DISCRIMINATOR. An unmounted path answers 404 and a mounted resource route answers
    // 404 for an absent resource, so the status cannot separate them. Only a SCIM handler
    // produces this content type.
    assert!(
        answer.contains("application/scim+json"),
        "the refusal must be a SCIM error document, which is what proves a SCIM handler ran \
         rather than the router falling through: {answer}"
    );
    assert!(
        process
            .log()
            .contains("SCIM 2.0 inbound provisioning mounted"),
        "the boot must SAY it mounted, so an operator can tell: {}",
        process.log()
    );
}

#[test]
fn every_scim_path_is_a_uniform_404_while_the_flag_is_off() {
    let db = futures_lite_block_on(TestDatabase::start());
    let (mut process, port) = boot(&db, false, "off");

    let root = get(port, "/");
    assert!(process.alive(), "the binary died; log:\n{}", process.log());
    assert!(
        root.starts_with("HTTP/1.1 "),
        "the public plane answered nothing at all: {root}"
    );

    for path in [
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/Users",
        "/scim/v2/Groups",
        "/scim/v2/Schemas",
    ] {
        let answer = get(port, path);
        assert!(process.alive(), "the binary died; log:\n{}", process.log());
        assert!(
            answer.contains("404"),
            "{path} must be a uniform 404 while the flag is off: {answer}"
        );
        assert!(
            !answer.contains("application/scim+json"),
            "{path} answered as a SCIM handler while the surface is disabled: {answer}"
        );
    }
    assert!(
        process.log().contains("scim.enabled is false"),
        "the boot must say WHY nothing mounted: {}",
        process.log()
    );
}

/// Block on a future without pulling in a runtime dependency this crate does not have.
///
/// `TestDatabase::start` is async and these tests are sync, because the HTTP they drive is a
/// hand-written socket rather than an async client. One small executor is cheaper than making
/// the whole file async for two awaits.
fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}
