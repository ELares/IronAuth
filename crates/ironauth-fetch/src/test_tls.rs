// SPDX-License-Identifier: MIT OR Apache-2.0

//! A throwaway TLS identity for tests that must complete a real handshake (issue #959).
//!
//! Reachable only under `test-harness`, so a released binary never links `rcgen` and never
//! has a path to any of this.
//!
//! ## Why this exists
//!
//! [`crate::Fetcher::for_tests`] and [`crate::Fetcher::from_parts`] both build a client with
//! an EMPTY trust store. That is correct for the tests they were written for: they assert
//! SSRF refusals and route shapes, and none of them speaks to anyone. It also avoids reading
//! the host keychain, which once coupled three unrelated crates to a machine-level condition
//! and failed the gate about half the time.
//!
//! The cost is a ceiling on one class of caller: anything reachable only over `https`.
//!
//! A test that opts its request into plaintext with `allow_plaintext_http` already gets a
//! full response through the hardened fetcher, and several do: `tests/behavior.rs` asserts
//! status, body bytes and the caps, and federation covers status classification and JWKS
//! signature verification. The response half is not untested in general, and this module
//! should not be read as claiming it was.
//!
//! The flow-target consultation is the case that could not be reached END TO END. It builds
//! its request WITHOUT the plaintext opt-in, correctly, because no production caller should
//! send a signed envelope in the clear.
//!
//! Its verdict PARSER is separately well covered by inline tests over hand-built responses, so
//! this is not first coverage of that. What was missing is the integration: a real
//! registration, through the real dispatcher, over a real transport, ending in what the flow
//! API renders. Two of issue #112's acceptance criteria are stated as integration properties
//! and were unprovable for that reason.
//!
//! ## What this does and does not relax
//!
//! It supplies a trust anchor and NOTHING else. Resolution, destination validation, the deny
//! policy, the byte and time caps, and address pinning all run exactly as in production, so a
//! test still proves the policy rather than stepping around it. A test pointed at a loopback
//! or private address is still refused, and there is a test in this crate that says so.

use std::sync::{Arc, Mutex};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A self-signed root and one leaf issued under it, both freshly generated.
///
/// Nothing here is committed to the repository, which is deliberate: a checked-in private key
/// is a credential on disk whatever the intent, and this repo scans for exactly that. Minting
/// per run also means no test can accidentally depend on another's material.
#[derive(Debug)]
pub struct TestTlsIdentity {
    /// The root, DER encoded. Hand this to [`crate::Fetcher::from_parts_trusting`].
    pub root_der: CertificateDer<'static>,
    /// The leaf chain to serve, leaf first, as a rustls server config wants it.
    pub leaf_chain: Vec<CertificateDer<'static>>,
    /// The leaf's private key, for the server side only.
    pub leaf_key: PrivateKeyDer<'static>,
}

impl TestTlsIdentity {
    /// Mint a root and a leaf valid for `dns_name`.
    ///
    /// `dns_name` must be the name the fetcher will VERIFY, which is the host in the URL under
    /// test, not the address the dialer connects to. Those differ on purpose here: the
    /// resolver answers a public address so destination validation does real work, while the
    /// dialer lands the socket on a local listener. The certificate belongs to the name, and
    /// the policy still judges the address.
    ///
    /// # Panics
    ///
    /// If key generation or self-signing fails, which for a fresh in-memory keypair means the
    /// crypto provider is broken and no test below this could be meaningful anyway.
    #[must_use]
    pub fn generate(dns_name: &str) -> Self {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut root_name = DistinguishedName::new();
        root_name.push(DnType::CommonName, "ironauth test root");
        root_params.distinguished_name = root_name;
        let root_key = KeyPair::generate().expect("generate a root keypair");
        let root = root_params
            .self_signed(&root_key)
            .expect("self-sign the test root");
        let root_der = root.der().clone();

        let mut leaf_params = CertificateParams::new(vec![dns_name.to_owned()])
            .expect("the DNS name is a valid subject alternative name");
        let mut leaf_name = DistinguishedName::new();
        leaf_name.push(DnType::CommonName, dns_name);
        leaf_params.distinguished_name = leaf_name;
        let leaf_key = KeyPair::generate().expect("generate a leaf keypair");
        // Signed with the SAME root certificate and key that were just self-signed above, so
        // the certificate the leaf chains to is by construction the one the client is handed
        // as its anchor.
        let leaf = leaf_params
            .signed_by(&leaf_key, &root, &root_key)
            .expect("sign the leaf under the test root");

        Self {
            root_der,
            leaf_chain: vec![leaf.der().clone()],
            leaf_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        }
    }
}

/// An in-process HTTPS target that ANSWERS, for tests of the response half (issue #959).
///
/// Lives here rather than in each consumer's test file for two reasons. Running a TLS listener
/// needs a server-side stack, and putting it here means a crate that only wants to be answered
/// does not grow a TLS server dependency of its own. And every consumer then drives the same
/// far side, so a difference between two suites is a difference in the code under test rather
/// than in two hand-rolled servers.
///
/// It records each request it receives, head AND body, which is what lets a test assert on
/// what was SENT (the headers, the signature, and the envelope the signature covers) rather
/// than only on what came back.
pub struct TestTlsTarget {
    /// Where the dialer should be pointed. Loopback: the resolver still answers a public
    /// address, so destination validation does real work while the socket lands here.
    pub addr: std::net::SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl TestTlsTarget {
    /// Start a listener that answers every connection with `status` and `body`.
    ///
    /// Serves in a loop rather than once, so a retrying caller is answered each time instead
    /// of seeing a connection refused on the second attempt and testing the wrong branch.
    ///
    /// For a target whose answer must depend on the REQUEST, such as one signing its response
    /// under a delivery id it has to read out of the request headers, use
    /// [`TestTlsTarget::start_with`].
    ///
    /// # Panics
    ///
    /// If the generated leaf cannot form a server config, or the loopback bind fails.
    pub async fn start(identity: &TestTlsIdentity, status: u16, body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        Self::start_with(identity, move |_request| (status, body.clone(), Vec::new())).await
    }

    /// Start a listener whose answer is computed FROM the request.
    ///
    /// `respond` receives the recorded request (head and body) and returns the status, the
    /// body, and any extra response headers.
    ///
    /// The callback exists so that signing stays OUT of this crate. A target that signs its
    /// response has to read the delivery id from the request and compute an HMAC, which is
    /// webhook domain knowledge; putting it here would mean this transport crate depending on
    /// the JOSE crate to serve a test fixture. The caller already has both.
    ///
    /// # Panics
    ///
    /// If the generated leaf cannot form a server config, or the loopback bind fails.
    pub async fn start_with<F>(identity: &TestTlsIdentity, respond: F) -> Self
    where
        F: Fn(&[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) + Send + Sync + 'static,
    {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(identity.leaf_chain.clone(), identity.leaf_key.clone_key())
            .expect("the generated leaf and key form a valid server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind a loopback listener");
        let addr = listener.local_addr().expect("local addr");

        let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let respond = Arc::new(respond);

        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let sink = Arc::clone(&sink);
                let respond = Arc::clone(&respond);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    // Read the head, then the body its `content-length` declares.
                    //
                    // The body is not optional detail: it carries the ENVELOPE, which is what
                    // a signature is computed over, so a test that wants to verify what was
                    // sent needs it. An earlier revision stopped at the blank line and this
                    // type's own doc still promised the envelope, which is a doc describing a
                    // capability the code did not have.
                    let mut seen = Vec::new();
                    let mut buf = [0_u8; 1024];
                    let mut head_end = None;
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        seen.extend_from_slice(&buf[..n]);
                        // Scanned over the WHOLE accumulated buffer rather than the latest
                        // read, so a terminator split across two reads is still found.
                        if let Some(at) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                            head_end = Some(at + 4);
                            break;
                        }
                    }

                    // `content-length` only. No chunked support, deliberately: nothing in
                    // this workspace sends a chunked request body, and a half-implemented
                    // decoder would fail in a way that looks like the code under test.
                    //
                    // NOT EXERCISED by any current caller, and worth saying so precisely,
                    // because the threshold is not the one you would guess.
                    //
                    // The loop runs iff the head and the body do NOT arrive together in one
                    // read of the 1024-byte buffer above. `already` is whatever body bytes
                    // rode along in the read that completed the head, so the head is
                    // subtracted from the body's budget: the real allowance is
                    // `1024 - head_len`, not 1024. Today's consult head is roughly 250 bytes
                    // (request line, content-type, the three Standard Webhooks headers, host,
                    // content-length), leaving about 770 for the body, and the envelope is
                    // near 300. An 800-byte body would be "smaller than one read" and would
                    // still enter this loop.
                    //
                    // Measured on this tree: forcing `remaining` to 0 leaves every test
                    // green, because with today's sizes the loop runs zero times anyway;
                    // discarding the captured body reddens them (0 against 299). So the
                    // RECORDING is pinned and this remainder loop is defensive only, and a
                    // caller near that `1024 - head_len` boundary should not assume otherwise.
                    if let Some(head_end) = head_end {
                        let head = String::from_utf8_lossy(&seen[..head_end]).to_ascii_lowercase();
                        let declared = head
                            .split("\r\n")
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        // Some of the body may already have arrived in the read that
                        // completed the head, so only the REMAINDER is taken from the socket.
                        let already = seen.len() - head_end;
                        let mut remaining = declared.saturating_sub(already);
                        while remaining > 0 {
                            match tls.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    seen.extend_from_slice(&buf[..n]);
                                    remaining = remaining.saturating_sub(n);
                                }
                            }
                        }
                    }
                    let (status, body, extra) = respond(&seen);
                    if let Ok(mut guard) = sink.lock() {
                        guard.push(seen);
                    }
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let mut head = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\n",
                        body.len()
                    );
                    for (name, value) in extra {
                        use std::fmt::Write as _;
                        let _ignored = writeln!(head, "{name}: {value}\r");
                    }
                    head.push_str("\r\n");
                    let _ignored = tls.write_all(head.as_bytes()).await;
                    let _ignored = tls.write_all(&body).await;
                    let _ignored = tls.flush().await;
                });
            }
        });

        Self { addr, received }
    }

    /// The requests received so far, oldest first, each one head and body together.
    ///
    /// The body is included because the envelope is what a signature is computed over, so a
    /// test verifying a delivery needs the exact bytes rather than the headers alone.
    #[must_use]
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}
