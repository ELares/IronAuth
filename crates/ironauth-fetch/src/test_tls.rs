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
//! The cost is a ceiling. An in-process server can be DIALED and never spoken to, so nothing
//! in the workspace could test the response half of an outbound feature: verdict parsing,
//! signature verification, status classification. Issue #112's flow-target tests stop at "it
//! dialed" for exactly this reason, and two of its acceptance criteria were unprovable.
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
/// It records the request bytes it receives, which is what lets a test assert on what was
/// SENT (headers, signature, envelope) and not only on what came back.
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
    /// # Panics
    ///
    /// If the generated leaf cannot form a server config, or the loopback bind fails.
    pub async fn start(identity: &TestTlsIdentity, status: u16, body: impl Into<Vec<u8>>) -> Self {
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
        let body = body.into();
        let reason = if status == 200 { "OK" } else { "Error" };

        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let sink = Arc::clone(&sink);
                let body = body.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    // Read to the end of the request head, then answer. The head is what
                    // carries the headers a test wants to inspect.
                    let mut seen = Vec::new();
                    let mut buf = [0_u8; 1024];
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        seen.extend_from_slice(&buf[..n]);
                        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    if let Ok(mut guard) = sink.lock() {
                        guard.push(seen);
                    }
                    let head = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ignored = tls.write_all(head.as_bytes()).await;
                    let _ignored = tls.write_all(&body).await;
                    let _ignored = tls.flush().await;
                });
            }
        });

        Self { addr, received }
    }

    /// The request heads received so far, oldest first.
    #[must_use]
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}
