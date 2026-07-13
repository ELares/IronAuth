// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two injectable seams the connector is built on: DNS resolution and TCP
//! dialing.
//!
//! Splitting resolution from dialing is what makes the resolve-validate-pin
//! design both correct and testable. The connector resolves a host to addresses
//! exactly ONCE through [`Resolve`], validates every address, and then hands a
//! single validated [`std::net::SocketAddr`] to [`Dial`]; the dialer is given an
//! address, never a hostname, so nothing re-resolves between the check and the
//! connect. In production the seams are [`SystemResolver`] (the OS resolver) and
//! [`SystemDialer`] (a direct `TcpStream::connect`).
//!
//! Under the `test-harness` feature the seams are exposed together with three
//! doubles: [`StaticResolver`] and [`SequenceResolver`] control what an address
//! lookup returns (including a record that flips between calls, for the
//! rebinding proof), and [`RecordingDialer`] captures the exact address the
//! connector tried to reach while forwarding the bytes to an in-process test
//! server. That combination lets a test assert both that a private address is
//! never dialed and that the connection is pinned to the once-validated public
//! address.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use tokio::net::TcpStream;

/// Resolve a host name to a set of candidate IP addresses.
///
/// The connector calls this at most once per fetch. Returning multiple
/// addresses is expected; the connector validates every one and blocks the
/// whole fetch if any is denied.
pub trait Resolve: Send + Sync {
    /// Resolve `host` (for the given `port`) to zero or more addresses.
    ///
    /// # Errors
    ///
    /// Returns the resolver's I/O error if the name cannot be resolved. The
    /// connector treats any error as a uniform block.
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;
}

/// Open a TCP connection to an already-validated address.
///
/// The dialer receives a concrete [`SocketAddr`], never a hostname, so it has no
/// opportunity to re-resolve; this is the pin that closes the rebinding window.
pub trait Dial: Send + Sync {
    /// Connect to `addr`.
    ///
    /// # Errors
    ///
    /// Returns the connect I/O error. The connector maps a dial failure to a
    /// uniform upstream error.
    fn dial(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + '_>>;
}

/// The production resolver, backed by the operating system's name resolution.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, port)).await?;
            Ok(addrs.map(|socket| socket.ip()).collect())
        })
    }
}

/// The production dialer: a direct TCP connect to the pinned address.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemDialer;

impl Dial for SystemDialer {
    fn dial(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + '_>> {
        Box::pin(async move { TcpStream::connect(addr).await })
    }
}

#[cfg(feature = "test-harness")]
pub use harness::{RecordingDialer, SequenceResolver, StaticResolver};

#[cfg(feature = "test-harness")]
mod harness {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::net::TcpStream;

    use super::{Dial, Resolve};

    /// A resolver that always returns the same fixed address set, counting the
    /// calls it receives. Use it for the multi-record case (one denied address
    /// in the set) and for hostname-resolves-to-private scenarios.
    #[derive(Debug)]
    pub struct StaticResolver {
        addrs: Vec<IpAddr>,
        calls: AtomicUsize,
    }

    impl StaticResolver {
        /// A resolver that resolves every host to `addrs`.
        #[must_use]
        pub fn new(addrs: Vec<IpAddr>) -> Self {
            Self {
                addrs,
                calls: AtomicUsize::new(0),
            }
        }

        /// How many times the resolver was asked to resolve a host.
        #[must_use]
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Resolve for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let addrs = self.addrs.clone();
            Box::pin(async move { Ok(addrs) })
        }
    }

    /// A resolver whose answer changes between calls: it returns the queued
    /// answers in order, then repeats the last one. This models a DNS record
    /// that flips between the validation lookup and a (hypothetical) second
    /// lookup at connect time; the connector must consult it only once.
    #[derive(Debug)]
    pub struct SequenceResolver {
        answers: Mutex<VecDeque<Vec<IpAddr>>>,
        calls: AtomicUsize,
    }

    impl SequenceResolver {
        /// A resolver that returns `answers` in order (repeating the final entry
        /// once exhausted). `answers` must be non-empty.
        #[must_use]
        pub fn new(answers: Vec<Vec<IpAddr>>) -> Self {
            Self {
                answers: Mutex::new(answers.into_iter().collect()),
                calls: AtomicUsize::new(0),
            }
        }

        /// How many times the resolver was consulted. The rebinding proof
        /// asserts this is exactly one.
        #[must_use]
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Resolve for SequenceResolver {
        fn resolve<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut queue = self.answers.lock().expect("resolver lock poisoned");
            let answer = if queue.len() > 1 {
                queue.pop_front().expect("checked non-empty")
            } else {
                queue.front().cloned().unwrap_or_default()
            };
            Box::pin(async move { Ok(answer) })
        }
    }

    /// A dialer that records every address the connector asked it to reach and
    /// forwards the actual bytes to a fixed in-process server. The recorded
    /// addresses prove which address the connection was pinned to (and that a
    /// denied address is never dialed at all).
    #[derive(Debug)]
    pub struct RecordingDialer {
        forward_to: SocketAddr,
        requested: Mutex<Vec<SocketAddr>>,
    }

    impl RecordingDialer {
        /// A dialer that forwards every connection to `forward_to` (the loopback
        /// test server) regardless of the pinned address it is handed.
        #[must_use]
        pub fn new(forward_to: SocketAddr) -> Self {
            Self {
                forward_to,
                requested: Mutex::new(Vec::new()),
            }
        }

        /// The addresses the connector asked to dial, in order. Empty means the
        /// connector blocked before ever attempting a connection.
        ///
        /// # Panics
        ///
        /// Panics if the internal lock is poisoned, which only happens after a
        /// panic on another thread sharing this dialer.
        #[must_use]
        pub fn requested(&self) -> Vec<SocketAddr> {
            self.requested.lock().expect("dialer lock poisoned").clone()
        }
    }

    impl Dial for RecordingDialer {
        fn dial(
            &self,
            addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + '_>> {
            self.requested
                .lock()
                .expect("dialer lock poisoned")
                .push(addr);
            let forward_to = self.forward_to;
            Box::pin(async move { TcpStream::connect(forward_to).await })
        }
    }
}
