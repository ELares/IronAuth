// SPDX-License-Identifier: MIT OR Apache-2.0

//! Readiness probing for `/readyz`.
//!
//! Provisional until issue #7 (persistence substrate) lands: with no database
//! driver in the graph yet, readiness is a TCP reachability check against the
//! configured Postgres address. It answers "could this instance plausibly
//! serve" (listeners up, database socket reachable) without importing a driver
//! or opening a real connection. When #7 lands, this is replaced by a pool
//! health check; the endpoint contract (200 ready, 503 not) stays.
//!
//! The probe is bounded by a fixed monotonic deadline via `tokio::time`, so a
//! black-holed database address never hangs the probe.

use std::time::Duration;

use ironauth_config::DatabaseConfig;
use tokio::net::TcpStream;

/// Maximum time to wait for the database TCP connect before reporting not
/// ready. Kept short so orchestrator probes stay responsive.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// A readiness probe over the configured database address.
#[derive(Debug, Clone)]
pub struct ReadinessProbe {
    host: String,
    port: u16,
    timeout: Duration,
}

/// The result of a readiness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Listeners are up and the database address is TCP-reachable.
    Ready,
    /// The database address could not be reached within the probe timeout.
    DatabaseUnreachable,
}

impl Readiness {
    /// Whether the instance is ready to serve.
    #[must_use]
    pub fn is_ready(self) -> bool {
        matches!(self, Readiness::Ready)
    }
}

impl ReadinessProbe {
    /// Build a probe from the database config. The host is taken from the DSN
    /// (IPv6 brackets stripped for connection); the port defaults to the
    /// Postgres default when the DSN omits it.
    #[must_use]
    pub fn from_config(database: &DatabaseConfig) -> Self {
        let raw_host = database.url.host();
        let host = raw_host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(raw_host)
            .to_owned();
        Self {
            host,
            port: database.url.port().unwrap_or(5432),
            timeout: PROBE_TIMEOUT,
        }
    }

    /// Probe the database address once.
    ///
    /// Returns [`Readiness::Ready`] only if a TCP connection is established
    /// within the timeout. A refused, timed-out, or unresolvable address is
    /// [`Readiness::DatabaseUnreachable`]; no bytes are exchanged and no
    /// database protocol is spoken.
    pub async fn probe(&self) -> Readiness {
        match tokio::time::timeout(
            self.timeout,
            TcpStream::connect((self.host.as_str(), self.port)),
        )
        .await
        {
            Ok(Ok(_stream)) => Readiness::Ready,
            Ok(Err(_)) | Err(_) => Readiness::DatabaseUnreachable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_config::Config;

    #[test]
    fn probe_reads_host_and_port_from_dsn() {
        let config = Config::from_toml_str(
            "[database]\nurl = \"postgres://u@db.internal:6000/x\"\n",
            "<inline>",
        )
        .expect("valid")
        .config;
        let probe = ReadinessProbe::from_config(&config.database);
        assert_eq!(probe.host, "db.internal");
        assert_eq!(probe.port, 6000);
    }

    #[test]
    fn probe_defaults_port_and_strips_ipv6_brackets() {
        let config =
            Config::from_toml_str("[database]\nurl = \"postgres://[::1]/x\"\n", "<inline>")
                .expect("valid")
                .config;
        let probe = ReadinessProbe::from_config(&config.database);
        assert_eq!(probe.host, "::1");
        assert_eq!(probe.port, 5432);
    }

    #[tokio::test]
    async fn unreachable_address_reports_not_ready() {
        // Reserved TEST-NET-1 (RFC 5737) address; connect will not succeed.
        let probe = ReadinessProbe {
            host: "192.0.2.1".to_owned(),
            port: 5432,
            timeout: Duration::from_millis(150),
        };
        assert_eq!(probe.probe().await, Readiness::DatabaseUnreachable);
    }
}
