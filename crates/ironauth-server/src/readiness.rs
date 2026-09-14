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
    /// The optional components this deployment attached, and how to ask whether each is there.
    ///
    /// EMPTY IN A DEFAULT DEPLOYMENT, which is what makes `Degraded` unreachable there rather
    /// than merely unused: a deployment that attached no accelerator cannot be degraded by one
    /// being absent, and reporting otherwise would page an operator about a component they
    /// chose not to run.
    optional: Vec<OptionalComponent>,
}

/// An optional component whose absence degrades rather than stops the deployment.
#[derive(Clone)]
pub struct OptionalComponent {
    /// The tier to report when this one is unreachable.
    pub tier: DegradedTier,
    /// Host and port to probe.
    pub address: (String, u16),
}

impl std::fmt::Debug for OptionalComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The address can carry a host an operator would rather not see in a log line; the tier
        // is what identifies which component this is.
        f.debug_struct("OptionalComponent")
            .field("tier", &self.tier)
            .finish_non_exhaustive()
    }
}

/// The result of a readiness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Listeners are up, the database address is TCP-reachable, and every optional component
    /// this deployment attached is answering.
    Ready,
    /// Serving correctly with an optional component absent (issue #149).
    ///
    /// # This is a 200, and that is the whole point
    ///
    /// A degraded tier is one where every flow still completes and only latency or timeliness
    /// suffers. Reporting it as `503` would have a Kubernetes readiness probe remove the pod
    /// from its Service -- taking a replica that can still serve out of rotation because an
    /// OPTIONAL component is down, which is how an accelerator outage becomes an availability
    /// outage. The tier is reported in the BODY so an operator and a dashboard can see it,
    /// while the orchestrator keeps routing.
    Degraded(DegradedTier),
    /// The database address could not be reached within the probe timeout.
    ///
    /// HARD DOWN, and the only `503`: Postgres is the tier everything is complete on, so a
    /// deployment that cannot reach it cannot serve, and a probe that said otherwise would
    /// route traffic into errors.
    DatabaseUnreachable,
}

/// Which optional component is absent (issue #149).
///
/// # Why an enum and not a string
///
/// An operator's runbook and an alert both key on this, so it is a closed set with one variant
/// per DOCUMENTED tier rather than free text a caller assembles. A tier that is not in this enum
/// is a tier nobody wrote a runbook for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedTier {
    /// The hot-state accelerator is unreachable.
    ///
    /// Every flow completes on Postgres alone and reads are slower, which is the property
    /// `ironauth_hot::Tiered` holds and its outage tests measure by running one script against a
    /// working accelerator, a failing one, and none at all.
    AcceleratorAbsent,
    /// The async backbone is unreachable.
    ///
    /// Outbox work accumulates and drains on recovery rather than being lost, because the drain
    /// is a Postgres poll and the backbone only decides WHEN it runs.
    BackboneAbsent,
}

impl DegradedTier {
    /// The stable token a probe body and an alert match on.
    ///
    /// NOT the `Debug` rendering. A body an operator greps is a wire format, and deriving it
    /// from a type name means renaming the variant silently breaks every alert keyed on it.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::AcceleratorAbsent => "accelerator_absent",
            Self::BackboneAbsent => "backbone_absent",
        }
    }
}

impl Readiness {
    /// Whether the instance is ready to serve.
    ///
    /// DEGRADED IS READY. The distinction this type draws is between "serving" and "serving
    /// everything it could"; a caller asking whether to route traffic wants the first, and a
    /// caller asking what to page about wants [`Readiness::degraded_tier`].
    #[must_use]
    pub fn is_ready(self) -> bool {
        matches!(self, Readiness::Ready | Readiness::Degraded(_))
    }

    /// The tier this instance is degraded to, or [`None`] when it is healthy or hard down.
    #[must_use]
    pub const fn degraded_tier(self) -> Option<DegradedTier> {
        match self {
            Self::Degraded(tier) => Some(tier),
            Self::Ready | Self::DatabaseUnreachable => None,
        }
    }
}

impl ReadinessProbe {
    /// A probe over an explicit address, for a caller that is not reading config.
    ///
    /// [`ReadinessProbe::from_config`] is the production path; this exists so a test can point a
    /// probe at a port it controls, which is the only way to exercise a component being absent
    /// without making the test depend on something being down on the machine.
    #[must_use]
    pub fn new(host: String, port: u16, timeout: Duration) -> Self {
        Self {
            host,
            port,
            timeout,
            optional: Vec::new(),
        }
    }

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
            optional: Vec::new(),
        }
    }

    /// Probe the database address once.
    ///
    /// Returns [`Readiness::Ready`] only if a TCP connection is established
    /// within the timeout. A refused, timed-out, or unresolvable address is
    /// [`Readiness::DatabaseUnreachable`]; no bytes are exchanged and no
    /// database protocol is spoken.
    pub async fn probe(&self) -> Readiness {
        // THE DATABASE FIRST, AND IT SHORT-CIRCUITS. A deployment that cannot reach Postgres is
        // hard down whatever else is true, and reporting it as merely degraded because an
        // accelerator answered would route traffic into errors. There is no tier below this one.
        match tokio::time::timeout(
            self.timeout,
            TcpStream::connect((self.host.as_str(), self.port)),
        )
        .await
        {
            Ok(Ok(_stream)) => {}
            Ok(Err(_)) | Err(_) => return Readiness::DatabaseUnreachable,
        }

        // THE FIRST ABSENT COMPONENT NAMES THE TIER, in declaration order. Two absent at once is
        // a real state and this reports only the first, which is a deliberate simplification
        // rather than an oversight: a readiness body is read by an orchestrator and a pager, and
        // both act on "is it serving" plus one thing to look at. The metrics carry per-component
        // detail for the case where an operator wants the whole picture.
        for component in &self.optional {
            let reachable = tokio::time::timeout(
                self.timeout,
                TcpStream::connect((component.address.0.as_str(), component.address.1)),
            )
            .await;
            if !matches!(reachable, Ok(Ok(_))) {
                return Readiness::Degraded(component.tier);
            }
        }

        Readiness::Ready
    }

    /// Declare an optional component whose absence is a degraded tier rather than an outage.
    ///
    /// # Errors
    ///
    /// None; a component whose address cannot be parsed is the CALLER's to reject, because only
    /// the caller knows whether a malformed accelerator address should stop a boot or be
    /// ignored. This takes host and port already separated so there is no parse here to get
    /// wrong.
    #[must_use]
    pub fn with_optional(mut self, tier: DegradedTier, host: &str, port: u16) -> Self {
        self.optional.push(OptionalComponent {
            tier,
            address: (host.to_owned(), port),
        });
        self
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
            optional: Vec::new(),
        };
        assert_eq!(probe.probe().await, Readiness::DatabaseUnreachable);
    }
}

#[cfg(test)]
mod degraded_tests {
    use super::*;

    /// A port nothing listens on, for "this component is absent".
    const CLOSED_PORT: u16 = 1;

    /// A listener that accepts, for "this component is there".
    async fn open_port() -> (tokio::net::TcpListener, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        (listener, port)
    }

    #[tokio::test]
    async fn a_deployment_with_no_optional_components_is_never_degraded() {
        // THE PROPERTY THAT KEEPS THIS FROM PAGING ABOUT NOTHING. A deployment that attached no
        // accelerator cannot be degraded by one being absent, so `Degraded` must be unreachable
        // there rather than merely unused.
        let (_database, port) = open_port().await;
        let probe = ReadinessProbe::new("127.0.0.1".to_owned(), port, Duration::from_millis(200));

        let outcome = probe.probe().await;
        assert_eq!(outcome, Readiness::Ready);
        assert_eq!(
            outcome.degraded_tier(),
            None,
            "a default deployment reports no tier"
        );
    }

    #[tokio::test]
    async fn an_absent_optional_component_degrades_and_still_serves() {
        // CRITERION 6. The tier is reported DISTINCTLY from healthy, and the instance stays
        // ready -- which is the half that matters to an orchestrator, because a degraded tier
        // still completes every flow.
        let (_database, port) = open_port().await;
        let probe = ReadinessProbe::new("127.0.0.1".to_owned(), port, Duration::from_millis(200))
            .with_optional(DegradedTier::AcceleratorAbsent, "127.0.0.1", CLOSED_PORT);

        let outcome = probe.probe().await;
        assert_eq!(
            outcome,
            Readiness::Degraded(DegradedTier::AcceleratorAbsent),
            "an unreachable accelerator is a degraded tier"
        );
        assert!(
            outcome.is_ready(),
            "a degraded instance must still be READY: answering otherwise takes a replica that \
             can serve out of rotation because an optional component is down"
        );
        assert_ne!(
            outcome,
            Readiness::Ready,
            "and it must not read as healthy, or nothing tells an operator to look"
        );
    }

    #[tokio::test]
    async fn a_present_optional_component_is_not_a_tier() {
        // THE CONTROL. Without it, a probe that reported Degraded whenever any optional
        // component was DECLARED -- reachable or not -- passes the test above.
        let (_database, db_port) = open_port().await;
        let (_accelerator, accelerator_port) = open_port().await;
        let probe =
            ReadinessProbe::new("127.0.0.1".to_owned(), db_port, Duration::from_millis(200))
                .with_optional(
                    DegradedTier::AcceleratorAbsent,
                    "127.0.0.1",
                    accelerator_port,
                );

        assert_eq!(
            probe.probe().await,
            Readiness::Ready,
            "a component that answers is not a degraded tier"
        );
    }

    #[tokio::test]
    async fn an_unreachable_database_is_hard_down_whatever_else_answers() {
        // THERE IS NO TIER BELOW POSTGRES. Reporting a database outage as merely degraded --
        // because an accelerator happened to answer -- would route traffic into errors.
        let (_accelerator, accelerator_port) = open_port().await;
        let probe = ReadinessProbe::new(
            "127.0.0.1".to_owned(),
            CLOSED_PORT,
            Duration::from_millis(200),
        )
        .with_optional(
            DegradedTier::AcceleratorAbsent,
            "127.0.0.1",
            accelerator_port,
        );

        let outcome = probe.probe().await;
        assert_eq!(outcome, Readiness::DatabaseUnreachable);
        assert!(
            !outcome.is_ready(),
            "hard down is the one state that must not be routed to"
        );
        assert_eq!(
            outcome.degraded_tier(),
            None,
            "hard down is not a degraded tier: it is the absence of the tier everything rests on"
        );
    }

    #[test]
    fn every_tier_has_a_distinct_stable_token() {
        // THE TOKEN IS A WIRE FORMAT. A runbook and an alert match on it, so two tiers sharing
        // one would make an alert fire for the wrong component, and deriving it from the variant
        // name would let a rename break every alert silently.
        let tiers = [
            DegradedTier::AcceleratorAbsent,
            DegradedTier::BackboneAbsent,
        ];
        let mut tokens: Vec<&str> = tiers.iter().map(|tier| tier.token()).collect();
        let before = tokens.len();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(before, tokens.len(), "two tiers share a token: {tokens:?}");
        for token in &tokens {
            assert!(
                token.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{token:?} is not a stable lowercase token"
            );
        }
    }
}
