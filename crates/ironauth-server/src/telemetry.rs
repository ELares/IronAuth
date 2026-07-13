// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tracing subscriber wiring: structured logs, an async writer, and the
//! optional OTLP trace exporter.
//!
//! The subscriber (spans plus events) is wired regardless of build features;
//! the JSON formatter uses ECS-friendly field names on the request span so the
//! stream drops into a log pipeline unedited. The non-blocking writer keeps
//! logging off the request path. OTLP trace export is compiled in only behind
//! the non-default `otlp` feature, so the default build and the musl static
//! lane stay lean and protoc-free; when the feature is absent a configured
//! `telemetry.otlp_endpoint` logs a warning and is otherwise inert.
//!
//! Redaction is structural, not a scrubbing pass: log call sites carry route
//! templates and safe fields only (see [`crate::observe`]), and sensitive
//! runtime values travel wrapped in [`crate::Redacted`]. Nothing here parses
//! log lines looking for secrets.

use ironauth_config::{LogFormat, TelemetryConfig};
use tracing::{Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, fmt};

/// Keeps the async logging worker (and, with the `otlp` feature, the tracer
/// provider) alive for the process lifetime. Drop flushes buffered logs and
/// shuts the exporter down.
#[must_use = "dropping the guard flushes and stops logging"]
pub struct TelemetryGuard {
    _appender: crate::logwriter::WriterGuard,
    #[cfg(feature = "otlp")]
    otel: Option<opentelemetry_sdk::trace::TracerProvider>,
}

#[cfg(feature = "otlp")]
impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.otel.take() {
            // Best-effort flush of pending spans on shutdown.
            let _ = provider.shutdown();
        }
    }
}

/// Initialize the global tracing subscriber from telemetry config.
///
/// Installs the process-wide subscriber and returns a guard the caller must
/// hold for the process lifetime. Call once, before serving.
///
/// # Panics
///
/// Panics if a global subscriber was already installed by other code; in this
/// binary this function is the sole installer.
pub fn init(telemetry: &TelemetryConfig) -> TelemetryGuard {
    let (writer, appender_guard) = crate::logwriter::stdout();

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();
    layers.push(fmt_layer(telemetry.log_format, writer, level_from_env()));

    #[cfg(feature = "otlp")]
    let otel = {
        let (layer, provider) = otlp::build(telemetry);
        if let Some(layer) = layer {
            layers.push(layer);
        }
        provider
    };

    Registry::default().with(layers).init();

    #[cfg(not(feature = "otlp"))]
    if telemetry.otlp_endpoint.is_some() {
        tracing::warn!(
            "telemetry.otlp_endpoint is set but this binary was built without the \
             'otlp' feature; trace export is disabled"
        );
    }

    TelemetryGuard {
        _appender: appender_guard,
        #[cfg(feature = "otlp")]
        otel,
    }
}

/// Build a standalone subscriber writing to `make_writer`, for tests that
/// capture output. This shares the exact formatter [`init`] installs, so a
/// leak asserted absent here is absent in production.
#[must_use]
pub fn build_subscriber<W>(format: LogFormat, make_writer: W) -> impl Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    Registry::default().with(fmt_layer(format, make_writer, level_from_env()))
}

/// Construct the formatting layer for the chosen format, filtered to `level`.
fn fmt_layer<W>(
    format: LogFormat,
    writer: W,
    level: Level,
) -> Box<dyn Layer<Registry> + Send + Sync>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let filter = LevelFilter::from_level(level);
    let base = fmt::layer().with_writer(writer).with_ansi(false);
    match format {
        LogFormat::Json => base
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .with_filter(filter)
            .boxed(),
        LogFormat::Pretty => base.pretty().with_filter(filter).boxed(),
    }
}

/// The log level, from a bare `RUST_LOG` value (`trace`..`error`), default
/// `info`. A deliberately small parser: no regex-backed directive matching, so
/// the dependency graph stays lean for the musl static lane.
fn level_from_env() -> Level {
    match std::env::var("RUST_LOG") {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        },
        Err(_) => Level::INFO,
    }
}

#[cfg(feature = "otlp")]
mod otlp {
    //! OTLP exporter wiring, compiled only with the `otlp` feature.

    use ironauth_config::TelemetryConfig;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::runtime::Tokio;
    use opentelemetry_sdk::trace::TracerProvider;
    use tracing_subscriber::Layer;
    use tracing_subscriber::registry::Registry;

    /// Build the OTLP trace layer and its provider from config. Returns
    /// `(None, None)` when no endpoint is configured. Uses the tonic (gRPC)
    /// transport with no TLS: export targets a bundled collector reachable on
    /// a trusted network, which keeps the graph protoc-free and openssl-free.
    pub(super) fn build(
        telemetry: &TelemetryConfig,
    ) -> (
        Option<Box<dyn Layer<Registry> + Send + Sync>>,
        Option<TracerProvider>,
    ) {
        let Some(endpoint) = telemetry.otlp_endpoint.as_deref() else {
            return (None, None);
        };
        let exporter = match opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
        {
            Ok(exporter) => exporter,
            Err(error) => {
                tracing::warn!(%error, "OTLP exporter init failed; trace export disabled");
                return (None, None);
            }
        };
        let provider = TracerProvider::builder()
            .with_batch_exporter(exporter, Tokio)
            .build();
        let tracer = provider.tracer("ironauth");
        let layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();
        (Some(layer), Some(provider))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_level_is_info() {
        // The parser must never widen below info by accident; unknown values
        // clamp to info rather than trace.
        assert_eq!(level_from_env(), Level::INFO);
    }
}
