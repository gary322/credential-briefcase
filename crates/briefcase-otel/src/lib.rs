use std::sync::OnceLock;

use anyhow::Context as _;
use http::HeaderMap;
use opentelemetry::Context;
use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::TraceContextExt as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

static PROPAGATOR_INSTALLED: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct TracingInitOptions<'a> {
    pub service_name: &'a str,
    pub service_version: &'a str,
    pub default_env_filter: &'a str,
}

fn ensure_propagator_installed() {
    PROPAGATOR_INSTALLED.get_or_init(|| {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
    });
}

fn env_true(name: &str) -> bool {
    let Ok(v) = std::env::var(name) else {
        return false;
    };
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn otel_enabled() -> bool {
    // Standard OTel env var or briefcase-specific switch.
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
        || env_true("BRIEFCASE_OTEL")
}

fn otlp_endpoint() -> String {
    if let Ok(v) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        && !v.trim().is_empty()
    {
        return v;
    }
    // Default for local collectors (Jaeger/otelcol). Only used when BRIEFCASE_OTEL is set.
    "http://127.0.0.1:4318".to_string()
}

fn join_otlp_endpoint(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{base}{path}")
}

fn otlp_traces_endpoint() -> String {
    if let Ok(v) = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        && !v.trim().is_empty()
    {
        return v;
    }
    join_otlp_endpoint(&otlp_endpoint(), "/v1/traces")
}

fn otlp_metrics_endpoint() -> String {
    if let Ok(v) = std::env::var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
        && !v.trim().is_empty()
    {
        return v;
    }
    join_otlp_endpoint(&otlp_endpoint(), "/v1/metrics")
}

pub fn init_tracing(opts: TracingInitOptions<'_>) -> anyhow::Result<()> {
    ensure_propagator_installed();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| opts.default_env_filter.into());

    let fmt_layer = tracing_subscriber::fmt::layer().json();

    if otel_enabled() {
        use opentelemetry::KeyValue;
        use opentelemetry_otlp::{Protocol, WithExportConfig as _};
        use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;

        let resource = opentelemetry_sdk::Resource::builder()
            .with_service_name(opts.service_name.to_string())
            .with_attributes([KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
                opts.service_version.to_string(),
            )])
            .build();

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(otlp_traces_endpoint())
            .with_protocol(Protocol::HttpBinary)
            .build()
            .context("build otlp span exporter")?;

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)))
            .with_resource(resource.clone())
            .build();
        opentelemetry::global::set_tracer_provider(tracer_provider);
        let tracer = opentelemetry::global::tracer(opts.service_name.to_string());

        // Metrics: export spend/approvals counters when enabled. Uses the same OTLP endpoint.
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(otlp_metrics_endpoint())
            .with_protocol(Protocol::HttpBinary)
            .build()
            .context("build otlp metric exporter")?;
        let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_periodic_exporter(metric_exporter)
            .with_resource(resource)
            .build();
        opentelemetry::global::set_meter_provider(meter_provider);

        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
        Ok(())
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .json()
            .init();
        Ok(())
    }
}

pub fn inject_trace_headers(headers: &mut HeaderMap) {
    ensure_propagator_installed();

    let cx = tracing::Span::current().context();
    if !cx.span().span_context().is_valid() {
        return;
    }

    opentelemetry::global::get_text_map_propagator(|prop| {
        prop.inject_context(&cx, &mut HeaderInjector { headers });
    });
}

pub fn extract_trace_context(headers: &HeaderMap) -> Context {
    ensure_propagator_installed();
    opentelemetry::global::get_text_map_propagator(|prop| {
        prop.extract(&HeaderExtractor { headers })
    })
}

struct HeaderInjector<'a> {
    headers: &'a mut HeaderMap,
}

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes()) else {
            return;
        };
        let Ok(val) = http::header::HeaderValue::from_str(&value) else {
            return;
        };
        self.headers.insert(name, val);
    }
}

struct HeaderExtractor<'a> {
    headers: &'a HeaderMap,
}

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(|k| k.as_str()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct Metrics {
    approvals_required_total: opentelemetry::metrics::Counter<u64>,
    approvals_approved_total: opentelemetry::metrics::Counter<u64>,
    spend_microusd_total: opentelemetry::metrics::Counter<u64>,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(|| {
        let meter = opentelemetry::global::meter("credential-briefcase");

        let approvals_required_total = meter
            .u64_counter("briefcase_approvals_required_total")
            .with_description("Count of tool calls that required approval.")
            .build();

        let approvals_approved_total = meter
            .u64_counter("briefcase_approvals_approved_total")
            .with_description("Count of approvals granted.")
            .build();

        let spend_microusd_total = meter
            .u64_counter("briefcase_spend_microusd_total")
            .with_description("Total spend recorded by briefcased (microusd).")
            .build();

        Metrics {
            approvals_required_total,
            approvals_approved_total,
            spend_microusd_total,
        }
    })
}

impl Metrics {
    pub fn record_approval_required(&self, tool_id: &str, reason: &str) {
        self.approvals_required_total.add(
            1,
            &[
                opentelemetry::KeyValue::new("tool_id", tool_id.to_string()),
                opentelemetry::KeyValue::new("reason", reason.to_string()),
            ],
        );
    }

    pub fn record_approval_approved(&self, tool_id: &str) {
        self.approvals_approved_total.add(
            1,
            &[opentelemetry::KeyValue::new("tool_id", tool_id.to_string())],
        );
    }

    pub fn record_spend_microusd(&self, category: &str, amount_microusd: i64) {
        let Ok(amount) = u64::try_from(amount_microusd) else {
            return;
        };
        self.spend_microusd_total.add(
            amount,
            &[opentelemetry::KeyValue::new(
                "category",
                category.to_string(),
            )],
        );
    }
}
