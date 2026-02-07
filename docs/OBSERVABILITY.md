# Observability (OpenTelemetry)

`credential-briefcase` uses `tracing` for structured logs, and can optionally export **OpenTelemetry traces and metrics** over **OTLP/HTTP (protobuf)**.

The goal is to make the full execution chain visible:

`agent -> mcp-gateway -> briefcased -> sandbox -> upstream (provider / remote MCP)`

## What’s Instrumented

Traces include spans like:

- `gateway.call_tool` (gateway tool execution entrypoint)
- `http.request` (daemon request span, with traceparent extraction)
- `tool.execute` (daemon tool execution)
- `policy.decide` (Cedar allow/deny/approval decision)
- `sandbox.execute` (WASM tool execution)
- `provider.quote_request` (example upstream call span)

Metrics include counters:

- `briefcase_approvals_required_total` (labels: `tool_id`, `reason`)
- `briefcase_approvals_approved_total` (labels: `tool_id`)
- `briefcase_spend_microusd_total` (labels: `category`)

## Enable OTLP Export

Export is **off by default**.

To turn it on, set either:

- `BRIEFCASE_OTEL=1` (uses `OTEL_EXPORTER_OTLP_ENDPOINT` if set, otherwise defaults to `http://127.0.0.1:4318`)
- `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318`

Optional per-signal overrides:

- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces`
- `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://127.0.0.1:4318/v1/metrics`

## Local Demo (Collector Logging Exporter)

This demo runs an OpenTelemetry Collector that prints received spans/metrics to its logs.

1. Start an OTLP/HTTP collector on `:4318`:

```bash
cat > /tmp/otelcol.yaml <<'YAML'
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  batch:
exporters:
  logging:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging]
YAML

docker run --rm \
  -p 4318:4318 \
  -v /tmp/otelcol.yaml:/etc/otelcol/config.yaml:ro \
  otel/opentelemetry-collector-contrib:0.101.0 \
  --config /etc/otelcol/config.yaml
```

2. In another terminal, run the provider + daemon + CLI call with OTLP export enabled:

```bash
export BRIEFCASE_OTEL=1
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318

cargo run -p agent-access-gateway
```

```bash
export BRIEFCASE_SECRET_BACKEND=file
export BRIEFCASE_MASTER_PASSPHRASE='dev-passphrase-change-me'
cargo run -p briefcased
```

```bash
cargo run -p briefcase-cli -- tools call quote --args-json '{"symbol":"AAPL"}'
```

3. Watch the collector logs for spans and metrics (look for the span names listed above).

## Tests

`briefcased` includes an end-to-end trace assertion:

```bash
cargo test -p briefcased observability_otel_trace_contains_policy_and_upstream_spans
```

