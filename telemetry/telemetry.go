// Package telemetry initializes OpenTelemetry tracing and metrics for a CLI.
//
// When an OTLP endpoint is configured, every CLI command execution is wrapped
// in a trace span. The span carries operator, context, app, and ticket
// attributes so traces can be correlated with audit log entries.
//
// If no endpoint is configured the package is a no-op and adds no latency.
package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config controls package-level OpenTelemetry names.
type Config struct {
	ServiceName         string
	AttributePrefix     string
	MetricNamePrefix    string
	DomainAttributeName string
}

var config = Config{ServiceName: "opskit", AttributePrefix: "opskit", MetricNamePrefix: "opskit", DomainAttributeName: "app"}

// Configure sets package-level OpenTelemetry names for a consumer CLI.
func Configure(next Config) {
	if next.ServiceName != "" {
		config.ServiceName = next.ServiceName
	}
	if next.AttributePrefix != "" {
		config.AttributePrefix = strings.TrimSuffix(next.AttributePrefix, ".")
	}
	if next.MetricNamePrefix != "" {
		config.MetricNamePrefix = strings.TrimSuffix(next.MetricNamePrefix, "_")
	}
	if next.DomainAttributeName != "" {
		config.DomainAttributeName = strings.Trim(next.DomainAttributeName, ".")
	}
}

// ShutdownFunc flushes and stops the tracer provider. Always call it (safe
// even if telemetry is disabled — it is a no-op in that case).
type ShutdownFunc func(context.Context)

var (
	metricsMu            sync.RWMutex
	commandTotal         metric.Int64Counter
	commandDuration      metric.Float64Histogram
	authorizeDeniedTotal metric.Int64Counter
	auditQueryEntries    metric.Int64Counter
)

// Init configures the global OpenTelemetry tracer and returns a shutdown
// function. If endpoint is empty telemetry is disabled (no-op tracer).
func Init(ctx context.Context, endpoint string, insecure bool, version string) ShutdownFunc {
	if endpoint == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) {}
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(endpoint)}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) {}
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(config.ServiceName),
		semconv.ServiceVersion(version),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithExportTimeout(5*time.Second)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return func(shutCtx context.Context) {
		_ = tp.Shutdown(shutCtx)
	}
}

// InitMetrics configures the global OpenTelemetry meter provider.
func InitMetrics(ctx context.Context, endpoint string, insecure bool, version string) ShutdownFunc {
	if endpoint == "" {
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
		resetMetricInstruments()
		return func(context.Context) {}
	}

	opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpointURL(endpoint)}
	if insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	exp, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
		resetMetricInstruments()
		return func(context.Context) {}
	}
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(config.ServiceName),
		semconv.ServiceVersion(version),
	)
	reader := sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(5*time.Second))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res))
	otel.SetMeterProvider(mp)
	initMetricInstruments()
	return func(shutCtx context.Context) {
		_ = mp.Shutdown(shutCtx)
		resetMetricInstruments()
	}
}

// Tracer returns the global CLI tracer.
func Tracer() trace.Tracer {
	return otel.Tracer(config.ServiceName)
}

// RecordCommand records command count and duration metrics.
func RecordCommand(ctx context.Context, command, status string, duration time.Duration, attrs []attribute.KeyValue) {
	total, hist := commandMetrics()
	if total == nil || hist == nil {
		return
	}
	attrs = append(attrs, attribute.String("command", command), attribute.String("status", status))
	total.Add(ctx, 1, metric.WithAttributes(attrs...))
	hist.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}

// RecordAuthorizationDenied records a rejected authorization attempt.
func RecordAuthorizationDenied(ctx context.Context, reason string, attrs []attribute.KeyValue) {
	counter := authorizeMetric()
	if counter == nil {
		return
	}
	attrs = append(attrs, attribute.String("reason", reason))
	counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordAuditQueryEntries records valid and malformed audit query entries.
func RecordAuditQueryEntries(ctx context.Context, valid, malformed int, attrs []attribute.KeyValue) {
	counter := auditQueryMetric()
	if counter == nil {
		return
	}
	if valid > 0 {
		counter.Add(ctx, int64(valid), metric.WithAttributes(append(attrs, attribute.String("result", "valid"))...))
	}
	if malformed > 0 {
		counter.Add(ctx, int64(malformed), metric.WithAttributes(append(attrs, attribute.String("result", "malformed"))...))
	}
}

// SpanAttributes builds the standard attribute set for a CLI span.
func SpanAttributes(operator, contextName, env, app, ticket string, protected bool, redact bool, appPlainPrefix string) []attribute.KeyValue {
	if redact {
		operator = hashPrefix(operator, 12)
		if app != "" && (appPlainPrefix == "" || !strings.HasPrefix(app, appPlainPrefix)) {
			app = hashPrefix(app, 8)
		}
		ticket = redactTicket(ticket)
	}
	prefix := config.AttributePrefix + "."
	attrs := []attribute.KeyValue{
		attribute.String(prefix+"operator", operator),
		attribute.String(prefix+"context", contextName),
		attribute.String(prefix+"env", env),
		attribute.Bool(prefix+"protected", protected),
	}
	if app != "" {
		attrs = append(attrs, attribute.String(prefix+config.DomainAttributeName, app))
	}
	if ticket != "" {
		attrs = append(attrs, attribute.String(prefix+"ticket", ticket))
	}
	return attrs
}

func initMetricInstruments() {
	meter := otel.Meter(config.ServiceName)
	total, _ := meter.Int64Counter(config.MetricNamePrefix + "_command_total")
	duration, _ := meter.Float64Histogram(config.MetricNamePrefix + "_command_duration_seconds")
	denied, _ := meter.Int64Counter(config.MetricNamePrefix + "_authorize_denied_total")
	auditEntries, _ := meter.Int64Counter(config.MetricNamePrefix + "_audit_query_entries")
	metricsMu.Lock()
	defer metricsMu.Unlock()
	commandTotal = total
	commandDuration = duration
	authorizeDeniedTotal = denied
	auditQueryEntries = auditEntries
}

func resetMetricInstruments() {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	commandTotal = nil
	commandDuration = nil
	authorizeDeniedTotal = nil
	auditQueryEntries = nil
}

func commandMetrics() (metric.Int64Counter, metric.Float64Histogram) {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return commandTotal, commandDuration
}

func authorizeMetric() metric.Int64Counter {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return authorizeDeniedTotal
}

func auditQueryMetric() metric.Int64Counter {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return auditQueryEntries
}

func hashPrefix(value string, length int) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	encoded := hex.EncodeToString(sum[:])
	if len(encoded) < length {
		return encoded
	}
	return encoded[:length]
}

func redactTicket(ticket string) string {
	if ticket == "" {
		return ""
	}
	if idx := strings.Index(ticket, "-"); idx > 0 {
		return ticket[:idx+1] + "***"
	}
	return ticket
}
