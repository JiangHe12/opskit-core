package telemetry

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

func TestSpanAttributesRedaction(t *testing.T) {
	Configure(Config{ServiceName: "sentinel-cli", AttributePrefix: "sentinel", MetricNamePrefix: "sentinel_cli"})
	t.Cleanup(func() {
		Configure(Config{ServiceName: "opskit", AttributePrefix: "opskit", MetricNamePrefix: "opskit"})
	})

	attrs := SpanAttributes("alice@company.com", "prod", "prod", "order-service", "OPS-1234", true, true, "")
	got := attrMap(attrs)

	if got["sentinel.operator"] == "alice@company.com" {
		t.Fatalf("operator was not redacted: %q", got["sentinel.operator"])
	}
	if len(got["sentinel.operator"]) != 12 {
		t.Fatalf("operator hash length = %d, want 12", len(got["sentinel.operator"]))
	}
	if got["sentinel.app"] == "order-service" {
		t.Fatalf("app was not redacted: %q", got["sentinel.app"])
	}
	if len(got["sentinel.app"]) != 8 {
		t.Fatalf("app hash length = %d, want 8", len(got["sentinel.app"]))
	}
	if got["sentinel.ticket"] != "OPS-***" {
		t.Fatalf("ticket = %q, want OPS-***", got["sentinel.ticket"])
	}

	attrs = SpanAttributes("alice@company.com", "prod", "prod", "order-service", "OPS-1234", true, true, "order-")
	got = attrMap(attrs)
	if got["sentinel.app"] != "order-service" {
		t.Fatalf("whitelisted app = %q, want order-service", got["sentinel.app"])
	}
}

func TestSpanAttributesDomainAttributeName(t *testing.T) {
	Configure(Config{
		ServiceName:         "nacos-cli",
		AttributePrefix:     "nacos",
		MetricNamePrefix:    "nacos_cli",
		DomainAttributeName: "namespace",
	})
	t.Cleanup(func() {
		Configure(Config{ServiceName: "opskit", AttributePrefix: "opskit", MetricNamePrefix: "opskit", DomainAttributeName: "app"})
	})

	attrs := SpanAttributes("alice@company.com", "prod", "prod", "public-ns", "OPS-1234", true, true, "public-")
	got := attrMap(attrs)
	if _, ok := got["nacos.app"]; ok {
		t.Fatalf("unexpected nacos.app attribute: %q", got["nacos.app"])
	}
	if got["nacos.namespace"] != "public-ns" {
		t.Fatalf("whitelisted namespace = %q, want public-ns", got["nacos.namespace"])
	}

	attrs = SpanAttributes("alice@company.com", "prod", "prod", "private-ns", "OPS-1234", true, true, "public-")
	got = attrMap(attrs)
	if got["nacos.namespace"] == "private-ns" {
		t.Fatalf("namespace was not redacted: %q", got["nacos.namespace"])
	}
	if len(got["nacos.namespace"]) != 8 {
		t.Fatalf("namespace hash length = %d, want 8", len(got["nacos.namespace"]))
	}
}

func TestMetricsNoEndpointIsNoop(t *testing.T) {
	Configure(Config{ServiceName: "sentinel-cli", AttributePrefix: "sentinel", MetricNamePrefix: "sentinel_cli"})
	t.Cleanup(func() {
		Configure(Config{ServiceName: "opskit", AttributePrefix: "opskit", MetricNamePrefix: "opskit"})
	})

	shutdown := InitMetrics(context.Background(), "", false, "test")
	defer shutdown(context.Background())

	attrs := SpanAttributes("alice@company.com", "prod", "prod", "order-service", "OPS-1234", true, true, "")
	RecordCommand(context.Background(), "sentinel-cli.test", "success", time.Millisecond, attrs)
	RecordAuthorizationDenied(context.Background(), "ticket", attrs)
	RecordAuditQueryEntries(context.Background(), 1, 1, attrs)
}

func attrMap(attrs []attribute.KeyValue) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		out[string(attr.Key)] = attr.Value.AsString()
	}
	return out
}
