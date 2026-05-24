package caps

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

var (
	globalTracerProvider trace.TracerProvider = otel.GetTracerProvider()
	globalMeterProvider  metric.MeterProvider = otel.GetMeterProvider()
)

// SetTracerProvider sets the global tracer provider for capability tracing.
// If tp is nil, the global OTel tracer provider is used.
func SetTracerProvider(tp trace.TracerProvider) {
	if tp == nil {
		globalTracerProvider = otel.GetTracerProvider()
		return
	}
	globalTracerProvider = tp
}

// SetMeterProvider sets the global meter provider for capability metrics.
// If mp is nil, the global OTel meter provider is used.
func SetMeterProvider(mp metric.MeterProvider) {
	if mp == nil {
		globalMeterProvider = otel.GetMeterProvider()
		return
	}
	globalMeterProvider = mp
}

// SetNoopTelemetry disables all tracing and metrics by setting
// noop providers for both traces and metrics.
func SetNoopTelemetry() {
	globalTracerProvider = tracenoop.NewTracerProvider()
	globalMeterProvider = noop.NewMeterProvider()
}

func tracer() trace.Tracer {
	return globalTracerProvider.Tracer("github.com/mishudark/citron/caps")
}

func meter() metric.Meter {
	return globalMeterProvider.Meter("github.com/mishudark/citron/caps")
}

func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return tracer().Start(ctx, name,
		trace.WithAttributes(attrs...),
	)
}

func EndSpan(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

// RecordRequest records a capability request counter.
func RecordRequest(ctx context.Context, capType string) {
	c, err := meter().Int64Counter("caps.requests",
		metric.WithDescription("Total number of capability requests"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", capType),
	))
}

// RecordOperation records a capability operation outcome: counter and duration.
func RecordOperation(ctx context.Context, operation string, err error) {
	status := "ok"
	if err != nil {
		status = "error"
	}

	c, err := meter().Int64Counter("caps.operations",
		metric.WithDescription("Total number of capability operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("status", status),
	))
}

// RecordOperationWithKind records a capability operation outcome with a
// classified error kind dimension.  The kind distinguishes error categories
// such as "analysis", "timeout", "runtime", "setup", or "capability".
// When err is nil the kind is ignored.
func RecordOperationWithKind(ctx context.Context, operation, kind string, err error) {
	status := "ok"
	if err != nil {
		status = "error"
	}

	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
		attribute.String("status", status),
	}
	if err != nil && kind != "" {
		attrs = append(attrs, attribute.String("error_kind", kind))
	}

	c, cerr := meter().Int64Counter("caps.operations",
		metric.WithDescription("Total number of capability operations"),
		metric.WithUnit("1"),
	)
	if cerr != nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordOperationDuration records the execution duration of a capability
// operation as a histogram, tagged with operation name and status.
func RecordOperationDuration(ctx context.Context, operation string, duration time.Duration, err error) {
	status := "ok"
	if err != nil {
		status = "error"
	}

	h, herr := meter().Int64Histogram("caps.operation_duration_ms",
		metric.WithDescription("Duration of capability operations"),
		metric.WithUnit("ms"),
	)
	if herr != nil {
		return
	}
	h.Record(ctx, duration.Milliseconds(),
		metric.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("status", status),
		),
	)
}
