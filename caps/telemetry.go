package caps

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// The provider globals are read on every span/metric call and written by the
// Set* functions, potentially from concurrent SafeExecute calls, so all
// access is guarded by telMu.
var (
	telMu          sync.RWMutex
	tracerProvider trace.TracerProvider = otel.GetTracerProvider()
	meterProvider  metric.MeterProvider = otel.GetMeterProvider()
)

// Instruments are created once per meter and reused; creating them on every
// call defeats aggregation and adds allocation to every operation.
var (
	instMu       sync.Mutex
	instMeter    metric.Meter
	instRequests metric.Int64Counter
	instOps      metric.Int64Counter
	instDuration metric.Int64Histogram
)

// SetTracerProvider sets the global tracer provider for capability tracing.
// If tp is nil, the global OTel tracer provider is used.
func SetTracerProvider(tp trace.TracerProvider) {
	telMu.Lock()
	defer telMu.Unlock()
	if tp == nil {
		tracerProvider = otel.GetTracerProvider()
		return
	}
	tracerProvider = tp
}

// SetMeterProvider sets the global meter provider for capability metrics.
// If mp is nil, the global OTel meter provider is used.
func SetMeterProvider(mp metric.MeterProvider) {
	telMu.Lock()
	defer telMu.Unlock()
	if mp == nil {
		meterProvider = otel.GetMeterProvider()
		return
	}
	meterProvider = mp
}

// SetNoopTelemetry disables all tracing and metrics by setting
// noop providers for both traces and metrics.
func SetNoopTelemetry() {
	telMu.Lock()
	defer telMu.Unlock()
	tracerProvider = tracenoop.NewTracerProvider()
	meterProvider = noop.NewMeterProvider()
}

func tracer() trace.Tracer {
	telMu.RLock()
	defer telMu.RUnlock()
	return tracerProvider.Tracer("github.com/mishudark/citron/caps")
}

func meter() metric.Meter {
	telMu.RLock()
	defer telMu.RUnlock()
	return meterProvider.Meter("github.com/mishudark/citron/caps")
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

// cachedInstruments returns the request/operation counters bound to the
// current meter, creating them on first use or when the meter changes.
func cachedInstruments() (metric.Int64Counter, metric.Int64Counter, metric.Int64Histogram, bool) {
	m := meter()
	instMu.Lock()
	defer instMu.Unlock()
	if instRequests == nil || instMeter != m {
		reqs, err := m.Int64Counter("caps.requests",
			metric.WithDescription("Total number of capability requests"),
			metric.WithUnit("1"),
		)
		if err != nil {
			return nil, nil, nil, false
		}
		ops, err := m.Int64Counter("caps.operations",
			metric.WithDescription("Total number of capability operations"),
			metric.WithUnit("1"),
		)
		if err != nil {
			return nil, nil, nil, false
		}
		dur, err := m.Int64Histogram("caps.operation_duration_ms",
			metric.WithDescription("Duration of capability operations"),
			metric.WithUnit("ms"),
		)
		if err != nil {
			return nil, nil, nil, false
		}
		instRequests, instOps, instDuration = reqs, ops, dur
		instMeter = m
	}
	return instRequests, instOps, instDuration, true
}

// RecordRequest records a capability request counter.
func RecordRequest(ctx context.Context, capType string) {
	reqs, _, _, ok := cachedInstruments()
	if !ok {
		return
	}
	reqs.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", capType),
	))
}

// RecordOperation records a capability operation outcome: counter and duration.
func RecordOperation(ctx context.Context, operation string, err error) {
	status := "ok"
	if err != nil {
		status = "error"
	}
	_, ops, _, ok := cachedInstruments()
	if !ok {
		return
	}
	ops.Add(ctx, 1, metric.WithAttributes(
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

	_, ops, _, ok := cachedInstruments()
	if !ok {
		return
	}
	ops.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordOperationDuration records the execution duration of a capability
// operation as a histogram, tagged with operation name and status.
func RecordOperationDuration(ctx context.Context, operation string, duration time.Duration, err error) {
	status := "ok"
	if err != nil {
		status = "error"
	}

	_, _, dur, ok := cachedInstruments()
	if !ok {
		return
	}
	dur.Record(ctx, duration.Milliseconds(),
		metric.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("status", status),
		),
	)
}
