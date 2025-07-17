// Copyright 2025 Phillip Lindsay
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracingHelper provides convenient methods for creating and managing spans
// with consistent attributes and error handling.
type TracingHelper struct {
	tracer trace.Tracer
}

// NewTracingHelper creates a new tracing helper for the given service.
//
// Example:
//
//	helper := telemetry.NewTracingHelper("my-service")
//	ctx, span := helper.StartSpan(ctx, "operation-name")
//	defer span.End()
func NewTracingHelper(serviceName string) *TracingHelper {
	tracer := otel.Tracer(serviceName)
	return &TracingHelper{tracer: tracer}
}

// StartSpan starts a new span with the given name and returns the context and span.
// The span should be ended by calling span.End() when the operation completes.
func (t *TracingHelper) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, opts...)
}

// StartGRPCServerSpan starts a span for a gRPC server operation with standard attributes.
func (t *TracingHelper) StartGRPCServerSpan(ctx context.Context, method string) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, method,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("rpc.system", "grpc"),
			attribute.String("rpc.method", method),
		),
	)
	return ctx, span
}

// StartGRPCClientSpan starts a span for a gRPC client operation with standard attributes.
func (t *TracingHelper) StartGRPCClientSpan(ctx context.Context, method, target string) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, method,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("rpc.system", "grpc"),
			attribute.String("rpc.method", method),
			attribute.String("rpc.service", target),
		),
	)
	return ctx, span
}

// StartHTTPServerSpan starts a span for an HTTP server operation with standard attributes.
func (t *TracingHelper) StartHTTPServerSpan(ctx context.Context, method, route string) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, fmt.Sprintf("%s %s", method, route),
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("http.method", method),
			attribute.String("http.route", route),
		),
	)
	return ctx, span
}

// StartHTTPClientSpan starts a span for an HTTP client operation with standard attributes.
func (t *TracingHelper) StartHTTPClientSpan(ctx context.Context, method, url string) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, fmt.Sprintf("%s %s", method, url),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.method", method),
			attribute.String("http.url", url),
		),
	)
	return ctx, span
}

// StartDatabaseSpan starts a span for a database operation with standard attributes.
func (t *TracingHelper) StartDatabaseSpan(ctx context.Context, operation, table, system string) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, fmt.Sprintf("%s %s", operation, table),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", system),
			attribute.String("db.operation", operation),
			attribute.String("db.sql.table", table),
		),
	)
	return ctx, span
}

// RecordError records an error on the current span and sets the span status.
// This is a convenience method that should be called when an error occurs.
func RecordError(span trace.Span, err error, description string) {
	if err == nil {
		return
	}

	span.RecordError(err)
	span.SetStatus(codes.Error, description)
	span.SetAttributes(
		attribute.String("error.type", fmt.Sprintf("%T", err)),
		attribute.String("error.message", err.Error()),
	)
}

// SetSpanAttributes sets multiple attributes on a span at once.
// This is useful for adding custom business logic attributes to spans.
func SetSpanAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(attrs...)
}

// AddSpanEvent adds an event to the span with optional attributes.
// Events are useful for marking significant moments during span execution.
func AddSpanEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SpanFromContext extracts the current span from the context.
// Returns a non-recording span if no span is found.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// TraceIDFromContext extracts the trace ID from the current span in the context.
// Returns an empty string if no trace is active.
func TraceIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// SpanIDFromContext extracts the span ID from the current span in the context.
// Returns an empty string if no span is active.
func SpanIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// WithSpanAttributes creates a new span with the given attributes.
// This is a convenience function for creating spans with initial attributes.
func (t *TracingHelper) WithSpanAttributes(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// RecordGRPCStatus records gRPC-specific status information on the span.
func RecordGRPCStatus(span trace.Span, code int, message string) {
	span.SetAttributes(
		attribute.Int("rpc.grpc.status_code", code),
		attribute.String("rpc.grpc.status_message", message),
	)

	// Set span status based on gRPC status code
	if code != 0 { // gRPC OK is 0
		span.SetStatus(codes.Error, message)
	} else {
		span.SetStatus(codes.Ok, "")
	}
}

// RecordHTTPStatus records HTTP-specific status information on the span.
func RecordHTTPStatus(span trace.Span, statusCode int, statusText string) {
	span.SetAttributes(
		attribute.Int("http.status_code", statusCode),
		attribute.String("http.status_text", statusText),
	)

	// Set span status based on HTTP status code
	if statusCode >= 400 {
		span.SetStatus(codes.Error, statusText)
	} else {
		span.SetStatus(codes.Ok, "")
	}
}

// RecordPayloadSizes records request and response payload sizes on the span.
func RecordPayloadSizes(span trace.Span, requestBytes, responseBytes int64) {
	if requestBytes > 0 {
		span.SetAttributes(attribute.Int64("request.size", requestBytes))
	}
	if responseBytes > 0 {
		span.SetAttributes(attribute.Int64("response.size", responseBytes))
	}
}
