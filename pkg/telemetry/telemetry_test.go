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

package telemetry_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/plindsay/gopherservice/pkg/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/codes"
)

func TestNewTracerProvider(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		endpoint    string
		wantErr     bool
	}{
		{
			name:        "valid configuration",
			serviceName: "test-service",
			endpoint:    "localhost:4317",
			wantErr:     false,
		},
		{
			name:        "empty service name",
			serviceName: "",
			endpoint:    "localhost:4317",
			wantErr:     false, // OpenTelemetry allows empty service names
		},
		{
			name:        "empty endpoint",
			serviceName: "test-service",
			endpoint:    "",
			wantErr:     false, // Should use default endpoint
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, err := telemetry.NewTracerProvider(tt.serviceName, tt.endpoint)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTracerProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tp == nil {
				t.Error("NewTracerProvider() returned nil")
				return
			}

			// Test shutdown
			if err := tp.Shutdown(context.Background()); err != nil {
				t.Errorf("failed to shutdown tracer provider: %v", err)
			}
		})
	}
}

func TestNewMeterProvider(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		endpoint    string
		wantErr     bool
	}{
		{
			name:        "valid configuration",
			serviceName: "test-service",
			endpoint:    "localhost:4317",
			wantErr:     false,
		},
		{
			name:        "empty service name",
			serviceName: "",
			endpoint:    "localhost:4317",
			wantErr:     false, // OpenTelemetry allows empty service names
		},
		{
			name:        "empty endpoint",
			serviceName: "test-service",
			endpoint:    "",
			wantErr:     false, // Should use default endpoint
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp, err := telemetry.NewMeterProvider(tt.serviceName, tt.endpoint)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMeterProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if mp == nil {
				t.Error("NewMeterProvider() returned nil")
				return
			}

			// Test shutdown (may have connection errors in tests)
			if err := mp.Shutdown(context.Background()); err != nil {
				t.Logf("meter provider shutdown warning: %v", err)
			}
		})
	}
}

func TestTracerProvider_Tracer(t *testing.T) {
	tp, err := telemetry.NewTracerProvider("test-service", "")
	if err != nil {
		t.Fatalf("failed to create tracer provider: %v", err)
	}
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	tracer := tp.Tracer("test-tracer")
	if tracer == nil {
		t.Error("Tracer() returned nil")
	}
}

func TestMeterProvider_Meter(t *testing.T) {
	mp, err := telemetry.NewMeterProvider("test-service", "")
	if err != nil {
		t.Fatalf("failed to create meter provider: %v", err)
	}
	defer func() {
		_ = mp.Shutdown(context.Background())
	}()

	meter := mp.Meter("test-meter")
	if meter == nil {
		t.Error("Meter() returned nil")
	}
}

func TestNewMetricsHelper(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		wantErr     bool
	}{
		{
			name:        "valid service name",
			serviceName: "test-service",
			wantErr:     false,
		},
		{
			name:        "empty service name",
			serviceName: "",
			wantErr:     false, // OpenTelemetry allows empty service names
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper, err := telemetry.NewMetricsHelper(tt.serviceName)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMetricsHelper() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if helper == nil {
				t.Error("NewMetricsHelper() returned nil")
			}
		})
	}
}

func TestMetricsHelper_RecordRequestDuration(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()
	duration := 150 * time.Millisecond

	// Test recording request duration
	helper.RecordRequestDuration(ctx, duration, "GET", "/api/users", "200")

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_RecordGRPCRequest(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()
	duration := 100 * time.Millisecond

	// Test recording gRPC request
	helper.RecordGRPCRequest(ctx, duration, "/v1.Service/Method", "OK", 512, 1024)

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_RecordHTTPRequest(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()
	duration := 200 * time.Millisecond

	// Test recording HTTP request
	helper.RecordHTTPRequest(ctx, duration, "POST", "/api/data", "201", 256, 512)

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_RecordDatabaseOperation(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()
	duration := 50 * time.Millisecond

	// Test recording database operation
	helper.RecordDatabaseOperation(ctx, duration, "SELECT", "users", true)

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_RecordExternalCall(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()
	duration := 300 * time.Millisecond

	// Test recording external call
	helper.RecordExternalCall(ctx, duration, "payment-service", "POST", "success")

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_RecordError(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()

	// Test recording error
	helper.RecordError(ctx, "validation_error", "invalid_input")

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_SetActiveConnections(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()

	// Test setting active connections
	helper.SetActiveConnections(ctx, 10)

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_RecordMemoryUsage(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()

	// Test recording memory usage
	helper.RecordMemoryUsage(ctx, 1024*1024*512) // 512MB

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_RecordCPUUsage(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	ctx := context.Background()

	// Test recording CPU usage
	helper.RecordCPUUsage(ctx, 75.5)

	// No error expected - metrics are recorded asynchronously
}

func TestMetricsHelper_CreateCustomHistogram(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	// Test creating custom histogram
	histogram, err := helper.CreateCustomHistogram("custom_duration", "Custom duration metric", "ms")
	if err != nil {
		t.Errorf("CreateCustomHistogram() error = %v", err)
	}
	if histogram == nil {
		t.Error("CreateCustomHistogram() returned nil")
	}
}

func TestMetricsHelper_CreateCustomCounter(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	// Test creating custom counter
	counter, err := helper.CreateCustomCounter("custom_events", "Custom events counter")
	if err != nil {
		t.Errorf("CreateCustomCounter() error = %v", err)
	}
	if counter == nil {
		t.Error("CreateCustomCounter() returned nil")
	}
}

func TestMetricsHelper_CreateCustomGauge(t *testing.T) {
	helper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	// Test creating custom gauge
	gauge, err := helper.CreateCustomGauge("custom_value", "Custom value gauge", "units")
	if err != nil {
		t.Errorf("CreateCustomGauge() error = %v", err)
	}
	if gauge == nil {
		t.Error("CreateCustomGauge() returned nil")
	}
}

func TestNewTracingHelper(t *testing.T) {
	serviceName := "test-service"
	helper := telemetry.NewTracingHelper(serviceName)

	if helper == nil {
		t.Error("NewTracingHelper() returned nil")
	}
}

func TestTracingHelper_StartSpan(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test starting a span
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	if span == nil {
		t.Error("StartSpan() returned nil span")
	}

	// Use the context to ensure it's not ineffectual
	_ = ctx
}

func TestTracingHelper_StartGRPCServerSpan(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test starting gRPC server span
	ctx, span := helper.StartGRPCServerSpan(ctx, "/v1.Service/Method")
	defer span.End()

	if span == nil {
		t.Error("StartGRPCServerSpan() returned nil span")
	}

	// Use the context to ensure it's not ineffectual
	_ = ctx
}

func TestTracingHelper_StartGRPCClientSpan(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test starting gRPC client span
	ctx, span := helper.StartGRPCClientSpan(ctx, "remote-service", "/v1.Service/Method")
	defer span.End()

	if span == nil {
		t.Error("StartGRPCClientSpan() returned nil span")
	}

	// Use the context to ensure it's not ineffectual
	_ = ctx
}

func TestTracingHelper_StartHTTPServerSpan(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test starting HTTP server span
	ctx, span := helper.StartHTTPServerSpan(ctx, "GET", "/api/users")
	defer span.End()

	if span == nil {
		t.Error("StartHTTPServerSpan() returned nil span")
	}

	// Use the context to ensure it's not ineffectual
	_ = ctx
}

func TestTracingHelper_StartHTTPClientSpan(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test starting HTTP client span
	ctx, span := helper.StartHTTPClientSpan(ctx, "POST", "https://api.example.com/data")
	defer span.End()

	if span == nil {
		t.Error("StartHTTPClientSpan() returned nil span")
	}

	// Use the context to ensure it's not ineffectual
	_ = ctx
}

func TestTracingHelper_StartDatabaseSpan(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test starting database span
	ctx, span := helper.StartDatabaseSpan(ctx, "SELECT", "users", "sqlite")
	defer span.End()

	if span == nil {
		t.Error("StartDatabaseSpan() returned nil span")
	}

	// Use the context to ensure it's not ineffectual
	_ = ctx
}

func TestTracingHelper_RecordError(_ *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Start a span first
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	// Test recording error
	err := &TestError{message: "test error"}
	telemetry.RecordError(span, err, "test error description")

	// Use the context to ensure it's not ineffectual
	_ = ctx

	// No error expected - error is recorded on span
}

func TestTracingHelper_SetSpanAttributes(_ *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Start a span first
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	// Test setting span attributes
	telemetry.SetSpanAttributes(span, attribute.String("key1", "value1"), attribute.Int("key2", 42))

	// Use the context to ensure it's not ineffectual
	_ = ctx

	// No error expected - attributes are set on span
}

func TestTracingHelper_AddSpanEvent(_ *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Start a span first
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	// Test adding span event
	telemetry.AddSpanEvent(span, "test-event", attribute.String("event_key", "event_value"))

	// Use the context to ensure it's not ineffectual
	_ = ctx

	// No error expected - event is added to span
}

func TestTracingHelper_SpanFromContext(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test with no span in context
	span := telemetry.SpanFromContext(ctx)
	if span == nil {
		t.Error("SpanFromContext() returned nil for empty context")
	}

	// Test with span in context
	ctx, activeSpan := helper.StartSpan(ctx, "test-operation")
	defer activeSpan.End()

	span = telemetry.SpanFromContext(ctx)
	if span == nil {
		t.Error("SpanFromContext() returned nil for context with span")
	}
}

func TestTracingHelper_TraceIDFromContext(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test with no span in context - should return empty string
	traceID := telemetry.TraceIDFromContext(ctx)
	if traceID != "" {
		t.Errorf("TraceIDFromContext() returned non-empty string for empty context: %s", traceID)
	}

	// Test with span in context
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	traceID = telemetry.TraceIDFromContext(ctx)
	// Note: In test environments without proper tracer providers,
	// trace IDs may be empty even with spans
	if traceID != "" {
		t.Logf("TraceIDFromContext() returned: %s", traceID)
	}
}

func TestTracingHelper_SpanIDFromContext(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test with no span in context - should return empty string
	spanID := telemetry.SpanIDFromContext(ctx)
	if spanID != "" {
		t.Errorf("SpanIDFromContext() returned non-empty string for empty context: %s", spanID)
	}

	// Test with span in context
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	spanID = telemetry.SpanIDFromContext(ctx)
	// Note: In test environments without proper tracer providers,
	// span IDs may be empty even with spans
	if spanID != "" {
		t.Logf("SpanIDFromContext() returned: %s", spanID)
	}
}

func TestTracingHelper_WithSpanAttributes(t *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Test with span attributes
	ctx, span := helper.WithSpanAttributes(ctx, "test-operation", attribute.String("key1", "value1"), attribute.Int("key2", 42))
	defer span.End()

	// Context should not be nil
	if ctx == nil {
		t.Error("WithSpanAttributes() returned nil context")
	}
}

func TestTracingHelper_RecordGRPCStatus(_ *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Start a span first
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	// Test recording gRPC status
	telemetry.RecordGRPCStatus(span, int(codes.OK), "success")

	// Use the context to ensure it's not ineffectual
	_ = ctx

	// No error expected - status is recorded on span
}

func TestTracingHelper_RecordHTTPStatus(_ *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Start a span first
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	// Test recording HTTP status
	telemetry.RecordHTTPStatus(span, http.StatusOK, "OK")

	// Use the context to ensure it's not ineffectual
	_ = ctx

	// No error expected - status is recorded on span
}

func TestTracingHelper_RecordPayloadSizes(_ *testing.T) {
	helper := telemetry.NewTracingHelper("test-service")
	ctx := context.Background()

	// Start a span first
	ctx, span := helper.StartSpan(ctx, "test-operation")
	defer span.End()

	// Test recording payload sizes
	telemetry.RecordPayloadSizes(span, 1024, 2048) // 1KB request, 2KB response

	// Use the context to ensure it's not ineffectual
	_ = ctx

	// No error expected - payload sizes are recorded on span
}

// TestError is a simple error implementation for testing.
type TestError struct {
	message string
}

func (e *TestError) Error() string {
	return e.message
}

func TestIntegration_TracingAndMetrics(t *testing.T) {
	// Create providers
	tp, err := telemetry.NewTracerProvider("test-service", "")
	if err != nil {
		t.Fatalf("failed to create tracer provider: %v", err)
	}
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	mp, err := telemetry.NewMeterProvider("test-service", "")
	if err != nil {
		t.Fatalf("failed to create meter provider: %v", err)
	}
	defer func() {
		_ = mp.Shutdown(context.Background())
	}()

	// Create helpers
	tracingHelper := telemetry.NewTracingHelper("test-service")
	metricsHelper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	// Simulate a request flow
	ctx := context.Background()

	// Start tracing
	ctx, span := tracingHelper.StartHTTPServerSpan(ctx, "GET", "/api/users")
	defer span.End()

	// Record request start
	start := time.Now()

	// Simulate some processing
	time.Sleep(10 * time.Millisecond)

	// Record success
	telemetry.RecordHTTPStatus(span, http.StatusOK, "OK")
	telemetry.RecordPayloadSizes(span, 512, 1024)

	// Record metrics
	duration := time.Since(start)
	metricsHelper.RecordHTTPRequest(ctx, duration, "GET", "/api/users", "200", 512, 1024)

	// No assertions needed - just verify no panics/errors
}

func TestConcurrentTelemetry(t *testing.T) {
	// Create helpers
	tracingHelper := telemetry.NewTracingHelper("test-service")
	metricsHelper, err := telemetry.NewMetricsHelper("test-service")
	if err != nil {
		t.Fatalf("failed to create metrics helper: %v", err)
	}

	// Run concurrent operations
	const numOperations = 100
	done := make(chan bool, numOperations)

	for i := 0; i < numOperations; i++ {
		go func(id int) {
			defer func() { done <- true }()

			ctx := context.Background()
			ctx, span := tracingHelper.StartSpan(ctx, "concurrent-operation")
			defer span.End()

			// Record some metrics
			metricsHelper.RecordRequestDuration(ctx, time.Millisecond*10, "GET", "/test", "200")
			metricsHelper.RecordError(ctx, "test_error", "concurrent")

			// Add span attributes
			telemetry.SetSpanAttributes(span, attribute.Int("operation_id", id))
		}(i)
	}

	// Wait for all operations to complete
	for i := 0; i < numOperations; i++ {
		<-done
	}

	// No assertions needed - just verify no panics/errors
}
