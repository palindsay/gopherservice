// Copyright 2025 Paddy Lindsay
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
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// MetricsHelper provides convenient methods for recording common telemetry metrics
// with best practices for gRPC and HTTP services.
type MetricsHelper struct {
	meter metric.Meter

	// Duration metrics with exponential histograms
	requestDuration      metric.Float64Histogram
	grpcDuration         metric.Float64Histogram
	httpDuration         metric.Float64Histogram
	databaseDuration     metric.Float64Histogram
	externalCallDuration metric.Float64Histogram

	// Counter metrics
	requestCount metric.Int64Counter
	errorCount   metric.Int64Counter
	grpcRequests metric.Int64Counter
	httpRequests metric.Int64Counter

	// Gauge metrics
	activeConnections metric.Int64UpDownCounter
	memoryUsage       metric.Int64Gauge
	cpuUsage          metric.Float64Gauge

	// Payload size metrics
	requestSize  metric.Int64Histogram
	responseSize metric.Int64Histogram
}

// NewMetricsHelper creates a new metrics helper with pre-configured instruments
// for common service metrics following OpenTelemetry best practices.
//
// serviceName should match the service name used in tracer/meter providers.
//
// Example:
//
//	helper, err := telemetry.NewMetricsHelper("my-service")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Record request duration
//	helper.RecordRequestDuration(ctx, 150*time.Millisecond, "GET", "/api/users", "200")
func NewMetricsHelper(serviceName string) (*MetricsHelper, error) {
	meter := otel.Meter(serviceName)

	// Create duration histograms with exponential buckets
	requestDuration, err := meter.Float64Histogram(
		"request_duration",
		metric.WithDescription("Duration of requests"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request_duration histogram: %w", err)
	}

	grpcDuration, err := meter.Float64Histogram(
		"grpc_request_duration",
		metric.WithDescription("Duration of gRPC requests"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc_request_duration histogram: %w", err)
	}

	httpDuration, err := meter.Float64Histogram(
		"http_request_duration",
		metric.WithDescription("Duration of HTTP requests"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create http_request_duration histogram: %w", err)
	}

	databaseDuration, err := meter.Float64Histogram(
		"database_operation_duration",
		metric.WithDescription("Duration of database operations"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create database_operation_duration histogram: %w", err)
	}

	externalCallDuration, err := meter.Float64Histogram(
		"external_call_duration",
		metric.WithDescription("Duration of external service calls"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create external_call_duration histogram: %w", err)
	}

	// Create counter metrics
	requestCount, err := meter.Int64Counter(
		"requests_total",
		metric.WithDescription("Total number of requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create requests_total counter: %w", err)
	}

	errorCount, err := meter.Int64Counter(
		"errors_total",
		metric.WithDescription("Total number of errors"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create errors_total counter: %w", err)
	}

	grpcRequests, err := meter.Int64Counter(
		"grpc_requests_total",
		metric.WithDescription("Total number of gRPC requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc_requests_total counter: %w", err)
	}

	httpRequests, err := meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create http_requests_total counter: %w", err)
	}

	// Create gauge metrics
	activeConnections, err := meter.Int64UpDownCounter(
		"active_connections",
		metric.WithDescription("Number of active connections"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create active_connections gauge: %w", err)
	}

	memoryUsage, err := meter.Int64Gauge(
		"memory_usage_bytes",
		metric.WithDescription("Memory usage in bytes"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory_usage_bytes gauge: %w", err)
	}

	cpuUsage, err := meter.Float64Gauge(
		"cpu_usage_percent",
		metric.WithDescription("CPU usage percentage"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cpu_usage_percent gauge: %w", err)
	}

	// Create payload size histograms
	requestSize, err := meter.Int64Histogram(
		"request_size_bytes",
		metric.WithDescription("Size of request payloads in bytes"),
		metric.WithUnit("byte"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request_size_bytes histogram: %w", err)
	}

	responseSize, err := meter.Int64Histogram(
		"response_size_bytes",
		metric.WithDescription("Size of response payloads in bytes"),
		metric.WithUnit("byte"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create response_size_bytes histogram: %w", err)
	}

	return &MetricsHelper{
		meter:                meter,
		requestDuration:      requestDuration,
		grpcDuration:         grpcDuration,
		httpDuration:         httpDuration,
		databaseDuration:     databaseDuration,
		externalCallDuration: externalCallDuration,
		requestCount:         requestCount,
		errorCount:           errorCount,
		grpcRequests:         grpcRequests,
		httpRequests:         httpRequests,
		activeConnections:    activeConnections,
		memoryUsage:          memoryUsage,
		cpuUsage:             cpuUsage,
		requestSize:          requestSize,
		responseSize:         responseSize,
	}, nil
}

// RecordRequestDuration records the duration of a generic request with common attributes.
func (m *MetricsHelper) RecordRequestDuration(ctx context.Context, duration time.Duration, method, endpoint, statusCode string) {
	m.requestDuration.Record(ctx, duration.Seconds(),
		metric.WithAttributes(
			attribute.String("method", method),
			attribute.String("endpoint", endpoint),
			attribute.String("status_code", statusCode),
		),
	)
}

// RecordGRPCRequest records metrics for a gRPC request including duration, count, and payload sizes.
func (m *MetricsHelper) RecordGRPCRequest(ctx context.Context, duration time.Duration, method, statusCode string, requestBytes, responseBytes int64) {
	attrs := metric.WithAttributes(
		attribute.String("method", method),
		attribute.String("status_code", statusCode),
	)

	// Record duration
	m.grpcDuration.Record(ctx, duration.Seconds(), attrs)

	// Record request count
	m.grpcRequests.Add(ctx, 1, attrs)

	// Record payload sizes if provided
	if requestBytes > 0 {
		m.requestSize.Record(ctx, requestBytes, attrs)
	}
	if responseBytes > 0 {
		m.responseSize.Record(ctx, responseBytes, attrs)
	}
}

// RecordHTTPRequest records metrics for an HTTP request including duration, count, and payload sizes.
func (m *MetricsHelper) RecordHTTPRequest(ctx context.Context, duration time.Duration, method, route, statusCode string, requestBytes, responseBytes int64) {
	attrs := metric.WithAttributes(
		attribute.String("method", method),
		attribute.String("route", route),
		attribute.String("status_code", statusCode),
	)

	// Record duration
	m.httpDuration.Record(ctx, duration.Seconds(), attrs)

	// Record request count
	m.httpRequests.Add(ctx, 1, attrs)

	// Record payload sizes if provided
	if requestBytes > 0 {
		m.requestSize.Record(ctx, requestBytes, attrs)
	}
	if responseBytes > 0 {
		m.responseSize.Record(ctx, responseBytes, attrs)
	}
}

// RecordDatabaseOperation records metrics for database operations.
func (m *MetricsHelper) RecordDatabaseOperation(ctx context.Context, duration time.Duration, operation, table string, success bool) {
	status := "success"
	if !success {
		status = "error"
	}

	m.databaseDuration.Record(ctx, duration.Seconds(),
		metric.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("table", table),
			attribute.String("status", status),
		),
	)
}

// RecordExternalCall records metrics for external service calls.
func (m *MetricsHelper) RecordExternalCall(ctx context.Context, duration time.Duration, service, endpoint, statusCode string) {
	m.externalCallDuration.Record(ctx, duration.Seconds(),
		metric.WithAttributes(
			attribute.String("service", service),
			attribute.String("endpoint", endpoint),
			attribute.String("status_code", statusCode),
		),
	)
}

// RecordError records an error occurrence with categorization.
func (m *MetricsHelper) RecordError(ctx context.Context, errorType, operation string) {
	m.errorCount.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("error_type", errorType),
			attribute.String("operation", operation),
		),
	)
}

// SetActiveConnections updates the active connections gauge.
func (m *MetricsHelper) SetActiveConnections(ctx context.Context, count int64) {
	m.activeConnections.Add(ctx, count)
}

// RecordMemoryUsage records current memory usage.
func (m *MetricsHelper) RecordMemoryUsage(ctx context.Context, bytes int64) {
	m.memoryUsage.Record(ctx, bytes)
}

// RecordCPUUsage records current CPU usage percentage.
func (m *MetricsHelper) RecordCPUUsage(ctx context.Context, percent float64) {
	m.cpuUsage.Record(ctx, percent)
}

// CreateCustomHistogram creates a custom exponential histogram with the specified name and description.
// This is useful for application-specific metrics that don't fit the standard patterns.
func (m *MetricsHelper) CreateCustomHistogram(name, description, unit string) (metric.Float64Histogram, error) {
	return m.meter.Float64Histogram(
		name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
}

// CreateCustomCounter creates a custom counter with the specified name and description.
func (m *MetricsHelper) CreateCustomCounter(name, description string) (metric.Int64Counter, error) {
	return m.meter.Int64Counter(
		name,
		metric.WithDescription(description),
	)
}

// CreateCustomGauge creates a custom gauge with the specified name and description.
func (m *MetricsHelper) CreateCustomGauge(name, description, unit string) (metric.Int64Gauge, error) {
	return m.meter.Int64Gauge(
		name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
}
