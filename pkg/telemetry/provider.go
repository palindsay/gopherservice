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

// Package telemetry provides reusable OpenTelemetry abstractions for distributed tracing and metrics.
//
// This package simplifies the setup and configuration of OpenTelemetry providers,
// making it easy to add observability to Go applications with minimal boilerplate.
// It includes helpers for creating tracer and meter providers, as well as utilities
// for working with exponential histograms and common telemetry patterns.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TracerProvider wraps the OpenTelemetry tracer provider with additional functionality.
type TracerProvider struct {
	*sdktrace.TracerProvider
}

// MeterProvider wraps the OpenTelemetry meter provider with additional functionality.
type MeterProvider struct {
	*sdkmetric.MeterProvider
}

// NewTracerProvider creates and configures a new OpenTelemetry tracer provider for distributed tracing.
//
// serviceName is used to identify the service in traces.
// endpoint is the OTLP collector endpoint (e.g., "localhost:4317").
//
// The provider is configured with:
// - OTLP gRPC exporter for sending traces
// - Batch span processor for efficient export
// - Resource identification with service name and version
// - W3C Trace Context and Baggage propagation
//
// Example:
//
//	tp, err := telemetry.NewTracerProvider("my-service", "localhost:4317")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer tp.Shutdown(context.Background())
func NewTracerProvider(serviceName, endpoint string) (*TracerProvider, error) {
	ctx := context.Background()

	// Create OTLP trace exporter
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create resource with service identification
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider with batch span processor
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		// Sample all traces in development, adjust for production
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)

	// Set global propagator for W3C Trace Context and Baggage
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &TracerProvider{TracerProvider: tp}, nil
}

// NewMeterProvider creates and configures a new OpenTelemetry meter provider for metrics collection.
//
// serviceName is used to identify the service in metrics.
// endpoint is the OTLP collector endpoint (e.g., "localhost:4317").
//
// The provider is configured with:
// - OTLP gRPC exporter for sending metrics
// - Delta temporality for efficient metric aggregation
// - Exponential histogram aggregation for latency metrics
// - Resource identification with service name and version
//
// Example:
//
//	mp, err := telemetry.NewMeterProvider("my-service", "localhost:4317")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer mp.Shutdown(context.Background())
func NewMeterProvider(serviceName, endpoint string) (*MeterProvider, error) {
	ctx := context.Background()

	// Create OTLP metric exporter
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	exporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create metric exporter: %w", err)
	}

	// Create resource with service identification
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create meter provider with periodic reader
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			exporter,
			sdkmetric.WithInterval(10*time.Second), // Export metrics every 10 seconds
		)),
		sdkmetric.WithResource(res),
		// Use delta temporality for efficient aggregation
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Name: "*"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationBase2ExponentialHistogram{
				MaxSize:  4096, // Maximum number of buckets
				MaxScale: 20,   // Maximum scale factor
			}},
		)),
	)

	// Set global meter provider
	otel.SetMeterProvider(mp)

	return &MeterProvider{MeterProvider: mp}, nil
}

// Tracer returns a tracer for the given name and options.
// This is a convenience method that wraps otel.Tracer().
func (tp *TracerProvider) Tracer(name string, options ...trace.TracerOption) trace.Tracer {
	return tp.TracerProvider.Tracer(name, options...)
}

// Meter returns a meter for the given name and options.
// This is a convenience method that wraps otel.Meter().
func (mp *MeterProvider) Meter(name string, options ...metric.MeterOption) metric.Meter {
	return mp.MeterProvider.Meter(name, options...)
}
