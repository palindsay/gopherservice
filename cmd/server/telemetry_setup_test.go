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

//go:build test

package main

import (
	"log/slog"

	"github.com/plindsay/gopherservice/internal/config"
	"github.com/plindsay/gopherservice/pkg/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// initTelemetry initializes mock telemetry providers for testing
func initTelemetry(logger *slog.Logger, cfg *config.Config) (*telemetry.TracerProvider, *telemetry.MeterProvider) {
	// Create no-op providers for testing
	tp := &telemetry.TracerProvider{
		TracerProvider: sdktrace.NewTracerProvider(),
	}

	mp := &telemetry.MeterProvider{
		MeterProvider: sdkmetric.NewMeterProvider(),
	}

	return tp, mp
}
