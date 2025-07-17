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

//go:build !test

package main

import (
	"log/slog"

	"github.com/plindsay/gopherservice/internal/config"
	"github.com/plindsay/gopherservice/pkg/telemetry"
)

// initTelemetry initializes OpenTelemetry tracing and metrics providers for the server.
// It creates both a tracer provider for distributed tracing and a meter provider for metrics collection.
// The function configures the providers with the service name and endpoint from the configuration.
// Returns the initialized tracer and meter providers, or nil if initialization fails.
func initTelemetry(logger *slog.Logger, cfg *config.Config) (*telemetry.TracerProvider, *telemetry.MeterProvider) {
	// Initialize OpenTelemetry tracer provider for distributed tracing.
	tp, err := telemetry.NewTracerProvider(cfg.Telemetry.ServiceName, cfg.Telemetry.Endpoint)
	if err != nil {
		logger.Error("failed to initialize tracer provider", slog.Any("error", err))
		return nil, nil
	}

	// Initialize OpenTelemetry meter provider for metrics.
	mp, err := telemetry.NewMeterProvider(cfg.Telemetry.ServiceName, cfg.Telemetry.Endpoint)
	if err != nil {
		logger.Error("failed to initialize meter provider", slog.Any("error", err))
		return nil, nil
	}

	return tp, mp
}
