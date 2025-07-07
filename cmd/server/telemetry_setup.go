//go:build !test

package main

import (
	"context"
	"log/slog"

	"github.com/plindsay/gopherservice/internal/config"
	"github.com/plindsay/gopherservice/pkg/telemetry"
)

func initTelemetry(logger *slog.Logger, cfg *config.Config) (*telemetry.TracerProvider, *telemetry.MeterProvider) {
	// Initialize OpenTelemetry tracer provider for distributed tracing.
	tp, err := telemetry.NewTracerProvider(cfg.Telemetry.ServiceName, cfg.Telemetry.Endpoint)
	if err != nil {
		logger.Error("failed to initialize tracer provider", slog.Any("error", err))
		return nil, nil
	}
	// Ensure the tracer provider is shut down gracefully on exit.
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			logger.Error("failed to shut down tracer provider", slog.Any("error", err))
		}
	}()

	// Initialize OpenTelemetry meter provider for metrics.
	mp, err := telemetry.NewMeterProvider(cfg.Telemetry.ServiceName, cfg.Telemetry.Endpoint)
	if err != nil {
		logger.Error("failed to initialize meter provider", slog.Any("error", err))
		return nil, nil
	}
	// Ensure the meter provider is shut down gracefully on exit.
	defer func() {
		if err := mp.Shutdown(context.Background()); err != nil {
			logger.Error("failed to shut down meter provider", slog.Any("error", err))
		}
	}()

	return tp, mp
}
