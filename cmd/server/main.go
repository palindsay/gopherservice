package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authsvc "github.com/plindsay/gopherservice/internal/auth"
	"github.com/plindsay/gopherservice/internal/config"
	"github.com/plindsay/gopherservice/internal/log"
	"github.com/plindsay/gopherservice/internal/petstore"
	grpcserver "github.com/plindsay/gopherservice/internal/server/grpc"
	"github.com/plindsay/gopherservice/pkg/auth"
	"github.com/plindsay/gopherservice/pkg/telemetry"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

var (
	grpcPort = flag.Int("grpc-port", getEnvAsInt("GRPC_PORT", 8080), "The gRPC server port")
	httpPort = flag.Int("http-port", getEnvAsInt("HTTP_PORT", 8081), "The HTTP server port")
)

// main is the entry point of the gopherservice application.
func main() {
	flag.Parse()

	// Initialize logger for structured logging using Go's native slog.
	logger := log.New()

	// Load application configuration from config.yaml.
	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	// Initialize OpenTelemetry tracer provider for distributed tracing.
	tp, err := telemetry.NewTracerProvider(cfg.Telemetry.ServiceName, cfg.Telemetry.Endpoint)
	if err != nil {
		logger.Error("failed to initialize tracer provider", slog.Any("error", err))
		os.Exit(1)
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
		os.Exit(1)
	}
	// Ensure the meter provider is shut down gracefully on exit.
	defer func() {
		if err := mp.Shutdown(context.Background()); err != nil {
			logger.Error("failed to shut down meter provider", slog.Any("error", err))
		}
	}()

	// Create a context that is canceled when an interrupt signal (e.g., Ctrl+C) is received.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Run the gRPC and HTTP servers. This function blocks until the context is canceled.
	if err := run(ctx, logger, cfg); err != nil {
		logger.Error("server error", slog.Any("error", err))
		os.Exit(1)
	}
}

// run starts and manages the gRPC and HTTP servers with authentication.
// It takes a context for graceful shutdown, a logger for logging, and the application configuration.
// It returns an error if any server fails to start or encounters a critical issue.
func run(ctx context.Context, logger *slog.Logger, cfg *config.Config) error {
	// Initialize JWT manager
	secretKey := getEnvAsString("JWT_SECRET", "your-super-secret-jwt-key-change-in-production-32chars")
	jwtManager := auth.NewJWTManager(
		secretKey,
		15*time.Minute, // Access token duration
		7*24*time.Hour, // Refresh token duration
		cfg.Telemetry.ServiceName,
		logger,
	)

	// Create service instances
	authService := authsvc.NewService(logger, jwtManager)
	petStoreService := petstore.NewService(logger)

	// Start the gRPC server in a goroutine.
	grpcServer, lis, err := grpcserver.New(ctx, logger, *grpcPort, petStoreService, authService, jwtManager)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}
	go func() {
		logger.Info("starting gRPC server with authentication", slog.Int("port", *grpcPort))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("gRPC server failed", slog.Any("error", err))
		}
	}()

	// Start the HTTP server (gRPC-Gateway) in a goroutine.
	// The gRPC-Gateway proxies HTTP requests to the gRPC server.
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	grpcEndpoint := fmt.Sprintf("localhost:%d", *grpcPort)

	// Register both services with the gateway
	if err := v1.RegisterPetStoreServiceHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts); err != nil {
		return fmt.Errorf("failed to register PetStore gRPC-Gateway: %w", err)
	}
	if err := v1.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts); err != nil {
		return fmt.Errorf("failed to register Auth gRPC-Gateway: %w", err)
	}

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *httpPort),
		Handler: mux,
	}

	go func() {
		logger.Info("starting HTTP server with authentication", slog.Int("port", *httpPort))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", slog.Any("error", err))
		}
	}()

	// Wait for the context to be canceled (e.g., by an interrupt signal).
	<-ctx.Done()

	// Perform graceful shutdown of both gRPC and HTTP servers.
	logger.Info("shutting down servers")
	grpcServer.GracefulStop()
	if err := httpServer.Shutdown(context.Background()); err != nil {
		logger.Error("HTTP server shutdown failed", slog.Any("error", err))
	}

	return nil
}

// getEnvAsInt retrieves an environment variable as an integer.
// It takes the environment variable name and a default value.
// If the environment variable is not set or cannot be parsed as an integer, the default value is returned.
func getEnvAsInt(name string, defaultValue int) int {
	if valueStr, ok := os.LookupEnv(name); ok {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}

// getEnvAsString retrieves an environment variable as a string.
// It takes the environment variable name and a default value.
// If the environment variable is not set, the default value is returned.
func getEnvAsString(name string, defaultValue string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return defaultValue
}
