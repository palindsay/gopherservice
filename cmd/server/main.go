package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/plindsay/gopherservice/internal/config"
	"github.com/plindsay/gopherservice/internal/log"
	"github.com/plindsay/gopherservice/internal/petstore"
	grpcserver "github.com/plindsay/gopherservice/internal/server/grpc"
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

	// Initialize logger for structured logging.
	logger, err := log.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	// Ensure all buffered log entries are flushed before exiting.
	defer func() {
		_ = logger.Sync()
	}()

	// Load application configuration from config.yaml.
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("failed to load configuration", zap.Error(err))
	}

	// Initialize OpenTelemetry tracer provider for distributed tracing.
	tp, err := telemetry.NewTracerProvider(cfg.Telemetry.ServiceName, cfg.Telemetry.Endpoint)
	if err != nil {
		logger.Fatal("failed to initialize tracer provider", zap.Error(err))
	}
	// Ensure the tracer provider is shut down gracefully on exit.
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			logger.Error("failed to shut down tracer provider", zap.Error(err))
		}
	}()

	// Initialize OpenTelemetry meter provider for metrics.
	mp, err := telemetry.NewMeterProvider(cfg.Telemetry.ServiceName, cfg.Telemetry.Endpoint)
	if err != nil {
		logger.Fatal("failed to initialize meter provider", zap.Error(err))
	}
	// Ensure the meter provider is shut down gracefully on exit.
	defer func() {
		if err := mp.Shutdown(context.Background()); err != nil {
			logger.Error("failed to shut down meter provider", zap.Error(err))
		}
	}()

	// Create a context that is canceled when an interrupt signal (e.g., Ctrl+C) is received.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Run the gRPC and HTTP servers. This function blocks until the context is canceled.
	if err := run(ctx, logger, cfg); err != nil {
		logger.Fatal("server error", zap.Error(err))
	}
}

// run starts and manages the gRPC and HTTP servers.
// It takes a context for graceful shutdown, a logger for logging, and the application configuration.
// It returns an error if any server fails to start or encounters a critical issue.
func run(ctx context.Context, logger *zap.Logger, _ *config.Config) error {
	// Create a new PetStore service instance.
	petStoreService := petstore.NewService(logger)

	// Start the gRPC server in a goroutine.
	grpcServer, lis, err := grpcserver.New(ctx, logger, *grpcPort, petStoreService)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}
	go func() {
		logger.Info("starting gRPC server", zap.Int("port", *grpcPort))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("gRPC server failed", zap.Error(err))
		}
	}()

	// Start the HTTP server (gRPC-Gateway) in a goroutine.
	// The gRPC-Gateway proxies HTTP requests to the gRPC server.
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	grpcEndpoint := fmt.Sprintf("localhost:%d", *grpcPort)
	if err := v1.RegisterPetStoreServiceHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts); err != nil {
		return fmt.Errorf("failed to register gRPC-Gateway: %w", err)
	}

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *httpPort),
		Handler: mux,
	}

	go func() {
		logger.Info("starting HTTP server", zap.Int("port", *httpPort))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", zap.Error(err))
		}
	}()

	// Wait for the context to be canceled (e.g., by an interrupt signal).
	<-ctx.Done()

	// Perform graceful shutdown of both gRPC and HTTP servers.
	logger.Info("shutting down servers")
	grpcServer.GracefulStop()
	if err := httpServer.Shutdown(context.Background()); err != nil {
		logger.Error("HTTP server shutdown failed", zap.Error(err))
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
