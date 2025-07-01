package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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
	grpcPort = flag.Int("grpc-port", 8080, "The gRPC server port")
	httpPort = flag.Int("http-port", 8081, "The HTTP server port")
)

func main() {
	flag.Parse()

	// Initialize logger
	logger, err := log.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("failed to load configuration", zap.Error(err))
	}

	// Initialize telemetry
	tp, err := telemetry.NewTracerProvider(cfg.Telemetry.ServiceName, cfg.Telemetry.Endpoint)
	if err != nil {
		logger.Fatal("failed to initialize telemetry", zap.Error(err))
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			logger.Error("failed to shut down telemetry provider", zap.Error(err))
		}
	}()

	// Create a context that is canceled on interruption
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Run the gRPC and HTTP servers
	if err := run(ctx, logger, cfg); err != nil {
		logger.Fatal("server error", zap.Error(err))
	}
}

func run(ctx context.Context, logger *zap.Logger, cfg *config.Config) error {
	// Create a new PetStore service
	petStoreService := petstore.NewService(logger)

	// Start the gRPC server
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

	// Start the HTTP server (gRPC-Gateway)
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

	// Wait for the context to be canceled
	<-ctx.Done()

	// Shut down the servers
	logger.Info("shutting down servers")
	grpcServer.GracefulStop()
	if err := httpServer.Shutdown(context.Background()); err != nil {
		logger.Error("HTTP server shutdown failed", zap.Error(err))
	}

	return nil
}