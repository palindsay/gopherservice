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
	"github.com/plindsay/gopherservice/internal/database"
	"github.com/plindsay/gopherservice/internal/log"
	"github.com/plindsay/gopherservice/internal/petstore"
	grpcserver "github.com/plindsay/gopherservice/internal/server/grpc"
	pkgauth "github.com/plindsay/gopherservice/pkg/auth"

	v1 "github.com/plindsay/gopherservice/api/v1"
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

	// Initialize telemetry providers
	tp, mp := initTelemetry(logger, cfg)
	if tp == nil || mp == nil {
		os.Exit(1)
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			logger.Error("failed to shut down tracer provider", slog.Any("error", err))
		}
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
	// Initialize database
	db, err := database.New(cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// JWT Configuration from application config
	jwtSecretKey := cfg.JWT.SecretKey
	accessTokenDuration := time.Duration(cfg.JWT.TokenDuration) * time.Minute
	refreshTokenDuration := time.Duration(cfg.JWT.RefreshDuration) * time.Minute
	jwtIssuer := cfg.Telemetry.ServiceName // Using service name as issuer as before

	// Create service instances
	// authsvc.NewService now takes JWT config directly instead of a jwtManager
	authService := authsvc.NewService(logger, db, jwtSecretKey, accessTokenDuration, refreshTokenDuration, jwtIssuer)
	petStoreService := petstore.NewService(logger)

	// Determine gRPC and HTTP ports, prioritizing environment variables
	grpcPort := cfg.Server.Port
	if pStr := os.Getenv("GRPC_PORT"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil {
			grpcPort = p
		} else {
			logger.Warn("invalid GRPC_PORT environment variable, using default", "value", pStr)
		}
	}

	httpPort := cfg.Server.Port + 1
	if pStr := os.Getenv("HTTP_PORT"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil {
			httpPort = p
		} else {
			logger.Warn("invalid HTTP_PORT environment variable, using default", "value", pStr)
		}
	}

	// Start the gRPC server in a goroutine.
	// grpcserver.New now takes jwtSecret and jwtIssuer directly
	grpcServer, lis, err := grpcserver.New(ctx, logger, grpcPort, petStoreService, authService, jwtSecretKey, jwtIssuer)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}
	go func() {
		logger.Info("starting gRPC server with authentication", slog.Int("port", grpcPort))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("gRPC server failed", slog.Any("error", err))
		}
	}()

	// Start the HTTP server (gRPC-Gateway) in a goroutine.
	// The gRPC-Gateway proxies HTTP requests to the gRPC server with JWT authentication.
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	grpcEndpoint := fmt.Sprintf("localhost:%d", grpcPort)

	// Register both services with the gateway
	if err := v1.RegisterPetStoreServiceHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts); err != nil {
		return fmt.Errorf("failed to register PetStore gRPC-Gateway: %w", err)
	}
	if err := v1.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts); err != nil {
		return fmt.Errorf("failed to register Auth gRPC-Gateway: %w", err)
	}

	// Create JWT manager for HTTP middleware
	jwtManager, err := pkgauth.NewManager(pkgauth.Config{
		SecretKey:            cfg.JWT.SecretKey,
		AccessTokenDuration:  time.Duration(cfg.JWT.TokenDuration) * time.Minute,
		RefreshTokenDuration: time.Duration(cfg.JWT.RefreshDuration) * time.Minute,
		Issuer:               cfg.Telemetry.ServiceName,
		Audience:             []string{"api"},
	}, logger)
	if err != nil {
		return fmt.Errorf("failed to create JWT manager for HTTP: %w", err)
	}

	// Create HTTP middleware for JWT authentication
	httpMiddleware := pkgauth.NewAdvancedHTTPMiddleware(jwtManager, logger)

	// Configure public HTTP paths
	for _, path := range pkgauth.PublicPaths() {
		httpMiddleware.AddPublicPath(path)
	}

	// Configure role-based access control for HTTP paths
	for path, roles := range pkgauth.DefaultHTTPRoleRequirements() {
		httpMiddleware.AddRoleRequirement(path, roles)
	}

	// Configure pattern-based role requirements
	httpMiddleware.AddPathPattern("/v1/users/", []string{"user", "admin"})
	httpMiddleware.AddPathPattern("/v1/pets/", []string{"user", "admin"})
	httpMiddleware.AddPathPattern("/v1/orders/", []string{"user", "admin"})

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", httpPort),
		Handler: httpMiddleware.Handler(mux),
	}

	go func() {
		logger.Info("starting HTTP server with authentication", slog.Int("port", httpPort))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", slog.Any("error", err))
		}
	}()

	// Wait for the context to be canceled (e.g., by an interrupt signal).
	<-ctx.Done()

	// Perform graceful shutdown of both gRPC and HTTP servers.
	logger.Info("shutting down servers")
	grpcServer.GracefulStop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.GracefulShutdownTimeout)*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown failed", slog.Any("error", err))
	}

	return nil
}
