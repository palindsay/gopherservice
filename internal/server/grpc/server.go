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

// Package grpc provides gRPC server implementation with authentication, telemetry,
// and service registration. It includes middleware for logging, authentication,
// and request/response tracing, along with health checks and reflection services.
package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	v1 "github.com/plindsay/gopherservice/api/v1"
	authsvc "github.com/plindsay/gopherservice/internal/auth"
	"github.com/plindsay/gopherservice/internal/petstore"
	"github.com/plindsay/gopherservice/pkg/auth"
)

// New creates a new gRPC server instance and a listener with authentication.
// It takes a context, a logger, the port to listen on, and the service implementations.
// It returns the gRPC server, the network listener, and an error if the listener cannot be created.
func New(_ context.Context, logger *slog.Logger, port int, petStoreService *petstore.Service, authService *authsvc.Service, jwtManager *auth.JWTManager) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen: %w", err)
	}

	// Create authentication interceptor
	authInterceptor := auth.NewInterceptor(jwtManager, logger)

	// Configure public methods (no authentication required)
	authInterceptor.AddPublicMethod("/v1.AuthService/RegisterUser")
	authInterceptor.AddPublicMethod("/v1.AuthService/Login")
	authInterceptor.AddPublicMethod("/v1.AuthService/ValidateToken")
	authInterceptor.AddPublicMethod("/v1.AuthService/DebugCreateUserAndToken")
	authInterceptor.AddPublicMethod("/grpc.health.v1.Health/Check")

	// Configure role-based access control
	authInterceptor.AddRoleRequirement("/v1.AuthService/ListUsers", []string{"admin"})
	authInterceptor.AddRoleRequirement("/v1.PetStoreService/CreatePet", []string{"user", "admin"})
	authInterceptor.AddRoleRequirement("/v1.PetStoreService/GetPet", []string{"user", "admin"})
	authInterceptor.AddRoleRequirement("/v1.PetStoreService/PlaceOrder", []string{"user", "admin"})
	authInterceptor.AddRoleRequirement("/v1.PetStoreService/GetOrder", []string{"user", "admin"})

	// Production-ready server options with authentication
	opts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			authInterceptor.Unary(),
			loggingInterceptor(logger),
		),
		grpc.ChainStreamInterceptor(
			authInterceptor.Stream(),
		),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Second,
			MaxConnectionAge:      30 * time.Second,
			MaxConnectionAgeGrace: 5 * time.Second,
			Time:                  5 * time.Second,
			Timeout:               1 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	s := grpc.NewServer(opts...)

	// Register services
	v1.RegisterPetStoreServiceServer(s, petStoreService)
	v1.RegisterAuthServiceServer(s, authService)

	// Register health check service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("v1.PetStoreService", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("v1.AuthService", grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable gRPC reflection for development and debugging
	reflection.Register(s)

	return s, lis, nil
}

// loggingInterceptor creates a gRPC unary interceptor that logs incoming requests.
// It logs the method name, request duration, response code, and any errors.
// For successful requests, it logs at INFO level. For failed requests, it logs at ERROR level.
func loggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		if err != nil {
			code := status.Code(err)
			logger.Error("gRPC request failed",
				slog.String("method", info.FullMethod),
				slog.Duration("duration", duration),
				slog.String("code", code.String()),
				slog.Any("error", err),
			)
		} else {
			logger.Info("gRPC request completed",
				slog.String("method", info.FullMethod),
				slog.Duration("duration", duration),
				slog.String("code", codes.OK.String()),
			)
		}

		return resp, err
	}
}
