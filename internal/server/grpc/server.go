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
	"github.com/plindsay/gopherservice/internal/auth"
	"github.com/plindsay/gopherservice/internal/petstore"
	pkgauth "github.com/plindsay/gopherservice/pkg/auth"
)

// createJWTManager creates a JWT manager from the provided configuration.
func createJWTManager(jwtSecret, jwtIssuer string, logger *slog.Logger) (*pkgauth.Manager, error) {
	return pkgauth.NewManager(pkgauth.Config{
		SecretKey:            jwtSecret,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		Issuer:               jwtIssuer,
		Audience:             []string{"api"},
	}, logger)
}

// loggingInterceptor creates a gRPC unary interceptor that logs requests.
func loggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		code := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				code = st.Code()
			}
		}

		logger.Info("gRPC request completed",
			slog.String("method", info.FullMethod),
			slog.Int64("duration", duration.Microseconds()),
			slog.String("code", code.String()))

		return resp, err
	}
}

// New creates a new gRPC server instance and a listener with JWT authentication.
// It takes a context, a logger, the port to listen on, and the service implementations.
// It returns the gRPC server, the network listener, and an error if the listener cannot be created.
func New(_ context.Context, logger *slog.Logger, port int, petStoreService *petstore.Service, authService *auth.Service, jwtSecret, jwtIssuer string) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen: %w", err)
	}

	// Create JWT manager
	jwtManager, err := createJWTManager(jwtSecret, jwtIssuer, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create JWT manager: %w", err)
	}

	// Create authentication interceptor
	authInterceptor := pkgauth.NewInterceptor(jwtManager, logger)

	// Configure public methods (no authentication required)
	for _, method := range pkgauth.PublicMethods() {
		authInterceptor.AddPublicMethod(method)
	}

	// Configure role-based access control
	for method, roles := range pkgauth.DefaultRoleRequirements() {
		authInterceptor.AddRoleRequirement(method, roles)
	}

	// Production-ready server options with authentication
	opts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			loggingInterceptor(logger), // Logging should be first to capture all requests
			authInterceptor.UnaryInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			// Add stream logging interceptor if needed
			authInterceptor.StreamInterceptor(),
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
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("v1.PetStoreService", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("v1.AuthService", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(s, healthServer)

	// Register reflection service (useful for development and debugging)
	reflection.Register(s)

	return s, lis, nil
}
