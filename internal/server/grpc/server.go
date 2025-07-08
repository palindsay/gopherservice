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
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	v1 "github.com/plindsay/gopherservice/api/v1"
	internalauth "github.com/plindsay/gopherservice/internal/auth" // Renamed to avoid conflict
	"github.com/plindsay/gopherservice/internal/petstore"
	// "github.com/plindsay/gopherservice/pkg/auth" // This will be removed
)

// userClaimsContextKey is the key for UserClaims in context.
type userClaimsContextKey struct{}

// AuthInterceptor provides gRPC interceptors for authentication and authorization.
type AuthInterceptor struct {
	logger         *slog.Logger
	jwtSecretKey   []byte
	jwtIssuer      string
	publicMethods  map[string]bool
	roleRequirements map[string][]string
}

// NewAuthInterceptor creates a new AuthInterceptor.
func NewAuthInterceptor(logger *slog.Logger, jwtSecretKey string, jwtIssuer string) *AuthInterceptor {
	return &AuthInterceptor{
		logger:         logger,
		jwtSecretKey:   []byte(jwtSecretKey),
		jwtIssuer:      jwtIssuer,
		publicMethods:  make(map[string]bool),
		roleRequirements: make(map[string][]string),
	}
}

// AddPublicMethod marks a gRPC method as public (no authentication required).
func (i *AuthInterceptor) AddPublicMethod(methodFullName string) {
	i.publicMethods[methodFullName] = true
}

// AddRoleRequirement specifies the roles required to access a gRPC method.
func (i *AuthInterceptor) AddRoleRequirement(methodFullName string, roles []string) {
	i.roleRequirements[methodFullName] = roles
}

// Unary returns a UnaryServerInterceptor for authentication and authorization.
func (i *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if i.publicMethods[info.FullMethod] {
			return handler(ctx, req) // Public method, skip auth
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
		}

		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
		}

		authHeader := authHeaders[0]
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return nil, status.Errorf(codes.Unauthenticated, "authorization token format is Bearer <token>")
		}
		tokenString := parts[1]

		claims := &internalauth.UserClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return i.jwtSecretKey, nil
		})

		if err != nil {
			i.logger.Warn("token validation failed", "error", err, "method", info.FullMethod)
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		if !token.Valid {
			i.logger.Warn("token is invalid", "method", info.FullMethod)
			return nil, status.Errorf(codes.Unauthenticated, "token is invalid")
		}

		if claims.Issuer != i.jwtIssuer {
			i.logger.Warn("token issuer mismatch", "expected", i.jwtIssuer, "got", claims.Issuer, "method", info.FullMethod)
			return nil, status.Errorf(codes.Unauthenticated, "token issuer mismatch")
		}

		// Role-Based Access Control (RBAC)
		requiredRoles, methodHasRoleRequirement := i.roleRequirements[info.FullMethod]
		if methodHasRoleRequirement {
			hasPermission := false
			for _, userRole := range claims.Roles {
				for _, requiredRole := range requiredRoles {
					if userRole == requiredRole {
						hasPermission = true
						break
					}
				}
				if hasPermission {
					break
				}
			}
			if !hasPermission {
				i.logger.Warn("permission denied", "user_id", claims.UserID, "roles", claims.Roles, "required_roles", requiredRoles, "method", info.FullMethod)
				return nil, status.Errorf(codes.PermissionDenied, "insufficient permissions")
			}
		}

		// Add claims to context
		newCtx := context.WithValue(ctx, userClaimsContextKey{}, claims)
		return handler(newCtx, req)
	}
}

// Stream returns a StreamServerInterceptor for authentication and authorization.
// Note: Stream interceptor implementation is basic and mirrors unary.
// Proper stream handling might require wrapping the server stream.
func (i *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if i.publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Similar logic to Unary interceptor for token validation and RBAC
		md, ok := metadata.FromIncomingContext(ss.Context())
		if !ok {
			return status.Errorf(codes.Unauthenticated, "metadata is not provided")
		}

		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return status.Errorf(codes.Unauthenticated, "authorization token is not provided")
		}
		authHeader := authHeaders[0]
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return status.Errorf(codes.Unauthenticated, "authorization token format is Bearer <token>")
		}
		tokenString := parts[1]

		claims := &internalauth.UserClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return i.jwtSecretKey, nil
		})

		if err != nil || !token.Valid || claims.Issuer != i.jwtIssuer {
			i.logger.Warn("stream token validation failed", "error", err, "method", info.FullMethod, "valid", token.Valid, "issuer_ok", claims.Issuer == i.jwtIssuer)
			return status.Errorf(codes.Unauthenticated, "invalid token")
		}

		requiredRoles, methodHasRoleRequirement := i.roleRequirements[info.FullMethod]
		if methodHasRoleRequirement {
			hasPermission := false
			for _, userRole := range claims.Roles {
				for _, requiredRole := range requiredRoles {
					if userRole == requiredRole {
						hasPermission = true
						break
					}
				}
				if hasPermission {
					break
				}
			}
			if !hasPermission {
				i.logger.Warn("stream permission denied", "user_id", claims.UserID, "roles", claims.Roles, "required_roles", requiredRoles, "method", info.FullMethod)
				return status.Errorf(codes.PermissionDenied, "insufficient permissions")
			}
		}

		newCtx := context.WithValue(ss.Context(), userClaimsContextKey{}, claims)

		// Wrap the ServerStream with the new context
		// This is a simplified way. A more robust way involves creating a new struct that embeds grpc.ServerStream
		// and overrides Context() method.
		wrappedStream := &wrappedServerStream{ServerStream: ss, newCtx: newCtx}

		return handler(srv, wrappedStream)
	}
}

// wrappedServerStream wraps grpc.ServerStream to override its context.
type wrappedServerStream struct {
	grpc.ServerStream
	newCtx context.Context
}

// Context returns the wrapped context.
func (w *wrappedServerStream) Context() context.Context {
	return w.newCtx
}


// New creates a new gRPC server instance and a listener with authentication.
// It takes a context, a logger, the port to listen on, and the service implementations.
// It returns the gRPC server, the network listener, and an error if the listener cannot be created.
// jwtSecret and jwtIssuer are now required for the AuthInterceptor.
func New(_ context.Context, logger *slog.Logger, port int, petStoreService *petstore.Service, authService *internalauth.Service, jwtSecret, jwtIssuer string) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen: %w", err)
	}

	// Create authentication interceptor
	authInterceptor := NewAuthInterceptor(logger, jwtSecret, jwtIssuer)

	// Configure public methods (no authentication required)
	// Note: ValidateToken and DebugCreateUserAndToken might need re-evaluation if they should be public
	// For now, keeping them as per original logic.
	authInterceptor.AddPublicMethod("/v1.AuthService/RegisterUser")
	authInterceptor.AddPublicMethod("/v1.AuthService/Login")
	authInterceptor.AddPublicMethod("/v1.AuthService/RefreshToken") // Refresh token endpoint should be public
	// authInterceptor.AddPublicMethod("/v1.AuthService/ValidateToken") // This was likely for the old system, consider removing or securing
	// authInterceptor.AddPublicMethod("/v1.AuthService/DebugCreateUserAndToken") // Typically not for production
	authInterceptor.AddPublicMethod("/grpc.health.v1.Health/Check")

	// Configure role-based access control
	authInterceptor.AddRoleRequirement("/v1.AuthService/GetUser", []string{"user", "admin"}) // Added example for GetUser
	authInterceptor.AddRoleRequirement("/v1.AuthService/ListUsers", []string{"admin"})
	authInterceptor.AddRoleRequirement("/v1.PetStoreService/CreatePet", []string{"user", "admin"})
	authInterceptor.AddRoleRequirement("/v1.PetStoreService/GetPet", []string{"user", "admin"})
	// Removed PlaceOrder and GetOrder as they are not in v1.PetStoreService based on current files
	// authInterceptor.AddRoleRequirement("/v1.PetStoreService/PlaceOrder", []string{"user", "admin"})
	// authInterceptor.AddRoleRequirement("/v1.PetStoreService/GetOrder", []string{"user", "admin"})


	// Production-ready server options with authentication
	opts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			authInterceptor.Unary(),
			loggingInterceptor(logger), // loggingInterceptor should ideally be first if you want to log unauthenticated requests too
		),
		grpc.ChainStreamInterceptor(
			authInterceptor.Stream(),
			// Add stream logging interceptor if needed
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
	v1.RegisterAuthServiceServer(s, authService) // authService is of type *internalauth.Service

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
