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

package auth

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Interceptor provides gRPC interceptors for JWT authentication and authorization.
// It supports both unary and streaming gRPC methods with role-based access control.
type Interceptor struct {
	manager          *Manager
	logger           *slog.Logger
	publicMethods    map[string]bool
	roleRequirements map[string][]string
}

// NewInterceptor creates a new gRPC authentication interceptor.
func NewInterceptor(manager *Manager, logger *slog.Logger) *Interceptor {
	return &Interceptor{
		manager:          manager,
		logger:           logger,
		publicMethods:    make(map[string]bool),
		roleRequirements: make(map[string][]string),
	}
}

// AddPublicMethod marks a gRPC method as public (no authentication required).
// The method should be in the format "/package.service/method".
func (i *Interceptor) AddPublicMethod(method string) {
	i.publicMethods[method] = true
}

// AddRoleRequirement sets the required roles for a gRPC method.
// Users must have at least one of the specified roles to access the method.
func (i *Interceptor) AddRoleRequirement(method string, roles []string) {
	i.roleRequirements[method] = roles
}

// UnaryInterceptor returns a gRPC unary server interceptor for JWT authentication.
func (i *Interceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip authentication for public methods
		if i.publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Authenticate and authorize the request
		claims, err := i.authenticate(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		// Add claims to context for use in handlers
		ctx = AddClaimsToContext(ctx, claims)

		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC stream server interceptor for JWT authentication.
func (i *Interceptor) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip authentication for public methods
		if i.publicMethods[info.FullMethod] {
			return handler(srv, stream)
		}

		// Authenticate and authorize the request
		claims, err := i.authenticate(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		// Create a new context with claims
		ctx := AddClaimsToContext(stream.Context(), claims)

		// Wrap the stream with the new context
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}

		return handler(srv, wrappedStream)
	}
}

// authenticate extracts and validates the JWT token from the request context.
// It also performs role-based authorization if required for the method.
func (i *Interceptor) authenticate(ctx context.Context, method string) (*Claims, error) {
	// Extract metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Get authorization header
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}

	// Extract token from header
	token, err := ExtractTokenFromHeader(authHeaders[0])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid authorization header: "+err.Error())
	}

	// Validate token
	claims, err := i.manager.ValidateToken(token)
	if err != nil {
		i.logger.Warn("token validation failed",
			slog.String("method", method),
			slog.String("error", err.Error()))
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	// Check role-based access control
	if err := i.checkRoleAccess(claims, method); err != nil {
		return nil, err
	}

	return claims, nil
}

// checkRoleAccess validates if the user has the required roles for the method.
func (i *Interceptor) checkRoleAccess(claims *Claims, method string) error {
	requiredRoles, hasRoleRequirement := i.roleRequirements[method]
	if !hasRoleRequirement {
		return nil // No specific role requirement
	}

	// Check if user has any of the required roles
	for _, userRole := range claims.Roles {
		for _, requiredRole := range requiredRoles {
			if userRole == requiredRole {
				return nil // User has required role
			}
		}
	}

	i.logger.Warn("insufficient permissions",
		slog.String("method", method),
		slog.String("user_id", claims.UserID),
		slog.Any("user_roles", claims.Roles),
		slog.Any("required_roles", requiredRoles))

	return status.Error(codes.PermissionDenied, "insufficient permissions")
}

// wrappedServerStream wraps a grpc.ServerStream with a custom context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// PublicMethods returns a list of commonly used public methods.
// These are methods that typically don't require authentication.
func PublicMethods() []string {
	return []string{
		"/grpc.health.v1.Health/Check",
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/v1.AuthService/RegisterUser",
		"/v1.AuthService/Login",
	}
}

// DefaultRoleRequirements returns a sensible default set of role requirements.
// This can be customized based on your application's needs.
func DefaultRoleRequirements() map[string][]string {
	return map[string][]string{
		// Auth service methods
		"/v1.AuthService/GetUser":        {"user", "admin"},
		"/v1.AuthService/UpdateUser":     {"user", "admin"},
		"/v1.AuthService/ChangePassword": {"user", "admin"},
		"/v1.AuthService/ListUsers":      {"admin"},
		"/v1.AuthService/RefreshToken":   {"user", "admin"},

		// PetStore service methods
		"/v1.PetStoreService/CreatePet": {"user", "admin"},
		"/v1.PetStoreService/GetPet":    {"user", "admin"},
		"/v1.PetStoreService/UpdatePet": {"user", "admin"},
		"/v1.PetStoreService/DeletePet": {"user", "admin"},
		"/v1.PetStoreService/ListPets":  {"user", "admin"},
	}
}
