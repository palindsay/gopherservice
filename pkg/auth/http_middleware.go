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

package auth

import (
	"log/slog"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
)

// HTTPMiddleware provides HTTP middleware for JWT authentication.
// This is specifically designed to work with gRPC-Gateway to ensure
// JWT tokens are properly forwarded from HTTP requests to gRPC services.
type HTTPMiddleware struct {
	manager      *Manager
	logger       *slog.Logger
	publicPaths  map[string]bool
	pathRoleReqs map[string][]string
}

// NewHTTPMiddleware creates a new HTTP middleware for JWT authentication.
func NewHTTPMiddleware(manager *Manager, logger *slog.Logger) *HTTPMiddleware {
	return &HTTPMiddleware{
		manager:      manager,
		logger:       logger,
		publicPaths:  make(map[string]bool),
		pathRoleReqs: make(map[string][]string),
	}
}

// AddPublicPath marks an HTTP path as public (no authentication required).
// The path should be the full path like "/v1/auth/login".
func (m *HTTPMiddleware) AddPublicPath(path string) {
	m.publicPaths[path] = true
}

// AddRoleRequirement sets the required roles for an HTTP path.
func (m *HTTPMiddleware) AddRoleRequirement(path string, roles []string) {
	m.pathRoleReqs[path] = roles
}

// Handler returns an HTTP handler that validates JWT tokens and forwards them to gRPC.
// This middleware ensures that JWT authentication works seamlessly with gRPC-Gateway.
func (m *HTTPMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for public paths
		if m.publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Extract and validate JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		token, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			m.writeError(w, http.StatusUnauthorized, "invalid authorization header: "+err.Error())
			return
		}

		claims, err := m.manager.ValidateToken(token)
		if err != nil {
			m.logger.Warn("HTTP token validation failed",
				slog.String("path", r.URL.Path),
				slog.String("method", r.Method),
				slog.String("error", err.Error()))
			m.writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Check role-based access control
		if err := m.checkRoleAccess(claims, r.URL.Path); err != nil {
			m.writeError(w, http.StatusForbidden, "insufficient permissions")
			return
		}

		// Forward the authorization header to gRPC via metadata
		// This ensures the gRPC service receives the JWT token
		md := metadata.New(map[string]string{
			"authorization": authHeader,
		})
		ctx := metadata.NewOutgoingContext(r.Context(), md)

		// Add claims to context for potential use in HTTP handlers
		ctx = AddClaimsToContext(ctx, claims)

		// Create new request with updated context
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// checkRoleAccess validates if the user has the required roles for the path.
func (m *HTTPMiddleware) checkRoleAccess(claims *Claims, path string) error {
	requiredRoles, hasRoleRequirement := m.pathRoleReqs[path]
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

	m.logger.Warn("HTTP insufficient permissions",
		slog.String("path", path),
		slog.String("user_id", claims.UserID),
		slog.Any("user_roles", claims.Roles),
		slog.Any("required_roles", requiredRoles))

	return http.ErrAbortHandler
}

// writeError writes an error response to the HTTP response writer.
func (m *HTTPMiddleware) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := `{"error": "` + message + `"}`
	_, _ = w.Write([]byte(response))
}

// PublicPaths returns a list of commonly used public HTTP paths.
// These are paths that typically don't require authentication.
func PublicPaths() []string {
	return []string{
		"/v1/auth/register",
		"/v1/auth/login",
		"/health",
		"/healthz",
		"/v1/health",
	}
}

// DefaultHTTPRoleRequirements returns a sensible default set of role requirements for HTTP paths.
// This can be customized based on your application's REST API structure.
func DefaultHTTPRoleRequirements() map[string][]string {
	return map[string][]string{
		// Auth endpoints
		"/v1/auth/refresh": {"user", "admin"},
		"/v1/auth/logout":  {"user", "admin"},
		"/v1/users":        {"admin"},
		"/v1/users/":       {"user", "admin"}, // This covers /v1/users/{id}

		// PetStore endpoints
		"/v1/pets":    {"user", "admin"},
		"/v1/pets/":   {"user", "admin"}, // This covers /v1/pets/{id}
		"/v1/orders":  {"user", "admin"},
		"/v1/orders/": {"user", "admin"}, // This covers /v1/orders/{id}
	}
}

// PathMatcher checks if a request path matches a pattern.
// This is useful for handling path patterns with parameters like /v1/users/{id}.
func PathMatcher(requestPath, pattern string) bool {
	// Exact match
	if requestPath == pattern {
		return true
	}

	// Pattern matching for paths ending with '/'
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(requestPath, pattern)
	}

	return false
}

// AdvancedHTTPMiddleware provides more sophisticated path matching and role checking.
type AdvancedHTTPMiddleware struct {
	*HTTPMiddleware
	pathPatterns map[string][]string // Pattern -> roles mapping
}

// NewAdvancedHTTPMiddleware creates a new advanced HTTP middleware with pattern matching.
func NewAdvancedHTTPMiddleware(manager *Manager, logger *slog.Logger) *AdvancedHTTPMiddleware {
	return &AdvancedHTTPMiddleware{
		HTTPMiddleware: NewHTTPMiddleware(manager, logger),
		pathPatterns:   make(map[string][]string),
	}
}

// AddPathPattern adds a path pattern with role requirements.
// Patterns ending with '/' will match all sub-paths.
func (m *AdvancedHTTPMiddleware) AddPathPattern(pattern string, roles []string) {
	m.pathPatterns[pattern] = roles
}

// Handler returns an HTTP handler with advanced path pattern matching.
func (m *AdvancedHTTPMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for public paths
		if m.publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Extract and validate JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		token, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			m.writeError(w, http.StatusUnauthorized, "invalid authorization header: "+err.Error())
			return
		}

		claims, err := m.manager.ValidateToken(token)
		if err != nil {
			m.logger.Warn("HTTP token validation failed",
				slog.String("path", r.URL.Path),
				slog.String("method", r.Method),
				slog.String("error", err.Error()))
			m.writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Check role-based access control with pattern matching
		if err := m.checkPatternRoleAccess(claims, r.URL.Path); err != nil {
			m.writeError(w, http.StatusForbidden, "insufficient permissions")
			return
		}

		// Forward the authorization header to gRPC via metadata
		md := metadata.New(map[string]string{
			"authorization": authHeader,
		})
		ctx := metadata.NewOutgoingContext(r.Context(), md)

		// Add claims to context
		ctx = AddClaimsToContext(ctx, claims)

		// Create new request with updated context
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// checkPatternRoleAccess validates roles with pattern matching support.
func (m *AdvancedHTTPMiddleware) checkPatternRoleAccess(claims *Claims, path string) error {
	// Check exact path requirements first
	if err := m.HTTPMiddleware.checkRoleAccess(claims, path); err == nil {
		return nil
	}

	// Check pattern requirements
	for pattern, requiredRoles := range m.pathPatterns {
		if PathMatcher(path, pattern) {
			for _, userRole := range claims.Roles {
				for _, requiredRole := range requiredRoles {
					if userRole == requiredRole {
						return nil
					}
				}
			}
			// If pattern matches but no role matches, deny access
			return http.ErrAbortHandler
		}
	}

	// No pattern matched, allow access (default behavior)
	return nil
}
