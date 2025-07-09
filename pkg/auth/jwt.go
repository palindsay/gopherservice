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

// Package auth provides JWT-based authentication and authorization functionality.
//
// This package implements secure JWT token generation, validation, and middleware
// for protecting gRPC and HTTP endpoints. It follows security best practices
// for token handling and provides flexible role-based access control.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// JWTManager handles JWT token creation, validation, and management.
type JWTManager struct {
	secretKey       string
	tokenDuration   time.Duration
	refreshDuration time.Duration
	issuer          string
	refreshTokens   map[string]string // Stores refresh_token -> user_id. In production, use Redis or similar
	logger          *slog.Logger
}

// CustomClaims represents the custom claims in our JWT tokens.
type CustomClaims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

// NewJWTManager creates a new JWT manager with the specified configuration.
//
// secretKey should be a cryptographically secure random string (at least 32 bytes).
// tokenDuration is how long access tokens remain valid.
// refreshDuration is how long refresh tokens remain valid.
// issuer is the JWT issuer identifier.
//
// Example:
//
//	manager := auth.NewJWTManager("your-secret-key", 15*time.Minute, 7*24*time.Hour, "my-service", logger)
func NewJWTManager(secretKey string, tokenDuration, refreshDuration time.Duration, issuer string, logger *slog.Logger) *JWTManager {
	return &JWTManager{
		secretKey:       secretKey,
		tokenDuration:   tokenDuration,
		refreshDuration: refreshDuration,
		issuer:          issuer,
		refreshTokens:   make(map[string]string),
		logger:          logger,
	}
}

// GenerateToken creates a new JWT token for the given user.
func (m *JWTManager) GenerateToken(userID, email string, roles []string) (*v1.JWTToken, error) {
	now := time.Now()
	expiresAt := now.Add(m.tokenDuration)

	claims := &CustomClaims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			Audience:  []string{"api"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(m.secretKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := m.generateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token (in a real app, this would be in a persistent store like Redis)
	m.refreshTokens[refreshToken] = userID

	return &v1.JWTToken{
		AccessToken:  signedToken,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt.Unix(),
		RefreshToken: refreshToken,
		Scopes:       roles,
	}, nil
}

// ValidateToken validates a JWT token and returns the claims.
func (m *JWTManager) ValidateToken(tokenString string) (*v1.TokenClaims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Convert to protobuf TokenClaims
	return &v1.TokenClaims{
		UserId:    claims.UserID,
		Email:     claims.Email,
		Roles:     claims.Roles,
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		IssuedAt:  claims.IssuedAt.Unix(),
		ExpiresAt: claims.ExpiresAt.Unix(),
		NotBefore: claims.NotBefore.Unix(),
	}, nil
}

// RefreshToken creates a new access token using a refresh token.
func (m *JWTManager) RefreshToken(refreshToken string) (*v1.JWTToken, error) {
	userID, ok := m.refreshTokens[refreshToken]
	if !ok {
		return nil, fmt.Errorf("invalid or expired refresh token")
	}

	// Invalidate the old refresh token
	delete(m.refreshTokens, refreshToken)

	// For simplicity, we'll just generate a new token with dummy email and roles.
	// In a real application, you'd retrieve user details from a database using userID.
	return m.GenerateToken(userID, "", []string{})
}

// RevokeToken removes a token from the valid refresh tokens.
func (m *JWTManager) RevokeToken(tokenString string) {
	delete(m.refreshTokens, tokenString)
	m.logger.Info("token revoked", slog.String("token_prefix", tokenString[:10]+"..."))
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedBytes), nil
}

// VerifyPassword verifies a password against its hash.
func VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// generateJTI generates a unique JWT ID (JTI claim) for token identification.
// It creates a 16-byte random value and encodes it as a hex string.
// The JTI is used for token tracking and revocation purposes.
func generateJTI() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes) // rand.Read always returns len(bytes), nil on valid input
	return hex.EncodeToString(bytes)
}

// generateRefreshToken generates a cryptographically secure refresh token.
// It creates a 32-byte random value and encodes it as a hex string for secure token storage.
// The refresh token is used for obtaining new access tokens without re-authentication.
func (m *JWTManager) generateRefreshToken(_ string) (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Interceptor is a gRPC interceptor that validates JWT tokens.
type Interceptor struct {
	jwtManager    *JWTManager
	logger        *slog.Logger
	publicMethods map[string]bool     // Methods that don't require authentication
	requiredRoles map[string][]string // Method -> required roles mapping
}

// NewInterceptor creates a new authentication interceptor.
func NewInterceptor(jwtManager *JWTManager, logger *slog.Logger) *Interceptor {
	return &Interceptor{
		jwtManager:    jwtManager,
		logger:        logger,
		publicMethods: make(map[string]bool),
		requiredRoles: make(map[string][]string),
	}
}

// AddPublicMethod marks a method as public (no authentication required).
func (i *Interceptor) AddPublicMethod(method string) {
	i.publicMethods[method] = true
}

// AddRoleRequirement sets the required roles for a method.
func (i *Interceptor) AddRoleRequirement(method string, roles []string) {
	i.requiredRoles[method] = roles
}

// Unary returns a unary server interceptor for authentication.
func (i *Interceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip authentication for public methods
		if i.publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract and validate token
		claims, err := i.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		// Add claims to context for use in handlers
		ctx = context.WithValue(ctx, ClaimsKey, claims)
		ctx = context.WithValue(ctx, UserIDKey, claims.UserId)

		return handler(ctx, req)
	}
}

// Stream returns a stream server interceptor for authentication.
func (i *Interceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip authentication for public methods
		if i.publicMethods[info.FullMethod] {
			return handler(srv, stream)
		}

		// Extract and validate token
		claims, err := i.authorize(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		// Create a new context with claims
		ctx := context.WithValue(stream.Context(), ClaimsKey, claims)
		ctx = context.WithValue(ctx, UserIDKey, claims.UserId)

		// Wrap the stream with the new context
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}

		return handler(srv, wrappedStream)
	}
}

// authorize extracts and validates the JWT token from the request context.
func (i *Interceptor) authorize(ctx context.Context, method string) (*v1.TokenClaims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}

	token := values[0]
	if !strings.HasPrefix(token, "Bearer ") {
		return nil, status.Error(codes.Unauthenticated, "invalid authorization header format")
	}

	token = strings.TrimPrefix(token, "Bearer ")
	claims, err := i.jwtManager.ValidateToken(token)
	if err != nil {
		i.logger.Error("token validation failed", slog.Any("error", err))
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	// Check role-based access control
	if requiredRoles, exists := i.requiredRoles[method]; exists {
		if !hasRequiredRole(claims.Roles, requiredRoles) {
			return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
		}
	}

	return claims, nil
}

// hasRequiredRole checks if the user has at least one of the required roles for access control.
// It takes the user's roles and a list of required roles and returns true if there's a match.
// This function is used for role-based access control (RBAC) in the authentication system.
func hasRequiredRole(userRoles, requiredRoles []string) bool {
	roleSet := make(map[string]bool)
	for _, role := range userRoles {
		roleSet[role] = true
	}

	for _, required := range requiredRoles {
		if roleSet[required] {
			return true
		}
	}
	return false
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

// GetClaimsFromContext extracts JWT claims from the context.
func GetClaimsFromContext(ctx context.Context) (*v1.TokenClaims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(*v1.TokenClaims)
	return claims, ok
}

// GetUserIDFromContext extracts the user ID from the context.
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDKey).(string)
	return userID, ok
}
