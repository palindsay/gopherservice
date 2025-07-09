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

// Package auth provides a simplified, production-ready JWT authentication system.
// This package implements secure JWT token generation, validation, and middleware
// for both gRPC and HTTP endpoints using the latest golang-jwt/jwt v5 features.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	v1 "github.com/plindsay/gopherservice/api/v1"
)

// Claims represents the JWT claims for our application.
// This structure includes both custom claims and standard JWT registered claims.
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

// Manager handles JWT token creation, validation, and management.
// It provides a simplified interface for JWT operations with proper security practices.
type Manager struct {
	secretKey            []byte
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	issuer               string
	audience             []string
	logger               *slog.Logger
	revokedTokens        map[string]bool // Simple in-memory token blacklist
	mu                   sync.RWMutex    // Protect revokedTokens map
}

// Config holds the configuration for JWT Manager.
type Config struct {
	SecretKey            string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	Issuer               string
	Audience             []string
}

// NewManager creates a new JWT manager with the specified configuration.
// It follows security best practices and validates the configuration.
func NewManager(config Config, logger *slog.Logger) (*Manager, error) {
	if len(config.SecretKey) < 32 {
		return nil, fmt.Errorf("JWT secret key must be at least 32 characters long")
	}

	if config.AccessTokenDuration <= 0 {
		config.AccessTokenDuration = 15 * time.Minute
	}

	if config.RefreshTokenDuration <= 0 {
		config.RefreshTokenDuration = 7 * 24 * time.Hour
	}

	if config.Issuer == "" {
		config.Issuer = "gopherservice"
	}

	if len(config.Audience) == 0 {
		config.Audience = []string{"api"}
	}

	return &Manager{
		secretKey:            []byte(config.SecretKey),
		accessTokenDuration:  config.AccessTokenDuration,
		refreshTokenDuration: config.RefreshTokenDuration,
		issuer:               config.Issuer,
		audience:             config.Audience,
		logger:               logger,
		revokedTokens:        make(map[string]bool),
	}, nil
}

// GenerateToken creates a new JWT access token for the given user.
// It returns a protobuf JWTToken with access token, refresh token, and metadata.
func (m *Manager) GenerateToken(userID, email string, roles []string) (*v1.JWTToken, error) {
	now := time.Now()
	accessExpiresAt := now.Add(m.accessTokenDuration)

	// Create access token claims
	accessClaims := Claims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			Audience:  m.audience,
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateSecureID(16),
		},
	}

	// Create and sign access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(m.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token (simpler claims, longer duration)
	refreshExpiresAt := now.Add(m.refreshTokenDuration)
	refreshClaims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			Audience:  []string{"refresh"},
			ExpiresAt: jwt.NewNumericDate(refreshExpiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateSecureID(16),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(m.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &v1.JWTToken{
		AccessToken:  accessTokenString,
		TokenType:    "Bearer",
		ExpiresAt:    accessExpiresAt.Unix(),
		RefreshToken: refreshTokenString,
		Scopes:       roles,
	}, nil
}

// ValidateToken validates a JWT token and returns the claims.
// This implements the latest JWT v5 security practices with proper algorithm validation.
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method - this is critical for security
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		} else if method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected HMAC method: %v", method.Alg())
		}
		return m.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if token is revoked
	if m.isTokenRevoked(tokenString) {
		return nil, fmt.Errorf("token has been revoked")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate issuer
	if claims.Issuer != m.issuer {
		return nil, fmt.Errorf("invalid token issuer: %s", claims.Issuer)
	}

	// Validate audience for access tokens
	if len(claims.Audience) > 0 && !contains(claims.Audience, m.audience[0]) {
		return nil, fmt.Errorf("invalid token audience: %v", claims.Audience)
	}

	return claims, nil
}

// RefreshToken creates a new access token using a valid refresh token.
// It validates the refresh token and generates a new access token with updated expiration.
func (m *Manager) RefreshToken(refreshTokenString string, getUserDetails func(userID string) (email string, roles []string, err error)) (*v1.JWTToken, error) {
	// Parse and validate refresh token
	token, err := jwt.ParseWithClaims(refreshTokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		} else if method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected HMAC method: %v", method.Alg())
		}
		return m.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	// Check if refresh token is revoked
	if m.isTokenRevoked(refreshTokenString) {
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid refresh token claims")
	}

	// Validate this is actually a refresh token
	if len(claims.Audience) == 0 || !contains(claims.Audience, "refresh") {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	// Get fresh user details
	email, roles, err := getUserDetails(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user details: %w", err)
	}

	// Revoke the old refresh token to prevent reuse
	m.RevokeToken(refreshTokenString)

	// Generate new access token
	return m.GenerateToken(claims.UserID, email, roles)
}

// RevokeToken adds a token to the revocation list.
// In a production system, this would typically be stored in a database or distributed cache.
func (m *Manager) RevokeToken(tokenString string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedTokens[tokenString] = true
}

// isTokenRevoked checks if a token has been revoked.
func (m *Manager) isTokenRevoked(tokenString string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revokedTokens[tokenString]
}

// ExtractTokenFromHeader extracts a JWT token from an Authorization header.
// It expects the format "Bearer <token>" and returns the token string.
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("authorization header format must be 'Bearer <token>'")
	}

	return parts[1], nil
}

// generateSecureID generates a cryptographically secure random ID of the specified byte length.
// This is used for JTI (JWT ID) claims to ensure token uniqueness.
func generateSecureID(byteLength int) string {
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based ID if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// contains checks if a slice contains a specific string value.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ContextKey represents the type for context keys to avoid collisions.
type ContextKey string

const (
	// ClaimsContextKey is the context key for JWT claims.
	ClaimsContextKey ContextKey = "jwt_claims"
	// UserIDContextKey is the context key for user ID.
	UserIDContextKey ContextKey = "user_id"
)

// GetClaimsFromContext extracts JWT claims from the context.
func GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return claims, ok
}

// GetUserIDFromContext extracts the user ID from the context.
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDContextKey).(string)
	return userID, ok
}

// AddClaimsToContext adds JWT claims to the context.
func AddClaimsToContext(ctx context.Context, claims *Claims) context.Context {
	ctx = context.WithValue(ctx, ClaimsContextKey, claims)
	ctx = context.WithValue(ctx, UserIDContextKey, claims.UserID)
	return ctx
}
