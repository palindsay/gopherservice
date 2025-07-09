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

// Package auth_test provides tests for the auth package.
package auth_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	v1 "github.com/plindsay/gopherservice/api/v1"
	"github.com/plindsay/gopherservice/pkg/auth"
)

func TestMain(m *testing.M) {
	// Run tests
	exitVal := m.Run()
	os.Exit(exitVal)
}

func newTestJWTManager(t *testing.T) *auth.JWTManager {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return auth.NewJWTManager("test-secret", 5*time.Minute, 1*time.Hour, "test-issuer", logger)
}

func TestJWTManager_GenerateAndValidateToken(t *testing.T) {
	manager := newTestJWTManager(t)
	userID := "test-user"
	email := "test@example.com"
	roles := []string{"user"}

	token, err := manager.GenerateToken(userID, email, roles)
	require.NoError(t, err)
	require.NotNil(t, token)

	assert.NotEmpty(t, token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)

	claims, err := manager.ValidateToken(token.AccessToken)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, userID, claims.UserId)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, roles, claims.Roles)
}

func TestJWTManager_TokenExpiration(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	manager := auth.NewJWTManager("test-secret", -1*time.Second, 1*time.Hour, "test-issuer", logger)
	userID := "test-user"
	email := "test@example.com"
	roles := []string{"user"}

	token, err := manager.GenerateToken(userID, email, roles)
	require.NoError(t, err)

	_, err = manager.ValidateToken(token.AccessToken)
	require.Error(t, err)
}

func TestJWTManager_RevokeToken(t *testing.T) {
	manager := newTestJWTManager(t)
	userID := "test-user"
	email := "test@example.com"
	roles := []string{"user"}

	token, err := manager.GenerateToken(userID, email, roles)
	require.NoError(t, err)

	manager.RevokeToken(token.RefreshToken)

	_, err = manager.RefreshToken(token.RefreshToken)
	require.Error(t, err)
}

func TestJWTManager_RefreshToken(t *testing.T) {
	manager := newTestJWTManager(t)
	userID := "test-user"
	email := "test@example.com"
	roles := []string{"user"}

	// Generate initial token
	token, err := manager.GenerateToken(userID, email, roles)
	require.NoError(t, err)
	require.NotNil(t, token)

	// Refresh token
	newToken, err := manager.RefreshToken(token.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, newToken)

	assert.NotEmpty(t, newToken.AccessToken)
	assert.NotEmpty(t, newToken.RefreshToken)

	// Verify old refresh token is invalid
	_, err = manager.RefreshToken(token.RefreshToken)
	require.Error(t, err)

	// Validate new access token
	claims, err := manager.ValidateToken(newToken.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserId)
}

func TestPasswordHashing(t *testing.T) {
	password := "password123"
	hash, err := auth.HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	assert.True(t, auth.VerifyPassword(hash, password))
	assert.False(t, auth.VerifyPassword(hash, "wrongpassword"))
}

func TestAuthInterceptor_Unary(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	jwtManager := newTestJWTManager(t)
	interceptor := auth.NewInterceptor(jwtManager, logger)

	// Test case 1: Public method, no token required
	interceptor.AddPublicMethod("/test.Service/PublicMethod")
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "success", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/PublicMethod"}
	_, err := interceptor.Unary()(context.Background(), nil, info, handler)
	require.NoError(t, err)

	// Test case 2: Protected method, valid token
	userID := "test-user"
	email := "test@example.com"
	roles := []string{"user"}
	token, err := jwtManager.GenerateToken(userID, email, roles)
	require.NoError(t, err)

	md := metadata.New(map[string]string{"authorization": "Bearer " + token.AccessToken})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	handler = func(ctx context.Context, _ interface{}) (interface{}, error) {
		claims, ok := auth.GetClaimsFromContext(ctx)
		require.True(t, ok)
		assert.Equal(t, userID, claims.UserId)
		return "success", nil
	}
	info = &grpc.UnaryServerInfo{FullMethod: "/test.Service/ProtectedMethod"}
	_, err = interceptor.Unary()(ctx, nil, info, handler)
	require.NoError(t, err)

	// Test case 3: Protected method, no token
	info = &grpc.UnaryServerInfo{FullMethod: "/test.Service/ProtectedMethod"}
	_, err = interceptor.Unary()(context.Background(), nil, info, handler)
	require.Error(t, err)

	// Test case 4: Role requirement
	interceptor.AddRoleRequirement("/test.Service/AdminMethod", []string{"admin"})
	info = &grpc.UnaryServerInfo{FullMethod: "/test.Service/AdminMethod"}
	_, err = interceptor.Unary()(ctx, nil, info, handler)
	require.Error(t, err)
}

func TestContextGetters(t *testing.T) {
	claims := &v1.TokenClaims{UserId: "test-user"}
	ctx := context.WithValue(context.Background(), auth.ClaimsKey, claims)
	ctx = context.WithValue(ctx, auth.UserIDKey, "test-user")

	retrievedClaims, ok := auth.GetClaimsFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, claims, retrievedClaims)

	retrievedUserID, ok := auth.GetUserIDFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "test-user", retrievedUserID)

	_, ok = auth.GetClaimsFromContext(context.Background())
	assert.False(t, ok)

	_, ok = auth.GetUserIDFromContext(context.Background())
	assert.False(t, ok)
}
