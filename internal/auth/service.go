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

// Package auth provides authentication and authorization services for the gopherservice.
// It implements user registration, login, JWT token generation and validation, and token refresh functionality.
// The package handles both access tokens and refresh tokens, with role-based access control support.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/plindsay/gopherservice/api/v1"
	// "github.com/plindsay/gopherservice/pkg/auth" // Will be removed.
	"github.com/plindsay/gopherservice/pkg/errors"
)

// UserClaims defines the JWT claims for a user.
type UserClaims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

// Service implements the AuthService gRPC interface.
// It provides user authentication, registration, and token management functionality.
type Service struct {
	v1.UnimplementedAuthServiceServer
	logger                  *slog.Logger
	db                      *sql.DB
	jwtSecretKey            []byte
	jwtAccessTokenDuration  time.Duration
	jwtRefreshTokenDuration time.Duration
	jwtIssuer               string
}

// NewService creates a new authentication service instance.
func NewService(logger *slog.Logger, db *sql.DB, jwtSecretKey string, accessTokenDuration, refreshTokenDuration time.Duration, jwtIssuer string) *Service {
	return &Service{
		logger:                  logger,
		db:                      db,
		jwtSecretKey:            []byte(jwtSecretKey),
		jwtAccessTokenDuration:  accessTokenDuration,
		jwtRefreshTokenDuration: refreshTokenDuration,
		jwtIssuer:               jwtIssuer,
	}
}

// HashPassword generates a bcrypt hash of the password.
// This function was previously in pkg/auth/auth.go.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// VerifyPassword compares a bcrypt hashed password with its possible plaintext equivalent.
// Returns true if the password matches, false otherwise.
// This function was previously in pkg/auth/auth.go.
func VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// RegisterUser creates a new user account.
func (s *Service) RegisterUser(ctx context.Context, req *v1.RegisterUserRequest) (*v1.RegisterUserResponse, error) {
	// Validate input
	if req.Email == "" {
		return nil, errors.NewValidationError("email is required").ToGRPCStatus()
	}
	if req.Password == "" {
		return nil, errors.NewValidationError("password is required").ToGRPCStatus()
	}
	if req.FullName == "" {
		return nil, errors.NewValidationError("full name is required").ToGRPCStatus()
	}

	// Check if user already exists
	var existingID string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM users WHERE email = ?", req.Email).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return nil, errors.NewInternalError("failed to check for existing user", err).ToGRPCStatus()
	}
	if existingID != "" {
		return nil, errors.NewConflictError("user", req.Email, "a user with this email already exists").ToGRPCStatus()
	}

	// Hash password
	hashedPassword, err := HashPassword(req.Password) // Using local HashPassword
	if err != nil {
		return nil, errors.NewInternalError("failed to hash password", err).ToGRPCStatus()
	}

	// Create user
	userID := uuid.New().String()
	roles := req.Roles
	if len(roles) == 0 {
		roles = []string{"user"} // Default role
	}
	rolesJSON, _ := json.Marshal(roles)

	user := &v1.User{
		Id:        userID,
		Email:     req.Email,
		FullName:  req.FullName,
		Roles:     roles,
		IsActive:  true,
		CreatedAt: timestamppb.Now(),
		UpdatedAt: timestamppb.Now(),
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.NewInternalError("failed to begin transaction", err).ToGRPCStatus()
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			s.logger.Error("failed to rollback transaction", "error", err)
		}
	}()

	_, err = tx.ExecContext(ctx, "INSERT INTO users (id, email, full_name, roles, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		user.Id, user.Email, user.FullName, string(rolesJSON), user.IsActive, user.CreatedAt.AsTime(), user.UpdatedAt.AsTime())
	if err != nil {
		return nil, errors.NewInternalError("failed to create user", err).ToGRPCStatus()
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO passwords (user_id, hash) VALUES (?, ?)", user.Id, hashedPassword)
	if err != nil {
		return nil, errors.NewInternalError("failed to save password", err).ToGRPCStatus()
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.NewInternalError("failed to commit transaction", err).ToGRPCStatus()
	}

	s.logger.Info("user registered", "user_id", userID, "email", req.Email)

	return &v1.RegisterUserResponse{User: user}, nil
}

// Login authenticates a user and returns a JWT token.
func (s *Service) Login(ctx context.Context, req *v1.LoginRequest) (*v1.LoginResponse, error) {
	if req.Credentials == nil {
		return nil, errors.NewValidationError("credentials are required").ToGRPCStatus()
	}

	email := req.Credentials.Email
	password := req.Credentials.Password

	if email == "" || password == "" {
		return nil, errors.NewValidationError("email and password are required").ToGRPCStatus()
	}

	var user v1.User
	var rolesJSON string
	var hashedPassword string
	var lastLogin sql.NullTime
	createdAt := time.Time{}
	updatedAt := time.Time{}

	err := s.db.QueryRowContext(ctx, "SELECT id, full_name, roles, is_active, created_at, updated_at, last_login_at FROM users WHERE email = ?", email).Scan(
		&user.Id, &user.FullName, &rolesJSON, &user.IsActive, &createdAt, &updatedAt, &lastLogin,
	)
	if err == sql.ErrNoRows {
		return nil, errors.NewAuthenticationError("invalid credentials").ToGRPCStatus()
	}
	if err != nil {
		return nil, errors.NewInternalError("failed to find user", err).ToGRPCStatus()
	}
	user.Email = email
	user.CreatedAt = timestamppb.New(createdAt)
	user.UpdatedAt = timestamppb.New(updatedAt)
	if lastLogin.Valid {
		user.LastLoginAt = timestamppb.New(lastLogin.Time)
	}

	if !user.IsActive {
		return nil, errors.NewAuthorizationError("login", "user account is disabled").ToGRPCStatus()
	}

	err = s.db.QueryRowContext(ctx, "SELECT hash FROM passwords WHERE user_id = ?", user.Id).Scan(&hashedPassword)
	if err != nil {
		return nil, errors.NewInternalError("failed to retrieve password", err).ToGRPCStatus()
	}

	if !VerifyPassword(hashedPassword, password) { // Using local VerifyPassword
		return nil, errors.NewAuthenticationError("invalid credentials").ToGRPCStatus()
	}

	if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
		return nil, errors.NewInternalError("failed to parse user roles", err).ToGRPCStatus()
	}

	// Generate Access Token
	accessClaims := UserClaims{
		UserID: user.Id,
		Email:  user.Email,
		Roles:  user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.jwtAccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.jwtIssuer,
			Subject:   user.Id,
			ID:        uuid.NewString(),
			Audience:  []string{"gopherservice_users"},
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(s.jwtSecretKey)
	if err != nil {
		return nil, errors.NewInternalError("failed to generate access token", err).ToGRPCStatus()
	}

	// Generate Refresh Token
	refreshClaims := UserClaims{ // Refresh token might carry less info or just an ID
		UserID: user.Id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.jwtRefreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.jwtIssuer,
			Subject:   user.Id,          // Linking refresh token to user
			ID:        uuid.NewString(), // Unique ID for the refresh token itself
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(s.jwtSecretKey)
	if err != nil {
		return nil, errors.NewInternalError("failed to generate refresh token", err).ToGRPCStatus()
	}

	token := &v1.JWTToken{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(s.jwtAccessTokenDuration).Unix(),
	}

	now := time.Now()
	user.LastLoginAt = timestamppb.New(now)
	user.UpdatedAt = timestamppb.New(now)

	_, err = s.db.ExecContext(ctx, "UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?", now, now, user.Id)
	if err != nil {
		s.logger.Error("failed to update last login time", "error", err)
		// Non-critical error, so we don't return an error to the user
	}

	s.logger.Info("user logged in", "user_id", user.Id, "email", user.Email)

	return &v1.LoginResponse{User: &user, Token: token}, nil
}

// Logout invalidates a user's token.
// Note: With stateless JWTs, true server-side revocation requires a denylist.
// This simplified version removes the active revocation call.
// Client should discard the token.
func (s *Service) Logout(_ context.Context, req *v1.LogoutRequest) (*v1.LogoutResponse, error) {
	if req.Token == "" {
		// Even if token is not required by server for logout, good to check if client sent it
		// as per original logic, though it's not used with stateless JWTs on server side.
		s.logger.Debug("logout request received, token provided but not actively invalidated on server", "token", req.Token)
	}

	// s.jwtManager.RevokeToken(req.Token) // Removed as standard JWTs are stateless.
	// Implement denylist logic here if true revocation is needed.
	s.logger.Info("user logged out (client-side token removal expected)")

	return &v1.LogoutResponse{Message: "Successfully logged out. Please discard your token."}, nil
}

// RefreshToken is not fully implemented.
// This refactor focuses on replacing JWT library, not implementing new features.
// If RefreshToken were to be implemented with golang-jwt/jwt:
// 1. Validate the incoming refresh token (req.RefreshToken) using jwt.ParseWithClaims.
// 2. Check if it's a valid refresh token (e.g., not expired, correct issuer, present in a refresh token store if used).
// 3. If valid, generate a new access token (and potentially a new refresh token - refresh token rotation).
// 4. Return the new v1.JWTToken.
func (s *Service) RefreshToken(ctx context.Context, req *v1.RefreshTokenRequest) (*v1.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, errors.NewValidationError("refresh token is required").ToGRPCStatus()
	}

	// Placeholder for parsing the refresh token
	claims := &UserClaims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.NewAuthenticationError("unexpected signing method: %v", token.Header["alg"].(string)).ToGRPCStatus()
		}
		return s.jwtSecretKey, nil
	})

	if err != nil {
		s.logger.Warn("refresh token validation failed", "error", err)
		return nil, errors.NewAuthenticationError("invalid refresh token").ToGRPCStatus()
	}

	if !token.Valid || claims.UserID == "" {
		return nil, errors.NewAuthenticationError("invalid refresh token claims").ToGRPCStatus()
	}

	// At this point, the refresh token is valid.
	// We would typically check it against a store of active refresh tokens or a denylist.
	// For this example, assume it's valid if parsed correctly and not expired.

	// Fetch user details to ensure account is still active, roles haven't changed etc.
	// This part is crucial in a real implementation.
	// For now, we'll use the UserID from the refresh token claims.
	var user v1.User
	var rolesJSON string
	err = s.db.QueryRowContext(ctx, "SELECT email, full_name, roles, is_active FROM users WHERE id = ?", claims.UserID).Scan(
		&user.Email, &user.FullName, &rolesJSON, &user.IsActive,
	)
	if err != nil {
		return nil, errors.NewInternalError("failed to find user for refresh token", err).ToGRPCStatus()
	}
	if !user.IsActive {
		return nil, errors.NewAuthorizationError("refresh_token", "user account is disabled").ToGRPCStatus()
	}
	if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
		return nil, errors.NewInternalError("failed to parse user roles for refresh token", err).ToGRPCStatus()
	}

	// Generate new Access Token
	newAccessClaims := UserClaims{
		UserID: claims.UserID,
		Email:  user.Email, // Use fresh email from DB
		Roles:  user.Roles, // Use fresh roles from DB
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.jwtAccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.jwtIssuer,
			Subject:   claims.UserID,
			ID:        uuid.NewString(),
			Audience:  []string{"gopherservice_users"},
		},
	}
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newAccessClaims)
	newAccessTokenString, err := newAccessToken.SignedString(s.jwtSecretKey)
	if err != nil {
		return nil, errors.NewInternalError("failed to generate new access token", err).ToGRPCStatus()
	}

	// Optionally, generate a new Refresh Token (rotation)
	// For simplicity, we are not rotating refresh token here, but it's a good practice.
	// If rotating, the old refresh token should be invalidated.

	newToken := &v1.JWTToken{
		AccessToken:  newAccessTokenString,
		RefreshToken: req.RefreshToken, // Return the same refresh token or a new one if rotating
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(s.jwtAccessTokenDuration).Unix(),
	}

	s.logger.Info("access token refreshed", "user_id", claims.UserID)
	return &v1.RefreshTokenResponse{Token: newToken}, nil
}

// GetUser retrieves a user by their ID.
func (s *Service) GetUser(ctx context.Context, req *v1.GetUserRequest) (*v1.GetUserResponse, error) {
	if req.UserId == "" {
		return nil, errors.NewValidationError("user ID is required").ToGRPCStatus()
	}

	var user v1.User
	var rolesJSON string
	var lastLogin sql.NullTime
	createdAt := time.Time{}
	updatedAt := time.Time{}

	err := s.db.QueryRowContext(ctx, "SELECT email, full_name, roles, is_active, created_at, updated_at, last_login_at FROM users WHERE id = ?", req.UserId).Scan(
		&user.Email, &user.FullName, &rolesJSON, &user.IsActive, &createdAt, &updatedAt, &lastLogin,
	)
	if err == sql.ErrNoRows {
		return nil, errors.NewNotFoundError("user", req.UserId).ToGRPCStatus()
	}
	if err != nil {
		return nil, errors.NewInternalError("failed to get user", err).ToGRPCStatus()
	}
	user.Id = req.UserId
	user.CreatedAt = timestamppb.New(createdAt)
	user.UpdatedAt = timestamppb.New(updatedAt)
	if lastLogin.Valid {
		user.LastLoginAt = timestamppb.New(lastLogin.Time)
	}

	if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
		return nil, errors.NewInternalError("failed to parse user roles", err).ToGRPCStatus()
	}

	return &v1.GetUserResponse{User: &user}, nil
}

// UpdateUser updates a user's information.
func (s *Service) UpdateUser(ctx context.Context, req *v1.UpdateUserRequest) (*v1.UpdateUserResponse, error) {
	if req.UserId == "" {
		return nil, errors.NewValidationError("user ID is required").ToGRPCStatus()
	}
	if req.User == nil {
		return nil, errors.NewValidationError("user data is required").ToGRPCStatus()
	}

	// For simplicity, we only support updating a few fields.
	// A full implementation would use a field mask.
	query := "UPDATE users SET updated_at = ?"
	args := []interface{}{time.Now()}

	if req.User.FullName != "" {
		query += ", full_name = ?"
		args = append(args, req.User.FullName)
	}
	if req.User.Email != "" {
		query += ", email = ?"
		args = append(args, req.User.Email)
	}

	query += " WHERE id = ?"
	args = append(args, req.UserId)

	_, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewInternalError("failed to update user", err).ToGRPCStatus()
	}

	// Fetch the updated user to return
	getUserResponse, err := s.GetUser(ctx, &v1.GetUserRequest{UserId: req.UserId})
	if err != nil {
		return nil, err
	}
	return &v1.UpdateUserResponse{User: getUserResponse.User}, nil
}

// ChangePassword changes a user's password.
func (s *Service) ChangePassword(ctx context.Context, req *v1.ChangePasswordRequest) (*v1.ChangePasswordResponse, error) {
	if req.UserId == "" {
		return nil, errors.NewValidationError("user ID is required").ToGRPCStatus()
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		return nil, errors.NewValidationError("current and new passwords are required").ToGRPCStatus()
	}

	var currentHash string
	err := s.db.QueryRowContext(ctx, "SELECT hash FROM passwords WHERE user_id = ?", req.UserId).Scan(&currentHash)
	if err != nil {
		return nil, errors.NewInternalError("failed to retrieve current password", err).ToGRPCStatus()
	}

	if !VerifyPassword(currentHash, req.CurrentPassword) { // Using local VerifyPassword
		return nil, errors.NewAuthenticationError("current password is incorrect").ToGRPCStatus()
	}

	newHash, err := HashPassword(req.NewPassword) // Using local HashPassword
	if err != nil {
		return nil, errors.NewInternalError("failed to hash new password", err).ToGRPCStatus()
	}

	_, err = s.db.ExecContext(ctx, "UPDATE passwords SET hash = ? WHERE user_id = ?", newHash, req.UserId)
	if err != nil {
		return nil, errors.NewInternalError("failed to update password", err).ToGRPCStatus()
	}

	s.logger.Info("password changed", "user_id", req.UserId)
	return &v1.ChangePasswordResponse{Message: "Password changed successfully"}, nil
}

// ListUsers lists users with pagination and filtering.
func (s *Service) ListUsers(ctx context.Context, req *v1.ListUsersRequest) (*v1.ListUsersResponse, error) {
	query := "SELECT id, email, full_name, roles, is_active, created_at, updated_at, last_login_at FROM users"
	countQuery := "SELECT COUNT(*) FROM users"
	var args []interface{}
	var conditions []string

	if req.IsActive != nil {
		conditions = append(conditions, "is_active = ?")
		args = append(args, *req.IsActive)
	}
	if req.RoleFilter != "" {
		conditions = append(conditions, "roles LIKE ?")
		args = append(args, "%"+req.RoleFilter+"%")
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
		countQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	var totalCount int32
	err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, errors.NewInternalError("failed to count users", err).ToGRPCStatus()
	}

	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	query += " LIMIT ?"
	args = append(args, pageSize)

	// Note: Full pagination with tokens is not implemented for simplicity.

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewInternalError("failed to list users", err).ToGRPCStatus()
	}
	defer rows.Close()

	var users []*v1.User
	for rows.Next() {
		var user v1.User
		var rolesJSON string
		var lastLogin sql.NullTime
		createdAt := time.Time{}
		updatedAt := time.Time{}

		if err := rows.Scan(&user.Id, &user.Email, &user.FullName, &rolesJSON, &user.IsActive, &createdAt, &updatedAt, &lastLogin); err != nil {
			return nil, errors.NewInternalError("failed to scan user row", err).ToGRPCStatus()
		}
		user.CreatedAt = timestamppb.New(createdAt)
		user.UpdatedAt = timestamppb.New(updatedAt)
		if lastLogin.Valid {
			user.LastLoginAt = timestamppb.New(lastLogin.Time)
		}
		if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
			return nil, errors.NewInternalError("failed to parse user roles", err).ToGRPCStatus()
		}
		users = append(users, &user)
	}

	return &v1.ListUsersResponse{
		Users:      users,
		TotalCount: totalCount,
	}, nil
}
