package auth

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/plindsay/gopherservice/api/v1"
	"github.com/plindsay/gopherservice/pkg/auth"
	"github.com/plindsay/gopherservice/pkg/errors"
)

// Service implements the AuthService gRPC interface.
// It provides user authentication, registration, and token management functionality.
type Service struct {
	v1.UnimplementedAuthServiceServer
	logger     *slog.Logger
	jwtManager *auth.JWTManager
	users      map[string]*v1.User // In production, use a database
	passwords  map[string]string   // In production, store in secure database
	mu         sync.RWMutex        // Mutex to protect concurrent access
}

// NewService creates a new authentication service instance.
// It initializes in-memory storage for users and passwords.
// In production, this should be replaced with proper database storage.
func NewService(logger *slog.Logger, jwtManager *auth.JWTManager) *Service {
	service := &Service{
		logger:     logger,
		jwtManager: jwtManager,
		users:      make(map[string]*v1.User),
		passwords:  make(map[string]string),
	}

	// Create a default admin user for testing
	service.createDefaultUsers()

	return service
}

// createDefaultUsers creates some default users for testing purposes.
// In production, this should be removed and users should be created through proper channels.
func (s *Service) createDefaultUsers() {
	// Create admin user
	adminID := uuid.New().String()
	hashedPassword, _ := auth.HashPassword("admin123")

	s.users[adminID] = &v1.User{
		Id:          adminID,
		Email:       "admin@example.com",
		FullName:    "System Administrator",
		Roles:       []string{"admin", "user"},
		IsActive:    true,
		CreatedAt:   timestamppb.Now(),
		UpdatedAt:   timestamppb.Now(),
		LastLoginAt: nil,
	}
	s.passwords[adminID] = hashedPassword

	// Create regular user
	userID := uuid.New().String()
	hashedPassword, _ = auth.HashPassword("user123")

	s.users[userID] = &v1.User{
		Id:          userID,
		Email:       "user@example.com",
		FullName:    "Regular User",
		Roles:       []string{"user"},
		IsActive:    true,
		CreatedAt:   timestamppb.Now(),
		UpdatedAt:   timestamppb.Now(),
		LastLoginAt: nil,
	}
	s.passwords[userID] = hashedPassword

	s.logger.Info("created default users",
		slog.String("admin_email", "admin@example.com"),
		slog.String("user_email", "user@example.com"),
	)
}

// RegisterUser creates a new user account.
func (s *Service) RegisterUser(_ context.Context, req *v1.RegisterUserRequest) (*v1.RegisterUserResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate input
	if req.Email == "" {
		return nil, errors.NewValidationError("email is required", "Email field cannot be empty").ToGRPCStatus()
	}
	if req.Password == "" {
		return nil, errors.NewValidationError("password is required", "Password field cannot be empty").ToGRPCStatus()
	}
	if req.FullName == "" {
		return nil, errors.NewValidationError("full name is required", "FullName field cannot be empty").ToGRPCStatus()
	}

	// Check if user already exists
	for _, user := range s.users {
		if user.Email == req.Email {
			return nil, errors.NewConflictError("user", req.Email, "User with this email already exists").ToGRPCStatus()
		}
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, errors.NewInternalError("failed to hash password", err).ToGRPCStatus()
	}

	// Create user
	userID := uuid.New().String()
	roles := req.Roles
	if len(roles) == 0 {
		roles = []string{"user"} // Default role
	}

	user := &v1.User{
		Id:        userID,
		Email:     req.Email,
		FullName:  req.FullName,
		Roles:     roles,
		IsActive:  true,
		CreatedAt: timestamppb.Now(),
		UpdatedAt: timestamppb.Now(),
	}

	s.users[userID] = user
	s.passwords[userID] = hashedPassword

	s.logger.Info("user registered",
		slog.String("user_id", userID),
		slog.String("email", req.Email),
		slog.Any("roles", roles),
	)

	return &v1.RegisterUserResponse{
		User: user,
	}, nil
}

// Login authenticates a user and returns a JWT token.
func (s *Service) Login(_ context.Context, req *v1.LoginRequest) (*v1.LoginResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Credentials == nil {
		return nil, errors.NewValidationError("credentials are required").ToGRPCStatus()
	}

	email := req.Credentials.Email
	password := req.Credentials.Password

	if email == "" || password == "" {
		return nil, errors.NewValidationError("email and password are required", "Both email and password fields must be provided").ToGRPCStatus()
	}

	// Find user by email
	var user *v1.User
	var userID string
	var hashedPassword string

	for id, u := range s.users {
		if u.Email == email {
			user = u
			userID = id
			hashedPassword = s.passwords[id]
			break
		}
	}

	if user == nil {
		return nil, errors.NewAuthenticationError("invalid credentials", "User not found or password incorrect").ToGRPCStatus()
	}

	if !user.IsActive {
		return nil, errors.NewAuthorizationError("login", "User account is disabled").ToGRPCStatus()
	}

	// Verify password
	if !auth.VerifyPassword(hashedPassword, password) {
		return nil, errors.NewAuthenticationError("invalid credentials", "Password verification failed").ToGRPCStatus()
	}

	// Generate JWT token
	token, err := s.jwtManager.GenerateToken(userID, user.Email, user.Roles)
	if err != nil {
		s.logger.Error("failed to generate token", slog.Any("error", err))
		return nil, errors.NewInternalError("failed to generate token", err).ToGRPCStatus()
	}

	// Update last login time
	user.LastLoginAt = timestamppb.Now()
	user.UpdatedAt = timestamppb.Now()

	s.logger.Info("user logged in",
		slog.String("user_id", userID),
		slog.String("email", email),
	)

	return &v1.LoginResponse{
		User:  user,
		Token: token,
	}, nil
}

// Logout invalidates a user's token.
func (s *Service) Logout(_ context.Context, req *v1.LogoutRequest) (*v1.LogoutResponse, error) {
	if req.Token == "" {
		return nil, errors.NewValidationError("token is required", "Token field cannot be empty").ToGRPCStatus()
	}

	// Revoke the token
	s.jwtManager.RevokeToken(req.Token)

	s.logger.Info("user logged out")

	return &v1.LogoutResponse{
		Message: "Successfully logged out",
	}, nil
}

// RefreshToken obtains a new access token using a refresh token.
func (s *Service) RefreshToken(ctx context.Context, req *v1.RefreshTokenRequest) (*v1.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, errors.NewValidationError("refresh token is required", "RefreshToken field cannot be empty").ToGRPCStatus()
	}

	// In a real implementation, you would validate the refresh token against a database
	// For this example, we'll return an error since we don't have a full refresh token implementation
	return nil, errors.NewInternalError("refresh token functionality not fully implemented", nil).ToGRPCStatus()
}

// ValidateToken validates a JWT token and returns its claims.
func (s *Service) ValidateToken(ctx context.Context, req *v1.ValidateTokenRequest) (*v1.ValidateTokenResponse, error) {
	if req.Token == "" {
		return nil, errors.NewValidationError("token is required", "Token field cannot be empty").ToGRPCStatus()
	}

	claims, err := s.jwtManager.ValidateToken(req.Token)
	if err != nil {
		return &v1.ValidateTokenResponse{
			IsValid:      false,
			ErrorMessage: err.Error(),
		}, nil
	}

	return &v1.ValidateTokenResponse{
		IsValid: true,
		Claims:  claims,
	}, nil
}

// GetUser retrieves user information by ID.
func (s *Service) GetUser(ctx context.Context, req *v1.GetUserRequest) (*v1.GetUserResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if req.UserId == "" {
		return nil, errors.NewValidationError("user ID is required", "UserId field cannot be empty").ToGRPCStatus()
	}

	user, exists := s.users[req.UserId]
	if !exists {
		return nil, errors.NewNotFoundError("user", req.UserId).ToGRPCStatus()
	}

	return &v1.GetUserResponse{
		User: user,
	}, nil
}

// UpdateUser updates user information.
func (s *Service) UpdateUser(ctx context.Context, req *v1.UpdateUserRequest) (*v1.UpdateUserResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.UserId == "" {
		return nil, errors.NewValidationError("user ID is required", "UserId field cannot be empty").ToGRPCStatus()
	}

	if req.User == nil {
		return nil, errors.NewValidationError("user data is required", "User field cannot be empty").ToGRPCStatus()
	}

	existingUser, exists := s.users[req.UserId]
	if !exists {
		return nil, errors.NewNotFoundError("user", req.UserId).ToGRPCStatus()
	}

	// Update fields based on update mask
	// For simplicity, we'll update all provided fields
	if req.User.FullName != "" {
		existingUser.FullName = req.User.FullName
	}
	if req.User.Email != "" {
		existingUser.Email = req.User.Email
	}
	if len(req.User.Roles) > 0 {
		existingUser.Roles = req.User.Roles
	}
	if req.User.IsActive != existingUser.IsActive {
		existingUser.IsActive = req.User.IsActive
	}

	existingUser.UpdatedAt = timestamppb.Now()

	s.logger.Info("user updated",
		slog.String("user_id", req.UserId),
		slog.String("email", existingUser.Email),
	)

	return &v1.UpdateUserResponse{
		User: existingUser,
	}, nil
}

// ChangePassword changes a user's password.
func (s *Service) ChangePassword(ctx context.Context, req *v1.ChangePasswordRequest) (*v1.ChangePasswordResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.UserId == "" {
		return nil, errors.NewValidationError("user ID is required", "UserId field cannot be empty").ToGRPCStatus()
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		return nil, errors.NewValidationError("current password and new password are required", "Both CurrentPassword and NewPassword fields must be provided").ToGRPCStatus()
	}

	user, exists := s.users[req.UserId]
	if !exists {
		return nil, errors.NewNotFoundError("user", req.UserId).ToGRPCStatus()
	}

	// Verify current password
	currentHash := s.passwords[req.UserId]
	if !auth.VerifyPassword(currentHash, req.CurrentPassword) {
		return nil, errors.NewAuthenticationError("current password is incorrect", "Current password verification failed").ToGRPCStatus()
	}

	// Hash new password
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		return nil, errors.NewInternalError("failed to hash new password", err).ToGRPCStatus()
	}

	// Update password
	s.passwords[req.UserId] = newHash
	user.UpdatedAt = timestamppb.Now()

	s.logger.Info("password changed",
		slog.String("user_id", req.UserId),
		slog.String("email", user.Email),
	)

	return &v1.ChangePasswordResponse{
		Message: "Password changed successfully",
	}, nil
}

// ListUsers lists users with pagination and filtering.
func (s *Service) ListUsers(ctx context.Context, req *v1.ListUsersRequest) (*v1.ListUsersResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var users []*v1.User
	totalCount := 0

	// Apply filters and collect users
	for _, user := range s.users {
		// Filter by active status if specified
		if req.IsActive != nil && user.IsActive != *req.IsActive {
			continue
		}

		// Filter by role if specified
		if req.RoleFilter != "" {
			hasRole := false
			for _, role := range user.Roles {
				if role == req.RoleFilter {
					hasRole = true
					break
				}
			}
			if !hasRole {
				continue
			}
		}

		users = append(users, user)
		totalCount++
	}

	// Apply pagination (simplified implementation)
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 10 // Default page size
	}

	// For simplicity, we're not implementing full pagination with tokens
	// In production, you would implement proper cursor-based pagination

	if int(pageSize) < len(users) {
		users = users[:pageSize]
	}

	return &v1.ListUsersResponse{
		Users:      users,
		TotalCount: int32(totalCount),
	}, nil
}

// GetUserByEmail is a helper method to find a user by email (not part of the gRPC interface).
func (s *Service) GetUserByEmail(email string) (*v1.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Email == email {
			return user, true
		}
	}
	return nil, false
}
