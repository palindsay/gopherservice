// Package auth_test provides tests for the auth service.
package auth_test

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite" // SQLite driver
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/plindsay/gopherservice/api/v1"
	"github.com/plindsay/gopherservice/internal/auth"
	"github.com/plindsay/gopherservice/internal/database"
	pkgauth "github.com/plindsay/gopherservice/pkg/auth"
)

var (
	testAuthService *auth.Service
	testJWTManager  *pkgauth.JWTManager
	testDB          *sql.DB
)

func TestMain(m *testing.M) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	testJWTManager = pkgauth.NewJWTManager("test-secret", 5*time.Minute, 1*time.Hour, "test-issuer", logger)

	// Setup test database
	var err error
	testDB, err = database.New("file::memory:?cache=shared")
	if err != nil {
		panic(err)
	}
	defer testDB.Close()

	testAuthService = auth.NewService(logger, testJWTManager, testDB)

	exitVal := m.Run()
	os.Exit(exitVal)
}

func cleanupDB(t *testing.T) {
	t.Helper()
	_, err := testDB.Exec("DELETE FROM users")
	require.NoError(t, err)
	_, err = testDB.Exec("DELETE FROM passwords")
	require.NoError(t, err)
}

func TestAuthService_RegisterUser(t *testing.T) {
	cleanupDB(t)
	req := &v1.RegisterUserRequest{
		Email:    "testuser@example.com",
		Password: "password123",
		FullName: "Test User",
	}
	res, err := testAuthService.RegisterUser(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, req.Email, res.User.Email)
	assert.Equal(t, req.FullName, res.User.FullName)

	// Test duplicate user
	_, err = testAuthService.RegisterUser(context.Background(), req)
	require.Error(t, err)
}

func TestAuthService_Login(t *testing.T) {
	cleanupDB(t)
	// Register a user first
	registerReq := &v1.RegisterUserRequest{
		Email:    "loginuser@example.com",
		Password: "password123",
		FullName: "Login User",
	}
	_, err := testAuthService.RegisterUser(context.Background(), registerReq)
	require.NoError(t, err)

	// Test login
	loginReq := &v1.LoginRequest{
		Credentials: &v1.UserCredentials{
			Email:    "loginuser@example.com",
			Password: "password123",
		},
	}
	res, err := testAuthService.Login(context.Background(), loginReq)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.Token.AccessToken)
}

func TestAuthService_Login_InvalidCredentials(t *testing.T) {
	cleanupDB(t)
	loginReq := &v1.LoginRequest{
		Credentials: &v1.UserCredentials{
			Email:    "nonexistent@example.com",
			Password: "wrongpassword",
		},
	}
	_, err := testAuthService.Login(context.Background(), loginReq)
	require.Error(t, err)
}

func TestAuthService_GetUser(t *testing.T) {
	cleanupDB(t)
	// Register a user first
	registerReq := &v1.RegisterUserRequest{
		Email:    "getuser@example.com",
		Password: "password123",
		FullName: "Get User",
	}
	registerRes, err := testAuthService.RegisterUser(context.Background(), registerReq)
	require.NoError(t, err)

	// Test GetUser
	getUserReq := &v1.GetUserRequest{UserId: registerRes.User.Id}
	getUserRes, err := testAuthService.GetUser(context.Background(), getUserReq)
	require.NoError(t, err)
	require.NotNil(t, getUserRes)
	assert.Equal(t, registerRes.User.Id, getUserRes.User.Id)
}

func TestAuthService_UpdateUser(t *testing.T) {
	cleanupDB(t)
	// Register a user first
	registerReq := &v1.RegisterUserRequest{
		Email:    "updateuser@example.com",
		Password: "password123",
		FullName: "Update User",
	}
	registerRes, err := testAuthService.RegisterUser(context.Background(), registerReq)
	require.NoError(t, err)

	// Test UpdateUser
	updateReq := &v1.UpdateUserRequest{
		UserId: registerRes.User.Id,
		User: &v1.User{
			FullName: "Updated User Name",
		},
	}
	updateRes, err := testAuthService.UpdateUser(context.Background(), updateReq)
	require.NoError(t, err)
	require.NotNil(t, updateRes)
	assert.Equal(t, "Updated User Name", updateRes.User.FullName)
}

func TestAuthService_ChangePassword(t *testing.T) {
	cleanupDB(t)
	// Register a user first
	registerReq := &v1.RegisterUserRequest{
		Email:    "changepassword@example.com",
		Password: "password123",
		FullName: "Change Password User",
	}
	registerRes, err := testAuthService.RegisterUser(context.Background(), registerReq)
	require.NoError(t, err)

	// Test ChangePassword
	changePasswordReq := &v1.ChangePasswordRequest{
		UserId:          registerRes.User.Id,
		CurrentPassword: "password123",
		NewPassword:     "newpassword",
	}
	_, err = testAuthService.ChangePassword(context.Background(), changePasswordReq)
	require.NoError(t, err)

	// Verify new password
	loginReq := &v1.LoginRequest{
		Credentials: &v1.UserCredentials{
			Email:    "changepassword@example.com",
			Password: "newpassword",
		},
	}
	_, err = testAuthService.Login(context.Background(), loginReq)
	require.NoError(t, err)
}

func TestAuthService_ListUsers(t *testing.T) {
	cleanupDB(t)
	// Register some users
	_, err := testAuthService.RegisterUser(context.Background(), &v1.RegisterUserRequest{Email: "user1@example.com", Password: "p", FullName: "User One", Roles: []string{"user"}})
	require.NoError(t, err)
	_, err = testAuthService.RegisterUser(context.Background(), &v1.RegisterUserRequest{Email: "user2@example.com", Password: "p", FullName: "User Two", Roles: []string{"user", "admin"}})
	require.NoError(t, err)

	// Test ListUsers
	listRes, err := testAuthService.ListUsers(context.Background(), &v1.ListUsersRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(2), listRes.TotalCount)

	// Test ListUsers with role filter
	listRes, err = testAuthService.ListUsers(context.Background(), &v1.ListUsersRequest{RoleFilter: "admin"})
	require.NoError(t, err)
	assert.Equal(t, int32(1), listRes.TotalCount)
}
