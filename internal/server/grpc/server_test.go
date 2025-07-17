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
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"

	v1 "github.com/plindsay/gopherservice/api/v1"
	authsvc "github.com/plindsay/gopherservice/internal/auth"
	"github.com/plindsay/gopherservice/internal/database"
	"github.com/plindsay/gopherservice/internal/petstore"
)

// Test constants.
const (
	testJWTSecretKey = "test-secret-key-that-is-long-enough-32-chars"
	testJWTIssuer    = "test-service"
)

// Helper to create test database.
func createTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	return db
}

// Helper to create test logger.
func createTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func TestNew(t *testing.T) {
	logger := createTestLogger()
	db := createTestDatabase(t)
	defer db.Close()

	authService := authsvc.NewService(logger, db, testJWTSecretKey, 15*time.Minute, 7*24*time.Hour, testJWTIssuer)
	petStoreService := petstore.NewService(logger)

	tests := []struct {
		name     string
		port     int
		wantErr  bool
		checkErr func(error) bool
	}{
		{
			name:    "valid port",
			port:    0, // OS will assign a free port
			wantErr: false,
		},
		{
			name:    "invalid port",
			port:    -1,
			wantErr: true,
			checkErr: func(err error) bool {
				return err != nil && err.Error() != ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			server, lis, err := New(ctx, logger, tt.port, petStoreService, authService, testJWTSecretKey, testJWTIssuer)

			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkErr != nil && !tt.checkErr(err) {
				t.Errorf("New() error check failed: %v", err)
				return
			}

			if server != nil {
				defer server.Stop()
			}
			if lis != nil {
				defer lis.Close()
			}
		})
	}
}

func TestServerComponents(t *testing.T) {
	logger := createTestLogger()
	db := createTestDatabase(t)
	defer db.Close()

	authService := authsvc.NewService(logger, db, testJWTSecretKey, 15*time.Minute, 7*24*time.Hour, testJWTIssuer)
	petStoreService := petstore.NewService(logger)

	ctx := context.Background()
	server, lis, err := New(ctx, logger, 0, petStoreService, authService, testJWTSecretKey, testJWTIssuer)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Stop()
	defer lis.Close()

	// Start the server
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		if err := server.Serve(lis); err != nil {
			serverDone <- err
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create client connection
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Test health check service
	t.Run("Health Check", func(t *testing.T) {
		client := grpc_health_v1.NewHealthClient(conn)
		resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		if err != nil {
			t.Errorf("health check failed: %v", err)
		}
		if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
			t.Errorf("expected SERVING status, got %v", resp.Status)
		}
	})

	// Test reflection service - it's available but requires authentication
	t.Run("Reflection Service Authentication", func(t *testing.T) {
		client := grpc_reflection_v1.NewServerReflectionClient(conn)
		stream, err := client.ServerReflectionInfo(ctx)
		if err != nil {
			t.Errorf("failed to create reflection stream: %v", err)
			return
		}

		// Send list services request - should fail without auth
		err = stream.Send(&grpc_reflection_v1.ServerReflectionRequest{
			MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_ListServices{},
		})
		if err == nil {
			// If no error on send, we should get an error on receive
			_, err = stream.Recv()
			if err == nil {
				t.Error("expected authentication error for reflection service")
			}
		}
	})

	// Test authentication - should fail without token
	t.Run("Authentication Required", func(t *testing.T) {
		client := v1.NewPetStoreServiceClient(conn)
		_, err := client.CreatePet(ctx, &v1.CreatePetRequest{
			Pet: &v1.Pet{
				Name:    "Test Pet",
				Species: "Dog",
			},
		})
		if err == nil {
			t.Error("expected authentication error")
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("expected Unauthenticated error, got %v", status.Code(err))
		}
	})

	// Cleanup
	server.GracefulStop()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Logf("server shutdown with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Log("server shutdown timeout")
	}
}

func TestLoggingInterceptor(t *testing.T) {
	// Create a buffer to capture logs
	var logOutput []string
	var mu sync.Mutex

	// Create a custom logger that captures output
	logger := slog.New(slog.NewTextHandler(&testWriter{
		write: func(p []byte) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			logOutput = append(logOutput, string(p))
			return len(p), nil
		},
	}, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create a mock handler that returns success
	mockHandler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "success", nil
	}

	// Create a mock handler that returns error
	mockErrorHandler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, status.Error(codes.Internal, "test error")
	}

	interceptor := loggingInterceptor(logger)

	t.Run("Success Case", func(t *testing.T) {
		mu.Lock()
		logOutput = []string{}
		mu.Unlock()

		info := &grpc.UnaryServerInfo{
			FullMethod: "/v1.TestService/TestMethod",
		}

		resp, err := interceptor(context.Background(), nil, info, mockHandler)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if resp != "success" {
			t.Errorf("expected 'success', got %v", resp)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logOutput) == 0 {
			t.Error("expected log output")
		}
	})

	t.Run("Error Case", func(t *testing.T) {
		mu.Lock()
		logOutput = []string{}
		mu.Unlock()

		info := &grpc.UnaryServerInfo{
			FullMethod: "/v1.TestService/TestMethod",
		}

		resp, err := interceptor(context.Background(), nil, info, mockErrorHandler)
		if err == nil {
			t.Error("expected error")
		}
		if resp != nil {
			t.Errorf("expected nil response, got %v", resp)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logOutput) == 0 {
			t.Error("expected log output")
		}
	})
}

func TestPublicMethods(t *testing.T) {
	logger := createTestLogger()
	db := createTestDatabase(t)
	defer db.Close()

	authService := authsvc.NewService(logger, db, testJWTSecretKey, 15*time.Minute, 7*24*time.Hour, testJWTIssuer)
	petStoreService := petstore.NewService(logger)

	ctx := context.Background()
	server, lis, err := New(ctx, logger, 0, petStoreService, authService, testJWTSecretKey, testJWTIssuer)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Stop()
	defer lis.Close()

	// Start the server
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		if err := server.Serve(lis); err != nil {
			serverDone <- err
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create client connection
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Test public methods (should work without authentication)
	t.Run("RegisterUser Public Method", func(t *testing.T) {
		client := v1.NewAuthServiceClient(conn)
		resp, err := client.RegisterUser(ctx, &v1.RegisterUserRequest{
			Email:    "test@example.com",
			Password: "password123",
			FullName: "Test User",
		})
		if err != nil {
			t.Errorf("RegisterUser failed: %v", err)
		}
		if resp == nil {
			t.Error("expected response")
		}
	})

	t.Run("Login Public Method", func(t *testing.T) {
		client := v1.NewAuthServiceClient(conn)
		resp, err := client.Login(ctx, &v1.LoginRequest{
			Credentials: &v1.UserCredentials{
				Email:    "test@example.com",
				Password: "password123",
			},
		})
		if err != nil {
			t.Errorf("Login failed: %v", err)
		}
		if resp == nil {
			t.Error("expected response")
		}
	})

	// Cleanup
	server.GracefulStop()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Logf("server shutdown with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Log("server shutdown timeout")
	}
}

func TestServerOptions(t *testing.T) {
	logger := createTestLogger()
	db := createTestDatabase(t)
	defer db.Close()

	authService := authsvc.NewService(logger, db, testJWTSecretKey, 15*time.Minute, 7*24*time.Hour, testJWTIssuer)
	petStoreService := petstore.NewService(logger)

	ctx := context.Background()
	server, lis, err := New(ctx, logger, 0, petStoreService, authService, testJWTSecretKey, testJWTIssuer)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Stop()
	defer lis.Close()

	// Test that server was created successfully
	if server == nil {
		t.Error("server should not be nil")
	}

	// Test listener was created
	if lis == nil {
		t.Error("listener should not be nil")
	}

	// Test that we can get the address
	addr := lis.Addr()
	if addr == nil {
		t.Error("listener address should not be nil")
	}
}

// testWriter is a helper for capturing log output.
type testWriter struct {
	write func([]byte) (int, error)
}

func (w *testWriter) Write(p []byte) (int, error) {
	return w.write(p)
}

func TestConcurrentRequests(t *testing.T) {
	logger := createTestLogger()
	db := createTestDatabase(t)
	defer db.Close()

	authService := authsvc.NewService(logger, db, testJWTSecretKey, 15*time.Minute, 7*24*time.Hour, testJWTIssuer)
	petStoreService := petstore.NewService(logger)

	ctx := context.Background()
	server, lis, err := New(ctx, logger, 0, petStoreService, authService, testJWTSecretKey, testJWTIssuer)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Stop()
	defer lis.Close()

	// Start the server
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		if err := server.Serve(lis); err != nil {
			serverDone <- err
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test concurrent health checks
	const numRequests = 10
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := grpc.NewClient(
				lis.Addr().String(),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()

			client := grpc_health_v1.NewHealthClient(conn)
			resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
			if err != nil {
				errors <- err
				return
			}
			if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
				errors <- fmt.Errorf("expected SERVING status, got %v", resp.Status)
				return
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		if err != nil {
			t.Errorf("concurrent request failed: %v", err)
		}
	}

	// Cleanup
	server.GracefulStop()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Logf("server shutdown with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Log("server shutdown timeout")
	}
}
