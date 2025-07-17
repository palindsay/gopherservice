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

package log

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperationLogger(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	// Test successful operation
	op := logger.StartOperation(ctx, "test-operation", "param1", "value1")
	require.NotNil(t, op)

	op.Progress(ctx, "halfway done", "progress", 50)
	op.Complete(ctx, "result", "success")

	output := buf.String()
	assert.Contains(t, output, "operation started")
	assert.Contains(t, output, "operation progress")
	assert.Contains(t, output, "operation completed")
	assert.Contains(t, output, "test-operation")
	assert.Contains(t, output, "success")
}

func TestOperationLoggerFailure(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	// Test failed operation
	op := logger.StartOperation(ctx, "test-operation", "param1", "value1")
	require.NotNil(t, op)

	testErr := errors.New("test error")
	op.Fail(ctx, testErr, "error_code", "TEST_ERROR")

	output := buf.String()
	assert.Contains(t, output, "operation started")
	assert.Contains(t, output, "operation failed")
	assert.Contains(t, output, "test-operation")
	assert.Contains(t, output, "failed")
	assert.Contains(t, output, "test error")
}

func TestRequestLogger(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	// Test successful request
	req := logger.StartRequest(ctx, "GET", "/api/v1/test", "client_id", "test-client")
	require.NotNil(t, req)

	req.Complete(ctx, 200, 1024, "cache_hit", true)

	output := buf.String()
	assert.Contains(t, output, "request started")
	assert.Contains(t, output, "request completed")
	assert.Contains(t, output, "GET")
	assert.Contains(t, output, "/api/v1/test")
	assert.Contains(t, output, "200")
}

func TestRequestLoggerWithErrors(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	// Test client error
	req := logger.StartRequest(ctx, "GET", "/api/v1/test")
	req.Complete(ctx, 400, 0)

	// Test server error
	req2 := logger.StartRequest(ctx, "POST", "/api/v1/test")
	req2.Complete(ctx, 500, 0)

	output := buf.String()
	assert.Contains(t, output, "request completed with client error")
	assert.Contains(t, output, "request completed with server error")
	assert.Contains(t, output, "400")
	assert.Contains(t, output, "500")
}

func TestRequestLoggerFailure(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	// Test failed request
	req := logger.StartRequest(ctx, "GET", "/api/v1/test")
	testErr := errors.New("network error")
	req.Fail(ctx, testErr, "error_type", "network")

	output := buf.String()
	assert.Contains(t, output, "request started")
	assert.Contains(t, output, "request failed")
	assert.Contains(t, output, "network error")
}

func TestDatabaseLogger(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	// Test successful database operation
	db := logger.StartDatabaseOperation(ctx, "SELECT", "users", "query_id", "12345")
	require.NotNil(t, db)

	db.Complete(ctx, 5, "execution_plan", "index_scan")

	output := buf.String()
	assert.Contains(t, output, "database operation started")
	assert.Contains(t, output, "database operation completed")
	assert.Contains(t, output, "SELECT")
	assert.Contains(t, output, "users")
	assert.Contains(t, output, "5")
}

func TestDatabaseLoggerFailure(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	// Test failed database operation
	db := logger.StartDatabaseOperation(ctx, "INSERT", "users")
	testErr := errors.New("constraint violation")
	db.Fail(ctx, testErr, "constraint", "unique_email")

	output := buf.String()
	assert.Contains(t, output, "database operation started")
	assert.Contains(t, output, "database operation failed")
	assert.Contains(t, output, "constraint violation")
}

func TestAuthenticationLogger(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	authLogger := logger.NewAuthenticationLogger()
	require.NotNil(t, authLogger)

	// Test login events
	authLogger.LoginAttempt(ctx, "user@example.com", "192.168.1.1", "Mozilla/5.0")
	authLogger.LoginSuccess(ctx, "user123", "user@example.com", "192.168.1.1", "Mozilla/5.0")
	authLogger.LoginFailure(ctx, "user@example.com", "192.168.1.1", "Mozilla/5.0", "invalid_password")

	// Test token events
	expiresAt := time.Now().Add(15 * time.Minute)
	authLogger.TokenGenerated(ctx, "user123", "access_token", expiresAt)
	authLogger.TokenRevoked(ctx, "user123", "access_token", "user_logout")

	// Test security event
	authLogger.SecurityEvent(ctx, "suspicious_activity", "Multiple failed login attempts", "attempts", 5)

	output := buf.String()
	assert.Contains(t, output, "login attempt")
	assert.Contains(t, output, "login successful")
	assert.Contains(t, output, "login failed")
	assert.Contains(t, output, "token generated")
	assert.Contains(t, output, "token revoked")
	assert.Contains(t, output, "security event")
	assert.Contains(t, output, "user@example.com")
	assert.Contains(t, output, "192.168.1.1")
}

func TestBusinessLogger(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	bizLogger := logger.NewBusinessLogger("petstore")
	require.NotNil(t, bizLogger)

	// Test entity operations
	bizLogger.EntityCreated(ctx, "pet", "pet123", "name", "Fluffy")
	bizLogger.EntityUpdated(ctx, "pet", "pet123", []string{"name", "age"}, "name", "Fluffy Jr", "age", 2)
	bizLogger.EntityDeleted(ctx, "pet", "pet123", "reason", "adopted")

	// Test business rules
	bizLogger.BusinessRule(ctx, "pet_age_limit", true, "Pet age is within acceptable range", "age", 2)
	bizLogger.BusinessRule(ctx, "pet_name_length", false, "Pet name is too long", "name_length", 50)

	output := buf.String()
	assert.Contains(t, output, "entity created")
	assert.Contains(t, output, "entity updated")
	assert.Contains(t, output, "entity deleted")
	assert.Contains(t, output, "business rule passed")
	assert.Contains(t, output, "business rule violated")
	assert.Contains(t, output, "petstore")
	assert.Contains(t, output, "pet123")
}

func TestPerformanceLogger(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	perfLogger := logger.NewPerformanceLogger()
	require.NotNil(t, perfLogger)

	// Test performance issues
	perfLogger.SlowQuery(ctx, "SELECT * FROM large_table", 5*time.Second, 1*time.Second)
	perfLogger.HighMemoryUsage(ctx, 800, 1000)
	perfLogger.HighCPUUsage(ctx, 85.5, 80.0)

	output := buf.String()
	assert.Contains(t, output, "slow query detected")
	assert.Contains(t, output, "high memory usage detected")
	assert.Contains(t, output, "high CPU usage detected")
	assert.Contains(t, output, "performance_issue")
}

func TestLogPanic(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	// Test panic recovery
	func() {
		defer LogPanic(ctx, logger)
		panic("test panic")
	}()

	output := buf.String()
	assert.Contains(t, output, "panic recovered")
	assert.Contains(t, output, "test panic")
}

func TestLogPanicWithCallback(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := New(config)
	ctx := context.Background()

	callbackCalled := false
	callback := func() {
		callbackCalled = true
	}

	// Test panic recovery with callback
	func() {
		defer LogPanicWithCallback(ctx, logger, callback)
		panic("test panic")
	}()

	output := buf.String()
	assert.Contains(t, output, "panic recovered")
	assert.Contains(t, output, "test panic")
	assert.True(t, callbackCalled)
}

func TestWithFields(t *testing.T) {
	logger := NewWithDefaults()

	fieldsLogger := WithFields(logger, "key1", "value1", "key2", "value2")
	require.NotNil(t, fieldsLogger)
	assert.IsType(t, &slog.Logger{}, fieldsLogger)
}

func TestWithUserContext(t *testing.T) {
	logger := NewWithDefaults()

	userLogger := WithUserContext(logger, "user123", "user@example.com", []string{"user", "admin"})
	require.NotNil(t, userLogger)
	assert.IsType(t, &slog.Logger{}, userLogger)
}

func TestWithRequestContext(t *testing.T) {
	logger := NewWithDefaults()

	requestLogger := WithRequestContext(logger, "GET", "/api/v1/test", "192.168.1.1")
	require.NotNil(t, requestLogger)
	assert.IsType(t, &slog.Logger{}, requestLogger)
}
