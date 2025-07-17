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

// Package log_test provides tests for the log package.
package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/plindsay/gopherservice/internal/log"
)

func TestMain(m *testing.M) {
	// Run tests
	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestDefaultConfig(t *testing.T) {
	config := log.DefaultConfig()
	require.NotNil(t, config)
	assert.Equal(t, slog.LevelInfo, config.Level)
	assert.Equal(t, "json", config.Format)
	assert.Equal(t, "gopherservice", config.ServiceName)
	assert.Equal(t, "1.0.0", config.ServiceVersion)
	assert.True(t, config.AddSource)
	assert.Equal(t, os.Stdout, config.Output)
}

func TestConfigFromEnv(t *testing.T) {
	// Save original environment
	originalLogLevel := os.Getenv("LOG_LEVEL")
	originalLogFormat := os.Getenv("LOG_FORMAT")
	originalServiceName := os.Getenv("SERVICE_NAME")
	originalEnvironment := os.Getenv("ENVIRONMENT")

	// Set test environment variables
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_FORMAT", "text")
	os.Setenv("SERVICE_NAME", "test-service")
	os.Setenv("ENVIRONMENT", "test")

	// Restore environment after test
	defer func() {
		os.Setenv("LOG_LEVEL", originalLogLevel)
		os.Setenv("LOG_FORMAT", originalLogFormat)
		os.Setenv("SERVICE_NAME", originalServiceName)
		os.Setenv("ENVIRONMENT", originalEnvironment)
	}()

	config := log.ConfigFromEnv()
	require.NotNil(t, config)
	assert.Equal(t, slog.LevelDebug, config.Level)
	assert.Equal(t, "text", config.Format)
	assert.Equal(t, "test-service", config.ServiceName)
	assert.Equal(t, "test", config.Environment)
}

func TestNew(t *testing.T) {
	logger := log.New(nil)
	require.NotNil(t, logger)
	assert.IsType(t, &log.Logger{}, logger)
	assert.NotNil(t, logger.Logger)
}

func TestNewWithDefaults(t *testing.T) {
	logger := log.NewWithDefaults()
	require.NotNil(t, logger)
	assert.IsType(t, &log.Logger{}, logger)
}

func TestCorrelationID(t *testing.T) {
	ctx := context.Background()

	// Test with no correlation ID
	id := log.CorrelationIDFromContext(ctx)
	assert.Empty(t, id)

	// Test with correlation ID
	testID := "test-correlation-id"
	ctx = log.WithCorrelationID(ctx, testID)
	retrievedID := log.CorrelationIDFromContext(ctx)
	assert.Equal(t, testID, retrievedID)

	// Test with new correlation ID
	ctx = log.WithNewCorrelationID(ctx)
	newID := log.CorrelationIDFromContext(ctx)
	assert.NotEmpty(t, newID)
	assert.NotEqual(t, testID, newID)
}

func TestRequestID(t *testing.T) {
	ctx := context.Background()

	// Test with no request ID
	id := log.RequestIDFromContext(ctx)
	assert.Empty(t, id)

	// Test with request ID
	testID := "test-request-id"
	ctx = log.WithRequestID(ctx, testID)
	retrievedID := log.RequestIDFromContext(ctx)
	assert.Equal(t, testID, retrievedID)
}

func TestUserID(t *testing.T) {
	ctx := context.Background()

	// Test with no user ID
	id := log.UserIDFromContext(ctx)
	assert.Empty(t, id)

	// Test with user ID
	testID := "test-user-id"
	ctx = log.WithUserID(ctx, testID)
	retrievedID := log.UserIDFromContext(ctx)
	assert.Equal(t, testID, retrievedID)
}

func TestFromContext(t *testing.T) {
	ctx := context.Background()

	// Test with no logger in context
	logger := log.FromContext(ctx)
	require.NotNil(t, logger)
	assert.IsType(t, &log.Logger{}, logger)

	// Test with logger in context
	originalLogger := log.NewWithDefaults()
	ctx = log.WithContext(ctx, originalLogger)
	retrievedLogger := log.FromContext(ctx)
	require.NotNil(t, retrievedLogger)
	assert.Equal(t, originalLogger, retrievedLogger)
}

func TestWithContext(t *testing.T) {
	ctx := context.Background()
	logger := log.NewWithDefaults()

	newCtx := log.WithContext(ctx, logger)
	require.NotNil(t, newCtx)

	retrievedLogger := log.FromContext(newCtx)
	assert.Equal(t, logger, retrievedLogger)
}

func TestContextualLogger(t *testing.T) {
	logger := log.NewWithDefaults()
	ctx := context.Background()

	// Add correlation ID, request ID, and user ID
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")
	ctx = log.WithRequestID(ctx, "test-request-id")
	ctx = log.WithUserID(ctx, "test-user-id")

	// Create contextual logger
	contextualLogger := logger.ContextualLogger(ctx)
	require.NotNil(t, contextualLogger)
	assert.IsType(t, &slog.Logger{}, contextualLogger)
}

func TestContextualLoggerWithTrace(t *testing.T) {
	logger := log.NewWithDefaults()

	// Create a tracer and span
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-operation")
	defer span.End()

	// Create contextual logger
	contextualLogger := logger.ContextualLogger(ctx)
	require.NotNil(t, contextualLogger)
	assert.IsType(t, &slog.Logger{}, contextualLogger)
}

func TestLoggerMethods(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	config := &log.Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := log.New(config)
	ctx := log.WithCorrelationID(context.Background(), "test-correlation-id")

	// Test different log levels
	logger.Debug(ctx, "debug message", "key", "value")
	logger.Info(ctx, "info message", "key", "value")
	logger.Warn(ctx, "warn message", "key", "value")
	logger.Error(ctx, "error message", "key", "value")

	// Verify log output contains expected fields
	output := buf.String()
	assert.Contains(t, output, "test-service")
	assert.Contains(t, output, "test-correlation-id")
	assert.Contains(t, output, "debug message")
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "warn message")
	assert.Contains(t, output, "error message")
}

func TestErrorWithError(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	config := &log.Config{
		Level:          slog.LevelError,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := log.New(config)
	ctx := context.Background()

	// Test error with error value
	testErr := assert.AnError
	logger.ErrorWithError(ctx, "test error message", testErr, "key", "value")

	// Verify log output contains error information
	output := buf.String()
	assert.Contains(t, output, "test error message")
	assert.Contains(t, output, testErr.Error())
}

func TestGlobalLogger(t *testing.T) {
	// Test getting global logger
	logger := log.GetGlobalLogger()
	require.NotNil(t, logger)
	assert.IsType(t, &log.Logger{}, logger)

	// Test setting global logger
	newLogger := log.NewWithDefaults()
	log.SetGlobalLogger(newLogger)
	retrievedLogger := log.GetGlobalLogger()
	assert.Equal(t, newLogger, retrievedLogger)
}

func TestPackageLevelFunctions(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	config := &log.Config{
		Level:          slog.LevelDebug,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := log.New(config)
	log.SetGlobalLogger(logger)

	ctx := context.Background()

	// Test package-level functions
	log.Debug(ctx, "debug message")
	log.Info(ctx, "info message")
	log.Warn(ctx, "warn message")
	log.Error(ctx, "error message")
	log.ErrorWithError(ctx, "error with error", assert.AnError)

	// Verify log output
	output := buf.String()
	assert.Contains(t, output, "debug message")
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "warn message")
	assert.Contains(t, output, "error message")
	assert.Contains(t, output, "error with error")
}

func TestJSONLogFormat(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	config := &log.Config{
		Level:          slog.LevelInfo,
		Format:         "json",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		AddSource:      false,
		Output:         &buf,
	}

	logger := log.New(config)
	ctx := log.WithCorrelationID(context.Background(), "test-correlation-id")

	logger.Info(ctx, "test message", "key", "value")

	// Verify JSON format
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	assert.Greater(t, len(lines), 0)

	// Parse JSON log entry
	var logEntry map[string]interface{}
	err := json.Unmarshal([]byte(lines[0]), &logEntry)
	require.NoError(t, err)

	// Verify expected fields
	assert.Equal(t, "test message", logEntry["message"])
	assert.Equal(t, "info", logEntry["level"])
	assert.Equal(t, "test-service", logEntry["service"])
	assert.Equal(t, "1.0.0", logEntry["version"])
	assert.Equal(t, "test", logEntry["environment"])
	assert.Equal(t, "test-correlation-id", logEntry["correlation_id"])
	assert.Equal(t, "value", logEntry["key"])
	assert.Contains(t, logEntry, "timestamp")
}

func TestEnhancedLoggerCompatibility(t *testing.T) {
	// Test that enhanced logger provides underlying slog.Logger
	logger := log.NewWithDefaults()
	require.NotNil(t, logger)
	assert.IsType(t, &log.Logger{}, logger)
	assert.IsType(t, &slog.Logger{}, logger.Logger)
}
