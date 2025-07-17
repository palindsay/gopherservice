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

package errors

import (
	"context"
	"errors"
	"testing"

	"github.com/plindsay/gopherservice/internal/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockLogger implements the Logger interface for testing.
type MockLogger struct {
	LoggedMessages []LoggedMessage
}

type LoggedMessage struct {
	Level   string
	Message string
	Args    []any
}

func (ml *MockLogger) Error(_ context.Context, msg string, args ...any) {
	ml.LoggedMessages = append(ml.LoggedMessages, LoggedMessage{
		Level:   "error",
		Message: msg,
		Args:    args,
	})
}

func (ml *MockLogger) Warn(_ context.Context, msg string, args ...any) {
	ml.LoggedMessages = append(ml.LoggedMessages, LoggedMessage{
		Level:   "warn",
		Message: msg,
		Args:    args,
	})
}

func (ml *MockLogger) Info(_ context.Context, msg string, args ...any) {
	ml.LoggedMessages = append(ml.LoggedMessages, LoggedMessage{
		Level:   "info",
		Message: msg,
		Args:    args,
	})
}

func (ml *MockLogger) Debug(_ context.Context, msg string, args ...any) {
	ml.LoggedMessages = append(ml.LoggedMessages, LoggedMessage{
		Level:   "debug",
		Message: msg,
		Args:    args,
	})
}

func TestLogError(t *testing.T) {
	ctx := context.Background()
	mockLogger := &MockLogger{}

	// Test with nil error
	LogError(ctx, mockLogger, nil)
	assert.Empty(t, mockLogger.LoggedMessages)

	// Test with contextual error
	appErr := NewValidationError("test validation error", "test details")
	ce := NewContextualError(ctx, appErr)

	LogError(ctx, mockLogger, ce)
	require.Len(t, mockLogger.LoggedMessages, 1)

	logged := mockLogger.LoggedMessages[0]
	assert.Equal(t, "warn", logged.Level)
	assert.Equal(t, "error occurred", logged.Message)
	assert.Contains(t, logged.Args, "error_type")
	assert.Contains(t, logged.Args, "contextual_error")
	assert.Contains(t, logged.Args, "error_code")
	assert.Contains(t, logged.Args, "VALIDATION_ERROR")
}

func TestLogErrorWithMessage(t *testing.T) {
	ctx := context.Background()
	mockLogger := &MockLogger{}

	appErr := NewInternalError("test internal error", nil)
	ce := NewContextualError(ctx, appErr)

	LogErrorWithMessage(ctx, mockLogger, ce, "custom error message")
	require.Len(t, mockLogger.LoggedMessages, 1)

	logged := mockLogger.LoggedMessages[0]
	assert.Equal(t, "error", logged.Level)
	assert.Equal(t, "custom error message", logged.Message)
}

func TestDetermineLogLevel(t *testing.T) {
	testCases := []struct {
		name     string
		error    error
		expected string
	}{
		{
			name:     "ValidationError",
			error:    NewValidationError("test"),
			expected: "warn",
		},
		{
			name:     "NotFoundError",
			error:    NewNotFoundError("user", "123"),
			expected: "info",
		},
		{
			name:     "ConflictError",
			error:    NewConflictError("user", "123"),
			expected: "warn",
		},
		{
			name:     "AuthenticationError",
			error:    NewAuthenticationError("test"),
			expected: "warn",
		},
		{
			name:     "AuthorizationError",
			error:    NewAuthorizationError("read", "user"),
			expected: "warn",
		},
		{
			name:     "InternalError",
			error:    NewInternalError("test", nil),
			expected: "error",
		},
		{
			name:     "ExternalError",
			error:    NewExternalError("service", "operation", nil),
			expected: "error",
		},
		{
			name:     "RateLimitError",
			error:    NewRateLimitError(100, "minute"),
			expected: "warn",
		},
		{
			name:     "StandardError",
			error:    errors.New("standard error"),
			expected: "error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			level := determineLogLevel(tc.error)
			assert.Equal(t, tc.expected, level)
		})
	}
}

func TestDetermineLogLevelWithContextualError(t *testing.T) {
	ctx := context.Background()
	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	level := determineLogLevel(ce)
	assert.Equal(t, "warn", level)
}

func TestExtractLoggingFields(t *testing.T) {
	ctx := context.Background()
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")
	ctx = log.WithUserID(ctx, "test-user-id")

	appErr := NewValidationError("test validation error", "test details")
	_ = appErr.WithMetadata("field", "value")

	ce := NewContextualError(ctx, appErr)
	ce.Context = ce.Context.WithComponent("test-component").WithOperation("test-operation")

	fields := extractLoggingFields(ce)

	// Check that all expected fields are present
	assert.Contains(t, fields, "error_type")
	assert.Contains(t, fields, "contextual_error")
	assert.Contains(t, fields, "error_code")
	assert.Contains(t, fields, "VALIDATION_ERROR")
	assert.Contains(t, fields, "error_message")
	assert.Contains(t, fields, "test validation error")
	assert.Contains(t, fields, "error_details")
	assert.Contains(t, fields, "test details")
	assert.Contains(t, fields, "correlation_id")
	assert.Contains(t, fields, "test-correlation-id")
	assert.Contains(t, fields, "user_id")
	assert.Contains(t, fields, "test-user-id")
	assert.Contains(t, fields, "component")
	assert.Contains(t, fields, "test-component")
	assert.Contains(t, fields, "operation")
	assert.Contains(t, fields, "test-operation")
	assert.Contains(t, fields, "metadata_field")
	assert.Contains(t, fields, "value")
}

func TestExtractLoggingFieldsWithChain(t *testing.T) {
	ctx := context.Background()

	appErr := NewInternalError("test internal error", nil)
	ce := NewContextualError(ctx, appErr)

	err1 := errors.New("error 1")
	err2 := errors.New("error 2")
	ce.AddToChain(err1).AddToChain(err2) // nolint: errcheck

	fields := extractLoggingFields(ce)

	assert.Contains(t, fields, "error_chain")

	// Find the chain value
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok && key == "error_chain" {
				if chain, ok := fields[i+1].(string); ok {
					assert.Contains(t, chain, "error 1")
					assert.Contains(t, chain, "error 2")
				}
			}
		}
	}
}

func TestExtractLoggingFieldsAppError(t *testing.T) {
	appErr := NewValidationError("test validation error", "test details")
	_ = appErr.WithMetadata("field", "value")

	cause := errors.New("underlying cause")
	_ = appErr.WithCause(cause)

	fields := extractLoggingFields(appErr)

	assert.Contains(t, fields, "error_type")
	assert.Contains(t, fields, "app_error")
	assert.Contains(t, fields, "error_code")
	assert.Contains(t, fields, "VALIDATION_ERROR")
	assert.Contains(t, fields, "error_message")
	assert.Contains(t, fields, "test validation error")
	assert.Contains(t, fields, "error_details")
	assert.Contains(t, fields, "test details")
	assert.Contains(t, fields, "metadata_field")
	assert.Contains(t, fields, "value")
	assert.Contains(t, fields, "underlying_cause")
	assert.Contains(t, fields, "underlying cause")
}

func TestExtractLoggingFieldsStandardError(t *testing.T) {
	err := errors.New("standard error")

	fields := extractLoggingFields(err)

	assert.Contains(t, fields, "error_type")
	assert.Contains(t, fields, "standard_error")
	assert.Contains(t, fields, "error_message")
	assert.Contains(t, fields, "standard error")
}

func TestReportingErrorLogger(t *testing.T) {
	mockLogger := &MockLogger{}
	mockReporter := &MockErrorReporter{}

	reportingLogger := NewReportingErrorLogger(mockLogger, mockReporter)

	ctx := context.Background()
	testErr := errors.New("test error")

	reportingLogger.Error(ctx, "error occurred", "error", testErr)

	require.Len(t, mockLogger.LoggedMessages, 1)
	assert.Equal(t, "error", mockLogger.LoggedMessages[0].Level)

	require.Len(t, mockReporter.ReportedErrors, 1)
	assert.Equal(t, testErr, mockReporter.ReportedErrors[0])
}

func TestLogAndWrapError(t *testing.T) {
	mockLogger := &MockLogger{}
	ctx := context.Background()

	originalErr := errors.New("original error")

	wrappedErr := LogAndWrapError(ctx, mockLogger, originalErr, "wrapped error")

	require.NotNil(t, wrappedErr)
	assert.Contains(t, wrappedErr.Error(), "wrapped error")
	assert.Equal(t, originalErr, wrappedErr.Unwrap())

	require.Len(t, mockLogger.LoggedMessages, 1)
	assert.Equal(t, "error", mockLogger.LoggedMessages[0].Level)
}

func TestLogAndReturnError(t *testing.T) {
	mockLogger := &MockLogger{}
	ctx := context.Background()

	// Test with nil error
	err := LogAndReturnError(ctx, mockLogger, nil, "test message")
	assert.Nil(t, err)
	assert.Empty(t, mockLogger.LoggedMessages)

	// Test with actual error
	originalErr := errors.New("original error")
	err = LogAndReturnError(ctx, mockLogger, originalErr, "test message")
	assert.Equal(t, originalErr, err)

	require.Len(t, mockLogger.LoggedMessages, 1)
	assert.Equal(t, "error", mockLogger.LoggedMessages[0].Level)
}

func TestMustLogError(t *testing.T) {
	mockLogger := &MockLogger{}
	ctx := context.Background()

	// Test with nil error (should not panic)
	MustLogError(ctx, mockLogger, nil, "test message")
	assert.Empty(t, mockLogger.LoggedMessages)

	// Test with actual error (should panic)
	originalErr := errors.New("original error")

	assert.Panics(t, func() {
		MustLogError(ctx, mockLogger, originalErr, "test message")
	})

	require.Len(t, mockLogger.LoggedMessages, 1)
	assert.Equal(t, "error", mockLogger.LoggedMessages[0].Level)
}

func TestMetricsErrorLogger(t *testing.T) {
	mockLogger := &MockLogger{}
	mockMetrics := &MockErrorMetrics{}

	metricsLogger := NewMetricsErrorLogger(mockLogger, mockMetrics)

	ctx := context.Background()

	metricsLogger.Error(ctx, "error occurred", "error_type", "validation", "error_code", "VALIDATION_ERROR")

	require.Len(t, mockLogger.LoggedMessages, 1)
	assert.Equal(t, "error", mockLogger.LoggedMessages[0].Level)

	assert.Equal(t, 1, mockMetrics.ErrorCounts["validation:VALIDATION_ERROR"])
}

func TestMockErrorReporter(t *testing.T) {
	reporter := &MockErrorReporter{}
	ctx := context.Background()

	err1 := errors.New("error 1")
	err2 := errors.New("error 2")

	_ = reporter.ReportError(ctx, err1)
	_ = reporter.ReportError(ctx, err2)

	require.Len(t, reporter.ReportedErrors, 2)
	assert.Equal(t, err1, reporter.ReportedErrors[0])
	assert.Equal(t, err2, reporter.ReportedErrors[1])
}

func TestMockErrorMetrics(t *testing.T) {
	metrics := &MockErrorMetrics{}

	metrics.IncrementErrorCount("validation", "VALIDATION_ERROR")
	metrics.IncrementErrorCount("validation", "VALIDATION_ERROR")
	metrics.IncrementErrorCount("internal", "INTERNAL_ERROR")

	assert.Equal(t, 2, metrics.ErrorCounts["validation:VALIDATION_ERROR"])
	assert.Equal(t, 1, metrics.ErrorCounts["internal:INTERNAL_ERROR"])

	metrics.RecordErrorLatency("validation", 100.5)
	metrics.RecordErrorLatency("validation", 200.5)

	require.Len(t, metrics.Latencies["validation"], 2)
	assert.Equal(t, 100.5, metrics.Latencies["validation"][0])
	assert.Equal(t, 200.5, metrics.Latencies["validation"][1])
}

func TestLogErrorWithNilLogger(_ *testing.T) {
	ctx := context.Background()
	err := errors.New("test error")

	// Should not panic with nil logger
	LogError(ctx, nil, err)
	LogErrorWithMessage(ctx, nil, err, "test message")
}

func TestDetermineLogLevelFromAppErrorNil(t *testing.T) {
	level := determineLogLevelFromAppError(nil)
	assert.Equal(t, "error", level)
}

func TestExtractLoggingFieldsWithStackTrace(t *testing.T) {
	ctx := context.Background()
	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	fields := extractLoggingFields(ce)

	// Check that stack trace is included
	assert.Contains(t, fields, "stack_trace")

	// Find the stack trace value
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok && key == "stack_trace" {
				if stack, ok := fields[i+1].(string); ok {
					assert.NotEmpty(t, stack)
				}
			}
		}
	}
}
