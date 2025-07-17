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
	"strings"
)

// Logger interface for logging errors. This allows for easy testing and
// different logger implementations.
type Logger interface {
	Error(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Info(ctx context.Context, msg string, args ...any)
	Debug(ctx context.Context, msg string, args ...any)
}

// LogError logs an error with appropriate context and severity level.
func LogError(ctx context.Context, logger Logger, err error) {
	if err == nil || logger == nil {
		return
	}

	// Determine the log level based on error type
	logLevel := determineLogLevel(err)

	// Extract contextual information
	fields := extractLoggingFields(err)

	// Log the error with appropriate level
	switch logLevel {
	case "debug":
		logger.Debug(ctx, "error occurred", fields...)
	case "info":
		logger.Info(ctx, "error occurred", fields...)
	case "warn":
		logger.Warn(ctx, "error occurred", fields...)
	case "error":
		logger.Error(ctx, "error occurred", fields...)
	default:
		logger.Error(ctx, "error occurred", fields...)
	}
}

// LogErrorWithMessage logs an error with a custom message.
func LogErrorWithMessage(ctx context.Context, logger Logger, err error, message string) {
	if err == nil || logger == nil {
		return
	}

	// Determine the log level based on error type
	logLevel := determineLogLevel(err)

	// Extract contextual information
	fields := extractLoggingFields(err)

	// Log the error with appropriate level
	switch logLevel {
	case "debug":
		logger.Debug(ctx, message, fields...)
	case "info":
		logger.Info(ctx, message, fields...)
	case "warn":
		logger.Warn(ctx, message, fields...)
	case "error":
		logger.Error(ctx, message, fields...)
	default:
		logger.Error(ctx, message, fields...)
	}
}

// determineLogLevel determines the appropriate log level for an error.
func determineLogLevel(err error) string {
	if ce, ok := err.(*ContextualError); ok {
		return determineLogLevelFromAppError(ce.AppError)
	}

	if ae, ok := err.(*AppError); ok {
		return determineLogLevelFromAppError(ae)
	}

	// Default to error level for unknown error types
	return "error"
}

// determineLogLevelFromAppError determines the log level from an AppError.
func determineLogLevelFromAppError(appErr *AppError) string {
	if appErr == nil {
		return "error"
	}

	switch appErr.Code {
	case ValidationError:
		return "warn"
	case NotFoundError:
		return "info"
	case ConflictError:
		return "warn"
	case AuthenticationError:
		return "warn"
	case AuthorizationError:
		return "warn"
	case InternalError:
		return "error"
	case ExternalError:
		return "error"
	case RateLimitError:
		return "warn"
	default:
		return "error"
	}
}

// extractLoggingFields extracts structured logging fields from an error.
func extractLoggingFields(err error) []any {
	var fields []any

	if ce, ok := err.(*ContextualError); ok {
		fields = append(fields, "error_type", "contextual_error")
		fields = append(fields, "error_code", string(ce.AppError.Code))
		fields = append(fields, "error_message", ce.AppError.Message)

		if ce.AppError.Details != "" {
			fields = append(fields, "error_details", ce.AppError.Details)
		}

		// Add context information
		if ce.Context != nil {
			if ce.Context.CorrelationID != "" {
				fields = append(fields, "correlation_id", ce.Context.CorrelationID)
			}
			if ce.Context.TraceID != "" {
				fields = append(fields, "trace_id", ce.Context.TraceID)
			}
			if ce.Context.SpanID != "" {
				fields = append(fields, "span_id", ce.Context.SpanID)
			}
			if ce.Context.UserID != "" {
				fields = append(fields, "user_id", ce.Context.UserID)
			}
			if ce.Context.RequestID != "" {
				fields = append(fields, "request_id", ce.Context.RequestID)
			}
			if ce.Context.Component != "" {
				fields = append(fields, "component", ce.Context.Component)
			}
			if ce.Context.Operation != "" {
				fields = append(fields, "operation", ce.Context.Operation)
			}

			// Add timestamp
			fields = append(fields, "error_timestamp", ce.Context.Timestamp)
		}

		// Add metadata
		if len(ce.AppError.Metadata) > 0 {
			for key, value := range ce.AppError.Metadata {
				fields = append(fields, "metadata_"+key, value)
			}
		}

		// Add chain information
		if len(ce.Chain) > 0 {
			var chainMessages []string
			for _, chainErr := range ce.Chain {
				if chainErr != nil {
					chainMessages = append(chainMessages, chainErr.Error())
				}
			}
			if len(chainMessages) > 0 {
				fields = append(fields, "error_chain", strings.Join(chainMessages, " -> "))
			}
		}

		// Add stack trace (first few frames)
		if len(ce.Context.StackTrace) > 0 {
			var stackFrames []string
			for i, frame := range ce.Context.StackTrace {
				if i >= 3 { // Limit to first 3 frames for logging
					break
				}
				stackFrames = append(stackFrames, frame.Function)
			}
			if len(stackFrames) > 0 {
				fields = append(fields, "stack_trace", strings.Join(stackFrames, " -> "))
			}
		}

		return fields
	}

	if ae, ok := err.(*AppError); ok {
		fields = append(fields, "error_type", "app_error")
		fields = append(fields, "error_code", string(ae.Code))
		fields = append(fields, "error_message", ae.Message)

		if ae.Details != "" {
			fields = append(fields, "error_details", ae.Details)
		}

		// Add metadata
		if len(ae.Metadata) > 0 {
			for key, value := range ae.Metadata {
				fields = append(fields, "metadata_"+key, value)
			}
		}

		// Add underlying cause
		if ae.Cause != nil {
			fields = append(fields, "underlying_cause", ae.Cause.Error())
		}

		return fields
	}

	// For regular errors
	fields = append(fields, "error_type", "standard_error")
	fields = append(fields, "error_message", err.Error())

	return fields
}

// ErrorReporter provides functionality to report errors to external systems.
type ErrorReporter interface {
	ReportError(ctx context.Context, err error) error
}

// ReportingErrorLogger wraps a Logger and also reports errors to an external system.
type ReportingErrorLogger struct {
	logger   Logger
	reporter ErrorReporter
}

// NewReportingErrorLogger creates a new reporting error logger.
func NewReportingErrorLogger(logger Logger, reporter ErrorReporter) *ReportingErrorLogger {
	return &ReportingErrorLogger{
		logger:   logger,
		reporter: reporter,
	}
}

// Error logs an error message and reports it to the external system.
func (rel *ReportingErrorLogger) Error(ctx context.Context, msg string, args ...any) {
	rel.logger.Error(ctx, msg, args...)

	// Try to extract error from args for reporting
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			if key, ok := args[i].(string); ok && key == "error" {
				if err, ok := args[i+1].(error); ok {
					_ = rel.reporter.ReportError(ctx, err)
				}
			}
		}
	}
}

// Warn logs a warning message.
func (rel *ReportingErrorLogger) Warn(ctx context.Context, msg string, args ...any) {
	rel.logger.Warn(ctx, msg, args...)
}

// Info logs an info message.
func (rel *ReportingErrorLogger) Info(ctx context.Context, msg string, args ...any) {
	rel.logger.Info(ctx, msg, args...)
}

// Debug logs a debug message.
func (rel *ReportingErrorLogger) Debug(ctx context.Context, msg string, args ...any) {
	rel.logger.Debug(ctx, msg, args...)
}

// MockErrorReporter is a mock implementation of ErrorReporter for testing.
type MockErrorReporter struct {
	ReportedErrors []error
}

// ReportError reports an error (mock implementation).
func (mer *MockErrorReporter) ReportError(_ context.Context, err error) error {
	mer.ReportedErrors = append(mer.ReportedErrors, err)
	return nil
}

// LogAndWrapError logs an error and wraps it with context.
func LogAndWrapError(ctx context.Context, logger Logger, err error, message string) *ContextualError {
	// Log the original error
	LogErrorWithMessage(ctx, logger, err, "error occurred before wrapping")

	// Wrap the error with context
	return WrapWithContext(ctx, err, message)
}

// LogAndReturnError logs an error and returns it (for use in defer statements).
func LogAndReturnError(ctx context.Context, logger Logger, err error, message string) error {
	if err == nil {
		return nil
	}

	LogErrorWithMessage(ctx, logger, err, message)
	return err
}

// MustLogError logs an error and panics if the error is not nil (for critical errors).
func MustLogError(ctx context.Context, logger Logger, err error, message string) {
	if err == nil {
		return
	}

	LogErrorWithMessage(ctx, logger, err, message)
	panic(err)
}

// ErrorMetrics provides metrics collection for errors.
type ErrorMetrics interface {
	IncrementErrorCount(errorType string, errorCode string)
	RecordErrorLatency(errorType string, duration float64)
}

// MetricsErrorLogger wraps a Logger and also collects error metrics.
type MetricsErrorLogger struct {
	logger  Logger
	metrics ErrorMetrics
}

// NewMetricsErrorLogger creates a new metrics error logger.
func NewMetricsErrorLogger(logger Logger, metrics ErrorMetrics) *MetricsErrorLogger {
	return &MetricsErrorLogger{
		logger:  logger,
		metrics: metrics,
	}
}

// Error logs an error message and records metrics.
func (mel *MetricsErrorLogger) Error(ctx context.Context, msg string, args ...any) {
	mel.logger.Error(ctx, msg, args...)

	// Extract error information for metrics
	errorType := "unknown"
	errorCode := "unknown"

	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			if key, ok := args[i].(string); ok {
				if key == "error_type" {
					if val, ok := args[i+1].(string); ok {
						errorType = val
					}
				} else if key == "error_code" {
					if val, ok := args[i+1].(string); ok {
						errorCode = val
					}
				}
			}
		}
	}

	mel.metrics.IncrementErrorCount(errorType, errorCode)
}

// Warn logs a warning message.
func (mel *MetricsErrorLogger) Warn(ctx context.Context, msg string, args ...any) {
	mel.logger.Warn(ctx, msg, args...)
}

// Info logs an info message.
func (mel *MetricsErrorLogger) Info(ctx context.Context, msg string, args ...any) {
	mel.logger.Info(ctx, msg, args...)
}

// Debug logs a debug message.
func (mel *MetricsErrorLogger) Debug(ctx context.Context, msg string, args ...any) {
	mel.logger.Debug(ctx, msg, args...)
}

// MockErrorMetrics is a mock implementation of ErrorMetrics for testing.
type MockErrorMetrics struct {
	ErrorCounts map[string]int
	Latencies   map[string][]float64
}

// IncrementErrorCount increments the error count for a given type and code.
func (mem *MockErrorMetrics) IncrementErrorCount(errorType string, errorCode string) {
	if mem.ErrorCounts == nil {
		mem.ErrorCounts = make(map[string]int)
	}
	key := errorType + ":" + errorCode
	mem.ErrorCounts[key]++
}

// RecordErrorLatency records the latency for a given error type.
func (mem *MockErrorMetrics) RecordErrorLatency(errorType string, duration float64) {
	if mem.Latencies == nil {
		mem.Latencies = make(map[string][]float64)
	}
	mem.Latencies[errorType] = append(mem.Latencies[errorType], duration)
}
