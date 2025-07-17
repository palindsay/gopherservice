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

// Package log provides enhanced structured logging with correlation IDs,
// OpenTelemetry integration, and context propagation for the application.
//
// This package implements Google's structured logging best practices with
// automatic correlation ID generation, trace/span ID injection, and
// consistent log formatting across all services.
package log

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// loggerKey is the context key for the logger.
	loggerKey = contextKey("logger")
	// correlationIDKey is the context key for correlation IDs.
	correlationIDKey = contextKey("correlation_id")
	// requestIDKey is the context key for request IDs.
	requestIDKey = contextKey("request_id")
	// userIDKey is the context key for user IDs.
	userIDKey = contextKey("user_id")
)

// Config holds configuration for the logger.
type Config struct {
	// Level is the minimum log level to output.
	Level slog.Level
	// Format specifies the output format ("json" or "text").
	Format string
	// ServiceName is the name of the service for log entries.
	ServiceName string
	// ServiceVersion is the version of the service.
	ServiceVersion string
	// Environment is the deployment environment (e.g., "production", "staging").
	Environment string
	// AddSource adds source location information to log entries.
	AddSource bool
	// Output specifies where to write logs (defaults to os.Stdout).
	Output io.Writer
}

// DefaultConfig returns a default configuration for the logger.
func DefaultConfig() *Config {
	return &Config{
		Level:          slog.LevelInfo,
		Format:         "json",
		ServiceName:    "gopherservice",
		ServiceVersion: "1.0.0",
		Environment:    getEnv("ENVIRONMENT", "development"),
		AddSource:      true,
		Output:         os.Stdout,
	}
}

// getEnv gets an environment variable with a default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ConfigFromEnv creates a configuration from environment variables.
func ConfigFromEnv() *Config {
	config := DefaultConfig()

	// Set log level from environment
	if levelStr := os.Getenv("LOG_LEVEL"); levelStr != "" {
		switch strings.ToLower(levelStr) {
		case "debug":
			config.Level = slog.LevelDebug
		case "info":
			config.Level = slog.LevelInfo
		case "warn", "warning":
			config.Level = slog.LevelWarn
		case "error":
			config.Level = slog.LevelError
		}
	}

	// Set format from environment
	if format := os.Getenv("LOG_FORMAT"); format != "" {
		config.Format = format
	}

	// Set service name from environment
	if serviceName := os.Getenv("SERVICE_NAME"); serviceName != "" {
		config.ServiceName = serviceName
	}

	// Set service version from environment
	if serviceVersion := os.Getenv("SERVICE_VERSION"); serviceVersion != "" {
		config.ServiceVersion = serviceVersion
	}

	// Set environment from environment variable
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		config.Environment = env
	}

	return config
}

// Logger wraps slog.Logger with additional functionality.
type Logger struct {
	*slog.Logger
	config *Config
}

// New creates a new enhanced logger with the given configuration.
func New(config *Config) *Logger {
	if config == nil {
		config = DefaultConfig()
	}

	// Create handler options
	opts := &slog.HandlerOptions{
		Level:     config.Level,
		AddSource: config.AddSource,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Customize attribute formatting
			if a.Key == slog.TimeKey {
				// Use RFC3339 format for timestamps
				return slog.Attr{
					Key:   "timestamp",
					Value: slog.StringValue(a.Value.Time().Format(time.RFC3339)),
				}
			}
			if a.Key == slog.LevelKey {
				// Use lowercase level names
				return slog.Attr{
					Key:   "level",
					Value: slog.StringValue(strings.ToLower(a.Value.String())),
				}
			}
			if a.Key == slog.MessageKey {
				return slog.Attr{
					Key:   "message",
					Value: a.Value,
				}
			}
			return a
		},
	}

	// Create the appropriate handler
	var handler slog.Handler
	if config.Format == "text" {
		handler = slog.NewTextHandler(config.Output, opts)
	} else {
		handler = slog.NewJSONHandler(config.Output, opts)
	}

	// Create the logger with service metadata
	logger := slog.New(handler).With(
		"service", config.ServiceName,
		"version", config.ServiceVersion,
		"environment", config.Environment,
	)

	return &Logger{
		Logger: logger,
		config: config,
	}
}

// NewWithDefaults creates a new logger with default configuration.
func NewWithDefaults() *Logger {
	return New(DefaultConfig())
}

// NewFromEnv creates a new logger configured from environment variables.
func NewFromEnv() *Logger {
	return New(ConfigFromEnv())
}

// generateCorrelationID generates a new correlation ID.
func generateCorrelationID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based ID if crypto/rand fails
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// WithCorrelationID adds a correlation ID to the context.
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	if correlationID == "" {
		correlationID = generateCorrelationID()
	}
	return context.WithValue(ctx, correlationIDKey, correlationID)
}

// WithNewCorrelationID generates and adds a new correlation ID to the context.
func WithNewCorrelationID(ctx context.Context) context.Context {
	return WithCorrelationID(ctx, generateCorrelationID())
}

// WithRequestID adds a request ID to the context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// WithUserID adds a user ID to the context.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// CorrelationIDFromContext extracts the correlation ID from the context.
func CorrelationIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return ""
}

// RequestIDFromContext extracts the request ID from the context.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// UserIDFromContext extracts the user ID from the context.
func UserIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(userIDKey).(string); ok {
		return id
	}
	return ""
}

// WithContext returns a new context with the logger embedded.
func (l *Logger) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext returns the logger from the context, or a default logger if none is found.
func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}
	return NewWithDefaults()
}

// WithContext returns a new context with the logger embedded (package-level function).
func WithContext(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// ContextualLogger creates a logger with context-specific fields.
func (l *Logger) ContextualLogger(ctx context.Context) *slog.Logger {
	logger := l.Logger

	// Add correlation ID if present
	if correlationID := CorrelationIDFromContext(ctx); correlationID != "" {
		logger = logger.With("correlation_id", correlationID)
	}

	// Add request ID if present
	if requestID := RequestIDFromContext(ctx); requestID != "" {
		logger = logger.With("request_id", requestID)
	}

	// Add user ID if present
	if userID := UserIDFromContext(ctx); userID != "" {
		logger = logger.With("user_id", userID)
	}

	// Add OpenTelemetry trace and span IDs if present
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		logger = logger.With(
			"trace_id", span.SpanContext().TraceID().String(),
			"span_id", span.SpanContext().SpanID().String(),
		)
	}

	return logger
}

// Debug logs a debug message with context.
func (l *Logger) Debug(ctx context.Context, msg string, args ...any) {
	l.ContextualLogger(ctx).Debug(msg, args...)
}

// Info logs an info message with context.
func (l *Logger) Info(ctx context.Context, msg string, args ...any) {
	l.ContextualLogger(ctx).Info(msg, args...)
}

// Warn logs a warning message with context.
func (l *Logger) Warn(ctx context.Context, msg string, args ...any) {
	l.ContextualLogger(ctx).Warn(msg, args...)
}

// Error logs an error message with context.
func (l *Logger) Error(ctx context.Context, msg string, args ...any) {
	l.ContextualLogger(ctx).Error(msg, args...)
}

// ErrorWithError logs an error message with an error value.
func (l *Logger) ErrorWithError(ctx context.Context, msg string, err error, args ...any) {
	logger := l.ContextualLogger(ctx)
	if err != nil {
		logger = logger.With("error", err.Error())
	}
	logger.Error(msg, args...)
}

// Global logger instance.
var (
	globalLogger *Logger
	globalMu     sync.RWMutex
)

// init initializes the global logger.
func init() {
	globalLogger = NewFromEnv()
}

// SetGlobalLogger sets the global logger instance.
func SetGlobalLogger(logger *Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = logger
}

// GetGlobalLogger returns the global logger instance.
func GetGlobalLogger() *Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogger
}

// Package-level convenience functions using the global logger

// Debug logs a debug message using the global logger.
func Debug(ctx context.Context, msg string, args ...any) {
	GetGlobalLogger().Debug(ctx, msg, args...)
}

// Info logs an info message using the global logger.
func Info(ctx context.Context, msg string, args ...any) {
	GetGlobalLogger().Info(ctx, msg, args...)
}

// Warn logs a warning message using the global logger.
func Warn(ctx context.Context, msg string, args ...any) {
	GetGlobalLogger().Warn(ctx, msg, args...)
}

// Error logs an error message using the global logger.
func Error(ctx context.Context, msg string, args ...any) {
	GetGlobalLogger().Error(ctx, msg, args...)
}

// ErrorWithError logs an error message with an error value using the global logger.
func ErrorWithError(ctx context.Context, msg string, err error, args ...any) {
	GetGlobalLogger().ErrorWithError(ctx, msg, err, args...)
}
