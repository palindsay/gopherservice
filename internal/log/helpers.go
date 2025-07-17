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
	"context"
	"log/slog"
	"time"
)

// OperationLogger provides structured logging for operations with timing and status.
type OperationLogger struct {
	logger    *Logger
	operation string
	startTime time.Time
	fields    []any
}

// StartOperation starts logging an operation with timing information.
func (l *Logger) StartOperation(ctx context.Context, operation string, fields ...any) *OperationLogger {
	op := &OperationLogger{
		logger:    l,
		operation: operation,
		startTime: time.Now(),
		fields:    fields,
	}

	// Log operation start
	op.logger.Info(ctx, "operation started", append([]any{
		"operation", operation,
		"start_time", op.startTime.Format(time.RFC3339),
	}, fields...)...)

	return op
}

// Complete completes the operation with success status.
func (op *OperationLogger) Complete(ctx context.Context, fields ...any) {
	duration := time.Since(op.startTime)

	allFields := append([]any{
		"operation", op.operation,
		"status", "success",
		"duration_ms", duration.Milliseconds(),
		"duration", duration.String(),
	}, op.fields...)
	allFields = append(allFields, fields...)

	op.logger.Info(ctx, "operation completed", allFields...)
}

// Fail completes the operation with failure status.
func (op *OperationLogger) Fail(ctx context.Context, err error, fields ...any) {
	duration := time.Since(op.startTime)

	allFields := append([]any{
		"operation", op.operation,
		"status", "failed",
		"duration_ms", duration.Milliseconds(),
		"duration", duration.String(),
	}, op.fields...)
	allFields = append(allFields, fields...)

	op.logger.ErrorWithError(ctx, "operation failed", err, allFields...)
}

// Progress logs progress during the operation.
func (op *OperationLogger) Progress(ctx context.Context, message string, fields ...any) {
	duration := time.Since(op.startTime)

	allFields := append([]any{
		"operation", op.operation,
		"progress", message,
		"elapsed_ms", duration.Milliseconds(),
	}, op.fields...)
	allFields = append(allFields, fields...)

	op.logger.Info(ctx, "operation progress", allFields...)
}

// RequestLogger provides structured logging for HTTP/gRPC requests.
type RequestLogger struct {
	logger    *Logger
	method    string
	path      string
	startTime time.Time
	fields    []any
}

// StartRequest starts logging a request with timing and metadata.
func (l *Logger) StartRequest(ctx context.Context, method, path string, fields ...any) *RequestLogger {
	req := &RequestLogger{
		logger:    l,
		method:    method,
		path:      path,
		startTime: time.Now(),
		fields:    fields,
	}

	// Log request start
	req.logger.Info(ctx, "request started", append([]any{
		"method", method,
		"path", path,
		"start_time", req.startTime.Format(time.RFC3339),
	}, fields...)...)

	return req
}

// Complete completes the request with status code and response information.
func (req *RequestLogger) Complete(ctx context.Context, statusCode int, responseSize int64, fields ...any) {
	duration := time.Since(req.startTime)

	allFields := append([]any{
		"method", req.method,
		"path", req.path,
		"status_code", statusCode,
		"response_size", responseSize,
		"duration_ms", duration.Milliseconds(),
		"duration", duration.String(),
	}, req.fields...)
	allFields = append(allFields, fields...)

	// Use appropriate log level based on status code
	if statusCode >= 500 {
		req.logger.Error(ctx, "request completed with server error", allFields...)
	} else if statusCode >= 400 {
		req.logger.Warn(ctx, "request completed with client error", allFields...)
	} else {
		req.logger.Info(ctx, "request completed", allFields...)
	}
}

// Fail completes the request with an error.
func (req *RequestLogger) Fail(ctx context.Context, err error, fields ...any) {
	duration := time.Since(req.startTime)

	allFields := append([]any{
		"method", req.method,
		"path", req.path,
		"duration_ms", duration.Milliseconds(),
		"duration", duration.String(),
	}, req.fields...)
	allFields = append(allFields, fields...)

	req.logger.ErrorWithError(ctx, "request failed", err, allFields...)
}

// DatabaseLogger provides structured logging for database operations.
type DatabaseLogger struct {
	logger    *Logger
	query     string
	table     string
	startTime time.Time
	fields    []any
}

// StartDatabaseOperation starts logging a database operation.
func (l *Logger) StartDatabaseOperation(ctx context.Context, operation, table string, fields ...any) *DatabaseLogger {
	db := &DatabaseLogger{
		logger:    l,
		query:     operation,
		table:     table,
		startTime: time.Now(),
		fields:    fields,
	}

	// Log database operation start
	db.logger.Debug(ctx, "database operation started", append([]any{
		"db_operation", operation,
		"db_table", table,
		"start_time", db.startTime.Format(time.RFC3339),
	}, fields...)...)

	return db
}

// Complete completes the database operation with result information.
func (db *DatabaseLogger) Complete(ctx context.Context, rowsAffected int64, fields ...any) {
	duration := time.Since(db.startTime)

	allFields := append([]any{
		"db_operation", db.query,
		"db_table", db.table,
		"rows_affected", rowsAffected,
		"duration_ms", duration.Milliseconds(),
		"duration", duration.String(),
	}, db.fields...)
	allFields = append(allFields, fields...)

	db.logger.Debug(ctx, "database operation completed", allFields...)
}

// Fail completes the database operation with an error.
func (db *DatabaseLogger) Fail(ctx context.Context, err error, fields ...any) {
	duration := time.Since(db.startTime)

	allFields := append([]any{
		"db_operation", db.query,
		"db_table", db.table,
		"duration_ms", duration.Milliseconds(),
		"duration", duration.String(),
	}, db.fields...)
	allFields = append(allFields, fields...)

	db.logger.ErrorWithError(ctx, "database operation failed", err, allFields...)
}

// AuthenticationLogger provides structured logging for authentication events.
type AuthenticationLogger struct {
	logger *Logger
}

// NewAuthenticationLogger creates a new authentication logger.
func (l *Logger) NewAuthenticationLogger() *AuthenticationLogger {
	return &AuthenticationLogger{logger: l}
}

// LoginAttempt logs a login attempt.
func (auth *AuthenticationLogger) LoginAttempt(ctx context.Context, email, ipAddress string, userAgent string) {
	auth.logger.Info(ctx, "login attempt",
		"email", email,
		"ip_address", ipAddress,
		"user_agent", userAgent,
		"event_type", "login_attempt",
	)
}

// LoginSuccess logs a successful login.
func (auth *AuthenticationLogger) LoginSuccess(ctx context.Context, userID, email, ipAddress string, userAgent string) {
	auth.logger.Info(ctx, "login successful",
		"user_id", userID,
		"email", email,
		"ip_address", ipAddress,
		"user_agent", userAgent,
		"event_type", "login_success",
	)
}

// LoginFailure logs a failed login attempt.
func (auth *AuthenticationLogger) LoginFailure(ctx context.Context, email, ipAddress string, userAgent, reason string) {
	auth.logger.Warn(ctx, "login failed",
		"email", email,
		"ip_address", ipAddress,
		"user_agent", userAgent,
		"failure_reason", reason,
		"event_type", "login_failure",
	)
}

// TokenGenerated logs token generation.
func (auth *AuthenticationLogger) TokenGenerated(ctx context.Context, userID, tokenType string, expiresAt time.Time) {
	auth.logger.Info(ctx, "token generated",
		"user_id", userID,
		"token_type", tokenType,
		"expires_at", expiresAt.Format(time.RFC3339),
		"event_type", "token_generated",
	)
}

// TokenRevoked logs token revocation.
func (auth *AuthenticationLogger) TokenRevoked(ctx context.Context, userID, tokenType, reason string) {
	auth.logger.Info(ctx, "token revoked",
		"user_id", userID,
		"token_type", tokenType,
		"reason", reason,
		"event_type", "token_revoked",
	)
}

// SecurityEvent logs security-related events.
func (auth *AuthenticationLogger) SecurityEvent(ctx context.Context, eventType, description string, fields ...any) {
	allFields := append([]any{
		"event_type", eventType,
		"description", description,
		"security_event", true,
	}, fields...)

	auth.logger.Warn(ctx, "security event", allFields...)
}

// BusinessLogger provides structured logging for business logic events.
type BusinessLogger struct {
	logger *Logger
	domain string
}

// NewBusinessLogger creates a new business logger for a specific domain.
func (l *Logger) NewBusinessLogger(domain string) *BusinessLogger {
	return &BusinessLogger{
		logger: l,
		domain: domain,
	}
}

// EntityCreated logs entity creation.
func (biz *BusinessLogger) EntityCreated(ctx context.Context, entityType, entityID string, fields ...any) {
	allFields := append([]any{
		"domain", biz.domain,
		"entity_type", entityType,
		"entity_id", entityID,
		"action", "created",
	}, fields...)

	biz.logger.Info(ctx, "entity created", allFields...)
}

// EntityUpdated logs entity updates.
func (biz *BusinessLogger) EntityUpdated(ctx context.Context, entityType, entityID string, changedFields []string, fields ...any) {
	allFields := append([]any{
		"domain", biz.domain,
		"entity_type", entityType,
		"entity_id", entityID,
		"action", "updated",
		"changed_fields", changedFields,
	}, fields...)

	biz.logger.Info(ctx, "entity updated", allFields...)
}

// EntityDeleted logs entity deletion.
func (biz *BusinessLogger) EntityDeleted(ctx context.Context, entityType, entityID string, fields ...any) {
	allFields := append([]any{
		"domain", biz.domain,
		"entity_type", entityType,
		"entity_id", entityID,
		"action", "deleted",
	}, fields...)

	biz.logger.Info(ctx, "entity deleted", allFields...)
}

// BusinessRule logs business rule enforcement.
func (biz *BusinessLogger) BusinessRule(ctx context.Context, ruleName string, passed bool, description string, fields ...any) {
	allFields := append([]any{
		"domain", biz.domain,
		"rule_name", ruleName,
		"rule_passed", passed,
		"description", description,
	}, fields...)

	if passed {
		biz.logger.Debug(ctx, "business rule passed", allFields...)
	} else {
		biz.logger.Warn(ctx, "business rule violated", allFields...)
	}
}

// PerformanceLogger provides structured logging for performance metrics.
type PerformanceLogger struct {
	logger *Logger
}

// NewPerformanceLogger creates a new performance logger.
func (l *Logger) NewPerformanceLogger() *PerformanceLogger {
	return &PerformanceLogger{logger: l}
}

// SlowQuery logs slow database queries.
func (perf *PerformanceLogger) SlowQuery(ctx context.Context, query string, duration time.Duration, threshold time.Duration) {
	perf.logger.Warn(ctx, "slow query detected",
		"query", query,
		"duration_ms", duration.Milliseconds(),
		"threshold_ms", threshold.Milliseconds(),
		"performance_issue", true,
	)
}

// HighMemoryUsage logs high memory usage.
func (perf *PerformanceLogger) HighMemoryUsage(ctx context.Context, currentMB, limitMB int64) {
	perf.logger.Warn(ctx, "high memory usage detected",
		"current_memory_mb", currentMB,
		"limit_memory_mb", limitMB,
		"memory_usage_percent", float64(currentMB)/float64(limitMB)*100,
		"performance_issue", true,
	)
}

// HighCPUUsage logs high CPU usage.
func (perf *PerformanceLogger) HighCPUUsage(ctx context.Context, cpuPercent float64, threshold float64) {
	perf.logger.Warn(ctx, "high CPU usage detected",
		"cpu_percent", cpuPercent,
		"threshold_percent", threshold,
		"performance_issue", true,
	)
}

// Package-level helper functions for common logging patterns

// LogPanic logs and recovers from panics.
func LogPanic(ctx context.Context, logger *Logger) { // nolint: revive
	if r := recover(); r != nil {
		logger.Error(ctx, "panic recovered",
			"panic_value", r,
			"recovered", true,
		)
	}
}

// LogPanicWithCallback logs and recovers from panics with a callback.
func LogPanicWithCallback(ctx context.Context, logger *Logger, callback func()) { // nolint: revive
	if r := recover(); r != nil {
		logger.Error(ctx, "panic recovered",
			"panic_value", r,
			"recovered", true,
		)
		if callback != nil {
			callback()
		}
	}
}

// WithFields creates a logger with predefined fields.
func WithFields(logger *Logger, fields ...any) *slog.Logger {
	return logger.Logger.With(fields...)
}

// WithUserContext creates a logger with user context information.
func WithUserContext(logger *Logger, userID, email string, roles []string) *slog.Logger {
	return logger.Logger.With(
		"user_id", userID,
		"user_email", email,
		"user_roles", roles,
	)
}

// WithRequestContext creates a logger with request context information.
func WithRequestContext(logger *Logger, method, path, remoteAddr string) *slog.Logger {
	return logger.Logger.With(
		"method", method,
		"path", path,
		"remote_addr", remoteAddr,
	)
}
