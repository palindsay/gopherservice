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

// Package errors provides custom error types and utilities for structured error handling.
//
// This package defines domain-specific error types that provide consistent error
// messaging and proper gRPC status code mapping. It follows Go best practices
// for error handling while providing rich context for debugging and monitoring.
package errors

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorCode represents different types of application errors.
type ErrorCode string

const (
	// ValidationError represents input validation failures.
	ValidationError ErrorCode = "VALIDATION_ERROR"
	// NotFoundError represents resource not found errors.
	NotFoundError ErrorCode = "NOT_FOUND_ERROR"
	// ConflictError represents resource conflict errors.
	ConflictError ErrorCode = "CONFLICT_ERROR"
	// AuthenticationError represents authentication failures.
	AuthenticationError ErrorCode = "AUTHENTICATION_ERROR"
	// AuthorizationError represents authorization failures.
	AuthorizationError ErrorCode = "AUTHORIZATION_ERROR"
	// InternalError represents internal server errors.
	InternalError ErrorCode = "INTERNAL_ERROR"
	// ExternalError represents external service errors.
	ExternalError ErrorCode = "EXTERNAL_ERROR"
	// RateLimitError represents rate limiting errors.
	RateLimitError ErrorCode = "RATE_LIMIT_ERROR"
)

// AppError represents a structured application error with context.
type AppError struct {
	Code     ErrorCode              `json:"code"`
	Message  string                 `json:"message"`
	Details  string                 `json:"details,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Cause    error                  `json:"-"`
	GRPCCode codes.Code             `json:"-"`
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause of the error.
func (e *AppError) Unwrap() error {
	return e.Cause
}

// ToGRPCStatus converts the AppError to a gRPC status error.
func (e *AppError) ToGRPCStatus() error {
	return status.Error(e.GRPCCode, e.Error())
}

// WithMetadata adds metadata to the error.
func (e *AppError) WithMetadata(key string, value interface{}) *AppError {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// WithCause adds an underlying cause to the error.
func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	return e
}

// NewValidationError creates a new validation error.
func NewValidationError(message string, details ...string) *AppError {
	detail := ""
	if len(details) > 0 {
		detail = details[0]
	}
	return &AppError{
		Code:     ValidationError,
		Message:  message,
		Details:  detail,
		GRPCCode: codes.InvalidArgument,
	}
}

// NewNotFoundError creates a new not found error.
func NewNotFoundError(resource, id string) *AppError {
	return &AppError{
		Code:     NotFoundError,
		Message:  fmt.Sprintf("%s not found", resource),
		Details:  fmt.Sprintf("Resource with ID '%s' does not exist", id),
		GRPCCode: codes.NotFound,
		Metadata: map[string]interface{}{
			"resource_type": resource,
			"resource_id":   id,
		},
	}
}

// NewConflictError creates a new conflict error.
func NewConflictError(resource, id string, reason ...string) *AppError {
	message := fmt.Sprintf("%s already exists", resource)
	detail := fmt.Sprintf("Resource with ID '%s' conflicts with existing resource", id)

	if len(reason) > 0 {
		detail = reason[0]
	}

	return &AppError{
		Code:     ConflictError,
		Message:  message,
		Details:  detail,
		GRPCCode: codes.AlreadyExists,
		Metadata: map[string]interface{}{
			"resource_type": resource,
			"resource_id":   id,
		},
	}
}

// NewAuthenticationError creates a new authentication error.
func NewAuthenticationError(message string, details ...string) *AppError {
	detail := "Invalid or missing authentication credentials"
	if len(details) > 0 {
		detail = details[0]
	}
	return &AppError{
		Code:     AuthenticationError,
		Message:  message,
		Details:  detail,
		GRPCCode: codes.Unauthenticated,
	}
}

// NewAuthorizationError creates a new authorization error.
func NewAuthorizationError(operation string, resource ...string) *AppError {
	message := "Insufficient permissions"
	detail := fmt.Sprintf("User does not have permission to perform '%s'", operation)

	if len(resource) > 0 {
		detail = fmt.Sprintf("User does not have permission to perform '%s' on '%s'", operation, resource[0])
	}

	return &AppError{
		Code:     AuthorizationError,
		Message:  message,
		Details:  detail,
		GRPCCode: codes.PermissionDenied,
		Metadata: map[string]interface{}{
			"operation": operation,
		},
	}
}

// NewInternalError creates a new internal server error.
func NewInternalError(message string, cause error) *AppError {
	return &AppError{
		Code:     InternalError,
		Message:  message,
		Details:  "An internal server error occurred",
		Cause:    cause,
		GRPCCode: codes.Internal,
	}
}

// NewExternalError creates a new external service error.
func NewExternalError(service, operation string, cause error) *AppError {
	return &AppError{
		Code:     ExternalError,
		Message:  fmt.Sprintf("External service '%s' error", service),
		Details:  fmt.Sprintf("Failed to perform '%s' operation", operation),
		Cause:    cause,
		GRPCCode: codes.Unavailable,
		Metadata: map[string]interface{}{
			"external_service": service,
			"operation":        operation,
		},
	}
}

// NewRateLimitError creates a new rate limit error.
func NewRateLimitError(limit int, window string) *AppError {
	return &AppError{
		Code:     RateLimitError,
		Message:  "Rate limit exceeded",
		Details:  fmt.Sprintf("Maximum %d requests per %s exceeded", limit, window),
		GRPCCode: codes.ResourceExhausted,
		Metadata: map[string]interface{}{
			"rate_limit":  limit,
			"time_window": window,
		},
	}
}

// FromGRPCStatus converts a gRPC status error to an AppError.
func FromGRPCStatus(err error) *AppError {
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}

	st, ok := status.FromError(err)
	if !ok {
		return NewInternalError("Unknown error", err)
	}

	var code ErrorCode
	switch st.Code() {
	case codes.InvalidArgument:
		code = ValidationError
	case codes.NotFound:
		code = NotFoundError
	case codes.AlreadyExists:
		code = ConflictError
	case codes.Unauthenticated:
		code = AuthenticationError
	case codes.PermissionDenied:
		code = AuthorizationError
	case codes.ResourceExhausted:
		code = RateLimitError
	case codes.Unavailable:
		code = ExternalError
	default:
		code = InternalError
	}

	return &AppError{
		Code:     code,
		Message:  st.Message(),
		GRPCCode: st.Code(),
		Cause:    err,
	}
}

// WrapError wraps an existing error with additional context.
func WrapError(err error, message string) *AppError {
	if appErr, ok := err.(*AppError); ok {
		return &AppError{
			Code:     appErr.Code,
			Message:  message,
			Details:  appErr.Error(),
			Cause:    appErr,
			GRPCCode: appErr.GRPCCode,
			Metadata: appErr.Metadata,
		}
	}

	return &AppError{
		Code:     InternalError,
		Message:  message,
		Details:  err.Error(),
		Cause:    err,
		GRPCCode: codes.Internal,
	}
}

// IsErrorCode checks if an error has a specific error code.
func IsErrorCode(err error, code ErrorCode) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == code
	}
	return false
}

// IsNotFound checks if an error is a not found error.
func IsNotFound(err error) bool {
	return IsErrorCode(err, NotFoundError)
}

// IsValidation checks if an error is a validation error.
func IsValidation(err error) bool {
	return IsErrorCode(err, ValidationError)
}

// IsConflict checks if an error is a conflict error.
func IsConflict(err error) bool {
	return IsErrorCode(err, ConflictError)
}

// IsAuthentication checks if an error is an authentication error.
func IsAuthentication(err error) bool {
	return IsErrorCode(err, AuthenticationError)
}

// IsAuthorization checks if an error is an authorization error.
func IsAuthorization(err error) bool {
	return IsErrorCode(err, AuthorizationError)
}

// IsInternal checks if an error is an internal error.
func IsInternal(err error) bool {
	return IsErrorCode(err, InternalError)
}
