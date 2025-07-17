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
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/plindsay/gopherservice/internal/log"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
)

// ErrorContext provides contextual information about where and when an error occurred.
type ErrorContext struct {
	// Timestamp when the error occurred
	Timestamp time.Time `json:"timestamp"`
	// CorrelationID for tracing across services
	CorrelationID string `json:"correlation_id,omitempty"`
	// TraceID from OpenTelemetry
	TraceID string `json:"trace_id,omitempty"`
	// SpanID from OpenTelemetry
	SpanID string `json:"span_id,omitempty"`
	// UserID if available
	UserID string `json:"user_id,omitempty"`
	// RequestID if available
	RequestID string `json:"request_id,omitempty"`
	// Component where error occurred
	Component string `json:"component,omitempty"`
	// Operation being performed
	Operation string `json:"operation,omitempty"`
	// StackTrace for debugging
	StackTrace []StackFrame `json:"stack_trace,omitempty"`
}

// StackFrame represents a single frame in the stack trace.
type StackFrame struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// captureStackTrace captures the current stack trace.
func captureStackTrace(skip int) []StackFrame {
	var frames []StackFrame

	// Skip additional frames: captureStackTrace + caller
	pcs := make([]uintptr, 32)
	n := runtime.Callers(skip+2, pcs)

	for i := 0; i < n; i++ {
		pc := pcs[i]
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}

		file, line := fn.FileLine(pc)

		// Skip runtime and internal frames, but not test files
		if strings.Contains(file, "runtime/") ||
			(strings.Contains(file, "pkg/errors/") && !strings.Contains(file, "_test.go")) {
			continue
		}

		frames = append(frames, StackFrame{
			Function: fn.Name(),
			File:     file,
			Line:     line,
		})

		// Limit stack trace depth
		if len(frames) >= 10 {
			break
		}
	}

	return frames
}

// NewErrorContext creates a new error context from the given context.
func NewErrorContext(ctx context.Context) *ErrorContext {
	ec := &ErrorContext{
		Timestamp: time.Now(),
	}

	// Extract correlation ID from context
	if correlationID := log.CorrelationIDFromContext(ctx); correlationID != "" {
		ec.CorrelationID = correlationID
	}

	// Extract request ID from context
	if requestID := log.RequestIDFromContext(ctx); requestID != "" {
		ec.RequestID = requestID
	}

	// Extract user ID from context
	if userID := log.UserIDFromContext(ctx); userID != "" {
		ec.UserID = userID
	}

	// Extract OpenTelemetry trace and span IDs
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		ec.TraceID = span.SpanContext().TraceID().String()
		ec.SpanID = span.SpanContext().SpanID().String()
	}

	// Capture stack trace
	ec.StackTrace = captureStackTrace(1)

	return ec
}

// WithComponent adds component information to the error context.
func (ec *ErrorContext) WithComponent(component string) *ErrorContext {
	ec.Component = component
	return ec
}

// WithOperation adds operation information to the error context.
func (ec *ErrorContext) WithOperation(operation string) *ErrorContext {
	ec.Operation = operation
	return ec
}

// String returns a string representation of the error context.
func (ec *ErrorContext) String() string {
	var parts []string

	if ec.Component != "" {
		parts = append(parts, fmt.Sprintf("component=%s", ec.Component))
	}

	if ec.Operation != "" {
		parts = append(parts, fmt.Sprintf("operation=%s", ec.Operation))
	}

	if ec.CorrelationID != "" {
		parts = append(parts, fmt.Sprintf("correlation_id=%s", ec.CorrelationID))
	}

	if ec.TraceID != "" {
		parts = append(parts, fmt.Sprintf("trace_id=%s", ec.TraceID))
	}

	if ec.UserID != "" {
		parts = append(parts, fmt.Sprintf("user_id=%s", ec.UserID))
	}

	if len(parts) == 0 {
		return ""
	}

	return fmt.Sprintf("[%s]", strings.Join(parts, ", "))
}

// StackTraceString returns a formatted stack trace string.
func (ec *ErrorContext) StackTraceString() string {
	if len(ec.StackTrace) == 0 {
		return ""
	}

	var lines []string
	for _, frame := range ec.StackTrace {
		lines = append(lines, fmt.Sprintf("  %s\n    %s:%d",
			frame.Function, frame.File, frame.Line))
	}

	return strings.Join(lines, "\n")
}

// ContextualError extends AppError with additional context information.
type ContextualError struct {
	*AppError
	Context *ErrorContext `json:"context,omitempty"`
	Chain   []error       `json:"-"` // Error chain for unwrapping
}

// Error implements the error interface.
func (ce *ContextualError) Error() string {
	baseError := ce.AppError.Error()
	if ce.Context != nil {
		contextStr := ce.Context.String()
		if contextStr != "" {
			return fmt.Sprintf("%s %s", baseError, contextStr)
		}
	}
	return baseError
}

// Unwrap returns the underlying cause of the error.
func (ce *ContextualError) Unwrap() error {
	if len(ce.Chain) > 0 {
		return ce.Chain[0]
	}
	return ce.AppError.Unwrap()
}

// Is checks if the error matches the target error.
func (ce *ContextualError) Is(target error) bool {
	if ce.AppError == target {
		return true
	}

	for _, err := range ce.Chain {
		if err == target {
			return true
		}
	}

	return false
}

// As finds the first error in the chain that matches the target type.
func (ce *ContextualError) As(target interface{}) bool {
	if ce.AppError != nil {
		switch t := target.(type) {
		case **AppError:
			*t = ce.AppError
			return true
		case **ContextualError:
			*t = ce
			return true
		}
	}

	for _, err := range ce.Chain {
		if err != nil {
			switch t := target.(type) {
			case **AppError:
				if appErr, ok := err.(*AppError); ok {
					*t = appErr
					return true
				}
			case **ContextualError:
				if ctxErr, ok := err.(*ContextualError); ok {
					*t = ctxErr
					return true
				}
			}
		}
	}

	return false
}

// AddToChain adds an error to the error chain.
func (ce *ContextualError) AddToChain(err error) *ContextualError {
	if err != nil {
		ce.Chain = append(ce.Chain, err)
	}
	return ce
}

// GetChain returns the complete error chain.
func (ce *ContextualError) GetChain() []error {
	return ce.Chain
}

// NewContextualError creates a new contextual error.
func NewContextualError(ctx context.Context, appErr *AppError) *ContextualError {
	return &ContextualError{
		AppError: appErr,
		Context:  NewErrorContext(ctx),
		Chain:    make([]error, 0),
	}
}

// WrapWithContext wraps an error with contextual information.
func WrapWithContext(ctx context.Context, err error, message string) *ContextualError {
	var appErr *AppError

	if contextualErr, ok := err.(*ContextualError); ok {
		// If it's already a contextual error, create a new one with the same context
		// but add the original to the chain
		appErr = &AppError{
			Code:     contextualErr.AppError.Code,
			Message:  message,
			Details:  contextualErr.AppError.Error(),
			Cause:    err,
			GRPCCode: contextualErr.AppError.GRPCCode,
			Metadata: contextualErr.AppError.Metadata,
		}

		ce := NewContextualError(ctx, appErr)
		return ce.AddToChain(err)
	}

	if ae, ok := err.(*AppError); ok {
		appErr = &AppError{
			Code:     ae.Code,
			Message:  message,
			Details:  ae.Error(),
			Cause:    err,
			GRPCCode: ae.GRPCCode,
			Metadata: ae.Metadata,
		}
	} else {
		appErr = &AppError{
			Code:     InternalError,
			Message:  message,
			Details:  err.Error(),
			Cause:    err,
			GRPCCode: codes.Internal,
		}
	}

	ce := NewContextualError(ctx, appErr)
	return ce.AddToChain(err)
}

// NewContextualValidationError creates a new contextual validation error.
func NewContextualValidationError(ctx context.Context, message string, details ...string) *ContextualError {
	appErr := NewValidationError(message, details...)
	return NewContextualError(ctx, appErr)
}

// NewContextualNotFoundError creates a new contextual not found error.
func NewContextualNotFoundError(ctx context.Context, resource, id string) *ContextualError {
	appErr := NewNotFoundError(resource, id)
	return NewContextualError(ctx, appErr)
}

// NewContextualConflictError creates a new contextual conflict error.
func NewContextualConflictError(ctx context.Context, resource, id string, reason ...string) *ContextualError {
	appErr := NewConflictError(resource, id, reason...)
	return NewContextualError(ctx, appErr)
}

// NewContextualAuthenticationError creates a new contextual authentication error.
func NewContextualAuthenticationError(ctx context.Context, message string, details ...string) *ContextualError {
	appErr := NewAuthenticationError(message, details...)
	return NewContextualError(ctx, appErr)
}

// NewContextualAuthorizationError creates a new contextual authorization error.
func NewContextualAuthorizationError(ctx context.Context, operation string, resource ...string) *ContextualError {
	appErr := NewAuthorizationError(operation, resource...)
	return NewContextualError(ctx, appErr)
}

// NewContextualInternalError creates a new contextual internal error.
func NewContextualInternalError(ctx context.Context, message string, cause error) *ContextualError {
	appErr := NewInternalError(message, cause)
	ce := NewContextualError(ctx, appErr)
	if cause != nil {
		return ce.AddToChain(cause)
	}
	return ce
}

// NewContextualExternalError creates a new contextual external error.
func NewContextualExternalError(ctx context.Context, service, operation string, cause error) *ContextualError {
	appErr := NewExternalError(service, operation, cause)
	ce := NewContextualError(ctx, appErr)
	if cause != nil {
		return ce.AddToChain(cause)
	}
	return ce
}

// NewContextualRateLimitError creates a new contextual rate limit error.
func NewContextualRateLimitError(ctx context.Context, limit int, window string) *ContextualError {
	appErr := NewRateLimitError(limit, window)
	return NewContextualError(ctx, appErr)
}

// ErrorChain represents a chain of errors for better error analysis.
type ErrorChain struct {
	errors []error
}

// NewErrorChain creates a new error chain.
func NewErrorChain() *ErrorChain {
	return &ErrorChain{
		errors: make([]error, 0),
	}
}

// Add adds an error to the chain.
func (ec *ErrorChain) Add(err error) *ErrorChain {
	if err != nil {
		ec.errors = append(ec.errors, err)
	}
	return ec
}

// Errors returns all errors in the chain.
func (ec *ErrorChain) Errors() []error {
	return ec.errors
}

// HasErrors returns true if the chain has any errors.
func (ec *ErrorChain) HasErrors() bool {
	return len(ec.errors) > 0
}

// First returns the first error in the chain.
func (ec *ErrorChain) First() error {
	if len(ec.errors) == 0 {
		return nil
	}
	return ec.errors[0]
}

// Last returns the last error in the chain.
func (ec *ErrorChain) Last() error {
	if len(ec.errors) == 0 {
		return nil
	}
	return ec.errors[len(ec.errors)-1]
}

// Error implements the error interface.
func (ec *ErrorChain) Error() string {
	if len(ec.errors) == 0 {
		return ""
	}

	if len(ec.errors) == 1 {
		return ec.errors[0].Error()
	}

	var messages []string
	for i, err := range ec.errors {
		messages = append(messages, fmt.Sprintf("%d: %s", i+1, err.Error()))
	}

	return fmt.Sprintf("Multiple errors occurred:\n%s", strings.Join(messages, "\n"))
}

// ToContextualError converts the error chain to a contextual error.
func (ec *ErrorChain) ToContextualError(ctx context.Context, message string) *ContextualError {
	if len(ec.errors) == 0 {
		return NewContextualInternalError(ctx, message, nil)
	}

	// Use the first error as the base
	baseErr := ec.errors[0]
	var appErr *AppError

	if ae, ok := baseErr.(*AppError); ok {
		appErr = ae
	} else if ce, ok := baseErr.(*ContextualError); ok {
		appErr = ce.AppError
	} else {
		appErr = NewInternalError(message, baseErr)
	}

	ctxErr := NewContextualError(ctx, appErr)

	// Add all errors to the chain
	for _, err := range ec.errors {
		ctxErr = ctxErr.AddToChain(err)
	}

	return ctxErr
}

// FormatError formats an error for display with optional stack trace.
func FormatError(err error, includeStackTrace bool) string {
	if err == nil {
		return ""
	}

	if ce, ok := err.(*ContextualError); ok {
		result := ce.Error()

		if includeStackTrace && ce.Context != nil {
			stackTrace := ce.Context.StackTraceString()
			if stackTrace != "" {
				result += "\n\nStack trace:\n" + stackTrace
			}
		}

		return result
	}

	return err.Error()
}

// ExtractCorrelationID extracts the correlation ID from an error.
func ExtractCorrelationID(err error) string {
	if ce, ok := err.(*ContextualError); ok && ce.Context != nil {
		return ce.Context.CorrelationID
	}
	return ""
}

// ExtractTraceID extracts the trace ID from an error.
func ExtractTraceID(err error) string {
	if ce, ok := err.(*ContextualError); ok && ce.Context != nil {
		return ce.Context.TraceID
	}
	return ""
}

// ExtractUserID extracts the user ID from an error.
func ExtractUserID(err error) string {
	if ce, ok := err.(*ContextualError); ok && ce.Context != nil {
		return ce.Context.UserID
	}
	return ""
}
