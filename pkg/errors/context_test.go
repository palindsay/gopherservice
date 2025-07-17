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
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestNewErrorContext(t *testing.T) {
	ctx := context.Background()

	// Add context values
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")
	ctx = log.WithRequestID(ctx, "test-request-id")
	ctx = log.WithUserID(ctx, "test-user-id")

	ec := NewErrorContext(ctx)
	require.NotNil(t, ec)

	assert.Equal(t, "test-correlation-id", ec.CorrelationID)
	assert.Equal(t, "test-request-id", ec.RequestID)
	assert.Equal(t, "test-user-id", ec.UserID)
	assert.NotZero(t, ec.Timestamp)
	assert.NotEmpty(t, ec.StackTrace)
}

func TestNewErrorContextWithTrace(t *testing.T) {
	// Set up a tracer provider
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)

	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-operation")
	defer span.End()

	ec := NewErrorContext(ctx)
	require.NotNil(t, ec)

	// Check that trace and span IDs are captured
	assert.NotEmpty(t, ec.TraceID)
	assert.NotEmpty(t, ec.SpanID)
}

func TestErrorContextWithComponent(t *testing.T) {
	ctx := context.Background()
	ec := NewErrorContext(ctx)

	ec = ec.WithComponent("test-component")
	assert.Equal(t, "test-component", ec.Component)
}

func TestErrorContextWithOperation(t *testing.T) {
	ctx := context.Background()
	ec := NewErrorContext(ctx)

	ec = ec.WithOperation("test-operation")
	assert.Equal(t, "test-operation", ec.Operation)
}

func TestErrorContextString(t *testing.T) {
	ctx := context.Background()
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")

	ec := NewErrorContext(ctx)
	ec = ec.WithComponent("test-component").WithOperation("test-operation")

	str := ec.String()
	assert.Contains(t, str, "component=test-component")
	assert.Contains(t, str, "operation=test-operation")
	assert.Contains(t, str, "correlation_id=test-correlation-id")
}

func TestErrorContextStackTrace(t *testing.T) {
	ctx := context.Background()
	ec := NewErrorContext(ctx)

	stackTrace := ec.StackTraceString()
	assert.NotEmpty(t, stackTrace)
	assert.Contains(t, stackTrace, "TestErrorContextStackTrace")
}

func TestContextualError(t *testing.T) {
	ctx := context.Background()
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")

	appErr := NewValidationError("test validation error", "test details")
	ce := NewContextualError(ctx, appErr)

	require.NotNil(t, ce)
	assert.Equal(t, appErr, ce.AppError)
	assert.NotNil(t, ce.Context)
	assert.Equal(t, "test-correlation-id", ce.Context.CorrelationID)
	assert.Contains(t, ce.Error(), "test validation error")
	assert.Contains(t, ce.Error(), "correlation_id=test-correlation-id")
}

func TestContextualErrorUnwrap(t *testing.T) {
	ctx := context.Background()
	cause := errors.New("underlying cause")

	appErr := NewInternalError("test internal error", cause)
	ce := NewContextualError(ctx, appErr)
	_ = ce.AddToChain(cause)

	unwrapped := ce.Unwrap()
	assert.Equal(t, cause, unwrapped)
}

func TestContextualErrorIs(t *testing.T) {
	ctx := context.Background()
	cause := errors.New("underlying cause")

	appErr := NewInternalError("test internal error", cause)
	ce := NewContextualError(ctx, appErr)
	_ = ce.AddToChain(cause)

	assert.True(t, ce.Is(cause))
	assert.True(t, ce.Is(appErr))
	assert.False(t, ce.Is(errors.New("different error")))
}

func TestContextualErrorAs(t *testing.T) {
	ctx := context.Background()
	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	var target *AppError
	assert.True(t, ce.As(&target))
	assert.Equal(t, appErr, target)

	var ctxTarget *ContextualError
	assert.True(t, ce.As(&ctxTarget))
	assert.Equal(t, ce, ctxTarget)
}

func TestWrapWithContext(t *testing.T) {
	ctx := context.Background()
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")

	originalErr := errors.New("original error")

	ce := WrapWithContext(ctx, originalErr, "wrapped error")
	require.NotNil(t, ce)

	assert.Contains(t, ce.Error(), "wrapped error")
	assert.Contains(t, ce.Error(), "correlation_id=test-correlation-id")
	assert.Equal(t, originalErr, ce.Unwrap())
	assert.Len(t, ce.Chain, 1)
	assert.Equal(t, originalErr, ce.Chain[0])
}

func TestWrapWithContextAppError(t *testing.T) {
	ctx := context.Background()

	appErr := NewValidationError("original validation error")
	ce := WrapWithContext(ctx, appErr, "wrapped validation error")

	require.NotNil(t, ce)
	assert.Equal(t, ValidationError, ce.AppError.Code)
	assert.Contains(t, ce.Error(), "wrapped validation error")
	assert.Len(t, ce.Chain, 1)
	assert.Equal(t, appErr, ce.Chain[0])
}

func TestWrapWithContextContextualError(t *testing.T) {
	ctx := context.Background()

	appErr := NewValidationError("original validation error")
	originalCe := NewContextualError(ctx, appErr)

	wrappedCe := WrapWithContext(ctx, originalCe, "wrapped contextual error")

	require.NotNil(t, wrappedCe)
	assert.Equal(t, ValidationError, wrappedCe.AppError.Code)
	assert.Contains(t, wrappedCe.Error(), "wrapped contextual error")
	assert.Len(t, wrappedCe.Chain, 1)
	assert.Equal(t, originalCe, wrappedCe.Chain[0])
}

func TestContextualErrorConstructors(t *testing.T) {
	ctx := context.Background()
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")

	// Test all contextual error constructors
	validationErr := NewContextualValidationError(ctx, "validation error", "details")
	assert.Equal(t, ValidationError, validationErr.AppError.Code)
	assert.Equal(t, "test-correlation-id", validationErr.Context.CorrelationID)

	notFoundErr := NewContextualNotFoundError(ctx, "user", "123")
	assert.Equal(t, NotFoundError, notFoundErr.AppError.Code)
	assert.Equal(t, "test-correlation-id", notFoundErr.Context.CorrelationID)

	conflictErr := NewContextualConflictError(ctx, "user", "123", "email already exists")
	assert.Equal(t, ConflictError, conflictErr.AppError.Code)
	assert.Equal(t, "test-correlation-id", conflictErr.Context.CorrelationID)

	authErr := NewContextualAuthenticationError(ctx, "auth error", "invalid token")
	assert.Equal(t, AuthenticationError, authErr.AppError.Code)
	assert.Equal(t, "test-correlation-id", authErr.Context.CorrelationID)

	authzErr := NewContextualAuthorizationError(ctx, "read", "user")
	assert.Equal(t, AuthorizationError, authzErr.AppError.Code)
	assert.Equal(t, "test-correlation-id", authzErr.Context.CorrelationID)

	cause := errors.New("underlying cause")
	internalErr := NewContextualInternalError(ctx, "internal error", cause)
	assert.Equal(t, InternalError, internalErr.AppError.Code)
	assert.Equal(t, "test-correlation-id", internalErr.Context.CorrelationID)
	assert.Len(t, internalErr.Chain, 1)
	assert.Equal(t, cause, internalErr.Chain[0])

	externalErr := NewContextualExternalError(ctx, "external-service", "get-user", cause)
	assert.Equal(t, ExternalError, externalErr.AppError.Code)
	assert.Equal(t, "test-correlation-id", externalErr.Context.CorrelationID)
	assert.Len(t, externalErr.Chain, 1)
	assert.Equal(t, cause, externalErr.Chain[0])

	rateLimitErr := NewContextualRateLimitError(ctx, 100, "minute")
	assert.Equal(t, RateLimitError, rateLimitErr.AppError.Code)
	assert.Equal(t, "test-correlation-id", rateLimitErr.Context.CorrelationID)
}

func TestErrorChain(t *testing.T) {
	ec := NewErrorChain()
	require.NotNil(t, ec)

	assert.False(t, ec.HasErrors())
	assert.Nil(t, ec.First())
	assert.Nil(t, ec.Last())
	assert.Empty(t, ec.Error())

	err1 := errors.New("error 1")
	err2 := errors.New("error 2")
	err3 := errors.New("error 3")

	_ = ec.Add(err1).Add(err2).Add(err3)

	assert.True(t, ec.HasErrors())
	assert.Equal(t, err1, ec.First())
	assert.Equal(t, err3, ec.Last())
	assert.Len(t, ec.Errors(), 3)

	errorStr := ec.Error()
	assert.Contains(t, errorStr, "error 1")
	assert.Contains(t, errorStr, "error 2")
	assert.Contains(t, errorStr, "error 3")
}

func TestErrorChainToContextualError(t *testing.T) {
	ctx := context.Background()
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")

	ec := NewErrorChain()
	err1 := errors.New("error 1")
	err2 := errors.New("error 2")

	ec.Add(err1).Add(err2) // nolint: errcheck

	ce := ec.ToContextualError(ctx, "multiple errors occurred")
	require.NotNil(t, ce)

	assert.Equal(t, InternalError, ce.AppError.Code)
	assert.Equal(t, "test-correlation-id", ce.Context.CorrelationID)
	assert.Len(t, ce.Chain, 2)
	assert.Equal(t, err1, ce.Chain[0])
	assert.Equal(t, err2, ce.Chain[1])
}

func TestErrorChainEmpty(t *testing.T) {
	ctx := context.Background()
	ec := NewErrorChain()

	ce := ec.ToContextualError(ctx, "no errors")
	require.NotNil(t, ce)

	assert.Equal(t, InternalError, ce.AppError.Code)
	assert.Contains(t, ce.Error(), "no errors")
	assert.Empty(t, ce.Chain)
}

func TestFormatError(t *testing.T) {
	ctx := context.Background()
	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	// Test without stack trace
	formatted := FormatError(ce, false)
	assert.Contains(t, formatted, "test validation error")
	assert.NotContains(t, formatted, "Stack trace:")

	// Test with stack trace
	formatted = FormatError(ce, true)
	assert.Contains(t, formatted, "test validation error")
	assert.Contains(t, formatted, "Stack trace:")
}

func TestFormatErrorNil(t *testing.T) {
	formatted := FormatError(nil, true)
	assert.Empty(t, formatted)
}

func TestFormatErrorRegular(t *testing.T) {
	err := errors.New("regular error")
	formatted := FormatError(err, true)
	assert.Equal(t, "regular error", formatted)
}

func TestExtractCorrelationID(t *testing.T) {
	ctx := context.Background()
	ctx = log.WithCorrelationID(ctx, "test-correlation-id")

	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	correlationID := ExtractCorrelationID(ce)
	assert.Equal(t, "test-correlation-id", correlationID)

	// Test with regular error
	correlationID = ExtractCorrelationID(errors.New("regular error"))
	assert.Empty(t, correlationID)
}

func TestExtractTraceID(t *testing.T) {
	// Set up a tracer provider
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)

	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-operation")
	defer span.End()

	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	traceID := ExtractTraceID(ce)
	assert.NotEmpty(t, traceID)

	// Test with regular error
	traceID = ExtractTraceID(errors.New("regular error"))
	assert.Empty(t, traceID)
}

func TestExtractUserID(t *testing.T) {
	ctx := context.Background()
	ctx = log.WithUserID(ctx, "test-user-id")

	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	userID := ExtractUserID(ce)
	assert.Equal(t, "test-user-id", userID)

	// Test with regular error
	userID = ExtractUserID(errors.New("regular error"))
	assert.Empty(t, userID)
}

func TestStackFrameCapture(t *testing.T) {
	frames := captureStackTrace(0)
	assert.NotEmpty(t, frames)

	// Check that at least one frame contains this test function
	found := false
	for _, frame := range frames {
		if frame.Function != "" && frame.Line > 0 {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestContextualErrorChainManipulation(t *testing.T) {
	ctx := context.Background()
	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	err1 := errors.New("error 1")
	err2 := errors.New("error 2")

	ce.AddToChain(err1).AddToChain(err2) // nolint: errcheck

	chain := ce.GetChain()
	assert.Len(t, chain, 2)
	assert.Equal(t, err1, chain[0])
	assert.Equal(t, err2, chain[1])
}

func TestContextualErrorChainNilHandling(t *testing.T) {
	ctx := context.Background()
	appErr := NewValidationError("test validation error")
	ce := NewContextualError(ctx, appErr)

	// Adding nil should not crash
	_ = ce.AddToChain(nil)

	chain := ce.GetChain()
	assert.Empty(t, chain)
}

func TestNewErrorContextEmptyContext(t *testing.T) {
	ctx := context.Background()
	ec := NewErrorContext(ctx)

	require.NotNil(t, ec)
	assert.Empty(t, ec.CorrelationID)
	assert.Empty(t, ec.RequestID)
	assert.Empty(t, ec.UserID)
	assert.Empty(t, ec.TraceID)
	assert.Empty(t, ec.SpanID)
	assert.NotZero(t, ec.Timestamp)
}

func TestErrorContextStringEmpty(t *testing.T) {
	ctx := context.Background()
	ec := NewErrorContext(ctx)

	str := ec.String()
	assert.Empty(t, str)
}

func TestErrorContextStackTraceEmpty(t *testing.T) {
	ec := &ErrorContext{
		StackTrace: []StackFrame{},
	}

	stackTrace := ec.StackTraceString()
	assert.Empty(t, stackTrace)
}
