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

// Package errors_test provides tests for the errors package.
package errors_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apperrors "github.com/plindsay/gopherservice/pkg/errors"
)

func TestNewValidationError(t *testing.T) {
	err := apperrors.NewValidationError("test message")
	assert.Equal(t, apperrors.ValidationError, err.Code)
	assert.Equal(t, "VALIDATION_ERROR: test message", err.Error())

	s, ok := status.FromError(err.ToGRPCStatus())
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, s.Code())
}

func TestNewAuthenticationError(t *testing.T) {
	err := apperrors.NewAuthenticationError("test message")
	assert.Equal(t, apperrors.AuthenticationError, err.Code)
	assert.Equal(t, "AUTHENTICATION_ERROR: test message (Invalid or missing authentication credentials)", err.Error())

	s, ok := status.FromError(err.ToGRPCStatus())
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, s.Code())
}

func TestNewAuthorizationError(t *testing.T) {
	err := apperrors.NewAuthorizationError("test operation", "test resource")
	assert.Equal(t, apperrors.AuthorizationError, err.Code)
	assert.Equal(t, "AUTHORIZATION_ERROR: Insufficient permissions (User does not have permission to perform 'test operation' on 'test resource')", err.Error())

	s, ok := status.FromError(err.ToGRPCStatus())
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, s.Code())
}

func TestNewNotFoundError(t *testing.T) {
	err := apperrors.NewNotFoundError("test resource", "123")
	assert.Equal(t, apperrors.NotFoundError, err.Code)
	assert.Equal(t, "NOT_FOUND_ERROR: test resource not found (Resource with ID '123' does not exist)", err.Error())

	s, ok := status.FromError(err.ToGRPCStatus())
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, s.Code())
}

func TestNewConflictError(t *testing.T) {
	err := apperrors.NewConflictError("test resource", "123", "test message")
	assert.Equal(t, apperrors.ConflictError, err.Code)
	assert.Equal(t, "CONFLICT_ERROR: test resource already exists (test message)", err.Error())

	s, ok := status.FromError(err.ToGRPCStatus())
	assert.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, s.Code())
}

func TestNewInternalError(t *testing.T) {
	err := apperrors.NewInternalError("test message", errors.New("internal"))
	assert.Equal(t, apperrors.InternalError, err.Code)
	assert.Equal(t, "INTERNAL_ERROR: test message (An internal server error occurred)", err.Error())

	s, ok := status.FromError(err.ToGRPCStatus())
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, s.Code())
}

func TestFromGRPCStatus(t *testing.T) {
	s := status.New(codes.NotFound, "not found")
	err := apperrors.FromGRPCStatus(s.Err())
	assert.Equal(t, apperrors.NotFoundError, err.Code)
}

func TestWrapError(t *testing.T) {
	err := errors.New("original error")
	wrappedErr := apperrors.WrapError(err, "wrapped message")
	assert.Equal(t, apperrors.InternalError, wrappedErr.Code)
	assert.Equal(t, "INTERNAL_ERROR: wrapped message (original error)", wrappedErr.Error())
}

func TestIsErrorCode(t *testing.T) {
	err := apperrors.NewValidationError("test")
	assert.True(t, apperrors.IsErrorCode(err, apperrors.ValidationError))
	assert.False(t, apperrors.IsErrorCode(err, apperrors.NotFoundError))
}
