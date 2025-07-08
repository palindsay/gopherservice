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

// Package log_test provides tests for the log package.
package log_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/plindsay/gopherservice/internal/log"
)

func TestNew(t *testing.T) {
	logger := log.New()
	require.NotNil(t, logger)
}

func TestWithContext(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx := log.WithContext(context.Background(), logger)
	retrievedLogger := log.FromContext(ctx)
	require.NotNil(t, retrievedLogger)

	retrievedLogger.Info("test message")
	assert.Contains(t, buf.String(), "test message")
}

func TestFromContext_NoLogger(t *testing.T) {
	logger := log.FromContext(context.Background())
	require.NotNil(t, logger)
}
