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
