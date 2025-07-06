// Package log provides structured logging for the application.
package log

import (
	"context"
	"log/slog"
	"os"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// loggerKey is the context key for the logger.
	loggerKey = contextKey("logger")
)

// New creates a new slog logger with a JSON handler.
func New() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, nil))
}

// FromContext returns the logger from the context, or a default logger if none is found.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return New()
}

// WithContext returns a new context with the logger embedded.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}
