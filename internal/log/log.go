package log

import (
	"context"
	"log/slog"
	"os"
)

// New creates a new structured logger using Go's native slog package.
// It returns a *slog.Logger configured for production use with JSON output.
func New() *slog.Logger {
	// Create a JSON handler for structured logging in production
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
		// AddSource adds file and line information to log records
		AddSource: true,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	return slog.New(handler)
}

// NewWithLevel creates a new structured logger with the specified log level.
// level should be one of: slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError.
func NewWithLevel(level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	return slog.New(handler)
}

// LoggerFromContext retrieves a logger from the context.
// If no logger is found, it returns the default logger.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value("logger").(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// ContextWithLogger adds a logger to the context.
func ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, "logger", logger)
}
