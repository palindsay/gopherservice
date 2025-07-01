package log

import (
	"go.uber.org/zap"
)

// New creates a new zap logger.
// It returns a *zap.Logger and an error if the logger creation fails.
func New() (*zap.Logger, error) {
	return zap.NewProduction()
}
