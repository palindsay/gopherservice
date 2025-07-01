package log

import (
	"go.uber.org/zap"
)

// New creates a new zap logger.
func New() (*zap.Logger, error) {
	return zap.NewProduction()
}
