// Package config_test provides tests for the config package.
package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/plindsay/gopherservice/internal/config"
)

func TestLoad(t *testing.T) {
	// Create a temporary config file
	content := []byte(`
server:
  port: 8080
jwt:
  secretKey: "test-secret"
  tokenDuration: 15
  refreshDuration: 10080
database:
  dsn: "test.db"
telemetry:
  serviceName: "test-service"
  endpoint: "test-endpoint"
`)
	tmpfile, err := os.CreateTemp("", "config.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	require.NoError(t, err)
	err = tmpfile.Close()
	require.NoError(t, err)

	// Temporarily move the working directory to the temp file's directory
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(os.TempDir()))
	defer func() {
		require.NoError(t, os.Chdir(wd))
	}()

	// Rename the temp file to config.yaml
	err = os.Rename(tmpfile.Name(), "config.yaml")
	require.NoError(t, err)
	defer os.Remove("config.yaml")

	cfg, err := config.Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	require.Equal(t, 8080, cfg.Server.Port)
	require.Equal(t, "test-secret", cfg.JWT.SecretKey)
	require.Equal(t, "test.db", cfg.Database.DSN)
	require.Equal(t, "test-service", cfg.Telemetry.ServiceName)
}
