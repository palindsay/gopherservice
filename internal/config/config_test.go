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
  secretKey: "test-secret-key-that-is-long-enough-for-validation"
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
	require.Equal(t, "test-secret-key-that-is-long-enough-for-validation", cfg.JWT.SecretKey)
	require.Equal(t, "test.db", cfg.Database.DSN)
	require.Equal(t, "test-service", cfg.Telemetry.ServiceName)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		wantErr     bool
		errorSubstr string
	}{
		{
			name: "valid config",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   15,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{
					DSN: "test.db",
				},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{
					ServiceName: "test-service",
					Endpoint:    "test-endpoint",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid server port - too low",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    0,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   15,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "server port must be between 1 and 65535",
		},
		{
			name: "invalid server port - too high",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    70000,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   15,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "server port must be between 1 and 65535",
		},
		{
			name: "invalid graceful shutdown timeout - negative",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: -1,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   15,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "graceful shutdown timeout must be non-negative",
		},
		{
			name: "empty JWT secret key",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "",
					TokenDuration:   15,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "JWT secret key is required",
		},
		{
			name: "JWT secret key too short",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "short",
					TokenDuration:   15,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "JWT secret key must be at least 32 characters long",
		},
		{
			name: "invalid token duration - zero",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   0,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "JWT token duration must be positive",
		},
		{
			name: "invalid refresh duration - zero",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   15,
					RefreshDuration: 0,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "JWT refresh duration must be positive",
		},
		{
			name: "refresh duration not greater than token duration",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   60,
					RefreshDuration: 30,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "refresh duration (30) must be greater than token duration (60)",
		},
		{
			name: "empty database DSN",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   15,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: ""},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: "test-service"},
			},
			wantErr:     true,
			errorSubstr: "database DSN is required",
		},
		{
			name: "empty telemetry service name",
			config: &config.Config{
				Server: struct {
					Port                    int `yaml:"port"`
					GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
				}{
					Port:                    8080,
					GracefulShutdownTimeout: 5,
				},
				JWT: struct {
					SecretKey       string `yaml:"secretKey"`
					TokenDuration   int    `yaml:"tokenDuration"`
					RefreshDuration int    `yaml:"refreshDuration"`
				}{
					SecretKey:       "long-enough-secret-key-for-validation",
					TokenDuration:   15,
					RefreshDuration: 10080,
				},
				Database: struct {
					DSN string `yaml:"dsn"`
				}{DSN: "test.db"},
				Telemetry: struct {
					ServiceName string `yaml:"serviceName"`
					Endpoint    string `yaml:"endpoint"`
				}{ServiceName: ""},
			},
			wantErr:     true,
			errorSubstr: "telemetry service name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
