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

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration.
type Config struct {
	Server struct {
		Port                    int `yaml:"port"`
		GracefulShutdownTimeout int `yaml:"gracefulShutdownTimeout"`
	} `yaml:"server"`
	JWT struct {
		SecretKey       string `yaml:"secretKey"`
		TokenDuration   int    `yaml:"tokenDuration"`
		RefreshDuration int    `yaml:"refreshDuration"`
	} `yaml:"jwt"`
	Database struct {
		DSN string `yaml:"dsn"`
	} `yaml:"database"`
	Telemetry struct {
		ServiceName string `yaml:"serviceName"`
		Endpoint    string `yaml:"endpoint"`
	} `yaml:"telemetry"`
}

// Load loads the configuration from a file.
func Load() (*Config, error) {
	cfg := Config{
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
			TokenDuration:   15,
			RefreshDuration: 10080,
		},
		Database: struct {
			DSN string `yaml:"dsn"`
		}{
			DSN: "gopherservice.db",
		},
		Telemetry: struct {
			ServiceName string `yaml:"serviceName"`
			Endpoint    string `yaml:"endpoint"`
		}{
			ServiceName: "gopherservice",
			Endpoint:    "otel-collector:4317",
		},
	}

	// Load configuration from file
	f, err := os.Open("config.yaml")
	if err == nil {
		defer f.Close()
		if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// Override with environment variables
	if secret := os.Getenv("JWT_SECRET_KEY"); secret != "" {
		cfg.JWT.SecretKey = secret
	}
	if dsn := os.Getenv("DATABASE_DSN"); dsn != "" {
		cfg.Database.DSN = dsn
	}
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); endpoint != "" {
		cfg.Telemetry.Endpoint = endpoint
	}
	if serviceName := os.Getenv("OTEL_SERVICE_NAME"); serviceName != "" {
		cfg.Telemetry.ServiceName = serviceName
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate validates the configuration and returns an error if any values are invalid.
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server port must be between 1 and 65535, got %d", c.Server.Port)
	}
	if c.Server.GracefulShutdownTimeout < 0 {
		return fmt.Errorf("server graceful shutdown timeout must be non-negative, got %d", c.Server.GracefulShutdownTimeout)
	}

	// Validate JWT configuration
	if c.JWT.SecretKey == "" {
		return fmt.Errorf("JWT secret key is required")
	}
	if len(c.JWT.SecretKey) < 32 {
		return fmt.Errorf("JWT secret key must be at least 32 characters long for security, got %d characters", len(c.JWT.SecretKey))
	}
	if c.JWT.TokenDuration <= 0 {
		return fmt.Errorf("JWT token duration must be positive, got %d", c.JWT.TokenDuration)
	}
	if c.JWT.RefreshDuration <= 0 {
		return fmt.Errorf("JWT refresh duration must be positive, got %d", c.JWT.RefreshDuration)
	}
	if c.JWT.TokenDuration >= c.JWT.RefreshDuration {
		return fmt.Errorf("JWT refresh duration (%d) must be greater than token duration (%d)", c.JWT.RefreshDuration, c.JWT.TokenDuration)
	}

	// Validate database configuration
	if c.Database.DSN == "" {
		return fmt.Errorf("database DSN is required")
	}

	// Validate telemetry configuration
	if c.Telemetry.ServiceName == "" {
		return fmt.Errorf("telemetry service name is required")
	}

	return nil
}
