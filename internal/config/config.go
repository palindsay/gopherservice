package config

import (
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

	return &cfg, nil
}
