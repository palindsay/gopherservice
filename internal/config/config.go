package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration.
type Config struct {
	Telemetry struct {
		ServiceName string `yaml:"serviceName"`
		Endpoint    string `yaml:"endpoint"`
	} `yaml:"telemetry"`
}

// Load loads the configuration from a file.
func Load() (*Config, error) {
	// Load loads the configuration from a file named config.yaml.
	// It returns a pointer to a Config struct and an error if the loading fails.
	f, err := os.Open("config.yaml")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
