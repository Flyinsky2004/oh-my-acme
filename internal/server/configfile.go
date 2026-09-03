package server

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadConfigFile reads config.json into a Config.
func LoadConfigFile(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// SaveConfigFile atomically writes config.json.
func SaveConfigFile(path string, cfg Config) error {
	b, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
