package main

import (
	"github.com/pelletier/go-toml"
	"io/ioutil"
	"log"
	"os"
)

type Config struct {
	LogDir            string `toml:"log_dir"`
	FlushInterval     int    `toml:"flush_interval"`     // in seconds
	SelectedInterface string `toml:"selected_interface"` // Network interface
}

// LoadConfig loads the configuration from a TOML file
func LoadConfig(filePath string) (*Config, error) {
	config := &Config{}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return config, nil // Return an empty config with defaults if the file does not exist
	}

	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = toml.Unmarshal(file, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// SaveConfig saves the current configuration to a TOML file
func SaveConfig(filePath string, config *Config) error {
	data, err := toml.Marshal(config)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}
	log.Printf("Configuration saved to %s", filePath)

	return nil
}
