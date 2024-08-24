package main

import (
	"fmt"
	"github.com/pelletier/go-toml"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	LogDir            string `toml:"log_dir"`
	FlushInterval     int    `toml:"flush_interval"`     // in seconds
	SelectedInterface string `toml:"selected_interface"` // Network interface
}

const (
	SS_NETWORK_ANALYZER_CONFIG_DIR_LINUX   = "/etc/" + AppName + "/config"
	SS_NETWORK_ANALYZER_CONFIG_DIR_MACOS   = "/Library/Application Support/" + AppName + "/config"
	SS_NETWORK_ANALYZER_CONFIG_DIR_WINDOWS = `C:\ProgramData\` + AppName + `\config`
)

// GetConfigPaths returns a list of potential configuration file paths
func GetConfigPaths() []string {
	var paths []string

	// 1. Look in the directory where the binary is located
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		paths = append(paths, filepath.Join(exeDir, configFileName))
	}

	// 2. User-specific config directory
	switch runtime.GOOS {
	case "linux", "darwin":
		homeDir, err := os.UserHomeDir()
		if err == nil {
			paths = append(paths, filepath.Join(homeDir, ".config", AppName, configFileName))
		}
	case "windows":
		appDataDir := os.Getenv("APPDATA")
		if appDataDir != "" {
			paths = append(paths, filepath.Join(appDataDir, AppName, configFileName))
		}
	}

	// 3. System-wide config directory
	switch runtime.GOOS {
	case "linux":
		paths = append(paths, filepath.Join(SS_NETWORK_ANALYZER_CONFIG_DIR_LINUX, configFileName))
	case "darwin":
		paths = append(paths, filepath.Join(SS_NETWORK_ANALYZER_CONFIG_DIR_MACOS, configFileName))
	case "windows":
		paths = append(paths, filepath.Join(SS_NETWORK_ANALYZER_CONFIG_DIR_WINDOWS, configFileName))
	}

	return paths
}

// DetermineConfigFilePath determines the path to the config file by finding the first valid path
func DetermineConfigFilePath() (string, error) {
	for _, path := range GetConfigPaths() {
		if _, err := os.Stat(path); err == nil || os.IsNotExist(err) {
			return path, nil
		}
	}
	return "", fmt.Errorf("no valid config file path found")
}

// LoadConfig searches for and loads the configuration file, creating it with defaults if not found
func LoadConfig() (*Config, error) {
	for _, path := range GetConfigPaths() {
		if _, err := os.Stat(path); err == nil {
			log.Printf("Loading config file from: %s", path)
			return LoadConfigFromPath(path)
		}
	}

	// If no config file is found, create one with default values in the first system-wide path
	defaultConfig := getDefaultConfig()
	systemWidePath := GetSystemWideConfigPath()
	log.Printf("Config file not found. Creating default config file at: %s", systemWidePath)
	if err := SaveConfigToPath(systemWidePath, defaultConfig); err != nil {
		return nil, fmt.Errorf("failed to create default config file: %v", err)
	}

	return defaultConfig, nil
}

func GetSystemWideConfigPath() string {
	switch runtime.GOOS {
	case "linux":
		return filepath.Join(SS_NETWORK_ANALYZER_CONFIG_DIR_LINUX, configFileName)
	case "darwin":
		return filepath.Join(SS_NETWORK_ANALYZER_CONFIG_DIR_MACOS, configFileName)
	case "windows":
		return filepath.Join(SS_NETWORK_ANALYZER_CONFIG_DIR_WINDOWS, configFileName)
	default:
		log.Fatalf("Unsupported operating system: %s", runtime.GOOS)
		return ""
	}
}

// SaveConfigToPath saves the current configuration to the specified path
func SaveConfigToPath(filePath string, config *Config) error {
	data, err := toml.Marshal(config)
	if err != nil {
		return err
	}

	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}

	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}

	log.Printf("Configuration saved to %s", filePath)
	return nil
}

// SaveConfig saves the current configuration to the determined path
func SaveConfig(config *Config) error {
	configPath, err := DetermineConfigFilePath()
	if err != nil {
		return err
	}
	return SaveConfigToPath(configPath, config)
}

// LoadConfigFromPath loads the configuration from the specified file path
func LoadConfigFromPath(filePath string) (*Config, error) {
	config := &Config{}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return config, err // Return an error if the file does not exist
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
