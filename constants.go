package main

import (
	"log"
	"runtime"
)

const configFileName = "network-analyzer.conf"

const AppName = "ss-network-analyzer"

// Constants for log directories based on the operating system
const (
	NETWORK_ANALYZER_LOG_PATH_LINUX   = "/var/log/" + AppName + "/"
	NETWORK_ANALYZER_LOG_PATH_MACOS   = "/usr/local/var/log/" + AppName + "/"
	NETWORK_ANALYZER_LOG_PATH_WINDOWS = `C:\ProgramData\` + AppName + `\logs\`
)

// GetDefaultLogDir returns the default log directory based on the operating system
func GetDefaultLogDir() string {
	switch runtime.GOOS {
	case "linux":
		return NETWORK_ANALYZER_LOG_PATH_LINUX
	case "darwin":
		return NETWORK_ANALYZER_LOG_PATH_MACOS
	case "windows":
		return NETWORK_ANALYZER_LOG_PATH_WINDOWS
	default:
		log.Fatalf("Unsupported operating system: %s", runtime.GOOS)
		return NETWORK_ANALYZER_LOG_PATH_LINUX
	}
}
