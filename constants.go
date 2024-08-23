package main

import (
	"log"
	"runtime"
)

const AppName = "ss-network-analyzer"

const configFileName = "network-analyzer.conf"

// Constants for log directories based on the operating system
const (
	ZEEK_LOG_PATH_LINUX   = "/opt/" + AppName + "/logs/current"
	ZEEK_LOG_PATH_MACOS   = "/usr/local/" + AppName + "/logs/current"
	ZEEK_LOG_PATH_WINDOWS = `C:\ProgramData\` + AppName + `\logs\current`
	ZEEK_LOG_PATH_DEFAULT = ZEEK_LOG_PATH_LINUX // Default to Linux if OS is not supported
)

// GetDefaultLogDir returns the default log directory based on the operating system
func GetDefaultLogDir() string {
	switch runtime.GOOS {
	case "linux":
		return ZEEK_LOG_PATH_LINUX
	case "darwin":
		return ZEEK_LOG_PATH_MACOS
	case "windows":
		return ZEEK_LOG_PATH_WINDOWS
	default:
		log.Fatalf("Unsupported operating system: %s", runtime.GOOS)
		return ""
	}
}
