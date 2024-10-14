//go:build !windows
// +build !windows

package main

func isWindowsService() bool {
	return false
}

func runService(name string) {
	// Do nothing on non-Windows platforms
}
