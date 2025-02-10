package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const version = "1.0.0"

var (
	verbose           bool
	listDevicesFlag   bool
	connectionTimeout time.Duration
	showVersion       bool
	configFilePath    string
	pcapFile          string
	outputFormat      string
	interfaceName     string
)

func main() {
	log.SetOutput(os.Stdout)

	// Define flags
	flag.BoolVar(&showVersion, "version", false, "Show the version of the program")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&listDevicesFlag, "list-devices", false, "List available network devices")
	flag.DurationVar(&connectionTimeout, "timeout", 120*time.Second, "Connection timeout duration")
	flag.StringVar(&configFilePath, "config", "", "Path to configuration file")
	flag.StringVar(&pcapFile, "pcap", "", "Path to PCAP file for offline analysis")
	flag.StringVar(&outputFormat, "format", "json", "Output format: 'json' or 'plain'")
	flag.StringVar(&interfaceName, "interface", "", "Network interface to capture traffic")
	flag.Parse()

	if showVersion {
		fmt.Printf("Network Analyzer version %s\n", version)
		return
	}

	if isWindowsService() {
		// Run as Windows service
		runService("NetworkAnalyzerService")
		return
	}

	// For non-service mode or non-Windows, run the application normally
	stopChan := make(chan struct{})
	runApplication(stopChan)
}

func runApplication(stopChan chan struct{}) {
	var config *Config
	var err error

	if configFilePath != "" {
		// If the config flag is used, load the specified file and quit if not found
		config, err = LoadConfigFromPath(configFilePath)
		if err != nil {
			log.Fatalf("Configuration file not found at specified path: %s", configFilePath)
		}
		log.Printf("Loaded configuration from specified path: %s", configFilePath)
	} else {
		// If no config flag, attempt to find the configuration file
		config, err = LoadConfig()
		if err != nil {
			log.Printf("Could not find a configuration file, using defaults: %v", err)
			config = getDefaultConfig()
		}
	}

	// Handle listing devices and exit
	if listDevicesFlag {
		deviceManager := &DeviceManager{Verbose: verbose}
		_, _, err := deviceManager.ListDevicesWithPacketCounts(3000 * time.Millisecond)
		if err != nil {
			log.Fatalf("Error listing devices: %v", err)
		}
		return
	}

	// If the interface flag is provided, it overrides the config
	if interfaceName != "" {
		log.Printf("Using specified network interface: %s", interfaceName)
		config.SelectedInterface = interfaceName
	} else if config.SelectedInterface != "" {
		log.Printf("Using configured network interface: %s", config.SelectedInterface)
	} else {
		log.Fatalf("No network interface specified or configured.")
	}

	var context *LogContext

	if pcapFile != "" {
		// Process PCAP file
		context, err = processPcapFile(pcapFile, config.LogDir, config.FlushInterval, outputFormat)
		if err != nil {
			log.Fatalf("Error processing packets: %v", err)
		}
		// Close log files and exit after processing PCAP file
		context.Close()
		fmt.Println("Finished processing PCAP file")
		return
	} else {
		// Live capture
		context = runCapture(config.SelectedInterface, config.LogDir, config.FlushInterval, stopChan)
	}

	// Set up graceful shutdown for live capture
	if !isWindowsService() {
		// Only set up signal handling in console mode
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			sig := <-sigs
			fmt.Println()
			fmt.Println(sig)
			close(stopChan) // Signal the capture to stop
		}()

		fmt.Println("Press Ctrl+C to stop")
	}

	// Wait for stop signal
	<-stopChan
	fmt.Println("Stopping...")

	// Close log files
	context.Close()

	fmt.Println("Exiting")
}

//// isWindowsService returns true if the program is running as a Windows service.
//// On non-Windows platforms, it always returns false.
//func isWindowsService() bool {
//	return false
//}
//
//// runService is a placeholder on non-Windows platforms.
//func runService(name string) {
//	// Do nothing on non-Windows platforms
//}
