package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const version = "1.0.0"

var verbose bool
var listDevicesFlag bool
var connectionTimeout time.Duration
var showVersion bool

func main() {
	flag.BoolVar(&showVersion, "version", false, "Show the version of the program")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&listDevicesFlag, "list-devices", false, "List available network devices")
	flag.DurationVar(&connectionTimeout, "timeout", 120*time.Second, "Connection timeout duration")
	flag.Parse()

	if showVersion {
		fmt.Printf("Network Analyzer version %s\n", version)
		return
	}

	// Load the configuration
	config, err := LoadConfig(configFileName)
	if err != nil {
		log.Printf("Could not load config file, using defaults: %v", err)
		config = getDefaultConfig()
	}

	// Apply configuration settings
	logDir := config.LogDir
	if logDir == "" {
		logDir = GetDefaultLogDir()
	}
	log.Printf("Log directory: %s", logDir)

	flushInterval := config.FlushInterval
	if flushInterval == 0 {
		flushInterval = 1 // Default to 1 second flush interval
		log.Printf("Flush interval: %d seconds", flushInterval)
	}

	// Handle termination signals for graceful shutdown
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	stopChan := make(chan struct{})
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	var context *LogContext
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		deviceManager := &DeviceManager{Verbose: verbose}
		var deviceName string

		if config.SelectedInterface != "" {
			deviceName = config.SelectedInterface
		} else {
			// Wait 1.5 seconds before listing devices with packet counts
			log.Println("Waiting 1.5 seconds before listing devices..")
			time.Sleep(1500 * time.Millisecond)

			// List devices and get packet counts over a 1.5-second duration
			devices, packetCounts, err := deviceManager.ListDevicesWithPacketCounts(1500 * time.Millisecond)
			if err != nil {
				log.Fatalf("Error listing devices: %v", err)
			}

			if len(devices) == 0 {
				log.Fatal("No devices found. Exiting.")
			}

			// Prompt the user or automatically select the device with the highest packet count
			deviceName, err = deviceManager.PromptUserOrAutoSelect(devices, packetCounts, 5*time.Second)
			if err != nil {
				log.Fatalf("Error selecting device: %v", err)
			}

			// Save the selected interface to the config
			config.SelectedInterface = deviceName
			SaveConfig(configFileName, config)
		}

		log.Printf("Selected device: %s", deviceName)

		// Capture process and log context setup
		context = runCapture(deviceName, logDir, flushInterval)
	}()

	// Wait for a termination signal
	go func() {
		sig := <-sigs
		log.Printf("Received signal: %s, shutting down gracefully...", sig)
		close(stopChan) // Signal to stop packet capture
		wg.Wait()       // Wait for capture to finish
		log.Println("Exiting program, ensuring all logs are flushed...")
		if context != nil {
			context.Close() // Ensure all logs are flushed
		}
		done <- true
	}()

	// Ensure that the program doesn't exit prematurely
	<-done
	log.Println("Program has exited.")
}

func runCapture(deviceName, logDir string, flushInterval int) *LogContext {
	// Check if the directory exists, and create it if it doesn't
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		log.Printf("Log directory does not exist. Creating: %s", logDir)
		if err := os.MkdirAll(logDir, os.ModePerm); err != nil {
			log.Fatalf("Failed to create log directory: %s", err)
		}
	}

	// Print the log directory path
	log.Printf("Writing logs to directory: %s", logDir)

	logFiles, err := createLogFiles(logDir)
	if err != nil {
		log.Fatalf("Failed to create log files: %v", err)
	}

	connManager := NewConnectionManager(connectionTimeout) // Use the configured timeout
	context := NewLogContext()
	context.AddStrategy("conn", NewConnLogStrategy(logFiles["conn"], connManager, flushInterval))
	context.AddStrategy("dns", NewDNSLogStrategy(logFiles["dns"], flushInterval))
	context.AddStrategy("http", NewHTTPLogStrategy(logFiles["http"], flushInterval))

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	wg.Add(1)
	go capturePackets(deviceName, context, &wg, stopChan)

	// Periodically remove inactive connections and print active connections count
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			connManager.RemoveInactiveConnections()
			connManager.PrintActiveConnectionsCount()
		}
	}()

	go func() {
		<-stopChan
		log.Println("Received stop signal, waiting for capture to finish...")
		wg.Wait() // Wait for the capturePackets goroutine to finish
		ticker.Stop()
		context.Close() // Ensure all logs are flushed
	}()

	return context
}

func capturePackets(deviceName string, context *LogContext, wg *sync.WaitGroup, stopChan chan struct{}) {
	defer wg.Done()
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening device %s: %v", deviceName, err)
		return
	}
	defer handle.Close()

	log.Printf("Starting packet capture on device %s...\n", deviceName)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case packet := <-packetChan:
			// Generate a session ID and other packet processing
			sessionID := generateSessionID(packet)
			uid := generateUID(packet)

			if verbose {
				log.Printf("Captured packet with UID: %s, SessionID: %s\n", uid, sessionID)
			}

			// Send event to the logging context
			context.Log(PacketEvent{
				Timestamp: packet.Metadata().Timestamp,
				Uid:       uid,
				SessionID: sessionID,
				Packet:    packet,
			})

		case <-stopChan:
			log.Println("Received stop signal, stopping packet capture.")
			return
		}
	}
}

// Generate a unique session ID based on packet IP and port information using SHA256
func generateSessionID(packet gopacket.Packet) string {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	var srcIP, dstIP string
	var srcPort, dstPort uint16

	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}

	data := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// Generate a unique identifier for the session based on packet timestamp
func generateUID(packet gopacket.Packet) string {
	return fmt.Sprintf("%x", packet.Metadata().CaptureInfo.Timestamp.UnixNano())
}

func getDefaultConfig() *Config {
	return &Config{
		LogDir:        GetDefaultLogDir(),
		FlushInterval: 1,
	}
}
