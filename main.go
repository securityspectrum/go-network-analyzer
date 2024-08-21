package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	deviceManager := &DeviceManager{Verbose: verbose}

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

	// If -list-devices is provided, just list devices and exit
	if listDevicesFlag {
		log.Println("Listing devices and exiting due to -list-devices flag.")
		os.Exit(0)
	}

	// Prompt the user or automatically select the device with the highest packet count
	deviceName, err := deviceManager.PromptUserOrAutoSelect(devices, packetCounts, 5*time.Second)
	if err != nil {
		log.Fatalf("Error selecting device: %v", err)
	}

	log.Printf("Selected device: %s", deviceName)
	runCapture(deviceName)
}

func runCapture(deviceName string) {
	logDir := filepath.Join(os.Getenv("USERPROFILE"), "Documents", "NetworkLogs")
	logFiles, err := createLogFiles(logDir)
	if err != nil {
		log.Fatalf("Failed to create log files: %v", err)
	}
	defer func() {
		for _, logFile := range logFiles {
			logFile.Close()
		}
	}()

	connManager := NewConnectionManager(connectionTimeout) // Use the configured timeout
	context := NewLogContext()
	context.AddStrategy("conn", NewConnLogStrategy(logFiles["conn"], connManager))
	context.AddStrategy("dns", NewDNSLogStrategy(logFiles["dns"]))
	context.AddStrategy("http", NewHTTPLogStrategy(logFiles["http"]))

	var wg sync.WaitGroup

	wg.Add(1)
	go capturePackets(deviceName, context, &wg)

	// Periodically remove inactive connections and print active connections count
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			connManager.RemoveInactiveConnections()
			connManager.PrintActiveConnectionsCount()
		}
	}()

	wg.Wait()

	ticker.Stop()
	context.Close()
}

func capturePackets(deviceName string, context *LogContext, wg *sync.WaitGroup) {
	defer wg.Done()
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening device %s: %v", deviceName, err)
		return
	}
	defer handle.Close()

	log.Printf("Starting packet capture on device %s...\n", deviceName)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
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
