package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func runCapture(deviceName, logDir string, flushInterval int, stopChan chan struct{}) *LogContext {
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
	context.AddStrategy("conn", NewConnLogStrategy(logFiles["conn"], connManager, flushInterval, outputFormat))
	context.AddStrategy("dns", NewDNSLogStrategy(logFiles["dns"], flushInterval, outputFormat))
	context.AddStrategy("http", NewHTTPLogStrategy(logFiles["http"], flushInterval, outputFormat))

	var wg sync.WaitGroup

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

	wg.Wait()

	ticker.Stop()
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

	if verbose {
		log.Printf("Starting packet capture on device %s...\n", deviceName)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-stopChan:
			// Stop signal received, exit loop to stop capturing packets
			log.Println("Stopping packet capture...")
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			// Use our updated generateSessionID
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
}

func processPcapFile(filename string, logDir string, flushInterval int, outputFormat string) (*LogContext, error) {
	// Open the pcap file
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Create log files
	logFiles, err := createLogFiles(logDir)
	if err != nil {
		return nil, fmt.Errorf("error creating log files: %v", err)
	}

	// Initialize ConnectionManager
	connectionManager := NewConnectionManager(5 * time.Minute)

	// Initialize LogContext and strategies
	context := NewLogContext()

	// Added outputFormat parameter to strategy initializations
	connLogStrategy := NewConnLogStrategy(logFiles["conn"], connectionManager, flushInterval, outputFormat)
	dnsLogStrategy := NewDNSLogStrategy(logFiles["dns"], flushInterval, outputFormat)
	httpLogStrategy := NewHTTPLogStrategy(logFiles["http"], flushInterval, outputFormat)

	context.AddStrategy("conn", connLogStrategy)
	context.AddStrategy("dns", dnsLogStrategy)
	context.AddStrategy("http", httpLogStrategy)

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Process packets
	for packet := range packetSource.Packets() {
		event := PacketEvent{
			Timestamp: packet.Metadata().Timestamp,
			Packet:    packet,
			Uid:       generateUID(packet),
			SessionID: generateSessionID(packet),
		}

		connectionManager.UpdateConnection(event)
		context.Log(event)

		if verbose {
			log.Printf("Processed packet: %s -> %s\n",
				packet.NetworkLayer().NetworkFlow().Src(),
				packet.NetworkLayer().NetworkFlow().Dst())
		}
	}

	if verbose {
		log.Println("Finished processing PCAP file")
	}

	return context, nil
}

// Updated generateSessionID: now uses determineEndpoints to be consistent with updateConnection.
func generateSessionID(packet gopacket.Packet) string {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return ""
	}
	ip, _ := ipLayer.(*layers.IPv4)
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	var srcPort, dstPort uint16
	var protocol string
	var tcp *layers.TCP
	if t := packet.Layer(layers.LayerTypeTCP); t != nil {
		tcp = t.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = "tcp"
	} else if u := packet.Layer(layers.LayerTypeUDP); u != nil {
		udp := u.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = "udp"
	} else {
		srcPort = 0
		dstPort = 0
		protocol = "unknown_transport"
	}

	origH, origP, respH, respP := determineEndpoints(srcIP, srcPort, dstIP, dstPort, tcp)
	return GetConnectionKey(origH, origP, respH, respP, protocol)
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
