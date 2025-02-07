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

// runCapture starts live packet capture and returns the logging context.
func runCapture(deviceName, logDir string, flushInterval int, stopChan chan struct{}) *LogContext {
	// Ensure log directory exists.
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		log.Printf("Log directory does not exist. Creating: %s", logDir)
		if err := os.MkdirAll(logDir, os.ModePerm); err != nil {
			log.Fatalf("Failed to create log directory: %s", err)
		}
	}
	log.Printf("Writing logs to directory: %s", logDir)
	logFiles, err := createLogFiles(logDir)
	if err != nil {
		log.Fatalf("Failed to create log files: %v", err)
	}

	// Use configurable timeouts (e.g. TCP: connectionTimeout, UDP/ICMP: 15 seconds)
	connManager := NewConnectionManager(connectionTimeout, 15*time.Second, 15*time.Second)
	context := NewLogContext()
	context.AddStrategy("conn", NewConnLogStrategy(logFiles["conn"], connManager, flushInterval, outputFormat))
	context.AddStrategy("dns", NewDNSLogStrategy(logFiles["dns"], flushInterval, outputFormat))
	context.AddStrategy("http", NewHTTPLogStrategy(logFiles["http"], flushInterval, outputFormat))

	var wg sync.WaitGroup
	wg.Add(1)
	go capturePackets(deviceName, context, &wg, stopChan)

	// Periodically clean up inactive connections.
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			connManager.RemoveInactiveConnections()
			connManager.PrintActiveConnectionsCount()
		}
	}()
	wg.Wait()
	ticker.Stop()

	// IMPORTANT: Close the logging context so that buffers are flushed
	context.Close()
	return context
}

// capturePackets performs live packet capture.
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
			log.Println("Stopping packet capture...")
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			sessionID := generateSessionID(packet)
			uid := generateUID(packet)
			if verbose {
				log.Printf("Captured packet with UID: %s, SessionID: %s\n", uid, sessionID)
			}
			// *** Un-commented the call to context.Log so that the packet event is processed ***
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
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	logFiles, err := createLogFiles(logDir)
	if err != nil {
		return nil, fmt.Errorf("error creating log files: %v", err)
	}

	// Use configurable timeouts.
	connectionManager := NewConnectionManager(5*time.Minute, 15*time.Second, 15*time.Second)
	context := NewLogContext()

	connLogStrategy := NewConnLogStrategy(logFiles["conn"], connectionManager, flushInterval, outputFormat)
	dnsLogStrategy := NewDNSLogStrategy(logFiles["dns"], flushInterval, outputFormat)
	httpLogStrategy := NewHTTPLogStrategy(logFiles["http"], flushInterval, outputFormat)

	context.AddStrategy("conn", connLogStrategy)
	context.AddStrategy("dns", dnsLogStrategy)
	context.AddStrategy("http", httpLogStrategy)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		event := PacketEvent{
			Timestamp: packet.Metadata().Timestamp,
			Packet:    packet,
			Uid:       generateUID(packet),
			SessionID: generateSessionID(packet),
		}
		//connectionManager.UpdateConnection(event)
		context.Log(event)
	}
	// Force removal of inactive connections to trigger logging of pending flows.
	connectionManager.RemoveInactiveConnections()

	if verbose {
		log.Println("Finished processing PCAP file")
	}
	// Close the logging context to flush buffered data.
	context.Close()
	return context, nil
}

// generateSessionID now supports both IPv4 and IPv6.
func generateSessionID(packet gopacket.Packet) string {
	var srcIP, dstIP string
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		} else {
			return ""
		}
	}

	var srcPort, dstPort uint16
	var protocol string
	if t := packet.Layer(layers.LayerTypeTCP); t != nil {
		tcp := t.(*layers.TCP)
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
	origH, origP, respH, respP := determineEndpoints(srcIP, srcPort, dstIP, dstPort)
	return GetConnectionKey(origH, origP, respH, respP, protocol)
}

func generateUID(packet gopacket.Packet) string {
	return fmt.Sprintf("%x", packet.Metadata().CaptureInfo.Timestamp.UnixNano())
}

func getDefaultConfig() *Config {
	return &Config{
		LogDir:        GetDefaultLogDir(),
		FlushInterval: 1,
	}
}
