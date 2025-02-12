// capture.go
package main

import (
	"crypto/rand"
	"fmt"
	"github.com/google/gopacket/layers"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

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

	// Create connection manager with configurable timeouts.
	connManager := NewConnectionManager(connectionTimeout, 15*time.Second, 15*time.Second)
	context := NewLogContext()
	context.AddStrategy("conn", NewConnLogStrategy(logFiles["conn"], connManager, flushInterval, outputFormat))
	context.AddStrategy("dns", NewDNSLogStrategy(logFiles["dns"], flushInterval, outputFormat))
	context.AddStrategy("http", NewHTTPLogStrategy(logFiles["http"], flushInterval, outputFormat))

	// Start the DNS query expiration routine.
	// Retrieve the DNS log strategy from the strategies map.
	if dnsStrat, ok := context.strategies["dns"].(*DNSLogStrategy); ok {
		go dnsStrat.ExpireQueries(1 * time.Second)
	} else {
		log.Printf("DNS log strategy not found for query expiration")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go capturePackets(deviceName, context, &wg, stopChan)

	// Periodically remove inactive connections.
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				connManager.RemoveInactiveConnections()
			case <-stopChan:
				ticker.Stop()
				return
			}
		}
	}()

	// Flush logs.
	context.Close()
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

	log.Printf("Starting packet capture on device %s...", deviceName)
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
				log.Printf("Captured packet with UID: %s, SessionID: %s", uid, sessionID)
			}
			context.Log(PacketEvent{
				Timestamp: packet.Metadata().Timestamp,
				Uid:       uid,
				SessionID: sessionID,
				Packet:    packet,
			})
		}
	}
}

func processPcapFile(filename, logDir string, flushInterval int, outputFormat string) (*LogContext, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	logFiles, err := createLogFiles(logDir)
	if err != nil {
		return nil, fmt.Errorf("error creating log files: %v", err)
	}

	connManager := NewConnectionManager(5*time.Minute, 15*time.Second, 15*time.Second)
	context := NewLogContext()

	connLogStrategy := NewConnLogStrategy(logFiles["conn"], connManager, flushInterval, outputFormat)
	dnsLogStrategy := NewDNSLogStrategy(logFiles["dns"], flushInterval, outputFormat)
	httpLogStrategy := NewHTTPLogStrategy(logFiles["http"], flushInterval, outputFormat)

	context.AddStrategy("conn", connLogStrategy)
	context.AddStrategy("dns", dnsLogStrategy)
	context.AddStrategy("http", httpLogStrategy)

	// Start the DNS query expiration routine.
	// Retrieve the DNS log strategy from the strategies map.
	if dnsStrat, ok := context.strategies["dns"].(*DNSLogStrategy); ok {
		go dnsStrat.ExpireQueries(1 * time.Second)
	} else {
		log.Printf("DNS log strategy not found for query expiration")
	}

	log.Println("Processing PCAP file...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		event := PacketEvent{
			Timestamp: packet.Metadata().Timestamp,
			Packet:    packet,
			Uid:       generateUID(packet),
			SessionID: generateSessionID(packet),
		}
		// processing flow information (4 or 5 tuple) for each packet
		context.Log(event)
	}
	connManager.RemoveInactiveConnections()
	log.Println("Finished processing PCAP file")
	// Flush logs (this will now flush pending DNS queries).
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
	origH, origP, respH, respP := determineEndpoints(srcIP, srcPort, dstIP, dstPort, protocol)
	return GetConnectionKey(origH, origP, respH, respP, protocol)
}

var connectionCounter uint64

func base62EncodeBig(i *big.Int) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	if i.Cmp(big.NewInt(0)) == 0 {
		return string(alphabet[0])
	}
	result := ""
	base := big.NewInt(62)
	zero := big.NewInt(0)
	mod := new(big.Int)
	for i.Cmp(zero) > 0 {
		i.DivMod(i, base, mod)
		result = string(alphabet[mod.Int64()]) + result
	}
	return result
}

func generateRandomUID() (string, error) {
	b := make([]byte, 16) // 16 bytes = 128 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	i := new(big.Int).SetBytes(b)
	// Encode to base62.
	return base62EncodeBig(i), nil
}

func generateUID(packet gopacket.Packet) string {
	uid, err := generateRandomUID()
	if err != nil {
		// Fallback: use timestamp if randomness fails.
		return "C" + fmt.Sprintf("%d", time.Now().UnixNano())
	}
	// Prepend "C" to mimic Zeek’s style.
	return "C" + uid
}

func getDefaultConfig() *Config {
	return &Config{
		LogDir:        GetDefaultLogDir(),
		FlushInterval: 1,
	}
}
