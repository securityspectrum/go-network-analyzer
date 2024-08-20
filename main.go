package main

import (
	"crypto/md5"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var verbose bool
var connectionTimeout time.Duration

func listDevices() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	if verbose {
		fmt.Println("Devices found:")
		for i, device := range devices {
			fmt.Printf("%d: %s (%s)\n", i, device.Name, device.Description)
			for _, address := range device.Addresses {
				fmt.Printf("  - IP address: %s\n", address.IP)
				fmt.Printf("  - Subnet mask: %s\n", address.Netmask)
			}
		}
	}

	return devices, nil
}

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
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func capturePackets(device string, context *LogContext, wg *sync.WaitGroup) {
	defer wg.Done()
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening device %s: %v", device, err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Generate a session ID
		sessionID := generateSessionID(packet)

		// Create a unique identifier for the session
		uid := fmt.Sprintf("%x", packet.Metadata().CaptureInfo.Timestamp.UnixNano())

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

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.DurationVar(&connectionTimeout, "timeout", 120*time.Second, "Connection timeout duration")
	flag.Parse()

	devices, err := listDevices()
	if err != nil {
		log.Fatal(err)
	}

	if len(devices) == 0 {
		log.Fatal("No devices found. Exiting.")
	}

	fmt.Print("Enter the device number to capture packets from: ")
	var deviceIndex string
	fmt.Scanln(&deviceIndex)
	index, err := strconv.Atoi(deviceIndex)
	if err != nil || index < 0 || index >= len(devices) {
		log.Fatalf("Invalid device number: %s", deviceIndex)
	}

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
	go capturePackets(devices[index].Name, context, &wg)

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
