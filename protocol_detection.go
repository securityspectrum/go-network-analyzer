package main

import (
	"bytes"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DetectProtocol is the main function for protocol detection
func DetectProtocol(conn *Connection, packet gopacket.Packet) string {
	// Check if service is already determined
	if conn.service != "" && conn.service != "unknown" {
		return conn.service
	}

	// Get transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return "unknown"
	}

	// Get application layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return "unknown"
	}

	payload := applicationLayer.Payload()

	// TCP-based protocol detection
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return detectTCPProtocol(payload, tcp.SrcPort, tcp.DstPort)
	}

	// UDP-based protocol detection
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return detectUDPProtocol(payload, udp.SrcPort, udp.DstPort)
	}

	// If no protocol detected, return unknown
	return "unknown"
}

func detectTCPProtocol(payload []byte, srcPort, dstPort layers.TCPPort) string {
	if detectHTTP(payload) {
		return "HTTP"
	}
	if detectTLS(payload) {
		return "SSL"
	}
	if detectSSH(payload) {
		return "SSH"
	}
	if detectFTP(payload, srcPort, dstPort) {
		return "FTP"
	}
	if detectSMTP(payload) {
		return "SMTP"
	}
	// Add more TCP protocol detections here
	return "unknown"
}

func detectUDPProtocol(payload []byte, srcPort, dstPort layers.UDPPort) string {
	if detectDNS(payload) {
		return "dns" // always lowercase for consistency
	}
	if detectDHCP(payload) {
		return "dhcp"
	}
	// Add more UDP protocol detections here
	return "unknown"
}

func detectHTTP(data []byte) bool {
	methods := []string{"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method+" ")) {
			return true
		}
	}
	return bytes.HasPrefix(data, []byte("HTTP/"))
}

func detectTLS(data []byte) bool {
	return len(data) >= 3 &&
		data[0] == 0x16 && // Handshake
		data[1] == 0x03 && // SSL/TLS version
		(data[2] >= 0x00 && data[2] <= 0x03) // SSL/TLS version minor
}

func detectSSH(data []byte) bool {
	return bytes.HasPrefix(data, []byte("SSH-"))
}

func detectFTP(data []byte, srcPort, dstPort layers.TCPPort) bool {
	if srcPort == 21 || dstPort == 21 {
		return bytes.HasPrefix(data, []byte("220 ")) ||
			bytes.HasPrefix(data, []byte("USER ")) ||
			bytes.HasPrefix(data, []byte("PASS "))
	}
	return false
}

func detectSMTP(data []byte) bool {
	return bytes.HasPrefix(data, []byte("220 ")) ||
		bytes.HasPrefix(data, []byte("HELO ")) ||
		bytes.HasPrefix(data, []byte("EHLO "))
}

func detectDNS(data []byte) bool {
	// Check that we have a DNS header length.
	if len(data) < 12 {
		return false
	}
	// In a DNS header:
	// - Bytes 0-1: Transaction ID (any value)
	// - Byte 2: Flags high; the first 4 bits are opcode (should be <= 15)
	opcode := (data[2] >> 3) & 0x0F
	if opcode > 15 {
		return false
	}
	// Optionally, check that QDCOUNT (bytes 4-5) is nonzero.
	qdCount := uint16(data[4])<<8 | uint16(data[5])
	return qdCount > 0
}

func detectDHCP(data []byte) bool {
	return len(data) > 236 &&
		data[0] == 0x01 && // Boot request or reply
		data[1] == 0x01 && // Ethernet hardware type
		data[2] == 0x06 && // Hardware address length
		data[3] == 0x00 // Hops
}

func DetectServiceForConnection(conn *Connection, packet gopacket.Packet) string {
	detected := DetectProtocol(conn, packet)
	if detected != "unknown" {
		return strings.ToLower(detected)
	}
	return fallbackService(conn)
}

func fallbackService(conn *Connection) string {
	switch conn.respP {
	case 80, 8080:
		return "http"
	case 443:
		return "ssl"
	case 53:
		return "dns"
	// Add more port heuristics if needed
	default:
		return ""
	}
}
