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
	// If payload looks HTTP-like, we require more evidence before labeling it.
	if detectHTTP(payload) {
		// Optionally check if the payload contains "HTTP/" at the expected position
		// or if it matches a more detailed regex.
		if len(payload) > 12 && bytes.Contains(payload, []byte(" HTTP/")) {
			return "HTTP"
		}
		// If only a weak match (e.g., just a common method and space) exists,
		// you may want to return "unknown" to be conservative.
		return "unknown"
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
	// Check known DNS ports.
	if srcPort == 53 || dstPort == 53 ||
		srcPort == 5353 || dstPort == 5353 ||
		srcPort == 5355 || dstPort == 5355 {
		if detectDNS(payload) {
			return "dns"
		}
	}
	if detectDHCP(payload) {
		return "dhcp"
	}
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

func detectTLS(payload []byte) bool {
	// TLS record header is 5 bytes.
	if len(payload) < 5 {
		return false
	}
	// Check that the content type is one of the allowed TLS types.
	// While handshake (22) is most common for detection,
	// some records may begin with Change Cipher Spec (20),
	// Alert (21) or Application Data (23).
	ct := payload[0]
	if ct != 20 && ct != 21 && ct != 22 && ct != 23 {
		return false
	}
	// Check TLS version: typically, the major version is 3.
	major := payload[1]
	minor := payload[2]
	if major != 3 {
		return false
	}
	// Accept minor versions 1-4 (TLS 1.0, 1.1, 1.2, and TLS 1.3 respectively).
	if minor < 1 || minor > 4 {
		return false
	}
	// Extract the TLS record length (bytes 3-4, big-endian).
	recordLength := int(payload[3])<<8 | int(payload[4])
	// TLS records should have a positive length and are typically no larger than 16KB.
	if recordLength <= 0 || recordLength > 16384 {
		return false
	}
	return true
}

func detectSSH(payload []byte) bool {
	// SSH banners typically start with "SSH-" and include a version string.
	if len(payload) < 5 {
		return false
	}
	if !bytes.HasPrefix(payload, []byte("SSH-")) {
		return false
	}
	// After "SSH-", there should be a version number (e.g., "2.0").
	// A simple check: look for a dot within the next 5 bytes.
	idx := bytes.IndexByte(payload[4:], '.')
	if idx == -1 || idx > 5 {
		return false
	}
	return true
}

func detectFTP(data []byte, srcPort, dstPort layers.TCPPort) bool {
	if srcPort == 21 || dstPort == 21 {
		return bytes.HasPrefix(data, []byte("220 ")) ||
			bytes.HasPrefix(data, []byte("USER ")) ||
			bytes.HasPrefix(data, []byte("PASS "))
	}
	return false
}

func detectSMTP(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	// Check for server greeting "220 " (which is standard for SMTP servers).
	if bytes.HasPrefix(payload, []byte("220 ")) {
		// Optionally, check that there is some text following "220 ".
		if len(payload) > 5 && payload[4] != '\r' && payload[4] != '\n' {
			return true
		}
	}
	// Check for client commands like "HELO " or "EHLO ".
	if bytes.HasPrefix(payload, []byte("HELO ")) || bytes.HasPrefix(payload, []byte("EHLO ")) {
		return true
	}
	// You might also check for "MAIL FROM:" or "RCPT TO:" but those are later in the SMTP transaction.
	return false
}

func detectDNS(payload []byte) bool {
	// DNS header is 12 bytes minimum.
	if len(payload) < 12 {
		return false
	}
	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return false
	}
	// Basic sanity: at least one question or answer should be present.
	if dns.QDCount == 0 && dns.ANCount == 0 {
		return false
	}
	return true
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
