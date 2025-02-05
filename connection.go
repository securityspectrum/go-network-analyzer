package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Connection represents the state of a network connection.
type Connection struct {
	origH          string
	origP          uint16
	respH          string
	respP          uint16
	protocol       string
	ipVersion      int
	uid            string
	startTime      float64
	lastSeen       float64
	productiveTime float64
	origBytes      int
	respBytes      int
	origPkts       int
	respPkts       int
	service        string
	duration       float64
	origIPBytes    int
	respIPBytes    int
	history        string
	seenFirstAck   bool
	origState      string
	respState      string
	localOrig      bool
	localResp      bool
	PacketCount    uint64
	logged         bool
	ipProto        int
	lastPacketTS   float64
}

type ConnectionManager struct {
	connections      sync.Map
	totalConnections uint64
	timeout          time.Duration // Connection timeout duration (for TCP)
}

func NewConnectionManager(timeout time.Duration) *ConnectionManager {
	return &ConnectionManager{timeout: timeout}
}

func GetConnectionKey(origH string, origP uint16, respH string, respP uint16, protocol string) string {
	return fmt.Sprintf("%s:%d-%s:%d-%s", origH, origP, respH, respP, protocol)
}

// determineEndpoints tries to label originator vs. responder.
func determineEndpoints(srcIP string, srcPort uint16, dstIP string, dstPort uint16, tcp *layers.TCP) (origH string, origP uint16, respH string, respP uint16) {
	if tcp != nil {
		if tcp.SYN && !tcp.ACK {
			return srcIP, srcPort, dstIP, dstPort
		}
		// Use well-known port heuristics.
		if srcPort < 1024 && dstPort >= 1024 {
			return dstIP, dstPort, srcIP, srcPort
		}
		if dstPort < 1024 && srcPort >= 1024 {
			return srcIP, srcPort, dstIP, dstPort
		}
	}
	// Fallback: compare IP addresses.
	ip1 := net.ParseIP(srcIP)
	ip2 := net.ParseIP(dstIP)
	if bytes.Compare(ip1, ip2) <= 0 {
		return srcIP, srcPort, dstIP, dstPort
	}
	return dstIP, dstPort, srcIP, srcPort
}

func (cm *ConnectionManager) UpdateConnection(event PacketEvent) *Connection {
	packet := event.Packet
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)
	ipProto := int(ip.Protocol)

	var srcPort, dstPort uint16
	var protocol string

	// Handle TCP, UDP, and ICMP properly
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = "tcp"
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = "udp"
	} else if icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		srcPort = uint16(icmp.TypeCode >> 8)
		dstPort = 0
		protocol = "icmp"
	} else {
		protocol = "unknown_transport"
	}

	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	// Determine connection direction and local/remote status
	var origH, respH string
	var origP, respP uint16
	var localOrig, localResp bool

	if isLocalIP(srcIP) && !isLocalIP(dstIP) {
		origH, origP, respH, respP = srcIP, srcPort, dstIP, dstPort
		localOrig = true
		localResp = false
	} else if !isLocalIP(srcIP) && isLocalIP(dstIP) {
		origH, origP, respH, respP = dstIP, dstPort, srcIP, srcPort
		localOrig = false
		localResp = true
	} else {
		origH, origP, respH, respP = determineEndpoints(srcIP, srcPort, dstIP, dstPort, nil)
		localOrig = isLocalIP(origH)
		localResp = isLocalIP(respH)
	}

	key := GetConnectionKey(origH, origP, respH, respP, protocol)
	nowSec := float64(event.Timestamp.UnixNano()) / 1e9

	// Get or create connection
	value, exists := cm.connections.Load(key)
	var conn *Connection
	if !exists {
		conn = &Connection{
			origH:        origH,
			origP:        origP,
			respH:        respH,
			respP:        respP,
			protocol:     protocol,
			startTime:    nowSec,
			lastSeen:     nowSec,
			uid:          event.Uid,
			localOrig:    localOrig,
			localResp:    localResp,
			ipProto:      ipProto,
			lastPacketTS: nowSec,
		}
		cm.connections.Store(key, conn)
		atomic.AddUint64(&cm.totalConnections, 1)
	} else {
		conn = value.(*Connection)
		if nowSec > conn.lastSeen {
			conn.lastSeen = nowSec
			conn.duration = conn.lastSeen - conn.startTime
		}
	}

	// Update connection state and service
	cm.updateConnectionState(conn, packet, (srcIP == conn.origH))
	if conn.service == "" {
		conn.service = DetectServiceForConnection(conn, packet)
	}

	return conn
}

// updateConnectionState: collect stats and update flags.
func (cm *ConnectionManager) updateConnectionState(conn *Connection, packet gopacket.Packet, isOrig bool) {
	atomic.AddUint64(&conn.PacketCount, 1)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	// Use the total IP packet length (header + payload)
	ipLen := int(ip.Length)

	if isOrig {
		conn.origPkts++
		conn.origIPBytes += ipLen
	} else {
		conn.respPkts++
		conn.respIPBytes += ipLen
	}

	nowSec := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9
	productivity := false

	// TCP, UDP, or ICMP processing:
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN || (tcp.SYN && tcp.ACK) || (len(tcp.Payload) > 0) {
			productivity = true
		}
		if isOrig {
			conn.origBytes += len(tcp.Payload)
		} else {
			conn.respBytes += len(tcp.Payload)
		}
		cm.updateTCPState(conn, tcp, isOrig)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if len(udp.Payload) > 0 {
			productivity = true
		}
		if isOrig {
			conn.origBytes += len(udp.Payload)
		} else {
			conn.respBytes += len(udp.Payload)
		}
		cm.addHistory(conn, 'D', isOrig)
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		// For ICMP, mark as productive if there is payload.
		productive := false
		if icmp, _ := icmpLayer.(*layers.ICMPv4); icmp != nil {
			if len(icmp.Payload) > 0 {
				productive = true
			}
		}
		productivity = productive
		cm.addHistory(conn, 'D', isOrig)
	}

	if productivity {
		conn.productiveTime = nowSec
	}
}

// updateTCPState sets flags based on SYN/ACK/FIN/RST.
func (cm *ConnectionManager) updateTCPState(conn *Connection, tcp *layers.TCP, isOrig bool) {
	if tcp.SYN && !tcp.ACK {
		cm.addHistory(conn, 'S', isOrig)
		conn.origState = "SYN_SENT"
		return
	}
	if tcp.SYN && tcp.ACK && !isOrig {
		conn.respState = "SYN_RECV"
		if !conn.seenFirstAck {
			cm.addHistory(conn, 'h', isOrig)
			conn.seenFirstAck = true
		}
		return
	}
	// Pure ACK-only packets (no FIN, no RST, no payload)
	if tcp.ACK && !tcp.FIN && !tcp.RST && len(tcp.Payload) == 0 {
		// If this ACK comes after a FIN (e.g. within 100 ms) and the last history flag is FIN,
		// then append an "A" (for final ACK) if not already appended.
		if tcp.Ack != 0 && len(conn.history) > 0 && conn.history[len(conn.history)-1] == 'F' {
			// Append an ACK for responder FIN; for originator, similar logic could be applied.
			cm.addHistory(conn, 'A', isOrig)
		} else {
			cm.addHistory(conn, 'A', isOrig)
		}
		return
	}
	if len(tcp.Payload) > 0 {
		cm.addHistory(conn, 'D', isOrig)
		if conn.service == "" {
			payloadStr := string(tcp.Payload)
			if strings.HasPrefix(payloadStr, "GET") ||
				strings.HasPrefix(payloadStr, "POST") ||
				strings.HasPrefix(payloadStr, "HTTP/") {
				conn.service = "http"
			}
		}
		return
	}
	if tcp.FIN {
		if isOrig {
			cm.addHistory(conn, 'F', true)
			conn.origState = "CLOSED"
		} else {
			cm.addHistory(conn, 'F', false)
			conn.respState = "CLOSED"
		}
		return
	}
	if tcp.RST {
		if isOrig {
			cm.addHistory(conn, 'R', true)
			conn.origState = "RESET"
		} else {
			cm.addHistory(conn, 'R', false)
			conn.respState = "RESET"
		}
	}
}

// addHistory appends a flag to the connection history string.
func (cm *ConnectionManager) addHistory(conn *Connection, flag byte, isOrig bool) {
	// If the first packet from the responder is a FIN, Zeek-style: prepend '^f'
	if !isOrig && flag == 'F' && len(conn.history) == 0 {
		conn.history += "^f"
		return
	}
	var newFlag byte
	if isOrig {
		newFlag = flag
	} else {
		// Convert uppercase to lowercase for responder.
		if flag >= 'A' && flag <= 'Z' {
			newFlag = flag + 32
		} else {
			newFlag = flag
		}
	}
	// Avoid appending the same flag twice in a row.
	if len(conn.history) > 0 && conn.history[len(conn.history)-1] == newFlag {
		return
	}
	conn.history += string(newFlag)
}

// GetConnState returns a Zeek-like state string based on the connection flags.
// Improved to return S2/S3 for one-sided FIN events.
func (cm *ConnectionManager) GetConnState(conn *Connection) string {
	if conn.protocol == "icmp" {
		return "OTH"
	}
	if conn.protocol == "unknown_transport" {
		return "OTH"
	}
	if conn.origState == "RESET" || conn.respState == "RESET" {
		return "RSTO"
	}
	if conn.origState == "CLOSED" && conn.respState == "CLOSED" {
		return "SF"
	}
	if conn.respState == "CLOSED" && conn.origState != "CLOSED" {
		return "SHR"
	}
	if conn.origState == "CLOSED" && conn.respState != "CLOSED" {
		return "SH"
	}
	if conn.origState == "SYN_SENT" {
		return "S0"
	}
	if conn.seenFirstAck {
		return "S1"
	}
	return "S0"
}

func (cm *ConnectionManager) RemoveInactiveConnections() {
	now := float64(time.Now().UnixNano()) / 1e9
	cm.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		// Use different timeouts for UDP/ICMP versus TCP.
		var timeoutSeconds float64
		switch conn.protocol {
		case "udp", "icmp":
			timeoutSeconds = 10.0 // 10 seconds inactivity for UDP and ICMP flows.
		default:
			timeoutSeconds = float64(cm.timeout) / float64(time.Second) // e.g., 300 seconds for TCP.
		}
		if now-conn.lastSeen > timeoutSeconds {
			// Finalize and log the connection.
			cm.FinalizeConnection(conn)
			state := cm.GetConnState(conn)
			// Only log if the connection is not in early states.
			if !conn.logged && state != "S0" && state != "S1" {
				logConn(conn, state)
				conn.logged = true
			}
			cm.connections.Delete(key)
			if verbose {
				log.Printf("Removed inactive connection: %s\n", key)
			}
		}
		return true
	})
}

// FinalizeConnection computes the connection duration.
func (cm *ConnectionManager) FinalizeConnection(conn *Connection) {
	if conn.startTime > 0 && conn.productiveTime > conn.startTime {
		conn.duration = conn.productiveTime - conn.startTime
	}
}

// logConn is a minimal logger for a finalized connection.
func logConn(conn *Connection, state string) {
	if verbose {
		log.Printf("[FINAL] uid=%s history=%s duration=%.6f state=%s\n",
			conn.uid, conn.history, conn.duration, state)
	}
}

func (cm *ConnectionManager) PrintActiveConnectionsCount() {
	activeConnections := 0
	cm.connections.Range(func(key, value interface{}) bool {
		activeConnections++
		return true
	})
	if verbose {
		log.Printf("Number of active connections: %d\n", activeConnections)
	}
}

func generateConnectionUID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte('A' + i)
		}
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
