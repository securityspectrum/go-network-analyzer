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
	origH        string
	origP        uint16
	respH        string
	respP        uint16
	protocol     string
	ipVersion    int
	uid          string
	startTime    float64 // stored in seconds
	lastSeen     float64 // stored in seconds
	origBytes    int
	respBytes    int
	origPkts     int
	respPkts     int
	service      string
	duration     float64
	origIPBytes  int
	respIPBytes  int
	history      string
	seenFirstAck bool
	origState    string
	respState    string
	localOrig    bool
	localResp    bool
	PacketCount  uint64
	logged       bool
	ipProto      int
	lastPacketTS float64
}

type ConnectionManager struct {
	connections      sync.Map
	totalConnections uint64
	timeout          time.Duration // Connection timeout duration
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

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	var srcPort, dstPort uint16
	var protocol string
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
	} else {
		srcPort = 0
		dstPort = 0
		protocol = "unknown_transport"
	}

	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	var origH, respH string
	var origP, respP uint16
	var localOrig, localResp bool

	// Decide local vs. remote if exactly one side is local
	if isLocalIP(srcIP) && !isLocalIP(dstIP) {
		origH, origP, respH, respP = srcIP, srcPort, dstIP, dstPort
		localOrig = true
		localResp = false
	} else if !isLocalIP(srcIP) && isLocalIP(dstIP) {
		origH, origP, respH, respP = dstIP, dstPort, srcIP, srcPort
		localOrig = false
		localResp = true
	} else {
		// Both sides local or both sides remote -> fallback
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			oh, op, rh, rp := determineEndpoints(srcIP, srcPort, dstIP, dstPort, tcp)
			origH, origP, respH, respP = oh, op, rh, rp
		} else {
			oh, op, rh, rp := determineEndpoints(srcIP, srcPort, dstIP, dstPort, nil)
			origH, origP, respH, respP = oh, op, rh, rp
		}
		// If both local, mark both sides local
		if isLocalIP(origH) && isLocalIP(respH) {
			localOrig, localResp = true, true
		}
	}

	key := GetConnectionKey(origH, origP, respH, respP, protocol)
	nowSec := float64(event.Timestamp.UnixNano()) / 1e9

	// Either load existing or create new
	value, exists := cm.connections.Load(key)
	if !exists {
		conn := &Connection{
			origH:        origH,
			origP:        origP,
			respH:        respH,
			respP:        respP,
			protocol:     protocol,
			ipVersion:    4,
			startTime:    nowSec,
			lastSeen:     nowSec,
			origState:    "INIT",
			respState:    "INIT",
			uid:          generateConnectionUID(),
			localOrig:    localOrig,
			localResp:    localResp,
			ipProto:      ipProto,
			lastPacketTS: nowSec, // initialize
		}
		cm.connections.Store(key, conn)
		atomic.AddUint64(&cm.totalConnections, 1)

		cm.updateConnectionState(conn, packet, (srcIP == origH))
		return conn
	}

	conn := value.(*Connection)
	if nowSec > conn.lastSeen {
		conn.lastSeen = nowSec
	}
	// *** Guard: only update if this packet is newer than the last processed packet ***
	if nowSec <= conn.lastPacketTS {
		return conn
	}
	conn.lastPacketTS = nowSec
	cm.updateConnectionState(conn, packet, (srcIP == conn.origH))
	return conn
}

// updateConnectionState: collect stats and update flags
func (cm *ConnectionManager) updateConnectionState(conn *Connection, packet gopacket.Packet, isOrig bool) {
	atomic.AddUint64(&conn.PacketCount, 1)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	ipLen := len(ip.Payload)

	if isOrig {
		conn.origPkts++
		conn.origIPBytes += ipLen
	} else {
		conn.respPkts++
		conn.respIPBytes += ipLen
	}

	// TCP or UDP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		// Account payload bytes
		if isOrig {
			conn.origBytes += len(tcp.Payload)
		} else {
			conn.respBytes += len(tcp.Payload)
		}
		cm.updateTCPState(conn, tcp, isOrig)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if isOrig {
			conn.origBytes += len(udp.Payload)
		} else {
			conn.respBytes += len(udp.Payload)
		}
		cm.addHistory(conn, 'D', isOrig)
	}
}

// updateTCPState sets flags based on SYN/ACK/FIN/RST
func (cm *ConnectionManager) updateTCPState(conn *Connection, tcp *layers.TCP, isOrig bool) {
	// SYN from originator
	if tcp.SYN && !tcp.ACK {
		cm.addHistory(conn, 'S', isOrig)
		conn.origState = "SYN_SENT"
		return
	}
	// SYN/ACK from responder
	if tcp.SYN && tcp.ACK && !isOrig {
		conn.respState = "SYN_RECV"
		if !conn.seenFirstAck {
			cm.addHistory(conn, 'h', isOrig)
			conn.seenFirstAck = true
		}
		return
	}
	// ACK-only
	if tcp.ACK && !tcp.FIN && !tcp.RST && len(tcp.Payload) == 0 {
		if isOrig {
			cm.addHistory(conn, 'A', true)
		} else {
			cm.addHistory(conn, 'A', false) // becomes lowercase
		}
		return
	}
	// Data
	if len(tcp.Payload) > 0 {
		if isOrig {
			cm.addHistory(conn, 'D', true)
		} else {
			cm.addHistory(conn, 'D', false)
		}
		// Basic http check
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
	// FIN
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
	// RST
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

// *** FIX: improved addHistory to prevent endless repeated flags
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
		// convert uppercase to lowercase for responder
		if flag >= 'A' && flag <= 'Z' {
			newFlag = flag + 32
		} else {
			newFlag = flag
		}
	}
	// If the last character is already the same, skip to avoid repeated letters
	if len(conn.history) > 0 && conn.history[len(conn.history)-1] == newFlag {
		return
	}
	conn.history += string(newFlag)
}

// Return a Zeek‑like state
func (cm *ConnectionManager) GetConnState(conn *Connection) string {
	if conn.protocol == "unknown_transport" {
		return "OTH"
	}
	if conn.origState == "RESET" || conn.respState == "RESET" {
		return "RSTO"
	} else if conn.origState == "CLOSED" && conn.respState == "CLOSED" {
		return "SF"
	} else if conn.respState == "CLOSED" {
		// if responder closed, partial close => SHR
		return "SHR"
	} else if conn.origState == "CLOSED" {
		// origin closed, but not responder => S1
		return "S1"
	} else if conn.origState == "SYN_SENT" {
		return "S0"
	} else if conn.seenFirstAck {
		return "S1"
	}
	return "S0"
}

func (cm *ConnectionManager) RemoveInactiveConnections() {
	now := float64(time.Now().UnixNano()) / 1e9
	timeoutSeconds := float64(cm.timeout) / float64(time.Second)
	cm.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		if now-conn.lastSeen > timeoutSeconds {
			// The connection is considered done. Finalize and log if terminal.
			cm.FinalizeConnection(conn)
			state := cm.GetConnState(conn)
			if !conn.logged && state != "S0" && state != "S1" {
				// Now we do the actual logging here, so we can capture final ACK
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

// Just finalize the duration
func (cm *ConnectionManager) FinalizeConnection(conn *Connection) {
	if conn.startTime > 0 && conn.lastSeen > conn.startTime {
		conn.duration = conn.lastSeen - conn.startTime
	}
}

// Example minimal logger: you can adapt this to your ConnLogStrategy code
func logConn(conn *Connection, state string) {
	// This is just a placeholder showing how you might log
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
