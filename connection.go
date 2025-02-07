// connection.go
package main

import (
	"bytes"
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

// Connection represents the state of a network flow.
type Connection struct {
	origH          string
	origP          uint16
	respH          string
	respP          uint16
	protocol       string
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
	// New fields:
	origFIN bool
	respFIN bool
	// Tracks if packets from both sides have been seen (for UDP/ICMP flows)
	bidirectional bool
	// For ICMP flows, store type and code
	icmpType          uint8
	icmpCode          uint8
	tunnelParents     string // For tunnel detection
	origSeenSYN       bool
	respSeenSYN       bool
	origSeenACK       bool
	respSeenACK       bool
	origSeenData      bool
	respSeenData      bool
	origSeenFIN       bool
	respSeenFIN       bool
	origSeenRST       bool
	respSeenRST       bool
	origSeenKeepalive bool
	respSeenKeepalive bool
	lastState         string // Track last state to detect changes
	lastHistory       string // Track last history to detect changes
}

// For TCP/UDP, the flow key is the standard 5-tuple.
// For ICMP, we use a pseudo-5-tuple that includes type and code.
func GetConnectionKey(origH string, origP uint16, respH string, respP uint16, protocol string, extras ...interface{}) string {
	if protocol == "icmp" && len(extras) >= 2 {
		icmpType := extras[0].(uint8)
		icmpCode := extras[1].(uint8)
		return fmt.Sprintf("%s-%s-icmp-%d-%d", origH, respH, icmpType, icmpCode)
	}
	return fmt.Sprintf("%s:%d-%s:%d-%s", origH, origP, respH, respP, protocol)
}

// determineEndpoints applies the well-known port heuristic regardless of TCP flags.
// If one port is below 1024 and the other is not, the side with the ephemeral port is considered the originator.
// Otherwise, lexicographical ordering is used.
func determineEndpoints(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (origH string, origP uint16, respH string, respP uint16) {
	if srcPort < 1024 && dstPort >= 1024 {
		// Server listens on well-known port; originator is client.
		return dstIP, dstPort, srcIP, srcPort
	}
	if dstPort < 1024 && srcPort >= 1024 {
		return srcIP, srcPort, dstIP, dstPort
	}
	// Fallback: order by IP (lexicographic)
	ip1 := net.ParseIP(srcIP)
	ip2 := net.ParseIP(dstIP)
	if bytes.Compare(ip1, ip2) <= 0 {
		return srcIP, srcPort, dstIP, dstPort
	}
	return dstIP, dstPort, srcIP, srcPort
}

// ConnectionManager caches flows.
type ConnectionManager struct {
	connections      sync.Map
	totalConnections uint64
	timeout          time.Duration // TCP inactivity timeout (default 5 minutes)
	udpTimeout       time.Duration // UDP inactivity timeout (default 1 minute)
	icmpTimeout      time.Duration // ICMP inactivity timeout (default 1 minute)
}

func NewConnectionManager(tcpTimeout, udpTimeout, icmpTimeout time.Duration) *ConnectionManager {
	return &ConnectionManager{
		timeout:     tcpTimeout,
		udpTimeout:  udpTimeout,
		icmpTimeout: icmpTimeout,
	}
}

// UpdateConnection processes a PacketEvent and either creates or updates an existing flow.
func (cm *ConnectionManager) UpdateConnection(event PacketEvent) *Connection {
	packet := event.Packet

	// Support both IPv4 and IPv6
	var ipLayer gopacket.Layer
	ipLayer = packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}
	if ipLayer == nil {
		return nil
	}
	var ipProto int
	var srcIP, dstIP string
	if ipv4, ok := ipLayer.(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
		ipProto = int(ipv4.Protocol)
	} else if ipv6, ok := ipLayer.(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
		ipProto = int(ipv6.NextHeader)
	}

	var srcPort, dstPort uint16
	var protocol string
	var extraParams []interface{}
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
		// For ICMP, we ignore ports and use type/code
		protocol = "icmp"
		extraParams = append(extraParams, uint8(icmp.TypeCode.Type()), uint8(icmp.TypeCode.Code()))
	} else if igmpLayer := packet.Layer(layers.LayerTypeIGMP); igmpLayer != nil {
		// IMPROVED: Detect IGMP packets.
		protocol = "igmp"
		// For IGMP, use no ports.
		srcPort, dstPort = 0, 0
	} else {
		protocol = "unknown_transport"
	}

	// Determine flow endpoints using the well-known port heuristic.
	var origH, respH string
	var origP, respP uint16
	// For ICMP, we use srcIP and dstIP directly.
	if protocol == "icmp" {
		origH = srcIP
		origP = 0
		respH = dstIP
		respP = 0
	} else {
		origH, origP, respH, respP = determineEndpoints(srcIP, srcPort, dstIP, dstPort)
	}

	// Key calculation: if ICMP, include type/code.
	var key string
	if protocol == "icmp" {
		key = GetConnectionKey(origH, origP, respH, respP, protocol, extraParams...)
	} else {
		key = GetConnectionKey(origH, origP, respH, respP, protocol)
	}

	nowSec := float64(event.Timestamp.UnixNano()) / 1e9
	// Lookup or create connection.
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
			localOrig:    isLocalIP(origH),
			localResp:    isLocalIP(respH),
			ipProto:      ipProto,
			lastPacketTS: nowSec,
		}
		// For ICMP, record type/code.
		if protocol == "icmp" && len(extraParams) >= 2 {
			conn.icmpType = extraParams[0].(uint8)
			conn.icmpCode = extraParams[1].(uint8)
		}
		cm.connections.Store(key, conn)
		atomic.AddUint64(&cm.totalConnections, 1)
		if verbose {
			log.Printf("[%.6f] [New Connection] Created: %s:%d -> %s:%d Protocol=%s",
				conn.lastSeen,
				conn.origH, conn.origP, conn.respH, conn.respP, conn.protocol)
			conn.lastState = cm.GetConnState(conn)
			conn.lastHistory = conn.history
		}
	} else {
		conn = value.(*Connection)
		if nowSec > conn.lastSeen {
			conn.lastSeen = nowSec
			conn.duration = conn.lastSeen - conn.startTime
		}

		// Only log if state or history has changed
		currentState := cm.GetConnState(conn)
		if verbose && (currentState != conn.lastState || conn.history != conn.lastHistory) {
			duration := conn.lastSeen - conn.startTime
			log.Printf("[%.6f] [Update Connection] State/History Change: %s:%d -> %s:%d Protocol=%s State=%s->%s History=%s Duration=%.6fs Packets(orig/resp)=%d/%d Bytes(orig/resp)=%d/%d",
				conn.lastSeen,
				conn.origH, conn.origP, conn.respH, conn.respP,
				conn.protocol,
				conn.lastState, currentState,
				conn.history,
				duration,
				conn.origPkts, conn.respPkts,
				conn.origBytes, conn.respBytes)
			conn.lastState = currentState
			conn.lastHistory = conn.history
		}
	}

	// Update bidirectional flag:
	// If the packet's source IP differs from the connection's originator, mark as bidirectional.
	if srcIP != conn.origH {
		conn.bidirectional = true
	}

	// Update connection state based on protocol.
	switch protocol {
	case "tcp":
		cm.updateTCPState(conn, tcpLayer.(*layers.TCP), srcIP == conn.origH)
	case "udp":
		cm.addHistory(conn, 'D', srcIP == conn.origH)
	case "icmp":
		cm.addHistory(conn, 'D', srcIP == conn.origH)
	}

	// (Optional) Detect service if not already set.
	if conn.service == "" {
		conn.service = DetectServiceForConnection(conn, packet)
	}

	// Update packet and byte counts - only count in one direction
	if srcIP == conn.origH {
		// Only count originator packets
		conn.origPkts++
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			conn.origIPBytes += len(ip.Contents) + len(ip.Payload)

			// Get application bytes from transport layer
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if len(tcp.Payload) > 0 {
					conn.origBytes += len(tcp.Payload)
				}
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if len(udp.Payload) > 0 {
					conn.origBytes += len(udp.Payload)
				}
			}
		}
	} else {
		// Only count responder packets
		conn.respPkts++
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			conn.respIPBytes += len(ip.Contents) + len(ip.Payload)

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if len(tcp.Payload) > 0 {
					conn.respBytes += len(tcp.Payload)
				}
			}
		}
	}

	// Update productive time for duration calculation
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		if len(appLayer.Payload()) > 0 {
			conn.productiveTime = float64(event.Timestamp.UnixNano()) / 1e9
		}
	}

	return conn
}
func (cm *ConnectionManager) updateTCPState(conn *Connection, tcp *layers.TCP, isOrig bool) {
	// Log significant events (for debugging).
	if verbose {
		log.Printf("[%.6f] [TCP State] %s:%d -> %s:%d Flags: SYN=%v ACK=%v FIN=%v RST=%v",
			conn.lastSeen, conn.origH, conn.origP, conn.respH, conn.respP,
			tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST)
	}
	// Initial SYN from originator.
	if tcp.SYN && !tcp.ACK {
		if isOrig && !conn.origSeenSYN {
			conn.origSeenSYN = true
			conn.origState = "S0"
			cm.addHistory(conn, 'S', isOrig)
		} else if !isOrig && !conn.respSeenSYN {
			conn.respSeenSYN = true
		}
		return
	}
	// SYN-ACK from responder.
	if tcp.SYN && tcp.ACK && !isOrig {
		if !conn.seenFirstAck {
			conn.seenFirstAck = true
			cm.addHistory(conn, 'h', isOrig)
			conn.respState = "S1"
		}
		return
	}
	// Pure ACK (no payload, FIN, or RST): no state change.
	if tcp.ACK && !tcp.FIN && !tcp.RST && len(tcp.Payload) == 0 {
		return
	}
	// Data payload: record once per direction.
	if len(tcp.Payload) > 0 {
		if isOrig && !conn.origSeenData {
			conn.origSeenData = true
			cm.addHistory(conn, 'D', isOrig)
		} else if !isOrig && !conn.respSeenData {
			conn.respSeenData = true
			cm.addHistory(conn, 'D', isOrig)
		}
		// Optionally set service to HTTP if payload starts with HTTP methods.
		payloadStr := string(tcp.Payload)
		if strings.HasPrefix(payloadStr, "GET") ||
			strings.HasPrefix(payloadStr, "POST") ||
			strings.HasPrefix(payloadStr, "HTTP/") {
			conn.service = "http"
		}
		return
	}
	// FIN events: record once per side.
	if tcp.FIN {
		if isOrig && !conn.origSeenFIN {
			conn.origSeenFIN = true
			cm.addHistory(conn, 'F', isOrig)
			conn.origState = "FIN"
		} else if !isOrig && !conn.respSeenFIN {
			conn.respSeenFIN = true
			cm.addHistory(conn, 'F', isOrig)
			conn.respState = "FIN"
		}
		return
	}
	// RST events: mark connection as rejected.
	if tcp.RST {
		if isOrig && !conn.origSeenRST {
			conn.origSeenRST = true
		} else if !isOrig && !conn.respSeenRST {
			conn.respSeenRST = true
		}
		cm.addHistory(conn, 'R', isOrig)
		conn.origState = "RESET"
		conn.respState = "RESET"
		return
	}
}

// addHistory appends a flag to the connection history, preventing identical flags
func (cm *ConnectionManager) addHistory(conn *Connection, flag byte, isOrig bool) {
	var newFlag byte
	if isOrig {
		newFlag = flag // Uppercase for originator.
	} else {
		newFlag = flag + 32 // Lowercase for responder.
	}
	// Only append if this side has not yet recorded the event.
	// (Using strings.IndexByte so that if the flag appears anywhere, we skip.)
	if strings.IndexByte(conn.history, newFlag) == -1 {
		conn.history += string(newFlag)
	}
}

func (cm *ConnectionManager) GetConnState(conn *Connection) string {
	switch conn.protocol {
	case "tcp":
		if conn.origState == "RESET" || conn.respState == "RESET" {
			return "REJ"
		}
		if conn.origSeenFIN && conn.respSeenFIN {
			return "SF"
		}
		if conn.origSeenFIN || conn.respSeenFIN {
			return "SHR"
		}
		if conn.seenFirstAck {
			return "S1"
		}
		return "S0"
	case "udp":
		if conn.bidirectional {
			return "SF"
		}
		return "S0"
	case "icmp":
		if conn.bidirectional {
			return "SF"
		}
		return "OTH"
	case "igmp":
		// For IGMP, mimic Zeek by returning unknown_transport or OTH.
		return "OTH"
	default:
		return "OTH"
	}
}

// RemoveInactiveConnections iterates over flows and evicts those that are inactive
func (cm *ConnectionManager) RemoveInactiveConnections() {
	cm.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		var timeoutSeconds float64
		switch conn.protocol {
		case "udp":
			timeoutSeconds = cm.udpTimeout.Seconds()
		case "icmp":
			timeoutSeconds = cm.icmpTimeout.Seconds()
		default: // TCP
			timeoutSeconds = cm.timeout.Seconds()
		}

		duration := conn.lastSeen - conn.startTime

		shouldRemove := false
		reason := ""

		if conn.protocol == "tcp" {
			state := cm.GetConnState(conn)
			if (state == "SF" || state == "REJ") && duration > 30 {
				shouldRemove = true
				reason = fmt.Sprintf("connection finished (%s) + 30s wait", state)
			} else if duration > timeoutSeconds {
				shouldRemove = true
				reason = fmt.Sprintf("%.2fs inactivity timeout", duration)
			}
		} else if duration > timeoutSeconds {
			shouldRemove = true
			reason = fmt.Sprintf("%.2fs inactivity timeout", duration)
		}

		if shouldRemove {
			if verbose {
				log.Printf("[%.6f] [Remove] Removing connection (%s): %s:%d -> %s:%d Protocol=%s State=%s History=%s Duration=%.2fs",
					conn.lastSeen, reason,
					conn.origH, conn.origP, conn.respH, conn.respP,
					conn.protocol, cm.GetConnState(conn), conn.history,
					conn.lastSeen-conn.startTime)
			}

			cm.FinalizeConnection(conn)
			cm.connections.Delete(key)
		}
		return true
	})
}

// FinalizeConnection computes the effective duration.
func (cm *ConnectionManager) FinalizeConnection(conn *Connection) {
	if conn.startTime > 0 && conn.productiveTime > conn.startTime {
		conn.duration = conn.productiveTime - conn.startTime
	}
}

// logConn writes a final log record for a connection.
func logConn(conn *Connection, state string) {
	if verbose {
		log.Printf("[FINAL] uid=%s history=%s duration=%.6f state=%s\n",
			conn.uid, conn.history, conn.duration, state)
	}
}

// PrintActiveConnectionsCount is used for diagnostics.
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
