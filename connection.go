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
	origH, respH             string
	origP, respP             uint16
	protocol                 string
	uid                      string
	startTime, lastSeen      float64
	productiveTime           float64
	origBytes, respBytes     int
	origPkts, respPkts       int
	service                  string
	duration                 float64
	origIPBytes, respIPBytes int
	history                  string
	historyCount             map[byte]int
	seenFirstAck             bool
	origState, respState     string
	localOrig, localResp     bool
	PacketCount              uint64
	logged                   bool
	ipProto                  int
	lastPacketTS             float64

	// TCP event flags:
	origSeenSYN, respSeenSYN   bool
	origSeenACK, respSeenACK   bool
	origSeenData, respSeenData bool
	origSeenFIN, respSeenFIN   bool
	origSeenRST, respSeenRST   bool

	// Other fields...
	bidirectional bool

	// For ICMP flows:
	icmpType uint8
	icmpCode uint8

	// For debugging state changes:
	lastState   string
	lastHistory string
}

// GetConnectionKey returns the key (5-tuple) for a connection.
func GetConnectionKey(origH string, origP uint16, respH string, respP uint16, protocol string, extras ...interface{}) string {
	if protocol == "icmp" && len(extras) >= 2 {
		icmpType := extras[0].(uint8)
		icmpCode := extras[1].(uint8)
		return fmt.Sprintf("%s-%s-icmp-%d-%d", origH, respH, icmpType, icmpCode)
	}
	return fmt.Sprintf("%s:%d-%s:%d-%s", origH, origP, respH, respP, protocol)
}

// determineEndpoints uses a well-known port heuristic.
func determineEndpoints(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (origH string, origP uint16, respH string, respP uint16) {
	if srcPort < 1024 && dstPort >= 1024 {
		return dstIP, dstPort, srcIP, srcPort
	}
	if dstPort < 1024 && srcPort >= 1024 {
		return srcIP, srcPort, dstIP, dstPort
	}
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
	timeout          time.Duration // TCP inactivity timeout
	udpTimeout       time.Duration // UDP inactivity timeout
	icmpTimeout      time.Duration // ICMP inactivity timeout
}

func NewConnectionManager(tcpTimeout, udpTimeout, icmpTimeout time.Duration) *ConnectionManager {
	return &ConnectionManager{
		timeout:     tcpTimeout,
		udpTimeout:  udpTimeout,
		icmpTimeout: icmpTimeout,
	}
}

// UpdateConnection processes a PacketEvent and creates/updates a connection record.
func (cm *ConnectionManager) UpdateConnection(event PacketEvent) *Connection {
	packet := event.Packet

	// Support both IPv4 and IPv6.
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
		protocol = "icmp"
		extraParams = append(extraParams, uint8(icmp.TypeCode.Type()), uint8(icmp.TypeCode.Code()))
	} else if igmpLayer := packet.Layer(layers.LayerTypeIGMP); igmpLayer != nil {
		protocol = "igmp"
		srcPort, dstPort = 0, 0
	} else {
		protocol = "unknown_transport"
	}

	// Determine endpoints.
	var origH, respH string
	var origP, respP uint16
	if protocol == "icmp" {
		origH = srcIP
		origP = 0
		respH = dstIP
		respP = 0
	} else {
		origH, origP, respH, respP = determineEndpoints(srcIP, srcPort, dstIP, dstPort)
	}

	if verbose {
		log.Printf("[%.6f] [Processing] %s:%d -> %s:%d protocol=%s\n",
			float64(event.Timestamp.UnixNano())/1e9, origH, origP, respH, respP, protocol)
	}

	// Compute connection key.
	var key string
	if protocol == "icmp" {
		key = GetConnectionKey(origH, origP, respH, respP, protocol, extraParams...)
	} else {
		key = GetConnectionKey(origH, origP, respH, respP, protocol)
	}

	nowSec := float64(event.Timestamp.UnixNano()) / 1e9
	var conn *Connection
	value, exists := cm.connections.Load(key)

	if verbose {
		log.Printf("[%.6f] [Processing Key Check] %s exists=%t, uid: %s\n", nowSec, key, exists, event.Uid)
	}

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
			history:      "",
			historyCount: make(map[byte]int),
		}
		if protocol == "icmp" && len(extraParams) >= 2 {
			conn.icmpType = extraParams[0].(uint8)
			conn.icmpCode = extraParams[1].(uint8)
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

	// Mark connection as bidirectional if srcIP differs from origH.
	if srcIP != conn.origH {
		conn.bidirectional = true
	}

	// Update TCP state if applicable.
	switch protocol {
	case "tcp":
		cm.updateTCPState(conn, tcpLayer.(*layers.TCP), srcIP == conn.origH)
	case "udp":
		cm.addHistory(conn, 'D', srcIP == conn.origH)
	case "icmp":
		cm.addHistory(conn, 'D', srcIP == conn.origH)
	}

	// Optionally detect service.
	if conn.service == "" {
		conn.service = DetectServiceForConnection(conn, packet)
	}

	// Update packet and byte counts.
	if srcIP == conn.origH {
		conn.origPkts++
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			conn.origIPBytes += len(ip.Contents) + len(ip.Payload)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if len(tcp.Payload) > 0 {
					conn.origBytes += len(tcp.Payload)
				}
			} else if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if len(udp.Payload) > 0 {
					conn.origBytes += len(udp.Payload)
				}
			}
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			conn.origIPBytes += len(ip.Contents) + len(ip.Payload)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if len(tcp.Payload) > 0 {
					conn.origBytes += len(tcp.Payload)
				}
			} else if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if len(udp.Payload) > 0 {
					conn.origBytes += len(udp.Payload)
				}
			}
		}
	} else {
		conn.respPkts++
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			conn.respIPBytes += len(ip.Contents) + len(ip.Payload)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if len(tcp.Payload) > 0 {
					conn.respBytes += len(tcp.Payload)
				}
			}
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			conn.respIPBytes += len(ip.Contents) + len(ip.Payload)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if len(tcp.Payload) > 0 {
					conn.respBytes += len(tcp.Payload)
				}
			}
		}
	}

	// Update productive time if application data exists.
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		if len(appLayer.Payload()) > 0 {
			conn.productiveTime = float64(event.Timestamp.UnixNano()) / 1e9
		}
	}

	return conn
}

// updateTCPState processes TCP flags and updates connection state.
func (cm *ConnectionManager) updateTCPState(conn *Connection, tcp *layers.TCP, isOrig bool) {
	if verbose {
		log.Printf("[%.6f] [TCP State] %s:%d -> %s:%d Flags: SYN=%v ACK=%v FIN=%v RST=%v",
			conn.lastSeen, conn.origH, conn.origP, conn.respH, conn.respP,
			tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST)
	}
	// SYN (without ACK)
	if tcp.SYN && !tcp.ACK {
		if isOrig && !conn.origSeenSYN {
			conn.origSeenSYN = true
			conn.origState = "S0"
			cm.addHistory(conn, 'S', true)
		} else if !isOrig && !conn.respSeenSYN {
			conn.respSeenSYN = true
			// Pass uppercase 'S' to be normalized.
			cm.addHistory(conn, 'S', false)
		}
		return
	}
	// SYN-ACK from responder.
	if tcp.SYN && tcp.ACK && !isOrig {
		if !conn.seenFirstAck {
			conn.seenFirstAck = true
			// Pass uppercase 'H'; addHistory converts it to lowercase.
			cm.addHistory(conn, 'H', false)
			conn.respState = "S1"
		}
		return
	}
	// Pure ACK (no payload, FIN, or RST)
	if tcp.ACK && !tcp.FIN && !tcp.RST && len(tcp.Payload) == 0 {
		if isOrig && !conn.origSeenACK {
			conn.origSeenACK = true
			conn.seenFirstAck = true
			cm.addHistory(conn, 'A', true)
		}
		return
	}
	// Data payload.
	if len(tcp.Payload) > 0 {
		if isOrig && !conn.origSeenData {
			conn.origSeenData = true
			cm.addHistory(conn, 'D', true)
		} else if !isOrig && !conn.respSeenData {
			conn.respSeenData = true
			cm.addHistory(conn, 'D', false)
		}
		// Optionally detect service (e.g. HTTP) from payload.
		payloadStr := string(tcp.Payload)
		if strings.HasPrefix(payloadStr, "GET") ||
			strings.HasPrefix(payloadStr, "POST") ||
			strings.HasPrefix(payloadStr, "HTTP/") {
			conn.service = "http"
		}
		return
	}
	// FIN events.
	if tcp.FIN {
		if isOrig && !conn.origSeenFIN {
			conn.origSeenFIN = true
			cm.addHistory(conn, 'F', true)
			conn.origState = "FIN"
		} else if !isOrig && !conn.respSeenFIN {
			conn.respSeenFIN = true
			cm.addHistory(conn, 'F', false)
			conn.respState = "FIN"
		}
		return
	}
	// RST events.
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

// addHistory appends a flag to the connection history.
// Normalizes responder flags by converting uppercase to lowercase.
func (cm *ConnectionManager) addHistory(conn *Connection, flag byte, isOrig bool) {
	var normFlag byte
	if isOrig {
		normFlag = flag
	} else {
		// Convert uppercase letter to lowercase.
		if flag >= 'A' && flag <= 'Z' {
			normFlag = flag + 32
		} else {
			normFlag = flag
		}
	}
	// For once-only flags: A, D, I, Q.
	onceOnly := "ADIQadiq"
	if strings.ContainsRune(onceOnly, rune(normFlag)) {
		if strings.Contains(conn.history, string(normFlag)) {
			return
		}
		conn.history += string(normFlag)
		return
	}
	// For flags that can repeat, avoid consecutive duplicates.
	if len(conn.history) > 0 && conn.history[len(conn.history)-1] == normFlag {
		return
	}
	conn.history += string(normFlag)
}

// GetConnState computes the connection state based on the recorded flags and counters.
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
		if conn.seenFirstAck || conn.origSeenACK {
			// If handshake is complete, promote to OTH if any payload or byte count exists.
			if conn.origSeenData || conn.respSeenData || conn.origBytes > 0 || conn.respBytes > 0 {
				return "OTH"
			}
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
		return "OTH"
	default:
		return "OTH"
	}
}

// RemoveInactiveConnections evicts connections inactive for longer than the timeout.
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
					duration)
			}
			cm.FinalizeConnection(conn)
			cm.connections.Delete(key)
		}
		return true
	})
}

// FinalizeConnection computes the effective connection duration.
func (cm *ConnectionManager) FinalizeConnection(conn *Connection) {
	if conn.startTime > 0 && conn.productiveTime > conn.startTime {
		conn.duration = conn.productiveTime - conn.startTime
	} else {
		conn.duration = conn.lastSeen - conn.startTime
	}
}

// logConn writes the final connection log record.
func logConn(conn *Connection, state string) {
	if verbose {
		log.Printf("[FINAL] uid=%s history=%s duration=%.6f state=%s\n",
			conn.uid, conn.history, conn.duration, state)
	}
}

// PrintActiveConnectionsCount logs the count of active connections.
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
