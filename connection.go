package main

import (
	"fmt"
	"github.com/google/gopacket"
	"log"
	"sync"
	"sync/atomic"
	"time"

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
	startTime    int64 // Unix timestamp in nanoseconds
	lastSeen     int64 // Unix timestamp in nanoseconds
	origBytes    int
	respBytes    int
	origPkts     int
	respPkts     int
	service      string
	duration     float64
	origIPBytes  int
	respIPBytes  int
	history      string
	origFlags    map[byte]bool
	respFlags    map[byte]bool
	seenFirstAck bool
	origState    string
	respState    string
	localOrig    bool
	localResp    bool
}

// ConnectionManager manages all active connections.
type ConnectionManager struct {
	connections      sync.Map
	totalConnections uint64
	timeout          time.Duration // Connection timeout duration
}

// NewConnectionManager creates a new ConnectionManager with a timeout.
func NewConnectionManager(timeout time.Duration) *ConnectionManager {
	return &ConnectionManager{
		timeout: timeout,
	}
}

// GetConnectionKey returns a unique key for a connection based on its attributes.
func GetConnectionKey(origH string, origP uint16, respH string, respP uint16, protocol string) string {
	return fmt.Sprintf("%s:%d-%s:%d-%s", origH, origP, respH, respP, protocol)
}

// UpdateConnection updates the state of a connection or creates a new one if it doesn't exist.
func (cm *ConnectionManager) UpdateConnection(event PacketEvent) {
	packet := event.Packet
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
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
			return
		}

		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()
		isLocalSrc := isLocalIP(srcIP)

		var origH, respH string
		var origP, respP uint16
		var localOrig, localResp bool

		if isLocalSrc {
			origH, origP, respH, respP = srcIP, srcPort, dstIP, dstPort
			localOrig, localResp = true, isLocalIP(dstIP)
		} else {
			origH, origP, respH, respP = dstIP, dstPort, srcIP, srcPort
			localOrig, localResp = true, false
		}

		key := GetConnectionKey(origH, origP, respH, respP, protocol)
		now := time.Now().UnixNano()

		value, exists := cm.connections.Load(key)
		if exists {
			conn := value.(*Connection)
			atomic.StoreInt64(&conn.lastSeen, now)
			cm.updateConnectionState(conn, packet, isLocalSrc)
		} else {
			conn := &Connection{
				origH:     origH,
				origP:     origP,
				respH:     respH,
				respP:     respP,
				protocol:  protocol,
				ipVersion: 4, // Assuming IPv4 for now
				startTime: now,
				lastSeen:  now,
				origState: "INIT",
				respState: "INIT",
				uid:       event.Uid,
				localOrig: localOrig,
				localResp: localResp,
				origFlags: make(map[byte]bool),
				respFlags: make(map[byte]bool),
			}
			cm.connections.Store(key, conn)
			atomic.AddUint64(&cm.totalConnections, 1)
			cm.updateConnectionState(conn, packet, isLocalSrc)
		}

		if verbose {
			log.Printf("Updated connection: %s\n", key)
		}
	}
}

func (cm *ConnectionManager) updateConnectionState(conn *Connection, packet gopacket.Packet, isOrig bool) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ipLen := len(ip.Payload)

		if isOrig {
			conn.origPkts++
			conn.origIPBytes += ipLen
		} else {
			conn.respPkts++
			conn.respIPBytes += ipLen
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			cm.updateTCPState(conn, tcpLayer.(*layers.TCP), isOrig)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			cm.updateUDPState(conn, udpLayer.(*layers.UDP), isOrig)
		}
	}
}

func (cm *ConnectionManager) updateTCPState(conn *Connection, tcp *layers.TCP, isOrig bool) {
	if isOrig {
		conn.origBytes += len(tcp.Payload)
	} else {
		conn.respBytes += len(tcp.Payload)
	}

	cm.updateHistory(conn, tcp, isOrig)
	cm.updateState(conn, tcp, isOrig)
}

func (cm *ConnectionManager) updateUDPState(conn *Connection, udp *layers.UDP, isOrig bool) {
	if isOrig {
		conn.origBytes += len(udp.Payload)
	} else {
		conn.respBytes += len(udp.Payload)
	}

	cm.addHistory(conn, 'D', isOrig)
}

func (cm *ConnectionManager) updateHistory(conn *Connection, tcp *layers.TCP, isOrig bool) {
	if tcp.SYN {
		cm.addHistory(conn, 'S', isOrig)
	}
	if tcp.ACK {
		if !isOrig && !conn.seenFirstAck {
			conn.seenFirstAck = true
		}
		cm.addHistory(conn, 'A', isOrig)
	}
	if tcp.FIN {
		cm.addHistory(conn, 'F', isOrig)
	}
	if tcp.RST {
		cm.addHistory(conn, 'R', isOrig)
	}
	if len(tcp.Payload) > 0 {
		cm.addHistory(conn, 'D', isOrig)
	}
}

func (cm *ConnectionManager) addHistory(conn *Connection, flag byte, isOrig bool) {
	if isOrig {
		if !conn.origFlags[flag] {
			conn.origFlags[flag] = true
			conn.history += string(flag)
		}
	} else {
		if !conn.respFlags[flag] {
			conn.respFlags[flag] = true
			conn.history += string(flag + 32) // Convert to lowercase
		}
	}
}

func (cm *ConnectionManager) updateState(conn *Connection, tcp *layers.TCP, isOrig bool) {
	if tcp.RST {
		if isOrig {
			conn.origState = "RESET"
		} else {
			conn.respState = "RESET"
		}
	} else if tcp.FIN {
		if isOrig {
			conn.origState = "CLOSED"
		} else {
			conn.respState = "CLOSED"
		}
	}
}

func (cm *ConnectionManager) GetConnState(conn *Connection) string {
	if conn.origState == "RESET" || conn.respState == "RESET" {
		return "RSTO"
	} else if conn.origState == "CLOSED" && conn.respState == "CLOSED" {
		return "SF"
	} else if conn.origState == "CLOSED" || conn.respState == "CLOSED" {
		return "OTH"
	} else {
		return "S0"
	}
}

// GetConnection retrieves a connection by session ID.
func (cm *ConnectionManager) GetConnection(sessionID string) *Connection {
	var connection *Connection
	cm.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		if conn.uid == sessionID {
			connection = conn
			return false
		}
		return true
	})
	return connection
}

// RemoveInactiveConnections removes connections that have been inactive for longer than the timeout.
func (cm *ConnectionManager) RemoveInactiveConnections() {
	now := time.Now().UnixNano()
	cm.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		lastSeen := atomic.LoadInt64(&conn.lastSeen)

		if time.Duration(now-lastSeen) > cm.timeout {
			cm.connections.Delete(key)
			if verbose {
				log.Printf("Removed inactive connection: %s\n", key)
			}
		}
		return true
	})
}

// PrintActiveConnectionsCount prints the number of active connections.
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

// FinalizeConnection calculates the final duration of the connection.
func (cm *ConnectionManager) FinalizeConnection(conn *Connection) {
	if conn.startTime > 0 && conn.lastSeen > 0 {
		conn.duration = float64(conn.lastSeen-conn.startTime) / float64(time.Second)
	}
}
