package main

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"
)

// Connection represents the state of a network connection.
type Connection struct {
	srcIP       string
	srcPort     uint16
	dstIP       string
	dstPort     uint16
	protocol    string
	startTime   int64 // Unix timestamp in nanoseconds
	lastSeen    int64 // Unix timestamp in nanoseconds
	packetCount uint64
	origBytes   int
	respBytes   int
	origPkts    int
	respPkts    int
	origIPBytes int
	respIPBytes int
	connState   string
	uid         string
	sessionID   string
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
func GetConnectionKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string) string {
	return fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, protocol)
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
			protocol = "TCP"
		} else if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			protocol = "UDP"
		} else {
			return
		}

		key := GetConnectionKey(ip.SrcIP.String(), srcPort, ip.DstIP.String(), dstPort, protocol)
		now := time.Now().UnixNano()

		value, exists := cm.connections.Load(key)
		if exists {
			conn := value.(*Connection)
			atomic.StoreInt64(&conn.lastSeen, now)
			atomic.AddUint64(&conn.packetCount, 1)

			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if event.Packet.NetworkLayer().NetworkFlow().Src().String() == conn.srcIP {
					conn.origBytes += len(packet.Data())
					conn.origPkts++
					conn.origIPBytes += len(ip.Payload)
				} else {
					conn.respBytes += len(packet.Data())
					conn.respPkts++
					conn.respIPBytes += len(ip.Payload)
				}

				if tcp.FIN || tcp.RST {
					conn.connState = "CLOSED"
					if verbose {
						log.Printf("Connection closed: %s\n", key)
					}
				}
			} else if udpLayer != nil {
				if event.Packet.NetworkLayer().NetworkFlow().Src().String() == conn.srcIP {
					conn.origBytes += len(packet.Data())
					conn.origPkts++
					conn.origIPBytes += len(ip.Payload)
				} else {
					conn.respBytes += len(packet.Data())
					conn.respPkts++
					conn.respIPBytes += len(ip.Payload)
				}
			}
		} else {
			conn := &Connection{
				srcIP:     ip.SrcIP.String(),
				srcPort:   srcPort,
				dstIP:     ip.DstIP.String(),
				dstPort:   dstPort,
				protocol:  protocol,
				startTime: now,
				lastSeen:  now,
				connState: "NEW",
				uid:       event.Uid,
				sessionID: event.SessionID,
			}
			cm.connections.Store(key, conn)
			atomic.AddUint64(&cm.totalConnections, 1)
		}

		if verbose {
			log.Printf("Updated connection: %s\n", key)
		}
	}
}

// GetConnection retrieves a connection by session ID.
func (cm *ConnectionManager) GetConnection(sessionID string) *Connection {
	var connection *Connection
	cm.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		if conn.sessionID == sessionID {
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

		if conn.connState == "CLOSED" {
			cm.connections.Delete(key)
			if verbose {
				log.Printf("Removed closed connection: %s\n", key)
			}
		} else if time.Duration(now-lastSeen) > cm.timeout {
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

func (cm *ConnectionManager) GetPacketCount(sessionID string) uint64 {
	var count uint64
	cm.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		if conn.sessionID == sessionID {
			count = atomic.LoadUint64(&conn.packetCount)
			return false
		}
		return true
	})
	return count
}
