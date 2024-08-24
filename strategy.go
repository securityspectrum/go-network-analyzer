package main

import (
	"bufio"
	"encoding/json"
	"github.com/google/gopacket/layers"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LogStrategy interface defines the method that each logging strategy must implement
type LogStrategy interface {
	Log(event PacketEvent)
	Close()
}

type BaseLogger struct {
	file   *os.File
	writer *bufio.Writer
	lock   sync.Mutex
}

// NewBaseLogger creates a new BaseLogger instance and starts the periodic flushing
func NewBaseLogger(file *os.File) *BaseLogger {
	logger := &BaseLogger{
		file:   file,
		writer: bufio.NewWriter(file),
	}

	// Start a goroutine to periodically flush the buffer every second
	go logger.periodicFlush(1 * time.Second)

	return logger
}

// periodicFlush periodically flushes the buffer every given interval
func (logger *BaseLogger) periodicFlush(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		logger.lock.Lock()
		err := logger.writer.Flush()
		logger.lock.Unlock()

		if err != nil {
			log.Printf("Error flushing log buffer: %v", err)
		}
	}
}

// Close flushes the buffer and closes the file
func (logger *BaseLogger) Close() {
	logger.lock.Lock()
	defer logger.lock.Unlock()
	err := logger.writer.Flush()
	if err != nil {
		log.Printf("Error flushing log buffer: %v", err)
	}
	logger.file.Close()
}

type ConnLogStrategy struct {
	*BaseLogger
	connManager   *ConnectionManager
	flushInterval int
}

func NewConnLogStrategy(file *os.File, connManager *ConnectionManager, flushInterval int) *ConnLogStrategy {
	logger := &ConnLogStrategy{
		BaseLogger:    NewBaseLogger(file),
		connManager:   connManager,
		flushInterval: flushInterval,
	}
	// Start a goroutine to periodically flush the buffer based on the flushInterval
	go logger.periodicFlush(time.Duration(flushInterval) * time.Second)
	return logger
}

func (logger *ConnLogStrategy) Log(event PacketEvent) {
	packet := event.Packet
	var srcIP, dstIP, proto string
	var srcPort, dstPort uint16

	// Extract IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		proto = ip.Protocol.String()
	}

	// Extract TCP/UDP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}

	logger.connManager.UpdateConnection(event)

	conn := logger.connManager.GetConnection(event.SessionID)
	if conn == nil {
		if verbose {
			log.Printf("Warning: Connection not found for session ID: %s", event.SessionID)
		}
		return
	}

	startTime := time.Unix(0, atomic.LoadInt64(&conn.startTime))
	lastSeen := time.Unix(0, atomic.LoadInt64(&conn.lastSeen))
	duration := lastSeen.Sub(startTime).Seconds()

	logger.lock.Lock()
	defer logger.lock.Unlock()
	logEntry := ConnLog{
		Timestamp:   event.Timestamp.Format(time.RFC3339),
		Uid:         event.Uid,
		SessionID:   event.SessionID,
		SrcIP:       srcIP,
		SrcPort:     srcPort,
		DstIP:       dstIP,
		DstPort:     dstPort,
		Proto:       proto,
		Duration:    duration,
		OrigBytes:   conn.origBytes,
		RespBytes:   conn.respBytes,
		OrigPkts:    conn.origPkts,
		RespPkts:    conn.respPkts,
		OrigIPBytes: conn.origIPBytes,
		RespIPBytes: conn.respIPBytes,
		ConnState:   conn.connState,
		PacketCount: conn.packetCount,
	}
	jsonLogEntry, err := json.Marshal(logEntry)
	if err != nil {
		log.Println("Error encoding JSON:", err)
		return
	}
	logger.writer.Write(jsonLogEntry)
	logger.writer.Write([]byte("\n"))

	if verbose {
		log.Printf("Logged connection event: %s\n", jsonLogEntry)
	}
}

type DNSLogStrategy struct {
	*BaseLogger
	flushInterval int
}

func NewDNSLogStrategy(file *os.File, flushInterval int) *DNSLogStrategy {
	logger := &DNSLogStrategy{
		BaseLogger:    NewBaseLogger(file),
		flushInterval: flushInterval,
	}
	// Start a goroutine to periodically flush the buffer based on the flushInterval
	go logger.periodicFlush(time.Duration(flushInterval) * time.Second)
	return logger
}

func (logger *DNSLogStrategy) Log(event PacketEvent) {
	packet := event.Packet
	var srcIP, dstIP, proto string
	var srcPort, dstPort uint16

	var dnsTransID uint16
	var dnsQuery, dnsRCodeName string
	var dnsRCode uint16
	var dnsAA, dnsTC, dnsRD, dnsRA, dnsRejected bool
	var dnsZ uint8
	var dnsAnswers []string
	var dnsTTLs []uint32

	// Extract IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		proto = ip.Protocol.String()
	}

	// Extract TCP/UDP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}

	// Extract DNS layer
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		dnsTransID = dns.ID
		if len(dns.Questions) > 0 {
			dnsQuery = string(dns.Questions[0].Name)
		}
		dnsRCode = uint16(dns.ResponseCode)
		dnsRCodeName = dnsResponseCodeToString(dns.ResponseCode)
		dnsAA = dns.AA
		dnsTC = dns.TC
		dnsRD = dns.RD
		dnsRA = dns.RA
		dnsZ = dns.Z
		dnsRejected = dns.OpCode == layers.DNSOpCodeNotify // Assuming Notify means rejected
		for _, answer := range dns.Answers {
			dnsAnswers = append(dnsAnswers, string(answer.Name))
			dnsTTLs = append(dnsTTLs, answer.TTL)
		}
	}

	logger.lock.Lock()
	defer logger.lock.Unlock()
	logEntry := DNSLog{
		Timestamp: event.Timestamp.Format(time.RFC3339),
		Uid:       event.Uid,
		SessionID: event.SessionID,
		OrigH:     srcIP,
		OrigP:     srcPort,
		RespH:     dstIP,
		RespP:     dstPort,
		Proto:     proto,
		TransID:   dnsTransID,
		Query:     dnsQuery,
		RCode:     dnsRCode,
		RCodeName: dnsRCodeName,
		AA:        dnsAA,
		TC:        dnsTC,
		RD:        dnsRD,
		RA:        dnsRA,
		Z:         dnsZ,
		Answers:   dnsAnswers,
		TTLs:      dnsTTLs,
		Rejected:  dnsRejected,
	}
	jsonLogEntry, err := json.Marshal(logEntry)
	if err != nil {
		log.Println("Error encoding JSON:", err)
		return
	}
	logger.writer.Write(jsonLogEntry)
	logger.writer.Write([]byte("\n"))

	if verbose {
		log.Printf("Logged DNS event: %s\n", jsonLogEntry)
	}
}

type HTTPLogStrategy struct {
	*BaseLogger
	flushInterval int
}

func NewHTTPLogStrategy(file *os.File, flushInterval int) *HTTPLogStrategy {
	logger := &HTTPLogStrategy{
		BaseLogger:    NewBaseLogger(file),
		flushInterval: flushInterval,
	}
	// Start a goroutine to periodically flush the buffer based on the flushInterval
	go logger.periodicFlush(time.Duration(flushInterval) * time.Second)
	return logger
}

func parseHTTPRequest(payload []byte) (method, host, uri, userAgent, version string, requestBodyLen int) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(payload))))
	if err != nil {
		return
	}
	method = req.Method
	host = req.Host
	uri = req.RequestURI
	userAgent = req.UserAgent()
	version = req.Proto
	// Calculate the length of the request body
	if req.ContentLength > 0 {
		requestBodyLen = int(req.ContentLength)
	}
	return
}

func parseHTTPResponse(payload []byte) (statusCode int, statusMsg string, responseBodyLen int) {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(payload))), nil)
	if err != nil {
		return
	}
	statusCode = resp.StatusCode
	statusMsg = resp.Status
	// Calculate the length of the response body
	if resp.ContentLength > 0 {
		responseBodyLen = int(resp.ContentLength)
	}
	return
}

func (logger *HTTPLogStrategy) Log(event PacketEvent) {
	packet := event.Packet
	var srcIP, dstIP, proto string
	var srcPort, dstPort uint16

	var httpMethod, httpHost, httpURI, httpUserAgent, httpVersion string
	var transDepth, requestBodyLen, responseBodyLen, statusCode int
	var statusMsg string
	var tags, respFuids []string

	// Extract IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		proto = ip.Protocol.String()
	}

	// Extract TCP/UDP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}

	// Extract HTTP request/response from the application layer
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if isHTTPRequest(payload) {
			httpMethod, httpHost, httpURI, httpUserAgent, httpVersion, requestBodyLen = parseHTTPRequest(payload)
		} else if isHTTPResponse(payload) {
			statusCode, statusMsg, responseBodyLen = parseHTTPResponse(payload)
		}
	}

	logger.lock.Lock()
	defer logger.lock.Unlock()
	logEntry := HTTPLog{
		Timestamp:       event.Timestamp.Format(time.RFC3339),
		Uid:             event.Uid,
		SessionID:       event.SessionID,
		OrigH:           srcIP,
		OrigP:           srcPort,
		RespH:           dstIP,
		RespP:           dstPort,
		Proto:           proto,
		TransDepth:      transDepth,
		Method:          httpMethod,
		Host:            httpHost,
		URI:             httpURI,
		UserAgent:       httpUserAgent,
		Version:         httpVersion,
		RequestBodyLen:  requestBodyLen,
		ResponseBodyLen: responseBodyLen,
		StatusCode:      statusCode,
		StatusMsg:       statusMsg,
		Tags:            tags,
		RespFuids:       respFuids,
	}
	jsonLogEntry, err := json.Marshal(logEntry)
	if err != nil {
		log.Println("Error encoding JSON:", err)
		return
	}
	logger.writer.Write(jsonLogEntry)
	logger.writer.Write([]byte("\n"))

	if verbose {
		log.Printf("Logged HTTP event: %s\n", jsonLogEntry)
	}
}

func isHTTPRequest(payload []byte) bool {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(payload))))
	return err == nil && req.Method != ""
}

func isHTTPResponse(payload []byte) bool {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(payload))), nil)
	return err == nil && resp.StatusCode > 0
}

type LogContext struct {
	strategies map[string]LogStrategy
}

func NewLogContext() *LogContext {
	return &LogContext{strategies: make(map[string]LogStrategy)}
}

func (context *LogContext) AddStrategy(logType string, strategy LogStrategy) {
	context.strategies[logType] = strategy
}

func (context *LogContext) Log(event PacketEvent) {
	for _, strategy := range context.strategies {
		strategy.Log(event)
	}
}

func (context *LogContext) Close() {
	for _, strategy := range context.strategies {
		strategy.Close()
	}
}
