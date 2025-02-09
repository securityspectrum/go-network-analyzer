// strategy.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogStrategy defines the interface for logging strategies.
type LogStrategy interface {
	Log(event PacketEvent)
	Close()
}

// BaseLogger uses lumberjack for log rotation.
type BaseLogger struct {
	closer io.WriteCloser
	writer *bufio.Writer
	lock   sync.Mutex
}

func NewBaseLogger(filePath string, flushInterval time.Duration) *BaseLogger {
	fmt.Println("Writing to file:", filePath)
	ljLogger := &lumberjack.Logger{
		Filename:   filePath,
		MaxSize:    100, // megabytes
		MaxBackups: 3,
		MaxAge:     28, // days
		Compress:   true,
	}
	bl := &BaseLogger{
		closer: ljLogger,
		writer: bufio.NewWriter(ljLogger),
	}
	go bl.periodicFlush(flushInterval)
	return bl
}

func (b *BaseLogger) periodicFlush(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		b.lock.Lock()
		if err := b.writer.Flush(); err != nil {
			log.Printf("Error flushing log buffer: %v", err)
		}
		b.lock.Unlock()
	}
}

func (b *BaseLogger) Close() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.writer.Flush()
	if err := b.closer.Close(); err != nil {
		log.Printf("Error closing log file: %v", err)
	}
}

// ConnLogStrategy logs connection events.
type ConnLogStrategy struct {
	*BaseLogger
	connManager  *ConnectionManager
	outputFormat string
}

func NewConnLogStrategy(filePath string, connManager *ConnectionManager, flushInterval int, outputFormat string) *ConnLogStrategy {
	return &ConnLogStrategy{
		BaseLogger:   NewBaseLogger(filePath, time.Duration(flushInterval)*time.Second),
		connManager:  connManager,
		outputFormat: outputFormat,
	}
}

func (logger *ConnLogStrategy) Log(event PacketEvent) {
	conn := logger.connManager.UpdateConnection(event)
	if conn == nil {
		return
	}
	state := logger.connManager.GetConnState(conn)
	// For TCP, log if state is not S0 (i.e. handshake complete and/or data exists)
	if conn.protocol == "tcp" {
		if state != "S0" && !conn.logged {
			logger.logConnection(conn, state)
			conn.logged = true
		}
	}
	// For other protocols, log immediately.
	if conn.protocol == "udp" || conn.protocol == "icmp" || conn.protocol == "igmp" {
		if !conn.logged {
			logger.logConnection(conn, state)
			conn.logged = true
		}
	}
}

func (logger *ConnLogStrategy) logConnection(conn *Connection, state string) {
	logger.connManager.FinalizeConnection(conn)
	localOrig := "F"
	if conn.localOrig {
		localOrig = "T"
	}
	localResp := "F"
	if conn.localResp {
		localResp = "T"
	}
	logEntry := ConnLog{
		Timestamp:     fmt.Sprintf("%.6f", conn.startTime),
		Uid:           conn.uid,
		OrigH:         conn.origH,
		OrigP:         conn.origP,
		RespH:         conn.respH,
		RespP:         conn.respP,
		Proto:         conn.protocol,
		Service:       conn.service,
		Duration:      conn.duration,
		OrigBytes:     conn.origBytes,
		RespBytes:     conn.respBytes,
		ConnState:     state,
		LocalOrig:     localOrig,
		LocalResp:     localResp,
		MissedBytes:   0,
		History:       conn.history,
		OrigPkts:      conn.origPkts,
		OrigIPBytes:   conn.origIPBytes,
		RespPkts:      conn.respPkts,
		RespIPBytes:   conn.respIPBytes,
		TunnelParents: "-",
		IPProto:       conn.ipProto,
	}
	var logString string
	if logger.outputFormat == "plain" {
		logString = logger.formatPlainLog(logEntry)
	} else {
		data, err := json.Marshal(logEntry)
		if err != nil {
			log.Println("Error encoding JSON:", err)
			return
		}
		logString = string(data)
	}
	logger.lock.Lock()
	logger.writer.WriteString(logString + "\n")
	logger.lock.Unlock()
	if verbose {
		log.Printf("Logged connection: %s", logString)
	}
}

func (logger *ConnLogStrategy) formatPlainLog(connLog ConnLog) string {
	service := connLog.Service
	if service == "" {
		service = "-"
	}
	durationStr := "-"
	if connLog.Duration > 0 {
		durationStr = fmt.Sprintf("%.6f", connLog.Duration)
	}
	origBytesStr := "-"
	if connLog.OrigBytes > 0 {
		origBytesStr = fmt.Sprintf("%d", connLog.OrigBytes)
	}
	respBytesStr := "-"
	if connLog.RespBytes > 0 {
		respBytesStr = fmt.Sprintf("%d", connLog.RespBytes)
	}
	historyStr := "-"
	if connLog.History != "" {
		historyStr = connLog.History
	}
	tunnelParents := "-"
	if connLog.TunnelParents != "" {
		tunnelParents = connLog.TunnelParents
	}
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%s\t%d",
		connLog.Timestamp,
		connLog.Uid,
		connLog.OrigH,
		connLog.OrigP,
		connLog.RespH,
		connLog.RespP,
		connLog.Proto,
		service,
		durationStr,
		origBytesStr,
		respBytesStr,
		connLog.ConnState,
		connLog.LocalOrig,
		connLog.LocalResp,
		connLog.MissedBytes,
		historyStr,
		connLog.OrigPkts,
		connLog.OrigIPBytes,
		connLog.RespPkts,
		connLog.RespIPBytes,
		tunnelParents,
		connLog.IPProto,
	)
}

func (logger *ConnLogStrategy) Close() {
	logger.BaseLogger.Close()
}

type DNSLogStrategy struct {
	*BaseLogger
	outputFormat   string
	queries        map[string]time.Time
	loggedSessions map[string]bool
	qsLock         sync.Mutex
}

func NewDNSLogStrategy(filePath string, flushInterval int, outputFormat string) *DNSLogStrategy {
	return &DNSLogStrategy{
		BaseLogger:     NewBaseLogger(filePath, time.Duration(flushInterval)*time.Second),
		outputFormat:   outputFormat,
		queries:        make(map[string]time.Time),
		loggedSessions: make(map[string]bool),
	}
}

func (logger *DNSLogStrategy) Log(event PacketEvent) {
	if verbose {
		log.Printf("[%.6f] [Processing packet in DNSLogStrategy] Uid: %s\n",
			(float64(event.Timestamp.UnixNano()) / 1e9),
			event.Uid)
	}
	dnsLayer := event.Packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		if udpLayer := event.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			// Check if either source or destination port is 5353 or 5355.
			if udp.SrcPort == 5353 || udp.DstPort == 5353 || udp.SrcPort == 5355 || udp.DstPort == 5355 {
				// Attempt to decode the UDP payload as a DNS layer.
				var dns layers.DNS
				err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback)
				if err != nil {
					log.Printf("[%.6f] [DNS decode failed] Uid: %s Error: %v\n",
						float64(event.Timestamp.UnixNano())/1e9, event.Uid, err)
					return
				}
				// If decoding was successful, assign dnsLayer.
				dnsLayer = &dns
			}
		}
	}

	// If still no DNS layer is found, skip processing.
	if dnsLayer == nil {
		log.Printf("[%.6f] [Processing packet in DNSLogStrategy] Uid: %s Skipped\n",
			float64(event.Timestamp.UnixNano())/1e9, event.Uid)
		return
	}

	dns, _ := dnsLayer.(*layers.DNS)

	var srcPort, dstPort uint16
	var proto string
	if tcpLayer := event.Packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		proto = "tcp"
	} else if udpLayer := event.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		proto = "udp"
	}

	// Build a composite key from SessionID and DNS transaction ID.
	key := event.SessionID + fmt.Sprintf("-%d", dns.ID)

	// For multicast DNS or similar (ports 5353 and 5355), append the packet timestamp (nanosecond resolution)
	// so that each packet gets a unique key.
	if srcPort == 5353 || dstPort == 5353 || srcPort == 5355 || dstPort == 5355 {
		key = key + fmt.Sprintf("-%d", event.Timestamp.UnixNano())
	}

	// print the event that is being processed
	if verbose {
		log.Printf("[%.6f] [Processing packet in DNSLogStrategy] key: %s, DNS: %v",
			(float64(event.Timestamp.UnixNano()) / 1e9), key, dns)
	}

	logger.qsLock.Lock()
	// Store queries for later RTT computation.
	if !dns.QR {
		// Store the query under the composite key.
		if _, exists := logger.queries[key]; !exists {
			logger.queries[key] = event.Timestamp
		}
		logger.qsLock.Unlock()
		return
	}

	// At this point, we have a response.
	var rttStr string = "-"
	if ts, found := logger.queries[key]; found {
		rttSec := event.Timestamp.Sub(ts).Seconds()
		rttStr = fmt.Sprintf("%.6f", rttSec)
		delete(logger.queries, key)
	}
	logger.loggedSessions[key] = true
	logger.qsLock.Unlock()

	var srcIP, dstIP string
	if ipLayer := event.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ipLayer := event.Packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	var dnsQuery string
	var qclass uint16 = 0
	var qclassName string = "-"
	var qtype uint16 = 0
	var qtypeName string = "-"
	if len(dns.Questions) > 0 {
		question := dns.Questions[0]
		dnsQuery = string(question.Name)
		qclass = uint16(question.Class)
		qclassName = dnsClassToString(question.Class)
		qtype = uint16(question.Type)
		qtypeName = dnsTypeToString(question.Type)
	}

	var origH, respH string
	var origPort, respPort uint16
	if dns.QR {
		origH = dstIP
		origPort = dstPort
		respH = srcIP
		respPort = srcPort
	} else {
		origH = srcIP
		origPort = srcPort
		respH = dstIP
		respPort = dstPort
	}

	logEntry := DNSLog{
		Timestamp:  fmt.Sprintf("%.6f", float64(event.Timestamp.UnixNano())/1e9),
		Uid:        event.Uid,
		SessionID:  event.SessionID,
		OrigH:      origH,
		OrigP:      origPort,
		RespH:      respH,
		RespP:      respPort,
		Proto:      proto,
		TransID:    dns.ID,
		Rtt:        rttStr,
		Query:      dnsQuery,
		QClass:     qclass,
		QClassName: qclassName,
		QType:      qtype,
		QTypeName:  qtypeName,
		RCode:      uint16(dns.ResponseCode),
		RCodeName:  dnsResponseCodeToString(dns.ResponseCode),
		AA:         dns.AA,
		TC:         dns.TC,
		RD:         dns.RD,
		RA:         dns.RA,
		Z:          dns.Z,
		Answers:    []string{},
		TTLs:       []uint32{},
		Rejected:   (dns.OpCode == layers.DNSOpCodeNotify),
	}
	for _, answer := range dns.Answers {
		logEntry.Answers = append(logEntry.Answers, string(answer.Name))
		logEntry.TTLs = append(logEntry.TTLs, answer.TTL)
	}
	var logString string
	if logger.outputFormat == "plain" {
		logString = logger.formatPlainLog(logEntry)
	} else {
		data, err := json.Marshal(logEntry)
		if err != nil {
			log.Println("Error encoding DNS JSON:", err)
			return
		}
		logString = string(data)
	}
	logger.lock.Lock()
	logger.writer.WriteString(logString + "\n")
	logger.lock.Unlock()

	if verbose {
		log.Printf("Logged DNS event: %s\n", logString)
	}
}

func boolToStr(b bool) string {
	if b {
		return "T"
	}
	return "F"
}

func (logger *DNSLogStrategy) formatPlainLog(dnsLog DNSLog) string {
	query := dnsLog.Query
	if query == "" {
		query = "-"
	}
	rtt := dnsLog.Rtt
	if rtt == "" {
		rtt = "-"
	}
	answers := "-"
	if len(dnsLog.Answers) > 0 {
		answers = strings.Join(dnsLog.Answers, ",")
	}
	ttls := "-"
	if len(dnsLog.TTLs) > 0 {
		ttlStrings := make([]string, len(dnsLog.TTLs))
		for i, ttl := range dnsLog.TTLs {
			ttlStrings[i] = fmt.Sprintf("%.6f", float64(ttl))
		}
		ttls = strings.Join(ttlStrings, ",")
	}
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s",
		dnsLog.Timestamp,
		dnsLog.Uid,
		dnsLog.OrigH,
		dnsLog.OrigP,
		dnsLog.RespH,
		dnsLog.RespP,
		dnsLog.Proto,
		dnsLog.TransID,
		rtt,
		query,
		dnsLog.QClass,
		dnsLog.QClassName,
		dnsLog.QType,
		dnsLog.QTypeName,
		dnsLog.RCode,
		dnsLog.RCodeName,
		boolToStr(dnsLog.AA),
		boolToStr(dnsLog.TC),
		boolToStr(dnsLog.RD),
		boolToStr(dnsLog.RA),
		dnsLog.Z,
		answers,
		ttls,
		boolToStr(dnsLog.Rejected),
	)
}

func (logger *DNSLogStrategy) Close() {
	logger.BaseLogger.Close()
}

//---------------- HTTPLogStrategy ----------------//

type HTTPLogStrategy struct {
	*BaseLogger
	outputFormat string
}

func NewHTTPLogStrategy(filePath string, flushInterval int, outputFormat string) *HTTPLogStrategy {
	return &HTTPLogStrategy{
		BaseLogger:   NewBaseLogger(filePath, time.Duration(flushInterval)*time.Second),
		outputFormat: outputFormat,
	}
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
	if resp.ContentLength > 0 {
		responseBodyLen = int(resp.ContentLength)
	}
	return
}

func (logger *HTTPLogStrategy) Log(event PacketEvent) {
	var srcIP, dstIP, proto string
	var srcPort, dstPort uint16
	var httpMethod, httpHost, httpURI, httpUserAgent, httpVersion string
	var transDepth, requestBodyLen, responseBodyLen, statusCode int
	var statusMsg string
	var tags, respFuids []string

	if ipLayer := event.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		proto = ip.Protocol.String()
	} else if ipLayer := event.Packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		proto = "ipv6"
	}
	if tcpLayer := event.Packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		proto = "tcp"
	} else if udpLayer := event.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		proto = "udp"
	}
	if appLayer := event.Packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if isHTTPRequest(payload) {
			httpMethod, httpHost, httpURI, httpUserAgent, httpVersion, requestBodyLen = parseHTTPRequest(payload)
		} else if isHTTPResponse(payload) {
			statusCode, statusMsg, responseBodyLen = parseHTTPResponse(payload)
		}
	}
	if httpMethod == "" && statusCode == 0 {
		return
	}

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
	var logString string
	if logger.outputFormat == "plain" {
		logString = logger.formatPlainLog(logEntry)
	} else {
		data, err := json.Marshal(logEntry)
		if err != nil {
			log.Println("Error encoding HTTP JSON:", err)
			return
		}
		logString = string(data)
	}
	logger.lock.Lock()
	logger.writer.WriteString(logString + "\n")
	logger.lock.Unlock()
	if verbose {
		log.Printf("Logged HTTP event: %s\n", logString)
	}
}

func (logger *HTTPLogStrategy) formatPlainLog(httpLog HTTPLog) string {
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s",
		httpLog.Timestamp,        // string
		httpLog.Uid,              // string
		httpLog.OrigH,            // string
		httpLog.OrigP,            // %d
		httpLog.RespH,            // string
		httpLog.RespP,            // %d
		httpLog.Proto,            // string
		httpLog.TransDepth,       // %d
		httpLog.Method,           // string
		httpLog.Host,             // string
		httpLog.URI,              // string
		httpLog.Version,          // string
		httpLog.RequestBodyLen,   // %d
		httpLog.ResponseBodyLen,  // %d
		httpLog.StatusCode,       // %d
		httpLog.StatusMsg,        // string
		formatTags(httpLog.Tags), // string
	)
}

func (logger *HTTPLogStrategy) Close() {
	logger.BaseLogger.Close()
}

func formatTags(tags []string) string {
	if len(tags) == 0 {
		return "-"
	}
	return strings.Join(tags, ",")
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

// NewLogContext creates a new LogContext.
func NewLogContext() *LogContext {
	return &LogContext{strategies: make(map[string]LogStrategy)}
}

// AddStrategy adds a logging strategy.
func (lc *LogContext) AddStrategy(name string, strat LogStrategy) {
	lc.strategies[name] = strat
}

// Log sends a packet event to all logging strategies.
func (lc *LogContext) Log(event PacketEvent) {
	for _, strat := range lc.strategies {
		strat.Log(event)
	}
}

// Close calls Close on all strategies.
func (lc *LogContext) Close() {
	for _, strat := range lc.strategies {
		strat.Close()
	}
}
