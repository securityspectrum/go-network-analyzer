package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

// ----------------------------------------------------------------------
// Logging Strategies and BaseLogger
// ----------------------------------------------------------------------

// LogStrategy defines the method that each logging strategy must implement.
type LogStrategy interface {
	Log(event PacketEvent)
	Close()
}

// BaseLogger wraps a buffered writer and flushes it periodically.
type BaseLogger struct {
	file   *os.File
	writer *bufio.Writer
	lock   sync.Mutex
}

// NewBaseLogger creates a new BaseLogger with the specified flush interval.
func NewBaseLogger(file *os.File, flushInterval time.Duration) *BaseLogger {
	logger := &BaseLogger{
		file:   file,
		writer: bufio.NewWriter(file),
	}
	go logger.periodicFlush(flushInterval)
	return logger
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
	b.file.Close()
}

// ----------------------------------------------------------------------
// ConnLogStrategy (for connection logging)
// ----------------------------------------------------------------------

type ConnLogStrategy struct {
	*BaseLogger
	connManager  *ConnectionManager
	outputFormat string
}

func NewConnLogStrategy(file *os.File, connManager *ConnectionManager, flushInterval int, outputFormat string) *ConnLogStrategy {
	return &ConnLogStrategy{
		BaseLogger:   NewBaseLogger(file, time.Duration(flushInterval)*time.Second),
		connManager:  connManager,
		outputFormat: outputFormat,
	}
}

// Instead of calling UpdateConnection and then a separate GetConnectionForEvent,
// we now call UpdateConnection (which returns the updated connection) so that each event is processed only once.
func (logger *ConnLogStrategy) Log(event PacketEvent) {
	conn := logger.connManager.UpdateConnection(event)
	if conn == nil {
		return
	}

	// Get current state
	state := logger.connManager.GetConnState(conn)

	// For UDP and ICMP, log immediately
	if conn.protocol == "udp" || conn.protocol == "icmp" {
		if !conn.logged {
			logger.logConnection(conn, state)
			conn.logged = true
		}
		return
	}

	// For TCP, wait for terminal state
	if conn.protocol == "tcp" {
		if state != "S0" && state != "S1" && !conn.logged {
			logger.logConnection(conn, state)
			conn.logged = true
		}
	}
}

// Add a new method to handle the actual logging
func (logger *ConnLogStrategy) logConnection(conn *Connection, state string) {
	logger.connManager.FinalizeConnection(conn)

	// Convert boolean values to "T"/"F" strings
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
}

func (logger *ConnLogStrategy) formatPlainLog(connLog ConnLog) string {
	// If service is empty, set it to "-"
	service := connLog.Service
	if service == "" {
		service = "-"
	}

	// Format duration with proper precision
	durationStr := "-"
	if connLog.Duration > 0 {
		durationStr = fmt.Sprintf("%.6f", connLog.Duration)
	}

	// Format byte counts
	origBytesStr := "-"
	if connLog.OrigBytes > 0 {
		origBytesStr = fmt.Sprintf("%d", connLog.OrigBytes)
	}
	respBytesStr := "-"
	if connLog.RespBytes > 0 {
		respBytesStr = fmt.Sprintf("%d", connLog.RespBytes)
	}

	// Format history string
	historyStr := "-"
	if connLog.History != "" {
		historyStr = connLog.History
	}

	// Format tunnel parents
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
		connLog.IPProto)
}

func (logger *ConnLogStrategy) Close() {
	logger.BaseLogger.Close()
}

// ----------------------------------------------------------------------
// DNSLogStrategy
// ----------------------------------------------------------------------

type DNSLogStrategy struct {
	*BaseLogger
	outputFormat   string
	queries        map[string]time.Time // map of sessionID -> query timestamp
	loggedSessions map[string]bool      // ensure one log per transaction
	qsLock         sync.Mutex           // protects queries and loggedSessions
}

func NewDNSLogStrategy(file *os.File, flushInterval int, outputFormat string) *DNSLogStrategy {
	return &DNSLogStrategy{
		BaseLogger:     NewBaseLogger(file, time.Duration(flushInterval)*time.Second),
		outputFormat:   outputFormat,
		queries:        make(map[string]time.Time),
		loggedSessions: make(map[string]bool),
	}
}

// boolToStr converts a bool to "T" or "F"
func boolToStr(b bool) string {
	if b {
		return "T"
	}
	return "F"
}

// Log logs a DNS event. It logs one record per session (using event.SessionID).
func (logger *DNSLogStrategy) Log(event PacketEvent) {
	dnsLayer := event.Packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)

	// Get the transport-layer info (for ports and protocol)
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

	// Use the SessionID from capture (derived from connection endpoints)
	key := event.SessionID

	// Lock state for this DNS mapping.
	logger.qsLock.Lock()
	// If this session has already been logged, skip.
	if logger.loggedSessions[key] {
		logger.qsLock.Unlock()
		return
	}

	// Determine if this is an mDNS packet (port 5353)
	isMDNS := (srcPort == 5353 || dstPort == 5353)

	// For non-mDNS, we prefer to log only once upon receiving a response.
	if !dns.QR && !isMDNS {
		// Store the query timestamp if not seen already.
		if _, exists := logger.queries[key]; !exists {
			logger.queries[key] = event.Timestamp
		}
		logger.qsLock.Unlock()
		return
	}

	// If this is a response, try to compute rtt using the stored query timestamp.
	var rttStr string = "-"
	if dns.QR {
		if ts, found := logger.queries[key]; found {
			rttSec := event.Timestamp.Sub(ts).Seconds()
			rttStr = fmt.Sprintf("%.6f", rttSec)
			delete(logger.queries, key)
		}
	}
	// For mDNS packets or responses with no query, rtt remains "-".

	// Mark this session as logged.
	logger.loggedSessions[key] = true
	logger.qsLock.Unlock()

	// Extract source/destination IPs (using IPv4 here)
	var srcIP, dstIP string
	if ipLayer := event.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	// Extract question-specific fields if available.
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

	// Determine originator and responder based on DNS QR flag
	var origH, respH string
	var origPort, respPort uint16
	if dns.QR {
		// Response packet - responder is the source
		origH = dstIP
		origPort = dstPort
		respH = srcIP
		respPort = srcPort
	} else {
		// Query packet - originator is the source
		origH = srcIP
		origPort = srcPort
		respH = dstIP
		respPort = dstPort
	}

	// Construct the DNSLog entry.
	logEntry := DNSLog{
		// Use Unix timestamp with microsecond precision
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

	// Process answers.
	for _, answer := range dns.Answers {
		logEntry.Answers = append(logEntry.Answers, string(answer.Name))
		logEntry.TTLs = append(logEntry.TTLs, answer.TTL)
	}

	// Format the log entry.
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

	// Write out the log entry.
	logger.lock.Lock()
	logger.writer.WriteString(logString + "\n")
	logger.lock.Unlock()

	if verbose {
		log.Printf("Logged DNS event: %s\n", logString)
	}
}

// formatPlainLog formats a DNS log entry in Zeek's plaintext output
func (logger *DNSLogStrategy) formatPlainLog(dnsLog DNSLog) string {
	// If query is empty, set it to "-"
	query := dnsLog.Query
	if query == "" {
		query = "-"
	}

	// If rtt is empty, set it to "-"
	rtt := dnsLog.Rtt
	if rtt == "" {
		rtt = "-"
	}

	// For answers, join them with commas; use "-" if empty.
	answers := "-"
	if len(dnsLog.Answers) > 0 {
		answers = strings.Join(dnsLog.Answers, ",")
	}

	// For TTLs, join each TTL with 6-decimal formatting; use "-" if none.
	ttls := "-"
	if len(dnsLog.TTLs) > 0 {
		ttlStrings := make([]string, len(dnsLog.TTLs))
		for i, ttl := range dnsLog.TTLs {
			ttlStrings[i] = fmt.Sprintf("%.6f", float64(ttl))
		}
		ttls = strings.Join(ttlStrings, ",")
	}

	// Build the formatted string with exactly 24 fields:
	// 1 ts, 2 uid, 3 id.orig_h, 4 id.orig_p, 5 id.resp_h, 6 id.resp_p,
	// 7 proto, 8 trans_id, 9 rtt, 10 query, 11 qclass, 12 qclass_name,
	// 13 qtype, 14 qtype_name, 15 rcode, 16 rcode_name, 17 AA, 18 TC,
	// 19 RD, 20 RA, 21 Z, 22 answers, 23 TTLs, 24 rejected.
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s",
		dnsLog.Timestamp,           // field 1: ts
		dnsLog.Uid,                 // field 2: uid
		dnsLog.OrigH,               // field 3: id.orig_h
		dnsLog.OrigP,               // field 4: id.orig_p
		dnsLog.RespH,               // field 5: id.resp_h
		dnsLog.RespP,               // field 6: id.resp_p
		dnsLog.Proto,               // field 7: proto
		dnsLog.TransID,             // field 8: trans_id
		rtt,                        // field 9: rtt
		query,                      // field 10: query
		dnsLog.QClass,              // field 11: qclass
		dnsLog.QClassName,          // field 12: qclass_name
		dnsLog.QType,               // field 13: qtype
		dnsLog.QTypeName,           // field 14: qtype_name
		dnsLog.RCode,               // field 15: rcode
		dnsLog.RCodeName,           // field 16: rcode_name
		boolToStr(dnsLog.AA),       // field 17: AA ("T" or "F")
		boolToStr(dnsLog.TC),       // field 18: TC ("T" or "F")
		boolToStr(dnsLog.RD),       // field 19: RD ("T" or "F")
		boolToStr(dnsLog.RA),       // field 20: RA ("T" or "F")
		dnsLog.Z,                   // field 21: Z
		answers,                    // field 22: answers
		ttls,                       // field 23: TTLs
		boolToStr(dnsLog.Rejected), // field 24: rejected
	)
}

func (logger *DNSLogStrategy) Close() {
	logger.BaseLogger.Close()
}

// ----------------------------------------------------------------------
// HTTPLogStrategy
// ----------------------------------------------------------------------

type HTTPLogStrategy struct {
	*BaseLogger
	outputFormat string
}

func NewHTTPLogStrategy(file *os.File, flushInterval int, outputFormat string) *HTTPLogStrategy {
	return &HTTPLogStrategy{
		BaseLogger:   NewBaseLogger(file, time.Duration(flushInterval)*time.Second),
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
		httpLog.Timestamp,
		httpLog.Uid,
		httpLog.OrigH,
		httpLog.OrigP,
		httpLog.RespH,
		httpLog.RespP,
		httpLog.Proto,
		httpLog.TransDepth,
		httpLog.Method,
		httpLog.Host,
		httpLog.URI,
		httpLog.Version,
		httpLog.UserAgent,
		httpLog.RequestBodyLen,
		httpLog.ResponseBodyLen,
		httpLog.StatusCode,
		httpLog.StatusMsg,
		formatTags(httpLog.Tags),
	)
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

// ----------------------------------------------------------------------
// LogContext: Aggregates all strategies.
// ----------------------------------------------------------------------

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
