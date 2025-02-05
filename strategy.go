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
	logger.connManager.FinalizeConnection(conn)
	// Only log terminal connections (state not "S0" or "S1")
	state := logger.connManager.GetConnState(conn)
	if state == "S0" || state == "S1" {
		return
	}
	if conn.logged {
		return
	}
	conn.logged = true

	logEntry := ConnLog{
		Timestamp:     fmt.Sprintf("%.6f", conn.startTime), // already in seconds
		Uid:           conn.uid,
		OrigH:         conn.origH,
		OrigP:         conn.origP,
		RespH:         conn.respH,
		RespP:         conn.respP,
		Proto:         conn.protocol,
		Duration:      conn.duration,
		Service:       conn.service,
		OrigBytes:     conn.origBytes,
		RespBytes:     conn.respBytes,
		ConnState:     state,
		LocalOrig:     conn.localOrig,
		LocalResp:     conn.localResp,
		MissedBytes:   0,
		History:       conn.history,
		OrigPkts:      conn.origPkts,
		OrigIPBytes:   conn.origIPBytes,
		RespPkts:      conn.respPkts,
		RespIPBytes:   conn.respIPBytes,
		TunnelParents: []string{},
		PacketCount:   conn.PacketCount,
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
		log.Printf("Logged connection event: %s\n", logString)
	}
}

func (logger *ConnLogStrategy) formatPlainLog(connLog ConnLog) string {
	ipProtoStr := fmt.Sprintf("%d", connLog.IPProto)
	localOrig := "F"
	if connLog.LocalOrig {
		localOrig = "T"
	}
	localResp := "F"
	if connLog.LocalResp {
		localResp = "T"
	}
	service := connLog.Service
	if service == "" || service == "%!d(string=-)" {
		service = "-"
	}
	tunnelParents := "-"
	var durationStr, origBytesStr, respBytesStr string
	if connLog.Proto == "unknown_transport" {
		durationStr, origBytesStr, respBytesStr = "-", "-", "-"
	} else {
		durationStr = fmt.Sprintf("%.6f", connLog.Duration)
		origBytesStr = fmt.Sprintf("%d", connLog.OrigBytes)
		respBytesStr = fmt.Sprintf("%d", connLog.RespBytes)
	}
	connState := connLog.ConnState
	if connLog.Proto == "unknown_transport" {
		connState = "OTH"
	}
	historyStr := "-"
	if connLog.History != "" {
		historyStr = strings.ReplaceAll(connLog.History, "\n", "")
	}
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s",
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
		connState,
		localOrig,
		localResp,
		connLog.MissedBytes,
		historyStr,
		connLog.OrigPkts,
		connLog.OrigIPBytes,
		connLog.RespPkts,
		connLog.RespIPBytes,
		tunnelParents,
		ipProtoStr,
	)
}

func (logger *ConnLogStrategy) Close() {
	logger.BaseLogger.Close()
}

// ----------------------------------------------------------------------
// DNSLogStrategy
// ----------------------------------------------------------------------

type DNSLogStrategy struct {
	*BaseLogger
	outputFormat string
}

func NewDNSLogStrategy(file *os.File, flushInterval int, outputFormat string) *DNSLogStrategy {
	return &DNSLogStrategy{
		BaseLogger:   NewBaseLogger(file, time.Duration(flushInterval)*time.Second),
		outputFormat: outputFormat,
	}
}

func (logger *DNSLogStrategy) Log(event PacketEvent) {
	dnsLayer := event.Packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	var srcIP, dstIP, proto string
	var srcPort, dstPort uint16
	var dnsTransID uint16
	var dnsQuery, dnsRCodeName string
	var dnsRCode uint16
	var dnsAA, dnsTC, dnsRD, dnsRA, dnsRejected bool
	var dnsZ uint8
	var dnsAnswers []string
	var dnsTTLs []uint32

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
	dnsRejected = dns.OpCode == layers.DNSOpCodeNotify
	for _, answer := range dns.Answers {
		dnsAnswers = append(dnsAnswers, string(answer.Name))
		dnsTTLs = append(dnsTTLs, answer.TTL)
	}
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

func (logger *DNSLogStrategy) formatPlainLog(dnsLog DNSLog) string {
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%t\t%t\t%t\t%t\t%d\t%s\t%s\t%t",
		dnsLog.Timestamp,
		dnsLog.Uid,
		dnsLog.OrigH,
		dnsLog.OrigP,
		dnsLog.RespH,
		dnsLog.RespP,
		dnsLog.Proto,
		dnsLog.TransID,
		dnsLog.Query,
		0,   // qclass (not implemented)
		"-", // qclass_name (not implemented)
		0,   // qtype (not implemented)
		"-", // qtype_name (not implemented)
		dnsLog.RCode,
		dnsLog.RCodeName,
		dnsLog.AA,
		dnsLog.TC,
		dnsLog.RD,
		dnsLog.RA,
		dnsLog.Z,
		strings.Join(dnsLog.Answers, ","),
		formatTTLs(dnsLog.TTLs),
		dnsLog.Rejected,
	)
}

func formatTTLs(ttls []uint32) string {
	var ttlStrings []string
	for _, ttl := range ttls {
		ttlStrings = append(ttlStrings, fmt.Sprintf("%d", ttl))
	}
	return strings.Join(ttlStrings, ",")
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
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s",
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
