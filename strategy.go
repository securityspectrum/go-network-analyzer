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
	outputFormat  string
}

func (logger *ConnLogStrategy) writeHeader() {
	if logger.outputFormat == "plain" {
		header := "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n"
		types := "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n"
		logger.writer.WriteString(header)
		logger.writer.WriteString(types)
	}
}

func NewConnLogStrategy(file *os.File, connManager *ConnectionManager, flushInterval int, outputFormat string) *ConnLogStrategy {
	logger := &ConnLogStrategy{
		BaseLogger:    NewBaseLogger(file),
		connManager:   connManager,
		flushInterval: flushInterval,
		outputFormat:  outputFormat,
	}
	// Start a goroutine to periodically flush the buffer based on the flushInterval
	go logger.periodicFlush(time.Duration(flushInterval) * time.Second)
	return logger
}

func (logger *ConnLogStrategy) Log(event PacketEvent) {
	packet := event.Packet
	var origL2Addr, respL2Addr string
	var vlan, innerVlan int

	// Extract Ethernet layer for L2 addresses and VLAN info
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		origL2Addr = eth.SrcMAC.String()
		respL2Addr = eth.DstMAC.String()
	}

	// Extract VLAN info
	if vlanLayer := packet.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
		vlan1q, _ := vlanLayer.(*layers.Dot1Q)
		vlan = int(vlan1q.VLANIdentifier)
		if vlan1q.Type == layers.EthernetTypeDot1Q {
			innerVlanLayer := packet.Layer(layers.LayerTypeDot1Q)
			if innerVlanLayer != nil {
				innerVlan1q, _ := innerVlanLayer.(*layers.Dot1Q)
				innerVlan = int(innerVlan1q.VLANIdentifier)
			}
		}
	}

	logger.connManager.UpdateConnection(event)

	conn := logger.connManager.GetConnection(event.Uid)
	if conn == nil {
		if verbose {
			log.Printf("Warning: Connection not found for UID: %s", event.Uid)
		}
		return
	}

	logger.connManager.FinalizeConnection(conn)

	logger.lock.Lock()
	defer logger.lock.Unlock()
	logEntry := ConnLog{
		Timestamp:     time.Unix(0, conn.startTime).Format(time.RFC3339Nano),
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
		ConnState:     logger.connManager.GetConnState(conn),
		LocalOrig:     conn.localOrig,
		LocalResp:     conn.localResp,
		MissedBytes:   0, // Assuming we don't track missed bytes
		History:       conn.history,
		OrigPkts:      conn.origPkts,
		OrigIPBytes:   conn.origIPBytes,
		RespPkts:      conn.respPkts,
		RespIPBytes:   conn.respIPBytes,
		TunnelParents: []string{}, // Assuming we don't track tunnel parents
		OrigL2Addr:    origL2Addr,
		RespL2Addr:    respL2Addr,
		Vlan:          vlan,
		InnerVlan:     innerVlan,
	}

	var logString string
	if logger.outputFormat == "plain" {
		logString = logger.formatPlainLog(logEntry)
	} else {
		jsonLogEntry, err := json.Marshal(logEntry)
		if err != nil {
			log.Println("Error encoding JSON:", err)
			return
		}
		logString = string(jsonLogEntry)
	}

	logger.writer.WriteString(logString + "\n")

	if verbose {
		log.Printf("Logged connection event: %s\n", logString)
	}
}

func (logger *ConnLogStrategy) formatPlainLog(connLog ConnLog) string {
	tunnelParents := "-"
	if len(connLog.TunnelParents) > 0 {
		tunnelParents = strings.Join(connLog.TunnelParents, ",")
	}

	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%s\t%s\t%.6f\t%d\t%d\t%s\t%t\t%t\t%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%d\t%d",
		connLog.Timestamp,
		connLog.Uid,
		connLog.OrigH,
		connLog.OrigP,
		connLog.RespH,
		connLog.RespP,
		connLog.Proto,
		connLog.Service,
		connLog.Duration,
		connLog.OrigBytes,
		connLog.RespBytes,
		connLog.ConnState,
		connLog.LocalOrig,
		connLog.LocalResp,
		connLog.MissedBytes,
		connLog.History,
		connLog.OrigPkts,
		connLog.OrigIPBytes,
		connLog.RespPkts,
		connLog.RespIPBytes,
		tunnelParents,
		connLog.OrigL2Addr,
		connLog.RespL2Addr,
		connLog.Vlan,
		connLog.InnerVlan,
	)
}

// Helper function to format tunnel parents
func formatTunnelParents(tunnelParents []string) string {
	if len(tunnelParents) == 0 {
		return "-"
	}
	return strings.Join(tunnelParents, ",")
}

type DNSLogStrategy struct {
	*BaseLogger
	flushInterval int
	outputFormat  string
}

func NewDNSLogStrategy(file *os.File, flushInterval int, outputFormat string) *DNSLogStrategy {
	logger := &DNSLogStrategy{
		BaseLogger:    NewBaseLogger(file),
		flushInterval: flushInterval,
		outputFormat:  outputFormat,
	}
	// Start a goroutine to periodically flush the buffer based on the flushInterval
	go logger.periodicFlush(time.Duration(flushInterval) * time.Second)
	return logger
}

func (logger *DNSLogStrategy) writeHeader() {
	if logger.outputFormat == "plain" {
		header := "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected\n"
		types := "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool\n"
		logger.writer.WriteString(header)
		logger.writer.WriteString(types)
	}
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

	var logString string
	if logger.outputFormat == "plain" {
		logString = logger.formatPlainLog(logEntry)
	} else {
		jsonLogEntry, err := json.Marshal(logEntry)
		if err != nil {
			log.Println("Error encoding JSON:", err)
			return
		}
		logString = string(jsonLogEntry)
	}

	logger.writer.WriteString(logString + "\n")

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
		0,   // qclass (not implemented in this example)
		"-", // qclass_name (not implemented in this example)
		0,   // qtype (not implemented in this example)
		"-", // qtype_name (not implemented in this example)
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

func extractDNSAnswers(dns *layers.DNS) []string {
	var answers []string
	for _, answer := range dns.Answers {
		answers = append(answers, string(answer.Name))
	}
	return answers
}

func extractDNSTTLs(dns *layers.DNS) []uint32 {
	var ttls []uint32
	for _, answer := range dns.Answers {
		ttls = append(ttls, answer.TTL)
	}
	return ttls
}

func formatTTLs(ttls []uint32) string {
	var ttlStrings []string
	for _, ttl := range ttls {
		ttlStrings = append(ttlStrings, fmt.Sprintf("%d", ttl))
	}
	return strings.Join(ttlStrings, ",")
}

type HTTPLogStrategy struct {
	*BaseLogger
	flushInterval int
	outputFormat  string
}

func NewHTTPLogStrategy(file *os.File, flushInterval int, outputFormat string) *HTTPLogStrategy {
	logger := &HTTPLogStrategy{
		BaseLogger:    NewBaseLogger(file),
		flushInterval: flushInterval,
		outputFormat:  outputFormat,
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
	var logString string
	if logger.outputFormat == "plain" {
		logString = logger.formatPlainLog(logEntry)
	} else {
		jsonLogEntry, err := json.Marshal(logEntry)
		if err != nil {
			log.Println("Error encoding JSON:", err)
			return
		}
		logString = string(jsonLogEntry)
	}

	logger.writer.WriteString(logString + "\n")

	if verbose {
		log.Printf("Logged DNS event: %s\n", logString)
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

// Helper function to format tags
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
