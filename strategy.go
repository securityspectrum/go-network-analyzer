package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"gopkg.in/natefinch/lumberjack.v2"
)

func selectDNSQuestion(questions []layers.DNSQuestion) layers.DNSQuestion {
	if len(questions) == 0 {
		return layers.DNSQuestion{}
	}
	// Prefer a PTR question if one exists.
	for _, q := range questions {
		if q.Type == layers.DNSTypePTR {
			return q
		}
	}
	// Fallback: return the last question in the list.
	return questions[len(questions)-1]
}

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
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			// do not return, just log the rerror
			log.Printf("Failed to create log directory: %v", err)
		}
	}

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

// ConnLogStrategy (unchanged)
type ConnLogStrategy struct {
	*BaseLogger
	connManager  *ConnectionManager
	outputFormat string
}

func (logger *ConnLogStrategy) finalizeCallback(conn *Connection, state string) {
	// Only log if not already logged
	if !conn.logged {
		logger.logConnection(conn, state)
		conn.logged = true
	}
}

func NewConnLogStrategy(filePath string, connManager *ConnectionManager, flushInterval int, outputFormat string) *ConnLogStrategy {
	logger := &ConnLogStrategy{
		BaseLogger:   NewBaseLogger(filePath, time.Duration(flushInterval)*time.Second),
		connManager:  connManager,
		outputFormat: outputFormat,
	}
	// Set the connection manager’s finalize callback to our method.
	connManager.finalizeCallback = logger.finalizeCallback
	return logger
}

func (logger *ConnLogStrategy) Log(event PacketEvent) {
	_ = logger.connManager.UpdateConnection(event)
	//if conn == nil {
	//	return
	//}
	//state := logger.connManager.GetConnState(conn)
	//// For TCP, log if state is not S0.
	//if conn.protocol == "tcp" {
	//	if state != "S0" && !conn.logged {
	//		logger.logConnection(conn, state)
	//		conn.logged = true
	//	}
	//}
	//// For other protocols, log immediately.
	//if conn.protocol == "udp" || conn.protocol == "icmp" || conn.protocol == "igmp" {
	//	if !conn.logged {
	//		logger.logConnection(conn, state)
	//		conn.logged = true
	//	}
	//}
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
	// Log any connections that have not yet been finalized.
	logger.connManager.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		if !conn.logged {
			state := logger.connManager.GetConnState(conn)
			logger.logConnection(conn, state)
			conn.logged = true
		}
		return true
	})
	logger.BaseLogger.Close()
}

type QueryInfo struct {
	Timestamp time.Time
	DNS       *layers.DNS
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	SessionID string
	Uid       string
}

// DNSLogStrategy logs DNS events.
type DNSLogStrategy struct {
	*BaseLogger
	outputFormat   string
	queries        map[string]QueryInfo // stores a deep copy of DNS info
	loggedSessions map[string]bool
	qsLock         sync.Mutex
}

func NewDNSLogStrategy(filePath string, flushInterval int, outputFormat string) *DNSLogStrategy {
	dls := &DNSLogStrategy{
		BaseLogger:     NewBaseLogger(filePath, time.Duration(flushInterval)*time.Second),
		outputFormat:   outputFormat,
		queries:        make(map[string]QueryInfo),
		loggedSessions: make(map[string]bool),
	}
	// Start the expiration routine
	go dls.ExpireQueries(5 * time.Second)
	return dls
}

// dnsQuestionsToString returns a comma-separated string of all DNS question names.
func dnsQuestionsToString(questions []layers.DNSQuestion) string {
	if len(questions) == 0 {
		return "-"
	}
	var qnames []string
	for _, q := range questions {
		qnames = append(qnames, string(q.Name))
	}
	return strings.Join(qnames, ",")
}

func (logger *DNSLogStrategy) Log(event PacketEvent) {
	// Try to get the DNS layer.
	dnsLayer := event.Packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		// For known DNS UDP ports, try manual decode.
		if udpLayer := event.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if udp.SrcPort == 53 || udp.DstPort == 53 ||
				udp.SrcPort == 5353 || udp.DstPort == 5353 ||
				udp.SrcPort == 5355 || udp.DstPort == 5355 {
				var dns layers.DNS
				if err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err == nil {
					dnsLayer = &dns
				} else {
					log.Printf("[%.6f] [DNS decode failed] Uid: %s Error: %v",
						float64(event.Timestamp.UnixNano())/1e9, event.Uid, err)
					return
				}
			} else {
				return
			}
		} else {
			return
		}
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

	// Build a composite key using SessionID and DNS transaction ID.
	key := event.SessionID + fmt.Sprintf("-%d", dns.ID)
	// For multicast DNS ports, append timestamp to ensure uniqueness.
	if srcPort == 5353 || dstPort == 5353 || srcPort == 5355 || dstPort == 5355 {
		key = key + fmt.Sprintf("-%d", event.Timestamp.UnixNano())
	}

	logger.qsLock.Lock()
	// If this is a query (QR == false), store full QueryInfo and return.
	if !dns.QR {
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
		qi := QueryInfo{
			Timestamp: event.Timestamp,
			DNS:       dns,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			SessionID: event.SessionID,
			Uid:       event.Uid,
		}
		logger.queries[key] = qi
		logger.qsLock.Unlock()
		if verbose {
			log.Printf("[%.6f] [DNSLogStrategy] Stored query, key: %s, Uid: %s",
				float64(event.Timestamp.UnixNano())/1e9, key, event.Uid)
		}
		return
	}

	// For responses, retrieve and remove the stored QueryInfo.
	var rttStr string = "-"
	var qi QueryInfo
	if stored, found := logger.queries[key]; found {
		qi = stored
		rttSec := event.Timestamp.Sub(stored.Timestamp).Seconds()
		rttStr = fmt.Sprintf("%.6f", rttSec)
		delete(logger.queries, key)
	}
	logger.loggedSessions[key] = true
	logger.qsLock.Unlock()

	// Get source/destination IP addresses.
	var srcIP, dstIP string
	if qi.SrcIP != "" && qi.DstIP != "" {
		srcIP = qi.SrcIP
		dstIP = qi.DstIP
	} else {
		if ipLayer := event.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		} else if ipLayer := event.Packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		}
	}

	// Instead of choosing a single DNS question via a heuristic, we join all questions.
	dnsQuery := dnsQuestionsToString(dns.Questions)
	qclass := uint16(0)
	qtype := uint16(0)
	qclassName := "-"
	qtypeName := "-"
	if len(dns.Questions) > 0 {
		// Use the first question’s class and type.
		qclass = uint16(dns.Questions[0].Class)
		qtype = uint16(dns.Questions[0].Type)
		qclassName = dnsClassToString(qclass)
		qtypeName = dnsTypeToString(dns.Questions[0].Type)
	}

	// Determine originator/responder: for responses, flip IPs.
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
		log.Printf("Logged DNS event: %s", logString)
	}
}

func (logger *DNSLogStrategy) ExpireQueries(expireAfter time.Duration) {
	ticker := time.NewTicker(expireAfter)
	defer ticker.Stop()

	for range ticker.C {
		logger.qsLock.Lock()
		now := time.Now()
		for key, qi := range logger.queries {
			if now.Sub(qi.Timestamp) > expireAfter {
				// Build a log record for the unanswered query.
				dns := qi.DNS
				chosenQuestion := selectDNSQuestion(dns.Questions)
				dnsQuery := string(chosenQuestion.Name)
				qclass := uint16(chosenQuestion.Class)
				qtype := uint16(chosenQuestion.Type)
				qclassName := dnsClassToString(qclass)
				qtypeName := dnsTypeToString(chosenQuestion.Type)

				logEntry := DNSLog{
					Timestamp:  fmt.Sprintf("%.6f", float64(qi.Timestamp.UnixNano())/1e9),
					Uid:        qi.Uid,
					SessionID:  qi.SessionID,
					OrigH:      qi.SrcIP,
					OrigP:      qi.SrcPort,
					RespH:      qi.DstIP,
					RespP:      qi.DstPort,
					Proto:      "udp",
					TransID:    dns.ID,
					Rtt:        "-",
					Query:      dnsQuery,
					QClass:     qclass,
					QClassName: qclassName,
					QType:      qtype,
					QTypeName:  qtypeName,
					RCode:      0,
					RCodeName:  "-",
					AA:         dns.AA,
					TC:         dns.TC,
					RD:         dns.RD,
					RA:         dns.RA,
					Z:          dns.Z,
					Answers:    []string{},
					TTLs:       []uint32{},
					Rejected:   false,
				}
				var logString string
				if logger.outputFormat == "plain" {
					logString = logger.formatPlainLog(logEntry)
				} else {
					data, err := json.Marshal(logEntry)
					if err != nil {
						log.Printf("Error encoding DNS JSON in ExpireQueries: %v", err)
						continue
					}
					logString = string(data)
				}
				logger.lock.Lock()
				logger.writer.WriteString(logString + "\n")
				logger.lock.Unlock()
				delete(logger.queries, key)
			}
		}
		logger.qsLock.Unlock()
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
		dnsLog.Query,
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
	// Flush remaining queries.
	logger.qsLock.Lock()
	for key, qi := range logger.queries {
		dns := qi.DNS
		query := dnsQuestionsToString(dns.Questions)
		qclass := uint16(0)
		qtype := uint16(0)
		qclassName := "-"
		qtypeName := "-"
		if len(dns.Questions) > 0 {
			qclass = uint16(dns.Questions[0].Class)
			qtype = uint16(dns.Questions[0].Type)
			qclassName = dnsClassToString(qclass)
			qtypeName = dnsTypeToString(dns.Questions[0].Type)
		}
		logEntry := DNSLog{
			Timestamp:  fmt.Sprintf("%.6f", float64(qi.Timestamp.UnixNano())/1e9),
			Uid:        qi.Uid,
			SessionID:  qi.SessionID,
			OrigH:      qi.SrcIP,
			OrigP:      qi.SrcPort,
			RespH:      qi.DstIP,
			RespP:      qi.DstPort,
			Proto:      "udp",
			TransID:    dns.ID,
			Rtt:        "-",
			Query:      query,
			QClass:     qclass,
			QClassName: qclassName,
			QType:      qtype,
			QTypeName:  qtypeName,
			RCode:      0,
			RCodeName:  "-",
			AA:         dns.AA,
			TC:         dns.TC,
			RD:         dns.RD,
			RA:         dns.RA,
			Z:          dns.Z,
			Answers:    []string{},
			TTLs:       []uint32{},
			Rejected:   false,
		}
		var logString string
		if logger.outputFormat == "plain" {
			logString = logger.formatPlainLog(logEntry)
		} else {
			data, err := json.Marshal(logEntry)
			if err != nil {
				log.Printf("Error encoding DNS JSON in Close: %v", err)
				continue
			}
			logString = string(data)
		}
		logger.lock.Lock()
		logger.writer.WriteString(logString + "\n")
		logger.lock.Unlock()
		delete(logger.queries, key)
	}
	logger.qsLock.Unlock()

	// Finally close the base logger.
	logger.BaseLogger.Close()
}

//---------------- HTTPLogStrategy ----------------//

type HTTPLogStrategy struct {
	*BaseLogger
	outputFormat string
	// Map of pending HTTP transactions, keyed by SessionID.
	httpTransactions map[string]*HTTPTransaction
	txLock           sync.Mutex
}

func NewHTTPLogStrategy(filePath string, flushInterval int, outputFormat string) *HTTPLogStrategy {
	return &HTTPLogStrategy{
		BaseLogger:       NewBaseLogger(filePath, time.Duration(flushInterval)*time.Second),
		outputFormat:     outputFormat,
		httpTransactions: make(map[string]*HTTPTransaction),
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

func extractSrcIP(packet gopacket.Packet) string {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		return ip.SrcIP.String()
	}
	return ""
}

func extractDstIP(packet gopacket.Packet) string {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		return ip.DstIP.String()
	}
	return ""
}

func extractSrcPort(packet gopacket.Packet) uint16 {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return uint16(tcp.SrcPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return uint16(udp.SrcPort)
	}
	return 0
}

func extractDstPort(packet gopacket.Packet) uint16 {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return uint16(udp.DstPort)
	}
	return 0
}

func (logger *HTTPLogStrategy) logHTTPTransaction(tx *HTTPTransaction) {
	// Build an HTTPLog record from the transaction.
	httpLog := HTTPLog{
		Timestamp:       tx.Timestamp.Format(time.RFC3339),
		Uid:             tx.Uid,
		SessionID:       tx.SessionID,
		OrigH:           tx.OrigH,
		OrigP:           tx.OrigP,
		RespH:           tx.RespH,
		RespP:           tx.RespP,
		Proto:           "tcp", // for HTTP, typically tcp
		TransDepth:      tx.TransDepth,
		Method:          tx.Method,
		Host:            tx.Host,
		URI:             tx.URI,
		UserAgent:       tx.UserAgent,
		Version:         tx.Version,
		RequestBodyLen:  tx.RequestBodyLen,
		ResponseBodyLen: tx.ResponseBodyLen,
		StatusCode:      tx.StatusCode,
		StatusMsg:       tx.StatusMsg,
		Tags:            []string{},
		RespFuids:       []string{},
	}
	var logString string
	if logger.outputFormat == "plain" {
		logString = logger.formatPlainLog(httpLog)
	} else {
		data, err := json.Marshal(httpLog)
		if err != nil {
			log.Printf("Error encoding HTTP JSON: %v", err)
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

func (logger *HTTPLogStrategy) Log(event PacketEvent) {
	appLayer := event.Packet.ApplicationLayer()
	if appLayer == nil {
		return
	}
	payload := appLayer.Payload()

	logger.txLock.Lock()
	defer logger.txLock.Unlock()

	// If the packet is an HTTP request...
	if isHTTPRequest(payload) {
		httpMethod, httpHost, httpURI, httpUserAgent, httpVersion, requestBodyLen := parseHTTPRequest(payload)
		// Create a new transaction record.
		tx := &HTTPTransaction{
			Timestamp:      event.Timestamp,
			Uid:            event.Uid,
			SessionID:      event.SessionID,
			OrigH:          extractSrcIP(event.Packet), // assume request comes from the client
			OrigP:          extractSrcPort(event.Packet),
			RespH:          extractDstIP(event.Packet),
			RespP:          extractDstPort(event.Packet),
			TransDepth:     1,
			Method:         httpMethod,
			Host:           httpHost,
			URI:            httpURI,
			UserAgent:      httpUserAgent,
			Version:        httpVersion,
			RequestBodyLen: requestBodyLen,
		}
		logger.httpTransactions[event.SessionID] = tx
		return
	}

	// If the packet is an HTTP response...
	if isHTTPResponse(payload) {
		statusCode, statusMsg, responseBodyLen := parseHTTPResponse(payload)
		if tx, exists := logger.httpTransactions[event.SessionID]; exists {
			tx.ResponseBodyLen = responseBodyLen
			tx.StatusCode = statusCode
			tx.StatusMsg = statusMsg
			logger.logHTTPTransaction(tx)
			delete(logger.httpTransactions, event.SessionID)
		} else {
			// No matching request found: log a partial transaction.
			tx := &HTTPTransaction{
				Timestamp:       event.Timestamp,
				Uid:             event.Uid,
				SessionID:       event.SessionID,
				OrigH:           extractDstIP(event.Packet),
				OrigP:           extractDstPort(event.Packet),
				RespH:           extractSrcIP(event.Packet),
				RespP:           extractSrcPort(event.Packet),
				TransDepth:      1,
				ResponseBodyLen: responseBodyLen,
				StatusCode:      statusCode,
				StatusMsg:       statusMsg,
			}
			logger.logHTTPTransaction(tx)
		}
	}
}

func (logger *HTTPLogStrategy) formatPlainLog(httpLog HTTPLog) string {
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s",
		httpLog.Timestamp,        // ts
		httpLog.Uid,              // uid
		httpLog.OrigH,            // id.orig_h
		httpLog.OrigP,            // id.orig_p
		httpLog.RespH,            // id.resp_h
		httpLog.RespP,            // id.resp_p
		httpLog.TransDepth,       // trans_depth
		httpLog.Method,           // method
		httpLog.Host,             // host
		httpLog.URI,              // uri
		httpLog.UserAgent,        // user_agent
		httpLog.Version,          // version
		httpLog.RequestBodyLen,   // request_body_len
		httpLog.ResponseBodyLen,  // response_body_len
		httpLog.StatusCode,       // status_code
		httpLog.StatusMsg,        // status_msg
		formatTags(httpLog.Tags), // tags
		// (Add more fields as needed to match Zeek’s output)
		"-",
		"-",
	)
}

func (logger *HTTPLogStrategy) Close() {
	logger.txLock.Lock()
	for _, tx := range logger.httpTransactions {
		logger.logHTTPTransaction(tx)
	}
	logger.txLock.Unlock()
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
