package main

import (
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketEvent struct {
	Timestamp time.Time
	Uid       string
	SessionID string
	Packet    gopacket.Packet
}

type ConnLog struct {
	Timestamp     string  `json:"ts"`
	Uid           string  `json:"uid"`
	OrigH         string  `json:"id.orig_h"`
	OrigP         uint16  `json:"id.orig_p"`
	RespH         string  `json:"id.resp_h"`
	RespP         uint16  `json:"id.resp_p"`
	Proto         string  `json:"proto"`
	Service       string  `json:"service,omitempty"`
	Duration      float64 `json:"duration,omitempty"`
	OrigBytes     int     `json:"orig_bytes,omitempty"`
	RespBytes     int     `json:"resp_bytes,omitempty"`
	ConnState     string  `json:"conn_state,omitempty"`
	LocalOrig     string  `json:"local_orig,omitempty"`
	LocalResp     string  `json:"local_resp,omitempty"`
	MissedBytes   int     `json:"missed_bytes,omitempty"`
	History       string  `json:"history,omitempty"`
	OrigPkts      int     `json:"orig_pkts,omitempty"`
	OrigIPBytes   int     `json:"orig_ip_bytes,omitempty"`
	RespPkts      int     `json:"resp_pkts,omitempty"`
	RespIPBytes   int     `json:"resp_ip_bytes,omitempty"`
	TunnelParents string  `json:"tunnel_parents,omitempty"`
	IPProto       int     `json:"ip_proto"`
}

type DNSLog struct {
	Timestamp  string   `json:"ts"`
	Uid        string   `json:"uid"`
	SessionID  string   `json:"session_id"`
	OrigH      string   `json:"id.orig_h"`
	OrigP      uint16   `json:"id.orig_p"`
	RespH      string   `json:"id.resp_h"`
	RespP      uint16   `json:"id.resp_p"`
	Proto      string   `json:"proto"`
	TransID    uint16   `json:"trans_id"`
	Rtt        string   `json:"rtt"`
	Query      string   `json:"query"`
	QClass     uint16   `json:"qclass"`
	QClassName string   `json:"qclass_name"`
	QType      uint16   `json:"qtype"`
	QTypeName  string   `json:"qtype_name"`
	RCode      uint16   `json:"rcode"`
	RCodeName  string   `json:"rcode_name"`
	AA         bool     `json:"AA"`
	TC         bool     `json:"TC"`
	RD         bool     `json:"RD"`
	RA         bool     `json:"RA"`
	Z          uint8    `json:"Z"`
	Answers    []string `json:"answers"`
	TTLs       []uint32 `json:"TTLs"`
	Rejected   bool     `json:"rejected"`
}

type HTTPLog struct {
	Timestamp       string   `json:"ts"`
	Uid             string   `json:"uid"`
	SessionID       string   `json:"session_id"`
	OrigH           string   `json:"id.orig_h"`
	OrigP           uint16   `json:"id.orig_p"`
	RespH           string   `json:"id.resp_h"`
	RespP           uint16   `json:"id.resp_p"`
	Proto           string   `json:"proto"`
	TransDepth      int      `json:"trans_depth"`
	Method          string   `json:"method"`
	Host            string   `json:"host"`
	URI             string   `json:"uri"`
	UserAgent       string   `json:"user_agent"`
	Version         string   `json:"version"`
	RequestBodyLen  int      `json:"request_body_len"`
	ResponseBodyLen int      `json:"response_body_len"`
	StatusCode      int      `json:"status_code"`
	StatusMsg       string   `json:"status_msg"`
	Tags            []string `json:"tags"`
	RespFuids       []string `json:"resp_fuids"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	RespMimeTypes   []string `json:"resp_mime_types"`
}

// HTTPTransaction holds the request and response information for one HTTP transaction.
type HTTPTransaction struct {
	Timestamp  time.Time
	Uid        string
	SessionID  string
	OrigH      string // client IP
	OrigP      uint16 // client port
	RespH      string // server IP
	RespP      uint16 // server port
	TransDepth int
	// Request fields:
	Method         string
	Host           string
	URI            string
	UserAgent      string
	Version        string
	RequestBodyLen int
	// Response fields:
	ResponseBodyLen int
	StatusCode      int
	StatusMsg       string
	// Extracted credentials from basic auth:
	Username string
	Password string
	// Extracted MIME type from the response:
	RespMimeType string
}

func dnsClassToString(dnsClass uint16) string {
	switch dnsClass {
	case 1:
		return "C_INTERNET"
	case 2:
		return "CS"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 32769:
		return "qclass-32769"
	default:
		return "UNKNOWN"
	}
}

func dnsTypeToString(dnsType layers.DNSType) string {
	switch dnsType {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeSRV:
		return "SRV"
	default:
		return "UNKNOWN"
	}
}

func dnsResponseCodeToString(dnsRCode layers.DNSResponseCode) string {
	switch dnsRCode {
	case layers.DNSResponseCodeNoErr:
		return "NOERROR"
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeNotImp:
		return "NOTIMP"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	default:
		return "UNKNOWN"
	}
}

func createLogFiles(baseDir string) (map[string]string, error) {
	logs := make(map[string]string)
	logFileNames := map[string]string{
		"conn": "conn.log",
		"dns":  "dns.log",
		"http": "http.log",
	}
	for logType, fileName := range logFileNames {
		logFilePath := filepath.Join(baseDir, fileName)
		logs[logType] = logFilePath
	}
	return logs, nil
}
