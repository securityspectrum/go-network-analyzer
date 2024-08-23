package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketEvent represents a captured packet event with extended fields.
type PacketEvent struct {
	Timestamp time.Time
	Uid       string
	SessionID string
	Packet    gopacket.Packet
}

// ConnLog represents a connection log entry.
type ConnLog struct {
	Timestamp     string   `json:"ts"`
	Uid           string   `json:"uid"`
	SessionID     string   `json:"session_id"`
	SrcIP         string   `json:"id.orig_h"`
	SrcPort       uint16   `json:"id.orig_p"`
	DstIP         string   `json:"id.resp_h"`
	DstPort       uint16   `json:"id.resp_p"`
	Proto         string   `json:"proto"`
	Service       string   `json:"service,omitempty"`
	Duration      float64  `json:"duration,omitempty"`
	OrigBytes     int      `json:"orig_bytes,omitempty"`
	RespBytes     int      `json:"resp_bytes,omitempty"`
	ConnState     string   `json:"conn_state,omitempty"`
	LocalOrig     bool     `json:"local_orig,omitempty"`
	LocalResp     bool     `json:"local_resp,omitempty"`
	MissedBytes   int      `json:"missed_bytes,omitempty"`
	History       string   `json:"history,omitempty"`
	OrigPkts      int      `json:"orig_pkts,omitempty"`
	OrigIPBytes   int      `json:"orig_ip_bytes,omitempty"`
	RespPkts      int      `json:"resp_pkts,omitempty"`
	RespIPBytes   int      `json:"resp_ip_bytes,omitempty"`
	TunnelParents []string `json:"tunnel_parents,omitempty"`
	OrigL2Addr    string   `json:"orig_l2_addr,omitempty"`
	RespL2Addr    string   `json:"resp_l2_addr,omitempty"`
	Vlan          int      `json:"vlan,omitempty"`
	InnerVlan     int      `json:"inner_vlan,omitempty"`
	PacketCount   uint64   `json:"packet_count"`
}

// DNSLog represents a DNS log entry.
type DNSLog struct {
	Timestamp string   `json:"ts"`
	Uid       string   `json:"uid"`
	SessionID string   `json:"session_id"`
	OrigH     string   `json:"id.orig_h"`
	OrigP     uint16   `json:"id.orig_p"`
	RespH     string   `json:"id.resp_h"`
	RespP     uint16   `json:"id.resp_p"`
	Proto     string   `json:"proto"`
	TransID   uint16   `json:"trans_id"`
	Query     string   `json:"query,omitempty"`
	RCode     uint16   `json:"rcode"`
	RCodeName string   `json:"rcode_name"`
	AA        bool     `json:"AA"`
	TC        bool     `json:"TC"`
	RD        bool     `json:"RD"`
	RA        bool     `json:"RA"`
	Z         uint8    `json:"Z"`
	Answers   []string `json:"answers,omitempty"`
	TTLs      []uint32 `json:"TTLs,omitempty"`
	Rejected  bool     `json:"rejected"`
}

// HTTPLog represents an HTTP log entry.
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
}

// Helper functions for DNS translation.
func dnsClassToString(dnsClass layers.DNSClass) string {
	switch dnsClass {
	case layers.DNSClassIN:
		return "IN"
	case layers.DNSClassCS:
		return "CS"
	case layers.DNSClassCH:
		return "CH"
	case layers.DNSClassHS:
		return "HS"
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

func createLogFiles(baseDir string) (map[string]*os.File, error) {
	logs := make(map[string]*os.File)

	// Define the log file names
	logFileNames := map[string]string{
		"conn": "conn.log",
		"dns":  "dns.log",
		"http": "http.log",
	}

	for logType, fileName := range logFileNames {
		logFilePath := filepath.Join(baseDir, fileName)
		// Create or open the log file directly in the base directory
		logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		logs[logType] = logFile
	}

	return logs, nil
}
