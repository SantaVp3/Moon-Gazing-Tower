package scanner

import "time"

// PortResult represents the result of a port scan
type PortResult struct {
	Port        int      `json:"port"`
	State       string   `json:"state"` // open, closed, filtered
	Service     string   `json:"service,omitempty"`
	Version     string   `json:"version,omitempty"`
	Banner      string   `json:"banner,omitempty"`
	Fingerprint []string `json:"fingerprint,omitempty"`
}

// ScanResult represents the complete scan result for a target
type ScanResult struct {
	Target    string       `json:"target"`
	IP        string       `json:"ip"`
	StartTime time.Time    `json:"start_time"`
	EndTime   time.Time    `json:"end_time"`
	Ports     []PortResult `json:"ports"`
	Error     string       `json:"error,omitempty"`
}

// Common ports to scan
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017,
}

// TopPorts returns top N common ports
var TopPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
	1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
}

// PortServiceMap maps common ports to service names
var PortServiceMap = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	445:   "microsoft-ds",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	2049:  "nfs",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	9000:  "cslistener",
	27017: "mongodb",
}
