package core

import (
	"moongazing/config"
	"time"
)

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

// GetCommonPorts returns common ports to scan (loaded from config)
func GetCommonPorts() []int {
	return config.GetCommonPorts()
}

// GetTopPorts returns top N common ports (loaded from config)
func GetTopPorts() []int {
	return config.GetTopPorts()
}

// GetPortServiceMap returns port to service name mapping (loaded from config)
func GetPortServiceMap() map[int]string {
	return config.GetPortServiceMap()
}

// GetServiceName returns the service name for a port
func GetServiceName(port int) string {
	serviceMap := GetPortServiceMap()
	if name, ok := serviceMap[port]; ok {
		return name
	}
	return "unknown"
}

// IsHTTPPort checks if a port is likely to run HTTP service
func IsHTTPPort(port int) bool {
	return config.IsHTTPPort(port)
}

// IsNonHTTPPort checks if a port is definitely not HTTP
func IsNonHTTPPort(port int) bool {
	return config.IsNonHTTPPort(port)
}

// DirEntry represents a discovered directory or file
type DirEntry struct {
	URL           string `json:"url"`
	Path          string `json:"path"`
	StatusCode    int    `json:"status_code"`
	ContentType   string `json:"content_type,omitempty"`
	ContentLength int64  `json:"content_length"`
	Title         string `json:"title,omitempty"`
	RedirectTo    string `json:"redirect_to,omitempty"`
}
