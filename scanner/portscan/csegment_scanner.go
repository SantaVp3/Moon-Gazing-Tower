package portscan

import (
	"context"
	"fmt"
	"moongazing/scanner/core"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// HostResult represents the result of scanning a single host
type HostResult struct {
	IP        string       `json:"ip"`
	Alive     bool         `json:"alive"`
	Hostname  string       `json:"hostname,omitempty"`
	OpenPorts []core.PortResult `json:"open_ports,omitempty"`
	ScanTime  time.Duration `json:"scan_time_ms"`
}

// CSegmentResult represents the result of a C segment scan
type CSegmentResult struct {
	Network     string       `json:"network"`
	StartIP     string       `json:"start_ip"`
	EndIP       string       `json:"end_ip"`
	TotalHosts  int          `json:"total_hosts"`
	AliveHosts  int          `json:"alive_hosts"`
	StartTime   time.Time    `json:"start_time"`
	EndTime     time.Time    `json:"end_time"`
	Duration    string       `json:"duration"`
	Hosts       []HostResult `json:"hosts"`
}

// CSegmentScanner handles C segment scanning
type CSegmentScanner struct {
	RustScanner *RustScanScanner
	Timeout     time.Duration
	Concurrency int
	PingTimeout time.Duration
}

// NewCSegmentScanner creates a new C segment scanner
func NewCSegmentScanner(concurrency int) *CSegmentScanner {
	if concurrency == 0 {
		concurrency = 50
	}
	return &CSegmentScanner{
		RustScanner: NewRustScanScanner(),
		Timeout:     2 * time.Second,
		Concurrency: concurrency,
		PingTimeout: 1 * time.Second,
	}
}

// ParseCSegment parses a C segment notation and returns IP range
// Supports: 192.168.1.0/24, 192.168.1.1-254, 192.168.1.*
func ParseCSegment(input string) ([]string, string, error) {
	input = strings.TrimSpace(input)
	var ips []string
	var network string

	// Handle CIDR notation: 192.168.1.0/24
	if strings.Contains(input, "/24") {
		base := strings.Split(input, "/")[0]
		parts := strings.Split(base, ".")
		if len(parts) != 4 {
			return nil, "", fmt.Errorf("invalid IP format")
		}
		network = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		for i := 1; i <= 254; i++ {
			ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], i))
		}
		return ips, network, nil
	}

	// Handle wildcard: 192.168.1.*
	if strings.HasSuffix(input, ".*") {
		base := strings.TrimSuffix(input, ".*")
		parts := strings.Split(base, ".")
		if len(parts) != 3 {
			return nil, "", fmt.Errorf("invalid IP format")
		}
		network = base + ".0/24"
		for i := 1; i <= 254; i++ {
			ips = append(ips, fmt.Sprintf("%s.%d", base, i))
		}
		return ips, network, nil
	}

	// Handle range: 192.168.1.1-254 or 192.168.1.100-200
	if strings.Contains(input, "-") {
		parts := strings.Split(input, ".")
		if len(parts) != 4 {
			return nil, "", fmt.Errorf("invalid IP format")
		}
		
		rangePart := parts[3]
		rangeParts := strings.Split(rangePart, "-")
		if len(rangeParts) != 2 {
			return nil, "", fmt.Errorf("invalid range format")
		}

		var start, end int
		fmt.Sscanf(rangeParts[0], "%d", &start)
		fmt.Sscanf(rangeParts[1], "%d", &end)

		if start < 1 {
			start = 1
		}
		if end > 254 {
			end = 254
		}
		if start > end {
			return nil, "", fmt.Errorf("invalid range: start > end")
		}

		network = fmt.Sprintf("%s.%s.%s.%d-%d", parts[0], parts[1], parts[2], start, end)
		for i := start; i <= end; i++ {
			ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], i))
		}
		return ips, network, nil
	}

	// Single IP with assumed C segment
	parts := strings.Split(input, ".")
	if len(parts) == 4 {
		network = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		for i := 1; i <= 254; i++ {
			ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], i))
		}
		return ips, network, nil
	}

	return nil, "", fmt.Errorf("unsupported format")
}

// IsHostAlive checks if a host is alive using TCP connect to common ports
func (s *CSegmentScanner) IsHostAlive(ctx context.Context, ip string) bool {
	// Try common ports to detect if host is alive
	alivePorts := []int{80, 443, 22, 445, 139, 3389, 8080}
	
	for _, port := range alivePorts {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, s.PingTimeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// ScanHost scans a single host for open ports
func (s *CSegmentScanner) ScanHost(ctx context.Context, ip string, ports []int) HostResult {
	start := time.Now()
	result := HostResult{
		IP:    ip,
		Alive: false,
	}

	// Check if host is alive first
	if !s.IsHostAlive(ctx, ip) {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}

	result.Alive = true

	// Try to get hostname
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		result.Hostname = strings.TrimSuffix(names[0], ".")
	}

	// Scan specified ports using RustScan
	if len(ports) > 0 && s.RustScanner.IsAvailable() {
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = fmt.Sprintf("%d", p)
		}
		scanResult, err := s.RustScanner.ScanPorts(ctx, ip, strings.Join(portStrs, ","))
		if err == nil && scanResult != nil {
			result.OpenPorts = scanResult.Ports
		}
	}

	result.ScanTime = time.Since(start) / time.Millisecond
	return result
}

// ScanCSegment scans an entire C segment
func (s *CSegmentScanner) ScanCSegment(ctx context.Context, target string, ports []int, aliveOnly bool) *CSegmentResult {
	ips, network, err := ParseCSegment(target)
	if err != nil {
		return &CSegmentResult{
			Network: target,
			Hosts:   []HostResult{{IP: target, Alive: false}},
		}
	}

	result := &CSegmentResult{
		Network:    network,
		StartIP:    ips[0],
		EndIP:      ips[len(ips)-1],
		TotalHosts: len(ips),
		StartTime:  time.Now(),
		Hosts:      make([]HostResult, 0),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.Concurrency)

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime).String()
			return result
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(ipAddr string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			hostResult := s.ScanHost(ctx, ipAddr, ports)
			
			mu.Lock()
			if aliveOnly {
				if hostResult.Alive {
					result.Hosts = append(result.Hosts, hostResult)
					result.AliveHosts++
				}
			} else {
				if hostResult.Alive {
					result.AliveHosts++
				}
				result.Hosts = append(result.Hosts, hostResult)
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()

	// Sort hosts by IP
	sort.Slice(result.Hosts, func(i, j int) bool {
		return ipToInt(result.Hosts[i].IP) < ipToInt(result.Hosts[j].IP)
	})

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	return result
}

// ipToInt converts IP string to integer for sorting
func ipToInt(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var result uint32
	for i, part := range parts {
		var num int
		fmt.Sscanf(part, "%d", &num)
		result |= uint32(num) << (24 - 8*i)
	}
	return result
}

// QuickCSegmentScan performs a quick C segment scan (alive detection only)
func (s *CSegmentScanner) QuickCSegmentScan(ctx context.Context, target string) *CSegmentResult {
	return s.ScanCSegment(ctx, target, nil, true)
}

// FullCSegmentScan performs a full C segment scan with port scanning
func (s *CSegmentScanner) FullCSegmentScan(ctx context.Context, target string, ports []int) *CSegmentResult {
	if len(ports) == 0 {
		ports = core.GetTopPorts()
	}
	return s.ScanCSegment(ctx, target, ports, true)
}
