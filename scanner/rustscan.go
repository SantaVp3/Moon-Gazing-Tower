package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RustScanScanner 使用 RustScan 进行高速端口扫描
type RustScanScanner struct {
	BinPath       string
	Timeout       int    // 超时时间(毫秒)
	BatchSize     int    // 批量大小 (并发数)
	Ulimit        int    // 文件描述符限制
	TempDir       string
	VerifyPorts   bool   // 是否验证端口服务
	VerifyTimeout int    // 验证超时时间(秒)
	VerifyWorkers int    // 验证并发数
}

// RustScanConfig RustScan 扫描配置
type RustScanConfig struct {
	Timeout   int // 超时时间(秒)，会转换为毫秒
	BatchSize int // 批量大小/并发数
	RateLimit int // 速率限制（暂不使用，RustScan 主要靠 BatchSize 控制）
}

// NewRustScanScanner 创建 RustScan 扫描器
func NewRustScanScanner() *RustScanScanner {
	tm := NewToolsManager()
	binPath := tm.GetToolPath("rustscan")

	return &RustScanScanner{
		BinPath:       binPath,
		Timeout:       1500,  // 1.5秒超时 (毫秒) - 默认值
		BatchSize:     1000,  // 降低批量大小以提高准确性
		Ulimit:        5000,  // 文件描述符
		TempDir:       os.TempDir(),
		VerifyPorts:   true,  // 默认开启端口验证
		VerifyTimeout: 3,     // 验证超时3秒
		VerifyWorkers: 50,    // 并发验证50个端口
	}
}

// NewRustScanScannerWithConfig 使用配置创建 RustScan 扫描器
func NewRustScanScannerWithConfig(config *RustScanConfig) *RustScanScanner {
	scanner := NewRustScanScanner()
	
	if config != nil {
		// 超时时间：配置是秒，转换为毫秒
		if config.Timeout > 0 {
			scanner.Timeout = config.Timeout * 1000
		}
		// 批量大小/并发数
		if config.BatchSize > 0 {
			scanner.BatchSize = config.BatchSize
		}
	}
	
	return scanner
}

// SetConfig 更新扫描器配置
func (r *RustScanScanner) SetConfig(config *RustScanConfig) {
	if config == nil {
		return
	}
	if config.Timeout > 0 {
		r.Timeout = config.Timeout * 1000 // 秒转毫秒
	}
	if config.BatchSize > 0 {
		r.BatchSize = config.BatchSize
	}
}

// IsAvailable 检查是否可用
func (r *RustScanScanner) IsAvailable() bool {
	return r.BinPath != "" && fileExists(r.BinPath)
}

// ScanPorts 扫描端口
// target: 目标 IP 或域名
// ports: 逗号分隔的端口列表，如 "80,443,8080"
func (r *RustScanScanner) ScanPorts(ctx context.Context, target string, ports string) (*ScanResult, error) {
	if !r.IsAvailable() {
		return nil, fmt.Errorf("rustscan not available")
	}

	result := &ScanResult{
		Target:    target,
		StartTime: time.Now(),
		Ports:     make([]PortResult, 0),
	}

	// 构建命令
	// rustscan -a target -u 5000 -b 1000 -t 1500 --tries 2 -g [-p ports | -r range | --top]
	args := []string{
		"-a", target,
		"-u", fmt.Sprintf("%d", r.Ulimit),
		"-b", fmt.Sprintf("%d", r.BatchSize),
		"-t", fmt.Sprintf("%d", r.Timeout),
		"--tries", "2", // 增加重试次数减少误报
		"-g", // greppable 输出格式
	}

	if ports != "" {
		// 检查是否是端口范围格式 (如 "8000-10000")
		// 端口范围只包含数字和单个横杠，且横杠不在开头或结尾
		if isPortRange(ports) {
			args = append(args, "-r", ports)
		} else {
			args = append(args, "-p", ports)
		}
	}

	cmd := exec.CommandContext(ctx, r.BinPath, args...)

	fmt.Printf("[*] Running RustScan: %s %s\n", r.BinPath, strings.Join(args, " "))

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		// RustScan 可能在没有开放端口时返回非零
		fmt.Printf("[!] RustScan error: %v\n", err)
	}

	// 解析输出
	// greppable 格式: target -> [port1,port2,port3]
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "->") {
			continue
		}

		// 解析: 192.168.1.1 -> [80,443,8080]
		parts := strings.Split(line, "->")
		if len(parts) != 2 {
			continue
		}

		portsPart := strings.TrimSpace(parts[1])
		portsPart = strings.Trim(portsPart, "[]")

		for _, portStr := range strings.Split(portsPart, ",") {
			portStr = strings.TrimSpace(portStr)
			if portStr == "" {
				continue
			}

			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}

			result.Ports = append(result.Ports, PortResult{
				Port:    port,
				State:   "open",
				Service: guessService(port),
			})
		}
	}

	// 验证端口服务
	result.Ports = r.verifyPorts(ctx, target, result.Ports)

	result.EndTime = time.Now()

	return result, nil
}

// ScanRange 扫描端口范围
// target: 目标 IP 或域名
// portRange: 端口范围，如 "1-65535"
func (r *RustScanScanner) ScanRange(ctx context.Context, target string, portRange string) (*ScanResult, error) {
	if !r.IsAvailable() {
		return nil, fmt.Errorf("rustscan not available")
	}

	result := &ScanResult{
		Target:    target,
		StartTime: time.Now(),
		Ports:     make([]PortResult, 0),
	}

	args := []string{
		"-a", target,
		"-u", fmt.Sprintf("%d", r.Ulimit),
		"-b", fmt.Sprintf("%d", r.BatchSize),
		"-t", fmt.Sprintf("%d", r.Timeout),
		"--tries", "2", // 增加重试次数减少误报
		"-g",
		"-r", portRange, // 使用 -r 参数指定范围
	}

	cmd := exec.CommandContext(ctx, r.BinPath, args...)
	fmt.Printf("[*] Running RustScan: %s %s\n", r.BinPath, strings.Join(args, " "))

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		fmt.Printf("[!] RustScan error: %v\n", err)
	}

	// 解析输出
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "->") {
			continue
		}

		parts := strings.Split(line, "->")
		if len(parts) != 2 {
			continue
		}

		portsPart := strings.TrimSpace(parts[1])
		portsPart = strings.Trim(portsPart, "[]")

		for _, portStr := range strings.Split(portsPart, ",") {
			portStr = strings.TrimSpace(portStr)
			if portStr == "" {
				continue
			}

			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}

			result.Ports = append(result.Ports, PortResult{
				Port:    port,
				State:   "open",
				Service: guessService(port),
			})
		}
	}

	// 验证端口服务
	result.Ports = r.verifyPorts(ctx, target, result.Ports)

	result.EndTime = time.Now()
	return result, nil
}

// Top1000Scan 扫描 Top 1000 常用端口 (使用 RustScan 内置 --top 参数)
func (r *RustScanScanner) Top1000Scan(ctx context.Context, target string) (*ScanResult, error) {
	if !r.IsAvailable() {
		return nil, fmt.Errorf("rustscan not available")
	}

	result := &ScanResult{
		Target:    target,
		StartTime: time.Now(),
		Ports:     make([]PortResult, 0),
	}

	args := []string{
		"-a", target,
		"-u", fmt.Sprintf("%d", r.Ulimit),
		"-b", fmt.Sprintf("%d", r.BatchSize),
		"-t", fmt.Sprintf("%d", r.Timeout),
		"--tries", "2", // 增加重试次数减少误报
		"-g",
		"--top", // 使用内置的 top 1000 端口
	}

	cmd := exec.CommandContext(ctx, r.BinPath, args...)
	fmt.Printf("[*] Running RustScan: %s %s\n", r.BinPath, strings.Join(args, " "))

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		fmt.Printf("[!] RustScan error: %v\n", err)
	}

	// 解析输出
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "->") {
			continue
		}

		parts := strings.Split(line, "->")
		if len(parts) != 2 {
			continue
		}

		portsPart := strings.TrimSpace(parts[1])
		portsPart = strings.Trim(portsPart, "[]")

		for _, portStr := range strings.Split(portsPart, ",") {
			portStr = strings.TrimSpace(portStr)
			if portStr == "" {
				continue
			}

			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}

			result.Ports = append(result.Ports, PortResult{
				Port:    port,
				State:   "open",
				Service: guessService(port),
			})
		}
	}

	// 验证端口服务
	result.Ports = r.verifyPorts(ctx, target, result.Ports)

	result.EndTime = time.Now()
	return result, nil
}

// QuickScan 快速扫描常用端口
func (r *RustScanScanner) QuickScan(ctx context.Context, target string) (*ScanResult, error) {
	// 常用端口 (约20个)
	commonPorts := "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
	return r.ScanPorts(ctx, target, commonPorts)
}

// FullScan 全端口扫描
func (r *RustScanScanner) FullScan(ctx context.Context, target string) (*ScanResult, error) {
	return r.ScanRange(ctx, target, "1-65535")
}

// guessService 根据端口猜测服务
func guessService(port int) string {
	services := map[int]string{
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
		1723:  "pptp",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

// isPortRange 检查是否是端口范围格式 (如 "8000-10000")
// 端口范围格式：数字-数字，只有一个横杠，横杠不在开头或结尾
func isPortRange(ports string) bool {
	// 必须包含横杠
	if !strings.Contains(ports, "-") {
		return false
	}
	
	// 分割检查是否是 "数字-数字" 格式
	parts := strings.Split(ports, "-")
	if len(parts) != 2 {
		return false
	}
	
	// 两边都必须是纯数字
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	
	return true
}

// verifyPorts 验证端口是否真正开放服务
func (r *RustScanScanner) verifyPorts(ctx context.Context, target string, ports []PortResult) []PortResult {
	if !r.VerifyPorts || len(ports) == 0 {
		return ports
	}

	fmt.Printf("[*] Verifying %d ports on %s...\n", len(ports), target)

	var verified []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 使用 channel 控制并发
	sem := make(chan struct{}, r.VerifyWorkers)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return verified
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p PortResult) {
			defer wg.Done()
			defer func() { <-sem }()

			if r.verifyPort(target, p.Port) {
				mu.Lock()
				verified = append(verified, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	fmt.Printf("[*] Verified: %d/%d ports are actually open\n", len(verified), len(ports))
	return verified
}

// verifyPort 验证单个端口是否真正开放
func (r *RustScanScanner) verifyPort(target string, port int) bool {
	address := fmt.Sprintf("%s:%d", target, port)
	timeout := time.Duration(r.VerifyTimeout) * time.Second

	// 尝试建立 TCP 连接
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(timeout))

	// 根据端口发送探针并检查响应
	banner := r.probeBanner(conn, port)
	
	// 如果能建立连接且有响应，则认为端口开放
	// 对于某些服务，可能需要先发送数据才能获得响应
	return banner != "" || r.isConnectionValid(conn, port)
}

// probeBanner 尝试获取服务 banner
func (r *RustScanScanner) probeBanner(conn net.Conn, port int) string {
	// 设置短超时
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 某些服务会主动发送 banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		return strings.TrimSpace(string(buffer[:n]))
	}

	// 对 HTTP 端口发送请求
	if isHTTPPort(port) {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err = conn.Read(buffer)
		if err == nil && n > 0 {
			return strings.TrimSpace(string(buffer[:n]))
		}
	}

	return ""
}

// isConnectionValid 检查连接是否有效（针对不返回 banner 的服务）
func (r *RustScanScanner) isConnectionValid(conn net.Conn, port int) bool {
	// 尝试写入少量数据检查连接是否真正建立
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	
	// 发送一个空行或简单探针
	var probe []byte
	switch {
	case isHTTPPort(port):
		probe = []byte("GET / HTTP/1.0\r\n\r\n")
	case port == 22:
		probe = []byte("SSH-2.0-Test\r\n")
	case port == 21:
		probe = []byte("QUIT\r\n")
	case port == 25 || port == 587:
		probe = []byte("EHLO test\r\n")
	default:
		probe = []byte("\r\n")
	}

	_, err := conn.Write(probe)
	if err != nil {
		return false
	}

	// 尝试读取响应
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 256)
	n, _ := conn.Read(buffer)
	
	// 如果有任何响应数据，说明服务存在
	return n > 0
}

// isHTTPPort 判断是否是 HTTP 相关端口
func isHTTPPort(port int) bool {
	httpPorts := map[int]bool{
		80: true, 443: true, 8080: true, 8443: true,
		8000: true, 8888: true, 9000: true, 9090: true,
		3000: true, 5000: true, 8081: true, 8082: true,
	}
	return httpPorts[port]
}
