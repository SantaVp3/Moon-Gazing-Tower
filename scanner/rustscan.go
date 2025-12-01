package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// RustScanScanner 使用 RustScan 进行高速端口扫描
type RustScanScanner struct {
	BinPath   string
	Timeout   int      // 超时时间(毫秒)
	BatchSize int      // 批量大小 (并发数)
	Ulimit    int      // 文件描述符限制
	TempDir   string
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
		BinPath:   binPath,
		Timeout:   3000,  // 3秒超时 (毫秒)
		BatchSize: 4500,  // 批量大小
		Ulimit:    5000,  // 文件描述符
		TempDir:   os.TempDir(),
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
	// rustscan -a target -u 5000 -b 4500 -t 3000 -g [-p ports | -r range | --top]
	args := []string{
		"-a", target,
		"-u", fmt.Sprintf("%d", r.Ulimit),
		"-b", fmt.Sprintf("%d", r.BatchSize),
		"-t", fmt.Sprintf("%d", r.Timeout),
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
