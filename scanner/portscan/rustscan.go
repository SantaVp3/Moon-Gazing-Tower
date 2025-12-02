package portscan

import (
	"bufio"
	"context"
	"fmt"
	"moongazing/scanner/core"
	"net"
	"os"
	"os/exec"
	"regexp"
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
	tm := core.NewToolsManager()
	binPath := tm.GetToolPath("rustscan")

	return &RustScanScanner{
		BinPath:       binPath,
		Timeout:       3000,  // 3秒超时 (毫秒) - 参考 ScopeSentry-Scan
		BatchSize:     1500,  // 批量大小 - 参考 ScopeSentry-Scan
		Ulimit:        5000,  // 文件描述符
		TempDir:       os.TempDir(),
		VerifyPorts:   false, // 默认关闭端口验证，RustScan 已经足够准确
		VerifyTimeout: 5,     // 验证超时5秒（如果开启验证）
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

// IPv6 正则匹配 [IPv6]:port 格式
var ipv6PortRegex = regexp.MustCompile(`^\[([0-9a-fA-F:]+)\]:(\d+)$`)

// ScanPorts 扫描端口
// target: 目标 IP 或域名
// ports: 逗号分隔的端口列表，如 "80,443,8080" 或端口范围如 "1-1000"
func (r *RustScanScanner) ScanPorts(ctx context.Context, target string, ports string) (*core.ScanResult, error) {
	if !r.IsAvailable() {
		return nil, fmt.Errorf("rustscan not available")
	}

	result := &core.ScanResult{
		Target:    target,
		StartTime: time.Now(),
		Ports:     make([]core.PortResult, 0),
	}

	// 使用 map 去重
	portMap := make(map[int]bool)

	// 构建命令 - 参考 ScopeSentry-Scan 的实现
	// 使用 --accessible 模式便于实时解析输出
	args := []string{
		"-b", fmt.Sprintf("%d", r.BatchSize),
		"-t", fmt.Sprintf("%d", r.Timeout),
		"-a", target,
		"--accessible",        // 便于解析的输出格式
		"--scan-order", "Random", // 随机扫描顺序，避免 IDS 检测
		"--scripts", "None",   // 不运行额外脚本
	}

	if ports != "" {
		// 检查是否是端口范围格式 (如 "8000-10000")
		if isPortRange(ports) {
			args = append(args, "-r", ports)
		} else {
			args = append(args, "-r", ports) // 使用 -r 支持 1,2,3 和 1-100 两种格式
		}
	}

	cmd := exec.CommandContext(ctx, r.BinPath, args...)

	fmt.Printf("[*] Running RustScan: %s %s\n", r.BinPath, strings.Join(args, " "))

	// 使用 StdoutPipe 实时读取输出 - 参考 ScopeSentry-Scan
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start rustscan: %v", err)
	}

	// 实时解析输出
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("[RustScan] %s\n", line)

		// 跳过无关输出
		if strings.Contains(line, "File limit higher than batch size") ||
			strings.Contains(line, "Looks like I didn't find any open ports") ||
			strings.Contains(line, "*I used") ||
			strings.Contains(line, "Alternatively, increase") {
			continue
		}

		// 解析 "Open" 格式的输出: "Open 192.168.1.1:80"
		if strings.Contains(line, "Open") {
			portResult := r.parseOpenLine(line, target)
			if portResult != nil && !portMap[portResult.Port] {
				portMap[portResult.Port] = true
				result.Ports = append(result.Ports, *portResult)
			}
			continue
		}

		// 跳过 "->" 格式，因为 "Open" 已经包含了所有端口信息
		// "->" 格式是汇总信息，会造成重复
	}

	// 等待命令完成
	if err := cmd.Wait(); err != nil {
		// RustScan 在没有发现端口时可能返回非零
		fmt.Printf("[!] RustScan finished with: %v\n", err)
	}

	// 可选：验证端口服务
	if r.VerifyPorts {
		result.Ports = r.verifyPorts(ctx, target, result.Ports)
	}

	result.EndTime = time.Now()
	fmt.Printf("[*] Found %d open ports on %s\n", len(result.Ports), target)

	return result, nil
}

// parseOpenLine 解析 "Open" 格式的行
// 格式: "Open 192.168.1.1:80" 或 "Open [::1]:80"
func (r *RustScanScanner) parseOpenLine(line, target string) *core.PortResult {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return nil
	}

	ipPort := strings.TrimSpace(parts[1])

	// 检查是否是 IPv6 格式
	if match := ipv6PortRegex.FindStringSubmatch(ipPort); match != nil {
		port, err := strconv.Atoi(match[2])
		if err != nil {
			return nil
		}
		return &core.PortResult{
			Port:    port,
			State:   "open",
			Service: guessService(port),
		}
	}

	// IPv4 格式: ip:port
	portParts := strings.SplitN(ipPort, ":", 2)
	if len(portParts) != 2 {
		return nil
	}

	port, err := strconv.Atoi(portParts[1])
	if err != nil {
		return nil
	}

	return &core.PortResult{
		Port:    port,
		State:   "open",
		Service: guessService(port),
	}
}

// parseArrowLine 解析 "->" 格式的行
// 格式: "192.168.1.1 -> [80,443,8080]"
func (r *RustScanScanner) parseArrowLine(line string) []core.PortResult {
	var results []core.PortResult

	parts := strings.Split(line, "->")
	if len(parts) != 2 {
		return results
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

		results = append(results, core.PortResult{
			Port:    port,
			State:   "open",
			Service: guessService(port),
		})
	}

	return results
}

// ScanRange 扫描端口范围
// target: 目标 IP 或域名
// portRange: 端口范围，如 "1-65535"
func (r *RustScanScanner) ScanRange(ctx context.Context, target string, portRange string) (*core.ScanResult, error) {
	// 直接使用 ScanPorts，它已经支持端口范围格式
	return r.ScanPorts(ctx, target, portRange)
}

// Top1000Scan 扫描 Top 1000 常用端口
// 使用常见端口列表而不是 --top 参数，因为 --accessible 模式下 --top 可能不生效
func (r *RustScanScanner) Top1000Scan(ctx context.Context, target string) (*core.ScanResult, error) {
	// Top 1000 常用端口（精简版）
	top1000 := "1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000"
	return r.ScanPorts(ctx, target, top1000)
}

// QuickScan 快速扫描常用端口
func (r *RustScanScanner) QuickScan(ctx context.Context, target string) (*core.ScanResult, error) {
	// 从配置加载常用端口
	ports := core.GetCommonPorts()
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	commonPorts := strings.Join(portStrs, ",")
	return r.ScanPorts(ctx, target, commonPorts)
}

// FullScan 全端口扫描
func (r *RustScanScanner) FullScan(ctx context.Context, target string) (*core.ScanResult, error) {
	return r.ScanRange(ctx, target, "1-65535")
}

// guessService 根据端口猜测服务
func guessService(port int) string {
	// 从配置加载端口服务映射
	services := core.GetPortServiceMap()

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
func (r *RustScanScanner) verifyPorts(ctx context.Context, target string, ports []core.PortResult) []core.PortResult {
	if !r.VerifyPorts || len(ports) == 0 {
		return ports
	}

	fmt.Printf("[*] Verifying %d ports on %s...\n", len(ports), target)

	var verified []core.PortResult
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

		go func(p core.PortResult) {
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

	// TCP 连接成功就说明端口开放
	// 不需要额外验证 banner，因为很多服务不会主动发送数据
	return true
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
	if core.IsHTTPPort(port) {
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
	case core.IsHTTPPort(port):
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
