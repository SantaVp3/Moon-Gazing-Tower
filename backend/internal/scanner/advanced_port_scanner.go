package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"github.com/reconmaster/backend/internal/models"
)

// AdvancedPortScanner 高级端口扫描器
// 支持两种扫描模式:
// 1. Go原生TCP Connect扫描 - 快速、无依赖
// 2. nmap集成扫描 - 精确、需要系统安装nmap
type AdvancedPortScanner struct {
	timeout       time.Duration
	maxConcurrent int
	useNmap       bool   // 是否使用nmap (需要系统安装)
	scanMode      string // fast, normal, comprehensive
	progressChan  chan *ScanProgress
}

// ScanProgress 扫描进度
type ScanProgress struct {
	TaskID      string    `json:"task_id"`
	Stage       string    `json:"stage"`        // port_scan
	Current     int       `json:"current"`      // 当前完成数
	Total       int       `json:"total"`        // 总数
	Percentage  float64   `json:"percentage"`   // 百分比
	Speed       float64   `json:"speed"`        // 速度 (ports/sec)
	OpenPorts   int       `json:"open_ports"`   // 发现的开放端口数
	ElapsedTime int64     `json:"elapsed_time"` // 已用时间(秒)
	ETA         int64     `json:"eta"`          // 预计剩余时间(秒)
	Message     string    `json:"message"`      // 状态消息
	Timestamp   time.Time `json:"timestamp"`
}

// NewAdvancedPortScanner 创建高级端口扫描器
func NewAdvancedPortScanner() *AdvancedPortScanner {
	scanner := &AdvancedPortScanner{
		timeout:       3 * time.Second,
		maxConcurrent: 500,
		useNmap:       false, // 默认不使用nmap
		scanMode:      "normal",
		progressChan:  make(chan *ScanProgress, 100),
	}
	
	// 检测nmap是否可用
	if isNmapAvailable() {
		scanner.useNmap = true
		fmt.Println("✓ nmap detected - using fast SYN scan (10-100x faster)")
		fmt.Println("  • fast mode: SYN scan with T5 timing")
		fmt.Println("  • normal mode: SYN scan + service detection")
		fmt.Println("  • comprehensive mode: SYN scan + service + OS detection")
		fmt.Println("  ⚠ NOTE: SYN scan requires root/admin privileges for best performance")
	} else {
		fmt.Println("✓ Using optimized TCP Connect scanner")
		fmt.Println("  • fast mode: 500ms timeout, 1000 concurrency")
		fmt.Println("  • normal mode: 1s timeout, 500 concurrency")
		fmt.Println("  ⚠ TIP: Install nmap for 10-100x faster scanning:")
		fmt.Println("    macOS: brew install nmap")
		fmt.Println("    Linux: apt install nmap / yum install nmap")
	}
	
	return scanner
}

// SetProgressChannel 设置进度推送通道
func (aps *AdvancedPortScanner) SetProgressChannel(ch chan *ScanProgress) {
	aps.progressChan = ch
}

// SetScanMode 设置扫描模式
// fast: 快速SYN扫描（需要nmap），1000并发TCP Connect（fallback），1秒超时
// normal: SYN扫描+基础服务识别（需要nmap），500并发TCP Connect（fallback），3秒超时
// comprehensive: SYN扫描+深度服务探测+版本识别+OS指纹（需要nmap），200并发，5秒超时
func (aps *AdvancedPortScanner) SetScanMode(mode string) {
	aps.scanMode = mode
	switch mode {
	case "fast":
		aps.timeout = 1 * time.Second
		aps.maxConcurrent = 1000
		// fast模式优先使用nmap SYN扫描（快10-100倍）
	case "normal":
		aps.timeout = 3 * time.Second
		aps.maxConcurrent = 500
		// normal模式使用nmap或优化的TCP Connect
	case "comprehensive":
		aps.timeout = 5 * time.Second
		aps.maxConcurrent = 200
		// comprehensive模式必须使用nmap获取详细信息
		if !aps.useNmap {
			aps.useNmap = isNmapAvailable()
		}
	}
}

// ScanWithProgress 执行端口扫描并推送进度
func (aps *AdvancedPortScanner) ScanWithProgress(ctx *ScanContext, ips []models.IP, ports []int) ([]*PortScanResult, error) {
	startTime := time.Now()
	totalScans := len(ips) * len(ports)
	
	ctx.Logger.Printf("=== Advanced Port Scanner Started ===")
	ctx.Logger.Printf("Scan Mode: %s", aps.scanMode)
	ctx.Logger.Printf("Target IPs: %d", len(ips))
	ctx.Logger.Printf("Ports per IP: %d", len(ports))
	ctx.Logger.Printf("Total scans: %d", totalScans)
	ctx.Logger.Printf("Max concurrency: %d", aps.maxConcurrent)
	ctx.Logger.Printf("Timeout: %v", aps.timeout)

	// 发送初始进度
	aps.sendProgress(ctx, 0, totalScans, 0, 0, startTime, "开始端口扫描...")

	var results []*PortScanResult
	
	// 优先使用nmap进行快速SYN扫描
	if aps.useNmap && isNmapAvailable() {
		ctx.Logger.Printf("Using nmap %s scan (mode: %s)...", getNmapScanType(aps.scanMode), aps.scanMode)
		results = aps.scanWithNmap(ctx, ips, ports, startTime, totalScans)
	} else {
		if aps.scanMode == "comprehensive" {
			ctx.Logger.Printf("WARNING: nmap not available, comprehensive mode features limited")
		}
		ctx.Logger.Printf("Using optimized TCP Connect scanner (mode: %s)...", aps.scanMode)
		results = aps.scanWithNativeOptimized(ctx, ips, ports, startTime, totalScans)
	}

	elapsed := time.Since(startTime)
	ctx.Logger.Printf("=== Scan Complete ===")
	ctx.Logger.Printf("Open ports found: %d", len(results))
	ctx.Logger.Printf("Total time: %v", elapsed)
	ctx.Logger.Printf("Average speed: %.0f ports/sec", float64(totalScans)/elapsed.Seconds())

	// 发送完成进度
	aps.sendProgress(ctx, totalScans, totalScans, len(results), 0, startTime, "端口扫描完成")

	return results, nil
}

// scanWithNativeOptimized 使用优化的Go原生TCP Connect扫描
// 优化策略：
// 1. 启发式扫描 - 优先扫描常见端口（提前发现目标）
// 2. 激进超时 - fast模式500ms，normal模式1s（比默认3s快很多）
// 3. 高并发 - fast模式1000，normal模式500（充分利用CPU）
// 4. 早期终止 - 连接失败立即返回，不等待完整超时
// 5. 跳过Banner - fast模式不抓取Banner（节省2-3秒/端口）
func (aps *AdvancedPortScanner) scanWithNativeOptimized(ctx *ScanContext, ips []models.IP, ports []int, startTime time.Time, totalScans int) []*PortScanResult {
	var results []*PortScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	semaphore := make(chan struct{}, aps.maxConcurrent)
	completed := 0
	lastProgressTime := time.Now()

	// 启发式端口排序 - 常见端口优先
	sortedPorts := aps.prioritizePorts(ports)
	
	// 根据模式调整超时（更激进）
	scanTimeout := aps.timeout
	if aps.scanMode == "fast" {
		scanTimeout = 500 * time.Millisecond // 快速模式：500ms超时
	} else if aps.scanMode == "normal" {
		scanTimeout = 1 * time.Second // 标准模式：1s超时
	}

	ctx.Logger.Printf("TCP Connect scan: timeout=%v, concurrency=%d", scanTimeout, aps.maxConcurrent)

	// 进度更新频率控制（每50次扫描或每0.5秒更新一次）
	progressUpdateInterval := 50
	if totalScans < 1000 {
		progressUpdateInterval = 10 // 小任务更频繁更新
	}

	// 按IP并发扫描
	for _, ip := range ips {
		// 检查任务是否被取消
		select {
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("Port scan cancelled")
			wg.Wait()
			return results
		default:
		}

		// 跳过CDN IP
		if ctx.Task.Options.SkipCDN && ip.CDN {
			mu.Lock()
			completed += len(ports)
			mu.Unlock()
			continue
		}

		// 为每个IP扫描所有端口
		for _, port := range sortedPorts {
			wg.Add(1)
			go func(ipAddr string, p int) {
				defer wg.Done()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				// 检查取消
				select {
				case <-ctx.Ctx.Done():
					return
				default:
				}

				// 快速TCP扫描（使用优化的超时）
				result := aps.quickScan(ctx, ipAddr, p, scanTimeout)
				
				if result.Open {
					mu.Lock()
					results = append(results, result)
					if aps.scanMode != "fast" {
						ctx.Logger.Printf("[+] %s:%d - %s", ipAddr, p, result.Service)
					}
					mu.Unlock()
				}

				// 更新进度
				mu.Lock()
				completed++
				
				// 更频繁的进度更新：每N次扫描或每0.5秒更新一次
				shouldUpdate := (completed % progressUpdateInterval == 0) || 
								(time.Since(lastProgressTime) >= 500*time.Millisecond) || 
								(completed == totalScans)
				
				if shouldUpdate {
					openPorts := len(results)
					speed := float64(completed) / time.Since(startTime).Seconds()
					aps.sendProgress(ctx, completed, totalScans, 
						openPorts, speed, startTime, fmt.Sprintf("扫描中... 已发现 %d 个开放端口", openPorts))
					lastProgressTime = time.Now()
				}
				mu.Unlock()
			}(ip.IPAddress, port)
		}
	}

	wg.Wait()
	return results
}

// quickScan 快速TCP扫描单个端口（优化版）
func (aps *AdvancedPortScanner) quickScan(ctx *ScanContext, ip string, port int, timeout time.Duration) *PortScanResult {
	result := &PortScanResult{
		IP:       ip,
		Port:     port,
		Protocol: "tcp",
		Open:     false,
	}

	// TCP连接测试（使用传入的超时时间）
	address := fmt.Sprintf("%s:%d", ip, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", address)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.Open = true
	result.Service = getServiceName(port)

	// 只在非fast模式抓取Banner
	if aps.scanMode != "fast" {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n > 0 {
			result.Banner = strings.TrimSpace(string(buf[:n]))
			// 截断过长的banner
			if len(result.Banner) > 200 {
				result.Banner = result.Banner[:200] + "..."
			}
		}
	}

	return result
}

// scanWithNmap 使用nmap进行扫描
func (aps *AdvancedPortScanner) scanWithNmap(ctx *ScanContext, ips []models.IP, ports []int, startTime time.Time, totalScans int) []*PortScanResult {
	var results []*PortScanResult
	var mu sync.Mutex

	ctx.Logger.Printf("=== nmap Scanner Started ===")

	// 构建IP列表
	var ipList []string
	for _, ip := range ips {
		if ctx.Task.Options.SkipCDN && ip.CDN {
			continue
		}
		ipList = append(ipList, ip.IPAddress)
	}

	if len(ipList) == 0 {
		return results
	}

	// 构建端口范围字符串
	portRanges := buildPortRanges(ports)
	ctx.Logger.Printf("Scanning %d IPs, ports: %s", len(ipList), portRanges)

	// 分批扫描（动态调整批次大小）
	// 大量IP时使用更小的批次，提供更频繁的进度更新
	batchSize := 20
	if len(ipList) <= 10 {
		batchSize = 5  // 小任务使用更小批次
	} else if len(ipList) > 100 {
		batchSize = 30 // 大任务稍微增大批次
	}
	
	ctx.Logger.Printf("Using batch size: %d IPs per batch", batchSize)
	
	for i := 0; i < len(ipList); i += batchSize {
		// 检查取消
		select {
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("nmap scan cancelled")
			return results
		default:
		}

		end := i + batchSize
		if end > len(ipList) {
			end = len(ipList)
		}

		batch := ipList[i:end]
		
		// 根据扫描模式选择nmap参数
		var scanner *nmap.Scanner
		var err error
		
		switch aps.scanMode {
		case "fast":
			// 快速SYN扫描：-sS（需要root权限，否则自动降级到TCP Connect）
			scanner, err = nmap.NewScanner(
				nmap.WithTargets(batch...),
				nmap.WithPorts(portRanges),
				nmap.WithSYNScan(),                              // SYN扫描（快速）
				nmap.WithTimingTemplate(nmap.TimingFastest),     // T5 最快速度
				nmap.WithSkipHostDiscovery(),                    // 跳过主机发现
			)
		case "normal":
			// 标准扫描：SYN + 基础服务识别
			scanner, err = nmap.NewScanner(
				nmap.WithTargets(batch...),
				nmap.WithPorts(portRanges),
				nmap.WithSYNScan(),                              // SYN扫描
				nmap.WithServiceInfo(),                          // 服务识别
				nmap.WithTimingTemplate(nmap.TimingAggressive),  // T4 激进速度
			)
		case "comprehensive":
			// 全面扫描：SYN + 服务版本 + OS指纹
			scanner, err = nmap.NewScanner(
				nmap.WithTargets(batch...),
				nmap.WithPorts(portRanges),
				nmap.WithSYNScan(),                              // SYN扫描
				nmap.WithServiceInfo(),                          // 服务识别
				nmap.WithOSDetection(),                          // OS检测
				nmap.WithTimingTemplate(nmap.TimingNormal),      // T3 标准速度
			)
		default:
			scanner, err = nmap.NewScanner(
				nmap.WithTargets(batch...),
				nmap.WithPorts(portRanges),
				nmap.WithSYNScan(),
				nmap.WithTimingTemplate(nmap.TimingAggressive),
			)
		}

		if err != nil {
			ctx.Logger.Printf("nmap scanner creation failed: %v", err)
			ctx.Logger.Printf("Falling back to Go native scanner...")
			return aps.scanWithNativeOptimized(ctx, ips, ports, startTime, totalScans)
		}

		// 执行扫描
		ctx.Logger.Printf("Scanning batch %d/%d (%d IPs)...", (i/batchSize)+1, (len(ipList)+batchSize-1)/batchSize, len(batch))
		nmapResults, warnings, err := scanner.Run()
		
		if err != nil {
			ctx.Logger.Printf("nmap scan failed: %v", err)
			continue
		}

		if len(warnings) > 0 {
			for _, warning := range warnings {
				ctx.Logger.Printf("nmap warning: %s", warning)
			}
		}

		// 解析结果
		if nmapResults != nil {
			for _, host := range nmapResults.Hosts {
				if len(host.Addresses) == 0 {
					continue
				}

				hostIP := host.Addresses[0].Addr
				
				for _, port := range host.Ports {
					if port.State.State == "open" {
						result := &PortScanResult{
							IP:       hostIP,
							Port:     int(port.ID),
							Protocol: port.Protocol,
							Open:     true,
							Service:  port.Service.Name,
							Banner:   fmt.Sprintf("%s %s", port.Service.Product, port.Service.Version),
						}
						
						// 清理Banner
						result.Banner = strings.TrimSpace(result.Banner)
						if result.Service == "" {
							result.Service = "unknown"
						}
						
						mu.Lock()
						results = append(results, result)
						ctx.Logger.Printf("[nmap] %s:%d - %s (%s)", result.IP, result.Port, result.Service, result.Banner)
						mu.Unlock()
					}
				}
			}
		}

		// 更新进度（更准确的计算）
		completed := end * len(ports) // 已扫描的IP数 × 每个IP的端口数
		progress := float64(completed) / float64(totalScans) * 100
		speed := float64(completed) / time.Since(startTime).Seconds()
		
		aps.sendProgress(ctx, completed, totalScans, 
			len(results), speed, startTime, 
			fmt.Sprintf("nmap扫描: 批次 %d/%d (%.1f%%)", 
				(i/batchSize)+1, (len(ipList)+batchSize-1)/batchSize, progress))
		
		ctx.Logger.Printf("Batch %d/%d completed, found %d open ports so far", 
			(i/batchSize)+1, (len(ipList)+batchSize-1)/batchSize, len(results))
	}

	return results
}

// probeService 深度服务探测 - 发送探测包并分析响应
func (aps *AdvancedPortScanner) probeService(ctx *ScanContext, ip string, port int) (string, string) {
	service := getServiceName(port)
	banner := ""

	// 只对 comprehensive 模式进行深度探测
	if aps.scanMode != "comprehensive" {
		return service, banner
	}

	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, aps.timeout)
	if err != nil {
		return service, banner
	}
	defer conn.Close()

	// 尝试多种探测方式
	probes := getServiceProbes(port)
	
	for _, probe := range probes {
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		conn.Write([]byte(probe))

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			response := string(buf[:n])
			banner = strings.TrimSpace(response)
			
			// 根据响应识别服务
			detectedService := identifyServiceFromBanner(response, port)
			if detectedService != "unknown" {
				service = detectedService
			}
			break
		}
	}

	return service, banner
}

// prioritizePorts 端口优先级排序 - 常见端口优先
func (aps *AdvancedPortScanner) prioritizePorts(ports []int) []int {
	// 定义高优先级端口
	highPriority := map[int]bool{
		80: true, 443: true, 22: true, 21: true, 23: true,
		25: true, 53: true, 110: true, 143: true, 3306: true,
		3389: true, 5432: true, 6379: true, 8080: true, 8443: true,
		1433: true, 27017: true, 9200: true, 11211: true,
	}

	var high, low []int
	for _, p := range ports {
		if highPriority[p] {
			high = append(high, p)
		} else {
			low = append(low, p)
		}
	}

	return append(high, low...)
}

// sendProgress 发送扫描进度
func (aps *AdvancedPortScanner) sendProgress(ctx *ScanContext, current, total, openPorts int, speed float64, startTime time.Time, message string) {
	if ctx.ProgressChan == nil {
		return // 没有进度通道，跳过
	}

	elapsed := time.Since(startTime)
	percentage := float64(current) / float64(total) * 100
	
	if current > 0 && elapsed.Seconds() > 0 {
		speed = float64(current) / elapsed.Seconds()
	}

	var eta int64
	if speed > 0 {
		remaining := total - current
		eta = int64(float64(remaining) / speed)
	}

	progress := &ScanProgress{
		TaskID:      ctx.Task.ID,
		Stage:       "port_scan",
		Current:     current,
		Total:       total,
		Percentage:  percentage,
		Speed:       speed,
		OpenPorts:   openPorts,
		ElapsedTime: int64(elapsed.Seconds()),
		ETA:         eta,
		Message:     message,
		Timestamp:   time.Now(),
	}

	// 非阻塞发送
	select {
	case ctx.ProgressChan <- progress:
	default:
	}
}

// getServiceProbes 获取服务探测包
func getServiceProbes(port int) []string {
	// 根据端口返回相应的探测包
	probes := []string{
		"",  // 空探测，等待服务器主动发送Banner
	}

	switch port {
	case 21: // FTP
		probes = append(probes, "USER anonymous\r\n")
	case 22: // SSH
		// SSH服务器会主动发送Banner
	case 25, 587: // SMTP
		probes = append(probes, "EHLO test\r\n")
	case 80, 8080, 8000, 8888: // HTTP
		probes = append(probes, "GET / HTTP/1.0\r\n\r\n")
	case 110: // POP3
		probes = append(probes, "USER test\r\n")
	case 143: // IMAP
		probes = append(probes, "A001 CAPABILITY\r\n")
	case 443, 8443: // HTTPS
		probes = append(probes, "GET / HTTP/1.0\r\n\r\n")
	case 3306: // MySQL
		// MySQL会主动发送握手包
	case 5432: // PostgreSQL
		// PostgreSQL会响应特定的字节序列
	case 6379: // Redis
		probes = append(probes, "PING\r\n", "INFO\r\n")
	case 27017: // MongoDB
		// MongoDB使用二进制协议
	case 9200: // Elasticsearch
		probes = append(probes, "GET / HTTP/1.0\r\n\r\n")
	}

	return probes
}

// identifyServiceFromBanner 从Banner识别服务
func identifyServiceFromBanner(banner string, port int) string {
	banner = strings.ToLower(banner)

	// HTTP服务器
	if strings.Contains(banner, "http/") {
		if strings.Contains(banner, "nginx") {
			return "nginx"
		} else if strings.Contains(banner, "apache") {
			return "apache"
		} else if strings.Contains(banner, "iis") {
			return "microsoft-iis"
		} else if strings.Contains(banner, "tomcat") {
			return "tomcat"
		}
		return "http"
	}

	// SSH
	if strings.Contains(banner, "ssh") {
		if strings.Contains(banner, "openssh") {
			return "openssh"
		}
		return "ssh"
	}

	// FTP
	if strings.Contains(banner, "ftp") || strings.Contains(banner, "220") {
		return "ftp"
	}

	// MySQL
	if strings.Contains(banner, "mysql") || strings.Contains(banner, "\x00\x00\x00\x0a") {
		return "mysql"
	}

	// PostgreSQL
	if strings.Contains(banner, "postgresql") {
		return "postgresql"
	}

	// Redis
	if strings.Contains(banner, "redis") || strings.Contains(banner, "+pong") {
		return "redis"
	}

	// MongoDB
	if strings.Contains(banner, "mongodb") {
		return "mongodb"
	}

	// Elasticsearch
	if strings.Contains(banner, "elasticsearch") || strings.Contains(banner, "\"cluster_name\"") {
		return "elasticsearch"
	}

	// SMTP
	if strings.Contains(banner, "smtp") || strings.Contains(banner, "220") && port == 25 {
		return "smtp"
	}

	// Memcached
	if strings.Contains(banner, "version") && port == 11211 {
		return "memcached"
	}

	return "unknown"
}

// buildPortRanges 构建nmap端口范围字符串
// 例如: [80,81,82,443,8080] -> "80-82,443,8080"
func buildPortRanges(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	// 简单实现: 逗号分隔
	// TODO: 优化为范围格式以提高nmap效率
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(portStrs, ",")
}

// isNmapAvailable 检查系统是否安装nmap
func isNmapAvailable() bool {
	scanner, err := nmap.NewScanner()
	if err != nil {
		return false
	}
	return scanner != nil
}

// getNmapScanType 获取nmap扫描类型描述
func getNmapScanType(mode string) string {
	switch mode {
	case "fast":
		return "SYN (T5 Fastest)"
	case "normal":
		return "SYN + Service Detection (T4)"
	case "comprehensive":
		return "SYN + Service + OS Detection (T3)"
	default:
		return "SYN"
	}
}

// getServiceName 根据端口号获取服务名称 (使用共享映射表)
func getServiceName(port int) string {
	services := getCommonPortServices()
	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}
