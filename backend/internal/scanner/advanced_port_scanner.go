package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// AdvancedPortScanner 高级端口扫描器
// 使用 Naabu + Nmap 组合
// - 阶段1：Naabu 快速发现所有开放端口
// - 阶段2：Nmap 详细识别服务版本和指纹
type AdvancedPortScanner struct {
	scanMode     string // normal, comprehensive
	progressChan chan *ScanProgress
	naabuEngine  *NaabuEngine // Naabu 引擎实例
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
		scanMode:     "normal",
		progressChan: make(chan *ScanProgress, 100),
		naabuEngine:  NewNaabuEngine(),
	}

	fmt.Println("✓ Port Scanner Ready - Naabu + Nmap Mode")
	fmt.Println("  • Stage 1: Naabu rapid port discovery (high performance)")
	fmt.Println("  • Stage 2: Nmap service & version detection")
	fmt.Println("  • Perfect for: Internal network scanning")
	fmt.Println("  ⚠️  IMPORTANT: Naabu requires root/sudo privileges")
	fmt.Println("     Run server with: sudo ./bin/server")

	return scanner
}

// SetProgressChannel 设置进度推送通道
func (aps *AdvancedPortScanner) SetProgressChannel(ch chan *ScanProgress) {
	aps.progressChan = ch
}

// SetScanMode 设置扫描模式
// normal: Naabu 自适应速率 + Nmap 标准扫描
// comprehensive: Naabu 自适应速率 + Nmap 深度扫描
func (aps *AdvancedPortScanner) SetScanMode(mode string) {
	aps.scanMode = mode
	// Naabu使用自适应速率，无需手动设置
	// 速率会根据目标数量和端口范围自动调整
}

// ApplyConfig 应用扫描器配置（兼容接口）
func (aps *AdvancedPortScanner) ApplyConfig(config *ScannerConfig, portCount int) {
	// Naabu使用自适应速率，这里保留配置接口以兼容现有代码
}

// ScanWithProgress 执行端口扫描并推送进度
func (aps *AdvancedPortScanner) ScanWithProgress(ctx *ScanContext, ips []models.IP, ports []int) ([]*PortScanResult, error) {
	if aps == nil {
		return nil, fmt.Errorf("port scanner not initialized")
	}

	if aps.naabuEngine == nil {
		ctx.Logger.Printf("ERROR: Naabu engine not available")
		return nil, fmt.Errorf("Naabu engine not initialized")
	}

	startTime := time.Now()
	totalScans := len(ips) * len(ports)

	ctx.Logger.Printf("=== Naabu Port Scanner Started ===")
	ctx.Logger.Printf("Scan Mode: %s", aps.scanMode)
	ctx.Logger.Printf("Target IPs: %d", len(ips))
	ctx.Logger.Printf("Ports per IP: %d", len(ports))
	ctx.Logger.Printf("Total port checks: %d", totalScans)

	// 发送初始进度
	aps.sendProgress(ctx, 0, totalScans, 0, 0, startTime, "开始 Naabu 快速发现...")

	// 使用 Naabu + Nmap 扫描
	results := aps.scanWithNaabu(ctx, ips, ports, startTime, totalScans)

	elapsed := time.Since(startTime)
	ctx.Logger.Printf("=== Scan Complete ===")
	ctx.Logger.Printf("Open ports found: %d", len(results))
	ctx.Logger.Printf("Total time: %v", elapsed)
	if totalScans > 0 {
		ctx.Logger.Printf("Average speed: %.0f ports/sec", float64(totalScans)/elapsed.Seconds())
	}

	// 发送完成进度
	aps.sendProgress(ctx, totalScans, totalScans, len(results), 0, startTime, "端口扫描完成")

	return results, nil
}

// scanWithNaabu 使用 Naabu + Nmap 进行扫描
func (aps *AdvancedPortScanner) scanWithNaabu(ctx *ScanContext, ips []models.IP, ports []int, startTime time.Time, totalScans int) []*PortScanResult {
	if aps.naabuEngine == nil {
		ctx.Logger.Printf("ERROR: Naabu engine not initialized")
		return []*PortScanResult{}
	}

	// 转换IP列表为字符串数组
	ipStrings := make([]string, len(ips))
	for i, ip := range ips {
		ipStrings[i] = ip.IPAddress
	}

	ctx.Logger.Printf("Stage 1/2: Naabu rapid discovery...")
	aps.sendProgress(ctx, 0, totalScans, 0, 0, startTime, "Naabu快速发现开放端口...")

	// 使用 Naabu 引擎扫描
	results, err := aps.naabuEngine.ScanPorts(ipStrings, ports)
	if err != nil {
		ctx.Logger.Printf("ERROR: Naabu scan failed: %v", err)
		return []*PortScanResult{}
	}

	ctx.Logger.Printf("Stage 2/2: Nmap service detection completed")
	ctx.Logger.Printf("Found %d open ports total", len(results))

	// 实时保存结果到数据库
	for _, result := range results {
		aps.savePortResult(ctx, result)
	}

	// 更新最终进度
	aps.sendProgress(ctx, totalScans, totalScans, len(results), 0, startTime, "Naabu + Nmap扫描完成")

	return results
}

// sendProgress 发送扫描进度
func (aps *AdvancedPortScanner) sendProgress(ctx *ScanContext, current, total, openPorts int, speed float64, startTime time.Time, message string) {
	if aps.progressChan == nil {
		return
	}

	elapsed := time.Since(startTime).Seconds()
	var eta int64
	if current > 0 && current < total {
		remainingScans := total - current
		eta = int64(float64(remainingScans) / speed)
	}

	progress := &ScanProgress{
		TaskID:      ctx.Task.ID,
		Stage:       "port_scan",
		Current:     current,
		Total:       total,
		Percentage:  float64(current) / float64(total) * 100,
		Speed:       speed,
		OpenPorts:   openPorts,
		ElapsedTime: int64(elapsed),
		ETA:         eta,
		Message:     message,
		Timestamp:   time.Now(),
	}

	select {
	case aps.progressChan <- progress:
	default:
		// 通道满，跳过此次进度更新
	}
}

// savePortResult 实时保存端口扫描结果到数据库
func (aps *AdvancedPortScanner) savePortResult(ctx *ScanContext, result *PortScanResult) {
	if ctx.DB == nil || ctx.Task == nil {
		return
	}

	// 创建Port资产记录
	port := &models.Port{
		TaskID:    ctx.Task.ID,
		IPAddress: result.IP,
		Port:      result.Port,
		Protocol:  result.Protocol,
		Service:   result.Service,
		Banner:    result.Banner,
	}

	// 使用 WithContext 确保可以取消
	dbCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := ctx.DB.WithContext(dbCtx).Create(port).Error; err != nil {
		// 忽略重复记录错误
		if !isDuplicateError(err) {
			ctx.Logger.Printf("WARNING: Failed to save port result: %v", err)
		}
	}
}

// isDuplicateError 判断是否为重复记录错误
func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return containsStringIgnoreCase(errMsg, "duplicate") || containsStringIgnoreCase(errMsg, "UNIQUE")
}

// containsStringIgnoreCase 字符串包含检查（不区分大小写，避免重名）
func containsStringIgnoreCase(str, substr string) bool {
	return strings.Contains(strings.ToLower(str), strings.ToLower(substr))
}
