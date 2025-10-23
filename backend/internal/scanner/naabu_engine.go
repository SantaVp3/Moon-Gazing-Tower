package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// NaabuEngine Naabu端口扫描引擎
type NaabuEngine struct {
	rate        int
	timeout     time.Duration
	concurrency int
}

// NewNaabuEngine 创建Naabu扫描引擎
func NewNaabuEngine() *NaabuEngine {
	return &NaabuEngine{
		rate:        0, // 0表示自适应速率
		timeout:     3 * time.Second,
		concurrency: 25, // 默认25并发
	}
}

// SetRate 设置扫描速率（手动指定）
func (ne *NaabuEngine) SetRate(rate int) {
	ne.rate = rate
}

// calculateAdaptiveRate 根据扫描规模计算自适应速率
func (ne *NaabuEngine) calculateAdaptiveRate(targetCount, portCount int) int {
	// 如果手动设置了速率，直接使用
	if ne.rate > 0 {
		return ne.rate
	}

	// 计算总扫描量
	totalScans := targetCount * portCount

	var adaptiveRate int

	switch {
	case portCount <= 100:
		// 小范围扫描（TOP100端口）：超高速
		adaptiveRate = 10000

	case portCount <= 1000:
		// 中等范围扫描（TOP1000端口）：高速
		adaptiveRate = 5000

	case portCount <= 10000:
		// 大范围扫描（1-10000端口）：中速
		if targetCount > 100 {
			// C段以上：降低速率避免网络拥塞
			adaptiveRate = 3000
		} else {
			adaptiveRate = 5000
		}

	default:
		// 全端口扫描（65535端口）：根据目标数量调整
		if targetCount == 1 {
			// 单目标全端口：高速
			adaptiveRate = 8000
		} else if targetCount <= 10 {
			// 少量目标全端口：中高速
			adaptiveRate = 5000
		} else if targetCount <= 100 {
			// C段全端口：中速
			adaptiveRate = 3000
		} else {
			// 大规模全端口：保守速率
			adaptiveRate = 2000
		}
	}

	fmt.Printf("🎯 Adaptive Rate: %d pps (targets=%d, ports=%d, total=%d scans)\n",
		adaptiveRate, targetCount, portCount, totalScans)

	return adaptiveRate
}

// ScanPorts 使用Naabu扫描端口
func (ne *NaabuEngine) ScanPorts(targets []string, ports []int) ([]*PortScanResult, error) {
	// 计算自适应速率
	adaptiveRate := ne.calculateAdaptiveRate(len(targets), len(ports))

	fmt.Printf("=== Naabu Port Scanner ===\n")
	fmt.Printf("Targets: %d | Ports: %d | Rate: %d pps\n", len(targets), len(ports), adaptiveRate)

	// 用于收集结果
	var results []*PortScanResult
	var resultsMutex sync.Mutex

	// 创建Naabu选项（必须在创建runner之前设置好回调）
	options := &runner.Options{
		Host:    targets,
		Ports:   formatPortsForNaabu(ports),
		Rate:    adaptiveRate,
		Timeout: ne.timeout,
		Retries: 1,
		Threads: ne.concurrency,
		Silent:  true,
		OnResult: func(hr *result.HostResult) {
			resultsMutex.Lock()
			defer resultsMutex.Unlock()

			fmt.Printf("✓ Found open ports on %s: %v\n", hr.Host, hr.Ports)

			for _, port := range hr.Ports {
				results = append(results, &PortScanResult{
					IP:       hr.Host,
					Port:     port.Port,
					Protocol: "tcp",
					Open:     true,
					Service:  "unknown", // Naabu不做服务识别
				})
			}
		},
	}

	// 创建Naabu runner
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create naabu runner: %w", err)
	}
	defer naabuRunner.Close()

	// 执行扫描
	fmt.Println("Starting Naabu scan...")
	ctx := context.Background()
	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		return nil, fmt.Errorf("naabu scan failed: %w", err)
	}

	fmt.Printf("✓ Naabu scan complete: found %d open ports\n", len(results))

	// 使用gonmap进行服务识别（纯Go实现，无需nmap二进制）
	if len(results) > 0 {
		fmt.Println("🔍 Performing service detection with gonmap...")
		detector := NewServiceDetector()
		results = detector.DetectServices(results)
	}

	return results, nil
}

// formatPortsForNaabu 将端口列表格式化为Naabu接受的字符串
func formatPortsForNaabu(ports []int) string {
	if len(ports) == 0 {
		return "1-65535"
	}

	// Naabu支持逗号分隔的端口列表
	portStr := ""
	for i, port := range ports {
		if i > 0 {
			portStr += ","
		}
		portStr += fmt.Sprintf("%d", port)
	}
	return portStr
}
