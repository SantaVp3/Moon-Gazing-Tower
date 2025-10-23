package scanner

import (
	"fmt"
	"time"

	"github.com/lcvvvv/gonmap"
)

// ServiceDetector 服务识别器（基于gonmap）
type ServiceDetector struct {
	timeout time.Duration
}

// NewServiceDetector 创建服务识别器
func NewServiceDetector() *ServiceDetector {
	return &ServiceDetector{
		timeout: 5 * time.Second,
	}
}

// DetectService 识别单个端口的服务
func (sd *ServiceDetector) DetectService(ip string, port int) (service, version, product string) {
	// 使用gonmap进行服务探测
	scanner := gonmap.New()

	// 设置超时
	scanner.SetTimeout(sd.timeout)

	// 扫描单个端口
	status, response := scanner.ScanTimeout(ip, port, sd.timeout)

	if status == gonmap.Matched && response != nil && response.FingerPrint != nil {
		// 成功匹配到服务指纹
		fp := response.FingerPrint
		service = fp.Service
		version = fp.Version
		product = fp.ProductName

		// 如果没有版本信息，尝试从Info字段获取
		if version == "" && fp.Info != "" {
			version = fp.Info
		}

		return service, version, product
	}

	// 未匹配到指纹，返回基本信息
	if status == gonmap.Open {
		// 端口开放但无法识别服务
		service = guessServiceByPort(port)
		return service, "", ""
	}

	// 默认返回 unknown
	return "unknown", "", ""
}

// DetectServices 批量识别多个端口的服务
func (sd *ServiceDetector) DetectServices(results []*PortScanResult) []*PortScanResult {
	fmt.Printf("🔍 Starting service detection for %d ports...\n", len(results))

	for i, result := range results {
		service, version, product := sd.DetectService(result.IP, result.Port)

		// 更新服务信息
		result.Service = service
		if version != "" {
			result.Version = version
		}
		if product != "" {
			result.Product = product
		}

		// 打印进度
		if (i+1)%10 == 0 || i == len(results)-1 {
			fmt.Printf("  ✓ Detected %d/%d services\n", i+1, len(results))
		}
	}

	fmt.Printf("✓ Service detection complete\n")
	return results
}

// guessServiceByPort 根据端口号猜测服务类型（fallback）
func guessServiceByPort(port int) string {
	commonPorts := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "domain",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		5432:  "postgresql",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		9200:  "elasticsearch",
		27017: "mongodb",
		5000:  "upnp",
		8888:  "http-alt",
	}

	if service, exists := commonPorts[port]; exists {
		return service
	}

	return "unknown"
}
