package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// PortScanner 端口扫描器 - 使用优化的混合扫描策略
type PortScanner struct {
	portSets map[string][]int
	scanner  *AdvancedPortScanner
}

// NewPortScanner 创建端口扫描器
func NewPortScanner() *PortScanner {
	ps := &PortScanner{
		portSets: map[string][]int{
			"test":    {80, 443, 22, 3306, 3389, 8080, 8443},
			"top100":  generateTop100Ports(),
			"top1000": generateTop1000Ports(),
			"all":     generateAllPorts(),
		},
		scanner: NewAdvancedPortScanner(),
	}

	fmt.Println("✓ Advanced port scanner initialized successfully")
	fmt.Println("✓ Features: Real-time progress, optimized scanning, nmap integration")

	return ps
}

// Scan 执行端口扫描
func (ps *PortScanner) Scan(ctx *ScanContext) error {
	// 获取所有IP
	var ips []models.IP
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&ips)

	if len(ips) == 0 {
		ctx.Logger.Printf("No IPs found for port scanning")
		return nil
	}

	// 获取端口列表
	portScanType := ctx.Task.Options.PortScanType
	if portScanType == "" {
		portScanType = "top100"
	}

	ports, exists := ps.portSets[portScanType]
	if !exists {
		return fmt.Errorf("unknown port scan type: %s", portScanType)
	}

	// 根据端口数量选择扫描模式
	scanMode := "normal"
	if len(ports) <= 100 {
		scanMode = "fast"
	} else if len(ports) > 1000 {
		scanMode = "comprehensive"
	}

	ctx.Logger.Printf("Starting port scan with mode: %s", scanMode)
	ps.scanner.SetScanMode(scanMode)
	return ps.scanWithScanner(ctx, ips, ports)
}

// scanWithScanner 执行端口扫描
func (ps *PortScanner) scanWithScanner(ctx *ScanContext, ips []models.IP, ports []int) error {
	startTime := time.Now()
	results, err := ps.scanner.ScanWithProgress(ctx, ips, ports)
	if err != nil {
		return fmt.Errorf("port scan failed: %v", err)
	}
	return ps.saveResults(ctx, results, ips, ports, startTime)
}

// saveResults 保存扫描结果到数据库 (提取共用逻辑)
func (ps *PortScanner) saveResults(ctx *ScanContext, results []*PortScanResult, ips []models.IP, ports []int, startTime time.Time) error {
	ctx.Logger.Printf("Saving %d open ports to database...", len(results))
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	savedCount := 0
	semaphore := make(chan struct{}, 20)

	for _, result := range results {
		wg.Add(1)
		go func(r *PortScanResult) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			portModel := &models.Port{
				TaskID:    ctx.Task.ID,
				IPAddress: r.IP,
				Port:      r.Port,
				Protocol:  r.Protocol,
				Service:   r.Service,
				Banner:    r.Banner,
			}

			if err := ctx.DB.Where("task_id = ? AND ip_address = ? AND port = ?",
				ctx.Task.ID, r.IP, r.Port).FirstOrCreate(portModel).Error; err != nil {
				ctx.Logger.Printf("Failed to save port %s:%d: %v", r.IP, r.Port, err)
				return
			}

			mu.Lock()
			savedCount++
			if savedCount%100 == 0 {
				ctx.Logger.Printf("Saved %d/%d ports...", savedCount, len(results))
			}
			mu.Unlock()
		}(result)
	}

	wg.Wait()

	elapsed := time.Since(startTime)
	ctx.Logger.Printf("=== Port Scan Summary ===")
	ctx.Logger.Printf("Total IPs scanned: %d", len(ips))
	ctx.Logger.Printf("Total ports checked: %d", len(ips)*len(ports))
	ctx.Logger.Printf("Open ports found: %d", len(results))
	ctx.Logger.Printf("Ports saved to database: %d", savedCount)
	ctx.Logger.Printf("Total time elapsed: %v", elapsed)

	return nil
}

// generateTop100Ports 生成TOP100端口列表
func generateTop100Ports() []int {
	return []int{
		// Web服务
		80, 443, 8080, 8443, 8000, 8008, 8081, 8088, 8888, 9000,
		// 数据库
		3306, 5432, 1433, 1521, 27017, 6379, 11211, 9200, 9300,
		// 远程访问
		22, 23, 3389, 5900, 5901,
		// 邮件
		25, 110, 143, 465, 587, 993, 995,
		// 文件服务
		21, 20, 69, 139, 445, 2049,
		// DNS和目录
		53, 389, 636,
		// 中间件
		8009, 8161, 9043, 7001, 7002, 9080, 9090,
		// 消息队列
		5672, 61616, 9092,
		// 容器
		2375, 2376, 6443, 10250,
		// 其他常用
		111, 135, 161, 162, 514, 873, 1080, 1723, 1883,
		3000, 3128, 4848, 5000, 5984, 6000, 7000, 7070,
		8001, 8060, 8069, 8083, 8086, 8087, 8089, 8091,
		9001, 9002, 9060, 9081, 9091, 9999, 10000,
		50000, 50070, 50030, 50060, 50075,
		// 额外的Web端口
		81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
	}
}

// generateTop1000Ports 生成TOP1000端口列表
func generateTop1000Ports() []int {
	ports := make([]int, 0, 1000)
	
	// 先添加Top100
	ports = append(ports, generateTop100Ports()...)
	
	// 添加1-1024范围内的其他端口
	commonExclude := make(map[int]bool)
	for _, p := range ports {
		commonExclude[p] = true
	}
	
	for i := 1; i <= 1024; i++ {
		if !commonExclude[i] {
			ports = append(ports, i)
		}
	}
	
	// 添加一些高端口常用服务
	highPorts := []int{
		1025, 1026, 1027, 1028, 1029, 1030,
		1080, 1194, 1337, 1433, 1434, 1521, 1723, 1755,
		2000, 2001, 2002, 2003, 2004, 2005, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
		2222, 2375, 2376, 2379, 2380,
		3000, 3001, 3002, 3003, 3128, 3268, 3269, 3306, 3307, 3389,
		4000, 4001, 4002, 4369, 4444, 4445, 4567, 4711, 4712, 4848, 4899,
		5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009,
		5432, 5555, 5560, 5631, 5632, 5672, 5800, 5801, 5900, 5901, 5984,
		6000, 6001, 6002, 6003, 6004, 6005, 6379, 6443, 6666, 6667, 6668, 6669,
		7000, 7001, 7002, 7070, 7071, 7443, 7474, 7547, 7777,
		8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
		8010, 8011, 8012, 8020, 8021, 8022, 8030, 8031, 8042, 8060,
		8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
		8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
		8161, 8180, 8200, 8222, 8243, 8280, 8281, 8443, 8500, 8530, 8531,
		8800, 8834, 8880, 8887, 8888, 8983, 9000, 9001, 9002, 9003,
		9009, 9010, 9011, 9012, 9042, 9043, 9060, 9080, 9081, 9090, 9091, 9092,
		9100, 9111, 9200, 9201, 9300, 9301, 9392, 9443, 9595, 9800, 9870, 9871,
		9999, 10000, 10001, 10002, 10003, 10004, 10005, 10443, 10080, 10081,
		11211, 11214, 11215, 12000, 12345, 13000, 15672, 16010, 16030,
		17500, 18080, 18081, 18082, 18083, 18084, 18085, 18086, 18087, 18088,
		19999, 20000, 20720, 21000, 27017, 27018, 27019, 28017,
		30000, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776,
		33060, 33890, 37777, 38080, 40000, 40001, 40002,
		44818, 47001, 49152, 49153, 49154, 49155, 49156, 49157,
		50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007,
		50030, 50050, 50060, 50070, 50075, 50090, 50095, 50111,
		55553, 55554, 60000, 60001, 60010, 60020, 60030,
		61616, 65535,
	}
	
	for _, p := range highPorts {
		if !commonExclude[p] && p <= 65535 {
			ports = append(ports, p)
			if len(ports) >= 1000 {
				break
			}
		}
	}
	
	return ports
}

// generateAllPorts 生成全端口列表 (1-65535)
func generateAllPorts() []int {
	ports := make([]int, 65535)
	for i := 0; i < 65535; i++ {
		ports[i] = i + 1
	}
	return ports
}
