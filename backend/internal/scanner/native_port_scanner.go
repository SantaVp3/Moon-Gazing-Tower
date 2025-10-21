package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// NativePortScanner Go原生端口扫描器
type NativePortScanner struct {
	timeout       time.Duration
	maxGoroutines int
	commonPorts   map[int]string // 常见端口和服务映射
}

// NewNativePortScanner 创建原生端口扫描器
func NewNativePortScanner() *NativePortScanner {
	return &NativePortScanner{
		timeout:       2 * time.Second, // 每个端口2秒超时
		maxGoroutines: 100,             // 最多100个并发goroutine
		commonPorts:   getCommonPortServices(),
	}
}

// ScanPort 扫描单个端口
func (nps *NativePortScanner) ScanPort(ip string, port int) (*PortScanResult, error) {
	result := &PortScanResult{
		IP:       ip,
		Port:     port,
		Protocol: "tcp",
		Open:     false,
	}

	// TCP连接测试
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, nps.timeout)
	if err != nil {
		return result, nil // 端口关闭，不是错误
	}
	defer conn.Close()

	result.Open = true

	// 尝试识别服务
	result.Service = nps.identifyService(port, conn)

	// 尝试抓取Banner
	result.Banner = nps.grabBanner(conn)

	return result, nil
}

// ScanPorts 批量扫描端口
func (nps *NativePortScanner) ScanPorts(ctx *ScanContext, ips []models.IP, ports []int) ([]*PortScanResult, error) {
	var results []*PortScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 创建信号量来限制并发
	semaphore := make(chan struct{}, nps.maxGoroutines)

	totalScans := len(ips) * len(ports)
	completed := 0

	ctx.Logger.Printf("=== Native Port Scanner Started ===")
	ctx.Logger.Printf("Target IPs: %d", len(ips))
	ctx.Logger.Printf("Ports per IP: %d", len(ports))
	ctx.Logger.Printf("Total scans: %d", totalScans)
	ctx.Logger.Printf("Max concurrency: %d", nps.maxGoroutines)

	startTime := time.Now()

	// 遍历所有IP和端口进行扫描
	for _, ip := range ips {
		// 检查任务是否被取消
		select {
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("Port scan cancelled by user")
			return results, ctx.Ctx.Err()
		default:
		}

		// 检查是否应该跳过CDN IP
		if ctx.Task.Options.SkipCDN && ip.CDN {
			ctx.Logger.Printf("Skipping CDN IP: %s", ip.IPAddress)
			continue
		}

		for _, port := range ports {
			// 再次检查取消状态
			select {
			case <-ctx.Ctx.Done():
				ctx.Logger.Printf("Port scan cancelled by user")
				wg.Wait() // 等待已启动的goroutine完成
				return results, ctx.Ctx.Err()
			default:
			}

			wg.Add(1)
			go func(ipAddr string, p int) {
				defer wg.Done()

				// 获取信号量
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				// 再次检查取消状态
				select {
				case <-ctx.Ctx.Done():
					return
				default:
				}

				// 扫描端口
				result, err := nps.ScanPort(ipAddr, p)
				if err != nil {
					ctx.Logger.Printf("Error scanning %s:%d - %v", ipAddr, p, err)
					return
				}

				// 只记录开放的端口
				if result.Open {
					mu.Lock()
					results = append(results, result)
					ctx.Logger.Printf("[OPEN] %s:%d - %s (%s)", ipAddr, p, result.Service, result.Banner[:min(50, len(result.Banner))])
					mu.Unlock()
				}

				// 更新进度
				mu.Lock()
				completed++
				if completed%1000 == 0 || completed == totalScans {
					progress := float64(completed) / float64(totalScans) * 100
					elapsed := time.Since(startTime)
					rate := float64(completed) / elapsed.Seconds()
					ctx.Logger.Printf("Progress: %d/%d (%.1f%%) - %.0f ports/sec",
						completed, totalScans, progress, rate)
				}
				mu.Unlock()
			}(ip.IPAddress, port)
		}
	}

	wg.Wait()

	elapsed := time.Since(startTime)
	ctx.Logger.Printf("=== Native Port Scanner Completed ===")
	ctx.Logger.Printf("Open ports found: %d", len(results))
	ctx.Logger.Printf("Time elapsed: %v", elapsed)
	ctx.Logger.Printf("Scan rate: %.2f ports/sec", float64(totalScans)/elapsed.Seconds())

	return results, nil
}

// identifyService 识别服务类型
func (nps *NativePortScanner) identifyService(port int, conn net.Conn) string {
	// 首先检查常见端口映射
	if service, ok := nps.commonPorts[port]; ok {
		return service
	}

	// 如果不在常见端口列表中，尝试通过banner识别
	// 这部分可以通过grabBanner的结果进一步分析
	return "unknown"
}

// grabBanner 抓取服务Banner
func (nps *NativePortScanner) grabBanner(conn net.Conn) string {
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// 尝试读取banner
	reader := bufio.NewReader(conn)

	// 先尝试直接读取（有些服务会主动发送banner）
	banner := make([]byte, 4096)
	n, err := reader.Read(banner)
	if err == nil && n > 0 {
		return sanitizeBanner(string(banner[:n]))
	}

	// 如果没有主动发送，尝试发送探测包
	// HTTP探测
	conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = reader.Read(banner)
	if err == nil && n > 0 {
		return sanitizeBanner(string(banner[:n]))
	}

	return ""
}

// sanitizeBanner 清理和截断banner
func sanitizeBanner(banner string) string {
	// 移除不可打印字符
	banner = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			if r == '\n' || r == '\r' || r == '\t' {
				return ' '
			}
			return -1
		}
		return r
	}, banner)

	// 移除多余的空白
	banner = strings.Join(strings.Fields(banner), " ")

	// 截断过长的banner
	if len(banner) > 500 {
		banner = banner[:500] + "..."
	}

	return strings.TrimSpace(banner)
}

// PortScanResult 端口扫描结果
type PortScanResult struct {
	IP       string
	Port     int
	Protocol string
	Open     bool
	Service  string
	Banner   string
}

// getCommonPortServices 获取常见端口和服务映射
func getCommonPortServices() map[int]string {
	return map[int]string{
		// Web服务
		80:   "http",
		443:  "https",
		8000: "http-alt",
		8008: "http-alt",
		8080: "http-proxy",
		8081: "http-alt",
		8088: "http-alt",
		8443: "https-alt",
		8888: "http-alt",
		9000: "http-alt",

		// 数据库
		3306:  "mysql",
		5432:  "postgresql",
		1433:  "mssql",
		1521:  "oracle",
		27017: "mongodb",
		27018: "mongodb-shard",
		6379:  "redis",
		11211: "memcached",
		9200:  "elasticsearch",
		9300:  "elasticsearch-cluster",

		// 远程访问
		22:   "ssh",
		23:   "telnet",
		3389: "rdp",
		5900: "vnc",
		5901: "vnc",

		// 邮件服务
		25:  "smtp",
		110: "pop3",
		143: "imap",
		465: "smtps",
		587: "submission",
		993: "imaps",
		995: "pop3s",

		// 文件服务
		21:   "ftp",
		20:   "ftp-data",
		69:   "tftp",
		139:  "netbios-ssn",
		445:  "smb",
		2049: "nfs",

		// DNS和目录服务
		53:  "dns",
		389: "ldap",
		636: "ldaps",

		// 中间件和应用服务器
		8009: "ajp13",
		8161: "activemq",
		9043: "websphere-admin",
		7001: "weblogic",
		7002: "weblogic-ssl",
		9080: "websphere",
		9090: "websphere-admin",

		// 消息队列
		5672:  "amqp/rabbitmq",
		61616: "activemq",
		9092:  "kafka",
		4369:  "rabbitmq-epmd",

		// 容器和编排
		2375:  "docker",
		2376:  "docker-ssl",
		6443:  "kubernetes-api",
		10250: "kubelet",

		// 其他常见服务
		161:   "snmp",
		162:   "snmptrap",
		514:   "syslog",
		873:   "rsync",
		1080:  "socks",
		1883:  "mqtt",
		3000:  "grafana",
		3128:  "squid-proxy",
		4848:  "glassfish-admin",
		5000:  "docker-registry",
		5984:  "couchdb",
		6000:  "x11",
		7000:  "afs3-fileserver",
		7070:  "realserver",
		9091:  "xmltec-xmlmail",
		10000: "webmin",
		50000: "db2",
		50070: "hadoop-namenode",
	}
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
