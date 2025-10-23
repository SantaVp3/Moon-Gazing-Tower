package scanner

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// ServiceScanner 服务扫描器
type ServiceScanner struct {
	serviceMap   map[int]string
	timeout      time.Duration // 从配置加载
	bannerMaxLen int           // 从配置加载
}

// NewServiceScanner 创建服务扫描器
func NewServiceScanner() *ServiceScanner {
	return &ServiceScanner{
		serviceMap: map[int]string{
			21:    "ftp",
			22:    "ssh",
			23:    "telnet",
			25:    "smtp",
			53:    "dns",
			80:    "http",
			110:   "pop3",
			143:   "imap",
			443:   "https",
			445:   "smb",
			3306:  "mysql",
			3389:  "rdp",
			5432:  "postgresql",
			5900:  "vnc",
			6379:  "redis",
			8080:  "http-proxy",
			8443:  "https-alt",
			9200:  "elasticsearch",
			27017: "mongodb",
		},
	}
}

// Detect 识别服务
func (ss *ServiceScanner) Detect(ctx *ScanContext) error {
	// 🆕 加载扫描器配置
	scannerConfig := LoadScannerConfig(ctx)
	ss.timeout = scannerConfig.ServiceTimeout
	ss.bannerMaxLen = scannerConfig.BannerMaxLength
	ctx.Logger.Printf("[Config] Service scanner: timeout=%v, banner_max_len=%d", ss.timeout, ss.bannerMaxLen)

	var ports []models.Port
	ctx.DB.Where("task_id = ? AND (service IS NULL OR service = '')", ctx.Task.ID).Find(&ports)

	ctx.Logger.Printf("Detecting services for %d ports", len(ports))

	// SSL扫描器
	sslScanner := NewSSLScanner()

	for _, port := range ports {
		service := ss.detectService(port.IPAddress, port.Port)
		banner := ss.grabBanner(port.IPAddress, port.Port)

		updates := make(map[string]interface{})

		if service != "" {
			updates["service"] = service
		}

		if banner != "" {
			updates["banner"] = banner

			// 从banner检测版本
			version := ss.extractVersion(banner)
			if version != "" {
				updates["version"] = version
			}
		}

		// 如果启用SSL证书获取
		if ctx.Task.Options.EnableSSLCert {
			if port.Port == 443 || port.Port == 8443 || service == "https" {
				certInfo, err := sslScanner.GetCertificate(port.IPAddress, port.Port)
				if err == nil {
					updates["ssl_cert"] = sslScanner.FormatCertInfo(certInfo)
					ctx.Logger.Printf("SSL cert obtained: %s:%d", port.IPAddress, port.Port)

					// 从证书提取域名（需要验证是否属于目标域名）
					if len(certInfo.DNSNames) > 0 {
						// 获取目标域名列表
						targets := strings.Split(ctx.Task.Target, ",")
						for _, domain := range certInfo.DNSNames {
							if !strings.HasPrefix(domain, "*") {
								// 验证域名是否属于任何一个目标域名
								isValidDomain := false
								for _, target := range targets {
									target = strings.TrimSpace(target)
									if ss.isSubdomainOf(domain, target) {
										isValidDomain = true
										break
									}
								}

								if isValidDomain {
									// 保存发现的域名
									d := &models.Domain{
										TaskID:    ctx.Task.ID,
										Domain:    domain,
										Source:    "ssl_cert",
										IPAddress: port.IPAddress,
									}
									ctx.DB.Create(d)
								}
							}
						}
					}
				}
			}
		}

		if len(updates) > 0 {
			ctx.DB.Model(&port).Updates(updates)
			ctx.Logger.Printf("Service detected: %s:%d -> %s", port.IPAddress, port.Port, service)
		}
	}

	return nil
}

// extractVersion 从banner提取版本信息
func (ss *ServiceScanner) extractVersion(banner string) string {
	// 简单的版本提取逻辑
	// 匹配常见的版本格式: 数字.数字.数字
	re := regexp.MustCompile(`\d+\.\d+\.?\d*`)
	match := re.FindString(banner)
	return match
}

// detectService 检测服务（优化：减少误报）
func (ss *ServiceScanner) detectService(ip string, port int) string {
	// 首先尝试从已知端口映射获取
	if service, exists := ss.serviceMap[port]; exists {
		// 优化：对于标准端口，先验证banner再返回
		banner := ss.grabBanner(ip, port)
		if banner != "" {
			// 验证banner是否与预期服务匹配
			if ss.verifyService(service, banner) {
				return service
			}
			// 如果不匹配，尝试从banner识别真实服务
			if realService := ss.identifyFromBanner(banner); realService != "" {
				return realService
			}
		}
		// 即使没有banner，标准端口也返回预期服务
		return service
	}

	// 对于非标准端口，尝试banner抓取
	banner := ss.grabBanner(ip, port)
	if banner != "" {
		// 从banner识别服务
		if service := ss.identifyFromBanner(banner); service != "" {
			return service
		}
		return "unknown"
	}

	return ""
}

// verifyService 验证服务是否与banner匹配（减少误报）
func (ss *ServiceScanner) verifyService(expectedService, banner string) bool {
	banner = strings.ToLower(banner)

	// 定义服务特征关键词
	serviceKeywords := map[string][]string{
		"ssh":           {"ssh", "openssh"},
		"http":          {"http", "server:", "nginx", "apache"},
		"https":         {"http", "server:", "nginx", "apache"},
		"ftp":           {"ftp", "220"},
		"smtp":          {"smtp", "220"},
		"mysql":         {"mysql", "mariadb"},
		"redis":         {"redis"},
		"mongodb":       {"mongodb"},
		"postgresql":    {"postgresql"},
		"elasticsearch": {"elasticsearch"},
	}

	keywords, exists := serviceKeywords[expectedService]
	if !exists {
		return true // 没有特征关键词的服务，默认信任
	}

	// 检查是否包含任何关键词
	for _, keyword := range keywords {
		if strings.Contains(banner, keyword) {
			return true
		}
	}

	return false
}

// identifyFromBanner 从banner识别服务类型
func (ss *ServiceScanner) identifyFromBanner(banner string) string {
	banner = strings.ToLower(banner)

	// 定义服务识别规则
	identifyRules := map[string][]string{
		"ssh":           {"ssh-", "openssh"},
		"http":          {"http/1", "server:"},
		"ftp":           {"220", "ftp"},
		"smtp":          {"220", "smtp", "esmtp"},
		"mysql":         {"mysql", "mariadb"},
		"redis":         {"-err", "redis"},
		"mongodb":       {"mongodb"},
		"postgresql":    {"postgresql"},
		"elasticsearch": {"elasticsearch"},
		"nginx":         {"nginx"},
		"apache":        {"apache"},
	}

	for service, keywords := range identifyRules {
		for _, keyword := range keywords {
			if strings.Contains(banner, keyword) {
				return service
			}
		}
	}

	return ""
}

// isSubdomainOf 检查是否是子域名
func (ss *ServiceScanner) isSubdomainOf(subdomain, domain string) bool {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	domain = strings.ToLower(strings.TrimSpace(domain))

	// 完全匹配
	if subdomain == domain {
		return true
	}

	// 子域名必须以 .domain 结尾
	suffix := "." + domain
	if strings.HasSuffix(subdomain, suffix) {
		return true
	}

	return false
}

// grabBanner 抓取banner
func (ss *ServiceScanner) grabBanner(ip string, port int) string {
	// 🆕 使用配置的超时时间
	timeout := ss.timeout
	if timeout == 0 {
		timeout = 3 * time.Second // 默认3秒
	}

	// 🆕 使用配置的banner最大长度
	bannerLen := ss.bannerMaxLen
	if bannerLen == 0 {
		bannerLen = 2048 // 默认2048字节
	}

	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, bannerLen)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}
